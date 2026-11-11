#!/bin/bash
# Build, upload and register an attested worker image, and record what went
# into it. Run as root on an Amazon Linux 2023 build host (kiwi-cli,
# veritysetup, erofs-utils, aws-nitro-tpm-tools, nvidia-release, coldsnap), from
# a checkout of this repository, with the engine root already made by
# engine-root.sh (default /root/engroot):
#
#   attested-worker/build.sh <name> [engine root]
#   VERIFY=1 attested-worker/build.sh <name> [engine root]
#   BOOT_FROM=<release> attested-worker/build.sh <name> [engine root]
#
# An image is two volumes. The boot volume (kiwi: kernel, initrd, the
# worker, broker, sandbox and service, measured into PCR4) and the engine
# root (the solver's userspace: an erofs filesystem under dm-verity, whose
# root hash a machine measures into PCR15 before mounting it, and which only
# ever runs unprivileged in the sandbox).
#
# VERIFY=1 only builds and prints the PCR4 and the engine root hash, to compare
# with published ones (an auditor's rebuild): nothing is recorded, uploaded or
# registered. BOOT_FROM=<release> builds only the engine root and registers
# it with that release's boot volume: a solver update that leaves PCR4 alone.
#
# Writes attested-worker/releases/<name>/: pcr_measurements.json (its PCR4 is
# what gets published), packages.txt (every package and version installed),
# inputs.txt (this commit, the repository pins, the engine root's digest),
# engine.txt (the engine root hash) and image.txt (snapshots and AMI). Commit
# that folder with the release; publish the PCR4 (kind "image", unless
# BOOT_FROM) and the engine root hash (kind "engine") with web's
# attested-publish workflow once the image has passed its tests, then remove
# its blit-testing tag.
#
# From a Mac, copy the description with COPYFILE_DISABLE=1 tar (else "._"
# files end up in the image and change its measurements).
#
# Reproducible: two builds of one commit give the same PCR4. Every timestamp
# is the commit's (SOURCE_DATE_EPOCH: kiwi seeds its UUIDs from it, dracut and
# mkfs.erofs stamp files with it), and the verity salt and the filesystem,
# verity and partition UUIDs, which the tools would draw at random, are
# derived from it (the wrappers in $SHIMS, ahead of the real tools on PATH).
# The rest is in the image description: config.sh (NVIDIA modules),
# root/etc/fstab.script (logs, caches, package database) and
# edit_boot_install.sh (the UKI's PE timestamp).
set -euo pipefail
NAME=${1:?usage: build.sh <name> [engine root]}
ENGROOT=${2:-/root/engroot}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=/root/attested-out/$NAME
REC=$HERE/releases/$NAME
[ -d "$ENGROOT/home/ubuntu" ] || { echo "no engine root at $ENGROOT (engine-root.sh)"; exit 1; }
[ -z "${VERIFY:-}" ] && [ -e "$REC" ] && { echo "$REC exists: pick a new name"; exit 1; }
# What is copied from the repository into the image, beside this folder.
TRUSTED="../attested/__init__.py ../attested/worker.py ../attested/broker.py ../attested/forward.py ../attested/jail.py
  ../attested/jobenv.sh ../attested/rekey.py ../attested/service.py ../attested/ai.py ../attested/sandboxes.py
  ../attested/shim.sh ../blitcrypto/__init__.py ../blitcrypto/attest.py ../utils/run_creds.py"
[ -z "$(git -C "$HERE" status --porcelain -- . $TRUSTED)" ] || { echo "uncommitted changes in the image's sources"; exit 1; }
export SOURCE_DATE_EPOCH=$(git -C "$HERE" log -1 --format=%ct -- . $TRUSTED)
SEED=$(printf 'blit/attested-image/%s' "$SOURCE_DATE_EPOCH" | sha256sum | cut -c1-64)
uuid_of() { printf '%s-%s' "$SEED" "$1" | sha256sum | sed -E 's/^(.{8})(.{4}).(.{3}).(.{3})(.{12}).*/\1-\2-4\3-8\4-\5/'; }
SHIMS=$(mktemp -d)
cat > "$SHIMS/veritysetup" <<SHIM
#!/bin/bash
if [ "\$1" = format ]; then shift; exec $(command -v veritysetup) format --salt=$SEED --uuid=$(uuid_of verity) "\$@"; fi
exec $(command -v veritysetup) "\$@"
SHIM
cat > "$SHIMS/mkfs.erofs" <<SHIM
#!/bin/bash
exec $(command -v mkfs.erofs) -U $(uuid_of erofs) "\$@"
SHIM
# GPT GUIDs: kiwi lets sgdisk pick random ones, and the root partition's is
# written into the initrd (so into PCR4).
export BLIT_SEED=$SEED BLIT_SGDISK=$(command -v sgdisk)
cat > "$SHIMS/sgdisk" <<'SHIM'
#!/bin/bash
"$BLIT_SGDISK" "$@" || exit
u() { printf '%s-%s' "$BLIT_SEED" "$1" | sha256sum | sed -E 's/^(.{8})(.{4}).(.{3}).(.{3})(.{12}).*/\1-\2-4\3-8\4-\5/'; }
a=("$@")
for i in "${!a[@]}"; do
  [ "${a[$i]}" = -n ] || continue
  n=${a[$((i+1))]%%:*}
  [ -n "$n" ] && "$BLIT_SGDISK" -u "$n:$(u part$n)" -U "$(u disk)" "${a[-1]}" >/dev/null
done
exit 0
SHIM
chmod 755 "$SHIMS/veritysetup" "$SHIMS/mkfs.erofs" "$SHIMS/sgdisk"
REAL_VERITYSETUP=$(command -v veritysetup) REAL_MKFS_EROFS=$(command -v mkfs.erofs)
export PATH="$SHIMS:$PATH"

# The description, with the engine root in place, in a scratch copy.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK" "$SHIMS"' EXIT
cp -a "$HERE/image" "$WORK/image"
find "$WORK/image" -name '._*' -delete
# The worker, broker and sandbox: part of the measurement.
LIB=$WORK/image/root/usr/local/lib/blit
for f in $TRUSTED; do install -D -m 644 "$HERE/$f" "$LIB/${f#../}"; done
sed 's#/home/ubuntu/compute/utils#/opt/blit/utils#' "$HERE/../utils/run_creds.conf" > "$LIB/utils/run_creds.conf"
chmod 644 "$LIB/utils/run_creds.conf"
bash "$WORK/image/fetch-assets.sh"
# The worker and the job sandbox use the same path for these files on the
# host and, bound read-only, inside the engine root.
mkdir -p "$WORK/image/root/opt"
ln -s /usr/local/lib/blit "$WORK/image/root/opt/blit"
ENGINE_DIGEST=$(cd "$ENGROOT" && find . -xdev -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)

# The engine root volume: erofs, then its dm-verity hash tree, then (in the
# volume's last 4 KiB) the root hash and where the tree starts. The boot
# script reads that block, measures the hash and opens the volume with it;
# a wrong hash or offset only makes the volume unreadable. Its UUIDs are
# its own (the boot volume's root is found by UUID).
EOUT=/root/attested-out/$NAME-engine
rm -rf "$EOUT"; mkdir -p "$EOUT"
EIMG=$EOUT/engine.img
"$REAL_MKFS_EROFS" -zlz4hc,12 -U "$(uuid_of engine-erofs)" "$EIMG" "$ENGROOT" >/dev/null
DATA=$(stat -c %s "$EIMG")
[ $((DATA % 4096)) = 0 ] || { echo "engine root image not 4 KiB aligned"; exit 1; }
ENGINE_HASH=$("$REAL_VERITYSETUP" format --salt="$SEED" --uuid="$(uuid_of engine-verity)" --data-blocks=$((DATA / 4096)) \
  --hash-offset="$DATA" "$EIMG" "$EIMG" | awk '/^Root hash:/ {print $3}')
[[ "$ENGINE_HASH" =~ ^[0-9a-f]{64}$ ]] || { echo "no engine root hash"; exit 1; }
END=$(stat -c %s "$EIMG")
TOTAL=$(( (END + 4096 + (1 << 30) - 1) / (1 << 30) * (1 << 30) ))
truncate -s "$TOTAL" "$EIMG"
printf '{"v":1,"root_hash":"%s","hash_offset":%d}' "$ENGINE_HASH" "$DATA" |
  dd of="$EIMG" bs=4096 seek=$((TOTAL / 4096 - 1)) conv=notrunc status=none
echo "engine root: $ENGINE_HASH ($((TOTAL >> 30)) GiB volume)"

if [ -n "${BOOT_FROM:-}" ]; then
  [ -z "${VERIFY:-}" ] || { echo "VERIFY and BOOT_FROM do not go together"; exit 1; }
  FROM=$HERE/releases/$BOOT_FROM
  SNAP=$(awk '/^snapshot:/ {print $2}' "$FROM/image.txt")
  [ -n "$SNAP" ] || { echo "no boot snapshot in $FROM/image.txt"; exit 1; }
  mkdir -p "$REC"
  cp "$FROM/pcr_measurements.json" "$FROM/packages.txt" "$REC/"
else
rm -rf "$OUT"
kiwi-ng --loglevel 20 system build --description "$WORK/image" --target-dir "$OUT"
RAW=$(ls "$OUT"/*.raw)
if [ -n "${VERIFY:-}" ]; then
  echo "PCR4: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Measurements"]["PCR4"])' "$OUT/pcr_measurements.json")"
  echo "engine root: $ENGINE_HASH"
  exit 0
fi

mkdir -p "$REC"
cp "$OUT/pcr_measurements.json" "$REC/"
cp "$(ls "$OUT"/*.packages)" "$REC/packages.txt"
fi
echo "$ENGINE_HASH" > "$REC/engine.txt"
{
  [ -n "${BOOT_FROM:-}" ] && echo "boot volume: release $BOOT_FROM"
  echo "compute commit: $(git -C "$HERE" rev-parse HEAD)"
  grep -o 'https://[^"]*guids/[^"]*' "$HERE/image/appliance.kiwi" | sed 's/^/repository: /'
  echo "engine root sha256 (file contents, sorted): $ENGINE_DIGEST"
  echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
  echo "built: $(date -u +%FT%TZ)"
} > "$REC/inputs.txt"

export AWS_REGION=${AWS_REGION:-us-east-1}
[ -n "${BOOT_FROM:-}" ] || SNAP=$(coldsnap upload --wait "$RAW")
ESNAP=$(coldsnap upload --wait "$EIMG")
AMI=$(aws ec2 register-image --name "blit-attested-$NAME" --boot-mode uefi --tpm-support v2.0 --ena-support \
  --virtualization-type hvm --architecture x86_64 --root-device-name /dev/xvda \
  --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=$SNAP,VolumeType=gp3}" \
    "DeviceName=/dev/xvdb,Ebs={SnapshotId=$ESNAP,VolumeType=gp3}" \
  --tag-specifications "ResourceType=image,Tags=[{Key=blit-attested,Value=1},{Key=blit-testing,Value=1}]" \
  --query ImageId --output text)
printf 'snapshot: %s\nengine snapshot: %s\nami: %s\n' "$SNAP" "$ESNAP" "$AMI" > "$REC/image.txt"
echo "PCR4: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Measurements"]["PCR4"])' "$REC/pcr_measurements.json")"
echo "engine root: $ENGINE_HASH"
echo "$AMI registered (blit-testing: only the developer account's runs use it). Record: $REC"

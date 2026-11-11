#!/bin/bash
# What a sandboxed job can see, built as root in the job's own mount, network
# and PID namespaces, with the image's own tools; the job's programs run
# unprivileged inside the engine root (jail.py beside this file enters it).
# Nothing of the engine root or the compute commit is run as root.
#
#   jobenv.sh <job folder> <broker socket> <uid> <shell command to run in the sandbox>
set -e
LIB=$(dirname "$(readlink -f "$0")")
R=/run/engine   # the engine root (blit-worker-boot)
TMP=$1 SOCK=$2 ID=$3 CMD=$4
chmod o+x $R/home/ubuntu   # the job reads the code under it

# This PID namespace's own /proc.
mount -t proc -o nosuid,nodev,noexec proc $R/proc

# A private /tmp, and the engine's other fixed scratch folder inside it.
chown "$ID:$ID" "$TMP"
mount --bind "$TMP" $R/tmp
mkdir -m 1777 $R/tmp/.X11-unix
mkdir -p $R/tmp/home $R/tmp/.render $R/var/cache/blit-render
cp -a $R/var/cache/blit-render/. $R/tmp/.render/   # fonts and plotting caches, if the root has them
chown -R "$ID:$ID" $R/tmp/home $R/tmp/.render
mount --bind $R/tmp/.render $R/var/cache/blit-render
: > $R/tmp/.broker
mount --bind "$SOCK" $R/tmp/.broker

# Loopback is the only interface, and it starts down.
python3 -I "$LIB/forward.py" --up

# Only these devices: no TPM, no disks, no console.
GPU=$(for d in /dev/nvidia[0-9]* /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia-uvm-tools; do
  [ -c "$d" ] && stat -c '%n %t %T' "$d"; done; true)
mount -t tmpfs -o mode=755,nosuid,size=1m tmpfs $R/dev
while read -r n a b; do [ -z "$n" ] || mknod -m 666 "$R$n" c $((16#$a)) $((16#$b)); done <<< "$GPU"
mknod -m 666 $R/dev/null c 1 3
mknod -m 666 $R/dev/zero c 1 5
mknod -m 666 $R/dev/full c 1 7
mknod -m 666 $R/dev/random c 1 8
mknod -m 666 $R/dev/urandom c 1 9
ln -s /proc/self/fd $R/dev/fd
ln -s /proc/self/fd/0 $R/dev/stdin
ln -s /proc/self/fd/1 $R/dev/stdout
ln -s /proc/self/fd/2 $R/dev/stderr
mkdir -m 1777 $R/dev/shm
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs $R/dev/shm

# Of /sys, only what the GPU runtime reads to find the card.
mkdir -p /run/job-sys
mount --rbind /sys /run/job-sys
mount -t tmpfs -o mode=755,size=1m tmpfs $R/sys
for p in devices/system bus/pci /run/job-sys/devices/pci*; do
  p=${p#/run/job-sys/}
  mkdir -p "$R/sys/$p"
  mount --rbind "/run/job-sys/$p" "$R/sys/$p"
done
umount -l /run/job-sys

export RESULTS_BASE_DIR=/tmp/results PDF_REPORT_DIR=/tmp/.report HOME=/tmp/home USER=nobody LOGNAME=nobody DISPLAY=:99
exec python3 -I "$LIB/jail.py" "$ID" --root $R bash -c '
  python3 -I /opt/blit/attested/forward.py /tmp/.broker /tmp/.forward-ready &
  for i in $(seq 1 100); do [ -e /tmp/.forward-ready ] && break; sleep 0.1; done
  [ -e /tmp/.forward-ready ] || exit 1
  Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp </dev/null >/dev/null 2>&1 &
  for i in $(seq 1 100); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.1; done
  '"$CMD"

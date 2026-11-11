set -e
R=/root/engroot
rsync -aHA --numeric-ids --delete \
  --exclude=/boot --exclude=/usr/lib/modules --exclude=/lib/modules --exclude=/usr/src \
  --exclude=/snap --exclude=/var/lib/snapd --exclude=/var/snap --exclude="/var/cache/*" --exclude="/var/log/*" \
  --exclude="/usr/local/cuda*" --exclude=/opt/nvidia --exclude="/root/.cache/pip" --exclude=/root/.ci-keys \
  --exclude="/home/ubuntu/*.log" --exclude=/home/ubuntu/compute --exclude="/tmp/*" --exclude="/var/tmp/*" \
  --exclude="/usr/share/doc/*" --exclude="/usr/share/man/*" --exclude=/lost+found \
  --exclude="/etc/ssh/ssh_host_*" --exclude=/var/lib/cloud --exclude="/home/ubuntu/.ssh" --exclude="/root/.ssh" \
  --exclude=/proc --exclude=/sys --exclude=/dev \
  /mnt/eng/ $R/
for d in proc sys dev; do mkdir -p $R/$d; done
mount -t proc proc $R/proc; mount --rbind /dev $R/dev; mount --make-rslave $R/dev; mount --rbind /sys $R/sys; mount --make-rslave $R/sys
trap 'for m in dev sys proc; do umount -R -l "$R/$m" 2>/dev/null; done; true' EXIT
PKGS=$(chroot $R dpkg -l | awk '/^ii/ && /nvidia|libnvidia|xserver-xorg-video-nvidia|screen-resolution-extra/ {print $2}')
chroot $R env DEBIAN_FRONTEND=noninteractive dpkg --purge --force-depends $PKGS openssh-server cloud-init ec2-instance-connect >/tmp/purge.log 2>&1 || tail -5 /tmp/purge.log
# What the purge leaves that differs from one run to the next: its log (dated
# lines) and ldconfig's aux-cache (inode numbers and times).
rm -rf $R/var/log/* $R/var/cache/ldconfig/aux-cache
echo "nvidia libs left: $(ls $R/usr/lib/x86_64-linux-gnu | grep -c 'libcuda\|libnvidia' || true)"
du -xsh $R
# The import check runs on a throwaway overlay: importing the PDF and plotting
# stacks starts fontconfig, which would otherwise write its caches into the
# root under freshly drawn random UUIDs (a .uuid in every font directory),
# and no two engine roots would match.
C=$(mktemp -d); mkdir -p $C/u $C/w $C/m
mount -t overlay overlay -o lowerdir=$R,upperdir=$C/u,workdir=$C/w $C/m
mount -t proc proc $C/m/proc; mount --rbind /dev $C/m/dev; mount --make-rslave $C/m/dev; mount --rbind /sys $C/m/sys; mount --make-rslave $C/m/sys
chroot $C/m python3 -c "import openEMS, CSXCAD, torch, gmsh, netgen, petsc4py, slepc4py, playwright, vtk, weasyprint, trimesh, shapely, skfem; print('imports ok', openEMS.__file__)"
for m in dev sys proc; do umount -R -l "$C/m/$m"; done; umount -l $C/m; rm -rf $C

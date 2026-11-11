# Enable the set-hostname-imds service. This will set the hostname
# based on IMDS in place of cloud-init

echo "enable set-hostname-imds.service" >> /usr/lib/systemd/system-preset/80-amzn-overrides.preset

systemctl preset set-hostname-imds
systemctl enable blit-worker.service
# Build the NVIDIA module for the IMAGE's kernel, not the build host's.
# Unsigned: DKMS would sign it with a key made on the spot (different every
# build, and enrolled nowhere, so it proves nothing), which is what kept two
# builds from matching. Its build tree and logs go too (timestamps).
KV=$(ls /lib/modules | sort -V | tail -1)
mkdir -p /etc/dkms/framework.conf.d
echo 'sign_file="/nonexistent"' > /etc/dkms/framework.conf.d/blit-unsigned.conf
# The NVIDIA build stamps `date`, the user and the host name into the modules,
# so those are fixed in the source and the modules (already built when the
# package went in) are built again.
sed -i -e 's/^DATE \( *\)?= date$/DATE \1?= echo -/' \
       -e 's/^NV_BUILD_USER \( *\)?= .*/NV_BUILD_USER \1?= root/' \
       -e 's/^NV_BUILD_HOST \( *\)?= .*/NV_BUILD_HOST \1?= build/' /usr/src/nvidia-*/utils.mk
[ "$(grep -c -e '^DATE .*= echo -$' -e '^NV_BUILD_USER .*= root$' -e '^NV_BUILD_HOST .*= build$' /usr/src/nvidia-*/utils.mk)" = 3 ]
for d in /usr/src/nvidia-*/; do d=${d%/}; v="nvidia/${d##*-}"
  dkms build --force "$v" -k "$KV" && dkms install --force "$v" -k "$KV"
done
rm -rf /var/lib/dkms/*/*/build /var/lib/dkms/*/*/*/log /var/lib/dkms/mok.*
ls -la /lib/modules/$KV/extra/ || find /lib/modules/$KV -name 'nvidia*.ko*'
depmod "$KV"
# With no syslog in the build chroot, dracut logs to /dev/kmsg instead, which
# (no /dev mounted there) becomes a file in the image.
echo 'sysloglvl=0' > /etc/dracut.conf.d/90-build-log.conf

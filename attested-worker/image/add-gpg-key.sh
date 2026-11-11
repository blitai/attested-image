# Add the AL2023 public key to the kiwi build repository
repo_file=$1
echo "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-amazon-linux-2023" >> ${repo_file}

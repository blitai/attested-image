#!/bin/bash
# Binaries the image carries that are not packages: fetched by pinned URL and
# checked against pinned digests before they go into the image root.
set -euo pipefail
cd "$(dirname "$0")"
fetch() {  # url sha256 dest
  curl -sSfL -o "$3.tmp" "$1"
  echo "$2  $3.tmp" | sha256sum -c --quiet
  mv "$3.tmp" "$3"; chmod 755 "$3"
}
# AWS Lambda runtime interface emulator v1.37 (digest as GitHub publishes it):
# runs the processing service's Lambda images on the machine.
fetch https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/download/v1.37/aws-lambda-rie-x86_64 \
  6b1e686e62ab2baf5759c412c4864276ef2a88b094fca53ec070637ccba9b9a5 root/usr/local/bin/aws-lambda-rie

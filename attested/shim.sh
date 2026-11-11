#!/bin/sh
# Inside a processing function's container, which has no network: the function's
# S3 client reaches the service's broker, and the service reaches the function,
# through unix sockets in /sock.
export HOME=/tmp
python3 -I /shim/forward.py /sock/broker.sock /tmp/.forward-ready &
python3 -I /shim/forward.py --serve /sock/invoke.sock 8080 &
exec /rie "$@"

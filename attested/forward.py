"""Inside a job's network namespace: relay 127.0.0.1:9000 to the broker's unix
socket, the job's only way out.

  forward.py --up                                  (once, while still root)
  forward.py <broker socket> <file to create once listening>
  forward.py --serve <socket> <port>    (the other way round, once the port answers)
"""
import fcntl
import os
import socket
import struct
import sys
import threading
import time

SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
PORT = 9000


def loopback_up():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flags = struct.unpack("16sh22x", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sh22x", b"lo", 0)))[1]
    fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sh22x", b"lo", flags | IFF_UP))
    s.close()


def pump(a, b):
    try:
        while True:
            data = a.recv(1 << 20)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def serve(path, port):
    """A unix socket onto a local TCP port, created only once the port answers."""
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            time.sleep(0.05)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path + ".new")
    srv.listen(16)
    os.rename(path + ".new", path)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=relay, args=(client, ("127.0.0.1", port), socket.AF_INET), daemon=True).start()


def relay(client, address, family=socket.AF_UNIX):
    upstream = socket.socket(family, socket.SOCK_STREAM)
    try:
        upstream.connect(address)
        t = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        t.start()
        pump(client, upstream)
        t.join()
    finally:
        upstream.close()
        client.close()


def main():
    if sys.argv[1] == "--up":
        return loopback_up()
    if sys.argv[1] == "--serve":
        return serve(sys.argv[2], int(sys.argv[3]))
    path, ready = sys.argv[1], sys.argv[2]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(128)
    open(ready, "w").close()
    while True:
        client, _ = srv.accept()
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=relay, args=(client, path), daemon=True).start()


if __name__ == "__main__":
    main()

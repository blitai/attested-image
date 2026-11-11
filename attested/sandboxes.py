"""The processing functions, one sandbox per function and project.

Each sandbox is a container with no network, no capabilities and a read-only
root, running as an unprivileged user, that serves one function for one
project. The project key stays in this process: the function reaches its files
through a broker (broker.py) that holds the key and allows only that project's
folder. A sandbox is never reused for another project or another user, so what
a function kept from one call can only go back where it came from.
"""
import hashlib
import http.client
import json
import os
import shutil
import socket
import threading
import time
import uuid

from attested.broker import DELETABLE_SERVICE, WRITABLE_SERVICE, Broker
from blitcrypto import wrap_s3

ROOT = "/run/blit-svc"
DOCKER = "/run/docker.sock"
JOB_UID = 65534
IDLE_S = 10 * 60
MAX_SANDBOXES = 6
READY_S = 120
CALL_S = 900


class _Unix(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.unix = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.unix)
        self.sock = s


def _docker(method, path, body=None):
    c = _Unix(DOCKER, 60)
    try:
        c.request(method, path, json.dumps(body) if body is not None else None, {"Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
        if r.status >= 300:
            raise RuntimeError(f"docker {method}: {r.status}")
        return json.loads(data) if data else None
    finally:
        c.close()


class _Sandbox:
    def __init__(self, function, s3, bucket, root, role, key):
        self.lock = threading.Lock()
        self.used = time.time()
        self.dir = f"{ROOT}/{uuid.uuid4().hex}"
        os.makedirs(self.dir, mode=0o700)
        os.chown(self.dir, JOB_UID, JOB_UID)
        self.broker = Broker(f"{self.dir}/broker.sock", s3, wrap_s3(s3, root, key), bucket, root,
                             writable=WRITABLE_SERVICE, deletable=DELETABLE_SERVICE, read_only=role == "viewer")
        os.chown(f"{self.dir}/broker.sock", JOB_UID, JOB_UID)
        env = ["BLIT_LOCAL_JOBS=1", "AWS_REGION=us-east-1", "AWS_DEFAULT_REGION=us-east-1",
               "AWS_ACCESS_KEY_ID=sandbox", "AWS_SECRET_ACCESS_KEY=sandbox", "AWS_EC2_METADATA_DISABLED=true",
               "AWS_REQUEST_CHECKSUM_CALCULATION=when_required", "AWS_RESPONSE_CHECKSUM_VALIDATION=when_required",
               "BLIT_S3_ENDPOINT=http://127.0.0.1:9000", f"BLIT_PROJECT_ROOT={root}", f"BLIT_PROJECT_ROLE={role}"]
        made = _docker("POST", "/containers/create", {
            "Image": function["image"], "User": f"{JOB_UID}:{JOB_UID}", "Env": env,
            "Entrypoint": ["/bin/sh", "/shim/shim.sh"], "Cmd": function["command"],
            "HostConfig": {
                "NetworkMode": "none", "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
                "ReadonlyRootfs": True, "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=6g,mode=1777"}, "PidsLimit": 4096,
                "AutoRemove": True, "LogConfig": {"Type": "none", "Config": {}},
                "Binds": ["/usr/local/bin/aws-lambda-rie:/rie:ro", "/usr/local/lib/blit/attested:/shim:ro",
                          f"{self.dir}:/sock"]}})
        self.container = made["Id"]
        _docker("POST", f"/containers/{self.container}/start")
        deadline = time.time() + READY_S
        while not os.path.exists(f"{self.dir}/invoke.sock"):
            if time.time() > deadline:
                self.close()
                raise RuntimeError("sandbox did not start")
            time.sleep(0.05)

    def invoke(self, event):
        c = _Unix(f"{self.dir}/invoke.sock", CALL_S)
        try:
            c.request("POST", "/2015-03-31/functions/function/invocations", json.dumps(event))
            return json.loads(c.getresponse().read() or b"null")
        finally:
            c.close()

    def active(self):
        return max(self.used, self.broker.last_active)

    def close(self):
        try:
            _docker("POST", f"/containers/{self.container}/kill")
        except Exception:
            pass
        self.broker.stop()
        shutil.rmtree(self.dir, ignore_errors=True)


class Sandboxes:
    def __init__(self, functions, s3, bucket):
        self.functions, self.s3, self.bucket = functions, s3, bucket
        self.boxes, self.lock = {}, threading.Lock()
        os.makedirs(ROOT, mode=0o711, exist_ok=True)
        threading.Thread(target=self._reap, daemon=True).start()

    def _reap(self):
        while True:
            time.sleep(30)
            with self.lock:
                idle = [k for k, b in self.boxes.items() if time.time() - b.active() > IDLE_S and not b.lock.locked()]
                gone = [self.boxes.pop(k) for k in idle]
            for b in gone:
                b.close()

    def _box(self, fn, root, role, key):
        name = (fn, root, role, hashlib.sha256(key).hexdigest())
        with self.lock:
            box = self.boxes.get(name)
            if box is not None:
                return box
            spare = sorted(self.boxes, key=lambda k: self.boxes[k].active())
            out = [self.boxes.pop(k) for k in spare[:max(0, len(spare) + 1 - MAX_SANDBOXES)]]
        for b in out:
            b.close()
        box = _Sandbox(self.functions[fn], self.s3, self.bucket, root, role, key)
        with self.lock:
            self.boxes[name] = box
        return box

    def call(self, fn, root, role, key, event):
        box = self._box(fn, root, role, key)
        with box.lock:
            box.used = time.time()
            box.broker.refused_names.clear()
            reply = box.invoke(event)
            box.used = time.time()
        if box.broker.refused_names and isinstance(reply, dict):
            reply["sandboxRefused"] = sorted(box.broker.refused_names)[:50]
        return reply

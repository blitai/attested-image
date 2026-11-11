"""The attested worker, part of the measured image from this release on
(attested-worker/image: blit-worker-boot starts it from /opt/blit, on the
image's own Python, after measuring the engine root into ENGINE_PCR and the
run's compute commit into CODE_PCR). Everything from that commit and the
engine root runs in the sandbox, unprivileged.

  1. A P-256 key pair made here; the NitroTPM attestation document binds its
     public key and the job ticket's hash (user_data) and the browser's
     challenge (nonce). The document goes to S3, in plain: it holds no secret.
  2. The browser verifies it (web/src/services/crypto/attestation.ts) and
     seals the project key to that public key; it arrives through S3.
  3. As the coordinator, plan the run as the run Lambda would (plan.py, in
     the sandbox) and split its jobs into lanes, one per machine: the Lambda launches peers
     with tickets naming us, each peer attests to OUR challenge, and we check
     it is this image running this commit before sealing it the key and its
     lane (job assignments name sweep parameters, so they travel sealed
     too). A peer that never verifies has its lane run here. As a peer: run
     the lane the coordinator sealed to us.

Nothing here ever writes the key, or anything decrypted with it, anywhere but
this machine's RAM and its encrypted scratch.

Control files, all plain JSON or CBOR, under attested/<run>/<instance>/ in
the bucket: doc.cbor (ours), key.json (the browser's), and attested/<run>/stop.
"""
import argparse
import base64
import hashlib
import json
import shlex
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import uuid

import boto3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import run_creds  # noqa: E402
run_creds.use()  # before any AWS client: the run's own credentials, for this process and its jobs
from blitcrypto import wrap_s3  # noqa: E402
from blitcrypto.attest import (CODE_PCR, ENGINE_PCR, AttestationError, _cbor_decode, new_instance_key, unwrap,  # noqa: E402
                               verify_attestation, wrap_for_instance)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

BUCKET = "blitai-dev-bucket"
KEY_WAIT_S = 15 * 60
KEY_POLL_S = 0.5     # the key arrives seconds after the document; a run starts that much sooner
PEER_WAIT_S = 20 * 60
MAX_MACHINES = 16            # = the run Lambda's MAX_RUN_INSTANCES
COMPUTE = "/home/ubuntu/compute"
BROKER_SOCK = "/run/blit-jobs/broker.sock"
JOB_UID = 65534   # nobody
LIB = os.path.dirname(os.path.abspath(__file__))
MAX_JOBS = 1 << 16
PLAN_BYTES = 64 << 20   # = broker.PLAN_BYTES
PORT_RE = re.compile(r"[\w(),]{1,24}")
S3 = boto3.client("s3", region_name="us-east-1")


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _exists(key):
    try:
        S3.head_object(Bucket=BUCKET, Key=key)
        return True
    except Exception:
        return False


def attest(ticket_bytes, ticket, base):
    """Make our key, get the document binding it, publish the document."""
    priv, spki = new_instance_key()
    user_data = json.dumps({"v": 1, "spki": _b64u(spki),
                            "ticket": hashlib.sha256(ticket_bytes).hexdigest()}, separators=(",", ":")).encode()
    nonce = base64.urlsafe_b64decode(ticket["challenge"] + "=" * (-len(ticket["challenge"]) % 4))
    os.makedirs("/run/blit", mode=0o700, exist_ok=True)
    with open("/run/blit/user_data", "wb") as f:
        f.write(user_data)
    with open("/run/blit/nonce", "wb") as f:
        f.write(nonce)
    doc = subprocess.run(["nitro-tpm-attest", "-u", "/run/blit/user_data", "-n", "/run/blit/nonce"],
                         check=True, stdout=subprocess.PIPE, timeout=120).stdout
    with open("/run/blit/doc.cbor", "wb") as f:
        f.write(doc)
    S3.put_object(Bucket=BUCKET, Key=base + "doc.cbor", Body=doc)
    log(f"attested ({len(doc)} bytes)")
    return priv


def _b64d(v):
    return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))


def receive(priv, ticket, base):
    """What was sealed to us, by role: from the browser, the project key
    (coordinator) or {"key"} (optimizer); from the coordinator (peer)
    {"key", "session"}. Returns (key, extra)."""
    role = ticket.get("role")
    if role == "rekey":
        return receive_rekey(priv, ticket, base)
    label = f"blit/attested-{'peer' if role == 'peer' else 'run'}/{ticket['run']}"
    deadline = time.time() + KEY_WAIT_S
    while time.time() < deadline:
        if _exists(f"attested/{ticket['run']}/stop"):
            return None, None
        try:
            wrapped = json.loads(S3.get_object(Bucket=BUCKET, Key=base + "key.json")["Body"].read())
        except Exception:
            time.sleep(KEY_POLL_S)
            continue
        opened = unwrap(priv, wrapped, label)
        if role == "peer":
            payload = json.loads(opened)
            key, extra = _b64d(payload["key"]), _b64d(payload["session"])
        elif role == "optimizer":
            payload = json.loads(opened)
            key, extra = _b64d(payload["key"]), None
        else:
            key, extra = opened, None
        if len(key) != 32:
            raise ValueError("project key must be 32 bytes")
        log("project key received")
        return key, extra
    return None, None


def receive_rekey(priv, ticket, base):
    """A re-key job (attested/rekey.py): each project's old and new key, sealed
    by the browser. Returns (None, {projectId: (old, new)})."""
    deadline = time.time() + KEY_WAIT_S
    while time.time() < deadline:
        try:
            wrapped = json.loads(S3.get_object(Bucket=BUCKET, Key=base + "key.json")["Body"].read())
        except Exception:
            time.sleep(KEY_POLL_S)
            continue
        payload = json.loads(unwrap(priv, wrapped, f"blit/attested-rekey/{ticket['run']}"))
        dec = lambda v: base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
        projects = {pid: (dec(k["old"]), dec(k["new"])) for pid, k in payload["projects"].items()}
        if not all(len(o) == 32 and len(n) == 32 for o, n in projects.values()):
            raise ValueError("project keys must be 32 bytes")
        log(f"re-key: {len(projects)} project(s)")
        return None, projects
    return None, None


def own_pcrs():
    """Our image's PCR4, our code's CODE_PCR and our engine root's ENGINE_PCR,
    from our own document, and the PCRs the boot stub extends only when handed
    a command line, credentials or extensions, which must not have been
    extended."""
    top = _cbor_decode(open("/run/blit/doc.cbor", "rb").read())
    body = _cbor_decode((top[2] if isinstance(top, tuple) else top)[2])
    return {4: body["nitrotpm_pcrs"][4].hex(), 12: "00" * 48, 13: "00" * 48,
            CODE_PCR: body["nitrotpm_pcrs"][CODE_PCR].hex(), ENGINE_PCR: body["nitrotpm_pcrs"][ENGINE_PCR].hex()}


def launch_peers(ticket, instance, n):
    """n peers from the run Lambda, each with a challenge of ours: [(id, challenge)]."""
    challenges = [_b64u(os.urandom(32)) for _ in range(n)]
    resp = boto3.client("lambda", region_name="us-east-1").invoke(
        FunctionName="run_simulation",
        Payload=json.dumps({"_attested_peers": 1, "run": ticket["run"], "coordinator": instance,
                            "challenges": challenges}).encode())
    out = json.loads(resp["Payload"].read())
    peers = json.loads(out.get("body") or "{}").get("peers", []) if out.get("statusCode") == 200 else []
    log(f"{len(peers)} of {n} peer(s) launched")
    return list(zip(peers, challenges))


def _lane_aad(run, peer, k):
    return f"blit/v1/lane/{run}/{peer}/{k}".encode()


class PeerPool:
    """Peers of this run, verified once and then given lanes for as long as
    the run lasts (an optimization dispatches an iteration after another).

    Each peer attests to a challenge of ours; we check it is this image
    running this commit, its key bound to its ticket, and seal it the project
    key and a session key. Lanes -- job assignments name sweep parameters --
    are then sealed under the session key, one file per lane, numbered. A
    peer that never verifies has its lanes run here instead. end() lets the
    peers go once their lanes are done."""

    def __init__(self, ticket, instance, key, stop, run_lane):
        self.t, self.instance, self.key, self.stop, self.run_lane = ticket, instance, key, stop, run_lane
        self.run = ticket["run"]
        self.peers = []            # [{"id", "session", "seq", "state": pending|ready|failed, "held": [lanes]}]
        self.lock = threading.Lock()
        self.local = []            # threads running lanes here

    def grow(self, n):
        if n <= len(self.peers):
            return
        pcrs = own_pcrs()
        for peer, challenge in launch_peers(self.t, self.instance, n - len(self.peers)):
            p = {"id": peer, "session": os.urandom(32), "seq": 0, "state": "pending", "held": []}
            self.peers.append(p)
            threading.Thread(target=self._serve, args=(p, challenge, pcrs), daemon=True).start()

    def _serve(self, p, challenge, pcrs):
        base = f"attested/{self.run}/{p['id']}/"
        deadline, nonce = time.time() + PEER_WAIT_S, _b64d(challenge)
        while time.time() < deadline and not self.stop.is_set():
            try:
                doc = S3.get_object(Bucket=BUCKET, Key=base + "doc.cbor")["Body"].read()
                ticket_bytes = S3.get_object(Bucket=BUCKET, Key=base + "ticket.json")["Body"].read()
            except Exception:
                time.sleep(3)
                continue
            try:
                v = verify_attestation(doc, pcrs, nonce=nonce, max_age_s=PEER_WAIT_S)
                bound = json.loads(v["user_data"] or b"{}")
                if bound.get("v") != 1 or bound.get("ticket") != hashlib.sha256(ticket_bytes).hexdigest():
                    raise AttestationError("attestation: the peer's key is not bound to its ticket")
                if json.loads(ticket_bytes).get("coordinator") != self.instance:
                    raise AttestationError("attestation: not our peer")
            except (AttestationError, ValueError) as e:
                log(f"peer {p['id']} rejected: {e}")
                break
            payload = json.dumps({"key": _b64u(self.key), "session": _b64u(p["session"])}).encode()
            S3.put_object(Bucket=BUCKET, Key=base + "key.json", Body=json.dumps(
                wrap_for_instance(_b64d(bound["spki"]), payload, f"blit/attested-peer/{self.run}")).encode())
            with self.lock:
                p["state"] = "ready"
            log(f"peer {p['id']} verified")
            return
        with self.lock:
            p["state"], held, p["held"] = "failed", p["held"], []
        log(f"peer {p['id']} unavailable; {len(held)} lane(s) run here")
        for lane in held:
            self._here(lane)

    def _here(self, lane):
        t = threading.Thread(target=self.run_lane, args=(lane,), daemon=True)
        t.start()
        self.local.append(t)

    def assign(self, i, lane):
        """Lane `lane` to peer i (or here, if it failed)."""
        with self.lock:
            p = self.peers[i]
            if p["state"] == "failed":
                self._here(lane)
                return
            if p["state"] == "pending":
                p["held"].append(lane)   # run here instead if it never verifies
            k, p["seq"] = p["seq"], p["seq"] + 1
        iv = os.urandom(12)
        ct = AESGCM(p["session"]).encrypt(iv, json.dumps(lane).encode(), _lane_aad(self.run, p["id"], k))
        S3.put_object(Bucket=BUCKET, Key=f"attested/{self.run}/{p['id']}/lane-{k}.json",
                      Body=json.dumps({"iv": _b64u(iv), "ct": _b64u(ct)}).encode())

    def dispatch(self, jobs):
        """Job 0 (the master: it solves, then waits for every other job and
        consolidates them) here, beside everything else; the rest over the
        peers, one lane each."""
        if jobs:
            master = threading.Thread(target=self.run_lane, args=(jobs[:1],), daemon=True)
            _MASTERS.append(master)
            master.start()
        rest = jobs[1:]
        if not rest:
            return
        self.grow(min(len(rest), MAX_MACHINES - 1))
        n = len(self.peers)
        if not n:
            self._here(rest)
            return
        for i in range(n):
            lane = rest[i::n]
            if lane:
                self.assign(i, lane)

    def end(self):
        S3.put_object(Bucket=BUCKET, Key=f"attested/{self.run}/end", Body=b"")


def peer_lanes(ticket, instance, session, stop, run_lane):
    """A peer: run the coordinator's lanes, in order, until it ends the run."""
    run, k = ticket["run"], 0
    while not stop.is_set():
        try:
            box = json.loads(S3.get_object(Bucket=BUCKET, Key=f"attested/{run}/{instance}/lane-{k}.json")["Body"].read())
        except Exception:
            if _exists(f"attested/{run}/end"):
                return
            time.sleep(3)
            continue
        lane = json.loads(AESGCM(session).decrypt(_b64d(box["iv"]), _b64d(box["ct"]), _lane_aad(run, instance, k)))
        log(f"lane {k}: {len(lane)} job(s)")
        run_lane([tuple(j) for j in lane])
        k += 1


_JOB_SEQ = iter(range(1, 1 << 30))


def run_job(ticket, case, port, stop):
    """One engine run: the compute process and its stream sibling, as the run
    Lambda's init_script starts them. In its own mount, network and PID
    namespaces, unprivileged, with only loopback, the GPU and the forwarder to
    the broker (attested/jobenv.sh, attested/jail.py). The job is given no
    key: the broker encrypts what it writes."""
    args = ["--username", ticket["user"], "--prefix", ticket["prefix"]]
    if port is not None:
        args += ["--excite", str(port)]
    if case:
        args += ["--parameters", case]
    q = shlex.join(args)
    return _sandboxed(f"cd {COMPUTE}; cp -r pdf_report /tmp/.report; "
                      f"PERF_ROLE=compute python3 engine.py {q} > /tmp/engine.log 2>&1 & C=$!; sleep 2; "
                      f"PERF_ROLE=stream python3 -u engine.py {q} --stream > /tmp/stream_bash.log 2>&1; wait $C", stop)


def _sandboxed(command, stop, setup=None):
    """One shell command from the compute commit, in the sandbox; its exit code."""
    n = next(_JOB_SEQ)
    tmp = f"/run/blit-jobs/{n}"
    os.makedirs(tmp, mode=0o700, exist_ok=True)
    if setup:
        setup(tmp)
    os.chown(BROKER_SOCK, JOB_UID, JOB_UID)
    env = {k: v for k, v in os.environ.items() if k not in ("AWS_CONFIG_FILE", "AWS_PROFILE")}
    env.update(PYTHONFAULTHANDLER="1", OPENEMS_PROF="1", BLIT_S3_ENDPOINT="http://127.0.0.1:9000",
               AWS_ACCESS_KEY_ID="sandbox", AWS_SECRET_ACCESS_KEY="sandbox", AWS_DEFAULT_REGION="us-east-1",
               AWS_EC2_METADATA_DISABLED="true", AWS_REQUEST_CHECKSUM_CALCULATION="when_required",
               AWS_RESPONSE_CHECKSUM_VALIDATION="when_required")
    job = subprocess.Popen(["unshare", "-m", "-n", "-p", "-f", "--kill-child", "--mount-proc", "--propagation", "private",
                            "bash", f"{LIB}/jobenv.sh", tmp, BROKER_SOCK, str(JOB_UID), command],
                           cwd="/", env=env, start_new_session=True)
    while job.poll() is None:
        if stop.is_set():
            os.killpg(job.pid, 9)
            break
        time.sleep(2)
    log(f"job {n}: exit {job.returncode}")
    return job.returncode


def plan_jobs(ticket, broker, files, stop):
    """The run's jobs, from plan.py in the sandbox. Only what this function
    accepts leaves the sandbox: job names that are the project's own cases."""
    broker.planning, broker.plan = True, None
    try:
        rc = _sandboxed(f"cd {COMPUTE}; python3 attested/plan.py {shlex.quote(ticket['prefix'])} > /tmp/plan.log 2>&1", stop)
    finally:
        broker.planning = False
    if rc != 0 or broker.plan is None or len(broker.plan) > PLAN_BYTES:
        raise RuntimeError(f"planning failed ({rc})")
    jobs = json.loads(broker.plan)
    cases = json.loads(files.get_object(Bucket=BUCKET, Key=ticket["prefix"] + "case.json")["Body"].read())
    if not isinstance(jobs, list) or not 0 < len(jobs) <= MAX_JOBS:
        raise RuntimeError("bad plan")
    for job in jobs:
        if not (isinstance(job, list) and len(job) == 2 and isinstance(job[0], str) and job[0] in cases
                and (job[1] is None or (isinstance(job[1], str) and PORT_RE.fullmatch(job[1])))):
            raise RuntimeError("bad plan")
    return [tuple(j) for j in jobs]


_MASTERS = []


def _wait_master_and_local(pool, stop):
    while not stop.is_set() and (any(t.is_alive() for t in _MASTERS) or any(t.is_alive() for t in pool.local)):
        time.sleep(5)


SITE = "https://www.blit.ai"
SITE_FILE = re.compile(r"/static/[\w.\-/]{1,200}")


def fetch_site(dest):
    """The app as the site serves it now, for the optimizer's headless browser.
    Its sandbox has no network, so this list, fixed before it starts, is all
    it will get: a request for anything else can't carry anything out."""
    from concurrent.futures import ThreadPoolExecutor

    def get(path):
        with urllib.request.urlopen(SITE + path, timeout=60) as r:
            return r.read()

    manifest = json.loads(get("/asset-manifest.json"))
    files = sorted({f for f in manifest["files"].values() if SITE_FILE.fullmatch(f) and not f.endswith(".map")})

    def save(path):
        data = get(path)
        out = dest + path
        os.makedirs(os.path.dirname(out), mode=0o755, exist_ok=True)
        with open(out, "wb") as f:
            f.write(data)
    os.makedirs(dest, mode=0o755, exist_ok=True)
    with open(dest + "/index.html", "wb") as f:
        f.write(get("/index.html"))
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(save, files))
    log(f"site: {len(files)} files")


class ProcessingService:
    """The attested processing service, for an optimizer's headless app, which
    has no network and no key: verified as a browser would, each call sealed
    to it with the project key added here."""

    FUNCTIONS = ("generate_mesh", "classify_mesh")

    def __init__(self, ticket, instance, key):
        self.ticket, self.instance, self.key = ticket, instance, key
        self.project = ticket["prefix"].rstrip("/").split("/")[-1]
        self.session, self.lock = None, threading.Lock()

    def _relay(self, action, **body):
        resp = boto3.client("lambda", region_name="us-east-1").invoke(
            FunctionName="run_simulation",
            Payload=json.dumps({"_attested_svc": 1, "run": self.ticket["run"], "coordinator": self.instance,
                                "action": action, "body": body}).encode())
        out = json.loads(resp["Payload"].read())
        return out.get("statusCode"), json.loads(out.get("body") or "null")

    def _wait(self, rid, status, out, seconds):
        deadline = time.time() + seconds
        while status == 200 and isinstance(out, dict) and out.get("pending") and time.time() < deadline:
            status, out = self._relay("svc_result", id=rid)
        if status != 200 or not isinstance(out, dict) or out.get("pending") or out.get("error"):
            raise RuntimeError(f"processing service: {status}")
        return out

    def _open(self):
        from cryptography.hazmat.primitives import serialization
        deadline = time.time() + 15 * 60
        while True:
            _, st = self._relay("svc_status")
            if isinstance(st, dict) and st.get("state") == "ready":
                break
            if time.time() > deadline or (isinstance(st, dict) and st.get("state") == "unavailable"):
                raise RuntimeError("the processing service is not available")
            time.sleep(5)
        nonce, rid = os.urandom(32), uuid.uuid4().hex
        status, out = self._relay("svc_hello", id=rid, nonce=_b64u(nonce))
        out = self._wait(rid, status, out, 60)
        # A published image, as a browser would require; from this release on
        # such an image runs its service only from what it measured.
        with urllib.request.urlopen(SITE + "/attested-releases.json", timeout=30) as r:
            images = [i["pcr4"] for i in json.load(r)["images"]]
        v = None
        for pcr4 in images:
            try:
                v = verify_attestation(base64.b64decode(out["doc"]), {4: pcr4, 12: "00" * 48, ENGINE_PCR: "00" * 48},
                                       nonce=nonce, max_age_s=300)
                break
            except AttestationError:
                pass
        if v is None:
            raise AttestationError("the processing service is not a published image")
        bound = json.loads(v["user_data"])
        if bound.get("v") != 1 or bound.get("role") != "service":
            raise AttestationError("not the processing service")
        return out["instance"], serialization.load_der_public_key(_b64d(bound["spki"]))

    def _call(self, fn, event):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        with self.lock:
            if self.session is None:
                self.session = self._open()
            instance, service = self.session
        rid = uuid.uuid4().hex
        eph = ec.generate_private_key(ec.SECP256R1())
        pub = eph.public_key()
        raw = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        key = AESGCM(HKDF(algorithm=hashes.SHA256(), length=32, salt=raw,
                          info=b"blit/v1/svc/" + rid.encode()).derive(eph.exchange(ec.ECDH(), service)))
        n = pub.public_numbers()
        epk = {"kty": "EC", "crv": "P-256", "x": _b64u(n.x.to_bytes(32, "big")), "y": _b64u(n.y.to_bytes(32, "big"))}
        iv = os.urandom(12)
        ct = key.encrypt(iv, json.dumps({"fn": fn, "event": event}).encode(), b"blit/v1/svc-req/" + rid.encode())
        status, out = self._relay("svc_call", id=rid, instance=instance, epk=epk, iv=_b64u(iv), ct=_b64u(ct))
        if status == 409:
            raise LookupError("replaced")
        out = self._wait(rid, status, out, 15 * 60)
        return json.loads(key.decrypt(_b64d(out["iv"]), _b64d(out["ct"]), b"blit/v1/svc-resp/" + rid.encode()))

    def __call__(self, fn, raw):
        sent = json.loads(raw)
        body = dict(sent["body"], projectId=self.project, projectKey=_b64u(self.key))
        event = {"resource": "/" + fn, "httpMethod": "POST", "body": json.dumps(body)}
        for attempt in (0, 1):
            try:
                return self._call(fn, event)
            except LookupError:                # the service machine was replaced: verify the new one
                with self.lock:
                    self.session = None
        raise RuntimeError("the processing service keeps being replaced")


def run_optimizer(ticket, instance, key, pool, plan, broker, project_files, stop):
    """The optimizer (compute optimizer.py) and its headless app, together in
    the sandbox with no key, no sign-in and no network. Its iterations are
    planned and dispatched here (broker.dispatch); its app's mesh requests
    are made to the processing service from here (broker.service)."""
    def dispatch():
        jobs = plan()
        log(f"iteration: {len(jobs)} job(s)")
        pool.dispatch(jobs)
        return True
    broker.dispatch = dispatch
    broker.service = ProcessingService(ticket, instance, key)
    broker.service_functions = ProcessingService.FUNCTIONS
    args = shlex.join(["--username", ticket["user"], "--prefix", ticket["prefix"], "--sandboxed"])
    tmp_n = []
    rc = _sandboxed(f"cd {COMPUTE}; PLAYWRIGHT_BROWSERS_PATH=/root/.cache/ms-playwright PERF_ROLE=optimizer "
                    f"python3 optimizer.py {args} > /tmp/optimizer.log 2>&1", stop,
                    setup=lambda tmp: (tmp_n.append(tmp.rsplit("/", 1)[1]), fetch_site(tmp + "/.site")))
    log(f"optimizer: exit {rc}")
    # For the project's own user, encrypted: why a run went wrong, if it did.
    notes = {"exit": rc, "refused": sorted(broker.refused_names)}
    if rc != 0 or notes["refused"]:
        try:
            fd = os.open(f"/run/blit-jobs/{tmp_n[-1]}/optimizer.log", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as f:
                notes["log"] = f.read(1 << 20)[-20000:].decode("utf-8", "replace")
        except OSError:
            pass
        project_files.put_object(Bucket=BUCKET, Key=ticket["prefix"] + "v1/results/sandbox_notes.json", Body=json.dumps(notes))
    _wait_master_and_local(pool, stop)
    pool.end()
    return 0


def warm_up(instance):
    """A warm-pool machine's first boot (the run Lambda's attested pool): no
    run, no key, no project. Read the whole root volume, so EBS fetches its
    blocks from the snapshot now rather than during a run, check the GPU with
    one small engine case, then mark this machine ready; the image powers it
    off and the instance stops. A run starting it later boots it afresh:
    the TPM resets, and the image measures that run's commit and attests as
    on any first boot (the root is read-only and verity-checked; nothing
    written now survives the stop)."""
    import glob
    vols = [d for d in glob.glob("/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_*") if "-part" not in d]
    t0 = time.time()
    for dev in vols:
        fd = os.open(dev, os.O_RDONLY)
        try:
            size = os.lseek(fd, 0, os.SEEK_END)
            chunk, streams = 4 << 20, 8          # parallel reads hydrate faster
            def read(i):
                for off in range(i * chunk, size, streams * chunk):
                    os.pread(fd, chunk, off)
            threads = [threading.Thread(target=read, args=(i,)) for i in range(streams)]
            [t.start() for t in threads]
            [t.join() for t in threads]
        finally:
            os.close(fd)
        log(f"read {dev} ({size >> 30} GB) in {time.time() - t0:.0f} s")
    os.makedirs(os.path.dirname(BROKER_SOCK), mode=0o700, exist_ok=True)
    open(BROKER_SOCK, "a").close()   # no broker: the check reads and writes nothing outside
    rc = _sandboxed("cd /tmp && timeout 300 python3 /home/ubuntu/openEMS-Project/openEMS/python/Tests/CUDA_Engine.py pml"
                    " >/dev/null 2>&1", threading.Event())
    if rc != 0:
        log(f"GPU check failed ({rc}); not ready")
        return 1
    boto3.client("ec2", region_name="us-east-1").create_tags(
        Resources=[instance], Tags=[{"Key": "PoolState", "Value": "ready"}])
    log("warm, ready")
    return 0


IDLE_S = 10 * 60   # = the run Lambda's IDLE_AFTER_RUN: how long a machine waits for its user's next run
RUN_FILES = ["/run/blit/user_data", "/run/blit/nonce", "/run/blit/doc.cbor"]
RUN_DIRS = ["/run/blit-jobs"]


def _instance_clients():
    """S3 and EC2 with the instance role's own credentials (not a run's), and
    this machine's ARN: to read its next ticket and mark it idle, between runs."""
    req = urllib.request.Request(f"{run_creds.IMDS}/api/token", method="PUT",
                                 headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"})
    with urllib.request.urlopen(req, timeout=5) as r:
        token = r.read().decode()
    doc = json.loads(run_creds._imds("dynamic/instance-identity/document", token))
    role = run_creds._imds("meta-data/iam/security-credentials/", token).split()[0]
    c = json.loads(run_creds._imds(f"meta-data/iam/security-credentials/{role}", token))
    kw = dict(region_name="us-east-1", aws_access_key_id=c["AccessKeyId"],
              aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["Token"])
    arn = f"arn:aws:ec2:{doc['region']}:{doc['accountId']}:instance/{doc['instanceId']}"
    return boto3.client("s3", **kw), boto3.client("ec2", **kw), arn


def _wipe():
    """Between runs: nothing of the last one stays. Its process (holding the
    key and everything it decrypted) has exited; this removes what it left in
    RAM-backed files and the jobs' scratch, and any process it left behind."""
    import shutil
    subprocess.run(["pkill", "-9", "-f", "engine.py|optimizer.py|attested/forward.py"], check=False)
    for f in RUN_FILES:
        try:
            os.remove(f)
        except OSError:
            pass
    for d in RUN_DIRS:
        shutil.rmtree(d, ignore_errors=True)


def _next_ticket(instance, last_run):
    """Wait, marked idle, for the run Lambda to hand this machine its next run
    (only ever one of the same project, of the commit measured at boot); the
    ticket's bytes, or None once IDLE_S passes. Idle is the time it went idle,
    and 0 again the moment a run arrives: the Lambda hands runs only to
    machines idle by that tag, and drops an idle machine's run credentials."""
    s3, ec2, arn = _instance_clients()

    def mark(v):
        ec2.create_tags(Resources=[instance], Tags=[{"Key": "Idle", "Value": str(v)}])

    def pending():
        try:
            # The one ticket this machine's role may read: its own, at its ARN.
            body = s3.get_object(Bucket=BUCKET, Key=f"attested/tickets/{arn}")["Body"].read()
            return body if json.loads(body).get("run") != last_run else None
        except Exception:
            return None

    body = pending()   # handed one already (a standby taken while it booted)
    if body is None:
        mark(int(time.time()))
        log("idle")
        deadline, renew = time.time() + IDLE_S, time.time() + 240
        while body is None and time.time() < deadline:
            time.sleep(1)
            if time.time() > renew:   # instance-role credentials last hours; refresh well inside them
                s3, ec2, arn = _instance_clients()
                renew = time.time() + 240
            body = pending()
    if body is not None:
        mark(0)
    return body


def main():
    """One machine, one user: the boot's run, then -- each in a fresh process,
    with the files of the one before wiped -- any next runs of the same user the
    run Lambda hands it while it waits idle. A "standby" ticket (a machine
    started ahead of a run) has no run: it goes straight to waiting."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--ticket", required=True)
    ap.add_argument("--instance", required=True)
    ap.add_argument("--one", action="store_true", help="run this ticket's run and exit")
    a = ap.parse_args()
    if a.one:
        return run_once(a)
    ticket = json.loads(open(a.ticket, "rb").read())
    if ticket.get("role") == "warmup":
        return warm_up(a.instance)
    commit = ticket["commit"]   # the one the image measured into CODE_PCR at boot
    while True:
        if ticket.get("role") != "standby":
            rc = subprocess.run([sys.executable, os.path.abspath(__file__), "--one",
                                 "--ticket", a.ticket, "--instance", a.instance]).returncode
            log(f"run {ticket['run']}: exit {rc}")
        _wipe()
        if ticket.get("role") == "rekey":
            return 0   # it held every key of a workspace: never kept for another run
        nxt = _next_ticket(a.instance, ticket["run"])
        if nxt is None:
            log("no next run")
            return 0
        ticket = json.loads(nxt)
        if ticket.get("commit") != commit:
            log("the next run is for another commit")
            return 0
        fd = os.open(a.ticket, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(nxt)


def run_once(a):
    ticket_bytes = open(a.ticket, "rb").read()
    ticket = json.loads(ticket_bytes)
    base = f"attested/{ticket['run']}/{a.instance}/"

    priv = attest(ticket_bytes, ticket, base)
    key, extra = receive(priv, ticket, base)
    del priv
    if ticket.get("role") == "rekey":
        peer_jobs = extra
        if not peer_jobs:
            log("no keys (none arrived in time)")
            return 1
        from attested.rekey import rekey_projects
        progress = lambda c: S3.put_object(Bucket=BUCKET, Key=f"attested/{ticket['run']}/progress.json",
                                           Body=json.dumps(c).encode())
        counts = rekey_projects(S3, BUCKET, ticket["prefix"], peer_jobs, progress)
        log(f"re-key done: {counts}")
        return 0 if not counts["failed"] else 2
    if key is None:
        log("no key (stopped, or none arrived in time)")
        return 1

    stop = threading.Event()
    from attested.broker import DELETABLE, DELETABLE_SERVICE, WRITABLE, WRITABLE_OPTIMIZER, Broker
    project_s3 = wrap_s3(S3, ticket["prefix"], key)
    broker = Broker(BROKER_SOCK, S3, project_s3, BUCKET, ticket["prefix"],
                    writable=WRITABLE_OPTIMIZER if ticket.get("role") == "optimizer" else WRITABLE,
                    deletable=DELETABLE_SERVICE if ticket.get("role") == "optimizer" else DELETABLE)

    def watch():
        while not stop.is_set():
            if _exists(f"attested/{ticket['run']}/stop"):
                stop.set()
            time.sleep(10)
    threading.Thread(target=watch, daemon=True).start()

    def run_lane(lane):
        for case, port in lane:
            if stop.is_set():
                break
            run_job(ticket, case, port, stop)

    try:
        role = ticket.get("role")
        if role == "peer":
            peer_lanes(ticket, a.instance, extra, stop, run_lane)
            return 0
        pool = PeerPool(ticket, a.instance, key, stop, run_lane)
        if role == "optimizer":
            return run_optimizer(ticket, a.instance, key, pool, lambda: plan_jobs(ticket, broker, project_s3, stop), broker, project_s3, stop)
        jobs = plan_jobs(ticket, broker, project_s3, stop)
        log(f"{len(jobs)} job(s)")
        pool.dispatch(jobs)
        # The master waits for every job, so when it ends the run is done.
        _wait_master_and_local(pool, stop)
        pool.end()
    finally:
        broker.stop()
        log(f"broker refused {broker.refused} request(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""The attested processing service: the model-processing functions
(generate_mesh, classify_mesh, step2stl, project2step, recompute_elements,
predict) for end-to-end projects, on an attested machine instead of Lambda,
because they read and write the model in plain.

The machine runs the very images those Lambdas run -- pulled by the digests
of the ticket's manifest, which the image measured into MANIFEST_PCR before
pulling -- each in a sandbox of its own per project (sandboxes.py). This
process is part of the measured image; it holds the project keys and never
gives one to a function. It proves itself to the browser and carries requests:

  hello  {"t": "hello", "id", "nonce"}: an attestation document answering the
         browser's nonce, binding this process's P-256 key (user_data).
  call   {"t": "call", "id", "epk", "iv", "ct"}: sealed to that key
         (ECDH-ES: HKDF-SHA256, salt the ephemeral key, info
         "blit/v1/svc/" + id; AES-GCM, AAD "blit/v1/svc-req/" + id) as
         {"fn", "event"}; the reply {"statusCode", "body"} sealed under the
         same key (AAD "blit/v1/svc-resp/" + id).

  ai     the AI assistant's requests for zero-knowledge projects (ai.py).

Requests arrive through an SQS queue and answers leave through S3
(attested-svc/out/<id>.json), both via the run Lambda's relay, which sees
only ciphertext. Nothing a function says is kept: their logs are discarded.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import boto3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from blitcrypto import key_from_b64  # noqa: E402
from blitcrypto.attest import _point_from_jwk, new_instance_key  # noqa: E402
import ai  # noqa: E402
from attested.sandboxes import Sandboxes  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

BUCKET = "blitai-dev-bucket"
REGION = "us-east-1"
_ID_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-")
_RESOURCE = re.compile(r"^/[a-z0-9_]{1,64}$")
_NAME = re.compile(r"^[A-Za-z0-9-]{1,128}$")


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def attest(priv_spki, nonce, manifest_hash):
    """An attestation document binding our key to the manifest we measured."""
    user_data = json.dumps({"v": 1, "role": "service", "spki": _b64u(priv_spki), "manifest": manifest_hash},
                           separators=(",", ":")).encode()
    with open("/run/blit/user_data", "wb") as f:
        f.write(user_data)
    with open("/run/blit/nonce", "wb") as f:
        f.write(nonce)
    return subprocess.run(["nitro-tpm-attest", "-u", "/run/blit/user_data", "-n", "/run/blit/nonce"],
                          check=True, stdout=subprocess.PIPE, timeout=60).stdout


def session_key(priv, epk_jwk, rid):
    epk = _point_from_jwk(epk_jwk)
    raw = epk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=raw,
                info=b"blit/v1/svc/" + rid.encode()).derive(priv.exchange(ec.ECDH(), epk))


def project_access(ddb, username, project_id):
    """(the project's folder, the caller's role), or PermissionError."""
    if not (isinstance(username, str) and _NAME.match(username) and isinstance(project_id, str) and _NAME.match(project_id)):
        raise PermissionError("invalid request")
    p = ddb.Table("blit-projects").get_item(Key={"projectId": project_id}).get("Item")
    if not p:
        raise PermissionError("no such project")
    for table, k in (("blit-members", {"wsId": p["wsId"], "userId": username}),
                     ("blit-project-shares", {"projectId": project_id, "userId": username})):
        row = ddb.Table(table).get_item(Key=k).get("Item")
        if row and row.get("role") in ("owner", "editor", "viewer"):
            return f"ws/{p['wsId']}/projects/{project_id}/", row["role"]
    raise PermissionError("no access to this project")


def call(boxes, ddb, fn, sent, claims):
    """One function call: take the key out of the request and run the function
    in its project's sandbox."""
    if fn not in boxes.functions:
        return {"statusCode": 404, "body": json.dumps({"error": f"no function {fn}"})}
    resource, body_s = sent.get("resource"), sent.get("body")
    if not (isinstance(resource, str) and _RESOURCE.match(resource) and isinstance(body_s, str)):
        raise ValueError("bad event")
    body = json.loads(body_s)
    key = key_from_b64(body.pop("projectKey"))
    try:
        root, role = project_access(ddb, claims.get("cognito:username"), body.get("projectId"))
    except PermissionError as e:
        return {"statusCode": 403, "body": json.dumps({"error": str(e)})}
    event = {"resource": resource, "httpMethod": "POST", "body": json.dumps(body),
             "requestContext": {"authorizer": {"claims": claims}}}
    return boxes.call(fn, root, role, key, event)


def main():
    queue = os.environ["BLIT_SVC_QUEUE"]
    functions = json.loads(os.environ["BLIT_SVC_FUNCTIONS"])   # {fn: {"image", "command"}}
    manifest_hash = os.environ["BLIT_SVC_MANIFEST_SHA384"]
    priv, spki = new_instance_key()
    sqs, s3 = boto3.client("sqs", region_name=REGION), boto3.client("s3", region_name=REGION)
    ai_threads = ThreadPoolExecutor(max_workers=8)          # AI assistant replies (ai.py)
    boxes, ddb = Sandboxes(functions, s3, BUCKET), boto3.resource("dynamodb", region_name=REGION)
    s3.put_object(Bucket=BUCKET, Key=f"attested-svc/ready/{os.environ.get('BLIT_SVC_INSTANCE', 'unknown')}.json",
                  Body=json.dumps({"t": int(time.time()), "functions": sorted(functions)}).encode())
    log(f"serving {sorted(functions)}")
    while True:
        msgs = sqs.receive_message(QueueUrl=queue, MaxNumberOfMessages=10, WaitTimeSeconds=20,
                                   VisibilityTimeout=900).get("Messages", [])
        for m in msgs:
            sqs.delete_message(QueueUrl=queue, ReceiptHandle=m["ReceiptHandle"])
            try:
                req = json.loads(m["Body"])
                rid = str(req["id"])
            except Exception:
                continue
            if not rid or len(rid) > 64 or set(rid) - _ID_OK:
                continue
            try:
                if req["t"] == "ai":
                    # A reply streams for minutes: on its own thread, so the
                    # functions keep serving meanwhile (ai.py writes it).
                    ai_threads.submit(ai.handle, s3, session_key(priv, req["epk"], rid), req)
                    continue
                if req["t"] == "hello":
                    out = {"doc": base64.b64encode(attest(spki, _unb64u(req["nonce"]), manifest_hash)).decode()}
                elif req["t"] == "call":
                    key = session_key(priv, req["epk"], rid)
                    body = json.loads(AESGCM(key).decrypt(_unb64u(req["iv"]), _unb64u(req["ct"]),
                                                          b"blit/v1/svc-req/" + rid.encode()))
                    # Who is asking is the relay's (Cognito-verified) word, as the
                    # Lambda's authorizer would put it.
                    reply = call(boxes, ddb, body["fn"], body["event"], req.get("claims") or {})
                    iv = os.urandom(12)
                    out = {"iv": _b64u(iv), "ct": _b64u(AESGCM(key).encrypt(
                        iv, json.dumps(reply).encode(), b"blit/v1/svc-resp/" + rid.encode()))}
                else:
                    continue
            except Exception as e:
                out = {"error": type(e).__name__}
            s3.put_object(Bucket=BUCKET, Key=f"attested-svc/out/{rid}.json", Body=json.dumps(out).encode())


if __name__ == "__main__":
    main()

"""Re-key projects, on an attested worker: every file of each project is
re-encrypted from its old project key to a new one that Blit never saw.

Turning a standard workspace end-to-end deletes blit.ai's copy of its key,
but the keys stay recoverable from earlier copies (backups), and so do the
project keys sealed under them. So the browser makes a new workspace key and
new project keys, verifies this worker, seals it each project's old and new
key, and once every file is re-encrypted commits the new keys (sealed under
the new workspace key) to the workspace in one call.

Only the encryption layer changes: a compressed file (BLITENCZ) keeps its
gzip payload and its marker, and each file keeps its path-bound AAD.
"""
import json
import time
from concurrent.futures import ThreadPoolExecutor

from blitcrypto import MAGIC, MAGIC_Z, NONCE_BYTES, _aad, _aesgcm, is_encrypted
import os


def rekey_blob(old, new, blob, path):
    """`blob` re-encrypted under `new`; None if it already is (or is plain)."""
    if not is_encrypted(blob):
        return None
    magic = bytes(blob[:len(MAGIC)])
    compressed = magic == MAGIC_Z
    aad = _aad(path, compressed)
    nonce, body = bytes(blob[len(MAGIC):len(MAGIC) + NONCE_BYTES]), bytes(blob[len(MAGIC) + NONCE_BYTES:])
    try:
        inner = _aesgcm()(old).decrypt(nonce, body, aad)
    except Exception:
        _aesgcm()(new).decrypt(nonce, body, aad)  # already re-keyed (a resumed run); raises if neither
        return None
    n = os.urandom(NONCE_BYTES)
    return magic + n + _aesgcm()(new).encrypt(n, inner, aad)


def rekey_projects(s3, bucket, prefix, projects, progress, workers=16):
    """projects: {projectId: (old key, new key)}; prefix: the workspace's
    projects folder. progress(dict) is called with counts only."""
    keys = []
    for pid in projects:
        root = f"{prefix}{pid}/"
        token = None
        while True:
            kw = {"Bucket": bucket, "Prefix": root}
            if token:
                kw["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kw)
            keys += [(pid, root, o["Key"]) for o in resp.get("Contents", [])]
            if not resp.get("IsTruncated"):
                break
            token = resp["NextContinuationToken"]
    counts = {"total": len(keys), "rekeyed": 0, "unchanged": 0, "failed": 0}
    progress(dict(counts))

    def one(item):
        pid, root, key = item
        old, new = projects[pid]
        try:
            obj = s3.get_object(Bucket=bucket, Key=key)
            out = rekey_blob(old, new, obj["Body"].read(), key[len(root):])
            if out is None:
                return "unchanged"
            s3.put_object(Bucket=bucket, Key=key, Body=out,
                          **({"ContentType": obj["ContentType"]} if obj.get("ContentType") else {}))
            return "rekeyed"
        except Exception:
            return "failed"

    last = time.time()
    with ThreadPoolExecutor(workers) as pool:
        for result in pool.map(one, keys):
            counts[result] += 1
            if time.time() - last > 5:
                progress(dict(counts))
                last = time.time()
    progress(dict(counts, done=True))
    return counts

"""End-to-end encryption of project files (format BLITENC1).

Project files are encrypted in the browser with the project's data key, a
random AES-256 key that Blit never stores: it lives only wrapped (encrypted)
for each member, and the browser hands it to a Lambda or a worker for the
duration of one request or run. This module is the server-side half: the file
envelope. Key wrapping (user key pairs, workspace keys) happens in the
browser -- see web/src/services/crypto -- and the two must stay byte-for-byte
compatible (tests/test_blitcrypto.py has vectors produced by the browser code).

Envelope:  b"BLITENC1" | 12-byte nonce | AES-256-GCM ciphertext | 16-byte tag
AAD:       b"blit/v1/" + the file's path relative to the project root
           (e.g. "case.json", "v1/results/results.json"), so a file can't be
           swapped for another one of the same project unnoticed.

Compressed variant: b"BLITENCZ" | nonce | AES-256-GCM(gzip(content)) | tag,
with AAD b"blit/v1z/" + path. The browser writes it for large JSON files
(case.json is ~150 MB for a 2,000-patch array; encrypted data can't be
compressed afterwards). decrypt() returns the content either way.

Anything that doesn't start with a magic is treated as plaintext: projects
written before encryption (and the migration window) keep working.
"""
import base64
import os

MAGIC = b"BLITENC1"
MAGIC_Z = b"BLITENCZ"  # gzip inside
NONCE_BYTES = 12
KEY_BYTES = 32


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:  # workers: same install-on-first-use as rtree
        import subprocess, sys
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "cryptography"], check=True)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM


def _aad(path, compressed=False):
    return (b"blit/v1z/" if compressed else b"blit/v1/") + path.lstrip("/").encode("utf-8")


def key_from_b64(value):
    """A project key as sent by the browser (base64url, 32 bytes)."""
    if value is None:
        return None
    s = str(value).strip()
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if len(raw) != KEY_BYTES:
        raise ValueError("project key must be 32 bytes")
    return raw


def is_encrypted(blob):
    return isinstance(blob, (bytes, bytearray)) and bytes(blob[:len(MAGIC)]) in (MAGIC, MAGIC_Z)


def encrypt(key, data, path, compress=False):
    """Encrypt `data` (bytes or str) for `path`; with no key, returns it
    unchanged. `compress` gzips it first (format BLITENCZ)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if key is None:
        return data
    nonce = os.urandom(NONCE_BYTES)
    if compress:
        import gzip
        return MAGIC_Z + nonce + _aesgcm()(key).encrypt(nonce, gzip.compress(bytes(data), 6), _aad(path, True))
    return MAGIC + nonce + _aesgcm()(key).encrypt(nonce, bytes(data), _aad(path))


def decrypt(key, blob, path):
    """Decrypt a file read from S3. Plaintext (no magic) is returned as is;
    an encrypted file without the key, or with the wrong one, raises."""
    if not is_encrypted(blob):
        return bytes(blob)
    if key is None:
        raise PermissionError(f"{path} is encrypted and no project key was provided")
    compressed = bytes(blob[:len(MAGIC)]) == MAGIC_Z
    nonce = bytes(blob[len(MAGIC):len(MAGIC) + NONCE_BYTES])
    plain = _aesgcm()(key).decrypt(nonce, bytes(blob[len(MAGIC) + NONCE_BYTES:]), _aad(path, compressed))
    if compressed:
        import gzip
        return gzip.decompress(plain)
    return plain


class _Body:
    """Stand-in for a botocore StreamingBody over bytes already read."""

    def __init__(self, data):
        import io
        self._io = io.BytesIO(data)

    def read(self, amt=None):
        return self._io.read() if amt is None else self._io.read(amt)

    def iter_chunks(self, chunk_size=1024 * 1024):
        while True:
            chunk = self._io.read(chunk_size)
            if not chunk:
                return
            yield chunk

    def close(self):
        pass


def _as_bytes(body):
    if body is None:
        return b""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    return body.read()


class EncryptingS3:
    """A boto3 S3 client that encrypts what it writes under one project's
    folder and decrypts what it reads from there, keyed by the path relative
    to that folder. Everything else (other keys, listings, deletes, heads)
    passes straight through. With key=None it IS the plain client: every
    call is forwarded unchanged.
    """

    def __init__(self, client, root, key, require_key=False):
        self._c = client
        self._root = root if root.endswith("/") else root + "/"
        self._key = key
        # A workspace project is always encrypted: without its key, reading
        # an encrypted file raises a clear error and writing is refused, so
        # nothing is ever stored in plaintext there by mistake.
        self._require = require_key

    def __getattr__(self, name):
        return getattr(self._c, name)

    def _rel(self, key):
        if self._key is not None and isinstance(key, str) and key.startswith(self._root):
            return key[len(self._root):]
        return None

    def _guarded(self, key):
        """Under the folder of a project that needs a key we don't have."""
        return (self._key is None and self._require and isinstance(key, str) and key.startswith(self._root))

    def _refuse_write(self, key):
        if self._guarded(key):
            raise PermissionError(f"{key[len(self._root):]}: this project is encrypted; the project key is required")

    def get_object(self, **kw):
        resp = self._c.get_object(**kw)
        if self._guarded(kw.get("Key")):
            data = resp["Body"].read()
            if is_encrypted(data):
                raise PermissionError(f"{kw['Key'][len(self._root):]} is encrypted; the project key is required")
            resp["Body"] = _Body(data)
            return resp
        rel = self._rel(kw.get("Key"))
        if rel is not None:
            data = decrypt(self._key, resp["Body"].read(), rel)
            resp["Body"] = _Body(data)
            resp["ContentLength"] = len(data)
        return resp

    def put_object(self, **kw):
        self._refuse_write(kw.get("Key"))
        rel = self._rel(kw.get("Key"))
        if rel is not None:
            kw["Body"] = encrypt(self._key, _as_bytes(kw.get("Body")), rel)
            kw.pop("ContentMD5", None)
        return self._c.put_object(**kw)

    def upload_file(self, Filename, Bucket, Key, ExtraArgs=None, Callback=None, Config=None):
        self._refuse_write(Key)
        rel = self._rel(Key)
        if rel is None:
            return self._c.upload_file(Filename, Bucket, Key, ExtraArgs=ExtraArgs, Callback=Callback, Config=Config)
        with open(Filename, "rb") as f:
            data = f.read()
        self._c.put_object(Bucket=Bucket, Key=Key, Body=encrypt(self._key, data, rel), **(ExtraArgs or {}))

    def upload_fileobj(self, Fileobj, Bucket, Key, ExtraArgs=None, Callback=None, Config=None):
        self._refuse_write(Key)
        rel = self._rel(Key)
        if rel is None:
            return self._c.upload_fileobj(Fileobj, Bucket, Key, ExtraArgs=ExtraArgs, Callback=Callback, Config=Config)
        self._c.put_object(Bucket=Bucket, Key=Key, Body=encrypt(self._key, Fileobj.read(), rel), **(ExtraArgs or {}))

    def _fetch(self, Bucket, Key, Config):
        # The ciphertext still comes down through the transfer manager (ranged
        # parts in parallel when Config asks for it), then is decrypted.
        import io
        buf = io.BytesIO()
        self._c.download_fileobj(Bucket, Key, buf, Config=Config)
        return buf.getvalue()

    def download_file(self, Bucket, Key, Filename, ExtraArgs=None, Callback=None, Config=None):
        rel = self._rel(Key)
        if self._guarded(Key):
            data = self._fetch(Bucket, Key, Config)
            if is_encrypted(data):
                raise PermissionError(f"{Key[len(self._root):]} is encrypted; the project key is required")
            with open(Filename, "wb") as f:
                f.write(data)
            return
        if rel is None:
            return self._c.download_file(Bucket, Key, Filename, ExtraArgs=ExtraArgs, Callback=Callback, Config=Config)
        data = decrypt(self._key, self._fetch(Bucket, Key, Config), rel)
        with open(Filename, "wb") as f:
            f.write(data)

    def download_fileobj(self, Bucket, Key, Fileobj, ExtraArgs=None, Callback=None, Config=None):
        rel = self._rel(Key)
        if self._guarded(Key):
            data = self._fetch(Bucket, Key, Config)
            if is_encrypted(data):
                raise PermissionError(f"{Key[len(self._root):]} is encrypted; the project key is required")
            Fileobj.write(data)
            return
        if rel is None:
            return self._c.download_fileobj(Bucket, Key, Fileobj, ExtraArgs=ExtraArgs, Callback=Callback, Config=Config)
        Fileobj.write(decrypt(self._key, self._fetch(Bucket, Key, Config), rel))

    def copy_object(self, **kw):
        self._refuse_write(kw.get("Key"))
        # The path is bound into each file's encryption, so a copy within the
        # project is decrypted and re-encrypted for its new path.
        src = kw.get("CopySource")
        src_key = src.get("Key") if isinstance(src, dict) else str(src).split("/", 1)[-1]
        src_bucket = src.get("Bucket") if isinstance(src, dict) else str(src).split("/", 1)[0]
        rel_dst, rel_src = self._rel(kw.get("Key")), self._rel(src_key)
        if rel_dst is None and rel_src is None:
            return self._c.copy_object(**kw)
        data = self._c.get_object(Bucket=src_bucket, Key=src_key)["Body"].read()
        if rel_src is not None:
            data = decrypt(self._key, data, rel_src)
        if rel_dst is not None:
            data = encrypt(self._key, data, rel_dst)
        return self._c.put_object(Bucket=kw["Bucket"], Key=kw["Key"], Body=data)


def read_key_file(path):
    """The project key a run was started with (see run_simulation's init
    script: fetched from Parameter Store into a root-only tmpfs file)."""
    if not path:
        return None
    with open(path) as f:
        return key_from_b64(f.read())


def wrap_s3(client, root, key, require_key=False):
    """The client for one project: EncryptingS3 when there is a key or the
    project requires one, otherwise the plain client itself."""
    if key is None and not require_key:
        return client
    return EncryptingS3(client, root, key, require_key=require_key)

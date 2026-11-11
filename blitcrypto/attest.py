"""Attested workers: verify a peer's NitroTPM attestation document, and hand a
project key to a verified instance.

The browser does the same with web/src/services/crypto/attestation.ts (verify)
and crypto/index.ts wrapForInstance (wrap); the two sides must agree byte for
byte -- tests/test_attest.py checks this side against a real document and
against a key the browser wrapped.

Verification: the document is a COSE_Sign1 (CBOR) signed with ES384 by a
certificate chaining to the AWS Nitro root, pinned here by its DER bytes; its
PCRs say which image booted (PCR4) and which compute commit runs (CODE_PCR),
its user_data is the instance's own P-256 public key and its nonce answers
our challenge. Anything not understood is rejected.

Wrapping (ECDH-ES): an ephemeral P-256 key agrees with the recipient's; HKDF-
SHA256 (salt: the ephemeral public key, uncompressed; info: "blit/v1/wrap/" +
label) gives an AES-256-GCM key that seals the secret with `label` as AAD.
"""
import base64
import datetime
import hashlib
import json
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# CN=aws.nitro-enclaves; SHA-256 641A0321...8F79BB5B, as AWS publishes it.
NITRO_ROOT_G1 = base64.b64decode(
    "MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoG"
    "A1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQG"
    "EwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuB"
    "BAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ"
    "3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0P"
    "AQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi"
    "85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y="
)
NITRO_ROOT_SHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

# The PCR a worker extends, once, with the compute commit it fetched.
CODE_PCR = 14
# The PCR a worker extends, once, with the dm-verity root hash of the engine
# root it mounted (none on the processing service, so zero there).
ENGINE_PCR = 15


class AttestationError(Exception):
    pass


def _fail(msg):
    raise AttestationError(msg)


# ------------------------------------------------------------------ CBOR

_BREAK = object()


def _cbor_decode(data):
    data = bytes(data)
    pos = [0]

    def byte():
        if pos[0] >= len(data):
            _fail("CBOR: truncated")
        pos[0] += 1
        return data[pos[0] - 1]

    def arg(info):
        if info < 24:
            return info
        n = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
        if n is None:
            _fail("CBOR: indefinite or reserved length")
        if pos[0] + n > len(data):
            _fail("CBOR: truncated")
        v = int.from_bytes(data[pos[0]:pos[0] + n], "big")
        pos[0] += n
        return v

    def take(n):
        if pos[0] + n > len(data):
            _fail("CBOR: truncated")
        pos[0] += n
        return data[pos[0] - n:pos[0]]

    def item(depth):
        if depth > 16:
            _fail("CBOR: nested too deep")
        ib = byte()
        major, info = ib >> 5, ib & 31
        if major == 0:
            return arg(info)
        if major == 1:
            return -1 - arg(info)
        if major == 2:
            return take(arg(info))
        if major == 3:
            return take(arg(info)).decode("utf-8")
        if major in (4, 5):
            # The Nitro hypervisor writes the payload as an indefinite map.
            n = None if info == 31 else arg(info)
            out = [] if major == 4 else {}
            i = 0
            while n is None or i < n:
                if n is None and data[pos[0]:pos[0] + 1] == b"\xff":
                    pos[0] += 1
                    break
                if major == 4:
                    out.append(item(depth + 1))
                else:
                    k = item(depth + 1)
                    if not isinstance(k, (int, str)):
                        _fail("CBOR: unsupported map key")
                    if k in out:
                        _fail("CBOR: duplicate map key")
                    out[k] = item(depth + 1)
                i += 1
            return out
        if major == 6:
            return ("tag", arg(info), item(depth + 1))
        if info == 20:
            return False
        if info == 21:
            return True
        if info == 22:
            return None
        _fail("CBOR: unsupported simple value")

    out = item(0)
    if pos[0] != len(data):
        _fail("CBOR: trailing bytes")
    return out


def _cbor_head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([(major << 5) | info]) + n.to_bytes(size, "big")


def _sig_structure(protected, payload):
    ctx = b"Signature1"
    return (_cbor_head(4, 4) + _cbor_head(3, len(ctx)) + ctx + _cbor_head(2, len(protected)) + protected
            + _cbor_head(2, 0) + _cbor_head(2, len(payload)) + payload)


# ------------------------------------------------------------------ verify

def code_pcr(commit):
    """CODE_PCR on a worker that fetched `commit` (one SHA-384 extend of zeros)."""
    if not (isinstance(commit, str) and len(commit) == 40 and all(c in "0123456789abcdef" for c in commit)):
        _fail("attestation: not a commit id")
    digest = hashlib.sha384(("blit/compute/v1:" + commit).encode()).digest()
    return hashlib.sha384(b"\0" * 48 + digest).hexdigest()


def engine_pcr(root_hash):
    """ENGINE_PCR on a worker that mounted the engine root with this dm-verity
    root hash (one SHA-384 extend of zeros)."""
    if not (isinstance(root_hash, str) and len(root_hash) == 64 and all(c in "0123456789abcdef" for c in root_hash)):
        _fail("attestation: not an engine root hash")
    digest = hashlib.sha384(("blit/engine/v1:" + root_hash).encode()).digest()
    return hashlib.sha384(b"\0" * 48 + digest).hexdigest()


def _verify_cert(cert, issuer):
    key = issuer.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        _fail("attestation: issuer key is not EC")
    try:
        key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    except InvalidSignature:
        _fail("attestation: certificate signature invalid")


def _is_ca(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def verify_attestation(doc, pcrs, nonce=None, max_age_s=None, now=None):
    """Verify a NitroTPM attestation document. `pcrs`: {index: expected hex},
    at least one. Returns the document's fields (user_data is the instance's
    public key, DER SubjectPublicKeyInfo)."""
    if not pcrs:
        _fail("attestation: no expected PCRs given")
    now = now or datetime.datetime.utcnow()

    top = _cbor_decode(doc)
    if isinstance(top, tuple):
        if top[1] != 18:
            _fail("COSE: unexpected tag")
        top = top[2]
    if not isinstance(top, list) or len(top) != 4:
        _fail("COSE: not a COSE_Sign1")
    protected, _unprotected, payload, signature = top
    if not all(isinstance(x, bytes) for x in (protected, payload, signature)):
        _fail("COSE: bad COSE_Sign1")
    ph = _cbor_decode(protected)
    if not isinstance(ph, dict) or ph.get(1) != -35:
        _fail("COSE: algorithm is not ES384")

    body = _cbor_decode(payload)
    if not isinstance(body, dict):
        _fail("attestation: payload is not a map")
    for k in ("module_id", "timestamp", "digest", "nitrotpm_pcrs", "certificate", "cabundle"):
        if k not in body:
            _fail("attestation: missing " + k)
    if body["digest"] != "SHA384" or not isinstance(body["timestamp"], int) or not isinstance(body["module_id"], str):
        _fail("attestation: bad header fields")
    bundle = body["cabundle"]
    if not isinstance(bundle, list) or not bundle or not all(isinstance(c, bytes) for c in bundle):
        _fail("attestation: bad CA bundle")
    if bundle[0] != NITRO_ROOT_G1:
        _fail("attestation: CA bundle does not start at the AWS Nitro root")

    chain = [body["certificate"]] + list(reversed(bundle[1:])) + [NITRO_ROOT_G1]
    certs = [x509.load_der_x509_certificate(c) for c in chain]
    for i, c in enumerate(certs):
        if not (c.not_valid_before <= now <= c.not_valid_after):
            _fail("attestation: certificate %d outside its validity period" % i)
        if i == len(certs) - 1:
            break
        issuer = certs[i + 1]
        if not _is_ca(issuer):
            _fail("attestation: certificate %d is not a CA" % (i + 1))
        if c.issuer.public_bytes() != issuer.subject.public_bytes():
            _fail("attestation: certificate %d not issued by the next" % i)
        _verify_cert(c, issuer)

    leaf_key = certs[0].public_key()
    if not isinstance(leaf_key, ec.EllipticCurvePublicKey) or leaf_key.curve.name != "secp384r1":
        _fail("COSE: signing key is not P-384")
    if len(signature) != 96:
        _fail("COSE: bad signature length")
    der = encode_dss_signature(int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big"))
    try:
        leaf_key.verify(der, _sig_structure(protected, payload), ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        _fail("attestation: document signature invalid")

    got = {}
    for k, v in body["nitrotpm_pcrs"].items():
        if not isinstance(k, int) or not isinstance(v, bytes):
            _fail("attestation: bad PCR entry")
        got[k] = v.hex()
    for k, want in pcrs.items():
        if got.get(int(k)) != want.lower():
            _fail("attestation: PCR%s does not match the expected image" % k)
    if nonce is not None and body.get("nonce") != nonce:
        _fail("attestation: nonce does not match")
    if max_age_s is not None:
        # Both naive UTC (as the certificates' validity is): .timestamp()
        # would read `now` as local time.
        age = (now - datetime.datetime.utcfromtimestamp(body["timestamp"] / 1000.0)).total_seconds()
        if age > max_age_s or age < -60:
            _fail("attestation: document too old")
    return {
        "module_id": body["module_id"],
        "timestamp": body["timestamp"],
        "pcrs": got,
        "user_data": body.get("user_data"),
        "public_key": body.get("public_key"),
        "nonce": body.get("nonce"),
    }


# ------------------------------------------------------------------ key handoff

def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _shared_key(private_key, peer_public, epk_raw, label):
    bits = private_key.exchange(ec.ECDH(), peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk_raw,
                info=b"blit/v1/wrap/" + label.encode()).derive(bits)


def _point_from_jwk(jwk):
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        _fail("wrap: not a P-256 key")
    return ec.EllipticCurvePublicNumbers(int.from_bytes(_unb64u(jwk["x"]), "big"),
                                         int.from_bytes(_unb64u(jwk["y"]), "big"),
                                         ec.SECP256R1()).public_key()


def new_instance_key():
    """A P-256 key pair for this instance: (private key, DER SPKI to attest)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, spki


def unwrap(private_key, wrapped, label):
    """Open {"epk": JWK, "iv", "ct"} sealed to this instance's key."""
    epk = _point_from_jwk(wrapped["epk"])
    epk_raw = epk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key = _shared_key(private_key, epk, epk_raw, label)
    return AESGCM(key).decrypt(_unb64u(wrapped["iv"]), _unb64u(wrapped["ct"]), label.encode())


def wrap_for_instance(spki_der, secret, label):
    """Seal `secret` to an attested instance's public key (DER SPKI)."""
    peer = serialization.load_der_public_key(spki_der)
    if not isinstance(peer, ec.EllipticCurvePublicKey) or peer.curve.name != "secp256r1":
        _fail("wrap: recipient is not a P-256 key")
    eph = ec.generate_private_key(ec.SECP256R1())
    epk = eph.public_key()
    epk_raw = epk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key = _shared_key(eph, peer, epk_raw, label)
    iv = os.urandom(12)
    n = epk.public_numbers()
    return {
        "epk": {"kty": "EC", "crv": "P-256", "x": _b64u(n.x.to_bytes(32, "big")), "y": _b64u(n.y.to_bytes(32, "big"))},
        "iv": _b64u(iv),
        "ct": _b64u(AESGCM(key).encrypt(iv, secret, label.encode())),
    }


if hashlib.sha256(NITRO_ROOT_G1).hexdigest() != NITRO_ROOT_SHA256:  # a mistyped pin fails loudly
    raise RuntimeError("blitcrypto.attest: pinned Nitro root does not match its fingerprint")

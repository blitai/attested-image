"""The AI assistant for zero-knowledge projects, on the attested processing
service (service.py): what the assistant is told about a project -- the
model, its history, attachments -- is decrypted only here, sent on to the
model provider over TLS, and the reply comes back sealed. The relay (the
claude-proxy Lambda) carries ciphertext and counts tokens, nothing more.

  ai  {"t": "ai", "id", "epk", "key", "claims", "allow"}: the request,
      sealed as for a function call (ECDH-ES to this process's key, info
      "blit/v1/svc/" + id; AES-GCM, AAD "blit/v1/ai-req/" + id) and left by
      the browser at `key` in its own S3 folder. It is the claude-proxy body
      the browser would otherwise send in plain: type "chat" (streamed),
      "thinking_steps" (one JSON reply) or "upload_file" (filename,
      mediaType, data: base64 -> {"file_id"}).

The reply is written as numbered chunks, attested-svc/ai/<id>/<n>.json, each
sealed under the request's key (AAD "blit/v1/ai-resp/<id>/<n>"): for a chat,
the server-sent events the proxy would have streamed; otherwise one JSON
body. Then end.json, in plain, says how many chunks there were, the HTTP
status and the tokens used (for the daily limit). The browser checks the
count, so a dropped chunk shows. A cancel file (attested-svc/ai/<id>/cancel)
stops a reply part way.
"""
import base64
import hashlib
import http.client
import json
import os
import ssl
import time
import uuid

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Where this machine's files live: from the instance's launch settings (blit-worker-boot).
BUCKET = os.environ["BLIT_BUCKET"]
REGION = "us-east-1"
API_HOST = "api.anthropic.com"
API_VERSION = "2023-06-01"
FILES_BETA = "files-api-2025-04-14"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
KEY_SECRET = os.environ["BLIT_AI_KEY_SECRET"]  # the model provider's API key, by name
# As the proxy: the models and server tools the frontend uses, unless the
# relay passes its (environment-configured) lists.
DEFAULT_MODELS = ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1"]
DEFAULT_SERVER_TOOLS = ["code_execution_20260120"]
MAX_TOKENS_CAP = 65536
MAX_TOOLS = 128
MAX_UPLOAD_BYTES = 32 * 1024 * 1024
FILE_OWNERSHIP_SINCE = "2026-10-13T16:00:00Z"
CHUNK_SECONDS = 0.25          # how long events gather before a chunk is written
CHUNK_BYTES = 256 * 1024
THINKING_CAP_BYTES = 18 * 1024 * 1024

_api_key = None
_owner_cache = {}


def _key():
    global _api_key
    if _api_key is None:
        _api_key = boto3.client("secretsmanager", region_name=REGION).get_secret_value(
            SecretId=KEY_SECRET)["SecretString"].strip()
    return _api_key


def _tls():
    """Verified TLS with the CA bundle boto3 itself uses on this machine."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        import botocore
        bundled = os.path.join(os.path.dirname(botocore.__file__), "cacert.pem")
        return ssl.create_default_context(cafile=bundled) if os.path.exists(bundled) else ssl.create_default_context()


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _request(method, path, body=None, headers=None, stream=False, timeout=600):
    conn = http.client.HTTPSConnection(API_HOST, timeout=timeout, context=_tls())
    h = {"x-api-key": _key(), "anthropic-version": API_VERSION}
    h.update(headers or {})
    conn.request(method, path, body=body, headers=h)
    resp = conn.getresponse()
    if resp.status >= 400:
        raw = resp.read()
        conn.close()
        try:
            msg = json.loads(raw).get("error", {}).get("message") or f"HTTP {resp.status}"
        except Exception:
            msg = f"HTTP {resp.status}"
        raise ApiError(resp.status, msg)
    if stream:
        return conn, resp
    out = json.loads(resp.read() or b"null")
    conn.close()
    return out


# ------------------------------------------------------------------ files

def owner_tag(user):
    return "u" + hashlib.sha256(user.encode()).hexdigest()[:16]


def _file_owner(file_id):
    """The owner tag in a file's name ("" for files from before tagging, "?"
    for untagged later ones), or None if the file is gone."""
    if file_id in _owner_cache:
        return _owner_cache[file_id]
    try:
        meta = _request("GET", f"/v1/files/{file_id}", headers={"anthropic-beta": FILES_BETA}, timeout=30)
    except ApiError as e:
        if e.status == 404:
            return None
        raise
    name = meta.get("filename") or ""
    if len(name) > 19 and name[0] == "u" and name[17:19] == "__":
        owner = name[:17]
    else:
        owner = "" if (meta.get("created_at") or "") < FILE_OWNERSHIP_SINCE else "?"
    _owner_cache[file_id] = owner
    return owner


def _referenced_files(node, out):
    if isinstance(node, list):
        for n in node:
            _referenced_files(n, out)
    elif isinstance(node, dict):
        if node.get("type") == "file" and isinstance(node.get("file_id"), str):
            out.add(node["file_id"])
        for v in node.values():
            _referenced_files(v, out)
    return out


def _assert_owns(file_ids, user):
    tag = owner_tag(user)
    for fid in file_ids:
        owner = _file_owner(fid)
        if owner not in (None, "", tag):
            raise ApiError(400, "a referenced file does not belong to this user")


def upload_file(body, user):
    raw = str(body.get("data") or "").replace("-", "+").replace("_", "/")   # either alphabet
    data = base64.b64decode(raw + "=" * (-len(raw) % 4))
    name = str(body.get("filename") or "file")[:200]
    if not data:
        raise ApiError(400, "Invalid upload request: no data")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ApiError(413, f"File too large: {len(data) / 1024 / 1024:.1f} MB exceeds the 32 MB limit")
    media = str(body.get("mediaType") or "application/octet-stream")[:100]
    boundary = uuid.uuid4().hex
    filename = f"{owner_tag(user)}__{name}".replace('"', "_").replace("\r", "_").replace("\n", "_")
    payload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
               f"Content-Type: {media}\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    out = _request("POST", "/v1/files", body=payload, timeout=300, headers={
        "anthropic-beta": FILES_BETA, "content-type": f"multipart/form-data; boundary={boundary}"})
    return {"file_id": out["id"]}


# ------------------------------------------------------------------ messages

def _system_field(sp):
    if isinstance(sp, str):
        return [{"type": "text", "text": sp, "cache_control": {"type": "ephemeral"}}]
    blocks = [{"type": "text", "text": sp["static"], "cache_control": {"type": "ephemeral"}}]
    if sp.get("dynamic"):
        blocks.append({"type": "text", "text": sp["dynamic"]})
    return blocks


def _validate(body, allow):
    if body.get("type") not in ("chat", "thinking_steps"):
        raise ApiError(400, "Invalid type: must be 'chat' or 'thinking_steps'")
    if not isinstance(body.get("messages"), list) or not body["messages"]:
        raise ApiError(400, "messages must be a non-empty array")
    sp = body.get("systemPrompt")
    if not sp or not (isinstance(sp, str) or (isinstance(sp, dict) and isinstance(sp.get("static"), str) and sp["static"])):
        raise ApiError(400, "systemPrompt must be a string or { static, dynamic? }")
    model = body.get("model") or "claude-opus-5-5"
    if model not in (allow.get("models") or DEFAULT_MODELS):
        raise ApiError(400, f"Model not allowed: {str(model)[:64]}")
    tools = body.get("tools")
    if tools is not None:
        if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
            raise ApiError(400, f"tools must be an array of at most {MAX_TOOLS} entries")
        for t in tools:
            kind = t.get("type") if isinstance(t, dict) else None
            if kind not in (None, "custom") and kind not in (allow.get("serverTools") or DEFAULT_SERVER_TOOLS):
                raise ApiError(400, f"Tool type not allowed: {str(kind)[:64]}")
    return model


def _uses_classifiers(model):
    return model.startswith(("claude-fable-", "claude-mythos-", "claude-opus-5", "claude-sonnet-5-5"))


def _params(body, model, stream):
    """The Messages API request, built as the proxy builds it."""
    p = {"model": model, "max_tokens": min(int(body.get("max_tokens") or MAX_TOKENS_CAP), MAX_TOKENS_CAP),
         "messages": body["messages"]}
    if stream:
        p["stream"] = True
        p["system"] = _system_field(body["systemPrompt"])
    else:
        sp = body["systemPrompt"]
        p["system"] = sp if isinstance(sp, str) else "\n".join(s for s in (sp["static"], sp.get("dynamic") or "") if s)
    if body.get("thinking"):
        p["thinking"] = body["thinking"]
        if stream and body["thinking"].get("type") == "enabled":
            p["temperature"] = 1
    elif body.get("temperature") is not None:
        p["temperature"] = body["temperature"]
    for k in ("output_config", "tool_choice"):
        if body.get(k):
            p[k] = body[k]
    if body.get("tools"):
        p["tools"] = body["tools"]
    betas = [FILES_BETA]
    if stream and _uses_classifiers(model):
        p["fallbacks"] = "default"
        betas.append(FALLBACK_BETA)
    return p, betas


def weighted_tokens(usage):
    if not usage:
        return 0
    return (usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
            + usage.get("cache_creation_input_tokens", 0) + -(-usage.get("cache_read_input_tokens", 0) // 10))


# ------------------------------------------------------------------ reply

class Reply:
    """Writes a reply as sealed, numbered chunks, then end.json."""

    def __init__(self, s3, key, rid):
        self.s3, self.aes, self.rid, self.n = s3, AESGCM(key), rid, 0
        self.prefix = f"attested-svc/ai/{rid}/"

    def chunk(self, data: bytes):
        iv = os.urandom(12)
        ct = self.aes.encrypt(iv, data, f"blit/v1/ai-resp/{self.rid}/{self.n}".encode())
        self.s3.put_object(Bucket=BUCKET, Key=f"{self.prefix}{self.n:06d}.json",
                           Body=json.dumps({"iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
                                            "ct": base64.urlsafe_b64encode(ct).decode().rstrip("=")}).encode())
        self.n += 1

    def end(self, status, tokens):
        self.s3.put_object(Bucket=BUCKET, Key=f"{self.prefix}end.json",
                           Body=json.dumps({"chunks": self.n, "status": status, "tokens": int(tokens)}).encode())

    def cancelled(self):
        try:
            self.s3.head_object(Bucket=BUCKET, Key=f"{self.prefix}cancel")
            return True
        except Exception:
            return False


def _stream_chat(body, model, reply):
    """Streams the reply's events into chunks; the usage."""
    params, betas = _params(body, model, stream=True)
    conn, resp = _request("POST", "/v1/messages", body=json.dumps(params).encode(), stream=True,
                          headers={"content-type": "application/json", "anthropic-beta": ",".join(betas)})
    usage, buf, last, sent, capped, failed = {}, [], time.time(), 0, False, None
    last_cancel_check = time.time()
    try:
        for raw in resp:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            kind = ev.get("type")
            if kind == "error":
                failed = (ev.get("error") or {}).get("message") or "the model provider failed"
            if kind == "message_start":
                usage = dict((ev.get("message") or {}).get("usage") or {})
            elif kind == "message_delta" and ev.get("usage"):
                usage.update(ev["usage"])
            thinking = kind == "content_block_delta" and (ev.get("delta") or {}).get("type") == "thinking_delta"
            frame = f"data: {data}\n\n"
            if thinking and (capped or sent + len(frame) > THINKING_CAP_BYTES):
                capped = True          # as the proxy: past the cap, thinking is dropped
                continue
            buf.append(frame)
            sent += len(frame)
            now = time.time()
            if now - last >= CHUNK_SECONDS or sum(map(len, buf)) >= CHUNK_BYTES:
                reply.chunk("".join(buf).encode())
                buf, last = [], now
            if now - last_cancel_check >= 2:
                last_cancel_check = now
                if reply.cancelled():
                    if buf:
                        reply.chunk("".join(buf).encode())
                    return usage, False
        if failed:
            if buf:
                reply.chunk("".join(buf).encode())
            raise ApiError(502, failed)
        buf.append("data: [DONE]\n\n")
        reply.chunk("".join(buf).encode())
        return usage, True
    finally:
        conn.close()


def handle(s3, key, req):
    """Serve one sealed AI request (key: the request's AES key)."""
    rid = req["id"]
    reply = Reply(s3, key, rid)
    user = (req.get("claims") or {}).get("cognito:username") or ""
    allow = req.get("allow") or {}
    tokens, status = 0, 200
    try:
        src = req.get("key") or ""
        if not (src.startswith("public/") and src.endswith(f"/ai-in/{rid}.json")):
            raise ApiError(400, "bad request location")
        blob = json.loads(s3.get_object(Bucket=BUCKET, Key=src)["Body"].read())
        s3.delete_object(Bucket=BUCKET, Key=src)
        un = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        body = json.loads(AESGCM(key).decrypt(un(blob["iv"]), un(blob["ct"]), f"blit/v1/ai-req/{rid}".encode()))
        if body.get("type") == "upload_file":
            reply.chunk(json.dumps(upload_file(body, user)).encode())
        else:
            model = _validate(body, allow)
            _assert_owns(_referenced_files(body["messages"], set()), user)
            if body["type"] == "chat":
                usage, _ = _stream_chat(body, model, reply)
            else:
                params, betas = _params(body, model, stream=False)
                out = _request("POST", "/v1/messages", body=json.dumps(params).encode(),
                               headers={"content-type": "application/json", "anthropic-beta": ",".join(betas)})
                usage = out.get("usage") or {}
                reply.chunk(json.dumps(out).encode())
            tokens = weighted_tokens(usage)
    except ApiError as e:
        status = e.status
        reply.chunk(json.dumps({"error": str(e)}).encode())
    except Exception as e:
        status = 500
        reply.chunk(json.dumps({"error": f"the assistant failed ({type(e).__name__})"}).encode())
    reply.end(status, tokens)


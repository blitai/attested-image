"""The one way a sandboxed job reaches the project's files.

A job runs with no network and no project key. Its S3 client talks to this
server through a unix socket; the server speaks the part of the S3 protocol
the engine uses, holds the key, encrypts what the job writes and decrypts what
it reads, and refuses anything outside the run's project folder. Nonces are
chosen here, so the job has no say over the ciphertext.
"""
import datetime
import email.utils
import http.server
import json
import os
import re
import socketserver
import threading
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from collections import OrderedDict
from xml.sax.saxutils import escape

from botocore.exceptions import ClientError

from blitcrypto import MAGIC, MAGIC_Z, NONCE_BYTES

XMLNS = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'
OVERHEAD = len(MAGIC) + NONCE_BYTES + 16   # what the envelope adds to a file
CACHE_BYTES = 2 << 30                      # decrypted files kept for ranged reads
PASSED_HEADERS = {"Content-Type": "ContentType", "Cache-Control": "CacheControl",
                  "Content-Disposition": "ContentDisposition", "Content-Encoding": "ContentEncoding"}


_FREQ = r"\(\d+(?:\.\d+)? [kKMGT]?Hz\)"
_PORT = r"(?: \[[\w(),]{1,24}\])?"
_TAG = r"(?: \[#\d+\])?"   # an optimizer candidate
_FILE = "|".join((
    rf"Farfield \w{{1,40}}(?: \| (?:Theta|Phi) Cut)? {_FREQ}{_PORT}{_TAG}\.(?:vtp|json)",
    rf"model Farfield {_FREQ}{_PORT}{_TAG}\.csv",
    rf"Model{_TAG}\.stl",
    rf"(?:E|H|RotH)-Field (?:{_FREQ}|\(Time\)){_PORT}{_TAG}(?: \(Surface\))?\.vtkjs",
    r"(?:eta_rad_[\w(),]{1,24}|plane_wave_scattering)_[\d.e+]{1,24}\.json",
    r"(?:Ef|Hf|RotHf)_[\w(),]{1,24}_\d+\.npz",
    r"model\.s\d+p",
))
_FOLDER = r"(?:farfield|farfield_raw|farfield_meta|cuts_2d|field_meta|(?:e|h|roth)_field(?:_td)?)"
# What a job may create, relative to the project folder. Object names are plain
# in storage, so nothing in them may come from the model.
WRITABLE = re.compile(
    r"info\.json|v\d+/results/(?:"
    r"results\.json|manifest\.json|partial/case_\d+\.json"
    r"|perf/(?:compute|stream)_cfg\d+_excite[\w(),]{1,24}_pid\d+\.json"
    r"|port_modes/(?:ports\.json|port_\w{1,24}_mode_\d+_[EH]\.csv)"
    r"|model\.(?:csv|pdf)"
    rf"|(?:runs/run_\d+/)?(?:{_FOLDER}/)?(?:{_FILE})"
    r")")
DELETABLE = re.compile(r"v\d+/results/.+", re.S)
# The processing functions: the mesh and imported-model files they make, and
# beam results beside a run's own.
WRITABLE_SERVICE = re.compile(WRITABLE.pattern + "|" + "|".join((
    r"tmp/(?:model\.json|model\.step|geometry\.json|mesh_simulation\.json|stl\.json|export\.step)",
    r"v\d+/mesh\.json",
    rf"v\d+/results/(?:runs/run_\d+/)?{_FOLDER}/(?:E|H|RotH)-Field {_FREQ} \[Beam\d+\](?: \(Surface\))?\.vtkjs",
)))
# An optimization: the optimizer's own files, and what its headless app writes.
WRITABLE_OPTIMIZER = re.compile(WRITABLE.pattern + "|" + "|".join((
    r"history\.json|case\.json|v\d+/properties\.json|v\d+/mesh\.json",
    r"tmp/(?:geometry\.json|mesh_simulation\.json)",
    r"v\d+/results/perf/optimizer_pid\d+\.json",
    r"v\d+/results/screenshots/\d+\.jpg",
)))
DELETABLE_SERVICE = re.compile(DELETABLE.pattern + r"|tmp/.+", re.S)
PLAN_OBJECT = ".plan"          # how the planner hands its job list back
DISPATCH_OBJECT = ".dispatch"  # how an optimizer asks for its next iteration
SERVICE_BODY_BYTES = 200_000
PLAN_BYTES = 64 << 20


class Refused(Exception):
    pass


class _Plaintexts:
    """Whole decrypted files, for reads a transfer splits into ranges; each is
    fetched once however many parts ask for it at the same time."""

    def __init__(self):
        self.lock, self.files, self.busy = threading.Lock(), OrderedDict(), {}

    def get(self, key, etag, fetch):
        with self.lock:
            lock = self.busy.setdefault((key, etag), threading.Lock())
        with lock:
            with self.lock:
                if (key, etag) in self.files:
                    self.files.move_to_end((key, etag))
                    return self.files[(key, etag)]
            data = fetch()
            with self.lock:
                self.files[(key, etag)] = data
                while len(self.files) > 1 and sum(len(v) for v in self.files.values()) > CACHE_BYTES:
                    self.files.popitem(last=False)
            return data

    def clear(self):
        with self.lock:
            self.files.clear()
            self.busy.clear()


def _http_date(d):
    return email.utils.format_datetime(d.astimezone(datetime.timezone.utc), usegmt=True)


def _iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _contents(items):
    return "".join(
        f"<Contents><Key>{escape(o['Key'])}</Key><LastModified>{_iso(o['LastModified'])}</LastModified>"
        f"<ETag>{escape(o['ETag'])}</ETag><Size>{o['Size']}</Size><StorageClass>STANDARD</StorageClass></Contents>"
        for o in items)


def _common(items):
    return "".join(f"<CommonPrefixes><Prefix>{escape(p['Prefix'])}</Prefix></CommonPrefixes>" for p in items)


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):   # never the names of a project's files
        pass

    def address_string(self):
        return "job"

    # -- replies

    def _send(self, status, body=b"", headers=None, include_body=True):
        self.send_response(status)
        headers = dict(headers or {})
        headers.setdefault("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if include_body and body:
            self.wfile.write(body)

    def _xml(self, text, status=200):
        self._send(status, ('<?xml version="1.0" encoding="UTF-8"?>' + text).encode(), {"Content-Type": "application/xml"})

    def _error(self, status, code):
        self._xml(f"<Error><Code>{escape(code)}</Code><Message>{escape(code)}</Message></Error>", status)

    # -- the request

    def _parse(self):
        self._read_body = False   # one connection carries many requests
        self.server.broker.last_active = time.time()
        url = urllib.parse.urlsplit(self.path)
        bucket, _, key = url.path.lstrip("/").partition("/")
        self.bucket, self.key = bucket, urllib.parse.unquote(key)
        self.query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}

    def _body(self):
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def _allow(self, op, key):
        b = self.server.broker
        ok = self.bucket == b.bucket and isinstance(key, str) and key.startswith(b.prefix) and ".." not in key.split("/")
        if b.audit:
            b.audit(op, key, ok)
        if not ok:
            b.refused += 1
            raise Refused()

    def _allow_name(self, pattern, op, key):
        b = self.server.broker
        self._allow(op, key)
        name = key[len(b.prefix):]
        if b.read_only or not getattr(b, pattern).fullmatch(name):
            b.refused += 1
            if len(b.refused_names) < 200:
                b.refused_names.add(name[:300])   # returned only to the project's user, sealed
            raise Refused()

    def _dispatch(self, method):
        self._parse()
        try:
            method()
        except Refused:
            self._body_drain()
            self._error(403, "AccessDenied")
        except ClientError as e:
            r = e.response
            self._error(r["ResponseMetadata"]["HTTPStatusCode"], r.get("Error", {}).get("Code", "InternalError"))
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as e:
            print(f"broker: {type(e).__name__}", flush=True)
            self._error(500, "InternalError")

    def _body_drain(self):
        if self.command in ("PUT", "POST") and not self._read_body:
            self._body()

    def do_GET(self):
        self._dispatch(lambda: self._get() if self.key else self._get_list())

    def do_HEAD(self):
        self._dispatch(self._head)

    def do_PUT(self):
        self._dispatch(self._put)

    def do_DELETE(self):
        self._dispatch(self._delete)

    def do_POST(self):
        self._dispatch(self._post)

    # -- objects

    def _head(self):
        b = self.server.broker
        self._allow("head", self.key)
        raw = b.s3.head_object(Bucket=b.bucket, Key=self.key)
        size = b.plain_size(self.key, raw)
        self._send(200, headers={"Content-Length": str(size), "ETag": raw["ETag"],
                                 "Last-Modified": _http_date(raw["LastModified"]),
                                 "Content-Type": raw.get("ContentType", "binary/octet-stream"),
                                 "Accept-Ranges": "bytes"}, include_body=False)

    def _get(self):
        b = self.server.broker
        self._allow("get", self.key)
        rng = self.headers.get("Range")
        if rng:
            etag = b.s3.head_object(Bucket=b.bucket, Key=self.key)["ETag"]
            data = b.plain(self.key, etag)
            first, last = _span(rng, len(data))
            part = data[first:last + 1]
            return self._send(206, part, {"ETag": etag, "Content-Type": "binary/octet-stream",
                                          "Content-Range": f"bytes {first}-{last}/{len(data)}"})
        r = b.files.get_object(Bucket=b.bucket, Key=self.key)
        self._send(200, r["Body"].read(), {"ETag": r["ETag"], "Content-Type": r.get("ContentType", "binary/octet-stream"),
                                           "Last-Modified": _http_date(r["LastModified"])})

    def _extra(self):
        return {arg: self.headers[h] for h, arg in PASSED_HEADERS.items() if self.headers.get(h)}

    def _put(self):
        b = self.server.broker
        if self.key == b.prefix + PLAN_OBJECT and b.planning:   # the planner's answer: never leaves this machine
            b.plan = self._body()[:PLAN_BYTES + 1]
            self._read_body = True
            return self._send(200, headers={"ETag": '"plan"'})
        if self.key == b.prefix + DISPATCH_OBJECT and b.dispatch:   # an optimizer's next iteration
            self._body()
            self._read_body = True
            return self._send(200 if b.dispatch() else 500)
        if self.key == b.prefix + "case.json" and b.planning:
            self._allow("put", self.key)
        else:
            self._allow_name("writable", "put", self.key)
        source = self.headers.get("x-amz-copy-source")
        if source:
            src_bucket, _, src_key = urllib.parse.unquote(source).lstrip("/").partition("/")
            self._allow("copy", src_key)
            if src_bucket != b.bucket:
                raise Refused()
            r = b.files.copy_object(Bucket=b.bucket, Key=self.key, CopySource={"Bucket": src_bucket, "Key": src_key})
            b.changed()
            return self._xml(f"<CopyObjectResult {XMLNS}><ETag>{escape(r['ETag'])}</ETag>"
                             f"<LastModified>{_iso(_now())}</LastModified></CopyObjectResult>")
        body = self._body()
        self._read_body = True
        upload = self.query.get("uploadId")
        if upload:
            b.parts(upload)["parts"][int(self.query["partNumber"])] = body
            return self._send(200, headers={"ETag": f'"{uuid.uuid4().hex}"'})
        r = b.files.put_object(Bucket=b.bucket, Key=self.key, Body=body, **self._extra())
        b.changed()
        self._send(200, headers={"ETag": r["ETag"]})

    def _delete(self):
        b = self.server.broker
        self._allow_name("deletable", "delete", self.key)
        upload = self.query.get("uploadId")
        if upload:
            b.uploads.pop(upload, None)
        else:
            b.s3.delete_object(Bucket=b.bucket, Key=self.key)
            b.changed()
        self._send(204)

    def _post(self):
        b = self.server.broker
        if self.bucket == "__svc":   # a processing function, for an optimization's headless app
            body = self._body()
            self._read_body = True
            if not b.service or self.key not in b.service_functions or len(body) > SERVICE_BODY_BYTES:
                raise Refused()
            return self._send(200, json.dumps(b.service(self.key, body)).encode(), {"Content-Type": "application/json"})
        if "delete" in self.query:
            return self._delete_many()
        self._allow_name("writable", "put", self.key)
        if "uploads" in self.query:
            upload = uuid.uuid4().hex
            b.uploads[upload] = {"parts": {}, "extra": self._extra()}
            self._body()
            self._read_body = True
            return self._xml(f"<InitiateMultipartUploadResult {XMLNS}><Bucket>{escape(b.bucket)}</Bucket>"
                             f"<Key>{escape(self.key)}</Key><UploadId>{upload}</UploadId></InitiateMultipartUploadResult>")
        self._body()
        self._read_body = True
        job = b.uploads.pop(self.query["uploadId"])
        data = b"".join(job["parts"][n] for n in sorted(job["parts"]))
        r = b.files.put_object(Bucket=b.bucket, Key=self.key, Body=data, **job["extra"])
        b.changed()
        self._xml(f"<CompleteMultipartUploadResult {XMLNS}><Bucket>{escape(b.bucket)}</Bucket><Key>{escape(self.key)}</Key>"
                  f"<ETag>{escape(r['ETag'])}</ETag></CompleteMultipartUploadResult>")

    def _delete_many(self):
        b = self.server.broker
        root = ET.fromstring(self._body())
        self._read_body = True
        keys = [e.text for e in root.iter() if e.tag.endswith("}Key") or e.tag == "Key"]
        for key in keys:
            self._allow_name("deletable", "delete", key)
        if keys:
            b.s3.delete_objects(Bucket=b.bucket, Delete={"Objects": [{"Key": k} for k in keys]})
            b.changed()
        done = "".join(f"<Deleted><Key>{escape(k)}</Key></Deleted>" for k in keys)
        self._xml(f"<DeleteResult {XMLNS}>{done}</DeleteResult>")

    def _get_list(self):
        b = self.server.broker
        q = self.query
        self._allow("list", q.get("prefix", ""))
        kw = {"Bucket": b.bucket, "Prefix": q["prefix"]}
        for arg, name in (("Delimiter", "delimiter"), ("MaxKeys", "max-keys")):
            if q.get(name):
                kw[arg] = int(q[name]) if arg == "MaxKeys" else q[name]
        head = f"<Name>{escape(b.bucket)}</Name><Prefix>{escape(q['prefix'])}</Prefix>"
        if q.get("list-type") == "2":
            for arg, name in (("ContinuationToken", "continuation-token"), ("StartAfter", "start-after")):
                if q.get(name):
                    kw[arg] = q[name]
            r = b.s3.list_objects_v2(**kw)
            more = (f"<NextContinuationToken>{escape(r['NextContinuationToken'])}</NextContinuationToken>"
                    if r.get("NextContinuationToken") else "")
            head += f"<KeyCount>{r.get('KeyCount', 0)}</KeyCount>"
        else:
            if q.get("marker"):
                kw["Marker"] = q["marker"]
            r = b.s3.list_objects(**kw)
            more = f"<NextMarker>{escape(r['NextMarker'])}</NextMarker>" if r.get("NextMarker") else ""
        trunc = "true" if r.get("IsTruncated") else "false"
        self._xml(f"<ListBucketResult {XMLNS}>{head}<MaxKeys>{r.get('MaxKeys', 1000)}</MaxKeys><IsTruncated>{trunc}</IsTruncated>"
                  f"{more}{_contents(r.get('Contents', []))}{_common(r.get('CommonPrefixes', []))}</ListBucketResult>")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _span(header, size):
    """(first, last) of a "bytes=a-b" header, inclusive."""
    a, _, b = header.split("=", 1)[1].partition("-")
    first = int(a) if a else max(0, size - int(b))
    last = min(int(b), size - 1) if a and b else size - 1
    return first, last


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 128


class Broker:
    """Serve one run's project folder on a unix socket until stop()."""

    def __init__(self, sock, s3, files, bucket, prefix, audit=None, writable=WRITABLE, deletable=DELETABLE, read_only=False):
        self.s3, self.files, self.bucket, self.prefix, self.audit = s3, files, bucket, prefix, audit
        self.uploads, self.refused = {}, 0
        self.planning, self.plan, self.dispatch = False, None, None
        self.service, self.service_functions = None, ()
        self.writable, self.deletable, self.read_only = writable, deletable, read_only
        self.refused_names, self.last_active = set(), time.time()
        self._plain = _Plaintexts()
        os.makedirs(os.path.dirname(sock), mode=0o700, exist_ok=True)
        if os.path.exists(sock):
            os.remove(sock)
        self.sock = sock
        self.server = _Server(sock, _Handler)
        os.chmod(sock, 0o600)
        self.server.broker = self
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def parts(self, upload):
        return self.uploads[upload]

    def changed(self):
        self._plain.clear()

    def plain(self, key, etag):
        return self._plain.get(key, etag, lambda: self.files.get_object(Bucket=self.bucket, Key=key)["Body"].read())

    def plain_size(self, key, raw):
        size = raw["ContentLength"]
        if size == 0:
            return 0
        magic = self.s3.get_object(Bucket=self.bucket, Key=key, Range=f"bytes=0-{len(MAGIC) - 1}")["Body"].read()
        if magic == MAGIC:
            return size - OVERHEAD
        if magic == MAGIC_Z:
            return len(self.plain(key, raw["ETag"]))
        return size

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.uploads.clear()
        self._plain.clear()

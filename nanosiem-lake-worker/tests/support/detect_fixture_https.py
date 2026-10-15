#!/usr/bin/env python3
"""Local HTTPS control/owner/object fixture for the real detect-child test."""

import base64
import hashlib
import http.server
import json
import pathlib
import ssl
import sys
import urllib.parse
import xml.etree.ElementTree as ET
import threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

body_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
cert, key = sys.argv[3:5]
tenant = sys.argv[5]
notice_dir = root.parent / "notices"
notice_dir.mkdir(exist_ok=True)
notice_lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        if self.path not in ("/v1/lake/cells/risk-cell/credential-exchange", "/owner-sign", f"/v1/tenants/{tenant}/parsed-objects:ack"):
            self.send_error(404)
            return
        body = json.loads(body_path.read_text())
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size))
        if self.path.endswith("credential-exchange"):
            if self.headers.get("Authorization") != "Bearer fixture-bootstrap-token" or request not in (
                # Each role declares exactly the classes it consumes (NAN-2949
                # `accepts`; detect per NAN-2916: no lake_part_log).
                {"tenant_id": tenant, "role": "detect",
                 "accepts": ["lake_part_read", "lake_part", "enrichment_reader"]},
                # query also declares the optional NAN-3042 `job_results`
                # class; this fixture mints none (jobs then fail typed).
                {"tenant_id": tenant, "role": "query",
                 "accepts": ["lake_part_read", "enrichment_reader", "job_results"]},
                {"tenant_id": tenant, "role": "ingest",
                 "accepts": ["bronze_reader", "lake_part", "lake_part_log", "lake_prevalence_state", "enrichment_reader"]},
            ):
                self.send_error(403)
                return
            if request["role"] == "query":
                response = {"schema_version": 1, "tenant_id": tenant, "role": "query",
                    "credentials": [body["credentials"][0]], "trusted_keys": body["trusted_keys"],
                    "query_engine": body["query_engine"]}
            elif request["role"] == "ingest":
                response = {"schema_version": 1, "tenant_id": tenant, "role": "ingest",
                    "writer_epoch": body["writer_epoch"], "credentials": [
                        body["bronze_reader"], body["credentials"][1], body["credentials"][2]],
                    "trusted_keys": body["trusted_keys"], "owner_sign": body["owner_sign"],
                    "notices": {"url": body["notices_url"], "bearer": "fixture-notice-token"}}
            else:
                response = dict(body)
                part = dict(body["credentials"][1])
                part["prefixes"] = [prefix for prefix in part["prefixes"]
                    if not prefix.endswith("log/checkpoints/")]
                response["credentials"] = [body["credentials"][0], part]
        elif self.path.endswith("parsed-objects:ack"):
            if self.headers.get("Authorization") != "Bearer fixture-notice-token" or self.path != f"/v1/tenants/{tenant}/parsed-objects:ack":
                self.send_error(403)
                return
            ids = request.get("ids")
            if not isinstance(ids, list) or any(not isinstance(value, str) or "/" in value for value in ids):
                self.send_error(400)
                return
            with notice_lock:
                for value in ids:
                    (notice_dir / f"{value}.json").unlink(missing_ok=True)
            response = {}
        else:
            if self.headers.get("Authorization") != "Bearer fixture-owner-token" or set(request) != {
                "schema_version", "request_id", "tenant_id", "parts"
            } or request["schema_version"] != 1 or request["tenant_id"] != tenant:
                self.send_error(403)
                return
            key = Ed25519PrivateKey.from_private_bytes(bytes([37]) * 32)
            results = []
            for part in request["parts"]:
                if set(part) != {"part_id", "record_sha256", "record_base64"}:
                    self.send_error(400)
                    return
                canonical = base64.b64decode(part["record_base64"], validate=True)
                record = json.loads(canonical)
                if hashlib.sha256(canonical).hexdigest() != part["record_sha256"] or record["tenant_id"] != request["tenant_id"] or record["part_id"] != part["part_id"]:
                    self.send_error(400)
                    return
                signature = key.sign(b"nano-lake-part-provenance-v1\0" + canonical)
                results.append({"part_id": part["part_id"], "record_sha256": part["record_sha256"],
                    "signature": {"alg": "ed25519", "key_id": "fixture-owner", "sig": base64.b64encode(signature).decode()}, "error": None})
            response = {"schema_version": 1, "request_id": request["request_id"], "results": results}
        data = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_HEAD(self):
        self.object_response(False)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == f"/v1/tenants/{tenant}/parsed-objects":
            if self.headers.get("Authorization") != "Bearer fixture-notice-token":
                self.send_error(403)
                return
            limit = min(int(urllib.parse.parse_qs(parsed.query).get("limit", ["64"])[0]), 1000)
            with notice_lock:
                notices = [json.loads(path.read_text()) for path in sorted(notice_dir.glob("*.json"))[:limit]]
            data = json.dumps({"notices": notices}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if parsed.path == "/risk-fixture" and urllib.parse.parse_qs(parsed.query).get("list-type") == ["2"]:
            self.list_objects(urllib.parse.parse_qs(parsed.query))
        else:
            self.object_response(True)

    def list_objects(self, query):
        prefix = query.get("prefix", [""])[0]
        tenant_prefix = f"lake/parts/v1/tenant={tenant}/"
        if not prefix.startswith(tenant_prefix) or ".." in pathlib.PurePosixPath(prefix).parts:
            self.send_error(403)
            return
        root_element = ET.Element("ListBucketResult", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
        ET.SubElement(root_element, "Name").text = "risk-fixture"
        ET.SubElement(root_element, "Prefix").text = prefix
        files = sorted(path for path in root.rglob("*") if path.is_file()
                       and path.relative_to(root).as_posix().startswith(prefix))
        ET.SubElement(root_element, "KeyCount").text = str(len(files))
        ET.SubElement(root_element, "MaxKeys").text = "1000"
        ET.SubElement(root_element, "IsTruncated").text = "false"
        for path in files:
            item = ET.SubElement(root_element, "Contents")
            ET.SubElement(item, "Key").text = path.relative_to(root).as_posix()
            ET.SubElement(item, "LastModified").text = "2026-09-26T00:00:00.000Z"
            ET.SubElement(item, "ETag").text = '"' + hashlib.md5(path.read_bytes()).hexdigest() + '"'
            ET.SubElement(item, "Size").text = str(path.stat().st_size)
            ET.SubElement(item, "StorageClass").text = "STANDARD"
        data = ET.tostring(root_element, encoding="utf-8", xml_declaration=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if not path.startswith(f"/risk-fixture/lake/parts/v1/tenant={tenant}/") or ".." in pathlib.PurePosixPath(path).parts:
            self.send_error(403)
            return
        if self.headers.get("If-None-Match") != "*" or not self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 "):
            self.send_error(403)
            return
        size = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(size)
        digest = hashlib.sha256(data).digest()
        if (self.headers.get("x-amz-checksum-sha256") != base64.b64encode(digest).decode()
                or self.headers.get("x-amz-content-sha256") != digest.hex()):
            self.send_error(400, "BadDigest")
            return
        candidate = root / path.removeprefix("/risk-fixture/")
        candidate.parent.mkdir(parents=True, exist_ok=True)
        try:
            with candidate.open("xb") as output:
                output.write(data)
        except FileExistsError:
            self.send_response(412)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("ETag", '"' + hashlib.md5(data).hexdigest() + '"')
        self.send_header("x-amz-checksum-sha256", base64.b64encode(digest).decode())
        self.send_header("Content-Length", "0")
        self.end_headers()

    def object_response(self, send_body):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        allowed = (f"/risk-fixture/lake/parts/v1/tenant={tenant}/", f"/risk-fixture/bronze-v2/shard=0/tenant_id={tenant}/")
        if not path.startswith(allowed) or ".." in pathlib.PurePosixPath(path).parts:
            self.send_error(404)
            return
        candidate = root / path.removeprefix("/risk-fixture/")
        if not candidate.is_file():
            self.send_error(404)
            return
        data = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if send_body:
            self.wfile.write(data)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()

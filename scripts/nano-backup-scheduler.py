#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Automatic backups for compose installs (NAN-5204).

Runs in the `nano-backup` image (PostgreSQL base + python3/openssl) with NO
Docker socket and a READ-ONLY install directory:

* ``serve`` / ``run-once``: at the configured local time, (re)provision the
  dedicated `nano_backup` identities with the admin credentials from .env,
  then build a standard signed `nano-backup-v2` bundle:
  - PostgreSQL: `pg_dump -Fc` over the network as the read-only role, from
    one exported REPEATABLE READ snapshot that the signed row counts share;
  - the ClickHouse lookup-table rows (`SELECT ... FORMAT Native` as the
    SELECT-only ClickHouse user), read while that snapshot is held;
  - .env and the host identity files.
  The payload is encrypted to the recipient CERTIFICATE (no private key on
  the host) and the manifest signed with the host signing key. The bundle is
  written to a directory or uploaded to an S3-compatible bucket, the
  destination is pruned to the newest N, and the outcome is reported to
  nano-api. Failures retry with backoff until the next scheduled slot.
  `scripts/nano restore --key-file <off-host recovery key>` restores it.
* ``configure`` (install.sh, `scripts/nano backup-schedule --configure`):
  asks on a TTY or reads NANO_BACKUP_*, generates the key material (the
  recovery key is moved off the host), validates the destination with a
  write/list/delete probe, and records the answers in .env.
* ``status`` / ``list`` / ``fetch``: host-side views and downloads.

Destinations are a local or mounted directory (NFS, SMB) or an S3-compatible
bucket (AWS S3, Wasabi, RustFS or any S3-compatible store), spoken to with a
small SigV4 client. Secrets live only in the mode-0600 .env; nothing here
prints them, and the API report carries no credentials.
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import hmac
import http.client
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any, Callable, Iterable

AUTO_PREFIX = "nano-auto-"
AUTO_NAME = re.compile(r"^nano-auto-[0-9]{8}T[0-9]{6}Z(\.tar)?$")
SCHEDULE = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
REGION = re.compile(r"^[A-Za-z0-9-]{1,64}$")
PREFIX = re.compile(r"^[A-Za-z0-9!_.*'()/-]{0,256}$")
# .env values are read by docker compose, bash and Python. Refuse characters
# any of them would interpret instead of quoting them three different ways.
ENV_SAFE = re.compile(r"^[^\s'\"$`\\#]*$")
MULTIPART_THRESHOLD = 256 * 1024 * 1024
MIN_PART = 64 * 1024 * 1024
STALE_HOURS = 36
BACKOFF_MINUTES = (15, 30, 60, 120)
REPORT_URL = "http://nano-api:3000/api/internal/backup-status"


class BackupError(Exception):
    pass


def log(message: str) -> None:
    print(f"nano-backup: {message}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- .env

def read_env(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if match:
            value = match.group(2)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[match.group(1)] = value
    return values


def write_env(path: pathlib.Path, updates: dict[str, str]) -> None:
    """Replace or append assignments in place. The resolved file is rewritten
    through a 0600 temporary file, so a symlinked .env stays a link."""
    for key, value in updates.items():
        if not ENV_SAFE.fullmatch(value):
            raise BackupError(f"{key} contains whitespace, quotes, '$', '`', '\\' or '#'")
    target = path.resolve()
    lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if match and match.group(1) in updates:
            key = match.group(1)
            if key in seen:
                continue
            out.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            out.append(line)
    pending = [key for key in updates if key not in seen]
    if pending:
        out.append("")
        out.append("# Automatic backups (scripts/nano backup-schedule --configure)")
        out.extend(f"{key}={updates[key]}" for key in pending)
    fd, temp = tempfile.mkstemp(dir=str(target.parent), prefix=".env.backup.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(out) + "\n")
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    except BaseException:
        with_suppressed(lambda: os.unlink(temp))
        raise


def with_suppressed(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except OSError:
        pass


def profiles_with(current: str, profile: str, enabled: bool) -> str:
    items = [item for item in current.split(",") if item and item != profile]
    if enabled:
        items.append(profile)
    return ",".join(items)


# --------------------------------------------------------------------------- config

KEYS_DIR = ".nano-backup/keys"
RECIPIENT_CERT = f"{KEYS_DIR}/recipient.crt"
SIGNING_KEY = f"{KEYS_DIR}/signing.pem"
RECOVERY_KEY = f"{KEYS_DIR}/recovery-key.pem"
BACKUP_ROLE = "nano_backup"
# NAN-5367: the SELECT-only ClickHouse backup user never accepts connections
# from any address: loopback and private address space (the Compose, inventory
# and pod networks the scheduler runs on).
BACKUP_CH_HOSTS = ("IP '127.0.0.1', IP '::1', IP '10.0.0.0/8', IP '172.16.0.0/12', "
                   "IP '192.168.0.0/16', IP '100.64.0.0/10', IP 'fc00::/7'")
# NAN-5404: nano_backup accepts exactly the networks of the app user
# `nanosiem`, which the deployment narrows to the networks it really runs on
# (Docker pools, inventory hosts, clickhouse.allowedNetworks). The private
# ranges above are only the fallback while `nanosiem` still accepts any address
# (an install that predates NAN-5367) or cannot be read: on those, an Agent
# Lane agent on a private LAN would otherwise overlap nano_backup.
APP_CH_USER = "nanosiem"
_HOST_TOKEN_RE = re.compile(r"^[0-9A-Za-z.:/_-]{1,253}$")


def app_user_hosts(rows: list[dict[str, Any]]) -> tuple[frozenset[str], frozenset[str]] | None:
    """`(host_ip, host_names)` of APP_CH_USER from system.users rows, or None
    when it is missing, accepts any address, matches by reverse DNS, has no
    entry at all, or carries a value that is not a plain address or name."""
    app = next((r for r in rows if r.get("name") == APP_CH_USER), None)
    if app is None or app.get("host_names_regexp") or app.get("host_names_like"):
        return None
    ips = [str(v) for v in app.get("host_ip") or []]
    names = [str(v) for v in app.get("host_names") or []]
    if not (ips or names) or any(v.endswith("/0") or not _HOST_TOKEN_RE.fullmatch(v) for v in ips + names):
        return None
    return frozenset(ips), frozenset(names)


def host_clause(ips: Iterable[str], names: Iterable[str]) -> str:
    """A CREATE/ALTER USER HOST clause; `localhost` is ClickHouse's LOCAL."""
    parts = [f"IP '{ip}'" for ip in sorted(ips)]
    parts += ["LOCAL" if n == "localhost" else f"NAME '{n}'" for n in sorted(names)]
    return ", ".join(parts)
# NAN-1728: on a multi-shard cluster each shard holds the lookup rows that
# were written through it; reads go through the `_distributed` wrapper (the
# argMax dedup collapses cross-shard copies). Single node: the local table.
LOOKUP_COUNT_SQL = ("SELECT count() FROM (SELECT argMax(deleted, version) AS d FROM nanosiem.{table} "
                    "GROUP BY lookup_table_name, row_id HAVING d = 0) FORMAT TSVRaw")


class Config:
    def __init__(self, install_dir: pathlib.Path, env: dict[str, str]):
        self.install_dir = install_dir
        self.env = env
        self.enabled = env.get("NANO_BACKUP_ENABLED", "false") == "true"
        self.kind = env.get("NANO_BACKUP_DESTINATION", "")
        self.path = env.get("NANO_BACKUP_PATH", "")
        self.schedule = env.get("NANO_BACKUP_SCHEDULE", "02:00")
        self.keep = int(env.get("NANO_BACKUP_KEEP", "7") or 7)
        self.token = env.get("NANO_BACKUP_STATUS_TOKEN", "")
        self.state_dir = pathlib.Path(os.environ.get("NANO_BACKUP_STATE_DIR")
                                      or install_dir / ".nano-backup" / "state")

    def file(self, relative: str) -> pathlib.Path:
        """Key material is recorded relative to the install directory, which
        is mounted at a different path inside the container."""
        return self.install_dir / relative

    def s3(self) -> "S3":
        return S3(
            self.env.get("NANO_BACKUP_S3_ENDPOINT", ""), self.env.get("NANO_BACKUP_S3_BUCKET", ""),
            self.env.get("NANO_BACKUP_S3_REGION", "") or "us-east-1",
            self.env.get("NANO_BACKUP_S3_ACCESS_KEY", ""), self.env.get("NANO_BACKUP_S3_SECRET_KEY", ""),
            self.env.get("NANO_BACKUP_S3_PREFIX", ""),
        )

    def destination_label(self) -> str:
        if self.kind == "s3":
            s3 = self.s3()
            return f"s3://{s3.bucket}/{s3.prefix}".rstrip("/")
        return self.path


def load_config(install_dir: pathlib.Path) -> Config:
    env = read_env(install_dir / ".env")
    # The Compose project passes the operator's outbound proxy to nano's own
    # services through .env; honour it for S3 uploads too.
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"):
        if env.get(name) and not os.environ.get(name):
            os.environ[name] = env[name]
    return Config(install_dir, env)


# --------------------------------------------------------------------------- S3

class S3:
    """Minimal SigV4 client: put (single or multipart), get, delete, list."""

    def __init__(self, endpoint: str, bucket: str, region: str, access_key: str, secret_key: str, prefix: str):
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.path not in {"", "/"} \
                or parsed.query or parsed.fragment or parsed.username:
            raise BackupError("S3 endpoint must be https://host[:port] (http:// only for a private test store)")
        if not BUCKET.fullmatch(bucket):
            raise BackupError("S3 bucket name is invalid")
        if not REGION.fullmatch(region):
            raise BackupError("S3 region is invalid")
        if not PREFIX.fullmatch(prefix) or ".." in prefix.split("/"):
            raise BackupError("S3 prefix may use letters, digits and !_.*'()/- only")
        if not access_key or not secret_key:
            raise BackupError("S3 access key and secret are required")
        self.scheme, self.host, self.port = parsed.scheme, parsed.hostname, parsed.port
        self.bucket, self.region = bucket, region
        self.access_key, self.secret_key = access_key, secret_key
        self.prefix = prefix.strip("/")
        # AWS endpoints use virtual-hosted addressing; every other
        # S3-compatible store (Wasabi, RustFS, ...) accepts path style.
        self.virtual = self.host.endswith(".amazonaws.com")

    def key(self, name: str) -> str:
        return f"{self.prefix}/{name}" if self.prefix else name

    def _connection(self) -> http.client.HTTPConnection:
        host = f"{self.bucket}.{self.host}" if self.virtual else self.host
        proxy = os.environ.get("HTTPS_PROXY") if self.scheme == "https" else os.environ.get("HTTP_PROXY")
        no_proxy = [item.strip() for item in os.environ.get("NO_PROXY", "").split(",") if item.strip()]
        if proxy and not any(host == item or host.endswith("." + item.lstrip(".")) for item in no_proxy):
            proxied = urllib.parse.urlsplit(proxy)
            if self.scheme == "https":
                conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                    proxied.hostname, proxied.port or 8080, timeout=120, context=ssl.create_default_context())
                headers = {}
                if proxied.username:
                    import base64
                    raw = f"{urllib.parse.unquote(proxied.username)}:{urllib.parse.unquote(proxied.password or '')}"
                    headers["Proxy-Authorization"] = "Basic " + base64.b64encode(raw.encode()).decode()
                conn.set_tunnel(host, self.port or 443, headers=headers)
                return conn
            return http.client.HTTPConnection(proxied.hostname, proxied.port or 8080, timeout=120)
        if self.scheme == "https":
            return http.client.HTTPSConnection(host, self.port, timeout=120, context=ssl.create_default_context())
        return http.client.HTTPConnection(host, self.port, timeout=120)

    def _host_header(self) -> str:
        host = f"{self.bucket}.{self.host}" if self.virtual else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port in (None, default) else f"{host}:{self.port}"

    def _path(self, key: str) -> str:
        encoded = urllib.parse.quote(key, safe="/-_.~")
        return f"/{encoded}" if self.virtual else f"/{self.bucket}/{encoded}" if key else f"/{self.bucket}"

    def request(self, method: str, key: str, query: dict[str, str] | None = None,
                body: bytes | Any = b"", payload_hash: str | None = None,
                length: int | None = None, headers: dict[str, str] | None = None,
                stream_to: Any = None) -> tuple[int, dict[str, str], bytes]:
        query = query or {}
        now = dt.datetime.now(dt.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date = now.strftime("%Y%m%d")
        if payload_hash is None:
            payload_hash = hashlib.sha256(body if isinstance(body, bytes) else b"").hexdigest()
        path = self._path(key) if key or not self.virtual else "/"
        canonical_query = "&".join(
            f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
            for k, v in sorted(query.items())
        )
        all_headers = {"host": self._host_header(), "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
        for name, value in (headers or {}).items():
            all_headers[name.lower()] = value
        signed = ";".join(sorted(all_headers))
        canonical_headers = "".join(f"{name}:{all_headers[name].strip()}\n" for name in sorted(all_headers))
        canonical = "\n".join([method, path, canonical_query, canonical_headers, signed, payload_hash])
        scope = f"{date}/{self.region}/s3/aws4_request"
        to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
        signing = ("AWS4" + self.secret_key).encode()
        for part in (date, self.region, "s3", "aws4_request"):
            signing = hmac.new(signing, part.encode(), hashlib.sha256).digest()
        signature = hmac.new(signing, to_sign.encode(), hashlib.sha256).hexdigest()
        all_headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
        )
        if length is None:
            length = len(body) if isinstance(body, bytes) else 0
        all_headers["content-length"] = str(length)
        target = path + (f"?{canonical_query}" if canonical_query else "")
        conn = self._connection()
        try:
            conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            for name, value in all_headers.items():
                conn.putheader(name, value)
            conn.endheaders()
            if isinstance(body, bytes):
                if body:
                    conn.send(body)
            else:
                remaining = length
                while remaining > 0:
                    chunk = body.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise BackupError("upload source ended early")
                    conn.send(chunk)
                    remaining -= len(chunk)
            response = conn.getresponse()
            response_headers = {k.lower(): v for k, v in response.getheaders()}
            if stream_to is not None and response.status == 200:
                shutil.copyfileobj(response, stream_to, 1024 * 1024)
                return response.status, response_headers, b""
            return response.status, response_headers, response.read()
        except (OSError, http.client.HTTPException) as error:
            raise BackupError(f"S3 {method} failed: {type(error).__name__}: {error}") from None
        finally:
            conn.close()

    def _check(self, status: int, body: bytes, what: str, ok: Iterable[int] = (200,)) -> None:
        if status not in ok:
            code = ""
            try:
                code = ET.fromstring(body).findtext("Code") or ""
            except ET.ParseError:
                pass
            raise BackupError(f"S3 {what} failed: HTTP {status} {code}".strip())

    def put_bytes(self, name: str, data: bytes) -> None:
        status, _, body = self.request("PUT", self.key(name), body=data)
        self._check(status, body, "write")

    def delete(self, name: str) -> None:
        status, _, body = self.request("DELETE", self.key(name))
        self._check(status, body, "delete", (200, 204))

    def list(self) -> list[str]:
        names: list[str] = []
        token = ""
        prefix = f"{self.prefix}/" if self.prefix else ""
        while True:
            query = {"list-type": "2", "prefix": prefix}
            if token:
                query["continuation-token"] = token
            status, _, body = self.request("GET", "", query=query)
            self._check(status, body, "list")
            root = ET.fromstring(body)
            ns = {"s": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
            find = (lambda node, tag: node.findall(f"s:{tag}", ns)) if ns else (lambda node, tag: node.findall(tag))
            findtext = (lambda node, tag: node.findtext(f"s:{tag}", default="", namespaces=ns)) if ns \
                else (lambda node, tag: node.findtext(tag, default=""))
            for item in find(root, "Contents"):
                key = findtext(item, "Key")
                if key.startswith(prefix) and "/" not in key[len(prefix):]:
                    names.append(key[len(prefix):])
            if findtext(root, "IsTruncated") != "true":
                return names
            token = findtext(root, "NextContinuationToken")
            if not token:
                return names

    def upload_file(self, name: str, source: pathlib.Path) -> None:
        size = source.stat().st_size
        if size <= MULTIPART_THRESHOLD:
            digest = sha256_file(source)
            with source.open("rb") as handle:
                status, _, body = self.request("PUT", self.key(name), body=handle, payload_hash=digest, length=size)
            self._check(status, body, "upload")
            return
        status, _, body = self.request("POST", self.key(name), query={"uploads": ""})
        self._check(status, body, "multipart start")
        upload_id = ET.fromstring(body).findtext("{*}UploadId") or ET.fromstring(body).findtext("UploadId")
        if not upload_id:
            raise BackupError("S3 multipart start returned no UploadId")
        part_size = max(MIN_PART, -(-size // 9000))
        parts: list[tuple[int, str]] = []
        try:
            with source.open("rb") as handle:
                number, offset = 1, 0
                while offset < size:
                    length = min(part_size, size - offset)
                    handle.seek(offset)
                    digest = hashlib.sha256()
                    remaining = length
                    while remaining:
                        chunk = handle.read(min(1024 * 1024, remaining))
                        digest.update(chunk)
                        remaining -= len(chunk)
                    handle.seek(offset)
                    status, headers, body = self.request(
                        "PUT", self.key(name), query={"partNumber": str(number), "uploadId": upload_id},
                        body=handle, payload_hash=digest.hexdigest(), length=length)
                    self._check(status, body, f"upload part {number}")
                    parts.append((number, headers.get("etag", "")))
                    number += 1
                    offset += length
            manifest = "<CompleteMultipartUpload>" + "".join(
                f"<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>" for n, etag in parts
            ) + "</CompleteMultipartUpload>"
            status, _, body = self.request("POST", self.key(name), query={"uploadId": upload_id},
                                           body=manifest.encode())
            self._check(status, body, "multipart complete")
            if b"<Error>" in body:
                raise BackupError("S3 multipart complete reported an error")
        except BaseException:
            try:
                self.request("DELETE", self.key(name), query={"uploadId": upload_id})
            except BackupError:
                pass
            raise

    def download(self, name: str, destination: pathlib.Path) -> None:
        with destination.open("wb") as handle:
            status, _, body = self.request("GET", self.key(name), stream_to=handle)
        self._check(status, body, "download")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# --------------------------------------------------------------------------- destinations

def probe_destination(config: Config) -> None:
    """Write and delete a small probe; listing must work too (retention)."""
    probe = f".nano-backup-probe-{secrets.token_hex(6)}"
    if config.kind == "path":
        root = pathlib.Path(config.path)
        if not root.is_absolute():
            raise BackupError("backup path must be absolute")
        if not root.is_dir():
            raise BackupError(f"backup path does not exist or is not a directory: {root} (mount the share first)")
        target = root / probe
        try:
            target.write_bytes(b"nano backup destination probe\n")
            if target.read_bytes() != b"nano backup destination probe\n":
                raise BackupError("backup path did not read back the probe")
            target.unlink()
            list(root.iterdir())
        except OSError as error:
            with_suppressed(lambda: target.unlink())
            raise BackupError(f"backup path is not writable: {error.strerror or error}") from None
        return
    if config.kind == "s3":
        s3 = config.s3()
        s3.put_bytes(probe, b"nano backup destination probe\n")
        try:
            names = s3.list()
            if probe not in names:
                raise BackupError("S3 list did not show the probe object (check the prefix and ListBucket permission)")
        finally:
            s3.delete(probe)
        return
    raise BackupError("backup destination must be 'path' or 's3'")


MARKER_NAME = ".nano-backup-destination"
PARTIAL_PREFIX = "."  # in-flight copies: `.nano-auto-<time>.partial-<hex>`
PARTIAL_STALE_SECS = 6 * 3600


def newest_mtime(path: pathlib.Path) -> float:
    """Latest modification time anywhere under an in-flight copy."""
    newest = path.lstat().st_mtime
    for child in path.rglob("*"):
        try:
            newest = max(newest, child.lstat().st_mtime)
        except OSError:
            continue
    return newest


def write_destination_marker(root: pathlib.Path, marker_id: str) -> None:
    """Review M3: the marker proves that the directory a run writes to is
    the destination that was configured, not an empty mount point (a share
    that is not mounted, or the empty directory Docker creates for a missing
    bind-mount source)."""
    path = root / MARKER_NAME
    path.write_text(json.dumps({"format": "nano-backup-destination-v1", "id": marker_id}) + "\n")


def check_destination_marker(config: Config) -> None:
    root = pathlib.Path(config.path)
    expected = config.env.get("NANO_BACKUP_DESTINATION_ID", "")
    if not re.fullmatch(r"[0-9a-f]{32}", expected):
        raise BackupError("NANO_BACKUP_DESTINATION_ID is missing from .env; run scripts/nano backup-schedule --configure")
    try:
        found = json.loads((root / MARKER_NAME).read_text()).get("id", "")
    except (OSError, ValueError):
        found = ""
    if found != expected:
        raise BackupError(f"backup destination {root} does not carry this install's marker ({MARKER_NAME}): "
                          "is the share mounted? Nothing was written.")


def complete_bundle(path: pathlib.Path) -> bool:
    """Review M2: only a signed, complete bundle counts as a backup."""
    if path.is_symlink() or not path.is_dir():
        return False
    single = all((path / item).is_file() for item in ("manifest.json", "manifest.sig", "payload.cms"))
    role_split = all((path / "postgres" / item).is_file() for item in ("manifest.json", "manifest.sig", "payload.cms")) \
        and (path / "recovery-set" / "recovery-set.sig").is_file()
    return single or role_split


def auto_names(config: Config) -> list[str]:
    if config.kind == "path":
        root = pathlib.Path(config.path)
        return sorted(p.name for p in root.iterdir() if AUTO_NAME.fullmatch(p.name) and complete_bundle(p))
    return sorted(name for name in config.s3().list() if AUTO_NAME.fullmatch(name) and name.endswith(".tar"))


def prune(config: Config) -> list[str]:
    """Keep the newest N automatic backups. Only complete `nano-auto-*`
    bundles this scheduler wrote are ever counted; manual backups are never
    touched. Abandoned in-flight copies (`.nano-auto-*.partial-*`) idle for
    PARTIAL_STALE_SECS are removed; a younger one may belong to another app
    host writing to the same shared destination."""
    if config.kind == "path":
        # NAN-5215: on a destination shared by several app hosts another host
        # may be writing its copy right now; only a long-idle copy is abandoned.
        stale_before = time.time() - PARTIAL_STALE_SECS
        for leftover in pathlib.Path(config.path).glob(f"{PARTIAL_PREFIX}{AUTO_PREFIX}*.partial-*"):
            if leftover.is_dir() and not leftover.is_symlink() and newest_mtime(leftover) < stale_before:
                shutil.rmtree(leftover, ignore_errors=True)
                log(f"removed an incomplete copy: {leftover.name}")
    names = auto_names(config)
    doomed = names[: max(0, len(names) - config.keep)]
    for name in doomed:
        if config.kind == "path":
            shutil.rmtree(pathlib.Path(config.path) / name)
        else:
            config.s3().delete(name)
        log(f"pruned {name} (keep {config.keep})")
    return doomed


def bundle_size(path: pathlib.Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def tar_bundle(source: pathlib.Path, target: pathlib.Path) -> None:
    with tarfile.open(target, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise BackupError(f"bundle contains a symbolic link: {path}")
            archive.add(path, arcname=f"{source.name}/{path.relative_to(source)}", recursive=False)


def safe_extract(archive_path: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive_path, "r:") as archive:
        tops = set()
        for member in archive.getmembers():
            target = (root / member.name).resolve()
            if target == root or root not in target.parents:
                raise BackupError(f"unsafe archive path: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise BackupError(f"unsupported archive entry: {member.name}")
            tops.add(pathlib.PurePosixPath(member.name).parts[0])
        if len(tops) != 1:
            raise BackupError("archive must contain exactly one backup directory")
        archive.extractall(root)
    out = root / tops.pop()
    for path in [out, *out.rglob("*")]:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    return out


# --------------------------------------------------------------------------- run

class NativeReader:
    """Just enough of ClickHouse's Native format to count the live lookup
    rows of an export (review M1): the count is derived from the exported
    bytes themselves, and a truncated or malformed file fails to parse."""

    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, size: int) -> bytes:
        if self.pos + size > len(self.data):
            raise BackupError("lookup-row export is truncated")
        chunk = self.data[self.pos:self.pos + size]
        self.pos += size
        return chunk

    def varint(self) -> int:
        result = shift = 0
        while True:
            byte = self.take(1)[0]
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result
            shift += 7
            if shift > 63:
                raise BackupError("lookup-row export has a malformed length")

    def string(self) -> bytes:
        return self.take(self.varint())

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), "little")

    def column(self, kind: str, rows: int) -> list[Any]:
        widths = {"UInt8": 1, "UInt16": 2, "UInt32": 4, "UInt64": 8}
        if kind in widths:
            return [self.uint(widths[kind]) for _ in range(rows)]
        if kind == "String":
            return [self.string() for _ in range(rows)]
        if kind == "LowCardinality(String)":
            # SerializationLowCardinality, Native: version, then for the block
            # the index type with flags, the additional-keys dictionary and
            # the per-row indexes.
            if rows == 0:
                return []
            if self.uint(8) != 1:
                raise BackupError("unsupported LowCardinality serialization in the lookup-row export")
            index_type = self.uint(8)
            width = {0: 1, 1: 2, 2: 4, 3: 8}.get(index_type & 0xFF)
            if width is None or not index_type & (1 << 9):
                raise BackupError("unsupported LowCardinality index in the lookup-row export")
            keys = [self.string() for _ in range(self.uint(8))]
            count = self.uint(8)
            if count != rows:
                raise BackupError("LowCardinality row count mismatch in the lookup-row export")
            indexes = [self.uint(width) for _ in range(count)]
            if any(i >= len(keys) for i in indexes):
                raise BackupError("LowCardinality index out of range in the lookup-row export")
            return [keys[i] for i in indexes]
        raise BackupError(f"unexpected column type in the lookup-row export: {kind}")


LOOKUP_COLUMNS = ("lookup_table_name", "row_id", "key_raw", "key_lc", "cols_json", "version", "deleted")


def native_lookup_counts(path: pathlib.Path) -> tuple[int, int]:
    """(stored rows, live rows) of a Native lookup_rows export. Live rows use
    the same rule as the read path: argMax(deleted, version) per
    (lookup_table_name, row_id), deleted = 0."""
    reader = NativeReader(path.read_bytes())
    latest: dict[tuple[bytes, int], tuple[int, int]] = {}
    stored = 0
    while reader.pos < len(reader.data):
        columns, rows = reader.varint(), reader.varint()
        block: dict[str, list[Any]] = {}
        for _ in range(columns):
            name = reader.string().decode()
            kind = reader.string().decode()
            block[name] = reader.column(kind, rows)
        if columns and set(block) != set(LOOKUP_COLUMNS):
            raise BackupError(f"lookup-row export has unexpected columns: {sorted(block)}")
        for i in range(rows if columns else 0):
            key = (block["lookup_table_name"][i], block["row_id"][i])
            version, deleted = block["version"][i], block["deleted"][i]
            if key not in latest or version >= latest[key][0]:
                latest[key] = (version, deleted)
        stored += rows if columns else 0
    return stored, sum(1 for _, deleted in latest.values() if deleted == 0)


class ClickHouseHTTPS(http.client.HTTPSConnection):
    """HTTPS to an inventory address, verifying the inventory TLS name."""

    def __init__(self, host: str, port: int | None, server_name: str, context: ssl.SSLContext, timeout: int):
        super().__init__(host, port, timeout=timeout, context=context)
        self.server_name = server_name
        self.tls_context = context

    def connect(self) -> None:
        import socket
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self.tls_context.wrap_socket(sock, server_hostname=self.server_name)


class Database:
    """PostgreSQL and ClickHouse reached over the network.

    ``ch_only`` serves `scripts/nano` on a role-split PostgreSQL host
    (lookup rows only): the endpoint, TLS CA and server name come from that
    host's `.nano-role.env`, and a run without NANO_BACKUP_CH_PASSWORD uses a
    one-time password for the `nano_backup` user."""

    def __init__(self, config: Config, ch_only: bool = False):
        env = config.env
        self.pg_host = os.environ.get("NANO_BACKUP_PG_HOST", "postgres")
        self.pg_port = os.environ.get("NANO_BACKUP_PG_PORT", "5432")
        # NAN-5214: verified TLS to the Patroni leader on an HA cluster.
        self.pg_sslmode = os.environ.get("NANO_BACKUP_PG_SSLMODE", "prefer")
        self.pg_sslrootcert = os.environ.get("NANO_BACKUP_PG_SSLROOTCERT", "")
        if self.pg_sslmode not in {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}:
            raise BackupError("unsafe NANO_BACKUP_PG_SSLMODE")
        self.pg_db = env.get("POSTGRES_DB") or "nanosiem"
        self.pg_admin = env.get("POSTGRES_USER") or "nanosiem"
        self.pg_admin_password = env.get("POSTGRES_PASSWORD", "")
        self.backup_pg_password = env.get("NANO_BACKUP_PG_PASSWORD", "")
        self.ch_url = os.environ.get("NANO_BACKUP_CLICKHOUSE_URL", "http://clickhouse:8123")
        self.ch_admin_password = env.get("CLICKHOUSE_ADMIN_PASSWORD", "")
        self.backup_ch_password = env.get("NANO_BACKUP_CH_PASSWORD", "")
        self.ch_cluster = os.environ.get("NANO_BACKUP_CLICKHOUSE_CLUSTER", "")
        self.ch_ca = os.environ.get("NANO_BACKUP_CLICKHOUSE_CA", "")
        self.ch_server_name = os.environ.get("NANO_BACKUP_CLICKHOUSE_SERVER_NAME", "")
        role_env = read_env(config.install_dir / ".nano-role.env")
        if ch_only and role_env:
            scheme = role_env.get("NANO_PRIVATE_SCHEME", "https")
            address = role_env.get("NANO_CLICKHOUSE_REMOTE_ADDRESS", "")
            port = role_env.get("NANO_CLICKHOUSE_HTTP_PORT", "8123")
            if scheme not in {"http", "https"} or not re.fullmatch(r"[A-Za-z0-9.:-]+", address) \
                    or not port.isdigit():
                raise BackupError("the role inventory has no usable ClickHouse HTTP endpoint")
            # An explicit NANO_BACKUP_CLICKHOUSE_URL wins (a host that reaches
            # ClickHouse through a different address than the inventory one).
            self.ch_url = os.environ.get("NANO_BACKUP_CLICKHOUSE_URL") or f"{scheme}://{address}:{port}"
            self.ch_cluster = role_env.get("CLICKHOUSE_CLUSTER", "default")
            self.ch_ca = role_env.get("NANO_TLS_CA", "")
            self.ch_server_name = role_env.get("NANO_TLS_SERVER_NAME", "")
        if ch_only and not self.backup_ch_password:
            self.backup_ch_password = secrets.token_hex(32)
        for name, value in (("POSTGRES_DB", self.pg_db), ("POSTGRES_USER", self.pg_admin)):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", value):
                raise BackupError(f"unsafe {name}")
        if not re.fullmatch(r"[A-Za-z0-9_-]{0,64}", self.ch_cluster):
            raise BackupError("unsafe ClickHouse cluster name")
        required = [("NANO_BACKUP_CH_PASSWORD", self.backup_ch_password)]
        if not ch_only:
            required.insert(0, ("NANO_BACKUP_PG_PASSWORD", self.backup_pg_password))
        for name, value in required:
            if not re.fullmatch(r"[0-9a-f]{32,128}", value):
                raise BackupError(f"{name} is missing from .env; run scripts/nano backup-schedule --configure")

    def pg_env(self, admin: bool) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        env.update(PGHOST=self.pg_host, PGPORT=self.pg_port, PGDATABASE=self.pg_db, PGCONNECT_TIMEOUT="15",
                   PGUSER=self.pg_admin if admin else BACKUP_ROLE,
                   PGPASSWORD=self.pg_admin_password if admin else self.backup_pg_password,
                   PGAPPNAME="nano-backup", PGSSLMODE=self.pg_sslmode)
        if self.pg_sslmode.startswith("verify-") and self.pg_sslrootcert:
            env["PGSSLROOTCERT"] = self.pg_sslrootcert
        return env

    def psql(self, sql: str, admin: bool = False) -> str:
        result = subprocess.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "--tuples-only", "--no-align", "--quiet"],
                                input=sql, text=True, capture_output=True, env=self.pg_env(admin), check=False)
        if result.returncode != 0:
            raise BackupError(f"PostgreSQL: {result.stderr.strip()[-300:]}")
        return result.stdout

    def _connection(self) -> http.client.HTTPConnection:
        parsed = urllib.parse.urlsplit(self.ch_url)
        if parsed.scheme != "https":
            return http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=300)
        context = ssl.create_default_context(cafile=self.ch_ca or None)
        return ClickHouseHTTPS(parsed.hostname or "", parsed.port, self.ch_server_name or parsed.hostname or "",
                               context, 300)

    def ch(self, sql: str, admin: bool = False, out: Any = None, data: Any = None,
           length: int | None = None) -> bytes:
        """POST a query; with ``data`` the query goes in the URL and the body
        is the INSERT payload (streamed from a file)."""
        user, password = ("nanosiem_admin", self.ch_admin_password) if admin else (BACKUP_ROLE, self.backup_ch_password)
        conn = self._connection()
        headers = {"X-ClickHouse-User": user, "X-ClickHouse-Key": password}
        # Review M1: wait_end_of_query buffers the whole result server-side,
        # so an error during execution is an HTTP error, not a 200 whose
        # body stops part-way (ClickHouse then appends an exception trailer).
        params = {"wait_end_of_query": "1"}
        try:
            if data is None:
                conn.request("POST", "/?" + urllib.parse.urlencode(params), body=sql.encode(), headers=headers)
            else:
                headers["Content-Length"] = str(length)
                conn.request("POST", "/?" + urllib.parse.urlencode({**params, "query": sql}), body=data,
                             headers=headers)
            response = conn.getresponse()
            exception_code = response.getheader("X-ClickHouse-Exception-Code")
            if response.status != 200 or exception_code:
                raise BackupError(f"ClickHouse: HTTP {response.status} {response.read()[:300].decode(errors='replace')}")
            if out is not None:
                shutil.copyfileobj(response, out, 1024 * 1024)
                return b""
            body = response.read()
            if b"Code: " in body[-2048:] and b"DB::Exception" in body[-2048:]:
                raise BackupError(f"ClickHouse reported an error after the result began: {body[-300:]!r}")
            return body
        except (OSError, http.client.HTTPException) as error:
            raise BackupError(f"ClickHouse unreachable at {self.ch_url}: {error}") from None
        finally:
            conn.close()

    def _user_rows(self) -> list[dict[str, Any]]:
        raw = self.ch(f"SELECT name, host_ip, host_names, host_names_regexp, host_names_like FROM system.users "
                      f"WHERE name IN ('{APP_CH_USER}', '{BACKUP_ROLE}') FORMAT JSONEachRow", admin=True)
        rows = []
        for line in raw.decode(errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows

    def backup_hosts(self, rows: list[dict[str, Any]] | None = None) -> tuple[str, tuple[frozenset[str], frozenset[str]] | None]:
        """NAN-5404: (HOST clause, wanted (ips, names)) for nano_backup: the app
        user's networks, else (legacy / unreadable) BACKUP_CH_HOSTS and None."""
        app = app_user_hosts(self._user_rows() if rows is None else rows)
        if app is None:
            return BACKUP_CH_HOSTS, None
        return host_clause(*app), app

    def align_backup_hosts(self, cluster: str) -> bool:
        """ALTER nano_backup's HOST list only when it admits anything outside
        the wanted one (see backup_hosts). Legacy fallback: only an any-address user is
        tightened, to BACKUP_CH_HOSTS. Returns whether it altered the user."""
        rows = self._user_rows()
        backup = next((r for r in rows if r.get("name") == BACKUP_ROLE), None)
        if backup is None:
            return False
        hosts, wanted = self.backup_hosts(rows)
        current = (frozenset(str(v) for v in backup.get("host_ip") or []),
                   frozenset(str(v) for v in backup.get("host_names") or []))
        if wanted is not None:
            # Narrow only: a list already inside the app user's is left alone,
            # so nodes whose app-user lists differ slightly (role split: Docker
            # pools only on hosts that also run bridge services) never flap.
            inside = current[0] <= wanted[0] and current[1] <= wanted[1] and (current[0] or current[1])
            if inside and not backup.get("host_names_regexp") and not backup.get("host_names_like"):
                return False
        elif not any(str(v).endswith("/0") for v in current[0]):
            return False
        self.ch(f"ALTER USER {BACKUP_ROLE}{cluster} HOST {hosts}", admin=True)
        return True

    def provision_clickhouse(self) -> None:
        """Review M4: touch the cluster only when the `nano_backup`
        credential does not work. A working user is left alone, so a routine
        run issues no ON CLUSTER DDL (one replica down cannot block it) and
        never leaves the user dropped on part of the cluster. A repair creates
        the user if it is missing, resets its password and grants SELECT on
        the two lookup tables only; nothing is ever dropped."""
        cluster = f" ON CLUSTER '{self.ch_cluster}'" if self.ch_cluster else ""
        try:
            self.ch("SELECT 1 FROM nanosiem.lookup_rows LIMIT 0")
            # NAN-5367 / NAN-5404: keep the host list in line with the app
            # user's. A local read; a routine run on a user already in line
            # issues no cluster DDL.
            self.align_backup_hosts(cluster)
            return
        except BackupError as error:
            if "unreachable" in str(error):
                raise
        hosts, _ = self.backup_hosts()
        self.ch(f"CREATE USER IF NOT EXISTS {BACKUP_ROLE}{cluster} IDENTIFIED WITH sha256_password BY "
                f"'{self.backup_ch_password}' HOST {hosts}", admin=True)
        self.ch(f"ALTER USER {BACKUP_ROLE}{cluster} IDENTIFIED WITH sha256_password BY "
                f"'{self.backup_ch_password}' HOST {hosts}", admin=True)
        for table in ("lookup_rows", "lookup_rows_distributed"):
            self.ch(f"GRANT{cluster} SELECT ON nanosiem.{table} TO {BACKUP_ROLE}", admin=True)

    def lookup_table(self, admin: bool = False) -> str:
        exists = self.ch("EXISTS TABLE nanosiem.lookup_rows_distributed FORMAT TSVRaw", admin=admin)
        return "lookup_rows_distributed" if exists.decode().strip() == "1" else "lookup_rows"

    def export_lookups(self, payload: pathlib.Path) -> str:
        """One Native export as the SELECT-only user (across every shard when
        the cluster has the `_distributed` wrapper). Review M1: the signed
        count is derived from the exported file, so a concurrent lookup
        write can never make it disagree with the rows actually stored."""
        table = self.lookup_table()
        native = payload / "clickhouse-lookup-rows.native"
        with native.open("wb") as handle:
            self.ch(f"SELECT {', '.join(LOOKUP_COLUMNS)} FROM nanosiem.{table} "
                    "SETTINGS low_cardinality_allow_in_native_format = 0 FORMAT Native", out=handle)
        _, rows = native_lookup_counts(native)
        (payload / "clickhouse-lookup-rows.count").write_text(f"{rows}\n")
        for name in ("clickhouse-lookup-rows.native", "clickhouse-lookup-rows.count"):
            os.chmod(payload / name, 0o600)
        return str(rows)

    def import_lookups(self, payload: pathlib.Path) -> str:
        """Replace the lookup rows with the backed-up ones (admin) and check
        the signed live-row count. Review M1: the file is validated against
        the signed count BEFORE the table is truncated."""
        source = payload / "clickhouse-lookup-rows.native"
        expected = (payload / "clickhouse-lookup-rows.count").read_text().strip()
        if not expected.isdigit():
            raise BackupError("signed lookup-row count is invalid")
        _, live = native_lookup_counts(source)
        if str(live) != expected:
            raise BackupError(f"lookup-row export holds {live} live rows, the signed count is {expected}; "
                              "the target table was not touched")
        cluster = f" ON CLUSTER '{self.ch_cluster}'" if self.ch_cluster else ""
        self.ch(f"TRUNCATE TABLE nanosiem.lookup_rows{cluster}", admin=True)
        with source.open("rb") as handle:
            self.ch("INSERT INTO nanosiem.lookup_rows FORMAT Native", admin=True, data=handle,
                    length=source.stat().st_size)
        actual = self.ch(LOOKUP_COUNT_SQL.format(table=self.lookup_table(admin=True)), admin=True).decode().strip()
        if actual != expected:
            raise BackupError(f"restored lookup rows ({actual}) do not match the signed backup ({expected})")
        return actual

    def provision(self) -> None:
        """Idempotently (re)create the dedicated read-only identities. Runs
        before every backup, so a restored or rebuilt database heals itself."""
        self.psql(f"""
SELECT format('CREATE ROLE {BACKUP_ROLE} LOGIN') WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{BACKUP_ROLE}')
\\gexec
ALTER ROLE {BACKUP_ROLE} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '{self.backup_pg_password}';
GRANT pg_read_all_data TO {BACKUP_ROLE};
GRANT CONNECT ON DATABASE {self.pg_db} TO {BACKUP_ROLE};
""", admin=True)


def topology(config: Config) -> dict[str, str]:
    """The manifest identity fields `scripts/nano` would record on this host."""
    role_env = read_env(config.install_dir / ".nano-role.env")
    if role_env:
        shard_count = "1"
        cluster_xml = config.install_dir / ".nano-generated/clickhouse/config.d/zz-sovereign-cluster.xml"
        if cluster_xml.is_file():
            root = ET.parse(cluster_xml).getroot()
            shard_count = str(max(1, len(root.findall("./remote_servers/default/shard"))))
        identity = role_env.get("NANO_DEPLOYMENT_IDENTITY_SHA256", "")
        return {"mode": "role-split", "deployment": role_env.get("NANO_DEPLOYMENT_ID", ""), "identity": identity,
                "host": role_env.get("NANO_HOST_ID", ""), "roles": role_env.get("NANO_ROLE_PROFILES", ""),
                "shard": "1", "replica": "1", "shard_count": shard_count}
    return {"mode": "single", "deployment": "single", "identity": "", "host": "single",
            "roles": "app,ingest,clickhouse,keeper,postgres", "shard": "1", "replica": "1", "shard_count": "1"}


def openssl(*args: str) -> str:
    result = subprocess.run(["openssl", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise BackupError(f"openssl {args[0]} failed: {result.stderr.strip()[-200:]}")
    return result.stdout


def capture_lookups(db: "Database", payload: pathlib.Path) -> tuple[str, str]:
    """(live rows, warning). Review M4: ClickHouse unreachable (or one
    replica down for a user repair) must not cost the PostgreSQL backup; the
    bundle then records clickhouse_data=excluded and the run is reported as
    partial, with the reason, never as a clean success."""
    try:
        db.provision_clickhouse()
        return db.export_lookups(payload), ""
    except BackupError as error:
        for item in ("clickhouse-lookup-rows.native", "clickhouse-lookup-rows.count"):
            with_suppressed(lambda item=item: (payload / item).unlink())
        warning = f"lookup rows not included: {error}"
        log(f"WARNING: {warning}")
        return "0", warning


def publish_bundle(source: pathlib.Path, output_root: pathlib.Path, name: str) -> pathlib.Path:
    """Review M2: the destination is usually another mount, where a move is
    a copy. Copy under a dot name, then rename on the destination, so a
    failed or interrupted copy never looks like a backup."""
    final = output_root / name
    staged = output_root / f"{PARTIAL_PREFIX}{name}.partial-{secrets.token_hex(4)}"
    try:
        shutil.copytree(str(source), str(staged))
        os.rename(staged, final)
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    return final


def network_backup(config: Config, output_root: pathlib.Path, name: str) -> tuple[pathlib.Path, str]:
    """Write one signed nano-backup-v2 bundle (a recovery set on a role-split
    app host) under output_root/name. Nothing here needs the Docker socket."""
    recipient = config.file(config.env.get("NANO_BACKUP_RECIPIENT_CERT") or RECIPIENT_CERT)
    signing = config.file(config.env.get("NANO_BACKUP_SIGNING_KEY") or SIGNING_KEY)
    for path, label in ((recipient, "recipient certificate"), (signing, "signing key")):
        if not path.is_file():
            raise BackupError(f"backup {label} is missing: {path}")
    db = Database(config)
    db.provision()  # PostgreSQL only; ClickHouse is handled below (review M4)
    version = (config.env.get("NANO_VERSION") or "").removeprefix("v")
    edition = config.env.get("NANO_EDITION") or "open"
    schema = config.env.get("NANO_SCHEMA_PROFILE") or "udm"
    topo = topology(config)
    created = iso(dt.datetime.now(dt.timezone.utc))
    work = pathlib.Path(tempfile.mkdtemp(prefix="nano-backup-", dir=str(config.state_dir)))
    os.chmod(work, 0o700)
    try:
        payload = work / "payload"
        payload.mkdir(mode=0o700)
        for item in (".env", ".nano-host-identity", ".nano-role.env"):
            if (config.install_dir / item).is_file():
                shutil.copyfile(config.install_dir / item, payload / item)
        # One REPEATABLE READ snapshot: the dump, the signed row counts and
        # (while it is held) the lookup-row export.
        exporter = subprocess.Popen(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1", "--tuples-only", "--no-align", "--quiet"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=db.pg_env(admin=False))
        try:
            assert exporter.stdin is not None and exporter.stdout is not None
            exporter.stdin.write(
                "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
                "SELECT '__NANO_SNAPSHOT__|' || pg_export_snapshot() || '|' || "
                "COALESCE((SELECT MAX(version) FROM public._sqlx_migrations), 0) || '|' || "
                "pg_database_size(current_database());\n")
            exporter.stdin.flush()
            line = ""
            while not line.startswith("__NANO_SNAPSHOT__|"):
                line = exporter.stdout.readline()
                if not line:
                    raise BackupError("PostgreSQL snapshot exporter exited: "
                                      + (exporter.stderr.read() if exporter.stderr else "")[-300:])
            snapshot, pg_mig, pg_bytes = line.strip().split("|")[1:4]
            if not re.fullmatch(r"[0-9A-F]{8}-[0-9A-F]{8}-[0-9]+", snapshot):
                raise BackupError("PostgreSQL returned an invalid snapshot")
            # Review M4: ClickHouse being unreachable (or one replica down
            # for the user repair) must not cost the PostgreSQL backup. The
            # bundle then records clickhouse_data=excluded and the run is
            # reported as partial, with the reason, never as success.
            rows, lookup_warning = capture_lookups(db, payload)
            with (payload / "postgres.dump").open("wb") as handle:
                dump = subprocess.run(["pg_dump", f"--snapshot={snapshot}", "-Fc", "--no-owner", "--no-privileges"],
                                      stdout=handle, stderr=subprocess.PIPE, env=db.pg_env(admin=False), check=False)
            if dump.returncode != 0:
                raise BackupError(f"pg_dump failed: {dump.stderr.decode(errors='replace').strip()[-300:]}")
            counts = db.psql(f"""BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET TRANSACTION SNAPSHOT '{snapshot}';
SELECT format('SELECT %L || ''|'' || count(*) FROM %I.%I;', schemaname || '.' || tablename, schemaname, tablename)
FROM pg_tables
WHERE schemaname <> 'information_schema' AND schemaname NOT LIKE 'pg\\_%' ESCAPE '\\'
ORDER BY 1;
\\gexec
COMMIT;
""")
            lines = sorted(line for line in counts.splitlines() if line.strip())
            (payload / "postgres-row-counts.tsv").write_text("".join(f"{line}\n" for line in lines))
            exporter.stdin.write("COMMIT;\n\\q\n")
            exporter.stdin.close()
            if exporter.wait(timeout=60) != 0:
                raise BackupError("PostgreSQL snapshot exporter failed")
        finally:
            if exporter.poll() is None:
                exporter.kill()
        for path in payload.iterdir():
            os.chmod(path, 0o600)
        log(f"captured PostgreSQL (migration {pg_mig})"
            + (f" and {rows} lookup-table row(s)" if not lookup_warning else " WITHOUT the lookup-table rows"))

        bundle_parent = work / "out"
        bundle = bundle_parent / ("postgres" if topo["mode"] == "role-split" else name)
        bundle.mkdir(parents=True, mode=0o700)
        tar_path = work / "payload.tar"
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(payload.rglob("*")):
                archive.add(path, arcname=f"./{path.relative_to(payload)}", recursive=False)
        openssl("cms", "-encrypt", "-binary", "-aes-256-gcm", "-in", str(tar_path), "-outform", "DER",
                "-out", str(bundle / "payload.cms"), str(recipient))
        fingerprint = openssl("x509", "-in", str(recipient), "-noout", "-fingerprint", "-sha256")
        fingerprint = fingerprint.strip().split("=", 1)[1].replace(":", "")
        backup_id = f"{name}-{topo['host']}"
        set_id = name if topo["mode"] == "role-split" else ""
        quiesce = created if topo["mode"] == "role-split" else ""
        manifest_tool = pathlib.Path(__file__).resolve().parent / "nano-manifest.py"
        values = [str(bundle / "manifest.json"), str(payload), sha256_file(bundle / "payload.cms"), backup_id,
                  version, edition, schema, topo["mode"], topo["deployment"], topo["identity"], topo["host"],
                  topo["roles"], topo["shard"], topo["replica"], topo["shard_count"],
                  # On a role-split app host the PostgreSQL component is taken
                  # over the network, not on the PostgreSQL host: scope it to
                  # the cluster so the PostgreSQL host can restore it.
                  "true", pg_mig, pg_bytes, "false", "0", "0", "", "", "false", "false",
                  "cluster" if topo["mode"] == "role-split" else "host", "", "",
                  created, fingerprint, set_id, quiesce, "excluded" if lookup_warning else "lookups"]
        written = subprocess.run([sys.executable, "-I", str(manifest_tool), "write-manifest", *values],
                                 capture_output=True, text=True, check=False)
        if written.returncode != 0:
            raise BackupError(f"manifest: {written.stderr.strip()[-300:]}")
        openssl("dgst", "-sha256", "-sign", str(signing), "-out", str(bundle / "manifest.sig"),
                str(bundle / "manifest.json"))
        if topo["mode"] == "role-split":
            rset = bundle_parent / "recovery-set"
            rset.mkdir(mode=0o700)
            created_set = subprocess.run(
                [sys.executable, "-I", str(manifest_tool), "create-set", "--set-id", set_id, "--quiesce-epoch",
                 quiesce, "--output", str(rset / "recovery-set.json"), str(bundle / "manifest.json")],
                capture_output=True, text=True, check=False)
            if created_set.returncode != 0:
                raise BackupError(f"recovery set: {created_set.stderr.strip()[-300:]}")
            openssl("dgst", "-sha256", "-sign", str(signing), "-out", str(rset / "recovery-set.sig"),
                    str(rset / "recovery-set.json"))
        for path in bundle_parent.rglob("*"):
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
        final = output_root / name
        source = bundle_parent if topo["mode"] == "role-split" else bundle
        if final.exists():
            raise BackupError(f"backup output exists: {final}")
        publish_bundle(source, output_root, name)
        return final, lookup_warning
    finally:
        shutil.rmtree(work, ignore_errors=True)


class InstallLock:
    """The same advisory lock `scripts/nano upgrade`/`rollback` hold on the
    install directory: a scheduled backup never overlaps an upgrade, and an
    upgrade refuses to start while a scheduled backup runs."""

    def __init__(self, install_dir: pathlib.Path):
        self.install_dir = install_dir
        self.fd = -1

    def __enter__(self) -> "InstallLock":
        import fcntl
        self.fd = os.open(self.install_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise BackupError("an upgrade or rollback holds the install lock; the backup will be retried") from None
        return self

    def __exit__(self, *_: Any) -> None:
        import fcntl
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


# NAN-5215: every app host of a role-split cluster runs the scheduler, so the
# daily backup survives the loss of any one of them. One PostgreSQL session
# lock makes exactly one host take a slot; the others wait for it and then see
# the finished bundle in the shared destination. Ids sit beside
# nano-upgrade.py's PgMigrationLock (5_000_001 upgrade .. 5_000_003).
CLUSTER_BACKUP_LOCK_ID = 5_000_004
UPGRADE_LOCK_ID = 5_000_001
# Every app host computes the same HH:MM slot; only their clocks differ (NTP:
# seconds). A bundle started this long before the slot still counts as that
# slot's backup. Kept small so a backup from an earlier slot or a manual run
# never suppresses the next scheduled one.
SLOT_SKEW = dt.timedelta(minutes=2)


class ClusterBusy(BackupError):
    """Another app host holds the cluster backup lock (it is taking the slot)."""


class ClusterLock:
    """A live PostgreSQL advisory lock, released when this psql session ends
    (including when its host dies mid-backup, so a survivor can take over)."""

    def __init__(self, config: Config, timeout: float = 30):
        self.config = config
        self.timeout = timeout
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> "ClusterLock":
        import selectors
        db = Database(self.config)
        env = db.pg_env(admin=True)
        # PostgreSQL must notice a dead holder in seconds, not after the OS
        # keepalive default (~2 h): a host that dies mid-backup releases the
        # slot to the next app host within about half a minute.
        env["PGOPTIONS"] = ("-c tcp_keepalives_idle=10 -c tcp_keepalives_interval=5 "
                            "-c tcp_keepalives_count=3 -c tcp_user_timeout=20000")
        self.process = subprocess.Popen(
            ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
            env=env)
        assert self.process.stdin is not None and self.process.stdout is not None
        # Take the slot lock and hold it; only probe the upgrade lease (an
        # upgrade run from any host holds it on PostgreSQL for its whole run).
        self.process.stdin.write(
            f"SELECT CASE WHEN NOT pg_try_advisory_lock({CLUSTER_BACKUP_LOCK_ID}) THEN '__NANO_BACKUP_BUSY__' "
            f"WHEN NOT pg_try_advisory_lock({UPGRADE_LOCK_ID}) THEN '__NANO_BACKUP_UPGRADE__' "
            f"WHEN pg_advisory_unlock({UPGRADE_LOCK_ID}) THEN '__NANO_BACKUP_LOCKED__' END;\n")
        self.process.stdin.flush()
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        line = ""
        if selector.select(self.timeout):
            line = self.process.stdout.readline().strip()
        if line == "__NANO_BACKUP_LOCKED__":
            return self
        self.close()
        if line == "__NANO_BACKUP_BUSY__":
            raise ClusterBusy("another app host is taking this backup")
        if line == "__NANO_BACKUP_UPGRADE__":
            raise BackupError("a cluster upgrade holds the PostgreSQL upgrade lease; the backup will be retried")
        raise BackupError("cannot take the cluster backup lock in PostgreSQL")

    def close(self) -> None:
        if self.process is None:
            return
        with_suppressed(lambda: self.process.stdin.close())  # type: ignore[union-attr]
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process = None

    def __exit__(self, *_: Any) -> None:
        self.close()


def cluster_lock(config: Config) -> Any:
    """The cluster lock on a role-split install (several app hosts may run
    the scheduler); a single-node install has exactly one scheduler."""
    import contextlib
    if (config.install_dir / ".nano-role.env").is_file():
        return ClusterLock(config)
    return contextlib.nullcontext()


def auto_started_at(name: str) -> dt.datetime | None:
    if not AUTO_NAME.fullmatch(name):
        return None
    stamp = name[len(AUTO_PREFIX):].removesuffix(".tar")
    return dt.datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)


def slot_already_taken(config: Config, slot: dt.datetime) -> str | None:
    """The newest complete automatic backup at or after this slot, if any
    (written by this host or, through a shared destination, another one)."""
    floor = slot - SLOT_SKEW
    for name in reversed(auto_names(config)):
        started = auto_started_at(name)
        if started is not None and started >= floor:
            return name
    return None


def run_once(config: Config, now: dt.datetime | None = None,
             slot: dt.datetime | None = None) -> dict[str, Any]:
    """One backup. With ``slot`` (the scheduler) the run is skipped when
    another app host already stored that slot's backup, and reported as
    outcome ``elsewhere`` (not recorded) while another host is taking it."""
    started = now or dt.datetime.now(dt.timezone.utc)
    name = AUTO_PREFIX + started.strftime("%Y%m%dT%H%M%SZ")
    status: dict[str, Any] = {
        "enabled": True, "started_at": iso(started), "destination_kind": config.kind,
        "destination": config.destination_label(), "schedule": config.schedule, "keep": config.keep,
        # Scheduled backups take the default scope: PostgreSQL, configuration
        # and the lookup-table rows. The API's scope field is binary.
        "clickhouse_data": "excluded",
    }
    try:
        with InstallLock(config.install_dir), cluster_lock(config):
            taken = slot_already_taken(config, slot) if slot is not None else None
            if taken:
                log(f"backup {taken} already covers the {iso(slot)} slot; nothing to do on this host")
                status.update(outcome="elsewhere", backup_id=taken)
            else:
                store(config, status, name)
    except ClusterBusy as busy:
        log(f"{busy}; this host stands by")
        status.update(outcome="elsewhere")
    except Exception as error:  # every failure is reported, then retried
        status.update(outcome="failure", error=str(error)[:1000])
        log(f"backup failed: {error}")
    status["finished_at"] = iso(dt.datetime.now(dt.timezone.utc))
    return status


def store(config: Config, status: dict[str, Any], name: str) -> None:
    if config.kind == "path":
        root = pathlib.Path(config.path)
        if not root.is_dir():
            raise BackupError(f"backup path is not mounted: {root}")
        check_destination_marker(config)
        bundle, warning = network_backup(config, root, name)
        size = bundle_size(bundle)
    else:
        staging = config.state_dir / "staging"
        staging.mkdir(parents=True, exist_ok=True)
        os.chmod(staging, 0o700)
        bundle, warning = network_backup(config, staging, name)
        archive = staging / f"{name}.tar"
        try:
            tar_bundle(bundle, archive)
            size = archive.stat().st_size
            log(f"uploading {archive.name} ({size} bytes) to {config.destination_label()}")
            config.s3().upload_file(archive.name, archive)
        finally:
            shutil.rmtree(bundle, ignore_errors=True)
            with_suppressed(lambda: archive.unlink())
    prune(config)
    if warning:
        status.update(outcome="partial", backup_id=name, size_bytes=size, error=warning[:1000])
        log(f"backup {name} stored ({size} bytes) WITHOUT the lookup-table rows")
    else:
        status.update(outcome="success", backup_id=name, size_bytes=size)
        log(f"backup {name} stored ({size} bytes)")


def iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def status_file(config: Config) -> pathlib.Path:
    return config.state_dir / "status.json"


def record_status(config: Config, status: dict[str, Any]) -> None:
    path = status_file(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    previous: dict[str, Any] = {}
    if path.is_file():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            previous = {}
    merged = {**previous, "last": status}
    if status.get("outcome") == "success":
        merged["last_success"] = status
    elif status.get("outcome") == "failure":
        merged["last_failure"] = status
    fd, temp = tempfile.mkstemp(dir=str(path.parent), prefix=".status.")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(merged, handle, sort_keys=True, indent=2)
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    report(config, status)


def report(config: Config, status: dict[str, Any]) -> None:
    """Best-effort report to nano-api (compose network). Nothing leaves the
    deployment; a failed report is logged and the local status file stays."""
    if not config.token:
        return
    url = os.environ.get("NANO_BACKUP_REPORT_URL", REPORT_URL)
    if not urllib.parse.urlsplit(url).hostname:
        return
    parsed = urllib.parse.urlsplit(url)
    body = json.dumps({k: v for k, v in status.items() if v is not None}).encode()
    try:
        conn_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = conn_type(parsed.hostname, parsed.port, timeout=15)
        conn.request("POST", parsed.path, body=body, headers={
            "Authorization": f"Bearer {config.token}", "Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        if response.status >= 300:
            log(f"status report to nano-api returned HTTP {response.status}")
        conn.close()
    except (OSError, http.client.HTTPException) as error:
        log(f"status report to nano-api failed: {error}")


def next_run(schedule: str, after: dt.datetime) -> dt.datetime:
    """Next local wall-clock occurrence of HH:MM strictly after `after`."""
    match = SCHEDULE.fullmatch(schedule)
    if not match:
        raise BackupError("schedule must be HH:MM (24-hour, local time)")
    local = after.astimezone()
    candidate = local.replace(hour=int(match.group(1)), minute=int(match.group(2)), second=0, microsecond=0)
    if candidate <= local:
        candidate = (candidate + dt.timedelta(days=1)).replace(
            hour=int(match.group(1)), minute=int(match.group(2)))
        candidate = candidate.astimezone().replace(hour=int(match.group(1)), minute=int(match.group(2)))
    return candidate


def serve(install_dir: pathlib.Path, *, clock: Callable[[], dt.datetime] | None = None,
          sleep: Callable[[float], None] = time.sleep, max_runs: int | None = None) -> int:
    clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
    stopping = {"flag": False}

    def stop(*_: Any) -> None:
        stopping["flag"] = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    runs = 0
    reported_disabled = False
    log("scheduler started")
    while not stopping["flag"]:
        config = load_config(install_dir)
        if not config.enabled:
            if not reported_disabled:
                log("automatic backups are disabled in .env; idling")
                now = iso(clock())
                record_status(config, {
                    "enabled": False, "outcome": "disabled", "started_at": now, "finished_at": now,
                    "destination_kind": config.kind or "path", "destination": config.destination_label(),
                    "clickhouse_data": "excluded", "schedule": config.schedule, "keep": config.keep})
                reported_disabled = True
            for _ in range(60):
                if stopping["flag"]:
                    return 0
                sleep(60)
            continue
        reported_disabled = False
        due = next_run(config.schedule, clock())
        log(f"next backup at {due.isoformat(timespec='minutes')}")
        while not stopping["flag"] and clock() < due:
            sleep(min(60.0, max(1.0, (due - clock()).total_seconds())))
        if stopping["flag"]:
            break
        attempt = 0
        while attempt < len(BACKOFF_MINUTES) + 1:
            config = load_config(install_dir)
            status = run_once(config, clock(), slot=due)
            if status["outcome"] == "elsewhere":
                # Another app host owns (or finished) this slot. Its report
                # reaches the shared API; stand by in case it dies mid-run
                # (its lock then drops) until the slot is covered.
                if status.get("backup_id") or clock() + dt.timedelta(seconds=30) >= next_run(config.schedule, clock()):
                    break
                waited = clock() + dt.timedelta(seconds=30)
                while not stopping["flag"] and clock() < waited:
                    sleep(min(30.0, max(1.0, (waited - clock()).total_seconds())))
                if stopping["flag"]:
                    break
                continue
            attempt += 1
            status["next_run_at"] = iso(next_run(config.schedule, clock()))
            record_status(config, status)
            # A partial backup is stored and reported; retrying would only
            # pile up more copies while ClickHouse stays unreachable.
            if status["outcome"] in {"success", "partial"} or attempt > len(BACKOFF_MINUTES):
                break
            wait = dt.timedelta(minutes=BACKOFF_MINUTES[attempt - 1])
            following = next_run(config.schedule, clock())
            if clock() + wait >= following:
                break
            log(f"retrying in {BACKOFF_MINUTES[attempt - 1]} minutes")
            retry_at = clock() + wait
            while not stopping["flag"] and clock() < retry_at:
                sleep(min(60.0, max(1.0, (retry_at - clock()).total_seconds())))
            if stopping["flag"]:
                break
        runs += 1
        if max_runs is not None and runs >= max_runs:
            break
    return 0


# --------------------------------------------------------------------------- configure

def have_tty() -> bool:
    """A controlling terminal, not merely a /dev/tty node (services and CI
    have the node, but opening it fails with ENXIO)."""
    try:
        os.close(os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY))
        return True
    except OSError:
        return False


class Prompter:
    def __init__(self) -> None:
        self.fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)

    def _write(self, text: str) -> None:
        os.write(self.fd, text.encode())

    def _readline(self) -> str:
        data = b""
        while not data.endswith(b"\n"):
            chunk = os.read(self.fd, 1)
            if not chunk:
                break
            data += chunk
        return data.decode(errors="replace").rstrip("\r\n")

    def ask(self, prompt: str, default: str = "", secret: bool = False) -> str:
        shown = f"{prompt} [{default}]: " if default else f"{prompt}: "
        if secret:
            # getpass turns echo off on the controlling terminal itself.
            value = getpass.getpass(shown)
        else:
            self._write(shown)
            value = self._readline()
        return value.strip() or default

    def yes_no(self, prompt: str, default: bool) -> bool:
        hint = "[Y/n]" if default else "[y/N]"
        while True:
            answer = self.ask(f"{prompt} {hint}").lower()
            if not answer:
                return default
            if answer in {"y", "yes"}:
                return True
            if answer in {"n", "no"}:
                return False
            self.say("Answer y or n.")

    def say(self, text: str) -> None:
        self._write(text + "\n")


def ensure_keys(install_dir: pathlib.Path, prompter: "Prompter | None", say: Callable[[str], None]) -> None:
    """Create the recipient and signing key pairs once. Only the recipient
    CERTIFICATE and the signing key stay on the host; the recovery key file
    (recipient private key + both certificates) must leave it."""
    keys = install_dir / KEYS_DIR
    if (keys / "recipient.crt").exists():
        return
    result = subprocess.run([str(install_dir / "scripts" / "nano"), "backup-keygen", "--split", str(keys)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        raise BackupError(f"backup-keygen failed: {result.stderr.strip()[-300:]}")
    recovery = keys / "recovery-key.pem"
    say("")
    say("=" * 76)
    say(f"  Backup RECOVERY KEY: {recovery}")
    say("  Copy this file OFF this server now (password manager, vault, safe).")
    say("  It is the only thing that can decrypt your backups; restores need it.")
    say("  nano never shows it again, and it must not stay on this server.")
    say("=" * 76)
    if prompter is not None:
        if prompter.yes_no("Have you copied the recovery key off this server? Answer y to delete it here", False):
            remove_recovery_key(recovery)
            say("Recovery key deleted from this server.")
        else:
            say(f"The recovery key is still at {recovery}. Delete it once you have a copy elsewhere.")
    else:
        say(f"Unattended install: move {recovery} off this server, then delete it.")
    say("")


def remove_recovery_key(path: pathlib.Path) -> None:
    try:
        size = path.stat().st_size
        with path.open("r+b") as handle:
            handle.write(secrets.token_bytes(size))
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    with_suppressed(lambda: path.unlink())


def gather(env: dict[str, str], install_dir: pathlib.Path, interactive: bool,
           prompter: Prompter | None, confirmed: bool = False) -> dict[str, str] | None:
    """Return the .env updates, or None when the operator declined."""
    if interactive:
        assert prompter is not None
        if not confirmed and not prompter.yes_no("Set up automatic backups?", False):
            return None
        kind = ""
        while kind not in {"path", "s3"}:
            kind = prompter.ask("Destination: (1) local or mounted path (NFS/SMB share), "
                                "(2) S3-compatible bucket (AWS S3, Wasabi, RustFS ...)", "1")
            kind = {"1": "path", "2": "s3", "path": "path", "s3": "s3"}.get(kind, "")
        updates = {"NANO_BACKUP_DESTINATION": kind}
        if kind == "path":
            updates["NANO_BACKUP_PATH"] = prompter.ask("Backup directory (absolute path; mount the share first)",
                                                       env.get("NANO_BACKUP_PATH", ""))
        else:
            updates["NANO_BACKUP_S3_ENDPOINT"] = prompter.ask(
                "S3 endpoint URL", env.get("NANO_BACKUP_S3_ENDPOINT", "https://s3.us-east-1.amazonaws.com"))
            updates["NANO_BACKUP_S3_BUCKET"] = prompter.ask("Bucket", env.get("NANO_BACKUP_S3_BUCKET", ""))
            updates["NANO_BACKUP_S3_REGION"] = prompter.ask("Region", env.get("NANO_BACKUP_S3_REGION", "us-east-1"))
            updates["NANO_BACKUP_S3_PREFIX"] = prompter.ask("Key prefix", env.get("NANO_BACKUP_S3_PREFIX", "nano"))
            updates["NANO_BACKUP_S3_ACCESS_KEY"] = prompter.ask("Access key ID", "", secret=True)
            updates["NANO_BACKUP_S3_SECRET_KEY"] = prompter.ask("Secret access key", "", secret=True)
        updates["NANO_BACKUP_SCHEDULE"] = prompter.ask("Daily backup time (HH:MM, local)",
                                                       env.get("NANO_BACKUP_SCHEDULE", "02:00"))
        updates["NANO_BACKUP_KEEP"] = prompter.ask("Backups to keep", env.get("NANO_BACKUP_KEEP", "7"))
        return updates
    enabled = os.environ.get("NANO_BACKUP_ENABLED", "").strip().lower()
    if enabled in {"", "0", "false", "no", "n", "off"}:
        return None
    if enabled not in {"1", "true", "yes", "y", "on"}:
        raise BackupError("NANO_BACKUP_ENABLED must be true or false")
    source = os.environ
    kind = source.get("NANO_BACKUP_DESTINATION", "").strip()
    updates = {"NANO_BACKUP_DESTINATION": kind}
    names = ["NANO_BACKUP_PATH"] if kind == "path" else [
        "NANO_BACKUP_S3_ENDPOINT", "NANO_BACKUP_S3_BUCKET", "NANO_BACKUP_S3_REGION", "NANO_BACKUP_S3_PREFIX",
        "NANO_BACKUP_S3_ACCESS_KEY", "NANO_BACKUP_S3_SECRET_KEY"]
    for name in names:
        updates[name] = source.get(name, "").strip()
    if kind == "s3":
        updates["NANO_BACKUP_S3_REGION"] = updates["NANO_BACKUP_S3_REGION"] or "us-east-1"
    updates["NANO_BACKUP_SCHEDULE"] = source.get("NANO_BACKUP_SCHEDULE", "02:00").strip() or "02:00"
    updates["NANO_BACKUP_KEEP"] = source.get("NANO_BACKUP_KEEP", "7").strip() or "7"
    include = source.get("NANO_BACKUP_INCLUDE_CLICKHOUSE_DATA", "false").strip().lower()
    if include in {"1", "true", "yes", "y", "on"}:
        raise BackupError("scheduled backups take the default scope (PostgreSQL, configuration and lookup tables); "
                          "back up ClickHouse data with scripts/nano backup --include-clickhouse-data")
    return updates


def validate_updates(updates: dict[str, str]) -> None:
    if updates.get("NANO_BACKUP_DESTINATION") not in {"path", "s3"}:
        raise BackupError("NANO_BACKUP_DESTINATION must be path or s3")
    if not SCHEDULE.fullmatch(updates["NANO_BACKUP_SCHEDULE"]):
        raise BackupError("schedule must be HH:MM (24-hour)")
    if not re.fullmatch(r"[1-9][0-9]{0,3}", updates["NANO_BACKUP_KEEP"]):
        raise BackupError("keep must be a whole number from 1 to 9999")
    for key, value in updates.items():
        if not ENV_SAFE.fullmatch(value):
            raise BackupError(f"{key} contains whitespace, quotes, '$', '`', '\\' or '#'")


def host_timezone() -> str:
    if os.environ.get("TZ") and ENV_SAFE.fullmatch(os.environ["TZ"]):
        return os.environ["TZ"].lstrip(":")
    try:
        text = pathlib.Path("/etc/timezone").read_text(encoding="utf-8").strip()
        if text and ENV_SAFE.fullmatch(text):
            return text
    except OSError:
        pass
    try:
        target = os.readlink("/etc/localtime")
        if "zoneinfo/" in target:
            return target.split("zoneinfo/", 1)[1]
    except OSError:
        pass
    return "UTC"


def configure(install_dir: pathlib.Path, *, from_installer: bool, force: bool) -> int:
    env_path = install_dir / ".env"
    env = read_env(env_path)
    if from_installer and env.get("NANO_BACKUP_ASKED") == "true" and not force:
        return 0
    interactive = "NANO_BACKUP_ENABLED" not in os.environ and have_tty()
    prompter = Prompter() if interactive else None
    say = prompter.say if prompter else log
    for attempt in range(3):
        # A rejected destination re-asks the destination, not the question.
        updates = gather(env, install_dir, interactive, prompter, confirmed=attempt > 0)
        if updates is None:
            write_env(env_path, {
                "NANO_BACKUP_ASKED": "true", "NANO_BACKUP_ENABLED": "false",
                "COMPOSE_PROFILES": profiles_with(env.get("COMPOSE_PROFILES", ""), "backup", False),
            })
            say("Automatic backups are off. Turn them on later with: scripts/nano backup-schedule --configure")
            return 0
        try:
            validate_updates(updates)
            probe_destination(Config(install_dir, {**env, **updates}))
            break
        except BackupError as error:
            say(f"Backup destination rejected: {error}")
            if not interactive or attempt == 2:
                raise
            # Re-ask from the top; nothing was written.
    marker_id = ""
    if updates["NANO_BACKUP_DESTINATION"] == "path":
        marker_id = env.get("NANO_BACKUP_DESTINATION_ID") or secrets.token_hex(16)
        write_destination_marker(pathlib.Path(updates["NANO_BACKUP_PATH"]), marker_id)
    ensure_keys(install_dir, prompter, say)
    state = install_dir / ".nano-backup" / "state"
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    updates.update({
        "NANO_BACKUP_ASKED": "true", "NANO_BACKUP_ENABLED": "true",
        "NANO_BACKUP_RECIPIENT_CERT": RECIPIENT_CERT, "NANO_BACKUP_SIGNING_KEY": SIGNING_KEY,
        "NANO_BACKUP_STATUS_TOKEN": env.get("NANO_BACKUP_STATUS_TOKEN") or secrets.token_hex(32),
        "NANO_BACKUP_PG_PASSWORD": env.get("NANO_BACKUP_PG_PASSWORD") or secrets.token_hex(32),
        "NANO_BACKUP_CH_PASSWORD": env.get("NANO_BACKUP_CH_PASSWORD") or secrets.token_hex(32),
        "NANO_BACKUP_UID": str(os.getuid()), "NANO_BACKUP_GID": str(os.getgid()),
        "NANO_BACKUP_TZ": host_timezone(), "NANO_INSTALL_DIR": str(install_dir),
        "NANO_BACKUP_DESTINATION_ID": marker_id,
        "COMPOSE_PROFILES": profiles_with(env.get("COMPOSE_PROFILES", ""), "backup", True),
    })
    write_env(env_path, updates)
    label = Config(install_dir, {**env, **updates}).destination_label()
    say(f"Automatic backups: daily at {updates['NANO_BACKUP_SCHEDULE']} ({updates['NANO_BACKUP_TZ']}) to {label}, "
        f"keeping {updates['NANO_BACKUP_KEEP']}; PostgreSQL, configuration and lookup tables.")
    return 0


def disable(install_dir: pathlib.Path) -> int:
    env_path = install_dir / ".env"
    env = read_env(env_path)
    # The service keeps running idle: it reports "disabled" to nano-api (the
    # host cannot reach the API's internal endpoint), which clears the
    # staleness banner. Re-enabling needs no Compose change.
    write_env(env_path, {"NANO_BACKUP_ASKED": "true", "NANO_BACKUP_ENABLED": "false"})
    log("automatic backups disabled; the nano-backup service now idles and reports it to nano")
    return 0


def show_status(install_dir: pathlib.Path) -> int:
    config = load_config(install_dir)
    path = status_file(config)
    data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    print(f"enabled:      {'yes' if config.enabled else 'no'}")
    if config.enabled:
        print(f"destination:  {config.destination_label()}")
        print(f"schedule:     daily {config.schedule} ({config.env.get('NANO_BACKUP_TZ', 'UTC')}), keep {config.keep}")
        print("scope:        PostgreSQL, configuration and ClickHouse lookup tables")
        if config.file(RECOVERY_KEY).exists():
            print(f"WARNING: the recovery key is still on this server: {config.file(RECOVERY_KEY)}")
    success, failure = data.get("last_success"), data.get("last_failure")
    print(f"last success: {success['finished_at'] + '  ' + success['backup_id'] + '  ' + str(success['size_bytes']) + ' bytes' if success else 'never'}")
    if failure:
        print(f"last failure: {failure['finished_at']}  {failure.get('error', '')}")
    if config.enabled:
        reference = success["finished_at"] if success else None
        if reference:
            age = dt.datetime.now(dt.timezone.utc) - dt.datetime.strptime(reference, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=dt.timezone.utc)
            if age > dt.timedelta(hours=STALE_HOURS):
                print(f"WARNING: no successful backup in {STALE_HOURS} hours")
    return 0


def fetch(install_dir: pathlib.Path, name: str, destination: pathlib.Path) -> int:
    config = load_config(install_dir)
    names = auto_names(config)
    if name == "latest":
        if not names:
            raise BackupError("the destination holds no automatic backups")
        name = names[-1]
    stem = name.removesuffix(".tar")
    if config.kind == "path":
        source = pathlib.Path(config.path) / stem
        if not source.is_dir():
            raise BackupError(f"no backup named {stem} in {config.path}")
        print(source)
        return 0
    if f"{stem}.tar" not in names:
        raise BackupError(f"no backup named {stem} in {config.destination_label()}")
    destination.mkdir(parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    archive = destination / f".{stem}.tar.partial"
    try:
        config.s3().download(f"{stem}.tar", archive)
        out = safe_extract(archive, destination)
    finally:
        with_suppressed(lambda: archive.unlink())
    print(out)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/nano backup-schedule")
    parser.add_argument("--install-dir", default=os.environ.get("NANO_INSTALL_DIR")
                        or str(pathlib.Path(__file__).resolve().parent.parent))
    sub = parser.add_subparsers(dest="command", required=True)
    configure_parser = sub.add_parser("configure")
    configure_parser.add_argument("--from-installer", action="store_true")
    sub.add_parser("disable")
    sub.add_parser("probe")
    sub.add_parser("serve")
    sub.add_parser("run-once")
    sub.add_parser("status")
    sub.add_parser("list")
    # Used by `scripts/nano backup` / `restore` on a role-split PostgreSQL
    # host, which has no ClickHouse role: lookup rows over the network.
    export_parser = sub.add_parser("lookup-export")
    export_parser.add_argument("--payload", required=True)
    import_parser = sub.add_parser("lookup-import")
    import_parser.add_argument("--payload", required=True)
    count_parser = sub.add_parser("lookup-count")
    count_parser.add_argument("--file", required=True)
    fetch_parser = sub.add_parser("fetch")
    fetch_parser.add_argument("name", help="backup name (nano-auto-...) or 'latest'")
    fetch_parser.add_argument("--to", required=True)
    args = parser.parse_args(argv)
    install_dir = pathlib.Path(args.install_dir).resolve()
    try:
        if args.command == "configure":
            return configure(install_dir, from_installer=args.from_installer, force=not args.from_installer)
        if args.command == "disable":
            return disable(install_dir)
        if args.command == "probe":
            probe_destination(load_config(install_dir))
            print("destination ok")
            return 0
        if args.command == "serve":
            return serve(install_dir)
        if args.command == "run-once":
            config = load_config(install_dir)
            if not config.enabled:
                raise BackupError("automatic backups are not configured; run scripts/nano backup-schedule --configure")
            status = run_once(config)
            if status["outcome"] == "elsewhere":
                raise BackupError("another app host is taking a backup right now; try again when it finishes")
            record_status(config, status)
            return {"success": 0, "partial": 3}.get(status["outcome"], 1)
        if args.command == "status":
            return show_status(install_dir)
        if args.command == "list":
            for name in auto_names(load_config(install_dir)):
                print(name)
            return 0
        if args.command == "lookup-count":
            print(native_lookup_counts(pathlib.Path(args.file))[1])
            return 0
        if args.command in {"lookup-export", "lookup-import"}:
            config = load_config(install_dir)
            db = Database(config, ch_only=True)
            payload = pathlib.Path(args.payload)
            if args.command == "lookup-export":
                db.provision_clickhouse()
                print(db.export_lookups(payload))
            else:
                print(db.import_lookups(payload))
            return 0
        if args.command == "fetch":
            return fetch(install_dir, args.name, pathlib.Path(args.to).resolve())
    except BackupError as error:
        log(str(error))
        return 1
    except OSError as error:
        log(f"{error.strerror or error}: {error.filename or ''}".rstrip(": "))
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())

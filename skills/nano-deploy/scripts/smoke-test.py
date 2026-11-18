#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""nano post-install smoke test: health -> login -> license -> ingest -> search.

Run it ON THE APP HOST (standard library only; secrets never leave the host and
are never printed):

  ssh USER@APP_HOST 'python3 -I - --app-url http://localhost' < smoke-test.py
  ssh USER@APP_HOST 'python3 -I - --app-url http://localhost --ingest-url http://10.0.0.12' < smoke-test.py

What it does, like the product's Add-source flow:
  1. GET  /api/health on the app URL (and GET /healthz on the ingest URL when it differs)
  2. POST /api/auth/login as the admin from --creds (default ~/.nano-admin-credentials)
  3. GET  /api/license and reports state / validity / expiry
  4. imports the first-party json_generic parser as a linked log source (reused if present),
     deploys it only if it is not deployed yet (--redeploy forces it), and issues a
     short-lived source-bound ingest token
  5. POSTs one JSON event with a unique marker to <ingest-url>/ingest/
  6. polls POST /api/search until the marker is found, and measures the write latency:
     the time from the accepted POST to the event being searchable. It FAILS when that
     exceeds --write-sla (default 60 s) even if the event arrives later: a write stall
     that outlasts a failover must not read as a pass. The search keeps polling until
     --timeout only to report how late the event was.
  7. optional: --hec posts one event to <ingest-url>/services/collector/event (with a
     channel, as every nano HEC request needs), --otlp posts one OTLP/HTTP protobuf log
     record to <ingest-url>/otlp/v1/logs. Each FAILS on a non-2xx answer; whether the
     event becomes searchable is reported as a WARN only (it depends on the source the
     token is bound to). --otlp-traces / --otlp-metrics post one span / one gauge point
     to /otlp/v1/traces and /otlp/v1/metrics and FAIL unless it shows up in the spans /
     metrics search dataset (the otel_spans / otel_metrics tables; no source involved).
     --otlp-grpc HOST:PORT sends one log record, span and gauge point over OTLP/gRPC to
     a raw Vector port (unauthenticated by design, loopback-bound by default; uses curl
     with HTTP2, else a pinned curl image through Docker, else WARNs as skipped).
     --otlp-auth-check asserts the /otlp edge answers 401 with no token and with an
     invalid one (every edition authenticates OTLP/HTTP at the edge).
     --otlp-all = all of the above, gRPC to 127.0.0.1:4317 when run on the app host
     (--app-url localhost) and --otlp-grpc is not given; an unreachable default port is a
     WARN (role-split and Helm hosts do not have it), and off the app host gRPC is skipped
     with a WARN unless --otlp-grpc names a target.
     The release post-build runs: smoke-test.py --hec --otlp-all
  8. revokes the token it issued (the log source is kept; it is harmless and reused)

Failover drills: run it while a host is down. Deploying a log source publishes a new
Vector configuration to every ingest host, so it never redeploys one that is
already deployed (the HA guide: make such changes in a quiet period).

TLS: https URLs are verified. Pass --ca-file for a private CA. There is no option
to skip verification.

Exit 0 = every required check passed; 1 = a check failed; 2 = usage error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

RESULTS: list[tuple[str, str, str]] = []


def add(check: str, status: str, detail: str) -> None:
    RESULTS.append((check, status, detail))
    print(f"{status:<4} {check:<10} {detail}", flush=True)


def read_env(path: str) -> dict:
    out: dict = {}
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                    v = v[1:-1]
                out[k.strip()] = v
    except FileNotFoundError:
        pass
    return out


def short(raw: bytes | str, n: int = 140) -> str:
    s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


class Client:
    def __init__(self, ca_file: str | None) -> None:
        self.ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        self.jwt = ""

    def http(self, method: str, url: str, body=None, headers=None, timeout: float = 60.0):
        data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as err:
            raw, status = err.read(), err.code
        except (urllib.error.URLError, OSError) as err:
            return 0, None, str(err).encode()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        return status, parsed, raw

    def api(self, method: str, base: str, path: str, body=None, timeout: float = 60.0):
        headers = {"Authorization": "Bearer " + self.jwt} if self.jwt else {}
        return self.http(method, base + path, body, headers, timeout)


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(num: int, payload: bytes) -> bytes:  # length-delimited (wire type 2)
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def _fixed64(num: int, value: int) -> bytes:  # wire type 1
    return _varint(num << 3 | 1) + value.to_bytes(8, "little")


def _double(num: int, value: float) -> bytes:  # wire type 1
    return _varint(num << 3 | 1) + struct.pack("<d", value)


def _any_str(v: str) -> bytes:
    return _field(1, v.encode())  # AnyValue.string_value


def _kv(key: str, value: str) -> bytes:
    return _field(1, key.encode()) + _field(2, _any_str(value))  # KeyValue


def _resource(service: str) -> bytes:
    return _field(1, _kv("service.name", service))  # Resource.attributes


def _scope() -> bytes:
    return _field(1, b"nano-deploy-smoke")  # InstrumentationScope.name


def otlp_logs_request(message: str, service: str = "nano-deploy-smoke") -> bytes:
    """A minimal OTLP ExportLogsServiceRequest (protobuf; nano's OTLP/HTTP
    endpoint answers 415 to JSON): one resource with service.name, one log
    record with time_unix_nano and a string body."""
    now = time.time_ns()
    record = (_fixed64(1, now)                                            # time_unix_nano
              + _fixed64(11, now)                                         # observed_time_unix_nano
              + _field(5, _any_str(message)))                             # body
    scope_logs = _field(2, record)                                        # ScopeLogs.log_records
    resource_logs = _field(1, _resource(service)) + _field(2, scope_logs)  # ResourceLogs
    return _field(1, resource_logs)                                       # ExportLogsServiceRequest


def otlp_traces_request(span_name: str, service: str, trace_id: bytes | None = None,
                        span_id: bytes | None = None) -> bytes:
    """A minimal OTLP ExportTraceServiceRequest: one resource with service.name,
    one SERVER span (16-byte trace_id, 8-byte span_id, 5 ms long, status OK)
    carrying the marker as its name and as a span attribute."""
    trace_id = trace_id or os.urandom(16)
    span_id = span_id or os.urandom(8)
    end = time.time_ns()
    span = (_field(1, trace_id) + _field(2, span_id)                      # trace_id, span_id
            + _field(5, span_name.encode())                               # name
            + _varint(6 << 3 | 0) + _varint(2)                            # kind = SPAN_KIND_SERVER
            + _fixed64(7, end - 5_000_000) + _fixed64(8, end)             # start/end_time_unix_nano
            + _field(9, _kv("nano.smoke_mark", span_name))                # attributes
            + _field(15, _varint(3 << 3 | 0) + _varint(1)))               # status.code = OK
    scope_spans = _field(1, _scope()) + _field(2, span)                   # ScopeSpans
    resource_spans = _field(1, _resource(service)) + _field(2, scope_spans)  # ResourceSpans
    return _field(1, resource_spans)                                      # ExportTraceServiceRequest


def otlp_metrics_request(metric_name: str, service: str, value: float = 42.0) -> bytes:
    """A minimal OTLP ExportMetricsServiceRequest: one resource with
    service.name, one gauge metric with one double data point."""
    now = time.time_ns()
    point = (_fixed64(3, now)                                             # NumberDataPoint.time_unix_nano
             + _double(4, value)                                          # as_double
             + _field(7, _kv("nano.smoke_mark", metric_name)))            # attributes
    metric = (_field(1, metric_name.encode())                             # Metric.name
              + _field(3, b"1")                                           # unit
              + _field(5, _field(1, point)))                              # gauge.data_points
    scope_metrics = _field(1, _scope()) + _field(2, metric)               # ScopeMetrics
    resource_metrics = _field(1, _resource(service)) + _field(2, scope_metrics)  # ResourceMetrics
    return _field(1, resource_metrics)                                    # ExportMetricsServiceRequest


# --- OTLP over gRPC --------------------------------------------------------------
# The standard library has no HTTP/2, so the gRPC sends use curl (HTTP/2 prior
# knowledge for h2c, ALPN for TLS): the host's curl when it was built with HTTP2,
# else a pinned curl image through Docker (Linux hosts: --network host is the
# host's loopback only there). Neither available -> the gRPC checks WARN as skipped. curl reports gRPC trailers in its header dump.
GRPC_METHODS = {
    "logs": "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
    "traces": "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
    "metrics": "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
}
CURL_IMAGE = "curlimages/curl:8.16.0@sha256:463eaf6072688fe96ac64fa623fe73e1dbe25d8ad6c34404a669ad3ce1f104b6"
GRPC_DEFAULT = "127.0.0.1:4317"
LOOPBACK = ("localhost", "127.0.0.1", "::1")
HEC_PORT = 8088  # Vector's HEC listener on a single-host install


def grpc_target(value: str) -> tuple[str, str]:
    """--otlp-grpc value -> (scheme, host:port). Accepts HOST:PORT, [IPv6]:PORT,
    and an optional http:// (plaintext h2c, the default) or https:// prefix."""
    scheme, sep, rest = value.partition("://")
    if not sep:
        scheme, rest = "http", value
    if scheme not in ("http", "https"):
        raise argparse.ArgumentTypeError(f"--otlp-grpc scheme must be http or https, got {value!r}")
    rest = rest.rstrip("/")
    host, colon, port = rest.rpartition(":")
    if not colon or not host or not port.isdigit() or not 0 < int(port) < 65536 or "/" in rest:
        raise argparse.ArgumentTypeError(f"--otlp-grpc expects HOST:PORT, got {value!r}")
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        raise argparse.ArgumentTypeError(f"--otlp-grpc: write an IPv6 address as [ADDR]:PORT, got {value!r}")
    return scheme, rest


def grpc_frame(message: bytes) -> bytes:
    """gRPC length-prefixed message: uncompressed flag + 4-byte big-endian length."""
    return b"\x00" + len(message).to_bytes(4, "big") + message


def grpc_runner(run=subprocess.run, which=shutil.which) -> list[str] | None:
    """The curl command prefix to use, or None when no HTTP/2-capable curl exists."""
    curl = which("curl")
    if curl:
        try:
            out = run([curl, "-V"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        if "HTTP2" in out.split("Features:", 1)[-1]:
            return [curl]
    docker = which("docker")
    if docker:
        try:
            ok = run([docker, "version", "--format", "{{.Server.Version}}"],
                     capture_output=True, text=True, timeout=20).returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
        if ok:
            return [docker, "run", "--rm", "-i", "--network", "host", CURL_IMAGE]
    return None


def parse_grpc_reply(dump: str) -> tuple[int, int | None, str]:
    """curl -D output (headers, then trailers) -> (http status, grpc-status, grpc-message)."""
    http, gstatus, gmsg = 0, None, ""
    for line in dump.splitlines():
        line = line.strip()
        if line.upper().startswith("HTTP/"):
            parts = line.split()
            http = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            continue
        key, sep, val = line.partition(":")
        if not sep:
            continue
        key, val = key.strip().lower(), val.strip()
        if key == "grpc-status" and val.isdigit():
            gstatus = int(val)
        elif key == "grpc-message":
            gmsg = urllib.parse.unquote(val)
    return http, gstatus, gmsg


def grpc_send(runner: list[str], target: tuple[str, str], signal: str, message: bytes,
              ca_file: str | None = None, run=subprocess.run) -> tuple[bool, str]:
    """One unary OTLP Export call. Returns (ok, detail); ok = HTTP 200 and grpc-status 0."""
    scheme, hostport = target
    cmd = list(runner)
    if ca_file and scheme == "https":
        if runner[0].endswith("docker"):
            cmd[-1:-1] = ["-v", f"{os.path.abspath(ca_file)}:/tmp/nano-ca.pem:ro"]
            ca_file = "/tmp/nano-ca.pem"
        cmd += ["--cacert", ca_file]
    cmd += ["-sS", "--max-time", "30", "-o", "/dev/null", "-D", "-", "-X", "POST",
            "--http2-prior-knowledge" if scheme == "http" else "--http2",
            "-H", "Content-Type: application/grpc", "-H", "TE: trailers",
            "--data-binary", "@-", f"{scheme}://{hostport}{GRPC_METHODS[signal]}"]
    try:
        proc = run(cmd, input=grpc_frame(message), capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as err:
        return False, f"could not run curl: {err}"
    out = proc.stdout.decode("utf-8", "replace")
    http, gstatus, gmsg = parse_grpc_reply(out)
    if proc.returncode != 0 and not http:
        return False, f"curl exit {proc.returncode}: {short(proc.stderr, 120)}"
    ok = http == 200 and gstatus == 0
    return ok, f"HTTP {http} grpc-status={gstatus}" + (f" {short(gmsg, 80)}" if gmsg else "")


def install_resolve(pairs: list[str]) -> None:
    """--resolve HOST:IP: pin HOST to IP for every connection (TLS still
    verifies the certificate for HOST)."""
    pins = {}
    for pair in pairs:
        host, sep, ip = pair.partition(":")  # a hostname has no ':'; the IP may be IPv6
        port, colon, rest = ip.partition(":")
        if colon and port.isdigit() and rest:  # curl form HOST:PORT:IP
            ip = rest
        if not sep or not host or not ip:
            raise SystemExit(f"--resolve expects HOST:IP, got {pair!r}")
        pins[host.lower()] = ip.strip("[]")
    if not pins:
        return
    real = socket.getaddrinfo

    def pinned(host, *args, **kwargs):
        return real(pins.get(str(host).lower(), host), *args, **kwargs)
    socket.getaddrinfo = pinned


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app-url", default="http://localhost")
    ap.add_argument("--ingest-url", help="base URL of an ingest frontend (default: the app URL)")
    ap.add_argument("--creds", default="~/.nano-admin-credentials")
    ap.add_argument("--env-file", default="~/nano/.env", help="read only for NANO_SCHEMA_PROFILE")
    ap.add_argument("--profile", choices=["ocsf", "udm"])
    ap.add_argument("--ca-file")
    ap.add_argument("--timeout", type=int, default=240,
                    help="seconds to keep polling search, to report how late a stalled write lands")
    ap.add_argument("--write-sla", type=int, default=60,
                    help="FAIL when the event takes longer than this many seconds to become searchable")
    ap.add_argument("--redeploy", action="store_true",
                    help="deploy the smoke log source even if it is already deployed (never during a failover drill)")
    ap.add_argument("--require-license", "--require-licence", dest="require_licence", action="store_true",
                    help="fail (not warn) when the license is not valid (--require-licence is the original spelling, still accepted)")
    ap.add_argument("--resolve", action="append", default=[], metavar="HOST:IP",
                    help="connect to IP for HOST, keeping HOST for TLS/SNI and the Host header "
                         "(repeatable). Also accepts curl's HOST:PORT:IP form (the port is ignored: "
                         "every port of HOST goes to IP). E.g. before DNS points at the load balancers")
    ap.add_argument("--hec", action="store_true", help="also send one event through HEC (/services/collector/event)")
    ap.add_argument("--hec-url", help="base URL for --hec (default: the ingest URL; on a single-host install, where "
                                      f"nginx does not proxy HEC, a 404/405 there retries on http://127.0.0.1:{HEC_PORT} when run on the app host)")
    ap.add_argument("--otlp", action="store_true", help="also send one OTLP/HTTP protobuf log record (/otlp/v1/logs)")
    ap.add_argument("--otlp-traces", action="store_true",
                    help="also send one OTLP/HTTP protobuf span (/otlp/v1/traces) and find it in the spans dataset")
    ap.add_argument("--otlp-metrics", action="store_true",
                    help="also send one OTLP/HTTP protobuf gauge point (/otlp/v1/metrics) and find it in the metrics dataset")
    ap.add_argument("--otlp-grpc", type=grpc_target, metavar="HOST:PORT",
                    help="also send one log record, span and gauge point over OTLP/gRPC to this raw Vector port "
                         "(http:// h2c by default; https:// for TLS). Needs curl with HTTP2 or Docker")
    ap.add_argument("--otlp-auth-check", action="store_true",
                    help="check the /otlp edge refuses a request with no token and with an invalid token (401)")
    ap.add_argument("--otlp-all", action="store_true",
                    help="--otlp --otlp-traces --otlp-metrics --otlp-auth-check, plus gRPC to "
                         f"{GRPC_DEFAULT} when --app-url is this host and --otlp-grpc is not given (a WARN, not a "
                         "FAIL, when that port is not there; skipped with a WARN when --app-url is another host)")
    a = ap.parse_args()
    grpc_explicit = a.otlp_grpc is not None
    grpc_skipped = ""
    if a.otlp_all:
        a.otlp = a.otlp_traces = a.otlp_metrics = a.otlp_auth_check = True
        if not grpc_explicit:
            # The raw OTLP/gRPC port binds loopback on the app host. Run from
            # anywhere else (a laptop against Helm), 127.0.0.1:4317 is not nano's.
            if urllib.parse.urlsplit(a.app_url).hostname in LOOPBACK:
                a.otlp_grpc = grpc_target(GRPC_DEFAULT)
            else:
                grpc_skipped = (f"skipped: --app-url is not this host, so {GRPC_DEFAULT} is not nano's raw OTLP/gRPC "
                                "port; pass --otlp-grpc HOST:PORT to test gRPC")
    install_resolve(a.resolve)
    app = a.app_url.rstrip("/")
    ingest = (a.ingest_url or a.app_url).rstrip("/")
    c = Client(a.ca_file)

    # 1. health
    st, _, raw = c.http("GET", app + "/api/health")
    add("health", "PASS" if st == 200 else "FAIL", f"GET {app}/api/health -> {st} {short(raw, 60)}")
    if ingest != app:
        # Readiness briefly drops to 503 while an ingest host installs a new config
        # generation; require 200 within 60 s rather than on the first probe.
        deadline, tries = time.time() + 60, 0
        while True:
            tries += 1
            st, _, raw = c.http("GET", ingest + "/healthz")
            if st == 200 or time.time() > deadline:
                break
            time.sleep(5)
        add("ingest-hz", "PASS" if st == 200 else "FAIL", f"GET {ingest}/healthz -> {st} {short(raw, 60)} (probes={tries})")

    # 2. login
    creds = read_env(a.creds)
    email, password = creds.get("NANO_ADMIN_EMAIL", ""), creds.get("NANO_ADMIN_PASSWORD", "")
    if not email or not password:
        add("login", "FAIL", f"no NANO_ADMIN_EMAIL/NANO_ADMIN_PASSWORD in {a.creds}")
        return finish()
    st, data, raw = c.http("POST", app + "/api/auth/login", {"email": email, "password": password})
    password = ""
    token = ((data or {}).get("tokens") or {}).get("access_token") if isinstance(data, dict) else None
    c.jwt = token or ""
    add("login", "PASS" if token else "FAIL", f"admin {email} -> {st}" + ("" if token else f" {short(raw, 80)}"))
    if not token:
        return finish()

    # 3. license
    st, data, raw = c.api("GET", app, "/api/license")
    if st == 200 and isinstance(data, dict):
        ent = data.get("entitlement") or {}
        # /api/license carries an `entitlement` object only for an evaluation
        # license; an online or offline paid license reports its contracted
        # capacity through /api/license/usage. Print what is known, never "None".
        capacity = ent.get("capacity_gb_per_day")
        if capacity is None:
            ust, usage, _ = c.api("GET", app, "/api/license/usage")
            if ust == 200 and isinstance(usage, dict):
                capacity = usage.get("capacity_gb_per_day")
        known = {"state": data.get("state"), "valid": data.get("valid"), "mode": data.get("mode"),
                 "enforcement": data.get("enforcement_enabled"), "tier": data.get("tier"),
                 "expires": data.get("expires_at") or ent.get("expires_at"), "offering": ent.get("offering")}
        fields = [f"{key}={value}" for key, value in known.items() if value is not None and value != ""]
        fields.append(f"capacity_gb_day={capacity:g}" if isinstance(capacity, (int, float))
                      else "capacity_gb_day=not set")
        if data.get("locked_reason"):
            fields.append(f"locked_reason={data['locked_reason']}")
        detail = " ".join(fields)
        # "valid" alone is not proof of a license: an install with no license configured
        # can report state=active with no entitlement, expiry or license id bound to it.
        bound = bool(ent or data.get("expires_at") or data.get("license_id"))
        ok = bool(data.get("valid")) and bound
        if data.get("valid") and not bound:
            detail += " -> NO LICENSE BOUND (no entitlement/expiry): enrollment not applied or not reaching the API"
        add("license", "PASS" if ok else ("FAIL" if a.require_licence else "WARN"), detail)
    else:
        add("license", "FAIL" if a.require_licence else "WARN", f"GET /api/license -> {st} {short(raw, 80)}")

    # 4. source + token
    profile = a.profile or read_env(a.env_file).get("NANO_SCHEMA_PROFILE") or "ocsf"
    parser_path = "parsers-ocsf/json_generic/parser.yaml" if profile == "ocsf" else "parsers/json_generic/parser.yaml"
    st, data, raw = c.api("GET", app, "/api/parser-repositories")
    repos = (data or {}).get("repositories", []) if isinstance(data, dict) else []
    repo = next((r for r in repos if "nano-rs/parsers" in (r.get("url") or "")), repos[0] if repos else None)
    if not repo:
        add("source", "FAIL", f"no parser repository registered ({st} {short(raw, 80)})")
        return finish()
    rid = repo["id"]
    if not repo.get("parser_count"):
        c.api("POST", app, f"/api/parser-repositories/{rid}/sync")
    deadline, count = time.time() + 300, 0
    while time.time() < deadline:
        st, data, _ = c.api("GET", app, f"/api/parser-repositories/{rid}/sync/status")
        count = (data or {}).get("parser_count") or 0
        if count and (data or {}).get("status") not in ("syncing", "pending", "running"):
            break
        time.sleep(5)
    if not count:
        add("source", "FAIL", "first-party parser repository did not sync (outbound access to GitHub?)")
        return finish()
    st, data, _ = c.api("GET", app, f"/api/parser-repositories/{rid}/parsers?limit=500")
    parsers = data if isinstance(data, list) else (data or {}).get("parsers", [])
    entry = next((p for p in parsers if (p.get("parser") or p).get("file_path") == parser_path), None)
    if entry is None:
        add("source", "FAIL", f"{parser_path} not in the parser catalog")
        return finish()
    log_source_id = entry.get("linked_log_source_id")
    if not log_source_id:
        path = urllib.parse.quote(parser_path, safe="")
        st, data, raw = c.api("POST", app, f"/api/parser-repositories/{rid}/parsers/import/{path}",
                              {"import_type": "linked", "source_type": "json_generic", "ingestion_method": "routed"})
        log_source_id = (data or {}).get("log_source_id") if isinstance(data, dict) else None
        if not log_source_id:
            add("source", "FAIL", f"import {parser_path} -> {st} {short(raw, 100)}")
            return finish()
    deployed, attempts = False, 0
    already = False
    if not a.redeploy:
        st, data, _ = c.api("GET", app, f"/api/log-sources/{log_source_id}")
        src = (data.get("log_source") or data.get("data") or data) if isinstance(data, dict) else {}
        already = st == 200 and isinstance(src, dict) and src.get("deployed") is True and src.get("enabled", True) is not False
    if already:
        deployed = True
        add("source", "PASS", f"json_generic ({profile}) log source {log_source_id} already deployed (not redeployed)")
    while not deployed and attempts < 3:  # deploy is idempotent; small hosts can time out transiently
        attempts += 1
        st, data, raw = c.api("POST", app, f"/api/log-sources/{log_source_id}/deploy", {}, timeout=180)
        deployed = st == 200 and (not isinstance(data, dict) or data.get("success", True) is not False)
        if not deployed and attempts < 3:
            time.sleep(15)
    # In 2.0.x role-split installs the app host has no local Vector, so deploy can report
    # success=false ("No reload was delivered to Vector") even though the new config
    # generation reaches every ingest host. Ingest -> search below is the real proof.
    if not already:
        add("source", "PASS" if deployed else "WARN",
            f"json_generic ({profile}) log source {log_source_id} deploy -> {st} (attempts={attempts})"
            + ("" if deployed else f" reported not deployed: {short(raw, 200)}; continuing, ingest->search decides"))
        if st != 200:
            return finish()
    run = "nds" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    st, data, raw = c.api("POST", app, "/api/ingest-tokens", {"name": f"{run}-smoke", "source_id": log_source_id})
    ingest_token = (data or {}).get("token") if isinstance(data, dict) else None
    cred = ((data or {}).get("credential") or {}) if isinstance(data, dict) else {}
    cred_id = cred.get("credential_id") or cred.get("id")
    add("token", "PASS" if ingest_token else "FAIL", f"source-bound ingest token issued -> {st} (value not shown)")
    if not ingest_token:
        return finish()

    try:
        # 5. ingest
        mark = f"{run}-mark"
        event = {"timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "message": f"nano-deploy smoke test {mark}", "smoke_mark": mark,
                 "src_ip": "10.1.2.3", "dest_ip": "10.4.5.6", "dest_port": 443, "action": "allow",
                 "hostname": "nano-deploy-smoke"}
        accepted, deadline, t_accept = None, time.time() + 90, None
        while time.time() < deadline:
            st, _, raw = c.http("POST", ingest + "/ingest/", event,
                                {"Authorization": "Bearer " + ingest_token, "X-Source-Type": "json_generic"})
            accepted = st
            if 200 <= st < 300:
                t_accept = time.time()
                break
            time.sleep(5)  # token and parser deploy propagate to Vector within seconds
        add("ingest", "PASS" if accepted and 200 <= accepted < 300 else "FAIL",
            f"POST {ingest}/ingest/ -> {accepted}" + ("" if accepted and 200 <= accepted < 300 else f" {short(raw, 80)}"))
        if not (accepted and 200 <= accepted < 300):
            return finish()

        # 6. search
        start = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat().replace("+00:00", "Z")
        t0 = t_accept or time.time()
        found, deadline = 0, t0 + max(a.timeout, a.write_sla)
        while time.time() < deadline and not found:
            end = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
            st, data, raw = c.api("POST", app, "/api/search", {
                "query": f'"{mark}"', "time_range": {"start": start, "end": end}, "limit": 10,
                "skip_field_stats": True, "skip_histogram": True})
            results = (data or {}).get("results") or [] if isinstance(data, dict) else []
            found = sum(1 for r in results if mark in json.dumps(r))
            if not found:
                time.sleep(2)
        latency = time.time() - t0
        on_time = found and latency <= a.write_sla
        detail = f'search "{mark}" -> {found} hit(s); write latency {latency:.0f}s (bound {a.write_sla}s)'
        if found and not on_time:
            detail += " -> WRITES STALLED: the event landed late. Check cluster-health.py on every host (gateways)"
        elif not found:
            detail += f" -> not searchable after {latency:.0f}s, last status {st}"
        add("search", "PASS" if on_time else "FAIL", detail)
        add("latency", "PASS" if on_time else "FAIL", f"write_latency_seconds={latency:.1f} bound={a.write_sla}")

        # 7. optional protocols: HEC and OTLP/HTTP through the same ingest frontend.
        def searchable(marker: str, wait: float = 60.0, dataset: str | None = None, query: str | None = None) -> int:
            """Hits for `marker` in the logs dataset (default) or in `dataset`
            (spans / metrics: the OTLP tables, searched with `query`)."""
            end_t = time.time() + wait
            while time.time() < end_t:
                end = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
                body = {"query": query or f'"{marker}"', "time_range": {"start": start, "end": end}, "limit": 10,
                        "skip_field_stats": True, "skip_histogram": True}
                if dataset:
                    body["dataset"] = dataset
                _, data, _ = c.api("POST", app, "/api/search", body)
                hits = (data or {}).get("results") or [] if isinstance(data, dict) else []
                n = sum(1 for r in hits if marker in json.dumps(r))
                if n:
                    return n
                time.sleep(3)
            return 0

        if a.hec:
            hmark = f"{run}-hec"
            body = json.dumps({"event": {"message": f"nano-deploy smoke test {hmark}", "smoke_mark": hmark,
                                         "hostname": "nano-deploy-smoke"}, "sourcetype": "_json"}).encode()
            hec_base = (a.hec_url or ingest).rstrip("/")
            hec_headers = {"Authorization": "Splunk " + ingest_token}
            st, data, raw = c.http("POST", hec_base + "/services/collector/event", body,
                                   dict(hec_headers, **{"X-Splunk-Request-Channel": str(uuid.uuid4())}))
            if (st in (404, 405) and not a.hec_url and ingest == app
                    and urllib.parse.urlsplit(app).hostname in LOOPBACK):
                # A single-host install serves HEC on Vector's own plain-HTTP port, not
                # through nginx (only a role-split ingest edge proxies
                # /services/collector). Retry only on this host: off the host the token
                # would cross the network in cleartext; pass --hec-url there.
                hec_base = f"http://127.0.0.1:{HEC_PORT}"
                st, data, raw = c.http("POST", hec_base + "/services/collector/event", body,
                                       dict(hec_headers, **{"X-Splunk-Request-Channel": str(uuid.uuid4())}))
            ok = 200 <= st < 300 and (not isinstance(data, dict) or data.get("code", 0) == 0)
            add("hec", "PASS" if ok else "FAIL", f"POST {hec_base}/services/collector/event -> {st} {short(raw, 80)}")
            if ok:
                n = searchable(hmark)
                add("hec-search", "PASS" if n else "WARN",
                    f'search "{hmark}" -> {n} hit(s)' + ("" if n else " (accepted but not searchable within 60 s:"
                                                         " check the token's source and its parser)"))
        if a.otlp:
            omark = f"{run}-otlp"
            st, _, raw = c.http("POST", ingest + "/otlp/v1/logs", otlp_logs_request(f"nano-deploy smoke test {omark}"),
                                {"Authorization": "Bearer " + ingest_token, "Content-Type": "application/x-protobuf"})
            ok = 200 <= st < 300
            add("otlp", "PASS" if ok else "FAIL", f"POST {ingest}/otlp/v1/logs (protobuf) -> {st} {short(raw, 80)}")
            if ok:
                n = searchable(omark)
                add("otlp-search", "PASS" if n else "WARN",
                    f'search "{omark}" -> {n} hit(s)' + ("" if n else " (accepted but not searchable within 60 s)"))
        # Spans and metrics do not depend on the token's source (they land in the
        # otel_spans / otel_metrics tables whatever the credential), so an
        # accepted record that never shows up in its dataset is a FAIL.
        otlp_headers = {"Authorization": "Bearer " + ingest_token, "Content-Type": "application/x-protobuf"}
        if a.otlp_traces:
            tmark = f"{run}-otlptr"
            st, _, raw = c.http("POST", ingest + "/otlp/v1/traces", otlp_traces_request(tmark, tmark), otlp_headers)
            ok = 200 <= st < 300
            add("otlp-trace", "PASS" if ok else "FAIL", f"POST {ingest}/otlp/v1/traces (protobuf) -> {st} {short(raw, 80)}")
            if ok:
                n = searchable(tmark, 90, "spans", f'service_name="{tmark}"')
                add("otlp-spans", "PASS" if n else "FAIL", f'spans: service_name="{tmark}" -> {n} span(s)'
                    + ("" if n else " (accepted but not in the spans dataset within 90 s)"))
        if a.otlp_metrics:
            mmark = f"{run}-otlpmx"
            st, _, raw = c.http("POST", ingest + "/otlp/v1/metrics", otlp_metrics_request(mmark, mmark), otlp_headers)
            ok = 200 <= st < 300
            add("otlp-metric", "PASS" if ok else "FAIL", f"POST {ingest}/otlp/v1/metrics (protobuf) -> {st} {short(raw, 80)}")
            if ok:
                n = searchable(mmark, 90, "metrics", f'metric_name="{mmark}"')
                add("otlp-points", "PASS" if n else "FAIL", f'metrics: metric_name="{mmark}" -> {n} point(s)'
                    + ("" if n else " (accepted but not in the metrics dataset within 90 s)"))
        if grpc_skipped:
            add("grpc", "WARN", grpc_skipped)
        elif a.otlp_grpc:
            grpc_checks(a, c_search=searchable, run=run, grpc_explicit=grpc_explicit)
        if a.otlp_auth_check:
            otlp_auth_check(c, ingest)
    finally:
        # 8. cleanup
        if cred_id:
            st = c.api("POST", app, f"/api/ingest-tokens/{cred_id}/revoke", {})[0]
            add("cleanup", "PASS" if st in (200, 204) else "WARN", f"revoked smoke token -> {st}")
    return finish()


def grpc_checks(a, c_search, run: str, grpc_explicit: bool) -> None:
    """OTLP/gRPC to the raw Vector port: logs, traces, metrics. That port has no
    credential gate (it binds loopback by default), so the log record lands in the
    generic OTLP lane (source_type otlp_log), not in a token's source."""
    scheme, hostport = a.otlp_grpc
    runner = grpc_runner()
    if runner is None:
        add("grpc", "WARN", "skipped: no curl with HTTP2 and no Docker on this host (OTLP/gRPC not tested)")
        return
    label = f"{scheme}://{hostport}"
    marks = {"logs": f"{run}-grpclog", "traces": f"{run}-grpctr", "metrics": f"{run}-grpcmx"}
    bodies = {"logs": otlp_logs_request(f"nano-deploy smoke test {marks['logs']}", marks["logs"]),
              "traces": otlp_traces_request(marks["traces"], marks["traces"]),
              "metrics": otlp_metrics_request(marks["metrics"], marks["metrics"])}
    sent = {}
    for signal in ("logs", "traces", "metrics"):
        ok, detail = grpc_send(runner, a.otlp_grpc, signal, bodies[signal], a.ca_file)
        if not ok and not grpc_explicit:
            # 7 = connection refused, 28 = timeout; 125 = docker could not start the
            # curl image (no registry access): the default target is a best effort.
            if detail.startswith(("curl exit 7:", "curl exit 28:")):
                add("grpc", "WARN", f"{label} not reachable ({detail}); on a role-split or Helm install pass "
                                    "--otlp-grpc HOST:PORT of an ingest host's OTLP/gRPC port")
                return
            if detail.startswith("curl exit 125:"):
                add("grpc", "WARN", f"skipped: Docker could not run {CURL_IMAGE.split('@')[0]} ({detail})")
                return
        sent[signal] = ok
        add(f"grpc-{signal}", "PASS" if ok else "FAIL", f"{label}{GRPC_METHODS[signal]} -> {detail}")
    if sent.get("logs"):
        n = c_search(marks["logs"])
        add("grpc-lsrch", "PASS" if n else "WARN", f'search "{marks["logs"]}" -> {n} hit(s)'
            + ("" if n else " (accepted but not searchable within 60 s: the unauthenticated OTLP log lane"
               " needs a deployed parser or the generic lane)"))
    if sent.get("traces"):
        n = c_search(marks["traces"], 90, "spans", f'service_name="{marks["traces"]}"')
        add("grpc-spans", "PASS" if n else "FAIL", f'spans: service_name="{marks["traces"]}" -> {n} span(s)')
    if sent.get("metrics"):
        n = c_search(marks["metrics"], 90, "metrics", f'metric_name="{marks["metrics"]}"')
        add("grpc-points", "PASS" if n else "FAIL", f'metrics: metric_name="{marks["metrics"]}" -> {n} point(s)')


def otlp_auth_check(c: "Client", ingest: str) -> None:
    """The /otlp edge authenticates a source-bound ingest token on every request
    (nginx auth_request -> nano-api /api/internal/otlp-auth), the same in the open
    and enterprise editions: no token or an unknown token -> 401. A 2xx means the
    edge accepted OTLP with no valid credential (FAIL)."""
    cases = [("none", "logs", None), ("none", "traces", None), ("none", "metrics", None),
             ("invalid", "logs", "Bearer nds-invalid-" + uuid.uuid4().hex)]
    bodies = {"logs": otlp_logs_request("nano-deploy smoke auth probe"),
              "traces": otlp_traces_request("nano-deploy-smoke-auth-probe", "nano-deploy-smoke"),
              "metrics": otlp_metrics_request("nano_deploy_smoke_auth_probe", "nano-deploy-smoke")}
    for kind, signal, auth in cases:
        headers = {"Content-Type": "application/x-protobuf"}
        if auth:
            headers["Authorization"] = auth
        st, _, raw = c.http("POST", f"{ingest}/otlp/v1/{signal}", bodies[signal], headers)
        if st == 401:
            status, note = "PASS", "refused"
        elif 200 <= st < 300:
            status, note = "FAIL", "ACCEPTED WITHOUT A VALID CREDENTIAL"
        elif st == 404:
            status, note = "FAIL", "no /otlp route on this ingest URL"
        else:
            status, note = "WARN", "expected 401"
        add("otlp-auth", status, f"{kind} token POST /otlp/v1/{signal} -> {st} ({note}) {short(raw, 60)}".rstrip())


def finish() -> int:
    fails = [r for r in RESULTS if r[1] == "FAIL"]
    print(f"SMOKE {'PASS' if not fails else 'FAIL'} checks={len(RESULTS)} failed={len(fails)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""nano post-install smoke test: health -> login -> licence -> ingest -> search.

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
  7. revokes the token it issued (the log source is kept; it is harmless and reused)

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
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

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
    ap.add_argument("--require-licence", action="store_true", help="fail (not warn) when the licence is not valid")
    a = ap.parse_args()
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

    # 3. licence
    st, data, raw = c.api("GET", app, "/api/license")
    if st == 200 and isinstance(data, dict):
        ent = data.get("entitlement") or {}
        detail = (f"state={data.get('state')} valid={data.get('valid')} mode={data.get('mode')} "
                  f"enforcement={data.get('enforcement_enabled')} tier={data.get('tier')} "
                  f"expires={data.get('expires_at') or ent.get('expires_at')} "
                  f"offering={ent.get('offering')} capacity_gb_day={ent.get('capacity_gb_per_day')} "
                  f"locked_reason={data.get('locked_reason')}")
        # "valid" alone is not proof of a licence: an install with no licence configured
        # can report state=active with no entitlement, expiry or licence id bound to it.
        bound = bool(ent or data.get("expires_at") or data.get("license_id"))
        ok = bool(data.get("valid")) and bound
        if data.get("valid") and not bound:
            detail += " -> NO LICENCE BOUND (no entitlement/expiry): enrollment not applied or not reaching the API"
        add("licence", "PASS" if ok else ("FAIL" if a.require_licence else "WARN"), detail)
    else:
        add("licence", "FAIL" if a.require_licence else "WARN", f"GET /api/license -> {st} {short(raw, 80)}")

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
    finally:
        # 7. cleanup
        if cred_id:
            st = c.api("POST", app, f"/api/ingest-tokens/{cred_id}/revoke", {})[0]
            add("cleanup", "PASS" if st in (200, 204) else "WARN", f"revoked smoke token -> {st}")
    return finish()


def finish() -> int:
    fails = [r for r in RESULTS if r[1] == "FAIL"]
    print(f"SMOKE {'PASS' if not fails else 'FAIL'} checks={len(RESULTS)} failed={len(fails)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

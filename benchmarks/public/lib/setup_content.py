#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Load the public benchmark's content into a fresh nano install.

Runs ON THE APP HOST (standard library only). Secrets are written to 0600
files under --out and are never printed:

  ssh APP 'python3 -I - --out ~/bench --rules -' < setup_content.py   # (rules via a 2nd file, see run.sh)

What it does, through the product API only (the same calls the UI makes):
  1. logs in as the admin from ~/.nano-admin-credentials
  2. syncs the first-party parser catalog and, for every benchmark source type,
     imports the matching OCSF parser as a linked log source and deploys it
  3. mints one ingest token per source type -> <out>/tokens.json
     (nano v2 binds each token to one log source; log-blaster --tokens-file)
  4. creates a search API key -> <out>/api.env (API_KEY=...)
  5. creates the detection rule set from --rules (skips names that exist)
  6. optional --agentlane N: enables Agent Lane and mints N agent tokens ->
     <out>/agentlane.json (enterprise + license; the listener must already be
     configured at install time)
  7. writes <out>/content.json: what was loaded, ids, versions (no secrets)

Exit 0 when every required step passed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Benchmark source type -> candidate OCSF parser directory names in the
# first-party catalog (nano-rs/parsers, parsers-ocsf/<dir>/parser.yaml). The
# first candidate present wins; the chosen path is recorded in content.json.
SOURCES = {
    "windows_sysmon": ["windows_sysmon", "microsoft_sysmon_json", "sysmon"],
    "windows_event": ["windows_event", "windows_event_log"],
    "conduit_proxy": ["conduit_proxy", "conduit_mitm_proxy"],
    "apache_access": ["apache", "apache_http_server", "apache_access"],
    "aws_cloudtrail": ["aws_cloudtrail", "cloudtrail"],
    # Marker records (log-blaster --run-id): any JSON parser that keeps the
    # raw record as `message`.
    "bench_marker": ["json_generic"],
}

SEARCH_KEY_PERMS = ["search:view", "search:execute", "dashboards:view", "detections:view", "alerts:view"]


def log(msg: str) -> None:
    print(f"[setup] {msg}", flush=True)


def read_env(path: str) -> dict:
    out = {}
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


def write_secret(path: str, text: str) -> None:
    path = os.path.expanduser(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


class Api:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.jwt = ""
        self.creds: dict | None = None

    def login(self, creds: dict):
        """Log in; kept so a long run (parser deploys can take 15+ min on a
        multi-host cluster) re-authenticates when the access token expires."""
        self.creds, self.jwt = creds, ""
        st, data, raw = self.call("POST", "/api/auth/login",
                                  {"email": creds.get("NANO_ADMIN_EMAIL", ""), "password": creds.get("NANO_ADMIN_PASSWORD", "")})
        self.jwt = (((data or {}).get("tokens") or {}).get("access_token") or "") if isinstance(data, dict) else ""
        return st, raw

    def call(self, method: str, path: str, body=None, timeout: float = 120.0):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self.jwt:
            headers["Authorization"] = "Bearer " + self.jwt
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as err:
            raw, status = err.read(), err.code
        except (urllib.error.URLError, OSError) as err:
            return 0, None, str(err)
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        if status == 401 and self.jwt and self.creds and not path.startswith("/api/auth/"):
            self.login(self.creds)  # expired access token: log in again once, then retry
            if self.jwt:
                return self.call(method, path, body, timeout)
        return status, parsed, raw.decode("utf-8", "replace")[:300]


def find_repo(api: Api) -> str:
    st, data, raw = api.call("GET", "/api/parser-repositories")
    repos = (data or {}).get("repositories", []) if isinstance(data, dict) else (data or [])
    repo = next((r for r in repos if "nano-rs/parsers" in (r.get("url") or "")), repos[0] if repos else None)
    if not repo:
        raise SystemExit(f"no parser repository registered ({st} {raw})")
    rid = repo["id"]
    if not repo.get("parser_count"):
        api.call("POST", f"/api/parser-repositories/{rid}/sync")
    deadline = time.time() + 300
    while time.time() < deadline:
        _, s, _ = api.call("GET", f"/api/parser-repositories/{rid}/sync/status")
        if (s or {}).get("parser_count") and (s or {}).get("status") not in ("syncing", "pending", "running"):
            return rid
        time.sleep(5)
    raise SystemExit("first-party parser catalog did not sync (outbound access to GitHub?)")


def catalog(api: Api, rid: str) -> list:
    _, data, _ = api.call("GET", f"/api/parser-repositories/{rid}/parsers?limit=1000")
    return data if isinstance(data, list) else (data or {}).get("parsers", [])


def ensure_source(api: Api, rid: str, parsers: list, source_type: str, profile: str) -> dict:
    root = "parsers-ocsf" if profile == "ocsf" else "parsers"
    by_path = {(p.get("parser") or p).get("file_path"): p for p in parsers}
    path = next((f"{root}/{d}/parser.yaml" for d in SOURCES[source_type]
                 if f"{root}/{d}/parser.yaml" in by_path), None)
    if path is None:
        raise SystemExit(f"{source_type}: none of {SOURCES[source_type]} under {root}/ in the catalog")
    entry = by_path[path]
    ls_id = entry.get("linked_log_source_id")
    if not ls_id:
        st, data, raw = api.call(
            "POST", f"/api/parser-repositories/{rid}/parsers/import/{urllib.parse.quote(path, safe='')}",
            {"import_type": "linked", "source_type": source_type, "ingestion_method": "routed"})
        ls_id = (data or {}).get("log_source_id") if isinstance(data, dict) else None
        if not ls_id:
            raise SystemExit(f"{source_type}: import {path} -> {st} {raw}")
    t0 = time.time()
    ok, attempts, last, history = False, 0, "", []
    while not ok and attempts < 4:  # idempotent; small or busy hosts can time out
        attempts += 1
        a0 = time.time()
        st, data, raw = api.call("POST", f"/api/log-sources/{ls_id}/deploy", {}, timeout=240)
        ok = st == 200 and (not isinstance(data, dict) or data.get("success", True) is not False)
        last = f"{st} {raw}"
        history.append({"status": st, "secs": round(time.time() - a0, 1), "ok": ok,
                        **({} if ok else {"error": raw[:200]})})
        if not ok:
            # Role-split 2.0.x: the app host has no local Vector, so deploy can
            # report success=false while the config still reaches every ingest
            # host. Ingest -> search is the real proof (run.sh smoke step).
            if st == 200 and "No reload was delivered" in raw:
                ok = True
                break
            time.sleep(15)
    rec = {"source_type": source_type, "parser_path": path, "log_source_id": ls_id,
           "deploy_ok": ok, "deploy_attempts": attempts, "deploy_secs": round(time.time() - t0, 1),
           "deploy_history": history}
    if not ok:
        rec["deploy_error"] = last[:300]
    log(f"{source_type}: {path} -> log source {ls_id} deploy={'ok' if ok else 'FAILED'} "
        f"({attempts} attempt(s), {rec['deploy_secs']}s)")
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app-url", default="http://localhost")
    ap.add_argument("--creds", default="~/.nano-admin-credentials")
    ap.add_argument("--env-file", default="~/nano/.env")
    ap.add_argument("--out", default="~/bench")
    ap.add_argument("--rules", help="rules JSON file ({\"rules\": [...]}) on this host")
    ap.add_argument("--rule-mode", default="alerting", choices=["staging", "live", "alerting"])
    ap.add_argument("--agentlane", type=int, default=0, help="mint N Agent Lane tokens (enterprise)")
    ap.add_argument("--rules-only", action="store_true", help="only (re)load the detection set")
    ap.add_argument("--run-tag", default=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M"))
    a = ap.parse_args()

    out = os.path.expanduser(a.out)
    os.makedirs(out, mode=0o700, exist_ok=True)
    api = Api(a.app_url)
    creds = read_env(a.creds)
    st, raw = api.login(creds)
    if not api.jwt:
        log(f"login failed: {st} {raw}")
        return 1
    profile = read_env(a.env_file).get("NANO_SCHEMA_PROFILE") or "ocsf"
    _, caps, _ = api.call("GET", "/api/capabilities")
    content = {"profile": profile, "nano_version": (caps or {}).get("version") if isinstance(caps, dict) else None,
               "loaded_at": dt.datetime.now(dt.timezone.utc).isoformat(), "sources": [], "rules": {}}
    log(f"logged in; schema profile {profile}; nano {content['nano_version']}")

    if a.rules_only:
        content["sources"] = None
    # 2-3. parsers, log sources, ingest tokens
    rid = None if a.rules_only else find_repo(api)
    parsers = catalog(api, rid) if rid else []
    tokens = {}
    for source_type in ([] if a.rules_only else SOURCES):
        rec = ensure_source(api, rid, parsers, source_type, profile)
        st, data, raw = api.call("POST", "/api/ingest-tokens",
                                 {"name": f"bench-{a.run_tag}-{source_type}", "source_id": rec["log_source_id"]})
        tok = (data or {}).get("token") if isinstance(data, dict) else None
        if not tok:
            log(f"{source_type}: ingest token -> {st} {raw}")
            return 1
        tokens[source_type] = tok
        content["sources"].append(rec)
    if not a.rules_only:
        write_secret(os.path.join(out, "tokens.json"), json.dumps(tokens) + "\n")
        log(f"ingest tokens for {len(tokens)} sources -> {out}/tokens.json (0600, values not shown)")

    # 4. search API key
    if not a.rules_only:
        st, data, raw = api.call("POST", "/api/api-keys", {"name": f"bench-{a.run_tag}", "permissions": SEARCH_KEY_PERMS})
        key = (data or {}).get("key") if isinstance(data, dict) else None
        if not key:
            log(f"api key -> {st} {raw}")
            return 1
        write_secret(os.path.join(out, "api.env"), f"API_KEY={key}\n")
        log(f"search API key -> {out}/api.env (0600)")

    # 5. detections
    if a.rules:
        with open(os.path.expanduser(a.rules), encoding="utf-8") as fh:
            rules = json.load(fh)["rules"]
        _, existing, _ = api.call("GET", "/api/rules?limit=2000")
        items = existing if isinstance(existing, list) else (existing or {}).get("rules", []) if isinstance(existing, dict) else []
        have = {r.get("name") for r in items}
        created = failed = skipped = 0
        errors = []
        for r in rules:
            if r["name"] in have:
                skipped += 1
                continue
            body = dict(r)
            body["mode"] = a.rule_mode
            st, data, raw = api.call("POST", "/api/rules", body)
            if st in (200, 201):
                created += 1
            else:
                failed += 1
                if len(errors) < 20:
                    errors.append({"name": r["name"], "status": st, "error": raw[:200]})
        content["rules"] = {"requested": len(rules), "created": created, "skipped_existing": skipped,
                            "failed": failed, "errors": errors, "mode": a.rule_mode,
                            "scheduled": sum(1 for r in rules if r.get("detection_mode", "scheduled") == "scheduled")}
        log(f"rules: created {created}, skipped {skipped}, failed {failed} (of {len(rules)})")

    # 6. Agent Lane tokens (enterprise)
    if a.agentlane:
        st, data, raw = api.call("PUT", "/api/settings/agentlane", {"enabled": True})
        log(f"agentlane enable -> {st}")
        lane = []
        exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)).isoformat()
        for i in range(a.agentlane):
            st, data, raw = api.call("POST", "/api/settings/agentlane/tokens",
                                     {"name": f"bench-agent-{i + 1}", "expires_at": exp, "ip_allowlist": []})
            if not isinstance(data, dict) or not data.get("token"):
                log(f"agentlane token {i + 1} -> {st} {raw}")
                content["agentlane"] = {"error": f"{st} {raw[:200]}"}
                break
            lane.append({"name": f"bench-agent-{i + 1}", "username": data.get("username"),
                         "password": data.get("password"), "url": data.get("connection_url")})
        if lane:
            write_secret(os.path.join(out, "agentlane.json"), json.dumps(lane) + "\n")
            content["agentlane"] = {"tokens": len(lane), "url": lane[0].get("url")}
            log(f"agentlane: {len(lane)} token(s) -> {out}/agentlane.json (0600)")

    name = "content-rules.json" if a.rules_only else "content.json"
    with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
        json.dump(content, fh, indent=2)
    bad = [s["source_type"] for s in (content["sources"] or []) if not s["deploy_ok"]]
    if bad:
        log(f"WARNING: deploy not confirmed for {bad}; run.sh smoke decides")
    return 0


if __name__ == "__main__":
    sys.exit(main())

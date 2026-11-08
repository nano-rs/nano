"""NAN-4972 upgrade lane: seed a retained v0.1 source through ITS API, verify after
the upgrade through the new one (driven by scripts/e2e/lanes/upgrade-from-v01.sh).

    python -I -m nano_e2e.upgrade_v01 seed   --manifest <run>/upgrade-manifest.json
    python -I -m nano_e2e.upgrade_v01 verify --manifest <run>/upgrade-manifest.json
    python -I -m nano_e2e.upgrade_v01 verify --compat-old-api --manifest <run>/upgrade-manifest.json

`seed` writes a manifest: the id of every object it created, the secrets it
needs to prove later (user passwords, API keys, an access token, credential
values; the manifest is 0600 inside the 0700 run dir and never printed), and
the answers the old release gave to a fixed set of searches over an absolute
time window. `verify` re-reads every object by id and compares, re-runs the
searches over the same window and requires identical answers, then proves the
stack still works: logins, keys, credential decryption, ingest with the
install token, rules firing on new events.

Each check prints one `ok`/`FAIL` line; any FAIL exits 1. Values of secrets
never appear in output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

EDITION = os.environ.get("E2E_LANE_EDITION", "open")
PROFILE = os.environ.get("E2E_LANE_PROFILE", "udm")
TAG = "upg4972"


# ------------------------------------------------------------------ output
class Failures:
    def __init__(self) -> None:
        self.items: list[str] = []

    def ok(self, msg: str) -> None:
        print(f"ok   {msg}", flush=True)

    def fail(self, msg: str) -> None:
        self.items.append(msg)
        print(f"FAIL {msg}", flush=True)

    def check(self, cond: bool, msg: str, detail: str = "") -> bool:
        if cond:
            self.ok(msg)
        else:
            self.fail(f"{msg}{(': ' + detail) if detail else ''}")
        return cond


def short(obj: Any, n: int = 400) -> str:
    s = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    return s if len(s) <= n else s[:n] + "..."


# ------------------------------------------------------------------ http
class Api:
    def __init__(self, base: str, headers: dict[str, str]):
        self.c = httpx.Client(base_url=base.rstrip("/"), headers=headers, timeout=60)

    def req(self, method: str, path: str, expect: tuple[int, ...] = (200, 201), **kw: Any) -> Any:
        r = self.c.request(method, path, **kw)
        if r.status_code not in expect:
            raise RuntimeError(f"{method} {path} -> {r.status_code}: {short(r.text)}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            return r.text

    def status(self, method: str, path: str, **kw: Any) -> int:
        return self.c.request(method, path, **kw).status_code

    def get(self, path: str, **kw: Any) -> Any:
        return self.req("GET", path, **kw)

    def post(self, path: str, body: Any = None, **kw: Any) -> Any:
        return self.req("POST", path, json=body, **kw)

    def put(self, path: str, body: Any = None, **kw: Any) -> Any:
        return self.req("PUT", path, json=body, **kw)


def env(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        raise SystemExit(f"{name} not set (run through scripts/e2e/lanes/upgrade-from-v01.sh)")
    return v


def api_key_client(key: str) -> Api:
    return Api(env("NANOSIEM_API_URL"), {"X-API-Key": key})


def search_client(key: str) -> Api:
    return Api(env("NANOSIEM_SEARCH_URL"), {"X-API-Key": key, "x-nano-cache-bypass": "1"})


def eventually(fn: Callable[[], Any], timeout: float, desc: str, interval: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        try:
            last = fn()
            if last:
                return last
        except Exception as exc:  # noqa: BLE001 - polled; the last error is reported
            last = exc
        time.sleep(interval)
    raise TimeoutError(f"{desc} not reached in {timeout:.0f}s (last: {short(str(last))})")


def items_of(body: Any, *keys: str) -> list[dict[str, Any]]:
    """A list response, whether bare or wrapped ({"rules": [...]}, {"items": [...]}, ...)."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for k in (*keys, "items", "data", "results"):
            v = body.get(k)
            if isinstance(v, list):
                return v
    return []


def obj_of(body: Any, *keys: str) -> dict[str, Any]:
    """The created / fetched object, whether bare or wrapped ({"rule": {...}})."""
    if isinstance(body, dict):
        for k in keys:
            v = body.get(k)
            if isinstance(v, dict):
                return v
        return body
    return {}


def ingest_http(token: str, source_type: str, docs: list[dict[str, Any]]) -> int:
    r = httpx.post(
        env("NANOSIEM_VECTOR_HTTP_URL") + "/",
        content="\n".join(json.dumps(d) for d in docs).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "X-Source-Type": source_type},
        timeout=30,
    )
    return r.status_code


def ingest_hec(token: str, source_type: str, events: list[dict[str, Any]]) -> int:
    body = "\n".join(json.dumps({"event": e, "sourcetype": source_type}) for e in events)
    r = httpx.post(
        env("NANOSIEM_HEC_URL") + "/services/collector/event",
        content=body.encode(),
        headers={"Authorization": f"Splunk {token}", "X-Splunk-Request-Channel": str(uuid.uuid4())},
        timeout=30,
    )
    return r.status_code


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ------------------------------------------------------------------ fixtures
# Event sources seeded before the upgrade. HTTP and HEC with the INSTALL token
# (VECTOR_AUTH_TOKEN), the only ingest credential v0.1.703 has; upg_parsed goes
# through a log source with a published VRL parser.
SOURCES: dict[str, dict[str, Any]] = {
    "upg_fw": {"via": "http", "n": 40},
    "upg_auth": {"via": "hec", "n": 20},
    "upg_proc": {"via": "http", "n": 15},
    "upg_parsed": {"via": "http", "n": 10},
    "upg_alert": {"via": "http", "n": 3},
}


# The upg_parsed parser uses the UDM contract (`.udm.*`); an OCSF-profile
# install's parsers emit OCSF instead, so on that profile the parser object is
# seeded and checked but no events are routed through it.
if PROFILE == "ocsf":
    SOURCES.pop("upg_parsed")


def make_event(st: str, i: int, phase: str) -> dict[str, Any]:
    base: dict[str, Any] = {"message": f"{TAG} {phase} {st} event {i}"}
    if st == "upg_fw":
        base.update(src_ip=f"10.1.0.{i % 7 + 1}", dest_ip="203.0.113.10", dest_port=[22, 443, 3389][i % 3],
                    action="blocked" if i % 4 == 0 else "allowed")
    elif st == "upg_auth":
        base.update(user=["alice", "bob", "carol"][i % 3], auth_result="failure" if i % 5 == 0 else "success",
                    src_ip=f"192.0.2.{i % 3 + 1}")
    elif st == "upg_proc":
        base.update(process_name=["cmd.exe", "powershell.exe", "bash"][i % 3],
                    command_line=f"whoami /{TAG}/{i}", src_host="ws-01")
    elif st == "upg_parsed":
        base.update(user=["alice", "bob"][i % 2])
    elif st == "upg_alert":
        base.update(user="mallory", action="upg_alert_trigger")
    return base


def send(st: str, events: list[dict[str, Any]]) -> int:
    tok = env("VECTOR_AUTH_TOKEN")
    if SOURCES.get(st, {}).get("via") == "hec":
        return ingest_hec(tok, st, events)
    return ingest_http(tok, st, events)


SEARCHES: list[tuple[str, str]] = [
    ("fw events", "source_type=upg_fw"),
    ("auth events", "source_type=upg_auth"),
    ("proc events", "source_type=upg_proc"),
    ("parsed events", "source_type=upg_parsed"),
    ("keyword", f"{TAG} seed"),
    ("auth failures", "source_type=upg_auth auth_result=failure"),
    ("fw by port", "source_type=upg_fw | stats count by dest_port"),
    ("auth by user", "source_type=upg_auth | stats count by user"),
    ("parsed by user", "source_type=upg_parsed | stats count by user"),
    ("parsed field filter", 'source_type=upg_parsed user="parsed-alice" process_name="upg-parser.exe"'),
]
if PROFILE == "ocsf":
    SEARCHES = [(label, q) for label, q in SEARCHES if "upg_parsed" not in q]


def run_search(s: Api, query: str, window: dict[str, str], limit: int = 1000) -> dict[str, Any]:
    body = {"query": query, "limit": limit, "skip_histogram": True, "skip_field_stats": True,
            "use_cache": False, "time_range": window, "request_id": f"upg-{uuid.uuid4().hex[:10]}"}
    return s.post("/api/search", body, expect=(200,))


def digest(res: dict[str, Any]) -> dict[str, Any]:
    """What must be identical across the upgrade: the count and the content
    (event messages, or the aggregate rows), order-insensitive."""
    rows = res.get("results") or []
    if rows and all("message" in r for r in rows):
        content = sorted(str(r.get("message")) for r in rows)
    else:
        content = sorted(json.dumps({k: v for k, v in r.items() if not k.startswith("_")}, sort_keys=True, default=str)
                         for r in rows)
    return {"total_count": res.get("total_count"), "rows": len(rows), "content": content}


def login(email: str, password: str) -> dict[str, Any]:
    r = httpx.post(env("NANOSIEM_API_URL") + "/api/auth/login", json={"email": email, "password": password}, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"login {email} -> {r.status_code}: {short(r.text)}")
    return r.json()


def jwt_client(token: str) -> Api:
    return Api(env("NANOSIEM_API_URL"), {"Authorization": f"Bearer {token}"})


# The pre-OCSF parser contract: a parser writes UDM fields under `.udm`.
PARSER_VRL = '.udm.user = "parsed-" + (string(.user) ?? "none")\n.udm.process_name = "upg-parser.exe"\n'


# ------------------------------------------------------------------ seed
def seed(manifest: Path) -> int:
    f = Failures()
    m: dict[str, Any] = {"edition": EDITION, "profile": PROFILE, "objects": {}, "secrets": {}, "searches": {}}
    admin = api_key_client(env("NANOSIEM_API_KEY"))
    search = search_client(env("NANOSIEM_API_KEY"))
    o, sec = m["objects"], m["secrets"]
    enterprise = EDITION == "enterprise"
    started = datetime.now(UTC) - timedelta(minutes=30)

    def step(name: str, fn: Callable[[], Any]) -> Any:
        try:
            out = fn()
            f.ok(f"seed {name}")
            return out
        except Exception as exc:  # noqa: BLE001 - every seed failure is reported, then fatal
            f.fail(f"seed {name}: {short(str(exc), 600)}")
            return None

    # ---- identity: admin session, users, role, API keys
    admin_login = login(env("NANO_ADMIN_EMAIL"), env("NANO_ADMIN_PASSWORD"))
    admin_jwt = jwt_client(admin_login["tokens"]["access_token"])
    sec["admin_refresh_token"] = admin_login["tokens"].get("refresh_token")
    sec["admin_access_token"] = admin_login["tokens"]["access_token"]
    sec["admin_access_expires_at"] = time.time() + float(admin_login["tokens"].get("expires_in") or 0)
    admin_perms = admin_login["user"].get("permissions") or []

    analyst_pw = f"Upg#{uuid.uuid4().hex[:12]}Aa1!"
    def mk_user() -> None:
        u = admin.post("/api/users", {"email": f"analyst.{TAG}@example.com", "name": "Upgrade Analyst", "password": analyst_pw})
        o["user"] = {"id": u["id"], "email": u["email"], "name": u["name"]}
        sec["analyst_password"] = analyst_pw
    step("user", mk_user)

    def mk_role() -> None:
        r = admin.post("/api/roles", {"name": f"{TAG}-role", "description": "upgrade lane",
                                      "permissions": ["search:execute", "alerts:view"]})
        o["role"] = {"id": r["id"], "name": r["name"], "permissions": sorted(r.get("permissions") or [])}
    step("custom role", mk_role)

    def mk_keys() -> None:
        lim = admin_jwt.post("/api/api-keys", {"name": f"{TAG}-limited", "permissions": ["search:execute"]})
        o["api_key_limited"] = {"id": lim["id"], "name": lim["name"], "prefix": lim.get("key_prefix")}
        sec["api_key_limited"] = lim["key"]
        full = admin_jwt.post("/api/api-keys", {"name": f"{TAG}-full", "permissions": admin_perms})
        o["api_key_full"] = {"id": full["id"], "name": full["name"], "prefix": full.get("key_prefix")}
        sec["api_key_full"] = full["key"]
        sec["api_key_bootstrap"] = env("NANOSIEM_API_KEY")
    step("API keys", mk_keys)

    # ---- encrypted secrets with an API decrypt check
    def mk_idp() -> None:
        admin.post("/api/settings/identity-providers", {"id": f"{TAG}-ad", "name": "Upgrade AD", "provider_type": "active_directory"})
        admin.post(f"/api/settings/identity-providers/{TAG}-ad/credentials", {"credentials": {"token": f"tok-{uuid.uuid4().hex}"}})
        t = admin.post(f"/api/settings/identity-providers/{TAG}-ad/test", {})
        if not (isinstance(t, dict) and t.get("success") is True):
            raise RuntimeError(f"identity provider test on the OLD release: {short(t)}")
        o["identity_provider"] = {"id": f"{TAG}-ad"}
    step("identity provider + encrypted credentials (decrypt test passes)", mk_idp)

    def mk_cloud_cred() -> None:
        c = admin.post("/api/credentials", {"name": f"{TAG}-s3", "provider": "aws_s3", "region": "us-east-1",
                                             "credentials": {"access_key_id": "AKIAUPG4972EXAMPLE", "secret_access_key": uuid.uuid4().hex}})
        admin.post(f"/api/credentials/{c['id']}/rotate", {"credentials": {"access_key_id": "AKIAUPG4972ROTATED", "secret_access_key": uuid.uuid4().hex}})
        vers = items_of(admin.get(f"/api/credentials/{c['id']}/versions"), "versions")
        o["cloud_credential"] = {"id": c["id"], "name": c["name"], "provider": c.get("provider"), "versions": len(vers)}
    step("cloud credential (+1 rotation)", mk_cloud_cred)

    if enterprise:
        def mk_ai() -> None:
            admin.put("/api/settings/ai-providers/anthropic", {"api_key": f"sk-ant-upg-{uuid.uuid4().hex}", "enabled": False})
            st = admin.status("POST", "/api/settings/ai-providers/anthropic/validate", json={})
            if st >= 500:
                raise RuntimeError(f"ai provider validate on the OLD release -> {st}")
            o["ai_provider"] = {"provider": "anthropic", "validate_status": st}
        step("AI provider key (encrypted)", mk_ai)

        def mk_agent_enr() -> None:
            admin.post("/api/settings/agent-enrichments", {"id": f"{TAG}-abuse", "name": "Upgrade AbuseIPDB",
                                                            "provider_type": "abuseipdb", "enabled": False,
                                                            "api_key": f"abuse-{uuid.uuid4().hex}"})
            st = admin.status("POST", f"/api/settings/agent-enrichments/{TAG}-abuse/test", json={})
            if st >= 500:
                raise RuntimeError(f"agent enrichment test on the OLD release -> {st}")
            o["agent_enrichment"] = {"id": f"{TAG}-abuse", "test_status": st}
        step("agent enrichment key (encrypted)", mk_agent_enr)

        def mk_oidc() -> None:
            p = admin.post("/api/settings/oidc", {"name": "Upgrade SSO", "slug": f"{TAG}-sso", "issuer": "https://accounts.google.com",
                                                   "client_id": f"{TAG}-client", "client_secret": f"cs-{uuid.uuid4().hex}",
                                                   "scopes": ["openid", "email", "profile"]})
            o["oidc"] = {"id": p["id"], "slug": f"{TAG}-sso", "issuer": "https://accounts.google.com"}
        step("OIDC SSO provider", mk_oidc)

    # ---- parsers, source configs
    def mk_log_source() -> None:
        ls = admin.post("/api/log-sources", {"name": "upg_parsed", "source_type": "routed", "match_values": ["upg_parsed"],
                                             "parser_vrl": PARSER_VRL, "description": "upgrade lane parser"})
        admin.post(f"/api/log-sources/{ls['id']}/publish")
        admin.post(f"/api/log-sources/{ls['id']}/deploy")
        o["log_source"] = {"id": ls["id"], "name": ls["name"], "parser_vrl": ls.get("parser_vrl")}
    step("log source (VRL parser, published + deployed)", mk_log_source)

    def mk_source_config() -> None:
        sc = admin.post("/api/source-configurations", {"name": f"{TAG}-http", "config_type": "http", "connection_config": {},
                                                       "default_source_type": "upg_fw", "description": "upgrade lane"})
        o["source_config"] = {"id": sc["id"], "name": sc["name"], "config_type": sc.get("config_type")}
    step("source configuration", mk_source_config)

    # ---- data
    time.sleep(10)  # the deployed parser reaches Vector through --watch-config
    def mk_events() -> None:
        for st, spec in SOURCES.items():
            evs = [make_event(st, i, "seed") for i in range(spec["n"])]
            code = send(st, evs)
            if code != 200:
                raise RuntimeError(f"ingest {st} -> {code}")
        window = {"start": iso(started), "end": iso(datetime.now(UTC) + timedelta(minutes=3))}
        for st, spec in SOURCES.items():
            eventually(lambda st=st, spec=spec: (run_search(search, f"source_type={st}", window).get("total_count") or 0) >= spec["n"],
                       timeout=180, desc=f"{spec['n']} {st} events searchable")
        m["window"] = window
        m["ingested"] = {st: spec["n"] for st, spec in SOURCES.items()}
    step("ingest (HTTP + HEC, install token) across 5 sources", mk_events)

    # ---- detection rules in every mode, alerts
    def mk_rules() -> None:
        rules = {
            "staging": {"name": f"{TAG} staging rule", "query": "source_type=upg_proc process_name=\"powershell.exe\"", "severity": "low", "mode": "staging"},
            "live": {"name": f"{TAG} live rule", "query": 'source_type=upg_parsed user="parsed-bob"', "severity": "medium", "mode": "live",
                     "schedule_cron": "*/1 * * * *", "lookback_minutes": 120},
            "alerting": {"name": f"{TAG} alerting rule", "query": "source_type=upg_alert", "severity": "high", "mode": "alerting",
                         "schedule_cron": "*/1 * * * *", "lookback_minutes": 120, "alert_mode": "per_event"},
            "realtime": {"name": f"{TAG} realtime rule", "query": "source_type=upg_fw action=blocked", "severity": "medium", "mode": "live",
                         "detection_mode": "real-time", "realtime_enabled": True},
            "paused": {"name": f"{TAG} paused rule", "query": "source_type=upg_fw dest_port=3389", "severity": "low", "mode": "paused"},
        }
        o["rules"] = {}
        for k, body in rules.items():
            r = obj_of(admin.post("/api/rules", body), "rule")
            o["rules"][k] = {"id": r["id"], "name": r["name"], "query": r.get("query"), "mode": r.get("mode"),
                             "severity": r.get("severity"), "detection_mode": r.get("detection_mode")}
    step("detection rules (staging, live, alerting, real-time, paused)", mk_rules)

    def mk_alerts() -> None:
        rid = o["rules"]["alerting"]["id"]
        admin.post(f"/api/rules/{rid}/trigger")
        alerts = eventually(lambda: [a for a in items_of(admin.get("/api/alerts", params={"limit": 200}), "alerts")
                                     if a.get("rule_id") == rid], timeout=120, desc="alerts from the alerting rule")
        o["alerts"] = sorted(a["id"] for a in alerts)
        o["alert_rule_id"] = rid
    step("alerts (alerting rule fired)", mk_alerts)

    if enterprise:
        def mk_case() -> None:
            c = obj_of(admin.post("/api/cases", {"title": f"{TAG} case", "severity": "high", "description": "upgrade lane case"}), "case")
            admin.post(f"/api/cases/{c['id']}/alerts", {"alert_id": o["alerts"][0], "is_primary": True})
            o["case"] = {"id": c["id"], "title": c.get("title"), "alert_id": o["alerts"][0]}
        step("case with a linked alert", mk_case)

        def mk_case_search() -> None:
            s = admin.post("/api/cases/saved-searches", {"name": f"{TAG} case search", "query": "severity:high"})
            o["case_saved_search"] = {"id": obj_of(s, "saved_search", "search").get("id"), "name": f"{TAG} case search"}
        step("cases saved search", mk_case_search)

        def mk_custom_enr() -> None:
            e = obj_of(admin.post("/api/custom-enrichments", {"name": f"{TAG}-enrichment", "enrichment_type": "data",
                                                              "code": "export default async () => ({})", "config": {}, "allowed_domains": []}),
                       "enrichment")
            o["custom_enrichment"] = {"id": e["id"], "name": e.get("name")}
        step("custom enrichment", mk_custom_enr)

    # ---- dashboards, saved searches, lookups, playbooks
    def mk_dash() -> None:
        d = admin.post("/api/dashboards", {"name": f"{TAG} dashboard", "description": "upgrade lane",
                                           "layout": {"items": [{"i": "p1", "x": 0, "y": 0, "w": 6, "h": 4}, {"i": "p2", "x": 6, "y": 0, "w": 6, "h": 4}]},
                                           "panels": [{"id": "p1", "title": "fw by port", "query": "source_type=upg_fw | stats count by dest_port",
                                                       "queryMode": "piped", "visualizationType": "bar"},
                                                      {"id": "p2", "title": "auth", "query": "source_type=upg_auth | stats count by user",
                                                       "queryMode": "piped", "visualizationType": "table"}]})
        o["dashboard"] = {"id": d["id"], "name": d["name"], "panels": len(d.get("panels") or [])}
    step("dashboard (2 panels)", mk_dash)

    def mk_saved() -> None:
        s = search.post("/api/search/saved", {"name": f"{TAG} saved search", "query": "source_type=upg_auth auth_result=failure",
                                              "time_range": {"relative": "24h"}})
        o["saved_search"] = {"id": s["id"], "name": s["name"], "query": s.get("query")}
    step("saved search", mk_saved)

    def mk_lookup() -> None:
        t = admin.post("/api/lookup-tables/schema", {"name": "upg_lookup", "description": "upgrade lane", "primary_key": "ip",
                                                     "columns": [{"name": "ip", "data_type": "text"}, {"name": "tag", "data_type": "text"}]})
        rows = [{"ip": f"10.1.0.{i}", "tag": "lab" if i % 2 else "prod"} for i in range(1, 8)]
        admin.post("/api/lookup-tables/upg_lookup/rows", {"rows": rows})
        o["lookup"] = {"id": obj_of(t, "table").get("id"), "name": "upg_lookup", "rows": len(rows)}
    step("lookup table (7 rows)", mk_lookup)

    def mk_playbook() -> None:
        if admin.status("GET", "/api/playbooks") == 403 or "playbooks:manage" not in admin_perms:
            m["skipped"] = m.get("skipped", []) + ["playbook: the v0.1 source admin role lacks playbooks:manage"]
            return
        p = admin.post("/api/playbooks", {"title": f"{TAG} playbook", "category": "endpoint", "doc": "# Steps\n1. Isolate host\n"})
        o["playbook"] = {"id": p["id"], "title": p.get("title")}
    step("playbook", mk_playbook)

    # ---- the answers the selected v0.1 source gives
    if "window" in m:
        for label, q in SEARCHES:
            try:
                m["searches"][label] = {"query": q, **digest(run_search(search, q, m["window"]))}
                f.ok(f"search '{label}': {m['searches'][label]['total_count']} ({m['searches'][label]['rows']} rows)")
            except Exception as exc:  # noqa: BLE001
                f.fail(f"search '{label}' on the old release: {short(str(exc))}")

    old = os.umask(0o077)
    try:
        manifest.write_text(json.dumps(m, indent=2, default=str))
    finally:
        os.umask(old)
    summary = {k: (len(v) if isinstance(v, (list, dict)) else 1) for k, v in o.items()}
    print(f"seeded objects: {json.dumps(summary)}", flush=True)
    return 1 if f.items else 0


# ------------------------------------------------------------------ verify
def verify(manifest: Path, *, compat_old_api: bool = False) -> int:
    f = Failures()
    m = json.loads(manifest.read_text())
    o, sec = m["objects"], m["secrets"]
    admin = api_key_client(sec.get("api_key_bootstrap") or env("NANOSIEM_API_KEY"))
    search = search_client(sec.get("api_key_bootstrap") or env("NANOSIEM_API_KEY"))
    enterprise = m.get("edition") == "enterprise"

    def check(name: str, fn: Callable[[], Any]) -> None:
        try:
            res = fn()
            if res is False:
                f.fail(name)
            else:
                f.ok(name + (f" ({res})" if isinstance(res, str) else ""))
        except Exception as exc:  # noqa: BLE001 - every check reports, the run fails at the end
            f.fail(f"{name}: {short(str(exc), 600)}")

    def same(label: str, want: dict[str, Any], got: dict[str, Any], keys: list[str]) -> str:
        diffs = {k: (want.get(k), got.get(k)) for k in keys if want.get(k) is not None and want.get(k) != got.get(k)}
        if diffs:
            raise AssertionError(f"{label} changed: {short(diffs)}")
        return "unchanged"

    # ---- logins and keys
    def admin_login() -> str:
        login(env("NANO_ADMIN_EMAIL"), env("NANO_ADMIN_PASSWORD"))
        return "password login ok"
    check("admin can log in with the pre-upgrade password", admin_login)

    if "user" in o:
        def analyst() -> str:
            r = login(o["user"]["email"], sec["analyst_password"])
            me = jwt_client(r["tokens"]["access_token"]).get("/api/auth/me")
            assert obj_of(me, "user").get("email") == o["user"]["email"], short(me)
            return "login + /api/auth/me"
        check("seeded user logs in with the pre-upgrade password", analyst)

    def old_session() -> str:
        notes = []
        if time.time() < float(sec.get("admin_access_expires_at") or 0) - 5:
            st = jwt_client(sec["admin_access_token"]).status("GET", "/api/auth/me")
            assert st == 200, f"pre-upgrade access token -> {st}"
            notes.append("pre-upgrade access token valid")
        else:
            notes.append("pre-upgrade access token already expired (not checked)")
        if compat_old_api and sec.get("admin_refresh_token"):
            notes.append("pre-upgrade refresh token reserved for the final HEAD verification")
        elif sec.get("admin_refresh_token"):
            r = httpx.post(env("NANOSIEM_API_URL") + "/api/auth/refresh", json={"refresh_token": sec["admin_refresh_token"]}, timeout=30)
            assert r.status_code == 200, f"refresh with the pre-upgrade refresh token -> {r.status_code}: {short(r.text)}"
            body = r.json()
            tok = (body.get("tokens") or {}).get("access_token") or body.get("access_token")
            assert tok and jwt_client(tok).status("GET", "/api/auth/me") == 200, "refreshed token rejected"
            notes.append("pre-upgrade refresh token -> new session")
        return "; ".join(notes)
    check("sessions survive (JWT_SECRET carried over)", old_session)

    def keys() -> str:
        for k in ("api_key_bootstrap", "api_key_full"):
            if sec.get(k):
                st = api_key_client(sec[k]).status("GET", "/api/rules")
                assert st == 200, f"{k} -> {st}"
        if sec.get("api_key_limited"):
            lim = sec["api_key_limited"]
            st = search_client(lim).status("POST", "/api/search", json={"query": "source_type=upg_fw", "limit": 1, "time_range": m["window"]})
            assert st == 200, f"limited key search -> {st}"
            st = api_key_client(lim).status("GET", "/api/users")
            assert st == 403, f"limited key on /api/users -> {st} (must stay 403)"
        return "bootstrap + full keys 200; limited key: search 200, /api/users 403"
    check("pre-upgrade API keys keep working with their scopes", keys)

    # ---- credentials decrypt
    if "identity_provider" in o:
        def idp() -> str:
            t = admin.post(f"/api/settings/identity-providers/{o['identity_provider']['id']}/test", {})
            assert isinstance(t, dict) and t.get("success") is True, short(t)
            return "test decrypts the pre-upgrade ciphertext"
        check("identity-provider credential decrypts (key ring)", idp)
    if "ai_provider" in o:
        def ai() -> str:
            st = admin.status("POST", "/api/settings/ai-providers/anthropic/validate", json={})
            assert st < 500, f"validate -> {st} (500 = decrypt failure)"
            return f"validate -> {st}"
        check("AI provider key decrypts", ai)
    if "agent_enrichment" in o:
        def agent() -> str:
            r = admin.c.post(f"/api/settings/agent-enrichments/{o['agent_enrichment']['id']}/test", json={})
            assert r.status_code < 500 and "decrypt" not in r.text.lower(), f"{r.status_code}: {short(r.text)}"
            return f"test -> {r.status_code}"
        check("agent-enrichment key decrypts", agent)
    def ring() -> str:
        body = admin.get("/api/system/credential-keys")
        usage = body.get("usage") or {}
        bad = [t["name"] for t in usage.get("targets") or [] if t.get("undecryptable")]
        assert usage.get("undecryptable") == 0 and not bad, f"undecryptable secrets: {bad} ({short(usage)})"
        want = 3 * ("cloud_credential" in o) + sum(k in o for k in ("identity_provider", "ai_provider", "agent_enrichment", "oidc"))
        assert (usage.get("scanned") or 0) >= want, f"scanned {usage.get('scanned')} < {want} seeded secrets"
        return f"{usage.get('scanned')} stored secrets open with ring key {body.get('active_key_id')}, 0 undecryptable"
    if compat_old_api:
        print("note credential key ring scan skipped (endpoint was added after the retained v0.1 sources)", flush=True)
    else:
        check("every pre-upgrade secret decrypts (credential key ring scan)", ring)
    if "cloud_credential" in o:
        def cred() -> str:
            c = obj_of(admin.get(f"/api/credentials/{o['cloud_credential']['id']}"), "credential")
            same("credential", o["cloud_credential"], c, ["name", "provider"])
            vers = items_of(admin.get(f"/api/credentials/{o['cloud_credential']['id']}/versions"), "versions")
            assert len(vers) == o["cloud_credential"]["versions"], f"versions {len(vers)} != {o['cloud_credential']['versions']}"
            return f"{len(vers)} versions"
        check("cloud credential + version history", cred)
    if "oidc" in o:
        def oidc() -> str:
            p = obj_of(admin.get(f"/api/settings/oidc/{o['oidc']['id']}"), "provider")
            same("oidc", o["oidc"], p, ["slug", "issuer"])
            pub = httpx.get(env("NANOSIEM_API_URL") + "/api/auth/oidc/providers", timeout=30)
            assert pub.status_code == 200, f"public provider list -> {pub.status_code}"
            return "provider kept; login provider list 200"
        check("OIDC SSO provider", oidc)

    # ---- objects by id
    for k in ("staging", "live", "alerting", "realtime", "paused"):
        r0 = (o.get("rules") or {}).get(k)
        if not r0:
            continue
        check(f"rule '{k}' kept", lambda r0=r0: same("rule", r0, obj_of(admin.get(f"/api/rules/{r0['id']}"), "rule"),
                                                       ["name", "query", "mode", "severity", "detection_mode"]))
    if o.get("alerts"):
        def alerts() -> str:
            for a in o["alerts"]:
                admin.get(f"/api/alerts/{a}")
            return f"{len(o['alerts'])} alerts readable"
        check("pre-upgrade alerts", alerts)
    if "case" in o:
        def case() -> str:
            body = admin.get(f"/api/cases/{o['case']['id']}")
            same("case", o["case"], obj_of(body, "case"), ["title"])
            linked = items_of(body, "alerts")
            ids = {str(x.get("alert_id") or x.get("id")) for x in linked}
            assert o["case"]["alert_id"] in ids, f"linked alert missing: {short(linked)}"
            return "title + linked alert"
        check("case", case)
    simple = [("dashboard", "/api/dashboards/{id}", ["name"]), ("playbook", "/api/playbooks/{id}", ["title"]),
              ("log_source", "/api/log-sources/{id}", ["name", "parser_vrl"]),
              ("source_config", "/api/source-configurations/{id}", ["name", "config_type"]),
              ("role", "/api/roles/{id}", ["name"]), ("user", "/api/users/{id}", ["email", "name"]),
              ("custom_enrichment", "/api/custom-enrichments/{id}", ["name"])]
    for key, path, fields in simple:
        if key in o:
            check(f"{key} kept", lambda key=key, path=path, fields=fields: same(
                key, o[key], obj_of(admin.get(path.format(id=o[key]["id"])), key, "enrichment", "log_source", "role"), fields))
    if "role" in o:
        def role_perms() -> str:
            r = obj_of(admin.get(f"/api/roles/{o['role']['id']}"), "role")
            assert sorted(r.get("permissions") or []) == o["role"]["permissions"], short(r)
            return "permissions unchanged"
        check("custom role permissions", role_perms)
    if "dashboard" in o:
        check("dashboard panels", lambda: len(obj_of(admin.get(f"/api/dashboards/{o['dashboard']['id']}")).get("panels") or []) == o["dashboard"]["panels"])
    if "saved_search" in o:
        # Read as the owner's session: an API key's principal is the key, so it
        # never sees its owner's private searches (NAN-2145; same in retained v0.1 sources).
        def saved() -> str:
            tok = login(env("NANO_ADMIN_EMAIL"), env("NANO_ADMIN_PASSWORD"))["tokens"]["access_token"]
            owner = Api(env("NANOSIEM_SEARCH_URL"), {"Authorization": f"Bearer {tok}"})
            return same("saved search", o["saved_search"], obj_of(owner.get(f"/api/search/saved/{o['saved_search']['id']}")), ["name", "query"])
        check("saved search kept", saved)
    if "lookup" in o:
        def lookup() -> str:
            rows = items_of(admin.get("/api/lookup-tables/upg_lookup/rows", params={"limit": 100}), "rows")
            assert len(rows) == o["lookup"]["rows"], f"{len(rows)} rows != {o['lookup']['rows']}"
            return f"{len(rows)} rows"
        check("lookup table rows", lookup)

        def lookup_delete() -> str:
            # Migration 183's grant: the runtime user must be able to purge rows.
            rows = items_of(admin.get("/api/lookup-tables/upg_lookup/rows"), "rows")
            admin.req("DELETE", f"/api/lookup-tables/upg_lookup/rows/{rows[0]['_row_id']}", expect=(200, 204))
            eventually(lambda: len(items_of(admin.get("/api/lookup-tables/upg_lookup/rows"), "rows")) == len(rows) - 1,
                       timeout=60, desc="lookup row deleted")
            return "row delete works"
        if compat_old_api:
            print("note lookup row delete skipped (preserve the baseline for final upgrade checks)", flush=True)
        else:
            check("lookup row delete after upgrade (ALTER DELETE grant)", lookup_delete)
    if "case_saved_search" in o:
        check("cases saved search kept", lambda: any(s.get("name") == o["case_saved_search"]["name"]
                                                     for s in items_of(admin.get("/api/cases/saved-searches"), "saved_searches", "searches")))

    # ---- searches: identical answers over the same window. On the OCSF
    # profile migration 180 moves the 1.8 store aside (ocsf_logs_legacy_v179,
    # no automatic backfill: decision 2026-11-03), so pre-upgrade OCSF rows are
    # not searchable by design; the lane asserts the legacy table kept them.
    searches = m.get("searches") or {}
    if m.get("profile") == "ocsf":
        print(f"note {len(searches)} pre-upgrade search answers not compared (OCSF profile: no backfill by design)", flush=True)
        searches = {}
    for label, want in searches.items():
        def cmp(label: str = label, want: dict[str, Any] = want) -> str:
            got = digest(run_search(search, want["query"], m["window"]))
            if got != {k: want[k] for k in ("total_count", "rows", "content")}:
                missing = sorted(set(want["content"]) - set(got["content"]))[:5]
                extra = sorted(set(got["content"]) - set(want["content"]))[:5]
                raise AssertionError(f"total {want['total_count']} -> {got['total_count']}, rows {want['rows']} -> {got['rows']}; "
                                     f"missing {short(missing)}; extra {short(extra)}")
            return f"{got['total_count']} identical"
        check(f"search '{label}' returns the pre-upgrade answer", cmp)

    # ---- the stack still works
    post_start = datetime.now(UTC) - timedelta(minutes=1)
    def ingest_post() -> str:
        prefix = "nminusone" if compat_old_api else "upg_post"
        # This verifier intentionally runs more than once in the backup/restore
        # bridge lane. Keep each continuity event unique so Vector's persistent
        # dedupe state does not turn a healthy second run into a false timeout.
        nonce = uuid.uuid4().hex
        assert ingest_http(env("VECTOR_AUTH_TOKEN"), f"{prefix}_http", [{"message": f"{prefix} http {nonce}"}]) == 200
        assert ingest_hec(env("VECTOR_AUTH_TOKEN"), f"{prefix}_hec", [{"message": f"{prefix} hec {nonce}"}]) == 200
        routes = [f"{prefix}_http", f"{prefix}_hec"]
        if not compat_old_api and "upg_parsed" in SOURCES:
            assert ingest_http(env("VECTOR_AUTH_TOKEN"), "upg_parsed", [{"message": f"{TAG} post parsed", "user": "dave"}]) == 200
            routes.append("upg_parsed")
        win = {"start": iso(post_start), "end": iso(datetime.now(UTC) + timedelta(minutes=5))}
        marker = "nminusone" if compat_old_api else "post"
        for st in routes:
            rows = eventually(lambda st=st: (run_search(search, f'source_type={st} "{marker}"', win).get("results") or []),
                              timeout=180, desc=f"post-upgrade {st} event searchable")
            assert all(r.get("source_type") == st for r in rows), f"{st} landed as {[r.get('source_type') for r in rows]}"
        if compat_old_api:
            return "install token continues to ingest through HTTP + HEC"
        return "install token (HTTP + HEC) and the pre-upgrade parser route still ingest"
    check("ingest continues with the pre-upgrade install token", ingest_post)

    if o.get("alert_rule_id"):
        def rules_run() -> str:
            rid = o["alert_rule_id"]
            before = set(o.get("alerts") or [])
            assert send("upg_alert", [make_event("upg_alert", 100 + i, "post") for i in range(2)]) == 200
            time.sleep(5)
            admin.post(f"/api/rules/{rid}/trigger")
            new = eventually(lambda: [a["id"] for a in items_of(admin.get("/api/alerts", params={"limit": 500}), "alerts")
                                      if a.get("rule_id") == rid and a["id"] not in before], timeout=180,
                             desc="a new alert from the pre-upgrade alerting rule")
            return f"{len(new)} new alert(s) after upgrade"
        check("pre-upgrade alerting rule keeps firing", rules_run)

        def scheduler() -> str:
            rid = o["alert_rule_id"]
            r0 = obj_of(admin.get(f"/api/rules/{rid}"), "rule")
            key = next((k for k in ("last_run_at", "last_executed_at", "last_execution_at", "last_run") if k in r0), None)
            if not key:
                return "no last-run field exposed (skipped)"
            first = r0.get(key)
            eventually(lambda: obj_of(admin.get(f"/api/rules/{rid}"), "rule").get(key) != first, timeout=150,
                       desc=f"scheduler advances {key}")
            return f"{key} advanced"
        check("scheduler executes pre-upgrade rules", scheduler)

    print(f"verify: {len(f.items)} failure(s)", flush=True)
    return 1 if f.items else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["seed", "verify"])
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument(
        "--compat-old-api",
        action="store_true",
        help="verify the N-1 binary on the migrated schema without newer-only or destructive checks",
    )
    a = ap.parse_args()
    return seed(a.manifest) if a.phase == "seed" else verify(a.manifest, compat_old_api=a.compat_old_api)


if __name__ == "__main__":
    sys.exit(main())

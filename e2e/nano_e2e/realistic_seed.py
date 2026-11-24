"""Apply the realistic seed profile (NAN-5764) to a throwaway stack.

The content is `nano_e2e.realistic_plan` (pure, deterministic). This module
puts it on a stack through the product's own APIs and nothing else: events
arrive through Vector HEC with a per-source ingest token, every object is
created, archived, deleted, run or installed through the API a person or an
integration would use. No database is written directly.

**Only a stack the harness created** (`check_target`, no override): the run
dir must be this checkout's `target/e2e/<run id>/` with the harness's own
`compose.env` marker, the compose project `nanoe2e-<run id>` whose containers
carry the harness's `nano.e2e.*` labels for this checkout, every service URL
on loopback at an ephemeral port (never Dan's dev ports 3000 / 3002 / 5173,
never a `*.nano.rs` host), and the OCSF schema profile. Anything else is
refused before the first request.

**Idempotent and resumable.** Every seeded object has a stable natural key
(its name, or `metadata.uid` for events), and every step checks each item on
its own, so a run interrupted anywhere finishes the job on the next run:

- a source left a draft is published; a source, case or imported rule the
  plan deletes is deleted when it still exists, and skipped when the audit
  log already records its delete;
- hunt findings are filed only on that hunt's OWN sweep: an in-flight sweep
  of the hunt is reused (reported with its fence when this runner holds it),
  and a claim that returns another hunt's sweep is never reported on;
- pending approvals are counted as the seeded flows' unfinished runs, so a
  run started just before an interruption is not started twice.

Secrets: the admin session's access and refresh tokens and every ingest
token are registered with the artifact guard and the API journal as soon as
they exist; ingest tokens are revoked when the events are in; the standalone
CLI scrubs the run's artifacts before it exits (the runner does it for
pytest sessions).

Two ways in:

- the UI suites opt in with `E2E_SEED_PROFILE=realistic` (or
  `scripts/e2e.sh run ui --seed realistic`): `nano_e2e.fixtures_seed` applies
  it once per session, before the first scenario;
- by hand against a kept stack:
  `e2e/.venv/bin/python -m nano_e2e.realistic_seed [--run <id>]`.

What it made (and what it found already there) is written to
`<artifacts>/realistic-seed.json`; a step the stack cannot do (no SOAR
catalog published yet, the open edition) is recorded there as a gap, and
`--strict` turns gaps into a failure.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from nano_e2e import artifact_guard, schema
from nano_e2e import realistic_plan as rp
from nano_e2e.client import Journal, Nano, expect
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, Timeout, eventually

PROFILE_ENV = "E2E_SEED_PROFILE"
PROFILE = "realistic"
EVENT_SPREAD_HOURS = 6  # events land over the last 6 h (inside every hunt's lookback)
SEARCH_DAYS = 30  # how far back seeded events are looked for (a kept stack ages)
HEC_BATCH = 250
CATALOG_WAIT_S = float(os.environ.get("E2E_SEED_CATALOG_WAIT_S", "420"))
AUDIT_SETTLE_S = 60.0  # a delete's audit row is written asynchronously
SWEEP_LEASE_S = 120  # short: a foreign sweep claimed by mistake is released soon
RUN_TERMINAL = {"succeeded", "failed", "canceled", "timed_out"}

# The lane parser: the HEC event body is already an OCSF object; the parser
# only stamps the route (the OCSF gate is acknowledged, as the session lane).
LANE_PARSER = f'.metadata.log_source = "{rp.LANE}"\n'

# ---------------------------------------------------------------- target guard
ROOT = Path(__file__).resolve().parents[2]
E2E_HOME = ROOT / "target" / "e2e"  # where scripts/e2e.sh keeps run dirs
EPHEMERAL_MIN = 32768  # Linux and macOS both hand out ephemeral ports above this
DEV_PORTS = {3000, 3002, 5173, 8080, 8088, 8123, 9000}  # the local dev stack's fixed ports
LOOPBACK_NAMES = {"localhost"}


class UnsafeTarget(RuntimeError):
    """The seed refused a stack the harness did not create."""


@dataclass(frozen=True)
class TargetInfo:
    started: float  # E2E_STARTED (epoch s): the stack's bring-up time


def _labels(container: str) -> dict[str, str]:
    """The docker labels of one container ({} when it does not exist)."""
    proc = subprocess.run(  # noqa: S603 - fixed argv
        ["docker", "inspect", "--format", "{{json .Config.Labels}}", container],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        return {}
    try:
        return json.loads(proc.stdout.strip() or "{}") or {}
    except ValueError:
        return {}


def _env_file(path: Path) -> dict[str, str]:
    """KEY=VALUE lines of a harness env file. Only the caller's chosen keys
    are ever read out of it; nothing is printed."""
    from nano_e2e import stackenv

    return stackenv.parse(path.read_text()) if path.is_file() else {}


def check_target(stack: Stack, *, labels: Callable[[str], dict[str, str]] | None = None) -> TargetInfo:
    """Refuse anything but a stack `scripts/e2e.sh up` created from THIS
    checkout. No flag turns this off."""
    labels = labels or _labels
    problems: list[str] = []
    if stack.target != "own" or os.environ.get("E2E_TARGET", "").strip().lower() == "existing":
        problems.append("--target existing (someone else's stack)")
    if not schema.is_ocsf():
        problems.append(f"schema profile {schema.profile()!r} (the seed is OCSF only)")
    project = f"nanoe2e-{stack.run_id}"
    if stack.project != project:
        problems.append(f"compose project {stack.project!r} is not the harness's {project!r}")
    run_dir = Path(stack.run_dir).resolve()
    home = Path(E2E_HOME).resolve()
    if run_dir.parent != home or run_dir.name != stack.run_id:
        problems.append(f"run dir {run_dir} is not {home}/{stack.run_id}")
    marker = _env_file(run_dir / "compose.env")
    if not marker:
        problems.append(f"no harness marker {run_dir}/compose.env")
    else:
        if marker.get("E2E_PROJECT") != project:
            problems.append("the run dir marker names another project")
        if Path(marker.get("E2E_OWNER") or "/nonexistent").resolve() != ROOT:
            problems.append(f"the stack was started by another checkout ({marker.get('E2E_OWNER')!r})")
        if not str(marker.get("NANO_SCHEMA_PROFILE", "ocsf")).startswith("ocsf"):
            problems.append(f"the stack was brought up {marker.get('NANO_SCHEMA_PROFILE')!r} (OCSF only)")
    for what, url in (("api", stack.api_url), ("search", stack.search_url), ("hec", stack.hec_url)):
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if host == "nano.rs" or host.endswith(".nano.rs"):
            problems.append(f"{what} URL {url} is a nano.rs host")
            continue
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host in LOOPBACK_NAMES
        if not loopback:
            problems.append(f"{what} URL {url} is not loopback")
        if u.port is None or u.port in DEV_PORTS or u.port < EPHEMERAL_MIN:
            problems.append(f"{what} URL {url} is not on an ephemeral e2e port (the local dev stack?)")
    if not problems:
        got = labels(f"{project}-postgres")
        if got.get("nano.e2e.project") != project:
            problems.append(
                f"container {project}-postgres lacks the harness label nano.e2e.project={project}"
            )
        elif Path(got.get("nano.e2e.owner") or "/nonexistent").resolve() != ROOT:
            problems.append(f"container {project}-postgres belongs to another checkout")
    if problems:
        raise UnsafeTarget(
            "the realistic seed only writes to a throwaway stack scripts/e2e.sh created from this checkout; "
            "refused: " + "; ".join(problems)
        )
    try:
        started = float(marker.get("E2E_STARTED", "0"))
    except ValueError:
        started = 0.0
    return TargetInfo(started=started)


def enabled() -> bool:
    return os.environ.get(PROFILE_ENV, "").strip().lower() == PROFILE


@dataclass
class Report:
    created: dict[str, int] = field(default_factory=dict)
    existing: dict[str, int] = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)
    ids: dict[str, Any] = field(default_factory=dict)
    seconds: dict[str, float] = field(default_factory=dict)

    def made(self, kind: str, n: int = 1) -> None:
        self.created[kind] = self.created.get(kind, 0) + n

    def found(self, kind: str, n: int = 1) -> None:
        self.existing[kind] = self.existing.get(kind, 0) + n

    def as_dict(self) -> dict[str, Any]:
        return {
            "created": self.created,
            "existing": self.existing,
            "gaps": self.gaps,
            "seconds": self.seconds,
            "ids": self.ids,
        }


# ---------------------------------------------------------------- small helpers
def _rows(body: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(body, list):
        return body
    for k in (*keys, "items", "data", "results"):
        if isinstance(body, dict) and isinstance(body.get(k), list):
            return body[k]
    return []


def _paged(
    get: Callable[[int, int], Any], *keys: str, limit: int = 100, pages: int = 100
) -> list[dict[str, Any]]:
    """Every row of a limit/offset list. A server may cap the page below
    `limit` (hunts serve 50), so the first page's size is the real page; an
    endpoint that ignores paging (the same rows again) ends the walk."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    page_size = 0
    for _ in range(pages):
        rows = _rows(get(limit, len(out)), *keys)
        ids = {str(r["id"]) for r in rows if isinstance(r, dict) and r.get("id") is not None}
        fresh = [r for r in rows if not (isinstance(r, dict) and str(r.get("id")) in seen)]
        if rows and ids and ids <= seen:
            break
        seen |= ids
        page_size = page_size or len(rows)
        out += fresh
        if not rows or len(rows) < page_size:
            break
    return out


def _secret(nano: Nano, stack: Stack, *values: str) -> None:
    """Register runtime secrets with the artifact guard and the journal."""
    artifact_guard.remember(*values, run_dir=stack.run_dir)
    nano.api.journal.remember(*values)


def _audited(nano: Nano, name: str, verbs: Iterable[str] = ("delete", "archive", "remove")) -> bool:
    """Whether the audit log records a delete-like action on the object named
    `name` (a plan object an earlier run deleted). A delete row may carry only
    the resource id (case_deleted has no resource_name, NAN-5790), so the ids
    of every row naming the object are looked up too."""

    def rows(q: str) -> list[dict[str, Any]]:
        return _rows(expect(nano.api.get("/api/audit", params={"q": q, "limit": 100}), 200), "logs")

    def deleted(row: dict[str, Any]) -> bool:
        return any(v in str(row.get("action", "")).lower() for v in verbs)

    named = [r for r in rows(name) if name in json.dumps(r, default=str, ensure_ascii=False)]
    if any(deleted(r) for r in named):
        return True
    for rid in {str(r["resource_id"]) for r in named if r.get("resource_id")}:
        if any(deleted(r) and str(r.get("resource_id")) == rid for r in rows(rid)):
            return True
    return False


def _await_audit(nano: Nano, name: str, report: Report, verbs: Iterable[str] = ("delete", "archive")) -> None:
    """After a delete: wait for its (asynchronous) audit row, which is what a
    later run reads to know the object is gone on purpose."""
    try:
        eventually(
            lambda: _audited(nano, name, verbs),
            timeout=AUDIT_SETTLE_S,
            interval=2,
            desc=f"the audit row of the delete of {name[:60]}",
        )
    except Timeout:
        report.gaps.append(f"no audit row for the delete of {name[:80]} (a re-run would re-create it)")


@contextmanager
def _session(stack: Stack, journal: Journal):
    """The throwaway stack's own admin as an interactive session (SOAR's
    switch refuses an API key, and a flow an API key saves is AI-originated).
    The session it opens is ended on exit (only that one)."""
    login = Nano(stack.api_url, stack.search_url, {}, journal)
    login_at = datetime.now(UTC) - timedelta(seconds=2)
    try:
        body = expect(
            login.api.post(
                "/api/auth/login", json={"email": stack.admin_email, "password": stack.admin_password}
            ),
            200,
        )
    finally:
        login.close()
    tokens = body.get("tokens") or {}
    jwt = tokens["access_token"]
    minted = [v for v in (jwt, tokens.get("refresh_token")) if v]
    artifact_guard.remember(*minted, run_dir=stack.run_dir)
    journal.remember(*minted)
    client = Nano(stack.api_url, stack.search_url, {"Authorization": f"Bearer {jwt}"}, journal)
    try:
        yield client
    finally:
        try:
            rows = _rows(expect(client.api.get("/api/sessions/me"), 200), "sessions")
            # `is_current` is never set today (NAN-5578): fall back to the
            # session this login created (the first one at or after it), as
            # the browser driver's end_session does.
            mine = [r for r in rows if r.get("is_current")] or sorted(
                (
                    r
                    for r in rows
                    if datetime.fromisoformat(str(r["created_at"]).replace("Z", "+00:00")) >= login_at
                ),
                key=lambda r: str(r["created_at"]),
            )[:1]
            for r in mine:
                expect(client.api.delete(f"/api/sessions/{r['id']}"), 200, 204)
        except Exception as exc:  # noqa: BLE001 - best effort; the session expires anyway
            print(f"WARNING: realistic seed could not end its own session: {exc}")
        client.close()


def _timed(report: Report, step: str):
    @contextmanager
    def cm():
        t0 = time.monotonic()
        try:
            yield
        finally:
            report.seconds[step] = round(time.monotonic() - t0, 1)

    return cm()


def _window(days: int = SEARCH_DAYS) -> dict[str, str]:
    return {
        "start": (datetime.now(UTC) - timedelta(days=days)).isoformat(),
        "end": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
    }


# ---------------------------------------------------------------- log sources + events
def _source_body(spec: rp.SourceSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "description": spec.description,
        "source_type": spec.method,
        "parser_vrl": LANE_PARSER if spec.active else f'.metadata.log_source = "{spec.route_key}"\n',
        "match_values": [spec.route_key],
        "vendor": spec.vendor,
        "product": spec.product,
        "category": "security",
        "lifecycle_status": "draft",
    }


def _sources(nano: Nano, plan: rp.Plan, report: Report) -> dict[str, dict[str, Any]]:
    have = {
        s.get("name"): s
        for s in _rows(expect(nano.api.get("/api/log-sources"), 200), "sources", "log_sources")
    }
    out: dict[str, dict[str, Any]] = {}
    for spec in plan.sources:
        src = have.get(spec.name)
        if src is None and spec.deleted and _audited(nano, spec.name):
            report.found("log_sources_deleted")
            continue
        if src is None:
            resp = nano.api.post("/api/log-sources", json=_source_body(spec))
            if resp.status_code not in (200, 201):
                report.gaps.append(
                    f"log source {spec.method!r} {spec.name!r}: {resp.status_code} {resp.text[:200]}"
                )
                continue
            src = resp.json()
            report.made("log_sources")
        else:
            report.found("log_sources")
        if spec.deleted:
            # Also when an earlier run made it and stopped before the delete.
            expect(nano.api.delete(f"/api/log-sources/{src['id']}"), 200, 204)
            report.made("log_sources_deleted")
            _await_audit(nano, spec.name, report)
            continue
        if spec.active and str(src.get("lifecycle_status", "draft")).lower() != "active":
            # Also when an earlier run made it and stopped before the publish.
            res = expect(
                nano.api.post(f"/api/log-sources/{src['id']}/publish", json={"acknowledge_unattested": True}),
                200,
            )
            assert res.get("success") is True, f"publishing the realistic lane parser failed: {res}"
            report.made("log_sources_published")
        out[spec.name] = src
    return out


def _seeded_uids(nano: Nano) -> set[str]:
    body = nano.search(
        f'source_type="{rp.LANE}" | stats count by metadata.uid', limit=10_000, time_range=_window()
    )
    out = set()
    for row in body.get("results") or []:
        uid = row.get("metadata.uid") or (row.get("metadata") or {}).get("uid")
        if uid:
            out.add(str(uid))
    return out


def _hec_post(url: str, body: bytes, token: str) -> int:
    r = httpx.post(
        url,
        content=body,
        headers={"Authorization": f"Splunk {token}", "X-Splunk-Request-Channel": str(uuid.uuid4())},
        timeout=60,
    )
    return r.status_code


def _hec_batch(stack: Stack, token: str, events: list[dict[str, Any]], times: list[float]) -> int:
    body = "".join(
        json.dumps({"event": e, "time": round(t, 3)}, ensure_ascii=False)
        for e, t in zip(events, times, strict=True)
    )
    return _hec_post(f"{stack.hec_url}/services/collector/event", body.encode(), token)


def _probe_event(nonce: str, word: str = "warm") -> dict[str, Any]:
    return {
        "class_uid": 3002,
        "category_uid": 3,
        "activity_id": 1,
        "type_uid": 300201,
        "severity_id": 1,
        "message": f"realistic seed token {word}",
        "metadata": {
            "uid": f"{rp.KEY}-settle-{nonce}",
            "version": "1.8.0",
            "log_source": rp.LANE,
            "product": {"name": rp.PRODUCT, "vendor_name": "nano"},
        },
    }


def _events(stack: Stack, nano: Nano, plan: rp.Plan, lane: dict[str, Any], report: Report) -> None:
    want = plan.uids()
    # Every run that sends events issues one lane token and revokes it when
    # done. A still-live one is a run that was killed before its cleanup:
    # revoke it. Any earlier token at all means an earlier run sent batches
    # that may still be on their way into search (a Ctrl-C revokes its token
    # but cannot wait for them), so a partial count is waited on.
    earlier = [t for t in _rows(nano.list_tokens(), "tokens") if t.get("route_key") == rp.LANE]
    for t in earlier:
        if t.get("state") == "active":
            nano.revoke_token(t["credential_id"])
            report.made("ingest_tokens_revoked_leftover")
    have = _seeded_uids(nano) & want
    if earlier and have != want:
        # Wait until the count stops growing (unchanged over three polls),
        # so nothing an earlier run sent is sent twice.
        seen: list[int] = []

        def quiet() -> bool:
            seen.append(len(_seeded_uids(nano) & want))
            return seen[-1] == len(want) or (len(seen) >= 3 and len(set(seen[-3:])) == 1)

        eventually(quiet, timeout=300, interval=10, desc="an earlier run's events to land")
        have = _seeded_uids(nano) & want
    missing = [e for e in plan.events if e["metadata"]["uid"] not in have]
    report.found("events", len(plan.events) - len(missing))
    if not missing:
        return
    # A token only when something is missing (a second run issues none), and
    # revoked once the events are in, whatever happens.
    cred, token = nano.issue_token(lane["id"], name=f"{rp.KEY}-lane-{int(time.time())}")
    _secret(nano, stack, token)
    report.made("ingest_tokens")
    try:
        streak = {"n": 0}

        def warm() -> int:
            code = _hec_batch(stack, token, [_probe_event("warm")], [time.time()])
            streak["n"] = streak["n"] + 1 if code == 200 else 0
            return streak["n"]

        eventually(
            warm,
            timeout=INGEST_VISIBLE,
            interval=1,
            desc="Vector to accept the realistic lane token",
            ok=lambda n: n >= 6,
        )
        # Settle: issuing the token reloads Vector, and a batch accepted during
        # that reload can strand for minutes. A fresh probe per poll must be
        # SEARCHABLE before the batches go (as tests/conftest.py's settle).
        # Any probe of THIS run counts (one word per run, so keyword search
        # finds it): checking only the probe just sent would always lose the
        # race with ingest latency.
        word = f"settle{uuid.uuid4().hex[:10]}"
        n = {"i": 0}

        def settled() -> int:
            n["i"] += 1
            _hec_batch(stack, token, [_probe_event(f"{word}-{n['i']}", word)], [time.time()])
            body = nano.search(f'source_type="{rp.LANE}" "{word}"', limit=1, time_range=_window(1))
            return int(body["total_count"])

        eventually(
            settled, timeout=300, interval=3, desc="a settle probe searchable (Vector past the token reload)"
        )
        now = time.time()
        span = EVENT_SPREAD_HOURS * 3600
        order = sorted(range(len(missing)), key=lambda i: missing[i]["metadata"]["uid"])
        times = {i: now - span + span * (k / max(1, len(order))) for k, i in enumerate(order)}
        sent: set[str] = set()
        try:
            for i in range(0, len(missing), HEC_BATCH):
                chunk = missing[i : i + HEC_BATCH]
                stamp = [times[j] for j in range(i, i + len(chunk))]
                events = [{**e, "time": int(t * 1000)} for e, t in zip(chunk, stamp, strict=True)]
                code = _hec_batch(stack, token, events, stamp)
                assert code == 200, f"HEC refused a realistic seed batch: HTTP {code}"
                sent |= {e["metadata"]["uid"] for e in chunk}
        except Exception:
            # Let what was accepted land before giving up, so the next run
            # sends only the rest.
            if sent:
                try:
                    eventually(
                        lambda: sent <= _seeded_uids(nano),
                        timeout=240,
                        interval=5,
                        desc="the accepted batches searchable",
                    )
                except Timeout:
                    pass
            raise
        report.made("events", len(missing))
        eventually(
            lambda: len(want & _seeded_uids(nano)),
            timeout=240,
            interval=5,
            desc=f"all {len(want)} realistic seed events searchable",
            ok=lambda got: got >= len(want),
        )
    finally:
        nano.revoke_token(cred)
        report.made("ingest_tokens_revoked")


def _event_ids(nano: Nano, field_name: str, value: str, limit: int = 3) -> list[str]:
    """Canonical event ids (`logs.id`) of seeded events naming one entity
    (hunt finding evidence)."""
    rows = nano.rows(f'source_type="{rp.LANE}" {field_name}="{value}"', limit=limit, time_range=_window())
    return [str(r["id"]) for r in rows if r.get("id")]


# ---------------------------------------------------------------- rules + alerts
def _all_rules(nano: Nano) -> dict[str, dict[str, Any]]:
    body = expect(nano.api.get("/api/rules", params={"include_archived": "true", "limit": 5000}), 200)
    return {r["name"]: r for r in _rows(body, "rules")}


def _tactics_for(nano_cat: dict[str, Any], tech: str) -> list[str]:
    for x in nano_cat.get("techniques", []):
        if x.get("id") == tech:
            return list(x.get("tactic_ids") or [])[:1]
    return []


def _rule_body(spec: rp.RuleSpec, cat: dict[str, Any]) -> dict[str, Any]:
    known = {x["id"] for x in cat.get("techniques", []) if not x.get("deprecated")}
    techs = [t for t in spec.techniques if t in known]
    tactics = sorted({t for tech in techs for t in _tactics_for(cat, tech)})
    return {
        "name": spec.name,
        "description": spec.description,
        "query": spec.query,
        "severity": spec.severity,
        "schedule_cron": rp.IDLE_CRON,
        "mode": spec.mode,
        "detection_mode": "scheduled",
        "lookback_minutes": 60 * 24,
        "folder": rp.FOLDER,
        "tags": list(spec.tags),
        "mitre_tactics": tactics,
        "mitre_techniques": techs,
    }


def _rules(nano: Nano, plan: rp.Plan, report: Report) -> None:
    cat = expect(nano.api.get("/api/mitre"), 200)
    have = _all_rules(nano)
    for spec in plan.rules:
        rule = have.get(spec.name)
        if spec.imported_then_deleted:
            # DELETE archives a rule: an archived one is done; a live one is an
            # import an earlier run made and did not get to delete.
            if rule is not None and rule.get("archived"):
                report.found("rules_deleted")
                continue
            if rule is None:
                expect(nano.api.post("/api/rules/import", json={"rules": [_rule_body(spec, cat)]}), 200, 201)
                rule = _all_rules(nano).get(spec.name)
                assert rule, f"the imported rule {spec.name} is not listed after import"
            expect(nano.api.delete(f"/api/rules/{rule['id']}"), 200, 204)
            report.made("rules_deleted")
            continue
        if rule is None:
            rule = expect(nano.api.post("/api/rules", json=_rule_body(spec, cat)), 200, 201)
            rule = rule.get("rule", rule)
            report.made("rules")
        else:
            report.found("rules")
        if spec.archived and not rule.get("archived"):
            expect(nano.api.put(f"/api/rules/{rule['id']}", json={"archived": True}), 200)
            report.made("rules_archived")
        if spec.fire and not spec.archived:
            alerts = _rows(
                expect(nano.api.get("/api/alerts", params={"rule_id": rule["id"], "limit": 5}), 200), "alerts"
            )
            if alerts:
                report.found("fired_rules")
            else:
                expect(nano.api.post(f"/api/rules/{rule['id']}/trigger"), 200)
                report.made("fired_rules")


# ---------------------------------------------------------------- cases
def _all_cases(nano: Nano) -> dict[str, dict[str, Any]]:
    rows = _paged(
        lambda lim, off: expect(nano.api.get("/api/cases", params={"limit": lim, "offset": off}), 200),
        "cases",
    )
    return {c.get("title"): c for c in rows}


def _cases(nano: Nano, plan: rp.Plan, report: Report) -> None:
    have = _all_cases(nano)
    for spec in plan.cases:
        case = have.get(spec.title)
        if case is None and spec.deleted and _audited(nano, spec.title):
            report.found("cases_deleted")
            continue
        if case is None:
            case = expect(
                nano.api.post(
                    "/api/cases",
                    json={"title": spec.title, "description": spec.description, "severity": spec.severity},
                ),
                200,
                201,
            )
            case = case.get("case", case)
            report.made("cases")
        else:
            report.found("cases")
        cid = case["id"]
        if spec.deleted:
            expect(nano.api.delete(f"/api/cases/{cid}"), 200, 204)
            report.made("cases_deleted")
            _await_audit(nano, spec.title, report)
            continue
        tags = {t.get("tag") for t in _rows(expect(nano.api.get(f"/api/cases/{cid}/tags"), 200), "tags")}
        for tag in spec.tags:
            if tag not in tags:
                resp = nano.api.post(f"/api/cases/{cid}/tags", json={"tag": tag})
                if resp.status_code != 200:
                    report.gaps.append(f"case tag {tag!r}: {resp.status_code} {resp.text[:160]}")
                    break
                report.made("case_tags")
        status = str(case.get("status", "")).lower()
        if spec.status != "open" and status != spec.status:
            body: dict[str, Any] = {"status": spec.status}
            if spec.status in ("resolved", "closed"):
                body["disposition"] = "false_positive" if spec.status == "closed" else "true_positive"
            resp = nano.api.post(f"/api/cases/{cid}/status", json=body)
            if resp.status_code == 200:
                report.made(f"cases_{spec.status}")
            else:
                report.gaps.append(f"case status {spec.status}: {resp.status_code} {resp.text[:200]}")


# ---------------------------------------------------------------- dashboards
def _dashboards(nano: Nano, plan: rp.Plan, report: Report) -> None:
    have = {d.get("name") for d in _rows(expect(nano.api.get("/api/dashboards"), 200), "dashboards")}
    for spec in plan.dashboards:
        if spec.name in have:
            report.found("dashboards")
            continue
        panel = {
            "id": "p1",
            "title": "Authentications by user (top 50, realistic seed)",
            "query": f'source_type="{rp.LANE}" class_uid=3002 | stats count by actor.user.name | head 50',
            "queryMode": "piped",
            "visualizationType": "table",
            "visualizationConfig": {},
            "timeRangeMode": "dashboard",
            "drilldownEnabled": True,
        }
        expect(
            nano.api.post(
                "/api/dashboards",
                json={
                    "name": spec.name,
                    "description": spec.description,
                    "visibility": "public",
                    "layout": {
                        "columns": 12,
                        "rowHeight": 80,
                        "items": [{"i": "p1", "x": 0, "y": 0, "w": 12, "h": 4}],
                    },
                    "panels": [panel],
                },
            ),
            200,
            201,
        )
        report.made("dashboards")


# ---------------------------------------------------------------- hunts + findings
def _all_hunts(nano: Nano) -> dict[str, dict[str, Any]]:
    rows = _paged(
        lambda lim, off: expect(nano.api.get("/api/hunts", params={"limit": lim, "offset": off}), 200),
        "hunts",
    )
    return {h.get("name") or h.get("title"): h for h in rows}


RUNNER_LABEL = f"{rp.KEY} realistic seed desktop runner (findings with long narratives)"


def _runner(nano: Nano, report: Report) -> dict[str, Any]:
    for r in _rows(expect(nano.api.get("/api/hunts/runners"), 200), "runners"):
        if r.get("label") == RUNNER_LABEL:
            return r
    report.made("hunt_runners")
    return expect(
        nano.api.post(
            "/api/hunts/runners",
            json={
                "label": RUNNER_LABEL,
                "hostname": "realistic-seed.e2e.invalid",
                "agent_tool": "claude",
                "agent_model": "nano-e2e-deterministic",
            },
        ),
        201,
    )


def _candidates(nano: Nano, spec: rp.HuntSpec, report: Report) -> list[dict[str, Any]]:
    out = []
    fields = {"host": "device.hostname", "user": "actor.user.name", "ip": "device.ip"}
    for f in spec.findings:
        ids = _event_ids(nano, fields[f.entity_type], f.entity_value)
        if not ids:
            report.gaps.append(f"hunt finding {f.entity_value}: no seeded event names it")
            continue
        out.append(
            {
                "entity_type": f.entity_type,
                "entity_value": f.entity_value,
                "mitre_technique": spec.technique,
                "signals": [spec.technique.lower()],
                "evidence_event_ids": ids,
                "narrative": f.narrative,
                "class": f.finding_class,
                "severity": f.severity,
                "confidence": 0.72,
                "benign_analysis": f.benign_analysis,
            }
        )
    return out


def _hid(hunt: dict[str, Any]) -> str:
    return str(hunt.get("playbook_id") or hunt["id"])


def _same(a: Any, b: Any) -> bool:
    """Two ids (TypeID or UUID spellings) name the same object."""
    from nano_e2e.soar_ui import uuid_of

    return bool(a) and bool(b) and uuid_of(str(a)) == uuid_of(str(b))


def _inflight(nano: Nano, hid: str) -> dict[str, Any] | None:
    body = expect(nano.api.get(f"/api/hunts/{hid}/sweeps", params={"limit": 20}), 200)
    return next(
        (s for s in _rows(body, "sweeps") if s.get("status") in ("queued", "leased", "running")), None
    )


def _own_sweep(nano: Nano, hid: str) -> dict[str, Any]:
    """This hunt's in-flight sweep, else a new one (one per hunt at a time)."""
    found = _inflight(nano, hid)
    if found:
        return found
    resp = nano.api.post(f"/api/hunts/{hid}/sweeps")
    if resp.status_code == 409:  # queued between the read and the post
        found = _inflight(nano, hid)
        assert found, f"hunt {hid}: 409 sweep in flight, but none is listed"
        return found
    return expect(resp, 200, 201, 202)


def _investigator_task(nano: Nano, sweep_id: str) -> str | None:
    body = expect(nano.api.get(f"/api/hunts/sweeps/{sweep_id}/tasks"), 200)
    return next((t.get("id") for t in _rows(body, "tasks") if t.get("kind") == "investigator"), None)


def _report_body(runner_id: str, fence: Any, task: str | None, candidates: list[dict[str, Any]]) -> dict:
    body: dict[str, Any] = {
        "runner_id": runner_id,
        "runner_fence": fence,
        "turns_used": 14,
        "tool_calls_used": 37,
        "rows_read": 4200,
        "wall_seconds": 312,
        "report": {
            "candidates": candidates,
            "trail": [
                {
                    "kind": "search",
                    "detail": f'source_type="{rp.LANE}" | stats count by device.hostname',
                    "rows_matched": 432,
                    "rows_read": 432,
                }
            ],
            "claimed_outcome": "completed",
            "note": "Realistic seed (NAN-5764): deterministic findings with long narratives.",
            "attribution": {"engine": "claude", "provider": "nano-e2e", "model": "deterministic"},
        },
    }
    if task:
        body["task_id"] = task
    return body


def _findings(nano: Nano, todo: list[tuple[dict[str, Any], rp.HuntSpec]], report: Report) -> None:
    """File each hunt's findings on ITS OWN sweep (one in flight per hunt).

    A claim is a global FIFO pop over every queued desktop sweep, so each
    claimed sweep is matched to its hunt by `playbook_id`: a seed hunt's sweep
    gets that hunt's findings, whichever order the queue hands them out in; a
    sweep of any other hunt is never reported on (the short lease returns it
    to the queue). A sweep an earlier, interrupted run of the seed still holds
    is reported under its own fence."""
    need: dict[str, tuple[dict[str, Any], rp.HuntSpec]] = {}
    for hunt, spec in todo:
        hid = _hid(hunt)
        leads = _rows(
            expect(nano.api.get("/api/hunts/leads", params={"playbook_id": hid, "limit": 100}), 200), "leads"
        )
        if leads:
            report.found("hunt_findings", len(leads))
        else:
            need[hid] = (hunt, spec)
    if not need:
        return
    runner = _runner(nano, report)

    def file(hid: str, sweep_id: str, fence: Any, task: str | None) -> None:
        hunt, spec = need.pop(hid)
        candidates = _candidates(nano, spec, report)
        body = _report_body(runner["id"], fence, task, candidates)
        res = expect(nano.api.post(f"/api/hunts/sweeps/{sweep_id}/report", json=body), 200)
        report.made("hunt_findings", len(candidates))
        report.ids.setdefault("sweep_reports", []).append(res)

    sweeps = {hid: _own_sweep(nano, hid) for hid in list(need)}
    for hid, sweep in sweeps.items():
        held = sweep.get("status") in ("leased", "running") and _same(sweep.get("runner_id"), runner["id"])
        if held and sweep.get("runner_fence") is not None:
            file(hid, sweep["id"], sweep["runner_fence"], _investigator_task(nano, sweep["id"]))
    for _ in range(len(need) + 8):  # bounded: our sweeps plus a few foreign ones ahead of them
        if not need:
            return
        claim = expect(
            nano.api.post(f"/api/hunts/runners/{runner['id']}/claim", json={"lease_seconds": SWEEP_LEASE_S}),
            200,
        ).get("sweep")
        if not claim:
            break
        got = claim.get("sweep") or {}
        hid = next((h for h in need if _same(h, got.get("playbook_id"))), None)
        if hid is None:
            report.gaps.append(
                f"claimed sweep {got.get('id')} of another hunt: not reported on, lease left to lapse"
            )
            continue
        task = claim.get("task_id") or next(
            (t.get("id") for t in claim.get("tasks", []) if t.get("kind") == "investigator"), None
        )
        file(hid, got["id"], claim.get("runner_fence", got.get("runner_fence")), task)
    for hid, (_, spec) in need.items():
        report.gaps.append(
            f"hunt findings for {spec.title[:60]}: its sweep {sweeps[hid].get('id')} was not handed "
            "to the seed's runner (held elsewhere); a re-run files them"
        )


def _hunt_body(spec: rp.HuntSpec) -> dict[str, Any]:
    return {
        "title": spec.title,
        "subtitle": spec.subtitle,
        "category": spec.category,
        "doc": spec.doc,
        "tags": list(spec.tags),
        "sweep_query": f'source_type="{rp.LANE}" | stats count by device.hostname',
        "mitre_tactic": spec.tactic,
        "mitre_technique": spec.technique,
        "hypothesis": spec.hypothesis,
        "runner_kind": "desktop",
        "reviewer_enabled": False,
        "lookback_window": "24h",
        "escalation_mode": "off",
    }


def _hunts(nano: Nano, plan: rp.Plan, report: Report) -> None:
    have = _all_hunts(nano)
    todo: list[tuple[dict[str, Any], rp.HuntSpec]] = []
    for spec in plan.hunts:
        hunt = have.get(spec.title)
        if hunt is None and spec.archived and _audited(nano, spec.title, ("archive", "delete")):
            report.found("hunts_archived")
            continue
        if hunt is None:
            hunt = expect(nano.api.post("/api/hunts", json=_hunt_body(spec)), 200, 201)
            hunt = hunt.get("hunt", hunt)
            report.made("hunts")
        else:
            report.found("hunts")
        if spec.findings and not spec.archived:
            todo.append((hunt, spec))
        if spec.archived and str(hunt.get("status", "")).lower() != "archived":
            expect(nano.api.delete(f"/api/hunts/{_hid(hunt)}"), 200, 204)
            report.made("hunts_archived")
            _await_audit(nano, spec.title, report)
    try:
        _findings(nano, todo, report)
    except AssertionError as exc:
        report.gaps.append(f"hunt findings: {str(exc)[:300]}")
    for d in plan.drafts:
        if d.title in have:
            report.found("hunt_drafts")
            continue
        for tech in d.techniques:
            out = expect(
                nano.api.post(
                    "/api/hunts/drafts",
                    json={
                        "drafts": [
                            {
                                "title": d.title,
                                "category": d.category,
                                "doc": d.doc,
                                "sweep_query": "class_uid=3002 | stats count by actor.user.name",
                                "mitre_tactic": d.tactic,
                                "mitre_technique": tech,
                                "required_source_types": [rp.LANE],
                            }
                        ]
                    },
                ),
                200,
            )
            status = (out.get("drafts") or [{}])[0].get("status")
            if status == "created":
                report.made("hunt_drafts")
                break
        else:
            report.gaps.append(f"hunt draft {d.title}: no free technique in {d.techniques}")


# ---------------------------------------------------------------- SOAR
def _soar_on(admin: Nano, report: Report) -> bool:
    settings = expect(admin.api.get("/api/soar/settings"), 200)
    if settings.get("soar_enabled"):
        report.found("soar_enabled")
        return True
    resp = admin.api.put(
        "/api/soar/settings",
        json={
            "soar_enabled": True,
            "expected_revision": settings.get("revision", 0),
            "reason": "realistic e2e seed (NAN-5764)",
        },
    )
    if resp.status_code != 200:
        report.gaps.append(f"SOAR switch: {resp.status_code} {resp.text[:200]}")
        return False
    report.made("soar_enabled")
    return True


def _packs(nano: Nano, report: Report, started: float) -> None:
    """Install every available pack. The catalog arrives through the license's
    content channel a few minutes after bring-up, so it is waited for only
    while the stack is younger than CATALOG_WAIT_S: a re-run on an older stack
    with no catalog checks once instead of waiting again."""

    def packs() -> list[dict[str, Any]]:
        return _rows(expect(nano.api.get("/api/soar/packs"), 200), "packs")

    budget = max(0.0, CATALOG_WAIT_S - (time.time() - started)) if started else CATALOG_WAIT_S
    try:
        listed = eventually(packs, timeout=budget, interval=10, desc="the SOAR catalog's packs", ok=bool)
    except Timeout:
        listed = []
    if not listed:
        report.gaps.append(
            "SOAR catalog: no packs published to this stack (the playbooks/integrations channel did not "
            f"apply within {CATALOG_WAIT_S:.0f}s of bring-up); the full-catalog surface is NOT seeded"
        )
        return
    for p in listed:
        if p.get("installed"):
            report.found("soar_packs")
            continue
        if p.get("availability") != "available":
            report.found(f"soar_packs_{p.get('availability')}")
            continue
        resp = nano.api.post(
            f"/api/soar/packs/{p['name']}/install", json={"version": p["version"], "upgrade": False}
        )
        if resp.status_code == 200:
            report.made("soar_packs")
        else:
            report.gaps.append(f"SOAR pack {p['name']}: {resp.status_code} {resp.text[:200]}")


def _flows(admin: Nano, nano: Nano, plan: rp.Plan, report: Report) -> None:
    """Top each seeded flow up to its planned number of unfinished runs (a
    run waiting on its approval is unfinished; an expired one is not). All
    missing runs start first, then one wait covers them all."""
    # GET /api/soar/flows takes no paging: one request lists every flow.
    have = {f.get("name"): f for f in _rows(expect(nano.api.get("/api/soar/flows"), 200), "flows")}
    runs = _paged(
        lambda lim, off: expect(nano.api.get("/api/soar/runs", params={"limit": lim, "offset": off}), 200),
        "runs",
        limit=100,
    )
    open_runs: dict[str, int] = {}
    for r in runs:
        if str(r.get("status", "")).lower() not in RUN_TERMINAL:
            key = str(r.get("flow_id"))
            open_runs[key] = open_runs.get(key, 0) + 1
    started: list[str] = []
    for spec in plan.flows:
        flow = have.get(spec.name)
        if flow is None:
            flow = expect(
                admin.api.post(
                    "/api/soar/flows",
                    json={
                        "name": spec.name,
                        "status": "live",
                        "trigger": {"on": "manual"},
                        "definition": {"summary": spec.description, "value": {"modules": list(spec.modules)}},
                    },
                ),
                200,
                201,
            )
            report.made("soar_flows")
        else:
            report.found("soar_flows")
        waiting = open_runs.get(str(flow["id"]), 0)
        report.found("pending_approvals", min(waiting, spec.runs))
        for _ in range(max(0, spec.runs - waiting)):
            run = expect(
                admin.api.post(f"/api/soar/flows/{flow['id']}/run", json={"inputs": {}, "dry_run": False}),
                200,
                201,
                202,
            )
            started.append(str(run["id"]))
    if not started:
        return

    def pending_ids() -> set[str]:
        rows = _paged(
            lambda lim, off: expect(
                nano.api.get(
                    "/api/soar/approvals", params={"status": "pending", "limit": lim, "offset": off}
                ),
                200,
            ),
            "approvals",
            limit=100,
        )
        return {str(a.get("run_id")) for a in rows}

    eventually(
        lambda: set(started) - pending_ids(),
        timeout=180,
        interval=3,
        desc=f"all {len(started)} new SOAR runs waiting on their approval",
        ok=lambda left: not left,
    )
    report.made("pending_approvals", len(started))


# ---------------------------------------------------------------- entry point
def apply(
    stack: Stack,
    plan: rp.Plan | None = None,
    *,
    journal: Journal | None = None,
    labels: Callable[[str], dict[str, str]] | None = None,
) -> Report:
    """Seed `stack` (idempotent, resumable). Refuses any stack the harness did
    not create (`check_target`)."""
    info = check_target(stack, labels=labels)
    plan = plan or rp.build()
    report = Report()
    journal = journal or Journal(stack.artifact_dir / "realistic-seed-api.jsonl")
    journal.remember(stack.api_key, stack.admin_password)
    nano = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key}, journal)
    t0 = time.monotonic()
    try:
        with _timed(report, "sources"):
            sources = _sources(nano, plan, report)
        lane = next(s for s in plan.sources if s.active)
        if lane.name not in sources:
            raise RuntimeError(f"the realistic lane source could not be created: {report.gaps[-1:]}")
        with _timed(report, "events"):
            _events(stack, nano, plan, sources[lane.name], report)
        with _timed(report, "rules"):
            _rules(nano, plan, report)
        with _timed(report, "dashboards"):
            _dashboards(nano, plan, report)
        if stack.edition == "open":
            report.gaps.append("open edition: cases, hunts and SOAR are enterprise surfaces (not seeded)")
        else:
            with _timed(report, "cases"):
                _cases(nano, plan, report)
            with _timed(report, "hunts"):
                _hunts(nano, plan, report)
            with _session(stack, journal) as admin:
                if _soar_on(admin, report):
                    with _timed(report, "soar_packs"):
                        _packs(nano, report, info.started)
                    with _timed(report, "soar_flows"):
                        _flows(admin, nano, plan, report)
    finally:
        nano.close()
        report.seconds["total"] = round(time.monotonic() - t0, 1)
        out = stack.artifact_dir / "realistic-seed.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.as_dict(), indent=2, default=str))
    return report


def scrub_artifacts(stack: Stack) -> list[str]:
    """Scrub every registered secret (and the stack's env-file secrets and the
    C05 license file) from the run's artifacts; the files still holding one."""
    run_dir = Path(stack.run_dir)
    license_file = os.environ.get("NANO_E2E_C05_LICENSE_FILE", "")
    secrets = artifact_guard.load(
        artifact_guard.registry_path(run_dir),
        [run_dir / "stack.env", run_dir / "compose.env", run_dir / "admin.env"],
        [Path(os.path.expanduser(license_file))] if license_file else [],
    )
    return artifact_guard.scrub(Path(stack.artifact_dir), secrets)


_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def main(argv: list[str] | None = None) -> int:
    from nano_e2e import stackenv

    ap = argparse.ArgumentParser(prog="nano_e2e.realistic_seed", description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--run", help="the kept stack's run id (default: the current one)")
    ap.add_argument("--stack-env", help="an explicit stack.env path")
    ap.add_argument("--strict", action="store_true", help="exit 1 when any step recorded a gap")
    args = ap.parse_args(argv)
    if args.run and not _RUN_ID.match(args.run):
        ap.error("--run must be a run id")
    stack = stackenv.load(args.run, args.stack_env)
    try:
        check_target(stack)
    except UnsafeTarget as exc:
        print(f"ERR {exc}", file=sys.stderr)
        return 2
    artifact_guard.remember(*artifact_guard.env_secrets(), run_dir=stack.run_dir)
    status = 0
    try:
        report = apply(stack)
        print(json.dumps({k: v for k, v in report.as_dict().items() if k != "ids"}, indent=2))
        status = 1 if (args.strict and report.gaps) else 0
    finally:
        left = scrub_artifacts(stack)
        if left:
            print("E2E-SECURITY: secret value(s) remain in artifacts after scrubbing:", file=sys.stderr)
            for f in left:
                print(f"  {f}", file=sys.stderr)
            status = 3
    return status


if __name__ == "__main__":
    sys.exit(main())

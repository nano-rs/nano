"""A SOC team for the deep workflow scenarios (NAN-5685): throwaway people with
distinct roles, real alerts from real detection rules over OCSF events, and
the reads every scenario compares the browser with.

- `TIER1` / `TIER2` / `MANAGER`: explicit permission sets. Tier 1 triages and
  works cases; tier 2 also closes, approves SOAR runs and triages hunts; the
  manager owns flows, hunts and the audit log. None is an admin.
- `fire_rule`: OCSF events through the session's OCSF lane, an `alerting`
  scheduled rule over them, forced to run; returns the rule and its alerts.
- `case_settings`: the case settings for one scenario, restored afterwards.
- `bug_shot`: an acceptance screenshot that is also copied to
  `E2E_BUG_SHOT_DIR` (when set) for the bug report.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.soar_ui import uuid_of
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually

# A schedule that never comes due during a scenario (once a year).
IDLE_CRON = "0 0 1 1 *"

TIER1 = [
    "alerts:view",
    "alerts:acknowledge",
    "alerts:assign",
    "cases:view",
    "cases:create",
    "cases:edit",
    "cases:assign",
    "cases:comment",
    "notebooks:view",
    "notebooks:create",
    "notebooks:edit",
    "users:view",
    "groups:view",
    "search:view",
    "search:execute",
    "soar:view",
]

TIER2 = [
    *TIER1,
    "alerts:close",
    "cases:close",
    "soar:run",
    "soar:approve",
    "hunts:view",
    "hunts:triage",
]

MANAGER = [
    *TIER2,
    "soar:manage",
    "hunts:manage",
    "hunts:run",
    "audit:view",
    "detections:view",
]


def short(mark: str) -> str:
    return re.sub(r"[^a-z0-9]", "", mark.lower())[-8:]


def fire_rule(
    stack: Stack,
    nano: Nano,
    lane: Any,
    mark: str,
    name: str,
    *,
    severity: str = "high",
    events: int = 2,
    user: str | None = None,
    host: str = "deep-host",
    ip: str = "203.0.113.50",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """`events` OCSF auth events tagged `<mark> <name>`, an alerting rule over
    them, triggered once; (rule, its alerts) once at least one alert exists."""
    tag = f"{mark} {name}"
    who = user or f"{name}-user"
    for i in range(events):
        lane.send(stack, mark, who, ip, host, note=f"{name} seq={i}")
    eventually(
        lambda: nano.search(f'"{mark}" "{name}"')["total_count"],
        timeout=INGEST_VISIBLE,
        desc=f"{name}: events searchable",
        ok=lambda n: n >= events,
    )
    rule = expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": name,
                "description": f"nano-e2e deep workflows (NAN-5685) {tag}",
                "query": f'source_type="{lane.lane}" "{mark}" "{name}"',
                "severity": severity,
                # Only the explicit /trigger calls fire it: a 1-minute
                # schedule could raise an extra alert between waves.
                "schedule_cron": IDLE_CRON,
                "mode": "alerting",
                "detection_mode": "scheduled",
                "lookback_minutes": 15,
            },
        ),
        200,
        201,
    )
    expect(nano.api.post(f"/api/rules/{rule['id']}/trigger"), 200)
    alerts = eventually(
        lambda: rule_alerts(nano, rule["id"]),
        timeout=DETECTION,
        interval=3,
        desc=f"{name}: alert",
        ok=bool,
    )
    return rule, alerts


def rule_alerts(nano: Nano, rule_id: str) -> list[dict[str, Any]]:
    body = expect(nano.api.get("/api/alerts", params={"rule_id": rule_id, "limit": 50}), 200)
    return body if isinstance(body, list) else body.get("alerts", [])


def retrigger(
    stack: Stack,
    nano: Nano,
    lane: Any,
    mark: str,
    rule: dict[str, Any],
    name: str,
    n: int,
    *,
    host: str = "deep-host",
    ip: str = "203.0.113.50",
) -> None:
    """More events for an existing rule, then force it again. `host`/`ip`
    must match what `fire_rule` sent when the scenario depends on grouping."""
    for i in range(n):
        lane.send(stack, mark, f"{name}-user", ip, host, note=f"{name} again={i}")
    eventually(
        lambda: nano.search(f'"{mark}" "{name}" "again"')["total_count"],
        timeout=INGEST_VISIBLE,
        desc=f"{name}: second wave searchable",
        ok=lambda c: c >= n,
    )
    expect(nano.api.post(f"/api/rules/{rule['id']}/trigger"), 200)


def delete_rule(nano: Nano, rule_id: str) -> None:
    nano.api.delete(f"/api/rules/{rule_id}")


@contextmanager
def case_settings(nano: Nano, **overrides: Any) -> Iterator[dict[str, Any]]:
    original = expect(nano.api.get("/api/settings/cases"), 200)
    try:
        yield expect(nano.api.put("/api/settings/cases", json={**original, **overrides}), 200)
    finally:
        expect(nano.api.put("/api/settings/cases", json=original), 200)


def case_full(client: Nano, case_id: str) -> dict[str, Any]:
    return expect(client.api.get(f"/api/cases/{case_id}"), 200)


def case_of(client: Nano, case_id: str) -> dict[str, Any]:
    body = case_full(client, case_id)
    return body.get("case", body)


def events_of(client: Nano, case_id: str) -> list[dict[str, Any]]:
    return case_full(client, case_id).get("workflow_events") or []


def audit_for(
    client: Nano, resource_uuid: str, *, resource_type: str, since: str, action: str | None = None
) -> list[dict[str, Any]]:
    """Audit rows about one resource, read as `client` (a person holding
    audit:view), filtered server-side by type, start time and action."""
    params: dict[str, Any] = {"resource_type": resource_type, "start_time": since, "limit": 500}
    if action:
        params["action"] = action
    body = expect(client.api.get("/api/audit", params=params), 200)
    want = uuid_of(resource_uuid)
    return [r for r in body["logs"] if uuid_of(str(r.get("resource_id") or "")) == want]


def audit_actions(client: Nano, *, action: str, since: str, **params: Any) -> list[dict[str, Any]]:
    """Audit rows of one action since `since`, read as `client`."""
    body = expect(
        client.api.get("/api/audit", params={"action": action, "start_time": since, "limit": 200, **params}), 200
    )
    return body["logs"]


def now_iso() -> str:
    """A scenario's start for server-side time filters (a minute early: clock skew)."""
    from datetime import UTC, datetime, timedelta

    return (datetime.now(UTC) - timedelta(minutes=1)).isoformat()


def notifications(client: Nano) -> list[dict[str, Any]]:
    body = expect(client.api.get("/api/notifications", params={"limit": 50}), 200)
    return body if isinstance(body, list) else body.get("notifications", [])


def notebook_entries(client: Nano, case_id: str) -> list[dict[str, Any]]:
    nb = expect(client.api.get(f"/api/cases/{case_id}/notebook"), 200)
    if not nb:
        return []
    return expect(client.api.get(f"/api/notebooks/{nb['id']}/entries"), 200)


def entries_text(entries: list[dict[str, Any]]) -> str:
    return json.dumps([e.get("content") for e in entries], sort_keys=True)


def bug_shot(page: uilib.UiPage, name: str) -> Path:
    """Screenshot into the scenario artifacts and, for the bug report, into
    E2E_BUG_SHOT_DIR when set."""
    shot = page.screenshot(name)
    dest = os.environ.get("E2E_BUG_SHOT_DIR", "")
    if dest:
        Path(dest).mkdir(parents=True, exist_ok=True)
        shutil.copy(shot, Path(dest) / name)
    return shot


# ---------------------------------------------------------------- case page ops
def open_case(page: uilib.UiPage, case_id: str, title: str) -> None:
    page.goto(f"/cases/{case_id}")
    page.wait_text(title, exact=False, timeout_ms=60_000)


def compose(page: uilib.UiPage, text: str) -> None:
    """Type into the case composer and send with Enter."""
    box = {"role": "textbox", "name": uilib.rx("^Ask the agent, or add a note")}
    page.wait_for(box, timeout_ms=30_000)
    eventually(lambda: page.attr(box, "disabled"), timeout=30, desc="composer enabled", ok=lambda d: d is None)
    page.fill(uilib.field(box, text))
    page.press_key(box, "Enter")


def close_case_ui(page: uilib.UiPage, reason: str) -> None:
    """The guided close flow: pick `reason` (tile label), acknowledge, confirm."""
    page.click({"role": "button", "name": "Close case", "exact": True})
    flow = {"testid": "close-case-flow"}
    page.wait_for(flow, timeout_ms=30_000)
    page.click({"role": "button", "name": uilib.rx("^" + re.escape(reason)), "within": flow})
    page.click({"role": "checkbox", "name": "Confirm case resolution", "exact": True, "within": flow})
    confirm = {"role": "button", "name": f"Close as {reason}", "exact": True, "within": flow}
    eventually(
        lambda: page.attr(confirm, "disabled"),
        timeout=15,
        interval=0.3,
        desc="close confirmation enabled",
        ok=lambda d: d is None,
    )
    page.press_key(confirm, "Enter")
    page.wait_for(flow, gone=True, timeout_ms=30_000)


PENDING_KINDS = {
    "await-user": "Waiting on user",
    "await-approval": "Waiting on approval",
    "await-vendor": "Waiting on vendor",
    "scheduled": "Scheduled re-check",
    "hold": "On hold",
}


def move_to_pending(page: uilib.UiPage, kind: str, context: str) -> None:
    """Workflow bar > Move to pending > <kind>, with context, confirmed."""
    menu = {"testid": "pending-menu"}
    page.click({"role": "button", "name": "Move to pending", "exact": True})
    page.wait_for(menu)
    page.click({"css": f'[data-pending-kind="{kind}"]', "within": menu})
    page.fill(uilib.field({"role": "textbox", "name": "Pending context", "exact": True, "within": menu}, context))
    page.click({"role": "button", "name": "Move to pending", "exact": True, "within": menu})
    page.wait_for(menu, gone=True, timeout_ms=30_000)

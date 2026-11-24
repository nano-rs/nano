"""Rule lifecycle setup shared by the open and enterprise lifecycle scenarios
(NAN-5765): three alerting rules mapped to one ATT&CK technique fire real
alerts over OCSF events, a fourth live rule matches enough events today to
count as noisy, then one is deleted from its row menu and the other three
with the Rules page's bulk bar, in the browser.

`deleted_rules(...)` does all of it and yields the `Deleted` record; a
`before_delete(deleted, nano)` hook adds a module's own positive controls
(e.g. SIEM Health, enterprise-only) before anything is deleted.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import httpx
import pytest

from nano_e2e import lifecycle
from nano_e2e import soar_ui as s
from nano_e2e import soc_team as t
from nano_e2e import ui as uilib
from nano_e2e.client import Journal, Nano, expect
from nano_e2e.runid import marker as make_marker
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually

FOLDER = "Automated"
# Preferred mapping (Brute Force); a stack whose ATT&CK catalog lacks it (the
# signed-content fixture catalog) uses its first technique instead.
PREFERRED = ("TA0006", "T1110")
NOISY_EVENTS = 1200  # past SIEM Health's 1000/day and health-summary's 500/week noisy bars

DE = (
    "search:view",
    "search:execute",
    "detections:view",
    "detections:create",
    "detections:edit",
    "detections:promote",
    "detections:delete",
    "alerts:view",
)


@dataclass
class Deleted:
    names: list[str]  # alerting rules that fired (names[0] deleted alone)
    noisy: str  # the live noisy rule (bulk-deleted)
    ids: dict[str, str]
    alerts: dict[str, list[dict[str, Any]]]
    fleet_before: dict[str, Any]
    summary_before: dict[str, Any]
    tag: str
    technique: str = ""

    @property
    def all_names(self) -> list[str]:
        return [*self.names, self.noisy]

    @property
    def needles(self) -> set[str]:
        out = set(self.all_names)
        for rid in self.ids.values():
            out |= lifecycle.id_spellings(rid, "rule")
        return out


def _rules(client: Nano, archived: bool = False) -> list[dict[str, Any]]:
    params = {"include_archived": "true"} if archived else None
    body = expect(client.api.get("/api/rules", params=params), 200)
    return body if isinstance(body, list) else body.get("rules", body.get("items", []))


def _coverage(client: Nano) -> Any:
    return expect(client.api.get("/api/mitre/coverage", params={"mode": "alerting,live,paused,staging"}), 200)


def _ch(stack: Stack, sql: str) -> str:
    r = httpx.post(stack.ch_url, content=sql.encode(), auth=(stack.ch_admin_user, stack.ch_admin_password),
                   timeout=120)
    assert r.status_code == 200, f"{r.status_code}: {r.text[:800]}"
    return r.text.strip()


def _noisy_events(stack: Stack, source_type: str, rows: int) -> None:
    """`rows` OCSF events of `source_type` within the last 4 minutes."""
    _ch(
        stack,
        f"""INSERT INTO nanosiem.ocsf_logs_raw (event, source_type)
        SELECT concat('{{"time":', toString(toUnixTimestamp64Milli(now64(3)) - number * 200),
          ',"class_uid":3002,"category_uid":3,"activity_id":1,"severity_id":1,',
          '"metadata":{{"log_source":"{source_type}","product":{{"name":"e2e"}}}}}}'), '{source_type}'
        FROM numbers({rows})""",
    )


def _mapping(nano: Nano) -> tuple[str, str]:
    """(tactic, technique) present in this stack's ATT&CK catalog."""
    from nano_e2e.hunt_coverage import wait_catalog

    wait_catalog(nano)  # a fresh stack installs the catalog after boot
    cat = expect(nano.api.get("/api/mitre"), 200)
    techs = {x["id"]: x for x in cat.get("techniques", []) if not x.get("deprecated")}
    if PREFERRED[1] in techs and PREFERRED[0] in (techs[PREFERRED[1]].get("tactic_ids") or []):
        return PREFERRED
    for tid, x in techs.items():
        if x.get("tactic_ids") and not x.get("is_subtechnique"):
            return x["tactic_ids"][0], tid
    pytest.skip("the stack's ATT&CK catalog has no technique to map")


def _detection_metrics(nano: Nano) -> dict[str, Any]:
    expect(nano.api.post("/api/siem-health/reports/trigger", timeout=300), 200)
    report = expect(nano.api.get("/api/siem-health/reports/latest"), 200)
    return (report.get("metrics") or {}).get("detection") or {}



def tag_of(module: str) -> str:
    return hashlib.sha256(module.encode()).hexdigest()[:6]


@contextmanager
def deleted_rules(
    stack: Stack,
    ocsf_lane: Any,
    page: uilib.UiPage,
    module: str,
    before_delete: Callable[[Deleted, Nano], None] | None = None,
) -> Iterator[Deleted]:
    """Create, fire and delete the lifecycle rules (see the module doc).
    `module` names the calling test module (run markers, the setup journal)."""
    nano = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key},
                Journal(stack.artifact_dir / "scenarios" / f"lifecycle-rule-setup-{tag_of(module)}.jsonl"))
    mark = make_marker(module, "module")
    tag = t.short(mark)
    made: list[str] = []
    tactic, technique = _mapping(nano)
    try:
        names = [f"lifecycle_rule_{i}_{tag}" for i in ("single", "bulk_a", "bulk_b")]
        alerts: dict[str, list[dict[str, Any]]] = {}
        ids: dict[str, str] = {}
        for name in names:
            for i in range(2):
                ocsf_lane.send(stack, mark, f"{name}-user", "203.0.113.50", "deep-host", note=f"{name} seq={i}")
            eventually(lambda name=name: nano.search(f'"{mark}" "{name}"')["total_count"], timeout=INGEST_VISIBLE,
                       desc=f"{name}: events searchable", ok=lambda n: n >= 2)
            rule = expect(nano.api.post("/api/rules", json={
                "name": name, "description": "nano-e2e lifecycle (NAN-5765)",
                "query": f'source_type="{ocsf_lane.lane}" "{mark}" "{name}"', "severity": "high",
                "schedule_cron": t.IDLE_CRON, "mode": "alerting", "detection_mode": "scheduled",
                "lookback_minutes": 15, "folder": FOLDER, "mitre_tactics": [tactic],
                "mitre_techniques": [technique],
            }), 200, 201)
            made.append(rule["id"])
            ids[name] = rule["id"]
            expect(nano.api.post(f"/api/rules/{rule['id']}/trigger"), 200)
            alerts[name] = eventually(lambda rid=rule["id"]: t.rule_alerts(nano, rid), timeout=DETECTION,
                                      interval=3, desc=f"{name}: alert", ok=bool)

        # A live rule with enough matches today to be noisy everywhere.
        noisy = f"lifecycle_rule_noisy_{tag}"
        key = f"e2e_nan5765_noisy_{tag}"
        _noisy_events(stack, key, NOISY_EVENTS)
        rule = expect(nano.api.post("/api/rules", json={
            "name": noisy, "description": "nano-e2e lifecycle (NAN-5765)", "query": f'source_type="{key}"',
            "severity": "low", "schedule_cron": t.IDLE_CRON, "mode": "live", "detection_mode": "scheduled",
            "lookback_minutes": 15, "folder": FOLDER, "mitre_tactics": [tactic], "mitre_techniques": [technique],
        }), 200, 201)
        made.append(rule["id"])
        ids[noisy] = rule["id"]

        def noisy_today() -> int:
            # Each run adds its matched events to today's stats; /api/rules/noisy
            # (7-day totals, live rules only) reads them back.
            expect(nano.api.post(f"/api/rules/{rule['id']}/trigger"), 200)
            body = expect(nano.api.get("/api/rules/noisy", params={"limit": 100}), 200)
            rows = body if isinstance(body, list) else body.get("rules", body.get("items", []))
            mine = [r for r in rows if r.get("name") == noisy or r.get("rule_name") == noisy]
            return int((mine[0].get("total_matches") or mine[0].get("match_count") or 0) if mine else 0)

        eventually(noisy_today, timeout=DETECTION * 2, interval=15,
                   desc="the noisy rule records > 1000 matches today", ok=lambda n: n > 1000)

        d = Deleted(names, noisy, ids, alerts, {}, {}, tag, technique)
        # Every summary lists them before the delete (else "absent" proves nothing).
        lifecycle.present(lambda: _coverage(nano), set(d.all_names), what="MITRE coverage")
        lifecycle.present(lambda: expect(nano.api.get("/api/rules/noisy"), 200), {noisy},
                          what="GET /api/rules/noisy", timeout=60)
        d.fleet_before = expect(nano.api.get("/api/rules/fleet-health"), 200)
        d.summary_before = expect(nano.api.get("/api/rules/health-summary"), 200)
        assert int(d.summary_before["noisy_count"]) >= 1, f"the noisy rule is not counted: {d.summary_before}"
        if before_delete is not None:
            before_delete(d, nano)

        # Single delete: the row menu.
        page.goto(f"/rules?ids={ids[names[0]]}")
        row = {"role": "row", "has": names[0]}
        page.wait_for(row, timeout_ms=30_000)
        page.click({"css": "button[aria-haspopup=menu]", "within": row})
        page.click({"role": "menuitem", "name": uilib.rx(r"^Delete")})
        dlg = {"role": "alertdialog", "has": "Delete 1 rule?"}
        page.wait_for(dlg)
        page.click({"role": "button", "name": "Delete 1 rule", "exact": True, "within": dlg})
        page.wait_for(row, gone=True, timeout_ms=30_000)

        # Bulk delete: select the rest, bulk bar > Delete.
        rest = [*names[1:], noisy]
        page.goto("/rules?ids=" + ",".join(ids[n] for n in rest))
        for n in rest:
            page.wait_for({"role": "row", "has": n}, timeout_ms=30_000)
            # The checkbox input is visually hidden: click its label.
            page.click({"css": f'label:has(> input[aria-label="Select {n}"])'})
        bar = {"role": "toolbar", "name": "Bulk rule actions"}
        if not page.count(bar):
            bar = {"css": '[aria-label="Bulk rule actions"]'}
        page.click({"role": "button", "name": "Delete", "exact": True, "within": bar})
        dlg = {"role": "alertdialog", "has": f"Delete {len(rest)} rules?"}
        page.wait_for(dlg)
        page.click({"role": "button", "name": f"Delete {len(rest)} rules", "exact": True, "within": dlg})
        for n in rest:
            page.wait_for({"role": "row", "has": n}, gone=True, timeout_ms=30_000)
        for rid in ids.values():
            eventually(lambda rid=rid: nano.api.get(f"/api/rules/{rid}").status_code, timeout=30,
                       desc=f"rule {rid} gone", ok=lambda c: c == 404)
        yield d
    finally:
        cleanup = s.Cleanup()
        cleanup.add("close the setup client", nano.close)
        for rid in made:
            cleanup.add(f"rule {rid}", lambda rid=rid: expect(nano.api.delete(f"/api/rules/{rid}"), 200, 204, 404))
        cleanup.close()



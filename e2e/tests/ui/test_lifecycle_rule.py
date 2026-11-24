"""Rule lifecycle (NAN-5765): delete rules that fired, then check every page
that summarizes rules, not only the Rules list.

A rule delete archives it (`DELETE /api/rules/{id}`: archived, staging, no
next run); its matches, alerts and signal logs are kept and stay linked. The
Rules page's bulk Delete deletes each selected rule (there is no bulk
endpoint). The module fixture makes three alerting rules mapped to one
ATT&CK technique that fire real alerts over OCSF events, plus a live rule
with enough matches today to count as noisy; one is deleted from its row
menu, the other three with the bulk bar, as a throwaway detection engineer.
Each scenario below then checks one summary:

- MITRE coverage (every mode) drops them, in the API and on /rules/coverage;
- detection health: fleet-health, the noisy list and health-summary's noisy
  count count only rules that exist;
- the rule editor rail: the Active tab and its folder count drop them, the
  Archived tab lists them, the footer counts what the tab lists;
- alerts: their alerts are history (kept, rule name shown), quietly.

SIEM Health's detection metrics (enterprise-only) are
tests/enterprise/ui/test_lifecycle_rule_siem_health.py, on the same setup
(nano_e2e.lifecycle_rules).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from nano_e2e import deep, lifecycle, schema
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.lifecycle_rules import DE, FOLDER, Deleted, _coverage, _rules, deleted_rules
from nano_e2e.soc_team import rule_alerts
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually


@pytest.fixture(scope="module")
def _de(stack: Stack, ui: uilib.Driver) -> Iterator[deep.ModulePersona]:
    with deep.module_persona(stack, ui, "rule-lifecycle", DE) as persona:
        yield persona


@pytest.fixture
def de(_de, request) -> Iterator[deep.Analyst]:
    with deep.analyst_for(_de, request) as a:
        yield a


@pytest.fixture(scope="module")
def deleted(stack: Stack, ocsf_lane, _de: deep.ModulePersona) -> Iterator[Deleted]:
    if not schema.is_ocsf():
        pytest.skip("the lifecycle rules match OCSF events")
    with deleted_rules(stack, ocsf_lane, _de.persona.page, "tests/ui/test_lifecycle_rule.py") as d:
        yield d


# ---------------------------------------------------------------- MITRE coverage
def test_mitre_coverage_drops_deleted_rules(nano: Nano, deleted: Deleted, de: deep.Analyst, timeline) -> None:
    lifecycle.absent(lambda: _coverage(nano), deleted.needles, what="GET /api/mitre/coverage")
    page = de.page
    technique = deleted.technique
    # The unified coverage page opens a technique's panel from `?tech=` (NAN-5850).
    page.goto(f"/rules/coverage?view=detections&tech={technique}")
    sheet = {"role": "dialog", "name": f"Technique {technique}", "exact": True}
    page.wait_for(sheet, timeout_ms=30_000)
    page.wait_for({"testid": "coverage-panel-detection"})
    text = " ".join(page.texts(sheet))
    timeline.step("coverage sheet", listed=[n for n in deleted.all_names if n in text])
    assert not [n for n in deleted.all_names if n in text], "the coverage sheet lists a deleted rule"
    assert not deep.new_page_errors(de)


# ---------------------------------------------------------------- detection health
def test_detection_health_counts_only_existing_rules(nano: Nano, deleted: Deleted, timeline) -> None:
    lifecycle.absent(lambda: expect(nano.api.get("/api/rules/noisy"), 200), deleted.needles,
                     what="GET /api/rules/noisy")
    # Fleet health counts the scheduled live/alerting rules that exist now.
    fleet = expect(nano.api.get("/api/rules/fleet-health"), 200)
    fleet_rules = [r for r in _rules(nano) if not r.get("archived") and r.get("mode") in ("live", "alerting")
                   and r.get("detection_mode") == "scheduled"]
    timeline.step("fleet", fleet=fleet, existing=len(fleet_rules))
    assert int(fleet["total"]) == len(fleet_rules), (fleet, len(fleet_rules))

    # health-summary's noisy count: never fewer than the live noisy rules,
    # and no more (a deleted rule is not noisy any more).
    summary = expect(nano.api.get("/api/rules/health-summary"), 200)
    rows = expect(nano.api.get("/api/rules/noisy", params={"limit": 100}), 200)["rules"]
    live_noisy = sum(1 for r in rows if int(r.get("match_count") or 0) > 500)
    count = int(summary["noisy_count"])
    timeline.step("health-summary", summary=summary, live_noisy=live_noisy)
    assert count >= live_noisy, f"health-summary noisy_count {count} < {live_noisy} live noisy rules"
    # NAN-5772: a deleted rule is not noisy any more.
    assert count == live_noisy, (
        f"health-summary noisy_count {count} > {live_noisy} live noisy rules (a deleted rule still counted)"
    )


# ---------------------------------------------------------------- rule folders
def _folder_count(text: str, folder: str) -> int:
    m = re.search(rf"{folder}\s*(\d+)", text)
    return int(m.group(1)) if m else 0


def test_rule_rail_folders_after_delete(nano: Nano, deleted: Deleted, de: deep.Analyst, timeline) -> None:
    page = de.page
    since = page.now_ms()
    page.goto("/rules/editor")
    rail = {"testid": "rule-editor-rail"}
    page.wait_for(rail, timeout_ms=30_000)
    lifecycle.page_loaded(page, "/api/rules", since)
    n = len(deleted.all_names)

    # Filtered to this module's rules: the Archived tab's folder holds all of
    # them (the positive control), the Active tab's none.
    filt = {"placeholder": "filter rules…", "within": rail}
    page.fill(uilib.field(filt, deleted.tag))
    page.click({"role": "tab", "name": "Archived", "exact": True, "within": rail})
    archived = eventually(lambda: _folder_count(page.texts(rail)[0], FOLDER), timeout=30, interval=1,
                          desc=f"the Archived tab's {FOLDER} folder lists them", ok=lambda c: c == n)
    page.screenshot("lifecycle-rule-rail-archived.png", full_page=False)
    page.click({"role": "tab", "name": "Active rules", "exact": True, "within": rail})
    active = eventually(lambda: _folder_count(page.texts(rail)[0], FOLDER), timeout=30, interval=1,
                        desc=f"the Active tab's {FOLDER} folder without the deleted rules", ok=lambda c: c == 0)
    timeline.step("rail folders", active=active, archived=archived)

    # The footer counts what the Active tab lists: never fewer than exist.
    page.fill(uilib.field(filt, ""))
    active_total = len([r for r in _rules(nano) if not r.get("archived")])
    footer = eventually(lambda: re.search(r"(\d+) rules? · (\d+) folders?", page.texts(rail)[0]), timeout=30,
                        interval=1, desc="the rail footer", ok=bool)
    shown = int(footer.group(1))
    timeline.step("rail footer", footer=footer.group(0), active=active_total)
    assert shown >= active_total, f"the rail footer shows {shown} rules, fewer than the {active_total} that exist"
    # NAN-5773: the footer counts what the Active tab lists.
    assert shown == active_total, f"rule rail footer counts deleted rules: {shown} rules shown > {active_total} exist"


# ---------------------------------------------------------------- alerts
def test_alerts_keep_deleted_rules_history(nano: Nano, deleted: Deleted, de: deep.Analyst, timeline) -> None:
    for name in deleted.names:
        alerts = rule_alerts(nano, deleted.ids[name])
        assert alerts, f"{name}: its alerts were dropped with the rule"
        assert {a.get("rule_name") for a in alerts} == {name}, [a.get("rule_name") for a in alerts]
    page = de.page
    page.goto("/alerts")
    page.wait_for({"testid": "alerts-search"}, timeout_ms=30_000)
    page.fill(uilib.field({"testid": "alerts-search"}, deleted.names[1]))
    eventually(lambda: page.count({"testid": "alert-row"}), timeout=30, interval=1,
               desc="the deleted rule's alerts listed", ok=bool)
    rows = " ".join(page.texts({"testid": "alert-row"}))
    timeline.step("alerts page", rows=rows[:300])
    assert deleted.names[1] in rows, rows[:300]
    assert not deep.new_page_errors(de)

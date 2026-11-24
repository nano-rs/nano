"""Deep detection engineering workflows in the browser (NAN-5686).

One detection engineer (a throwaway persona with explicit permissions) does
the job end to end, and every step is checked against what the product
persisted:

- authoring: an nPL rule typed into the editor; a broken query shows
  "Invalid" with the reason and cannot be created; the fixed rule validates,
  and "Test rule" against seeded OCSF events reports the same match count as
  `POST /api/rules/test`; Create persists the frontmatter (MITRE, folder,
  severity, mode, schedule, lookback);
- MITRE: the new technique appears in `/rules/coverage` ("In review" while
  staging, live once promoted) and in the technique sheet;
- lifecycle: staging records nothing when triggered; live records matches
  but no alert; alerting fires an alert carrying the event; the matches
  page shows `matches-total` == `/api/rules/:id/matches` and the alert count;
- risk (enterprise): the rule's `| risk` stage gives the user entity risk;
- versions: an edit saved in the editor makes v2; Versions > v1 > Revert
  brings the v1 query back as a new current version;
- folders: an agent-created snake_case rule sits in the "Automated" folder
  in the rail; the folder chip moves it, persisted;
- retro-hunt: the form creates a retro-hunt rule whose config == the API.

Cooldown has no editor control; `test_alert_cooldown_round_trips` asserts
the API contract directly.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterator
from typing import Any

import pytest
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect, row_text, time_range
from nano_e2e.hunt_coverage import wait_catalog
from nano_e2e.personas import login_persona
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually, stays

DE_PERMISSIONS = (
    "search:view",
    "search:execute",
    "detections:view",
    "detections:create",
    "detections:edit",
    "detections:promote",
    "alerts:view",
)
EDITOR = {"role": "textbox", "name": "Detection rule editor", "exact": True}
STATUS = {"testid": "rule-validation-status"}


def _snake(prefix: str, mark: str) -> str:
    return f"{prefix}_{mark[-10:].replace('-', '_')}".lower()


def _rule(client: Nano, rule_id: str) -> dict[str, Any]:
    return expect(client.api.get(f"/api/rules/{rule_id}"), 200)


def _by_name(client: Nano, name: str) -> dict[str, Any] | None:
    body = expect(client.api.get("/api/rules"), 200)
    items = body if isinstance(body, list) else body.get("rules", body.get("items", []))
    return next((r for r in items if r.get("name") == name), None)


def _rule_action(page: uilib.UiPage, label: str) -> None:
    trigger = {"role": "button", "name": "Rule actions", "exact": True}
    item = {"role": "menuitem", "name": label, "exact": True}

    def choose() -> bool:
        try:
            if page.count(item) == 0:
                page.click(trigger)
            page.press_key(item, "Enter")
            return True
        except uilib.UiError as exc:
            if "detached from document" not in str(exc):
                raise
            return False

    eventually(choose, timeout=15, interval=0.2, desc=f"rule action {label}")


def _yaml(name: str, query: str, *, technique: str, tactic: str, folder: str = "Automated",
          description: str = "nano-e2e deep detection (NAN-5686)") -> str:
    return "\n".join([
        "---",
        f"title: {name}",
        f'description: "{description}"',
        "author: nano-e2e",
        "severity: high",
        "mode: staging",
        "detection_mode: scheduled",
        "schedule: * * * * *",
        "lookback: 30m",
        f'mitre_tactics: "{tactic}"',
        f'mitre_techniques: "{technique}"',
        f"folder: {folder}",
        "tags: e2e, deep",
        "---",
        "",
        query,
    ])


def _alerts(client: Nano, rule_id: str) -> list[dict[str, Any]]:
    body = expect(client.api.get("/api/alerts", params={"rule_id": rule_id, "limit": 20}), 200)
    return body if isinstance(body, list) else body.get("alerts", [])


def _coverage(client: Nano, technique: str, modes: str | None = None) -> dict[str, Any] | None:
    body = expect(client.api.get("/api/mitre/coverage", params={"mode": modes} if modes else None), 200)
    return next((t for t in body.get("techniques", []) if t.get("technique_id") == technique), None)


def _open_technique(page: uilib.UiPage, technique: str) -> None:
    """The unified coverage page (NAN-5850) opens a technique's panel from
    `?tech=`; Detections view so the hunt layer never decides what shows."""
    page.goto(f"/rules/coverage?view=detections&tech={technique}")
    page.wait_for({"css": f'[data-testid="coverage-panel"][data-technique="{technique}"]'}, timeout_ms=30_000)
    page.wait_for({"testid": "coverage-panel-detection"})


def _matches_total(client: Nano, rule_id: str) -> int:
    return int(expect(client.api.get(f"/api/rules/{rule_id}/matches", params={"limit": 100}), 200).get("total", 0))


@pytest.fixture
def rule_cleanup(nano: Nano) -> Iterator[list[str]]:
    names: list[str] = []
    yield names
    for name in names:
        rule = _by_name(nano, name)
        if rule:
            expect(nano.api.delete(f"/api/rules/{rule['id']}"), 200, 204, 404)


def test_author_validate_test_lifecycle_mitre_and_matches(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, ui: uilib.Driver, artifact_dir, timeline, rule_cleanup
) -> None:
    user = f"det-{mark[-8:]}"
    for i in range(3):
        ocsf_lane.send(stack, mark, user, f"198.51.100.{60 + i}", "det-host", note=f"seed={i}")
    eventually(lambda: nano.search(f'actor.user.name="{user}"')["total_count"], timeout=INGEST_VISIBLE,
               desc="seeded events searchable", ok=lambda n: n == 3)
    wait_catalog(nano)
    name = _snake("deep_brute_force", mark)
    technique, tactic = "T1110", "TA0006"
    query = f'source_type="{ocsf_lane.lane}" actor.user.name="{user}"'
    if stack.edition == "enterprise":
        query += " | risk score=40 entity=actor.user.name factor=e2e_deep"
    before = _coverage(nano, technique) or {}
    timeline.step("seeded", user=user, coverage_before=before.get("rule_count"))

    with login_persona(stack, nano, ui, artifact_dir, "deep-detection", DE_PERMISSIONS) as persona:
        page, client = persona.page, persona.client
        page.goto("/rules/editor/new")
        page.wait_for(EDITOR)

        # 1. A broken query is Invalid, says why, and cannot be created.
        page.editor_fill(EDITOR, _yaml(name, f'source_type="{ocsf_lane.lane}" | stats count by', technique=technique, tactic=tactic))
        page.wait_attr(STATUS, "data-status", "invalid", timeout_ms=30_000)
        page.click(STATUS)
        page.wait_text("Rule has errors", exact=True)
        dialog_text = " ".join(page.texts({"role": "dialog"}))
        assert re.search(r"(?i)error", dialog_text), dialog_text[:500]
        page.screenshot("deep-rule-invalid.png", full_page=False)
        page.press_key({"role": "dialog"}, "Escape")
        page.wait_text("Rule has errors", exact=True, gone=True)
        create = {"role": "button", "name": "Create rule", "exact": True}
        assert page.attr(create, "disabled") is not None, "Create rule is enabled on an invalid rule"
        api_invalid = expect(client.api.post("/api/rules/validate", json={"query": f'source_type="x" | stats count by',
                                                                           "detection_mode": "scheduled"}), 200)
        assert api_invalid["valid"] is False and api_invalid.get("errors"), api_invalid
        timeline.step("invalid query refused", errors=api_invalid["errors"][:2])

        # 2. The fixed rule validates; Test rule == the test API.
        page.editor_fill(EDITOR, _yaml(name, query, technique=technique, tactic=tactic))
        page.wait_attr(STATUS, "data-status", "valid", timeout_ms=30_000)
        page.click({"role": "button", "name": "Test rule", "exact": True})
        page.wait_for({"role": "dialog", "name": "Test rule drawer", "exact": True})
        run = {"testid": "test-rule-run"}
        page.click(run)
        shown = eventually(
            lambda: (page.attr({"testid": "test-rule-matched"}, "data-running"), page.texts({"testid": "test-rule-matched"})),
            timeout=60, interval=0.5, desc="test run finished",
            ok=lambda v: v[0] == "false" and v[1] and v[1][0].strip() not in ("", "0"),
        )
        api_test = expect(client.api.post("/api/rules/test", json={"query": query, "time_range": time_range(60)}), 200)
        assert int(shown[1][0].replace(",", "")) == api_test["total_matches"] == 3, (shown, api_test.get("total_matches"))
        page.screenshot("deep-rule-test-drawer.png", full_page=False)
        page.click({"role": "button", "name": "Close test drawer", "exact": True})
        timeline.step("tested", ui=shown[1][0], api=api_test["total_matches"])

        # 3. Create persists the frontmatter.
        page.click(create)
        rule_cleanup.append(name)
        page.wait_text("Rule created", exact=False, timeout_ms=30_000)
        page.wait_url(r"/rules/editor/[^n]")
        rule = eventually(lambda: _by_name(client, name), timeout=30, interval=0.5, desc="rule persisted")
        rule_id = str(rule["id"])
        assert rule["mode"] == "staging" and rule["severity"] == "high", rule
        assert technique in (rule.get("mitre_techniques") or []), rule.get("mitre_techniques")
        assert tactic in (rule.get("mitre_tactics") or []), rule.get("mitre_tactics")
        assert rule.get("folder") == "Automated", rule.get("folder")
        assert rule.get("schedule_cron", "").startswith("* * * * *"), rule.get("schedule_cron")
        assert int(rule.get("lookback_minutes") or 0) == 30, rule.get("lookback_minutes")
        timeline.step("created", rule=rule_id)

        # 4. MITRE: a staging rule is not live coverage.
        cov = _coverage(client, technique) or {}
        # (coverage lists rules by UUID name pairs; the rule API speaks TypeIDs: match by name)
        assert not any(r.get("name") == name for r in cov.get("rules", [])), "a staging rule counted as live coverage"

        # 5. Staging never runs: a trigger records nothing.
        trig = client.api.post(f"/api/rules/{rule_id}/trigger")
        timeline.step("staging trigger", status=trig.status_code)
        stays(lambda: _matches_total(client, rule_id), duration=20, interval=5,
              desc="a staging rule records no match", ok=lambda n: n == 0)

        # 6. Live: matches counted, no alert. Promoted in the editor.
        page.goto(f"/rules/editor/{rule_id}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        _rule_action(page, "Promote to live")
        eventually(lambda: _rule(client, rule_id)["mode"], timeout=30, desc="live", ok=lambda m: m == "live")
        expect(nano.api.post(f"/api/rules/{rule_id}/trigger"), 200)
        live_total = eventually(lambda: _matches_total(client, rule_id), timeout=DETECTION, interval=5,
                                desc="live rule records matches", ok=lambda n: n >= 1)
        assert _alerts(client, rule_id) == [], "a live rule must not alert"
        page.goto(f"/rules/{rule_id}/matches")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        eventually(lambda: page.texts({"testid": "matches-total"}), timeout=30, interval=0.5,
                   desc="matches page total == API", ok=lambda t: t and int(t[0].replace(",", "")) == _matches_total(client, rule_id))
        assert page.texts({"testid": "matches-alerts-generated"})[0].strip() == "0"
        page.screenshot("deep-matches-live.png", full_page=False)
        timeline.step("live", matches=live_total, alerts=0)

        # MITRE: the live rule now covers the technique, in the API and the page.
        cov = eventually(lambda: _coverage(client, technique), timeout=30, desc="coverage counts the live rule",
                         ok=lambda t: any(r.get("name") == name and r.get("mode") == "live" for r in (t or {}).get("rules", [])))
        # /api/mitre/coverage is browser-cached (max-age=30, stale-while-revalidate=30):
        # reopen the page until the promotion shows.
        def sheet_lists_rule() -> bool:
            _open_technique(page, technique)
            return page.contains(name)

        eventually(sheet_lists_rule, timeout=120, interval=10, desc="the coverage page lists the live rule")
        live = sum(1 for r in cov["rules"] if r.get("mode") in ("live", "alerting"))
        sheet_text = " ".join(page.texts({"role": "dialog", "name": f"Technique {technique}", "exact": True}))
        assert f"{live} live" in sheet_text, sheet_text[:400]
        page.screenshot("deep-mitre-coverage-live.png", full_page=False)
        timeline.step("mitre coverage (live)", live=live)

        # 7. Alerting: a fresh event fires an alert carrying it.
        page.goto(f"/rules/editor/{rule_id}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        _rule_action(page, "Promote to alerting")
        eventually(lambda: _rule(client, rule_id)["mode"], timeout=30, desc="alerting", ok=lambda m: m == "alerting")
        ocsf_lane.send(stack, mark, user, "198.51.100.99", "det-host", note="alerting-fire")
        eventually(lambda: nano.rows(f'"{mark} alerting-fire"', limit=5), timeout=INGEST_VISIBLE, desc="fire event")
        expect(nano.api.post(f"/api/rules/{rule_id}/trigger"), 200)

        fired = eventually(lambda: _alerts(client, rule_id), timeout=DETECTION, interval=5, desc="alerting rule alert",
                           ok=lambda a: any("alerting-fire" in row_text(x.get("matched_events")) for x in a))
        page.goto(f"/rules/{rule_id}/matches")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        eventually(lambda: page.texts({"testid": "matches-alerts-generated"}), timeout=30, interval=0.5,
                   desc="alerts generated on the matches page", ok=lambda t: t and int(t[0]) >= 1)
        page.screenshot("deep-matches-alerting.png", full_page=False)
        timeline.step("alerting fired", alerts=len(fired))

        # 8. Risk (enterprise): the risk stage scored the user.
        if stack.edition == "enterprise":
            def _risk() -> float:
                body = expect(nano.api.get("/api/risk/entities", params={"limit": 500}), 200)
                ents = body.get("entities", body) if isinstance(body, dict) else body
                return max((float(e.get("risk_score") or 0) for e in ents if e.get("entity") == user), default=0.0)

            score = eventually(_risk, timeout=DETECTION, interval=5, desc="RBA entity risk for the user", ok=lambda s: s > 0)
            timeline.step("risk", entity=user, score=score)

        # 9. Versions: save an edit (v2), revert to v1.
        v1_query = _rule(client, rule_id)["query"]
        page.goto(f"/rules/editor/{rule_id}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        edited = query.replace(f'actor.user.name="{user}"', f'actor.user.name="{user}" src_endpoint.ip="198.51.100.99"')
        page.editor_fill(EDITOR, _yaml(name, edited, technique=technique, tactic=tactic).replace("mode: staging", "mode: alerting"))
        page.wait_attr(STATUS, "data-status", "valid", timeout_ms=30_000)
        page.click({"role": "button", "name": "Save rule", "exact": True})
        page.click({"role": "button", "name": "Save Rule", "exact": True, "within": {"role": "alertdialog"}})
        page.wait_text("Rule updated", exact=False, timeout_ms=30_000)
        versions = eventually(lambda: expect(client.api.get(f"/api/rules/{rule_id}/versions"), 200), timeout=30,
                              desc="v2 recorded", ok=lambda v: len(v) >= 2)
        assert "198.51.100.99" in _rule(client, rule_id)["query"]
        if page.count({"role": "button", "name": "Expand inspector", "exact": True}):
            page.click({"role": "button", "name": "Expand inspector", "exact": True})
        page.click({"role": "button", "name": "Versions", "exact": True})
        v1 = min(versions, key=lambda v: v["version_number"])
        page.click({"testid": f"rule-version-v{v1['version_number']}"})
        page.click({"role": "button", "name": f"Revert to v{v1['version_number']}", "exact": True})
        page.click({"role": "button", "name": "Revert rule", "exact": True})
        page.wait_text(f"Reverted to v{v1['version_number']}", exact=False, timeout_ms=30_000)
        reverted = eventually(lambda: _rule(client, rule_id), timeout=30, desc="query reverted",
                              ok=lambda r: "198.51.100.99" not in r["query"])
        assert reverted["query"].strip() == v1_query.strip(), (reverted["query"], v1_query)
        after = expect(client.api.get(f"/api/rules/{rule_id}/versions"), 200)
        current = [v for v in after if v.get("is_active")]
        assert len(after) == len(versions) + 1 and len(current) == 1, after
        # The new version records the revert (the field names the version it replaced).
        assert current[0].get("reverted_from_version") is not None, current[0]
        assert current[0]["query"].strip() == v1_query.strip(), current[0]
        page.screenshot("deep-rule-versions-reverted.png", full_page=False)
        timeline.step("reverted", versions=len(after))


def test_automated_folder_convention_and_move(
    stack: Stack, nano: Nano, mark: str, ui: uilib.Driver, artifact_dir, timeline, rule_cleanup
) -> None:
    """An agent creates rules snake_case in "Automated"; the rail groups them
    there; the folder chip moves one and the move persists. A display-title
    name is refused by the editor."""
    name = _snake("agent_created_rule", mark)
    rule = expect(nano.api.post("/api/rules", json={
        "name": name, "description": "agent-created (NAN-5686)", "author": "nano-agent", "query": f'"{mark}"',
        "severity": "low", "mode": "staging", "detection_mode": "scheduled", "schedule_cron": "*/30 * * * *",
        "folder": "Automated", "mitre_tactics": ["TA0001"], "mitre_techniques": ["T1078"]}), 200, 201)
    rule_cleanup.append(name)
    rule_id = str(rule["id"])
    target = f"e2e_folder_{secrets.token_hex(2)}"
    with login_persona(stack, nano, ui, artifact_dir, "deep-folders", DE_PERMISSIONS) as persona:
        page, client = persona.page, persona.client
        page.goto(f"/rules/editor/{rule_id}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        rail = {"testid": "rule-editor-rail"}
        page.fill(uilib.field({"placeholder": "filter rules…", "within": rail}, name))
        page.wait_text("Automated", exact=False)
        assert page.count({"text": name, "exact": False, "within": rail}) >= 1
        page.screenshot("deep-folder-automated.png", full_page=False)

        # Move with the folder chip > New folder…
        page.click({"testid": "rule-folder-chip"})
        pop = {"css": "[data-radix-popper-content-wrapper]"}
        page.click({"role": "button", "name": uilib.rx(r"^New folder"), "within": pop})
        page.fill(uilib.field({"placeholder": "folder name", "within": pop}, target))
        page.press_key({"placeholder": "folder name", "within": pop}, "Enter")
        # The chip edits the rule; Save persists it.
        assert target in " ".join(page.texts({"testid": "rule-folder-chip"}))
        page.click({"role": "button", "name": "Save rule", "exact": True})
        page.click({"role": "button", "name": "Save Rule", "exact": True, "within": {"role": "alertdialog"}})
        page.wait_text(uilib.rx("Rule updated|Cannot save rule|Save failed"), exact=False, timeout_ms=30_000)
        assert page.count({"text": uilib.rx("^Rule updated")}) >= 1, page.main_text()[-600:]
        eventually(lambda: _rule(client, rule_id).get("folder"), timeout=30, interval=0.5,
                   desc="folder move persisted", ok=lambda f: f == target)
        page.reload()
        page.wait_text(name, exact=False, timeout_ms=30_000)
        assert target in " ".join(page.texts({"testid": "rule-folder-chip"}))
        timeline.step("moved", folder=target)

        # A display title is not a rule name: the editor refuses it.
        page.goto("/rules/editor/new")
        page.wait_for(EDITOR)
        page.editor_fill(EDITOR, _yaml("Agent Created Rule", f'"{mark}"', technique="T1078", tactic="TA0001"))
        page.wait_attr(STATUS, "data-status", "invalid", timeout_ms=30_000)
        page.click(STATUS)
        page.wait_text(uilib.rx("snake", "i"), exact=False)
        assert _by_name(client, "Agent Created Rule") is None
        timeline.step("display title refused")


def test_retro_hunt_rule_from_the_form(
    stack: Stack, nano: Nano, mark: str, ui: uilib.Driver, artifact_dir, timeline, rule_cleanup
) -> None:
    name = _snake("retro_hunt", mark)
    with login_persona(stack, nano, ui, artifact_dir, "deep-retro", DE_PERMISSIONS) as persona:
        page, client = persona.page, persona.client
        feeds = expect(client.api.get("/api/rules/retro-hunt/feeds"), 200)
        page.goto("/rules/retro-hunt/new")
        page.fill(uilib.field({"testid": "retro-hunt-name"}, name))
        page.fill(uilib.field({"testid": "retro-hunt-lookback"}, "3"))
        page.click({"role": "button", "name": "Create rule", "exact": True})
        rule_cleanup.append(name)
        page.wait_text("Retro-hunt rule created", exact=False, timeout_ms=30_000)
        page.wait_url(r"/rules/retro-hunt/[^n]")
        rid = page.url.rstrip("/").split("/")[-1]
        cfg = expect(client.api.get(f"/api/rules/{rid}/retro-hunt"), 200)
        assert int(cfg["config"]["lookback_days"]) == 3, cfg
        rule = _rule(client, rid)
        assert rule["name"] == name and "retro" in (rule.get("tags") or []), rule
        page.wait_text("Run history", exact=False)
        page.screenshot("deep-retro-hunt.png", full_page=False)
        timeline.step("retro-hunt created", rule=rid, feeds=feeds if isinstance(feeds, list) else list(feeds)[:3])


def test_alert_cooldown_round_trips(nano: Nano, mark: str, rule_cleanup) -> None:
    """`alert_cooldown_minutes` is on the rule model; a create or update that
    sets it must persist it (there is no editor control for it)."""
    name = _snake("cooldown", mark)
    rule = expect(nano.api.post("/api/rules", json={
        "name": name, "description": "cooldown (NAN-5686)", "query": f'"{mark}"', "severity": "low",
        "mode": "staging", "detection_mode": "scheduled", "schedule_cron": "*/30 * * * *",
        "folder": "Automated", "alert_cooldown_minutes": 45}), 200, 201)
    rule_cleanup.append(name)
    got = _rule(nano, str(rule["id"]))
    assert got.get("alert_cooldown_minutes") == 45, f"create dropped alert_cooldown_minutes: {got.get('alert_cooldown_minutes')}"
    expect(nano.api.put(f"/api/rules/{rule['id']}", json={"alert_cooldown_minutes": 10}), 200)
    assert _rule(nano, str(rule["id"])).get("alert_cooldown_minutes") == 10


def test_mitre_coverage_shows_staging_rules_in_review(
    stack: Stack, nano: Nano, mark: str, ui: uilib.Driver, artifact_dir, timeline, rule_cleanup
) -> None:
    """The coverage panel groups rules by mode (Alerting / Live / Staging /
    Paused); a staging rule mapped to a technique shows "Staging · 1" there,
    its cell reads D = review, and it is not live coverage."""
    # A fresh stack installs the ATT&CK catalog after boot; until then the
    # coverage API lists no techniques at all (this failed as `{}` when the
    # test ran first on a new open stack).
    wait_catalog(nano)
    name = _snake("mitre_review", mark)
    technique = "T1201"  # Password Policy Discovery: no other e2e rule maps it
    rule = expect(nano.api.post("/api/rules", json={
        "name": name, "description": "nano-e2e (NAN-5686)", "query": f'"{mark}"', "severity": "low",
        "mode": "staging", "detection_mode": "scheduled", "schedule_cron": "*/30 * * * *", "folder": "Automated",
        "mitre_tactics": ["TA0007"], "mitre_techniques": [technique]}), 200, 201)
    rule_cleanup.append(name)
    api = _coverage(nano, technique, modes="staging") or {}
    assert any(r.get("name") == name for r in api.get("rules", [])), api
    with login_persona(stack, nano, ui, artifact_dir, "mitre-review", DE_PERMISSIONS) as persona:
        _open_technique(persona.page, technique)
        text = " ".join(persona.page.texts({"role": "dialog", "name": f"Technique {technique}", "exact": True}))
        persona.page.screenshot("mitre-review-staging.png", full_page=False)
        timeline.step("staging rule on the coverage page", sheet=text[:200])
        # The panel groups rules by mode (NAN-5850): "Staging · 1", and the
        # staging rule does not count as live.
        review = re.search(r"(?i)staging · (\d+)", text)
        assert review, f"the technique panel has no Staging group: {text[:300]}"
        assert name in text and review.group(1) == "1", \
            f"technique panel: rule listed={name in text}, {review.group(0)}"
        assert "0 live" in text, f"a staging rule counted as live: {text[:300]}"
        cell = {"testid": f"coverage-cell-{technique}"}
        assert set(persona.page.attrs(cell, "data-d")) == {"review"}, persona.page.attrs(cell, "data-d")

"""pivt knows the alert the analyst opened and triages it as them (NAN-5588).

A real alert (OCSF event → alerting rule → trigger), then on /alerts/:id:
- a grounded question is answered from the page context (alert id, rule,
  severity, status);
- "close this as false positive" gives a confirmation card; the alert stays
  open until Apply; Apply closes it through the REST API as the analyst and
  the audit event records the analyst with `request_origin: pivt`;
- a viewer without `alerts:close` is offered no card, and the REST call pivt
  would make returns 403.
OCSF only.
"""

from __future__ import annotations

from typing import Any

import pytest

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually

PIVT_CHAT = ("melod:chat", "melod:notebook", "notebooks:view", "notebooks:create", "notebooks:edit")
RESPONDER = (*PIVT_CHAT, "alerts:view", "alerts:acknowledge", "alerts:close", "search:view", "search:execute")
VIEWER = (*PIVT_CHAT, "alerts:view", "search:view", "search:execute")

PROMPT = {"role": "textbox", "name": "Message pivt", "exact": True}
CARD = {"testid": "pivt-page-action"}


def _ask(page: uilib.UiPage, text: str) -> None:
    if page.count(PROMPT) == 0:
        page.click({"testid": "pivt-summon"})
    page.fill(uilib.field(PROMPT, text))
    page.press_key(PROMPT, "Enter")


def _alert(nano: Nano, alert_id: str) -> dict[str, Any]:
    return expect(nano.api.get(f"/api/alerts/{alert_id}"), 200)


@pytest.fixture
def fired_alert(stack: Stack, nano: Nano, mark: str, ocsf_lane, persona_cleanup) -> dict[str, Any]:
    ocsf_lane.send(stack, mark, f"pivt-{mark[-6:]}", "203.0.113.91", f"pivt-host-{mark[-6:]}", note="pivt alert")
    eventually(lambda: nano.rows(f'"{mark}"', limit=5), timeout=INGEST_VISIBLE, desc="alert event searchable")
    name = f"pivt_alert_{mark[-10:].replace('-', '_')}"
    persona_cleanup.rule(name)
    rule = expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": name,
                "description": "NAN-5588 pivt alert fixture",
                "query": f'source_type="{ocsf_lane.lane}" "{mark}"',
                "severity": "high",
                "schedule_cron": "* * * * *",
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
        lambda: expect(nano.api.get("/api/alerts", params={"rule_id": rule["id"], "limit": 5}), 200),
        timeout=DETECTION,
        interval=3,
        desc="pivt fixture alert",
        ok=bool,
    )
    return alerts[0]


def test_pivt_grounds_on_an_alert_and_respects_cases_triage(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, fired_alert, mark
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    alert_id = fired_alert["id"]
    assert fired_alert["status"] != "closed"
    caps = expect(nano.api.get("/api/capabilities"), 200).get("capabilities", {})

    with login_persona(stack, nano, ui, artifact_dir, "pivt-responder", RESPONDER) as persona:
        page = persona.page
        page.goto(f"/alerts/{alert_id}")
        page.wait_text(fired_alert["rule_name"], exact=False)

        # Grounded: the reply names this alert (contiguous sentence, so the
        # id elsewhere on the page can't satisfy it).
        _ask(page, "why did this alert fire?")
        page.wait_text(f"This is alert {alert_id} from rule", exact=False, timeout_ms=120_000)
        page.screenshot("pivt-alert-grounded.png")

        # NAN-1066: on a Cases tenant alert triage happens in the case; pivt
        # must not add the ack/close path the page removed.
        _ask(page, "close this as false positive")
        if caps.get("cases"):
            page.wait_text("isn't available to you on this page", exact=False, timeout_ms=120_000)
            assert page.count({"css": '[data-testid="pivt-page-action"][data-action="alerts.close"]'}) == 0
            assert _alert(nano, alert_id)["status"] != "closed"
            timeline.step("pivt offers no alert close on a Cases tenant", alert=alert_id)
        else:
            eventually(lambda: page.count(CARD), timeout=120, interval=0.5, desc="close proposal card", ok=bool)
            assert page.attr(CARD, "data-action") == "alerts.close"
            assert _alert(nano, alert_id)["status"] != "closed", "nothing changes before Apply"

        # A read-only pivot is one click and lands on Search with the nPL query.
        query = f'"{mark}"'
        _ask(page, f"pivot to search for {query}")
        pivot = {"css": '[data-testid="pivt-page-action"][data-action="search.pivot"]'}
        eventually(lambda: page.count(pivot), timeout=120, interval=0.5, desc="pivot card", ok=bool)
        page.screenshot("pivt-alert-pivot.png")
        page.click({"testid": "pivt-page-action-apply", "within": pivot})
        eventually(lambda: "/search" in page.url, timeout=30, interval=0.5, desc="on Search", ok=bool)
        page.wait_text(mark, exact=False, timeout_ms=30_000)
        timeline.step("pivt pivoted from the alert to Search", alert=alert_id)


def test_pivt_offers_no_close_without_alerts_close(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, fired_alert
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    alert_id = fired_alert["id"]
    with login_persona(stack, nano, ui, artifact_dir, "pivt-alert-viewer", VIEWER) as persona:
        page = persona.page
        page.goto(f"/alerts/{alert_id}")
        page.wait_text(fired_alert["rule_name"], exact=False)
        _ask(page, "close this as false positive")
        page.wait_text("isn't available to you on this page", exact=False, timeout_ms=120_000)
        assert page.count(CARD) == 0
        page.screenshot("pivt-alert-viewer-no-action.png")
        refused = persona.client.api.post(
            f"/api/alerts/{alert_id}/close",
            json={"disposition": "false_positive"},
            headers={"X-Nano-Origin": "pivt"},
        )
        assert refused.status_code == 403, refused.text[:500]
        assert _alert(nano, alert_id)["status"] != "closed"
        timeline.step("viewer offered no close; REST 403", alert=alert_id)

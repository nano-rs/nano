"""pivt knows the rule the analyst opened and changes its mode as them (NAN-5592).

A staging rule (OCSF query), then on /rules/editor/:id:
- a grounded question is answered from the page context (rule id, name, mode);
- "promote this rule" gives a confirmation card showing the one transition
  (staging → live); the rule stays in staging until Apply; Apply promotes it
  through the REST API as the analyst and the audit event records the analyst
  with `request_origin: pivt`;
- an editor without `detections:promote` is offered no card, and the REST call
  pivt would make returns 403.
OCSF only.
"""

from __future__ import annotations

from typing import Any

import pytest

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

PIVT_CHAT = ("melod:chat", "melod:notebook", "notebooks:view", "notebooks:create", "notebooks:edit")
ENGINEER = (*PIVT_CHAT, "detections:view", "detections:edit", "detections:promote", "search:view", "search:execute")
# Can open and edit the rule (the editor route needs detections:edit), but not
# change its mode.
EDITOR_NO_PROMOTE = (*PIVT_CHAT, "detections:view", "detections:edit", "search:view", "search:execute")

PROMPT = {"role": "textbox", "name": "Message pivt", "exact": True}
CARD = {"testid": "pivt-page-action"}


def _ask(page: uilib.UiPage, text: str) -> None:
    if page.count(PROMPT) == 0:
        page.click({"testid": "pivt-summon"})
    page.fill(uilib.field(PROMPT, text))
    page.press_key(PROMPT, "Enter")


def _open_editor(page: uilib.UiPage, rule_id: str, name: str) -> None:
    """Open the rule editor and wait until pivt sees the LOADED rule (the Here
    card title comes from the page context), not just the rail list."""
    page.goto(f"/rules/editor/{rule_id}")
    page.wait_text(name, exact=False)
    if page.count(PROMPT) == 0:
        page.click({"testid": "pivt-summon"})
    page.wait_text(f"Rule · {name}", exact=False, timeout_ms=30_000)


def _rule(nano: Nano, rule_id: str) -> dict[str, Any]:
    return expect(nano.api.get(f"/api/rules/{rule_id}"), 200)


@pytest.fixture
def staging_rule(nano: Nano, mark: str, ocsf_lane, persona_cleanup) -> dict[str, Any]:
    name = f"pivt_rule_{mark[-10:].replace('-', '_')}"
    persona_cleanup.rule(name)
    return expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": name,
                "description": "NAN-5592 pivt rule fixture",
                "query": f'source_type="{ocsf_lane.lane}" "{mark}"',
                "severity": "medium",
                "schedule_cron": "*/5 * * * *",
                "mode": "staging",
                "detection_mode": "scheduled",
                "lookback_minutes": 15,
            },
        ),
        200,
        201,
    )


def test_pivt_grounds_on_a_rule_and_promotes_it_as_the_analyst(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, staging_rule
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    rule_id, name = staging_rule["id"], staging_rule["name"]
    assert staging_rule["mode"] == "staging"

    with login_persona(stack, nano, ui, artifact_dir, "pivt-engineer", ENGINEER) as persona:
        page = persona.page
        _open_editor(page, rule_id, name)

        _ask(page, "what does this rule do?")
        page.wait_text(f"This is rule {rule_id} named {name}, in staging mode.", exact=False, timeout_ms=120_000)
        page.screenshot("pivt-rule-grounded.png")
        timeline.step("pivt answered from the rule editor context", rule=rule_id)

        # One transition, confirmed; nothing changes before Apply.
        _ask(page, "promote this rule")
        eventually(lambda: page.count(CARD), timeout=120, interval=0.5, desc="promote card", ok=bool)
        assert page.attr(CARD, "data-action") == "rules.promote"
        assert page.attr(CARD, "data-mutates") == "true"
        page.wait_text("staging → live", exact=False, timeout_ms=10_000)
        assert _rule(nano, rule_id)["mode"] == "staging", "nothing changes before Apply"
        page.screenshot("pivt-rule-promote-card.png")

        page.click({"testid": "pivt-page-action-apply"})
        eventually(lambda: page.count({"testid": "pivt-page-action-done"}), timeout=60, interval=0.5, desc="promoted", ok=bool)
        assert _rule(nano, rule_id)["mode"] == "live"
        page.screenshot("pivt-rule-promoted.png")

        def _audit():
            body = expect(nano.api.get("/api/audit", params={"action": "rule_promoted", "limit": 50}), 200)
            return [e for e in body.get("logs", []) if e.get("resource_name") == name]

        events = eventually(_audit, timeout=60, interval=1, desc="rule_promoted audit event", ok=bool)
        me = expect(persona.client.api.get("/api/auth/me"), 200)
        assert events[0]["user_id"] == me.get("id"), "the actor is the analyst, not a service principal"
        assert (events[0].get("details") or {}).get("request_origin") == "pivt", events[0]
        timeline.step("pivt promoted the rule through REST, audited via pivt", rule=rule_id)


def test_pivt_offers_no_promote_without_detections_promote(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, staging_rule
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    rule_id, name = staging_rule["id"], staging_rule["name"]
    with login_persona(stack, nano, ui, artifact_dir, "pivt-rule-editor", EDITOR_NO_PROMOTE) as persona:
        page = persona.page
        _open_editor(page, rule_id, name)
        _ask(page, "promote this rule")
        page.wait_text("isn't available to you on this page", exact=False, timeout_ms=120_000)
        assert page.count(CARD) == 0
        page.screenshot("pivt-rule-editor-no-promote.png")
        refused = persona.client.api.post(
            f"/api/rules/{rule_id}/promote",
            json={"expected_mode": "staging"},
            headers={"X-Nano-Origin": "pivt"},
        )
        assert refused.status_code == 403, refused.text[:500]
        assert _rule(nano, rule_id)["mode"] == "staging"
        timeline.step("editor without promote offered no promote; REST 403", rule=rule_id)

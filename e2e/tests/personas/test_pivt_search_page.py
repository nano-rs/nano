"""pivt knows the Search page and acts on it as the analyst (NAN-5571).

Open Search, run a query, open pivt:
- a grounded question is answered from the page's own context (the query
  and the result count the page shows);
- "create a high rule named X" gives a confirmation card; nothing exists
  until Apply; Apply creates a STAGING rule through the REST API as the
  analyst, and the audit event records `request_origin: pivt`;
- a viewer (no detections:create) is never offered the action: no card,
  and the REST call pivt would make is refused (403).
"""

from __future__ import annotations

import pytest

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona, persona_ai_mode
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

PIVT_CHAT = ("melod:chat", "melod:notebook", "notebooks:view", "notebooks:create", "notebooks:edit")
ANALYST = (*PIVT_CHAT, "search:view", "search:execute", "detections:view", "detections:create")
VIEWER = (*PIVT_CHAT, "search:view", "search:execute", "detections:view")

PROMPT = {"role": "textbox", "name": "Message pivt", "exact": True}
CARD = {"testid": "pivt-page-action"}


def _ask(page: uilib.UiPage, text: str) -> None:
    if page.count(PROMPT) == 0:
        page.click({"testid": "pivt-summon"})
    page.fill(uilib.field(PROMPT, text))
    page.press_key(PROMPT, "Enter")


def _run_search(page: uilib.UiPage, query: str) -> None:
    uilib.run_search(page, query)


def _rule(nano: Nano, name: str):
    body = expect(nano.api.get("/api/rules"), 200)
    items = body if isinstance(body, list) else body.get("rules") or body.get("items") or []
    return next((r for r in items if r.get("name") == name), None)


def test_pivt_grounds_on_search_and_creates_a_rule_as_the_analyst(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, persona_cleanup, mark
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    rule_name = f"pivt_rule_{mark[-8:].replace('-', '_')}"
    persona_cleanup.rule(rule_name)
    query = f'"{mark}"'

    with login_persona(stack, nano, ui, artifact_dir, "pivt-analyst", ANALYST) as persona:
        page = persona.page
        page.goto("/search")
        _run_search(page, query)

        # Grounded: the answer cites the query the page shows. The exact
        # sentence is the stub's; a real model (E2E_PERSONA_AI_MODE=real) is
        # exercised on the action path below, where the result is structural.
        if persona_ai_mode() == "stub":
            _ask(page, "what am I looking at?")
            # The answer cites the page's own query and count (markdown renders the
            # query as code, so match the sentence and the query separately).
            page.wait_text("You are looking at the query", exact=False, timeout_ms=120_000)
            page.wait_text(query, exact=False, timeout_ms=10_000)
            page.wait_text("events on this page", exact=False, timeout_ms=10_000)
            page.screenshot("pivt-search-grounded.png")
            timeline.step("pivt answered from the Search page context", query=query)

        # Action: proposal card, nothing created until Apply.
        _ask(page, f"create a high rule named {rule_name}")
        eventually(lambda: page.count(CARD), timeout=120, interval=0.5, desc="rule proposal card", ok=bool)
        assert page.attr(CARD, "data-action") == "search.create_rule"
        assert page.attr(CARD, "data-mutates") == "true"
        assert _rule(nano, rule_name) is None
        page.screenshot("pivt-search-rule-proposal.png")

        page.click({"testid": "pivt-page-action-apply"})
        eventually(lambda: page.count({"testid": "pivt-page-action-done"}), timeout=60, interval=0.5, desc="rule created", ok=bool)
        rule = eventually(lambda: _rule(nano, rule_name), timeout=30, interval=0.5, desc="rule exists", ok=bool)
        assert rule["mode"] == "staging", rule
        page.screenshot("pivt-search-rule-applied.png")

        # Audited as the analyst, via pivt.
        def _audit():
            body = expect(nano.api.get("/api/audit", params={"action": "rule_created", "limit": 50}), 200)
            return [e for e in body.get("logs", []) if e.get("resource_name") == rule_name]

        events = eventually(_audit, timeout=60, interval=1, desc="rule_created audit event", ok=bool)
        me = expect(persona.client.api.get("/api/auth/me"), 200)
        assert events[0]["user_id"] == me.get("id"), "the actor is the analyst, not a service principal"
        assert (events[0].get("details") or {}).get("request_origin") == "pivt", events[0]
        timeline.step("pivt rule applied through REST, audited via pivt", rule=rule_name)


def test_pivt_offers_a_viewer_no_mutating_action(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, mark
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    if persona_ai_mode() == "real":
        # A real model may classify the ask as chat (prose) or detection (the
        # redirect); the permission boundary is covered by the stub run.
        pytest.skip("asserts the stub's classification")
    rule_name = f"pivt_viewer_{mark[-8:].replace('-', '_')}"
    with login_persona(stack, nano, ui, artifact_dir, "pivt-search-viewer", VIEWER) as persona:
        page = persona.page
        page.goto("/search")
        _run_search(page, f'"{mark}"')
        # NAN-5597: a viewer's Search offers no search.create_rule, so the
        # concierge keeps its rule-editor redirect (the stub classifies this as
        # `detection`, like real models): no card, a link to the editor.
        _ask(page, f"create a high rule named {rule_name}")
        page.wait_text("take you to the rule editor", exact=False, timeout_ms=120_000)
        assert page.count(CARD) == 0
        page.screenshot("pivt-search-viewer-no-action.png")
        # The REST call the action would make, marked as pivt's, is refused.
        refused = persona.client.api.post(
            "/api/rules",
            json={"name": rule_name, "query": f'"{mark}"', "severity": "high", "mode": "staging"},
            headers={"X-Nano-Origin": "pivt"},
        )
        assert refused.status_code == 403, refused.text[:500]
        assert _rule(nano, rule_name) is None
        timeline.step("viewer offered no mutating pivt action; REST 403", rule=rule_name)

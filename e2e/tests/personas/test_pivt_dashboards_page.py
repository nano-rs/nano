"""pivt knows the dashboard the analyst opened and adds a panel as them (NAN-5595).

On /dashboards/:id:
- a grounded question is answered from the page context (dashboard id, name,
  panel count);
- "add a table panel named … for <nPL>" gives a confirmation card with the
  nPL and a read-only preview of the query; the dashboard is unchanged until
  Apply; Apply saves it through the REST API as the analyst (owner), and the
  audit event records the analyst with `request_origin: pivt`;
- an analyst with `dashboards:edit` who does not own the dashboard sees no
  Edit, is offered no card, and "add a panel" is refused in chat, not
  redirected to the builder (the page withholds the panel actions, NAN-5637);
  the REST save pivt would make is refused (403).
OCSF only.
"""

from __future__ import annotations

from typing import Any

import pytest

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona, persona_ai_mode
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

PIVT_CHAT = ("melod:chat", "melod:notebook", "notebooks:view", "notebooks:create", "notebooks:edit")
BUILDER = (*PIVT_CHAT, "dashboards:view", "dashboards:create", "dashboards:edit", "search:view", "search:execute")
# Holds dashboards:edit but does not own the dashboard (and is not an admin):
# the server refuses the save, so pivt must not offer it.
NOT_OWNER = (*PIVT_CHAT, "dashboards:view", "dashboards:edit", "search:view", "search:execute")

PROMPT = {"role": "textbox", "name": "Message pivt", "exact": True}
CARD = {"testid": "pivt-page-action"}


def _ask(page: uilib.UiPage, text: str) -> None:
    if page.count(PROMPT) == 0:
        page.click({"testid": "pivt-summon"})
    page.fill(uilib.field(PROMPT, text))
    page.press_key(PROMPT, "Enter")


def _open(page: uilib.UiPage, dashboard: dict[str, Any]) -> None:
    """Open the dashboard and wait until pivt sees the LOADED dashboard."""
    page.goto(f"/dashboards/{dashboard['id']}")
    page.wait_text(dashboard["name"], exact=False)
    if page.count(PROMPT) == 0:
        page.click({"testid": "pivt-summon"})
    page.wait_text(f"Dashboard · {dashboard['name']}", exact=False, timeout_ms=30_000)


def _create(client: Nano, name: str) -> dict[str, Any]:
    return expect(
        client.api.post(
            "/api/dashboards",
            json={
                "name": name,
                "description": "NAN-5595 pivt dashboard fixture",
                "layout": {"columns": 12, "rowHeight": 80, "items": []},
                "panels": [],
            },
        ),
        200,
        201,
    )


def test_pivt_grounds_on_a_dashboard_and_adds_a_panel_as_the_analyst(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, persona_cleanup, ocsf_lane, mark
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    name = f"pivt_dash_{mark[-10:].replace('-', '_')}"
    persona_cleanup.dashboard(name)
    query = f'source_type="{ocsf_lane.lane}" | stats count by src_endpoint.ip'

    with login_persona(stack, nano, ui, artifact_dir, "pivt-builder", BUILDER) as persona:
        dashboard = _create(persona.client, name)  # owned by the analyst
        page = persona.page
        _open(page, dashboard)

        _ask(page, "what is on this dashboard?")
        page.wait_text(f"This is dashboard {dashboard['id']} named {name}, with 0 panels.", exact=False, timeout_ms=120_000)
        page.screenshot("pivt-dashboard-grounded.png")
        timeline.step("pivt answered from the dashboard context", dashboard=dashboard["id"])

        _ask(page, f"add a table panel named Top sources for {query}")
        eventually(lambda: page.count(CARD), timeout=120, interval=0.5, desc="add-panel card", ok=bool)
        assert page.attr(CARD, "data-action") == "dashboards.add_panel"
        assert page.attr(CARD, "data-mutates") == "true"
        # "1 row" or "N rows" (pluralized; a filtered run may see one source IP).
        page.wait_text(" in the current time range", exact=False, timeout_ms=30_000)  # the read-only preview ran
        assert expect(nano.api.get(f"/api/dashboards/{dashboard['id']}"), 200)["panels"] == [], "nothing changes before Apply"
        page.screenshot("pivt-dashboard-add-card.png")

        page.click({"testid": "pivt-page-action-apply"})
        eventually(lambda: page.count({"testid": "pivt-page-action-done"}), timeout=60, interval=0.5, desc="panel added", ok=bool)
        saved = expect(nano.api.get(f"/api/dashboards/{dashboard['id']}"), 200)
        assert [(p["title"], p["query"], p["queryMode"], p["visualizationType"]) for p in saved["panels"]] == [
            ("Top sources", query, "piped", "table")
        ]
        assert len(saved["layout"]["items"]) == 1
        page.screenshot("pivt-dashboard-panel-added.png")

        def _audit():
            body = expect(nano.api.get("/api/audit", params={"action": "dashboard_updated", "limit": 50}), 200)
            return [e for e in body.get("logs", []) if e.get("resource_name") == name]

        events = eventually(_audit, timeout=60, interval=1, desc="dashboard_updated audit event", ok=bool)
        me = expect(persona.client.api.get("/api/auth/me"), 200)
        assert events[0]["user_id"] == me.get("id"), "the actor is the analyst, not a service principal"
        assert (events[0].get("details") or {}).get("request_origin") == "pivt", events[0]
        timeline.step("pivt added the panel through REST, audited via pivt", dashboard=dashboard["id"])


def test_pivt_offers_no_panel_edit_on_a_dashboard_the_analyst_cannot_save(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, persona_cleanup, mark
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    if persona_ai_mode() == "real":
        # A real model words the refusal its own way; the permission
        # boundary is covered by the stub run.
        pytest.skip("asserts the stub's wording")
    name = f"pivt_dash_ro_{mark[-10:].replace('-', '_')}"
    persona_cleanup.dashboard(name)
    dashboard = _create(nano, name)  # the admin's
    # Explicitly public so the non-owner can open it (whatever the default).
    expect(nano.api.post(f"/api/dashboards/{dashboard['id']}/share", json={"visibility": "public"}), 200)
    dashboard = expect(nano.api.get(f"/api/dashboards/{dashboard['id']}"), 200)  # current updated_at

    with login_persona(stack, nano, ui, artifact_dir, "pivt-dash-not-owner", NOT_OWNER) as persona:
        page = persona.page
        _open(page, dashboard)
        # NAN-5637: no Edit for a non-owner (the server would refuse the save).
        assert page.count({"role": "button", "name": "Edit", "exact": True}) == 0
        _ask(page, "add a table panel named Nope for class_name=\"Authentication\" | stats count")
        # The page withholds dashboards.add_panel from the non-owner. The stub
        # classifies this as `dashboard`, like real models; the concierge
        # refuses in chat instead of redirecting to the builder.
        page.wait_text("isn't available to you on this page", exact=False, timeout_ms=120_000)
        assert page.count(CARD) == 0
        assert page.count({"text": "take you to the dashboard builder"}) == 0
        # Nor the redirect-fallback link (a suggestion, not reply prose).
        assert page.count({"text": "Open Dashboards"}) == 0
        page.screenshot("pivt-dashboard-not-owner-no-action.png")
        refused = persona.client.api.put(
            f"/api/dashboards/{dashboard['id']}",
            # A real change (one panel), so "panels still empty" proves nothing was written.
            json={
                "panels": [
                    {
                        "id": "panel-nope",
                        "title": "Nope",
                        "query": 'class_name="Authentication" | stats count',
                        "queryMode": "piped",
                        "visualizationType": "table",
                        "visualizationConfig": {},
                    }
                ],
                "expected_updated_at": dashboard["updated_at"],
            },
            headers={"X-Nano-Origin": "pivt"},
        )
        assert refused.status_code == 403, refused.text[:500]
        assert expect(nano.api.get(f"/api/dashboards/{dashboard['id']}"), 200)["panels"] == []
        timeline.step("non-owner offered no panel edit; REST refused", dashboard=dashboard["id"])

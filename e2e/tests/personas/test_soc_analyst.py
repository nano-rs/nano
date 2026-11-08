"""SOC analyst: ground-truth search, pivots, saved query, dashboard, pivt."""

from __future__ import annotations

import os

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import (
    SOC_ANALYST_PERMISSIONS,
    assert_ground_truth_api,
    assert_ground_truth_ui,
    login_persona,
    seed_ground_truth,
)
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually


def test_soc_analyst_journey(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, ui: uilib.Driver, artifact_dir, timeline,
    persona_cleanup, persona_ai,
) -> None:
    truth = seed_ground_truth(stack, nano, ocsf_lane, mark)
    assert_ground_truth_api(nano, truth)
    ai_mode = persona_ai

    with login_persona(
        stack, nano, ui, artifact_dir, "soc-analyst", SOC_ANALYST_PERMISSIONS
    ) as persona:
        page = persona.page
        assert set(persona.permissions) == set(SOC_ANALYST_PERMISSIONS)
        assert "dashboards:delete" not in persona.permissions
        assert_ground_truth_ui(page, persona.client, truth)
        timeline.step("keyword search", expected=truth.total, shown=uilib.results_count(page))

        # Pivot into an aggregate and compare every group with seeded truth.
        query = f'{truth.query} | stats count by actor.user.name'
        api_groups = {
            str(row["actor.user.name"]): int(row["count"])
            for row in persona.client.rows(query, limit=100)
        }
        uilib.run_search(page, query)
        header, rows = uilib.table_rows(page)
        shown_groups = {row[0]: int(row[1].replace(",", "")) for row in rows if row}
        assert header[:2] == ["actor.user.name", "count"], header
        assert shown_groups == api_groups == truth.users
        timeline.step("pivot", groups=shown_groups)

        # Drill down from the pivot by running the exact selected group.  The
        # response must equal both API ground truth and its seeded count.
        selected = next(iter(truth.users))
        drill = f'{truth.query} actor.user.name="{selected}"'
        uilib.run_search(page, drill)
        assert uilib.results_count(page) == nano.search(drill)["total_count"] == truth.users[selected]
        timeline.step("drilldown", user=selected, count=truth.users[selected])

        # Save through the browser, then verify persistence through the API.
        saved_name = f"persona saved {mark[-8:]}"
        page.click({"role": "button", "name": "Save", "exact": True})
        page.wait_text("Save query", exact=True)
        page.fill(uilib.field({"css": 'input[placeholder="e.g. Failed console logins"]'}, saved_name))
        page.click({"role": "button", "name": "Save query", "exact": True})
        page.wait_for({"css": 'input[placeholder="e.g. Failed console logins"]'}, gone=True)
        searches = eventually(
            lambda: expect(persona.client.search_http.get("/api/search/saved/mine"), 200),
            timeout=10,
            interval=0.1,
            desc="browser-created saved query to be visible through the persona API",
            ok=lambda values: any(item.get("name") == saved_name for item in values),
        )
        items = searches if isinstance(searches, list) else searches.get("saved_searches", searches.get("items", []))
        saved = next(item for item in items if item.get("name") == saved_name)
        persona.cleanup.register_http(
            f"saved search {saved['id']}",
            lambda: persona.client.search_http.delete(f"/api/search/saved/{saved['id']}"),
        )
        assert saved.get("query") == drill, saved
        timeline.step("saved search", id=saved.get("id"))

        # Build a blank dashboard in the UI, then edit its metadata on its own
        # editor page.  The created object is verified through the API.
        dashboard_name = f"Persona SOC {mark[-8:]}"
        page.goto("/dashboards")
        page.click({"role": "button", "name": "New Dashboard", "exact": True})
        page.fill(
            uilib.field({"css": 'input[placeholder="e.g., Security Overview"]'}, dashboard_name),
            uilib.field({"css": 'textarea[placeholder="What does this dashboard monitor?"]'}, "Persona ground truth"),
        )
        page.click({"role": "button", "name": "Create blank", "exact": True})
        page.wait_url(r"/dashboards/")
        persona_cleanup.dashboard(dashboard_name)
        dashboards = expect(persona.client.api.get("/api/dashboards"), 200)
        dash_items = dashboards if isinstance(dashboards, list) else dashboards.get("dashboards", dashboards.get("items", []))
        dashboard = next(item for item in dash_items if item.get("name") == dashboard_name)
        edited_description = f"Edited persona ground truth {mark[-8:]}"
        page.click({"role": "button", "name": "More actions", "exact": True})
        page.click({"role": "menuitem", "name": "Settings", "exact": True})
        page.wait_text("Dashboard settings", exact=True)
        page.fill(
            uilib.field({"css": 'textarea[placeholder="Describe this dashboard…"]'}, edited_description)
        )
        page.click({"role": "button", "name": "Save", "exact": True})
        page.wait_text("Settings saved", exact=False)

        def edited_dashboard():
            values = expect(persona.client.api.get("/api/dashboards"), 200)
            items = values if isinstance(values, list) else values.get("dashboards", values.get("items", []))
            return next((item for item in items if item.get("id") == dashboard["id"]), None)

        dashboard = eventually(
            edited_dashboard,
            timeout=10,
            interval=0.1,
            desc="browser-edited dashboard metadata to persist",
            ok=lambda item: item is not None and item.get("description") == edited_description,
        )
        timeline.step("dashboard built and edited", id=dashboard.get("id"))

        # This role can build dashboards but cannot delete them.  Prove the
        # same boundary in both surfaces: no list action and a persona-JWT 403.
        page.goto("/dashboards")
        page.wait_text(dashboard_name, exact=True)
        assert page.count({"role": "button", "name": "More actions", "exact": True}) == 0
        forbidden = persona.client.api.delete(f"/api/dashboards/{dashboard['id']}")
        assert forbidden.status_code == 403, forbidden.text[:1000]
        timeline.step("forbidden dashboard delete", ui="hidden", api=forbidden.status_code)

        page.goto("/search")
        uilib.run_search(page, truth.query)
        if ai_mode:
            page.click({"role": "button", "name": "Analyze", "exact": True})
            page.wait_for({"testid": "pivt-draft-run"}, timeout_ms=30_000)
            page.wait_attr({"testid": "pivt-draft-run"}, "data-status", "done", timeout_ms=300_000)
            if ai_mode == "stub":
                page.wait_text("Deterministic persona analysis", exact=False, timeout_ms=30_000)
            timeline.step("pivt analysis", provider=ai_mode)
        else:
            assert page.count({"role": "button", "name": "Analyze", "exact": True}) == 0
            timeline.step("pivt capability boundary", edition=os.environ["E2E_EDITION"])
        persona.checkpoint("search-dashboard-pivt")

    # Persona-scoped artifacts are removed before the role/group/user teardown.

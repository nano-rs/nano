"""Dashboards the way a SOC analyst builds and uses them (NAN-5684).

On the seeded `soc` dataset, as a throwaway analyst (explicit dashboards and
search permissions, never the install admin):

- build a dashboard from scratch in the UI and add one panel of every type
  the panel editor offers; what each panel renders equals the API and the
  seeded truth, and everything persists after a reload;
- edit a panel's title and query, duplicate one, delete one, drag one to a new
  place and resize another; the saved layout equals what was done;
- the dashboard time range drives every panel, Refresh re-queries, the
  auto-refresh interval shows as live, a table row drills into Search, and a
  panel's "Open in Search" carries its query;
- export to JSON, import that file back, share link, settings, delete from the
  list;
- a panel with no data and a panel with a broken query render cleanly.

Not offered by the product (so not tested): duplicating a whole dashboard
(no UI, no API), heatmap / gauge / markdown panels.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from nano_e2e import deep
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona
from nano_e2e.soc_seed import SocData
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

PANEL = "dashboard-panel"


@pytest.fixture(scope="module")
def _persona(stack: Stack, ui: uilib.Driver, soc: SocData):
    with deep.module_persona(stack, ui, "deep-dash", deep.ANALYST) as persona:
        yield persona


@pytest.fixture
def analyst(_persona, request):
    """The module's analyst, isolated per scenario (deep.analyst_for)."""
    with deep.analyst_for(_persona, request) as a:
        yield a


def _panel(pid: str) -> dict[str, Any]:
    return {"css": f'[data-testid="{PANEL}"][data-panel-id="{pid}"]'}


def _panel_titled(title: str) -> dict[str, Any]:
    return {"css": f'[data-testid="{PANEL}"][data-panel-title="{title}"]'}


def _get(client: Nano, did: str) -> dict[str, Any]:
    return expect(client.api.get(f"/api/dashboards/{did}"), 200)


def _create(analyst, name: str, panels: list[dict], items: list[dict], **layout: Any) -> dict[str, Any]:
    body = {
        "name": name,
        "description": "NAN-5684 deep e2e",
        "visibility": "private",
        "layout": {"columns": 12, "rowHeight": 80, "items": items, **layout},
        "panels": panels,
    }
    dash = expect(analyst.client.api.post("/api/dashboards", json=body), 200, 201)
    _cleanup(analyst, dash["id"])
    return dash


def _cleanup(analyst, did: str) -> None:
    """Delete at module end; a scenario that already deleted it gets 404
    (NAN-5711: a non-admin's DELETE of a missing dashboard is 404, not 403)."""
    client = analyst.client
    analyst.cleanup.register_http(f"dashboard {did}", lambda: client.api.delete(f"/api/dashboards/{did}"))


def _p(pid: str, title: str, query: str, viz: str, **extra: Any) -> dict[str, Any]:
    return {"id": pid, "title": title, "query": query, "queryMode": "piped", "visualizationType": viz,
            "visualizationConfig": extra.pop("config", {}), "timeRangeMode": "dashboard",
            "drilldownEnabled": True, **extra}


def _wait_status(page: uilib.UiPage, find: dict, want: str = "success", timeout: float = 60) -> str:
    return eventually(lambda: page.attr(find, "data-panel-status"), timeout=timeout, interval=0.5,
                      desc=f"panel {find} to be {want}", ok=lambda s: s == want)


def _window_preset_72h(soc: SocData) -> dict[str, Any]:
    return {"type": "preset", "preset": "Last 7 days"}


# Every type in the panel editor's visualization picker, with a query whose
# rendering can be checked against the seeded truth.
def _builder_panels(soc: SocData) -> list[tuple[str, str, str]]:
    return [
        ("single_value", "Failed logons", f'source_type="{soc.auth}" status="Failure" | stats count'),
        ("line", "Logons per hour", f'source_type="{soc.auth}" | timechart span=1h count'),
        ("area", "Flows per hour", f'source_type="{soc.net}" | timechart span=1h count'),
        ("bar", "Flows by port", f'source_type="{soc.net}" | stats count by dst_endpoint.port'),
        ("pie", "Logon outcome", f'source_type="{soc.auth}" | stats count by status'),
        ("table", "Logons by user", f'source_type="{soc.auth}" | stats count by actor.user.name | sort -count'),
        ("ranked_bar", "Top domains", f'source_type="{soc.dns}" | top 5 query.hostname'),
        ("timeline", "Process launches", f'source_type="{soc.proc}" | table timestamp, device.hostname, process.name | head 20'),
        ("transaction", "Brute-force session",
         f'source_type="{soc.auth}" actor.user.name="judy.chen" status="Failure" '
         f'| transaction device.hostname maxspan=30m'),
    ]


def test_build_a_dashboard_from_scratch_with_every_panel_type(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    name = f"deep_soc_overview_{soc.tag}"
    page.goto("/dashboards")
    page.click({"role": "button", "name": "New Dashboard", "exact": True})
    page.fill(uilib.field({"placeholder": "e.g., Security Overview"}, name),
              uilib.field({"placeholder": "What does this dashboard monitor?"}, "SOC overview (NAN-5684)"))
    page.click({"role": "button", "name": "Create blank", "exact": True})
    page.wait_url(r"/dashboards/dash_[^/?#]+\?edit=true")
    did = urlparse(page.url).path.rsplit("/", 1)[-1]
    _cleanup(analyst, did)

    panels = _builder_panels(soc)
    for viz, title, query in panels:
        page.click({"testid": "editor-add-panel"})
        page.wait_text("Add Panel", exact=True)
        page.fill(uilib.field({"placeholder": "Enter panel title"}, title))
        page.editor_fill({"css": '[data-testid="panel-editor-query"] .cm-content'}, query)
        page.click({"role": "tab", "name": "Visualization", "exact": True})
        page.click({"testid": f"viz-type-{viz}"})
        page.wait_attr({"testid": f"viz-type-{viz}"}, "aria-pressed", "true")
        page.click({"role": "button", "name": "Add panel", "exact": True})
        page.wait_for(_panel_titled(title))
    page.click({"testid": "editor-save"})
    page.wait_url(r"/dashboards/dash_[^/?#]+$", timeout_ms=30_000)

    saved = _get(client, did)
    timeline.step("saved", panels=[(p["title"], p["visualizationType"]) for p in saved["panels"]])
    assert [(p["visualizationType"], p["title"], p["query"]) for p in saved["panels"]] == panels
    assert len(saved["layout"]["items"]) == len(panels)

    # Reload: the view runs on Run, over a window covering the seeded data.
    page.reload()
    page.click({"testid": "time-range-trigger"})
    page.click({"css": '[data-testid="time-preset"][data-preset="Last 7 days"]'})
    page.click({"testid": "dashboard-run"})
    for _, title, _ in panels:
        _wait_status(page, _panel_titled(title))

    single = {"css": f'{_panel_titled("Failed logons")["css"]} [data-testid="viz-single-value"]'}
    assert int(float(page.attr(single, "data-value"))) == sum(soc.auth_failures_by_user.values())
    pie = eventually(lambda: page.count({"css": f'{_panel_titled("Logon outcome")["css"]} path.recharts-sector'}),
                     timeout=15, interval=0.5, desc="pie slices drawn (they animate in)", ok=lambda n: n >= 2)
    assert pie == 2, f"pie shows {pie} sectors for Success/Failure"
    bars = page.count({"css": f'{_panel_titled("Flows by port")["css"]} .recharts-bar-rectangle'})
    assert bars == len(soc.net_by_port), (bars, soc.net_by_port)
    for title in ("Logons per hour",):
        assert page.count({"css": f'{_panel_titled(title)["css"]} .recharts-line'}) >= 1
    assert page.count({"css": f'{_panel_titled("Flows per hour")["css"]} .recharts-area'}) >= 1
    rows = page.attr(_panel_titled("Logons by user"), "data-row-count")
    assert int(rows or 0) == len(soc.auth_by_user)
    table_text = " ".join(page.texts({"css": f'{_panel_titled("Logons by user")["css"]} tbody tr'}))
    top_user = max(soc.auth_by_user, key=soc.auth_by_user.get)
    assert top_user in table_text
    ranked = " ".join(page.texts(_panel_titled("Top domains")))
    for domain in sorted(soc.dns_by_domain, key=lambda d: -soc.dns_by_domain[d])[:3]:
        assert domain in ranked
    assert int(page.attr(_panel_titled("Process launches"), "data-row-count") or 0) == 20
    brute = " ".join(page.texts(_panel_titled("Brute-force session")))
    assert "jump-01" in brute, brute[:300]  # the 40-failure burst groups into one session on jump-01
    page.screenshot("dashboard-every-panel-type.png")


def test_edit_duplicate_delete_move_and_resize_panels(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    panels = [
        _p("p1", "Logons", f'source_type="{soc.auth}" | stats count', "single_value"),
        _p("p2", "By port", f'source_type="{soc.net}" | stats count by dst_endpoint.port', "bar"),
        _p("p3", "By user", f'source_type="{soc.auth}" | stats count by actor.user.name', "table"),
    ]
    items = [{"i": "p1", "x": 0, "y": 0, "w": 4, "h": 3}, {"i": "p2", "x": 4, "y": 0, "w": 4, "h": 3},
             {"i": "p3", "x": 8, "y": 0, "w": 4, "h": 3}]
    dash = _create(analyst, f"deep_edit_{soc.tag}", panels, items, defaultTimeRange=_window_preset_72h(soc))
    page.goto(f"/dashboards/{dash['id']}?edit=true")
    page.wait_text("Editing", exact=False)
    for pid in ("p1", "p2", "p3"):
        page.wait_for(_panel(pid))

    # Edit p1: rename + new query.
    page.click({"css": f'{_panel("p1")["css"]} [data-testid="panel-menu"]'})
    page.click({"role": "menuitem", "name": "Edit panel"})
    page.wait_text("Edit Panel", exact=True)
    page.fill(uilib.field({"placeholder": "Enter panel title"}, "Failed logons"))
    new_query = f'source_type="{soc.auth}" status="Failure" | stats count'
    page.editor_fill({"css": '[data-testid="panel-editor-query"] .cm-content'}, new_query)
    page.click({"role": "button", "name": "Update panel", "exact": True})
    page.wait_for(_panel_titled("Failed logons"))

    # Duplicate p2, delete p3.
    page.click({"css": f'{_panel("p2")["css"]} [data-testid="panel-menu"]'})
    page.click({"role": "menuitem", "name": "Duplicate"})
    page.wait_for(_panel_titled("By port (Copy)"))
    page.click({"css": f'{_panel("p3")["css"]} [data-testid="panel-menu"]'})
    page.click({"role": "menuitem", "name": "Delete"})
    page.click({"role": "button", "name": "Delete", "exact": True, "within": {"role": "dialog"}})
    page.wait_for(_panel("p3"), gone=True)

    # Drag p1 to the right of p2 (header area: the item is the drag source),
    # then resize p2 wider from its south-east handle.
    before = {b["key"]: b for b in page.boxes({"testid": PANEL}, "data-panel-id")}
    page.drag({"css": f'{_panel("p1")["css"]} [data-testid="panel-title"]'}, (0.5, 0.5), (4.5, 0.5))
    page.hover(_panel("p2"))
    handle = {"css": f'.react-grid-item:has({_panel("p2")["css"]}) .react-resizable-handle-se'}
    page.drag(handle, (0.5, 0.5), (6.0, 3.0), hover=True)
    after = {b["key"]: b for b in page.boxes({"testid": PANEL}, "data-panel-id")}
    timeline.step("layout", before=before, after=after)
    assert after["p2"]["width"] > before["p2"]["width"] + 20, "resize did not widen the panel"
    page.wait_text("Unsaved changes", exact=False)
    page.click({"testid": "editor-save"})
    page.wait_url(r"/dashboards/dash_[^/?#]+$", timeout_ms=30_000)

    saved = _get(client, dash["id"])
    by_id = {p["id"]: p for p in saved["panels"]}
    layout = {i["i"]: i for i in saved["layout"]["items"]}
    timeline.step("saved", panels=list(by_id), layout=layout)
    assert by_id["p1"]["title"] == "Failed logons" and by_id["p1"]["query"] == new_query
    assert "p3" not in by_id and "p3" not in layout
    copies = [p for p in saved["panels"] if p["title"] == "By port (Copy)"]
    assert len(copies) == 1 and copies[0]["query"] == by_id["p2"]["query"]
    assert layout["p2"]["w"] > 4, layout["p2"]
    assert (layout["p1"]["x"], layout["p1"]["y"]) != (0, 0), layout["p1"]

    # Persisted: the view shows the same panels after a reload.
    page.reload()
    page.click({"testid": "dashboard-run"})
    _wait_status(page, _panel("p1"))
    single = {"css": f'{_panel("p1")["css"]} [data-testid="viz-single-value"]'}
    assert int(float(page.attr(single, "data-value"))) == sum(soc.auth_failures_by_user.values())


def test_time_range_refresh_autorefresh_and_drilldown(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    panels = [
        _p("count", "Auth events", f'source_type="{soc.auth}" | stats count', "single_value"),
        _p("users", "Failures by user", f'source_type="{soc.auth}" status="Failure" | stats count by actor.user.name',
           "table"),
    ]
    items = [{"i": "count", "x": 0, "y": 0, "w": 4, "h": 3}, {"i": "users", "x": 4, "y": 0, "w": 8, "h": 4}]
    dash = _create(analyst, f"deep_time_{soc.tag}", panels, items, autoRun=True,
                   defaultTimeRange={"type": "preset", "preset": "Last 7 days"})
    page.goto(f"/dashboards/{dash['id']}")
    _wait_status(page, _panel("count"))
    single = {"css": f'{_panel("count")["css"]} [data-testid="viz-single-value"]'}
    assert int(float(page.attr(single, "data-value"))) == soc.by_source[soc.auth]

    # Narrow the dashboard window to the last hour: every panel re-queries.
    since = page.now_ms()
    page.click({"testid": "time-range-trigger"})
    page.click({"css": '[data-testid="time-preset"][data-preset="Last hour"]'})
    eventually(lambda: page.requests_containing("/api/dashboards/panel/query", since_ms=since), timeout=30,
               interval=0.5, desc="panel queries after the time change", ok=lambda r: len(r) >= 2)
    want = int(client.search(f'source_type="{soc.auth}"', limit=1, minutes_back=60)["total_count"])
    assert want > 0, "no seeded auth event in the last hour (a stale kept stack: re-seed with --fresh)"
    got = eventually(lambda: int(float(page.attr(single, "data-value") or -1)), timeout=30, interval=0.5,
                     desc="the last-hour count", ok=lambda v: abs(v - want) <= 1)
    timeline.step("last hour", shown=got, api=want)
    assert got < soc.by_source[soc.auth]

    # Refresh re-queries; auto-refresh shows as live.
    since = page.now_ms()
    page.click({"testid": "dashboard-run"})
    eventually(lambda: page.requests_containing("/api/dashboards/panel/query", since_ms=since), timeout=30,
               interval=0.5, desc="Refresh to re-query", ok=lambda r: len(r) >= 2)
    page.choose({"testid": "dashboard-autorefresh"}, "30 seconds")
    page.wait_text(uilib.rx(r"live\s*·\s*30 seconds"), timeout_ms=10_000)
    # It really re-queries on its own, then stops once turned off (so the
    # drill-down below cannot race a background refresh).
    since = page.now_ms()
    eventually(lambda: page.requests_containing("/api/dashboards/panel/query", since_ms=since), timeout=50,
               interval=1, desc="an auto-refresh re-query within 30 s", ok=lambda r: len(r) >= 2)
    page.choose({"testid": "dashboard-autorefresh"}, "Off")
    page.wait_text(uilib.rx(r"live\s*·"), timeout_ms=10_000, gone=True)

    # Back to 7 days, then drill from a table row into Search.
    since = page.now_ms()
    page.click({"testid": "time-range-trigger"})
    page.click({"css": '[data-testid="time-preset"][data-preset="Last 7 days"]'})
    eventually(lambda: page.requests_containing("/api/dashboards/panel/query", since_ms=since), timeout=30,
               interval=0.5, desc="panel queries for the 7-day window", ok=lambda r: len(r) >= 2)
    eventually(lambda: int(float(page.attr(single, "data-value") or -1)), timeout=30, interval=0.5,
               desc="the 7-day count back on the stat panel", ok=lambda v: v == soc.by_source[soc.auth])
    _wait_status(page, _panel("users"))
    page.click({"css": f'{_panel("users")["css"]} tbody tr', "has": "judy.chen"})
    page.wait_url(r"/search", timeout_ms=30_000)
    q = unquote(page.url)
    assert 'actor.user.name="judy.chen"' in q, q
    total = deep.shown_total(page)
    assert total == soc.auth_failures_by_user["judy.chen"], total
    timeline.step("drilldown", url=q[-200:], total=total)


def test_panel_open_in_search_carries_the_query(analyst, soc: SocData) -> None:
    page = analyst.page
    query = f'source_type="{soc.net}" | stats count by dst_endpoint.port'
    dash = _create(analyst, f"deep_open_{soc.tag}", [_p("p", "Ports", query, "bar")],
                   [{"i": "p", "x": 0, "y": 0, "w": 6, "h": 4}], autoRun=True,
                   defaultTimeRange={"type": "preset", "preset": "Last 7 days"})
    page.goto(f"/dashboards/{dash['id']}")
    _wait_status(page, _panel("p"))
    page.capture_window_open()
    page.click({"css": f'{_panel("p")["css"]} [data-testid="panel-menu"]'})
    page.click({"role": "menuitem", "name": "View query"})
    page.click({"role": "button", "name": "Open in Search", "exact": True})
    opened = eventually(page.opened, timeout=10, interval=0.3, desc="window.open", ok=bool)
    frag = parse_qs(urlparse(opened[0]).fragment)
    assert frag["q"][0] == query, opened
    start, end = datetime.fromisoformat(frag["start"][0].replace("Z", "+00:00")), \
        datetime.fromisoformat(frag["end"][0].replace("Z", "+00:00"))
    assert timedelta(days=6) < end - start <= timedelta(days=7, hours=1)


def test_export_import_share_settings_and_delete(analyst, soc: SocData, tmp_path, timeline) -> None:
    page, client = analyst.page, analyst.client
    panels = [_p("p", "DNS by domain", f'source_type="{soc.dns}" | stats count by query.hostname', "pie")]
    name = f"deep_export_{soc.tag}"
    dash = _create(analyst, name, panels, [{"i": "p", "x": 0, "y": 0, "w": 6, "h": 4}])
    page.goto(f"/dashboards/{dash['id']}")
    page.wait_text(name, exact=False)

    # Export as JSON.
    page.click({"role": "button", "name": "More actions", "exact": True})
    fname, text = page.download({"role": "menuitem", "name": "Export as JSON"})
    exported = json.loads(text)
    assert fname.endswith(".json")
    assert exported["dashboard"]["name"] == name
    assert [(p["title"], p["query"]) for p in exported["dashboard"]["panels"]] == [(p["title"], p["query"]) for p in panels]

    # Share copies the link.
    page.click({"role": "button", "name": "Share", "exact": True})
    link = eventually(page.clipboard, timeout=10, interval=0.3, desc="the share link", ok=lambda t: dash["id"] in t)
    assert link.endswith(f"/dashboards/{dash['id']}")

    # Settings: rename.
    renamed = f"{name}_renamed"
    page.click({"role": "button", "name": "More actions", "exact": True})
    page.click({"role": "menuitem", "name": "Settings", "exact": True})
    page.fill(uilib.field({"placeholder": "Dashboard name", "within": {"role": "dialog"}}, renamed))
    page.click({"role": "button", "name": "Save", "exact": True, "within": {"role": "dialog"}})
    page.wait_text("Settings saved", exact=False)
    assert eventually(lambda: _get(client, dash["id"])["name"], timeout=10, interval=0.3, desc="rename",
                      ok=lambda n: n == renamed) == renamed

    # Import the exported file from the list: a new private dashboard.
    imported_name = f"{name}_imported"
    exported["dashboard"]["name"] = imported_name
    path = tmp_path / "dash.json"
    path.write_text(json.dumps(exported))
    page.goto("/dashboards")
    page.upload({"css": 'input[type=file][accept=".json"]', "visible": False}, str(path))
    page.wait_url(r"/dashboards/dash_", timeout_ms=30_000)
    new_id = urlparse(page.url).path.rsplit("/", 1)[-1]
    _cleanup(analyst, new_id)
    imported = _get(client, new_id)
    assert imported["name"] == imported_name and imported["visibility"] == "private"
    assert [p["query"] for p in imported["panels"]] == [p["query"] for p in panels]

    # The list shows both; delete the renamed one from its card menu.
    page.goto("/dashboards")
    card = {"css": f'[data-testid="dashboard-card"][data-dashboard-id="{dash["id"]}"]'}
    page.wait_for(card)
    assert page.count({"css": f'[data-testid="dashboard-card"][data-dashboard-id="{new_id}"]'}) == 1
    page.hover(card)
    page.click({"role": "button", "name": "More actions", "within": card})
    page.click({"role": "menuitem", "name": "Delete", "exact": True})
    page.click({"role": "button", "name": "Delete", "exact": True, "within": {"role": "dialog"}})
    page.wait_for(card, gone=True)
    assert client.api.get(f"/api/dashboards/{dash['id']}").status_code == 404
    # NAN-5711: deleting it again reads as "already gone" for this non-admin.
    assert client.api.delete(f"/api/dashboards/{dash['id']}").status_code == 404
    page.reload()
    page.wait_for({"css": f'[data-testid="dashboard-card"][data-dashboard-id="{new_id}"]'})
    assert page.count(card) == 0
    timeline.step("deleted", id=dash["id"], imported=new_id)


def test_empty_and_error_panels_render_cleanly(analyst, soc: SocData, timeline) -> None:
    page = analyst.page
    panels = [
        _p("empty", "Nothing here", f'source_type="{soc.auth}" actor.user.name="nobody-{soc.tag}" | stats count by device.hostname', "table"),
        _p("broken", "Broken", f'source_type="{soc.auth}" | stats count by', "bar"),
        _p("ok", "Fine", f'source_type="{soc.auth}" | stats count', "single_value"),
    ]
    items = [{"i": p["id"], "x": 4 * i, "y": 0, "w": 4, "h": 3} for i, p in enumerate(panels)]
    dash = _create(analyst, f"deep_states_{soc.tag}", panels, items, autoRun=True,
                   defaultTimeRange={"type": "preset", "preset": "Last 7 days"})
    page.goto(f"/dashboards/{dash['id']}")
    _wait_status(page, _panel("ok"))
    _wait_status(page, _panel("empty"), "empty")
    _wait_status(page, _panel("broken"), "error")
    page.wait_for({"css": f'{_panel("empty")["css"]} [data-testid="panel-empty"]'})
    message = " ".join(page.texts({"css": f'{_panel("broken")["css"]} [data-testid="panel-error-message"]'}))
    timeline.step("states", error=message)
    assert message.strip(), "the error panel shows no reason"
    for leak in ("panicked", "DB::Exception", "stack backtrace", "SELECT "):
        assert leak not in message, message
    assert deep.new_page_errors(analyst) == []
    page.screenshot("empty-and-error-panels.png")

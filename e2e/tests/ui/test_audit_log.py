"""Settings > Audit (NAN-4930, on clickhouse/dev) against the audit API:

- an action taken with an API key shows its actor as "<owner> via key <key>",
  exactly the label the API's user_name/api_key_name make;
- the Action filter round-trips through the URL (a reload keeps it, the
  Filters button shows Active, every row has that action);
- Export CSV saves exactly the rows on screen, in order, every cell quoted,
  and a resource name a spreadsheet would evaluate is neutralized with a
  leading `'`.
"""

from __future__ import annotations

import csv
import io
import re
from typing import Any

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.runid import route_key
from nano_e2e.waits import eventually

FORMULA_PREFIX = re.compile(r"^\s*[=+\-@]")


def _actor_label(log: dict[str, Any]) -> str:
    owner = log.get("user_name") or log.get("user_id")
    key = log.get("api_key_name") or log.get("api_key_id")
    if key:
        return f"{owner} via key {key}" if owner else f"API key {key}"
    return owner or "system"


def _audit(nano: Nano, **params: Any) -> list[dict[str, Any]]:
    # A 500 "memory limit exceeded" from ClickHouse is retried briefly (seen on
    # a 4G probe stack under load; README finding).
    resp = eventually(
        lambda: nano.api.get("/api/audit", params={"limit": 50, **params}),
        timeout=60,
        interval=5,
        desc="the audit API to answer",
        ok=lambda r: r.status_code == 200 or "memory limit" not in r.text,
    )
    return api_expect(resp, 200)["logs"]


def test_audit_api_key_actor_filter_url_and_csv(nano: Nano, page: uilib.UiPage, request, timeline) -> None:
    rk = route_key(request.node.nodeid, "audit")
    # A resource name a spreadsheet would evaluate: the export must neutralize it.
    name = f"=1+1-{rk}"
    resp = nano.api.post(
        "/api/log-sources",
        json={
            "name": name,
            "description": "nano-e2e audit scenario (NAN-4937)",
            "source_type": "routed",
            "parser_vrl": "",
            "match_values": [rk],
            "lifecycle_status": "draft",
        },
    )
    if resp.status_code >= 400:  # the name is refused: fall back to a plain one
        name = rk
        src = nano.create_draft_source(name=name, route_key=rk)
    else:
        src = resp.json()
    try:
        row = eventually(
            lambda: next((r for r in _audit(nano) if (r.get("resource_name") or "") == name), None),
            timeout=30,
            desc="the create in the audit API",
            ok=lambda r: r is not None,
        )
        timeline.step("api row", action=row["action"], actor=_actor_label(row), key=row.get("api_key_name"))
        assert row.get("api_key_id") or row.get("api_key_name"), f"the API-key action has no key: {row}"
        action = row["action"]

        page.goto(f"/settings/audit?action={action}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        tr = {"role": "row", "has": name}
        # The actor cell truncates visually; its title carries the full label.
        actor = page.attr({"css": "span[title]", "within": tr}, "title") or ""
        timeline.step("ui actor", actor=actor)
        assert actor == _actor_label(row), (actor, _actor_label(row))

        # The filter is in the URL: a reload keeps it; Filters shows Active.
        page.reload()
        page.wait_text(name, exact=False, timeout_ms=30_000)
        assert f"action={action}" in page.url
        assert page.count({"role": "button", "name": uilib.rx("Filters.*Active")}) == 1
        api_rows = _audit(nano, action=action)
        ui_rows = [r for r in page.texts({"css": "tbody tr"}) if r.strip()]
        timeline.step("filtered", api=len(api_rows), ui=len(ui_rows))
        # Every row on screen is this action (rendered as its label): as many
        # rows as the API returns for the filter (one page).
        shown_action = re.sub(r"\b\w", lambda m: m.group(0).upper(), re.sub(r"[._]", " ", action))
        assert all(shown_action in r for r in ui_rows), ui_rows[:3]
        assert len(ui_rows) == len(api_rows), (len(ui_rows), len(api_rows))

        # CSV: exactly the rows on screen, quoted, formula-safe.
        fname, text = page.download({"role": "button", "name": "Export CSV"})
        rows = list(csv.reader(io.StringIO(text)))
        timeline.step("csv", file=fname, rows=len(rows) - 1)
        assert re.fullmatch(r"audit-log-\d{4}-\d{2}-\d{2}\.csv", fname), fname
        assert rows[0] == [
            "Timestamp",
            "Actor",
            "API Key",
            "Source",
            "Action",
            "Resource Type",
            "Resource Name",
            "IP Address",
            "Success",
            "Details",  # NAN-5324: scopes granted, old -> new values, denial reasons
        ]
        assert len(rows) - 1 == len(ui_rows), (len(rows) - 1, len(ui_rows))
        assert all(line.startswith('"') for line in text.splitlines()), "a cell is not quoted"
        mine = next(r for r in rows[1:] if name.lstrip("=") in r[6])
        assert mine[1] == _actor_label(row) and mine[4] == action
        if FORMULA_PREFIX.match(name):
            assert mine[6] == "'" + name, f"formula not neutralized: {mine[6]!r}"
        for r in rows[1:]:
            assert not any(FORMULA_PREFIX.match(c) for c in r), f"an exported cell evaluates: {r}"

        # NAN-5308: the search runs server-side, so "Export all" exports the
        # rows matching the filters AND the search box (never broader than the
        # visible result set) via POST /api/audit/export, bounded and formula-safe.
        search = {"placeholder": "Search logs…"}
        export_all = {"role": "button", "name": "Export all"}
        term = name.lstrip("=")
        page.fill(uilib.field(search, term))
        assert page.attr(export_all, "disabled") is None
        since = page.now_ms()
        all_name, all_text = page.download(export_all, timeout_ms=60_000)
        all_rows = list(csv.reader(io.StringIO(all_text)))
        timeline.step("server csv", file=all_name, rows=len(all_rows) - 1)
        assert all_name == "audit_logs.csv", all_name
        assert page.requests_containing("/api/audit/export", since_ms=since), "no server export request"
        assert all_rows[0] == [
            "id",
            "timestamp",
            "user_id",
            "user_name",
            "api_key_id",
            "api_key_name",
            "action",
            "source",
            "resource_type",
            "resource_id",
            "resource_name",
            "ip_address",
            "success",
            "message",
            "details",  # NAN-5324
        ]
        assert all(any(term.lower() in c.lower() for c in r) for r in all_rows[1:]), "export ignored the search"
        all_mine = next(r for r in all_rows[1:] if name.lstrip("=") in r[10])
        assert all_mine[6] == action
        if FORMULA_PREFIX.match(name):
            assert all_mine[10] == "'" + name, f"server export formula not neutralized: {all_mine[10]!r}"
        for exported in all_rows[1:]:
            assert not any(FORMULA_PREFIX.match(c) for c in exported), f"a server-exported cell evaluates: {exported}"
        page.screenshot("audit-export-all.png")
    finally:
        nano.delete_source(src["id"])

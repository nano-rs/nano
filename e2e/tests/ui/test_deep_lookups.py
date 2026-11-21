"""Lookup tables end to end in the browser (NAN-5686).

tests/ui/test_lookups_ui.py covers delete-refused-while-used and Replace data.
This walks the rest of the life of a table, as a throwaway persona:

- create by CSV upload (Create > Upload a file > save table): the rows API
  returns exactly the CSV;
- add a row in the grid: it persists (rows API); a cell edit is
  `test_lookup_cell_edit_updates_in_place`;
- use it in a search (`| lookup <t> actor.user.name AS account`):
  the owner column the UI shows == the search API, including the edited and
  the added row;
- use it in a rule: the rule enriches with the table and records matches only
  for users the table maps to the owner it filters on; the table's usage API
  names the rule.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually

PERMS = (
    "search:view",
    "search:execute",
    "lookup:view",
    "lookup:create",
    "lookup:edit",
    "detections:view",
    "detections:create",
    "detections:edit",
    "detections:promote",
)


def _rows(client: Nano, table: str) -> list[dict[str, Any]]:
    body = expect(client.api.get(f"/api/lookup-tables/{table}/rows", params={"page_size": 100}), 200)
    return body.get("rows", body) if isinstance(body, dict) else body


def _owners(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {str(r.get("account")): str(r.get("owner")) for r in rows}


def test_lookup_upload_edit_search_and_rule(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, ui: uilib.Driver, artifact_dir: Path, timeline
) -> None:
    sfx = mark[-6:].replace("-", "")
    users = {f"lk-alice-{sfx}": "finance", f"lk-bob-{sfx}": "eng", f"lk-carol-{sfx}": "eng"}
    table = f"e2e_owners_{secrets.token_hex(3)}"
    csv_path = artifact_dir / f"{table}.csv"
    csv_path.write_text("account,owner\n" + "".join(f"{u},{o}\n" for u, o in list(users.items())[:2]))
    for u in users:
        ocsf_lane.send(stack, mark, u, "198.51.100.120", "lk-host", note="lookup")
    eventually(lambda: nano.search(f'"{mark}"')["total_count"], timeout=INGEST_VISIBLE, desc="events",
               ok=lambda n: n == len(users))
    rule_id = None
    try:
        with login_persona(stack, nano, ui, artifact_dir, "deep-lookups", PERMS) as persona:
            page, client = persona.page, persona.client

            # 1. Upload a CSV.
            page.goto("/rules/lookup-tables/new")
            page.click({"role": "button", "name": uilib.rx("Upload a file")})
            page.upload({"css": 'input[type="file"]'}, str(csv_path))
            page.fill(uilib.field({"placeholder": "untitled_lookup_table"}, table))
            if page.count({"placeholder": "e.g. ip, user, hash"}):
                page.fill(uilib.field({"placeholder": "e.g. ip, user, hash"}, "account"))
            page.click({"role": "button", "name": "save table", "exact": True})
            page.wait_text("Lookup table created", exact=False, timeout_ms=60_000)
            page.wait_url(rf"/rules/lookup-tables/{table}")
            rows = _rows(client, table)
            assert _owners(rows) == dict(list(users.items())[:2]), rows
            timeline.step("uploaded", rows=len(rows))

            # 2. Add carol in the grid (cell edits: test_lookup_cell_edit_updates_in_place).
            carol = next(u for u in users if u.startswith("lk-carol"))
            page.click({"testid": "lookup-add-row"})
            page.fill(uilib.field({"testid": "lookup-new-row-account"}, carol),
                      uilib.field({"testid": "lookup-new-row-owner"}, users[carol]))
            page.press_key({"testid": "lookup-new-row-owner"}, "Enter")
            eventually(lambda: _owners(_rows(client, table)), timeout=30, interval=0.5,
                       desc="added row persisted", ok=lambda o: o == users)
            assert len(_rows(client, table)) == 3
            page.screenshot("deep-lookup-edited.png", full_page=False)
            timeline.step("edited", owners=users)

            # 3. Search with | lookup: UI == API == the table.
            q = f'"{mark}" | lookup {table} actor.user.name AS account | stats count by actor.user.name, owner'
            api = nano.search(q)
            api_map = {str(r.get("actor.user.name") or (r.get("actor") or {}).get("user", {}).get("name")): str(r.get("owner"))
                       for r in api.get("results") or []}
            assert api_map == users, api_map
            uilib.run_search(page, q)
            header, body = uilib.table_rows(page)
            idx_u = next(i for i, h in enumerate(header) if "user" in h.lower())
            idx_o = next(i for i, h in enumerate(header) if h.lower().startswith("owner"))
            ui_map = {r[idx_u]: r[idx_o] for r in body}
            assert ui_map == users, (header, body)
            timeline.step("search lookup", ui=ui_map)

            # 4. A rule that uses the table: only "eng" owners match.
            rule = expect(client.api.post("/api/rules", json={
                "name": f"lookup_owner_eng_{sfx}", "description": "nano-e2e lookup rule (NAN-5686)",
                "query": f'source_type="{ocsf_lane.lane}" "{mark}" | lookup {table} actor.user.name AS account | where owner="eng"',
                "severity": "low", "mode": "live", "detection_mode": "scheduled", "schedule_cron": "* * * * *",
                "lookback_minutes": 30, "folder": "Automated"}), 200, 201)
            rule_id = rule["id"]
            usage = expect(client.api.get(f"/api/lookup-tables/{table}/usage"), 200)
            assert rule["name"] in str(usage), usage
            expect(client.api.post(f"/api/rules/{rule_id}/trigger"), 200)
            want = sum(1 for o in users.values() if o == "eng")
            matches = eventually(
                lambda: expect(client.api.get(f"/api/rules/{rule_id}/matches", params={"limit": 50}), 200),
                timeout=DETECTION, interval=5, desc="lookup rule matched", ok=lambda m: m.get("total", 0) >= 1)
            events = [e for m in matches["matches"] for e in (m.get("events") or [])]
            seen = {str(e.get("actor", {}).get("user", {}).get("name") or e.get("actor.user.name")) for e in events}
            assert seen and all(users.get(u) == "eng" for u in seen), (seen, users)
            assert len(seen) <= want
            timeline.step("rule with lookup", matched_users=sorted(seen))
    finally:
        if rule_id:
            expect(nano.api.delete(f"/api/rules/{rule_id}"), 200, 204, 404)
        expect(nano.api.delete(f"/api/lookup-tables/{table}"), 200, 204, 404)


def test_lookup_csv_with_user_primary_key_keeps_columns(nano: Nano, timeline) -> None:
    """A CSV whose primary key column is named `user` keeps every column:
    the rows API returns what was uploaded."""
    table = f"e2e_userkey_{secrets.token_hex(3)}"
    body = b"user,owner\nalice,finance\nbob,eng\n"
    created = expect(nano.api.post(
        "/api/lookup-tables", files={"file": ("u.csv", body, "text/csv")},
        data={"config": json.dumps({"name": table, "format": "csv", "primary_key": "user", "mode": "append"})}),
        200, 201)
    try:
        assert created.get("records_inserted") == 2, created
        rows = [{k: v for k, v in r.items() if k != "_row_id"} for r in _rows(nano, table)]
        timeline.step("user-keyed table", rows=rows)
        users = sorted((r.get("user") for r in rows), key=str)
        owners = sorted((r.get("owner") for r in rows), key=str)
        assert users == ["alice", "bob"] and owners == ["eng", "finance"], \
            f"user-keyed CSV stored user={users}, owner={owners}"
    finally:
        expect(nano.api.delete(f"/api/lookup-tables/{table}"), 200, 204, 404)


def test_lookup_output_clause_returns_the_listed_columns(nano: Nano, ocsf_lane, stack: Stack, mark: str, timeline) -> None:
    """`| lookup t f AS key OUTPUT col` returns `col` from the matched row,
    exactly like the same lookup without OUTPUT does."""
    table = f"e2e_output_{secrets.token_hex(3)}"
    user = f"lkout-{mark[-6:]}"
    expect(nano.api.post(
        "/api/lookup-tables", files={"file": ("o.csv", f"account,owner\n{user},finance\n".encode(), "text/csv")},
        data={"config": json.dumps({"name": table, "format": "csv", "primary_key": "account", "mode": "append"})}),
        200, 201)
    try:
        ocsf_lane.send(stack, mark, user, "198.51.100.140", "lkout", note="output")
        eventually(lambda: nano.rows(f'actor.user.name="{user}"', limit=5), timeout=INGEST_VISIBLE, desc="event")
        base = f'actor.user.name="{user}" | lookup {table} actor.user.name AS account'
        plain = nano.rows(base + " | table actor.user.name, owner", limit=5)
        assert plain and plain[0].get("owner") == "finance", plain
        with_output = nano.rows(base + " OUTPUT owner | table actor.user.name, owner", limit=5)
        timeline.step("lookup OUTPUT", plain=plain[:1], output=with_output[:1])
        assert with_output, "the OUTPUT lookup returned no row at all"
        assert with_output[0].get("owner") == "finance", \
            f"OUTPUT clause returned owner={with_output[0].get('owner')!r} for a matched row"
    finally:
        expect(nano.api.delete(f"/api/lookup-tables/{table}"), 200, 204, 404)


def test_lookup_cell_edit_updates_in_place(stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir: Path, timeline) -> None:
    """Editing a cell in the grid changes that row: no new row, the key keeps
    one value."""
    table = f"e2e_celledit_{secrets.token_hex(3)}"
    expect(nano.api.post(
        "/api/lookup-tables", files={"file": ("c.csv", b"account,owner\nalice,finance\nbob,eng\n", "text/csv")},
        data={"config": json.dumps({"name": table, "format": "csv", "primary_key": "account", "mode": "append"})}),
        200, 201)
    try:
        with login_persona(stack, nano, ui, artifact_dir, "lookup-cell-edit", PERMS) as persona:
            page, client = persona.page, persona.client
            page.goto(f"/rules/lookup-tables/{table}")
            page.wait_for({"testid": "lookup-cell-0-owner"}, timeout_ms=30_000)
            idx = next(i for i in range(2) if page.texts({"testid": f"lookup-cell-{i}-account"})[0].strip() == "bob")
            page.click({"testid": f"lookup-cell-{idx}-owner"})
            cell = {"css": f'[data-testid="lookup-cell-{idx}-owner"] input'}
            page.fill(uilib.field(cell, "sec"))
            page.press_key(cell, "Enter")
            rows = eventually(lambda: _rows(client, table), timeout=30, interval=0.5, desc="edit saved",
                              ok=lambda rs: any(r.get("owner") == "sec" for r in rs))
            page.screenshot("lookup-cell-edit.png", full_page=False)
            bobs = sorted(str(r.get("owner")) for r in rows if r.get("account") == "bob")
            timeline.step("cell edit", rows=len(rows), bob=bobs)
            assert len(rows) == 2 and bobs == ["sec"], f"cell edit left {len(rows)} rows, bob={bobs}"
    finally:
        expect(nano.api.delete(f"/api/lookup-tables/{table}"), 200, 204, 404)

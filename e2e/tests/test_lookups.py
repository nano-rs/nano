"""Lookup lifecycle (NAN-4924 / NAN-2875 review fixes).

- A table an active rule uses through the NORMAL `| lookup <table> <field>`
  syntax cannot be deleted (409 naming the rule); once the rule is gone the
  delete succeeds. The rule is saved through the rules API, so the guard is
  judged against what the product actually stores.
- A replace switches schema and rows together: afterwards reads return only
  the new rows under the new schema.
"""

from __future__ import annotations

import json

from nano_e2e.client import Nano, expect

TABLE = "asset_inventory"


def _upload(nano: Nano, csv: str, mode: str) -> dict:
    config = {"name": TABLE, "format": "csv", "primary_key": "ip", "mode": mode}
    return expect(
        nano.api.post(
            "/api/lookup-tables",
            files={"file": ("assets.csv", csv.encode(), "text/csv")},
            data={"config": json.dumps(config)},
        ),
        200,
        201,
    )


def _drop_table_if_present(nano: Nano) -> None:
    resp = nano.api.delete(f"/api/lookup-tables/{TABLE}")
    assert resp.status_code in (200, 404), resp.text


def _rows(nano: Nano) -> list[dict]:
    body = expect(nano.api.get(f"/api/lookup-tables/{TABLE}/rows", params={"page_size": 50}), 200)
    return body.get("rows", body) if isinstance(body, dict) else body


def test_lookup_used_by_rule_cannot_be_deleted(nano: Nano, mark: str, timeline) -> None:
    _drop_table_if_present(nano)
    _upload(nano, "ip,owner\n10.0.0.1,alice\n10.0.0.2,bob\n", "append")
    rule = expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": f"e2e lookup ref {mark}",
                "description": "nano-e2e lookup reference (NAN-4924)",
                "query": f"* | lookup {TABLE} src_ip",
                "severity": "low",
                "mode": "staging",
                "detection_mode": "scheduled",
            },
        ),
        200,
        201,
    )
    timeline.step("rule saved", rule=rule["id"], query=rule.get("query"))
    try:
        blocked = nano.api.delete(f"/api/lookup-tables/{TABLE}")
        assert blocked.status_code == 409, blocked.text
        assert rule["name"] in blocked.text, blocked.text
        assert expect(nano.api.get(f"/api/lookup-tables/{TABLE}"), 200)["name"] == TABLE
        timeline.step("delete refused while referenced")
    finally:
        expect(nano.api.delete(f"/api/rules/{rule['id']}"), 200, 204)

    expect(nano.api.delete(f"/api/lookup-tables/{TABLE}"), 200)
    assert nano.api.get(f"/api/lookup-tables/{TABLE}").status_code == 404
    timeline.step("delete allowed once unreferenced")


def test_replace_switches_schema_and_rows_together(nano: Nano, timeline) -> None:
    _drop_table_if_present(nano)
    created = _upload(nano, "ip,owner\n10.0.0.1,alice\n10.0.0.2,bob\n", "append")
    old_physical = created["table"]["table_name"]
    try:
        replaced = _upload(nano, "ip,site\n10.9.9.9,dc-2\n", "replace")
        table = expect(nano.api.get(f"/api/lookup-tables/{TABLE}"), 200)
        assert table["table_name"] != old_physical, "pointer must move to the staged generation"
        assert [c["name"] for c in table["columns"]] == ["ip", "site"], table["columns"]
        assert table["row_count"] == 1, table
        rows = _rows(nano)
        assert [r.get("ip") for r in rows] == ["10.9.9.9"], rows
        assert all("owner" not in r for r in rows), rows
        timeline.step("replaced", physical=table["table_name"], inserted=replaced.get("records_inserted"))
    finally:
        _drop_table_if_present(nano)

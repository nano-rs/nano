"""Lookups in the browser (NAN-4924, on clickhouse/dev), against the lookup API:

- deleting a table an active rule uses (`| lookup <table> src_ip`) from the
  list's row menu is refused, the page names the rule, and the API still has
  the table;
- Replace data (Create > ?update=<table>, upload a CSV with a new schema)
  swaps schema and rows together: the rows API returns only the new rows and
  the table page shows them;
- once the rule is gone the same Delete succeeds and the API returns 404.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.waits import eventually


MISSING: list[float] = []  # regression evidence if the rows API gaps during replace


def _rows(nano: Nano, table: str) -> list[dict]:
    r = nano.api.get(f"/api/lookup-tables/{table}/rows", params={"page_size": 50})
    if r.status_code == 404:
        # NAN-4958 regression: record the gap, then keep polling so the final
        # assertion can report both the transient failure and the end state.
        MISSING.append(time.time())
        return []
    body = api_expect(r, 200)
    return body.get("rows", body) if isinstance(body, dict) else body


def _delete_from_list(page: uilib.UiPage, table: str) -> None:
    page.goto("/rules/lookup-tables")
    row = {"role": "row", "has": table}
    if not page.count(row):
        row = {"css": "[class*=group]", "has": table}
    page.wait_text(table, exact=False, timeout_ms=30_000)
    page.click({"role": "button", "name": "Row actions", "within": row})
    page.click({"role": "menuitem", "name": "Delete"})
    page.click({"role": "button", "name": "Delete", "exact": True, "within": {"role": "alertdialog"}})


def test_lookup_delete_in_use_refused_and_replace(
    nano: Nano, mark: str, page: uilib.UiPage, artifact_dir: Path, timeline
) -> None:
    MISSING.clear()
    table = f"e2e_lk_{secrets.token_hex(3)}"
    api_expect(
        nano.api.post(
            "/api/lookup-tables",
            files={"file": ("assets.csv", b"ip,owner\n10.0.0.1,alice\n10.0.0.2,bob\n", "text/csv")},
            data={"config": json.dumps({"name": table, "format": "csv", "primary_key": "ip", "mode": "append"})},
        ),
        200,
        201,
    )
    rule_name = f"e2e lookup ui {mark}"
    rule = api_expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": rule_name,
                "description": "nano-e2e lookup reference (NAN-4937)",
                "query": f"* | lookup {table} src_ip",
                "severity": "low",
                "mode": "live",
                "detection_mode": "scheduled",
            },
        ),
        200,
        201,
    )
    try:
        _delete_from_list(page, table)
        page.wait_text("Failed to delete", exact=False, timeout_ms=30_000)
        page.wait_text(rule_name, exact=False)
        assert nano.api.get(f"/api/lookup-tables/{table}").status_code == 200
        timeline.step("delete refused", rule=rule_name)

        # Replace: a new schema and new rows, together.
        csv = artifact_dir / "replacement.csv"
        csv.write_text("host,team\nws-1,red\nws-2,blue\nws-3,green\n")
        page.goto(f"/rules/lookup-tables/new?update={table}")
        page.wait_text(f"Replace data in {table}", timeout_ms=30_000)
        page.upload({"css": 'input[type="file"]'}, str(csv))
        page.click({"role": "button", "name": uilib.rx("^replace data$", "i")}, timeout_ms=30_000)
        rows = eventually(
            lambda: _rows(nano, table), timeout=30, desc="replaced rows", ok=lambda r: len(r) == 3
        )
        timeline.step("replaced", rows=rows, rows_api_404_during_replace=len(MISSING))
        assert not MISSING, "rows API returned 404 while Replace swapped lookup generations"
        assert all(set(r) >= {"host", "team"} and "ip" not in r for r in rows), rows
        page.goto(f"/rules/lookup-tables/{table}")
        for v in ("ws-1", "ws-2", "ws-3", "green"):
            page.wait_text(v, exact=False, timeout_ms=30_000)
        assert not page.contains("alice")
    finally:
        nano.api.delete(f"/api/rules/{rule['id']}")

    _delete_from_list(page, table)
    page.wait_text("Lookup table deleted", exact=False, timeout_ms=30_000)
    eventually(
        lambda: nano.api.get(f"/api/lookup-tables/{table}").status_code,
        timeout=30,
        desc="table gone",
        ok=lambda s: s == 404,
    )

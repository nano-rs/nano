"""Rule repositories in the browser (NAN-5686).

A fresh install follows nano-rs/rules on `main` with no clicks
(test_log_sources_nav.py proves the follow). Here a detection engineer:

- imports an AVAILABLE rule from its row (Import): the toast, the editor opens
  the new rule, the API has it in staging, and the repository row turns
  IMPORTED;
- "update available": the upstream copy moving ahead of the imported one is
  simulated in this throwaway stack's PostgreSQL (the imported rule's body
  made stale + `rule_imports.upstream_changed`, exactly what a sync that sees
  a new blob SHA writes). The page then shows the "imported rules have
  upstream updates" banner and the row UPDATED; Update brings the upstream
  body back and clears the flag;
- a linked rule edited locally: the row must say so (DRIFT), not keep
  claiming IMPORTED (`test_linked_rule_local_edit_shows_drift`).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import _psql_json, login_persona
from nano_e2e.rbac import typeid_uuid
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

PERMS = (
    "search:view",
    "detections:view",
    "detections:create",
    "detections:edit",
    "detections:promote",
    "rule_repositories:view",
    "rule_repositories:import",
)
ROW = "repo-rule-row"


def _repo(nano: Nano) -> dict[str, Any]:
    body = expect(nano.api.get("/api/rule-repositories"), 200)
    items = body.get("repositories", body) if isinstance(body, dict) else body
    return next(r for r in items if "nano-rs/rules" in str(r.get("url")))


def test_repositories_page_works_for_detections_view(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline
) -> None:
    """The rail shows Repositories, and the route opens it, for
    `detections:view` (AppLayout.tsx / App.tsx); its list must then load."""
    _synced_repo(nano)
    with login_persona(stack, nano, ui, artifact_dir, "repos-viewer", ("search:view", "detections:view")) as persona:
        page = persona.page
        page.goto("/rules/repositories")
        resp = persona.client.api.get("/api/rule-repositories")
        timeline.step("repositories as detections:view", api=resp.status_code)
        page.screenshot("repos-detections-view.png", full_page=False)
        assert resp.status_code == 200, f"rule-repositories answers {resp.status_code} for a role the page admits"


def _synced_repo(nano: Nano) -> dict[str, Any]:
    return eventually(lambda: _repo(nano), timeout=300, interval=5, desc="nano-rs/rules synced",
                      ok=lambda r: r.get("last_sync_status") == "success" or bool(r.get("last_synced_at")))


def _sql(query: str) -> Any:
    return _psql_json(query)


@pytest.fixture
def imported(stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline):
    """Import one AVAILABLE rule through the row's Import button."""
    repo = _synced_repo(nano)
    with login_persona(stack, nano, ui, artifact_dir, "deep-repos", PERMS) as persona:
        page, client = persona.page, persona.client
        page.goto("/rules/repositories")
        avail = {"css": f'[data-testid="{ROW}"][data-status="AVAILABLE"]'}
        page.wait_for(avail, timeout_ms=120_000)
        path = page.attr(avail, "data-path")
        row = {"css": f'[data-testid="{ROW}"][data-path="{path}"]'}
        page.click({"role": "button", "name": "Import", "exact": True, "within": row})
        page.wait_text("Rule imported", exact=False, timeout_ms=60_000)
        page.wait_url(r"/rules/editor/[^n]")
        rule_id = page.url.rstrip("/").split("/")[-1].split("?")[0]
        rule = expect(client.api.get(f"/api/rules/{rule_id}"), 200)
        # A row Import takes the repository rule's own mode (the preview pane picks another).
        assert rule["mode"] in ("staging", "live", "alerting"), rule
        page.goto("/rules/repositories")
        page.wait_attr(row, "data-status", "IMPORTED", timeout_ms=60_000)
        page.screenshot("deep-repo-imported.png", full_page=False)
        timeline.step("imported", path=path, rule=rule_id)
        try:
            yield {"repo": repo, "path": path, "row": row, "rule": rule, "page": page, "client": client}
        finally:
            expect(nano.api.delete(f"/api/rules/{rule_id}"), 200, 204, 404)


def test_import_then_update_available_applies_upstream(imported, nano: Nano, timeline) -> None:
    page, client, rule, row = imported["page"], imported["client"], imported["rule"], imported["row"]
    upstream_desc = rule.get("description") or ""
    rid = typeid_uuid(str(rule["id"]))
    flagged = _sql(
        "WITH r AS (UPDATE detection_rules SET description = 'e2e-stale-local-copy' "
        f"WHERE id = '{rid}' RETURNING id), "
        "i AS (UPDATE rule_imports SET upstream_changed = TRUE WHERE detection_rule_id IN (SELECT id FROM r) "
        "RETURNING id) SELECT json_build_object('rules', (SELECT count(*) FROM r), 'imports', (SELECT count(*) FROM i))"
    )
    assert flagged == {"rules": 1, "imports": 1}, flagged
    page.goto("/rules/repositories")
    page.wait_text(uilib.rx(r"imported rules? (has|have) upstream updates"), exact=False, timeout_ms=60_000)
    page.wait_attr(row, "data-status", "UPDATED", timeout_ms=60_000)
    page.screenshot("deep-repo-update-available.png", full_page=False)
    page.click({"role": "button", "name": "Update", "exact": True, "within": row})
    got = eventually(lambda: expect(client.api.get(f"/api/rules/{rule['id']}"), 200), timeout=60, interval=1,
                     desc="upstream body applied", ok=lambda r: r.get("description") != "e2e-stale-local-copy")
    assert (got.get("description") or "") == upstream_desc, (got.get("description"), upstream_desc)
    page.wait_attr(row, "data-status", "IMPORTED", timeout_ms=60_000)
    left = _sql(f"SELECT json_agg(upstream_changed) FROM rule_imports ri JOIN detection_rules d ON d.id = ri.detection_rule_id "
                f"WHERE d.id = '{rid}'")
    assert left == [False], left
    timeline.step("update applied", description=json.dumps(upstream_desc)[:80])


def test_linked_rule_local_edit_shows_drift(imported, timeline) -> None:
    page, client, rule, row = imported["page"], imported["client"], imported["rule"], imported["row"]
    expect(client.api.put(f"/api/rules/{rule['id']}", json={"description": "e2e local edit of a linked rule"}), 200)
    page.goto("/rules/repositories")
    page.wait_for(row, timeout_ms=60_000)
    status = eventually(lambda: page.attr(row, "data-status"), timeout=30, interval=1, desc="row status",
                        ok=lambda s: s in ("DRIFT", "IMPORTED", "UPDATED"))
    page.screenshot("deep-repo-linked-local-edit.png", full_page=False)
    timeline.step("linked rule edited locally", status=status)
    assert status == "DRIFT", f"a locally edited linked rule still reads {status}"

"""Rule archive / delete in the browser (v2.0.34, #10056 NAN-5672).

A deleted (archived) rule stays deleted:
- Rule actions > Archive rule > Archive Rule: the rule leaves the Rules list
  and the editor rail's Active list; `GET /api/rules/{id}` is a 404 while the
  console's `?include_archived=true` read still opens it;
- opening `/rules/editor/<id>` by URL shows the archived rule read-only
  (NAN-5683): the archived banner and state, no "streams via materialized
  view", no Test rule / Save / Tune settings, and Rule actions offers exactly
  Unarchive (no Pause, AI tune, Archive or Delete); the rail's Archived tab
  lists it;
- Unarchive brings it back in staging; a real-time rule gets its materialized
  view back and, promoted to live, records a match again;
- an editor without `detections:delete` is not offered Archive or Delete
  (NAN-5683), and the API refuses the archive (403); the rule is untouched.

Acting users are throwaway personas with explicit permissions. Rules are
snake_case in the "Automated" folder.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually

FOLDER = "Automated"
BASE = (
    "search:view",
    "search:execute",
    "detections:view",
    "detections:create",
    "detections:edit",
    "detections:promote",
)
ARCHIVER = (*BASE, "detections:delete")
EDITOR_NO_DELETE = BASE

ACTIONS = {"role": "button", "name": "Rule actions", "exact": True}


def _rule_name(prefix: str, mark: str) -> str:
    return f"{prefix}_{mark[-10:].replace('-', '_')}".lower()


def _get(client: Nano, rule_id: str, archived: bool = False) -> Any:
    params = {"include_archived": "true"} if archived else None
    return client.api.get(f"/api/rules/{rule_id}", params=params)


def _listed(client: Nano, name: str) -> bool:
    body = expect(client.api.get("/api/rules"), 200)
    items = body if isinstance(body, list) else body.get("rules", body.get("items", []))
    return any(item.get("name") == name for item in items)


def _choose(page: uilib.UiPage, label: str) -> None:
    """Rule actions > `label` (the menu can re-render under the click)."""
    item = {"role": "menuitem", "name": label, "exact": True}

    def choose() -> bool:
        try:
            if page.count(item) == 0:
                page.click(ACTIONS)
            page.press_key(item, "Enter")
            return True
        except uilib.UiError as exc:
            if "detached from document" not in str(exc):
                raise
            return False

    eventually(choose, timeout=15, interval=0.2, desc=f"rule action {label}")


def _menu_items(page: uilib.UiPage) -> list[str]:
    page.click(ACTIONS)
    items = page.texts({"role": "menuitem"})
    page.press_key(ACTIONS, "Escape")
    return items


@pytest.fixture
def rules(nano: Nano) -> Iterator[list[str]]:
    """Rule ids to delete afterwards (archive is idempotent; 404 is fine)."""
    ids: list[str] = []
    yield ids
    for rid in ids:
        expect(nano.api.delete(f"/api/rules/{rid}"), 200, 204, 404)


def _create(nano: Nano, rules: list[str], name: str, query: str, detection_mode: str) -> dict[str, Any]:
    rule = expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": name,
                "description": "nano-e2e v2.0.34 archive (NAN-5672)",
                "query": query,
                "severity": "medium",
                "schedule_cron": "*/5 * * * *",
                "mode": "staging",
                "detection_mode": detection_mode,
                "lookback_minutes": 15,
                "folder": FOLDER,
            },
        ),
        200,
        201,
    )
    rules.append(rule["id"])
    return rule


def test_archive_hides_rule_and_unarchive_restores_realtime(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, ui: uilib.Driver, artifact_dir, timeline, rules
) -> None:
    name = _rule_name("v2034_archive_rt", mark)
    user = f"arch-{mark[-8:]}"
    query = f'source_type="{ocsf_lane.lane}" actor.user.name="{user}"'
    rule = _create(nano, rules, name, query, "real-time")
    rule_id = rule["id"]
    assert rule["detection_mode"] == "real-time", f"the archive scenario needs a real-time rule: {rule}"
    assert (rule.get("folder") or "") == FOLDER, rule

    with login_persona(stack, nano, ui, artifact_dir, "rule-archiver", ARCHIVER) as persona:
        page, client = persona.page, persona.client
        # Live first, so archiving a running real-time rule is the case under test.
        expect(client.api.post(f"/api/rules/{rule_id}/promote", json={"expected_mode": "staging"}), 200)
        live = expect(_get(client, rule_id), 200)
        assert live["mode"] == "live" and live.get("materialized_view_name"), live
        timeline.step("real-time rule live", rule=rule_id, mv=live.get("materialized_view_name"))

        page.goto("/rules")
        page.wait_text(name, exact=False, timeout_ms=30_000)

        # Archive from the editor's Rule actions.
        page.goto(f"/rules/editor/{rule_id}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        _choose(page, "Archive rule")
        page.click(
            {"role": "button", "name": "Archive Rule", "exact": True, "within": {"role": "alertdialog"}}
        )
        page.wait_text("Rule archived", exact=False, timeout_ms=30_000)
        page.wait_url(r"/rules/editor/new")
        timeline.step("archived in the UI")

        assert _get(client, rule_id).status_code == 404, "an archived rule is a 404 without include_archived"
        archived = expect(_get(client, rule_id, archived=True), 200)
        assert archived["archived"] is True, archived
        assert archived["mode"] == "staging", archived
        assert not archived.get("materialized_view_name"), f"archive drops the real-time view: {archived}"
        assert not _listed(client, name), "an archived rule is not in the rules list"
        trigger = nano.api.post(f"/api/rules/{rule_id}/trigger")
        assert trigger.status_code == 404, f"a deleted rule never runs: {trigger.status_code}"
        timeline.step("API: 404 by default, archived via include_archived, MV dropped")

        page.goto("/rules")
        page.wait_for({"role": "heading"}, timeout_ms=30_000)
        eventually(
            lambda: page.contains(name),
            timeout=20,
            interval=0.5,
            desc="the archived rule leaves the Rules list",
            ok=lambda present: not present,
        )
        page.screenshot("v2034-rules-list-after-archive.png")

        # Opened by URL: the archived view (include_archived) is read-only, with
        # Unarchive the one action and no control the API now refuses (NAN-5683).
        page.goto(f"/rules/editor/{rule_id}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        page.wait_for({"testid": "archived-rule-banner"}, timeout_ms=15_000)
        items = _menu_items(page)
        assert items == ["Unarchive rule"], f"the archived rule offers a dead control: {items}"
        assert not page.contains("streams via materialized view"), "the header still claims the rule streams"
        assert page.contains("not running · read-only"), "the code header does not show the archived state"
        for dead in ("Test rule", "Save rule", "Saved"):
            assert page.count({"role": "button", "name": dead, "exact": True}) == 0, f"{dead} on an archived rule"
        assert not page.contains("Tune settings"), "Tune settings on an archived rule"
        rail = {"testid": "rule-editor-rail"}
        page.click({"role": "tab", "name": "Archived", "exact": True, "within": rail})
        page.wait_text(name, exact=False, timeout_ms=15_000)
        page.screenshot("v2034-archived-rule-by-url.png")
        timeline.step("archived view by URL", menu=items)

        _choose(page, "Unarchive rule")
        page.wait_text("Rule unarchived", exact=False, timeout_ms=30_000)
        back = eventually(
            lambda: expect(_get(client, rule_id), 200),
            timeout=30,
            interval=0.5,
            desc="unarchived rule readable without include_archived",
            ok=lambda r: r["archived"] is False and bool(r.get("materialized_view_name")),
        )
        assert back["mode"] == "staging" and back["detection_mode"] == "real-time", back
        assert _listed(client, name)
        timeline.step("unarchived", mode=back["mode"], mv=back.get("materialized_view_name"))

        # Working again: promote to live in the UI, then a match is recorded.
        page.goto(f"/rules/editor/{rule_id}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        _choose(page, "Promote to live")
        eventually(
            lambda: expect(_get(client, rule_id), 200)["mode"],
            timeout=30,
            interval=0.5,
            desc="promoted to live",
            ok=lambda m: m == "live",
        )
        ocsf_lane.send(stack, mark, user, "198.51.100.34", "arch-host", note="after-unarchive")
        eventually(
            lambda: nano.rows(f'actor.user.name="{user}"', limit=5),
            timeout=INGEST_VISIBLE,
            desc="matching event searchable",
        )
        eventually(
            lambda: expect(_get(client, rule_id), 200).get("live_match_count", 0),
            timeout=DETECTION,
            interval=3,
            desc="the unarchived real-time rule records a live match",
            ok=lambda n: n >= 1,
        )
        timeline.step("unarchived real-time rule matched")


def test_archive_without_delete_permission_is_refused(
    stack: Stack, nano: Nano, mark: str, ui: uilib.Driver, artifact_dir, timeline, rules
) -> None:
    name = _rule_name("v2034_archive_denied", mark)
    rule = _create(nano, rules, name, f'"{mark}"', "scheduled")
    rule_id = rule["id"]

    with login_persona(stack, nano, ui, artifact_dir, "rule-editor-nodelete", EDITOR_NO_DELETE) as persona:
        page = persona.page
        assert "detections:delete" not in persona.permissions
        page.goto(f"/rules/editor/{rule_id}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        items = _menu_items(page)
        # NAN-5683: archiving IS deleting (NAN-5672) — neither is offered
        # without detections:delete, while the editor's own actions remain.
        assert "Archive rule" not in items, items
        assert "Delete forever" not in items, items
        assert "Pause rule" in items, items
        page.screenshot("v2034-archive-refused.png")

        refused = persona.client.api.put(f"/api/rules/{rule_id}", json={"archived": True})
        assert refused.status_code == 403, refused.text[:500]
        still = expect(_get(nano, rule_id), 200)
        assert still["archived"] is False and still["mode"] == "staging", still
        timeline.step("archive refused without detections:delete", ui="Archive hidden", api=403)

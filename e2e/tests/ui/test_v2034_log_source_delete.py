"""Log-source deletes through the batcher (v2.0.34, #10060 / NAN-5678) on a live
PostgreSQL and Vector.

- A person (throwaway role: log_sources view/edit/delete) deletes one published
  source from Log Sources (row menu > Delete > Delete): the "Deleted" toast,
  no error toast, the row is gone, the API answers 404, and the source that
  stays keeps ingesting (a fresh event becomes searchable after the reload).
- The web UI has no bulk delete, so POST /api/log-sources/bulk-delete is driven
  through the API in the same run: 3 published sources in one request, every
  result `deleted`, every source 404 afterwards, ingest still flowing, and the
  audit holds exactly one `log_source_deleted` per source (by UUID before
  NAN-5683 / #10070, by its lsrc_ id and name after).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from nano_e2e import ingest
from nano_e2e import ui as uilib
from nano_e2e.client import Journal, Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.rbac import limited_user
from nano_e2e.runid import route_key as make_route_key
from nano_e2e.soar_ui import uuid_of
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

PARSER = """
.class_uid = 3002
.category_uid = 3
.activity_id = 1
.type_uid = 300201
.severity_id = 1
.actor.user.name = del(.user)
.metadata.log_source = "{lane}"
.metadata.product.name = "nano-e2e"
"""
DELETER_PERMS = ["log_sources:view", "log_sources:edit", "log_sources:delete", "credentials:view"]
ERROR_TOAST = {"css": "[data-sonner-toast][data-type=error], li.destructive[data-state=open]"}


def _published(nano: Nano, label: str) -> dict[str, Any]:
    rk = make_route_key(label, "v2034-del")
    src = nano.create_draft_source(name=rk, route_key=rk, parser_vrl=PARSER.format(lane=rk))
    res = api_expect(
        nano.api.post(f"/api/log-sources/{src['id']}/publish", json={"acknowledge_unattested": True}), 200
    )
    assert res.get("success") is True, f"publishing {rk} failed: {res}"
    return src


@pytest.fixture
def sources(nano: Nano) -> Iterator[list[str]]:
    ids: list[str] = []
    yield ids
    for sid in ids:
        r = nano.api.delete(f"/api/log-sources/{sid}")
        assert r.status_code in (200, 204, 404), f"cleanup {sid}: {r.status_code} {r.text[:200]}"


def _still_ingesting(stack: Stack, nano: Nano, lane, tag: str) -> None:
    user = f"{tag}-{lane.lane[-6:]}"
    n = {"i": 0}

    def probe() -> int:
        n["i"] += 1
        r = ingest.hec(stack.hec_url, lane.token, {"message": f"after delete {tag} {n['i']}", "user": user})
        assert r.status_code == 200, r.text
        return len(nano.rows(f'actor.user.name="{user}"', limit=5, minutes_back=15))

    eventually(
        probe, timeout=INGEST_VISIBLE, interval=3, desc=f"the remaining source still ingests ({tag})", ok=bool
    )


def _gone(nano: Nano, sid: str) -> None:
    eventually(
        lambda: nano.api.get(f"/api/log-sources/{sid}").status_code,
        timeout=30,
        interval=1,
        desc=f"{sid} answers 404",
        ok=lambda s: s == 404,
    )


def test_delete_one_source_in_the_ui_keeps_ingest_flowing(
    stack: Stack, nano: Nano, ocsf_lane, sources, ui: uilib.Driver, artifact_dir: Path, timeline
) -> None:
    victim = _published(nano, "ui-del")
    sources.append(victim["id"])
    with limited_user(stack, "lsdel", DELETER_PERMS, Journal(artifact_dir / "api.jsonl")) as user:
        p = uilib.UiPage.open(ui, artifact_dir / "ui-deleter", "log source deleter")
        failed = True
        try:
            uilib.login(p, user.email, user.password)
            p.goto("/ingestion/log-sources")
            row = {"role": "row", "has": victim["name"]}
            p.wait_for(row, timeout_ms=30_000)
            p.click({"css": "button[aria-haspopup=menu]", "within": row})
            p.click({"role": "menuitem", "name": "Delete", "exact": True})
            dlg = {"role": "alertdialog", "has": "Delete log source"}
            p.wait_for(dlg)
            since = p.now_ms()
            p.click({"role": "button", "name": "Delete", "exact": True, "within": dlg})
            # The delete waits for Vector's reload (310 s client budget, NAN-5678).
            p.wait_text(f'"{victim["name"]}" has been deleted.', exact=False, timeout_ms=320_000)
            assert p.count(ERROR_TOAST) == 0, p.texts(ERROR_TOAST)
            p.wait_for(row, gone=True, timeout_ms=30_000)
            events = p.events_since(since)
            failed_calls = [n for n in events["network"] if "/api/log-sources" in n["url"]]
            timeline.step("ui delete", source=victim["id"], failed_calls=failed_calls)
            assert not failed_calls, failed_calls
            p.screenshot("after-delete.png", full_page=False)
            failed = False
        finally:
            p.finish(failed)
    _gone(nano, victim["id"])
    _still_ingesting(stack, nano, ocsf_lane, "ui-del")


def test_bulk_delete_three_sources_one_audit_row_each(
    stack: Stack, nano: Nano, ocsf_lane, sources, timeline
) -> None:
    batch = [_published(nano, f"bulk-{i}") for i in range(3)]
    ids = [s["id"] for s in batch]
    sources.extend(ids)
    res = api_expect(nano.api.post("/api/log-sources/bulk-delete", json={"ids": ids}, timeout=320), 200)
    timeline.step("bulk delete", response=res)
    assert res["deleted"] == 3 and res["failed"] == 0, res
    assert sorted(r["id"] for r in res["results"] if r["deleted"]) == sorted(ids), res
    for sid in ids:
        _gone(nano, sid)

    names = {s["id"]: s["name"] for s in batch}

    def rows_per_source() -> dict[str, int]:
        logs = api_expect(
            nano.api.get("/api/audit", params={"limit": 200, "action": "log_source_deleted"}), 200
        )["logs"]
        # NAN-5683: each row carries the public lsrc_ TypeID the Log Sources API
        # shows (never the stored UUID) and the deleted source's name.
        raw = {uuid_of(sid) for sid in ids}
        leaked = [log.get("resource_id") for log in logs if (log.get("resource_id") or "").lower() in raw]
        assert not leaked, f"audit rows expose the raw UUID instead of the lsrc_ id: {leaked}"
        counts = {}
        for sid in ids:
            mine = [log for log in logs if log.get("resource_id") == sid]
            wrong = [log.get("resource_name") for log in mine if log.get("resource_name") != names[sid]]
            assert not wrong, f"{sid}: audit resource_name {wrong} != {names[sid]!r}"
            counts[sid] = len(mine)
        return counts

    counts = eventually(
        rows_per_source,
        timeout=60,
        interval=3,
        desc="one log_source_deleted audit row per source",
        ok=lambda c: all(v >= 1 for v in c.values()),
    )
    timeline.step("audit", counts=counts)
    assert all(v == 1 for v in counts.values()), counts

    # NAN-5683: the audit search takes the public id the rows show.
    probe = ids[0]
    found = api_expect(nano.api.get("/api/audit", params={"q": probe, "action": "log_source_deleted"}), 200)
    hits = [log for log in found["logs"] if log.get("resource_id") == probe]
    assert len(hits) == 1, f"q={probe} found {len(hits)} of its log_source_deleted rows: {found.get('total')}"
    _still_ingesting(stack, nano, ocsf_lane, "bulk-del")

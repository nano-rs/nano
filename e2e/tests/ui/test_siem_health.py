"""SIEM Health: the per-source health-series view, and deleted sources leaving
the health report (NAN-5760)."""

from __future__ import annotations

import httpx

from nano_e2e import schema
from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.runid import route_key as make_route_key
from nano_e2e.waits import eventually


def test_siem_health_lists_log_source_health(
    nano: Nano, ocsf_lane, page: uilib.UiPage, timeline
) -> None:
    series = eventually(
        lambda: api_expect(
            nano.api.get("/api/log-sources/health-series", params={"hours": 24}), 200
        ),
        timeout=60,
        interval=2,
        desc="the OCSF lane in the source health-series API",
        ok=lambda values: any(s.get("log_source_id") == ocsf_lane.source_id for s in values),
    )
    source = next(s for s in series if s["log_source_id"] == ocsf_lane.source_id)

    page.goto("/platform/health")
    page.wait_for({"testid": "log-source-health-section"}, timeout_ms=60_000)
    section = eventually(
        lambda: " ".join(page.texts({"testid": "log-source-health-section"})),
        timeout=60,
        interval=2,
        desc="the OCSF lane in SIEM Health",
        ok=lambda text: source["log_source_name"] in text,
    )
    timeline.step(
        "source health",
        source_id=source["log_source_id"],
        source_name=source["log_source_name"],
        state=source["state"],
    )
    assert "Log source health" in section
    assert source["log_source_name"] in section
    page.screenshot("siem-health-log-sources.png")


# ---------------------------------------------------------------- NAN-5760
# Deleted log sources leave SIEM Health. The report's per-source lists are
# keyed by ClickHouse `source_type`, and a deleted source's events stay in the
# logs table, so before the fix a source deleted with data in the prior 24h
# read as "silent" for up to 48h. Events are written straight to ClickHouse
# (30h old = silent, 5 min old = active) so the windows are deterministic.

def _ch(stack, sql: str) -> str:
    r = httpx.post(stack.ch_url, content=sql.encode(), auth=(stack.ch_admin_user, stack.ch_admin_password), timeout=120)
    assert r.status_code == 200, f"{r.status_code}: {r.text[:800]}"
    return r.text.strip()


def _write_events(stack, source_type: str, rows: int, hours_ago: float) -> None:
    ago_ms = int(hours_ago * 3_600_000)
    if schema.is_ocsf():
        _ch(
            stack,
            f"""INSERT INTO nanosiem.ocsf_logs_raw (event, source_type)
            SELECT concat('{{"time":', toString(toUnixTimestamp64Milli(now64(3)) - {ago_ms} - number * 1000),
              ',"class_uid":1007,"category_uid":1,"activity_id":1,"severity_id":1,',
              '"metadata":{{"log_source":"{source_type}","product":{{"name":"e2e"}}}}}}'), '{source_type}'
            FROM numbers({rows})""",
        )
    else:
        _ch(
            stack,
            f"""INSERT INTO nanosiem.logs (timestamp, source_type, message)
            SELECT now64(6) - toIntervalMillisecond({ago_ms} + number * 1000), '{source_type}', 'nan-5760 e2e'
            FROM numbers({rows})""",
        )


def _logs_count(stack, source_type: str) -> int:
    table = "nanosiem.ocsf_logs" if schema.is_ocsf() else "nanosiem.logs"
    return int(_ch(stack, f"SELECT count() FROM {table} WHERE source_type = '{source_type}' "
                          "AND timestamp >= now() - INTERVAL 48 HOUR") or 0)


def _ingestion(report: dict) -> dict:
    return (report.get("metrics") or {}).get("ingestion") or {}


def _types(rows: list) -> set[str]:
    return {r["source_type"] for r in rows or []}


def _trigger(nano: Nano) -> dict:
    api_expect(nano.api.post("/api/siem-health/reports/trigger", timeout=300), 200)
    return _latest(nano)


def _latest(nano: Nano) -> dict:
    return api_expect(nano.api.get("/api/siem-health/reports/latest"), 200)


def _future_events(stack, source_type: str, rows: int, minutes_ahead: int) -> None:
    """Events stamped after the delete (a sender still writing)."""
    _write_events(stack, source_type, rows=rows, hours_ago=-minutes_ahead / 60)


def test_siem_health_stops_reporting_deleted_sources(
    nano: Nano, stack, page: uilib.UiPage, timeline, request
) -> None:
    labels = ("kept", "single", "bulk_a", "bulk_b", "revived", "unclaimed")
    keys = {label: make_route_key(request.node.nodeid, label) for label in labels}
    ids: dict[str, str] = {}
    creds: list[str] = []
    try:
        # Sources that produced data have a live claim (a bound ingest token).
        for label in ("kept", "single", "bulk_a", "bulk_b", "revived"):
            ids[label] = nano.create_draft_source(name=keys[label], route_key=keys[label])["id"]
            creds.append(nano.issue_token(ids[label], name=f"{keys[label]}-tok")[0])
        # Evasion probe: a never-deployed, never-token-bound draft naming a
        # stream nobody claims (and a reserved lane). Deleting it hides nothing.
        ids["draft"] = nano.create_draft_source(name=keys["unclaimed"] + "_draft", route_key=keys["unclaimed"])["id"]

        # kept / single / bulk_a / revived / unclaimed went silent 30h ago;
        # bulk_b is still sending.
        for label in ("kept", "single", "bulk_a", "revived", "unclaimed"):
            _write_events(stack, keys[label], rows=20, hours_ago=30)
        _write_events(stack, keys["bulk_b"], rows=20, hours_ago=0.1)
        for key in keys.values():
            eventually(lambda key=key: _logs_count(stack, key), timeout=60, interval=2,
                       desc=f"{key} events in ClickHouse", ok=lambda n: n >= 20)

        before = _ingestion(_trigger(nano))
        silent = set(before.get("silent_sources") or [])
        timeline.step("report before delete", silent=sorted(silent & set(keys.values())))
        assert {keys[k] for k in ("kept", "single", "bulk_a", "revived", "unclaimed")} <= silent, before
        assert keys["bulk_b"] in _types(before.get("source_volumes"))

        # Single delete: the stored latest report follows at once.
        assert nano.api.delete(f"/api/log-sources/{ids.pop('single')}").status_code == 200
        latest = _ingestion(_latest(nano))
        assert keys["single"] not in (latest.get("silent_sources") or [])
        assert keys["single"] not in _types(latest.get("source_volumes"))
        assert keys["single"] in _types(latest.get("removed_sources"))
        assert keys["kept"] in (latest.get("silent_sources") or []), "a live source still alerts"

        # Bulk delete, including the evasion draft.
        bulk = api_expect(
            nano.api.post(
                "/api/log-sources/bulk-delete",
                json={"ids": [ids.pop("bulk_a"), ids.pop("bulk_b"), ids.pop("revived"), ids.pop("draft")]},
            ),
            200,
        )
        assert bulk["deleted"] == 4, bulk
        # `revived` keeps receiving events after its delete: live again.
        _future_events(stack, keys["revived"], rows=5, minutes_ahead=10)
        eventually(lambda: _logs_count(stack, keys["revived"]), timeout=60, interval=2,
                   desc="revived events in ClickHouse", ok=lambda n: n >= 25)

        removed = ("single", "bulk_a", "bulk_b")
        latest = _ingestion(_latest(nano))
        for label in removed:
            assert keys[label] not in (latest.get("silent_sources") or []), label
            assert keys[label] not in _types(latest.get("source_volumes")), label
            assert keys[label] in _types(latest.get("removed_sources")), label

        # A fresh report never counts them; the deleted data is a quiet state.
        after = _ingestion(_trigger(nano))
        after_removed = _types(after.get("removed_sources"))
        after_silent = set(after.get("silent_sources") or [])
        timeline.step(
            "report after delete",
            silent=sorted(after_silent & set(keys.values())),
            removed=sorted(after_removed & set(keys.values())),
        )
        assert keys["kept"] in after_silent
        for label in removed:
            assert keys[label] not in after_silent, label
            assert keys[label] not in _types(after.get("source_volumes")), label
        assert keys["unclaimed"] in after_silent, "a deleted draft never hides a stream it named"
        assert keys["unclaimed"] not in after_removed
        assert keys["revived"] in _types(after.get("source_volumes")), "events after the delete: live again"
        assert keys["revived"] not in after_removed
        assert not after_removed & {"audit", "findings", "signals"}, "platform lanes are never set aside"
        by_type = {r["source_type"]: r for r in after.get("removed_sources") or []}
        assert by_type[keys["bulk_b"]]["count_24h"] >= 20, "pre-delete data is shown, not active"
        assert by_type[keys["single"]]["log_source_name"] == keys["single"]

        page.goto("/platform/health")
        page.wait_for({"testid": "siem-health-removed-sources"}, timeout_ms=60_000)
        text = " ".join(page.texts({"testid": "siem-health-removed-sources"}))
        for label in removed:
            assert keys[label] in text, label
        assert keys["kept"] not in text
        assert keys["unclaimed"] not in text
        page.screenshot("siem-health-removed-sources.png")
    finally:
        for cred in creds:
            try:
                nano.revoke_token(cred)
            except Exception:  # noqa: BLE001,S110 - best-effort teardown
                pass
        for source_id in ids.values():
            nano.delete_source(source_id)

"""Detection -> alert: an event ingested with a per-source token matches an
Alerting rule and produces an alert carrying the event; a Live rule counts the
match but never alerts (the Staging -> Live -> Alerting contract)."""

from __future__ import annotations

from nano_e2e import ingest
from nano_e2e.client import Nano, expect, row_text
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually


def _rule(nano: Nano, name: str, query: str, mode: str) -> dict:
    return expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": name,
                "description": "nano-e2e scenario rule (NAN-4920)",
                "query": query,
                "severity": "high",
                "schedule_cron": "* * * * *",
                "mode": mode,
                "detection_mode": "scheduled",
                "lookback_minutes": 15,
            },
        ),
        200,
        201,
    )


def test_alerting_rule_creates_alert_live_rule_does_not(
    stack: Stack, nano: Nano, token_source, mark: str, timeline
) -> None:
    src = token_source()
    msg = f"{mark} failed login for admin from 203.0.113.7"
    assert ingest.hec(stack.hec_url, src.token, {"message": msg}).status_code == 200
    eventually(lambda: nano.rows(f'"{mark}"', limit=5), timeout=INGEST_VISIBLE, desc="event searchable")
    timeline.step("event searchable")

    query = f'source_type="{src.route_key}" "{mark}"'
    alerting = _rule(nano, f"e2e alerting {mark}", query, "alerting")
    live = _rule(nano, f"e2e live {mark}", query, "live")
    rule_ids = [alerting["id"], live["id"]]
    try:
        # Run both now rather than waiting for the cron tick (jobs also runs them).
        for rid in rule_ids:
            expect(nano.api.post(f"/api/rules/{rid}/trigger"), 200)
        timeline.step("rules triggered", alerting=alerting["id"], live=live["id"])

        alerts = eventually(
            lambda: expect(nano.api.get("/api/alerts", params={"rule_id": alerting["id"], "limit": 50}), 200),
            timeout=DETECTION,
            interval=5,
            desc="alert for the alerting rule",
            ok=lambda xs: any(mark in row_text(a.get("matched_events")) for a in xs),
        )
        hit = next(a for a in alerts if mark in row_text(a.get("matched_events")))
        assert hit["severity"] == "high", hit
        timeline.step("alert created", alert_id=hit["id"], status=hit.get("status"))

        matches = eventually(
            lambda: expect(nano.api.get(f"/api/rules/{live['id']}/matches", params={"limit": 10}), 200),
            timeout=DETECTION,
            interval=5,
            desc="live rule match recorded",
            ok=lambda m: (m.get("total") or 0) >= 1,
        )
        timeline.step("live rule matched", total=matches.get("total"))
        live_alerts = expect(nano.api.get("/api/alerts", params={"rule_id": live["id"], "limit": 50}), 200)
        assert live_alerts == [], f"a Live rule must not alert: {live_alerts}"
    finally:
        for rid in rule_ids:
            nano.api.delete(f"/api/rules/{rid}")

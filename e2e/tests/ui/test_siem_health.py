"""SIEM Health mounts the existing per-source health-series product view."""

from __future__ import annotations

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect
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

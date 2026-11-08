"""Real-browser acceptance of OTLP services, traces, metrics, and logs."""

from __future__ import annotations

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.otlp import CollectorSender, dataset
from nano_e2e.stack import Stack
from nano_e2e.ui import field, rx
from nano_e2e.waits import INGEST_VISIBLE, eventually


def test_otlp_observability_surfaces(
    stack: Stack,
    nano: Nano,
    token_source,
    mark: str,
    artifact_dir,
    page: uilib.UiPage,
    timeline,
) -> None:
    source = token_source("ui")
    service = f"nano-e2e-ui-{mark[-8:]}"
    data = dataset(f"{mark}-ui", service=service)

    with CollectorSender(
        stack,
        source.token,
        artifact_dir / "protobuf-sender",
        f"{mark}-ui",
    ) as sender:
        sender.send(data)

    eventually(
        lambda: expect(
            nano.search_http.get(
                f"/api/search/trace/{data.trace_id}", headers={"x-nano-cache-bypass": "1"}
            ),
            200,
        )["span_count"],
        timeout=INGEST_VISIBLE,
        interval=2,
        desc="UI trace available through the browser's backing API",
        ok=lambda count: count == 2,
    )
    eventually(
        lambda: nano.rows(f'source_type="{source.route_key}" "{data.marker}"', limit=5),
        timeout=INGEST_VISIBLE,
        interval=3,
        desc="UI OTLP log searchable",
    )
    timeline.step("OTLP UI dataset searchable", trace_id=data.trace_id, service=service)

    page.goto("/observability/services")
    page.wait_text(service, exact=True, timeout_ms=120_000)
    services_text = page.main_text()
    assert service in services_text and "SERVICE" in services_text, services_text[-2000:]
    page.screenshot("otlp-services.png")

    page.goto("/observability/traces")
    page.wait_text(data.trace_id, exact=True, timeout_ms=120_000)
    traces_text = page.main_text()
    assert service in traces_text and data.trace_id in traces_text and "2" in traces_text
    page.screenshot("otlp-traces-list.png")
    page.click({"text": data.trace_id, "exact": True})
    page.wait_text("Distributed trace", exact=True, timeout_ms=60_000)
    page.wait_text(f"{data.marker}-root", exact=True)
    page.wait_text(f"{data.marker}-child", exact=True)
    waterfall_text = page.main_text()
    assert "spans 2" in " ".join(waterfall_text.split()).lower(), waterfall_text[-2000:]
    page.screenshot("otlp-trace-waterfall.png")

    # Unknown trace ids are an honest empty state, not a fabricated waterfall.
    page.goto("/trace/00000000000000000000000000000000")
    page.wait_text("No spans found for this trace.", exact=True, timeout_ms=60_000)
    page.screenshot("otlp-trace-empty.png")

    page.goto("/observability/metrics")
    page.wait_text("Metrics explorer", exact=True, timeout_ms=120_000)
    # The catalog can contain data from the API scenario too. Select this
    # scenario's gauge explicitly, then require a populated chart state.
    page.click({"role": "button", "name": rx(r"^nano\.e2e\.")})
    picker = {"role": "textbox", "name": "Metric name"}
    page.fill(field(picker, data.metric_names[0]))
    page.click({"text": data.metric_names[0], "exact": True})
    page.wait_text(data.metric_names[0], exact=True, timeout_ms=60_000)
    page.wait_text(
        "No samples for this metric in the selected range and filters. A catalog entry can outlive its latest samples.",
        exact=True,
        timeout_ms=120_000,
        gone=True,
    )
    metrics_text = page.main_text()
    assert data.metric_names[0] in metrics_text and "Add to dashboard" in metrics_text
    page.screenshot("otlp-metrics-chart.png")

    uilib.run_search(page, f'"{data.marker}"')
    page.wait_text(data.marker, exact=False, timeout_ms=120_000)
    search_text = page.main_text()
    assert data.marker in search_text and source.route_key in search_text
    page.screenshot("otlp-log-search.png")
    timeline.step("browser screenshots captured", count=6)

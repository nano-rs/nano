"""OTLP protobuf/gRPC, auth, storage, rollups, search, and API e2e."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from nano_e2e.client import Nano, expect, row_text, time_range
from nano_e2e.otlp import CollectorSender, dataset, post_json, post_protobuf_probe
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, VECTOR_RELOAD, eventually


def _ch(stack: Stack, query: str) -> list[dict[str, Any]]:
    response = httpx.post(
        stack.ch_url,
        content=f"{query.rstrip(';')} FORMAT JSONEachRow".encode(),
        auth=(stack.ch_admin_user, stack.ch_admin_password),
        timeout=60,
    )
    assert response.status_code == 200, response.text[:2000]
    return [json.loads(line) for line in response.text.splitlines() if line]


def _quoted(values: list[str] | tuple[str, ...]) -> str:
    return ",".join("'" + value.replace("'", "''") + "'" for value in values)


def test_otlp_end_to_end(
    stack: Stack,
    nano: Nano,
    token_source,
    mark: str,
    artifact_dir,
    timeline,
) -> None:
    source = token_source("signals")
    service = f"nano-e2e-otlp-{mark[-8:]}"
    json_data = dataset(f"{mark}-json", service=service)
    proto_data = dataset(f"{mark}-protobuf", service=service)
    grpc_data = dataset(f"{mark}-grpc", service=service)
    base = stack.ingest_url

    # Every public OTLP signal is denied before a body reaches the receiver.
    for signal in json_data.payloads:
        missing = post_protobuf_probe(base, None, signal)
        wrong = post_protobuf_probe(base, "nit_" + "0" * 40, signal)
        assert missing.status_code == 401, (signal, missing.status_code, missing.text[:300])
        assert wrong.status_code == 401, (signal, wrong.status_code, wrong.text[:300])
    timeline.step("OTLP missing/wrong tokens rejected", signals=3)

    # JSON is a different OTLP/HTTP encoding, not a compatibility requirement:
    # the Vector fork accepts protobuf only. Require an explicit content-type
    # failure (Vector 0.61 currently reports InvalidHeader with HTTP 500).
    for signal, payload in json_data.payloads.items():
        response = post_json(base, source.token, signal, payload)
        assert response.status_code in {415, 500}, (
            signal,
            response.status_code,
            response.text[:500],
        )
        assert "content-type" in response.text.lower() or "unsupported" in response.text.lower(), (
            signal,
            response.text[:500],
        )
    timeline.step("OTLP/HTTP JSON rejected as unsupported", signals=3)

    # A real pinned OpenTelemetry Collector exports the second dataset as
    # application/x-protobuf through the same authenticated public edge.
    with CollectorSender(stack, source.token, artifact_dir / "protobuf-sender", mark) as sender:
        sender.send(proto_data)
    timeline.step("OTLP/HTTP protobuf accepted from real Collector", trace_id=proto_data.trace_id)

    # The trusted internal raw listener also supports OTLP/gRPC. It is
    # intentionally unauthenticated and loopback/internal-only in deployments;
    # send real Collector traces and metrics through it as an explicit
    # capability proof. Logs use the authenticated HTTP lane so they retain a
    # source route.
    with CollectorSender(
        stack,
        None,
        artifact_dir / "grpc-sender",
        f"{mark}-grpc",
        protocol="grpc",
    ) as sender:
        sender.send(grpc_data, signals=("traces", "metrics"))
    timeline.step("raw OTLP/gRPC accepted from real Collector", trace_id=grpc_data.trace_id)

    trace_ids = [proto_data.trace_id, grpc_data.trace_id]
    spans = eventually(
        lambda: _ch(
            stack,
            "SELECT trace_id, span_id, parent_span_id, service_name, span_name, span_kind, "
            "status_code, duration_ns, attributes, resource_attributes, events, src_ip, "
            f"dest_ip, user, host, start_time, end_time FROM nanosiem.otel_spans "
            f"WHERE trace_id IN ({_quoted(trace_ids)}) ORDER BY trace_id, start_time",
        ),
        timeout=INGEST_VISIBLE,
        interval=2,
        desc="four freshly marked OTLP spans stored",
        ok=lambda rows: len(rows) >= 4,
    )
    assert len(spans) == 4, f"OTLP retries/duplicates detected: {spans}"
    for data in (proto_data, grpc_data):
        mine = [row for row in spans if row["trace_id"] == data.trace_id]
        assert len(mine) == 2, mine
        root = next(row for row in mine if row["span_id"] == data.root_span_id)
        child = next(row for row in mine if row["span_id"] == data.child_span_id)
        assert root["parent_span_id"] == "" and child["parent_span_id"] == data.root_span_id
        assert root["service_name"] == child["service_name"] == service
        assert root["span_kind"] == "SERVER" and child["span_kind"] == "CLIENT"
        assert root["status_code"] == "OK" and child["status_code"] == "ERROR"
        assert root["duration_ns"] == 3_000_000_000 and child["duration_ns"] == 1_500_000_000
        assert root["attributes"]["nano.e2e.marker"] == data.marker
        assert root["resource_attributes"]["service.version"] == "1.2.3-e2e"
        assert "e2e.root.event" in root["events"]
        assert (root["src_ip"], root["dest_ip"], root["user"], root["host"]) == (
            "192.0.2.10",
            "198.51.100.20",
            "otlp-e2e-user",
            "otlp-e2e-host",
        )
        assert root["start_time"] < root["end_time"]

    metric_names = [name for data in (proto_data, grpc_data) for name in data.metric_names]
    metrics = eventually(
        lambda: _ch(
            stack,
            "SELECT metric_name, metric_type, unit, value, count, sum, bucket_counts, "
            "explicit_bounds, attributes, resource_attributes, service_name, timestamp "
            f"FROM nanosiem.otel_metrics WHERE metric_name IN ({_quoted(metric_names)}) "
            "ORDER BY metric_name",
        ),
        timeout=INGEST_VISIBLE,
        interval=2,
        desc="six freshly marked OTLP metric points stored",
        ok=lambda rows: len(rows) >= 6,
    )
    assert len(metrics) == 6, f"OTLP retries/duplicates detected: {metrics}"
    by_name = {row["metric_name"]: row for row in metrics}
    for data in (proto_data, grpc_data):
        gauge, total, histogram = (by_name[name] for name in data.metric_names)
        assert (gauge["metric_type"], gauge["value"]) == ("gauge", 12.5)
        assert (total["metric_type"], total["value"]) == ("sum", 42)
        assert histogram["metric_type"] == "histogram"
        # The fork's opentelemetry source drops Metric.unit before VRL. Keep the
        # input descriptors non-empty and pin the gap visibly until the fork
        # exposes the field (NAN-4994 report has the raw-event repro).
        assert (gauge["unit"], total["unit"], histogram["unit"]) == ("", "", "")
        assert (histogram["count"], histogram["sum"]) == (6, 21)
        assert histogram["bucket_counts"] == [1, 2, 3]
        assert histogram["explicit_bounds"] == [2, 5]
        for row in (gauge, total, histogram):
            assert row["service_name"] == service
            assert row["attributes"]["nano.e2e.marker"] == data.marker
            assert row["resource_attributes"]["service.version"] == "1.2.3-e2e"

    red = eventually(
        lambda: _ch(
            stack,
            "SELECT service_name, sum(request_count) AS requests, sum(error_count) AS errors "
            f"FROM nanosiem.otel_service_red_1m WHERE service_name = '{service}' GROUP BY service_name",
        ),
        timeout=INGEST_VISIBLE,
        interval=2,
        desc="service RED rollup",
    )
    assert red == [{"service_name": service, "requests": 4, "errors": 2}], red
    for table, bucket in (("otel_metrics_1m", "minute"), ("otel_metrics_1h", "hour")):
        rolled = eventually(
            lambda table=table, bucket=bucket: _ch(
                stack,
                f"SELECT metric_name, sum(value_count) AS points FROM nanosiem.{table} "
                f"WHERE metric_name IN ({_quoted(metric_names)}) GROUP BY metric_name, {bucket} "
                "ORDER BY metric_name",
            ),
            timeout=INGEST_VISIBLE,
            interval=2,
            desc=f"{table} rollup",
            ok=lambda rows: len(rows) >= 6,
        )
        assert len(rolled) == 6 and all(row["points"] == 1 for row in rolled), rolled
    timeline.step("storage and rollups verified", spans=4, metrics=6)

    # The log lane retains the authenticated source identity and is queryable
    # through nPL; status-only OTLP responses are never treated as proof.
    for data in (proto_data,):
        rows = eventually(
            lambda data=data: nano.rows(f'source_type="{source.route_key}" "{data.marker}"', limit=10),
            timeout=INGEST_VISIBLE,
            interval=3,
            desc=f"OTLP log {data.marker} searchable",
        )
        assert len(rows) == 1 and data.marker in row_text(rows[0]), rows

    trace = expect(nano.search_http.get(f"/api/search/trace/{proto_data.trace_id}"), 200)
    assert trace["span_count"] == 2 and [row["span_id"] for row in trace["spans"]] == [
        proto_data.root_span_id,
        proto_data.child_span_id,
    ]
    api_range = time_range(minutes_back=15)
    traces = expect(
        nano.search_http.get(
            "/api/search/traces",
            params={"service": service, "start": api_range["start"], "end": api_range["end"]},
            headers={"x-nano-cache-bypass": "1"},
        ),
        200,
    )
    assert set(trace_ids) <= {row["trace_id"] for row in traces["traces"]}
    services = expect(
        nano.search_http.get(
            "/api/search/services",
            params={"q": service, "start": api_range["start"], "end": api_range["end"]},
            headers={"x-nano-cache-bypass": "1"},
        ),
        200,
    )
    assert any(row["service"] == service for row in services["services"]), services
    names = expect(
        nano.search_http.get(
            "/api/search/metrics/names",
            params={"service": service, "window_hours": 1},
            headers={"x-nano-cache-bypass": "1"},
        ),
        200,
    )
    assert set(metric_names) <= {row["metric_name"] for row in names["names"]}
    series = expect(
        nano.search_http.post(
            "/api/search/metrics/timeseries",
            headers={"x-nano-cache-bypass": "1"},
            json={
                "metric_name": proto_data.metric_names[0],
                "service_name": service,
                "time_range": api_range,
                "step_secs": 60,
                "agg": "avg",
            },
        ),
        200,
    )
    assert series["series"] and series["series"][0]["points"], series
    timeline.step("nPL and observability APIs verified")

    nano.revoke_token(source.credential_id)
    eventually(
        lambda: post_protobuf_probe(base, source.token, "logs").status_code,
        timeout=VECTOR_RELOAD,
        interval=1,
        desc="revoked OTLP token rejected",
        ok=lambda status: status == 401,
    )
    timeline.step("revoked OTLP token rejected")

    # NAN-4986's enterprise runtime exposes a distinct app host. When that
    # topology is present, prove it cannot ingest; older single-edge harnesses
    # still get the chart-level split assertion in test_ingest_split.py.
    if stack.edition == "enterprise" and stack.edge_url != stack.ingest_url:
        for signal in json_data.payloads:
            response = post_protobuf_probe(stack.edge_url, source.token, signal)
            assert response.status_code == 404, (signal, response.status_code, response.text[:300])
        timeline.step("enterprise app hostname rejects OTLP", status=404)

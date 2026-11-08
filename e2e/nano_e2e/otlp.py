"""Real OTLP signal generation and the pinned Collector sender for e2e."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from nano_e2e import artifact_guard
from nano_e2e.stack import Stack

OTELCOL_IMAGE = (
    "otel/opentelemetry-collector-contrib:0.111.0"
    "@sha256:a2a52e43c1a80aa94120ad78c2db68780eb90e6d11c8db5b3ce2f6a0cc6b5029"
)


def _container_ingest_endpoint(url: str) -> str:
    """Translate a host-loopback e2e URL into the sender container's view."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"invalid OTLP ingest URL: {url}")
    if parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        host = "host.docker.internal"
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        parsed = parsed._replace(netloc=host)
    parsed = parsed._replace(path=parsed.path.rstrip("/") + "/otlp", query="", fragment="")
    return urlunsplit(parsed)


def _kv(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


@dataclass(frozen=True)
class Dataset:
    marker: str
    service: str
    trace_id: str
    root_span_id: str
    child_span_id: str
    metric_names: tuple[str, str, str]
    payloads: dict[str, dict[str, Any]]


def dataset(marker: str, *, service: str) -> Dataset:
    """A correlated log, two-span trace, and gauge/sum/histogram batch."""
    digest = hashlib.sha256(marker.encode()).digest()
    trace = digest[:16]
    root = digest[16:24]
    child = digest[24:32]
    linked = hashlib.sha256((marker + "-linked").encode()).digest()
    now = time.time_ns()
    root_start, root_end = now - 4_000_000_000, now - 1_000_000_000
    child_start, child_end = now - 3_500_000_000, now - 2_000_000_000
    suffix = digest.hex()[:10]
    names = (
        f"nano.e2e.gauge.{suffix}",
        f"nano.e2e.sum.{suffix}",
        f"nano.e2e.histogram.{suffix}",
    )
    resource = {
        "attributes": [
            _kv("service.name", service),
            _kv("service.version", "1.2.3-e2e"),
            _kv("deployment.environment.name", "e2e"),
            _kv("host.name", "otlp-e2e-host"),
            _kv("nano.e2e.marker", marker),
        ]
    }
    scope = {"name": "nano-e2e", "version": "1.0.0"}
    log = {
        "resourceLogs": [
            {
                "resource": resource,
                "scopeLogs": [
                    {
                        "scope": scope,
                        "logRecords": [
                            {
                                "timeUnixNano": str(now),
                                "observedTimeUnixNano": str(now),
                                "severityNumber": 9,
                                "severityText": "INFO",
                                "body": {"stringValue": f"{marker} OTLP log searchable"},
                                "attributes": [_kv("log.attribute", "preserved"), _kv("nano.e2e.marker", marker)],
                                "traceId": trace.hex(),
                                "spanId": child.hex(),
                            }
                        ],
                    }
                ],
            }
        ]
    }
    shared_attrs = [
        _kv("http.request.method", "GET"),
        _kv("client.address", "192.0.2.10"),
        _kv("server.address", "198.51.100.20"),
        _kv("enduser.id", "otlp-e2e-user"),
        _kv("nano.e2e.marker", marker),
    ]
    traces = {
        "resourceSpans": [
            {
                "resource": resource,
                "scopeSpans": [
                    {
                        "scope": scope,
                        "spans": [
                            {
                                "traceId": trace.hex(),
                                "spanId": root.hex(),
                                "name": f"{marker}-root",
                                "kind": 2,
                                "startTimeUnixNano": str(root_start),
                                "endTimeUnixNano": str(root_end),
                                "attributes": shared_attrs,
                                "events": [
                                    {
                                        "timeUnixNano": str(root_start + 100_000_000),
                                        "name": "e2e.root.event",
                                        "attributes": [_kv("event.attribute", "preserved")],
                                    }
                                ],
                                "links": [
                                    {
                                        "traceId": linked[:16].hex(),
                                        "spanId": linked[16:24].hex(),
                                        "attributes": [_kv("link.attribute", "preserved")],
                                    }
                                ],
                                "status": {"code": 1},
                            },
                            {
                                "traceId": trace.hex(),
                                "spanId": child.hex(),
                                "parentSpanId": root.hex(),
                                "name": f"{marker}-child",
                                "kind": 3,
                                "startTimeUnixNano": str(child_start),
                                "endTimeUnixNano": str(child_end),
                                "attributes": shared_attrs + [_kv("db.system.name", "clickhouse")],
                                "status": {"code": 2, "message": "intentional e2e error"},
                            },
                        ],
                    }
                ],
            }
        ]
    }
    point_attrs = [_kv("http.route", "/e2e"), _kv("nano.e2e.marker", marker)]
    metrics = {
        "resourceMetrics": [
            {
                "resource": resource,
                "scopeMetrics": [
                    {
                        "scope": scope,
                        "metrics": [
                            {
                                "name": names[0],
                                "unit": "1",
                                "gauge": {
                                    "dataPoints": [
                                        {
                                            "timeUnixNano": str(now),
                                            "asDouble": 12.5,
                                            "attributes": point_attrs,
                                        }
                                    ]
                                },
                            },
                            {
                                "name": names[1],
                                "unit": "{request}",
                                "sum": {
                                    "aggregationTemporality": 2,
                                    "isMonotonic": True,
                                    "dataPoints": [
                                        {
                                            "startTimeUnixNano": str(now - 60_000_000_000),
                                            "timeUnixNano": str(now),
                                            "asInt": "42",
                                            "attributes": point_attrs,
                                        }
                                    ],
                                },
                            },
                            {
                                "name": names[2],
                                "unit": "ms",
                                "histogram": {
                                    "aggregationTemporality": 2,
                                    "dataPoints": [
                                        {
                                            "startTimeUnixNano": str(now - 60_000_000_000),
                                            "timeUnixNano": str(now),
                                            "count": "6",
                                            "sum": 21.0,
                                            "min": 1.0,
                                            "max": 8.0,
                                            "bucketCounts": ["1", "2", "3"],
                                            "explicitBounds": [2.0, 5.0],
                                            "attributes": point_attrs,
                                        }
                                    ],
                                },
                            },
                        ],
                    }
                ],
            }
        ]
    }
    return Dataset(
        marker=marker,
        service=service,
        trace_id=trace.hex(),
        root_span_id=root.hex(),
        child_span_id=child.hex(),
        metric_names=names,
        payloads={"logs": log, "traces": traces, "metrics": metrics},
    )


def post_json(base_url: str, token: str, signal: str, payload: dict[str, Any]) -> httpx.Response:
    return httpx.post(
        f"{base_url.rstrip('/')}/otlp/v1/{signal}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=json.dumps(payload).encode(),
        timeout=30,
    )


def post_protobuf_probe(
    base_url: str, token: str | None, signal: str, body: bytes = b"\x00"
) -> httpx.Response:
    """Send a tiny protobuf-shaped request for edge auth/exposure assertions."""
    headers = {"Content-Type": "application/x-protobuf"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.post(
        f"{base_url.rstrip('/')}/otlp/v1/{signal}",
        headers=headers,
        content=body,
        timeout=30,
    )


class CollectorSender:
    """Pinned Collector: receives local JSON and exports real OTLP to nano."""

    def __init__(
        self,
        stack: Stack,
        token: str | None,
        out: Path,
        label: str,
        *,
        protocol: str = "http",
    ):
        if protocol not in {"http", "grpc"}:
            raise ValueError(f"unsupported OTLP protocol: {protocol}")
        self.stack = stack
        self.token = token or ""
        self.protocol = protocol
        self.ingest_endpoint = _container_ingest_endpoint(stack.ingest_url)
        self.out = out
        safe = "".join(c for c in label.lower() if c.isalnum())[-10:] or "sender"
        self.name = f"{stack.project}-otelcol-{safe}"
        self.config = out / "collector-sender.yaml"
        self.http_url = ""

    def __enter__(self) -> CollectorSender:
        if self.token:
            artifact_guard.remember(self.token)
        self.out.mkdir(parents=True, exist_ok=True)
        old_umask = os.umask(0o077)
        try:
            exporter = (
                "  otlphttp/nano:\n"
                f"    endpoint: {self.ingest_endpoint}\n"
                "    compression: none\n"
                "    headers:\n"
                f"      Authorization: Bearer {self.token}\n"
                if self.protocol == "http"
                else "  otlp/nano:\n    endpoint: vector:4317\n    tls:\n      insecure: true\n"
            )
            exporter_name = "otlphttp/nano" if self.protocol == "http" else "otlp/nano"
            self.config.write_text(
                "receivers:\n"
                "  otlp:\n"
                "    protocols:\n"
                "      http:\n"
                "        endpoint: 0.0.0.0:4318\n"
                "exporters:\n"
                f"{exporter}"
                "service:\n"
                "  pipelines:\n"
                f"    logs: {{receivers: [otlp], exporters: [{exporter_name}]}}\n"
                f"    metrics: {{receivers: [otlp], exporters: [{exporter_name}]}}\n"
                f"    traces: {{receivers: [otlp], exporters: [{exporter_name}]}}\n"
            )
        finally:
            os.umask(old_umask)
        proc = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                self.name,
                "--user",
                "0:0",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--add-host",
                "host.docker.internal:host-gateway",
                "--network",
                f"{self.stack.project}_default",
                "--label",
                f"nano.e2e.project={self.stack.project}",
                "--label",
                f"nano.e2e.owner={os.environ.get('E2E_OWNER', Path.cwd())}",
                "--label",
                f"nano.e2e.started={int(time.time())}",
                "-p",
                "127.0.0.1::4318",
                "-v",
                f"{self.config}:/etc/otelcol-contrib/config.yaml:ro",
                OTELCOL_IMAGE,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0:
            self.close()
            raise RuntimeError(f"E2E-INFRA: Collector did not start: {proc.stderr[-500:]}")
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                state = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Running}}", self.name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                logs = self._logs()
                if state.stdout.strip() == "true" and "Everything is ready" in logs:
                    break
                if state.stdout.strip() != "true":
                    raise RuntimeError(f"E2E-INFRA: Collector exited: {self._safe(logs)[-1000:]}")
                time.sleep(1)
            else:
                raise RuntimeError("E2E-INFRA: Collector was not ready within 60s")
            port = subprocess.run(
                ["docker", "port", self.name, "4318/tcp"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            ).stdout.strip()
            self.http_url = f"http://127.0.0.1:{port.rsplit(':', 1)[-1]}"
            return self
        except Exception:
            self.close()
            raise

    def _logs(self) -> str:
        return subprocess.run(
            ["docker", "logs", self.name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        ).stderr

    def _safe(self, text: str) -> str:
        return text.replace(self.token, "<redacted>") if self.token else text

    def send(self, data: Dataset, *, signals: tuple[str, ...] | None = None) -> None:
        selected = signals or tuple(data.payloads)
        for signal in selected:
            payload = data.payloads[signal]
            response = httpx.post(f"{self.http_url}/v1/{signal}", json=payload, timeout=30)
            if response.status_code != 200:
                raise AssertionError(f"Collector rejected {signal}: {response.status_code} {response.text[:500]}")

    def close(self) -> None:
        subprocess.run(
            ["docker", "stop", "--time", "15", self.name],
            capture_output=True,
            timeout=30,
            check=False,
        )
        if self.out.exists():
            try:
                (self.out / "collector.log").write_text(self._safe(self._logs())[-20_000:])
            except Exception:  # noqa: BLE001 - best-effort diagnostics
                pass
        subprocess.run(["docker", "rm", "-fv", self.name], capture_output=True, timeout=60, check=False)
        self.config.unlink(missing_ok=True)

    def __exit__(self, *_exc: object) -> None:
        self.close()

"""Event injection into Vector's ingest edges with a per-source ingest token.

- HEC:  POST {hec}/services/collector/event, `Authorization: Splunk <token>`
- HTTP: POST {vector_http}/, `Authorization: Bearer <token>`, NDJSON body
- OTLP: POST {otlp}/v1/logs, `Authorization: Bearer <token>`, OTLP/JSON

The token decides the source: a sender-declared sourcetype / X-Source-Type
survives only as `claimed_source_type`.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

_TIMEOUT = httpx.Timeout(30.0)


def hec(
    hec_url: str, token: str, event: Any, *, sourcetype: str | None = None, time: float | None = None
) -> httpx.Response:
    body: dict[str, Any] = {"event": event}
    if sourcetype:
        body["sourcetype"] = sourcetype
    if time is not None:
        body["time"] = round(time, 3)  # HEC epoch seconds (ms precision)
    return httpx.post(
        f"{hec_url}/services/collector/event",
        json=body,
        headers={"Authorization": f"Splunk {token}", "X-Splunk-Request-Channel": str(uuid.uuid4())},
        timeout=_TIMEOUT,
    )


def hec_health(hec_url: str) -> int:
    """Vector HEC's health endpoint status (200 = accepting)."""
    return httpx.get(f"{hec_url}/services/collector/health", timeout=_TIMEOUT).status_code


def http(
    vector_http_url: str, token: str, docs: list[dict[str, Any]], *, source_type: str | None = None
) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if source_type:
        headers["X-Source-Type"] = source_type
    return httpx.post(
        f"{vector_http_url}/",
        content="\n".join(json.dumps(d) for d in docs).encode(),
        headers=headers,
        timeout=_TIMEOUT,
    )


def otlp_logs(otlp_url: str, token: str, messages: list[str], *, service: str = "nano-e2e") -> httpx.Response:
    now_ns = str(time.time_ns())
    payload = {
        "resourceLogs": [
            {
                "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": service}}]},
                "scopeLogs": [
                    {
                        "logRecords": [
                            {"timeUnixNano": now_ns, "severityText": "INFO", "body": {"stringValue": m}}
                            for m in messages
                        ]
                    }
                ],
            }
        ]
    }
    return httpx.post(
        f"{otlp_url}/v1/logs",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=_TIMEOUT,
    )


def run_secret_script(run_dir: Path, script: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    """Run a shell snippet that embeds a secret (a copied sender snippet with
    its token) without putting it in any argv: it goes to a 0600 file inside
    the 0700 run dir, `bash <file>` runs it, and the file is removed at once.
    (Commands the snippet itself starts, e.g. curl, still see their own
    arguments: that is what executing the snippet as copied means.)"""
    fd, path = tempfile.mkstemp(prefix=".snippet-", suffix=".sh", dir=run_dir)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(script)
        return subprocess.run(  # noqa: S603 - fixed argv, script content in a 0600 file
            ["bash", path], capture_output=True, text=True, timeout=timeout, check=False
        )
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)

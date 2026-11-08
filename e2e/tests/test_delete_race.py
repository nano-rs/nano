"""Deleting a pull parser, then immediately its source config (NAN-4956).

The browser suite (NAN-4937, runs dan-ce83a096 / dan-b0f6bae4) deleted a pull
parser and then its source config; the config's undeploy rewrote only
`source_router`'s inputs, so `enrichment_router` (and a parser still claiming
the route) kept naming the removed `<config>_route`, and Vector refused every
reload for ~5 minutes. Here: both deletes back to back, then every reload
Vector attempted since is accepted and a later publish goes live.

Uses a Kafka source config pointing at a closed local port: Vector builds the
source without reaching a broker, so no cloud credentials are needed.
"""

from __future__ import annotations

import subprocess
import time
from datetime import UTC, datetime

import pytest

from nano_e2e import ingest
from nano_e2e.client import Nano, expect, row_text
from nano_e2e.runid import route_key as make_route_key
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually, vector_reloads_quiet

PARSER = '. = { "message": .message, "ext": { "e2e_parsed": "yes" } }'
REFUSAL_MARKERS = ("reload aborted", "Configuration error", "doesn't match any components")


def _vector_refusals(project: str, since: str) -> list[str]:
    out = subprocess.run(  # noqa: S603 - fixed argv, our own container
        ["docker", "logs", "--since", since, f"{project}-vector"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return [
        line
        for line in (out.stdout + out.stderr).splitlines()
        if any(m in line for m in REFUSAL_MARKERS) and '"source_type":"internal_logs"' not in line
    ]


def test_parser_then_source_config_delete_keeps_every_reload_accepted(
    stack: Stack, nano: Nano, token_source, mark: str, request, timeline
) -> None:
    if "kafka" not in nano.source_config_types():
        pytest.skip("kafka source type not in this build")
    rk = make_route_key(request.node.nodeid, "kafka")
    cfg = expect(
        nano.api.post(
            "/api/source-configurations",
            json={
                "name": f"{rk}_src",
                "config_type": "kafka",
                "connection_config": {
                    "bootstrap_servers": "127.0.0.1:9",
                    "topics": ["nano-e2e-none"],
                    "group_id": "nano-e2e",
                },
                "default_source_type": rk,
            },
        ),
        200,
        201,
    )
    parser_id: str | None = None
    cfg_deleted = False
    try:
        deployed = expect(nano.api.post(f"/api/source-configurations/{cfg['id']}/deploy"), 200)
        assert deployed.get("success") is True, f"kafka source config deploy failed: {deployed}"
        timeline.step("source config deployed")

        src = expect(
            nano.api.post(
                "/api/log-sources",
                json={
                    "name": rk,
                    "description": "nano-e2e delete race (NAN-4956)",
                    "source_type": "kafka",
                    "dispatch_source_config_id": cfg["id"],
                    "parser_vrl": PARSER,
                    "match_values": [rk],
                },
            ),
            200,
            201,
        )
        parser_id = src["id"]
        published = expect(nano.api.post(f"/api/log-sources/{parser_id}/publish"), 200)
        assert published.get("success") is True, f"bound pull parser publish failed: {published}"
        timeline.step("bound pull parser published")
        vector_reloads_quiet(stack.project, quiet=5, timeout=90)

        # Trailing Z: docker reads a zone-less --since as LOCAL time.
        since = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        time.sleep(1)
        expect(nano.api.delete(f"/api/log-sources/{parser_id}"), 200, 204)
        parser_id = None
        expect(nano.api.delete(f"/api/source-configurations/{cfg['id']}"), 200, 204)
        cfg_deleted = True
        timeline.step("parser and source config deleted back to back")

        vector_reloads_quiet(stack.project, quiet=10, timeout=150)
        refusals = _vector_refusals(stack.project, since)
        assert not refusals, "Vector refused a reload after the deletes:\n" + "\n".join(refusals[:10])
        timeline.step("no reload refused")

        # A later publish goes live.
        later = token_source("later")
        expect(nano.api.put(f"/api/log-sources/{later.source_id}", json={"parser_vrl": PARSER}), 200)
        res = expect(nano.api.post(f"/api/log-sources/{later.source_id}/publish"), 200)
        assert res.get("success") is True, f"publish after the deletes failed: {res}"
        n = {"i": 0}

        def send_and_read() -> list:
            n["i"] += 1
            m = f"{mark}-later-{n['i']}"
            assert ingest.http(stack.vector_http_url, later.token, [{"message": m}]).status_code == 200
            return eventually(lambda: nano.rows(f'"{m}"', limit=5), timeout=INGEST_VISIBLE, desc=m)

        eventually(
            send_and_read,
            timeout=150,
            interval=3,
            desc="a publish after the deletes goes live",
            ok=lambda rs: any("e2e_parsed" in row_text(r) for r in rs),
        )
        refusals = _vector_refusals(stack.project, since)
        assert not refusals, "Vector refused a reload:\n" + "\n".join(refusals[:10])
        timeline.step("later publish live, still no refusal")
    finally:
        if parser_id:
            nano.delete_source(parser_id)
        if not cfg_deleted:
            nano.api.delete(f"/api/source-configurations/{cfg['id']}")

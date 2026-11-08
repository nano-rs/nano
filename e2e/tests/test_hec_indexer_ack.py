"""HEC indexer acknowledgements end to end (NAN-4976).

Vector's `splunk_hec` source runs with `acknowledgements.enabled = true`
(config/vector/02-hec-source.toml): an event POST with an
`X-Splunk-Request-Channel` answers an `ackId`, and `/services/collector/ack`
reports it true only once every sink the event reached has finalized it.

The bug: a sender that compresses (Vector's own `splunk_hec_logs` sink with
`compression = "gzip"`, as nano-connect generates) sends the ack poll gzip-
encoded; the fork's source parsed the compressed bytes as JSON and answered
400, so the sender fell back to treating the plain 200 as delivery. Fixed in
the Vector fork (nano-rs/vector#23, `ack_gzip_tests.rs`), shipped in 0.61.0-nano.5.

What an ack means here: nano's ClickHouse event sinks sit behind a DISK buffer
(NAN-2253; `block` is forbidden on shared-ingest sinks, NAN-1114), and Vector
finalizes an event when it is durably written to that buffer. So an ackId
resolves once the event is committed to Vector's on-disk buffer in front of
ClickHouse (survives a Vector restart, delivered at-least-once), not at the
ClickHouse INSERT itself. `test_ack_is_durable_buffer_commit_not_clickhouse_insert`
pins that contract so a change to it is deliberate.

Scenarios:
- the protocol directly: N events on one channel, every ackId resolves over
  a gzip AND a plain ack poll, all N rows searchable as the token's source;
  the ack path refuses a missing/unknown/other-revoked token (401).
- the acceptance case: an upstream Vector `splunk_hec_logs` sink with gzip +
  indexer acks sends N events; its ack loop finalizes every ackId and never
  logs the "Acknowledging based on initial 200 OK" fallback; rows land.
- ClickHouse stopped: acks still resolve (buffer commit), the rows are absent
  while ClickHouse is down and land after it recovers, with no loss.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest

from nano_e2e import feeds
from nano_e2e.client import Nano, expect
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

N = 20
# The sender: upstream Vector (the nano fork image does not build the
# splunk_hec sink). Same release nano-connect validates its configs against.
SENDER_IMAGE = os.environ.get(
    "NANO_E2E_HEC_SENDER_IMAGE",
    "timberio/vector:0.59.0-alpine@sha256:0e36bc2a290039e9b6a5e92f04bd2f133223506f72d09682c1df16c015172b7a",
)
# The sink's own fallback message when the ack endpoint refuses it.
FALLBACK = "Acknowledging based on initial 200 OK"


def _post_event(stack: Stack, token: str, channel: str, message: str) -> httpx.Response:
    return httpx.post(
        f"{stack.hec_url}/services/collector/event",
        json={"event": {"message": message}},
        headers={"Authorization": f"Splunk {token}", "X-Splunk-Request-Channel": channel},
        timeout=30,
    )


def _ack_poll(
    stack: Stack, token: str | None, channel: str, ack_ids: list[int], *, gzip_body: bool
) -> httpx.Response:
    body = json.dumps({"acks": ack_ids}).encode()
    headers = {"X-Splunk-Request-Channel": channel, "Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Splunk {token}"
    if gzip_body:
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
    return httpx.post(f"{stack.hec_url}/services/collector/ack", content=body, headers=headers, timeout=30)


def _send_acked(stack: Stack, token: str, mark: str, n: int) -> tuple[str, list[int]]:
    channel = str(uuid.uuid4())
    ack_ids: list[int] = []
    for i in range(n):
        r = _post_event(stack, token, channel, f"{mark} hec-ack seq={i}")
        assert r.status_code == 200, r.text
        body = r.json()
        assert "ackId" in body, f"acks enabled: every event POST must answer an ackId, got {body}"
        ack_ids.append(int(body["ackId"]))
    assert len(set(ack_ids)) == n, f"ackIds must be distinct per channel: {ack_ids}"
    return channel, ack_ids


def _all_acked(stack: Stack, token: str, channel: str, ack_ids: list[int], *, gzip_body: bool) -> dict:
    r = _ack_poll(stack, token, channel, ack_ids, gzip_body=gzip_body)
    assert r.status_code == 200, f"ack poll (gzip={gzip_body}) refused: {r.status_code} {r.text!r}"
    return r.json()["acks"]


def _wait_for_acks(
    stack: Stack,
    token: str,
    channel: str,
    ack_ids: list[int],
    *,
    gzip_body: bool,
    desc: str,
) -> set[int]:
    """Observe every one-shot ack status, even when they resolve across polls.

    The fork removes an ackId as soon as a query reports it true, so querying
    the full original set repeatedly can never recover from a partial response:
    IDs seen true in an earlier poll read false in every later poll. Keep the
    assertion strict by polling only the IDs that have not yet been observed
    true and return only after every original ID has been observed.
    """
    pending = set(ack_ids)

    def poll() -> set[int]:
        statuses = _all_acked(
            stack, token, channel, sorted(pending), gzip_body=gzip_body
        )
        resolved = {
            ack_id for ack_id in pending if statuses.get(str(ack_id)) is True
        }
        pending.difference_update(resolved)
        return set(pending)

    eventually(
        poll,
        timeout=INGEST_VISIBLE,
        interval=1,
        desc=desc,
        ok=lambda remaining: not remaining,
    )
    return set(ack_ids)


def test_ack_poll_accumulates_one_shot_partial_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        {"0": True, "1": False, "2": False},
        {"1": True, "2": False},
        {"2": True},
    ]
    queries: list[list[int]] = []

    def fake_poll(
        _stack: Stack,
        _token: str,
        _channel: str,
        ack_ids: list[int],
        *,
        gzip_body: bool,
    ) -> dict:
        assert gzip_body is True
        queries.append(ack_ids)
        return responses.pop(0)

    monkeypatch.setattr(sys.modules[__name__], "_all_acked", fake_poll)
    observed = _wait_for_acks(
        None,  # type: ignore[arg-type] - the patched poll does not inspect it
        "token",
        "channel",
        [0, 1, 2],
        gzip_body=True,
        desc="all one-shot statuses observed",
    )

    assert observed == {0, 1, 2}
    assert queries == [[0, 1, 2], [1, 2], [2]]


def _rows_for(nano: Nano, mark: str, route_key: str) -> list[dict]:
    return nano.rows(f'source_type="{route_key}" "{mark}"', limit=N * 3, minutes_back=30)


def test_hec_ack_protocol_resolves_and_rows_land(stack: Stack, nano: Nano, token_source, mark: str, timeline) -> None:
    src = token_source(settle=True)
    channel, ack_ids = _send_acked(stack, src.token, mark, N)
    timeline.step("sent", n=N, first_ack=ack_ids[0], last_ack=ack_ids[-1])

    acks = _wait_for_acks(
        stack,
        src.token,
        channel,
        ack_ids,
        gzip_body=True,
        desc="every ackId true over a gzip ack poll",
    )
    timeline.step("gzip ack poll: all resolved", acks=len(acks))
    # Splunk semantics: an ackId reported true is released from its channel,
    # so a re-poll reads false. The plain (uncompressed) poll gets its own batch.
    assert not any(_all_acked(stack, src.token, channel, ack_ids, gzip_body=True).values())
    channel2, ack_ids2 = _send_acked(stack, src.token, f"{mark}-plain", N)
    _wait_for_acks(
        stack,
        src.token,
        channel2,
        ack_ids2,
        gzip_body=False,
        desc="every ackId true over a plain ack poll",
    )
    timeline.step("plain ack poll: all resolved")

    # The ack path is gated by the same per-source token store as the event path.
    assert _ack_poll(stack, None, channel, ack_ids, gzip_body=False).status_code == 401
    assert _ack_poll(stack, "nit_" + "0" * 40, channel, ack_ids, gzip_body=False).status_code == 401
    timeline.step("ack path: missing and unknown token refused")

    rows = eventually(
        lambda: _rows_for(nano, mark, src.route_key),
        timeout=INGEST_VISIBLE,
        interval=3,
        desc=f"all {2 * N} acked events searchable",
        ok=lambda r: len(r) >= 2 * N,
    )
    msgs = sorted(str(r.get("message", "")) for r in rows)
    expected = sorted([f"{mark} hec-ack seq={i}" for i in range(N)] + [f"{mark}-plain hec-ack seq={i}" for i in range(N)])
    assert msgs == expected, f"exactly the {2 * N} acked events, once each: {msgs[:5]}..."
    assert {r.get("source_type") for r in rows} == {src.route_key}, "the token decides the source"


def test_ack_path_refuses_a_revoked_token(stack: Stack, nano: Nano, token_source, mark: str) -> None:
    src = token_source()
    channel, ack_ids = _send_acked(stack, src.token, mark, 1)
    nano.revoke_token(src.credential_id)
    eventually(
        lambda: _ack_poll(stack, src.token, channel, ack_ids, gzip_body=True).status_code,
        timeout=30,
        interval=1,
        desc="revoked token refused on the ack path",
        ok=lambda s: s == 401,
    )


def _docker() -> str:
    exe = shutil.which("docker")
    if not exe:
        pytest.skip("docker is required to run the upstream Vector HEC sender")
    return exe


def _sender_config(token: str) -> str:
    # stdin: Vector exits at EOF once the sink has drained, i.e. once every
    # request's ackId resolved (or expired), so the exit is the measurement.
    return f"""
data_dir = "/tmp"

[sources.lines]
type = "stdin"

[sinks.nano]
type = "splunk_hec_logs"
inputs = ["lines"]
endpoint = "http://vector:8088"
default_token = "{token}"
encoding.codec = "text"
compression = "gzip"
batch.max_events = 5
acknowledgements.enabled = true
acknowledgements.indexer_acknowledgements_enabled = true
acknowledgements.query_interval = 1
acknowledgements.retry_limit = 60
"""


def _run_sender(stack: Stack, token: str, mark: str, n: int, workdir: Path) -> str:
    """Run an upstream Vector splunk_hec_logs sender on the stack's network,
    feeding `n` marked lines on stdin, to completion. Returns its log."""
    docker = _docker()
    cfg = workdir / "sender.toml"
    old = os.umask(0o077)
    try:
        cfg.write_text(_sender_config(token))
    finally:
        os.umask(old)
    os.chmod(workdir, 0o755)  # noqa: S103 - the container reads this test's own dir
    os.chmod(cfg, 0o644)
    name = f"{stack.project}-hecsender-{mark[-8:]}"
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            [
                docker, "run", "-i", "--name", name,
                "--network", f"{stack.project}_default",
                "--label", f"nano.e2e.project={stack.project}",
                "--label", f"nano.e2e.started={int(time.time())}",
                "-e", "VECTOR_LOG=info,vector::sinks::splunk_hec=debug",
                "-v", f"{workdir}:/etc/sender:ro",
                SENDER_IMAGE, "--config", "/etc/sender/sender.toml",
            ],
            input="".join(f"{mark} vector-sink seq={i}\n" for i in range(n)),
            capture_output=True, text=True, timeout=240, check=False,
        )
        log = proc.stdout + proc.stderr
        (workdir / "sender.log").write_text(log[-200_000:])
        assert proc.returncode == 0, f"sender exited {proc.returncode}: {log[-3000:]}"
        return log
    finally:
        subprocess.run([docker, "rm", "-fv", name], capture_output=True, timeout=60, check=False)  # noqa: S603
        cfg.unlink(missing_ok=True)


_STATUS = re.compile(r"Received ack statuses\. ack_query_response=HecAckStatusResponse \{ acks: \{([^}]*)\}")


def _acked_ids_in_sender_log(log: str) -> set[int]:
    """ackIds the sink's ack loop saw reported true (its debug log; the
    per-id lines are rate-limited, the status maps are not repeated)."""
    acked: set[int] = set()
    for m in _STATUS.finditer(log):
        for pair in filter(None, (p.strip() for p in m.group(1).split(","))):
            ack_id, _, status = pair.partition(":")
            if status.strip() == "true":
                acked.add(int(ack_id))
    return acked


def test_vector_hec_sink_with_indexer_acks(
    stack: Stack, nano: Nano, token_source, mark: str, artifact_dir: Path, timeline
) -> None:
    src = token_source(settle=True)
    log = _run_sender(stack, src.token, mark, N, artifact_dir)
    acked = _acked_ids_in_sender_log(log)
    timeline.step("sender done", acked=sorted(acked))
    assert FALLBACK not in log, "the sink fell back to the 200: the ack endpoint refused it"
    assert "Will retry" not in log, "an ack query failed"
    # batch.max_events = 5: at least N/5 requests, each with its own ackId
    # (ids are per channel, from 0), and every one reported true.
    assert len(acked) >= N // 5 and acked == set(range(len(acked))), f"every ackId resolved: {sorted(acked)}"

    rows = eventually(
        lambda: _rows_for(nano, mark, src.route_key),
        timeout=INGEST_VISIBLE,
        interval=3,
        desc=f"all {N} sink events searchable",
        ok=lambda r: len(r) >= N,
    )
    msgs = sorted(str(r.get("message", "")) for r in rows)
    assert msgs == sorted(f"{mark} vector-sink seq={i}" for i in range(N)), f"exactly the {N} lines once: {msgs[:5]}"


def _clickhouse(stack: Stack, action: str) -> None:
    name = f"{stack.project}-clickhouse"
    assert name.startswith("nanoe2e-"), name  # never another stack's container
    r = subprocess.run([_docker(), action, name], capture_output=True, text=True, timeout=180, check=False)  # noqa: S603
    assert r.returncode == 0, f"docker {action} {name}: {r.stderr}"


def _clickhouse_healthy(stack: Stack) -> bool:
    r = subprocess.run(  # noqa: S603 - fixed argv
        [_docker(), "inspect", "-f", "{{.State.Health.Status}}", f"{stack.project}-clickhouse"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    return r.stdout.strip() == "healthy"


# A published DB parser adds the parser-health branch (its own ClickHouse
# sink) to every event of the source, so the ack contract is checked on both
# shapes: raw (generic lane) and parsed. LANE_PARSER is valid under UDM and
# OCSF (it stamps the lane and a Base Event class).


def _published_source(stack: Stack, nano: Nano, token_source) -> object:
    src = token_source()
    vrl = feeds.LANE_PARSER.format(lane=src.route_key)
    expect(nano.api.put(f"/api/log-sources/{src.source_id}", json={"parser_vrl": vrl}), 200)
    res = expect(nano.api.post(f"/api/log-sources/{src.source_id}/publish"), 200)
    assert res.get("success") is True, f"publish failed: {res}"
    n = {"i": 0}

    def probe() -> list:
        n["i"] += 1
        _post_event(stack, src.token, str(uuid.uuid4()), f"parse-settle {src.route_key} {n['i']}")
        rows = nano.rows(f'source_type="{src.route_key}" "parse-settle"', limit=20, minutes_back=15)
        return [r for r in rows if _parsed(r)]

    eventually(probe, timeout=180, interval=3, desc=f"published parser for {src.route_key} live")
    return src


def _parsed(row: dict) -> bool:
    """The row went through the published parser: UDM rows carry
    metadata.parser_id (what db_parser_health keys on), OCSF rows the
    parser's own field."""
    return bool((row.get("metadata") or {}).get("parser_id")) or "e2e_connector_lane" in json.dumps(row)


@pytest.mark.parametrize("parsed", [False, True], ids=["raw", "parsed"])
def test_ack_is_durable_buffer_commit_not_clickhouse_insert(
    stack: Stack, nano: Nano, token_source, mark: str, timeline, parsed: bool
) -> None:
    src = _published_source(stack, nano, token_source) if parsed else token_source(settle=True)
    _clickhouse(stack, "stop")
    try:
        timeline.step("clickhouse stopped", parsed=parsed)
        channel, ack_ids = _send_acked(stack, src.token, mark, N)
        acks = _wait_for_acks(
            stack,
            src.token,
            channel,
            ack_ids,
            gzip_body=True,
            desc="acks resolve with ClickHouse down (committed to the disk buffer)",
        )
        timeline.step("acked while clickhouse down", acks=len(acks))
    finally:
        _clickhouse(stack, "start")
    eventually(lambda: _clickhouse_healthy(stack), timeout=180, interval=2, desc="clickhouse healthy again", ok=bool)
    timeline.step("clickhouse healthy")
    rows = eventually(
        lambda: _rows_for(nano, mark, src.route_key),
        timeout=INGEST_VISIBLE + 240,
        interval=5,
        desc=f"all {N} buffered events land after ClickHouse recovers",
        ok=lambda r: len(r) >= N,
    )
    assert len(rows) == N, f"no loss and no duplicates across the outage: {len(rows)}"
    if parsed:
        # These events took the parser (and parser-health) branch, so that
        # sink was on their ack path.
        assert all(_parsed(r) for r in rows), rows[:2]

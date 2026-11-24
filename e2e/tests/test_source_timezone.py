"""A source's timezone turns an offset-less device clock into true UTC (NAN-5839).

PAN-OS writes `receive_time` as device-local wall-clock time with no offset.
The first-party `palo_alto_ocsf` parser (imported LINKED from nano-rs/parsers
and published) reads that clock in the log source's timezone setting, which
nano injects as `.nano.source_timezone` (the nano-rs/parsers#87 contract).

Here: the source is set to America/New_York, a TRAFFIC-style line whose
`receive_time` is the CURRENT New York wall clock is sent over HEC, and the
stored event time must be the current instant in UTC (within ingest latency),
with `unmapped.nano_time_assumed_tz = America/New_York`. Without the setting
the same clock would be stored 4 or 5 hours early.

PENDING on nano-rs/parsers#87: until it merges, the synced palo_alto parser
does not read `.nano.source_timezone`, and this scenario skips with that
reason (detected from the imported parser, so it starts running by itself
once the parsers release lands).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from nano_e2e import feeds_live, ingest, schema
from nano_e2e.client import Nano, expect
from nano_e2e.feeds_live import VendorParser, row_get
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually, vector_reloads_quiet

PAN_PARSER = VendorParser("parsers-ocsf/palo_alto/parser.yaml", "palo_alto_ocsf", ("palo_alto",))
ZONE = "America/New_York"
CONTRACT_MARKER = ".nano.source_timezone"


def _platform_token(run_dir: Path) -> str:
    for line in (run_dir / "compose.env").read_text().splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "NANO_PLATFORM_INGEST_TOKEN":
            return value.strip().strip("'\"")
    pytest.fail("NANO_PLATFORM_INGEST_TOKEN missing from the run's compose.env")


def _pan_line(local_wall_clock: str, marker: str) -> str:
    # AUTHENTICATION layout from the parser's own sample; receive_time is
    # field 1, the user (field 9) carries the scenario marker.
    return (
        f"1,{local_wall_clock},013101000123,AUTHENTICATION,authentication-failed,2561,{local_wall_clock},"
        f"vsys1,203.0.113.5,corp\\{marker},{marker},mgmt,auth-policy-1,1,42,PAN-OS,LogForward,"
        "ldap-profile,Invalid credentials,Web,failure,1,987654328,0x0"
    )


def _event_ms(row: dict) -> int:
    t = row_get(row, "time")
    if isinstance(t, (int, float)) and t > 0:
        return int(t)
    ts = str(row_get(row, "timestamp")).replace("Z", "").replace(" ", "T")
    return int(datetime.fromisoformat(ts).replace(tzinfo=UTC).timestamp() * 1000)


def test_new_york_source_stores_true_utc(stack: Stack, nano: Nano, mark: str, timeline) -> None:
    if not schema.is_ocsf():
        pytest.skip("the source timezone is an OCSF parser contract: this stack is udm")
    source_id = feeds_live.ensure_vendor_parser(nano, PAN_PARSER)
    src = expect(nano.api.get(f"/api/log-sources/{source_id}"), 200)
    if CONTRACT_MARKER not in (src.get("parser_vrl") or ""):
        pytest.skip(
            "pending nano-rs/parsers#87: the synced palo_alto parser does not read .nano.source_timezone yet"
        )

    original = src.get("timezone") or "UTC"
    updated = expect(
        nano.api.put(f"/api/log-sources/{source_id}", json={"timezone": "america/new_york"}), 200
    )
    assert updated["timezone"] == ZONE, "stored canonical"
    refused = nano.api.put(f"/api/log-sources/{source_id}", json={"timezone": "Mars/Olympus_Mons"})
    assert refused.status_code == 422, refused.text
    try:
        expect(nano.api.post(f"/api/log-sources/{source_id}/deploy"), 200)
        timeline.step("timezone set and deployed", source=source_id, timezone=ZONE)
        timeline.step("vector reloads settled", waited=round(vector_reloads_quiet(stack.project)))
        token = _platform_token(stack.run_dir)
        marker = f"tz{mark[-10:]}".replace("-", "")
        sent: list[int] = []

        def probe() -> list:
            now = datetime.now(UTC)
            sent.append(int(now.timestamp() * 1000))
            local = now.astimezone(ZoneInfo(ZONE)).strftime("%Y/%m/%d %H:%M:%S")
            r = ingest.hec(stack.hec_url, token, _pan_line(local, marker), sourcetype="palo_alto")
            assert r.status_code == 200, r.text
            return nano.rows(f'source_type="palo_alto" "{marker}"', limit=20, minutes_back=60)

        rows = eventually(probe, timeout=INGEST_VISIBLE + 120, interval=5, desc="PAN-OS event searchable")
        row = rows[0]
        stored = _event_ms(row)
        assumed = row_get(row, "unmapped.nano_time_assumed_tz")
        timeline.step("landed", stored_ms=stored, assumed=assumed)
        # The stored instant is one of the send instants (seconds precision),
        # never 4-5 hours away.
        assert min(abs(stored - s) for s in sent) <= 2000, (stored, sent)
        assert assumed == ZONE, row
    finally:
        expect(nano.api.put(f"/api/log-sources/{source_id}", json={"timezone": original}), 200)
        nano.api.post(f"/api/log-sources/{source_id}/deploy")


def test_invalid_timezone_is_refused(nano: Nano) -> None:
    """The API refuses a zone the parsers cannot use, and normalizes offsets."""
    name = f"tz_{uuid.uuid4().hex[:10]}"
    base = {
        "name": name,
        "source_type": "routed",
        "parser_vrl": "",
        "match_values": [name],
        "lifecycle_status": "draft",
    }
    bad = nano.api.post("/api/log-sources", json={**base, "timezone": "+01:30"})
    assert bad.status_code == 422, bad.text
    created = expect(nano.api.post("/api/log-sources", json={**base, "timezone": "-0500"}), 200, 201)
    try:
        assert created["timezone"] == "-05:00"
        got = expect(nano.api.get(f"/api/log-sources/{created['id']}"), 200)
        assert got["timezone"] == "-05:00"
    finally:
        nano.delete_source(created["id"])

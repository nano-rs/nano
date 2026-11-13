"""An HEC object event keeps every key, whatever parser it is bound to (NAN-5340).

`{"event": {"message": "<text>", "probe_mark": ..., "seq": 7}}` reaches Vector
as `.message = "<text>"` with the other keys beside it. Before the fix the
OCSF Generic JSON parser ran `parse_json` on the text, failed, and replaced
the root, so `seq` and `probe_mark` were lost.

Now the first-party parsers from nano-rs/parsers, each bound to its own
ingest token:

* Generic JSON (a JSON-input parser) receives the whole object, as over HTTP
  `/ingest`: `message` maps to `status_detail` and every key is under
  `unmapped.*`.
* Syslog (a text parser) still reads `.message` = the log line and parses it
  exactly as before; the sibling keys land under `unmapped.*` beside what the
  parser set.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from nano_e2e import feeds_live, ingest
from nano_e2e.client import Nano
from nano_e2e.feeds_live import VendorParser, row_get
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually, vector_reloads_quiet

JSON_GENERIC = VendorParser("parsers-ocsf/json_generic/parser.yaml", "json_generic_ocsf", ("json_generic",))
SYSLOG = VendorParser("parsers-ocsf/syslog/parser.yaml", "syslog_ocsf", ("syslog",))


@pytest.fixture
def bind(stack: Stack, nano: Nano) -> Iterator:
    """Factory: import + publish a first-party parser and issue an ingest token
    bound to its source. Returns the raw token; revoked at teardown."""
    if not os.environ.get("NANO_SCHEMA_PROFILE", "udm").startswith("ocsf"):
        pytest.skip("`unmapped.*` is the OCSF lane: needs an ocsf stack (NANO_SCHEMA_PROFILE=ocsf)")
    creds: list[str] = []

    def make(parser: VendorParser) -> str:
        source_id = feeds_live.ensure_vendor_parser(nano, parser)
        cred, token = nano.issue_token(source_id, name=f"nan5340-{parser.lanes[0]}")
        creds.append(cred)
        vector_reloads_quiet(stack.project)
        eventually(
            lambda: ingest.hec(stack.hec_url, token, {"message": "nan5340 token warm-up"}).status_code,
            timeout=INGEST_VISIBLE,
            interval=1,
            desc="Vector accepts the new ingest token",
            ok=lambda code: code == 200,
        )
        return token

    yield make
    for cred in creds:
        try:
            nano.revoke_token(cred)
        except Exception:  # noqa: BLE001,S110 - best-effort teardown
            pass


def _land(stack: Stack, nano: Nano, token: str, event_for, mark: str) -> dict:
    n = {"i": 0}

    def probe() -> list:
        # A fresh event per poll: one sent during a reload may strand.
        n["i"] += 1
        r = ingest.hec(stack.hec_url, token, event_for(n["i"]))
        assert r.status_code == 200, r.text
        return nano.rows(f'unmapped.probe_mark="{mark}"', limit=5, minutes_back=30)

    rows = eventually(probe, timeout=INGEST_VISIBLE + 120, interval=5, desc=f"{mark} searchable by unmapped.probe_mark")
    return rows[0]


def test_json_generic_keeps_every_key(stack: Stack, nano: Nano, bind, mark: str, timeline) -> None:
    pm = f"{mark}-jg"
    row = _land(
        stack,
        nano,
        bind(JSON_GENERIC),
        lambda i: {"message": f"{pm} hec seq={i}", "probe_mark": pm, "seq": 7},
        pm,
    )
    sample = {k: row_get(row, k) for k in ("class_uid", "status_detail", "unmapped.seq", "unmapped.parse_error")}
    timeline.step("json_generic row", sample=sample)
    assert row_get(row, "unmapped.parse_error") in (None, ""), sample
    assert int(row_get(row, "unmapped.seq")) == 7, sample
    assert str(row_get(row, "status_detail")).startswith(f"{pm} hec seq="), sample
    assert row_get(row, "metadata.log_source") == "json_generic", sample
    # The sibling keys are searchable, not only stored.
    assert nano.rows(f'unmapped.probe_mark="{pm}" unmapped.seq=7', limit=5, minutes_back=30)


def test_syslog_line_parses_as_before_plus_sibling_keys(stack: Stack, nano: Nano, bind, mark: str, timeline) -> None:
    pm = f"{mark}-sl"
    # The line's own clock is the event time: keep it inside the search window.
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"<34>1 {now} edge-01 sshd 77 ID1 - {pm} Accepted password"
    row = _land(
        stack,
        nano,
        bind(SYSLOG),
        lambda _i: {"message": line, "probe_mark": pm, "seq": 7},
        pm,
    )
    sample = {
        k: row_get(row, k)
        for k in ("class_uid", "status_detail", "unmapped.facility", "unmapped.rfc_version", "unmapped.seq")
    }
    timeline.step("syslog row", sample=sample)
    # The parser read the log line (its own unmapped keys are there)...
    assert row_get(row, "unmapped.facility") == "auth", sample
    assert str(row_get(row, "unmapped.rfc_version")) == "5424", sample
    assert str(row_get(row, "status_detail")) == f"{pm} Accepted password", sample
    assert row_get(row, "unmapped.parse_error") in (None, ""), sample
    # ...and the sibling keys were kept beside them.
    assert int(row_get(row, "unmapped.seq")) == 7, sample
    assert row_get(row, "metadata.log_source") == "syslog", sample

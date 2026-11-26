"""A clashing field has ONE name on every ingest path (NAN-5849, NAN-5894).

One HEC event spells a path both flat and nested: `"a.b": <flat>` and
`"a": {"b": <nested>}`. ClickHouse reads both as the path `a.b`, so one copy
is renamed. Before NAN-5894 the name depended on the path: the no-parser lane
stored the flat copy as `unmapped.a~1b` (NAN-5849), while a parser's residual
spill stored it as `unmapped.a.b_2` (NAN-3604). Now both store `a~1b`:

* no parser (a draft source's token): the nested copy is `unmapped.a.b` and the
  flat copy `unmapped.a~1b`;
* the first-party Generic JSON parser (nano-rs/parsers, LINKED): the same two
  names, and nothing under the old `unmapped.a.b_2`.

Each value is found by searching its name. A search on the legacy name alone
has no reverse alias, so a hit on `unmapped.a.b_2` would mean the event was
stored with the old suffix. The Generic JSON case needs the nano-rs/parsers
side of NAN-5894 in the parsers repository the stack follows.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from nano_e2e import feeds_live, ingest, schema
from nano_e2e.client import Nano
from nano_e2e.feeds_live import VendorParser
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually, vector_reloads_quiet

JSON_GENERIC = VendorParser("parsers-ocsf/json_generic/parser.yaml", "json_generic_ocsf", ("json_generic",))


@pytest.fixture
def ocsf_only() -> None:
    if not schema.is_ocsf():
        pytest.skip("`unmapped.*` is the OCSF lane: this stack is udm, not the ocsf default")


def _clash_event(pm: str, i: int) -> dict:
    return {
        "message": f"{pm} clash seq={i}",
        "probe_mark": pm,
        "a.b": f"{pm}-flat",
        "a": {"b": f"{pm}-nested"},
    }


def _assert_one_name(stack: Stack, nano: Nano, token: str, pm: str, timeline, label: str) -> None:
    n = {"i": 0}

    def probe() -> list:
        # A fresh event per poll: one sent during a reload may strand.
        n["i"] += 1
        r = ingest.hec(stack.hec_url, token, _clash_event(pm, n["i"]))
        assert r.status_code == 200, r.text
        return nano.rows(f'unmapped.probe_mark="{pm}"', limit=5, minutes_back=30)

    eventually(probe, timeout=INGEST_VISIBLE + 120, interval=5, desc=f"{label}: {pm} searchable")

    flat = nano.rows(f'unmapped.probe_mark="{pm}" unmapped.a~1b="{pm}-flat"', limit=5, minutes_back=30)
    nested = nano.rows(f'unmapped.probe_mark="{pm}" unmapped.a.b="{pm}-nested"', limit=5, minutes_back=30)
    legacy = nano.rows(f'unmapped.probe_mark="{pm}" unmapped.a.b_2="{pm}-flat"', limit=5, minutes_back=30)
    timeline.step(f"{label} names", flat=len(flat), nested=len(nested), legacy=len(legacy))
    assert flat, f"{label}: the flat copy must be stored as unmapped.a~1b"
    assert nested, f"{label}: the nested copy must keep unmapped.a.b"
    assert not legacy, f"{label}: nothing may be stored under the old unmapped.a.b_2 name"


def test_no_parser_lane_names_the_flat_copy_a_1b(
    ocsf_only, stack: Stack, nano: Nano, token_source, mark: str, timeline
) -> None:
    src = token_source()
    _assert_one_name(stack, nano, src.token, f"{mark}-np", timeline, "no parser")


@pytest.fixture
def json_generic_token(stack: Stack, nano: Nano) -> Iterator[str]:
    source_id = feeds_live.ensure_vendor_parser(nano, JSON_GENERIC)
    cred, token = nano.issue_token(source_id, name="nan5894-json-generic")
    try:
        vector_reloads_quiet(stack.project)
        eventually(
            lambda: ingest.hec(stack.hec_url, token, {"message": "nan5894 token warm-up"}).status_code,
            timeout=INGEST_VISIBLE,
            interval=1,
            desc="Vector accepts the new ingest token",
            ok=lambda code: code == 200,
        )
        yield token
    finally:
        try:
            nano.revoke_token(cred)
        except Exception:  # noqa: BLE001,S110 - best-effort teardown
            pass


def test_json_generic_parser_names_the_flat_copy_a_1b(
    ocsf_only, stack: Stack, nano: Nano, json_generic_token: str, mark: str, timeline
) -> None:
    _assert_one_name(stack, nano, json_generic_token, f"{mark}-jg", timeline, "json_generic")

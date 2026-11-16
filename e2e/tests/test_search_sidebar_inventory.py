"""The Search sidebar never silently misses a field (NAN-5485).

Real ClickHouse, black-box over the search service, on OCSF and UDM stacks:

- field discovery (`POST /api/search/field-inventory`) reads the rows a
  search MATCHES: a spill key only the hunted host emits is listed;
- the matched-row count is reported even when those rows carry no keys, and
  a list past the matched-row bound is flagged `partial` (`row_limit`);
- a failed scan is a labelled partial list (`scan_failed`), not a 500;
- rows an `append` subsearch adds, and an unparseable query, are flagged;
- nothing is cached past new data: a key, and a column, filled only by events
  ingested after the first inventory appear on the next search;
- field stats say when they are a head sample (`sampled`): on a multi-source
  search past the row cap a whole source can be absent;
- OCSF `raw_data` is counted (not aggregated) on the plain and pipeline (CTE)
  paths and still listed, with every populated column kept.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from nano_e2e.client import Nano, expect
from nano_e2e.stack import Stack

ROW_BOUND = 100_000  # SPILL_INVENTORY_MATCHED_ROWS
STATS_CAP = 100_000  # FIELD_STATS_ROW_CAP


def _ch(stack: Stack, sql: str) -> str:
    r = httpx.post(stack.ch_url, content=sql.encode(), auth=(stack.ch_admin_user, stack.ch_admin_password), timeout=300)
    assert r.status_code == 200, f"{r.status_code}: {r.text[:800]}"
    return r.text.strip()


class Profile:
    """How to write synthetic events, and spell a host hunt, per schema."""

    def __init__(self, stack: Stack):
        self.ocsf = _ch(stack, "SELECT count() FROM system.tables WHERE database='nanosiem' AND name='ocsf_logs'") == "1"
        self.table = "nanosiem.ocsf_logs" if self.ocsf else "nanosiem.logs"
        self.host_field = "device.hostname" if self.ocsf else "src_host"

    def key(self, name: str) -> str:
        """The spill key the inventory returns for `name` (bare, top level)."""
        return f"event_data.{name}" if self.ocsf else name

    def insert(
        self, stack: Stack, lane: str, rows: int, host_expr: str, spill_expr: str, file_path: str = "", ago_ms: int = 0
    ) -> None:
        """`rows` events of source `lane`, in the 5 minutes before `ago_ms`
        ago. `spill_expr` is a ClickHouse String expression holding the spill
        JSON object."""
        if self.ocsf:
            file_part = f"'\"file\":{{\"path\":\"{file_path}\",\"name\":\"f\"}},'," if file_path else ""
            _ch(
                stack,
                f"""INSERT INTO nanosiem.ocsf_logs_raw (event, source_type)
                SELECT concat('{{',
                  '"time":', toString(toUnixTimestamp64Milli(now64(3)) - {ago_ms} - number % 300000), ',',
                  '"class_uid":1007,"category_uid":1,"activity_id":1,"severity_id":1,',
                  '"device":{{"hostname":', toJSONString({host_expr}), '}},',
                  '"metadata":{{"log_source":"{lane}","product":{{"name":"e2e"}}}},',
                  {file_part}
                  '"raw_data":', toJSONString(concat('<Event>', toString(number), '</Event>')), ',',
                  '"unmapped":', {spill_expr},
                '}}'), '{lane}'
                FROM numbers({rows})""",
            )
        else:
            _ch(
                stack,
                f"""INSERT INTO nanosiem.logs (timestamp, source_type, src_host, message, file_path, ext)
                SELECT now64(6) - toIntervalMillisecond({ago_ms} + number % 300000), '{lane}', {host_expr},
                       concat('e2e ', toString(number)), '{file_path}', {spill_expr}
                FROM numbers({rows})""",
            )

    def spill(self, name: str, value: str = "1") -> str:
        """A one-key spill object for `name` (SQL string literal)."""
        return f"'{{\"{self.key(name)}\":\"{value}\"}}'" if self.ocsf else f"'{{\"{name}\":\"{value}\"}}'"


def _window(minutes: int = 60) -> tuple[str, str]:
    now = datetime.now(UTC)
    return (now - timedelta(minutes=minutes)).isoformat(), (now + timedelta(minutes=2)).isoformat()


def _inventory(
    nano: Nano, query: str, bucket: str = "spill", request_id: str | None = None, minutes: int = 60
) -> dict:
    start, end = _window(minutes)
    body: dict = {"query": query, "start": start, "end": end}
    if bucket != "spill":
        body["bucket"] = bucket
    if request_id:
        body["request_id"] = request_id
    return expect(nano.search_http.post("/api/search/field-inventory", json=body), 200)


def _field_stats(nano: Nano, query: str, minutes: int = 60) -> dict:
    start, end = _window(minutes)
    return expect(
        nano.search_http.post(
            "/api/search/field-stats",
            json={"query": query, "start": start, "end": end},
            headers={"x-nano-cache-bypass": "1"},
        ),
        200,
    )


def _wait_rows(stack: Stack, profile: Profile, lane: str, n: int) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if int(_ch(stack, f"SELECT count() FROM {profile.table} WHERE source_type = '{lane}'")) >= n:
            return
        time.sleep(1)
    raise AssertionError(f"{lane}: fewer than {n} rows landed")


@pytest.fixture
def profile(stack: Stack) -> Profile:
    return Profile(stack)


def _lane() -> str:
    return f"e2einv{uuid.uuid4().hex[:10]}"


def test_a_key_only_the_hunted_host_emits_is_listed(stack: Stack, nano: Nano, profile: Profile) -> None:
    lane = _lane()
    # 30 hosts share a key; one host also emits its own, in 3 of 3,003 events.
    profile.insert(stack, lane, 3000, "concat('h', toString(number % 30), '.corp')", profile.spill("common"))
    target = (
        f"'{{\"{profile.key('only_on_target')}\":\"1\",\"{profile.key('common')}\":\"x\"}}'"
        if profile.ocsf
        else "'{\"only_on_target\":\"1\",\"common\":\"x\"}'"
    )
    profile.insert(stack, lane, 3, "'target.corp'", target)
    _wait_rows(stack, profile, lane, 3003)

    inv = _inventory(nano, f'source_type={lane} {profile.host_field}="target.corp"')
    assert profile.key("only_on_target") in inv["names"], inv
    assert inv["partial"] is False and inv["reason"] is None, inv
    assert inv["rows_examined"] == 3, inv

    broad = _inventory(nano, f"source_type={lane}")
    assert {profile.key("common"), profile.key("only_on_target")} <= set(broad["names"]), broad
    assert broad["partial"] is False, broad


def test_matched_rows_without_keys_are_counted_and_the_bound_is_flagged(
    stack: Stack, nano: Nano, profile: Profile
) -> None:
    lane = _lane()
    # Rows that carry NO spill keys at all.
    profile.insert(stack, lane, 50, "'nokeys.corp'", "'{}'")
    _wait_rows(stack, profile, lane, 50)
    inv = _inventory(nano, f"source_type={lane}")
    assert inv["names"] == [] and inv["rows_examined"] == 50 and inv["partial"] is False, inv

    # Past the bound, still keyless: the bound is reported, not lost with the keys.
    profile.insert(stack, lane, ROW_BOUND + 5_000, "'nokeys.corp'", "'{}'")
    _wait_rows(stack, profile, lane, ROW_BOUND + 5_050)
    inv = _inventory(nano, f"source_type={lane}")
    assert inv["partial"] is True and inv["reason"] == "row_limit", inv
    assert inv["rows_examined"] == ROW_BOUND and inv["row_limit"] == ROW_BOUND, inv


def test_a_failed_scan_is_a_labelled_partial_list(stack: Stack, nano: Nano, profile: Profile) -> None:
    lane = _lane()
    profile.insert(stack, lane, 5_000, "concat('h', toString(number % 10))", profile.spill("k"))
    _wait_rows(stack, profile, lane, 5_000)
    # A read cap below the lane's size makes the scan THROW in ClickHouse.
    try:
        stack.svc("restart", "search", env={"NANO_FIELD_INVENTORY_MAX_ROWS_TO_READ": "1000"})
        inv = _inventory(nano, f"source_type={lane}")
        assert inv["partial"] is True and inv["reason"] == "scan_failed" and inv["names"] == [], inv
    finally:
        stack.svc("restart", "search")
    inv = _inventory(nano, f"source_type={lane}")
    assert inv["partial"] is False and profile.key("k") in inv["names"], inv


def test_subsearch_rows_and_unparseable_queries_are_flagged(stack: Stack, nano: Nano, profile: Profile) -> None:
    lane, other = _lane(), _lane()
    profile.insert(stack, lane, 20, "'a.corp'", profile.spill("base_key"))
    profile.insert(stack, other, 20, "'b.corp'", profile.spill("sub_key"))
    _wait_rows(stack, profile, other, 20)
    inv = _inventory(nano, f"source_type={lane} | append [search source_type={other}]")
    assert inv["partial"] is True and inv["reason"] == "subsearch_rows_not_scanned", inv
    assert profile.key("base_key") in inv["names"], inv
    bad = _inventory(nano, f"source_type={lane} | stats count by")
    assert bad["partial"] is True and bad["reason"] == "query_not_scanned", bad


def test_new_data_shows_on_the_next_search(stack: Stack, nano: Nano, profile: Profile) -> None:
    lane = _lane()
    hunt = f'source_type={lane} {profile.host_field}="late.corp"'
    profile.insert(stack, lane, 20, "'late.corp'", profile.spill("early"))
    _wait_rows(stack, profile, lane, 20)
    first = _inventory(nano, hunt)
    assert profile.key("early") in first["names"] and profile.key("late") not in first["names"], first
    path_col = "file.path" if profile.ocsf else "file_path"
    assert path_col not in {f["name"] for f in _field_stats(nano, hunt)["fields"]}

    # Ingested after the first inventory and stats: a new spill key and a
    # column no earlier event filled.
    profile.insert(stack, lane, 5, "'late.corp'", profile.spill("late"), file_path="/tmp/late.txt")
    _wait_rows(stack, profile, lane, 25)
    assert profile.key("late") in _inventory(nano, hunt)["names"]
    assert path_col in {f["name"] for f in _field_stats(nano, hunt)["fields"]}


def test_field_stats_say_when_they_are_a_head_sample(stack: Stack, nano: Nano, profile: Profile) -> None:
    # Two sources; `a…` sorts before `b…` in the sort key, so the first
    # STATS_CAP matched rows of the pair are all `a…`.
    tag = uuid.uuid4().hex[:8]
    first, second = f"e2ea{tag}", f"e2eb{tag}"
    profile.insert(stack, first, STATS_CAP + 1_000, "'s.corp'", profile.spill("k"))
    profile.insert(stack, second, 50, "'s.corp'", profile.spill("k"), file_path="/tmp/only-in-second.txt")
    _wait_rows(stack, profile, second, 50)
    _wait_rows(stack, profile, first, STATS_CAP + 1_000)

    both = _field_stats(nano, f'source_type IN ("{first}", "{second}")')
    assert both["sampled"] is True and both["rows_examined"] == STATS_CAP == both["row_cap"], {
        k: v for k, v in both.items() if k != "fields"
    }
    small = _field_stats(nano, f"source_type={second}")
    assert small["sampled"] is False and small["rows_examined"] == 50, {k: v for k, v in small.items() if k != "fields"}


def test_raw_data_is_counted_and_listed_on_plain_and_pipeline_paths(stack: Stack, nano: Nano, profile: Profile) -> None:
    if not profile.ocsf:
        pytest.skip("raw_data is an OCSF column")
    lane = _lane()
    profile.insert(stack, lane, 40, "'raw.corp'", profile.spill("a"))
    _wait_rows(stack, profile, lane, 40)

    stats = {f["name"]: f for f in _field_stats(nano, f"source_type={lane}")["fields"]}
    raw = stats["raw_data"]
    assert raw["count"] == 40 and raw["top_values"] == [] and raw.get("cardinality") is None, raw
    assert "device.hostname" in stats

    # Inline companion over a pipeline (CTE path): still counted, and every
    # populated raw column keeps its stats (nothing is pruned).
    start, end = _window()
    body = expect(
        nano.search_http.post(
            "/api/search",
            json={
                "query": f'source_type={lane} | eval tag="x" | where tag="x"',
                "time_range": {"start": start, "end": end},
                "limit": 50,
                "skip_field_stats": False,
                "use_cache": False,
            },
            headers={"x-nano-cache-bypass": "1"},
        ),
        200,
    )
    fields = {f["name"]: f for f in body.get("fields") or []}
    assert fields.get("raw_data", {}).get("count") == 40, sorted(fields)
    assert "device.hostname" in fields and "class_uid" in fields, sorted(fields)


def test_in_query_earliest_sets_the_sidebar_window_like_the_results(stack: Stack, nano: Nano, profile: Profile) -> None:
    """Picker at 15 minutes, query `earliest=-7d`: the results cover 7 days,
    and so must the inventory and the field stats (NAN-5485 review P1)."""
    lane = _lane()
    three_days_ms = 3 * 24 * 3600 * 1000
    profile.insert(stack, lane, 30, "'old.corp'", profile.spill("old_key"), ago_ms=three_days_ms)
    profile.insert(stack, lane, 20, "'new.corp'", profile.spill("new_key"))
    _wait_rows(stack, profile, lane, 50)

    # Without the token: the picker's 15 minutes.
    plain = _inventory(nano, f"source_type={lane}", minutes=15)
    assert profile.key("new_key") in plain["names"] and profile.key("old_key") not in plain["names"], plain
    assert plain["rows_examined"] == 20, plain

    # With it: 7 days, exactly like the rows search.
    wide = _inventory(nano, f"source_type={lane} earliest=-7d", minutes=15)
    assert {profile.key("new_key"), profile.key("old_key")} <= set(wide["names"]), wide
    assert wide["rows_examined"] == 50 and wide["partial"] is False, wide

    stats = _field_stats(nano, f"source_type={lane} earliest=-7d", minutes=15)
    assert stats["rows_examined"] == 50, {k: v for k, v in stats.items() if k != "fields"}
    hosts = {f["name"]: f for f in stats["fields"]}[profile.host_field]
    assert {v[0] for v in hosts["top_values"]} == {"old.corp", "new.corp"}, hosts

    # And the rows search agrees on the count.
    start, end = _window(15)
    body = expect(
        nano.search_http.post(
            "/api/search",
            json={"query": f"source_type={lane} earliest=-7d", "time_range": {"start": start, "end": end},
                  "limit": 10, "skip_field_stats": True, "use_cache": False},
            headers={"x-nano-cache-bypass": "1"},
        ),
        200,
    )
    assert body["total_count"] == 50, body.get("total_count")


def test_non_log_datasets_are_not_listed_as_log_keys(stack: Stack, nano: Nano, profile: Profile) -> None:
    start, end = _window()
    inv = expect(
        nano.search_http.post(
            "/api/search/field-inventory",
            json={"query": "service.name=x", "start": start, "end": end, "dataset": "spans"},
        ),
        200,
    )
    assert inv["partial"] is True and inv["reason"] == "dataset_not_supported" and inv["names"] == [], inv


def test_pipeline_created_fields_are_flagged_not_listed(stack: Stack, nano: Nano, profile: Profile) -> None:
    lane = _lane()
    profile.insert(stack, lane, 10, "'p.corp'", profile.spill("k"))
    _wait_rows(stack, profile, lane, 10)
    inv = _inventory(nano, f'source_type={lane} | eval tag="x"')
    assert inv["partial"] is True and inv["reason"] == "derived_fields_not_listed", inv
    assert profile.key("k") in inv["names"], inv

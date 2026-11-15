"""Disk-pressure eviction drops the OCSF stores' oldest partitions (NAN-4982).

On the OCSF profile (the v2 default) the main event store is `ocsf_logs`, and
an upgraded install also carries the 1.8 store migration 180 renamed to
`ocsf_logs_legacy_v179`. Eviction used to list only the UDM `logs` table and
the side tables, so an OCSF box running out of disk never reclaimed space from
its event store.

Forced low-disk scenario: old daily partitions plus one far-future (2099)
event are seeded in `ocsf_logs` (through the ingest view),
`ocsf_logs_legacy_v179` and `logs`, and the jobs leader is restarted with
watermarks just below the disk's real usage (critical 99.9%: Elevated, the
FIFO drop path). The scenario waits until the evictor has dropped every old
partition from every table, kept today's (the floor) and the far-future event,
and written one `partition_dropped` audit entry per date naming the tables it
dropped from.

NAN-5464: since NAN-5447 the evictor refuses to drop when the non-ClickHouse
bytes alone are at or above the low watermark (deleting history could not
relieve that disk). A fixed 0.005% low watermark is therefore always refused
on a real box. The scenario instead seeds a few GiB of ClickHouse data in a
test-owned table and derives the watermarks from the live disk so that
ClickHouse is what holds the disk above the high watermark:
`non_clickhouse < low < high < used`. The far-future event is clamped to the
insert time by the ingest view, so it is asserted by its row, not by a 2099
partition.

The legacy table is created here with the 1.8 store's partitioning when the
stack is a fresh install (only an upgraded install has it).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from nano_e2e.client import Nano, expect
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

FORCED = {
    "DISK_PRESSURE_CHECK_INTERVAL_SECS": "5",
    "DISK_PRESSURE_CRITICAL_THRESHOLD": "0.999",
    "DISK_PRESSURE_EMERGENCY_THRESHOLD": "0.9999",
}
# Test-owned ClickHouse bytes that make ClickHouse the cause of the forced
# pressure (NAN-5464). Not a table the evictor knows, so it stays put and keeps
# the disk above the high watermark until every old partition is gone; dropped
# in `finally`. No materialized view reads it.
FILLER = "nan5464_disk_filler"
FILLER_BYTES = 6 * 1024**3
FILLER_ROW = 8192
LEGACY = "ocsf_logs_legacy_v179"
# A skewed source: one event stamped far in the future. It must neither be
# evicted nor make today's partition evictable (the old floor protected only
# max(partition)).
FUTURE = datetime(2099, 12, 31, 12, 0, tzinfo=UTC)


def _ch(stack: Stack):
    def run(sql: str) -> str:
        r = httpx.post(stack.ch_url, content=sql.encode(), auth=(stack.ch_admin_user, stack.ch_admin_password), timeout=120)
        assert r.status_code == 200, f"{r.status_code}: {r.text[:800]}"
        return r.text.strip()
    return run


def _day(days_ago: int) -> datetime:
    return (datetime.now(UTC) - timedelta(days=days_ago)).replace(hour=12, minute=0, second=0, microsecond=0)


def _partition(d: datetime) -> str:
    return d.strftime("%Y%m%d")


def _watermarks_with_clickhouse_filler(ch) -> dict[str, str]:
    """Seed FILLER_BYTES of ClickHouse data, then return high/low watermarks
    between the non-ClickHouse share and the current usage of the data disk
    (NAN-5464). Figures are physical (`+ keep_free_space`), as the evictor
    compares them since NAN-5463."""
    ch(f"CREATE TABLE IF NOT EXISTS nanosiem.{FILLER} (b String CODEC(NONE)) ENGINE = MergeTree ORDER BY tuple()")
    ch(f"INSERT INTO nanosiem.{FILLER} SELECT randomString({FILLER_ROW}) FROM numbers({FILLER_BYTES // FILLER_ROW}) "
       "SETTINGS async_insert = 0, max_insert_threads = 4")
    disk = json.loads(ch(
        "SELECT toUInt64(total_space + keep_free_space) AS total, toUInt64(free_space + keep_free_space) AS free "
        "FROM system.disks WHERE name = 'default' FORMAT JSONEachRow"))
    total, free = int(disk["total"]), int(disk["free"])
    ch_bytes = int(ch("SELECT toUInt64(sum(bytes_on_disk)) FROM system.parts WHERE active "
                      "AND disk_name IN (SELECT name FROM system.disks WHERE path LIKE '/var/lib/clickhouse/%')"))
    assert ch_bytes >= FILLER_BYTES, f"filler not on disk yet: {ch_bytes}"
    usage, ch_share = (total - free) / total, ch_bytes / total
    # non-ClickHouse share = usage - ch_share < low < high < usage. Margins are
    # fractions of the ClickHouse share (GiBs), far above disk churn in 4 min.
    high, low = usage - 0.25 * ch_share, usage - 0.6 * ch_share
    assert 0 < low < high < usage, (usage, ch_share)
    return {"DISK_PRESSURE_HIGH_WATERMARK": f"{high:.8f}", "DISK_PRESSURE_LOW_WATERMARK": f"{low:.8f}"}


def test_disk_pressure_evicts_the_oldest_ocsf_partitions(stack: Stack, nano: Nano, timeline) -> None:
    if not os.environ.get("NANO_SCHEMA_PROFILE", "udm").startswith("ocsf"):
        pytest.skip("OCSF eviction: needs an ocsf stack (`NANO_SCHEMA_PROFILE=ocsf scripts/e2e.sh up`)")
    ch = _ch(stack)
    ocsf_days = [_day(40), _day(39)]
    legacy_day, udm_day = _day(42), _day(41)

    rows = "\n".join(
        json.dumps({"source_type": "nan4982_disk", "event": {
            "class_uid": 4001, "time": int(d.timestamp() * 1000),
            "metadata": {"uid": f"disk-{_partition(d)}", "version": "1.8.0"}, "src_endpoint": {"ip": "192.0.2.1"}}})
        for d in [*ocsf_days, datetime.now(UTC), FUTURE]
    )
    ch(f"INSERT INTO nanosiem.ocsf_logs_raw (source_type, event) SETTINGS async_insert = 0 FORMAT JSONEachRow\n{rows}")
    created_legacy = ch(f"EXISTS TABLE nanosiem.{LEGACY}") == "0"
    if created_legacy:
        ch(f"CREATE TABLE nanosiem.{LEGACY} (timestamp DateTime64(3, 'UTC'), source_type LowCardinality(String), id UUID) "
           "ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (source_type, timestamp)")
    ch(f"INSERT INTO nanosiem.{LEGACY} VALUES ('{legacy_day:%Y-%m-%d %H:%M:%S}', 'nan4982_disk', generateUUIDv7())")
    ch(f"INSERT INTO nanosiem.logs (timestamp, message, source_type) SETTINGS async_insert = 0 "
       f"VALUES ('{udm_day:%Y-%m-%d %H:%M:%S}', 'nan4982 disk', 'nan4982_disk')")

    def parts() -> set[tuple[str, str]]:
        out = ch("SELECT DISTINCT table, partition FROM system.parts WHERE database = 'nanosiem' AND active "
                 f"AND table IN ('ocsf_logs', '{LEGACY}', 'logs') FORMAT JSONEachRow")
        return {(r["table"], r["partition"]) for r in map(json.loads, filter(None, out.splitlines()))}

    seeded = {("ocsf_logs", _partition(d)) for d in ocsf_days} | {(LEGACY, _partition(legacy_day)), ("logs", _partition(udm_day))}
    assert seeded <= parts(), parts()
    today = _partition(datetime.now(UTC))
    assert ("ocsf_logs", today) in parts()
    timeline.step("old partitions seeded", partitions=sorted(seeded))
    since = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()

    app_env = stack.run_dir / "app.env"
    original = app_env.read_text()
    try:
        forced = {**FORCED, **_watermarks_with_clickhouse_filler(ch)}
        timeline.step("clickhouse filler seeded", filler_bytes=FILLER_BYTES)
        app_env.write_text(original.rstrip("\n") + "\n" + "".join(f"export {k}={v}\n" for k, v in forced.items()))
        stack.svc("restart", "jobs")
        timeline.step("jobs restarted with forced watermarks", **forced)
        left = eventually(parts, timeout=240, interval=5, desc="old OCSF / legacy / UDM partitions evicted",
                          ok=lambda p: not (seeded & p))
        assert ("ocsf_logs", today) in left, f"today's partition must survive beside a future one: {sorted(left)}"
        future_rows = ch("SELECT count() FROM nanosiem.ocsf_logs WHERE source_type = 'nan4982_disk' "
                         f"AND `metadata.uid` = 'disk-{_partition(FUTURE)}'")
        # >= 1: a kept stack carries the same uid from earlier runs.
        assert int(future_rows) >= 1, f"the far-future event is never evicted: {future_rows}"
        timeline.step("evicted", remaining=sorted(left))

        def drops() -> list[dict]:
            body = expect(nano.api.get("/api/audit", params={"action": "partition_dropped", "start_time": since, "limit": 200}), 200)
            return body.get("logs", [])

        audits = eventually(drops, timeout=120, interval=5, desc="partition_dropped audit entries",
                            ok=lambda xs: {_partition(d) for d in [*ocsf_days, legacy_day, udm_day]}
                            <= {(a.get("details") or {}).get("partition_date") for a in xs})
        by_date = {(a.get("details") or {}).get("partition_date"): (a.get("details") or {}).get("tables") for a in audits}
        for d in ocsf_days:
            assert "ocsf_logs" in by_date[_partition(d)], by_date
        assert LEGACY in by_date[_partition(legacy_day)], by_date
        assert "logs" in by_date[_partition(udm_day)], by_date
        assert all("ocsf_logs_distributed" not in (t or []) for t in by_date.values()), by_date
        timeline.step("audited", by_date=by_date)
    finally:
        app_env.write_text(original)
        ch(f"DROP TABLE IF EXISTS nanosiem.{FILLER} SYNC")
        stack.svc("restart", "jobs")
        if created_legacy:
            ch(f"DROP TABLE IF EXISTS nanosiem.{LEGACY}")

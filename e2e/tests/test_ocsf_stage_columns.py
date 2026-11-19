"""Later pipeline stages read earlier stages' columns on OCSF (NAN-5634).

Found by the v2.0.32 OCSF query sweep (`scripts/test-ocsf-queries.py
--execute`). Each shape used to answer 400 on a real OCSF install:

* `sort -ports | … | rename ports AS unique_ports` ordered the final statement
  by `ports` after the rename removed it ("Field 'ports' does not exist").
* `bin bytes_in span=1024` read a bare `bytes_in`; the OCSF column is
  `traffic.bytes_in` ("Field 'bytes_in' does not exist. Did you mean
  'bytes_in'?").
* `append [… | rename dst_endpoint.ip AS src_endpoint.ip]` selected the
  renamed-away column from its arm.
* `| cloud service | stats …` folded the stats into the cloud view's base
  query ("Field 'cloud.provider' does not exist"); it is now a clear 400.
* `| inputlookup <missing table> | stats …` scanned up to the result limit of
  events (a memory-limit failure at scale) before reporting the missing table.

Here: OCSF Network Activity (4001) rows seeded straight into the ingest view,
then each shape runs through the real search service and ClickHouse.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from nano_e2e import schema
from nano_e2e.client import Nano, time_range
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

SRC_IPS = ["10.56.34.1", "10.56.34.2", "10.56.34.3"]
DST_PORTS = [22, 80, 443, 3389]


def _ch(stack: Stack):
    def run(sql: str) -> str:
        r = httpx.post(stack.ch_url, content=sql.encode(), auth=(stack.ch_admin_user, stack.ch_admin_password), timeout=120)
        assert r.status_code == 200, f"{r.status_code}: {r.text[:800]}"
        return r.text.strip()

    return run


def _search(nano: Nano, query: str) -> httpx.Response:
    body = {
        "query": query,
        "limit": 1000,
        "skip_histogram": True,
        "skip_field_stats": True,
        "use_cache": False,
        "time_range": time_range(120),
    }
    return nano.search_http.post("/api/search", json=body, headers={"x-nano-cache-bypass": "1"})


def _rows(nano: Nano, query: str) -> list[dict]:
    r = _search(nano, query)
    assert r.status_code == 200, f"{query}\n{r.status_code}: {r.text[:600]}"
    return r.json().get("results") or []


def test_later_stages_read_stage_columns_on_ocsf(stack: Stack, nano: Nano, mark: str, timeline) -> None:
    if not schema.is_ocsf():
        pytest.skip("the bugs are in the OCSF field resolution: this stack is udm")
    ch = _ch(stack)
    tag = mark[-8:].lower()
    lane = f"nan5634_{tag}"
    now = datetime.now(UTC)
    rows = []
    # Source i talks to the first i+1 ports, (i+1)*3 events each, so the
    # sources differ in both event count and distinct ports.
    for i, ip in enumerate(SRC_IPS):
        for j in range((i + 1) * 3):
            t = now - timedelta(minutes=3 + j + i)
            rows.append(json.dumps({"source_type": lane, "event": {
                "class_uid": 4001, "category_uid": 4, "activity_id": 6, "time": int(t.timestamp() * 1000),
                "metadata": {"uid": f"{lane}-{i}-{j}", "version": "1.8.0", "log_source": lane},
                "src_endpoint": {"ip": ip}, "dst_endpoint": {"ip": f"192.0.2.{10 + j % 2}", "port": DST_PORTS[j % (i + 1)]},
                "traffic": {"bytes_in": 1000 + 700 * j, "bytes_out": 10},
            }}))
    ch("INSERT INTO nanosiem.ocsf_logs_raw (source_type, event) SETTINGS async_insert = 0 FORMAT JSONEachRow\n"
       + "\n".join(rows))
    base = f'metadata.log_source="{lane}"'
    eventually(
        lambda: len(nano.rows(base, limit=100, minutes_back=120)) == len(rows) or None,
        timeout=60, interval=2, desc="seeded OCSF rows searchable",
    )

    # 1. A stats alias sorted, then renamed, then projected.
    scanners = _rows(nano, f"{base} | where isnotnull(src_endpoint.ip) "
                     "| stats count() as events, dc(dst_endpoint.port) as ports by src_endpoint.ip "
                     "| where events > 1 | sort -ports | head 20 "
                     "| rename src_endpoint.ip as scanner, ports as unique_ports "
                     "| table scanner, events, unique_ports")
    timeline.step("sort_rename_table", rows=scanners)
    assert [r["scanner"] for r in scanners] == list(reversed(SRC_IPS)), scanners
    assert [int(r["unique_ports"]) for r in scanners] == [3, 2, 1], scanners
    assert [int(r["events"]) for r in scanners] == [9, 6, 3], scanners

    by_ip = _rows(nano, f"{base} | stats count() as events by src_endpoint.ip | sort src_endpoint.ip "
                  "| eval pct = round(events / 18 * 100, 2) | rename src_endpoint.ip as ip")
    timeline.step("sort_eval_rename", rows=by_ip)
    assert [r["ip"] for r in by_ip] == SRC_IPS, by_ip
    assert [float(r["pct"]) for r in by_ip] == [16.67, 33.33, 50.0], by_ip

    # 2. Numeric bin of a UDM name resolves to the OCSF column.
    bins = _rows(nano, f"{base} | bin bytes_in span=1024 | stats count() by bytes_in | sort bytes_in")
    timeline.step("bin_udm_name", rows=bins)
    expected: dict[int, int] = {}
    for i in range(len(SRC_IPS)):
        for j in range((i + 1) * 3):
            b = (1000 + 700 * j) // 1024 * 1024
            expected[b] = expected.get(b, 0) + 1
    assert {int(float(r["bytes_in"])): int(r["count"]) for r in bins} == expected, bins

    # 3. append + rename: both arms keyed by src_endpoint.ip, no dst column.
    appended = _rows(nano, f"{base} | stats count() as events by src_endpoint.ip "
                     f"| append [search {base} | stats count() as events by dst_endpoint.ip "
                     "| rename dst_endpoint.ip as src_endpoint.ip]")
    timeline.step("append_rename", rows=appended)
    assert all("dst_endpoint.ip" not in r for r in appended), appended
    got = {(r["src_endpoint.ip"], int(r["events"])) for r in appended}
    assert {("10.56.34.1", 3), ("10.56.34.2", 6), ("10.56.34.3", 9)} <= got, appended
    assert sum(int(r["events"]) for r in appended) == 2 * len(rows), appended

    # 4. A command after `| cloud` is a clear refusal, not a field error.
    r = _search(nano, f"{base} | cloud service | stats count() by cloud_service")
    assert r.status_code == 400, r.text
    assert "must be the last command" in r.text and "cloud.provider" not in r.text, r.text

    # 5. A missing inputlookup table is refused before any event scan.
    r = _search(nano, f"| inputlookup nan5634_missing_{tag} | stats count() by threat_type")
    assert r.status_code == 400, r.text
    assert f"nan5634_missing_{tag}" in r.text and "does not exist" in r.text, r.text
    assert "Verify the URL" not in r.text, r.text

    # 6. A join over an aggregating subsearch pages as raw rows.
    joined = _rows(nano, f"{base} | join type=inner src_endpoint.ip "
                   f"[search {base} | stats count() as c by src_endpoint.ip]")
    timeline.step("join_raw_rows", rows=len(joined))
    assert len(joined) == len(rows), len(joined)
    assert {(r["src_endpoint.ip"], int(r["c"])) for r in joined} == {
        ("10.56.34.1", 3), ("10.56.34.2", 6), ("10.56.34.3", 9)}
    ch("SYSTEM FLUSH LOGS")
    windowed = ch(
        "SELECT count() FROM system.query_log WHERE event_time > now() - INTERVAL 10 MINUTE "
        f"AND query LIKE '%{lane}%' AND query LIKE '%JOIN%' AND query LIKE '%count(*) OVER ()%' "
        "AND query NOT LIKE '%system.query_log%'"
    )
    assert windowed == "0", "the join result was wrapped in count(*) OVER ()"

"""`| prevalence` followed by an aggregation runs on OCSF (NAN-5632).

The prevalence push-down wraps the joined rows as `prevalence_results` and
chains the aggregation after it as `pv_stage_*` CTEs. Each stage used to be
generated on its own, so a column an earlier stage produced was resolved as an
unknown OCSF event field:

* `… | timechart span=1h count()` is re-entered as `timechart | sort
  time_bucket`, and the sort read `unmapped."time_bucket"` (400 "Field
  'unmapped.time_bucket' does not exist").
* `… | stats count by src_endpoint.ip` gets the implicit `sort -count`, which
  read `event."count"` (400 "Field 'event.count' does not exist").

Here: OCSF DNS Activity (4003) rows seeded straight into the ingest view, then
the reported queries and a few neighbouring shapes run through the real search
service and ClickHouse. Each must answer 200 with the aggregated rows.
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

SRC_IPS = ["10.56.32.1", "10.56.32.2", "10.56.32.3"]
EVENTS_PER_IP = 4


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


def test_prevalence_then_aggregation_runs_on_ocsf(stack: Stack, nano: Nano, mark: str, timeline) -> None:
    if not schema.is_ocsf():
        pytest.skip("the bug is in the OCSF field resolver: this stack is udm")
    ch = _ch(stack)
    tag = mark[-8:].lower()
    lane = f"nan5632_{tag}"
    now = datetime.now(UTC)
    rows = []
    for i, ip in enumerate(SRC_IPS):
        for j in range(EVENTS_PER_IP):
            t = now - timedelta(minutes=5 + 7 * j + i)
            rows.append(json.dumps({"source_type": lane, "event": {
                "class_uid": 4003, "category_uid": 4, "activity_id": 1, "time": int(t.timestamp() * 1000),
                "metadata": {"uid": f"{lane}-{i}-{j}", "version": "1.8.0", "log_source": lane},
                "src_endpoint": {"ip": ip}, "dst_endpoint": {"ip": "192.0.2.53"},
                "device": {"hostname": f"host-{i}"},
                # A hostname label (no `_`): the domain prevalence views skip
                # names that are not valid hostnames.
                "query": {"hostname": f"rare-{i}.nan5632-{tag}.example.com", "type": "A"},
            }}))
    ch("INSERT INTO nanosiem.ocsf_logs_raw (source_type, event) SETTINGS async_insert = 0 FORMAT JSONEachRow\n"
       + "\n".join(rows))
    base = f'metadata.log_source="{lane}" class_uid=4003'
    eventually(
        lambda: len(nano.rows(base, limit=100, minutes_back=120)) == len(rows) or None,
        timeout=60, interval=2, desc="seeded OCSF rows searchable",
    )

    shapes = {
        # NAN-5632 query 1 (corpus 359 shape) and query 2 (corpus 1210 shape).
        "timechart_after_where_host_count":
            f"{base} | prevalence enrich=true window=24h | where host_count < 3 | timechart span=1h count()",
        "stats_after_eval_where":
            f"{base} | prevalence enrich=true | eval risky=if(host_count < 3, 1, 0) | where risky=1 "
            "| stats count by src_endpoint.ip",
        # Same bug class: a later stage reading an earlier stage's alias.
        "stats_sort": f"{base} | prevalence enrich=true | stats count by src_endpoint.ip | sort -count",
        "stats_rename_sort":
            f"{base} | prevalence enrich=true | stats count by src_endpoint.ip | rename count as n | sort -n | head 2",
        "stats_by_decoration": f"{base} | prevalence enrich=true | stats count by host_count | sort -count",
        "table": f"{base} | prevalence enrich=true | table src_endpoint.ip, host_count, is_rare",
        "sort_events": f"{base} | prevalence enrich=true | sort -host_count | head 5",
    }
    results: dict[str, list] = {}
    failures = {}
    for name, query in shapes.items():
        r = _search(nano, query)
        if r.status_code != 200:
            failures[name] = f"{r.status_code}: {r.text[:400]}"
            continue
        results[name] = r.json().get("results") or []
        timeline.step(name, rows=len(results[name]), sample=json.loads(json.dumps(results[name][:2], default=str)))
    assert not failures, failures

    total = len(SRC_IPS) * EVENTS_PER_IP
    # Every seeded domain is unique to this run and seen from one host. The
    # decorated-filter forms (`where host_count < 3`) re-verify such brand-new
    # artifacts against the prevalence summary (NAN-1705), so they are rare
    # there; the plain enrich form may still read them as unresolved (NULL)
    # until the dictionary refreshes, so it is not asserted on.
    for name in ("stats_sort", "stats_after_eval_where"):
        counts = {str(r.get("src_endpoint.ip")): int(r.get("count") or 0) for r in results[name]}
        assert sum(counts.values()) == total, (name, counts)
        assert set(counts) == set(SRC_IPS), (name, counts)
    assert [int(r["count"]) for r in results["stats_sort"]] == sorted(
        (int(r["count"]) for r in results["stats_sort"]), reverse=True
    )
    assert len(results["stats_rename_sort"]) == 2 and all("n" in r for r in results["stats_rename_sort"])
    assert sum(int(r.get("count") or 0) for r in results["stats_by_decoration"]) == total
    assert len(results["table"]) == total
    assert len(results["sort_events"]) == 5
    buckets = results["timechart_after_where_host_count"]
    assert buckets and all("time_bucket" in r or "_time" in r or "timestamp" in r for r in buckets), buckets
    assert sum(int(r.get("count") or 0) for r in buckets) == total, buckets

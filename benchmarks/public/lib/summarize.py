#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Median-of-runs summary for the published benchmark numbers.

  summarize.py --results benchmarks/public/results/v2.0.29-2026-11-16 > summary.json

Reads every ceiling.json and socday.json at any depth under --results (runs
from several installs, e.g. ceiling-install-a/ceiling-ing3-r1, pool by group)
and groups runs by their id prefix (everything before "-r<N>"), e.g.
ceil-ing3-r1..r3 -> "ceil-ing3", bench-soc50-r1..r3 -> "bench-soc50". Each
group reports the median of every headline metric plus the per-run values,
so the spread is visible next to the median.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import statistics
import sys


def med(xs):
    xs = [x for x in xs if isinstance(x, (int, float))]
    return round(statistics.median(xs), 1) if xs else None


def get(d, *path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def group_of(run_id: str) -> str:
    return re.sub(r"-r\d+$", "", run_id)


def ceiling_metrics(r: dict) -> dict:
    c = r.get("ceiling") or {}
    best = None
    for p in r.get("phases", []):
        if get(p, "slo", "pass") and (best is None or p["throughput"]["eps"] > best["throughput"]["eps"]):
            best = p
    broke = c.get("broke_at") or {}
    q = get(best, "queries_at_load", "search_by_tier") or {}
    hosts = r.get("hosts", {})
    busiest = {}
    for role in ("ing", "ch", "app"):
        cpus = [get(v, "cpu_busy_pct", "p95") for k, v in hosts.items() if k.startswith(role)]
        busiest[role] = max([x for x in cpus if x is not None], default=None)
    return {
        "sustained_eps": c.get("sustained_eps"),
        "sustained_gb_per_day": c.get("sustained_gb_per_day"),
        "lag_p50_ms": get(c, "lag_ms_at_ceiling", "p50"),
        "lag_p99_ms": get(c, "lag_ms_at_ceiling", "p99"),
        "broke_at_target_eps": broke.get("target_eps"),
        "broke_on": [k for k, v in (broke.get("slo") or {}).items() if v is False and k != "pass"],
        "hunt_p95_ms_at_ceiling": get(q, "hunt", "server", "p95_ms"),
        "triage_p95_ms_at_ceiling": get(q, "triage", "server", "p95_ms"),
        "cpu_p95_busiest_ingest": busiest["ing"],
        "cpu_p95_busiest_clickhouse": busiest["ch"],
        "usd_per_hour": get(r, "cost", "usd_per_hour"),
    }


def socday_metrics(r: dict) -> dict:
    p = (r.get("phases") or [{}])[0]
    q = r.get("queries") or {}
    t = q.get("search_by_tier") or {}
    hosts = r.get("hosts", {})
    nano = {k: v for k, v in hosts.items() if not k.startswith("blaster")}
    head_cpu = min([get(v, "headroom", "cpu_pct") for v in nano.values() if get(v, "headroom", "cpu_pct") is not None],
                   default=None)
    head_mem = min([get(v, "headroom", "mem_pct") for v in nano.values() if get(v, "headroom", "mem_pct") is not None],
                   default=None)
    head_disk = min([get(v, "headroom", "disk_pct") for v in nano.values() if get(v, "headroom", "disk_pct") is not None],
                    default=None)
    det = r.get("detections") or {}
    return {
        "eps": get(p, "throughput", "eps"),
        "gb_per_day": get(p, "throughput", "gb_per_day"),
        "lag_p50_ms": get(p, "ingest_lag_ms", "p50"),
        "lag_p99_ms": get(p, "ingest_lag_ms", "p99"),
        "exactly_once": get(p, "markers", "exactly_once"),
        "zero_loss": get(p, "slo", "zero_loss"),
        **{f"{tier}_p{n}_ms": get(t, tier, "server", f"p{n}_ms") for tier in ("triage", "hunt", "ir") for n in (50, 95)},
        "dashboard_refresh_p95_ms": get(q, "dashboard_refresh", "p95_ms"),
        "agent_query_p50_ms": get(q, "agent_queries", "p50_ms"),
        "agent_query_p95_ms": get(q, "agent_queries", "p95_ms"),
        "agent_queries": get(q, "agent_queries", "count"),
        "analyst_error_rate": get(q, "error_rates", "analysts"),
        "agent_error_rate": get(q, "error_rates", "agents"),
        "alert_p50_ms": get(det, "event_to_alert_ms", "p50"),
        "alert_p95_ms": get(det, "event_to_alert_ms", "p95"),
        "alert_1m_p50_ms": get(det, "event_to_alert_ms_tool_launch_rules", "p50"),
        "alert_1m_p95_ms": get(det, "event_to_alert_ms_tool_launch_rules", "p95"),
        "findings": det.get("findings"),
        "rules_fired": det.get("rules_fired"),
        "headroom_cpu_pct_min": head_cpu,
        "headroom_mem_pct_min": head_mem,
        "headroom_disk_pct_min": head_disk,
        "usd_per_hour": get(r, "cost", "usd_per_hour"),
        "usd_per_gb": get(r, "cost", "usd_per_gb_ingested"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", required=True)
    a = ap.parse_args()
    groups: dict = {}
    for path in sorted(glob.glob(os.path.join(a.results, "**", "*.json"), recursive=True)):
        name = os.path.basename(path)
        if name not in ("ceiling.json", "socday.json"):
            continue
        r = json.load(open(path))
        # Key by the path under --results so runs with the same id from two
        # installs never overwrite each other; group by the run id's base.
        run = os.path.relpath(os.path.dirname(path), a.results)
        fn = ceiling_metrics if name == "ceiling.json" else socday_metrics
        groups.setdefault((group_of(os.path.basename(run)), r.get("scenario")), []).append((run, fn(r)))
    out = {}
    for (g, scenario), runs in sorted(groups.items()):
        keys = runs[0][1].keys()
        out[g] = {"scenario": scenario, "runs": len(runs),
                  "median": {k: (med([m[k] for _, m in runs]) if not isinstance(runs[0][1][k], (list, bool))
                                 else [m[k] for _, m in runs]) for k in keys},
                  "per_run": {run: m for run, m in runs}}
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

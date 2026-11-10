#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Size a nano Self-run deployment from EPS / GB per day and retention.

Standard library only. Prints a plan for the chosen topology, or JSON with --json.

The ratios follow the public nano sizing guides (nano.rs/docs: Self-run install >
Size the host / Retention and disk, High availability, Kubernetes sizing presets):
  * host tiers: <=5 GB/day 4 vCPU/16 GB; 10-15 GB/day 8 vCPU/32 GB; 25-50 GB/day
    16 vCPU/64 GB; 50-100 GB/day 16-32 vCPU/64-128 GB; above that, Kubernetes;
  * data disk = GB/day x retention days / compression (plan 5:1) / 0.75 merge headroom,
    on its own SSD; keep ~100 GB more for the OS and Docker images;
  * ClickHouse needs >= 6 GB memory when the enrichment feeds are on (default).
The guide says the ratios are extrapolated until load-validated. Treat the
output as a starting point and watch ClickHouse CPU and memory with real data.

For a fully highly available cluster of cloud VMs (AWS, Azure, GCP), use
plan.py instead: it builds on these ratios and adds the role layout, instance
types, HA checks, tuned settings, a cost estimate and the inventory.

Examples:
  size.py --eps 141 --retention-days 365 --topology single
  size.py --gb-per-day 12.5 --retention-days 365 --topology ha3
  size.py --gb-per-day 80 --retention-days 90 --topology helm --json
"""
from __future__ import annotations

import argparse
import json
import math
import sys

COMPRESSION = 5.0           # conservative ratio the Self-run guide plans with (5:1 to 10:1 typical)
MERGE_FILL = 0.75           # keep the data disk under ~75% full for merges
OS_DISK_GB = 100            # OS + Docker images, separate disk
EXTRA_DATA_GB = 100         # PostgreSQL, findings, small tables, Vector disk buffers


def ceil_to(value: float, step: int) -> int:
    return int(math.ceil(value / step) * step)


def tier(gb_per_day: float) -> dict:
    """Single-host tier from the Self-run sizing table."""
    if gb_per_day <= 5:
        return {"name": "up to 5 GB/day", "vcpu": 4, "ram_gib": 16, "note": "Self-run sizing table"}
    if gb_per_day <= 15:
        return {"name": "10-15 GB/day", "vcpu": 8, "ram_gib": 32, "note": "Self-run sizing table (5-10 GB/day: use this row)"}
    if gb_per_day <= 50:
        return {"name": "25-50 GB/day", "vcpu": 16, "ram_gib": 64, "note": "Self-run sizing table (15-25 GB/day: use this row)"}
    if gb_per_day <= 100:
        return {"name": "50-100 GB/day", "vcpu": 32, "ram_gib": 128, "note": "Self-run sizing table: 16-32 vCPU, 64-128 GB"}
    return {"name": "above 100 GB/day", "vcpu": None, "ram_gib": None,
            "note": "one host handles up to ~100 GB/day; above that use Kubernetes (Helm) with values-large/xlarge"}


def helm_preset(gb_per_day: float) -> str:
    if gb_per_day <= 15:
        # The Kubernetes guide's ~12.5 GB/day example layers values-small.yaml plus
        # larger ClickHouse resources/storage; see references/helm.md.
        return "values-small.yaml"
    if gb_per_day <= 100:
        return "values-standard.yaml"
    if gb_per_day <= 1000:
        return "values-large.yaml"
    return "values-xlarge.yaml"


def plan(args: argparse.Namespace) -> dict:
    if args.gb_per_day is None and args.eps is None:
        raise SystemExit("give --eps and/or --gb-per-day")
    gb = args.gb_per_day
    eps = args.eps
    if gb is None:
        gb = eps * 86400 * args.avg_event_bytes / 1e9
    if eps is None:
        eps = gb * 1e9 / 86400 / args.avg_event_bytes
    gb_sized = gb * args.growth
    hot_gib = gb_sized * args.retention_days / args.compression
    # + ~100 GB for PostgreSQL, findings and Vector disk buffers; round up like the guide's table.
    data_disk_gib = ceil_to(hot_gib / MERGE_FILL + EXTRA_DATA_GB, 250)
    t = tier(gb_sized)
    ch_vcpu_needed = max(2.0, 5.0 * gb_sized / 1000)       # 5 vCPU per TB/day
    vector_vcpu_needed = max(1.0, 12.0 * gb_sized / 1000)   # heavy-parse worst case
    out: dict = {
        "input": {"eps": round(eps, 1), "gb_per_day": round(gb, 2), "avg_event_bytes": args.avg_event_bytes,
                  "retention_days": args.retention_days, "growth_factor": args.growth,
                  "sized_gb_per_day": round(gb_sized, 2)},
        "derived": {"stored_data_gb": round(hot_gib), "compression": f"{args.compression:g}:1", "clickhouse_vcpu_by_ratio": round(ch_vcpu_needed, 2),
                    "vector_vcpu_by_ratio": round(vector_vcpu_needed, 2),
                    "comment": "below ~50 GB/day the per-service floors, not the ratios, dominate"},
        "topology": args.topology,
    }
    if args.topology == "single":
        if t["vcpu"] is None:
            out["recommendation"] = {"error": t["note"]}
        else:
            ram = t["ram_gib"]
            out["recommendation"] = {
                "tier": t["name"], "tier_note": t["note"],
                "host": {"vcpu": t["vcpu"], "ram_gb": ram, "data_disk_gb_ssd": data_disk_gib, "os_disk_gb": OS_DISK_GB},
                "clickhouse_memory": "set by the installer from host RAM (about half on a 32 GB host); needs >= 6 GB for enrichment",
                "preflight_args": f"--min-cpu {t['vcpu']} --min-mem-gib {ram - 2} --min-disk-gib {data_disk_gib}",
                "note": "preflight --min-disk-gib checks the Docker data filesystem; with a separate data disk mounted for Docker, check that disk",
            }
    elif args.topology == "ha3":
        if t["vcpu"] is None:
            out["recommendation"] = {"error": t["note"]}
        else:
            # High availability guide: three identical hosts; ClickHouse replicas on nodes 2-3 only.
            out["recommendation"] = {
                "tier": t["name"], "tier_note": t["note"],
                "layout": "1 shard x 2 replicas + ingest on nano-2/nano-3, 3 Keepers; app + PostgreSQL on nano-1 (not HA)",
                "nodes": [
                    {"name": "nano-1", "roles": "app,postgres,keeper",
                     "vcpu": t["vcpu"], "ram_gb": t["ram_gib"], "data_disk_gb_ssd": 250, "os_disk_gb": OS_DISK_GB},
                    {"name": "nano-2", "roles": "clickhouse (replica 1),keeper,ingest",
                     "vcpu": t["vcpu"], "ram_gb": t["ram_gib"], "data_disk_gb_ssd": data_disk_gib, "os_disk_gb": OS_DISK_GB},
                    {"name": "nano-3", "roles": "clickhouse (replica 2),keeper,ingest",
                     "vcpu": t["vcpu"], "ram_gb": t["ram_gib"], "data_disk_gb_ssd": data_disk_gib, "os_disk_gb": OS_DISK_GB},
                    {"name": "load balancer", "roles": "TLS termination for both hostnames", "vcpu": 2, "ram_gb": 2},
                ],
                "note": "replicas add availability, not capacity: each replica stores and merges the full stream",
                "preflight_args_nano1": f"--min-cpu {t['vcpu']} --min-mem-gib {t['ram_gib'] - 2} --min-disk-gib 250",
                "preflight_args_nano23": f"--min-cpu {t['vcpu']} --min-mem-gib {t['ram_gib'] - 2} --min-disk-gib {data_disk_gib}",
            }
    else:
        out["recommendation"] = {
            "preset": helm_preset(gb_sized),
            "clickhouse_storage_gi": max(50, data_disk_gib),
            "clickhouse_replicas": "1 (set 2 for HA: ~2x ClickHouse cost, Keeper x3)",
            "note": "layer the preset, one exposure preset, the image-lock values and your values; see references/helm.md",
        }
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--eps", type=float)
    p.add_argument("--gb-per-day", type=float)
    p.add_argument("--avg-event-bytes", type=int, default=1000)
    p.add_argument("--retention-days", type=int, default=365)
    p.add_argument("--compression", type=float, default=COMPRESSION, help="ClickHouse ratio; plan 5 until measured")
    p.add_argument("--growth", type=float, default=1.0, help="multiplier for 12-month growth, e.g. 1.5")
    p.add_argument("--topology", choices=["single", "ha3", "helm"], default="single")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    result = plan(args)
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
        return 0
    i, d, r = result["input"], result["derived"], result["recommendation"]
    print(f"Input: {i['eps']} EPS ~= {i['gb_per_day']} GB/day (x{i['growth_factor']} growth -> {i['sized_gb_per_day']} GB/day), "
          f"retention {i['retention_days']} d")
    print(f"Stored data: ~{d['stored_data_gb']} GB (GB/day x days / {d['compression']}); disk sized for <=75% full")
    print(json.dumps(r, indent=2))
    print("Ratios are extrapolated until load-validated; watch ClickHouse CPU and memory once real data flows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

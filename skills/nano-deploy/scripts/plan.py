#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Plan a fully highly available nano Self-run deployment on N VMs.

Standard library only, deterministic, offline. Given the data volume, retention
and either the VMs the operator already has (--hosts) or a cloud (--cloud), it
prints (or writes as JSON):

  * the role layout per VM (ClickHouse shards x replicas chosen from volume;
    on existing VMs, roles stacked only as far as the VM count requires);
  * per-role vCPU, RAM and disks with headroom and the Vector disk-buffer budget;
  * instance and disk types per role for AWS, Azure or GCP (scripts/cloud-catalog.json);
  * the HA reasoning: which failure each choice survives, checked mechanically;
  * tuned settings the volume needs (settable ones go into the inventory);
  * a dated, labelled monthly cost estimate range;
  * the load balancer (managed, an HAProxy pair, or one HAProxy host, which is
    a single point of failure at the edge) and its backends;
  * an inventory.yaml for deploy/compose/render-inventory.py (--inventory-out)
    and the install order across hosts (--install-order).

Full HA (several app hosts, three PostgreSQL hosts with Patroni, etcd, Valkey
and Sentinel) needs nano 2.0.7+; --inventory-schema pre-2.0.7 targets earlier
releases.

It never calls a cloud API and never reads credentials.

Examples:
  plan.py --gb-per-day 12.5 --retention-days 365 --cloud aws
  plan.py --eps 141 --cloud azure --analysts 5 --max-nodes 8
  plan.py --gb-per-day 1000 --retention-days 90 --cloud gcp --json
  plan.py --gb-per-day 100 --cloud aws --inventory-out ./nano-deploy-work/inventory.yaml \\
      --cluster-name prod --deployment-id deploy_01abc --app-hostname nano.example.com \\
      --ingest-hostname ingest.nano.example.com --tls-server-name nano-private.example.com
  plan.py --gb-per-day 12.5 --hosts hosts.txt --lb haproxy-single   # 8 existing VMs, no managed LB
  plan.py --gb-per-day 12.5 --hosts hosts.txt --lb haproxy-single --install-order
  plan.py --port-matrix           # firewall flows derived from the renderer port matrix
  plan.py --gb-per-day 12.5 --hosts hosts.txt --lb haproxy-dns --firewall-script \
          --edge-source-cidr 10.20.0.0/16                                         # DOCKER-USER + UFW rules
  plan.py --gb-per-day 12.5 --hosts small.txt --lb haproxy-single --lab   # evaluation cluster, NOT FOR PRODUCTION

Production sizing per role is the HA guide's Server sizing table
(https://nano.rs/docs/getting-started/high-availability#server-sizing); the
constants below compute the same numbers and raise them with volume.

Every sizing constant below carries its source:
  MEASURED-external   measured on an external 16 TB/day Vector + ClickHouse
                      estate (2026-11-09 review). Not a nano measurement.
  nano-measured       measured on nano itself, or read from nano's shipped config.
  INFERRED            derived or estimated; replace with a measurement when one exists.
Nothing in nano is load-validated above about 5,267 EPS. Plans above that say so.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
from pathlib import Path

PLAN_VERSION = 1
HERE = Path(__file__).resolve().parent
CATALOG_PATH = HERE / "cloud-catalog.json"
GIB = 1024 ** 3
MIB = 1024 ** 2

# --- Volume model -----------------------------------------------------------
AVG_EVENT_BYTES = 1000            # nano-measured planning default (Self-run sizing guide: ~1 KB/event)
COMPRESSION = 5.0                 # nano-measured planning default (guide plans 5:1; nano dev measured 11.7-12x on logs)
PEAK_HOUR_FACTOR = 1.36           # MEASURED-external: 21.8 TB/day peak hour at 16 TB/day average
BURST_FACTOR = 3.0                # nano-measured guidance (Self-run guide: plan bursts of 3x average); absorbed by buffers
NANO_VALIDATED_EPS = 5267         # nano-measured: highest load result in the tree (30 s run)

# --- ClickHouse -------------------------------------------------------------
CH_BUSY_VCPU_PER_TB_DAY = 7.6     # MEASURED-external: 122 busy cores / 16 TB/day with a 22-MV insert cascade
CH_NANO_WRITE_FACTOR = 1.15       # INFERRED: same MV count (23) but 108-113 skip indexes vs 13
CH_TARGET_AVG_UTIL = 0.70         # INFERRED target acceptance (avg < 70 %)
CH_TARGET_PEAK_UTIL = 0.85        # INFERRED target acceptance (peak < 85 %)
CH_QUERY_CONCURRENCY_PER_ANALYST = 0.3  # INFERRED: share of analysts with a query in flight at once
CH_VCPU_PER_CONCURRENT_QUERY = 1.0      # INFERRED: per node, a distributed query runs on every shard
SEARCH_GLOBAL_ADHOC_LIMIT = 30    # nano-measured config: search admission global_adhoc_limit
CH_MEM_GIB_PER_VCPU = 8           # MEASURED-external: 503 GiB / 64 vCPU; the memory-optimised families picked are 8:1
CH_MIN_MEM_GIB_PER_VCPU = 4       # INFERRED floor per vCPU (an existing 8 vCPU / 32 GiB host qualifies at small volume)
CH_MIN_VCPU = 4                   # INFERRED floor for a dedicated ClickHouse node
CH_MIN_MEM_GIB = 32               # nano-measured: enrichment needs >= 6 GiB ClickHouse; 32 GiB keeps caches useful
CH_MAX_NODE_VCPU = 64             # nano-measured config: resource-sizing.sh clamps ClickHouse cores to 2..64
CH_MAX_NODE_DISK_GIB = 16384      # INFERRED cap per node (MEASURED-external ran 14 TB/node); keeps replica rebuilds bounded
CH_DISK_FILL = 0.70               # nano-measured: tiering moves data at move_factor 0.3 (70 % full); <= 75 % for merges
CH_MV_OVERHEAD = 1.15             # INFERRED: +10-20 % for MV-derived tables
CH_EXTRA_GIB = 100                # nano-measured guidance: PostgreSQL/findings/small tables beside the data
CH_LOCAL_NVME_MIN_GIB = 4096      # INFERRED: use local NVMe families only when the hot set is this large
HOT_DAY_CHOICES = (90, 30, 14, 7) # INFERRED; 7 d is MEASURED-external's TTL move to the cold tier

# --- Vector / ingest --------------------------------------------------------
VECTOR_CPU_MS_PER_EVENT_REF = 0.5     # MEASURED-external: ~0.5 ms total CPU per event per reader (0.27 ms VRL)
NANO_VECTOR_PIPELINE_FACTOR = 2.0     # INFERRED: nano runs 9-11 remaps + 2-3 routes + a health sink vs 5 + 3
VECTOR_TARGET_UTIL = 0.70             # INFERRED
VECTOR_PROCESS_EPS_REF = 20000        # MEASURED-external: one Vector process caps at ~18-22k ev/s
VECTOR_HOST_EPS_ROLE_SPLIT_REF = 50000  # MEASURED-external: 9 readers per 32-vCPU VM ~50k ev/s (needs the Vector role split)
VECTOR_MIN_SINK_BUFFER = GIB          # MEASURED-external: 1 GiB per sink held 500-790 MB under 10-25 s flush latency
VECTOR_MIN_MEM_GIB_AT_VOLUME = 8      # MEASURED-external: 2 GB OOM-looped 581x; readers run 8-12 GiB
VECTOR_MIB_PER_SOURCE = 10            # nano-measured: 470-512 MiB at 50 deployed sources
VECTOR_REQUEST_CONCURRENCY = 6        # nano-measured compose default; MEASURED-external: 6 held, 16 wedged prod
VECTOR_SINKS_PER_SHARD = 3            # nano-measured config: logs/ocsf, parser health and enrichment lanes per shard
# nano-measured config/vector/disk-buffer-budget.env and scripts/lib/resource-sizing.sh:
VECTOR_DISK_BUFFER_MIN_BYTES = 268435488
VECTOR_DISK_BUFFER_STATIC = 2
VECTOR_DISK_BUFFER_PER_SHARD = 6
VECTOR_BUFFER_MIN_MIB, VECTOR_BUFFER_MAX_MIB = 2048, 32768
INGEST_DATA_DISK_MIN_GIB = 128        # INFERRED: buffer budget + reserves + images; matches Azure P10
INGEST_IMAGES_GIB = 30                # INFERRED: Docker images and logs on the ingest data disk
INGEST_COLOCATE_MAX_GB_DAY = 100      # nano-measured guidance: one host handles up to ~100 GB/day

# --- App, PostgreSQL, Keeper -------------------------------------------------
APP_MIN = (4, 16)                     # INFERRED floor (vCPU, GiB): api + search + jobs + web + edges
APP_AT_VOLUME = (8, 32)               # MEASURED-external: 2 x 8 vCPU / 31 GiB app VMs, load1 0.55 at 16 TB/day
APP_MAX_HOST_VCPU = 32                # INFERRED: scale out above this
PG_TIERS = (                          # INFERRED (PostgreSQL write rate at volume is unmeasured)
    # (max GB/day, vCPU, GiB, data disk GiB, provisioned IOPS)
    (100, 2, 8, 100, 3000),
    (1000, 4, 16, 250, 3000),
    (10000, 8, 32, 500, 6000),
    (float("inf"), 12, 48, 1000, 12000),
)
KEEPER_COLOCATED = (1, 4)             # MEASURED-external: Keeper 2 vCPU / 7 GiB VMs ran at 16 % CPU, 343 MiB
HA_STATE_COLOCATED = (1, 2)           # INFERRED: etcd + Valkey + Sentinel + HAProxy beside PostgreSQL
OS_DISK_GIB = 100                     # nano-measured guidance: OS + Docker images on a separate ~100 GB disk
# A VM sold with N GB of RAM reports less (a 16 GB VM shows ~15 GiB); preflight.sh
# accepts 14 GiB for 16 GB. Host RAM counts as meeting a requirement at this share.
MEM_REPORTED_FACTOR = 0.875           # INFERRED from preflight's 14-of-16 GiB default
# --lab only: a rough fixed overhead (Docker images, logs) used to estimate how
# many days of hot data an undersized ClickHouse disk can hold. Production
# planning uses CH_EXTRA_GIB.
LAB_CH_OVERHEAD_GIB = 20              # INFERRED: images + logs on a fresh role-split ClickHouse host

# --- Network plan (deterministic; edit with --vpc-cidr) ----------------------
DEFAULT_VPC_CIDR = "10.40.0.0/16"
ROLE_ORDER = ("app", "control", "clickhouse", "ingest")

# --- Public docs the messages point at ------------------------------------------
SIZING_DOC = "https://nano.rs/docs/getting-started/high-availability#server-sizing"
LB_DOC = "https://nano.rs/docs/getting-started/high-availability#load-balancer-options"
FIREWALL_DOC = "https://nano.rs/docs/getting-started/high-availability#host-firewall"

# --- Renderer port matrix -----------------------------------------------------
# Vendored copy of deploy/compose/render-inventory.py PORT_DEFAULTS and
# ROLE_PORTS (v2.0.7, with the full-HA keys). The skill ships
# without deploy/, so it cannot import them. The test
# scripts/tests/test_nano_deploy_plan_inventory.py fails if they drift.
PORT_DEFAULTS = {
    "app": 80,
    "ingest": 80,
    "api_internal": 3000,
    "vector_tap": 8687,
    "postgres": 5432,
    "valkey": 6379,
    "patroni_api": 8008,
    "etcd_client": 2379,
    "etcd_peer": 2380,
    "sentinel": 26379,
    "clickhouse_http": 8123,
    "clickhouse_native": 9000,
    "clickhouse_interserver": 9009,
    "clickhouse_metrics": 9363,
    "keeper_client": 9181,
    "keeper_raft": 9234,
}
ROLE_PORTS = {
    "app": ("app", "api_internal"),
    "ingest": ("ingest", "vector_tap"),
    "postgres": ("postgres",),
    "clickhouse": ("clickhouse_http", "clickhouse_native", "clickhouse_interserver", "clickhouse_metrics"),
    "keeper": ("keeper_client", "keeper_raft"),
}
# The stateful-tier failover ports (render_ha.py). With three postgres hosts,
# etcd and Sentinel run on the postgres hosts, so every one of these lives on
# the postgres hosts. Valkey/Sentinel run only with two or more app hosts.
HA_PORTS = ("patroni_api", "etcd_client", "etcd_peer", "valkey", "sentinel")
# Who may connect to each port (source roles; "lb:app" / "lb:ingest" are the
# load balancers). Mirrors the multi-node guide's firewall tables. ClickHouse
# hosts reach PostgreSQL on 5432 for dictionaries; only app hosts run the
# PostgreSQL/Valkey routers, so only they need Patroni, Valkey and Sentinel.
PORT_SOURCES = {
    "app": ("lb:app",),
    "api_internal": ("ingest",),
    "ingest": ("lb:ingest", "app"),
    "vector_tap": ("app",),
    "postgres": ("app", "clickhouse", "postgres"),
    "patroni_api": ("app", "postgres"),
    "etcd_client": ("postgres",),
    "etcd_peer": ("postgres",),
    "valkey": ("app", "postgres"),
    "sentinel": ("app", "postgres"),
    "clickhouse_http": ("app", "ingest", "clickhouse"),
    "clickhouse_native": ("app", "ingest", "clickhouse"),
    "clickhouse_interserver": ("clickhouse",),
    "clickhouse_metrics": ("app",),
    "keeper_client": ("app", "clickhouse", "keeper"),
    "keeper_raft": ("keeper",),
}

# =============================================================================
# Inventory schemas. Full HA (several app hosts, three postgres hosts with
# Patroni, etcd, Valkey and Sentinel) ships in v2.0.7. `pre-2.0.7` is what earlier releases accept.
# =============================================================================
FULL_HA_RELEASE = "2.0.7"


def ha_schema() -> dict:
    """The v2.0.7 full-HA inventory schema (settled)."""
    return {
        "name": "full-ha",
        "release": FULL_HA_RELEASE,
        "roles": {"app": ["app"], "control": ["postgres", "keeper"], "clickhouse": ["clickhouse"], "ingest": ["ingest"]},
        "multi_app": True,          # any number of app hosts
        "multi_postgres": True,     # 3 postgres hosts -> Patroni + etcd, Valkey + Sentinel
        "postgres_ha": {"synchronous_mode": "on"},   # the documented default, written explicitly
        "health_checks": {
            "app": {"path": "/readyz", "port": "app",
                    "note": "200 only while that host's API and search are ready; 503 while an upgrade drains it"},
            "ingest": {"path": "/healthz", "port": "ingest",
                       "note": "200 only while that host's Vector is up with a confirmed config generation"},
        },
    }


def single_app_schema() -> dict:
    """What releases before v2.0.7 accept: exactly one app and one postgres host."""
    return {
        "name": "pre-2.0.7",
        "release": None,
        "roles": {"app": ["app"], "control": ["postgres", "keeper"], "clickhouse": ["clickhouse"], "ingest": ["ingest"]},
        "multi_app": False,
        "multi_postgres": False,
        "postgres_ha": None,
        "health_checks": {
            "app": {"path": "/healthz", "port": "app", "note": "one app host"},
            "ingest": {"path": "/healthz", "port": "ingest",
                       "note": "200 only while that host's Vector is up with a confirmed config generation"},
        },
    }


SCHEMAS = {"full-ha": ha_schema, "pre-2.0.7": single_app_schema}


def schema_for(name: str) -> dict:
    return SCHEMAS[name]()


# =============================================================================
class PlanError(ValueError):
    pass


def ceil_to(value: float, step: int) -> int:
    return int(math.ceil(value / step - 1e-9) * step)


def load_catalog(path: Path = CATALOG_PATH) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# --- Load -------------------------------------------------------------------
def derive_load(a: argparse.Namespace) -> dict:
    if a.gb_per_day is None and a.eps is None:
        raise PlanError("give --gb-per-day and/or --eps")
    gb = a.gb_per_day if a.gb_per_day is not None else a.eps * 86400 * a.avg_event_bytes / 1e9
    eps = a.eps if a.eps is not None else gb * 1e9 / 86400 / a.avg_event_bytes
    if gb <= 0 or eps <= 0:
        raise PlanError("volume must be positive")
    sized_gb = gb * a.growth
    sized_eps = eps * a.growth
    peak_eps = sized_eps * PEAK_HOUR_FACTOR
    mb_s = sized_gb * 1e3 / 86400
    return {
        "gb_per_day": round(gb, 2), "eps": round(eps, 1), "avg_event_bytes": a.avg_event_bytes,
        "growth_factor": a.growth, "sized_gb_per_day": round(sized_gb, 2), "sized_eps": round(sized_eps, 1),
        "peak_hour_eps": round(peak_eps), "burst_eps": round(sized_eps * BURST_FACTOR),
        "avg_mb_s": round(mb_s, 3), "peak_mb_s": round(mb_s * PEAK_HOUR_FACTOR, 3),
        "sized_tb_per_day": sized_gb / 1000.0,
        "extrapolated": peak_eps > NANO_VALIDATED_EPS,
        "_peak_eps": peak_eps, "_sized_gb": sized_gb,
    }


# --- SKU choice -------------------------------------------------------------
def choose_sku(cat: dict, cloud: str, family_key: str, vcpu: float, mem: float, nvme_gib: float = 0) -> dict | None:
    fam = cat["clouds"][cloud]["families"].get(family_key)
    if fam is None:
        return None
    fits = [s for s in fam["skus"]
            if s["vcpu"] >= vcpu - 1e-9 and s["mem_gib"] >= mem - 1e-9
            and (nvme_gib <= 0 or s.get("local_nvme_gb", 0) * 1e9 / GIB >= nvme_gib)]
    if not fits:
        return None
    return dict(min(fits, key=lambda s: (s["usd_hour"], s["vcpu"], s["name"])), family=fam["family"], disk=fam["disk"])


def largest_vcpu(cat: dict, cloud: str, family_key: str) -> int:
    return max(s["vcpu"] for s in cat["clouds"][cloud]["families"][family_key]["skus"])


# --- Product sizing mirror (scripts/lib/resource-sizing.sh) ------------------
def product_split_mib(mem_gib: int, roles: set[str]) -> dict:
    """Mirror resource-sizing.sh's role memory split (role topology)."""
    memory_mib = mem_gib * 1024
    os_reserve = min(max(memory_mib // 10, 384), 8192)
    alloc = memory_mib - os_reserve
    weights = {"clickhouse": 55, "postgres": 12, "ingest": 13, "app": 20, "keeper": 5}
    active = {r: w for r, w in weights.items() if r in roles}
    total = sum(active.values())
    split = {r: alloc * w // total for r, w in active.items()}
    floors = {"clickhouse": 2048, "postgres": 312, "ingest": 312, "app": 800, "keeper": 384}
    for r in split:
        split[r] = max(split[r], floors[r])
    remainder = alloc - sum(split.values())
    for r in ("clickhouse", "app", "ingest", "postgres", "keeper"):
        if r in split:
            split[r] += max(0, remainder)
            break
    return split


def product_vector_buffer(mem_gib: int, roles: set[str], shards: int, data_disk_gib: int) -> dict:
    """Vector disk-buffer budget the installer derives for this host."""
    split = product_split_mib(mem_gib, roles)
    vector_mib = max(256, split.get("ingest", 312) * 85 // 100)
    desired = min(max(vector_mib * 2, VECTOR_BUFFER_MIN_MIB), VECTOR_BUFFER_MAX_MIB) * MIB
    count = VECTOR_DISK_BUFFER_STATIC + VECTOR_DISK_BUFFER_PER_SHARD * shards
    cap = data_disk_gib * GIB
    reserved = 2 * max(cap // 10, 4 * GIB)
    if "clickhouse" in roles:
        reserved += max(cap // 4, 8 * GIB)
    allocatable = cap - reserved
    minimum = VECTOR_DISK_BUFFER_MIN_BYTES * count
    budget = max(min(desired, allocatable), minimum)
    return {
        "vector_mem_mib": vector_mib, "buffer_count": count, "budget_bytes": budget,
        "per_sink_bytes": budget // count, "disk_ok": allocatable >= minimum,
        "clickhouse_mib": split.get("clickhouse"),
    }


# --- ClickHouse -----------------------------------------------------------------
def clickhouse_shape(load: dict, a: argparse.Namespace, shards: int, hot_days: int, colocated_ingest_vcpu: float) -> dict:
    tb = load["sized_tb_per_day"] / shards
    busy = CH_BUSY_VCPU_PER_TB_DAY * CH_NANO_WRITE_FACTOR * tb
    ingest_vcpu = max(busy / CH_TARGET_AVG_UTIL, busy * PEAK_HOUR_FACTOR / CH_TARGET_PEAK_UTIL)
    concurrent = min(SEARCH_GLOBAL_ADHOC_LIMIT, max(1, math.ceil(a.analysts * CH_QUERY_CONCURRENCY_PER_ANALYST)))
    query_vcpu = concurrent * CH_VCPU_PER_CONCURRENT_QUERY
    vcpu = max(CH_MIN_VCPU, ingest_vcpu + query_vcpu) + colocated_ingest_vcpu
    mem = max(CH_MIN_MEM_GIB, vcpu * CH_MIN_MEM_GIB_PER_VCPU)
    hot_gib = load["_sized_gb"] * 1e9 / GIB * hot_days / a.compression * CH_MV_OVERHEAD / shards
    disk = ceil_to(hot_gib / CH_DISK_FILL + CH_EXTRA_GIB, 50)
    return {"shards": shards, "hot_days": hot_days, "shard_tb_per_day": round(tb, 3),
            "busy_vcpu_ingest": round(busy, 2), "vcpu_need": round(vcpu, 2), "mem_need_gib": round(mem, 1),
            "hot_data_gib_per_replica": round(hot_gib), "data_disk_gib": disk,
            "concurrent_queries": concurrent, "query_vcpu": query_vcpu}


def size_clickhouse(load: dict, a: argparse.Namespace, cat: dict | None, colocated_ingest_vcpu: float,
                    max_vcpu: int | None = None, max_disk_gib: int | None = None) -> dict:
    disk_cap = min(CH_MAX_NODE_DISK_GIB, max_disk_gib or CH_MAX_NODE_DISK_GIB)
    if cat is not None:
        max_vcpu = largest_vcpu(cat, a.cloud, "clickhouse")
    max_vcpu = min(CH_MAX_NODE_VCPU, max_vcpu or CH_MAX_NODE_VCPU)
    if a.hot_days is not None:
        hot_choices = [min(a.hot_days, a.retention_days)]
    else:
        hot_choices = [a.retention_days] + [d for d in HOT_DAY_CHOICES if d < a.retention_days]
    cpu_shards = None
    for shards in range(1, 257):
        if clickhouse_shape(load, a, shards, 1, colocated_ingest_vcpu)["vcpu_need"] <= max_vcpu:
            cpu_shards = shards
            break
    if cpu_shards is None:
        raise PlanError("volume exceeds 256 ClickHouse shards; contact nano")
    if a.shards:
        cpu_shards = max(cpu_shards, a.shards)
    chosen = None
    for hot in hot_choices:
        shape = clickhouse_shape(load, a, cpu_shards, hot, colocated_ingest_vcpu)
        if shape["data_disk_gib"] <= disk_cap:
            chosen = shape
            break
    if chosen is None:
        # The shortest hot window still does not fit: add shards for disk.
        hot = hot_choices[-1]
        for shards in range(cpu_shards, 257):
            shape = clickhouse_shape(load, a, shards, hot, colocated_ingest_vcpu)
            if shape["data_disk_gib"] <= disk_cap:
                chosen = shape
                break
    if chosen is None:
        raise PlanError("hot data does not fit 256 shards; shorten --hot-days")
    chosen["replicas"] = a.replicas
    chosen["cold_days"] = a.retention_days - chosen["hot_days"]
    cold_gib = load["_sized_gb"] * 1e9 / GIB * chosen["cold_days"] / a.compression * CH_MV_OVERHEAD
    chosen["cold_object_storage_gib"] = round(cold_gib * a.replicas)
    tb = chosen["shard_tb_per_day"]
    chosen["disk_iops"] = int(min(16000, 3000 + ceil_to(2000 * tb, 1000)))   # INFERRED
    chosen["disk_mbps"] = int(min(1000, 125 + ceil_to(100 * tb, 25)))       # INFERRED
    if cat is None:                              # existing hosts: no instance choice
        chosen["sku"], chosen["local_nvme"] = None, False
        return chosen
    # Disk choice: local NVMe families for a large hot set, else provisioned SSD.
    local = None
    if a.ch_disk in ("auto", "local") and "clickhouse_local" in cat["clouds"][a.cloud]["families"]:
        need_nvme = chosen["data_disk_gib"]
        if a.ch_disk == "local" or need_nvme >= CH_LOCAL_NVME_MIN_GIB:
            local = choose_sku(cat, a.cloud, "clickhouse_local", chosen["vcpu_need"], chosen["mem_need_gib"], need_nvme)
    if a.ch_disk == "local" and local is None:
        raise PlanError(f"{a.cloud} has no local-NVMe size for {chosen['vcpu_need']} vCPU / {chosen['data_disk_gib']} GiB")
    sku = local or choose_sku(cat, a.cloud, "clickhouse", chosen["vcpu_need"], chosen["mem_need_gib"])
    if sku is None:
        raise PlanError("no ClickHouse size fits; this is a planner bug")
    chosen["sku"] = sku
    chosen["local_nvme"] = local is not None
    return chosen


# --- Ingest ---------------------------------------------------------------------
def vector_cpu_ms() -> float:
    return VECTOR_CPU_MS_PER_EVENT_REF * NANO_VECTOR_PIPELINE_FACTOR


def vector_host_eps_ceiling() -> float:
    return VECTOR_PROCESS_EPS_REF / NANO_VECTOR_PIPELINE_FACTOR   # INFERRED: ~10k ev/s per nano ingest host today


def ingest_capacity_eps(vcpu: float) -> int:
    """Peak EPS one ingest host (or a co-located ingest share) carries."""
    return math.floor(min(vector_host_eps_ceiling(), vcpu * VECTOR_TARGET_UTIL * 1000 / vector_cpu_ms()))


def ingest_mem_need(load: dict, a: argparse.Namespace, vcpu: float) -> float:
    sources_mib = 1024 + VECTOR_MIB_PER_SOURCE * a.log_sources
    return max(16, 2 * vcpu, (VECTOR_MIN_MEM_GIB_AT_VOLUME if load["sized_tb_per_day"] >= 1 else 0) / 0.85 / 0.9,
               sources_mib / 1024 / 0.85 / 0.9)


def colocated_ingest_feasible(load: dict, ch_nodes: int) -> bool:
    return ch_nodes >= 2 and load["_peak_eps"] / (ch_nodes - 1) <= vector_host_eps_ceiling()


def size_ingest(load: dict, a: argparse.Namespace, cat: dict | None, ch_nodes: int, shards: int,
                force: str | None = None) -> dict:
    """Ingest tier. force: None (planner's choice), "colocated" or "dedicated"."""
    peak = load["_peak_eps"]
    ceiling = vector_host_eps_ceiling()
    if force is None:
        colocate = load["_sized_gb"] <= INGEST_COLOCATE_MAX_GB_DAY and ch_nodes >= 2 and not a.dedicated_ingest
    else:
        colocate = force == "colocated"
    if colocate:
        per_host_eps = peak / (ch_nodes - 1)        # one node down: the rest carry the peak
        vcpu = max(2, math.ceil(per_host_eps * vector_cpu_ms() / 1000 / VECTOR_TARGET_UTIL))
        return {"colocated": True, "hosts": ch_nodes, "load_hosts": 1, "vcpu_per_host": round(vcpu, 2),
                "per_host_capacity_eps": ingest_capacity_eps(vcpu),
                "peak_per_host_after_loss_eps": round(per_host_eps), "sku": None,
                "data_disk_gib": None, "ceiling_eps": round(ceiling)}
    per_host_target = min(ceiling, peak)
    vcpu = per_host_target * vector_cpu_ms() / 1000 / VECTOR_TARGET_UTIL
    mem = ingest_mem_need(load, a, vcpu)
    if cat is not None:
        sku = choose_sku(cat, a.cloud, "ingest", max(4, vcpu), mem)
        if sku is None:
            raise PlanError("no ingest size fits; this is a planner bug")
        sku_vcpu, sku_mem = sku["vcpu"], sku["mem_gib"]
    else:
        sku, sku_vcpu, sku_mem = None, max(4, math.ceil(vcpu)), math.ceil(mem)
    capacity = ingest_capacity_eps(sku_vcpu)
    load_hosts = max(1, math.ceil(peak / capacity - 1e-9))
    hosts = max(2, load_hosts + 1)
    if a.ingest_hosts:
        if a.ingest_hosts < hosts:
            raise PlanError(f"--ingest-hosts {a.ingest_hosts} cannot carry the peak with one host down; need {hosts}")
        hosts = a.ingest_hosts
    disk = INGEST_DATA_DISK_MIN_GIB
    while not product_vector_buffer(sku_mem, {"ingest"}, shards, disk)["disk_ok"] or \
            product_vector_buffer(sku_mem, {"ingest"}, shards, disk)["budget_bytes"] + \
            INGEST_IMAGES_GIB * GIB > disk * GIB * 0.8:
        disk += 64
    return {"colocated": False, "hosts": hosts, "load_hosts": load_hosts, "vcpu_per_host": round(vcpu, 2),
            "vcpu_need": max(4, math.ceil(vcpu)), "mem_need_gib": math.ceil(mem),
            "per_host_capacity_eps": round(capacity), "peak_per_host_after_loss_eps": round(peak / (hosts - 1)),
            "sku": sku, "data_disk_gib": disk, "ceiling_eps": round(ceiling)}


# --- App and control ---------------------------------------------------------
def size_app(load: dict, a: argparse.Namespace, cat: dict | None, concurrent: int) -> dict:
    vcpu, mem = APP_AT_VOLUME if load["_sized_gb"] > INGEST_COLOCATE_MAX_GB_DAY else APP_MIN
    vcpu = max(vcpu, 2 + concurrent)               # INFERRED: search service per concurrent query
    mem = max(mem, 2 * vcpu)
    hosts = 2
    if vcpu > APP_MAX_HOST_VCPU:
        load_hosts = math.ceil(vcpu / APP_MAX_HOST_VCPU)
        hosts, vcpu, mem = load_hosts + 1, APP_MAX_HOST_VCPU, 2 * APP_MAX_HOST_VCPU
    if a.app_hosts:
        hosts = max(hosts, a.app_hosts)
    sku = choose_sku(cat, a.cloud, "app", vcpu, mem) if cat is not None else None
    return {"hosts": hosts, "vcpu_need": vcpu, "mem_need_gib": mem, "disk_need_gib": 50, "sku": sku}


def size_control(load: dict, a: argparse.Namespace, cat: dict | None) -> dict:
    for max_gb, vcpu, mem, disk, iops in PG_TIERS:
        if load["_sized_gb"] <= max_gb:
            break
    need_vcpu = vcpu + KEEPER_COLOCATED[0] + HA_STATE_COLOCATED[0]
    need_mem = mem + KEEPER_COLOCATED[1] + HA_STATE_COLOCATED[1]
    sku = choose_sku(cat, a.cloud, "control", need_vcpu, need_mem) if cat is not None else None
    return {"hosts": 3, "pg_vcpu": vcpu, "pg_mem_gib": mem, "vcpu_need": need_vcpu, "mem_need_gib": need_mem,
            "data_disk_gib": disk, "disk_iops": iops, "sku": sku}


# --- Layout -----------------------------------------------------------------------
def node_ip(vpc: ipaddress.IPv4Network, zone_index: int, ordinal: int) -> str:
    subnet = list(vpc.subnets(new_prefix=24))[zone_index + 1]
    return str(subnet.network_address + 10 + ordinal)


def network_plan(vpc_cidr: str, zones: list[str]) -> dict:
    vpc = ipaddress.ip_network(vpc_cidr, strict=True)
    if vpc.prefixlen > 20 or not vpc.is_private:
        raise PlanError("--vpc-cidr must be a private network of /20 or larger")
    subnets = list(vpc.subnets(new_prefix=24))
    # Load-balancer subnets sit inside one aligned /22 (the 9th-12th /24s), so a
    # single CIDR names every LB source address (ingest_endpoint.trusted_cidr
    # takes exactly one CIDR).
    lb_supernet = list(vpc.subnets(new_prefix=22))[2]
    lb_subnets = list(lb_supernet.subnets(new_prefix=24))
    return {
        "vpc_cidr": str(vpc),
        "private_subnets": [{"zone": z, "cidr": str(subnets[i + 1])} for i, z in enumerate(zones)],
        "lb_subnets": [{"zone": z, "cidr": str(lb_subnets[i])} for i, z in enumerate(zones)],
        "lb_supernet": str(lb_supernet),
        "trusted_proxy_cidrs": [str(lb_supernet)],
    }


def build_nodes(a, cat, app, ctl, ch, ing, vpc) -> list[dict]:
    zones = cat["clouds"][a.cloud]["zones"]
    nodes: list[dict] = []
    per_zone = [0, 0, 0]

    disk_specs = cat["clouds"][a.cloud]["disks"]

    def add(kind, name, zone_i, sku, **extra):
        for d in extra.get("disks", []):
            if "iops_month" not in disk_specs.get(d["type"], {}):
                d.pop("iops", None)   # size-scaled or fixed-tier disks take no IOPS/throughput setting
                d.pop("mbps", None)
        if sku is None:
            raise PlanError(f"no {kind} size in the {a.cloud} catalog fits; add a larger SKU to cloud-catalog.json")
        ip = node_ip(vpc, zone_i, per_zone[zone_i])
        per_zone[zone_i] += 1
        nodes.append({"kind": kind, "name": name, "zone": zones[zone_i], "zone_index": zone_i, "address": ip,
                      "instance": sku["name"], "vcpu": sku["vcpu"], "mem_gib": sku["mem_gib"],
                      "usd_hour": sku["usd_hour"], "price_verified": sku["verified"], **extra})

    os_disk = cat["clouds"][a.cloud]["disks"]["os"]
    fam_disk = lambda key: cat["clouds"][a.cloud]["families"][key]["disk"]
    for i in range(app["hosts"]):
        add("app", f"nano-app-{i + 1}", i % 3, app["sku"],
            disks=[{"purpose": "os+docker", "type": os_disk["type"], "size_gib": os_disk["size_gib"]}])
    for i in range(3):
        # PostgreSQL, Keeper, etcd and Valkey all live in Docker volumes on this one provisioned-IOPS disk.
        disks = [{"purpose": "os", "type": os_disk["type"], "size_gib": os_disk["size_gib"]},
                 {"purpose": "docker: postgres+keeper", "type": fam_disk("control"), "size_gib": ctl["data_disk_gib"],
                  "iops": ctl["disk_iops"], "mbps": 250 if ctl["disk_iops"] > 3000 else 125}]
        add("control", f"nano-pg-{i + 1}", i, ctl["sku"], keeper_id=i + 1, disks=disks)
    for s in range(1, ch["shards"] + 1):
        for r in range(1, ch["replicas"] + 1):
            zi = (r - 1 + s - 1) % 3
            disks = [{"purpose": "os", "type": os_disk["type"], "size_gib": os_disk["size_gib"]}]
            if ch["local_nvme"]:
                disks.append({"purpose": "clickhouse+docker (RAID 0 of local NVMe, ephemeral)",
                              "type": "local-nvme", "size_gib": int(ch["sku"]["local_nvme_gb"] * 1e9 / GIB)})
            else:
                disks.append({"purpose": "clickhouse+docker", "type": fam_disk("clickhouse"),
                              "size_gib": ch["data_disk_gib"], "iops": ch["disk_iops"], "mbps": ch["disk_mbps"]})
            add("clickhouse", f"nano-ch-s{s}r{r}", zi, ch["sku"], shard=s, replica=r,
                ingest=ing["colocated"], disks=disks)
    if not ing["colocated"]:
        for i in range(ing["hosts"]):
            add("ingest", f"nano-ingest-{i + 1}", i % 3, ing["sku"],
                disks=[{"purpose": "os", "type": os_disk["type"], "size_gib": os_disk["size_gib"]},
                       {"purpose": "docker + Vector disk buffers", "type": fam_disk("ingest"),
                        "size_gib": ing["data_disk_gib"]}])
    return nodes


def roles_for(node: dict, schema: dict) -> list[str]:
    if "roles" in node:                      # existing-VM layouts carry explicit (possibly stacked) roles
        return list(node["roles"])
    roles = list(schema["roles"][node["kind"]])
    if node["kind"] == "clickhouse" and node.get("ingest"):
        roles = roles + ["ingest"]
    return roles


# --- HA invariant -----------------------------------------------------------------
def ha_failures(hosts: list[dict], peak_eps: float, failed: set[str]) -> list[str]:
    """Return the HA violations when the named hosts are down (empty = survives).

    `hosts` items: name, roles, shard/replica (clickhouse), ingest_capacity_eps.
    """
    alive = [h for h in hosts if h["name"] not in failed]
    problems = []
    keepers = [h for h in hosts if "keeper" in h["roles"]]
    if len([h for h in alive if "keeper" in h["roles"]]) <= len(keepers) // 2:
        problems.append("Keeper quorum lost")
    pgs = [h for h in hosts if "postgres" in h["roles"]]
    if len(pgs) >= 3 and len([h for h in alive if "postgres" in h["roles"]]) <= len(pgs) // 2:
        problems.append("etcd / Sentinel / Patroni quorum lost")
    if not any("postgres" in h["roles"] for h in alive):
        problems.append("no PostgreSQL member left")
    if not any("app" in h["roles"] for h in alive):
        problems.append("no app host left")
    shards = sorted({h["shard"] for h in hosts if "clickhouse" in h["roles"]})
    for s in shards:
        if not any("clickhouse" in h["roles"] and h["shard"] == s for h in alive):
            problems.append(f"ClickHouse shard {s} lost its last replica")
    capacity = sum(h.get("ingest_capacity_eps", 0) for h in alive if "ingest" in h["roles"])
    if capacity + 1e-6 < peak_eps:
        problems.append(f"ingest capacity {capacity:.0f} EPS below the {peak_eps:.0f} EPS peak")
    return problems


def ha_hosts(nodes: list[dict], schema: dict, ing: dict) -> list[dict]:
    out = []
    for n in nodes:
        roles = roles_for(n, schema)
        capacity = n.get("ingest_capacity_eps", ing["per_host_capacity_eps"]) if "ingest" in roles else 0
        out.append({"name": n["name"], "zone": n["zone"], "roles": roles, "shard": n.get("shard"),
                    "ingest_capacity_eps": capacity})
    return out


def ha_report(hosts: list[dict], peak_eps: float, lb: dict | None = None) -> dict:
    node_loss = {h["name"]: ha_failures(hosts, peak_eps, {h["name"]}) for h in hosts}
    zones = sorted({h["zone"] for h in hosts})
    # A zone loss must keep every quorum and replica; ingest capacity after it is reported, not promised.
    zone_loss = {z: ha_failures(hosts, 0, {h["name"] for h in hosts if h["zone"] == z}) for z in zones}
    zone_capacity = {z: round(sum(h["ingest_capacity_eps"] for h in hosts if h["zone"] != z and "ingest" in h["roles"]))
                     for z in zones}
    return {"any_one_node": all(not v for v in node_loss.values()),
            "node_loss_failures": {k: v for k, v in node_loss.items() if v},
            "any_one_zone": all(not v for v in zone_loss.values()),
            "zone_loss_failures": {k: v for k, v in zone_loss.items() if v},
            "zones_known": len(zones) < len(hosts),
            "ingest_capacity_after_zone_loss_eps": min(zone_capacity.values()),
            "zone_loss_carries_peak": min(zone_capacity.values()) >= peak_eps,
            "edge_single_point_of_failure": bool(lb and lb["single_point_of_failure"])}


def ha_reasoning(app, ch, ing, schema, lb: dict, ctl_layout: str = "separate") -> list[dict]:
    multi = schema["multi_app"]
    ctl_where = {"separate": "on 3 dedicated PostgreSQL hosts",
                 "on_app": "on the 2 app hosts plus 1 more host",
                 "on_app_ch": "on the 2 app hosts plus 1 ClickHouse host"}[ctl_layout]
    rows = [
        {"component": "UI / API / search / detections / alerting",
         "choice": (f"{app['hosts']} stateless app hosts in different failure domains behind the load balancer "
                    f"(health check {schema['health_checks']['app']['path']})") if multi else
                   "1 app host (releases before 2.0.7 allow only one)",
         "survives": "loss of any one app host; jobs leadership moves by PostgreSQL lease" if multi else
                     "nothing: the app host is a single point of failure until v2.0.7"},
        {"component": "PostgreSQL metadata",
         "choice": f"3 Patroni members {ctl_where}; etcd on the same 3; synchronous replication (on); "
                   "each app host's postgres-router follows the leader" if schema["multi_postgres"] else
                   "1 PostgreSQL host (releases before 2.0.7)",
         "survives": "loss of any one PostgreSQL host: writes, sign-ins and searches pause for about 20-25 s, up to about 30 s, while a standby is promoted (Patroni's leader timeout is 20 s; measured 20-24 s on a 7-host hard-kill test); a planned switchover pauses a few seconds; no acknowledged write lost" if schema["multi_postgres"] else
                     "nothing: PostgreSQL is a single point of failure until v2.0.7"},
        {"component": "Valkey (sessions, JWT revocations, search jobs)",
         "choice": "one member per PostgreSQL host + 3 Sentinels; each app host's valkey-router follows the master" if multi else
                   "local to the one app host",
         "survives": "loss of any one PostgreSQL host: failover in ~10 s, sign-outs survive" if multi else "-"},
        {"component": "ClickHouse Keeper",
         "choice": "3 members on the PostgreSQL hosts",
         "survives": "loss of any one member (2 of 3 keep quorum); two losses make ClickHouse read-only"},
        {"component": "ClickHouse events",
         "choice": f"{ch['shards']} shard(s) x {ch['replicas']} replicas; each shard's replicas in different failure domains",
         "survives": "loss of any one ClickHouse host: every shard keeps a replica; clickhouse-proxy drops a dead peer in ~2 s"},
        {"component": "Ingest",
         "choice": (f"{ing['hosts']} ingest hosts (peak needs {ing['load_hosts']}, so N+1)" if not ing["colocated"]
                    else f"ingest on all {ing['hosts']} ClickHouse hosts"),
         "survives": "loss of any one ingest host at peak-hour load; Vector disk buffers ride out short ClickHouse "
                     "stalls; ingest stays ready through an API/PostgreSQL outage of up to 300 s"},
        {"component": "Load balancer", "choice": lb["summary"], "survives": lb["survives"]},
        {"component": "Cold tier and backups", "choice": "S3-compatible object storage or a shared NFS path, off the nano hosts",
         "survives": "loss of any nano host; every app host runs the backup scheduler and exactly one takes each slot"},
    ]
    return rows


# --- Tuning -----------------------------------------------------------------------
def product_clickhouse_cores(vcpu: int, roles: set[str]) -> int:
    """ClickHouse's CPU share on a host, as resource-sizing.sh computes it."""
    weights = {"clickhouse": 55, "postgres": 12, "ingest": 13, "app": 20, "keeper": 5}
    total = sum(w for r, w in weights.items() if r in roles)
    others = sum(max(vcpu * 1000 * w // total, 250) for r, w in weights.items() if r in roles and r != "clickhouse")
    return min(max(math.ceil((vcpu * 1000 - others) / 1000), 2), 64)


def installer_ch_defaults(cores: int, ch_mib: int) -> dict:
    if ch_mib <= 4096:
        return {"insert": 20, "total": 50, "select": 30, "pool": 2, "ratio": 2, "ingest_mem_mib": 384}
    return {"insert": min(max(cores * 8, 20), 512), "total": min(max(cores * 25, 50), 1600),
            "select": min(max(cores * 19, 30), 1200), "pool": min(max(cores * 2, 4), 64),
            "ratio": 4 if cores >= 8 else 2, "ingest_mem_mib": min(max(ch_mib * 20 // 100, 384), 32768)}


def tuning(load, ch, ing, nodes, schema) -> tuple[dict, list[dict]]:
    """Return (per-kind inventory overrides, tuning report rows)."""
    rows: list[dict] = []
    overrides: dict[str, dict] = {"clickhouse": {}, "ingest": {}}
    ch_nodes = [n for n in nodes if "clickhouse" in roles_for(n, schema)]
    # The smallest ClickHouse host sets the installer default the override must beat.
    ch_node = min(ch_nodes, key=lambda n: (n["vcpu"], n["mem_gib"]))
    roles = set(roles_for(ch_node, schema))
    ch_mib = product_split_mib(ch_node["mem_gib"], roles)["clickhouse"]
    d = installer_ch_defaults(product_clickhouse_cores(ch_node["vcpu"], roles), ch_mib)
    ingest_hosts = sum(1 for n in nodes if "ingest" in roles_for(n, schema))
    inflight = ingest_hosts * VECTOR_SINKS_PER_SHARD * VECTOR_REQUEST_CONCURRENCY + 50
    want_insert = ceil_to(inflight * 1.5, 50)
    if want_insert > d["insert"]:
        val = min(want_insert, 1000)
        overrides["clickhouse"]["CLICKHOUSE_MAX_CONCURRENT_INSERT_QUERIES"] = val
        rows.append({"setting": "CLICKHOUSE_MAX_CONCURRENT_INSERT_QUERIES", "value": val, "default": d["insert"],
                     "applied": "inventory resources.overrides (ClickHouse hosts)", "topic": "insert concurrency",
                     "source": "INFERRED from in-flight inserts; ceiling 1000 is MEASURED-external",
                     "why": f"{ingest_hosts} ingest hosts x {VECTOR_SINKS_PER_SHARD} sinks x concurrency {VECTOR_REQUEST_CONCURRENCY} + app = ~{inflight} in flight per shard"})
        if want_insert > 1000:
            rows.append({"setting": "insert in-flight above 1000", "value": inflight, "applied": "warning",
                         "topic": "insert concurrency", "source": "MEASURED-external", "why": "beyond the largest ceiling measured; add shards or wait for per-user caps"})
        total = max(d["total"], val + d["select"] + 100)
        if total > d["total"]:
            overrides["clickhouse"]["CLICKHOUSE_MAX_CONCURRENT_QUERIES"] = min(total, 4000)
            rows.append({"setting": "CLICKHOUSE_MAX_CONCURRENT_QUERIES", "value": min(total, 4000), "default": d["total"],
                         "applied": "inventory resources.overrides (ClickHouse hosts)", "topic": "insert concurrency",
                         "source": "INFERRED; must exceed insert + select; 4000 is MEASURED-external",
                         "why": "server ceiling above the sum of insert and select ceilings"})
    if ch["shard_tb_per_day"] >= 1 and d["pool"] * d["ratio"] > 32:
        overrides["clickhouse"]["CLICKHOUSE_BACKGROUND_POOL_SIZE"] = 16
        overrides["clickhouse"]["CLICKHOUSE_BACKGROUND_MERGES_MUTATIONS_CONCURRENCY_RATIO"] = 2
        rows.append({"setting": "CLICKHOUSE_BACKGROUND_POOL_SIZE x RATIO", "value": "16 x 2 = 32 merge slots",
                     "default": f"{d['pool']} x {d['ratio']} = {d['pool'] * d['ratio']}",
                     "applied": "inventory resources.overrides (ClickHouse hosts)", "topic": "merge capacity",
                     "source": "MEASURED-external: 32 slots kept up at 16 TB/day on 64 cores",
                     "why": "unbounded merges on a 108-113-index table, with no memory soft limit yet"})
    if load["sized_tb_per_day"] >= 1 and d["ingest_mem_mib"] < 16384:
        overrides["clickhouse"]["CLICKHOUSE_INGEST_MAX_MEMORY_USAGE"] = 16 * GIB
        rows.append({"setting": "CLICKHOUSE_INGEST_MAX_MEMORY_USAGE", "value": "16 GiB",
                     "default": f"{d['ingest_mem_mib']} MiB", "applied": "inventory resources.overrides (ClickHouse hosts)",
                     "topic": "async-insert flushes", "source": "MEASURED-external: an async flush runs under the first query's limit and needed ~4-16 GB",
                     "why": "large async-insert flushes fan out to 23+ MVs"})
    rows.append({"setting": "VECTOR_CLICKHOUSE_REQUEST_CONCURRENCY", "value": VECTOR_REQUEST_CONCURRENCY,
                 "default": VECTOR_REQUEST_CONCURRENCY, "applied": "keep the default", "topic": "Vector delivery",
                 "source": "MEASURED-external: 6 held at 16 TB/day, 16 wedged production",
                 "why": "raise hosts, not concurrency"})
    pending = [
        ("ingest workload max_concurrent_threads", ">= 2 x cores (today fixed at 4)", "ingest workload threads", load["_peak_eps"] > NANO_VALIDATED_EPS,
         "MEASURED-external: a 48-lease cap stalled flushes for 30 min"),
        ("per-user insert caps (Vector, direct OCSF, app, rawsql)", "Vector ~ in-flight x 1.25; server ceiling above the sum", "insert concurrency",
         load["sized_tb_per_day"] >= 1, "MEASURED-external: per-user caps 200 / 512 were the fail-fast layer"),
        ("async_insert_busy_timeout_ms / async_insert_max_data_size", "5000 ms (adaptive 1000-10000) / 256 MiB", "async-insert flushes",
         load["sized_tb_per_day"] >= 1, "MEASURED-external: 5 s timer; a 5 s -> 2 s change doubled POST latency"),
        ("max_compress_block_size", "64 KiB on every delivery path", "async-insert flushes", load["sized_tb_per_day"] >= 1,
         "nano-measured: 1.23 GiB -> 176 MiB per 20k-row insert"),
        ("merges_mutations_memory_usage_soft_limit, per-table merge cap", "~25 % of RAM; 32 GiB", "merge capacity",
         ch["shard_tb_per_day"] >= 1, "MEASURED-external: 16 GiB soft limit, 32/8/1 GiB per-table caps"),
        ("sink acknowledgements, DLQ, delete_failed_message=false", "on for pull lanes", "Vector delivery",
         True, "nano-measured: acks off today; a 200 means 'in Vector's disk buffer'"),
        ("Vector role split (N readers per host)", f"~{VECTOR_HOST_EPS_ROLE_SPLIT_REF // int(NANO_VECTOR_PIPELINE_FACTOR)} ev/s per 32-vCPU host after the split",
         "Vector role split", not ing["colocated"] and ingest_hosts > 4, "MEASURED-external: 9 readers ~50k ev/s per 32-vCPU VM"),
        ("TTL-driven tiering (TO VOLUME cold)", f"move after {ch['hot_days']} d", "TTL tiering", ch["cold_days"] > 0,
         "nano-measured config: today tiering is free-space driven (move_factor 0.3)"),
    ]
    for setting, value, topic, applies, source in pending:
        if applies:
            rows.append({"setting": setting, "value": value, "applied": "not settable from the inventory yet",
                         "topic": topic, "source": source, "why": "needed at this volume"})
    return overrides, rows


# --- Cost ---------------------------------------------------------------------------
def disk_month(cat: dict, cloud: str, disk: dict) -> tuple[float, bool]:
    if disk["type"] == "local-nvme":
        return 0.0, True
    spec = cat["clouds"][cloud]["disks"][disk["type"]]
    if "fixed" in spec:
        tiers = sorted(spec["fixed"].values(), key=lambda t: t["size_gib"])
        n = 0
        for t in tiers:
            if disk["size_gib"] <= t["size_gib"]:
                return t["month"], spec["verified"]
        big = tiers[-1]
        n = math.ceil(disk["size_gib"] / big["size_gib"])
        return n * big["month"], False
    cost = disk["size_gib"] * spec["gb_month"]
    if "iops_month" in spec:
        cost += max(0, disk.get("iops", spec["free_iops"]) - spec["free_iops"]) * spec["iops_month"]
        cost += max(0, disk.get("mbps", spec["free_mbps"]) - spec["free_mbps"]) * spec["mbps_month"]
    return cost, spec["verified"]


def cost_estimate(cat: dict, a, load, ch, nodes) -> dict:
    c = cat["clouds"][a.cloud]
    hours = cat["hours_per_month"]
    unverified: list[str] = []
    compute = sum(n["usd_hour"] * hours for n in nodes)
    for n in nodes:
        if not n["price_verified"] and n["instance"] not in unverified:
            unverified.append(n["instance"])
    disks = 0.0
    for n in nodes:
        for d in n["disks"]:
            m, ok = disk_month(cat, a.cloud, d)
            disks += m
            if not ok and d["type"] not in unverified:
                unverified.append(d["type"])
    backup_gib = 50
    obj = (ch["cold_object_storage_gib"] + backup_gib) * c["object_storage"]["gb_month"]
    lb = c["load_balancer"]
    gb_month = load["_sized_gb"] * 30.4
    lbs = 2 * lb["usd_hour"] * hours + gb_month * lb["usd_per_gb_processed"]
    if not c["object_storage"].get("s3_compatible", True) and ch["cold_object_storage_gib"]:
        unverified.append("cold tier: " + c["object_storage"]["note"])
    if not lb["verified"]:
        unverified.append("load balancer: " + lb["note"])
    iz = c["inter_zone"]
    compressed_gb_day = load["_sized_gb"] / a.compression
    # INFERRED traffic model: ingest->ClickHouse inserts (gzip ~ compressed size, 2/3 cross-zone),
    # replication to the other replicas, and LB -> ingest cross-zone (2/3 of raw).
    iz_gb_day = compressed_gb_day * (2 / 3) + compressed_gb_day * (ch["replicas"] - 1) + load["_sized_gb"] * (2 / 3)
    inter_zone = iz_gb_day * 30.4 * iz["usd_per_gb"] * (2 if iz["both_directions"] else 1)
    if not iz["verified"]:
        unverified.append("inter-zone transfer: " + iz["note"])
    low = compute + disks + obj + lbs + inter_zone
    lines = [
        {"item": f"compute ({len(nodes)} VMs, on-demand)", "usd_month": round(compute)},
        {"item": "block storage (OS + data disks)", "usd_month": round(disks)},
        {"item": f"{c['object_storage']['name']}: {ch['cold_object_storage_gib']:,} GiB cold tier + {backup_gib} GiB backups", "usd_month": round(obj)},
        {"item": "load balancers (2) + data processed", "usd_month": round(lbs)},
        {"item": "cross-zone traffic (inserts, replication, LB) INFERRED model", "usd_month": round(inter_zone)},
    ]
    replica_cost = sum(n["usd_hour"] * hours for n in nodes if n["kind"] == "clickhouse" and n.get("replica", 1) > 1)
    return {"label": "ESTIMATE, not a quote", "as_of": cat["as_of"], "currency": cat["currency"],
            "basis": cat["basis"], "reference_region": c["region"],
            "region_note": None if a.region in (None, c["region"]) else f"prices are for {c['region']}; {a.region} differs (unverified)",
            "low_usd_month": round(low, -1), "high_usd_month": round(low * 1.25, -1),
            "high_note": "high end adds 25 % for snapshots, NAT/egress, monitoring and price drift (INFERRED)",
            "lines": lines, "clickhouse_extra_replicas_usd_month": round(replica_cost),
            "unverified": unverified,
            "excludes": "commitment discounts, support plans, license fees, taxes, internet egress to senders"}


# --- Port matrix -------------------------------------------------------------------
def port_matrix(schema: dict) -> list[dict]:
    rows = []
    for role, keys in ROLE_PORTS.items():
        for key in keys:
            rows.append({"port": PORT_DEFAULTS[key], "key": key, "on": role, "from": list(PORT_SOURCES[key]),
                         "proto": "tcp", "status": "always"})
    if schema["multi_postgres"]:
        for key in HA_PORTS:
            when = "2+ app hosts" if key in ("valkey", "sentinel") else "3 postgres hosts"
            rows.append({"port": PORT_DEFAULTS[key], "key": key, "on": "postgres", "from": list(PORT_SOURCES[key]),
                         "proto": "tcp", "status": f"full HA ({when})"})
    rows.append({"port": 22, "key": "ssh", "on": "all", "from": ["management CIDR", "app"], "proto": "tcp",
                 "status": "always (the first app host runs scripts/nano upgrade over SSH)"})
    return rows


ROLE_HOSTS = {"app": "app hosts", "ingest": "ingest hosts", "postgres": "PostgreSQL hosts",
              "clickhouse": "ClickHouse hosts", "keeper": "Keeper hosts (= PostgreSQL hosts)",
              "lb:app": "app load balancer", "lb:ingest": "ingest load balancer"}


def port_matrix_markdown(schema: dict) -> str:
    out = ["| Port | Key | On | Allow from | When |", "|---|---|---|---|---|"]
    for r in port_matrix(schema):
        src = ", ".join(ROLE_HOSTS.get(s, s) for s in r["from"])
        out.append(f"| {r['port']}/{r['proto']} | `{r['key']}` | {ROLE_HOSTS.get(r['on'], r['on'])} | {src} | {r['status']} |")
    return "\n".join(out)


# Firewall groups: one per VM kind plus the two load balancers. Keeper and
# PostgreSQL share the control VMs, so they share a group. A VM joins the group
# of every role it runs (stacked layouts join several).
FIREWALL_GROUP = {"app": "app", "ingest": "ingest", "postgres": "control", "keeper": "control",
                  "clickhouse": "clickhouse", "lb:app": "lb-app", "lb:ingest": "lb-ingest",
                  "management CIDR": "mgmt", "all": "all"}


def firewall_rules(schema: dict) -> list[tuple[int, str, str, str, str]]:
    """(port, target group, source group, key, when), deduplicated and sorted."""
    rules = set()
    for r in port_matrix(schema):
        targets = ["app", "ingest", "control", "clickhouse"] if r["on"] == "all" else [FIREWALL_GROUP[r["on"]]]
        for target in targets:
            for src in r["from"]:
                source = FIREWALL_GROUP[src]
                if r["on"] == "all" and source == target and source != "mgmt":
                    continue
                rules.add((r["port"], target, source, r["key"], r["status"].split(" (")[0]))
    return sorted(rules, key=lambda x: (x[1], x[0], x[2]))


def print_firewall_tsv(schema: dict) -> None:
    print("port\ttarget\tsource\tkey\twhen")
    for rule in firewall_rules(schema):
        print("\t".join(str(v) for v in rule))


# --- preflight thresholds -----------------------------------------------------
LB_HOST = (2, 2, 10)   # INFERRED: a dedicated HAProxy VM (vCPU, GB, GiB)


def role_floor(roles: set[str]) -> tuple[int, int, int]:
    """Volume-independent minimum (vCPU, nominal GB, disk GiB) for a host's roles.

    preflight.sh's role-split defaults are these numbers (a test compares them),
    summed the way host_slots() stacks role groups.
    """
    cpu = mem = disk = 0
    def add(c, m, d):
        nonlocal cpu, mem, disk
        cpu, mem, disk = cpu + c, mem + m, disk + d
    if "clickhouse" in roles:
        add(CH_MIN_VCPU, CH_MIN_MEM_GIB, CH_EXTRA_GIB)
        if "ingest" in roles:      # co-located ingest: at least 2 vCPU (size_ingest)
            add(2, 0, 0)
    if "postgres" in roles:        # smallest PG tier + Keeper + etcd/Valkey/Sentinel/HAProxy
        add(PG_TIERS[0][1] + KEEPER_COLOCATED[0] + HA_STATE_COLOCATED[0],
            PG_TIERS[0][2] + KEEPER_COLOCATED[1] + HA_STATE_COLOCATED[1], PG_TIERS[0][3])
    if "app" in roles:
        add(APP_MIN[0], APP_MIN[1], 50)
    if "ingest" in roles and "clickhouse" not in roles:
        add(4, 16, INGEST_DATA_DISK_MIN_GIB)
    if "keeper" in roles and not roles & {"postgres", "clickhouse"}:
        add(*KEEPER_COLOCATED, 0)
    if cpu == 0:
        add(*(LB_HOST if "lb" in roles else (APP_MIN[0], APP_MIN[1], 50)))
    return cpu, mem, disk


def reported_gib(nominal_gb: float) -> int:
    """The RAM preflight must see for a nominal size (MEM_REPORTED_FACTOR), as an integer GiB."""
    return int(math.floor(nominal_gb * MEM_REPORTED_FACTOR + 1e-9))


def preflight_args(p: dict, schema: dict) -> list[tuple[str, str, str]]:
    """(host, address, preflight.sh flags) for every host: each host's own requirement in this plan."""
    nodes = p["nodes"]
    lb_hosts = p["load_balancer"].get("lb_hosts", [])
    rows = []
    for n in nodes:
        roles = roles_for(n, schema) + (["lb"] if n["address"] in lb_hosts else [])
        if "requirement" in n:                       # existing hosts: the slot the planner placed here
            cpu, mem, disk = n["requirement"]
        else:                                        # new cloud VMs: the instance and data disk it picked
            data = [d for d in n["disks"] if not d["purpose"].startswith("os")]
            cpu, mem, disk = n["vcpu"], n["mem_gib"], data[0]["size_gib"] if data else 0
        peers = ",".join(m["address"] for m in nodes if m is not n)
        flags = (f"--topology ha --roles {','.join(roles)} --peers {peers} --min-cpu {math.ceil(cpu - 1e-9)} "
                 f"--min-mem-gib {reported_gib(mem)} --min-disk-size-gib {math.ceil(disk - 1e-9)}")
        rows.append((n["name"], n["address"], flags + (" --lab" if p.get("lab") else "")))
    for addr in lb_hosts:
        if addr not in {n["address"] for n in nodes}:
            cpu, mem, disk = LB_HOST
            rows.append((f"haproxy-{addr}", addr, f"--topology ha --roles lb --min-cpu {cpu} "
                         f"--min-mem-gib {reported_gib(mem)} --min-disk-size-gib {disk}"))
    return rows


# Docker-published (bridge) ports: UFW/INPUT does not see them, so they are
# filtered in DOCKER-USER. ClickHouse and Keeper use host networking, so UFW
# covers them. Mirrors deploy/compose/docker-compose.enterprise.yml.
BRIDGE_PORT_KEYS = ("app", "api_internal", "vector_tap", "postgres", "patroni_api", "etcd_client", "etcd_peer",
                    "valkey", "sentinel")
HOST_PORT_KEYS = ("clickhouse_http", "clickhouse_native", "clickhouse_interserver", "clickhouse_metrics",
                  "keeper_client", "keeper_raft")
DOCKER_FIREWALL_BIN = "/usr/local/sbin/nano-docker-firewall"
DOCKER_FIREWALL_UNIT = "nano-docker-firewall.service"


def _is_v6(addr: str) -> bool:
    return ipaddress.ip_network(addr, strict=False).version == 6


def docker_firewall_rules(peers: list[str], lb: list[str], ports: list[int]) -> str:
    """The DOCKER-USER program, live-tested on Docker 29 / Ubuntu 24.04.

    Drops only NEW connections to a published port that arrive from outside
    this host and from outside the cluster. Never touched: replies
    (ESTABLISHED/RELATED), loopback, this host's containers (docker0, br-*),
    whether they talk to each other or connect out on the same port numbers,
    and the cluster's own hosts. RETURN (not ACCEPT) hands everything else
    back to Docker's own rules. iptables-restore --noflush replaces the
    NANO-DOCKER chain atomically, so a re-run never opens a gap.
    """
    v4 = lambda xs: " ".join(x for x in xs if not _is_v6(x))   # noqa: E731
    v6 = lambda xs: " ".join(x for x in xs if _is_v6(x))       # noqa: E731
    return f"""#!/bin/sh
# nano: filter NEW inbound connections to Docker-published ports.
# Generated by nano-deploy plan.py --firewall-script; regenerate it, don't hand-edit.
# Applied by {DOCKER_FIREWALL_UNIT} at boot (before Docker) and after every Docker start.
set -eu
PORTS="{' '.join(str(x) for x in ports)}"
PEERS4="{v4(peers)}"
PEERS6="{v6(peers)}"
LB4="{v4(lb)}"
LB6="{v6(lb)}"
chain() {{ # chain <peers> <lb>: the NANO-DOCKER chain as iptables-restore input
  echo "*filter"
  echo ":NANO-DOCKER - [0:0]"
  echo "-A NANO-DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  for i in lo docker0 br-+; do echo "-A NANO-DOCKER -i $i -j RETURN"; done
  for s in $1; do echo "-A NANO-DOCKER -s $s -j RETURN"; done
  for s in $2; do echo "-A NANO-DOCKER -s $s -p tcp -m conntrack --ctorigdstport 80 -j RETURN"; done
  for p in $PORTS; do echo "-A NANO-DOCKER -p tcp -m conntrack --ctstate NEW --ctorigdstport $p -j DROP"; done
  echo "COMMIT"
}}
apply() {{ # apply <iptables|ip6tables> <peers> <lb>
  $1 -w -N DOCKER-USER 2>/dev/null || true
  chain "$2" "$3" | "$1-restore" -w --noflush
  $1 -w -C DOCKER-USER -j NANO-DOCKER 2>/dev/null || $1 -w -I DOCKER-USER 1 -j NANO-DOCKER
}}
apply iptables "$PEERS4" "$LB4"
if command -v ip6tables >/dev/null 2>&1 && ip6tables -w -S >/dev/null 2>&1; then
  apply ip6tables "$PEERS6" "$LB6"
fi
"""


DOCKER_FIREWALL_UNIT_TEXT = f"""[Unit]
Description=nano: filter inbound connections to Docker-published ports (DOCKER-USER)
Documentation={FIREWALL_DOC}
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={DOCKER_FIREWALL_BIN}

[Install]
WantedBy=multi-user.target
"""

# Docker keeps DOCKER-USER across restarts today; the drop-in re-asserts the
# chain after every Docker start anyway, so an upgrade that changes that can't
# silently reopen the ports. "-": a failed re-apply never stops Docker.
DOCKER_FIREWALL_DROPIN_TEXT = f"""[Service]
ExecStartPost=-{DOCKER_FIREWALL_BIN}
"""


OPEN_TO_ALL = {"0.0.0.0/0", "::/0"}


def edge_sources(p: dict, cidrs: list[str] | None) -> list[str]:
    """Who may reach 443 on the HAProxy hosts (never the whole internet by default)."""
    if not p["load_balancer"].get("lb_hosts"):
        return []
    if not cidrs:
        raise PlanError(
            "--firewall-script with HAProxy hosts needs --edge-source-cidr CIDR (repeatable): the networks your "
            "users and log senders connect from (office LAN, VPN, sender subnets). HAProxy binds 443 for both "
            "hostnames; the script opens 443 only to these sources. To open 443 to the whole internet, pass "
            "--edge-source-cidr 0.0.0.0/0 explicitly.")
    out: list[str] = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise PlanError(f"--edge-source-cidr {cidr!r} is not an IP network (e.g. 10.20.0.0/16 or 203.0.113.7/32)")
        if str(net) not in out:
            out.append(str(net))
    return out


def firewall_script(p: dict, schema: dict, edge_cidrs: list[str] | None = None) -> str:
    """Ready-to-paste host firewall for this plan: the same script on every nano host."""
    edge = edge_sources(p, edge_cidrs)
    nodes = p["nodes"]
    by_role: dict[str, list[str]] = {}
    for n in nodes:
        for r in roles_for(n, schema):
            by_role.setdefault(r, []).append(n["address"])
    peers: list[str] = []
    for n in nodes:
        if n["address"] not in peers:
            peers.append(n["address"])
    lb_hosts = p["load_balancer"].get("lb_hosts", [])
    for addr in peers + lb_hosts + list(p["network"]["trusted_proxy_cidrs"]):
        try:
            ipaddress.ip_network(addr, strict=False)
        except ValueError:
            raise PlanError(f"--firewall-script needs IP addresses, not hostnames: {addr!r}. "
                            "Firewall rules match packets by address; list each host's private IP in --hosts.")
    lb_sources = [c for c in p["network"]["trusted_proxy_cidrs"] if c.split("/")[0] not in peers]
    src = {"lb:app": lb_sources, "lb:ingest": lb_sources}
    for role in ("app", "ingest", "postgres", "clickhouse", "keeper"):
        src[role] = by_role.get(role, [])

    def sources(key: str) -> list[str]:
        out: list[str] = []
        for s in PORT_SOURCES[key]:
            for addr in src.get(s, []):
                if addr not in out:
                    out.append(addr)
        return out
    # Every bridge port, HA or not: a DROP for a port nothing publishes is harmless.
    ports = sorted({PORT_DEFAULTS[k] for k in BRIDGE_PORT_KEYS})
    host_ports = ",".join(str(PORT_DEFAULTS[k]) for k in HOST_PORT_KEYS)
    lines = ["#!/usr/bin/env bash",
             "# nano host firewall, generated by nano-deploy plan.py. Run the SAME script on every nano host",
             "# and every HAProxy host.",
             f"# Why and how: {FIREWALL_DOC}",
             "# 1. Docker-published ports bypass UFW/INPUT: they are filtered in DOCKER-USER by",
             f"#    {DOCKER_FIREWALL_BIN}, which {DOCKER_FIREWALL_UNIT} re-applies at boot and after every",
             "#    Docker start. It drops only NEW connections from outside this host and outside the cluster;",
             "#    this host's containers (to each other, and outbound on any port) are never filtered.",
             "# 2. Host-networked ClickHouse and Keeper ports: UFW, with SSH allowed first.",
             "# Do NOT install iptables-persistent/netfilter-persistent: on Debian/Ubuntu it uninstalls ufw,",
             "# and it saves Docker's own per-container rules. Re-run this script after any address change.",
             "# Don't use the inventory's bind_address for this: the installer health-checks localhost.",
             "# MGMT_CIDR is where you SSH from; the script stops before changing anything without it (no lock-out).",
             "set -euo pipefail",
             'MGMT_CIDR="${MGMT_CIDR:?set MGMT_CIDR to the network you SSH from, e.g. MGMT_CIDR=203.0.113.0/24}"',
             "command -v ufw >/dev/null || { echo 'ufw not found. This script targets Debian/Ubuntu with ufw. On RHEL"
             " (firewalld), install the DOCKER-USER part below as-is and express the ufw rules as firewalld rich"
             f" rules: {FIREWALL_DOC}' >&2; exit 1; }}",
             "if sudo docker info >/dev/null 2>&1; then",
             "  backend=$(sudo docker info --format '{{.FirewallBackend.Driver}}' 2>/dev/null || echo iptables)",
             '  [ "$backend" = iptables ] || { echo "Docker firewall backend is $backend: DOCKER-USER is not used;'
             ' set firewall-backend iptables in /etc/docker/daemon.json" >&2; exit 1; }',
             "else",
             "  echo 'Docker is not running: DOCKER-USER is created now and Docker hooks it in when it starts.' >&2",
             "fi",
             "this_host() { ip -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -qxF \"$1\"; }"]
    if p.get("lab"):
        lines.insert(1, f"# {LAB_BANNER}")
    rules = docker_firewall_rules(peers, lb_sources, ports)
    lines += [f"sudo tee {DOCKER_FIREWALL_BIN} >/dev/null <<'NANO_DOCKER_FIREWALL'",
              rules.rstrip("\n"),
              "NANO_DOCKER_FIREWALL",
              f"sudo chmod 0755 {DOCKER_FIREWALL_BIN}",
              f"sudo tee /etc/systemd/system/{DOCKER_FIREWALL_UNIT} >/dev/null <<'NANO_DOCKER_FIREWALL_UNIT'",
              DOCKER_FIREWALL_UNIT_TEXT.rstrip("\n"),
              "NANO_DOCKER_FIREWALL_UNIT",
              "sudo mkdir -p /etc/systemd/system/docker.service.d",
              "sudo tee /etc/systemd/system/docker.service.d/nano-docker-firewall.conf >/dev/null <<'NANO_DOCKER_DROPIN'",
              DOCKER_FIREWALL_DROPIN_TEXT.rstrip("\n"),
              "NANO_DOCKER_DROPIN",
              "sudo systemctl daemon-reload",
              f"sudo systemctl enable {DOCKER_FIREWALL_UNIT}",
              f"sudo systemctl restart {DOCKER_FIREWALL_UNIT}   # applies now; re-running the script updates the rules",
              "# Host-networked ClickHouse and Keeper ports: UFW with a default deny. SSH first, so you keep access.",
              'sudo ufw allow from "$MGMT_CIDR" to any port 22 proto tcp']
    first_app = by_role.get("app", [])[:1]
    for addr in first_app:
        lines.append(f"sudo ufw allow from {addr} to any port 22 proto tcp   # first app host runs scripts/nano upgrade")
    lines.append("sudo ufw default deny incoming")
    for key in HOST_PORT_KEYS:
        for addr in sources(key):
            lines.append(f"sudo ufw allow from {addr} to any port {PORT_DEFAULTS[key]} proto tcp")
    # This host's own containers reach the host-networked ports (e.g. the app
    # host's clickhouse-proxy on a stacked host), and a container reaching a
    # published port on its own host's address over its own network is
    # answered by docker-proxy on INPUT. Both arrive from a bridge address.
    lines.append("# This host's own containers: host-networked ports, and published ports via this host's address.")
    for ifc in ("docker0", "br-+"):
        for plist in (host_ports, ",".join(str(x) for x in ports)):
            lines.append(f"sudo ufw allow in on {ifc} to any port {plist} proto tcp")
    if lb_hosts:
        # HAProxy is a host service (INPUT/UFW, not Docker): it binds 443 for
        # both hostnames. Run this script on the HAProxy hosts too.
        lines.append("# HAProxy hosts: users and senders reach the front door on 443 (both hostnames),")
        lines.append(f"# only from --edge-source-cidr: {' '.join(edge)}")
        if OPEN_TO_ALL & set(edge):
            lines.append("# WARNING: 443 is open to the whole internet (--edge-source-cidr 0.0.0.0/0 was given).")
        vrrp = p["load_balancer"].get("vip") is not None
        for addr in lb_hosts:
            others = [o for o in lb_hosts if o != addr]
            lines.append(f"if this_host {addr}; then")
            # An earlier script opened 443 to every source; drop that rule (ufw
            # removes its IPv4 and IPv6 forms together) before the scoped ones.
            lines.append("  sudo ufw --force delete allow 443/tcp >/dev/null 2>&1 || true")
            for cidr in edge:
                lines.append(f"  sudo ufw allow from {cidr} to any port 443 proto tcp")
            if vrrp:
                for o in others:
                    lines.append(f"  sudo ufw allow from {o} proto vrrp   # keepalived peer; without it both claim the VIP")
            lines.append("fi")
    lines += ["sudo ufw --force enable",
              f"sudo iptables -S NANO-DOCKER   # the applied DOCKER-USER rules",
              "# Then, from a machine OUTSIDE the cluster: preflight.sh --exposure-probe <every host address>"]
    return "\n".join(lines) + "\n"


# --- Inventory -----------------------------------------------------------------------
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def host_id(cluster: str, name: str) -> str:
    hid = f"{cluster}-{name.removeprefix('nano-')}"
    if not ID_RE.match(hid):
        raise PlanError(f"host id {hid!r} is not valid; use a shorter --cluster-name or host name")
    return hid


def render_inventory(plan: dict, a: argparse.Namespace, schema_name: str) -> str:
    schema = schema_for(schema_name)
    for label, value in (("cluster-name", a.cluster_name), ("deployment-id", a.deployment_id)):
        if not ID_RE.match(value):
            raise PlanError(f"--{label} must match {ID_RE.pattern}")
    if a.app_hostname == a.ingest_hostname:
        raise PlanError("--app-hostname and --ingest-hostname must differ")
    nodes = plan["nodes"]
    where = f"cloud {plan['input']['cloud']}" if plan["input"]["cloud"] else "existing hosts"
    lines = ([f"# {LAB_BANNER}", "# Evaluation and functional tests only. Shortfalls:"]
             + [f"#   {s}" for s in (plan["lab"]["shortfalls"] or plan["lab"]["clickhouse_constraints"])]
             if plan.get("lab") else [])
    lines += [f"# nano role-split inventory generated by nano-deploy plan.py (plan v{PLAN_VERSION}).",
             f"# {where}, {plan['load']['sized_gb_per_day']} GB/day sized, "
             f"{plan['clickhouse']['shards']} shard(s) x {plan['clickhouse']['replicas']} replicas.",
             f"# Schema: {schema_name}" + (f" (needs nano {schema['release']} or newer)" if schema["release"] else
                                          " (releases before 2.0.7: one app and one postgres host)"),
             "# Same bytes on every host at /etc/nano/inventory.yaml (installer user, mode 0600).",
             "# Never change deployment_id, host names/ids, roles or shard/replica after the first install.",
             "version: 1", "cluster:", f"  name: {a.cluster_name}", f"  deployment_id: {a.deployment_id}",
             "  tls:", f"    cert: {a.tls_dir}/server.crt", f"    key: {a.tls_dir}/server.key",
             f"    ca: {a.tls_dir}/ca.crt", f"    server_name: {a.tls_server_name}",
             f"  trusted_proxy_cidrs: [{', '.join(plan['network']['trusted_proxy_cidrs'])}]",
             f"  app_hostname: {a.app_hostname}", f"  ingest_hostname: {a.ingest_hostname}"]
    if schema["postgres_ha"]:
        lines += ["  postgres_ha:"] + [f"    {k}: {v}" for k, v in schema["postgres_ha"].items()]
    if a.ingest_lb_address:
        if not a.ingest_lb_tls_name:
            raise PlanError("--ingest-lb-address needs --ingest-lb-tls-name (a name in a certificate that chains to cluster.tls.ca)")
        if not plan["network"].get("lb_supernet"):
            raise PlanError("--ingest-lb-address needs a cloud plan (its trusted CIDR is the planned LB subnet)")
        lines += ["load_balancer:", "  ingest_endpoint:", f"    address: {a.ingest_lb_address}",
                  f"    tls_name: {a.ingest_lb_tls_name}", f"    trusted_cidr: {plan['network']['lb_supernet']}"]
    lines.append("hosts:")
    skipped = []
    seen_app = seen_pg = False
    for n in nodes:
        roles = roles_for(n, schema)
        if not schema["multi_app"] and "app" in roles:
            if seen_app:
                roles = [r for r in roles if r != "app"]
            seen_app = True
        if not schema["multi_postgres"] and "postgres" in roles:
            if seen_pg:
                roles = [r for r in roles if r != "postgres"]
            seen_pg = True
        if not roles:
            skipped.append(n["name"])
            continue
        lines += [f"  - name: {n['name']}", f"    id: {host_id(a.cluster_name, n['name'])}",
                  f"    address: {n['address']}", f"    roles: [{', '.join(roles)}]"]
        if "clickhouse" in roles:
            lines.append(f"    clickhouse: {{\"shard\": {n['shard']}, \"replica\": {n['replica']}}}")
        if "keeper" in roles:
            lines.append(f"    keeper: {{\"id\": {n['keeper_id']}}}")
        ov = {}
        if "clickhouse" in roles:
            ov.update(plan["overrides"]["clickhouse"])
        if "ingest" in roles:
            ov.update(plan["overrides"]["ingest"])
        if ov:
            lines.append("    resources: " + json.dumps({"overrides": dict(sorted(ov.items()))}, sort_keys=True))
    if skipped:
        lines.append(f"# Not in this inventory before nano {FULL_HA_RELEASE}: {', '.join(skipped)} "
                     "(provision them now, add them after upgrading).")
    return "\n".join(lines) + "\n"


# --- Existing hosts: lay roles out on a list of VMs -----------------------------------
HOST_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


def read_hosts(path: str) -> list[dict]:
    """Read `name address vcpu mem_gib data_disk_gib [zone]` lines (spaces, tabs or commas).

    data_disk_gib is the size of the filesystem that will hold /var/lib/docker.
    zone is optional: an availability zone, rack or hypervisor, anything that
    fails together. Without it every host is its own failure domain.
    """
    hosts: list[dict] = []
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p for p in re.split(r"[\s,]+", line) if p]
        if parts[0].lower() == "name":
            continue                                   # header row
        if len(parts) not in (5, 6):
            raise PlanError(f"--hosts line {number}: want 'name address vcpu mem_gib data_disk_gib [zone]'")
        name, address = parts[0], parts[1]
        if not HOST_NAME_RE.match(name):
            raise PlanError(f"--hosts line {number}: host name {name!r} must be lowercase letters, digits and '-'")
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as error:
            # Host names would end up in iptables -s, trusted_proxy_cidrs and the HA checks, each
            # resolving on its own (or not at all). The plan needs the address the hosts really use.
            raise PlanError(f"--hosts line {number}: {address!r} is not an IP address; give the host's private "
                            "IP address (resolve the name yourself and check it is the private one)") from error
        if not ip.is_private:
            raise PlanError(f"--hosts line {number}: {address} is not a private address; use the private one")
        try:
            vcpu, mem, disk = int(parts[2]), int(float(parts[3])), int(float(parts[4]))
        except ValueError as error:
            raise PlanError(f"--hosts line {number}: vcpu, mem_gib and data_disk_gib must be numbers") from error
        hosts.append({"name": name, "address": address, "vcpu": vcpu, "mem_gib": mem, "disk_gib": disk,
                      "zone": parts[5] if len(parts) == 6 else None})
    if len({h["name"] for h in hosts}) != len(hosts) or len({h["address"] for h in hosts}) != len(hosts):
        raise PlanError("--hosts: names and addresses must be unique")
    if not hosts:
        raise PlanError("--hosts lists no hosts")
    return hosts


def _add(*reqs: tuple) -> tuple:
    return tuple(round(sum(r[i] for r in reqs), 2) for i in range(3))


def host_slots(app: dict, ctl: dict, ch: dict, ing: dict, ctl_layout: str) -> list[dict]:
    """The role groups ("slots") a layout needs, each with its (vCPU, GiB, disk GiB) requirement."""
    r_app = (app["vcpu_need"], app["mem_need_gib"], app["disk_need_gib"])
    r_ctl = (ctl["vcpu_need"], ctl["mem_need_gib"], ctl["data_disk_gib"])
    r_ch = (ch["vcpu_need"], ch["mem_need_gib"], ch["data_disk_gib"])
    slots: list[dict] = []
    for s in range(1, ch["shards"] + 1):
        for r in range(1, ch["replicas"] + 1):
            roles = ["clickhouse"] + (["ingest"] if ing["colocated"] else [])
            slots.append({"roles": roles, "req": r_ch, "shard": s, "replica": r,
                          "tags": {f"shard:{s}"} | ({"ingest"} if ing["colocated"] else set())})
    apps = [{"roles": ["app"], "req": r_app, "tags": {"app"}} for _ in range(app["hosts"])]
    ctls = [{"roles": ["postgres", "keeper"], "req": r_ctl, "tags": {"pg"}} for _ in range(3)]
    if ctl_layout in ("on_app", "on_app_ch"):
        for slot in apps[:2]:                         # app + PostgreSQL + Keeper on the first two app hosts
            slot["roles"] = ["app", "postgres", "keeper"]
            slot["req"] = _add(slot["req"], r_ctl)
            slot["tags"] = {"app", "pg"}
        ctls = ctls[2:]
    if ctl_layout == "on_app_ch":                     # the third member on a ClickHouse host
        first_ch = slots[0]
        first_ch["roles"] = first_ch["roles"] + ["postgres", "keeper"]
        first_ch["req"] = _add(first_ch["req"], r_ctl)
        first_ch["tags"] = first_ch["tags"] | {"pg"}
        ctls = []
    slots = apps + ctls + slots
    if not ing["colocated"]:
        r_ing = (ing["vcpu_need"], ing["mem_need_gib"], ing["data_disk_gib"])
        slots += [{"roles": ["ingest"], "req": r_ing, "tags": {"ingest"}} for _ in range(ing["hosts"])]
    return slots


def domain_clashes(placed: list[tuple[dict, dict]]) -> int:
    """Pairs of slots that share a group (a shard, PostgreSQL, app, ingest) and a failure domain."""
    total = 0
    for i, (s1, h1) in enumerate(placed):
        for s2, h2 in placed[i + 1:]:
            if (h1["zone"] or h1["name"]) == (h2["zone"] or h2["name"]) and s1["tags"] & s2["tags"]:
                total += 1
    return total


def mem_fits(have_gib: float, need_gib: float) -> bool:
    """A host's reported RAM meets a nominal requirement (see MEM_REPORTED_FACTOR)."""
    return have_gib >= need_gib * MEM_REPORTED_FACTOR - 1e-9


def host_fits(h: dict, need: tuple) -> bool:
    return h["vcpu"] >= need[0] - 1e-9 and mem_fits(h["mem_gib"], need[1]) and h["disk_gib"] >= need[2]


def assign_slots(hosts: list[dict], slots: list[dict], capacity: bool = True) -> tuple[list[tuple[dict, dict]], list[dict]] | None:
    """Best-fit placement that spreads every group over failure domains.

    Greedy best fit is tried in several deterministic slot orders (largest
    requirement first; each group first), and the placement with the fewest
    same-domain clashes wins, so one zone never holds both replicas of a shard
    when another placement avoids it.
    """
    size_key = lambda i: (-slots[i]["req"][0], -slots[i]["req"][1], -slots[i]["req"][2], i)
    orders = [sorted(range(len(slots)), key=size_key)]
    for group in ("shard", "pg", "app", "ingest"):
        first = [i for i in range(len(slots)) if any(t.split(":")[0] == group for t in slots[i]["tags"])]
        rest = [i for i in range(len(slots)) if i not in first]
        orders.append(sorted(first, key=size_key) + sorted(rest, key=size_key))
    best = None
    for order in orders:
        result = _assign_in_order(hosts, slots, order, capacity)
        if result is not None and (best is None or domain_clashes(result[0]) < domain_clashes(best[0])):
            best = result
    return best


def _assign_in_order(hosts: list[dict], slots: list[dict], order: list[int], capacity: bool = True):
    free = list(hosts)
    placed: list[tuple[dict, dict]] = []
    for i in order:
        slot = slots[i]
        need = slot["req"]
        fits = [h for h in free if host_fits(h, need)] if capacity else list(free)
        if not fits:
            return None

        def clashes(h: dict) -> int:
            zone = h["zone"] or h["name"]
            return sum(1 for s, p in placed if (p["zone"] or p["name"]) == zone and s["tags"] & slot["tags"])
        if capacity:   # best fit: the smallest host that is big enough
            best = min(fits, key=lambda h: (clashes(h), h["vcpu"], h["mem_gib"], h["disk_gib"], h["name"]))
        else:          # --lab: nothing fits, so the biggest slots get the biggest hosts
            best = min(fits, key=lambda h: (clashes(h), -h["vcpu"], -h["mem_gib"], -h["disk_gib"], h["name"]))
        free.remove(best)
        placed.append((slot, best))
    return placed, free


def _gib(value: float) -> str:
    return f"{value:,.0f} GiB"


def clickhouse_floor(load: dict, a: argparse.Namespace, hosts: list[dict]) -> dict:
    """The smallest ClickHouse host any layout on these hosts could use.

    Uses the most shards the host count allows and the shortest hot window, so
    if the biggest host misses this, nothing the planner tries will fit.
    """
    max_shards = max(1, len(hosts) // max(1, a.replicas))
    shortest = min(a.retention_days, HOT_DAY_CHOICES[-1] if a.hot_days is None else a.hot_days)
    coloc = (colocated_ingest_feasible(load, max(2, a.replicas)) and not a.dedicated_ingest
             and load["_sized_gb"] <= INGEST_COLOCATE_MAX_GB_DAY)
    ing_vcpu = 0.0
    if coloc:
        ing_vcpu = size_ingest(load, a, None, max(2, a.replicas), 1, force="colocated")["vcpu_per_host"]
    with_ing = clickhouse_shape(load, a, max_shards, shortest, ing_vcpu)
    without = clickhouse_shape(load, a, max_shards, shortest, 0)
    one_shard = clickhouse_shape(load, a, 1, shortest, ing_vcpu)   # the figure to quote: what one host must hold
    return {"shards": max_shards, "hot_days": shortest, "colocated": coloc,
            "vcpu": with_ing["vcpu_need"], "vcpu_without_ingest": without["vcpu_need"],
            "mem": with_ing["mem_need_gib"], "disk": with_ing["data_disk_gib"],
            "disk_one_shard": one_shard["data_disk_gib"], "hot_gib": one_shard["hot_data_gib_per_replica"],
            "fixed_gib": CH_EXTRA_GIB}


def clickhouse_shortfalls(load: dict, a: argparse.Namespace, hosts: list[dict]) -> list[str]:
    """Name every dimension in which even the biggest host cannot be a ClickHouse host."""
    f = clickhouse_floor(load, a, hosts)
    big_cpu = max(h["vcpu"] for h in hosts)
    big_mem = max(h["mem_gib"] for h in hosts)
    big_disk = max(h["disk_gib"] for h in hosts)
    out = []
    if not mem_fits(big_mem, f["mem"]):
        out.append(f"RAM: the largest host has {big_mem} GiB; a ClickHouse host needs {f['mem']:.0f} GB "
                   f"(a VM sold as {f['mem']:.0f} GB, which reports about {f['mem'] * MEM_REPORTED_FACTOR:.0f}+ GiB, qualifies). "
                   "Shorter retention does not change this")
    if big_cpu < f["vcpu"] - 1e-9:
        detail = (f"{math.ceil(f['vcpu'])} with ingest on the same host"
                  + (f" ({math.ceil(f['vcpu_without_ingest'])} without, which needs dedicated ingest hosts)"
                     if f["colocated"] and f["vcpu_without_ingest"] < f["vcpu"] else ""))
        out.append(f"vCPU: the largest host has {big_cpu}; a ClickHouse host needs {detail}")
    if big_disk < f["disk"]:
        hot = f"{f['hot_days']} d hot at this volume is {_gib(f['hot_gib'])} per replica, {_gib(f['hot_gib'] / CH_DISK_FILL)} at {CH_DISK_FILL:.0%} fill"
        line = (f"data disk: the largest Docker data filesystem is {_gib(big_disk)}; a ClickHouse host needs "
                f"{_gib(f['fixed_gib'])} fixed (Docker images, logs, system tables) plus hot data ({hot}), so at least "
                f"{_gib(f['disk_one_shard'])} with one shard")
        if big_disk <= f["fixed_gib"]:
            line += f". No --hot-days value fixes this: the fixed {_gib(f['fixed_gib'])} alone is more than the disk"
        out.append(line)
    return out


def layout_on_hosts(load, a, hosts: list[dict]) -> dict:
    """Pick the least-stacked full-HA layout that fits the operator's hosts.

    With --lab, hosts that miss the production sizing still get a layout; the
    plan then records every shortfall and is labelled NOT FOR PRODUCTION.
    """
    shortfalls = clickhouse_shortfalls(load, a, hosts)
    if shortfalls and not a.lab:
        raise PlanError(
            f"these {len(hosts)} hosts cannot carry a production full-HA layout at {load['sized_gb_per_day']} GB/day. "
            "Binding constraint(s) for the ClickHouse hosts:\n  - " + "\n  - ".join(shortfalls)
            + f"\nFix: give the {a.replicas} ClickHouse hosts that size (Server sizing table: {SIZING_DOC}), "
            "or, for an evaluation or test cluster only, re-run with --lab to plan anyway (labelled NOT FOR PRODUCTION)")
    lab = bool(shortfalls)
    max_host_vcpu = None if lab else max(h["vcpu"] for h in hosts)
    max_host_disk = None if lab else max(h["disk_gib"] for h in hosts)   # the hot window shortens to fit
    try:
        ch_d = size_clickhouse(load, a, None, 0, max_vcpu=max_host_vcpu, max_disk_gib=max_host_disk)
    except PlanError as error:
        raise PlanError(f"these {len(hosts)} hosts cannot carry a full-HA layout at this volume ({error}). "
                        f"See {SIZING_DOC}") from error
    variants: list[tuple[dict, dict]] = []
    ing_d = size_ingest(load, a, None, ch_d["shards"] * ch_d["replicas"], ch_d["shards"], force="dedicated")
    col = None
    if colocated_ingest_feasible(load, ch_d["shards"] * ch_d["replicas"]) and not a.dedicated_ingest:
        ing_c = size_ingest(load, a, None, ch_d["shards"] * ch_d["replicas"], ch_d["shards"], force="colocated")
        ch_c = size_clickhouse(load, a, None, ing_c["vcpu_per_host"], max_vcpu=max_host_vcpu, max_disk_gib=max_host_disk)
        ing_c = size_ingest(load, a, None, ch_c["shards"] * ch_c["replicas"], ch_c["shards"], force="colocated")
        col = (ch_c, ing_c)
    prefer_colocated = lab or load["_sized_gb"] <= INGEST_COLOCATE_MAX_GB_DAY
    if col and prefer_colocated:
        variants.append(col)
    variants.append((ch_d, ing_d))
    if col and not prefer_colocated:
        variants.append(col)
    app = size_app(load, a, None, ch_d["concurrent_queries"])
    ctl = size_control(load, a, None)
    tried = []
    for capacity in ((True, False) if a.lab else (True,)):
        for ctl_layout in ("separate", "on_app", "on_app_ch"):
            for ch, ing in variants:
                slots = host_slots(app, ctl, ch, ing, ctl_layout)
                tried.append((ctl_layout, ing["colocated"], len(slots)))
                if len(slots) > len(hosts):
                    continue
                result = assign_slots(hosts, slots, capacity=capacity)
                if result is None:
                    continue
                placed, spare = result
                lab_rows = [] if capacity else lab_shortfalls(placed)
                return {"ch": ch, "ing": ing, "app": app, "ctl": ctl, "ctl_layout": ctl_layout,
                        "placed": placed, "spare": spare, "lab": lab_rows, "lab_ch_findings": shortfalls}
    smallest = min(t[2] for t in tried)
    if len(hosts) < smallest:
        raise PlanError(
            f"these {len(hosts)} hosts cannot carry a full-HA layout: full HA needs at least {smallest} hosts at this volume (2 app, 3 PostgreSQL+Keeper members, "
            f"{ch_d['shards'] * ch_d['replicas']} ClickHouse, with roles stacked as far as HA allows); "
            f"you listed {len(hosts)}. Add hosts, or accept a layout with a single point of failure explicitly "
            "(scripts/size.py --topology ha3)")
    need = (f"app {app['vcpu_need']} vCPU/{app['mem_need_gib']} GB; PostgreSQL+Keeper {ctl['vcpu_need']} vCPU/"
            f"{ctl['mem_need_gib']} GB/{ctl['data_disk_gib']} GiB disk; ClickHouse {math.ceil(ch_d['vcpu_need'])} vCPU/"
            f"{ch_d['mem_need_gib']:.0f} GB/{ch_d['data_disk_gib']} GiB disk")
    raise PlanError(
        f"these {len(hosts)} hosts cannot carry a production full-HA layout at this volume: the roles do not fit "
        f"the individual hosts. Per role: {need} (Server sizing: {SIZING_DOC}). Use bigger hosts or add hosts; "
        "for an evaluation or test cluster only, re-run with --lab (labelled NOT FOR PRODUCTION)")


def lab_shortfalls(placed: list[tuple[dict, dict]]) -> list[str]:
    """One line per host that misses its roles' production requirement (--lab plans)."""
    rows = []
    for slot, host in sorted(placed, key=lambda sp: sp[1]["name"]):
        need = slot["req"]
        if host_fits(host, need):
            continue
        rows.append(f"{host['name']} ({','.join(slot['roles'])}): has {host['vcpu']} vCPU / {host['mem_gib']} GiB / "
                    f"{host['disk_gib']} GiB disk; production needs {math.ceil(need[0])} vCPU / {need[1]:.0f} GB / "
                    f"{need[2]:.0f} GiB")
    return rows


def lab_local_days(load: dict, a: argparse.Namespace, shards: int, disk_gib: float) -> int:
    """Rough days of hot data an undersized ClickHouse disk holds (--lab estimate only)."""
    per_day = load["_sized_gb"] * 1e9 / GIB / a.compression * CH_MV_OVERHEAD / shards
    usable = max(0.0, disk_gib - LAB_CH_OVERHEAD_GIB) * CH_DISK_FILL
    return int(usable // per_day) if per_day > 0 else 0


def nodes_from_hosts(layout: dict) -> list[dict]:
    nodes = []
    keeper = 0
    ing = layout["ing"]
    for slot, host in sorted(layout["placed"], key=lambda sp: [h["name"] for h in [sp[1]]]):
        roles = list(slot["roles"])
        kind = ("clickhouse" if "clickhouse" in roles else "app" if "app" in roles
                else "control" if "postgres" in roles else "ingest")
        node = {"kind": kind, "name": host["name"], "zone": host["zone"] or host["name"], "zone_index": None,
                "address": host["address"], "instance": "existing", "vcpu": host["vcpu"], "mem_gib": host["mem_gib"],
                "usd_hour": 0.0, "price_verified": True, "roles": roles, "requirement": list(slot["req"]),
                "disks": [{"purpose": "docker data filesystem", "type": "existing", "size_gib": host["disk_gib"]}]}
        if "clickhouse" in roles:
            node.update(shard=slot["shard"], replica=slot["replica"], ingest="ingest" in roles)
        if "ingest" in roles:
            share = ing["vcpu_per_host"] if ing["colocated"] else host["vcpu"]
            node["ingest_capacity_eps"] = ingest_capacity_eps(share)
        nodes.append(node)
    # Keeper ids follow inventory order; the first postgres host in that order bootstraps Patroni.
    order = {"app": 0, "control": 1, "clickhouse": 2, "ingest": 3}
    nodes.sort(key=lambda n: (order[n["kind"]], n.get("shard", 0), n.get("replica", 0), n["name"]))
    for n in nodes:
        if "keeper" in n["roles"]:
            keeper += 1
            n["keeper_id"] = keeper
    return nodes


# --- Load balancer ---------------------------------------------------------------------
def lb_plan(a: argparse.Namespace, nodes: list[dict], net: dict, schema: dict, cloud_mode: bool,
            spare: list[dict] | None = None) -> dict:
    mode = a.lb or ("cloud" if cloud_mode else None)
    if mode is None:
        raise PlanError("say how users and log senders reach nano: --lb cloud (a managed load balancer, plus "
                        "--trusted-proxy-cidr for its source addresses; recommended on any cloud), --lb haproxy-pair "
                        "(two HAProxy hosts with keepalived and a floating IP; needs L2 and VRRP), --lb haproxy-dns "
                        "(two HAProxy hosts, both in DNS with health-checked failover; no floating IP) or "
                        f"--lb haproxy-single (one HAProxy host: a single point of failure). See {LB_DOC}")
    apps = [n for n in nodes if "app" in roles_for(n, schema)]
    ingests = [n for n in nodes if "ingest" in roles_for(n, schema)]
    if not schema["multi_app"]:
        apps = apps[:1]
    app_path = schema["health_checks"]["app"]["path"]
    out = {"mode": mode, "app_backend": [f"{n['address']}:80" for n in apps],
           "ingest_backend": [f"{n['address']}:80" for n in ingests],
           "app_health_check": f"GET {app_path} expect 200", "ingest_health_check": "GET /healthz expect 200",
           "single_point_of_failure": False}
    nano_addresses = {n["address"]: roles_for(n, schema) for n in nodes}
    if mode == "cloud":
        if not cloud_mode and not a.trusted_proxy_cidr:
            raise PlanError("--lb cloud with existing hosts needs --trusted-proxy-cidr: the private source "
                            "range the load balancer connects from")
        out["summary"] = "managed, multi-zone cloud load balancer for both hostnames (TLS at the LB, HTTP to port 80)"
        out["survives"] = "zone loss (managed by the cloud provider)"
        return out
    want = 1 if mode == "haproxy-single" else 2
    addresses = list(a.lb_address)
    from_spare = []
    placement = None
    if not addresses and spare and len(spare) >= want:
        # Hosts the layout does not need make good HAProxy hosts.
        from_spare = spare[:want]
        addresses = [h["address"] for h in from_spare]
    elif not addresses:
        # No spare VM: HAProxy goes on PostgreSQL-only hosts, the lightest-loaded role. App, ingest and ClickHouse
        # hosts already carry the request path (and the app and ingest edges own port 80). The first PostgreSQL
        # host bootstraps Patroni, so take the last ones.
        pg_only = [n for n in nodes if set(roles_for(n, schema)) <= {"postgres", "keeper"}]
        if len(pg_only) >= want:
            chosen = pg_only[-want:]
            addresses = [n["address"] for n in chosen]
            placement = (f"no spare VM was listed, so HAProxy goes on PostgreSQL host(s) {', '.join(n['name'] for n in chosen)}: "
                         "the lightest-loaded role (app, ingest and ClickHouse hosts carry the request path). Losing "
                         "that host also costs a PostgreSQL member, and writes see a short pause (seconds, up to ~30 s) while a standby is "
                         f"promoted. To keep them apart, add {want} small VM(s) (2 vCPU / 2 GB) to the hosts file")
    if len(addresses) != want:
        raise PlanError(f"--lb {mode} needs {want} HAProxy host(s): pass {want} --lb-address, or list {want} "
                        "spare VM(s) beyond what the layout needs (no PostgreSQL-only host is free to share)")
    for addr in addresses:
        try:
            ipaddress.ip_address(addr)
        except ValueError as error:
            raise PlanError(f"--lb-address {addr!r} must be an IP address") from error
        roles = nano_addresses.get(addr)
        if roles and set(roles) & {"app", "ingest", "clickhouse"}:
            raise PlanError(f"--lb-address {addr} is a nano {'/'.join(roles)} host; HAProxy can share only a "
                            "PostgreSQL host (it binds 443; app and ingest edges own port 80)")
        if str(ipaddress.ip_network(f"{addr}/32")) not in net["trusted_proxy_cidrs"]:
            net["trusted_proxy_cidrs"].append(f"{addr}/32")
    shared = [addr for addr in addresses if addr in nano_addresses]
    out["lb_hosts"] = addresses
    out["lb_hosts_from_spare"] = [h["name"] for h in from_spare]
    for h in from_spare:
        spare.remove(h)
    out["shares_postgres_host"] = shared
    out["placement"] = placement
    out["config"] = ("copy deploy/compose/examples/load-balancer/haproxy.cfg from the installed bundle and replace "
                     "its server lines and hostnames with the ones below")
    if mode == "haproxy-pair":
        if not a.lb_vip:
            raise PlanError("--lb haproxy-pair needs --lb-vip: the floating address both DNS names point at")
        out["vip"] = a.lb_vip
        out["summary"] = (f"two HAProxy hosts ({', '.join(addresses)}) with keepalived holding {a.lb_vip}; "
                          "keepalived.conf from the same examples directory")
        out["survives"] = "loss of either HAProxy host: the other claims the floating address in ~3 s"
        out["requires"] = "the same L2 segment, VRRP (IP protocol 112) allowed between them, net.ipv4.ip_nonlocal_bind=1"
    elif mode == "haproxy-dns":
        out["summary"] = (f"two HAProxy hosts ({', '.join(addresses)}), each with its own address; both DNS names "
                          "carry both addresses as A records, with the DNS provider's health-checked failover")
        out["survives"] = ("loss of either HAProxy host once the DNS health check drops it (TTL plus check interval, "
                           "roughly 1-2 min, not measured by nano); senders must retry and re-resolve DNS")
        out["requires"] = ("a DNS provider with health-checked records and a TTL of 60 s or less; senders that "
                           "retry and re-resolve DNS (clients that cache DNS forever do not fail over)")
    else:
        out["single_point_of_failure"] = True
        out["summary"] = f"one HAProxy host ({addresses[0]}); both DNS names point at it"
        out["survives"] = ("NOTHING at the edge: if this host is down, users and log senders cannot reach nano "
                           "(the cluster behind it keeps running; senders must buffer and retry)")
    return out


def haproxy_server_lines(lb: dict) -> str:
    lines = ["backend nano_app_hosts   # replace the server lines in the example"]
    lines += [f"  server app-{i} {addr} check" for i, addr in enumerate(lb["app_backend"], 1)]
    lines += ["backend nano_ingest_hosts"]
    lines += [f"  server ingest-{i} {addr} check" for i, addr in enumerate(lb["ingest_backend"], 1)]
    return "\n".join(lines)


# --- Plan ---------------------------------------------------------------------------
def zones_for(cloud: str, region: str) -> list[str]:
    """Three zone names for a region (Azure numbers its zones)."""
    if not re.fullmatch(r"[a-z0-9-]{2,40}", region):
        raise PlanError(f"--region {region!r} is not a region name")
    return {"aws": [f"{region}{z}" for z in "abc"], "gcp": [f"{region}-{z}" for z in "abc"],
            "azure": ["1", "2", "3"]}[cloud]


def add_trusted(net: dict, cidrs: list[str]) -> None:
    for cidr in cidrs:
        try:
            canonical = str(ipaddress.ip_network(cidr, strict=True))
        except ValueError as error:
            raise PlanError(f"--trusted-proxy-cidr {cidr!r} is not a canonical CIDR") from error
        if canonical not in net["trusted_proxy_cidrs"]:
            net["trusted_proxy_cidrs"].append(canonical)


def make_plan(a: argparse.Namespace, cat: dict | None = None) -> dict:
    if a.replicas < 2:
        raise PlanError("full HA needs --replicas 2 or more")
    if a.retention_days < 1:
        raise PlanError("--retention-days must be at least 1")
    load = derive_load(a)
    schema = schema_for(a.inventory_schema)
    hosts_mode = bool(a.hosts)
    warnings: list[str] = []
    layout = None
    if a.lab and not hosts_mode:
        raise PlanError("--lab plans existing hosts that miss the production sizing; use it with --hosts")
    if hosts_mode:
        cat = None
        hosts = read_hosts(a.hosts)
        layout = layout_on_hosts(load, a, hosts)
        ch, ing, app, ctl = layout["ch"], layout["ing"], layout["app"], layout["ctl"]
        nodes = nodes_from_hosts(layout)
        net = {"trusted_proxy_cidrs": []}
        add_trusted(net, list(a.trusted_proxy_cidr))
        if layout["ctl_layout"] != "separate":
            warnings.append({"on_app": "stacked: PostgreSQL+Keeper run on the two app hosts and one more host",
                             "on_app_ch": "stacked: PostgreSQL+Keeper run on the two app hosts and one ClickHouse host"}
                            [layout["ctl_layout"]] + "; losing a stacked host loses all its roles at once (still survivable), "
                            "and the roles share its CPU and memory")
        if not any(h["zone"] for h in hosts):
            warnings.append("no failure domains given: the plan assumes every host fails alone. If hosts share a "
                            "hypervisor, rack or zone, add it as the 6th column and re-plan")
    else:
        cat = json.loads(json.dumps(cat or load_catalog()))   # private copy: the region may rename zones
        if a.cloud not in cat["clouds"]:
            raise PlanError(f"unknown cloud {a.cloud}")
        if a.region and a.region != cat["clouds"][a.cloud]["region"]:
            cat["clouds"][a.cloud]["zones"] = zones_for(a.cloud, a.region)
        # First pass assumes dedicated ingest to learn the ClickHouse node count.
        ch = size_clickhouse(load, a, cat, 0)
        ch_nodes = ch["shards"] * ch["replicas"]
        ing = size_ingest(load, a, cat, ch_nodes, ch["shards"])
        if ing["colocated"]:
            ch = size_clickhouse(load, a, cat, ing["vcpu_per_host"])
            ing = size_ingest(load, a, cat, ch["shards"] * ch["replicas"], ch["shards"])
        app = size_app(load, a, cat, ch["concurrent_queries"])
        ctl = size_control(load, a, cat)
        vpc = ipaddress.ip_network(a.vpc_cidr, strict=True)
        net = network_plan(a.vpc_cidr, cat["clouds"][a.cloud]["zones"])
        if (a.lb or "cloud") == "cloud":
            add_trusted(net, list(cat["clouds"][a.cloud].get("lb_trusted_proxy_cidrs", [])))
        else:
            net["trusted_proxy_cidrs"] = []          # HAProxy hosts are the only proxies
        add_trusted(net, list(a.trusted_proxy_cidr))
        nodes = build_nodes(a, cat, app, ctl, ch, ing, vpc)
        if a.max_nodes and len(nodes) > a.max_nodes:
            raise PlanError(
                f"full HA at this volume needs {len(nodes)} VMs ({app['hosts']} app, 3 PostgreSQL/Keeper, "
                f"{ch['shards'] * ch['replicas']} ClickHouse" + ("" if ing["colocated"] else f", {ing['hosts']} ingest")
                + f"); the limit is {a.max_nodes}. Raise the limit, list the VMs you already have with --hosts "
                "(roles can then share hosts), or accept a layout with a single point of failure explicitly "
                "(scripts/size.py --topology ha3) and say what it loses.")
        if a.max_nodes and len(nodes) < a.max_nodes:
            warnings.append(f"the plan uses {len(nodes)} of the {a.max_nodes} allowed VMs; the rest is not needed for HA at this volume")
    lb = lb_plan(a, nodes, net, schema, cloud_mode=not hosts_mode, spare=layout["spare"] if layout else None)
    if layout and lb.get("lb_hosts_from_spare"):
        warnings.append("HAProxy goes on " + ", ".join(lb["lb_hosts_from_spare"]) + ", which the layout does not need")
    if layout and layout["spare"]:
        warnings.append("not needed for HA at this volume: " + ", ".join(h["name"] for h in layout["spare"])
                        + " (keep as a replacement host, or add as another ingest host for headroom)")
    if lb["single_point_of_failure"]:
        warnings.append("SINGLE POINT OF FAILURE AT THE EDGE: one HAProxy host and no floating address. Everything "
                        "behind it survives any one host, but while the HAProxy host is down nobody can log in and "
                        "senders cannot deliver. Prefer a managed load balancer or an HAProxy pair with keepalived")
    if lb.get("placement"):
        warnings.append(lb["placement"])
    if lb.get("shares_postgres_host"):
        if lb["single_point_of_failure"]:
            warnings.append("HAProxy shares a PostgreSQL host: losing that host takes the edge down with it")
        else:
            warnings.append("HAProxy shares PostgreSQL host(s): losing one costs one HAProxy and one PostgreSQL "
                            "member at once; the other HAProxy keeps the edge up")
    # Vector buffer and memory per ingest host, as the installer will derive them.
    ing_node = next(n for n in nodes if "ingest" in roles_for(n, schema))
    ing_roles = set(roles_for(ing_node, schema))
    data_disk = next(d["size_gib"] for d in ing_node["disks"] if d["purpose"] != "os")
    buf = product_vector_buffer(ing_node["mem_gib"], ing_roles, ch["shards"], data_disk)
    ingest_count = sum(1 for n in nodes if "ingest" in roles_for(n, schema))
    per_host_bytes_s = load["peak_mb_s"] * 1e6 / max(1, ingest_count - 1)
    ride_min = buf["budget_bytes"] / per_host_bytes_s / 60 if per_host_bytes_s else float("inf")
    ing["buffer"] = {"budget_gib": round(buf["budget_bytes"] / GIB, 2), "buffers": buf["buffer_count"],
                     "per_sink_gib": round(buf["per_sink_bytes"] / GIB, 2), "vector_mem_gib": round(buf["vector_mem_mib"] / 1024, 1),
                     "ride_through_minutes_at_peak": round(min(ride_min, 1e6), 1),
                     "source": "derived like scripts/lib/resource-sizing.sh; 1 GiB/sink floor MEASURED-external"}
    if not buf["disk_ok"]:
        raise PlanError(f"{ing_node['name']}: its data filesystem is too small for Vector's disk buffers; give it at least {INGEST_DATA_DISK_MIN_GIB} GiB")
    if load["sized_tb_per_day"] >= 1 and buf["per_sink_bytes"] < VECTOR_MIN_SINK_BUFFER:
        warnings.append(f"Vector gets {buf['per_sink_bytes'] / GIB:.2f} GiB per sink, below the 1 GiB that held at volume")
    if load["sized_tb_per_day"] >= 1 and buf["vector_mem_mib"] < VECTOR_MIN_MEM_GIB_AT_VOLUME * 1024:
        warnings.append("Vector memory is below 8 GiB per ingest host at >= 1 TB/day (OOM risk)")
    if ride_min < 10:
        warnings.append(f"the Vector buffer covers only {ride_min:.1f} min of peak ingest per host; senders must buffer during a longer ClickHouse stall")
    if load["extrapolated"]:
        warnings.append(f"EXTRAPOLATED: peak {load['peak_hour_eps']:,} EPS is above the {NANO_VALIDATED_EPS:,} EPS nano has measured; "
                        "the ratios come from an external estate until nano's own load tests validate them")
    if load["_sized_gb"] > INGEST_COLOCATE_MAX_GB_DAY:
        warnings.append("above ~100 GB/day the Self-run guide also offers Kubernetes (Helm); this VM plan is the role-split Compose path")
    if load["sized_tb_per_day"] >= 15:
        warnings.append("at 15-20+ TB/day Vector is the first bottleneck; plan the Vector role split with nano before go-live")
    if ch["cold_days"] > 0:
        warnings.append(f"hot data stays {ch['hot_days']} d on local disk; {ch['cold_days']} d live in object storage "
                        "(configure tiering in Settings -> Storage & Retention after install; TTL-driven moves are planned)")
    if not hosts_mode and ch["cold_days"] > 0 and not cat["clouds"][a.cloud]["object_storage"].get("s3_compatible", True):
        warnings.append("the cold tier needs an S3-compatible store and Azure Blob has no S3 API: run RustFS on Azure "
                        "managed disks or use an external S3-compatible store (the cold-tier price is a Blob placeholder), "
                        "or keep all retention local with --hot-days " + str(a.retention_days))
    if ch.get("local_nvme"):
        warnings.append("ClickHouse uses local NVMe: it is wiped when a VM stops or is replaced; the other replica re-seeds it. "
                        "Never stop two replicas of one shard at once")
    if a.growth == 1.0:
        warnings.append("sized for today's volume; adding shards or replicas to a live cluster is not a supported flow yet, so pass --growth for 12-month volume")
    if a.analysts > 30:
        warnings.append("more than 30 concurrent analysts share one search admission pool and ClickHouse workload")
    if load["sized_tb_per_day"] > 10:
        warnings.append("PostgreSQL write rates above 10 TB/day are unmeasured")
    if not schema["multi_app"]:
        warnings.append(f"pre-2.0.7 inventory: one app host and one PostgreSQL host, so the UI, alerting and PostgreSQL "
                        f"are single points of failure. Install nano {FULL_HA_RELEASE} or newer for full HA")
    overrides, tune_rows = tuning(load, ch, ing, nodes, schema)
    hosts_ha = ha_hosts(nodes, schema, ing)
    ha = ha_report(hosts_ha, load["_peak_eps"], lb)
    if schema["multi_app"] and not ha["any_one_node"]:
        raise PlanError(f"planner produced a layout that does not survive one node loss: {ha['node_loss_failures']}")
    if ha["zones_known"] and not ha["any_one_zone"]:
        warnings.append("a single failure domain holds a quorum majority or every replica of a shard: "
                        + json.dumps(ha["zone_loss_failures"], sort_keys=True))
    ctl_layout = layout["ctl_layout"] if layout else "separate"
    lab = None
    if layout and (layout["lab"] or layout["lab_ch_findings"]):
        ch_disks = [n["disks"][0]["size_gib"] for n in nodes if "clickhouse" in roles_for(n, schema)]
        days = lab_local_days(load, a, ch["shards"], min(ch_disks))
        # The lab layout keeps what its disks hold locally; the rest would have to tier.
        ch["hot_days"] = min(days, a.retention_days)
        ch["cold_days"] = a.retention_days - ch["hot_days"]
        ch["cold_object_storage_gib"] = round(load["_sized_gb"] * 1e9 / GIB * ch["cold_days"] / a.compression
                                              * CH_MV_OVERHEAD * a.replicas)
        lab = {"not_for_production": True, "shortfalls": layout["lab"],
               "clickhouse_constraints": layout["lab_ch_findings"],
               "local_hot_days_estimate": days, "retention_days": a.retention_days}
        warnings.insert(0, "LAB PLAN - NOT FOR PRODUCTION: these hosts miss the production sizing "
                        f"({SIZING_DOC}); use this layout only for evaluation and functional tests. Shortfalls: "
                        + "; ".join(layout["lab"] or layout["lab_ch_findings"]))
        if days < a.retention_days:
            warnings.insert(1, f"LAB: the smallest ClickHouse disk holds about {days} d of events at this volume "
                            f"(estimate), not the {a.retention_days} d asked for. Shorten retention in Settings -> "
                            "Storage & Retention, or add S3-compatible tiering, before it fills")
    plan = {
        "plan_version": PLAN_VERSION,
        "input": {"cloud": None if hosts_mode else a.cloud,
                  "region": None if hosts_mode else (a.region or cat["clouds"][a.cloud]["region"]),
                  "hosts_file": bool(hosts_mode),
                  "gb_per_day": a.gb_per_day, "eps": a.eps, "avg_event_bytes": a.avg_event_bytes,
                  "retention_days": a.retention_days, "hot_days": a.hot_days, "compression": a.compression,
                  "growth": a.growth, "analysts": a.analysts, "replicas": a.replicas,
                  "max_nodes": a.max_nodes, "budget_usd_month": a.budget_usd_month, "log_sources": a.log_sources,
                  "inventory_schema": a.inventory_schema, "lb": lb["mode"]},
        "requires_release": schema["release"],
        "load": {k: v for k, v in load.items() if not k.startswith("_")},
        "clickhouse": {k: v for k, v in ch.items() if k != "sku"} | (
            {"instance": ch["sku"]["name"], "family": ch["sku"]["family"]} if ch.get("sku") else {}),
        "ingest": {k: v for k, v in ing.items() if k != "sku"} | ({"instance": ing["sku"]["name"]} if ing.get("sku") else {}),
        "app": {k: v for k, v in app.items() if k != "sku"} | ({"instance": app["sku"]["name"]} if app.get("sku") else {}),
        "control": {k: v for k, v in ctl.items() if k != "sku"} | ({"instance": ctl["sku"]["name"]} if ctl.get("sku") else {})
        | {"layout": ctl_layout},
        "network": net,
        "nodes": nodes,
        "spare_hosts": [h["name"] for h in layout["spare"]] if layout else [],
        "summary": {"total_vms": len(nodes), "app": sum(1 for n in nodes if "app" in roles_for(n, schema)),
                    "control": 3, "clickhouse": ch["shards"] * ch["replicas"],
                    "ingest_dedicated": sum(1 for n in nodes if roles_for(n, schema) == ["ingest"]),
                    "total_vcpu": sum(n["vcpu"] for n in nodes), "total_mem_gib": sum(n["mem_gib"] for n in nodes)},
        "ha": {"reasoning": ha_reasoning(app, ch, ing, schema, lb, ctl_layout), "check": ha},
        "load_balancer": lb,
        "health_checks": schema["health_checks"],
        "overrides": overrides,
        "tuning": tune_rows,
        "warnings": warnings,
        "lab": lab,
    }
    plan["cost"] = None if hosts_mode else cost_estimate(cat, a, load, ch, nodes)
    if plan["cost"] and a.budget_usd_month and plan["cost"]["low_usd_month"] > a.budget_usd_month:
        plan["warnings"].append(
            f"over budget: the estimate starts at ${plan['cost']['low_usd_month']:,.0f}/month against ${a.budget_usd_month:,.0f}. "
            "Levers that keep HA: fewer --hot-days, a measured --compression, commitment discounts. Never drop a replica to fit")
    return plan


# --- Text output -----------------------------------------------------------------------
LAB_BANNER = "*** LAB PLAN - NOT FOR PRODUCTION: planned with --lab on hosts below the production sizing ***"


def fmt_disks(n: dict) -> str:
    parts = []
    for d in n["disks"]:
        extra = ""
        if d.get("iops"):
            extra = f" {d['iops']} IOPS/{d['mbps']} MB/s"
        parts.append(f"{d['size_gib']} GiB {d['type']}{extra} ({d['purpose']})")
    return "; ".join(parts)


def print_text(p: dict) -> None:
    i, l, ch, ing = p["input"], p["load"], p["clickhouse"], p["ingest"]
    if p.get("lab"):
        print(LAB_BANNER)
    where = "your hosts" if i["hosts_file"] else f"{i['cloud'].upper()} {i['region']}"
    catalog = f", catalog {p['cost']['as_of']}" if p["cost"] else ""
    print(f"nano full-HA plan: {where}  (planner v{PLAN_VERSION}{catalog}; inventory {i['inventory_schema']}"
          + (f", needs nano {p['requires_release']}+" if p["requires_release"] else "") + ")")
    print(f"Load: {l['gb_per_day']} GB/day ~ {l['eps']:,} EPS at {l['avg_event_bytes']} B/event; sized "
          f"{l['sized_gb_per_day']} GB/day; peak hour {l['peak_hour_eps']:,} EPS; retention {i['retention_days']} d")
    if l["extrapolated"]:
        print(f"  EXTRAPOLATED above nano's measured {NANO_VALIDATED_EPS:,} EPS")
    print(f"ClickHouse: {ch['shards']} shard(s) x {ch['replicas']} replicas, "
          + (f"about {ch['hot_days']} d (lab estimate)" if p.get("lab") else f"{ch['hot_days']} d") + " hot on "
          f"{'local NVMe' if ch.get('local_nvme') else 'the data disk'}, {ch['cold_days']} d cold "
          f"({ch['cold_object_storage_gib']:,} GiB object storage across replicas)")
    print(f"Ingest: {'on the ClickHouse hosts' if ing['colocated'] else str(ing['hosts']) + ' dedicated hosts'}; "
          f"buffer {ing['buffer']['budget_gib']} GiB/host ({ing['buffer']['per_sink_gib']} GiB per sink, "
          f"~{ing['buffer']['ride_through_minutes_at_peak']} min at peak)")
    print()
    print(f"{'VM':<16} {'zone':<15} {'roles':<34} {'instance':<20} {'vCPU':>4} {'GiB':>4}  disks")
    sch = schema_for(i["inventory_schema"])
    for n in p["nodes"]:
        roles = ",".join(roles_for(n, sch))
        if "shard" in n:
            roles += f" s{n['shard']}r{n['replica']}"
        if "keeper_id" in n:
            roles += f" k{n['keeper_id']}"
        print(f"{n['name']:<16} {n['zone']:<15} {roles:<34} {n['instance']:<20} {n['vcpu']:>4} {n['mem_gib']:>4}  {fmt_disks(n)}")
    s = p["summary"]
    print(f"Total: {s['total_vms']} VMs, {s['total_vcpu']} vCPU, {s['total_mem_gib']} GiB RAM"
          + (f"; spare: {', '.join(p['spare_hosts'])}" if p["spare_hosts"] else ""))
    print()
    lb = p["load_balancer"]
    print(f"Load balancer ({lb['mode']}): {lb['summary']}")
    print(f"  app backend {', '.join(lb['app_backend'])} ({lb['app_health_check']}); "
          f"ingest backend {', '.join(lb['ingest_backend'])} ({lb['ingest_health_check']})")
    if lb.get("requires"):
        print(f"  requires {lb['requires']}")
    if lb["mode"] != "cloud":
        print(f"  {lb['config']}:")
        for line in haproxy_server_lines(lb).splitlines():
            print(f"    {line}")
    print()
    print("HA: what each choice survives")
    for r in p["ha"]["reasoning"]:
        print(f"  - {r['component']}: {r['choice']}. Survives {r['survives']}.")
    chk = p["ha"]["check"]
    zone = ("not given (every host is its own failure domain)" if not chk["zones_known"] else
            ("quorum and replicas OK" if chk["any_one_zone"] else "FAIL: " + json.dumps(chk["zone_loss_failures"], sort_keys=True))
            + f"; ingest after a zone loss {chk['ingest_capacity_after_zone_loss_eps']:,} EPS "
            f"({'carries' if chk['zone_loss_carries_peak'] else 'below'} the {p['load']['peak_hour_eps']:,} EPS peak)")
    print(f"  Checked: any one VM lost -> {'OK' if chk['any_one_node'] else 'FAIL'}; any one zone lost -> {zone}"
          + ("; EDGE: single point of failure" if chk["edge_single_point_of_failure"] else ""))
    print()
    print("Tuned settings for this volume:")
    for t in p["tuning"]:
        print(f"  - {t['setting']} = {t['value']} [{t['applied']}; {t['topic']}; {t['source']}]")
    c = p["cost"]
    if c:
        print()
        print(f"Monthly cost {c['label']} as of {c['as_of']} ({c['basis']}, {c['reference_region']}): "
              f"${c['low_usd_month']:,.0f} - ${c['high_usd_month']:,.0f}")
        for line in c["lines"]:
            print(f"  {line['item']}: ${line['usd_month']:,}")
        print(f"  of which ClickHouse replicas beyond the first: ${c['clickhouse_extra_replicas_usd_month']:,} (compute)")
        if c["region_note"]:
            print(f"  {c['region_note']}")
        for u in c["unverified"]:
            print(f"  unverified: {u}")
        print(f"  excludes {c['excludes']}")
    print_warnings(p)
    if p.get("lab"):
        print()
        print(LAB_BANNER)


def print_warnings(p: dict) -> None:
    if p["warnings"]:
        print()
        print("Warnings:")
        for w in p["warnings"]:
            print(f"  - {w}")


TSV_FIELDS = ("name", "kind", "zone", "address", "instance", "data_gib", "data_type", "data_iops", "data_mbps", "extra_gib")


def print_nodes_tsv(p: dict) -> None:
    """name kind zone address instance data_gib data_type data_iops data_mbps extra_gib (0/- when absent)."""
    print("\t".join(TSV_FIELDS))
    for n in p["nodes"]:
        data = [d for d in n["disks"] if not d["purpose"].startswith("os")]
        first = data[0] if data else {}
        extra = data[1]["size_gib"] if len(data) > 1 else 0
        print("\t".join(str(v) for v in (
            n["name"], n["kind"], n["zone"], n["address"], n["instance"], first.get("size_gib", 0),
            first.get("type", "-"), first.get("iops", 0), first.get("mbps", 0), extra)))


def print_install_order(p: dict, schema: dict) -> None:
    """One line per install.sh run, in order, with each host's complete role list at the end."""
    nodes = p["nodes"]
    r = {n["name"]: roles_for(n, schema) for n in nodes}
    steps: list[tuple[str, str, str]] = []
    first_app = next(n["name"] for n in nodes if "app" in r[n["name"]])
    steps.append((first_app, "prepare", "NANO_PREPARE_ONLY=1 ... --role " + ",".join(r[first_app])
                  + "  (creates the shared .env; then copy .env to every host)"))
    pg = [n["name"] for n in nodes if "postgres" in r[n["name"]]]
    for name in pg:   # the first postgres host in inventory order bootstraps; the others clone it
        roles = [x for x in r[name] if x in ("postgres", "keeper")]
        steps.append((name, "install", "--role " + ",".join(roles)))
    if len(pg) >= 2:
        # PostgreSQL HA: the cluster bootstraps only once a second postgres
        # host joins (etcd quorum), so the first postgres host cannot record
        # NANO_PG_HA_SYSTEM_ID during its own install. After the last postgres
        # host, it records it with --record-pg-ha-identity (reads only; renders,
        # pulls and restarts nothing), and ITS .env is the one to copy.
        steps.append((pg[0], "record identity", "./install.sh --record-pg-ha-identity  (no --role/--inventory; "
                      "records NANO_PG_HA_SYSTEM_ID in this host's .env; restarts nothing)"))
        steps.append((pg[0], "copy .env", f"stream {pg[0]}'s ~/nano/.env to every other host "
                      "(it now records NANO_PG_HA_SYSTEM_ID; Step 5 of multi-node-ha.md), "
                      "then check that every host's sha256sum matches"))
    for n in nodes:
        name = n["name"]
        if "clickhouse" in r[name]:
            roles = [x for x in r[name] if x in ("clickhouse", "keeper", "postgres")]
            steps.append((name, "install", "--role " + ",".join(roles)))
    for n in nodes:
        name = n["name"]
        if "app" in r[name]:
            steps.append((name, "install", "--role " + ",".join(r[name]) + "  (one at a time, first app host first)"))
    for n in nodes:
        name = n["name"]
        if "ingest" in r[name]:
            steps.append((name, "install", "--role " + ",".join(r[name])))
    print("step\thost\taction\tcommand (NANO_HOST_NAME=<host> NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh ... --inventory /etc/nano/inventory.yaml)")
    for i, (host, action, cmd) in enumerate(steps, 1):
        print(f"{i}\t{host}\t{action}\t{cmd}")
    print("rule\t-\tcopy .env\twhenever a run prints 'The shared .env changed', stream that host's .env "
          "to every other host before the next run anywhere")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--gb-per-day", type=float)
    p.add_argument("--eps", type=float)
    p.add_argument("--avg-event-bytes", type=int, default=AVG_EVENT_BYTES, help="ask: EDR JSON is often ~2300")
    p.add_argument("--retention-days", type=int, default=365)
    p.add_argument("--hot-days", type=int, help="days on local disk; default: the longest of the retention, 90, 30, "
                   "14 or 7 days that fits the data disk (the rest tiers to object storage)")
    p.add_argument("--compression", type=float, default=COMPRESSION)
    p.add_argument("--growth", type=float, default=1.0, help="12-month growth multiplier, e.g. 1.5")
    p.add_argument("--analysts", type=int, default=5, help="analysts searching at the same time of day")
    p.add_argument("--log-sources", type=int, default=20, help="deployed log sources (Vector memory)")
    p.add_argument("--cloud", choices=["aws", "azure", "gcp"], default="aws")
    p.add_argument("--region", help="target region (prices are for the catalog's reference region)")
    p.add_argument("--hosts", help="lay roles out on these existing hosts: a file (or '-') of "
                   "'name address vcpu mem_gib data_disk_gib [zone]' lines; no cloud catalog or cost")
    p.add_argument("--replicas", type=int, default=2)
    p.add_argument("--shards", type=int, help="minimum ClickHouse shard count")
    p.add_argument("--app-hosts", type=int)
    p.add_argument("--ingest-hosts", type=int)
    p.add_argument("--dedicated-ingest", action="store_true", help="never co-locate ingest on ClickHouse hosts")
    p.add_argument("--ch-disk", choices=["auto", "provisioned", "local"], default="auto")
    p.add_argument("--max-nodes", type=int)
    p.add_argument("--budget-usd-month", type=float)
    p.add_argument("--vpc-cidr", default=DEFAULT_VPC_CIDR)
    p.add_argument("--lb", choices=["cloud", "haproxy-pair", "haproxy-dns", "haproxy-single"],
                   help="how traffic reaches nano: a managed cloud LB (default for cloud plans, recommended on any "
                   "cloud), two HAProxy hosts with keepalived and a floating IP (needs L2/VRRP), two HAProxy hosts "
                   "in DNS with health-checked failover (no floating IP; ~1-2 min failover), or one HAProxy host "
                   "(a single point of failure at the edge)")
    p.add_argument("--lb-address", action="append", default=[], help="HAProxy host private address (repeat for a pair)")
    p.add_argument("--lb-vip", help="keepalived floating address for --lb haproxy-pair")
    p.add_argument("--trusted-proxy-cidr", action="append", default=[],
                   help="extra load-balancer source CIDR (repeatable), e.g. the GCP load balancer address as /32")
    p.add_argument("--lab", "--allow-undersized", dest="lab", action="store_true",
                   help="with --hosts: plan hosts that miss the production sizing anyway, for evaluation and test "
                   "clusters only; the plan, inventory and firewall script are labelled NOT FOR PRODUCTION")
    p.add_argument("--json", action="store_true")
    p.add_argument("--nodes-tsv", action="store_true",
                   help="print one tab-separated line per VM (for the cloud CLI loops) and exit")
    p.add_argument("--install-order", action="store_true", help="print the install.sh runs in order and exit")
    p.add_argument("--port-matrix", action="store_true", help="print the firewall flows as a Markdown table and exit")
    p.add_argument("--firewall-tsv", action="store_true",
                   help="print one rule per line: port, target group, source group, key, when; and exit")
    p.add_argument("--preflight-args", action="store_true",
                   help="print host, address and the exact preflight.sh flags for each host of this plan, and exit")
    p.add_argument("--firewall-script", action="store_true",
                   help="print ready-to-paste DOCKER-USER (iptables) and UFW rules for this plan's addresses and exit")
    p.add_argument("--edge-source-cidr", action="append", default=[],
                   help="with --firewall-script and HAProxy hosts: a network allowed to reach 443 on them "
                   "(repeatable: user LAN, VPN, log senders). Required; 0.0.0.0/0 only when given explicitly")
    p.add_argument("--inventory-schema", choices=sorted(SCHEMAS), default="full-ha",
                   help=f"full-ha = nano {FULL_HA_RELEASE}+ (several app hosts, 3 postgres hosts); "
                   "pre-2.0.7 = what earlier releases accept (one app, one postgres)")
    p.add_argument("--inventory-out", help="write inventory.yaml here ('-' for stdout)")
    p.add_argument("--cluster-name", default="nano")
    p.add_argument("--deployment-id", default="lab-plan", help="the app.nano.rs NANO_DEPLOYMENT_ID")
    p.add_argument("--app-hostname", default="nano.example.com")
    p.add_argument("--ingest-hostname", default="ingest.nano.example.com")
    p.add_argument("--tls-server-name", default="nano-private.example.com")
    p.add_argument("--tls-dir", default="/var/lib/nano/tls/staged")
    p.add_argument("--ingest-lb-address", help="private DNS name of the internal ingest load balancer (port 443)")
    p.add_argument("--ingest-lb-tls-name", help="its certificate name; the certificate must chain to cluster.tls.ca")
    return p


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    if a.port_matrix or a.firewall_tsv:
        schema = schema_for(a.inventory_schema)
        if a.firewall_tsv:
            print_firewall_tsv(schema)
        else:
            print(port_matrix_markdown(schema))
        return 0
    try:
        plan = make_plan(a)
        if plan.get("lab") and (a.nodes_tsv or a.install_order or a.firewall_script or a.preflight_args):
            print(LAB_BANNER, file=sys.stderr)
        if a.nodes_tsv:
            print_nodes_tsv(plan)
            return 0
        if a.install_order:
            print_install_order(plan, schema_for(a.inventory_schema))
            return 0
        if a.firewall_script:
            sys.stdout.write(firewall_script(plan, schema_for(a.inventory_schema), a.edge_source_cidr))
            return 0
        if a.preflight_args:
            print("host\taddress\tpreflight.sh flags")
            for row in preflight_args(plan, schema_for(a.inventory_schema)):
                print("\t".join(row))
            return 0
        if a.inventory_out:
            text = render_inventory(plan, a, a.inventory_schema)
            if a.inventory_out == "-":
                sys.stdout.write(text)
                return 0
            Path(a.inventory_out).write_text(text, encoding="utf-8")
    except PlanError as error:
        print(f"plan: {error}", file=sys.stderr)
        return 2
    if a.json:
        json.dump(plan, sys.stdout, indent=2, sort_keys=True)
        print()
    elif a.inventory_out:
        # Only the result and the warnings: the plan itself is what the operator already reviewed.
        if plan.get("lab"):
            print(LAB_BANNER)
        print(f"wrote {a.inventory_out} ({a.inventory_schema} schema, {plan['summary']['total_vms']} hosts)")
        print_warnings(plan)
    else:
        print_text(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

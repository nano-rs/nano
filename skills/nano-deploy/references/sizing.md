# Sizing

Run the calculator and show its output to the operator:

```bash
python3 scripts/size.py --eps <EPS> --retention-days <DAYS> --topology single|ha3|helm [--growth 1.5]
```

## The source of truth

The Self-run install guide (nano.rs/docs → Self-run install → Size the host,
and Retention and disk) is the authority. It marks the ratios as
extrapolated until load-tested.

| Daily volume | Average rate | vCPU | RAM | Data disk (SSD), 365 d | 90 d |
|---|---|---|---|---|---|
| up to 5 GB | ~60 EPS | 4 | 16 GB | 750 GB | 200 GB |
| 10–15 GB | ~120–170 EPS | 8 | 32 GB | 1.5 TB | 500 GB |
| 25–50 GB | ~300–600 EPS | 16 | 64 GB | 3–6 TB | 1–2 TB |
| 50–100 GB | ~600–1,200 EPS | 16–32 | 64–128 GB | 6–12 TB | 2–3 TB |

- Rates assume about 1 KB per event. Plan for bursts of 3× the average.
- Disk = GB/day × retention days ÷ compression ÷ 0.75 (merge headroom). Plan
  for 5:1 compression until the operator measures their own (Settings →
  Storage & Retention). Keep the OS and Docker images on a separate disk of
  about 100 GB.
- Above about 100 GB/day, use Kubernetes.
- Enrichment (geo/ASN, Tor, ThreatFox) is on by default and needs at least
  6 GB for ClickHouse. Any host with 16 GB of RAM or more clears that. The
  installer sizes every container from the host on each run. To pin a value,
  add it below the managed block in `.env`.
- Older data can move to S3-compatible object storage (storage tiering) and
  stays searchable. Configure that after install.

## Worked example: ~140 EPS, 1-year retention

`size.py --eps 141 --retention-days 365` gives about 12 GB/day and about
890 GB stored at 5:1:

- **single node:** 8 vCPU, 32 GB RAM, 1.5 TB data SSD plus a 100 GB OS disk;
- **3-node HA:** three 8 vCPU / 32 GB hosts. `nano-1` (app, PostgreSQL,
  Keeper) gets a 250 GB data disk. `nano-2` and `nano-3` (ClickHouse
  replicas, Keeper, ingest) get 1.5 TB each.
  Add a small redundant load balancer.

## What HA means here

The 3-node Compose layout keeps two ClickHouse replicas, a 3-member Keeper
quorum and ingest on the two ClickHouse hosts. One app host and one PostgreSQL host
remain. If `nano-1` fails, the stored events stay safe on the replicas, but
the UI, API, search, detections and alerting stop until it is back. Ingest
stops at the load balancer too, because the ingest nodes report not-ready
without the app API, so senders must buffer and retry. Mitigations: a
hypervisor HA restart of `nano-1`, tested backups, or Kubernetes with
`clickhouse.replicas: 2` and external PostgreSQL for full application HA.
Two or more app hosts (see multi-node-ha.md, "Several app hosts") keep the
UI, search and alerting up through the loss of an app host; PostgreSQL stays
a single host.
Say this plainly to the operator.

## Cloud planner model

`scripts/plan.py` sizes a **fully highly available** layout (nano 2.0.7+: 2+
app hosts, 3 PostgreSQL members, ClickHouse replicas in different failure
domains, N+1 ingest), either on new cloud VMs (`--cloud`) or on VMs the
operator already has (`--hosts`); see [cloud-vm.md](cloud-vm.md). `size.py`
stays the calculator for single-node, 3-node and Helm sizing.

Nothing in nano is load-validated above about **5,300 EPS** (5,267 EPS, 30 s).
Above that, every plan is marked `EXTRAPOLATED`. Its ratios are calibrated on an
external 16 TB/day Vector + ClickHouse estate (MEASURED there, not on nano),
then adjusted for nano's heavier pipeline. The load-test ladder (NAN-5191)
replaces them with nano measurements.

Source labels: **MEASURED-agentLake** = measured on that external estate;
**nano-measured** = measured on nano or read from its shipped config;
**INFERRED** = derived or estimated.

### Volume

| Constant | Value | Source |
|---|---|---|
| Event size | 1 KB (ask; EDR JSON is often ~2.3 KB) | nano-measured planning default |
| Compression | 5:1 until measured (nano dev measured 11.7-12x on `logs`) | nano-measured |
| Peak hour | 1.36 × average | MEASURED-agentLake (21.8 TB/day peak hour at 16 TB/day) |
| Bursts | 3 × average, absorbed by buffers | nano-measured guidance |

### ClickHouse

| Constant | Value | Source |
|---|---|---|
| Busy CPU | 7.6 vCPU per TB/day | MEASURED-agentLake (122 busy cores at 16 TB/day, 22-MV cascade) |
| nano write factor | × 1.15 (108-113 skip indexes vs 13; same MV count) | INFERRED (NAN-5182) |
| Utilisation targets | 70 % average, 85 % peak hour | INFERRED (NAN-5184 acceptance) |
| Query headroom | 0.3 concurrent queries per analyst, 1 vCPU each per node, capped at 30 | INFERRED; cap nano-measured (admission limit 30) |
| Memory | at least 4 GiB per vCPU and 32 GiB; the cloud families picked give 8 GiB per vCPU | INFERRED floor; 8:1 MEASURED-agentLake (503 GiB / 64 vCPU) |
| Node size | 4 to 64 vCPU; more load adds shards | nano-measured (installer clamps ClickHouse to 64 cores) |
| Local disk | hot days × GB/day ÷ compression × 1.15 ÷ shards, ≤ 70 % full, ≤ 16 TiB per node (on existing VMs, ≤ their largest data disk) | INFERRED; 70 % = tiering move point (nano-measured) |
| Hot days | the longest of retention, 90, 30, 14, 7 that fits; the rest moves to object storage | INFERRED; 7 d = MEASURED-agentLake TTL move |
| Replicas | 2 per shard, each in a different zone | full-HA requirement |

So ClickHouse provisions about 14 vCPU per TB/day per shard. At 13 TB/day that
is 3 shards × 64 vCPU (× 2 replicas), inside NAN-5184's 3-4 × 64 vCPU range for
20 TB/day. Replicas add availability, not capacity: the plan shows their cost.

### Ingest (Vector)

| Constant | Value | Source |
|---|---|---|
| CPU per event | 0.5 ms (reference) × 2 for nano's pipeline = 1 ms | MEASURED-agentLake × INFERRED factor (NAN-5180) |
| One Vector per host, ceiling | 20k ev/s ÷ 2 ≈ 10k ev/s per ingest host today | MEASURED-agentLake (18-22k ev/s per process) × INFERRED |
| After the role split | ~25k ev/s per 32-vCPU host (50k ÷ 2) | MEASURED-agentLake (9 readers per VM) × INFERRED; needs NAN-5179 |
| Hosts | enough for the peak hour with one host down (N+1), at least 2 | full-HA requirement |
| Disk buffer | the installer's budget: 2 × Vector memory, 2-32 GiB, over 2 + 6 × shards buffers | nano-measured (`resource-sizing.sh`, `disk-buffer-budget.env`) |
| Buffer floor at volume | ≥ 1 GiB per sink | MEASURED-agentLake (500-790 MB used of 1 GiB at 10-25 s flush latency) |
| Vector memory at ≥ 1 TB/day | ≥ 8 GiB | MEASURED-agentLake (2 GB OOM-looped 581 times) |
| Memory per deployed source | ~10 MiB | nano-measured (470-512 MiB at 50 sources, NAN-5193) |
| Request concurrency | keep 6 | nano-measured default; MEASURED-agentLake (16 wedged production) |
| Co-locate on ClickHouse hosts | up to 100 GB/day | nano-measured guidance |

The plan reports how many minutes of peak ingest the buffer rides out per
host. The planner mirrors the installer's arithmetic exactly, and a test runs
`resource-sizing.sh` on every planned host to prove it.

### App, PostgreSQL, Keeper

| Constant | Value | Source |
|---|---|---|
| App hosts | 2 (stateless, behind the LB); 4 vCPU / 16 GiB, 8 / 32 above 100 GB/day | MEASURED-agentLake (2 × 8 vCPU / 31 GiB at 16 TB/day, load1 0.55); floor INFERRED |
| PostgreSQL | 3 members, 2-12 vCPU by volume, provisioned IOPS | INFERRED (NAN-5190: write rate at volume unmeasured) |
| Keeper | 3, on the PostgreSQL hosts, +1 vCPU / 4 GiB | MEASURED-agentLake (2 vCPU / 7 GiB VMs at 16 % CPU) |
| etcd, Valkey, Sentinel, HAProxy | +1 vCPU / 2 GiB on the PostgreSQL hosts | INFERRED (NAN-5214) |

### Settings the volume needs

The planner emits tuned settings, not only node counts. Settable ones go into
the inventory as `resources.overrides`; the others name the issue that makes
them settable:

| Setting | When | How today | Issue |
|---|---|---|---|
| `CLICKHOUSE_MAX_CONCURRENT_INSERT_QUERIES` (+ total ceiling) | in-flight inserts exceed the installer default | inventory override, ≤ 1000 (MEASURED-agentLake) | NAN-5175 |
| Merge pool 16 × 2 = 32 slots | ≥ 1 TB/day per shard | inventory override (MEASURED-agentLake) | NAN-5177 |
| `CLICKHOUSE_INGEST_MAX_MEMORY_USAGE` ≥ 16 GiB | ≥ 1 TB/day | inventory override (MEASURED-agentLake) | NAN-5176 |
| ingest workload threads ≥ 2 × cores | above ~5,300 EPS | not settable (fixed at 4) | NAN-5174 |
| per-user insert caps | ≥ 1 TB/day | not settable | NAN-5175 |
| flush 5 s / 256 MiB, 64 KiB blocks | ≥ 1 TB/day | not settable | NAN-5176 |
| merge memory soft limit, per-table merge cap | ≥ 1 TB/day per shard | not settable | NAN-5177 |
| sink acks, DLQ, `delete_failed_message=false` | always | not settable | NAN-5178 |
| Vector role split | more than 4 ingest hosts | not available | NAN-5179 |
| TTL-driven tiering | when part of retention is cold | free-space tiering only | NAN-5183 |

Growth: adding shards or replicas to a live cluster is not a supported flow
yet (NAN-5201). Pass `--growth` for the 12-month volume.

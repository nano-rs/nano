# Sizing

Run the calculator and show its output to the operator:

```bash
python3 scripts/size.py --eps <EPS> --retention-days <DAYS> --topology single|ha3|helm [--growth 1.5] [--avg-event-bytes 300|1000|2000] [--ingest-path raw|preshaped]
```

## The source of truth

- **One server:** the Self-run install guide (nano.rs/docs → Self-run install
  → Size the host, and Retention and disk). The table below copies it.
- **Several servers (3-node HA, full HA):** the High availability guide's
  [Server sizing](https://nano.rs/docs/getting-started/high-availability#server-sizing)
  table, per role. `plan.py` computes the same numbers and raises them with
  volume, and `preflight.sh --topology ha` uses them as its default minimums.
  In short, for up to about 100 GB/day: ClickHouse (+ ingest) 8 vCPU / 32 GB;
  app 4 / 16; postgres + keeper 4 / 16 with a 100 GB SSD; app + postgres +
  keeper on one host 8 / 32; HAProxy 2 / 2. A VM sold as 16 GB reports about
  15 GiB and counts as 16 GB.
- **4 vCPU / 16 GB everywhere** runs nano for evaluation and functional tests
  only: `plan.py --lab` plans it and labels it NOT FOR PRODUCTION.

The guides mark the ratios as extrapolated until load-tested.

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
UI, search and alerting up through the loss of an app host. With three
`postgres` hosts (nano 2.0.7+, [postgres-ha.md](postgres-ha.md)) PostgreSQL
fails over too: about 20-25 s of failed writes and sign-ins when the leader's host dies, a few seconds for a planned switchover.
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
then adjusted for nano's heavier pipeline. nano's own load tests will replace
them with nano measurements.

Source labels: **MEASURED-external** = measured on that external estate;
**nano-measured** = measured on nano or read from its shipped config;
**INFERRED** = derived or estimated.

### Volume

| Constant | Value | Source |
|---|---|---|
| Event size | 1 KB (ask; EDR JSON is often ~2.3 KB) | nano-measured planning default |
| Compression | 5:1 until measured (nano dev measured 11.7-12x on `logs`) | nano-measured |
| Peak hour | 1.36 × average | MEASURED-external (21.8 TB/day peak hour at 16 TB/day) |
| Bursts | 3 × average, absorbed by buffers | nano-measured guidance |

### ClickHouse

| Constant | Value | Source |
|---|---|---|
| Busy CPU | 7.6 vCPU per TB/day | MEASURED-external (122 busy cores at 16 TB/day, 22-MV cascade) |
| nano write factor | × 1.15 (108-113 skip indexes vs 13; same MV count) | INFERRED |
| Utilisation targets | 70 % average, 85 % peak hour | INFERRED (acceptance targets) |
| Query headroom | 0.3 concurrent queries per analyst, 1 vCPU each per node, capped at 30 | INFERRED; cap nano-measured (admission limit 30) |
| Memory | at least 4 GiB per vCPU and 32 GiB; the cloud families picked give 8 GiB per vCPU | INFERRED floor; 8:1 MEASURED-external (503 GiB / 64 vCPU) |
| Node size | 4 to 64 vCPU; more load adds shards | nano-measured (installer clamps ClickHouse to 64 cores) |
| Local disk | hot days × GB/day ÷ compression × 1.15 ÷ shards, ≤ 70 % full, ≤ 16 TiB per node (on existing VMs, ≤ their largest data disk) | INFERRED; 70 % = tiering move point (nano-measured) |
| Hot days | the longest of retention, 90, 30, 14, 7 that fits; the rest moves to object storage | INFERRED; 7 d = MEASURED-external TTL move |
| Replicas | 2 per shard, each in a different zone | full-HA requirement |

So ClickHouse provisions about 14 vCPU per TB/day per shard. At 13 TB/day that
is 3 shards × 64 vCPU (× 2 replicas), inside the 3-4 × 64 vCPU range
expected for 20 TB/day. Replicas add availability, not capacity: the plan shows their cost.

### Ingest (Vector)

| Constant | Value | Source |
|---|---|---|
| CPU per event | 0.5 ms (reference) × 2 for nano's pipeline = 1 ms | MEASURED-external × INFERRED factor |
| One Vector per host, ceiling | 20k ev/s ÷ 2 ≈ 10k ev/s per ingest host today | MEASURED-external (18-22k ev/s per process) × INFERRED |
| After the role split | ~25k ev/s per 32-vCPU host (50k ÷ 2) | MEASURED-external (9 readers per VM) × INFERRED; needs the Vector role split |
| Hosts | enough for the peak hour with one host down (N+1), at least 2 | full-HA requirement |
| Disk buffer | the installer's budget: 2 × Vector memory, 2-32 GiB, over 2 + 6 × shards buffers | nano-measured (`resource-sizing.sh`, `disk-buffer-budget.env`) |
| Buffer floor at volume | ≥ 1 GiB per sink | MEASURED-external (500-790 MB used of 1 GiB at 10-25 s flush latency) |
| Vector memory at ≥ 1 TB/day | ≥ 8 GiB | MEASURED-external (2 GB OOM-looped 581 times) |
| Memory per deployed source | ~1 GiB at 16 sources; the installer floors Vector at 1 GiB plus 64 MiB per source beyond 16 | nano-measured 2026-11-13 (NAN-5193) |
| Vector CPU model | vCPU = 2 (peak) × events/s ÷ events per core; events/s = GB/day × 1e9 ÷ 86,400 ÷ average event bytes (`NANO_AVG_EVENT_BYTES` / `sizing.avgEventBytes` / `size.py --avg-event-bytes`, default 1000) | nano-measured (NAN-5372); `resource-sizing.sh`, Helm `sizing.*` and `size.py` share the constants (a test keeps them equal) |
| Vector events per core, raw logs parsed by nano | 1,900 (measured 1,950-6,500 across 16 shipped OCSF parsers: EDR 3,600-4,600, Okta 1,950, Palo Alto 2,527, Zeek 2,509). Per TB/day: ~41 vCPU at 300 B (firewall/flow), ~13 at 1,000 B (mixed/identity), ~7 at 2,000 B (EDR) | nano-measured 2026-11-13, 0.61.0-nano.11, after parsers#67 |
| Vector events per core, pre-shaped OCSF (Tenzir/Cribl) | 45,000 (ship-only measured 90-120k; half for bursts): ~0.5 vCPU per TB/day at 1,000 B | nano-measured 2026-11-13 |
| Request concurrency | keep 6 | nano-measured default; MEASURED-external (16 wedged production) |
| Co-locate on ClickHouse hosts | up to 100 GB/day | nano-measured guidance |

The plan reports how many minutes of peak ingest the buffer rides out per
host. The planner mirrors the installer's arithmetic exactly, and a test runs
`resource-sizing.sh` on every planned host to prove it.

### App, PostgreSQL, Keeper

| Constant | Value | Source |
|---|---|---|
| App hosts | 2 (stateless, behind the LB); 4 vCPU / 16 GiB, 8 / 32 above 100 GB/day | MEASURED-external (2 × 8 vCPU / 31 GiB at 16 TB/day, load1 0.55); floor INFERRED |
| PostgreSQL | 3 members, 2-12 vCPU by volume, provisioned IOPS | INFERRED (write rate at volume unmeasured) |
| Keeper | 3, on the PostgreSQL hosts, +1 vCPU / 4 GiB | MEASURED-external (2 vCPU / 7 GiB VMs at 16 % CPU) |
| etcd, Valkey, Sentinel, HAProxy | +1 vCPU / 2 GiB on the PostgreSQL hosts | INFERRED |

### Settings the volume needs

The planner emits tuned settings, not only node counts. Settable ones go into
the inventory as `resources.overrides`; the others are marked "not settable
from the inventory yet". Each row carries a plain-words topic:

| Setting | When | How today | Topic |
|---|---|---|---|
| `CLICKHOUSE_MAX_CONCURRENT_INSERT_QUERIES` (+ total ceiling) | in-flight inserts exceed the installer default | inventory override, ≤ 1000 (MEASURED-external) | insert concurrency |
| Merge pool 16 × 2 = 32 slots | ≥ 1 TB/day per shard | inventory override (MEASURED-external) | merge capacity |
| `CLICKHOUSE_INGEST_MAX_MEMORY_USAGE` ≥ 16 GiB | ≥ 1 TB/day | inventory override (MEASURED-external) | async-insert flushes |
| ingest workload threads ≥ 2 × cores | above ~5,300 EPS | not settable (fixed at 4) | ingest workload threads |
| per-user insert caps | ≥ 1 TB/day | not settable | insert concurrency |
| adaptive flush 1-5 s (1-10 s at ≥ 10 TB/day) / 256 MiB | ≥ 1 TB/day | `NANO_PLANNED_GB_PER_DAY` in the shared `.env` (NAN-5345) | async-insert flushes |
| 64 KiB compress blocks | always | shipped in `mergetree.xml` (NAN-5345) | async-insert flushes |
| part limits 2,000/4,000 (5,000/10,000), merge memory 50% of RAM | ≥ 1 TB/day | `NANO_PLANNED_GB_PER_DAY` in the shared `.env` (NAN-5345) | merge capacity |
| per-table merge cap | ≥ 1 TB/day per shard | not settable | merge capacity |
| prevalence `*_final_refresh` every 30 min (60 at ≥ 10 TB/day; 10 default) | ≥ 1 TB/day | `NANO_PLANNED_GB_PER_DAY` in the shared `.env`; Helm `migrations.prevalenceRefreshMinutes` (NAN-5345) | refresh CPU |
| sink acks, DLQ, `delete_failed_message=false` | always | not settable | Vector delivery |
| Vector role split | more than 4 ingest hosts | not available | Vector role split |
| TTL-driven tiering | when part of retention is cold | free-space tiering only | TTL tiering |

Growth: adding shards or replicas to a live cluster is not a supported flow
yet. Pass `--growth` for the 12-month volume.

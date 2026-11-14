# Dry run: v2.0.23, 2026-11-14 (not a published result)

This run proved the kit end to end on Rackspace Spot: provisioning, install,
content, load, metrics and the JSON output. It used the smallest topology
and short phases, so **don't quote these numbers**. The published runs
happen on v2.0.25 with the ceiling and SOC-day topologies.

| Host | Spot class (us-central-dfw-2) | CPU | Market / bid (USD/h) |
|---|---|---|---|
| app1 (app, postgres, keeper) | gp.vs2.large, 4 vCPU / 16 GB | AMD EPYC-Genoa | 0.04 / 0.08 |
| ch1 (clickhouse) | gp.vs2.xlarge, 8 vCPU / 32 GB | AMD EPYC-Genoa | 0.08 / 0.15 |
| ing1 (ingest) | ch.vs2.xlarge, 8 vCPU / 16 GB | AMD EPYC-Genoa | 0.06 / 0.12 |
| blaster1 (load generator) | ch.vs2.large, 4 vCPU / 8 GB | AMD EPYC-Genoa | 0.04 / 0.06 |

The nano hosts cost $0.18/h at market and $0.35/h at our bids.

## Timings

| Step | Time |
|---|---|
| vs2 pools requested until all 4 VMs assigned | 2.5 min |
| VMs ready (SSH plus cloud-init Docker) | +1 min |
| `prep` (firewall, disks) | 1 min |
| `install` | about 10 min total. The app host took 409 s; ClickHouse and ingest under 1 min each. |
| `content`: 6 OCSF parsers deployed | 35–85 s each, 6 min in all. Sysmon needed 2 attempts. |
| `tools`: log-blaster build in a rust container | 1 min |

The first attempt, on vs1 classes in us-east-iad-1, was abandoned. Those
hosts (Xeon E5-2670 / E5-2680 v2) have no AVX2, and `install.sh` correctly
refused them. The vs1 ingest pool also took about 9.5 minutes to get a
server.

## Results

**SOC day:** 10 minutes at the 50 GB/day rate, with 3 analysts and 2
dashboard viewers. There were no Agent Lane agents (see below).
[`socday.json`](socday.json)

- **Throughput:** 586 eps stored, measured at 49.75 GB/day of raw bytes.
- **Loss:**
  - 352,212 events sent and 352,212 stored.
  - 2,396 markers sent and 2,396 stored, all distinct: each one stored
    exactly once.
- **Ingest lag:** p50 6.6 s, p99 11.1 s.
- **Search, server-side p50 / p95:**
  - triage: 45 / 316 ms;
  - hunt: 45 / 318 ms;
  - IR: 36 / 132 ms.
- **Dashboards:** an 8-panel refresh took 542 ms at p95.
- **Analyst errors:** 7.5%. 4 of the 94 corpus queries fail on OCSF:
  - 3 are 400s caused by UDM-only syntax in the corpus;
  - 1 is a 500, filed as **NAN-5416**.

**Ceiling ramp:** 1,000, then 2,500, then 4,000 eps, 150 s per step.
[`ceiling.json`](ceiling.json)

- Every step passed every SLO. The dry-run ramp stops at 4,000 eps (335
  GB/day measured).
- **Lag p99 by step:** 11.1 s, then 9.5 s, then 5.2 s. Lag falls as load
  rises because insert batches fill sooner.
- **Utilization at 4,000 eps:**
  - ClickHouse CPU: p95 59%;
  - ingest CPU: p95 36%;
  - blaster: under 2%.

**Detections:** 200 rules. Event-to-alert latency comes from the OCSF
findings nano writes.

- **Scheduled rules:** p50 14.8 s, p95 138 s. This includes the 1- and
  5-minute schedules.
- **Real-time rules:** p50 97 s, p95 291 s. That is slower than expected;
  investigate in the full run before publishing anything about real-time.
- Rule noise is high: 15.5k findings in the window. After this run, the
  network-port rules were reworked to skip everyday Windows ports.

## Not exercised

**Agent Lane agents.** Agent Lane needs the install-time listener (TLS,
allow-list, host firewall). On v2.0.23 it also drops agent tokens after
about 40 s on Compose (NAN-5402, fixed in v2.0.24). The k6 `agents` scenario
was checked with `k6 inspect` only. The v2.0.25 SOC-day run must enable the
listener at install.

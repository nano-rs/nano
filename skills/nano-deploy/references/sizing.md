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
Say this plainly to the operator.

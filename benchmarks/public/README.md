# nano public benchmark

Everything needed to reproduce the numbers published on nano.rs: the topology,
the dataset generator and its seed, the query corpus, the detection set, the
run script and the raw results. The method is in [METHODOLOGY.md](METHODOLOGY.md).

There are two benchmarks:

| Benchmark | Question it answers | Output |
|---|---|---|
| **Ceiling** | How much can a role-split cluster ingest before it breaks, and what breaks first? | sustained events/s and GB/day, ingest lag p50/p99, query latency at peak, cost per hour |
| **SOC day** | At a normal sizing tier (50 and 100 GB/day), how does nano behave with analysts, detections, agents and dashboards all running? | search p50/p95 by query class, event-to-alert latency, ingest lag, CPU/memory/disk headroom, cost per GB/day |

This is deliberately thin. The heavy lifting is existing nano tooling:

- **Install:** the enterprise bundle's `install.sh` and role-split renderer
  (`deploy/compose/render-inventory.py`), with the
  [nano-deploy](../../skills/nano-deploy/) helpers.
- **Data:** [`tools/log-blaster`](../../tools/log-blaster/), seeded.
- **Queries:** [k6](https://k6.io) with the IR/SOC corpus in
  [`benchmarks/results/soc_ir_corpus.json`](../results/soc_ir_corpus.json).
- **Agents:** the [Agent Lane kit](../../skills/nano-agentlane/) recipes.

## Layout

```
benchmarks/public/
  run.sh                        thin orchestrator (prep, install, content, tools, smoke, socday, ceiling, collect)
  lib/setup_content.py          parsers, log sources, ingest tokens, detections, API key (runs on the app host)
  lib/collect.py                run artifacts + ClickHouse metrics -> results JSON (runs on your workstation)
  lib/hoststat.sh               5 s CPU / memory / disk / network samples on every host
  detections/build_rules.py     generates detections/rules.json (200 scheduled rules)
  dashboards/soc-overview.json  the panels a SOC wall display refreshes
  k6/soc_mix.js                 analysts + dashboards + Agent Lane agents, one k6 run
  topology/*.hosts.env.example  dry run, SOC day and ceiling topologies (Rackspace Spot vs2 classes)
  schema/results.schema.json    the results format
  results/                      raw JSON results of published runs
```

## The dataset is the generator

The benchmark doesn't ship gigabytes of logs. It ships the generator and a
seed. `log-blaster --seed N` builds the same fleet (hosts, users, addresses)
and the same per-worker event content every time.

To make a byte-identical file, for example the published sample day:

```bash
cargo build --release -p log-blaster
./target/release/log-blaster --seed 20261114 --assets 5000 --eps 590 \
  --events 50976000 --chain-interval-secs 0 --start-time 2026-01-01T00:00:00Z --output sample-day.ndjson
sha256sum sample-day.ndjson     # identical on every machine
```

`--output` is single-threaded and runs on a simulated clock, so the bytes are
fixed. Live runs (`--blast`) seed each sender process with `seed + N`. Event
content repeats, and timestamps follow the wall clock.

## Running it

You need a workstation with `ssh`, `python3` and `curl`. You also need a Self-run
license (enrollment values `LICENSE_URL`, `LICENSE_TOKEN`, `NANO_DEPLOYMENT_ID`)
and plain Ubuntu 24.04 VMs.

`NANO_VERSION` in the topology file picks the release. From v2.0.30
`install.sh` uses `images.enterprise.customer.lock` by default and logs in to
the registry itself with the license in `.env` (a private temporary
`DOCKER_CONFIG`; `~/.docker` is never touched), so `install` fetches no
registry credential and runs no `docker login`. For v2.0.29 and earlier it
still fetches the one-hour credential, logs in on every host and passes
`NANO_IMAGES_LOCK`. From v2.0.30 the installer also refuses hosts under its
size floor (2 vCPU, 8 GB RAM, 40 GB free for ClickHouse hosts); the benchmark
topologies are far above it.

- **CPU:** every nano host needs AVX2. ClickHouse 26.6+ and Keeper require it,
  and `install.sh` refuses hosts without it. On Rackspace Spot, use **vs2**
  server classes. The vs1 classes run on Xeon E5 v1/v2 and have no AVX2.
- **Disk:** if a VM has a large unformatted disk, `prep` puts Docker's data
  root on it.

### Provisioning on Rackspace Spot

1. Create a VM cloudspace named `bench-*` in a region with vs2 classes
   (us-central-dfw-2), with your SSH key.
2. Create one VM pool per role: Ubuntu 24.04, bid well above market, and
   record both prices in a `PRICING_FILE` next to your topology.
   - If the tool you use sends a null `vmCloudSpaceRef` (HTTP 422), use
     [`lib/spot_pool.sh`](lib/spot_pool.sh). It POSTs the `VMPool` with the
     reference set, using a refresh token kept in a 0600 file that is never
     printed.
   - Pool user data that installs Docker and touches
     `/var/lib/nano-bench-ready` is what `prep` waits for:
     results README for the exact script.
3. In the dry run, vs2 pools got servers in about 2.5 minutes.
4. **Tear down when you're done.** Delete the cloudspace, which also deletes
   its pools. Then confirm that the cloudspace and pool lists no longer show
   anything named `bench-`.

The VMs share a private 10/8 network. The inventory, TLS certificate and
senders use the private addresses; SSH uses the public ones.

### Agent Lane for the SOC-day run

Agent Lane is enterprise-only and off by default. Its listener (TLS on 8444,
source allow-list, host firewall) is configured at install time; see
`skills/nano-agentlane/references/connect.md` and the nano.rs Agent Lane docs.
Enable it on the app host before `content --agents 2`, and use v2.0.24 or
later: on v2.0.23 Compose, tokens are dropped after about 40 s (NAN-5402).
Agent Lane allows 2 active tokens by default on the SOC-day cluster size, and
each token has a default quota of 600 queries an hour, so the k6 mix gives
each agent its own token and a 6 to 12 s think time.

On v2.0.25 a role-split install needed `NANO_AGENTLANE_NODE_URLS` set by hand
(NAN-5451). From v2.0.29 the installer renders it, and the stock config works.
If `content` reports `agentlane token 1 -> 502` or `503` right after install,
the app's ClickHouse proxy briefly marked the node down (NAN-5519). Run
`python3 -I ~/bench/setup_content.py --out ~/bench --rules ~/bench/rules.json
--rules-only --agentlane 2` on the app host a few minutes later, then copy
`~/bench/agentlane.json` to the load generator.

```bash
cp benchmarks/public/topology/socday.hosts.env.example /secure/scratch/socday.hosts.env   # fill in IPs + key
T=/secure/scratch/socday.hosts.env
benchmarks/public/run.sh prep    --topology $T
AGENTLANE=1 benchmarks/public/run.sh install --topology $T --pki /secure/scratch/pki \
    --enrollment-cmd 'cat /secure/scratch/enrollment.env'
benchmarks/public/run.sh content --topology $T --run-id socday-50 --agents 2
benchmarks/public/run.sh tools   --topology $T
benchmarks/public/run.sh smoke   --topology $T --run-id socday-50
benchmarks/public/run.sh socday  --topology $T --run-id socday-50 --gb-per-day 50 --duration 4h --agents 2
ACTIVE_INGEST=3 benchmarks/public/run.sh ceiling --topology $T --run-id ceiling-ing3-r1   # on the ceiling topology
```

Results land in `benchmarks/public/results/<run-id>/{socday,ceiling}.json`.
The v2.0.23 dry run's output is kept under
[`results/dryrun-v2.0.23-2026-11-14/`](results/dryrun-v2.0.23-2026-11-14/)
as a worked example. It isn't a published result.

### What happens to secrets

The license, admin password, ingest tokens, API key, Agent Lane tokens and
(v2.0.29 and earlier) registry credential live only on the hosts, in 0600 files. They move host to
host through SSH pipes and are never printed or written on the workstation.
The private CA key stays in `--pki`; keep that directory out of the repo.
Results never contain host addresses.

### Network exposure

Spot VMs have public addresses only. `prep` installs a host firewall
(`NANO-BENCH` chain on INPUT and DOCKER-USER) that admits the cluster members
and the operator's address only. Cluster traffic uses the installer's default
private TLS.

## Results

`collect.py` writes one JSON per scenario, defined by
[`schema/results.schema.json`](schema/results.schema.json). Every published
number comes from these files.

# How we benchmark nano

*Draft for the nano.rs docs and marketing page. Every number below comes from
the nano v2.0.29 runs on 2026-11-16; the raw JSON is in
[`results/v2.0.29-2026-11-16/`](results/v2.0.29-2026-11-16/).*

nano is a SIEM, so we measure what a security team feels. Can it keep up with
everything we send? How long until an event is searchable? How long until a
detection fires? Do hunts stay fast while all of that is going on? What does
it cost?

We publish the whole kit, so you can rerun every number on your own hardware:
the generator and its seed, the query corpus, the detection set, the topology,
the run scripts and the raw JSON results.

## Two benchmarks

### 1. Ceiling: how far does one cluster go?

**Topology** (a role-split Compose install on plain VMs, as a customer would
run it):

| Role | Hosts | Spot class | vCPU / RAM |
|---|---|---|---|
| app (UI, API, search, detections, PostgreSQL, Keeper) | 1 | gp.vs2.xlarge | 8 / 32 GB |
| ClickHouse shard 1 (also Keeper) | 1 | gp.vs2.2xlarge | 16 / 64 GB |
| ClickHouse shard 2 (also Keeper) | 1 | mh.vs2.xlarge | 8 / 64 GB |
| ingest (Vector behind nginx) | 3, then 4 | ch.vs2.xlarge | 8 / 16 GB |
| load generators (log-blaster, k6) | 2 | gp.vs2.xlarge | 8 / 32 GB |

The load generators aren't part of the cluster and aren't in its cost. Twelve
sender processes send straight to the ingest hosts and spread the load evenly,
as a customer's load balancer would. All four ingest hosts are installed; in
the 3-host runs the fourth gets no traffic and is left out of the cost.

On 2026-11-16 Spot had no gp.vs2.2xlarge capacity left in us-central-dfw-2
(spot and on-demand bids both stayed unfulfilled), so the second ClickHouse
shard ran on an mh.vs2.xlarge (8 vCPU / 64 GB). The v2.0.25 runs used two
gp.vs2.2xlarge hosts. With 3 ingest hosts, ingest still saturated first. With
4, the smaller shard did.

**Method.** We ramp events per second in steps. Each step runs for 5 minutes,
followed by a 60-second drain. After each step we check four service-level
objectives:

- **Lag:** ingest-to-searchable lag p99 is at most 60 s.
- **Zero loss:** every event the senders had acknowledged is stored, and
  every sequence marker is stored exactly once.
- **Errors:** fewer than 0.1% of events fail at the sender after retries.
- **Keeps up:** the senders achieve at least 95% of the step's target rate.

The fourth objective is the one that breaks. Past its ceiling, nano doesn't
drop events or fall behind. The ingest tier pushes back on the senders, so
they slow down, lag stays flat and nothing is lost. Without "keeps up", a ramp
would pass every step forever at the same real throughput.

The **ceiling** is the highest step that meets all four. Each configuration
is ramped three times. The first ramp uses coarse steps (6,000 events/s); the
second and third start below it and use 2,000 events/s steps. We report the
median, where it broke and which resource was saturated. For v2.0.29, Spot
VM freezes forced a second fresh install partway through, so the median
pools every ramp that reached a passing step on either install: 6 with 3
ingest hosts and 5 with 4.

We expect Vector on the ingest hosts to saturate first. To show it, we add a
fourth ingest host and run the ramps again. If the ceiling moves, the
bottleneck was ingest, not storage.

**Reported:**

- sustained events/s and GB/day;
- lag p50 and p99 at the ceiling;
- query latency at peak (k6 analysts running during every step);
- per-host CPU, memory and disk;
- cost per hour.

| | 3 ingest hosts | 4 ingest hosts |
|---|---|---|
| Sustained events/s | 22,150 | 27,047 |
| Sustained GB/day | 1,879 | 2,295 |
| Ingest lag p50 / p99 | 4.7 s / 9.1 s | 5.2 s / 25.0 s |
| Search p95 at peak (hunt tier) | 676 ms | 959 ms |
| First saturated resource | ingest (Vector, 62 to 78% CPU; 72 to 78% in 5 of 6 ramps) | ClickHouse shard 2 (8 vCPU, 86 to 95% CPU) |
| Cluster cost per hour (Spot market) | $0.81 | $0.89 |

### 2. A normal SOC day

**Topology:**

| Role | Hosts | Spot class | vCPU / RAM |
|---|---|---|---|
| app | 1 | gp.vs2.large | 4 / 16 GB |
| ClickHouse | 1 | mh.vs2.xlarge | 8 / 64 GB |
| ingest | 1 | gp.vs2.xlarge | 8 / 32 GB |
| load generator (log-blaster, k6) | 1 | ch.vs2.large | 4 / 8 GB |

This one cluster shape is run at two sizing tiers: **50 GB/day** and
**100 GB/day**, on two identical clusters side by side. Ingest is held steady
at the tier's rate for 4 hours, once per tier. All of this runs at the same
time:

- **Analysts:** 8 analysts replay 94 real investigations from our IR/SOC
  corpus at the time window an analyst actually uses:
  - triage: 15 min to 1 h;
  - hunting: 6 to 24 h;
  - retro IR: up to 7 days.

  Each analyst pauses 5–20 s between queries to read results.
- **Detections:** 200 scheduled rules: 56 run every minute and 144 every 5
  minutes. They cover endpoint, identity, network, proxy and cloud, and are all
  in alerting mode.
- **Agents:** 2 AI agents hunt through Agent Lane, nano's read-only SQL lane
  for agents. Two is the most active agent tokens Agent Lane allows by default
  on this cluster size, and each agent has its own token. They run the agent
  kit's 24 recipes in native ClickHouse SQL and pause 6 to 12 s between
  queries, about the length of an LLM agent's turn. That keeps each agent
  under Agent Lane's default quota of 600 queries an hour per token.
- **Dashboards:** 4 wall displays refresh an 8-panel SOC overview every
  minute, with the cache bypassed.

**Reported:**

| | 50 GB/day | 100 GB/day |
|---|---|---|
| Search p50 / p95: triage | 44 / 318 ms | 46 / 253 ms |
| Search p50 / p95: hunt | 46 / 318 ms | 49 / 291 ms |
| Search p50 / p95: retro IR | 53 / 310 ms | 55 / 263 ms |
| Dashboard refresh (8 panels) p95 | 733 ms | 692 ms |
| Agent Lane query p95 | 82 ms | 127 ms |
| Event-to-alert p50 / p95: all rules | 19.1 / 32.2 s | 19.0 / 28.9 s |
| Event-to-alert p50 / p95: tool-launch rules (every minute) | 18.2 / 25.2 s | 19.2 / 25.3 s |
| Ingest lag p50 / p99 | 6.2 / 11.1 s | 6.4 / 11.5 s |
| CPU / memory / disk headroom (busiest host) | 74% / 86% / 87% | 67% / 84% / 83% |
| Cost per GB/day ingested | $0.116 per GB | $0.058 per GB |

## The data

We don't publish a pile of logs. The dataset **is** the generator,
[`log-blaster`](../../tools/log-blaster/), with a fixed seed (`20261114`).

The generator builds a simulated company of 5,000 hosts (20,000 for the
ceiling): workstations, laptops and servers, with users, IP plans and process
trees. It emits telemetry from five sources, with profiles taken from real lab
telemetry:

| Source | Share | OCSF classes |
|---|---|---|
| Windows Sysmon | 60% | Process, Network, File activity |
| Windows Security events | 10% | Authentication |
| Web proxy | 12% | HTTP Activity |
| Apache access logs | 10% | HTTP Activity |
| AWS CloudTrail | 8% | API Activity |

Events average about 1.1 KB raw. **GB/day is measured, not estimated:** it is
the raw bytes nano stored, divided by elapsed time.

The same seed always produces the same fleet and the same event content. To get
a byte-identical file, run `log-blaster --seed 20261114 --output`. We publish
one generated day as NDJSON and Parquet, so you can load it into anything.

Every event goes through the real ingest path:

1. HTTP to nginx and Vector on an ingest host.
2. Authentication with a per-source ingest token.
3. The source's official OCSF parser.
4. ClickHouse.

Nothing is written directly to the database.

## How we measure

- **Ingest-to-searchable lag:** for every stored event, the time it was
  inserted into ClickHouse minus its event timestamp. The generator stamps
  events as it sends them, so this covers the network, Vector, parsing,
  batching and the insert. We report p50, p95, p99 and max.
- **Zero loss:**
  - Every sender counts the events the ingest tier acknowledged.
  - We check that the stored count is at least the acknowledged count.
  - Each batch also carries one sequence-numbered marker. The run passes only
    if the stored markers, counted and counted distinct, both equal the
    markers sent. That proves each one landed exactly once.
- **Search latency:**
  - The server-side execution time nano reports, and the round trip k6 sees.
  - Reported per query class: triage, hunt and IR.
  - Dashboard refreshes and Agent Lane queries are reported separately.
- **Event-to-alert latency:** nano writes every detection as an OCSF
  Detection Finding (class 2004). For each finding, we take the time it was
  stored minus the timestamp of the newest event it covers. All benchmark
  rules are scheduled, so this includes the rule's interval by design: a
  5-minute rule waits up to 5 minutes. We also report the 20 tool-launch
  rules, which run every minute, on their own.
- **Headroom:** CPU busy %, memory used % and disk used % on every host,
  sampled every 5 s. Headroom is 100 minus the p95 (CPU) or the max (memory,
  disk).
- **Cost:** the Rackspace Spot market price of the nano hosts at run time.
  Load generators are excluded. We record our bid too, which is the most we
  could have paid. Cost per GB/day is the cluster's daily cost divided by the
  GB/day it sustained.

## Infrastructure

The runs use **Rackspace Spot** VMs: plain Ubuntu 24.04 machines in one region
(us-central-dfw-2). We bid well above the market price so a run isn't
preempted, and we record both prices.

nano needs AVX2 on every host that runs ClickHouse or Keeper. Spot's vs1
hardware (Xeon E5 v1/v2) doesn't have it, so the benchmark uses vs2 classes.
nano's installer checks this and refuses unsupported CPUs.

The install is what a customer runs:

- The signed enterprise bundle, verified before extraction.
- One inventory file.
- Private TLS between hosts.
- `install.sh` on each host for its own role.

The only addition is a host firewall that admits cluster members only, because
Spot VMs have public addresses.

## Fine print

- These are synthetic but realistic workloads. Your mix of sources and queries
  will differ, so rerun the kit with your own.
- Spot hardware varies between machines of the same class. We record the CPU
  model of every host.
- The SOC-day detections run in alerting mode with a 30-minute cooldown per
  rule. Alert volume reflects the generated data, not a tuned production rule
  set.
- We don't compare against other products. The method and data are public, so
  you can.

nano is made by nano, LLC. The benchmark kit is open source under the same
license as nano's open core.

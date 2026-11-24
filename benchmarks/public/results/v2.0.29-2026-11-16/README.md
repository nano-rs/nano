# nano v2.0.29 benchmark, 2026-11-16

These are the public benchmark runs for nano **v2.0.29**: a stock enterprise bundle,
licensed and installed fresh with the kit's `run.sh` on spot-priced cloud
VMs in one US region. Every host was wiped before the install. The method is in
[`../../METHODOLOGY.md`](../../METHODOLOGY.md). Every number here comes from
the JSON files in this directory, which `lib/collect.py` wrote.

| Directory | What it is |
|---|---|
| `ceiling-install-a/` | Ceiling ramps on the first install (5 ramps; see "What went wrong") |
| `ceiling-install-b/` | Ceiling ramps on a second fresh install of the same topology (7 ramps) |
| `socday-50/`, `socday-100/` | One 4-hour SOC day per tier, each on its own cluster, run side by side |

## Headline numbers

### Ceiling (role-split cluster, spot market price $0.81/h with 3 ingest hosts, $0.89/h with 4)

The medians are over every ramp that reached a passing step, from both installs.

| | 3 ingest hosts | 4 ingest hosts |
|---|---|---|
| Sustained events/s, median (range) | **22,150** (15,345 to 23,097; 6 ramps) | **27,047** (25,079 to 30,882; 5 ramps) |
| Sustained GB/day, median | **1,879** | **2,295** |
| Ingest lag p50 / p99 at the ceiling (median) | 4.7 s / 9.1 s | 5.2 s / 25.0 s |
| Search p95 at peak, hunt / triage (median) | 676 ms / 245 ms | 959 ms / 513 ms |
| What broke first | **Ingest**: Vector at 62 to 78% CPU on the ingest hosts (72 to 78% in 5 of 6 ramps); senders get backpressure and stop keeping up | **The smaller ClickHouse shard** (ch2, 8 vCPU): 86 to 95% CPU, while ingest sat at 64 to 77% |
| Cluster cost per hour (spot market / our bid) | $0.81 / $1.43 | $0.89 / $1.59 |
| Cost per GB/day sustained | $0.0104 per GB | $0.0093 per GB |

- Adding a fourth ingest host moved the ceiling about 22%. Then the
  second ClickHouse shard became the limit. That shard was an 8 vCPU
  mh.xlarge, because the provider had no gp.2xlarge capacity that day.
- No ramp lost data. Every step that broke, broke on **keeps up** (the
  ingest tier pushing back on the senders) or on **lag**. Two steps also
  show `zero_loss: false` at the moment of the check: install B's ing3 r3 at
  24k and ing4 r2 at 28k. In both, lag was longer than the 60 s drain, so
  events were still in flight. We recounted ing3 r3 afterwards: all
  7,144,182 events and all 10,727 markers were stored, each marker exactly
  once. ch1 was gone before we could recount ing4 r2.
- One ramp (`ceiling-install-b/ceiling-ing4-r3`) failed its first step
  (24,000 events/s: lag p99 122 s, 22,602 achieved). It ran right after five
  back-to-back ramps on that install. We report it, but it has no sustained
  value, so it isn't in the median.
- `ceiling-install-b/ceiling-ing4-r4` passed 32,000 (30,882 achieved). Then
  ch1 was lost during the 34,000 step (see below). Its JSON is built from the
  per-step SLO checks, and it has no per-host stats.

### SOC day (app 4 vCPU, ClickHouse 8 vCPU / 64 GB, ingest 8 vCPU; $0.24/h at spot market)

Each tier ran for 4 hours with 8 analysts replaying the 94-query IR/SOC
corpus, 4 dashboard viewers, 2 Agent Lane agents and 200 scheduled
detections in alerting mode.

| | 50 GB/day | 100 GB/day |
|---|---|---|
| Measured ingest | 586 events/s, **49.7 GB/day** | 1,173 events/s, **99.5 GB/day** |
| Events sent / stored | 8,444,268 / 8,444,268 | 16,885,890 / 16,885,890 |
| Markers stored exactly once | 57,444 of 57,444 | 114,870 of 114,870 |
| Search p50 / p95: triage | 44 / 318 ms | 46 / 253 ms |
| Search p50 / p95: hunt | 46 / 318 ms | 49 / 291 ms |
| Search p50 / p95: retro IR | 53 / 310 ms | 55 / 263 ms |
| Dashboard refresh (8 panels) p95 | 733 ms | 692 ms |
| Agent Lane query p50 / p95 | 15 / 82 ms (3,201 queries) | 18 / 127 ms (3,175 queries) |
| Query errors (analysts, dashboards, agents) | 0 / 0 / 0 (20,031 queries) | 0 / 0 / 0 (20,029 queries) |
| Event-to-alert p50 / p95: all rules | 19.1 / 32.2 s | 19.0 / 28.9 s |
| Event-to-alert p50 / p95: every-minute tool-launch rules | 18.2 / 25.2 s | 19.2 / 25.3 s |
| Ingest lag p50 / p99 | 6.2 / 11.1 s | 6.4 / 11.5 s |
| Busiest host (ClickHouse) CPU p95 | 26% (74% headroom) | 33% (67% headroom) |
| Lowest memory / disk headroom | 86% (app) / 87% (ClickHouse) | 84% (app) / 83% (ClickHouse) |
| Cost per GB/day ingested | **$0.116 per GB** ($5.76/day) | **$0.058 per GB** ($5.76/day) |

No search took longer than 1.2 s on the server, no dashboard refresh took longer than 1.4 s, and no query failed. The
SOC-day cluster at 100 GB/day used a third of its ClickHouse CPU. 200
rules wrote 47k and 75k findings; 27 rules fired.

## What went wrong, and what we did about it

- **Spot VM freezes (NAN-5493).** At 16:14 to 16:18 UTC, five VMs froze at once
  across all three clusters: the ceiling's app1 and ing3, soc50's app1, and
  soc100's ingest and ClickHouse hosts. Outbound heartbeats from each
  host, over both its private and public NIC, stopped at the same instant,
  and the hosts never came back. Their pools still showed the bids as
  fulfilled. At 20:40 the ceiling's ch1 dropped as well, but that pool showed
  `Lost`, so it was most likely preempted when the market rose above our bid. So these were
  real hangs, not hosts that were alive but cut off. The load before each
  freeze was ordinary. We replaced the five hosts, wiped every host, and
  reinstalled all three clusters from scratch (install B). Then we reran
  both SOC days in full and all ceiling ramps.
  - The first SOC-day attempts reached 3 h 30 min and were discarded.
    Install A's five completed ceiling ramps are kept, because they finished
    before the freeze.
- **gp.2xlarge capacity.** No second gp.2xlarge could be had, as spot
  or on-demand, so ClickHouse shard 2 ran on mh.xlarge (8 vCPU / 64 GB).
  That shard limits the 4-ingest-host ceiling.
- **Agent Lane token mint (NAN-5519).** On soc100, the first token mint after
  install returned 502 or 503, in both installs. The app's ClickHouse proxy
  had briefly marked its only node down. Rerunning the mint a few minutes
  later worked with the stock config. `socday-100/content.json` keeps the
  original error.
  - On install A only, we had also set `NANO_AGENTLANE_NODE_URLS` by hand
    before retrying. Install B needed no override.

## Not measured

- **Real-time rules.** The detection set is 200 scheduled rules, as in
  v2.0.25.
- **Three agents.** Agent Lane allows 2 active tokens on this ClickHouse size,
  so the SOC day runs 2 agents, each with its own token.

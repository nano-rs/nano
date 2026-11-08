# Demo Performance Report — Real-World IR/SOC Search (2026-05-31)

**Target:** `nano-demo` (GKE, ns `nanosiem`), ClickHouse Cloud backend, ~22M rows/24h of data.
**Measured under live production conditions:** ~200 EPS continuous ingestion + **26 live detection rules** running concurrently. Search load applied via k6 over `kubectl port-forward` to a **single** `nanosiem-search` replica (of 4) — i.e. no load-balancer help, one pod absorbing everything.
**Method:** JWT auth (`/api/auth/login`), read-only. Query corpus: `benchmarks/results/soc_ir_corpus.json`; replayed by `benchmarks/k6/search_realistic.js`.

## TL;DR

Real, source-scoped IR/SOC investigations run **fast at production scale**: triage in tens of ms, hunts double-digit-to-low-hundreds of ms, advanced multi-stage IR generally under ~1.5s — even while the box ingests ~200 EPS and runs 26 detections. The platform's interactive workloads are healthy. The only slow queries are deliberate worst-case stress probes (bare `error` over 24h), which are full-table scans no analyst actually runs (see Appendix).

---

## 1. Real-world corpus — coverage

**94 validated queries across 14 SOC/IR domains, 46 distinct MITRE ATT&CK techniques.** Every query was executed live against the demo (latency/row counts are measured, not estimated). 14 are zero-row **rare-event detectors** (clean-baseline now, fire on first occurrence — e.g. scheduled-task persistence, log clearing, DC enumeration).

Domains: endpoint/EDR (Sysmon), identity/auth, network/proxy, cloud/AWS, web, cross-source IR, persistence, defense-evasion, lateral-movement, exfil/staging, cloud-IAM abuse, impossible-travel, C2/DNS-beaconing, discovery/recon.

## 2. Latency under live load (server-side ClickHouse, 3 concurrent analysts, 210s)

1,117 queries executed, **error rate 0.18%**. All realistic SLO thresholds **passed**.

| Analyst tier | window | p50 | p95 | max | SLO (p95) |
|---|---|---|---|---|---|
| Triage | 15m–1h | **85 ms** | 785 ms | 2.6 s | < 1s ✅ |
| Hunt | 6–24h | **167 ms** | 1.01 s | 2.2 s | < 2s ✅ |
| Advanced IR | 24h–7d | **204 ms** | 1.97 s | 5.7 s | < 5s ✅ |
| **Overall** | mixed | **147 ms** | **1.10 s** | 5.7 s | — |

By domain (p50 / p95): Web 57 / 313ms · Network-proxy 97 / 373ms · Cloud-AWS 124 / 799ms · Identity 126 / 793ms · Cross-source IR 165 / 650ms · Cloud-IAM 63 / 784ms · C2/DNS 173 / 653ms · Impossible-travel 187 / 716ms · Exfil 159 / 729ms · Lateral-movement 152 / 927ms · Defense-evasion 253 / 1077ms · Persistence 287 / 1.30s · Discovery 252 / 1.50s · **Endpoint/EDR 356ms / 4.38s** (the one heavy tail — two full-text/fan-out Sysmon queries; see Findings #2/#3).

> Single-query (idle, one-at-a-time) latencies are even lower — overall median **83 ms**, p95 **489 ms**, max 1.5s. The numbers above include 3-VU contention *plus* live ingest + detection load, so they are an upper bound on what an analyst feels.

## 3. Representative queries (real nPL, measured single-shot)

**Triage (scoped, minutes–1h):**

| Use case | nPL (abbrev.) | win | ms |
|---|---|---|---|
| Encoded PowerShell | `source_type=windows_sysmon action=process_create command_line=/EncodedCommand/i \| stats count by src_host, user` | 1h | 40 |
| Brute force by account | `source_type=windows_event action=logon_failure \| stats count as failures, dc(src_ip) as src_ips by user \| where failures>20` | 1h | 33 |
| Blocked egress | `source_type=conduit_proxy action=deny OR action=blocked \| stats count by src_ip, dest_host` | 1h | 24 |
| Failed AssumeRole | `source_type=aws_cloudtrail action=assumerole status=failure \| stats count by user, src_ip` | 1h | 43 |
| Web auth abuse | `source_type=apache_access (http_status_code=401 OR http_status_code=403) \| stats count by src_ip, uri_path` | 1h | 20 |
| New scheduled task (rare-event) | `source_type=windows_sysmon action=process_create command_line=/(schtasks\|at\.exe).*(\/create\|\/sc )/i` | 24h | 128 |

**Hunt (multi-filter, 6–24h):**

| Use case | nPL (abbrev.) | win | ms |
|---|---|---|---|
| LOLBin → external C2 | `source_type=windows_sysmon action=network_connection (process_name=powershell.exe OR process_name=rundll32.exe OR …) \| stats count by process_name, dest_ip, src_host` | 6h | 93 |
| Failed-then-succeeded | `… \| stats count(eval(action="logon_failure")) as fails, count(eval(action="logon_success")) as wins by user \| where fails>30 AND wins>0` | 6h | 79 |
| Exfil by volume | `source_type=conduit_proxy action=allow \| stats sum(bytes_out) as bytes_out by src_ip, dest_host \| sort -bytes_out` | 6h | 48 |
| AWS recon burst | `source_type=aws_cloudtrail action=/describe.*/ \| stats count as recon_calls by user, src_ip \| where recon_calls>…` | 6h | 37 |
| DNS-based C2 | `source_type=windows_sysmon action=dns_query \| stats count as queries, dc(...) by src_host` | 24h | 131 |
| Geo-spray (web) | `source_type=apache_access enriched_src_country=/China\|Russia\|Iran\|…/ \| stats …` | 24h | 231 |

**Advanced / retro IR (parameter-heavy, multi-stage, 24h–7d):**

| Use case | nPL (abbrev.) | win | ms |
|---|---|---|---|
| Compromise → escalate | `source_type=windows_event \| stats count(eval(action="logon_failure")) as fails, count(eval(action="special_privileges_assigned")) as priv_grants by user \| where fails>100 AND priv_grants>100` | 24h | 62 |
| Single-host timeline | `src_host="ws-exec-087.corp.local" \| timechart span=1h count by action` | 6h | 36 |
| Cloud cred/secret harvest | `source_type=aws_cloudtrail action=/getsecretvalue\|listbuckets\|getobject\|…/ \| stats …` | 24h | 60 |
| AccessDenied spike | `source_type=aws_cloudtrail status=failure \| stats count as denials, dc(action) by user` | 24h | 269 |
| Registry persistence (heavy) | `source_type=windows_sysmon action=registry_value_set CurrentVersion \| top limit=20 src_host` | 24h | 1545 |

**The lever is source-scoping, not window size.** Scoping by `source_type` (+ action/process_name/field filters) lets ClickHouse prune to the relevant partitions/granules, so even 7-day multi-stage hunts stay sub-second-to-~1.5s. The only ~1.5s queries fall back to a **full-text scan** because the discriminating field isn't a UDM column (see Findings #3).

---

## Findings

1. **🐛 Histogram companion crashes on leading-pipe nPL.** Any search-term-less query (`| stats …`, `| timechart …`) logs `Parallel histogram query failed: Syntax error: Empty query`. Main result still 200, but the UI timeline for those queries silently fails. Reproducible & deterministic — `nanosiem-core/src/search/service/core_search`. **Recommend a Linear issue.**

2. **⚙️ count(\*) companion doubles I/O on broad fetches.** Every fetch fires a parallel `count(*)` over all matches; for broad scans `query_log` showed ~18.9 GiB read by the companion alongside the main query. Dominant cost for the heaviest queries. Consider skipping/estimating it for small `limit` or broad keyword searches.

3. **🧱 Some Sysmon detection fields aren't promoted to UDM columns** — `TargetImage`/`GrantedAccess` (process_access → lsass), `TargetObject` (registry Run-keys), DNS query name — they live only in the `message` JSON. So `… TargetImage=lsass.exe` returns 0; analysts must full-text the token (`CurrentVersion Run`) then drill into `message`. This is why the registry-persistence and shared-C2 hunts fall back to ~1.5s full-text scans. **Candidate UDM columns** if these hunts are common.

---

## Appendix — worst-case stress reference (NOT real-world)

`benchmarks/k6/search.js` deliberately runs **bare, unscoped keyword tokens and dense-column regex** to find the ceiling. These are full-table scans no analyst runs; included only to bound behavior. Results: `search.json` (6h), `search_24h.json` (24h).

| Category | 6h p50 / p95 | 24h p50 / p95 |
|---|---|---|
| Bare keyword (`error`, `denied`…) | 3.0s / 9.2s | 10.9s / 36.8s |
| Regex over dense `message` col | 2.0s / 10.9s | 22.3s / 45.8s |
| (everything else: stats/timechart/filter/eval/prevalence) | all sub-second p95 | sub-3s p95 |

Window-bound, not token-bound: `error | stats count` is a flat ~3s over 24h regardless of match count (even `timeout` with **0 matches** = 3.06s) and drops to **0.21s at 1h**. The bare-fetch form is ~2× the count-only cost due to the count(\*) companion (#2). Takeaway: narrower default windows + source-scoping (which real queries already do) keep the engine fast; the 24h bare-keyword path is the only thing that full-scans.

## Artifacts
- `soc_ir_corpus.json` — 94 validated IR/SOC queries (14 domains, 46 MITRE techniques) with measured latencies
- `search_realistic.json` — load-test results under live conditions (this report's §2)
- `search.json` / `search_24h.json` — stress reference (6h / 24h)
- `benchmarks/k6/search_realistic.js` — replays the corpus at per-query analyst windows

## Script changes (uncommitted, main checkout)
`search.js` retargeted to demo source types (`defender_edr`→`windows_sysmon`, logins→`windows_event`, real IP/user/host) + default window 24h→6h. Added `search_realistic.js` + corpus. `concurrent.js` retargeted (personas keep their per-role 1h–7d windows by design). `ingestion.js` untouched.

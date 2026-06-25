# nano - Show HN launch post

> Draft for HackerNews launch. Grounded in the codebase, pressure-tested against a harsh HN-skeptic pass.
> Search for `[FILL IN` and `[DEMO LINK]` / `[GITHUB/SITE LINK]` before posting. Do not ship brackets.

## Title (chosen)

**Show HN: nano – a Rust + ClickHouse SIEM with a piped query language**

Alternates:
- Show HN: nano – lightweight open-core SIEM in Rust on ClickHouse (AGPL)
- Show HN: nano – I built a Rust/ClickHouse SIEM to stop paying per GB to search my own logs

---

## Short HN submission (THIS is what goes in the HN text box, ~220 words)

I've spent 20+ years in cybersecurity and been around computers my whole life, and one of the hardest things to actually find is a SIEM that is reliable, fast, and modern (and cost effective). So I built nano, a SIEM to fit that slot.

nano is a SIEM platform with an open-core (AGPL) model for people who want reliable, familiar, fast search over their logs, and purchase tiers that layer AI on top: detection generation, parser writing, and autonomous investigation. The open core is a complete SIEM on its own (ingest, search, a real detection engine, alerting), not a teaser for the paid version. It has limits, lighter case management for example, but it stands on its own.

It's a few Rust services on ClickHouse for logs and Postgres for metadata. Vector handles ingestion with auto-generated VRL parsers into a 187-column unified data model. Search is nPL, a piped query language that compiles to ClickHouse SQL: `failed login | stats count by src_ip | where count > 10`. Detections move Staging to Live to Alerting and carry risk scores, so you triage by accumulated risk per entity instead of drowning in one-to-one alerts.

I load-tested the hosted demo (ClickHouse Cloud, ~22M rows/24h) under live ingest plus 26 running detections: 94 real SOC queries, p50 147ms, p95 1.1s, 0.18% errors, all on a single search pod. The full-scan cliff (bare keyword/regex over 24h) is in the benchmark too. I'd rather show it than hide it.

There's a live demo (the button on the site above, first name + email only so we can mail you your tenant). Code: https://github.com/nano-rs/nano. Tell me where it's wrong.

---

## Long version (NOTE: this now lives as the blog post — see BLOG_POST.md)

Kept here for reference. Do not paste this into the HN text box; it's the blog/README long-form. The short submission above goes in the box, and the first comment below carries the depth.

## The post

I've spent 20+ years in cybersecurity and been around computers my whole life, and one of the hardest things to actually find is a SIEM that is reliable, fast, and modern (and cost effective). So I built nano, a SIEM to fit that slot.

nano is a SIEM platform with an open-core (AGPL) model for people who want reliable, familiar, fast search over their logs, and purchase tiers that layer AI on top: detection generation, parser writing, and autonomous investigation. The open core is a complete SIEM on its own (ingest, search, a real detection engine, alerting), not a teaser for the paid version. It has limits, lighter case management for example, but it stands on its own.

nano is not a generic analytics platform with a security skin. It's built around how a SOC actually works: ingest, parse, hunt, write a detection, tune it, alert. That's the whole loop.

**What it actually is**

A few independent Rust services (API, search, and a background jobs worker) compiled from one Cargo workspace. ClickHouse stores the logs. Postgres holds metadata: rules, alerts, users, dashboards, audit. Both databases are required, on purpose. If ClickHouse is unreachable or its schema is behind, the services fail fast at boot rather than quietly serving you stale or partial data.

Ingestion goes through Vector. nano generates the Vector pipeline configs (VRL parsers, routers, combiners) and deploys them, so logs flow Vector -> ClickHouse directly and don't bottleneck on the API. Parsers normalize into a Unified Data Model: 187 explicit, indexed columns (src_ip, dest_ip, user, process_name, command_line, and so on). Anything that isn't a UDM field lands in a single `ext` JSON column, so you stay extensible without schema migrations. Out of the box the parser set covers the common sources I needed: syslog, Windows Event Log, Sysmon (JSON), and Apache/HTTP server logs, with the VRL-generation path meant to extend to whatever you point at it.

Search uses nPL (nano Pipe Language), a piped query language: `failed login | stats count by src_ip | where count > 10 | sort -count`. It parses with nom combinators and compiles to ClickHouse SQL.

**On trusting code that an LLM helped write**

I'm self-taught and I lean on LLMs hard to ship. On a security tool the fair question is: you let a model help write the thing that parses untrusted analyst queries and codegens SQL, and I'm supposed to trust it with my logs? So here's the boundary I actually hold the code to. The query path is SELECT-only enforced, runs against a banned-function list (no mutations, no system/file functions), and the generated SQL is parameterized rather than string-concatenated from user input. The nPL-to-SQL codegen has regression tests that pin the exact emitted SQL, so a refactor can't silently change a query's meaning. LLM-assisted authorship doesn't mean unreviewed query-execution paths, and I'd rather you attack that surface than take my word for it.

This is also the honest reason I reach for Rust. The query path parses untrusted input and codegens SQL, and the detection engine runs continuously, so I wanted the borrow checker watching the concurrency and parsing and predictable performance without a GC pausing mid-hunt. Rust doesn't make the detection logic correct, that's still on me, but it takes a whole class of crashes and memory bugs off the table.

**Why ClickHouse**

Logs are columnar and time-partitioned by day. An `src_ip` search reads the `src_ip` column, not your whole event. PREWHERE skips entire granules when the timestamp or an indexed field fails, and keyword search hits a tokenized bloom filter via `hasToken()` instead of scanning text. The 187 UDM columns are pre-indexed (bloom/set indexes), so the common hunts don't parse JSON at all. ClickHouse compression does the rest, and there's no per-GB ingestion license.

So instead of hand-waving, I load-tested it against the hosted demo (ClickHouse Cloud, ~22M rows per 24h) under live conditions: ~200 EPS still ingesting, 26 detection rules running, and all the search load aimed at a single search pod of four, no load balancer in front of it. I replayed a corpus of 94 real SOC/IR queries spanning 14 domains and 46 ATT&CK techniques. 1,117 executions, 0.18% error rate. Median 147ms, p95 1.10s. Broken out by how an analyst actually works:

- Triage (15m to 1h windows): p50 85ms, p95 785ms
- Hunt (6 to 24h): p50 167ms, p95 1.01s
- Advanced multi-stage IR (24h to 7d): p50 204ms, p95 1.97s

The honest catch is that the lever is source-scoping, not window size. Real queries filter by `source_type` and a field or two, which lets ClickHouse prune to the right partitions and granules, so even a 7-day hunt stays sub-second to about 1.5s. If you instead run a bare unscoped keyword, or a regex over the raw `message` column across 24h, you get a full-table scan and it's slow (think 10 to 45s). I left those in the benchmark on purpose as a ceiling. No analyst actually runs them, but I'd rather show you the cliff than pretend it isn't there.

**nPL over raw SQL**

SOC analysts already think in pipes (Splunk SPL, Unix). A five-stage hunt reads left to right and maps cleanly onto ClickHouse CTEs, one stage per `|`, so you can debug incrementally instead of untangling nested subqueries. Concretely, what works today: `stats`, `eval`, `where`, `sort`, `head`, `table`, `timechart`, and regex extraction, plus security-first extensions Splunk makes you bolt on: `cidr_match()`, `is_private_ip()`, `defang()`/`refang()` for safe IOC sharing, `entropy()` for spotting obfuscation, and `risk`/`prevalence`/`anomaly` commands. What does not exist yet: `transaction`, `eventstats`, `streamstats`, `map`, `append`. It is not an SPL clone and I'm not claiming SPL parity. The parser is bounded by design (max 25 pipe commands, max 50 nesting levels) so a runaway query can't explode into CTE soup.

**Detection lifecycle and risk-based alerting**

Alert fatigue is the actual enemy, so this is the part I've spent the most time on. Rules move through three modes: Staging (development, never executed), Live (matches counted and logged as searchable signals, but no alerts), and Alerting (production). A rule earns trust on real data before it ever pages anyone. Every firing, alert-bound or not, is logged as a searchable event in ClickHouse, so you tune a rule by querying its own history and audit exactly what fired when.

On top of that, rules carry a risk score and can group signals by entity (a user, a host, an IP) for cumulative scoring across a time window, so you triage by accumulated risk rather than drowning in one-to-one detections. Prevalence filtering lets a rule fire only on rare or newly-seen artifacts. To be clear: these are tools, not magic. They let a good analyst reduce noise. They don't tune your rules for you, and a high risk score means "lots of signal," not "definitely real."

**Auth and isolation**

Every request goes through central middleware: a JWT or a hashed API key, with OIDC SSO and TOTP MFA available. Permissions are resolved server-side rather than baked into the token, against a fine-grained role model (feature:action permissions over Admin, Editor, and ReadOnly), and token revocation uses a denylist shared across replicas. Security-relevant actions are audited to both Postgres and the searchable log store, so you can hunt your own audit trail in nPL.

On tenancy: nano is not a shared multi-tenant cluster with row-level scoping. Each customer runs as its own isolated deployment with a dedicated ClickHouse and Postgres, so one customer's data never sits in the same database as another's. The hosted demo (more below) is the single shared-tenant environment, on purpose, so it stays low-friction to try.

**AI features (where they live)**

In the hosted/enterprise build the AI is a set of focused agents. Detection generation writes a rule from a threat description, then validates it: parses it, runs it against ClickHouse to confirm it executes, and shows you the historical match rate so you know if it'll be noisy. To be precise: that proves the rule runs and shows how often it would fire, it does not prove it detects the right behavior. That's still a human review step. Parser generation turns sample logs into VRL. There's a query agent for natural-language-to-nPL, and a shadow investigation that runs on new case creation: it extracts entities, fires a deterministic playbook of hunting queries, and the LLM writes the narrative and recommendations on top. It's analyst emulation, not a free-roaming agent, and I think that's a feature.

**Open-core split**

The open build is AGPL-3.0 and ships ingestion, search, the detection engine, alerting, and the enrichment marketplace, fully functional. AI and Cases are the enterprise tier, gated at compile time by an `EDITION` build arg, and that enterprise code is not present in the open build's binary. For the workflows AI assists with, the open build still gives you the underlying primitives: VRL parser validation, the nPL command reference, and rule templates, so you write detections and parsers by hand rather than via an in-app agent.

**Try it**

Live demo: [DEMO LINK]
Code / site: [GITHUB/SITE LINK]

The demo is a shared tenant, and it's the same environment I ran the numbers above against, so you're hitting a box that's also ingesting and running detections while you query it. Other people are poking it at the same time you are, so if something feels slow that's contention, not the architecture. If you want a clean read, the one-command Docker install spins up the full stack locally so you can throw your own logs at it.

**What I'm looking for**

Mostly: does the detection lifecycle and risk model match how your team actually triages, or am I solving my own problem and assuming it's everyone's? Also keen on nPL gaps (what SPL/KQL muscle memory breaks), ClickHouse schema critiques, and whether the open-core line is drawn in a fair place. If you're already running Wazuh, Security Onion, or Matano, I'd genuinely like to hear where nano would and wouldn't earn a slot. Tell me where it's wrong.

---

## First comment (post right after submitting)

A few architecture notes that didn't fit up top, and the comparisons people will reasonably ask for:

**vs. the obvious open incumbents.** Wazuh is agent-and-rules-centric (HIDS heritage) and its store isn't a columnar analytics engine, so ad-hoc hunting over large windows is not its strength; nano is store-first and query-first. Matano is the closest architecturally (columnar, lake-style) but it's an Iceberg/object-store data lake you query with SQL; nano is a running SIEM service with a piped query language, a staged detection lifecycle, and entity risk scoring rather than a lake plus your own glue. Security Onion bundles a lot of tooling around Elastic; nano is narrower and built around ClickHouse and one query language. If your honest need is "Elastic Security Analytics or OpenSearch already does this," nano's bet is the detection lifecycle and risk/prevalence model, not raw search.

**Services.** Three Rust binaries from one workspace: `nanosiem-api` (REST, port 3000), `nanosiem-search` (query execution, port 3002), and a background jobs worker (detection scheduling, enrichment). Axum + tower across all of them, OpenAPI/Swagger auto-generated via utoipa, Prometheus metrics exported. Search is multi-pod and coordinates via a Redis/Dragonfly-backed result cache (SHA-hashed query keys) and a shared JWT denylist; it falls back to per-pod state if Redis isn't there.

**Storage detail.** The `ext` column is `JSON(max_dynamic_paths=512)` with ZSTD(3). Enrichment (GeoIP/ASN via dictGet, IOC threat-intel, prevalence, identity) is computed as MATERIALIZED columns at insert time, so enrichment is atomic and always in sync with the row. One sharp edge: ClickHouse excludes MATERIALIZED columns from `SELECT *`, so the multi-stage CTE codegen has to re-add them explicitly at each stage or you get errors. There are query guards (subsearch result limits, group-array size caps, a default 100k result cap) that exist to stop a small JOIN from exhausting memory. They're safety valves, not performance claims.

**Query safety.** nPL parses with nom into an AST, then codegens ClickHouse SQL. The path is SELECT-only with a banned-function list and parameterized values; the emitted SQL for each command is pinned by regression tests so codegen can't silently drift. Each pipe stage becomes a CTE sharing one table scan. `table_view` mode projects only visible columns and fetches the full row on expand, so the initial result set doesn't drag 187 columns per row. Keyword search prefers `hasToken()` (bloom-filtered) and falls back to `position()` for tokens with special chars (`cmd.exe`, literal IPs). Note nano uses ClickHouse's regex engine (RE2), so PCRE lookahead/lookbehind won't work, check your patterns.

**Detection internals.** Real-time rules generate a materialized view per rule (`mv_rt_detection_{rule_id}`) writing to a signals table; a signal processor polls that table (~1.5s) and bridges matches into Postgres alerts, optionally grouping them into cases. The MV path validates DDL field-name safety and rejects unsupported constructs (keyword/subsearch) up front. Scheduled and test-rule runs share the exact same `evaluate_window()` evaluator, so "test" and "prod" can't silently diverge in query semantics, and it records MTTD (earliest event timestamp vs. detection time) as a histogram metric.

**Build.** Multi-stage Dockerfile, cargo-chef for dependency caching, mold for linking, LTO in release, binaries built sequentially to keep peak memory sane. The `EDITION` build arg gates the enterprise crate (Cases, AI, risk scoring) at compile time; the open build genuinely doesn't carry that code.

**Benchmark methodology** (for the latency numbers up top). k6 over `kubectl port-forward` to one of four `nanosiem-search` replicas, so a single pod absorbed the entire load with no load-balancer help, while the cluster kept ingesting ~200 EPS and running 26 live detection rules. JWT auth, read-only, server-side timings pulled from ClickHouse `system.query_log` (not just round-trip). The corpus is 94 queries I hand-validated as things an analyst would actually type, including 14 zero-row rare-event detectors. The worst-case appendix (bare keyword / dense-column regex over 24h) is a separate run included specifically to find the ceiling. Same harness is in the repo under `benchmarks/` if you want to point it at your own data. Single-shot idle latencies are lower still (median 83ms, p95 489ms); the headline numbers include 3-way contention plus the live ingest and detection load, so treat them as an upper bound on what an analyst feels.

Happy to go deeper on any of it. The nPL-to-SQL codegen and the risk/prevalence model are where I've spent the most time and would most like the scrutiny.

---

## Notes for Dan

**Safe / grounded (post as-is):** Rust services + Cargo workspace; dual-DB fail-fast at boot; Vector -> ClickHouse pipeline gen; 187 UDM columns + single `ext` JSON; nPL pipes -> nom -> ClickHouse SQL with CTE-per-stage; SELECT-only + banned-function + parameterized + codegen regression tests; three-mode detection lifecycle; signal logging; risk/prevalence/entity grouping; AGPL open-core with `EDITION`-gated enterprise crate absent from the open binary; real-time MV limits + scheduler `FOR UPDATE SKIP LOCKED` + the rollback-releases-lock failure story; `ext` as `JSON(max_dynamic_paths=512)` ZSTD(3); MATERIALIZED-not-in-`SELECT *` edge; RE2 regex caveat.

**Performance numbers are now REAL** (sourced from `benchmarks/results/DEMO_SMOKE_REPORT.md`, run 2026-05-31 against nano-demo / ClickHouse Cloud, ~22M rows/24h, single search pod under live load). The old `[FILL IN]` brackets are gone. These are defensible and honest (single pod, no LB, live ingest + 26 rules, worst-case appendix shown). This is the strongest part of the post now, lead with it in the comments if perf gets questioned.

**Still to fill before posting (do NOT ship the brackets):**
- `[DEMO LINK]` / `[GITHUB/SITE LINK]`. The "72hr" demo duration was left out as unverifiable; only add a duration/SLA if confirmed.
- Parser source list (syslog / Windows Event Log / Sysmon / Apache) is from your config tree, double-check it matches what actually ships in the open build before claiming it.
- The vs.-incumbents comment characterizes Wazuh/Matano/Security Onion from general knowledge; re-read it for anything you'd consider unfair before posting, since those projects' maintainers may show up.

**Heads-up on the benchmark commentary (HN will probe these):**
- The 0.18% error rate is real but someone will ask what errored. Know the answer (timeouts on the heavy tail, or the leading-pipe histogram-companion bug noted in the report). Don't get caught flat.
- "Single pod of four, no load balancer" is a great flex but invites "so what does 4 pods + LB do." Have a one-liner even if it's "haven't formally measured the scale-out curve yet."
- The demo runs ~22M rows/24h, which is roughly ~20GB/day, not the "50-100 GB/day" design target. If you keep the 50-100 framing anywhere in marketing, be clear that's the design point, not what this specific benchmark proved.

**Have ready for the comment section (the three threads most likely to spawn):**
1. **SQL-injection / query safety deep-dive.** Be ready to show or describe the SELECT-only enforcement point, the banned-function list, and one concrete codegen regression test. Highest-signal attack vector and your biggest credibility win if you answer crisply.
2. **Detection content.** "A SIEM with no rule library is a query engine" is the predictable jab, and someone will ask "do I start from zero." Have a crisp answer for what ships today (nPL rules, MITRE tagging as metadata) and how you intend people to not start cold. Sigma is intentionally out of the post, so don't volunteer it; if asked directly, give your real current stance rather than a roadmap promise.
3. **Auth / isolation.** Expect "how is tenant isolation enforced, how do roles work." The post now states the real model (dedicated stack per customer, fine-grained RBAC, shared-denylist revocation, dual-sink audit), which is a strength, so lean into it. Be ready to confirm: each customer gets its own ClickHouse + Postgres (not row-level scoping), Admin/Editor/ReadOnly roles over `feature:action` permissions resolved server-side, OIDC SSO + TOTP MFA, and audit events queryable in nPL.

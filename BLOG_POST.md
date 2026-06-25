# nano: a Rust and ClickHouse SIEM, and why I built it

> Paste-ready blog post for blog.nano.rs (Emdash editor, edit the existing post in place).
> The Emdash block editor accepts pasted markdown; headings, bold, lists, and code blocks convert on paste. If a code block or heading doesn't convert cleanly, reformat that one block inline.
> Fill the two links (demo + GitHub) before publishing. Suggested taxonomy below the post.

---

## Title (chosen)

**nano: a Rust and ClickHouse SIEM, and why I built it**

Alternates:
- I built a SIEM in Rust on ClickHouse to stop paying per GB to search my own logs
- nano: a lightweight, open-core SIEM for people who actually run a SOC

## Excerpt

After 20+ years in cybersecurity, the hardest thing to actually find is a SIEM that is reliable, fast, modern, and cost effective. So I built nano: an open-core (AGPL) SIEM in Rust on ClickHouse, with a piped query language and a real detection lifecycle, plus paid tiers that add AI for detection generation, parsing, and investigation. Here is what it is and why every piece is the way it is.

---

## The post

I've spent 20+ years in cybersecurity and been around computers my whole life, and one of the hardest things to actually find is a SIEM that is reliable, fast, and modern (and cost effective). So I built nano, a SIEM to fit that slot.

nano is a SIEM platform with an open-core (AGPL) model for people who want reliable, familiar, fast search over their logs, and purchase tiers that layer AI on top: detection generation, parser writing, and autonomous investigation. The open core is a complete SIEM on its own (ingest, search, a real detection engine, alerting), not a teaser for the paid version. It has limits, lighter case management for example, but it stands on its own.

nano is not a generic analytics platform with a security skin. It's built around how a SOC actually works: ingest, parse, hunt, write a detection, tune it, alert. That's the whole loop.

### What it actually is

A few independent Rust services (API, search, and a background jobs worker) compiled from one Cargo workspace. ClickHouse stores the logs. Postgres holds metadata: rules, alerts, users, dashboards, audit. Both databases are required, on purpose. If ClickHouse is unreachable or its schema is behind, the services fail fast at boot rather than quietly serving you stale or partial data.

Ingestion goes through Vector. nano generates the Vector pipeline configs (VRL parsers, routers, combiners) and deploys them, so logs flow Vector to ClickHouse directly and don't bottleneck on the API. Parsers normalize into a Unified Data Model: 187 explicit, indexed columns (src_ip, dest_ip, user, process_name, command_line, and so on). Anything that isn't a UDM field lands in a single `ext` JSON column, so you stay extensible without schema migrations. Out of the box the parser set covers the common sources I needed: syslog, Windows Event Log, Sysmon (JSON), and Apache/HTTP server logs, with the VRL-generation path meant to extend to whatever you point at it.

Search uses nPL (nano Pipe Language), a piped query language: `failed login | stats count by src_ip | where count > 10 | sort -count`. It parses with nom combinators and compiles to ClickHouse SQL.

### On trusting code that an LLM helped write

I'm self-taught and I lean on LLMs hard to ship. On a security tool the fair question is: you let a model help write the thing that parses untrusted analyst queries and codegens SQL, and I'm supposed to trust it with my logs? So here's the boundary I actually hold the code to. The query path is SELECT-only enforced, runs against a banned-function list (no mutations, no system/file functions), and the generated SQL is parameterized rather than string-concatenated from user input. The nPL-to-SQL codegen has regression tests that pin the exact emitted SQL, so a refactor can't silently change a query's meaning. LLM-assisted authorship doesn't mean unreviewed query-execution paths, and I'd rather you attack that surface than take my word for it.

This is also the honest reason I reach for Rust. The query path parses untrusted input and codegens SQL, and the detection engine runs continuously, so I wanted the borrow checker watching the concurrency and parsing and predictable performance without a GC pausing mid-hunt. Rust doesn't make the detection logic correct, that's still on me, but it takes a whole class of crashes and memory bugs off the table.

### Why ClickHouse

Logs are columnar and time-partitioned by day. An `src_ip` search reads the `src_ip` column, not your whole event. PREWHERE skips entire granules when the timestamp or an indexed field fails, and keyword search hits a tokenized bloom filter via `hasToken()` instead of scanning text. The 187 UDM columns are pre-indexed (bloom/set indexes), so the common hunts don't parse JSON at all. ClickHouse compression does the rest, and there's no per-GB ingestion license.

So instead of hand-waving, I load-tested it against the hosted demo (ClickHouse Cloud, ~22M rows per 24h) under live conditions: ~200 EPS still ingesting, 26 detection rules running, and all the search load aimed at a single search pod of four, no load balancer in front of it. I replayed a corpus of 94 real SOC/IR queries spanning 14 domains and 46 ATT&CK techniques. 1,117 executions, 0.18% error rate. Median 147ms, p95 1.10s. Broken out by how an analyst actually works:

- Triage (15m to 1h windows): p50 85ms, p95 785ms
- Hunt (6 to 24h): p50 167ms, p95 1.01s
- Advanced multi-stage IR (24h to 7d): p50 204ms, p95 1.97s

The honest catch is that the lever is source-scoping, not window size. Real queries filter by `source_type` and a field or two, which lets ClickHouse prune to the right partitions and granules, so even a 7-day hunt stays sub-second to about 1.5s. If you instead run a bare unscoped keyword, or a regex over the raw `message` column across 24h, you get a full-table scan and it's slow (think 10 to 45s). I left those in the benchmark on purpose as a ceiling. No analyst actually runs them, but I'd rather show you the cliff than pretend it isn't there.

### nPL over raw SQL

SOC analysts already think in pipes (Splunk SPL, Unix). A five-stage hunt reads left to right and maps cleanly onto ClickHouse CTEs, one stage per `|`, so you can debug incrementally instead of untangling nested subqueries. Concretely, what works today: `stats`, `eval`, `where`, `sort`, `head`, `table`, `timechart`, and regex extraction, plus security-first extensions Splunk makes you bolt on: `cidr_match()`, `is_private_ip()`, `defang()`/`refang()` for safe IOC sharing, `entropy()` for spotting obfuscation, and `risk`/`prevalence`/`anomaly` commands. What does not exist yet: `transaction`, `eventstats`, `streamstats`, `map`, `append`. It is not an SPL clone and I'm not claiming SPL parity. The parser is bounded by design (max 25 pipe commands, max 50 nesting levels) so a runaway query can't explode into CTE soup.

### Detection lifecycle and risk-based alerting

Alert fatigue is the actual enemy, so this is the part I've spent the most time on. Rules move through three modes: Staging (development, never executed), Live (matches counted and logged as searchable signals, but no alerts), and Alerting (production). A rule earns trust on real data before it ever pages anyone. Every firing, alert-bound or not, is logged as a searchable event in ClickHouse, so you tune a rule by querying its own history and audit exactly what fired when.

On top of that, rules carry a risk score and can group signals by entity (a user, a host, an IP) for cumulative scoring across a time window, so you triage by accumulated risk rather than drowning in one-to-one detections. Prevalence filtering lets a rule fire only on rare or newly-seen artifacts. To be clear: these are tools, not magic. They let a good analyst reduce noise. They don't tune your rules for you, and a high risk score means "lots of signal," not "definitely real."

### Auth and isolation

Every request goes through central middleware: a JWT or a hashed API key, with OIDC SSO and TOTP MFA available. Permissions are resolved server-side rather than baked into the token, against a fine-grained role model (feature:action permissions over Admin, Editor, and ReadOnly), and token revocation uses a denylist shared across replicas. Security-relevant actions are audited to both Postgres and the searchable log store, so you can hunt your own audit trail in nPL.

On tenancy: nano is not a shared multi-tenant cluster with row-level scoping. Each customer runs as its own isolated deployment with a dedicated ClickHouse and Postgres, so one customer's data never sits in the same database as another's. The hosted demo is the single shared-tenant environment, on purpose, so it stays low-friction to try.

### AI features (where they live)

In the hosted/enterprise build the AI is a set of focused agents. Detection generation writes a rule from a threat description, then validates it: parses it, runs it against ClickHouse to confirm it executes, and shows you the historical match rate so you know if it'll be noisy. To be precise: that proves the rule runs and shows how often it would fire, it does not prove it detects the right behavior. That's still a human review step. Parser generation turns sample logs into VRL. There's a query agent for natural-language-to-nPL, and a shadow investigation that runs on new case creation: it extracts entities, fires a deterministic playbook of hunting queries, and the LLM writes the narrative and recommendations on top. It's analyst emulation, not a free-roaming agent, and I think that's a feature.

### Open-core split

The open build is AGPL-3.0 and ships ingestion, search, the detection engine, alerting, and the enrichment marketplace, fully functional. AI and Cases are the enterprise tier, gated at compile time by an `EDITION` build arg, and that enterprise code is not present in the open build's binary. For the workflows AI assists with, the open build still gives you the underlying primitives: VRL parser validation, the nPL command reference, and rule templates, so you write detections and parsers by hand rather than via an in-app agent.

### Under the hood

A few architecture notes for anyone who wants the detail.

**Services.** Three Rust binaries from one workspace: the API (REST), the search service (query execution), and a background jobs worker (detection scheduling, enrichment). Axum and tower across all of them, OpenAPI/Swagger auto-generated via utoipa, Prometheus metrics exported. Search is multi-pod and coordinates via a Redis/Dragonfly-backed result cache (SHA-hashed query keys) and a shared JWT denylist; it falls back to per-pod state if Redis isn't there.

**Storage.** The `ext` column is `JSON(max_dynamic_paths=512)` with ZSTD(3). Enrichment (GeoIP/ASN via dictGet, IOC threat-intel, prevalence, identity) is computed as MATERIALIZED columns at insert time, so enrichment is atomic and always in sync with the row. One sharp edge: ClickHouse excludes MATERIALIZED columns from `SELECT *`, so the multi-stage CTE codegen has to re-add them explicitly at each stage or you get errors. There are query guards (subsearch result limits, group-array size caps, a default 100k result cap) that exist to stop a small JOIN from exhausting memory. They're safety valves, not performance claims.

**Query safety.** nPL parses with nom into an AST, then codegens ClickHouse SQL. The path is SELECT-only with a banned-function list and parameterized values; the emitted SQL for each command is pinned by regression tests so codegen can't silently drift. Each pipe stage becomes a CTE sharing one table scan. `table_view` mode projects only visible columns and fetches the full row on expand, so the initial result set doesn't drag 187 columns per row. Keyword search prefers `hasToken()` (bloom-filtered) and falls back to `position()` for tokens with special chars (`cmd.exe`, literal IPs). Note nano uses ClickHouse's regex engine (RE2), so PCRE lookahead/lookbehind won't work, check your patterns.

**Detection internals.** Real-time rules generate a materialized view per rule writing to a signals table; a signal processor polls that table and bridges matches into Postgres alerts, optionally grouping them into cases. The materialized-view path validates field-name safety and rejects unsupported constructs up front. Scheduled and test-rule runs share the exact same evaluator, so "test" and "prod" can't silently diverge in query semantics, and it records mean-time-to-detect (earliest event timestamp vs. detection time) as a histogram metric.

**Benchmark methodology.** For the latency numbers above: k6 over `kubectl port-forward` to one of four search replicas, so a single pod absorbed the entire load with no load-balancer help, while the cluster kept ingesting ~200 EPS and running 26 live detection rules. JWT auth, read-only, server-side timings pulled from ClickHouse `system.query_log` (not just round-trip). The corpus is 94 queries I hand-validated as things an analyst would actually type, including 14 zero-row rare-event detectors. The worst-case appendix (bare keyword / dense-column regex over 24h) is a separate run included specifically to find the ceiling. Single-shot idle latencies are lower still (median 83ms, p95 489ms); the headline numbers include 3-way contention plus the live ingest and detection load, so treat them as an upper bound on what an analyst feels.

### Try it

There's a live demo you can poke without standing anything up: [DEMO LINK]. It's a shared tenant and it's the same environment I ran the numbers above against, so you're hitting a box that's also ingesting and running detections while you query it. If something feels slow that's contention, not the architecture. If you want a clean read, the one-command Docker install spins up the full stack locally so you can throw your own logs at it: [GITHUB LINK].

### What I'd love feedback on

Mostly whether the detection lifecycle and risk model match how your team actually triages, or whether I'm solving my own problem and assuming it's everyone's. I'm also keen on nPL gaps (what SPL or KQL muscle memory breaks), ClickHouse schema critiques, and whether the open-core line is drawn in a fair place. If you're running something else today, I'd genuinely like to hear where nano would and wouldn't earn a slot. Tell me where it's wrong.

---

## Suggested taxonomy (set these in the Emdash sidebar)

- **Byline:** Dan (`byline-dan`)
- **Category:** Engineering (or Product if you'd rather frame it as a launch)
- **Tags:** SIEM, ClickHouse, Rust, Detection Engineering, Announcement
- **Featured image:** reuse or refresh whatever the current post uses
- **Slug:** keep the existing post's slug if you're editing in place, so the URL stays stable

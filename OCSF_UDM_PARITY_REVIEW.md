# OCSF ↔ UDM Parity Review

**Date:** 2026-06-11 · **HEAD:** c5d59359 · **Active local profile:** `NANO_SCHEMA_PROFILE=ocsf`
**Method:** 6 survey lanes (schema/perf, query codegen, detection, platform surfaces, ingestion, UDM inventory), every finding adversarially re-verified against code at HEAD, git history, live `/api/search/explain` (:3002), and direct ClickHouse execution (local, ~2M UDM rows / ~1.19M OCSF rows — validates **correctness and index engagement only, not scale**; production is 22M+/day).

## Linear week-in-review

**75 OCSF-related issues, 2026-06-05 → 06-10** (NAN-1241 epic → hardening wave NAN-1299..1348 → security audit NAN-1350). ~62/75 Done. Shape of the week: SchemaProfile seam landed (NAN-1244/1246), a 44-site profile-awareness audit (NAN-1248, 13 blockers + 21 major — all surface fixes shipped), the asset/entity/cases/AI-prompt waves, two real perf regressions found **and fixed** (NAN-1334 sort-key, measured 6.7×; NAN-1333 class-split index eligibility via `*_unified` materialized columns), then the NAN-1339/1346/1348 codegen train (corpus 74→97/144 pass) and the security audit (one pre-existing injection, NAN-1352, fixed; defense-in-depth NAN-1354 wired — which regressed three features, see §4).

**Open items that matter (13 non-Done):**

| Issue | Status | Why it matters |
|---|---|---|
| NAN-1247 | In Progress | `toString()` orphans `lower(col)` text skip indexes → full scans on field-text hunts, **both schemas**. Matches confirmed finding §4-H3; the single biggest filed perf risk |
| NAN-1245 | Backlog | Phase 6b direct-OCSF ingestion **endpoint** (Tenzir/Cribl) never started — the landed "direct" path is raw ClickHouse INSERT, with the credential/validation consequences in §5 |
| NAN-1338 / NAN-1339 / NAN-1341 | Backlog / In Progress / Backlog | Linear is **stale** vs reality: the #2036–#2066 PR train (verified merged at HEAD) closed the NAN-1339/1346/1348 clusters on 06-09; NAN-1338's "19 regressions" largely overlap. NAN-1341 (computed-field shadowing) is genuinely still open. Transition these |
| NAN-1263 | Backlog | No CH-in-CI / dual-profile harness — every regression this week was caught by manual corpus runs, not CI |
| NAN-1312 | Backlog | Bare `\| prevalence` parse rejection breaks shadow-investigation AI hunts |
| NAN-1262 / NAN-1350 | In Progress / In Review | Hardening + security-audit parents; close out once the §4 blockers land |
| NAN-1243 | Backlog | Stale duplicate of NAN-1242 (Done) — close as dupe |
| NAN-1267 / NAN-1335 / NAN-1336 | In Progress / In Review / Backlog | Ludus sourcing, docs, pre-existing fixture failure — not OCSF-parity-relevant |

**Linear hygiene:** none of this review's confirmed blockers (§4: real-time `fetch_matched_log`, `%source_type` stash, Group-wrap PREWHERE, enum-int semantics, NAN-1354 regressions, MV blindness to direct writes) has a Linear issue yet — they were found here, after the audit wave.

---

## 1. Executive summary

The OCSF implementation is **architecturally sound and further along than any of the 06-05..09 handoff docs suggest**: the UDM core is untouched, the SchemaProfile seam is threaded through search, scheduled detection, prevalence, risk, cases, shadow investigation, and all the AI agents, and the physical `ocsf_logs` schema is a faithful perf translation of UDM doctrine (same engine/partitioning/TTL, class-first sort key, ~98 skip indexes, shared prevalence MV→dict plumbing). But it is **not production-ready today**: real-time detection produces **zero alerts under OCSF, silently and permanently** (one nonexistent column in `fetch_matched_log`); ingestion provenance is broken at HEAD (the `%source_type` Vector stash was never committed, so 100% of OCSF rows land `source_type='unknown'`); and the day-old NAN-1354 validator regressed three shipped features on **both** profiles. A second tier of silent-wrong-results bugs — enum-int value semantics (`auth_result="failure"` matches nothing), `toString()` index-orphaning on aliased substring hunts, and a `Group`-wrap bug that defeats entity PREWHERE on the standard API path — means UDM-authored content cannot yet be trusted against OCSF data. All of these are small, well-localized fixes (the worst is one function); roughly six targeted PRs separate this from a defensible parity claim.

---

## 2. Performance parity verdict

**Verdict: OCSF keeps pace with — and sometimes beats — UDM on every indexed hot path, and falls off a cliff on exactly two seams: non-Eq string operators on UDM-aliased fields, and the Group-wrapped entity-Eq path that affects both profiles.** All numbers below are local-scale (~1.19M OCSF / ~2.0M UDM rows); index-engagement conclusions transfer to production, absolute timings do not.

**Structural parity (confirmed live, DDL = `clickhouse/ocsf/init.sql:911-967`):**
- Identical `ENGINE MergeTree / PARTITION BY toYYYYMMDD(timestamp) / TTL 365d / SAMPLE BY cityHash64(id) / granularity 8192`.
- Class-first sort key `(class_uid, timestamp, src_endpoint.ip, cityHash64(id))` — NAN-1334 shipped and live.
- ~98 skip indexes mirroring UDM's 77, including `text(splitByNonAlpha)` words indexes on `lower(message)` and all 10 NAN-1333 `*_unified` class-split columns.
- Prevalence MVs (`ocsf_{ip,hash,domain}_prevalence_summary_mv`) write to the **same** summary tables UDM's dicts source from; enrichment columns call identical `dictGetOrDefault` paths.
- `table_view` slim projection (24 cols, no `event`), `LIMIT 1000000`, `max_execution_time=300` — same generator.

**Empirical pruning (fraction of rows/granules read, EXPLAIN indexes=1 + query_log):**

| Query shape | UDM (`logs`) | OCSF (`ocsf_logs`) | Parity |
|---|---|---|---|
| Keyword `error` (text index) | 25.7% | **9.2%** (55/597 granules) | better |
| `src_ip` Eq (correct PREWHERE shape) | 11.0% | 12.2% (idx 596→73) | parity |
| `user` Eq (class-split `user_unified`) | 8.1% | 9.2% | parity |
| Scoping: `source_type` (UDM) vs `class_uid` (OCSF) | 48% (260/541) | **9%** (54/598) | better |
| UDM-aliased CONTAINS/wildcard/prefix/suffix | 6.7% (CONTAINS) | **100%** (1,190,097/1,190,097) | broken |
| Entity Eq via standard API path (Group-wrapped) | full scan* | **100%** (8.2x I/O vs fixed shape) | broken, both profiles |

\* The Group-wrap bug (finding G3) blinds PREWHERE promotion under both profiles on the normal non-AUDIT_VIEW path; it predates OCSF.

**The two perf cliffs:**
1. **`toString()` orphans every index on non-Eq aliased operators** (`search_expr.rs:717`): CONTAINS / wildcard / STARTSWITH / ENDSWITH / regex on any of the ~89 `udm_field` aliases reads 100% of the time window. Native dotted spelling of the *same* hunt is index-served (`lower("dst_endpoint.hostname") iLike ...`) — identical queries differ ~10–600x in granules purely on field spelling. Caveat from adversarial review: wildcard/STARTSWITH/ENDSWITH/LIKE are unindexed under UDM too (shared pre-existing gap); the genuine OCSF-vs-UDM regression is CONTAINS / NOT CONTAINS / simple-regex.
2. **Entity-Eq full-scans at HEAD on the standard API path** — the NAN-1299 PREWHERE rescue is dead code because `enforce_non_audit_query` wraps the expression in `SearchExpr::Group`, which `collect_prewhere` doesn't traverse (`clickhouse_sql_gen.rs:670`). Redeploying does **not** fix this (staleness explanation refuted; the rescue fires only when the expr is not Group-wrapped).

**Compounding factor:** `ocsf_logs` is 2.0x heavier per row (266 vs 132 B compressed — raw event JSON retained), so every full-scan path above pays double I/O. At 22M rows/day, an aliased substring hunt is a full-partition scan of the heaviest table.

**Flagged as local-scale-only:** all row-fraction numbers, the 8.2x I/O delta, and bytes/row (fixture data may compress atypically). Per project policy, re-validate perf claims on demo (~22M rows/24h) before shipping fixes as "speedups."

---

## 3. Coverage matrix

Status legend: **works** · **partial** · **degraded** · **missing** · **BROKEN**. "(both)" = defect affects UDM and OCSF equally.

### Schema & storage

| Capability | UDM | OCSF | Notes |
|---|---|---|---|
| Engine / partition / TTL / SAMPLE BY / granularity | works | works | Byte-identical clauses |
| Sort-key entity locality (NAN-1334) | works | works | class_uid-led; hostname absent but skip indexes compensate |
| Skip indexes incl. words/text indexes | works | works | ~98 vs 77, incl. all 10 `*_unified` |
| Keyword full-text on `message` | works | works | 9.2% vs 25.7% rows read |
| Storage / scan weight per row | works | degraded | 266 vs 132 B/row (2.0x); doubles I/O on full-scan paths |
| `prevalence_min` column | works | missing | No column, no mapping; query 400s loudly (G11) |
| `registry_*`, `risk_*`, `user_identity_*`, `enrichment_value_*`, `ioc_*_{malware,confidence}`, `custom_ioc_*` columns | works | missing | JSON-tail full scan + silently empty (wrong key); `ioc_*_threat_type` IS promoted+indexed |
| `source_type` provenance | works | missing at HEAD | Uncommitted `%source_type` stash (G2) + direct writers don't set it (G13) |

### Search / nPL

| Capability | UDM | OCSF | Notes |
|---|---|---|---|
| Bare keyword | works | works | |
| `field=value` Eq, UDM names | degraded (both) | degraded (both) | Group-wrap defeats PREWHERE on standard API path (G3); resolution itself correct |
| Native dotted OCSF Eq | n/a | partial | NAN-1354 validator 400s `user.name`, `file.path`, `file.name`, `process.pid`, `cloud.provider`, `cloud.region`, `api.operation` (G5) |
| CONTAINS / NOT CONTAINS / simple-regex on UDM aliases | works | missing | toString full scan (G4) |
| Wildcard / STARTSWITH / ENDSWITH / LIKE on fields | degraded (both) | degraded (both) | Unindexed under both profiles (shared gap) |
| Comparison / NOT / OR / IN / grouping | works | works | |
| Enum-int value semantics (`auth_result`, `auth_type`) | works | missing | `lower(toString(status_id))='failure'` matches 0 rows (G6) |
| `ext.*` dotted paths | works | degraded | Silently empty (key never exists in `event`); inconsistent with `spath input=ext` which IS remapped (G14) |
| Negated JSON-tail comparison (NAN-1161 semantics) | works | works | Absent-key rows correctly retained |
| Numeric comparison on unmapped/tail field | works | BROKEN | Emits nonexistent `JSONExtractFloat64` → loud 400 (G11) |
| stats / chart / timechart / eval / where / sort / head / top / rare / bin / rename / fillnull / mvexpand | works | works | Executed on CH with real results |
| `table` / `fields` with partial wildcards (`src_*`); also bare `fields *` | BROKEN (both) | BROKEN (both) | NAN-1354 regressed #2064 one day after ship (G7) |
| rex + downstream use of capture | works | works | NAN-1341 shadowing open on both: capture normalizing to a schema alias is silently discarded (G9) |
| spath (path=, input=ext) | works | works | |
| dedup / eventstats / streamstats / transaction / join / append / sequence / funnel / anomaly / tree / lateral | works | works | Full #2036–#2066 fix train verified merged |
| `resolve_identity` bare `identity_*` aliases | BROKEN (both) | BROKEN (both) | 11/13 aliases 400 as presumed typos; NAN-1354 regression of #2057 (G8) |
| lookup (missing table) / inputlookup (failed fetch) | degraded (both) | degraded (both) | Opaque 500 / **silent HTTP 200 with un-enriched results** (G15) |
| prevalence command | works | works | Bare `| prevalence` parse error both (NAN-1312, low) |
| Guardrail refusals (OOM, high-card, terminal-only, 6h cloud cap…) | works | works | Actionable 400s, profile-independent |
| Field autocomplete / highlighting / field-stats enumeration | works | works | NAN-1256/1241 on main; `distinctJSONPaths(event)`, 3h bound |
| explain-endpoint error parity | degraded (both) | degraded (both) | FieldNotFound masked to "Query processing failed" on explain only |

### Detection

| Capability | UDM | OCSF | Notes |
|---|---|---|---|
| Scheduled lifecycle (Staging→Live→Alerting) | works | works | Profile-injected SearchService; empirically validated |
| Finding logging (searchable events) | works | works | OCSF 2004 Detection Finding into ocsf_logs (NAN-1254) |
| Real-time MV creation + WHERE codegen | works | works | FROM ocsf_logs, canonical profile-aware WHERE; probe MV created cleanly |
| **Real-time signal → alert/case/finding** | works | **BROKEN** | `fetch_matched_log` selects nonexistent `metadata` → every signal skipped, watermark advances (G1) |
| Matched-log timestamp decode | works | BROKEN | ms ticks read as µs → 1970-01-21 timestamps; live, not masked (G10) |
| Prevalence filtering (dict path) | works | works | OCSF MVs feed the shared summaries; traced empirically |
| Rule-repo sync (NAN-1266) | works | partial | `selected_paths` skips the -ocsf remap; tactic trees have no -ocsf siblings → 0 rules or never-firing UDM rules (G12) |
| Alert dedup / case grouping / shadow investigation / AI triage / tuning / sigma | works | works | NAN-1291/1294/1295/1296/1297 all ancestors of HEAD |

### Platform surfaces

| Capability | UDM | OCSF | Notes |
|---|---|---|---|
| Asset page / `| asset` / dossier | works | works | Live: 381 events, dossier identity+procs+network+auth populated |
| Risk scoring / entity classification | works | works | Alert entity-summary display list still UDM-only (cosmetic) |
| Cases / notebook sidebar / pivots | works | works | useSchemaEntityMap shared hook |
| Dashboards + AI generation | works | works | Native-named widgets hit the G5 validator bug |
| Saved searches | works | partial | UDM-named fine; native names near a UDM alias 400 (G5) |
| Cloud overview / facets / timelines | works | works | Enrichment/IOC columns dropped under OCSF (TODO at cloud.rs:312); UDM display names |
| Lateral movement | works | works | 10,339 edges live |
| Field stats / inspector / row expand / match timeline | works | works | |
| Audit logging | works | partial | Audit page works; audit events unsearchable from search bar under OCSF (G16) |
| GDPR erasure | works | works | OCSF branch covers 2 user fields vs UDM's 7 — scope follow-up |
| Exports / detection testing / playbook grammar / editor | works | works | |
| Aggregation-fed surfaces (first/last-seen, identity, cloud Users, NAT, source health) | partial (both) | partial | MVs read UDM `logs` only (G13); separately, `entity_time_range_mv` UNION ALL only fires its first branch → **zero src_host rows in BOTH profiles** (G13b) |
| Typed executor fast path | works | degraded (low) | Doomed typed attempt only on row-expand/raw-SQL paths, fails pre-scan |

### Ingestion & enrichment

| Capability | UDM | OCSF | Notes |
|---|---|---|---|
| Vector parsed-source lane | works | works | NAN-1246 per-parser route + NAN-1325 Base Event lane, merged |
| Unconfigured-source searchability | works | partial | Vector lane works (dual-writes to both tables); direct path has the TTL hole (G17) |
| Direct 3rd-party write (Tanzir/Cribl) | n/a | works | Insert-time enrichment proven end-to-end on a raw INSERT |
| Event-time fallback on direct path | works | missing | Missing/RFC3339/epoch-seconds `time` → 1970 → silent TTL annihilation; INSERT returns 200 (G17) |
| Ingest auth / least privilege | works | degraded | No INSERT-only CH role; shared app user has SELECT+INSERT on all of nanosiem.* (docker adds ALTER/CREATE/DROP) — exfiltration + dict-poisoning surface (G18) |
| Geo/ASN enrichment | works | partial | 8 dual-mode cols at insert (verified 8.8.8.8→US/Google LLC); full country name / continent_code / as_domain unmapped → silent empty |
| IOC enrichment | works | partial | threat_type only; malware/confidence unmapped → silent empty |
| Custom IP tags / prevalence columns + universe feed | works | works | Direct rows both feed and read the shared universe |
| Identity enrichment | works | partial | Query-time `| resolve_identity` only; bare `user_identity_*` filters silently empty |
| Case normalization | works | partial | MATERIALIZED cols lower() for any writer; client-written `source_type`/explicit cols stored verbatim (`MixedCase` invisible to filters) |
| Row id / TTL / partitioning / dedup | works | works | Server-minted UUIDv7 even on direct inserts |
| Routing/repo-sync fixes (NAN-1270/1271/1275) | works | works | Merged |

---

## 4. Confirmed gaps & risks (severity-ordered)

All verdicts below are post-adversarial-verification; "evidence" cites the decisive artifact.

### Blockers

**G1 — Real-time detection produces zero alerts under OCSF, silently and permanently.**
`SignalProcessor::fetch_matched_log` selects literal `metadata` from the profile's logs table; `ocsf_logs` has no such column (the *only* missing identifier of the three literals — `message`/`source_type` exist). CH Code 47 → `process_signal` errors → signal warn-skipped → **watermark still advances** (signals consumed, never retried). MVs are created against ocsf_logs, so the path is fully reachable; the rule-management UI looks healthy throughout.
Evidence: `nanosiem-core/src/detection/signal_processor.rs:729-756` (literal `metadata`), `:541` (`?` propagation), `:479-514` (warn + watermark advance); query reproduced live → `Unknown expression identifier 'metadata'`. Scheduled mode unaffected.
Fix: map `metadata` per-profile like the entity columns already are (one-column change). **No Linear issue yet.**

**G2 — `%source_type` Vector stash never committed: 100% of Vector-ingested OCSF rows are `source_type='unknown'`.**
The reader exists at HEAD (`parser_config.rs:46` reads `%source_type` with `?? "unknown"` fallback); the writer (`%source_type = downcase(source_type)`) exists **only as an uncommitted hunk in `config/vector/00-base.toml`**. `deploy.rs:69` embeds the file via `include_str!` at compile time, so every build from HEAD ships writer-less. Guts the provenance filter, asset source facets, and every saved `source_type=X` workflow against OCSF data; already-ingested rows are permanently mislabeled.
Evidence: `git show HEAD:config/vector/00-base.toml` has no `%source_type`; `git diff` shows the +hunk; local: 1,190,097 rows `unknown`, only 2 direct-write probes carry a real value.
Fix: commit the working-tree hunk + redeploy parsers (XS). **No Linear issue yet.**

### High

**G3 — Entity-Eq searches full-scan at HEAD on the standard API path (both profiles) — NOT deployment staleness.**
The NAN-1299 PREWHERE rescue (`extract_prewhere_conditions`) is correct but dead: for any principal without AUDIT_VIEW, `enforce_non_audit_query` wraps the user expression in `SearchExpr::Group` (`query_manipulation.rs:205-208`) and `collect_prewhere` matches only `And`/`FieldFilter{Eq}` — `Group` falls into `_ => {}` (`clickhouse_sql_gen.rs:670`). Verified by bypass probe: adding `source_type!="audit"` to the query (skipping the wrap) makes the bare PREWHERE equality appear. Cost: 100% rows read vs 12.2% fixed-shape, 8.2x I/O locally; correctness unaffected (counts identical). Predates NAN-1299 — UDM deployments likely never had entity PREWHERE on the API path either.
Fix: recurse into `Group` in `collect_prewhere` and `has_selective_prewhere` (safe — Group is pure parenthesization). Small. **No Linear issue yet.**

**G4 — Non-Eq string operators on UDM-aliased fields full-scan `ocsf_logs` (toString orphans every index).**
`generate_json_field_filter` wraps the resolved column in `toString()` (`search_expr.rs:717`); the NAN-1333 `lower()` exception exists only in the Eq/Ne arm (`:882-895`); PREWHERE extraction is Eq-only. Empirical: `toString(user_unified) iLike '%intern%'` → 600/600 granules; identical predicate with `lower(...)` → 55/600 via `idx_user_unified_words`. Native dotted spelling is index-served, so identical hunts differ ~10–600x on spelling alone. `toString` is a semantic no-op on these non-null MATERIALIZED-`''` String columns (counts verified identical), so the fix is safe.
Fix: extend the lower()-instead-of-toString exception to all string-pattern arms for fields resolving to non-null String columns (class-split unified + promoted ExplicitColumn). Medium. **No Linear issue yet.** (Wildcard/STARTSWITH/ENDSWITH/LIKE need the same treatment under UDM too — shared gap.)

**G5 — NAN-1354 validator is profile-blind: native OCSF columns near a UDM alias are 400-rejected.**
`is_valid_field` gates unknown names by Levenshtein distance to `UdmField::all()` only (threshold `max(2, len/3)`, `field_validation.rs:251-288`); `.`→`_` costs 1 edit. Live: `user.name`, `file.path`, `file.name`, `process.pid`, `cloud.provider`, `cloud.region`, `api.operation` all 400 ("Field not found") while distant names (`src_endpoint.ip`, `actor.user.name`) pass. All 11 probed names are real `ocsf_logs` columns. Contradicts the validator's own test intent ("native OCSF dotted names must keep passing"). Breaks native search, FieldsPanel click-to-filter, native-named dashboards/saved searches.
Fix: consult the active SchemaProfile (promoted-column set) before the typo gate. Small-medium. **NAN-1354 follow-up needed; no issue yet.**

**G6 — UDM enum-verb predicates silently match zero rows under OCSF (`auth_result`, `auth_type`).**
`auth_result="failure"` compiles to `lower(toString(status_id))='failure'`; `status_id` is UInt32 (2=Failure) → 0 matches vs 127,209 `status='Failure'` rows (11,929 in class 3002). No verb→enum transform exists anywhere in the general generator; only `asset_dossier.rs:953-966` hand-decodes via `transform()`. Both scheduled and real-time rule paths flow through the broken codegen — every UDM-authored auth rule silently under-detects to zero.
Fix: value-map enum-int targets in the Eq path (reuse the asset_dossier `transform()` decode, driven by manifest enum metadata). Medium. **No Linear issue yet.**

**G7 — NAN-1354 regressed `table`/`fields` wildcards one day after they shipped (both profiles).**
`| table src_*`, `| fields src_*`, `| fields - src_*`, and even literal `| fields *` 400 pre-codegen ("illegal character '*'") — only `table *` survives. #2064 (16e62d65, 06-09) shipped the feature; #2078 (ed88ac38, 06-10) broke it. Masked to "Query processing failed" on explain. The 97/144 corpus pass rate is stale-optimistic at HEAD.
Evidence: `field_validation.rs:479-488` (Table skips only literal `*`), `:535-541` (Fields, no skip); live 400s reproduced.
Fix: wildcard skip in both arms (XS). **No Linear issue yet.**

**G8 — NAN-1354 broke `resolve_identity` bare `identity_*` aliases — 11 of 13 rejected as typos (both profiles).**
#2057 registered the bare names only in the codegen registry (`field_analysis.rs:698-716`), not the validation registry — `collect_command_output_fields` has no `ResolveIdentity` arm (`derived_fields.rs:249` `_ => {}`). `identity_title`/`identity_email` pass purely on length accident.
Fix: add a ResolveIdentity arm mirroring the codegen registration (S). **No Linear issue yet.**

**G9 — NAN-1341 (open, has Linear issue): computed field normalizing to a schema alias is silently shadowed.**
`rex … (?P<method>…) | stats count by method` GROUP BYs the schema column (`http_request.http_method` / `http_method`), discarding the capture, and even renames the output column. Applies to any computed name that `normalize_field_name` remaps (uri, filename, event_id, …) or that directly resolves (user, status, …). Root cause: `resolves_to_column` checked before `is_computed_field` (`helpers.rs:172` vs `:206`; `:258` vs `:271`), and the check must use the pre-normalization name. **Linear: NAN-1341 (open, deferred in #2039).**

**G10 — Matched-log timestamps decode to 1970-01-21 under OCSF real-time (live once G1 is fixed — actually reachable now).**
`fetch_matched_log` reads `reinterpretAsInt64(timestamp)` then `from_timestamp_micros`; `ocsf_logs.timestamp` is DateTime64(**3**) (ms ticks) vs UDM's DateTime64(6). 1780850134811 ms ÷ as-µs = epoch+20.6 days; `from_timestamp_micros` returns `Some` so no fallback fires — silent corruption into alert context, grouping, shadow investigation. Adversarial note: the "masked by G1" framing was refuted — the path is reachable; fix together with G1.
Fix: `toUnixTimestamp64Micro(timestamp)` (precision-independent) — XS, same function as G1. **No Linear issue yet.**

**G11 (downgraded from "silent match-all") — `prevalence_min` has no OCSF mapping; fails LOUDLY, plus a broader latent bug.**
The original "TRUE for every row" mechanism was **refuted**: codegen emits `JSONExtractFloat64(event,…)`, which is not a ClickHouse function → hard 400 `UNKNOWN_FUNCTION` (verified end-to-end; `| where prevalence_min<5` also 400s). So: UDM-parity gap (saved content errors every run = rule outage, visible) — and the canonical `| prevalence` detection gate is client-side dict-based and unaffected. Broader bug: **any numeric comparison on any unmapped/tail field under OCSF emits the nonexistent `JSONExtractFloat64`** and 400s.
Fix: map `prevalence_min` → `least()` of the 4 existing materialized prevalence columns; fix the `Float64` function-name emission (`JSONExtractFloat` or generic `JSONExtract(…, 'Float64')`). Small. Medium severity. **No Linear issue yet.**

### Medium

**G12 — Rule-repo OCSF remap skips `selected_paths`; community OCSF content is demo-only.**
The rules/→rules-ocsf/ remap applies only to the Tree-API `rules_path` branch (`sync.rs:137→268`); the sparse-checkout folder-picker flow imports UDM rules verbatim, marked `conversion_status="success"` — which then hit G6 and never fire. Conversely, the remapped path finds no `-ocsf` siblings for the 12 tactic trees in nano-rs/rules (only `demo-ocsf/`, 15 genuinely OCSF-native rules) → silently 0 rules by design. **Net under OCSF: silently-zero or silently-never-firing rules for all non-demo content.** Fix: apply remap in the selected_paths branch + flag/translate UDM-format imports; publish -ocsf tactic trees. **No Linear issue yet (NAN-1266 was the original feature).**

**G13 — Aggregation MVs read UDM `logs` only: direct-written OCSF data invisible to identity / first-last-seen / cloud Users / NAT / source health.**
`clickhouse/ocsf/init.sql` defines only the 3 prevalence MVs; `entity_time_range_mv`, `identity_observations_mv`, `cloud_user_activity_mv`, `nat_detection_mv` (via identity_observations), `logs_per_source_5m_mv` all read `FROM nanosiem.logs` (`clickhouse/init.sql:1145-1330`), and `TableNames` is cluster-aware but not profile-aware — masked today by Vector dual-write, fatal for the Tanzir/Cribl direct-write capability (empirically: direct ocsf_logs insert produced zero agg writes; control logs insert populated `logs_per_source_5m`).
**G13b (separate, profile-independent, found during verification):** ClickHouse only attaches the insert trigger to the **first** SELECT of `entity_time_range_mv`'s UNION ALL — the src_host branch is dead (`agg` = 14,841 src_ip rows, **0 src_host**, both-fields probe materialized only the ip row), and the reader also queries an `entity_type='user'` partition that no branch ever writes. Hostname/user first-last-seen is empty under **both** profiles.
Fix: split the UNION into separate MVs (+ add user branch), add OCSF-side counterparts, backfill via INSERT…SELECT. Medium-large. **No Linear issues yet — G13b deserves its own.**

**G14 — `ext.*` (and `event.*`) search terms silently empty under OCSF; inconsistent with `spath input=ext`.**
`OcsfProfile::resolve` fallback (`ocsf.rs:556-559`) treats unknown dotted names as paths inside `event` without prefix-stripping; no top-level `ext`/`event` key exists. Demo: `ext.error_code` = 0 rows vs `unmapped.error_code` = 23,117. The NAN-1354 validator deliberately whitelists these as "potential ext JSON fields," so no feedback. `spath input=ext` IS remapped (#2043) — half-fixed inconsistency. Fix is a product decision (strip-and-remap vs validation warning); key layouts differ so 1:1 remap isn't guaranteed. **No Linear issue yet.**

**G15 — lookup/inputlookup failure surfacing (both profiles).**
`| lookup <missing>` → CH Code 60 masked to generic 500 (no table-existence pre-check, `commands.rs:213-252`). Worse than originally claimed: `| inputlookup` with a failed fetch is **fully silent** — `enrichment.rs:178-186` logs and returns the un-enriched results as HTTP 200 (verified live), directly contradicting the "zero silent failures" handoff claim. Fix: pre-validate lookup tables; surface inputlookup failures as a response warning/400. Small. **No Linear issue yet.**

**G16 — Audit events unsearchable from the search bar under OCSF.**
`AuditEmitter` hardcodes `insert::<ClickHouseLogRow>("logs")` (`emitter.rs:38,:81`); search reads `ocsf_logs` (0 audit rows vs 1,577 in logs, actively written today). Audit *page* unaffected (`audit/query.rs:286` reads `logs`). Scope is narrowed to AUDIT_VIEW holders (non-privileged search is already audit-filtered). Latent second gap: emitter isn't cluster-aware either (`"logs"` vs `logs_table()`'s `logs_distributed`). **No Linear issue yet.**

**G17 (downgraded blocker→high by verifier; listing here as the direct-path headline) — Direct-inserted rows with bad `time` are silently annihilated.**
No `timestamp` column + `time` absent/RFC3339/**epoch-seconds**/event-as-string → DEFAULT derives 1970 → 365d row TTL drops it at part-write. INSERT returns HTTP 200; row never exists; no dead-letter. Vector lane immune (`now()` fallback). Spec-conformant writers unaffected, but epoch-seconds is a pervasive real-world pipeline mistake — nonconformant input deserves rejection or defaulting, not silent loss.
Evidence: `clickhouse/ocsf/init.sql:187-189` + `:967`; all four variants reproduced live (200 + vanished).
Fix: DEFAULT falls back to `now64(3)` when `toInt64OrZero=0` + optional seconds-vs-ms heuristic, or TTL guard `timestamp > '2000-01-01'`. Small. **No Linear issue yet.**

**G18 — No INSERT-only credential for direct writers.**
De-facto contract hands out the shared app CH user (SELECT+INSERT on all of nanosiem.*; docker config adds ALTER/CREATE/DROP) — a foreign pipeline can read all logs and poison `user_registry`/prevalence feeds. Also: direct writers that don't pre-lowercase `source_type` produce filter-invisible rows (`MixedCase` probe). Fix: ship an INSERT-only role scoped to `ocsf_logs` in the documented contract + lowercase-normalize client-written columns. **No Linear issue yet.**

### Low / informational

- **2.0x bytes/row** on ocsf_logs (raw event retained) — re-measure on production-shaped data before optimizing.
- **Typed executor doomed-first-attempt** under OCSF — downgraded to low: only row-expand (`fetch_log_by_id`) and raw-SQL paths; fails at analysis pre-scan; raw searches route dynamic directly.
- **NAN-1312** (open): bare `| prevalence` parse error — downgraded low: hardcoded shadow-hunt templates use valid forms; only LLM-hallucinated bare emissions fail, visibly.
- **explain masks FieldNotFound** that /api/search surfaces verbatim — diagnosability split per endpoint.
- **Cloud enrichment/IOC columns dropped under OCSF** (explicit `TODO(OCSF)`, `cloud.rs:305-318`).
- **Alert entity-summary** extraction reads UDM keys only (`findings.rs:248-263`) — summary degrades to risk entity.
- **Native-display gap** on cloud + funnel surfaces (UDM names shown to OCSF users).
- **GDPR OCSF branch** matches only `user.name`/`actor.user.name` vs UDM's 7 user columns — scope follow-up.
- **Shadow-investigation extraction** misses top-level `process.name` (subject of 1007 events).
- **NAN-1313 / NAN-1307** (open): verdict-model routing + triage throughput — no commits.
- **Stale red test on main:** `ocsf_byfield_resolution.rs:112` asserts `user→user.name`; HEAD correctly resolves `user→user_unified` (NAN-1336 family, open).
- Legacy in-process `RealtimeEvaluator` / `PrevalenceEvaluator` are dead code (zero callers) — cleanup candidates, not gaps.

---

## 5. Direct-ingestion (no-Vector) assessment

**Soundness: the architecture genuinely works.** Because every derived/enriched/prevalence column on `ocsf_logs` is a MATERIALIZED/DEFAULT expression computed at INSERT (dual-mode: native value if the event carries it, else `dictGet`), a raw third-party INSERT gets the same insert-time treatment as a Vector-lane row at zero per-query cost. Proven end-to-end: a synthetic OCSF row inserted raw into local CH (no native enrichment) materialized US/Google LLC + AU/Cloudflare geo via dictGet, got a server-minted UUIDv7 id, landed in the right daily partition with all unified class-split columns populated, and surfaced through the live search API — then was cleanly deleted.

**Enrichment parity on the direct path:** geo/ASN 8 of 14 UDM columns (country_code/continent/ASN/as_name × src/dst — full country name, continent_code, as_domain unmapped → silently empty under UDM spelling); IOC threat_type only (malware/confidence unmapped); custom IP tags full parity; prevalence full parity **including the universe feed** (the 3 OCSF MVs write into the shared summary tables, so direct rows both feed and read prevalence); identity is query-time only (`| resolve_identity` works; ingest-time `user_identity_*` columns don't exist).

**The four holes that decide whether this capability is shippable:**
1. **Silent row annihilation on bad `time`** (G17) — HTTP 200, row never exists. Must fix before any external writer is onboarded.
2. **`source_type` is writer-optional and non-derivable by design** (`init.sql:210-220`) — 100% of local direct rows are `'unknown'` despite `metadata.product.name` being fully populated; every saved source_type-keyed detection scopes to nothing. Contract must require it (or add a query-layer fallback to `metadata.product.name`, noting vocabulary differences). `class_uid` is the functional, well-pruning replacement (PK, 599→54 granules).
3. **No least-privilege credential** (G18) — the path currently means handing a foreign pipeline read access to all logs plus write access to identity/prevalence dictionaries' source tables.
4. **Invisible to every aggregation surface** (G13) — first/last-seen, resolve_identity observations, cloud Users, NAT stitching, per-source health all read UDM-`logs`-fed MVs; only prevalence sees direct-written data. Plus case-normalization: client-written columns are stored verbatim (MixedCase `source_type` invisible to filters).

---

## 6. Refuted claims

Checked and cleared — do not re-chase:

1. **"`prevalence_min<5` silently matches every row"** — refuted: `JSONExtractFloat64` isn't a CH function; the query 400s loudly. (The schema gap itself is real, see G11.)
2. **"Entity-Eq full scans are deployment staleness; HEAD/redeploy fixes it"** — refuted: serving binary is current; the NAN-1299 rescue is dead code behind the `Group` wrap at HEAD (G3, worse than claimed).
3. **"Numeric OCSF `time` breaks timestamp materialization (1970 partitions)"** — refuted: `JSONExtractString` coerces JSON numbers; epoch-ms rows land correctly.
4. **"Wildcard/STARTSWITH/ENDSWITH/LIKE regress OCSF vs UDM"** — refuted for those operators: they emit bare `iLike` with no `lower()` under UDM too (541/541 granules) — shared pre-existing gap. Only CONTAINS/NOT CONTAINS/simple-regex genuinely regress.
5. **"`ioc_*` enrichment family is gapped under OCSF"** — partially refuted: `ioc_*_threat_type` (+ `custom_*_ip_tags`) resolve to promoted, bloom-indexed columns; only malware/confidence/custom_ioc_* variants are gapped.
6. **"inputlookup failures surface as masked 500 / memory-limit errors"** — refuted: failures return **HTTP 200 with silently un-enriched results** (a worse failure mode, but the original characterization was wrong).
7. **"The MV body stays UDM-shaped" (constructors.rs:128-129 comment)** — stale: real-time MV generation is fully profile-native at HEAD (superseded by NAN-1248).
8. **"Typed executor wastes a CH round-trip on every raw OCSF search"** — refuted: raw searches carry a query_id and route dynamic directly; only row-expand and raw-SQL paths hit the doomed typed attempt, which dies pre-scan.
9. **"The ms-as-µs timestamp bug is masked by the metadata blocker"** — refuted: the path is independently reachable; it's live (G10).
10. **"entity_time_range null first-seen proves the OCSF MV gap"** — evidence contaminated: the actual cause is the profile-independent UNION-ALL-first-branch-only bug (G13b); the structural OCSF gap was confirmed by a clean probe.
11. **"PrevalenceEvaluator's UDM-key extraction silently no-ops on OCSF events"** — moot: zero callers; production prevalence is the dict path, which works.
12. **"NAN-1325 'unconfigured data still searchable' fails on the direct path"** — framing refuted: that guarantee was always Vector-lane-only; the direct path's silent loss is real but was never covered by it.

---

## 7. Recommended next actions (ordered)

| # | Action | Size | Restores |
|---|---|---|---|
| 1 | Fix `fetch_matched_log`: profile-map `metadata` + use `toUnixTimestamp64Micro` (G1+G10, one function) | S | Real-time alerting under OCSF |
| 2 | Commit the `00-base.toml` `%source_type` hunk + redeploy parsers (G2) | XS | Ingestion provenance |
| 3 | Recurse into `SearchExpr::Group` in `collect_prewhere`/`has_selective_prewhere` (G3) | S | Entity-Eq PREWHERE on the API path, **both profiles** (~8x I/O) |
| 4 | NAN-1354 follow-up bundle: wildcard skip in Table/Fields validation (G7), `ResolveIdentity` arm in `collect_command_output_fields` (G8), profile-aware promoted-column whitelist before the typo gate (G5) | M | Three day-old features + native OCSF search |
| 5 | Extend the `lower()`-not-`toString` exception to all string-pattern arms of `generate_json_field_filter` (G4); do the same `lower()` for wildcard/prefix/suffix under UDM | M | Aliased hunt-query perf at scale (the 22M-rows/day decider) |
| 6 | Enum value mapping in codegen for `auth_result`/`auth_type` (manifest-driven `transform()`) (G6) | M | UDM-authored auth detections |
| 7 | Map `prevalence_min` → `least()` of the 4 prevalence columns; fix `JSONExtractFloat64`→`JSONExtractFloat` emission (G11) | S | Prevalence-gated saved content + all numeric tail comparisons |
| 8 | Direct-write hardening: timestamp DEFAULT fallback/TTL guard, INSERT-only CH role, lowercase normalization, contract doc (G17/G18) | M | Tanzir/Cribl capability shippable |
| 9 | Split `entity_time_range_mv` UNION into per-entity MVs (+user branch) and add OCSF-side aggregation MVs; backfill (G13/G13b — file G13b as its own ticket, it's broken under UDM today) | M–L | First/last-seen, identity, cloud Users, NAT, source health |
| 10 | Rule-repo: apply -ocsf remap in `selected_paths` branch + flag untranslated UDM imports; publish -ocsf tactic trees to nano-rs/rules (G12) | M | Community detection content under OCSF |
| 11 | Decide + implement `ext.*` handling (strip-and-remap to `unmapped.*` vs validation warning) (G14); fix NAN-1341 precedence (computed-before-resolved on pre-normalization name) (G9) | M | Migration parity + rex correctness |
| 12 | Smaller: lookup pre-validation + inputlookup warning surfacing (G15); audit emitter profile/cluster awareness or search-side union (G16); re-run the nPL corpus post-fixes (expect >97/144) | S each | Error surfacing, audit searchability, regression baseline |

Existing Linear coverage: NAN-1341, NAN-1336, NAN-1312, NAN-1313, NAN-1307 are open and confirmed still-open. **Everything else above — including both blockers — has no Linear issue yet.**

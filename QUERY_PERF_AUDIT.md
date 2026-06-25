# ClickHouse Query Performance Audit — UDM + OCSF Search

**Date:** 2026-06-12
**Scope:** nPL→SQL codegen (UDM via live `/explain`, OCSF via codegen capture), `logs` + `ocsf_logs` schemas, aggregation paths, execution layer, hand-optimized benchmarks.
**Method:** 7 audit lanes, every finding adversarially re-verified by an independent agent executing against local CH 26.4 (`logs` 2.0M rows, `ocsf_logs` 1.19M rows) with `EXPLAIN indexes=1` + `system.query_log` (read_rows/read_bytes/memory/duration, log_comment-isolated). Local CH validates **correctness and pruning ratios, not absolute scale** — `scale-sensitive` marks findings whose impact materializes at production volume (50–100GB/day, 90-day windows). All prior audit docs (NPL_SQL_CONVERSION_AUDIT, OCSF_COLUMN_AUDIT, OCSF_UDM_PARITY_REVIEW, SILENT_BUG_HUNT_FINDINGS, HANDOFF_OCSF_QUERY_CODEGEN) were deduped against; nothing here re-reports a known item without a new, measured dimension.

Note on the local environment: the live `:3002` search service runs the **OCSF profile**; UDM-profile SQL was verified via a second `:3012` instance (`NANO_SCHEMA_PROFILE=udm`), shared-generator source, and direct probes against `nanosiem.logs`.

---

## 1. Executive summary — top 5 by impact

1. **Explicit `PREWHERE timestamp` disables CH's auto move-to-prewhere** on every generated query (both profiles). Every filter not hand-promoted is evaluated *after* reading the full projection: 349x read_bytes on a zero-match entity hunt, 16x steady-state on a sparse regex hunt, 5.8x on numeric ranges. A plain `WHERE` matched or beat the hand-built PREWHERE in every probe. [A1]
2. **OCSF JSON-tail filters emit `JSONExtract*(event, …)` over the native-JSON `event` column** instead of subcolumn access — materializes the whole event object per row: 87–300x read_bytes, fix is a single chokepoint (`field_access_expr`). [C1]
3. **`lower(col)=` / `toString(col)=` equality orphans ~20 raw-column bloom_filter indexes** (file_hash, process_hash, process_guid, rule_id, url_domain, …): absent-IOC hash sweeps read 77x more rows; the canonical rare-IOC case prunes 0% instead of ~99.9%. [B1]
4. **Multi-token free-text needles (phrases, IPs, domains, `file.exe`) bypass the message text index entirely** — full message-column scan, 96–307x I/O vs single-token searches; the most common SIEM needles (IPs, filenames) are the worst case. [B2]
5. **Sync `/api/search` pagination is silently broken**: generator-baked LIMIT makes `inject_limit_offset` a no-op (page N == page 1), caps `total_count` at the page size (5 vs true 23,117), and the count companion burns a full duplicate scan to return a number that can never differ from `results.len()`. Streaming path is correct, pinning the regression to NAN-1159/1160. [E1]

Also high but not perf: `ext.channel="x"` is mangled to `ext.extchannel` → silent 0 rows on a supported, UI-visible field syntax. [B3]

---

## 2. Verified findings

Severity reflects post-verification adjudication. All findings confirmed by independent re-execution; verifier corrections are folded in and flagged.

### Area A — Shared codegen (both profiles)

#### A1. Explicit `PREWHERE timestamp` suppresses ClickHouse auto move-to-prewhere — 16x–349x read amplification — **HIGH**, scale-sensitive
*Lanes: ocsf-codegen + benchmark (independently found, both reproduced).*

Every generated query has the shape:

```sql
... FROM nanosiem.ocsf_logs
PREWHERE timestamp BETWEEN '...' AND '...' [AND <promoted Eq filters>]
WHERE (<everything else>)
```

CH does **not** auto-move WHERE conditions when an explicit PREWHERE exists. `extract_prewhere_conditions` promotes only `Eq` on ~12 prewhere-flagged columns; all numeric ranges, CONTAINS/wildcard/regex, class-split unified columns (NAN-1333 deferral), and JSON-tail filters sit post-read.

Measured (local ocsf_logs, `use_query_condition_cache=0`, query_log):
- `user="admin"` (0 matches, full view): **531 MiB / 186ms** generated vs **1.52 MiB / 8ms** with PREWHERE rewritten to plain WHERE = **349x**. read_rows identical both ways — skip-index pruning unaffected; waste is purely the wide post-PREWHERE column read.
- `message=/powershell.*-enc[od]*/` 7d hunt: generated **3.31 GiB / 266–381ms / 1.4 GiB mem** on *every* run (never benefits from the query-condition cache) vs **207 MiB warm / 170ms / 330 MiB** hand-tuned. Control with no PREWHERE at all = byte-identical to hand-tuned → `optimize_move_to_prewhere` reaches the optimum on its own.
- `http_response.code>=500`: 4.65 GiB vs 817 MiB (5.8x), identical 36,660 results.
- Null case (verifier): `user="jane.doe"` (matches scattered across most granules) — no difference. Amplification is selectivity-dependent; rare/zero-match hunts and ranges are the wins. Currently-promoted paths (`source_type=`) do not regress under option (a).

All variants result-identical in every probe. Deploy configs even set `optimize_move_to_prewhere=1` (clickhouse/users.d/query_limits.xml:51) — an expectation the explicit PREWHERE silently defeats. Detection-rule execution uses the non-table_view path every minute, so the scheduler pays this too.

**Files:** `nanosiem-core/src/query/clickhouse_sql_gen.rs:1259,1316-1326,1461` (also 2068/2095), `clickhouse_sql_gen.rs:583-664` (extract_prewhere_conditions — note: in clickhouse_sql_gen.rs, not search_expr.rs), `nanosiem-core/src/schema/ocsf.rs:892`.

**Fix:** (a) emit a single WHERE and let `optimize_move_to_prewhere` do placement — matched or beat the explicit PREWHERE in all probes including currently-promoted paths; or (b) promote ALL conjunctive top-level filters. Option (a) is smaller/safer but overturns a documented convention: update CLAUDE.md's "PREWHERE optimization" section and NPL_SQL_CONVERSION_AUDIT's "central performance contract" framing, and add the missing PREWHERE/WHERE snapshot tests in the same PR. Gate with a result-parity test + a query_log read_bytes regression probe on a sparse-match query. Validate both profiles (shape is parity-equal; OCSF blast radius larger because the default view includes `event`).

#### A2. Codegen-baked `SETTINGS max_threads=16, max_execution_time=300` overrides admission-control per-priority settings — **MEDIUM**
*Lanes: aggregation-codegen + execution-layer (same root cause, merged).*

`generate_settings()` (helpers.rs:23-41) unconditionally appends the clause; the executor applies per-priority settings via HTTP options (admission.rs:76-100 → paginated.rs:167-179). SQL-text SETTINGS beat URL/client settings — proven both by query_log (`Settings['max_threads']='16'` despite URL `max_threads=2`) and **behaviorally** (URL `max_rows_to_read=1000` killed a scan; SQL-text override let it complete). Live `priority=analytics` search logged mem=50GiB/prio=5 (URL values applied) but threads=16/timeout=300 (baked values beat Analytics' 32/3600).

Net effect (verifier-corrected): **Analytics-tier hunts are silently killed at 300s instead of their 3600s budget and capped at 16 threads.** Interactive coincides with the baked values (no-op). Detection's 8thr/30s settings are *dead code*, not an override victim — detection calls `search()` directly, never `search_with_admission`; the baked 300s is its only limit.

**Files:** `clickhouse_sql_gen/helpers.rs:23-41`, `search/admission.rs:75-100`, `execution/clickhouse_executor/{paginated.rs:167-179,query_execution.rs:346-376}`, `nanosiem-search/src/handlers/search.rs:73-76`.

**Fix:** do NOT just delete the two settings — paths with `effective_settings=None` (detection, un-admitted callers) would lose their only timeout (CH default = unlimited). Thread `QueryPriority` into the generator so the baked clause reflects the admitted budget, or omit SQL-text limits only when executor settings are present.

---

### Area B — UDM codegen + `logs` schema

#### B1. Case-insensitive equality (`lower(col)=` / `toString(col)=`) orphans ~20 raw-column bloom_filter indexes — IOC sweeps read 77x more rows — **HIGH**, scale-sensitive
*Lanes: udm-filter-codegen + logs-schema (independently found, merged).*

Any string field not in `LOWERCASE_NORMALIZED_FIELDS` (only 13 entries) gets `lower(col) = 'value'` (search_expr.rs Eq arm ~:803-812). CH matches skip indexes by *expression*; the blooms are on raw columns (idx_file_hash, idx_process_hash, idx_process_guid, idx_rule_id, idx_user_id, idx_url_domain, idx_file_name, idx_cve, idx_mitre_technique, idx_sender/recipient, idx_message_id, idx_signature_id, idx_risk_entity, idx_resource_id, idx_cloud_account_id, idx_enrichment_value_1..3, …) and these columns have **no** `lower(col)` text index.

```text
-- EXPLAIN indexes=1, day partition (423 granules / 1.50M rows):
lower(process_hash) = lower('CAAE...')   → NO Skip entry, 423/423, read_rows=1,504,542
process_hash = 'CAAE...'                  → Skip idx_process_hash 423→238
rare hash, raw form                       → Skip 423→16, read_rows=54,716 (27.5x rows, 16x bytes)
-- absent-IOC sweep (the common case):
lower(file_hash)='deadbeef…'              → 1,995,380 rows / 17.6 MiB
file_hash IN ('DEADBEEF…','deadbeef…')    → 25,984 rows / 242 KiB  (77x)
```

Data is NOT case-normalized at ingest (594,885 rows uppercase process_hash; file_hash stored all-uppercase; process_guid already-lowercase MATERIALIZED yet still wrapped), so dropping `lower()` is unsound as-is. Bonus defects: `rule_id` routes through `UUID_FIELDS` emitting `toString(rule_id)='<lowered>'` — zero index engagement AND a case-sensitive compare against a lowered literal (logs.rule_id is a plain String). Migration 119 explicitly kept the raw blooms "for whole-value equality lookups" — a shape the codegen never emits for these fields, so the documented assumption is wrong.

**Verifier-refuted mitigation:** the codegen-only OR form `(col='X' OR col='x' OR lower(col)='x')` does **not** prune (a granule can't be excluded while one disjunct is non-index-evaluable) — do not ship it.

**Files:** `clickhouse_sql_gen/search_expr.rs:803-815`, `clickhouse_sql_gen.rs:497-516,578`, `clickhouse/init.sql:861`, `clickhouse/119_splitbynonalpha_indexes.sql`.

**Fix (per column class):**
1. Hashes/GUIDs (file_hash, process_hash, process_guid): lowercase at ingest (VRL) + add to `LOWERCASE_NORMALIZED_FIELDS` — matches existing src_ip/user design; hex is case-insensitive by definition; schema's own enrichment dicts already key on `lower(file_hash)`. Needs a backfill story.
2. Or schema-side: `ADD INDEX idx_<col>_lower lower(<col>) TYPE bloom_filter GRANULARITY 4` for process_hash, file_hash, user_id, url_domain, file_name, session_id — purely additive, proven to engage by the expression-aligned `idx_user_words` result (lower(user) → 423→33).
3. `rule_id`: remove from UUID_FIELDS or compare `lower(toString(col))`.
4. Add src_user/dest_user to LOWERCASE_NORMALIZED_FIELDS (data already lowercase; currently rescued by their text indexes — consistency nit).
Saturn-validate per NAN-1035 before touching index lists.

#### B2. Multi-token free-text needles bypass the `lower(message)` text index — full message scan, 96–307x I/O — **HIGH**, scale-sensitive
*Lane: udm-filter-codegen.*

CH 26.4's `text(splitByNonAlpha)` index prunes single-token `iLike` via dictionary-substring scan but bails on any needle containing a non-alphanumeric char — exactly the needles SIEM analysts type (quoted phrases, IPs, domains, snake_case, `file.exe`).

```text
%error%          → idx_message_words 105/521 granules
%failed%         → 647,224 rows / 6.2 MiB   (+ text-index DIRECT READ: message never materialized)
%failed login%   → index ABSENT, 528/528 → 1,995,380 rows / 1.85 GiB  (~307x bytes)
%svchost%        → 14.5 MiB    vs   %svchost.exe% → 1.85 GiB  (130x)
%10.0.0.52%      → full scan, 1.85 GiB
```

Same root cause hits the regex pre-filter: `extract_longest_literal` splits only on regex metachars, so `message=/svchost\.exe (started|stopped)/` emits the multi-token guard `'%svchost.exe %'` → no index. `tokensForLikePattern('%failed login%') = []` confirms CH's analyzer extracts nothing. Migration 119 / search_expr comments assume iLike is dictionary-accelerated — true only for single tokens; unreported gap in the NAN-1026 design.

**Fix (verified sound):** tokenize the needle on non-alphanumeric runs; when >1 token, AND an index-served guard `lower(message) iLike '%<token>%'` for the **longest/rarest token (≥3 chars)** ahead of the full-phrase iLike — byte-identical results in all probes (each token is a substring of the needle), 5.2x less I/O on the sparse-phrase case. **Must be longest-token-only, not all-tokens AND** — all-tokens regressed dense matches (CPU 0.90M→1.63M µs for marginal I/O gain). Apply the same tokenization to `extract_longest_literal` so the regex guard picks the longest single *token*.

**Files:** `clickhouse_sql_gen/search_expr.rs:186-203` (Keyword), `:547-560` (regex-literal), `~:609` (Contains); `clickhouse_sql_gen/helpers.rs:689-696,815`; `clickhouse/119_splitbynonalpha_indexes.sql`. Applies to both profiles (ocsf_logs carries the identical index).

#### B3. `ext.`-prefixed field filters silently mangled (`ext.channel` → `ext.extchannel`) — 0 rows returned — **HIGH (correctness)**, not scale-sensitive
*Lane: udm-filter-codegen.*

`generate_json_field_filter` strips `metadata_`/`metadata.` but not `ext.`; the dotted name reaches `sanitize_json_path` which deletes the dot:

```sql
-- nPL: ext.channel="Microsoft-Windows-Sysmon/Operational"
lower(toString(ext.extchannel)) = 'microsoft-windows-sysmon/operational'  -- 0 rows
-- correct: lower(toString(ext.channel)) = '...'                          -- 816,589 rows
```

Bare `channel="..."` works; only the explicitly-prefixed form silently fails. The prefixed form is intended syntax (OcsfProfile deliberately strips/remaps it; UI surfaces `ext.`-prefixed names in ParserTestLab/EventViewer). Silent 0-result hunts = missed events.

**Fix (verifier-corrected):** the naive fix (strip `ext.` inside shared `generate_json_field_filter`) would **regress OCSF** — `ext.channel` must keep resolving to `(event,'unmapped','channel')` there. Strip `ext.` **UDM-scoped**: in `UdmProfile::resolve` (mirroring ocsf.rs:651) or in the `FieldResolution::Unknown` arm at clickhouse_sql_gen.rs:994 before `sanitize_json_path`. Add a regression test asserting `ext.channel` lowers to `ext.channel`.

**Files:** `clickhouse_sql_gen/search_expr.rs:837-843`, `clickhouse_sql_gen/helpers.rs:944-948`, `nanosiem-core/src/schema/udm.rs:239-248`, `clickhouse_sql_gen.rs:994`.

#### B4. Default cross-source 'newest first' search cannot read-in-order — reads the entire window to satisfy LIMIT (70x) — **HIGH**, scale-sensitive
*Lane: logs-schema.*

`ORDER BY (source_type, timestamp, …)` puts source_type first, so `ORDER BY timestamp DESC LIMIT N` can't early-terminate unless source_type is fixed by equality (the default `source_type != 'audit'` inequality doesn't fix the prefix). `ocsf_logs` is identically afflicted (`class_uid` leads).

```text
1-day window, ORDER BY timestamp DESC LIMIT 100:        read_rows=1,512,966 (entire window)  ReadType: Default
same + source_type='windows_sysmon':                    read_rows=21,529   (70.3x less)      ReadType: InReverseOrder
```

Sub-day time pruning itself is fine (1h window: 184→5 granules) — the loss is specifically sort early-termination. Caveat: the count/histogram companions scan the window regardless, so a fix bounds the events query, not total page I/O.

**Fix:** do NOT reorder the sort key (source-scoped binary-search pruning + compression earn their keep). Add execution-layer **adaptive time-slicing** for `ORDER BY timestamp DESC LIMIT N` with no selective filter: query the newest sub-window first, widen until LIMIT filled (same newest-N rows; ties already non-deterministic). Candidate site: `nanosiem-core/src/search/`. Re-validate the 70x on Saturn first.

**Files:** `clickhouse/init.sql:861`, `clickhouse_sql_gen.rs:725-760`.

#### B5. Missing text indexes: process_path, url, uri_path; session_id has no index at all — **MEDIUM**, scale-sensitive
*Lane: logs-schema.*

Migration 119 indexed 15 columns but skipped `process_path` (42% populated — file_path got one, process_path didn't), `url`, `uri_path`; `session_id` (143k rows) has nothing, so even equality full-scans. `lower(process_path) iLike '%temp%'` → zero Skip entries, full 1.5M rows; rare-token contrast on the *indexed* file_path: `%xmrig%` reads **0** rows vs process_path's 1,504,542. Storage is cheap-tier (idx_file_path_words = 147 KiB vs idx_message_words 145 MiB).

**Verifier caveat (set expectations in the ticket):** `text(splitByNonAlpha)` does NOT serve iLike patterns whose required substring contains non-alphanumeric chars — measured on indexed file_path, `%.tmp%` and `%temp\%` still full-scan. The new indexes accelerate the pure-alphanumeric-substring subset only (`%temp%`, `%powershell%`); the session_id equality bloom is the unambiguous clean win. (Verifier also could not reproduce the lane's "message prunes 423→33 for %login.php%" side-claim — same non-alpha limitation; doesn't change the verdict.)

**Fix:** new migration: `idx_process_path_words lower(process_path) TYPE text(tokenizer=splitByNonAlpha)`, same for url; `idx_session_id_lower lower(session_id) TYPE bloom_filter`; MATERIALIZE INDEX; uri_path optional. Saturn-validate pruning first.

**Files:** `clickhouse/119_splitbynonalpha_indexes.sql`, `clickhouse/init.sql:858-862`.

#### B6. Audit-event writer violates the LOWERCASE_NORMALIZED_FIELDS contract — `user=` equality silently misses audit rows — **LOW (correctness)**
*Lane: udm-filter-codegen.*

The raw-equality fast path (`"user" = 'dan lussier'`) is what makes idx_user prune — and it "correctly" prunes to 0 rows because the audit writer (`audit/mod.rs:261`, `user: self.actor_name`) stores display-case names ('Dan Lussier', 1,019 rows, all source_type='audit'). Hidden by the default `source_type != 'audit'` filter; an AUDIT_VIEW principal searching `user="dan lussier"` gets 0 of 677 rows (`countIf(user='dan lussier')=0` vs `lower()` form 677). The dedicated audit page filters by actor_id/action, never the `user` string — impact confined to search-bar nPL under UDM, hence low.

**Fix:** lowercase `user` in the audit CH writer **but preserve the display name** (audit/query.rs:280 renders it) — e.g. keep display in ext/metadata. Add a CI assertion: `countIf(f != lower(f)) = 0` for every LOWERCASE_NORMALIZED_FIELDS field across all source_types, so future writers can't break the fast-path's precondition.

**Files:** `clickhouse_sql_gen.rs:497-515`, `clickhouse_sql_gen/search_expr.rs:803-806`, `nanosiem-core/src/audit/mod.rs:261`, `nanosiem-search/src/handlers/search.rs:63-65`.

#### B7. Full-row SELECT shape costs 9.4x memory vs table_view; prefix wildcards get no index — **LOW**, scale-sensitive
*Lane: udm-filter-codegen.*

At LIMIT 100, CH 26.4 lazy materialization keeps read_bytes near-equal (15.3 vs 13.0 MiB) but memory is 48.6 vs 5.2 MiB (9.4x), latency 1.4x warm (lane's 3.4x was a cold run). **Sharp edge the lane missed (verifier):** `query_plan_max_limit_for_lazy_materialization` defaults to 10,000 — any API caller passing `limit>10000` with `table_view=false` silently loses lazy materialization and pays the full-column read (measured 1,017 MiB read / 422 MiB mem with it disabled). `QueryOptions.table_view` defaults to false. Separately, `field=val*` → `lower(col) iLike 'val%'` engages no index (anchored prefixes: not bloom-servable through lower(), not a complete token for the text index).

**Fix:** default `table_view=true` for programmatic callers or trim the always-appended MATERIALIZED list; document that prefix wildcards can't use indexes. No urgent action.

**Files:** `clickhouse_sql_gen.rs:468-478,1291`, `clickhouse_sql_gen/search_expr.rs:509-538`, `search/config.rs:31-32`.

#### B8. idx_message_words is ~0.94x the compressed message column and incompressible — migration 119's Saturn estimate is suspect — **LOW**, scale-sensitive
*Lane: logs-schema.*

`system.data_skipping_indices`: idx_message_words = 145.34 MiB compressed / 148.59 MiB uncompressed (posting lists don't compress) vs message at 154.32 MiB compressed. Migration 119 estimated a flat ~50 GB on Saturn; at the measured ratio a 50–100GB/day×90d tenant carries hundreds of GB — plausibly ~10x low. Index earns its cost (hasToken prunes 6/541 granules on rare tokens). Ratio is data-shape-dependent — treat as heuristic.

**Fix:** measure on Saturn (`system.data_skipping_indices`, admin) and fold the per-GB ratio into tenant sizing. No schema change.

#### B9. iLike substring eval costs ~15–17x CPU vs hasToken on granule-surviving rows — accepted NAN-1026 tradeoff, now quantified — **LOW**, scale-sensitive
*Lane: logs-schema.*

Pruning parity (both ~105/541 granules, equal read_rows/bytes); row-eval: iLike 53–71ms vs hasToken 3–4ms. The price of substring correctness (iLike 38,095 matches vs hasToken 3,743 — diff rows are real fragment hits, e.g. CloudTrail `"errorCode":`). **Keep as-is**; recorded so capacity work doesn't rediscover it. If it ever becomes a measured bottleneck: a hasToken pre-guard is only safe when the needle is non-alpha-bounded on both sides in the pattern — do not regress fragment matching.

**Files:** `clickhouse_sql_gen/search_expr.rs:190-205`.

---

### Area C — OCSF codegen + `ocsf_logs` schema

#### C1. JSON-tail fields use `JSONExtract*` on the JSON-typed `event` column instead of native subcolumn access — 87–300x read bytes — **HIGH**, scale-sensitive
*Lanes: ocsf-codegen + ocsf-schema + benchmark (three independent confirmations, merged).*

`field_access_expr`'s JsonPath arm emits `JSONExtract{String|Float|Bool}(event, 'a', 'b')` — but `event` is native `JSON` (139.75 MiB compressed / 1.76 GiB uncompressed, the largest column), so JSONExtract reconstructs the **entire event object per row**, while subcolumn access reads only that path's columnar substream. The UDM profile's Unknown arm already emits subcolumn `ext.{field}` — only the OCSF arm regressed. `clickhouse/ocsf/init.sql:166-169`'s comment ("JSONExtract* reads dynamic subpaths") is empirically false on CH 26.4.

```text
JSONExtractString(event,'unmapped','signature_status')='valid' → 3.08 GiB / 250ms / 1.58 GiB mem
toString(event.unmapped.signature_status)='valid'              → 26.9 MiB / 11ms / 32 MiB mem   (87x, identical 512,660)
nested path absent in data (connection_info.direction)         → 3.08 GiB vs 10.2 MiB (~300x)
JSONExtractFloat(event,'unmapped','EventID')=4624 (count probe)→ 3.08 GiB vs 19.3 MiB subcolumn (163x)
```

Every unpromoted field (registry_*, risk_*, unmapped.*, ext.* remaps, EventID hunts) in search/where/stats-by/spath pays this; `by_field_sql` routes GROUP BY through the same arm. Compounds with A1: full-view query for an unmapped filter read 4.66 GiB for 0 matching rows. Fix is one chokepoint — all tail consumers route through `field_access_expr`.

**Verifier-mandated semantics carve-outs (the headline rewrite alone changes results):**
- **String compares:** drop-in (missing key → `''` both ways; numbers coerce identically). Keep the NAN-1161 `toString()` guard.
- **Numeric compares:** `JSONExtractFloat` returns **0** for missing keys; bare `accurateCastOrNull` returns NULL — `=0` flips 632,625→0 and `!=7` flips 677,976→45,351 on local data. Ship `coalesce(accurateCastOrNull(event.path,'Float64'), 0.)` for exact parity (verified, still ~130x win) or deliberately pin new NULL semantics with tests. (Note: extractor suffix is `Float`, not `Float64` — NAN-1383.)
- **Object-valued paths:** JSONExtractString returns raw JSON, `toString(event.a)` returns `''` — restrict subcolumn emission to scalar/leaf comparisons or document the change.
- Keep `JSONExtractArrayRaw` forms for array paths (hashes/enrichment arrayFirst patterns). Production tenants exceeding `max_dynamic_paths=1024` push overflow into shared data — less surgical but never worse than full-event decode.

**Files:** `clickhouse_sql_gen.rs:980-996` (field_access_expr JsonPath arm), `:2392-2419` (table_view tail projections), `clickhouse_sql_gen/helpers.rs:243-249,288-296`, `nanosiem-core/src/schema/ocsf.rs:657-667`, `clickhouse/ocsf/init.sql:166-169`.

#### C2. LowCardinality parity gap: OCSF identity/process/file string columns are plain String where UDM uses LC — 5.2x bytes/row on `stats by user` — **MEDIUM**, scale-sensitive
*Lane: ocsf-schema.*

`user.name`, `actor.user.name`, `user_unified`, `process.name`, `actor.process.name`, `process_name_unified`, `file.name`, `module.file.name`, `activity`, `metadata.product.name` are plain String on ocsf_logs while logs declares the equivalents `LowCardinality(String)` — and ocsf/init.sql uses LC on ~20 *other* columns (even `src_host_unified` in the same overlay block), so this is inconsistency, not a design decision. Cardinalities are LC-friendly (uniq(user_unified)=639, process.name=98, activity=21). Measured: user_unified 15.46 MiB uncompressed vs LC src_host_unified 2.68 MiB at equal rows (5.8x); bare `GROUP BY user_unified` = 8.3 B/row vs UDM LC `GROUP BY user` = 1.6 B/row (**5.2x** — worse than the lane's PREWHERE-diluted 1.65x). nPL `stats count by user` on OCSF reads the plain-String column (ocsf.rs:450 maps user→user_unified).

**Fix:** ALTER the hot GROUP-BY/entity columns to LC in a new ocsf migration. Caveats: win is query-time read-bytes/memory (disk delta modest); MODIFY COLUMN on MATERIALIZED columns triggers full-column rewrite mutations; validate per-part cardinality on Saturn first (LC degrades past ~100k distinct/part). Correctness-neutral.

**Files:** `clickhouse/ocsf/init.sql:283,341,363,391,419,789` + ALTER overlay ~:1646 (change both places).

#### C3. `severity="High"` bypasses the enum-int machinery — string filter not promoted, severity_id routing unused — **LOW**, scale-sensitive
*Lane: ocsf-codegen.*

Emits `WHERE lower(severity)='high'`, no PREWHERE; `enum_int_mapping` only fires when the user types `severity_id`. Impact bounded: the `set(20)` skip index evaluates through lower() (555→143 granules); measured only ~1.2x (952 vs 790 MiB), and id-promotion adds nothing beyond PREWHERE promotion on this distribution — the big multiplier is A1.

**Verifier upgrade to the fix:** local data has id/string disagreement rows (severity='' with severity_id=1), so a blind string→id rewrite **changes results — the OR-fallback is mandatory**, not optional. Cheaper alternative capturing 100% of the measured benefit: flip the string sibling's manifest prewhere flag. Do after A1; measure on production distribution first.

**Files:** `nanosiem-core/src/schema/ocsf.rs:849-864` (+ resolve order ~:622/:637), `clickhouse_sql_gen/search_expr.rs:325`, `nanosiem-core/docs/ocsf/1.8.0/udm_ocsf_mapping.json`.

#### C4. idx_class_uid bloom is redundant with the leading PK column (prunes 1 extra granule of 478) — **LOW**
*Lane: ocsf-schema.*

PK `(class_uid, timestamp, …)` binary-search prunes 478→31; the bloom removes exactly 1 more (multi-value IN: also 1). Maintained on every insert/merge for ~zero benefit — though the index is only 703 B locally, so this is hygiene, not a win. Counter-measurement protecting the rest of the list: **idx_category_uid is load-bearing** (476→129, 73% — correlates with class-sorted layout but isn't in the key) — keep it and idx_activity_id/idx_type_uid. Aside: UDM logs has the same pattern (`idx_source_type` set index on its leading key) if a cleanup pass is cut.

**Fix:** drop only idx_class_uid after EXPLAIN at Saturn scale (NAN-1035 discipline). **Files:** `clickhouse/ocsf/init.sql:833`.

---

### Area D — Aggregation codegen

#### D1. `timechart limit=N` (top-N split-by) scans the base time range twice — **MEDIUM**, scale-sensitive
*Lane: aggregation-codegen.*

The rank subquery `WHERE source_type IN (SELECT … FROM stage_0 GROUP BY … LIMIT 3)` re-reads stage_0 (the raw scan CTE); CH inlines it and scans twice: read_rows 2,380,236 vs 1,190,118 without limit= — exactly 2x (plain EXPLAIN hides the second read under CreatingSets; physical read_rows is conclusive). Combined with the histogram companion (E-cluster), `timechart … by X limit 10` scans the window 3x.

**Fix (verifier-validated):** two-chained-CTE form — aggregate once into (bucket, field, count), then `sum(count) OVER (PARTITION BY field)` + rank on the *aggregated* stage — measured single scan (1,190,118 rows), identical results. Implementation caveats: exact for count/sum; avg needs sum+count carried; **dc/uniqExact is not per-bucket decomposable** (keep two-pass for dc or GROUPING SETS); use row_number-style tiebreak to match `IN(…LIMIT N)` tie semantics; the literal nested-window single-SELECT form fails on CH 26.4 (NOT_FOUND_COLUMN_IN_BLOCK).

**Files:** `clickhouse_sql_gen/aggregation.rs:341-385`.

#### D2. `dc()` always compiles to uniqExact — ~48x memory vs uniq on high-cardinality input — **MEDIUM**, scale-sensitive
*Lane: aggregation-codegen.*

`AggFunc::Dc → uniqExact` unconditionally (aggregation.rs:113/:272/:368, plus commands_advanced.rs:85/:193 — eventstats/streamstats windows, an even costlier shape). Measured: uniqExact(toString(id)) = **219 MiB** vs uniq = 4.6 MiB vs uniqCombined64(16) = 174 KiB; ~190 B/distinct-string state, linear toward the 20GB/query cap and 10GB external-group-by spill (query_limits.xml). Failure mode is bounded (query failure/spill, not server OOM); per-group blowup needs production-shape per-state cardinality.

**Verifier-corrected fix:** do **NOT** silently default dc() to approximate — detection thresholds (`where dc > N`) flip on ~1% error (uniqCombined64(16) measured 0.90%, not <0.5%), and Splunk parity is dc()=exact. Ship the alternative: add `estdc()` → uniqCombined64 and document dc()'s memory cost.

#### D3. Pre-aggregation rollup `logs_per_source_5m` is never consulted by search/histogram codegen — **LOW**, scale-sensitive
*Lane: aggregation-codegen; severity revised medium→low by verifier.*

The rollup exists (migration 116, AggregatingMergeTree, 7d TTL) and is consumed only by telemetry; nothing in codegen/histogram routes eligible shapes (`*` + timechart/histogram count) to it. Structurally bounded at 288 buckets/day×source_types vs raw rows — but the lane's "10,300x" compared mismatched table+window (honest local same-window ratio: ~9x), and a correct implementation needs real work the lane missed: **the OCSF MV writes to the SAME rollup table** (dual-write deployments would return combined UDM+OCSF counts), rollup source_type is normalized (group values diverge from raw), MVs miss pre-creation/gap rows (silent undercount in an analyst-facing timeline), edge buckets at non-aligned range endpoints, and the raw histogram scan is already narrow (~9 B/row). 116's decision log scoped the rollup to telemetry deliberately.

**Fix:** treat as a design opportunity, not a quick win: per-profile rollup separation + normalization handling + MV-gap fallback before any routing. Consider an hourly tier covering 90d retention if dashboards justify it.

---

### Area E — Execution layer (per-search fan-out, companions, cancellation)

Context: one sync `/api/search` fans out to exactly 4 CH queries — data (22.2 MiB), count companion (15.1 MiB), field-stats companion (185.0 MiB read / 169 MiB mem), histogram (1.06 MiB) — measured via isolated query_log capture.

#### E1. Generator-baked LIMIT silently disables pagination (page N == page 1) and caps total_count at page size; count companion is provably redundant I/O — **HIGH (correctness)**, not scale-sensitive
*Lane: execution-layer; severity revised critical→high by verifier (streaming/main-UI path is correct; blast radius = sync API contract).*

The generator bakes the request limit into raw-event SQL (`… ORDER BY timestamp DESC LIMIT 5 SETTINGS …`); `inject_limit_offset` returns SQL **unchanged** when it already contains `" LIMIT "` — user OFFSET never applied. Live proof: limit=5 offset=0 vs offset=5 returned **byte-identical** rows (md5-matched). Second face: `build_count_query` (NAN-1160) wraps the full SQL *including* the baked LIMIT → `total_count = min(limit, matches)`: live 5 and 100 vs true 23,117. The streaming endpoint's `quick_count` strips ORDER BY/LIMIT and returned the correct 23,117 — pinning the sync regression to fd41b551 (NAN-1159/1160, 2026-05-30) interacting with the Jan-31 limit-passthrough (cf128e99); build_count_query's "sql carries no user pagination LIMIT here" comment is false. The companion burns a duplicate scan (117k rows / 15–345 MiB depending on wrap) to return a number that can never differ from `results.len()`. Bonus: streaming per-chunk `inject_limit_offset(chunk_sql, remaining, 0)` is skipped for the same reason → cross-chunk over-delivery up to ~2x limit.

**Fix:** one owner for pagination. **Either way `inject_limit_offset` must become LIMIT-aware** (verifier: option (a) alone still bakes `LIMIT 1000000` and still no-ops the injector): make it REPLACE a trailing LIMIT with LIMIT/OFFSET, and make build_count_query strip the trailing LIMIT before wrapping. Interim: skip the count companion entirely (provably redundant; fallback yields the same capped number). Add a live regression test: `page(offset=N) != page(0)` and `total_count > limit` for a >limit match set.

**Files:** `clickhouse_sql_gen.rs:1177-1178,1291,1317-1324`, `execution/clickhouse_executor/sql_helpers.rs:33-48,70-86`, `paginated.rs:65-83,124-137`, `search/service/core_search.rs:524-556,656-672`, `search/service/streaming.rs:379-395`, `query_management.rs:142-173`.

#### E2. Field-stats companion reads 8.4x the data query's bytes, unsampled, with no admission control — **HIGH**, scale-sensitive
*Lane: execution-layer.*

The companion runs `topK(100)(toString(col)) + uniq(col)` for every one of ~90 columns over all matching rows: **185.02 MiB read / 168.8 MiB memory / 141ms** vs the data query's 22.2 MiB — 83% of the whole fan-out. `build_field_stats_sql` has a working SAMPLE path but both call sites pass `None` (core_search.rs comment "async endpoint handles large datasets" is false — it also passes None). The Search page fires `/api/search/field-stats` after **every** search; the handler calls `get_field_stats_for_query` directly — no admission permit, no query_id, no per-priority settings; N analysts = N concurrent unbounded all-columns scans gated only by the CH profile (300s/20GB).

**Verifier correction on the fix:** wiring `sample_rate` is **near-useless for I/O on this schema** — SAMPLE with `cityHash64(id)` last in the ORDER BY can't prune granules; measured read_bytes UNCHANGED at SAMPLE 0.1 (only modest CPU/mem savings). The effective lever is **column-set reduction**: a 5-column variant read 3.64 MiB vs 185 MiB (**50x**). Lead with: (1) compute stats over visible/page or analyst-pinned columns; (2) route the endpoint through admission with a derived query_id; (3) SAMPLE only as a CPU garnish.

**Files:** `execution/clickhouse_executor/field_stats.rs:209-291`, `search/service/core_search.rs:710-790`, `search/service/field_queries.rs:17-103`, `nanosiem-search/src/handlers/search.rs:453-479`.

#### E3. Cancel only kills the data query — count/histogram/field-stats companions (90% of the I/O) have no query_id and run to completion — **HIGH**, scale-sensitive
*Lane: execution-layer.*

`DELETE /api/search/{request_id}` → `KILL QUERY WHERE query_id='{request_id}'` exact-match; only the data query sets that id. Companions execute via plain `execute_count_query` (no id, no settings even on the settings-aware path), raw `ch_client.query()` (histogram, in a *detached* tokio::spawn), and unadorned field-stats — verified live: companions logged auto-generated UUIDs, carrying ~201 of 223 MiB read per search. Streaming disconnect cancels only the chunk query_id. Companions are bounded only by the CH profile (300s/20GB), not per-priority admission settings — so the single heaviest query per search is unkillable and uncapped. Cancel exists precisely for runaway expensive searches.

**Fix:** derive companion ids (`{request_id}-count/-hist/-fstats`) and kill all of them — verifier: prefer three exact derived ids over `LIKE '{request_id}%'` (client-provided ids could carry `%`/`_` wildcards). Pass the resolved `ClickHouseQuerySettings` into the companion executors (changes no result rows).

**Files:** `paginated.rs:71-75,126-130,165`, `query_execution.rs:186-243,261,363`, `query_management.rs:18-73`, `search/service/histogram.rs:110-134`, `field_stats.rs:295-339`, `core_search.rs:678-693`.

#### E4. Histogram companion doubles full-scan I/O for aggregation searches; count companion is redundant with the histogram — **MEDIUM**, scale-sensitive
*Lane: aggregation-codegen + execution-layer (companion-redundancy cluster, merged).*

Two related redundancies:
1. **Aggregation searches:** `* | timechart span=1h count` fires the timechart AND the histogram companion, each reading 1,190,097 rows / 10.21 MiB — exact 2x, at any selectivity (ratio holds with selective filters). Only `DetectionTesterPanel` sets `skip_histogram`; the Search page never does. **Verifier sharpening:** for timechart/ranked_bar/flow/asset/cloud/lateral display types the UI doesn't even render the timeline — the companion's scan is computed then **discarded**; `determine_display_type` runs server-side pre-execution, so the backend can skip the companion for those types with zero UI change. For trailing `stats` (Table) the timeline IS rendered — can't skip freely. Companion runs in a parallel spawn, so the cost is cluster I/O, not latency.
2. **Raw searches:** the histogram's bucket-sum IS the exact total (23,117 = direct count), computed 325x cheaper in read_bytes (1.06 MiB vs 345 MiB for the wide count wrap — CH prunes the histogram's subquery to timestamp-only; the count wrap of the ORDER-BY-LIMIT subquery reads the full column set at 437 MiB memory). **Verifier correctness gate:** the histogram wraps only the BASE (pre-pipe) query — `error | head 100` gives count=100 vs bucket-sum 23,117 — so deriving `total_count` from buckets must be gated on a row-preserving pipeline (covers the dominant bare-keyword/`*` path). Complementary cheap fix regardless: make build_count_query count over a column-pruned/ORDER-BY-stripped base.

**Files:** `search/service/core_search.rs:676-696`, `search/service/histogram.rs:8-110`, `search/service/mod.rs:85-102`, `paginated.rs:71-83`, `nanosiem-web/src/components/detection/editor/DetectionTesterPanel.tsx:201`.

#### E5. Histogram read loop swallows mid-stream CH errors — a 300s kill yields a silently fabricated timeline — **LOW**, scale-sensitive
*Lane: execution-layer.*

`while let Ok(Some(chunk)) = cursor.next().await` (histogram.rs:132) — the exact pattern NAN-1160/1177 fixed in count/field-stats but never in histogram (git-confirmed untouched). Mid-stream error = EOF → partial/empty buckets → `fill_histogram_gaps` zero-fills → confidently wrong timeline, no warning. Realistic manifestation (verifier, via forced `max_execution_time=0.005` → HTTP 408 before any block): an **all-zero timeline next to real result rows**. Window never opens locally (87ms); at scale the histogram is the full-range scan most likely to hit the 300s cap alone (data queries are day-chunked). Both call sites already wrap in match{Ok/Err→None}, so propagating Err yields `histogram:null` + logged warn with zero plumbing.

**Verifier sweep list for the fix PR — same swallowing loop also at:** `field_stats.rs:174` (schema query), `cloud.rs:542,1137,1420,1682`, `lateral.rs:486`, `nanosiem-search/src/handlers/identity.rs:143`.

**Files:** `search/service/histogram.rs:129-158`, reference fixed patterns at `query_execution.rs:199-216`, `field_stats.rs:476-494`.

---

## 3. What is already good — do not touch

**Codegen (both profiles)**
- Time bounds always in PREWHERE as DateTime64 literals; partition pruning works (Parts 6/26; out-of-range windows → 0/14 parts) and survives 5-stage CTE chains to the innermost ReadFromMergeTree.
- No `JSONExtract` on explicit UDM columns anywhere in a 20-query battery; `event_type` ALIAS resolves to `action` with set-index pruning.
- Selective Eq promotion to PREWHERE works (src_ip/user/source_type/event_type/process_name; OCSF class_uid/activity_id/endpoint IPs/user.name) with deliberate `optimize_read_in_order` toggling.
- Single-token keyword `lower(message) iLike '%kw%'` IS text-index accelerated on CH 26.4 (105/521 granules, 14.5 MiB vs 1.85 GiB; single-token also gets DIRECT READ — message never materialized). The old hasToken-vs-iLike perf fear is empirically dead; NAN-1026/1247/1381 work as designed for single tokens.
- Regex path adds an index-matchable iLike literal pre-filter (single-token cases).
- UDM `source_type` keeps the raw-equality PK fast path (40/541 granules + 44k rows vs 541/541 + 200k if lower()-wrapped); OCSF `lower(source_type)=` still set-index prunes identically to raw (set indexes evaluate the expression — EXPLAIN's "Condition: true" display is misleading).
- GROUP BY on raw columns for explicit fields; head/LIMIT pushed into the stage chain; aggregation path uses single-pass `count(*) OVER ()` (no count companion); `optimize_*_in_order=0` for non-timechart aggregations is deliberate and reasonable.
- The wide `SELECT *` + ~110-ALIAS stage_0 CTE is fully column-pruned by the CH 26.4 analyzer — generated vs hand-minimal SQL read byte-identical (verified both profiles; also with `enable_analyzer=0`).

**Schemas**
- Daily partitions + `ttl_only_drop_parts=1` global (mergetree.xml:43) — TTL expiry is part-drop-only.
- Sub-day time pruning works despite timestamp 2nd in sort key (1h: 184→5 granules generic exclusion).
- OCSF class-first PK earns its keep: class filter 478→31 binary-search; 30-min window ~1.12x over-read.
- text(splitByNonAlpha) indexes serve both iLike substring AND lower(col)= equality (user_unified 555→57; process.name 555→35); bloom on user.name 555→4; src_endpoint.ip bloom prunes absent IPs to 0 granules; combined set+text pruning zeroes disjoint keyword+source filters; OR trees use combined skip indexes.
- `GRANULARITY 100000000` in DDL is CH-normalized display (migration 119 wrote 1) — not a bug.
- ext is native JSON(512), 7% of table, index deliberately dropped in 118; JSON dynamic-path budget healthy (max 41 paths/row, zero shared-data overflow vs 1024).
- dest_port skip index deliberately NOT recommended — measured 98/184 granules contain matches (no pruning on this data; NAN-1035 measure-first).
- Codecs sane (LC enum-ish fields, T64 ports, Delta timestamps, http_user_agent ZSTD 48x); SAMPLE BY alive; migration-128 OCSF MVs read only promoted columns; count-only queries served by `_exact_count_projection`.
- No dead `*_search` columns exist — **CLAUDE.md's `_search` columns / hasToken guidance is stale doc drift** (schema uses lower(col) text indexes since 119), as is its "90-day TTL" (init.sql says 365d).

**Execution layer**
- Streaming `/api/search/stream` is genuinely incremental (JSONEachRow chunks, 50-row/200ms batching, per-day partitions newest-first, disconnect → KILL on chunk id) and its quick_count is correct.
- Dragonfly cache: identical repeat search → ZERO new CH queries; 90s TTL / no-empty-results / 10k-row caps sensible; key includes all query-affecting fields; audit-rewrite precedes cache check (no permission leak).
- ext-key enumeration uses the shipped distinctJSONPaths/3h-window/LIMIT 512 form, 5–10ms (NAN-1172/1177 intact).
- fetch_log_by_id: count companion correctly skipped (NAN-1032), source_type PK hint plumbed.
- Dashboards set skip_histogram+skip_field_stats; aggregation searches correctly suppress field-stats.
- Admission controller correctly wired for sync/async/queue; memory/priority/queue settings DO flow (only threads/timeout are overridden — A2).
- Server-side guards real: 20GB/query, external group-by spill at 10GB, max_result_rows 1M (query_limits.xml).

---

## 4. Suggested fix order

| # | Item | Type | Effort |
|---|------|------|--------|
| 1 | **E1** pagination: LIMIT-aware `inject_limit_offset` + strip-LIMIT in build_count_query; interim: drop the redundant count companion | correctness | S–M |
| 2 | **B3** strip `ext.` UDM-scoped (UdmProfile::resolve or Unknown arm) + regression test | correctness | S |
| 3 | **A1** single-WHERE emission (or full promotion); parity tests + read_bytes probe; update CLAUDE.md + audit framing | perf, biggest win | M |
| 4 | **C1** subcolumn emission in field_access_expr with coalesce-wrapped casts; scalar-only; NAN-1161 corpus | perf | M |
| 5 | **B1** lowercase hashes/guids at ingest + LOWERCASE_NORMALIZED_FIELDS (or lower() bloom indexes); fix rule_id UUID arm | perf | M |
| 6 | **B2** longest-token iLike guard for multi-token needles + extract_longest_literal tokenization | perf | S–M |
| 7 | **E2** field-stats: column-set reduction (50x) + admission permit + derived query_id | perf/ops | M |
| 8 | **E3** derived companion query_ids + multi-kill + pass settings to companions | ops | S |
| 9 | **A2** thread QueryPriority into generate_settings (do NOT just delete the caps) | ops | S |
| 10 | **E4** skip histogram companion for non-timeline display types; derive total from buckets when pipeline row-preserving; column-prune the count wrap | perf | S–M |
| 11 | **D1** timechart top-N two-CTE rewrite (count/sum exact; dc stays two-pass) | perf | S–M |
| 12 | **D2** add `estdc()` → uniqCombined64; document dc() memory | perf | S |
| 13 | **B5** migration: text indexes on process_path/url + session_id bloom (note non-alpha-pattern limitation); Saturn-validate | perf | S |
| 14 | **E5** histogram (+ cloud/lateral/identity) read-loop error propagation | robustness | S |
| 15 | **C2** LC ALTERs on hot OCSF entity columns (Saturn per-part cardinality gate) | perf | M |
| 16 | **B4** adaptive time-slicing executor for unfiltered newest-first (re-validate 70x on Saturn first) | perf | L |
| 17 | Low/defer: **B6** audit-writer lowercase + CI contract assert; **C4** drop idx_class_uid; **C3** severity prewhere flag (post-A1); **B8** Saturn index sizing; **D4** rollup routing design; **B7** table_view default for API callers | misc | S each |

Cross-cutting: every schema change Saturn-validates first (NAN-1035); update CLAUDE.md's stale `_search`/hasToken/90-day-TTL text alongside item 3.

---

## 5. Appendix — refuted / rejected claims (do not re-chase)

1. **"Post-stats sort/head/where defeats codegen field pruning"** — mechanism real, execution impact measured ZERO (CH analyzer prunes the CTE; identical reads even with `enable_analyzer=0`); duplicate of NPL_SQL_CONVERSION_AUDIT field_analysis-2 "not worth changing", and the pruned baseline never occurs live anyway (auto_sort injects `| sort` before codegen).
2. **"Hostname expansion re-wraps lower() on src_host, orphaning the raw bloom"** — empirically backwards: the lower() form is the BETTER-pruning form (text index serves both OR arms, 542→237) while the recommended raw form full-scans (OR's startsWith arm not bloom-servable); applying the fix would regress.
3. **"ocsf_logs TTL `DELETE WHERE` forces row-wise TTL merges"** — the WHERE guard is the documented NAN-1384 (G17) garbage-timestamp protection (migration 127 + user guide); the proposed DEFAULT-clamp can't work (explicit writes bypass DEFAULT); and `ttl_only_drop_parts=1` is already set server-wide, contradicting the cost model.
4. **"eval wraps numeric columns in toFloat64OrNull(toString()) — 2x CPU"** — reproduces (~13ns/row) but is the documented eval-numeric-cast-7 "not worth changing" decision; the measurement confirms rather than overturns it.
5. **"NAN-806 auto-sort flips grouped stats to the wide SELECT * projection"** — true mechanically, measured zero I/O/memory difference (analyzer prunes; wide variant even used LESS memory); duplicate of the same documented decision as #1.
6. **"Doomed UDM-typed first attempt on OCSF fetch-log (Code 47 then dynamic retry)"** — real and reproduced live, but a duplicate of OCSF_PROFILE_AWARENESS_AUDIT (NAN-1241) line 43 with the identical fix plan; the new datum (ExceptionBeforeStart = zero rows read) actually weakens the prior "double-fetch" wording. If counted at all: low, not medium.
7. **"Every interactive search fully sorts all matches under LIMIT 1,000,000"** — false: the auditor benchmarked `/explain` SQL (no limit → 1M default); the live execute path bakes `LIMIT 100` (verified in query_log: 114 MiB/137ms, not 541–730 MiB). Surviving kernel (read-in-order never engages on either table) is covered by B4. Collateral bug found while refuting — the baked-LIMIT/total_count interaction — is reported as E1.

---

## 6. Saturn validation addendum (2026-06-12, post-merge)

Read-only measurements on nano-saturn (nanosiem.logs, 1.32B rows / 240 GiB, CH 26.4.3.37), validating merged fixes and scale-gated claims:

- **A1 / NAN-1412 (merged)**: zero-match non-promoted hunt (session_id, 6h window, wide projection, LIMIT 100): explicit-PREWHERE form 192.7 MiB / ~200ms vs single-WHERE 24.3 MiB / ~110ms = **7.9x read_bytes**, 3 runs. Direction + materiality confirmed at scale pre-deploy (local OCSF full-view case was 349x; UDM narrower).
- **B2 / NAN-1416 (merged)**: dense control CPU ±1% with −18% bytes; adversarial 76%-density guard token +5% CPU / −11% bytes; sparse phrase **5.6x bytes / 2.7x CPU**. (Was the ship-gate for PR #2205.)
- **B1 / NAN-1415 (merged)**: `countIf(src_user != lower(src_user)) = 0` over 84.3M populated rows — the src_user raw-compare is safe in production. `dest_user`: **100% mixed-case (50.2M rows)** — the agent's STOP on dest_user fully vindicated; never add it without ingest normalization + backfill.
- **B6 / NAN-1432 (in flight)**: `user` contract violations in production = **772 rows, all source_type='audit'** (of 1.04B) — the audit-writer bug confirmed live; it is the only writer violating the contract.
- **B4**: full 6h window 11.04M rows / 172.6 MiB vs 15-min slice 420k rows / 10.6 MiB = **26x rows / 16x bytes**; scales linearly with window. Ticketed as NAN-1433-class backlog item with fix shape (reuse the streaming chunker for sync).
- **C2/C3/C4**: `ocsf_logs` does not exist on Saturn — formally deferred until a production-scale OCSF tenant exists to measure against.

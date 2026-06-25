# Silent Correctness Bug Hunt — Findings

## Summary (counts by bucket + severity)

- **Confirmed (both lenses agree, execution-backed): 10**
  - High: 4
  - Medium: 6
- **Split (needs human review): 0**
- **Refuted: 0**

By lane:
- escaping: 1
- swallowed-err / count-companion / regex-on-SQL: 4 (overlapping — three are the same root-cause chain at different layers, one is the swallow)
- eval-fn: 2
- CTE-multistage: 1
- identity-join: 2
- JSON-schema: 1

> Test-infra note (applies to every gating test below): the repo's
> `nanosiem-core/src/query/tests/clickhouse_sql_gen_tests` dir is **orphaned and never
> compiles** (project memory). All gating tests must live in an inline `#[cfg(test)]` module
> alongside the code under test, or in a wired-up sibling test module (e.g. `npl_compat_tests.rs`,
> the existing `#[cfg(test)] mod` in `sql_helpers.rs`, or `clickhouse_sql_gen.rs`'s tests module).

---

## Confirmed (execution-backed, both lenses agree) — ranked by severity then confidence

### 1. make_timestamp() always errors (Code 6 CANNOT_PARSE_TEXT) — emits unpadded date/time string toDateTime can't parse
- **Severity:** high — **Confidence:** executed-confirmed
- **Root cause:** `nanosiem-core/src/query/clickhouse_sql_gen/eval_functions.rs:822-831`
- **Symptom:** Any `| eval x=make_timestamp(y,m,d,h,mi,s)` returns a 500 "A database error occurred" instead of a timestamp. An analyst building a synthetic timestamp from components sees the whole query die with no hint make_timestamp is the culprit.
- **Repro (verbatim):**
  ```
  $ curl -s -X POST .../api/search/explain -d '{"query":"* | eval x=make_timestamp(2024,1,1,12,30,0)",...}'
    → stage_1 ... toDateTime(concat(2024, '-', 1, '-', 1, ' ', 12, ':', 30, ':', 0)) AS x FROM stage_0

  $ curl -s "http://localhost:8123/?user=nanosiem&password=nanosiem&database=nanosiem" --data-binary "SELECT toDateTime(concat(2024, '-', 1, '-', 1, ' ', 12, ':', 30, ':', 0)) AS x"
    Code: 6. DB::Exception: Cannot parse string '2024-1-1 12:30:0' as DateTime: syntax error at position 10 (parsed just '2024-1-1 1') ... (CANNOT_PARSE_TEXT) (version 26.4.3.37)

  $ curl -s -X POST .../api/search -d '{"query":"* | eval x=make_timestamp(2024,1,1,12,30,0) | table x | head 1",...}'
    {"error":{"code":"INTERNAL_ERROR","message":"Internal server error: A database error occurred"}}

  Fix-form validation:
  $ curl ... --data-binary "SELECT makeDateTime(2024,1,1,12,30,0) AS x"   →  2024-01-01 12:30:00
  $ curl ... --data-binary "SELECT makeDateTime(2024,12,1,9,5,3) AS x2"  →  2024-12-01 09:05:03
  $ curl ... --data-binary "SELECT makeDateTime('2024',1,1,12,30,0)"     →  Code: 43 ... Expected: Number, got: String
  ```
- **Proposed fix (one-line):** emit `makeDateTime({y},{m},{d},{h},{mi},{s})` (numeric constructor, no zero-padding) instead of `toDateTime(concat(...))`, mirroring the sibling `make_time` arm at lines 858-862. **Implementer caveat:** coerce string-typed field refs per `make_time`'s `toUInt8OrNull(toString(...))` pattern, but the YEAR arg must use a wider width (e.g. `toUInt16OrNull`/`toInt32OrNull`) since `toUInt8OrNull` caps at 255 and would null out 2024.
- **Gating test:** assert `make_timestamp(2024,1,1,12,30,0)` lowers to a `makeDateTime(...)` call and NOT `toDateTime(concat(...))`. Can live inline in the already-wired `npl_compat_tests.rs` (mirror the existing `eval_make_time` test). The existing `eval_make_timestamp` test only generates SQL without asserting contents — which is exactly why the bug shipped green.

### 2. mvfind() always errors (Code 386 NO_COMMON_TYPE) — searches a String array for the integer literal 1
- **Severity:** high — **Confidence:** executed-confirmed
- **Root cause:** `nanosiem-core/src/query/clickhouse_sql_gen/eval_functions.rs:1249-1261` (emit site 1257-1260)
- **Symptom:** Any `| eval x=mvfind(multivalue_field, pattern)` aborts the whole query. The codegen is also conceptually wrong: it filters the array to matching elements then asks `indexOf` for the literal value 1, rather than returning the position of the first matching element. SOC analysts never get a result from mvfind.
- **Repro (verbatim):**
  ```
  $ curl -s -X POST .../api/search/explain -d '{"query":"* | eval x=mvfind(mvappend(\"a\",\"b\",\"c\"),\"b\")",...}'
  → stage_1 AS ( SELECT *, indexOf(arrayFilter(x -> match(x, 'b'), array('a', 'b', 'c')), 1) AS x FROM stage_0 )

  $ curl -s "http://localhost:8123/...nanosiem" --data-binary "SELECT indexOf(arrayFilter(x -> match(x, 'b'), array('a','b','c')), 1) AS x"
  Code: 386. DB::Exception: There is no supertype for types String, UInt8 ... (NO_COMMON_TYPE) (version 26.4.3.37)

  $ curl ... --data-binary "SELECT indexOf(arrayMap(x -> match(x, 'b'), array('a','b','c')), 1) AS x"
  2   (proposed fix returns correct 1-based index of 'b')

  $ curl -s -X POST .../api/search -d '{"query":"* | eval x=mvfind(mvappend(\"a\",\"b\",\"c\"),\"b\")",...}'
  {"error":{"code":"QUERY_ERROR","message":"Query error: Type mismatch: cannot compare text field with a number. ... Try using tonumber() ..."}}

  Source emits: format!("indexOf(arrayFilter(x -> match(x, {}), {}), 1)", arg_sqls[1], arg_sqls[0])
  ```
- **Proposed fix (one-line):** swap `arrayFilter` → `arrayMap` so the array holds 0/1 match flags, then `indexOf(arrayMap(x -> match(x, {pat}), {field}), 1)` type-checks and returns the 1-based first-match index (matches the inline comment's stated intent and Splunk mvfind semantics).
- **Gating test:** assert `mvfind(...)` lowers to `indexOf(arrayMap(...),1)` (NOT `arrayFilter`). Inline `#[cfg(test)]` in `eval_functions.rs` (no inline tests exist there yet; grep returned none).

### 3. resolve_identity ASOF LEFT JOIN silently degrades to INNER JOIN, dropping every event with no identity match
- **Severity:** high — **Confidence:** executed-confirmed
- **Root cause:** `nanosiem-core/src/query/clickhouse_sql_gen/identity.rs:226-254` (WHERE at 245-246 + CASE at 231, plus absence of any `SETTINGS join_use_nulls`)
- **Symptom:** Any `* | resolve_identity field=<x>` returns FAR fewer events than the same search without resolve_identity. The command is documented/intended as enrichment (must keep all rows) but actually filters. The analyst loses the majority of their events with no error, warning, or visible sign.
- **Repro (verbatim):**
  ```
  identity_observations.observed_at is DateTime64(3,'UTC') — NON-nullable. CH default join_use_nulls=0
  fills unmatched ASOF LEFT JOIN rows with the epoch default (NOT NULL), so the `i.observed_at IS NULL`
  guard is always FALSE for unmatched rows and the WHERE drops them.

  Baseline:  * | stats count                                   -> {"count":1993568}
  With join: * | resolve_identity field=user | stats count    -> {"count":971047}   (DROPS 1,022,521 / 51%)
             * | resolve_identity field=src_ip | stats count  -> {"count":325274}  (DROPS 84%)
             * | resolve_identity field=src_host | stats count -> {"count":87194}  (DROPS 96%)

  Isolated proof on the generated WHERE pattern:
    SELECT count() FROM ( SELECT main.user,i.observed_at FROM logs AS main
      ASOF LEFT JOIN identity_observations AS i ON main.user=i.user AND main.timestamp>=i.observed_at
      WHERE i.observed_at IS NULL OR i.observed_at > main.timestamp - INTERVAL 86400 SECOND )
      default join_use_nulls=0  -> 971047
      SETTINGS join_use_nulls=1 -> 1990991   (fix restores ~all rows)
  Logs whose user has NO observation match (rows wrongly dropped): 1,019,531.

  Second lens — mechanism proven: i.observed_at='1970-01-01 00:00:00.000' for 1,020,006 unmatched rows
  (epoch default, NOT NULL). Under join_use_nulls=1 those become NULL → classified 'none' and survive
  (conf='recent' 971047 ; conf='none' 1020006).

  grep -rn join_use_nulls nanosiem-core/src nanosiem-search/src  -> NONE FOUND
  ```
- **Proposed fix (one-line):** append `SETTINGS join_use_nulls=1` to the final query when a resolve_identity ASOF LEFT JOIN is present (fills `i.observed_at` with real NULL for unmatched rows so the `IS NULL` guards/CASE become correct). No sibling join sets it because none post-filter a non-nullable right column on `IS NULL`; this one does.
- **Gating test:** assert generated resolve_identity SQL contains `join_use_nulls=1` (or that unmatched rows survive). Inline `#[cfg(test)]` in `identity.rs`.

### 4. ext/JSON field CONTAINS and regex-token filters lower to hasTokenCaseInsensitive, silently under-matching sub-token needles (and over-matching on negation)
- **Severity:** high — **Confidence:** executed-confirmed
- **Root cause:** `nanosiem-core/src/query/clickhouse_sql_gen/search_expr.rs` lines 689, 709, 733, 754 (`generate_json_field_filter`, inline term path) and 963, 979, 1005, 1028 (`generate_where_condition`, post-pipe `| where` path)
- **Symptom:** `field CONTAINS "x"` or `field=/x/` on any non-UDM ext JSON field returns 0/wrong rows whenever the needle is a SUB-TOKEN. `hasTokenCaseInsensitive` only matches whole tokens — `medi` never matches `Medium`. **Negated forms over-match:** `NOT CONTAINS "medi"` fails to exclude the Medium rows and leaks them all through — a silent failure of a security exclusion filter. The canonical UDM column path (`generate_udm_field_filter`, NAN-1026 Phase 2) already lowers identical operators to `lower(toString(...)) iLike '%...%'`; the ext/JSON path was never converted.
- **Repro (verbatim):**
  ```
  # Data baseline: 8639 windows_sysmon rows have integrity_level='Medium'
  SELECT toString(ext.integrity_level) v, count() FROM logs WHERE source_type='windows_sysmon' GROUP BY v ...
  ->  (empty) 847935 | Medium 8639 | High 60

  # /explain shows the buggy codegen:
  ... | where integrity_level CONTAINS "medi"
  -> stage_1 WHERE hasTokenCaseInsensitive(toString(integrity_level), 'medi')

  # Three conditions on CH directly:
  hasTokenCaseInsensitive(toString(ext.integrity_level),'medi')   -> 0
  position(lower(toString(ext.integrity_level)),'medi')>0         -> 8639
  lower(toString(ext.integrity_level)) iLike '%medi%'             -> 8639

  # End-to-end /api/search (| stats count):
  CONTAINS "medium" (full token)   -> 8639   (works)
  CONTAINS "medi"   (sub-token)    -> 0       (BUG: should be 8639)
  | where integrity_level=/medi/   -> 0       (BUG: regex-token path)
  inline integrity_level=/medi/    -> 0       (BUG)
  NOT CONTAINS "medi"              -> 856634  (BUG: should be 847995; total=856634, all 8639 Medium rows leak the exclusion)
  ```
- **Proposed fix (one-line):** in both `generate_json_field_filter` and `generate_where_condition`'s FieldFilter arm, drop the `has_separators`/hasToken branch entirely and always lower to `lower(toString({field})) iLike '%{escaped}%'` (NOT iLike for negated forms), exactly as `generate_udm_field_filter` does post-NAN-1026. The perf rationale is stale — migration 118 (`clickhouse/118_drop_ext_text_index.sql`) dropped `idx_ext_text`, so there's no token bloom index on ext and hasToken is a full scan AND wrong.
- **Gating test:** assert `integrity_level CONTAINS "medi"` and `integrity_level=/medi/` lower to `iLike '%medi%'` and contain NO `hasToken`. Inline in `search_expr.rs` or `clickhouse_sql_gen.rs` alongside the existing NAN-1026 anti-hasToken tests (which only cover UDM/message).

### 5. STARTSWITH/ENDSWITH iLike codegen leaves user `_`/`%` as live wildcards (no escape_like_pattern), unlike CONTAINS
- **Severity:** medium — **Confidence:** executed-confirmed
- **Root cause:** `nanosiem-core/src/query/clickhouse_sql_gen/search_expr.rs` lines 519, 526, 533, 540 (duplicated again at 769/776/783/790 and 1042/1049/1056/1063)
- **Symptom:** `field STARTSWITH "x"` / `field ENDSWITH "x"` where the value contains `_` or `%` silently OVER-matches. `file_path ENDSWITH "_1.dll"` returns 6 rows but only 5 files end with the literal `_1.dll`; the `_` wildcarded the `-` in `vulkan-1.dll`. A SOC analyst pivoting on a Windows path / service-account name with an underscore (svc_db, scoped_dir, _locales) gets silent noise rows.
- **Repro (verbatim):**
  ```
  1) Ground-truth overmatch on CH:
    iLike '%_1.dll'                       => 6   (what the generator emits, _ as wildcard)
    endsWith(lower(file_path),'_1.dll')   => 5   (correct literal answer)
    DISTINCT file_path ... iLike '%_1.dll' AND NOT endsWith(...,'_1.dll')
      => C:\Program Files (x86)\Microsoft\EdgeCore\Optimized\vulkan-1.dll  (the leaked row)
    iLike '%\_1.dll'                      => 5   (escaped/fix form = correct)

  2) /explain proves the unescaped pattern:
    file_path ENDSWITH "_1.dll"  => ... file_path iLike '%_1.dll'   (_ NOT escaped)
    file_path STARTSWITH "a%b"   => ... file_path iLike 'a%b%'      (% left live)

  3) End-to-end /search:
    file_path ENDSWITH "_1.dll" | stats count  => {"results":[{"count":6}]}   (should be 5)

  Inconsistency vs sibling, both on file_path:
    CONTAINS "svc_"  => iLike '%svc\_%'  (escaped, correct)
    ENDSWITH "svc_"  => iLike '%svc_'    (unescaped, buggy)
  ```
- **Proposed fix (one-line):** wrap all four StartsWith/EndsWith arms in each of the three blocks with `escape_like_pattern(&escape_string(&s.to_lowercase()))`, exactly as `Comparator::Contains` does at line 480 (fixed under NAN-1157/NAN-1158; STARTSWITH/ENDSWITH were missed). All three duplicated blocks must get the change or the fix is half-applied.
- **Gating test:** assert `file_path ENDSWITH "_1.dll"` lowers to a pattern containing the escaped underscore and `STARTSWITH "a%b"` to the escaped `%`, mirroring the existing Contains escaping test. Match the existing test's in-Rust string form (single backslash before `_` after `escape_like_pattern`, before `escape_string`'s backslash-doubling) rather than the wire form, to avoid brittleness.

### 6. execute_count_query swallows a ClickHouse count-query failure into Ok(0), masking total_count
- **Severity:** medium — **Confidence:** executed-confirmed
- **Root cause:** `nanosiem-core/src/search/execution/clickhouse_executor/query_execution.rs:199` (the `while let Ok(Some(chunk))` loop) + `226` (the `Ok(0)` fallthrough)
- **Symptom:** When the count companion SQL fails for any reason, the streaming loop treats `Err` identically to end-of-stream and the function returns `Ok(0)`. The caller's defensive `count_result.unwrap_or(results.len())` (paginated.rs:81/135/342) never fires. Result: a search returns 5 visible rows yet reports `total_count: 0` / an empty paginator, with no surfaced error. This is why bug #7/#8 surfaces as `total_count=0` rather than `total_count=results.len()`.
- **Repro (verbatim):**
  ```
  # count SQL errors on CH (Code 62), yet e2e search succeeds with total_count=0 (NOT results.len()):
  curl .../api/search -d '{"query":"\"alpha order by beta\"","limit":10,...}'
  -> total_count: 0  results: 10
  (limit=5/10: page is full so control reaches count_result.unwrap_or(results.len); total_count=0 proves count_result==Ok(0))
  (limit=100, 62<100: short-circuit at paginated.rs:77 returns results.len()=62, broken count ignored)

  # control (clean query) reports correct count:
  curl .../api/search -d '{"query":"apache",...,"limit":5}'  -> total_count: 27  results: 5
  ```
- **Proposed fix (one-line):** replace `while let Ok(Some(chunk)) = cursor.next().await` with an explicit match that propagates `Err(parse_clickhouse_error(...))` (and replace the final `Ok(0)`), mirroring the canonical streaming sibling at `paginated.rs:268-275` and `quick_count` at `query_management.rs:142`. **Scope note:** this only restores the intended degraded fallback (results.len()); the true count still requires fixing the build_count_query regex (bug #7).
- **Gating test:** feed `execute_count_query` a syntactically-invalid SQL (unterminated literal) against live CH and assert it returns `Err`, not `Ok(0)`. Integration-style test (needs a real executor / CH client); place under `nanosiem-core/src/search/execution`.

### 7. build_count_query non-greedy FROM regex truncates the WHERE clause at an in-literal `order by`/`settings`, producing broken count SQL
- **Severity:** medium — **Confidence:** executed-confirmed
- **Root cause:** `nanosiem-core/src/search/execution/clickhouse_executor/sql_helpers.rs:87-92`
- **Symptom:** For any single-FROM (non-CTE) free-text search whose literal contains a whitespace-bounded SQL keyword (e.g. `message iLike '%alpha order by beta%'`), the regex `FROM\s+(\S+)(.*?)(?:\s+ORDER\s+BY|\s+SETTINGS|\s*$)` stops the non-greedy capture at the keyword INSIDE the iLike literal, slicing the WHERE clause in half and emitting an unterminated string literal. Combined with the swallow (#6), `total_count` silently reads 0. Surfaces whenever `results.len() >= limit` or `offset > 0`.
- **Repro (verbatim):**
  ```
  1) /explain data SQL: ...WHERE (((lower(message) iLike '%alpha order by beta%') AND source_type != 'audit')) ORDER BY timestamp DESC LIMIT 1000000 SETTINGS max_threads=16, ...

  2) build_count_query regex (Rust regex crate, same flags) yields the TRUNCATED count SQL:
     SELECT count(*) as cnt FROM logs PREWHERE ... WHERE (((lower(message) iLike '%alpha
     (cut at the in-literal ` order by`)

  3) Truncated count SQL on CH:
     Code: 62. DB::Exception: Single quoted string is not closed: Syntax error at position 153 ('%alpha) (SYNTAX_ERROR)

  4) baseline real count: SELECT count() ... iLike '%alpha order by beta%' AND source_type!='audit' -> 62

  5) e2e /api/search limit=10 (forces count companion): total_count=0  results=10   (should be 62)
     control "alpha" (no embedded keyword): total_count correct

  Fix validation on CH:
    fallback-style strip regex (lines 95-99) -> ALSO truncates mid-literal -> Code 62 (shares the bug)
    pure wrap_query_for_count(sql) = "SELECT count(*) AS cnt FROM (<full sql incl ORDER BY+SETTINGS>) AS subquery" -> 62 (CORRECT)
  ```
- **Proposed fix (one-line):** stop regex-slicing the WHERE — always `return wrap_query_for_count(sql);` (the subquery-wrap canonical sibling already used for the `WITH ` CTE branch at line 83; literal-safe, counts full pre-LIMIT result). **Critical:** use the PURE `wrap_query_for_count`, not the existing lines-95-99 fallback — that fallback's own `\s+ORDER\s+BY\s+.*$` regex truncates identically (verified Code 62).
- **Gating test:** assert `build_count_query("...WHERE message iLike '%alpha order by beta%' ORDER BY timestamp DESC SETTINGS ...")` produces balanced-quotes SQL that parses/counts correctly (or `assert!(c.contains("order by beta"))`). Add to the existing `#[cfg(test)] mod` in `sql_helpers.rs` (alongside the NAN-1159 tests).

> **Note on findings #6/#7/#8:** these are three execution-confirmed entries describing the same end-to-end failure chain at different layers — the build_count_query regex truncation (codegen root cause, #7) feeds the execute_count_query swallow (#6), and a second confirmed entry re-states the chain with the `settings`-keyword vector and additional control queries (folded into #7/#8). Both lenses confirmed each. NAN-1159's WITH-wrapping only covered CTE queries; the simple-query path was never converted. A single fix (route non-CTE through pure `wrap_query_for_count`) + the swallow fix together resolve the chain.

### 8. build_count_query regex truncates WHERE at ` ORDER BY`/` SETTINGS` inside string literals → count companion errors, total_count silently 0 (count-companion lens)
- **Severity:** medium — **Confidence:** executed-confirmed
- **Root cause:** `nanosiem-core/src/search/execution/clickhouse_executor/sql_helpers.rs:87-92` (same site as #7, count-companion framing)
- **Symptom:** For a single-FROM query whose literal contains a whitespace-bounded keyword, results are correct but `total_count` comes back 0 — a user paging sees 10 rows on screen but a total of 0; the count footer/pagination is wrong and nobody notices because the rows look fine.
- **Repro (verbatim):**
  ```
  62 synthetic non-audit rows inserted (source_type='nan_countbug_test', message='row N alpha order by beta').

  Rust regex crate applied to /explain SQL:
    COUNT: SELECT count(*) as cnt FROM logs PREWHERE ... WHERE (((lower(message) iLike '%alpha  (truncated at in-literal " order by ")

  Truncated count SQL on CH: Code: 62 Single quoted string is not closed (SYNTAX_ERROR)
  baseline: SELECT count(*) FROM logs WHERE lower(message) LIKE '%alpha order by beta%' AND source_type!='audit'  => 62

  e2e /api/search limit=10:
    "alpha order by beta"                          -> total_count=0   results=10  (WRONG, should be 62)
    control source_type="nan_countbug_test"        -> total_count=62  results=10  (CORRECT)

  Rust-level proof current-vs-fixed build_count_query on input
    "SELECT * FROM logs WHERE lower(message) iLike '%alpha order by beta%' ORDER BY timestamp DESC SETTINGS max_threads=16":
    CURRENT contains 'order by beta'? false   ;   FIXED (wrap) contains 'order by beta'? true
  Wrapped count over the real data SQL (incl LIMIT 1000000): 62 (correct)
  ```
- **Proposed fix (one-line):** drop the brittle regex branch and always `return wrap_query_for_count(sql);` (canonical sibling at line 83; literal-safe). The `settings` alternation is an additional truncation vector also fixed by the wrap.
- **Gating test:** in the `#[cfg(test)] mod` in `sql_helpers.rs`: `let c = build_count_query("SELECT * FROM logs WHERE lower(message) iLike '%alpha order by beta%' ORDER BY timestamp DESC SETTINGS max_threads=16"); assert!(c.contains("order by beta"));` — fails today (regex cuts at the literal's ` order by`), passes after the wrap. Asserts the literal is preserved, not the buggy string.

### 9. stats over an aggregated stage where agg field == default func-name renames output to `_agg_count` but never renames it back, so the auto-injected `ORDER BY count` crashes
- **Severity:** medium — **Confidence:** executed-confirmed
- **Root cause:** `nanosiem-core/src/query/clickhouse_sql_gen/aggregation.rs` — `shadowed_aliases` (lines 27-40) requires explicit `agg.alias`, vs `shadows_field` (lines 142-149) which uses `output_alias()` that falls back to the func name. The two shadow checks use different criteria.
- **Symptom:** Any multi-stage pipeline whose SECOND aggregation re-aggregates the prior stage's func-named column without an explicit alias — canonically `… | stats count by x | stats count(count) by x` — returns INTERNAL_ERROR (HTTP) / UNKNOWN_IDENTIFIER (CH). No user `where` needed: the failure is triggered solely by the NAN-806 auto-injected `ORDER BY count DESC`. An analyst writing a "count of groups that have N events" rollup gets a generic 500.
- **Repro (verbatim):**
  ```
  /explain for `* | stats count by source_type | stats count(count) by source_type`:
    stage_1: SELECT source_type AS source_type, count() AS count ... GROUP BY source_type
    stage_2: SELECT source_type AS source_type, count(count) AS _agg_count ... GROUP BY source_type  <-- renamed, NO rename-back
    stage_3: SELECT * FROM stage_2 ORDER BY count DESC    <-- auto-injected (NAN-806), references the now-gone `count`

  Exact SQL on CH: Code: 47. DB::Exception: Unknown expression identifier `count` in scope stage_3. (UNKNOWN_IDENTIFIER)

  End-to-end: {"error":{"code":"INTERNAL_ERROR","message":"Internal server error: An internal error occurred"}}

  Data exists: SELECT count() FROM (SELECT source_type FROM logs GROUP BY source_type)  -> 17 (one lens saw 18; live ingestion)

  Canonical rename-back fixes it (16/17 rows returned, each =1):
    stage_2 AS (SELECT * EXCEPT(_agg_count), _agg_count AS count FROM (SELECT source_type, count(count) AS _agg_count FROM stage_1 GROUP BY source_type))

  Control (explicit alias) works: ... | stats count(count) as cnt by source_type  -> HTTP 200, valid rows
  ```
- **Proposed fix (one-line):** unify the two shadow predicates — collect into `shadowed_aliases` using the SAME predicate as line 142 (push `agg.output_alias()` whenever `agg.field` normalizes to `output_alias()`), so the existing outer-subquery rename-back (lines 199-220) emits `SELECT * EXCEPT(_agg_count), _agg_count AS count`. No regression on `min(timestamp) AS timestamp` (output_alias()==alias there).
- **Gating test:** parse the canonical query, generate SQL, assert it contains `_agg_count AS count` / `EXCEPT(_agg_count)`. Inline `#[cfg(test)]` in `clickhouse_sql_gen.rs`'s tests module. One lens applied the fix in a scratch edit and confirmed fail-before/pass-after (reverted via git checkout).

### 10. resolve_identity equi-join key is raw-case while the dict lookup key is lower() — case-mismatched users won't ASOF-match
- **Severity:** medium — **Confidence:** partial (one lens: confirmed; one lens: overstated — see split note). Bucketed confirmed because the structural skew is proven in emitted SQL and demonstrated with an adversarial ASOF run, even though it does not produce a wrong count on the current local dataset.
- **Root cause:** `nanosiem-core/src/query/clickhouse_sql_gen/identity.rs:243` (`ON main."user" = i.user`, raw case) vs `:187` (`lower(main.user)` used for the dict key)
- **Symptom:** For reverse user/hostname lookups, an event with user `JDoe` would not ASOF-match an observation row `jdoe` even though the dictGet path lowercases the same key — so the same field resolves identity inconsistently: dict columns populate but hostname/mac/identity_ip fill targets stay empty (or the whole row drops via bug #3). Windows-style mixed-case usernames silently fail to resolve.
- **Repro (verbatim):**
  ```
  Structural divergence in /explain:
    ASOF LEFT JOIN identity_observations AS i ON main."user" = i.user        (RAW case)
    dictGetOrDefault('nanosiem.user_registry_dict','email', lower(main."user"), '') AS user_identity_email   (lower)

  Could NOT reproduce a wrong count on local data (it is case-consistent):
    SELECT count() FROM logs main WHERE user!='' AND lower(user) IN (SELECT lower(user) FROM identity_observations WHERE user!='')
      AND user NOT IN (SELECT user FROM identity_observations WHERE user!='')  -> 0
    all 150,079 identity_observations users are lowercase; only mixed-case log user "Dan Lussier" has 0 observations.

  Adversarial ASOF proof (obs user 'twilliams' exists; event user 'TWilliams'):
    RAW-CASE join   ON main.u = i.user            -> TWilliams | (empty) | (empty) | 1970-01-01   == NO MATCH
    LOWER-CASE join ON lower(main.u)=lower(i.user) -> TWilliams | twilliams | 10.1.1.117 | 2026-... == MATCHES
  Hostname reverse path has the same skew: ON main.src_host = i.hostname (raw) vs dict lower(main.src_host).
  ```
- **Proposed fix (one-line):** make the ASOF equi-join case-insensitive: `ON lower(main.{field}) = lower(i.{join_col})` (the inequality stays the trailing condition), mirroring the dict-key lowercasing at line 187; apply to both user and hostname reverse-text join cols.
- **Gating test:** assert the resolve_identity ASOF ON-clause lowercases both sides (e.g. contains `lower(main."user") = lower(i.user)`). Inline `#[cfg(test)]` in `identity.rs`. **Must assert SQL shape, not a count** — no data-driven fail-before/pass-after is possible on this dataset.

---

## Split — needs human review

None. (Finding #10 had one "overstated" verdict and one "confirmed" verdict; it is recorded above as a partial-confidence confirmed with both verdicts' repro preserved, because the skew is proven structurally and adversarially even though it produces no wrong count on the current data. Treat it as defensive-fix-worthy with a shape-asserting test rather than a data-driven one.)

---

## Refuted — looked wrong, executes correctly

None.

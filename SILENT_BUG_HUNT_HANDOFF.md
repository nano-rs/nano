# Silent Correctness Bug Hunt — Handoff & Methodology

> Spun out of a session (2026-05-30) where a one-line "rule won't parse" complaint
> peeled back **four** distinct pre-existing bugs (NAN-1157/1158/1159), all of which
> had been silently broken for **months**. This documents the *class* of bug and a
> repeatable method to hunt the rest.

## The bug class: "silent correctness failures"

Not crashes. Not panics. Not compile errors. These **compile clean, run without
exceptions, and return a plausible-but-wrong answer** — usually **empty / zero /
default**. They survive for months because:

- **The failure looks like a non-event.** A detection rule that never matches looks
  identical to a rule with no true positives. A `total_count: 0` looks like "no data."
  Empty enrichment looks like "not enriched yet." Nobody files a bug for *absence*.
- **Errors are swallowed.** The real cause is logged as a `WARN` (or `{}` instead of
  `{:#}` so the root cause is hidden), or a fallback returns `0`/`None`/`default`.
- **Tests assert the wrong layer.** Unit tests check that generated SQL *strings* look
  right, or run against mock data — but never *execute* the query against real data and
  verify a non-zero result. The bug lives in the gap between "looks correct" and "is correct."

This session's four, by sub-pattern:

| Bug | Sub-pattern |
|---|---|
| nPL string ending in `\` broke parsing | **Escape-semantics edge case** — `\"` read as escaped quote |
| `iLike` ate literal backslashes → 0 matches | **Multi-layer escaping** — string-literal layer ✗ LIKE-escape layer |
| ...and 4 call sites **inlined** the escape helper instead of calling it | **Divergent duplication** — fix the fn, miss the copies |
| `build_count_query` regex broke on CTE → `total_count` silently 0 | **Regex parsing of structured text** (SQL) |
| `JSONExtractKeys(ext)` on a now-`JSON`-typed column → Code 43 (caught only as WARN) | **Schema drift / type assumption** |
| `fetch_one::<i64>()` on a `UInt64` CH result | **Type contract mismatch at a boundary** |
| (earlier) enrichment column in some lists but not others | **Parallel lists that must stay in sync** |
| (earlier) `VECTOR_AUTH_TOKEN`/netpol wired in vector pod but not api pod | **Incomplete cross-cut wiring** |

## The discovery method that actually worked

**Execute end-to-end against real data and compare counts at every layer.** The
backslash bug was *invisible* in code review and unit tests — it only revealed itself
when we ran the query against ~2M real rows and got **0** despite 552k matching rows
existing. The technique:

1. Pick a code path that **filters / matches / counts / transforms** a value.
2. Construct an input that **should** hit known data (e.g. a Windows path that 552k rows contain).
3. Trace the value through **every layer** and check the output at each:
   - nPL parse → AST value (is the literal preserved?)
   - AST → generated SQL (`/api/search/explain`) — count escapes/backslashes precisely (use `hex()` / `repr()`, not eyeballing)
   - generated SQL run **directly against CH** (`curl … :8123`) — does it match?
   - executed-via-service (`system.query_log` shows the *actual* SQL the driver sent) — same as explain?
   - service response — does the count/rows match the direct CH run?
4. **Any layer where the count drops to 0/wrong is the bug.** We found bugs at the parse
   layer, the SQL-gen escape layer, *and* the count-companion layer this way.

Ground-truth tools that cut through escaping confusion:
- `hex(col)` / `unhex('…')` in CH to see/inject exact bytes (backslash = `5C`).
- `system.query_log WHERE type='QueryStart'` to see what the driver *actually* sent (vs explain).
- `position(col, literal)` for an escape-free substring baseline to confirm data exists.

## Hunt list for the scan (prioritized)

**P0 — silent-empty error handling** (most likely to hide month-old bugs):
- `grep -rn "unwrap_or(0\|unwrap_or_default\|unwrap_or(String::new\|\.ok()\b\|= 0;" ` in query/search/detection/enrichment paths — anywhere an error/None collapses to a benign default that masks failure.
- `Err(e) => { warn!/debug! … None/0/Vec::new() }` — swallowed errors. Bonus: any `warn!("…: {}", e)` (vs `{:#}`) hides the anyhow root cause.
- Detection/alerting count paths: does match-counting come from a path that can silently 0 out? (Detection here uses `sample_events.len()`, *not* `total_count` — verify analogous code does too.)

**P1 — multi-layer escaping**:
- Every `iLike`/`LIKE`/`match(`/regex/JSON construction. Verify each literal value is escaped for **both** the SQL-string layer **and** the pattern layer. Hunt duplicated `.replace('%', …).replace('_', …)` chains that should be one helper (divergence risk).
- Anywhere a value crosses string↔SQL↔LIKE↔regex↔JSON↔shell. Test with values containing `\ % _ ' " ?` and non-ASCII.

**P1 — regex/string parsing of structured text**:
- `Regex::new(…).captures(sql)` / string-splitting SQL or nPL. These break on nesting (CTEs, subqueries, parens). `grep -rn "Regex::new" ` over the SQL-gen/executor and check each against a multi-stage CTE input.

**P2 — type/schema contracts at boundaries**:
- CH `fetch_one::<T>()` / `fetch::<T>()` where the SELECT type may not be `T` (UInt64 vs i64, Nullable, JSON vs String). `grep -rn "fetch_one::<\|fetch::<" `.
- Columns whose CH type evolved (e.g. `ext` String→`JSON`): grep for `JSONExtract*`, `ext != ''`, string ops on columns that are now native JSON.

**P2 — parallel lists / cross-cut wiring**:
- Lists that must stay in sync (e.g. `EXPLICIT_COLUMNS` / `MATERIALIZED_COLUMNS` / table_view struct / frontend `udm-fields`). A column in one but not all = half-broken feature. (See `project_materialized_enrichment_column_plumbing` memory.)
- Env/secret/netpol provisioned for one pod/repo but not the consumer (see `project_push_enrichment_cross_repo_provisioning`).

## How to run the scan
1. Don't trust unit tests that assert generated strings — for the top ~10 filter/count/transform
   paths, **write a throwaway test or curl that runs the query against the local CH (~2M rows)
   and asserts a non-zero / known count**. The local stack (`:8123` creds in docker-compose,
   `:3002` search w/ `X-API-Key`, `/api/search/explain`) is the lab.
2. For each P0/P1 grep hit, ask: *"if this silently returned empty/0/default, who would notice?"*
   If the answer is "nobody, for months" — it's a candidate; verify it end-to-end.
3. Prefer **adversarial inputs**: backslashes, trailing separators, `%`/`_`, embedded quotes,
   CTE/multi-stage queries, JSON-typed columns, empty/Null, very large counts (UInt64 range).

The meta-lesson: **these bugs are found by running, not reading.** Read to find candidates;
execute against real data to confirm. The ones that went months are exactly the ones where
"compiles + no error + plausible output" was mistaken for "correct."

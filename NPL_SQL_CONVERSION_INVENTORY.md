# nPL → SQL Conversion — Inventory & Audit Reference

> Working reference for the conversion-quality audit. The **conversion** = turning an nPL
> (nano Pipe Language) query string into ClickHouse SQL. Pipeline:
> **nPL string → Parse → AST → (Validate) → ClickHouse SQL → execute**.
> Public facade: `nanosiem-core/src/query/mod.rs`.
> Entrypoints: `parse_query()` (parser.rs) and `ClickHouseSqlGenerator::generate()/generate_with_options()` (clickhouse_sql_gen.rs).

---

## 1. Pipeline files (the conversion itself)

### Stage 1 — Parse (nPL text → AST), nom combinators
| File | Role |
|---|---|
| `nanosiem-core/src/query/parser.rs` | Entry `parse_query()` (~L214); comment/time-modifier stripping; nesting (MAX 50) & pipe-depth (MAX 25) guards |
| `nanosiem-core/src/query/parser/error.rs` | `ParseError`, nom-error conversion, position tracking, Levenshtein typo suggestions |
| `nanosiem-core/src/query/parser/search_expr.rs` | AND/OR/NOT, field/regex/keyword/IN/CIDR/subsearch filters, grouped exprs |
| `nanosiem-core/src/query/parser/eval_expr.rs` | `eval` + inline filter expressions; arithmetic/logical/comparison/fn-calls |
| `nanosiem-core/src/query/parser/values.rs` | Primitives: quoted/unquoted strings, IP/number/bool/interval literals, field names, comparators |
| `nanosiem-core/src/query/parser/commands_core.rs` | stats, chart, streamstats, where, search, sort, head/tail, timechart, table, rename, lookup, output |
| `nanosiem-core/src/query/parser/commands_extended.rs` | dedup, bin/bucket, rex, fields, top, rare, transaction, fillnull, mvexpand, spath, append, join, format, return |
| `nanosiem-core/src/query/parser/commands_security.rs` | risk, prevalence, sample, reverse, eventstats, sequence, funnel, anomaly, inputlookup, lateral |
| `nanosiem-core/src/query/parser/commands_enrichment.rs` | tree, resolve_identity, asset, cloud, ai |

### Stage 2 — AST (the IR)
| File | Role |
|---|---|
| `nanosiem-core/src/query/ast/mod.rs` | Re-exports all AST submodules |
| `nanosiem-core/src/query/ast/types.rs` | `Query`, `SearchExpr`, `Comparator`, `Value`, `BinSpan`, `WindowType`, `IntervalUnit` |
| `nanosiem-core/src/query/ast/commands.rs` | `Command` enum (30+ variants) + command types |
| `nanosiem-core/src/query/ast/aggregation.rs` | `Aggregation` + `AggFunc` (Count, Dc, Sum, Avg, Min/Max, Values, List, Percentile, Sparkline…) |
| `nanosiem-core/src/query/ast/eval.rs` | `EvalExpression`, `BinaryOperator`, `RiskScoreExpr`, `EvalAssignment`, `TableField`, `SortField` |
| `nanosiem-core/src/query/ast/lateral.rs` | `LateralSeedType`, `LateralMethod` |
| `nanosiem-core/src/query/ast/prevalence.rs` | `PrevalenceField/Operator/Threshold/TimeWindow`, `PrevalenceCondition` |

### Stage 3 — Validate (semantic/cost over AST)
| File | Role |
|---|---|
| `nanosiem-core/src/query/validation/mod.rs` | Facade |
| `nanosiem-core/src/query/validation/field_validation.rs` | UDM field-name validation + alias resolution + Levenshtein typo detection |
| `nanosiem-core/src/query/validation/derived_fields.rs` | Tracks pipeline-produced field names so downstream refs validate |
| `nanosiem-core/src/query/validation/query_checks.rs` | `contains_aggregation`, `contains_join`, `pre_aggregation_subquery` (real-time eligibility) |
| `nanosiem-core/src/query/validation/cost_analysis.rs` | Anti-pattern warnings + 0–100 cost score |

### Stage 4 — SQL generation (AST → ClickHouse SQL) — **PRIMARY AUDIT TARGET**
| File | LoC | Role |
|---|---:|---|
| `nanosiem-core/src/query/clickhouse_sql_gen.rs` | 1649 | Entry `generate()`/`generate_with_options()` (~L605); PREWHERE extraction; `EXPLICIT_COLUMNS`; CTE assembly; `QueryOptions`/`GeneratorContext` |
| `nanosiem-core/src/query/clickhouse_sql_gen/search_expr.rs` | 1351 | SearchExpr → WHERE/PREWHERE; UDM vs JSON filters; wildcard/regex (iLike vs hasToken); IN-list/subsearch |
| `nanosiem-core/src/query/clickhouse_sql_gen/eval_functions.rs` | 1303 | 100+ eval fns (cidr_match, defang, base64_decode, md5, date, math, regex) → CH SQL |
| `nanosiem-core/src/query/clickhouse_sql_gen/commands.rs` | 954 | Per-command dispatch: head/tail/sort/where/eval/table/fields/return/rename/mvexpand; `available_columns` tracking |
| `nanosiem-core/src/query/clickhouse_sql_gen/commands_advanced.rs` | 906 | streamstats/eventstats window fns, sequence/funnel correlation, anomaly, tree, asset/cloud, risk |
| `nanosiem-core/src/query/clickhouse_sql_gen/helpers.rs` | 963 | Field normalization/escaping, type detection, regex/wildcard/LIKE conversion, identifier quoting, regex-optimization analysis |
| `nanosiem-core/src/query/clickhouse_sql_gen/field_analysis.rs` | 692 | Field-requirement analysis (column pruning, table_view mode), aggregation detection |
| `nanosiem-core/src/query/clickhouse_sql_gen/aggregation.rs` | 400 | stats/timechart GROUP BY codegen; groupArray/uniqExact/quantile; time bucketing; sparkline |
| `nanosiem-core/src/query/clickhouse_sql_gen/identity.rs` | 256 | resolve_identity via ASOF JOIN to identity dicts (priority fills) |

### Call sites / orchestration
| File | Role |
|---|---|
| `nanosiem-core/src/query/mod.rs` | Public facade (re-exports) |
| `nanosiem-core/src/search/service/core_search.rs` | Primary: `search()` → `parse_query()` (~L386) → `generate()/generate_with_options()` (~L655-665) |
| `nanosiem-core/src/search/service/sql_execution.rs` | `explain()` (~L67) → parse (~L80) → generate (~L123-128); returns SQL without executing |
| `nanosiem-core/src/search/service/histogram.rs` | Time-bucketed histogram SQL |
| `nanosiem-core/src/search/service/field_queries.rs` | Field stats/values (cardinality/topK) |
| `nanosiem-core/src/search/service/streaming.rs` | SSE incremental streaming SQL |
| `nanosiem-core/src/search/query_processing/command_extraction.rs` | Extracts prevalence/lookup/AI/asset commands for routing |
| `nanosiem-search/src/handlers/search.rs` | HTTP `POST /api/search` + `/api/search/explain` |
| `nanosiem-api/src/handlers/search.rs` | `/api/search/explain` on API tier + saved-search |
| `nanosiem-core/src/detection/service/execution.rs` | Scheduled rules: parse rule nPL → SearchService.search() |
| `nanosiem-core/src/detection/materialized_view.rs` | Real-time: SearchExpr AST → `CREATE MATERIALIZED VIEW` WHERE clause |

### Parallel / not on the CH path (context only)
- `nanosiem-core/src/query/sql_gen.rs` + `sql_gen/` (3669 LoC) — **PostgreSQL** backend (same AST, different DB).
- `nanosiem-core/src/query/pretty_print/` — AST → query string (inverse direction).
- `nanosiem-core/src/rule_repository/npl_parser.rs` — separate parser for Sigma/external rule import (not the search path).

---

## 2. Test inventory (changes must keep these green)

### Unit (`nanosiem-core/src/query/tests/clickhouse_sql_gen_tests/`)
| File | #tests | Covers |
|---|---:|---|
| `integration.rs` | 35 | end-to-end pipeline → SQL |
| `field_pruning.rs` | 18 | column pruning / table_view |
| `search_expressions.rs` | 15 | SearchExpr → WHERE/PREWHERE |
| `command_sql.rs` | 13 | per-command SQL |
| `time_bucket.rs` | 6 | timechart bucketing |
| `json_extract.rs` | 4 | JSON/ext field access |
| `helpers.rs` | 4 | escaping/quoting/regex |
| `sql_syntax_validation.rs` | 4 | generated SQL parses/valid |
| `full_query.rs` | 2 | full assembly |

### Crate-level integration (`nanosiem-core/tests/`)
| File | #tests | Covers |
|---|---:|---|
| `docs_query_tests.rs` | 612 | every documented nPL example round-trips |
| `npl_compat_tests.rs` | 461 | Splunk/nPL compatibility surface |
| `pipeline_command_tests.rs` | 40 | multi-command pipelines |

> Baseline run target: `cargo test -p nanosiem-core query` and the three `tests/*.rs` integration suites.

---

## 3. Audit checklist (what "best conversion" means here)

### A. Correctness (highest priority — silent wrong results)
- **Alias shadowing** — `SELECT toX(col) AS col … WHERE col = ?` substitutes the expression into WHERE (Code 53). Use a distinct alias. *(NAN-1034)*
- **DateTime64 vs raw-int compare** — comparing a `DateTime64(…)` column to a raw int coerces the int as **seconds** (far-future); wrap ms with `fromUnixTimestamp64Milli`. *(NAN-1123)*
- **`lower()` consistency** — if PREWHERE uses `lower(x)`, WHERE/equality on the same field must too; `_search` columns are already lowered.
- Type detection: IPs, numbers, bools must map to the right CH function/literal; quoting/escaping must prevent injection AND not over-escape.
- Subsearch / IN-list semantics; NULL handling; empty-string vs NULL on UDM columns.

### B. ClickHouse performance / optimization
- **PREWHERE** — time bounds + indexed/low-card fields belong in PREWHERE, not WHERE.
- **`_search` columns + `hasToken()`** — full-text should hit the materialized `*_search` column + bloom filter via `hasToken`, not `iLike('%…%')` where a token search suffices.
- **No `JSONExtract` on explicit UDM columns** — direct column access only; `ext`/JSON path is for non-UDM only.
- **Partition pruning** — always a `timestamp` bound; daily partitions.
- **Field pruning** — `table_view` returns minimal columns; SELECT only required columns (esp. avoid pulling `message`/`ext` when unused).
- **Result limits** — default 100k guard present.
- **Redundant work** — watch for the parallel `count(*)` companion on fetch paths *(NAN-1032)*; unnecessary subqueries/CTEs; repeated expression evaluation.
- **Skip indexes** — current index state is in `clickhouse/init.sql` + migrations **118 (drop ext text index), 119 (splitbynonalpha), 120 (drop dead tokenbf)**. Do NOT assume an index exists/doesn't — read current schema. **Bloom filters on uniform-random columns can still prune 97%+; EXPLAIN/measure before asserting a perf win.** *(NAN-1035)*

### C. Idiomaticity / modern ClickHouse
- Use native aggregate combinators (`uniqExact`, `quantile`, `groupArray`, `-If`/`-Array` combinators) over hand-rolled equivalents.
- ASOF JOIN for identity/time-aligned lookups; dictionaries (`dictGet`) over JOINs where a dict exists.
- Avoid illegal nested aggregation *(NAN-1120)*.

### D. Test coverage of each conversion
- Does a test pin the generated SQL (or its result) for this conversion? An untested conversion that's also `BAD` is top priority.
- Static template VRL/SQL strings need compile/parse regression tests *(NAN-667)*.

---

## 4. Verdict scale (final report)
- **GOOD** — already optimal / idiomatic / correct; no change.
- **GOOD, NOT WORTH CHANGING** — works correctly; a theoretically nicer form exists but the win is marginal, risk/churn outweighs it, or it needs measurement that isn't justified.
- **BAD** — incorrect, materially slow, or non-idiomatic in a way worth fixing. Must include: concrete fix, the gating test(s) that would prove it, and whether EXPLAIN/measurement on real data is required before committing.

> Perf claims are **hypotheses until measured**. Mark `needs_measurement: true` rather than asserting a speedup. The user owns Saturn (read-only EXPLAIN is fine) for empirical validation.

# Handoff — OCSF/nPL query codegen hardening

**Date:** 2026-06-09
**Parent epic:** NAN-1339 (nPL native-OCSF query codegen failures)
**Active backlog:** NAN-1346 (remaining command clusters)
**Local main HEAD at handoff:** `66753391` (= origin/main, 0 ahead / 0 behind)

---

## Goal / framing

Validate that nPL queries a SIEM-migrating user would type work under the **OCSF**
SchemaProfile, and bring OCSF to parity with UDM **without breaking the UDM path**
(the founding constraint of the OCSF work). Methodology: run a native-OCSF query
corpus against the live OCSF search stack, bucket failures into
**guardrail (by-design) / codegen bug / parse gap / env-data**, fix the real bugs.

Guiding principle from the user: *"this user ran it in their previous SIEM like this, so it should
work here."* Guardrails (refusing unbounded `dedup`/`streamstats`/`values`/high-card
group-by / 6h asset-cloud caps) are **intentional**, not bugs.

---

## Current state (after this session)

Native-OCSF corpus (`scripts/test-ocsf-queries.py`, native-first): **87 pass / 41 fail /
16 empty of 144** (was 74 pass at session start).

Of the 41 failures:
- **21 guardrails** — working as designed, NOT bugs.
- **16 codegen bugs** — the NAN-1346 backlog below.
- **1 env/data** (missing lookup tables), **3 other** (lateral OCSF-awareness ×2, `ai` no backend).

103/144 execute cleanly (87 pass + 16 empty). nPL **parsing is solid end-to-end**;
what remains is codegen.

---

## Shipped this session — 8 PRs (all merged, all on main)

| PR | Issue | Fix | Profile |
|----|-------|-----|---------|
| #2036 | NAN-1339 | `rename`/`rex`/`spath` output cols register as computed (CTE projection) — `collect_computed_from_command` in `field_analysis.rs` | both |
| #2039 | NAN-1340 | `rex (?P<name>)` captures (`extract_named_groups`/`convert_named_groups_to_numbered` accept optional `P`) + `tostring(x,"%H")` honors strftime fmt | both |
| #2041 | NAN-1342 | **pretty-printer round-trip** — `transaction`/`funnel`/`anomaly`/`tree` formatters emitted nPL their own parser rejected; `enforce_non_audit_query` re-parses every query so this 400'd them for ALL users | both |
| #2043 | NAN-1343 | `spath input=ext` → OCSF `event` tail; added `SchemaProfile::json_tail_column()` (UDM `ext` / OCSF `event`) | both |
| #2045 | NAN-1344 | `chart over X by Y` leaked literal `by` as a group field; added `by`/`over` to `is_field_list_stop_keyword` | both |
| #2047 | NAN-1345 | `anomaly sum(bytes_in)` now resolves inner field via `by_field_sql` (was raw → Code 47 under OCSF) | both |
| #2049 | NAN-1346 #1 | `sequence` step captures resolve via `by_field_sql` (2 sites in `generate_sequence_sql`) — `action`→`activity` | both |
| #2050 | NAN-1346 #2 | `funnel` dropper argMax columns declared required so field-pruning keeps them in stage_0 | both |

**UDM safety: VERIFIED, not assumed.** Generated UDM-profile SQL for a representative
query from every fix and executed against `nanosiem.logs` (~2M rows). All resolve
byte-identically under UDM (`ext`→`ext`, `bytes_in`→`bytes_in`, `action`→`action`);
parser/pretty-print fixes are schema-agnostic.

---

## Remaining work — NAN-1346 (Backlog), 16 codegen bugs

> **Profile note:** items 4, 6, and tree-codegen in 5 are **profile-independent** —
> they fail identically on UDM and OCSF (the pretty-print fix made them *parse*, exposing
> pre-existing codegen bugs). Not regressions.

### 3. subsearch `append` — dotted col not projected + UNION arity
`… | append [search * | stats … by dst_endpoint.ip]` → Code 47 (`dst_endpoint.ip`
unknown in subsearch scope) + Code 53 (UNION different column counts). Append semantics pad
missing cols with NULL. **Fix:** route subsearch stats `by` fields through the same
projection / CTE re-add path as the main query; pad UNION columns to a common set.

### 4. subsearch `join` — Code 48 correlated subqueries not supported in JOINs (HARDEST)
`… | join type=left user.name [search …]`. ClickHouse rejects correlated subqueries in
JOIN. **Needs a join-strategy rewrite**: materialize the subsearch as an independent CTE
keyed on the join field, then `LEFT JOIN … USING`. Design first. Profile-independent.

### 5. enrichment commands under OCSF
- **resolve-identity**: emits prefixed `user_identity_department`; corpus uses bare
  `identity_department`. Reconcile output naming (relates to NAN-1341 shadowing).
  `identity.rs` `IDENTITY_COLUMN_FIELDS` / `resolve_identity_entity_prefix`.
- **asset**: `asset_criticality` not emitted by the dossier command → `where
  asset_criticality` 500s. Decide asset-view output schema.
- **tree presets**: `parent_process_guid`/`process_guid` are UDM process-lineage cols
  with no OCSF promoted equivalent — needs an OCSF process-lineage mapping (or graceful
  degradation). `parser/commands_enrichment.rs` tree presets ~line 40.
- **tree `… by X` / `depth=N` codegen** (profile-independent): positional `tree <field>
  by …` emits malformed SQL → Code 62. `by`/`depth` are parsed-then-discarded (not in the
  AST). Fix tree's positional-form codegen.

### 6. transaction `startswith=`/`endswith=` codegen (profile-independent, NEW)
`transaction user startswith="login" endswith="logout" maxspan=8h` now parses but the
transaction SQL gen errors at execution (both schemas). Simple form (`transaction user
maxspan=1h`) works. Investigate the startswith/endswith branch of the transaction
generator in `commands_advanced.rs` / `commands.rs`.

---

## Related filed issues (not yet started)
- **NAN-1341** — a computed field (rex capture / eval) whose name normalizes to a UDM
  alias (`method`→`http_method`) is shadowed by schema resolution in `stats … by`.
  `by_field_sql` (helpers.rs ~247) checks `resolves_to_column` before `is_computed_field`.
  Makes the rex `by method` case fully correct.
- **NAN-1336** — pre-existing `stats by src_endpoint.ip` fixture test (OCSF integration).

---

## How to validate (recipes)

**Run the native tester** (needs the OCSF search stack up on :3002):
```bash
# the native-first tester lives on branch chore/ocsf-tester-native-first (NOT merged to main)
git show chore/ocsf-tester-native-first:scripts/test-ocsf-queries.py > /tmp/test-ocsf-native.py
cp scripts/test-advanced-queries.py /tmp/test-advanced-queries.py   # sibling corpus it imports
API_KEY=-PopdJxnG9EY1P71Vt6XTcpuWOSLg6IJ8BZTwLKzY7Y NANO_DAYS=40 \
  python3 /tmp/test-ocsf-native.py --execute --json    # writes /tmp/ocsf-query-results.json
```

**Harvest the REAL error** behind a generic "Internal server error" — read `logs/search.log`
after running the query (the API masks the ClickHouse error; the log has the `Code: NN
DB::Exception` + the generated SQL echo). The pretty-print round-trip (`enforce_non_audit_query`)
echoes the re-rendered query — that's how the pretty-printer bug was found.

**Generate SQL for a query via the generator** (no DB), then run against local CH:
```rust
// throwaway integration test in nanosiem-core/tests/zz_*.rs
let g = ClickHouseSqlGenerator::with_table("nanosiem.ocsf_logs".into())
        .with_profile(Arc::new(OcsfProfile::new()));   // or UdmProfile + nanosiem.logs
std::fs::write("/tmp/x.sql", g.generate(&parse_query(q).unwrap(), &tr).unwrap()).unwrap();
```
```bash
# local CH :8123, creds in docker-compose.yml (user nanosiem). Tables: nanosiem.logs (UDM ~2M),
# nanosiem.ocsf_logs (OCSF). POST raw SQL via --data-binary (NOT query=).
PASS=$(grep -A40 "clickhouse:" docker-compose.yml | grep -m1 CLICKHOUSE_PASSWORD | sed 's/.*: *//;s/["'"'"']//g')
curl -s "http://localhost:8123/" --user "nanosiem:$PASS" --data-binary @/tmp/x.sql
```

**UDM-safety check** (do this for every profile-touching fix): generate the same query
under `UdmProfile` against `nanosiem.logs` and confirm it executes + the resolution is
byte-identical to the old behavior.

---

## Key gotchas / learnings (this codebase)

- **Every search round-trips through the pretty-printer.** `enforce_non_audit_query`
  (search/query_processing/query_manipulation.rs:181) parses → injects `source_type!=audit`
  → `.pretty_print()` → re-parses. A lossy formatter 400s the whole query. Always add a
  `parse → pretty_print → parse` AST-equality round-trip test for command formatter changes.
- **`field_to_sql_expr` vs `by_field_sql`** (helpers.rs): the former checks `is_computed_field`
  FIRST; the latter checks `resolves_to_column` first (NAN-1341 precedence bug lives here).
  Command SQL-gen that references fields must route through one of these, not raw
  `escape_identifier`, or OCSF UDM-named fields 500.
- **Field pruning drops "hidden" columns.** Commands that argMax/capture columns not in the
  query text (funnel droppers, sequence captures) must declare them in
  `analyze_required_fields` or they're pruned from stage_0.
- **OCSF JSON tail is `event`; UDM is `ext`.** Use `profile.json_tail_column()`.
- **The in-tree pretty_print test module is DEAD** (`#[cfg(any())]` in
  `pretty_print/mod.rs:13`, stale since #519 — references removed AST fields). New
  pretty-print tests go in `nanosiem-core/tests/npl_pretty_roundtrip.rs` (public API).
- **`clickhouse_sql_gen_tests/` dir is orphaned** (never compiles). Don't rely on its
  assertions; OCSF SQL-gen regression tests live in `nanosiem-core/tests/ocsf_query_integration.rs`.
- **Cargo.lock churns** the workspace version on local builds — `git checkout Cargo.lock`
  before each commit.
- **Ship rhythm:** worktree per fix → fix + regression test → local-CH validate →
  /code-review → squash-merge (`Fixes NAN-XXXX` for single-issue, `Refs` for the NAN-1339
  epic so it stays open) → pull main → `git worktree remove`.

---

## Session 2 update (2026-06-09, same day)

Shipped 4 more PRs (all `Refs NAN-1346` / `Refs NAN-1339`):

| PR | Item | Fix |
|----|------|-----|
| #2052 | NAN-1346 #3 | append: name-aligned NULL-padded UNION (`OutputShape` model), subsearch base select = stage_0 clause, double-LIMIT fix, Variant ORDER BY opt-in |
| #2053 | NAN-1346 #6 | transaction startswith/endswith: marker-bounded sessionization via layered windows (markers were parsed-then-discarded — silent wrong output, not an execution error) |
| #2054 | NAN-1346 #4 | join: `LIMIT max BY keys` replaces the ROW_NUMBER window (Code 48 was the window's ORDER BY timestamp resolving from the outer scope on aggregated subs), empty-key eviction, bare-name sub projection (fixes chained joins Code 403 + downstream `where` Code 386) |
| (branch `fix/NAN-1346-tree-positional`) | NAN-1346 #5 (tree codegen bullet) | parent-less positional `tree <field>` refuses with usage guidance instead of emitting `SELECT *, ,` (Code 62) |

New reusable machinery: `OutputShape` / `pipeline_output_shape` in clickhouse_sql_gen.rs —
statically tracks a pipeline prefix's output projection (Wide/Columns/Unknown). Used by
append alignment, join sub projection + rn ordering. Conservative: unmodeled commands →
Unknown → actionable refusal.

**Item 5 decisions made by the user (2026-06-09 evening) and shipped:**
| PR | Decision |
|----|----------|
| #2055 | parent-less positional `tree <field>` refuses with usage guidance (Code 62 fixed) |
| #2056 | tree OCSF lineage: manifest maps `parent_process_guid` → `actor.process.uid`; tree projections resolve via profile, alias back to nPL names |
| #2057 | identity: prefixed columns canonical; bare `identity_*` aliases emitted+registered when exactly ONE resolve_identity |
| #2058 | asset is terminal: commands piped after it refuse with guidance (criticality column deferred to an asset-inventory feature) |
| #2059 | bonus: OCSF reverse identity lookups no longer qualify JSONExtract exprs as `main.JSONExtract…` (Code 46) |

**EVERYTHING IS DONE — NAN-1339, NAN-1346, and NAN-1348 all closed (2026-06-09 night).**
Late wave: #2061 dest_user mapping, #2062 guardrail messages reach the client (the API was
masking SqlGenError InvalidQuery/UnsupportedOperation as "Query processing failed"), #2063
{func}_{field} agg references resolve reference-side, #2064 table/fields wildcards (plain
`table src_*` was broken at execution all along), #2066 lateral seeds span class-split
unified columns. Item H closed as not-reproducible on CH 26.4 (verified direct + live API).
Final corpus: 97/144 pass (from 74), 114/144 execute cleanly; ZERO silent failures remain — every residual either refuses with actionable guidance or needs dev-env data (lookup tables, ai backend).

**Vendor-name rule (IMPORTANT):** never write "Splunk" in code/tests/commits/PRs/Linear/docs —
describe behavior neutrally. One immutable mention remains in #2052's squash commit body.

**Pre-existing failures observed on main (not from this work):**
`ocsf_byfield_resolution::ocsf_user_maps_to_user_name` (stale NAN-1337 expectation: `user`
now → `user_unified`) and the `--ignored` `ocsf_npl_queries_execute_against_fixtures`
(fixture stats-by returns empty on local CH 26.4 — env drift, fails identically on main).

To re-run the corpus end-to-end, the local search service must be REBUILT first (it runs a
stale `./target/debug/nanosiem-search`); per-fix validation was done directly against local CH.

## Suggested next step
Start with **item 3 (append)** or **item 6 (transaction codegen)** — both tractable and
self-contained. Save **item 4 (join correlated-subquery rewrite)** for a design pass; it's
the biggest. The enrichment items (5) need product decisions on output schema.

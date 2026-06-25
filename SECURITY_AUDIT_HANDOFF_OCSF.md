# Security audit handoff — OCSF work since Friday (2026-06-05 → 06-09)

**Goal:** confirm the OCSF push didn't introduce or regress a **SQL injection / query-safety**
issue (the primary concern), and do a general security pass over the rest. The work was all
code-reviewed PR-by-PR, but no one has looked at it *as a body* through a security lens — that's
this audit.

**How to run it:** this is a `/security-review`-style pass plus targeted manual checks. The
codebase convention is code review per the CLAUDE.md pre-commit rule; here we want one
consolidated adversarial read of the merged diff. Suggested: `git diff ee9c3f6a..d52c5f87`
(the OCSF epic merge-base → current main) scoped to the files below, then the specific
hotspots called out.

---

## Scope — what shipped

**~30 OCSF PRs**, two waves, all merged to `main` (HEAD `d52c5f87`):

- **NAN-1241 epic** (merged Friday, `ee9c3f6a`): the pluggable `SchemaProfile` — OCSF as a
  first-class alternate schema. This is the foundation; everything else patches on top.
- **NAN-1299..1337** (Fri–Mon): profile-aware resolution across the query + search surfaces
  (PREWHERE, entity classification, asset/cloud/prevalence/identity/sequence, class-split
  columns, sort-key perf).
- **NAN-1339 / NAN-1346 / NAN-1348** (Monday night, this session): the command-codegen
  clusters — append, join, transaction, tree, identity, asset, chart-over, wildcards, lateral.

**Primary files to audit (SQL-generation core):**
- `nanosiem-core/src/query/clickhouse_sql_gen.rs` — CTE assembly, append/join SQL, wildcard
  expansion, the new `OutputShape`/`agg_reference_alias` infra
- `nanosiem-core/src/query/clickhouse_sql_gen/commands.rs` — per-command SQL (tree, transaction,
  asset, eval, dedup, sort)
- `nanosiem-core/src/query/clickhouse_sql_gen/identity.rs` — resolve_identity ASOF-join + dict
  lookups (most string-formatting density)
- `nanosiem-core/src/query/clickhouse_sql_gen/aggregation.rs`, `helpers.rs`, `search_expr.rs`,
  `field_analysis.rs`
- `nanosiem-core/src/schema/ocsf.rs`, `udm.rs`, `profile.rs` — the profile resolution
- `nanosiem-core/src/search/service/lateral.rs` — seed detection + bound CH queries
- `nanosiem-search/src/error.rs`, `handlers/search.rs` — error surfacing (changed Monday night)
- `nanosiem-core/docs/ocsf/1.8.0/udm_ocsf_mapping.json` — the manifest (data, drives resolution)

---

## Threat model for this surface

nPL is **user-supplied** (analysts type queries; AI wizards also generate them). It compiles to
ClickHouse SQL via string interpolation — so the core question is: **can a crafted field name,
alias, value, or wildcard reach the generated SQL unescaped?**

Existing defenses (verify they still hold under OCSF):
1. **Values** are parameterized / `escape_string`'d, never interpolated raw.
2. **Field names** route through `escape_identifier` (double-quote + `"`-doubling) and/or
   `validate_field_name_format` (SECURITY-tagged in `field_validation.rs`).
3. **Query validation** — SELECT-only, dangerous-function blocklist (`validate_query_fields`).
4. **Result limits / guardrails** — unbounded-query refusals (dedup/streamstats/values/
   high-card on `*`), subsearch `LIMIT … BY`, the 100k cap.

OCSF added a new wrinkle: **field names now resolve through a profile** (`resolve()` →
`ExplicitColumn` / `JsonPath` / `Unknown`) and OCSF columns are **dotted** (`src_endpoint.ip`),
which forces `escape_identifier` to quote them. The audit's core job: confirm every
profile-resolved column still passes through escaping, and that the manifest (now a resolution
*source*) can't smuggle anything.

---

## Hotspots — look here first

### 1. `escape_identifier` only quotes conditionally (`helpers.rs:887`)
```rust
if name.contains('.') || is_reserved_word(name) || name.contains(' ') {
    format!("\"{}\"", name.replace('"', "\"\""))
} else {
    name.to_string()   // <-- bare, unquoted
}
```
A name without dot/space/reserved-word is emitted **bare**. This is pre-OCSF behavior, but OCSF
widened what flows in. **Check:** can a resolved column or computed alias contain SQL
metacharacters (`(`, `,`, `)`, `;`, `'`) yet miss all three quote-triggers? Resolved columns come
from the fixed manifest (safe), but **computed aliases** (eval/rex/spath/stats output names) are
user-derived — trace whether they're validated before becoming `escape_identifier` input.

### 2. Eval alias is interpolated without `escape_identifier` (`commands.rs:258`)
```rust
select_parts.push(format!("{} AS {}", expr_sql, assignment.field));
```
`assignment.field` (the `eval X = …` target name) goes in raw. **Pre-existing**, not introduced
this session, but it's the single rawest field-name interpolation in the file and the OCSF
computed-field work (`collect_computed_field_names`, the new `agg_reference_alias`) now leans on
these alias names. Confirm the parser constrains eval target names (it likely does via the
identifier grammar) — if so, note it as defense-in-depth-by-grammar; if not, it's a real finding.

### 3. Two wildcard-expansion regexes, one escaped, one not
- `clickhouse_sql_gen.rs:411` `expand_wildcard_pattern` (the older/static one):
  `pattern.replace('*', ".*")` — **no `regex::escape`**. A pattern like `a.b*` becomes a regex
  where `.` is "any char". Low impact (it only ever *matches against a fixed column list*, can't
  reach SQL), but worth noting for ReDoS / over-match.
- `clickhouse_sql_gen.rs:974` `expand_wildcard` (my new computed-aware one): correctly uses
  `regex::escape(pattern).replace("\\*", ".*")`. **Confirm the new one is the path that runs**
  and the old one is dead/fallback only.

### 4. `identity.rs` — densest string-formatting, touched twice Monday night
- The `main.`-qualification fix (#2059): expressions vs columns. Verify the `field_escaped.contains('(')`
  guard can't be fooled into qualifying something injectable, and that `user_expr` (used as a
  `dictGetOrDefault` key) is escaped — it interpolates `field_escaped`.
- The bare-alias emission (#2057): the new `AS {suffix}` aliases come from the fixed
  `IDENTITY_COLUMN_FIELDS` const, not user input — should be clean, confirm.

### 5. `lateral.rs` — bound queries, but check the new seed path
Seed *values* feed CH queries. Confirm they go through binds (`base_binds`, line ~153), not
interpolation. The NAN-1348 change only altered which **result-row key** is read
(`lateral_seed_keys`), not how the value is used downstream — but verify the seed value still
reaches the traversal query as a bind, not a format-arg.

### 6. Error surfacing change (#2062) — information disclosure check
`nanosiem-search/src/error.rs` + `handlers/search.rs` now **un-mask** `SqlGenError` messages
prefixed `Invalid query:` / `Unsupported operation:` to the client (previously all masked as
"Query processing failed"). **Audit:** re-read the full inventory of those messages
(`grep -rn "InvalidQuery\|UnsupportedOperation" nanosiem-core/src/query/`) and confirm **none**
leak table names, column lists, file paths, or internal state — only query-syntax guidance
echoing the user's own input. I audited this when shipping and found it clean, but a second
adversarial read is exactly the point of this pass. The masking of *other* SqlGenError variants
(internal failures) must still hold.

### 7. The manifest as a resolution source (`udm_ocsf_mapping.json`)
`resolve()` now consults `udm_to_column` built from this file. It's checked-in data, not user
input, so not an injection vector — but a wrong/duplicate mapping is a **correctness/authz-shaped**
risk (e.g. a UDM field silently resolving to the wrong physical column could cross a data
boundary). The `dest_user → user.name` entry (#2061) and `parent_process_guid → actor.process.uid`
(#2056) are the two added this session — sanity-check they point where intended.

---

## What I already verified (so you can focus elsewhere)

- **Every codegen fix executed against local CH on BOTH profiles**; UDM SQL proven
  byte-identical via stash-diff wherever a resolution path changed (append, join, tree, identity,
  chart-over, dest_user). So **UDM is not regressed** — the audit can concentrate on the OCSF path
  and the shared infra.
- **Guardrails still fire**: the corpus re-run shows dedup/streamstats/values/high-card/
  transaction-unfiltered all still refused (20 of them). The append `LIMIT … BY`, subsearch caps,
  and empty-key eviction (join) are new bounded-ness, not new unboundedness.
- **No new `Option<DualPool>` / PG-only paths**, no migration edits, no auth changes — the work
  is entirely in query codegen + the search error layer.
- Final corpus: **97/144 pass, zero silent failures** — every residual either passes, returns
  empty, refuses with guidance, or needs dev-env data.

---

## Suggested audit plan (new session)

1. **`/security-review`** over `git diff ee9c3f6a..d52c5f87` scoped to the files above (or
   `/code-review ultra` if you want the multi-agent cloud pass on the same range).
2. **Manual injection probe** — the real test: craft nPL with adversarial field names / aliases /
   wildcards and run `/api/search/explain` (returns SQL without executing — see
   `[[reference_local_api_key]]`, search is :3002, `X-API-Key`). Try:
   - `eval` target names with `(`, `,`, quotes, `) AS x, (SELECT …`
   - rex/spath output names with metacharacters
   - field names that resolve-then-escape oddly under OCSF
   - wildcard patterns with regex metacharacters
   Confirm every one is either rejected by validation or safely quoted in the explained SQL.
3. **Info-disclosure read** of the un-masked error messages (#2062).
4. **Manifest sanity** — the two new `udm_field` mappings resolve where intended.
5. Spot-check hotspots 1–2 (the conditional-quote + raw eval alias) for a concrete bypass; if
   none, document them as grammar-constrained defense-in-depth.

## Key context / gotchas
- `/api/search/explain` generates SQL **without executing** — the injection-test tool of choice.
- Local CH `:8123` (creds in `docker-compose.yml`), `nanosiem.logs` (UDM ~2M) + `nanosiem.ocsf_logs`.
  Generate SQL per-profile via a throwaway `nanosiem-core/tests/zz_*.rs` (see
  `HANDOFF_OCSF_QUERY_CODEGEN.md` recipe) then POST raw via `--data-binary`.
- Memory `[[feedback_never_write_splunk]]` applies to any artifacts this audit produces.
- The OCSF resolution entrypoints: `OcsfProfile::resolve` (`schema/ocsf.rs:497`),
  `field_to_sql_expr` / `by_field_sql` (`helpers.rs`) — every command's field handling funnels
  through these; if escaping is sound there, most of the surface is covered.

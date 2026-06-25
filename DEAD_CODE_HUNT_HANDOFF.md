# Dead-Code Hunt — Handoff & Methodology

> Spun out of a session (2026-05-30) where "can we clean up the dead PG generator?"
> turned out to be the tip of a **fully dead PostgreSQL search backend** — ~5,000 lines
> across a codegen module, an executor, a histogram path, 8 `match` arms, and 4
> zero-caller constructors — plus a *latent wrong-backend bug* in enterprise melod
> (NAN-1162). This documents the *class* of cleanup and a repeatable method to find the rest.
>
> Companion to `SILENT_BUG_HUNT_HANDOFF.md`. That doc hunts wrong *behavior*; this one
> hunts code that does *nothing* — but the discipline is the same: **verify by tracing
> reachability and compiling, not by eyeballing.**

## The target: "dead code that compiles clean"

Not lint noise. Rust's `dead_code` lint only fires on **private** unused items — so the
dangerous dead code is exactly what the compiler stays silent about:

- **`pub` items with zero callers** (functions, methods, constructors, modules). The
  compiler assumes some external crate might use them, so it never warns.
- **Branches behind a selector that's never set** — `match self.backend { ClickHouse => …,
  PostgreSQL => … }` where nothing ever constructs the `PostgreSQL` selector. Each arm
  compiles; one is unreachable.
- **Whole modules that aren't wired in** — a `mod tests {}` left empty means an entire
  `tests/` subdirectory never compiles (so it can rot, and its "coverage" is fictional).
- **Divergent parallel implementations** where only one is live — e.g. a Postgres
  `SqlGenerator` next to the real `ClickHouseSqlGenerator`; both compile, one is wired.
- **Fields constructed but never read** — or read *only* by other dead code (a chain).
- **`#[allow(dead_code)]` / `#[cfg(any())]`** — these are *confessions*. Someone already
  knew it was dead and silenced it instead of removing it.

Why it survives for months/years: it compiles, tests are green (the dead path has no
tests, or its tests are orphaned), and "it might be used somewhere" is never checked.

## The discovery method that actually worked

**Trace reachability from the entry point inward, distinguishing "referenced" from
"reached." The compiler is the final gate.** The PG backend looked alive (a field
constructed in 13 places, 8 `match` arms, a whole codegen dir) and was 100% dead.

1. **Pick a lead.** A type/module you suspect (`SqlGenerator`), an `#[allow(dead_code)]`,
   an empty `mod tests {}`, a "legacy"/"v1"/"old" name, or a config flag (`SearchBackend`).
2. **Separate the shared types from the dead thing.** Before deleting a module, find what
   *else* lives in it that's still used. `sql_gen.rs` held the dead `SqlGenerator` **and**
   the live `TimeRange`/`SqlGenError` (consumed via re-export at 72 sites). Deleting the
   module wholesale would have broken the live generator. Keep the shared types; cut the rest.
3. **Construction ≠ use.** Grep for the type, then for **method calls**, separately. A
   field can be built in every constructor and never called. `pg_executor` was constructed
   13× and used by exactly one method (`execute_postgres_sql`), which was itself dead.
4. **For a branch, trace the *selector's* constructors.** `match self.backend` is only as
   live as the values `self.backend` can take. Find every site that sets it to the dead
   variant, then ask: *are those constructors called?* All 4 `PgPool`-based
   `SearchService::{new,with_config,with_lookup,with_config_and_lookup}` had **0 real
   callers** (the live code uses the `with_dual_pool*` constructors) → the `PostgreSQL`
   arm was unreachable.
5. **Follow the cascade.** Removing the obvious dead thing exposes the next layer. Deleting
   `execute_postgres_sql` made `pg_executor` unused; that made `PostgresExecutor` unused;
   that made `pg_row_to_json` unused; the PG histogram arm made `calculate_histogram_interval`
   unused. **Re-grep after every removal** until the surface is stable.
6. **Compile as the gate — every crate, including feature-gated ones.** `cargo build`
   private-dead warnings catch the cascade; a clean build + an empty confirmation grep is
   the proof. ⚠️ Build `--features enterprise` (and the crates that own that feature) — the
   merge gate builds open-edition only, so enterprise can be red on green main.

### Ground-truth commands that cut through "is it actually used?"

```bash
# 1. All references to a symbol (the noisy view)
grep -rn "SqlGenerator\b" --include='*.rs' nanosiem-core nanosiem-api nanosiem-search nanosiem-enterprise | grep -v "ClickHouseSqlGenerator"

# 2. CONSTRUCTION vs CALL — the distinction that matters
grep -rn "SqlGenerator::new\|: SqlGenerator" ...   # constructed here
grep -rn "\.generate(\|pg_sql_generator\." ...      # actually called here?

# 3. THE CONTINUATION-LINE TRAP (this one nearly fooled me):
#    `self.pg_sql_generator\n    .generate(...)` — the method call is on the NEXT line,
#    so `grep "pg_sql_generator\."` returns NOTHING and the field looks unused.
#    Always also grep the bare field name and read the few hits, or grep multi-line:
grep -rnA1 "pg_sql_generator" ...        # -A1 shows the continuation
rg -U "pg_sql_generator\s*\.\s*\n?\s*generate" ...   # ripgrep multiline

# 4. Is a constructor/method dead? Count callers excluding its own definition:
grep -rn "SearchService::new\b" --include='*.rs' . | grep -v "fn new"
#    BEWARE false positives: "SearchService::new" matched "CaseSavedSearchService::new"
#    as a substring. Read the hits; don't trust the count alone.

# 5. Orphaned test trees (fictional coverage):
grep -rn "mod tests {}\|cfg(any())\|#\[ignore\]" --include='*.rs' .

# 6. Confessions of dead code:
grep -rn "allow(dead_code)\|allow(unused)\|TODO: remove\|deprecated\|legacy\|_v1\|_old\b" --include='*.rs' .

# 7. Final proof after removal — must be empty:
grep -rn "execute_postgres_sql\|pg_sql_generator\|SearchBackend::PostgreSQL" nanosiem-core/src nanosiem-enterprise/src
cargo build -p nanosiem-core --tests && cargo build -p nanosiem-api --features enterprise
```

## Hunt list for the scan (prioritized)

**P0 — never-selected branches & zero-caller `pub` constructors** (highest yield, what
NAN-1162 was):
- Config/backend/mode enums matched across the code: find the enum, find every
  `match self.<field>` / `if self.<field> == Variant`, then trace whether the dead variant
  is ever *constructed by a reachable path*. Post-NAN-800, anything PG-only-shaped is suspect.
- `pub fn new*/with_*` constructors that take a legacy arg shape (e.g. a raw `PgPool`
  vs the current `&DualPool`). Count real callers.
- Repository/service methods (`*Repository`, `*Service`) — grep each method name for callers;
  SIEM repos accrete query helpers that nothing calls anymore.

**P1 — orphaned / disabled / divergent**:
- `mod tests {}` empties and `#[cfg(any())]` modules — entire trees that don't compile
  (known: `src/query/tests/` had an orphaned `sql_gen_tests.rs`; `clickhouse_sql_gen_tests/`
  is also orphaned per project memory). Either wire them up or delete them — don't leave
  fictional coverage.
- Parallel implementations: grep for `*_v1`/`*_old`/`legacy_*`, or two structs that do the
  same job (`FooGenerator` + `FooGeneratorV2`). One is usually wired, one orphaned.
- `#[allow(dead_code)]` / `#[allow(unused)]` — each is a lead; confirm and remove the code,
  not the allow.

**P2 — unused deps, fields, and frontend exports**:
- `cargo machete` or `cargo +nightly udeps` for unused crate dependencies in every `Cargo.toml`.
- Fields constructed-but-never-read (the compiler warns for private ones — don't ignore
  those warnings; for `pub` fields, trace reads manually).
- Frontend (`nanosiem-web`): `npx ts-prune` / `knip` for unused exports, dead components,
  and API-client methods with no callers. (Out of scope for the Rust pass, but a big
  separate win.)

## How to run it as a multi-agent session (recommended)

This parallelizes cleanly — model it on `.claude/workflows/silent-bug-hunt.js`:

- **Phase 1 — Map (fan-out, read-only).** One agent per subsystem (search, detection,
  query, enrichment, prevalence, cases, ingestion, repositories, extensions). Each builds a
  *reachability table*: for every `pub` item / branch in its area, "constructed where /
  called where / reachable from a live entry point? (yes/no/unsure)". Require evidence
  (the grep + the caller file:line), and force the continuation-line and substring-false-
  positive checks. Output: a structured list of **candidates** (dead | shared-keep | unsure).
- **Phase 2 — Verify (adversarial).** A second agent per candidate tries to *prove it's
  alive* (find one reachable caller). Default verdict: **alive unless proven dead.** This is
  the antidote to over-deletion — the mirror of the silent-bug-hunt's "refute" stage.
- **Phase 3 — Group & remove.** Cluster confirmed-dead into coherent units (a whole backend,
  a whole module) so each PR is one logical removal. Per unit: delete, follow the cascade,
  `cargo build` all crates incl. enterprise feature, run the test suites, confirm the grep is
  empty. One Linear issue + worktree + PR per unit.

Scale expectation: the user noted this "should've been our largest" cleanup — budget for
several PRs. Group by subsystem; don't try to land it all at once.

## The hard-won safety rules (don't skip these)

1. **Verify reachability before deleting. "Referenced" ≠ "reached" ≠ "constructed."** The
   PG backend was referenced ~40 times and reached zero times.
2. **Watch the two grep traps:** method calls on a *continuation line* (single-line grep
   misses them → looks dead when it's live), and *substring* false positives
   (`XService::new` matches `OtherXService::new` → looks live when it's dead). Read the hits.
3. **Keep the shared types.** Before deleting a module, identify what's still used inside it
   and preserve it (e.g. `TimeRange`/`SqlGenError`). Re-export from a sane location.
4. **The compiler is the gate — and the gate includes feature-gated crates.** Build
   `nanosiem-core --tests`, and `nanosiem-api --features enterprise` (the merge gate skips
   enterprise; that's where the dead PG `SqlGenerator` was still *called* by `melod::npl_to_sql`
   — which turned out to be a latent wrong-backend bug, fixed by the migration).
5. **Cascade, then re-grep.** Removing dead code reveals more dead code. Loop until a clean
   build + empty confirmation grep.
6. **Never `#[allow(dead_code)]` to make it compile.** If it's dead, remove it. If you can't
   remove it, you haven't proven it's dead.
7. **Surface scope jumps to the user.** "Clean up the dead generator" became "remove a whole
   dead subsystem." That's a decision the user owns — present what you found and the size,
   don't silently balloon (or silently downshift to a half-removal that leaves scaffolding).
8. **Bound the risk on cascading guards.** Fully inlining a now-single-variant enum + its
   always-true guards can touch ~20 call sites for cosmetic gain. It's legitimate to remove
   the dead *code* and leave the (correct, harmless) single-variant scaffolding, calling it
   out for a follow-up — quality over a risky big-bang.

The meta-lesson, same as the bug hunt: **found by tracing and compiling, not by reading.**
Read to find candidates; trace reachability and let the compiler prove the removal.

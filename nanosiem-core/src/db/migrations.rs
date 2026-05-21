// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL migration runner — open-tier path with safe fresh-init detection.
//!
//! This module owns the open-tier portion of the migration topology
//! introduced by NAN-747 (overlay split) and NAN-749 (fresh-init snapshot).
//! Callers in `nanosiem-api` invoke [`run_postgres_migrations`] in place of
//! `sqlx::migrate!("../migrations/postgres").run(pool)`. The enterprise
//! overlay (`migrations/postgres-enterprise/`) stays at the call site under
//! its `#[cfg(feature = "enterprise")]` block — this helper only deals with
//! the open-tier path because `nanosiem-core` does not see the enterprise
//! feature flag.
//!
//! Three deployment states (see `migrations/SPLIT_RATIONALE.md`):
//!
//! | State                | `_sqlx_migrations` | What runs here                                              |
//! |----------------------|--------------------|-------------------------------------------------------------|
//! | Legacy tenant        | populated 1..N     | `sqlx::migrate!("../migrations/postgres")` (unchanged path) |
//! | Fresh open install   | absent             | snapshot → backfill 1..=baseline → migrator runs 176+ only  |
//! | Fresh enterprise     | absent             | same as fresh open; caller layers the enterprise overlay    |
//!
//! The "baseline" cutoff is [`OPEN_INIT_BASELINE_VERSION`] — versions
//! at or below it are pre-applied via the snapshot and only need their
//! `_sqlx_migrations` row backfilled; versions above it must run normally
//! or their bodies are silently swallowed (NAN-791).
//!
//! Safety: misdetecting a legacy DB as fresh would be catastrophic. Three
//! independent layers guard against it:
//! 1. `is_fresh_database` requires BOTH (a) `_sqlx_migrations` missing AND
//!    (b) no well-known nanosiem table present. Either signal flips it to
//!    legacy.
//! 2. The snapshot file uses `IF NOT EXISTS` everywhere, so even if Layer 1
//!    misfires the snapshot is a no-op against a populated DB.
//! 3. `NANOSIEM_MIGRATION_MODE=legacy` env var bypasses detection entirely
//!    and forces the today-equivalent path. Pin this on known-existing
//!    deployments.

use sqlx::migrate::Migrator;
use sqlx::PgPool;
use thiserror::Error;
use tracing::{info, warn};

/// Embedded snapshot — applied only when [`run_postgres_migrations`] decides
/// it is operating against a truly fresh database. The snapshot creates the
/// open-tier schema as of legacy migration version 175.
///
/// Embedded via `include_str!` so the binary is self-contained; the
/// migrations directory does not need to be present at runtime (unlike
/// `nanosiem-core/src/demo/migrations.rs`, which is dev-only and reads
/// from the filesystem).
const OPEN_INIT_SNAPSHOT: &str =
    include_str!("../../../migrations/postgres-open/000_open_init.sql");

/// Highest legacy migration version baked into the open-init snapshot.
///
/// Versions `<=` this constant are pre-applied via DDL in
/// `000_open_init.sql` and need their `_sqlx_migrations` row backfilled
/// (with `execution_time = -1`) so that the subsequent `migrator.run()`
/// treats them as no-ops. Versions `>` this constant are **NOT** in the
/// snapshot and MUST run normally — backfilling them would silently swallow
/// their bodies (NAN-791: this exact bug silently broke fresh-tenant signup
/// after NAN-790 shipped the first post-baseline data migration).
///
/// Bump this only when the snapshot is regenerated (see
/// `tools/nan749_split_open_overlay.py`) and the new high-water mark of
/// migrations folded into the snapshot is known.
pub const OPEN_INIT_BASELINE_VERSION: i64 = 175;

/// Errors emitted by [`run_postgres_migrations`].
#[derive(Debug, Error)]
pub enum MigrationError {
    /// The open-init snapshot raw_sql execute failed.
    #[error("open-init snapshot apply failed: {0}")]
    SnapshotFailed(#[source] sqlx::Error),

    /// Backfilling `_sqlx_migrations` with rows for the legacy
    /// 1..=[`OPEN_INIT_BASELINE_VERSION`] history failed. Rare; usually only
    /// fires if the DB privilege model blocks INSERT into `_sqlx_migrations`.
    #[error("legacy migration history backfill failed: {0}")]
    BackfillFailed(#[source] sqlx::Error),

    /// `sqlx::migrate!("../migrations/postgres").run()` failed.
    #[error("postgres migrator failed: {0}")]
    MigratorFailed(#[from] sqlx::migrate::MigrateError),

    /// Pre-migration repair for the NAN-922 collision failed. See
    /// [`repair_nan922_185_collision`]. Rare; only fires if the DELETE
    /// against `_sqlx_migrations` is blocked (privilege model) or the
    /// table-exists probe fails.
    #[error("nan-922 collision repair failed: {0}")]
    RepairFailed(#[source] sqlx::Error),
}

/// Mode for [`run_postgres_migrations`], controlled by the
/// `NANOSIEM_MIGRATION_MODE` environment variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationMode {
    /// Default: detect fresh vs legacy at runtime via `is_fresh_database`.
    Auto,
    /// Force the today-equivalent path: skip snapshot + backfill, just run
    /// `sqlx::migrate!("../migrations/postgres").run()`. Pin this on
    /// known-existing deployments as a belt-and-suspenders safety net.
    Legacy,
    /// Force the snapshot path even when detection would have said legacy.
    /// Useful only for integration tests; would be unsafe in production.
    Fresh,
}

impl MigrationMode {
    /// Read `NANOSIEM_MIGRATION_MODE` from the environment. Unrecognized
    /// values fall back to [`MigrationMode::Auto`] with a warning.
    pub fn from_env() -> Self {
        match std::env::var("NANOSIEM_MIGRATION_MODE")
            .ok()
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("") | Some("auto") => Self::Auto,
            Some("legacy") => Self::Legacy,
            Some("fresh") => Self::Fresh,
            Some(other) => {
                warn!(
                    value = %other,
                    "unrecognized NANOSIEM_MIGRATION_MODE; defaulting to auto"
                );
                Self::Auto
            }
        }
    }
}

/// Returns `true` only when both signals indicate a truly fresh database:
/// `_sqlx_migrations` is absent AND no well-known nanosiem table exists.
///
/// The dual signal is deliberate. Either one alone could be misleading:
/// a partially-bootstrapped DB might have `users` but no migration history,
/// or a recovery scenario might drop `_sqlx_migrations` but keep the rest.
/// In either case we want to err on the side of "legacy" — false-positive
/// fresh detection is the dangerous failure mode (it would try to apply
/// the snapshot's `IF NOT EXISTS` no-ops, then backfill `_sqlx_migrations`
/// with `OPEN_INIT_BASELINE_VERSION` rows, leaving the DB in a confused state). False-negative is
/// safe: legacy path is what we did before NAN-749 anyway.
pub async fn is_fresh_database(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let has_sqlx_table: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = '_sqlx_migrations')",
    )
    .fetch_one(pool)
    .await?;
    if has_sqlx_table {
        return Ok(false);
    }

    let has_known_table: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' \
         AND table_name IN ('logs', 'users', 'detection_rules', 'alerts'))",
    )
    .fetch_one(pool)
    .await?;
    Ok(!has_known_table)
}

/// Description that sqlx assigns to a migration whose filename is
/// `*_brand_rename_system_ai.sql`. sqlx strips the leading version + `_`,
/// drops the `.sql` extension, and replaces remaining `_` with spaces.
///
/// Used by [`repair_nan922_185_collision`] to identify a poisoned legacy row
/// without depending on checksum comparison (which would also need to know
/// the exact byte content of the pre-rename file).
const NAN922_BRAND_RENAME_DESCRIPTION: &str = "brand rename system ai";

/// NAN-926: heal tenants stuck on the NAN-922 migration-185 collision.
///
/// NAN-922 (PR #1350) renamed `185_brand_rename_system_ai.sql` →
/// `187_brand_rename_system_ai.sql` to resolve a parallel-PR version
/// collision (NAN-910 + NAN-918 both landed at 185). For tenants that had
/// already applied the OLD 185 (NAN-910's brand-rename), the rename leaves
/// `_sqlx_migrations.version=185` pinned to the old checksum. On the next
/// `sqlx::migrate!` run, sqlx finds that the file at version 185 is now
/// `185_seed_splunk_hec_routing_rules.sql` (different checksum) and aborts
/// with "migration 185 was previously applied but has been modified",
/// blocking every subsequent migration. NAN-922's commit body documented
/// the manual recovery (`DELETE FROM _sqlx_migrations WHERE version = 185`)
/// but humans missed it on the 0.1.532 rollout and broke both saturn and the
/// local docker stack.
///
/// This function makes the recovery automatic. It deletes the poisoned row
/// IFF all three signals line up:
///   1. `_sqlx_migrations` exists (skip on fresh DBs that haven't bootstrapped
///      it yet — `migrator.run()` will create it next).
///   2. There IS a row at version 185, and its description is
///      `brand rename system ai` (the exact slug derived from the pre-rename
///      filename — unambiguous; that description only ever existed in the old
///      185 file because no other migration shares that name).
///   3. There is NO row at version 187. Once 187 lands the brand-rename has
///      been re-applied under its new version and self-healing is done; we
///      MUST NOT touch the table again.
///
/// All three together are tight enough to never fire on a legitimate row.
/// Once 187 is applied this function is a permanent no-op for that DB. A
/// fresh DB never satisfies signal 2. A DB that already applied the new 185
/// (HEC seed rules) has a different description there and won't match.
///
/// Both re-applied migration bodies are idempotent on the re-run:
///   - `185_seed_splunk_hec_routing_rules.sql` → `INSERT ... ON CONFLICT DO NOTHING`
///   - `187_brand_rename_system_ai.sql` → `UPDATE ... WHERE email = '<old>'`
///     (matches zero rows post-recovery because the column was already
///     rewritten by the original NAN-910 run).
///
/// Errors are not silenced: callers receive [`MigrationError::RepairFailed`]
/// so a broken privilege model surfaces as a boot failure rather than
/// half-fixing the DB and proceeding.
pub async fn repair_nan922_185_collision(pool: &PgPool) -> Result<(), sqlx::Error> {
    let has_sqlx_table: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = '_sqlx_migrations')",
    )
    .fetch_one(pool)
    .await?;
    if !has_sqlx_table {
        return Ok(());
    }

    let row_185: Option<(String,)> = sqlx::query_as(
        "SELECT description FROM public._sqlx_migrations WHERE version = 185",
    )
    .fetch_optional(pool)
    .await?;
    let Some((description_185,)) = row_185 else {
        return Ok(());
    };
    if description_185 != NAN922_BRAND_RENAME_DESCRIPTION {
        return Ok(());
    }

    let has_187: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM public._sqlx_migrations WHERE version = 187)",
    )
    .fetch_one(pool)
    .await?;
    if has_187 {
        return Ok(());
    }

    warn!(
        "NAN-922 collision detected: removing poisoned _sqlx_migrations row \
         (version=185, description='{}') so the renamed brand-rename can \
         re-land at version=187. See NAN-926.",
        NAN922_BRAND_RENAME_DESCRIPTION
    );
    sqlx::query(
        "DELETE FROM public._sqlx_migrations \
         WHERE version = 185 AND description = $1",
    )
    .bind(NAN922_BRAND_RENAME_DESCRIPTION)
    .execute(pool)
    .await?;

    Ok(())
}

/// Insert one row per migration in `migrator` whose version is
/// `<= OPEN_INIT_BASELINE_VERSION` into `_sqlx_migrations`, marking each as
/// already-applied with the actual checksum from the embedded migration
/// source. After this call, `migrator.run()` sees those rows, validates
/// checksums (they match — same source), and is a no-op for those versions;
/// versions ABOVE the baseline are deliberately NOT backfilled so that
/// `migrator.run()` executes them normally.
///
/// `execution_time = -1` is the sqlx convention for "never actually ran"
/// and matches the upstream INSERT in `sqlx-postgres-0.8.6/src/migrate.rs`.
/// `ON CONFLICT (version) DO NOTHING` makes this safe even if Layer 1
/// detection somehow misfires on a partially-populated DB.
///
/// NAN-791: the cutoff is load-bearing. Before this guard, every migration
/// the binary knew about got pre-marked applied, so post-baseline data
/// migrations (e.g. NAN-790's `176_seed_baseline_fresh_deploy.sql`) had
/// their bodies silently swallowed on fresh tenants. The
/// `migrations_to_backfill` helper isolates the filter so it can be
/// unit-tested without a real PG.
async fn backfill_legacy_migration_history(
    pool: &PgPool,
    migrator: &Migrator,
) -> Result<(), sqlx::Error> {
    // Schema-qualify everything as `public.*`. The snapshot's pg_dump
    // preamble sets `search_path=''` which persists on the connection;
    // an unqualified `_sqlx_migrations` would fail with "relation does
    // not exist".
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS public._sqlx_migrations ( \
            version BIGINT PRIMARY KEY, \
            description TEXT NOT NULL, \
            installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), \
            success BOOLEAN NOT NULL, \
            checksum BYTEA NOT NULL, \
            execution_time BIGINT NOT NULL \
        )",
    )
    .execute(pool)
    .await?;

    let mut count = 0usize;
    for migration in migrations_to_backfill(migrator) {
        sqlx::query(
            "INSERT INTO public._sqlx_migrations \
               (version, description, success, checksum, execution_time) \
             VALUES ($1, $2, TRUE, $3, -1) \
             ON CONFLICT (version) DO NOTHING",
        )
        .bind(migration.version)
        .bind(migration.description.as_ref())
        .bind(migration.checksum.as_ref())
        .execute(pool)
        .await?;
        count += 1;
    }
    info!(
        rows = count,
        baseline = OPEN_INIT_BASELINE_VERSION,
        "Backfilled legacy migration history"
    );
    Ok(())
}

/// Pure filter: which migrations in `migrator` should be backfilled into
/// `_sqlx_migrations` because they're already applied via the open-init
/// snapshot. Anything strictly above [`OPEN_INIT_BASELINE_VERSION`] is left
/// alone so the migrator runs it normally.
///
/// Extracted so the cutoff logic can be unit-tested without a real PG
/// (NAN-791).
fn migrations_to_backfill(
    migrator: &Migrator,
) -> impl Iterator<Item = &sqlx::migrate::Migration> {
    migrator
        .iter()
        .filter(|m| m.version <= OPEN_INIT_BASELINE_VERSION)
}

/// Run open-tier PostgreSQL migrations.
///
/// Decides between the legacy path (today's behavior) and the fresh-init
/// path (NAN-749) based on [`MigrationMode::from_env`] and, when in
/// `Auto` mode, runtime detection via [`is_fresh_database`]. The enterprise
/// overlay (`migrations/postgres-enterprise/`) is NOT applied here — call
/// sites layer it under their own `#[cfg(feature = "enterprise")]` block
/// because `nanosiem-core` does not see the enterprise feature flag.
pub async fn run_postgres_migrations(pool: &PgPool) -> Result<(), MigrationError> {
    let mode = MigrationMode::from_env();

    // The macro path is resolved at compile time relative to the crate's
    // Cargo.toml (nanosiem-core/Cargo.toml), so `../migrations/postgres`
    // points to the workspace-root migrations directory.
    let mut open_migrator = sqlx::migrate!("../migrations/postgres");
    // ignore_missing(true) so this migrator tolerates the enterprise
    // overlay's applied rows (versions 9_000_001+) when present, plus any
    // future migrators that may share `_sqlx_migrations`.
    open_migrator.set_ignore_missing(true);

    let take_fresh_path = match mode {
        MigrationMode::Legacy => {
            info!("NANOSIEM_MIGRATION_MODE=legacy — skipping fresh-init detection");
            false
        }
        MigrationMode::Fresh => {
            warn!(
                "NANOSIEM_MIGRATION_MODE=fresh — forcing snapshot path; \
                 unsafe in production"
            );
            true
        }
        MigrationMode::Auto => match is_fresh_database(pool).await {
            Ok(fresh) => {
                info!(
                    fresh,
                    "Detected database state for migration mode (auto)"
                );
                fresh
            }
            Err(err) => {
                // Detection failure → degrade to legacy (the safe choice).
                // We log loudly so ops sees it, but we do NOT propagate;
                // the legacy path is exactly what we did before NAN-749.
                warn!(
                    error = %err,
                    "Fresh-database detection errored; falling back to legacy path"
                );
                false
            }
        },
    };

    if take_fresh_path {
        info!("Applying open-init snapshot (migrations/postgres-open/000_open_init.sql)");
        sqlx::raw_sql(OPEN_INIT_SNAPSHOT)
            .execute(pool)
            .await
            .map_err(MigrationError::SnapshotFailed)?;
        // Defense-in-depth: `tools/nan749_split_open_overlay.py` strips
        // `set_config('search_path', '', false)` from the snapshot at
        // generation time (load-bearing fix), but if a regenerated
        // snapshot ever ships with that line restored — or if a pool
        // connection reuses session state from elsewhere — RESET
        // search_path here ensures `public.*` resolves for the
        // subsequent backfill INSERTs and `migrator.run()`.
        sqlx::query("RESET search_path")
            .execute(pool)
            .await
            .map_err(MigrationError::SnapshotFailed)?;
        backfill_legacy_migration_history(pool, &open_migrator)
            .await
            .map_err(MigrationError::BackfillFailed)?;
        info!("Open-init snapshot applied; legacy history backfilled");
    }

    // NAN-926: self-heal the NAN-922 migration-185 rename collision before
    // sqlx::migrate! gets a chance to abort on the mismatched checksum. No-op
    // on fresh DBs (signal: _sqlx_migrations absent), DBs that already
    // applied the new 185 (signal: description mismatch), and DBs that have
    // already self-healed (signal: 187 row present).
    repair_nan922_185_collision(pool)
        .await
        .map_err(MigrationError::RepairFailed)?;

    info!("Running PostgreSQL migrations (sqlx::migrate!('../migrations/postgres'))");
    open_migrator.run(pool).await?;
    info!("PostgreSQL migrations complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_mode_from_env_parses_known_values() {
        // Note: these tests touch process env, so run them serially via
        // `cargo test -- --test-threads=1` if they ever flake. For now the
        // set of values is small and the parser is total.
        std::env::remove_var("NANOSIEM_MIGRATION_MODE");
        assert_eq!(MigrationMode::from_env(), MigrationMode::Auto);

        std::env::set_var("NANOSIEM_MIGRATION_MODE", "legacy");
        assert_eq!(MigrationMode::from_env(), MigrationMode::Legacy);

        std::env::set_var("NANOSIEM_MIGRATION_MODE", "FRESH");
        assert_eq!(MigrationMode::from_env(), MigrationMode::Fresh);

        std::env::set_var("NANOSIEM_MIGRATION_MODE", "garbage");
        assert_eq!(MigrationMode::from_env(), MigrationMode::Auto);

        std::env::remove_var("NANOSIEM_MIGRATION_MODE");
    }

    /// NAN-791: the backfill must skip migrations strictly above
    /// `OPEN_INIT_BASELINE_VERSION`. Otherwise post-baseline migrations
    /// get pre-marked applied and their bodies are silently swallowed on
    /// fresh tenants (originally surfaced as NAN-790's seed data being
    /// AWOL after deploy).
    #[test]
    fn migrations_to_backfill_excludes_post_baseline_versions() {
        let migrator = sqlx::migrate!("../migrations/postgres");

        for migration in migrations_to_backfill(&migrator) {
            assert!(
                migration.version <= OPEN_INIT_BASELINE_VERSION,
                "version {} leaked past baseline {} — backfill would swallow its body on fresh deploys",
                migration.version,
                OPEN_INIT_BASELINE_VERSION
            );
        }
    }

    /// NAN-791: the cutoff is only meaningful if there's at least one
    /// migration above the baseline. If this assertion fires, either the
    /// constant is stale (a snapshot regeneration absorbed everything) or
    /// the migrations directory is in a degenerate state.
    #[test]
    fn at_least_one_migration_lives_above_the_baseline() {
        let migrator = sqlx::migrate!("../migrations/postgres");

        let past_baseline = migrator
            .iter()
            .filter(|m| m.version > OPEN_INIT_BASELINE_VERSION)
            .count();

        assert!(
            past_baseline > 0,
            "no migrations past baseline {} — bump OPEN_INIT_BASELINE_VERSION to the new snapshot high-water mark, or this guard is the only thing keeping the filter honest",
            OPEN_INIT_BASELINE_VERSION
        );
    }

    /// NAN-926: the repair function looks up the poisoned row by its
    /// sqlx-derived description. That description is the slug taken from
    /// the renamed file at version 187 — if anyone ever renames
    /// `187_brand_rename_system_ai.sql`, the constant goes stale silently.
    /// This guard pins the constant against the embedded migrator so the
    /// build fails loudly instead.
    #[test]
    fn nan922_brand_rename_description_matches_embedded_187() {
        let migrator = sqlx::migrate!("../migrations/postgres");
        let m187 = migrator
            .iter()
            .find(|m| m.version == 187)
            .expect("embedded migrator must include version 187 (post-NAN-922 brand rename)");
        assert_eq!(
            m187.description.as_ref(),
            NAN922_BRAND_RENAME_DESCRIPTION,
            "187's description drifted from NAN922_BRAND_RENAME_DESCRIPTION \
             — the repair function will no-op against legitimately poisoned \
             tenants. Update the constant if 187 was intentionally renamed."
        );
    }

    /// NAN-791: every migration `<= OPEN_INIT_BASELINE_VERSION` that the
    /// binary embeds must be selected for backfill — a fresh tenant relies
    /// on those rows landing so `migrator.run()` treats the DDL the
    /// snapshot already applied as a no-op rather than re-running it and
    /// hitting "relation already exists" errors.
    #[test]
    fn migrations_to_backfill_covers_full_pre_baseline_range() {
        let migrator = sqlx::migrate!("../migrations/postgres");

        let expected: Vec<i64> = migrator
            .iter()
            .filter(|m| m.version <= OPEN_INIT_BASELINE_VERSION)
            .map(|m| m.version)
            .collect();
        let actual: Vec<i64> = migrations_to_backfill(&migrator)
            .map(|m| m.version)
            .collect();

        assert_eq!(
            expected, actual,
            "backfill set diverged from pre-baseline range — filter is wrong"
        );
    }
}

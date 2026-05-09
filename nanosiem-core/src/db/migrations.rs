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
//! | Fresh open install   | absent             | snapshot → backfill 1..175 → migrator no-op for 1..175      |
//! | Fresh enterprise     | absent             | same as fresh open; caller layers the enterprise overlay    |
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

/// Errors emitted by [`run_postgres_migrations`].
#[derive(Debug, Error)]
pub enum MigrationError {
    /// The open-init snapshot raw_sql execute failed.
    #[error("open-init snapshot apply failed: {0}")]
    SnapshotFailed(#[source] sqlx::Error),

    /// Backfilling `_sqlx_migrations` with rows for the legacy 1..175 history
    /// failed. Rare; usually only fires if the DB privilege model blocks
    /// INSERT into `_sqlx_migrations`.
    #[error("legacy migration history backfill failed: {0}")]
    BackfillFailed(#[source] sqlx::Error),

    /// `sqlx::migrate!("../migrations/postgres").run()` failed.
    #[error("postgres migrator failed: {0}")]
    MigratorFailed(#[from] sqlx::migrate::MigrateError),
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
/// with 175 rows, leaving the DB in a confused state). False-negative is
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

/// Insert one row per migration in `migrator` into `_sqlx_migrations`,
/// marking each as already-applied with the actual checksum from the
/// embedded migration source. After this call, `migrator.run()` sees the
/// rows, validates checksums (they match — same source), and is a no-op
/// for those versions; only NEW migrations added later will execute.
///
/// `execution_time = -1` is the sqlx convention for "never actually ran"
/// and matches the upstream INSERT in `sqlx-postgres-0.8.6/src/migrate.rs`.
/// `ON CONFLICT (version) DO NOTHING` makes this safe even if Layer 1
/// detection somehow misfires on a partially-populated DB.
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
    for migration in migrator.iter() {
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
    info!(rows = count, "Backfilled legacy migration history");
    Ok(())
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
}

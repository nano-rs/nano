// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone ClickHouse schema migrator.
//!
//! Runs init.sql, applies all numbered migrations from `./clickhouse/`, and
//! creates the cross-shard distributed-table layer. Designed to run as a
//! one-shot pre-deploy step:
//!
//! - K8s: a Job that the api/search/jobs Deployments depend on (Pulumi
//!   `dependsOn`, or Helm `helm.sh/hook: pre-upgrade`).
//! - docker-compose: a service with `restart: "no"` that the app services
//!   gate on via `depends_on: { condition: service_completed_successfully }`.
//!
//! Exits 0 on success, non-zero on failure. App binaries verify the schema
//! is up-to-date on startup and refuse to serve traffic on a stale schema —
//! they no longer execute DDL themselves. See NAN-607 for context (saturn
//! crash-loop incident driven by an in-process backfill blowing past the
//! startup-probe budget).
//!
//! Environment variables (same as nanosiem-api):
//! - `DATABASE_URL`              — required; PG migrations are applied first
//!   (NAN-789) so CH dictionary sources can resolve their PG tables before
//!   `CREATE TABLE nanosiem.logs` validates materialized-column dict refs.
//! - `CLICKHOUSE_URL`            — required
//! - `CLICKHOUSE_DATABASE`       — defaults to `nanosiem`
//! - `CLICKHOUSE_USER`           — runtime user (fallback for migrations)
//! - `CLICKHOUSE_PASSWORD`       — runtime password
//! - `CLICKHOUSE_ADMIN_USER`     — admin user with DDL permissions (preferred)
//! - `CLICKHOUSE_ADMIN_PASSWORD` — admin password
//! - `CLICKHOUSE_MIGRATIONS_DIR` — defaults to `./clickhouse`
//! - `NANO_SCHEMA_PROFILE`       — `udm` (default) | `ocsf`. When `ocsf`, the
//!   OCSF table overlay `<CLICKHOUSE_MIGRATIONS_DIR>/ocsf/init.sql` is applied
//!   after the shared init + numbered migrations (NAN-1476). Must match the
//!   value the api/search/jobs binaries run with.
//! - `CLICKHOUSE_ENTERPRISE_MIGRATIONS_DIR` — defaults to
//!   `./clickhouse-enterprise`. Only consulted when this binary is built
//!   with `--features enterprise`. Today the directory is empty and the
//!   migrator is a no-op there; future enterprise-only ClickHouse
//!   overlays land in this directory (NAN-747 Phase 6).

use anyhow::{Context, Result};
use nanosiem_core::db::{ClickHouseMigrator, Database, DualPoolConfig};
use std::path::PathBuf;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("clickhouse-migrator");

    match run().await {
        Ok(()) => {
            tracing::info!("ClickHouse schema migration complete");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!("ClickHouse schema migration failed: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    tracing::info!("Starting ClickHouse schema migration");

    let config =
        DualPoolConfig::from_env().context("loading DualPool configuration from environment")?;

    // NAN-789: apply PostgreSQL migrations BEFORE any ClickHouse work. CH 26.3
    // eagerly validates dictionary sources during `CREATE TABLE nanosiem.logs`
    // (because materialized columns call `dictGet(...)`), so the PG tables
    // those dicts source from must exist by the time init.sql runs. Without
    // this preflight, fresh deploys deadlock: CH migrator fails on the
    // missing PG schema, api/jobs depend on the migrator to complete, and
    // PG migrations (which live in those binaries) never run.
    //
    // api/jobs still call `run_postgres_migrations` themselves on startup —
    // sqlx checks `_sqlx_migrations` and skips already-applied work, so the
    // canonical-and-redundant ordering is safe and keeps those binaries
    // resilient when run without this one-shot (e.g., local dev).
    tracing::info!("Applying PostgreSQL migrations before ClickHouse work");
    let pg_db = Database::connect(&config.postgres_url)
        .await
        .context("connecting to PostgreSQL for migration preflight")?;
    let pg_pool = pg_db.pool();
    nanosiem_core::db::run_postgres_migrations(pg_pool)
        .await
        .context("running PostgreSQL migrations")?;
    #[cfg(feature = "enterprise")]
    {
        tracing::info!("Applying enterprise PostgreSQL overlay migrations");
        let mut overlay_migrator = sqlx::migrate!("../migrations/postgres-enterprise");
        // ignore_missing(true) so the overlay's validator tolerates the
        // open history's applied rows that already sit in _sqlx_migrations.
        // Matches the same call in nanosiem-api/src/state/constructors.rs.
        overlay_migrator.set_ignore_missing(true);
        overlay_migrator
            .run(pg_pool)
            .await
            .context("running enterprise PostgreSQL overlay migrations")?;
    }
    pg_db.close().await;
    tracing::info!("PostgreSQL migrations complete");

    let (admin_client, is_admin) = config.create_admin_clickhouse_client();
    if !is_admin {
        tracing::warn!(
            "Migrator running without dedicated admin credentials \
             (CLICKHOUSE_ADMIN_USER/CLICKHOUSE_ADMIN_PASSWORD unset). \
             Falling back to the runtime user — DDL may fail if it lacks \
             CREATE/ALTER/DROP privileges."
        );
    }
    let mut migrator = ClickHouseMigrator::new(admin_client, config.clickhouse_database.clone());

    let migrations_dir: PathBuf = std::env::var("CLICKHOUSE_MIGRATIONS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./clickhouse"));

    // Read init.sql from disk at runtime (same source as numbered migrations).
    // Avoids the include_str! compile-time embed so the binary doesn't carry a
    // potentially-stale snapshot when run against a freshly-mounted clickhouse/
    // dir (e.g., the same image running with a CLICKHOUSE_MIGRATIONS_DIR
    // override pointing at a customer-specific clickhouse/).
    let init_sql_path = migrations_dir.join("init.sql");
    let init_sql = std::fs::read_to_string(&init_sql_path)
        .with_context(|| format!("reading {}", init_sql_path.display()))?;
    migrator
        .run_init_sql(&init_sql)
        .await
        .context("running init.sql")?;
    let count = migrator
        .run_migrations(&migrations_dir)
        .await
        .context("running incremental migrations")?;
    if count > 0 {
        tracing::info!("Applied {} ClickHouse migration(s)", count);
    } else {
        tracing::info!("ClickHouse migrations up to date");
    }

    // NAN-1476: when the deployment runs the OCSF schema profile, apply the
    // OCSF table overlay (`<migrations_dir>/ocsf/init.sql`) AFTER the shared
    // init.sql + numbered migrations. Those create the dictionaries and
    // `signals` table that the OCSF tables' `dictGet`-backed MATERIALIZED
    // columns depend on (CH validates dict sources at CREATE TABLE time), so
    // the overlay must run last. Without this, `ocsf_logs` is never created and
    // api/jobs/search fail-fast boot validation and crash-loop. The overlay is
    // hash-tracked under its own `__ocsf_init_sql` key so it never clobbers the
    // primary `__init_sql` hash. UDM deployments skip this entirely.
    let schema_raw = std::env::var(nanosiem_core::schema::SCHEMA_PROFILE_ENV).unwrap_or_default();
    let schema_id = nanosiem_core::schema::SchemaId::from_env_str(&schema_raw)
        .map_err(|e| anyhow::anyhow!("invalid {}: {e}", nanosiem_core::schema::SCHEMA_PROFILE_ENV))?;
    if matches!(schema_id, nanosiem_core::schema::SchemaId::Ocsf) {
        let ocsf_init_path = migrations_dir.join("ocsf").join("init.sql");
        tracing::info!(
            "OCSF schema profile active — applying OCSF overlay {}",
            ocsf_init_path.display()
        );
        let ocsf_init_sql = std::fs::read_to_string(&ocsf_init_path)
            .with_context(|| format!("reading {}", ocsf_init_path.display()))?;
        migrator
            .run_overlay_init_sql(&ocsf_init_sql, "__ocsf_init_sql", "ocsf/init.sql")
            .await
            .context("running OCSF overlay init.sql")?;
    }

    // NAN-747 Phase 6: enterprise overlay only on enterprise builds. The
    // directory is currently empty (the entire ClickHouse schema is
    // open-tier today), but wiring it now means future enterprise-only
    // ClickHouse migrations don't need a Rust change to this binary —
    // drop a `001_*.sql` into clickhouse-enterprise/ and rebuild.
    #[cfg(feature = "enterprise")]
    {
        let enterprise_dir: PathBuf = std::env::var("CLICKHOUSE_ENTERPRISE_MIGRATIONS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./clickhouse-enterprise"));
        if enterprise_dir.exists() {
            tracing::info!(
                "Applying enterprise ClickHouse overlay from {}",
                enterprise_dir.display()
            );
            let ent_count = migrator
                .run_migrations(&enterprise_dir)
                .await
                .context("running enterprise overlay migrations")?;
            if ent_count > 0 {
                tracing::info!("Applied {} enterprise ClickHouse migration(s)", ent_count);
            } else {
                tracing::info!("Enterprise ClickHouse overlay up to date");
            }
        } else {
            tracing::debug!(
                "Enterprise ClickHouse overlay directory not present at {} — skipping",
                enterprise_dir.display()
            );
        }
    }

    let dist_count = migrator
        .ensure_distributed_tables()
        .await
        .context("creating distributed tables")?;
    if dist_count > 0 {
        tracing::info!("Created {} distributed table(s)", dist_count);
    }

    let alias_count = migrator
        .sync_distributed_aliases()
        .await
        .context("syncing alias columns onto distributed wrappers")?;
    if alias_count > 0 {
        tracing::info!(
            "Synced {} alias column(s) onto distributed wrappers",
            alias_count
        );
    }

    // NAN-1652 / NAN-1655: converge each Distributed wrapper's columns to its
    // source local table — ADD columns the wrapper lacks and DROP ones the
    // source no longer has. Without this, a migration that ALTERs the local
    // table leaves the wrapper drifted, and wrapper reads (fetch-by-id /
    // `SELECT <col>`) fail with UNKNOWN_IDENTIFIER on clusters.
    let reconciled_count = migrator
        .reconcile_distributed_columns()
        .await
        .context("reconciling columns on distributed wrappers")?;
    if reconciled_count > 0 {
        tracing::info!(
            "Reconciled {} column(s) on distributed wrappers",
            reconciled_count
        );
    }

    // NAN-1728 (C2/P0): now that the reference-table `_distributed` wrappers
    // exist, repoint the five dict-refresh MVs' FROM at them so each per-node
    // staging dict sees the COMPLETE cross-shard keyspace. This MUST run AFTER
    // ensure_distributed_tables — init.sql created the MVs reading the LOCAL base
    // because refreshable-MV DDL validates its FROM eagerly and the wrapper did
    // not exist at init time. Cluster-only; a no-op on single-node (MVs keep
    // reading the local, complete base). Idempotent, so safe every boot.
    let repointed_mvs = migrator
        .repoint_dict_refresh_mvs_distributed()
        .await
        .context("repointing dict-refresh MVs to distributed reference-table wrappers")?;
    if repointed_mvs > 0 {
        tracing::info!(
            "Repointed {} dict-refresh MV(s) to distributed reference-table wrappers",
            repointed_mvs
        );
    }

    // NAN-1116: surface any FAILED dictionaries in the deploy log. A FAILED
    // dict referenced by a dictGet()-backed MATERIALIZED column silently drops
    // 100% of ingestion at runtime; this makes it loud at every migrate instead
    // of an invisible outage. Reported, never fatal (failing here would block
    // the deploy — the deadlock NAN-1115 just removed).
    let failed_dicts = migrator.report_failed_dictionaries().await;
    if failed_dicts > 0 {
        tracing::error!(
            "{} ClickHouse dictionary(ies) are FAILED after migration (see errors above) — \
             ingestion through their enrichment columns will be dropped until resolved",
            failed_dicts
        );
    }

    Ok(())
}

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
//!   A preflight (NAN-5260) first checks PostgreSQL >= 16 and that every
//!   required extension (pg_trgm, pgcrypto, uuid-ossp) can be created.
//! - `CLICKHOUSE_URL`            — required
//! - `CLICKHOUSE_DATABASE`       — defaults to `nanosiem`
//! - `CLICKHOUSE_USER`           — runtime user (fallback for migrations)
//! - `CLICKHOUSE_PASSWORD`       — runtime password
//! - `CLICKHOUSE_ADMIN_USER`     — admin user with DDL permissions (preferred)
//! - `CLICKHOUSE_ADMIN_PASSWORD` — admin password
//! - `CLICKHOUSE_MIGRATIONS_DIR` — defaults to `./clickhouse`
//! - `NANO_SCHEMA_PROFILE`       — `ocsf` (default) | `udm`. When `ocsf`, the
//!   OCSF table overlay `<CLICKHOUSE_MIGRATIONS_DIR>/ocsf/init.sql` is applied
//!   after the shared init + numbered migrations (NAN-1476). Must match the
//!   value the api/search/jobs binaries run with. When unset on a database
//!   that already holds a UDM install, the migrator refuses to start rather
//!   than apply the OCSF default to it (NAN-5271).
//! - `CLICKHOUSE_ENTERPRISE_MIGRATIONS_DIR` — defaults to
//!   `./clickhouse-enterprise`. Only consulted when this binary is built
//!   with `--features enterprise`. Today the directory is empty and the
//!   migrator is a no-op there; future enterprise-only ClickHouse
//!   overlays land in this directory (NAN-747 Phase 6).
//!
//! Operator subcommand (never run by a deploy):
//!
//! - `clickhouse_migrator drop-ocsf-legacy [--confirm]` — compares per-day row
//!   counts between `ocsf_logs_legacy_v179` and `ocsf_logs` after
//!   `scripts/ocsf-legacy-backfill.py`, refuses on any mismatch or missing day,
//!   and drops the legacy table (cluster-aware) only with `--confirm`. Dry run
//!   by default. Needs only the ClickHouse variables above (`CLICKHOUSE_URL`,
//!   `CLICKHOUSE_DATABASE`, admin or runtime credentials). See
//!   docs/design/OCSF-CLICKHOUSE.md §9.1 (NAN-4918).
//! - `clickhouse_migrator repair-future-timestamps [--skew-seconds N] [--confirm]`
//!   previews far-future rows and, only with confirmation, copies them at the
//!   current time, verifies every id, then removes the originals. Pause ingest
//!   first. See `docs/operations/future-timestamp-repair.md` (NAN-4939).
//! - `clickhouse_migrator purge-future-timestamp-repair --repair-id UUID [--confirm]`
//!   previews or removes metadata for one completed repair id and may release
//!   that id's expired confirmed-run lock. It never changes tenant rows.
//! - `clickhouse_migrator activate-migration-refreshes [--retry-exhausted]` runs one durable
//!   post-migration refresh pass. The API jobs leader normally owns this; the
//!   command exists for upgrade validation and operator diagnostics (NAN-4977).

use anyhow::{Context, Result};
use nanosiem_core::db::{ClickHouseMigrator, Database, DualPoolConfig};
use std::path::PathBuf;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    // NAN-5214: before anything can negotiate TLS with PostgreSQL.
    nanosiem_core::db::tls_provider::install_default_crypto_provider();
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("clickhouse-migrator");

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {}
        Some("drop-ocsf-legacy") => return drop_ocsf_legacy(&args[1..]).await,
        Some("repair-future-timestamps") => return repair_future_timestamps(&args[1..]).await,
        Some("purge-future-timestamp-repair") => {
            return purge_future_timestamp_repair(&args[1..]).await;
        }
        Some("activate-migration-refreshes") => {
            return activate_migration_refreshes(&args[1..]).await;
        }
        Some(other) => {
            eprintln!("unknown argument {other:?}; usage: clickhouse_migrator [drop-ocsf-legacy [--confirm] | repair-future-timestamps [--skew-seconds N] [--confirm] | purge-future-timestamp-repair --repair-id UUID [--confirm] | activate-migration-refreshes [--retry-exhausted]]");
            return ExitCode::from(2);
        }
    }

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

/// Session-level PostgreSQL advisory lock held for one migrator run.
struct MigrationLock {
    connection: Option<sqlx::PgConnection>,
}

impl MigrationLock {
    async fn acquire(postgres_url: &str) -> Result<Self> {
        let mut connection = connect_with_retry(postgres_url).await?;
        let lock_id = nanosiem_core::leader::lock_ids::SCHEMA_MIGRATOR;
        let started = std::time::Instant::now();
        loop {
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(lock_id)
                .fetch_one(&mut connection)
                .await
                .context("requesting the migration lock")?;
            if acquired {
                if started.elapsed().as_secs() > 0 {
                    tracing::info!(
                        waited_secs = started.elapsed().as_secs(),
                        "Acquired the migration lock after another migrator released it"
                    );
                }
                return Ok(Self {
                    connection: Some(connection),
                });
            }
            tracing::info!(
                waited_secs = started.elapsed().as_secs(),
                "Another migrator holds the cluster migration lock; waiting"
            );
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

/// The pool connect this lock now precedes retried until its acquire timeout;
/// keep that tolerance for a PostgreSQL that is still refusing connections or
/// reporting "the database system is starting up" (SQLSTATE 57P03) after a
/// host restart. Any other error, or 30 s without success, fails the run.
async fn connect_with_retry(postgres_url: &str) -> Result<sqlx::PgConnection> {
    use sqlx::Connection;
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
    let started = std::time::Instant::now();
    loop {
        match sqlx::PgConnection::connect(postgres_url).await {
            Ok(connection) => return Ok(connection),
            Err(error) if is_transient_connect_error(&error) && started.elapsed() < BUDGET => {
                tracing::info!(%error, "PostgreSQL not accepting connections yet; retrying the migration lock connect");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(error) => {
                return Err(anyhow::Error::new(error)
                    .context("connecting to PostgreSQL for the migration lock"));
            }
        }
    }
}

fn is_transient_connect_error(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut => true,
        sqlx::Error::Database(db) => {
            db.code().as_deref() == Some("57P03") || db.message().contains("starting up")
        }
        other => {
            let text = other.to_string();
            text.contains("Connection refused") || text.contains("starting up")
        }
    }
}

impl Drop for MigrationLock {
    fn drop(&mut self) {
        // Dropping the connection closes the session, which releases the
        // advisory lock; the process exits right after `run` in any case.
        drop(self.connection.take());
    }
}

async fn activate_migration_refreshes(args: &[String]) -> ExitCode {
    let retry_exhausted = match args {
        [] => false,
        [flag] if flag == "--retry-exhausted" => true,
        _ => {
            eprintln!(
                "usage: clickhouse_migrator activate-migration-refreshes [--retry-exhausted]"
            );
            return ExitCode::from(2);
        }
    };
    let result = async {
        let (client, database) = clickhouse_admin_from_env()?;
        let reset = if retry_exhausted {
            nanosiem_core::db::migration_refresh::retry_exhausted(&client, &database).await?
        } else {
            0
        };
        if retry_exhausted {
            println!("Re-armed {reset} exhausted migration refresh activation(s).");
        }
        nanosiem_core::db::migration_refresh::process_pending(&client, &client, &database).await
    }
    .await;
    match result {
        Ok(summary) => {
            println!(
                "Migration refresh activation: {} attempted, {} succeeded, {} failed, {} exhausted",
                summary.attempted, summary.succeeded, summary.failed, summary.exhausted
            );
            if summary.failed == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("activate-migration-refreshes failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// `repair-future-timestamps` (NAN-4939). Dry-run unless `--confirm` is
/// explicit. Exit 0 for a successful preview/no-op/repair; non-zero on refusal.
async fn repair_future_timestamps(args: &[String]) -> ExitCode {
    let mut confirm = false;
    let mut skew_seconds = 86_400_u64;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--confirm" => confirm = true,
            "--dry-run" => {}
            "--skew-seconds" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    eprintln!("--skew-seconds requires a non-negative integer");
                    return ExitCode::from(2);
                };
                match value.parse::<u64>() {
                    Ok(parsed) => skew_seconds = parsed,
                    Err(_) => {
                        eprintln!("invalid --skew-seconds value {value:?}");
                        return ExitCode::from(2);
                    }
                }
            }
            other => {
                eprintln!("unknown flag {other:?}; usage: clickhouse_migrator repair-future-timestamps [--skew-seconds N] [--confirm]");
                return ExitCode::from(2);
            }
        }
        index += 1;
    }

    match run_repair_future_timestamps(skew_seconds, confirm).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("repair-future-timestamps failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn purge_future_timestamp_repair(args: &[String]) -> ExitCode {
    let mut confirm = false;
    let mut repair_id = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--confirm" => confirm = true,
            "--repair-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    eprintln!("--repair-id requires a UUID");
                    return ExitCode::from(2);
                };
                match uuid::Uuid::parse_str(value) {
                    Ok(value) => repair_id = Some(value),
                    Err(_) => {
                        eprintln!("invalid --repair-id UUID {value:?}");
                        return ExitCode::from(2);
                    }
                }
            }
            other => {
                eprintln!("unknown flag {other:?}; usage: clickhouse_migrator purge-future-timestamp-repair --repair-id UUID [--confirm]");
                return ExitCode::from(2);
            }
        }
        index += 1;
    }
    let Some(repair_id) = repair_id else {
        eprintln!("--repair-id is required");
        return ExitCode::from(2);
    };
    match run_purge_future_timestamp_repair(repair_id, confirm).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("purge-future-timestamp-repair failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_purge_future_timestamp_repair(repair_id: uuid::Uuid, confirm: bool) -> Result<()> {
    use nanosiem_core::db::future_timestamp_repair::FutureTimestampRepair;

    let (client, database) = clickhouse_admin_from_env()?;
    let schema_raw = std::env::var(nanosiem_core::schema::SCHEMA_PROFILE_ENV).unwrap_or_default();
    let schema =
        nanosiem_core::schema::SchemaId::from_env_str(&schema_raw).map_err(anyhow::Error::msg)?;
    let repair = FutureTimestampRepair::new(&client, &database, schema, 86_400).await?;
    let preview = repair.preview_purge(repair_id).await?;
    println!(
        "repair {}: {} staged row(s), {} staged bad original(s) remaining, {} buffered IP row(s), {}/{} buffered fingerprints verified",
        preview.repair_id,
        preview.staged_rows,
        preview.staged_originals_remaining,
        preview.buffered_rows,
        preview.buffered_verified_rows,
        preview.buffered_distinct_rows
    );
    if preview.owns_lock {
        println!(
            "repair lock: {} until {}",
            if preview.owns_expired_lock {
                "expired"
            } else {
                "active"
            },
            preview.lock_lease_until
        );
    }
    if !confirm {
        println!("DRY RUN: no metadata or lock changed. Rerun with --confirm after verifying this repair completed.");
        return Ok(());
    }
    repair.purge_completed_repair(&preview).await?;
    println!("Purged completed repair metadata for {repair_id}.");
    Ok(())
}

async fn run_repair_future_timestamps(skew_seconds: u64, confirm: bool) -> Result<()> {
    use nanosiem_core::db::future_timestamp_repair::FutureTimestampRepair;

    let (client, database) = clickhouse_admin_from_env()?;
    let schema_raw = std::env::var(nanosiem_core::schema::SCHEMA_PROFILE_ENV).unwrap_or_default();
    let schema =
        nanosiem_core::schema::SchemaId::from_env_str(&schema_raw).map_err(anyhow::Error::msg)?;
    let repair = FutureTimestampRepair::new(&client, &database, schema, skew_seconds).await?;
    let preview = repair.preview().await?;
    println!(
        "{}: {} future row(s), {} distinct id(s), {} recoverable NAN-4938 epoch-ms row(s), cutoff {}, range {} .. {}",
        preview.table,
        preview.future_rows,
        preview.distinct_ids,
        preview.recoverable_epoch_millis_rows,
        preview.cutoff.to_rfc3339(),
        if preview.oldest_future.is_empty() {
            "n/a"
        } else {
            &preview.oldest_future
        },
        if preview.newest_future.is_empty() {
            "n/a"
        } else {
            &preview.newest_future
        },
    );
    let epoch_millis_previews = repair.preview_epoch_millis_tables().await?;
    for table in &epoch_millis_previews {
        println!(
            "{}: {} recoverable NAN-4938 row(s), {} distinct semantic row(s), {} pending buffered row(s), recovered range {} .. {}",
            table.table,
            table.affected_rows,
            table.distinct_rows,
            table.pending_buffer_rows,
            if table.oldest_recovered.is_empty() {
                "n/a"
            } else {
                &table.oldest_recovered
            },
            if table.newest_recovered.is_empty() {
                "n/a"
            } else {
                &table.newest_recovered
            },
        );
    }
    if preview.existing_id_collisions > 0 {
        anyhow::bail!(
            "{} future id(s) collide with an existing non-future row; no data changed",
            preview.existing_id_collisions
        );
    }
    let epoch_millis_rows: u64 = epoch_millis_previews
        .iter()
        .map(|table| table.affected_rows + table.pending_buffer_rows)
        .sum();
    if preview.future_rows == 0 && epoch_millis_rows == 0 {
        println!("No future timestamps need repair.");
        return Ok(());
    }
    if !confirm {
        println!(
            "DRY RUN: pause all ingest writers, then repeat with --confirm to copy, verify, and delete these originals."
        );
        return Ok(());
    }

    let lock = repair.acquire_confirm_lock().await?;
    println!("Acquired confirmed repair lock {}.", lock.owner());
    // Preview again after serialization. The first preview remains the operator
    // contract; this second snapshot prevents a queued confirmed command from
    // acting on another run's now-stale pending-buffer count.
    let result = async {
        let locked_preview = repair.preview().await?;
        if locked_preview.existing_id_collisions > 0 {
            anyhow::bail!(
                "{} future id(s) collide with an existing non-future row; no data changed",
                locked_preview.existing_id_collisions
            );
        }
        let locked_epoch_previews = repair.preview_epoch_millis_tables().await?;
        if locked_preview.future_rows > 0 {
            let outcome = repair.execute(&locked_preview).await?;
            println!(
                "{} repair complete: verified {} corrected id(s), removed {} future original row(s).",
                locked_preview.table, outcome.copied_ids, outcome.deleted_rows
            );
        }
        for table in &locked_epoch_previews {
            if table.affected_rows == 0 && table.pending_buffer_rows == 0 {
                continue;
            }
            let outcome = repair.execute_epoch_millis_table(table).await?;
            println!(
                "{} repair complete: verified {} corrected row(s), removed {} future original row(s).",
                outcome.table, outcome.repaired_rows, outcome.deleted_originals
            );
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let release = lock.release().await;
    match (result, release) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(release)) => Err(release),
        (Err(error), Err(release)) => Err(error.context(format!(
            "repair also failed to release its cluster-global lock: {release:#}"
        ))),
    }
}

/// `drop-ocsf-legacy [--confirm]` (NAN-4918). Exit 0: dropped, dry run, or
/// nothing to drop. Exit 1: refused (mismatch / missing day) or error.
async fn drop_ocsf_legacy(args: &[String]) -> ExitCode {
    let mut confirm = false;
    for a in args {
        match a.as_str() {
            "--confirm" => confirm = true,
            "--dry-run" => {}
            other => {
                eprintln!("unknown flag {other:?}; usage: clickhouse_migrator drop-ocsf-legacy [--confirm]");
                return ExitCode::from(2);
            }
        }
    }
    match run_drop_ocsf_legacy(confirm).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("drop-ocsf-legacy failed: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// ClickHouse admin client from the environment, without the PostgreSQL
/// settings `DualPoolConfig` requires (this subcommand touches only ClickHouse).
fn clickhouse_admin_from_env() -> Result<(clickhouse::Client, String)> {
    let url = std::env::var("CLICKHOUSE_URL").context("CLICKHOUSE_URL is required")?;
    let database = std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "nanosiem".to_string());
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let (user, password) = match (
        var("CLICKHOUSE_ADMIN_USER"),
        var("CLICKHOUSE_ADMIN_PASSWORD"),
    ) {
        (Some(u), Some(p)) => (u, p),
        _ => (
            // Same fallback as DualPool::from_env; never the container-local
            // `default` user.
            var("CLICKHOUSE_USER").unwrap_or_else(|| "nanosiem".to_string()),
            var("CLICKHOUSE_PASSWORD").unwrap_or_default(),
        ),
    };
    let mut client = nanosiem_core::db::clickhouse_transport::client()
        .with_url(url)
        .with_database(&database)
        .with_user(user);
    if !password.is_empty() {
        client = client.with_password(password);
    }
    Ok((client, database))
}

async fn run_drop_ocsf_legacy(confirm: bool) -> Result<bool> {
    use nanosiem_core::db::clickhouse_migrate::{
        LegacyDayStatus, OcsfLegacyDropOutcome, OcsfLegacyDropPlan, OCSF_LEGACY_TABLE,
    };

    let (client, database) = clickhouse_admin_from_env()?;
    let mut migrator = ClickHouseMigrator::new(client, database.clone());
    let print_plan = |plan: &OcsfLegacyDropPlan| {
        println!(
            "{database}.{OCSF_LEGACY_TABLE}: {} rows over {} day(s); cluster: {}",
            plan.legacy_rows(),
            plan.days.len(),
            plan.cluster.as_deref().unwrap_or("none (single node)")
        );
        println!(
            "{:<12} {:>14} {:>12} {:>12}  status",
            "day (UTC)", "legacy rows", "missing ids", "dup ids"
        );
        for d in &plan.days {
            let status = match d.status() {
                LegacyDayStatus::Match => "ok",
                LegacyDayStatus::Mismatch => "MISMATCH",
                LegacyDayStatus::Missing => "MISSING",
            };
            println!(
                "{:<12} {:>14} {:>12} {:>12}  {status}",
                d.day.to_string(),
                d.legacy_rows,
                d.missing_ids,
                d.duplicate_ids
            );
        }
    };
    match migrator.drop_ocsf_legacy(confirm).await? {
        OcsfLegacyDropOutcome::Absent => {
            println!("{database}.{OCSF_LEGACY_TABLE} does not exist: nothing to drop");
            Ok(true)
        }
        OcsfLegacyDropOutcome::Refused(plan) => {
            print_plan(&plan);
            eprintln!(
                "REFUSED: {} day(s) are missing or mismatched. Run scripts/ocsf-legacy-backfill.py \
                 for them (or wait for the legacy 365-day TTL); nothing was dropped.",
                plan.blocking_days().len()
            );
            Ok(false)
        }
        OcsfLegacyDropOutcome::DryRun(plan) => {
            print_plan(&plan);
            println!(
                "every day matches. Dry run: rerun with --confirm to execute:\n  {}",
                plan.drop_sql
            );
            Ok(true)
        }
        OcsfLegacyDropOutcome::Dropped(plan) => {
            print_plan(&plan);
            println!("dropped: {}", plan.drop_sql);
            Ok(true)
        }
    }
}

async fn run() -> Result<()> {
    tracing::info!("Starting ClickHouse schema migration");

    let config =
        DualPoolConfig::from_env().context("loading DualPool configuration from environment")?;

    // NAN-5213: a role-split cluster with several app hosts starts one
    // migrator per host. Serialize the whole run behind a cluster-wide
    // PostgreSQL advisory lock: the ClickHouse `_migrations` ledger has no
    // lock of its own, and the PostgreSQL fresh-database detection and
    // snapshot steps run outside sqlx's migration lock. A host that waits
    // here then finds nothing pending. The lock is session-scoped, so a
    // migrator that dies releases it with its connection.
    let _migration_lock = MigrationLock::acquire(&config.postgres_url).await?;

    // NAN-5271 (lane L): an unset NANO_SCHEMA_PROFILE now means OCSF. Refuse,
    // before any DDL, to apply that default to a database that already runs
    // UDM (an install whose .env never recorded the profile). install.sh and
    // `nano upgrade` pin `udm` for those installs; this catches every path
    // that skips them. An explicit value is always respected.
    {
        let schema_raw =
            std::env::var(nanosiem_core::schema::SCHEMA_PROFILE_ENV).unwrap_or_default();
        let (probe_client, _) = config.create_admin_clickhouse_client();
        let installed = ClickHouseMigrator::new(probe_client, config.clickhouse_database.clone())
            .refuse_unset_profile_on_udm_install(&schema_raw)
            .await
            .map_err(anyhow::Error::msg)?;
        if let Some(installed) = installed {
            tracing::info!(
                ?installed,
                "{} unset: using the OCSF default",
                nanosiem_core::schema::SCHEMA_PROFILE_ENV
            );
        }
    }

    // NAN-789: apply PostgreSQL migrations BEFORE any ClickHouse work. CH 26.3
    // eagerly validates dictionary sources during `CREATE TABLE nanosiem.logs`
    // (because materialized columns call `dictGet(...)`), so the PG tables
    // those dicts source from must exist by the time init.sql runs. Without
    // this preflight, fresh deploys deadlock: CH migrator fails on the
    // missing PG schema, api/jobs depend on the migrator to complete, and
    // PG migrations (which live in those binaries) never run.
    //
    // Serving processes only validate this embedded set and refuse to start
    // when it is behind. Keeping DDL here makes deploy ordering explicit and
    // prevents a runtime request from being the first observer of drift.
    tracing::info!("Applying PostgreSQL migrations before ClickHouse work");
    let pg_db = Database::connect(&config.postgres_url)
        .await
        .context("connecting to PostgreSQL for migration preflight")?;
    let pg_pool = pg_db.pool();
    // NAN-5260: refuse before any DDL when the server is older than the
    // supported floor or a required extension is not allow-listed (Azure
    // flexible server `azure.extensions`, RDS `rds.allowed_extensions`).
    // A half-applied snapshot is far harder to recover than a clear message.
    // NAN-5269: the schema-`public` CREATE check only blocks when there is
    // something to apply; an up-to-date install with nothing pending warns.
    let core_pending = nanosiem_core::db::postgres_migrations_pending(pg_pool).await;
    #[cfg(feature = "enterprise")]
    let migrations_pending = core_pending || {
        let overlay = sqlx::migrate!("../migrations/postgres-enterprise");
        nanosiem_core::db::migrator_has_pending_work(pg_pool, &overlay, "enterprise").await
    };
    #[cfg(not(feature = "enterprise"))]
    let migrations_pending = core_pending;
    let preflight = nanosiem_core::db::check_postgres_compatibility(pg_pool, migrations_pending)
        .await
        .context("PostgreSQL compatibility preflight")?;
    if let Some(warning) = &preflight.schema_warning {
        tracing::warn!("{warning}");
    }
    tracing::info!(
        server_version = %preflight.server_version,
        platform = ?preflight.platform,
        to_create = ?preflight.creatable,
        "PostgreSQL preflight passed"
    );
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
    let schema_id = nanosiem_core::schema::SchemaId::from_env_str(&schema_raw).map_err(|e| {
        anyhow::anyhow!("invalid {}: {e}", nanosiem_core::schema::SCHEMA_PROFILE_ENV)
    })?;
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

        // Profile-only numbered migrations run after the overlay so fresh and
        // upgraded OCSF installs follow the same path. Their `_migrations`
        // versions are namespaced (`ocsf/NNN`) to avoid colliding with the
        // shared ledger number.
        let ocsf_migrations_dir = migrations_dir.join("ocsf").join("migrations");
        let ocsf_count = migrator
            .run_migrations_with_prefix(&ocsf_migrations_dir, "ocsf/")
            .await
            .context("running OCSF incremental migrations")?;
        tracing::info!(
            count = ocsf_count,
            "OCSF profile-specific migrations complete"
        );
    }

    // Enterprise overlay is mandatory in enterprise builds. A missing image
    // payload must stop migration instead of silently booting without the
    // license witness (or any future enterprise-only schema).
    #[cfg(feature = "enterprise")]
    {
        let enterprise_dir: PathBuf = std::env::var("CLICKHOUSE_ENTERPRISE_MIGRATIONS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./clickhouse-enterprise"));
        anyhow::ensure!(
            enterprise_dir.is_dir(),
            "enterprise ClickHouse overlay directory is missing: {}",
            enterprise_dir.display()
        );
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

    // NAN-2003: bootstrap the raw-SQL feature users BEFORE the row policies that
    // grant TO them. On an existing tenant they were never created (compose
    // `clickhouse-init.sh` is fresh-only; the k8s bootstrap Job was racy), which
    // left the policy step below dead on `UNKNOWN_ROLE` and the app fail-closed.
    // Idempotent: a no-op wherever the users already exist (open-core users.xml,
    // fresh managed). Runs on every migrate so it self-heals existing tenants.
    let rawsql_users_created = migrator
        .ensure_rawsql_users(
            config.clickhouse_rawsql_password.as_deref(),
            config.clickhouse_rawsql_noaudit_password.as_deref(),
        )
        .await
        .context("ensuring raw-SQL feature users (NAN-2003)")?;
    if rawsql_users_created > 0 {
        tracing::info!(
            "NAN-2003: bootstrapped {} raw-SQL feature user(s)",
            rawsql_users_created
        );
    }

    // NAN-2001: (re)create the raw-SQL audit row policies for
    // `nanosiem_rawsql_noaudit` on the physical (`_local` on clusters) tables.
    // Runs AFTER the distributed split + column reconcile so `_local` tables
    // exist; the grants that form the allowlist come from users.xml or the
    // bootstrap step above, so only the policies are created here. Idempotent.
    let policy_count = migrator
        .ensure_rawsql_row_policies()
        .await
        .context("ensuring raw-SQL audit row policies (NAN-2001)")?;
    tracing::info!(
        "NAN-2001: ensured raw-SQL audit row policies on {} table(s)",
        policy_count
    );

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
            "Updated {} dict-refresh MV query(ies) (distributed repoint / NAN-5262 result caps)",
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

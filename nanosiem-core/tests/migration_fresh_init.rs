// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for the NAN-749 fresh-init migration path.
//!
//! Exercises the four critical scenarios:
//!   1. Fresh path — empty DB → snapshot applies, history backfilled,
//!      enterprise tables absent.
//!   2. Legacy path — populated DB → snapshot is skipped, today's
//!      `sqlx::migrate!` runs unchanged.
//!   3. Belt-and-suspenders detection — `_sqlx_migrations` absent but a
//!      well-known nanosiem table present → still picks legacy path.
//!   4. Env-var kill switch — `NANOSIEM_MIGRATION_MODE=legacy` overrides
//!      detection on a fresh DB.
//!
//! Prerequisites: a Postgres reachable at `TEST_DATABASE_URL`
//! (default: postgres://nanosiem:nanosiem@localhost:5432/postgres).
//! The test creates a uniquely-named throwaway database (`nanosiem_nan749_test`)
//! and drops/recreates the public schema between scenarios. SKIP via
//! SKIP_DB_TESTS=1.
//!
//! Run: `cargo test --test migration_fresh_init -- --nocapture --test-threads=1`
//! (single-threaded because scenarios share one process env).

use nanosiem_core::db::migrations::repair_nan922_185_collision;
use nanosiem_core::db::run_postgres_migrations;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};

const TEST_DB_NAME: &str = "nanosiem_nan749_test";

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/postgres".to_string())
}

fn test_db_url() -> String {
    let admin = admin_url();
    // Replace the database segment of the URL with our test DB name.
    let last_slash = admin.rfind('/').expect("admin url must contain '/'");
    format!("{}/{}", &admin[..last_slash], TEST_DB_NAME)
}

/// Connect to the admin DB and (re)create the test DB.
async fn recreate_test_db() -> Result<(), sqlx::Error> {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await?;
    // Terminate any lingering connections so DROP succeeds.
    let _ = admin
        .execute(
            format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = '{}' AND pid <> pg_backend_pid()",
                TEST_DB_NAME
            )
            .as_str(),
        )
        .await;
    admin
        .execute(format!("DROP DATABASE IF EXISTS {}", TEST_DB_NAME).as_str())
        .await?;
    admin
        .execute(format!("CREATE DATABASE {}", TEST_DB_NAME).as_str())
        .await?;
    Ok(())
}

/// Drop and recreate the public schema in the test DB, returning a fresh pool.
async fn fresh_schema_pool() -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&test_db_url())
        .await?;
    pool.execute("DROP SCHEMA IF EXISTS public CASCADE").await?;
    pool.execute("CREATE SCHEMA public").await?;
    Ok(pool)
}

async fn count_table(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = $1",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .unwrap_or(-1)
}

async fn migration_row_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await
        .unwrap_or(-1)
}

#[tokio::test]
async fn nan749_fresh_init_path_creates_open_schema_and_backfills_history() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("SKIP_DB_TESTS set — skipping NAN-749 integration test");
        return;
    }
    if let Err(e) = recreate_test_db().await {
        eprintln!("Could not (re)create test DB at {}: {}", admin_url(), e);
        eprintln!("Run a Postgres reachable via TEST_DATABASE_URL or SKIP_DB_TESTS=1");
        return;
    }

    // ------------------------------------------------------------------
    // Scenario 1 — Fresh path. Empty schema → snapshot + backfill.
    // ------------------------------------------------------------------
    {
        let pool = fresh_schema_pool().await.expect("fresh schema");
        std::env::set_var("NANOSIEM_MIGRATION_MODE", "fresh");
        run_postgres_migrations(&pool)
            .await
            .expect("fresh path migrations succeed");
        std::env::remove_var("NANOSIEM_MIGRATION_MODE");

        // Open-tier table present
        assert_eq!(
            count_table(&pool, "users").await,
            1,
            "expected `users` to be created by snapshot"
        );
        assert_eq!(
            count_table(&pool, "detection_rules").await,
            1,
            "expected `detection_rules` to be created by snapshot"
        );
        // Enterprise tables MUST NOT exist after the open-only snapshot
        assert_eq!(
            count_table(&pool, "cases").await,
            0,
            "snapshot leaked enterprise table `cases` into open schema"
        );
        assert_eq!(
            count_table(&pool, "melod_jobs").await,
            0,
            "snapshot leaked enterprise table `melod_jobs` into open schema"
        );
        assert_eq!(
            count_table(&pool, "notebooks").await,
            0,
            "snapshot leaked enterprise table `notebooks` into open schema"
        );
        // Backfill brought 175+ rows into _sqlx_migrations
        let rows = migration_row_count(&pool).await;
        assert!(
            rows >= 175,
            "expected ≥175 rows in _sqlx_migrations, got {}",
            rows
        );

        // Re-running is a no-op (idempotent)
        run_postgres_migrations(&pool)
            .await
            .expect("re-run is a no-op");
        let rows_after = migration_row_count(&pool).await;
        assert_eq!(
            rows, rows_after,
            "re-running fresh path changed migration row count"
        );
    }

    // ------------------------------------------------------------------
    // Scenario 2 — Env override forces legacy on a fresh DB.
    // Snapshot is NOT applied; the legacy migrator runs everything.
    // Result: ALL tables present, including enterprise (since the
    // legacy 175 history still creates them).
    // ------------------------------------------------------------------
    {
        let pool = fresh_schema_pool().await.expect("fresh schema");
        std::env::set_var("NANOSIEM_MIGRATION_MODE", "legacy");
        run_postgres_migrations(&pool)
            .await
            .expect("legacy path migrations succeed");
        std::env::remove_var("NANOSIEM_MIGRATION_MODE");

        // All tables present (legacy path = today's behavior)
        assert_eq!(count_table(&pool, "users").await, 1);
        assert_eq!(count_table(&pool, "cases").await, 1, "legacy path runs all 175");
        let rows = migration_row_count(&pool).await;
        assert!(rows >= 175, "expected ≥175 _sqlx_migrations rows, got {}", rows);
    }

    // ------------------------------------------------------------------
    // Scenario 3 — Belt-and-suspenders detection.
    // Drop schema, manually create just `users`, then run with auto.
    // Detection should see the legacy table and pick the legacy path,
    // even though `_sqlx_migrations` is absent.
    // ------------------------------------------------------------------
    {
        let pool = fresh_schema_pool().await.expect("fresh schema");
        pool.execute("CREATE TABLE public.users (id uuid PRIMARY KEY)")
            .await
            .expect("seed users table");
        // No env var → auto. Detection should refuse to call this fresh.
        std::env::remove_var("NANOSIEM_MIGRATION_MODE");
        // The legacy migrator will then attempt to run all 175 — most will
        // fail because tables/types already exist. We don't care about
        // the migration result here; what we care about is that the
        // SNAPSHOT was NOT applied (which would have wiped the manual
        // users table … actually no, it's CREATE TABLE IF NOT EXISTS, so
        // it would just be a no-op + backfill 175 rows). The dangerous
        // case is the BACKFILL writing 175 rows into _sqlx_migrations.
        // After the call, _sqlx_migrations should NOT have 175 rows
        // because the legacy path didn't take a backfill route.
        let result = run_postgres_migrations(&pool).await;
        // Legacy migrator will probably error on duplicate `users` table
        // since the migration tries to CREATE TABLE users without IF NOT
        // EXISTS. That's fine — we only assert that it took the legacy
        // path. Two-pronged check:
        // (a) backfill did NOT run (rows < 175)
        // (b) enterprise tables were NOT created — neither the
        //     fresh-snapshot path nor the failing-legacy path got far
        //     enough to create `cases`. If the snapshot HAD run, the
        //     CREATE TABLE IF NOT EXISTS for cases would be absent (good)
        //     but the BACKFILL still would have written 175 rows. So (a)
        //     is the canonical signal; (b) reinforces it.
        let _ = result; // we don't care if migrate errored
        let rows = migration_row_count(&pool).await;
        assert!(
            rows < 175,
            "snapshot leaked: backfill ran on populated schema (got {} rows)",
            rows
        );
        assert_eq!(
            count_table(&pool, "cases").await,
            0,
            "neither fresh path nor legacy migrator should have created \
             enterprise table `cases` in this scenario"
        );
    }

    // ------------------------------------------------------------------
    // Scenario 4 — Auto mode on truly fresh DB → snapshot path.
    // (Symmetric to scenario 1 but exercises the actual auto-detect
    // logic rather than the env override.)
    // ------------------------------------------------------------------
    {
        let pool = fresh_schema_pool().await.expect("fresh schema");
        std::env::remove_var("NANOSIEM_MIGRATION_MODE");
        run_postgres_migrations(&pool)
            .await
            .expect("auto-detect on fresh DB succeeds");

        assert_eq!(count_table(&pool, "users").await, 1);
        assert_eq!(
            count_table(&pool, "cases").await,
            0,
            "auto-detect on fresh DB should pick fresh path → no enterprise tables"
        );
    }
}

// ============================================================================
// NAN-926 — auto-repair the NAN-922 migration-185 rename collision.
//
// The fixture shape mirrors the broken tenant: `_sqlx_migrations` exists with
// a single row at version=185 whose description is the old brand-rename slug
// and whose checksum does NOT match the post-NAN-922 file at that version.
// We don't seed 1..=184 because `repair_nan922_185_collision` is independent
// of the rest of the migration history — its three signals all live in the
// `_sqlx_migrations` table itself.
// ============================================================================

/// Create just the `_sqlx_migrations` table (matching sqlx's own schema) and
/// return the pool. Used to set up the four NAN-926 scenarios without
/// dragging in the open-init snapshot.
async fn schema_with_empty_sqlx_migrations() -> PgPool {
    let pool = fresh_schema_pool().await.expect("fresh schema");
    pool.execute(
        "CREATE TABLE public._sqlx_migrations ( \
            version BIGINT PRIMARY KEY, \
            description TEXT NOT NULL, \
            installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), \
            success BOOLEAN NOT NULL, \
            checksum BYTEA NOT NULL, \
            execution_time BIGINT NOT NULL \
        )",
    )
    .await
    .expect("create _sqlx_migrations");
    pool
}

async fn insert_migration_row(pool: &PgPool, version: i64, description: &str) {
    sqlx::query(
        "INSERT INTO public._sqlx_migrations \
           (version, description, success, checksum, execution_time) \
         VALUES ($1, $2, TRUE, $3, 1000)",
    )
    .bind(version)
    .bind(description)
    // Arbitrary 20-byte checksum — the repair function never compares it,
    // it only looks at description + version=187 absence.
    .bind(vec![0u8; 20])
    .execute(pool)
    .await
    .expect("insert _sqlx_migrations row");
}

async fn version_present(pool: &PgPool, version: i64) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM public._sqlx_migrations WHERE version = $1)",
    )
    .bind(version)
    .fetch_one(pool)
    .await
    .unwrap_or(false)
}

#[tokio::test]
async fn nan926_repair_deletes_poisoned_185_when_187_absent() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        return;
    }
    if let Err(e) = recreate_test_db().await {
        eprintln!("Could not (re)create test DB at {}: {}", admin_url(), e);
        return;
    }

    // Poisoned legacy tenant: 185 = old brand-rename, 187 not present.
    let pool = schema_with_empty_sqlx_migrations().await;
    insert_migration_row(&pool, 185, "brand rename system ai").await;

    repair_nan922_185_collision(&pool)
        .await
        .expect("repair succeeds");

    assert!(
        !version_present(&pool, 185).await,
        "repair should have deleted the poisoned version=185 row"
    );

    // Idempotent: a second call on the now-clean DB is a no-op.
    repair_nan922_185_collision(&pool)
        .await
        .expect("second call is a no-op");
    assert!(!version_present(&pool, 185).await);
}

#[tokio::test]
async fn nan926_repair_leaves_healthy_185_alone() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        return;
    }
    if let Err(e) = recreate_test_db().await {
        eprintln!("Could not (re)create test DB at {}: {}", admin_url(), e);
        return;
    }

    // Post-rename healthy state: 185 = new HEC seed migration, 187 present.
    let pool = schema_with_empty_sqlx_migrations().await;
    insert_migration_row(&pool, 185, "seed splunk hec routing rules").await;
    insert_migration_row(&pool, 187, "brand rename system ai").await;

    repair_nan922_185_collision(&pool)
        .await
        .expect("repair succeeds");

    assert!(
        version_present(&pool, 185).await,
        "repair must not touch a healthy 185 row"
    );
    assert!(version_present(&pool, 187).await);
}

#[tokio::test]
async fn nan926_repair_is_noop_when_187_already_landed() {
    // Edge case: somehow both the poisoned 185 description AND a 187 row
    // exist. This can't happen via the normal migrator path, but if a
    // tenant manually re-applied the brand-rename at 187 and then forgot
    // to clean up the old row, the repair must NOT delete the 185 row a
    // second time (the new file's checksum is already there).
    //
    // Reality: the description check would have to also match — i.e. the
    // tenant's 185 row still has the old brand-rename description. In that
    // pathological case the safe move is "do nothing", because we'd be
    // deleting the row that records the new 185 application. The 187-absent
    // signal is what makes this safe; this test pins the behavior.
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        return;
    }
    if let Err(e) = recreate_test_db().await {
        eprintln!("Could not (re)create test DB at {}: {}", admin_url(), e);
        return;
    }

    let pool = schema_with_empty_sqlx_migrations().await;
    insert_migration_row(&pool, 185, "brand rename system ai").await;
    insert_migration_row(&pool, 187, "brand rename system ai").await;

    repair_nan922_185_collision(&pool)
        .await
        .expect("repair succeeds");

    assert!(
        version_present(&pool, 185).await,
        "with 187 present the repair must leave 185 alone"
    );
    assert!(version_present(&pool, 187).await);
}

#[tokio::test]
async fn nan926_repair_is_noop_without_sqlx_migrations_table() {
    // Fresh DB: the migrator hasn't bootstrapped _sqlx_migrations yet. The
    // repair must not fail with "relation does not exist" — it should
    // detect the missing table and return Ok.
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        return;
    }
    if let Err(e) = recreate_test_db().await {
        eprintln!("Could not (re)create test DB at {}: {}", admin_url(), e);
        return;
    }
    let pool = fresh_schema_pool().await.expect("fresh schema");

    repair_nan922_185_collision(&pool)
        .await
        .expect("repair is a no-op when _sqlx_migrations is absent");
}

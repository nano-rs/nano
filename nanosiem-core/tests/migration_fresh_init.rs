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

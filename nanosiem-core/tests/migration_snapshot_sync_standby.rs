// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5269: the open-init snapshot never waits forever on a synchronous
//! standby that is not there.
//!
//! A Patroni cluster in `synchronous_mode` names a synchronous standby in
//! `synchronous_standby_names`; while that standby is not streaming, every
//! commit waits for it, and the snapshot's single commit would wait forever.
//! The migrator must notice before it applies anything and fail with nothing
//! applied.
//!
//! Needs a DISPOSABLE PostgreSQL superuser at `TEST_DATABASE_URL`: the test
//! sets `synchronous_standby_names` server-wide with ALTER SYSTEM and resets
//! it. There is deliberately no localhost default: pointed at a developer's
//! running stack, a stray ALTER SYSTEM would make every commit on that server
//! wait forever. Skipped when `TEST_DATABASE_URL` is unset or SKIP_DB_TESTS=1.
//! The two scenarios hold one lock, so a parallel test run cannot let the
//! first one's server-wide setting stall the second. Takes about a minute.
//!
//! Run: `cargo test -p nanosiem-core --test migration_snapshot_sync_standby -- --nocapture --test-threads=1`
//! (single-threaded: the scenarios set process env).

use nanosiem_core::db::run_postgres_migrations;
use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;

/// Serializes the scenarios: one sets a server-wide setting and both set
/// process env.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const TEST_DB_NAME: &str = "nanosiem_nan5269_test";

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL").expect("checked by disposable_server_url")
}

/// The disposable server, or None (skip) when none is configured.
fn disposable_server_url() -> Option<String> {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        return None;
    }
    match std::env::var("TEST_DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("TEST_DATABASE_URL is not set (a disposable PostgreSQL superuser); skipping NAN-5269 test");
            None
        }
    }
}

fn test_db_url() -> String {
    let admin = admin_url();
    let last_slash = admin.rfind('/').expect("admin url must contain '/'");
    format!("{}/{}", &admin[..last_slash], TEST_DB_NAME)
}

#[tokio::test]
async fn snapshot_refuses_before_any_ddl_when_no_synchronous_standby_streams() {
    if disposable_server_url().is_none() {
        return;
    }
    let _serial = SERIAL.lock().await;
    let admin = match PgPoolOptions::new().max_connections(1).connect(&admin_url()).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("Could not connect to {}: {error}; skipping", admin_url());
            return;
        }
    };
    admin
        .execute(format!("DROP DATABASE IF EXISTS {TEST_DB_NAME} WITH (FORCE)").as_str())
        .await
        .expect("drop test db");
    admin
        .execute(format!("CREATE DATABASE {TEST_DB_NAME}").as_str())
        .await
        .expect("create test db");
    admin
        .execute("ALTER SYSTEM SET synchronous_standby_names = 'nano_missing_standby'")
        .await
        .expect("needs a superuser on a disposable server");
    admin.execute("SELECT pg_reload_conf()").await.expect("reload");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&test_db_url())
        .await;
    let started = std::time::Instant::now();
    let outcome = match &pool {
        Ok(pool) => {
            std::env::set_var("NANOSIEM_MIGRATION_MODE", "fresh");
            std::env::set_var("NANO_PG_SNAPSHOT_TIMEOUT_SECS", "30");
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(120),
                run_postgres_migrations(pool),
            )
            .await;
            std::env::remove_var("NANOSIEM_MIGRATION_MODE");
            std::env::remove_var("NANO_PG_SNAPSHOT_TIMEOUT_SECS");
            Some(outcome)
        }
        Err(_) => None,
    };

    // Restore the server before anything that can fail: a reset skipped by a
    // panic would leave every commit on this server waiting forever.
    admin
        .execute("ALTER SYSTEM RESET synchronous_standby_names")
        .await
        .expect("reset");
    admin.execute("SELECT pg_reload_conf()").await.expect("reload");

    let pool = pool.expect("test pool");
    let outcome = outcome.expect("ran with a pool");
    let users: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = 'users')",
    )
    .fetch_one(&pool)
    .await
    .expect("table probe");

    let error = outcome
        .expect("the migrator must end on its own, never hang")
        .expect_err("no synchronous standby: the snapshot must be refused");
    let text = error.to_string();
    assert!(text.contains("nothing was applied"), "{text}");
    assert!(text.contains("nano_missing_standby"), "{text}");
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
    assert!(!users, "no DDL may run before the commit path is known to work");

    // With replication back to asynchronous the same database installs.
    std::env::set_var("NANOSIEM_MIGRATION_MODE", "fresh");
    run_postgres_migrations(&pool)
        .await
        .expect("fresh install succeeds once commits can complete");
    std::env::remove_var("NANOSIEM_MIGRATION_MODE");
}

/// A snapshot that blocks (here: on a lock another session holds) ends at the
/// budget with a diagnosis, its session is ended, and nothing is applied.
#[tokio::test]
async fn a_stuck_snapshot_ends_at_its_budget_and_rolls_back() {
    if disposable_server_url().is_none() {
        return;
    }
    let _serial = SERIAL.lock().await;
    let admin = match PgPoolOptions::new().max_connections(1).connect(&admin_url()).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("Could not connect to {}: {error}; skipping", admin_url());
            return;
        }
    };
    let name = "nanosiem_nan5269_stuck_test";
    admin
        .execute(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)").as_str())
        .await
        .expect("drop test db");
    admin
        .execute(format!("CREATE DATABASE {name}").as_str())
        .await
        .expect("create test db");
    let url = {
        let admin_url = admin_url();
        let last_slash = admin_url.rfind('/').expect("admin url must contain '/'");
        format!("{}/{}", &admin_url[..last_slash], name)
    };
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .expect("test pool");

    // Another session creates the snapshot's first extension and keeps its
    // transaction open: the snapshot's CREATE EXTENSION waits on it.
    let mut holder = pool.acquire().await.expect("holder");
    holder.execute("BEGIN").await.expect("begin");
    holder
        .execute("CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public")
        .await
        .expect("hold");

    std::env::set_var("NANOSIEM_MIGRATION_MODE", "fresh");
    std::env::set_var("NANO_PG_SNAPSHOT_TIMEOUT_SECS", "30");
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        run_postgres_migrations(&pool),
    )
    .await;
    std::env::remove_var("NANOSIEM_MIGRATION_MODE");
    std::env::remove_var("NANO_PG_SNAPSHOT_TIMEOUT_SECS");
    holder.execute("ROLLBACK").await.expect("release");
    drop(holder);

    let error = outcome
        .expect("the migrator must end on its own, never hang")
        .expect_err("a blocked snapshot must fail at its budget");
    let text = error.to_string();
    assert!(text.contains("did not finish within 30 s"), "{text}");
    assert!(text.contains("waiting on Lock/"), "{text}");
    assert!(text.contains("rolled back"), "{text}");
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
    let users: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = 'users')",
    )
    .fetch_one(&pool)
    .await
    .expect("table probe");
    assert!(!users, "the snapshot is one transaction: nothing may remain");

    // A rerun on the same database succeeds.
    std::env::set_var("NANOSIEM_MIGRATION_MODE", "fresh");
    run_postgres_migrations(&pool)
        .await
        .expect("rerun succeeds once nothing blocks it");
    std::env::remove_var("NANOSIEM_MIGRATION_MODE");
}

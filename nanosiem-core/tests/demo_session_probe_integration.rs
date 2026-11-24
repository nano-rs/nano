// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5825: `is_demo_session_active` on an install without the demo schema
//! answers `false` without sending a statement PostgreSQL rejects (each one was
//! logged as `ERROR: relation "demo.sessions" does not exist` on every token
//! refresh), and on a demo install finds only active sessions (expired and
//! cleaned-up ones fail closed).
//!
//! Each case runs on its own freshly migrated scratch database (created and
//! dropped on the `DATABASE_URL` server), so the shared CI database is never
//! touched and the per-database probe cache starts empty. Runs in
//! pg-integration-tests:
//!
//!   cargo test -p nanosiem-core --test demo_session_probe_integration -- --ignored --test-threads=1

mod common;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

/// A brand-new migrated database; returns (admin pool, scratch pool, name).
/// The scratch pool holds ONE connection, so every statement in a case runs
/// on the same backend and its rollback counter is read deterministically.
async fn scratch_db(prefix: &str) -> (PgPool, PgPool, String) {
    let admin = common::migrated_pool().await;
    let name = format!("{prefix}_{}", Uuid::now_v7().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .expect("create scratch database");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let (head, query) = match base.split_once('?') {
        Some((h, q)) => (h.to_string(), format!("?{q}")),
        None => (base.clone(), String::new()),
    };
    let server = head.rsplit_once('/').map(|(s, _)| s).expect("database URL has a path");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{server}/{name}{query}"))
        .await
        .expect("connect scratch database");
    nanosiem_core::db::run_postgres_migrations(&pool)
        .await
        .expect("migrate scratch database");
    (admin, pool, name)
}

async fn drop_db(admin: PgPool, pool: PgPool, name: String) {
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")))
        .execute(&admin)
        .await
        .ok();
}

/// Transactions this pool's (single) backend has rolled back. A statement
/// PostgreSQL rejects in autocommit counts as one. The backend's pending
/// stats are flushed first, then the snapshot is cleared, all on the same
/// connection.
async fn rollbacks(pool: &PgPool) -> i64 {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_stat_force_next_flush()").execute(&mut *conn).await.unwrap();
    sqlx::query("SELECT 1").execute(&mut *conn).await.unwrap(); // flushes at its end
    sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *conn).await.unwrap();
    sqlx::query_scalar("SELECT xact_rollback FROM pg_stat_database WHERE datname = current_database()")
        .fetch_one(&mut *conn)
        .await
        .unwrap()
}

async fn insert_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Demo user', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("demo-{id}@example.test"))
    .execute(pool)
    .await
    .expect("insert user");
    id
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration-tests"]
async fn non_demo_install_never_queries_the_missing_relation() {
    let (admin, pool, name) = scratch_db("nan5825_plain").await;
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('demo.sessions') IS NOT NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!exists, "a migrated non-demo database has no demo schema");

    let before = rollbacks(&pool).await;
    for _ in 0..20 {
        assert!(!nanosiem_core::demo::is_demo_session_active(&pool, Uuid::new_v4()).await);
    }
    let after = rollbacks(&pool).await;
    drop_db(admin, pool, name).await;
    assert_eq!(after - before, 0, "a statement failed server-side ({} rollbacks)", after - before);
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration-tests"]
async fn demo_install_finds_only_active_sessions() {
    let (admin, pool, name) = scratch_db("nan5825_demo").await;
    // Read at runtime: a compile-time include of a path the open-core mirror
    // may strip would break the mirror build.
    let demo_sql = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../migrations/demo/001_demo_schema.sql"),
    )
    .expect("migrations/demo/001_demo_schema.sql");
    sqlx::raw_sql(sqlx::AssertSqlSafe(demo_sql)).execute(&pool).await.unwrap();

    let session = |user: Uuid, expires: &'static str, cleaned_up: bool| {
        let pool = pool.clone();
        async move {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO demo.sessions (token, user_id, expires_at, cleaned_up) VALUES ($1, $2, NOW() + INTERVAL '{expires}', $3)"
            )))
            .bind(Uuid::new_v4().simple().to_string())
            .bind(user)
            .bind(cleaned_up)
            .execute(&pool)
            .await
            .expect("insert demo session");
        }
    };
    let active = insert_user(&pool).await;
    let expired = insert_user(&pool).await;
    let cleaned = insert_user(&pool).await;
    let none = insert_user(&pool).await;
    session(active, "1 hour", false).await;
    session(expired, "-1 minute", false).await;
    session(cleaned, "1 hour", true).await;

    let before = rollbacks(&pool).await;
    let results = (
        nanosiem_core::demo::is_demo_session_active(&pool, active).await,
        nanosiem_core::demo::is_demo_session_active(&pool, expired).await,
        nanosiem_core::demo::is_demo_session_active(&pool, cleaned).await,
        nanosiem_core::demo::is_demo_session_active(&pool, none).await,
        nanosiem_core::demo::is_demo_session_active(&pool, Uuid::new_v4()).await,
    );
    let after = rollbacks(&pool).await;
    drop_db(admin, pool, name).await;
    assert_eq!(results, (true, false, false, false, false), "(active, expired, cleaned up, no session, unknown)");
    assert_eq!(after - before, 0, "no statement failed server-side");
}

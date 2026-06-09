// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared setup for the DB-backed integration suites (NAN-1272).
//!
//! Connects to the Postgres at `DATABASE_URL` (default: the docker-compose
//! `postgres` service) and applies the project migrations once per test
//! binary via the canonical [`run_postgres_migrations`] runner — the same path
//! the API uses at boot, so the test schema matches production exactly.
//!
//! Migration is guarded by a [`OnceCell`] so the parallel `#[tokio::test]`s in
//! a binary don't race the fresh-init snapshot (whose `CREATE TABLE`s aren't
//! advisory-locked the way `migrator.run()` is). These suites are `#[ignore]`d
//! so a plain `cargo test` skips them; the `pg-integration-tests` CI job (and
//! a local `docker compose up -d postgres`) runs them with `-- --ignored`.

use sqlx::PgPool;
use tokio::sync::OnceCell;

const DEFAULT_URL: &str = "postgres://nanosiem:nanosiem@localhost:5432/nanosiem";

static MIGRATED: OnceCell<()> = OnceCell::const_new();

/// A connected pool against a fully-migrated test database.
///
/// Panics with an actionable message if Postgres is unreachable — these tests
/// are `#[ignore]`d precisely because they need a live database.
#[allow(dead_code)] // not every test binary that `mod common`s uses every helper
pub async fn migrated_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let pool = PgPool::connect(&url).await.unwrap_or_else(|e| {
        panic!("connect to test Postgres at {url}: {e}\n(is `docker compose up -d postgres` running?)")
    });
    MIGRATED
        .get_or_init(|| async {
            nanosiem_core::db::run_postgres_migrations(&pool)
                .await
                .expect("apply Postgres migrations to the test database");
        })
        .await;
    pool
}

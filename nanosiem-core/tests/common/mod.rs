// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared setup for the DB-backed integration suites (NAN-1272).
//!
//! Connects to the test Postgres from the shared `nanosiem-test-db` helper
//! (`NANOSIEM_TEST_DATABASE_URL`, or the older `TEST_DATABASE_URL`; never
//! `DATABASE_URL`, NAN-5967) and applies the project migrations once per test
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

static MIGRATED: OnceCell<()> = OnceCell::const_new();

/// Strip credentials from a Postgres URL so panics can name the target
/// database without printing its password (NAN-5967: the shared helper).
#[allow(dead_code)]
pub fn redact_db_url(url: &str) -> String {
    nanosiem_test_db::redact(url)
}

/// Refuse to run against a database the operator has not explicitly sacrificed
/// (NAN-2215).
///
/// The DB-backed suites are destructive by construction: most begin by wiping
/// shared tables (`webhooks`, `restricted_source_types`, `alerts`, …) so cases
/// cannot leak state into one another. `DATABASE_URL` defaults to the LOCAL DEV
/// STACK's database, so simply running one of these suites on a developer
/// machine deletes real configuration with no warning and no undo.
///
/// This is not theoretical: during NAN-2207 validation a local run of
/// `webhook_delivery_integration` deleted the webhook a live end-to-end test was
/// using, which first presented as a product defect. NAN-2207 also added
/// `DELETE FROM restricted_source_types` to that suite — the per-source RBAC
/// registry — raising the cost of an accidental run from "lost webhooks" to
/// "silently un-restricted every source".
///
/// A name- or port-based heuristic cannot save us here: CI's throwaway
/// container uses `POSTGRES_DB=nanosiem`, the same database NAME as dev, on a
/// random port. Explicit consent is the only signal that distinguishes them.
#[allow(dead_code)]
pub fn assert_destructive_opt_in(url: &str) {
    nanosiem_test_db::assert_destructive_opt_in(&redact_db_url(url));
}

/// A connected pool against a fully-migrated test database.
///
/// Panics with an actionable message if Postgres is unreachable — these tests
/// are `#[ignore]`d precisely because they need a live database — or if the
/// destructive-test opt-in is absent (NAN-2215).
#[allow(dead_code)] // not every test binary that `mod common`s uses every helper
pub async fn migrated_pool() -> PgPool {
    let url = nanosiem_test_db::require_pg_url();
    // BEFORE connecting: the guard must fire ahead of any statement a suite
    // could issue, not merely ahead of the first DELETE.
    assert_destructive_opt_in(&url);
    let pool = nanosiem_test_db::connect_pg(nanosiem_test_db::pg_pool_options(10), &url).await;
    MIGRATED
        .get_or_init(|| async {
            nanosiem_core::db::run_postgres_migrations(&pool)
                .await
                .expect("apply Postgres migrations to the test database");
        })
        .await;
    pool
}

/// A pool whose sessions declare `key` as their credential write key, like
/// every api/jobs pool (NAN-4933 write fence). Secret writes through it are
/// fenced on `key` (registered, not retired), and stay allowed once the fence
/// is enforced for undeclared sessions.
#[allow(dead_code)]
pub async fn declared_pool(key: &str) -> PgPool {
    let url = nanosiem_test_db::require_pg_url();
    assert_destructive_opt_in(&url);
    nanosiem_core::crypto::rotation::declare_write_key(
        sqlx::postgres::PgPoolOptions::new().max_connections(4),
        key.to_owned(),
    )
    .connect(&url)
    .await
    .expect("connect declared pool")
}

/// Put the write fence back in rollout mode after a test that retired a key
/// (retirement enforces it), so later suites' undeclared fixtures still write.
#[allow(dead_code)]
pub async fn reset_write_fence(pool: &PgPool) {
    sqlx::query("UPDATE credential_write_fence_state SET enforce = FALSE, enforced_at = NULL, enforced_by = NULL")
        .execute(pool)
        .await
        .ok();
}

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

/// Explicit opt-in required before any DB-backed suite touches a database
/// (NAN-2215). See [`assert_destructive_opt_in`].
const DESTRUCTIVE_OPT_IN: &str = "NANOSIEM_ALLOW_DESTRUCTIVE_TESTS";

static MIGRATED: OnceCell<()> = OnceCell::const_new();

/// Strip credentials from a Postgres URL so panics can name the target database
/// without printing its password. Returns `host:port/dbname` when the URL is
/// well-formed, and a safe placeholder when it is not — never the raw string,
/// which is what carries the secret.
#[allow(dead_code)]
pub fn redact_db_url(url: &str) -> String {
    // postgres://user:pass@host:port/db?params -> host:port/db
    //
    // `splitn(2, …)`, not `split`: a password containing "://" would otherwise
    // truncate the remainder and the function would return the CREDENTIAL
    // segment — the one thing it exists to withhold.
    let after_scheme = url.splitn(2, "://").nth(1).unwrap_or("");
    let authority_and_path = after_scheme.rsplit('@').next().unwrap_or("");
    let without_query = authority_and_path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('/');
    if without_query.is_empty() {
        "<unparseable DATABASE_URL>".to_string()
    } else {
        without_query.to_string()
    }
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
    let opted_in = std::env::var(DESTRUCTIVE_OPT_IN)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE"))
        .unwrap_or(false);
    if opted_in {
        return;
    }
    panic!(
        "\n\
         refusing to run a DB-backed integration suite against {target}.\n\n\
         These suites DELETE FROM shared tables (webhooks, restricted_source_types,\n\
         alerts, …). DATABASE_URL defaults to the local dev stack's database, so\n\
         running them here would destroy real configuration.\n\n\
         If that database IS disposable, opt in explicitly:\n\
         \x20 {opt_in}=1 cargo test -p <crate> --test <suite> -- --ignored\n\n\
         For a throwaway instead: docker compose up -d postgres, and point\n\
         DATABASE_URL at it.\n",
        target = redact_db_url(url),
        opt_in = DESTRUCTIVE_OPT_IN,
    );
}

/// A connected pool against a fully-migrated test database.
///
/// Panics with an actionable message if Postgres is unreachable — these tests
/// are `#[ignore]`d precisely because they need a live database — or if the
/// destructive-test opt-in is absent (NAN-2215).
#[allow(dead_code)] // not every test binary that `mod common`s uses every helper
pub async fn migrated_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    // BEFORE connecting: the guard must fire ahead of any statement a suite
    // could issue, not merely ahead of the first DELETE.
    assert_destructive_opt_in(&url);
    let pool = PgPool::connect(&url).await.unwrap_or_else(|e| {
        // Redacted: the raw URL carries the password.
        panic!(
            "connect to test Postgres at {}: {e}\n(is `docker compose up -d postgres` running?)",
            redact_db_url(&url)
        )
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

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression test for NAN-1356: `GET /api/alerts` (AlertRepository::list) must
//! not 500 when an alert's `rule_id` is NULL.
//!
//! The `alerts_rule_id_fkey ... ON DELETE SET NULL` constraint sets `rule_id`
//! to NULL on every alert of a detection rule when that rule is deleted. The
//! `Alert` struct used to type `rule_id` as a non-optional `Uuid`, so
//! `sqlx::query_as::<_, Alert>` failed to decode the NULL and the entire alerts
//! list errored. `Alert.rule_id` is now `Option<Uuid>`.
//!
//! Gated like the other DB suites: compiles with every `cargo test` (catches
//! drift) but is `#[ignore]`d — run via the `pg-integration-tests` CI job, or
//! locally with `docker compose up -d postgres` and `cargo test -- --ignored`.

mod common;

use nanosiem_core::db::repository::AlertRepository;

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn list_does_not_error_on_null_rule_id() {
    let pool = common::migrated_pool().await;

    // The exact row state produced by deleting a rule (FK ON DELETE SET NULL):
    // an alert whose rule_id is NULL. Mirrors create_without_dedup's column set.
    sqlx::query(
        "INSERT INTO alerts (rule_id, severity, matched_events) \
         VALUES (NULL, 'high', '[]'::jsonb)",
    )
    .execute(&pool)
    .await
    .expect("insert alert with NULL rule_id");

    let repo = AlertRepository::new(pool.clone());

    // Pre-fix this 500'd while decoding column "rule_id": unexpected null.
    let alerts = repo
        .list(None, None, 100, 0)
        .await
        .expect("AlertRepository::list must not error on a NULL rule_id row");

    assert!(
        alerts.iter().any(|a| a.rule_id.is_none()),
        "the NULL-rule alert should be listed with rule_id = None"
    );
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! F-32(b): scheduled reports execute AS THE OWNER, so a disabled owner's
//! reports must stop being scheduled — independently of any caller. This
//! `#[ignore]`d DB-backed test (pg-integration CI: `cargo test -- --ignored`)
//! exercises the `claim_due_definitions` owner-active guard against a real
//! migrated Postgres, and is the schema-drift guard for that runtime `sqlx`.
//!
//! The complementary enforcement points are unit-level / handler-level and
//! covered elsewhere: `ReportService::run_and_record` fails an in-flight run for
//! a disabled owner (`ensure_owner_active`), and the `trigger_report` handler
//! 403s the admin-triggered path.

mod common;

use chrono::{Duration, Utc};
use nanosiem_core::auth::UserRepository;
use nanosiem_core::reports::{NewReportDefinition, ReportRepository, ReportSourceType};
use sqlx::PgPool;
use uuid::Uuid;

fn suffix() -> String {
    Uuid::now_v7().simple().to_string()[..16].to_string()
}

async fn create_user(pool: &PgPool, status: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Owner Disabled Test', 'x', $3, NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("owner-{id}@example.com"))
    .bind(status)
    .execute(pool)
    .await
    .expect("create user");
    id
}

/// A due, enabled definition owned by a DISABLED user is never claimed; enabling
/// the owner makes it claimable again.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn claim_skips_disabled_owner() {
    let pool = common::migrated_pool().await;
    let repo = ReportRepository::new(pool.clone());
    let user_repo = UserRepository::new(pool.clone());

    let sfx = suffix();
    let owner = create_user(&pool, "disabled").await;

    // Enabled + long-overdue (sorts FIRST by next_run_at ASC, so a batch of 100
    // is guaranteed to reach it) — the only reason it should NOT be claimed is
    // the disabled owner.
    let def = repo
        .create_definition(
            &NewReportDefinition {
                name: format!("owner-disabled-{sfx}"),
                description: None,
                source_type: ReportSourceType::Search,
                source_query: Some("error".to_string()),
                saved_query_id: None,
                source_dashboard_id: None,
                time_range_seconds: 3600,
                cron_expression: "0 * * * *".to_string(),
                owner_id: owner,
                enabled: true,
                retention_runs: 10,
            },
            Some(Utc::now() - Duration::days(1)),
        )
        .await
        .expect("create definition");

    // Disabled owner → not in the claimable set.
    let claimed = repo
        .claim_due_definitions(100, "f32b-node", 900)
        .await
        .expect("claim (owner disabled)");
    assert!(
        !claimed.iter().any(|c| c.definition.id == def.id),
        "a definition owned by a disabled user must not be claimed"
    );

    // Enable the owner → the still-due, still-unclaimed definition is claimable.
    user_repo.enable_user(owner).await.expect("enable owner");
    let claimed = repo
        .claim_due_definitions(100, "f32b-node", 900)
        .await
        .expect("claim (owner active)");
    assert!(
        claimed.iter().any(|c| c.definition.id == def.id),
        "once the owner is active the due definition must be claimable"
    );
}

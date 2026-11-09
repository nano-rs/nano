// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5039: a report query changed by a source-restricted non-owner records
//! that editor (migration 324), so runs execute under owner ∪ editor deny
//! sets. `#[ignore]`d PG suite (pg-integration lane).

mod common;

use nanosiem_core::reports::{NewReportDefinition, ReportRepository, ReportSourceType, UpdateReportDefinition};
use sqlx::PgPool;
use uuid::Uuid;

async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'NAN-5039', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("nan5039-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

fn query_edit(q: &str) -> UpdateReportDefinition {
    UpdateReportDefinition {
        name: None,
        description: None,
        source_query: Some(q.to_string()),
        time_range_seconds: None,
        cron_expression: None,
        enabled: None,
        retention_runs: None,
    }
}

async fn editor_of(pool: &PgPool, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT query_edited_by FROM report_definitions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read query_edited_by")
}

#[tokio::test]
#[ignore]
async fn a_restricted_non_owner_query_edit_is_recorded_and_owner_edits_reset_it() {
    let pool = common::migrated_pool().await;
    let repo = ReportRepository::new(pool.clone());
    let owner = create_user(&pool).await;
    let scoped_admin = create_user(&pool).await;
    let def = repo
        .create_definition(
            &NewReportDefinition {
                name: format!("nan5039-{owner}"),
                description: None,
                source_type: ReportSourceType::Search,
                source_query: Some("error".to_string()),
                saved_query_id: None,
                source_dashboard_id: None,
                time_range_seconds: 3600,
                cron_expression: "0 * * * *".to_string(),
                owner_id: owner,
                enabled: false,
                retention_runs: 10,
            },
            None,
        )
        .await
        .expect("create definition");
    assert_eq!(editor_of(&pool, def.id).await, None, "existing rows keep owner-only scope");

    // Exploit shape: a source-restricted admin rewrites someone else's query.
    repo.update_definition(def.id, &query_edit("source_type=hr_payroll"), None, Some(scoped_admin))
        .await
        .expect("edit");
    assert_eq!(editor_of(&pool, def.id).await, Some(scoped_admin));

    // Non-query edits keep the record.
    let mut rename = query_edit("x");
    rename.source_query = None;
    rename.name = Some("renamed".into());
    repo.update_definition(def.id, &rename, None, None).await.expect("rename");
    assert_eq!(editor_of(&pool, def.id).await, Some(scoped_admin));

    // Legitimate: the owner (or an unrestricted caller) re-saving the query
    // restores owner-only scope.
    repo.update_definition(def.id, &query_edit("error"), None, Some(owner))
        .await
        .expect("owner edit");
    assert_eq!(editor_of(&pool, def.id).await, None);
    repo.update_definition(def.id, &query_edit("error"), None, Some(scoped_admin))
        .await
        .expect("edit");
    repo.update_definition(def.id, &query_edit("error"), None, None)
        .await
        .expect("unrestricted edit");
    assert_eq!(editor_of(&pool, def.id).await, None);

    let _ = sqlx::query("DELETE FROM report_definitions WHERE id = $1")
        .bind(def.id)
        .execute(&pool)
        .await;
}

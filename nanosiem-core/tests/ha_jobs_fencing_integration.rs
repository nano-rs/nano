// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live-Postgres concurrency proofs for NAN-1781. These compile in the normal
//! suite and run in the existing `pg-integration-tests` lane with `--ignored`.

mod common;

use std::collections::HashMap;

use nanosiem_core::health::repository::{HealthNotification, HealthRepository};
use nanosiem_core::models::notification::NotificationType;
use nanosiem_core::{
    ColumnType, JobStatus, LookupColumn, LookupRepository, LookupService, NewLookupTable,
    SchedulerRepository,
};
use uuid::Uuid;

fn record(id: i64, value: &str) -> HashMap<String, serde_json::Value> {
    HashMap::from([
        ("id".to_string(), serde_json::json!(id)),
        ("value".to_string(), serde_json::json!(value)),
    ])
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn reclaimed_generation_fences_the_stale_job_owner() {
    let pool = common::migrated_pool().await;
    let suffix = Uuid::now_v7().simple().to_string();
    let lookup_name = format!("nan1781_claim_{}", &suffix[..12]);
    let physical_name = format!("lookup_{}", lookup_name);
    let lookup_id = Uuid::now_v7();
    let job_id = Uuid::now_v7();

    sqlx::query(
        r#"
        INSERT INTO lookup_tables_registry (id, name, table_name, columns)
        VALUES ($1, $2, $3, '[]'::jsonb)
        "#,
    )
    .bind(lookup_id)
    .bind(&lookup_name)
    .bind(&physical_name)
    .execute(&pool)
    .await
    .expect("seed lookup registry");
    sqlx::query(
        r#"
        INSERT INTO scheduled_jobs (
            id, name, cron_expression, url, destination_type,
            destination_config, parser_config, enabled, next_run_at,
            lookup_table_name
        ) VALUES (
            $1, $2, '* * * * *', 'https://example.com/feed.csv', 'lookup',
            jsonb_build_object('table_name', $3, 'mode', 'append'),
            '{"format":"csv","csv_delimiter":",","csv_has_headers":true,"custom_headers":null,"encoding":"utf-8","max_records":null,"skip_invalid":true}'::jsonb,
            true, NOW() - INTERVAL '1 minute', $3
        )
        "#,
    )
    .bind(job_id)
    .bind(format!("claim-{suffix}"))
    .bind(&lookup_name)
    .execute(&pool)
    .await
    .expect("seed scheduled job");

    let repo_a = SchedulerRepository::new(pool.clone());
    let repo_b = SchedulerRepository::new(pool.clone());
    let first = repo_a
        .claim_due_jobs(1, "node-a", 60)
        .await
        .expect("first claim")
        .pop()
        .expect("job claimed");
    sqlx::query(
        "UPDATE scheduled_jobs SET claimed_at = NOW() - INTERVAL '2 minutes' WHERE id = $1",
    )
    .bind(job_id)
    .execute(&pool)
    .await
    .expect("age first lease");
    let second = repo_b
        .claim_due_jobs(1, "node-b", 60)
        .await
        .expect("reclaim")
        .pop()
        .expect("stale job reclaimed");

    assert!(second.claim_generation > first.claim_generation);
    assert_eq!(second.claim_run_id, first.claim_run_id);
    assert!(!repo_a
        .renew_job_claim(job_id, "node-a", first.claim_generation)
        .await
        .expect("stale renewal query"));
    assert!(!repo_a
        .release_job_claim(
            job_id,
            "node-a",
            first.claim_generation,
            JobStatus::Success,
            None,
            None,
        )
        .await
        .expect("stale completion query"));
    assert!(repo_b
        .release_job_claim(
            job_id,
            "node-b",
            second.claim_generation,
            JobStatus::Success,
            None,
            None,
        )
        .await
        .expect("current completion query"));

    sqlx::query("DELETE FROM scheduled_jobs WHERE id = $1")
        .bind(job_id)
        .execute(&pool)
        .await
        .expect("delete job");
    sqlx::query("DELETE FROM lookup_tables_registry WHERE id = $1")
        .bind(lookup_id)
        .execute(&pool)
        .await
        .expect("delete lookup registry");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn append_replay_uses_the_same_rows_instead_of_duplicating() {
    let pool = common::migrated_pool().await;
    let suffix = Uuid::now_v7().simple().to_string();
    let table_name = format!("nan1781_append_{}", &suffix[..12]);
    let service = LookupService::new(LookupRepository::new(pool));
    service
        .create_table(
            NewLookupTable {
                name: table_name.clone(),
                description: None,
                columns: vec![
                    LookupColumn {
                        name: "id".to_string(),
                        data_type: ColumnType::Integer,
                        nullable: false,
                    },
                    LookupColumn {
                        name: "value".to_string(),
                        data_type: ColumnType::Text,
                        nullable: false,
                    },
                ],
                primary_key: Some("id".to_string()),
            },
            None,
        )
        .await
        .expect("create lookup");

    let run_id = Uuid::now_v7();
    let rows = vec![record(1, "one"), record(2, "two")];
    assert_eq!(
        service
            .insert_records_idempotent(&table_name, rows.clone(), run_id)
            .await
            .expect("first append"),
        2
    );
    assert_eq!(
        service
            .insert_records_idempotent(&table_name, rows, run_id)
            .await
            .expect("replayed append"),
        0
    );
    assert_eq!(
        service
            .get_table(&table_name)
            .await
            .expect("lookup metadata")
            .row_count,
        2
    );

    service.drop_table(&table_name).await.expect("drop lookup");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn concurrent_health_schedulers_create_one_notification() {
    let pool = common::migrated_pool().await;
    let suffix = Uuid::now_v7().simple().to_string();
    let user_id = Uuid::now_v7();
    let group_id = Uuid::now_v7();
    let issue_key = format!("nan1781-provider-{}", &suffix[..12]);

    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, status) VALUES ($1, $2, 'HA Test', 'x', 'active')",
    )
    .bind(user_id)
    .bind(format!("ha-{suffix}@example.com"))
    .execute(&pool)
    .await
    .expect("seed admin user");
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(group_id)
        .bind(format!("ha-{suffix}"))
        .execute(&pool)
        .await
        .expect("seed group");
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("seed membership");
    sqlx::query(
        "INSERT INTO group_roles (group_id, role_id) VALUES ($1, '00000000-0000-0000-0000-000000000001')",
    )
    .bind(group_id)
    .execute(&pool)
    .await
    .expect("seed admin role");

    let payload = HealthNotification {
        notification_type: NotificationType::AiProviderDown,
        title: "Provider down".to_string(),
        message: Some("unreachable".to_string()),
        link: Some("/settings/ai".to_string()),
        metadata: serde_json::json!({"provider": &issue_key}),
    };
    let repo_a = HealthRepository::new(pool.clone());
    let repo_b = HealthRepository::new(pool.clone());
    let (a, b) = tokio::join!(
        repo_a.notify_issue_once("ai_provider", &issue_key, &payload),
        repo_b.notify_issue_once("ai_provider", &issue_key, &payload),
    );
    let claims = [a.expect("scheduler A"), b.expect("scheduler B")]
        .into_iter()
        .filter(Option::is_some)
        .count();
    assert_eq!(claims, 1);
    let notifications: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND title = 'Provider down'",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("count notifications");
    assert_eq!(notifications, 1);

    sqlx::query("DELETE FROM notifications WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("delete notifications");
    sqlx::query("DELETE FROM health_issue_tracker WHERE issue_key = $1")
        .bind(&issue_key)
        .execute(&pool)
        .await
        .expect("delete issue");
    sqlx::query("DELETE FROM user_groups WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("delete membership");
    sqlx::query("DELETE FROM group_roles WHERE group_id = $1")
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("delete group role");
    sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("delete group");
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("delete user");
}

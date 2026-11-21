// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5721: deleting a user must not fail on records that name them.
//!
//! `siem_health_reports.triggered_by` (and eleven sibling author columns)
//! referenced `users(id)` with the default NO ACTION, so deleting anyone who
//! had ever run a health check failed with a foreign-key violation and the API
//! answered 500. Migration 396 makes them `ON DELETE SET NULL`.
//!
//! `#[ignore]`d DB-backed tests against a migrated throwaway Postgres:
//!
//! ```sh
//! NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 DATABASE_URL=postgres://…/throwaway \
//!   cargo test -p nanosiem-core --test user_delete_fk_integration -- --ignored
//! ```

mod common;

use nanosiem_core::auth::repository::UserRepositoryError;
use nanosiem_core::auth::UserRepository;
use nanosiem_core::siem_health::SuppressionRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'FK Delete Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("fk-delete-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

/// Every foreign key into `users` must either cascade or detach
/// (SET NULL / SET DEFAULT). A bare NO ACTION / RESTRICT reference makes
/// deleting any user who touched that table fail. New tables must pick one.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn no_user_foreign_key_blocks_deletion() {
    let pool = common::migrated_pool().await;
    let blocking: Vec<String> = sqlx::query_scalar(
        r#"SELECT conrelid::regclass::text || '.' || conname
             FROM pg_constraint
            WHERE contype = 'f'
              AND confrelid = 'public.users'::regclass
              AND confdeltype IN ('a', 'r')
              -- test fixtures from the StillReferenced case below
              AND conrelid::regclass::text NOT LIKE 'nan5721_%'
            ORDER BY 1"#,
    )
    .fetch_all(&pool)
    .await
    .expect("list user FKs");
    assert!(
        blocking.is_empty(),
        "these foreign keys to users(id) block user deletion; make them \
         ON DELETE SET NULL (records that must survive) or CASCADE (per-user \
         data): {blocking:?}"
    );
    // CASCADE is reserved for personal / identity data (migration 396 lists
    // the reasoning per table); everything else must survive the delete.
    const CASCADE_ALLOWED: &[&str] = &[
        "case_saved_searches.owner_id",
    // Demo deployments only: the ephemeral demo user's session row.
    "demo.sessions.user_id",
        "notebook_shares.shared_with_user_id",
        "notebook_tabs.user_id",
        "notebooks.owner_id",
        "notifications.user_id",
        "oidc_group_grant_sources.user_id",
        "onboarding_progress.user_id",
        "report_definitions.owner_id",
        "scim_group_members.user_id",
        "scim_users.user_id",
        "search_history.user_id",
        "sessions.user_id",
        "tuning_notifications.user_id",
        "user_groups.user_id",
        "user_recent_activity.user_id",
    ];
    let cascading: Vec<String> = sqlx::query_scalar(
        r#"SELECT c.conrelid::regclass::text || '.' || a.attname
             FROM pg_constraint c
             JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
            WHERE c.contype = 'f'
              AND c.confrelid = 'public.users'::regclass
              AND c.confdeltype = 'c'
            ORDER BY 1"#,
    )
    .fetch_all(&pool)
    .await
    .expect("list cascading user FKs");
    let unclassified: Vec<&String> = cascading
        .iter()
        .filter(|c| !CASCADE_ALLOWED.contains(&c.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "these user foreign keys CASCADE, deleting shared records with the user. \
         Make them ON DELETE SET NULL, or add them to CASCADE_ALLOWED if the data \
         is purely personal: {unclassified:?}"
    );
}

/// The reported bug end to end: a user who triggered a health report, created
/// and lifted a finding suppression, owns observability monitors, added a
/// marketplace repo and requested a GDPR anonymization can be deleted. Every
/// record survives with its author detached.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn deleting_user_detaches_health_reports_and_system_records() {
    let pool = common::migrated_pool().await;
    let repo = UserRepository::new(pool.clone());
    let user = create_user(&pool).await;
    let tag = &user.simple().to_string()[..12];

    let report: Uuid = sqlx::query_scalar(
        r#"INSERT INTO siem_health_reports
               (overall_score, overall_status, ingestion_score, parsing_score,
                detection_score, summary, triggered_by)
           VALUES (90, 'healthy', 90, 90, 90, 'nan5721', $1)
           RETURNING id"#,
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .expect("insert health report");

    let suppression: Uuid = sqlx::query_scalar(
        r#"INSERT INTO siem_health_finding_suppressions
               (finding_signature, title, reason, created_by, deactivated_by, deactivated_at)
           VALUES ($2, 'nan5721', 'test', $1, $1, NOW())
           RETURNING id"#,
    )
    .bind(user)
    .bind(format!("nan5721-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("insert suppression");

    let slo: Uuid = sqlx::query_scalar(
        r#"INSERT INTO observability_slos
               (name, service, sli_kind, target, window_days, created_by)
           VALUES ($2, 'svc', 'availability', 0.99, 30, $1) RETURNING id"#,
    )
    .bind(user)
    .bind(format!("nan5721-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("insert slo");

    let synthetic: Uuid = sqlx::query_scalar(
        r#"INSERT INTO observability_synthetic_checks
               (name, target_url, interval_secs, created_by)
           VALUES ($2, 'https://example.com', 60, $1) RETURNING id"#,
    )
    .bind(user)
    .bind(format!("nan5721-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("insert synthetic check");

    let monitor: Uuid = sqlx::query_scalar(
        r#"INSERT INTO observability_metric_monitors
               (name, metric_name, agg, comparator, threshold, window_secs,
                eval_interval_secs, created_by)
           VALUES ($2, 'm', 'avg', 'gt', 1.0, 60, 60, $1) RETURNING id"#,
    )
    .bind(user)
    .bind(format!("nan5721-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("insert metric monitor");

    let marketplace_repo: Uuid = sqlx::query_scalar(
        r#"INSERT INTO enrichment_marketplace_repos (name, slug, url, created_by)
           VALUES ($2, $2, 'https://example.com/repo.git', $1) RETURNING id"#,
    )
    .bind(user)
    .bind(format!("nan5721-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("insert marketplace repo");

    let gdpr: Uuid = sqlx::query_scalar(
        r#"INSERT INTO gdpr_anonymization_requests
               (identifier_type, identifier_hash, requested_by)
           VALUES ('username', $2, $1) RETURNING id"#,
    )
    .bind(user)
    .bind(format!("nan5721-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("insert gdpr request");

    let feedback: Uuid = sqlx::query_scalar(
        r#"INSERT INTO feedback (user_id, category, title, description)
           VALUES ($1, 'bug', 'nan5721', 'open bug report') RETURNING id"#,
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .expect("insert feedback");

    repo.delete_user(user)
        .await
        .expect("deleting a user who ran a health check must succeed");

    let gone: bool = sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(gone, "user row must be deleted");

    for (table, column, id) in [
        ("siem_health_reports", "triggered_by", report),
        ("siem_health_finding_suppressions", "created_by", suppression),
        ("siem_health_finding_suppressions", "deactivated_by", suppression),
        ("observability_slos", "created_by", slo),
        ("observability_synthetic_checks", "created_by", synthetic),
        ("observability_metric_monitors", "created_by", monitor),
        ("enrichment_marketplace_repos", "created_by", marketplace_repo),
        ("gdpr_anonymization_requests", "requested_by", gdpr),
        ("feedback", "user_id", feedback),
    ] {
        let author: Option<Option<Uuid>> =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT {column} FROM {table} WHERE id = $1")))
                .bind(id)
                .fetch_optional(&pool)
                .await
                .unwrap_or_else(|e| panic!("read {table}: {e}"));
        assert_eq!(
            author,
            Some(None),
            "{table} row must survive the delete with {column} detached"
        );
    }

    // The repository models read the detached author as None.
    let suppressions = SuppressionRepository::new(pool.clone())
        .list_all()
        .await
        .expect("list suppressions");
    let row = suppressions
        .iter()
        .find(|s| s.id == suppression)
        .expect("suppression listed");
    assert_eq!(row.created_by, None);
    assert_eq!(row.deactivated_by, None);
}

/// Should a future table add a bare `REFERENCES users(id)`, the delete is
/// refused as `StillReferenced` (the API's 409), not a raw database error
/// (the API's 500), and the user survives.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn remaining_fk_violation_maps_to_still_referenced() {
    let pool = common::migrated_pool().await;
    let repo = UserRepository::new(pool.clone());
    let user = create_user(&pool).await;

    let table = format!("nan5721_{}", &user.simple().to_string()[..12]);
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TABLE {table} (id SERIAL PRIMARY KEY, owner UUID REFERENCES users(id))"
    )))
    .execute(&pool)
    .await
    .expect("create fixture table");
    sqlx::query(sqlx::AssertSqlSafe(format!("INSERT INTO {table} (owner) VALUES ($1)")))
        .bind(user)
        .execute(&pool)
        .await
        .expect("insert fixture row");

    let err = repo.delete_user(user).await.expect_err("bare FK must block");

    sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE {table}")))
        .execute(&pool)
        .await
        .expect("drop fixture table");

    match err {
        UserRepositoryError::StillReferenced { constraint } => {
            assert!(constraint.starts_with(&table), "constraint = {constraint}")
        }
        other => panic!("expected StillReferenced, got {other:?}"),
    }
    let kept: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(kept, "a refused delete must roll back");
}

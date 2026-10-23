// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2065: durable report definitions must not preserve capabilities or
//! dashboard ACLs after they are revoked.
//!
//! These ignored DB-backed tests exercise the scheduler's authoritative,
//! no-cache resolver against a real migrated PostgreSQL schema.

mod common;

use nanosiem_core::auth::permissions;
use nanosiem_core::models::NewDashboard;
use nanosiem_core::reports::{
    report_run_requires_search_sql, NewReportDefinition, RenderedArtifact,
    ReportAuthorizationError, ReportAuthorizer, ReportRepository, ReportSourceType,
};
use nanosiem_core::DashboardRepository;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

struct OwnerFixture {
    user_id: Uuid,
    group_id: Uuid,
    role_id: Uuid,
}

async fn owner_fixture(pool: &PgPool) -> OwnerFixture {
    let user_id = Uuid::now_v7();
    let group_id = Uuid::now_v7();
    let role_id = Uuid::now_v7();
    let suffix = user_id.simple();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Report Authorization Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(user_id)
    .bind(format!("report-authz-{suffix}@example.com"))
    .execute(pool)
    .await
    .expect("create owner");
    // Fresh tenants automatically add every user to the seeded Everyone /
    // ReadOnly role, which already grants search:execute and dashboards:view.
    // Remove that ambient membership so each authorization transition below is
    // controlled only by this fixture's explicit grants and revocations.
    sqlx::query("DELETE FROM user_groups WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("remove ambient Everyone membership");
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(group_id)
        .bind(format!("report-authz-group-{suffix}"))
        .execute(pool)
        .await
        .expect("create group");
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(format!("report-authz-role-{suffix}"))
        .execute(pool)
        .await
        .expect("create role");
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(group_id)
        .execute(pool)
        .await
        .expect("create membership");
    sqlx::query("INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2)")
        .bind(group_id)
        .bind(role_id)
        .execute(pool)
        .await
        .expect("assign role");
    OwnerFixture {
        user_id,
        group_id,
        role_id,
    }
}

async fn grant(pool: &PgPool, role_id: Uuid, permission: &str) {
    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(role_id)
    .bind(permission)
    .execute(pool)
    .await
    .expect("grant permission");
}

async fn revoke(pool: &PgPool, role_id: Uuid, permission: &str) {
    sqlx::query("DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2")
        .bind(role_id)
        .bind(permission)
        .execute(pool)
        .await
        .expect("revoke permission");
}

async fn definition(
    pool: &PgPool,
    owner_id: Uuid,
    source_type: ReportSourceType,
    dashboard_id: Option<Uuid>,
) -> nanosiem_core::reports::ReportDefinition {
    ReportRepository::new(pool.clone())
        .create_definition(
            &NewReportDefinition {
                name: format!("report-authz-{}", Uuid::now_v7().simple()),
                description: None,
                source_type,
                source_query: (source_type == ReportSourceType::Search)
                    .then(|| "error".to_string()),
                saved_query_id: None,
                source_dashboard_id: dashboard_id,
                time_range_seconds: 3600,
                cron_expression: "0 * * * *".to_string(),
                owner_id,
                enabled: false,
                retention_runs: 10,
            },
            None,
        )
        .await
        .expect("create definition")
}

fn assert_denied<T>(result: Result<T, ReportAuthorizationError>, needle: &str) {
    match result {
        Err(ReportAuthorizationError::Denied(message)) => {
            assert!(
                message.contains(needle),
                "{message:?} did not contain {needle:?}"
            );
        }
        Err(other) => panic!("expected authorization denial, got {other}"),
        Ok(_) => panic!("expected authorization denial"),
    }
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn search_execution_tracks_zero_unrelated_revoked_and_restored_capability() {
    let pool = common::migrated_pool().await;
    let owner = owner_fixture(&pool).await;
    let report = definition(&pool, owner.user_id, ReportSourceType::Search, None).await;
    let authorizer = ReportAuthorizer::new(pool.clone());

    assert_denied(
        authorizer.authorize_execution(&report).await,
        permissions::SEARCH_EXECUTE,
    );

    grant(&pool, owner.role_id, permissions::DASHBOARDS_VIEW).await;
    assert_denied(
        authorizer.authorize_execution(&report).await,
        permissions::SEARCH_EXECUTE,
    );

    grant(&pool, owner.role_id, permissions::SEARCH_EXECUTE).await;
    authorizer
        .authorize_execution(&report)
        .await
        .expect("required capability allows execution");

    revoke(&pool, owner.role_id, permissions::SEARCH_EXECUTE).await;
    assert_denied(
        authorizer.authorize_execution(&report).await,
        permissions::SEARCH_EXECUTE,
    );

    grant(&pool, owner.role_id, permissions::SEARCH_EXECUTE).await;
    authorizer
        .authorize_execution(&report)
        .await
        .expect("restoration allows a new execution");
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn dashboard_execution_tracks_acl_and_capability_revocation_and_restoration() {
    let pool = common::migrated_pool().await;
    let owner = owner_fixture(&pool).await;
    grant(&pool, owner.role_id, permissions::SEARCH_EXECUTE).await;
    grant(&pool, owner.role_id, permissions::DASHBOARDS_VIEW).await;

    let dashboard_owner = owner_fixture(&pool).await;
    let dashboard = DashboardRepository::new(pool.clone())
        .create(&NewDashboard {
            name: format!("report-authz-dashboard-{}", Uuid::now_v7().simple()),
            description: None,
            layout: json!({}),
            panels: json!([]),
            refresh_interval: None,
            owner_id: Some(dashboard_owner.user_id),
            visibility: "group".to_string(),
        })
        .await
        .expect("create dashboard");
    sqlx::query("INSERT INTO dashboard_groups (dashboard_id, group_id) VALUES ($1, $2)")
        .bind(dashboard.id)
        .bind(owner.group_id)
        .execute(&pool)
        .await
        .expect("share dashboard");

    let report = definition(
        &pool,
        owner.user_id,
        ReportSourceType::Dashboard,
        Some(dashboard.id),
    )
    .await;
    let authorizer = ReportAuthorizer::new(pool.clone());
    authorizer
        .authorize_execution(&report)
        .await
        .expect("capabilities and ACL allow execution");

    sqlx::query("DELETE FROM dashboard_groups WHERE dashboard_id = $1 AND group_id = $2")
        .bind(dashboard.id)
        .bind(owner.group_id)
        .execute(&pool)
        .await
        .expect("revoke dashboard share");
    assert_denied(
        authorizer.authorize_execution(&report).await,
        "no longer has access",
    );

    sqlx::query("INSERT INTO dashboard_groups (dashboard_id, group_id) VALUES ($1, $2)")
        .bind(dashboard.id)
        .bind(owner.group_id)
        .execute(&pool)
        .await
        .expect("restore dashboard share");
    authorizer
        .authorize_execution(&report)
        .await
        .expect("restored ACL allows a new execution");

    revoke(&pool, owner.role_id, permissions::DASHBOARDS_VIEW).await;
    assert_denied(
        authorizer.authorize_execution(&report).await,
        permissions::DASHBOARDS_VIEW,
    );
    grant(&pool, owner.role_id, permissions::DASHBOARDS_VIEW).await;
    authorizer
        .authorize_execution(&report)
        .await
        .expect("restored capability allows a new execution");
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn raw_sql_dashboard_requires_current_capability_and_stamps_artifact_scope() {
    let pool = common::migrated_pool().await;
    let owner = owner_fixture(&pool).await;
    grant(&pool, owner.role_id, permissions::SEARCH_EXECUTE).await;
    grant(&pool, owner.role_id, permissions::DASHBOARDS_VIEW).await;

    let dashboard = DashboardRepository::new(pool.clone())
        .create(&NewDashboard {
            name: format!("report-sql-dashboard-{}", Uuid::now_v7().simple()),
            description: None,
            layout: json!({}),
            panels: json!([{
                "title": "Authorization probe",
                "queryMode": "sql",
                "query": "SELECT 424242 AS authorization_probe",
                "visualizationType": "table"
            }]),
            refresh_interval: None,
            owner_id: Some(owner.user_id),
            visibility: "private".to_string(),
        })
        .await
        .expect("create SQL dashboard");
    let report = definition(
        &pool,
        owner.user_id,
        ReportSourceType::Dashboard,
        Some(dashboard.id),
    )
    .await;
    let authorizer = ReportAuthorizer::new(pool.clone());

    assert_denied(
        authorizer.authorize_execution(&report).await,
        permissions::SEARCH_SQL,
    );

    grant(&pool, owner.role_id, permissions::SEARCH_SQL).await;
    let authorization = authorizer
        .authorize_execution(&report)
        .await
        .expect("search:sql allows the SQL-panel report");
    assert!(authorization.requires_search_sql());
    assert_eq!(
        authorization
            .dashboard_authorization()
            .expect("authorized dashboard snapshot")
            .dashboard()
            .id,
        dashboard.id
    );

    let repository = ReportRepository::new(pool.clone());
    let run_id = Uuid::now_v7();
    repository
        .upsert_run_running(run_id, report.id, "manual")
        .await
        .expect("create running row");
    repository
        .store_run_success(
            run_id,
            report.id,
            None,
            1,
            None,
            false,
            false,
            &[RenderedArtifact {
                kind: "html".to_string(),
                filename: "sql-report.html".to_string(),
                content_type: "text/html".to_string(),
                content: b"424242".to_vec(),
            }],
            &[],
            true,
            authorization.requires_search_sql(),
            true,
        )
        .await
        .expect("store SQL run");
    let run_scope = repository
        .get_run_authorization_scope(run_id)
        .await
        .expect("run authorization scope");
    assert!(run_scope.has_artifacts);
    assert!(report_run_requires_search_sql(
        report.source_type,
        run_scope.requires_search_sql,
        run_scope.search_sql_requirement_complete,
    ));
    let artifact_id = repository
        .list_artifacts_meta(run_id)
        .await
        .expect("list artifacts")[0]
        .id;
    let artifact_scope = repository
        .get_artifact_scope(artifact_id)
        .await
        .expect("artifact authorization scope");
    assert!(report_run_requires_search_sql(
        report.source_type,
        artifact_scope.requires_search_sql,
        artifact_scope.search_sql_requirement_complete,
    ));

    revoke(&pool, owner.role_id, permissions::SEARCH_SQL).await;
    assert_denied(
        authorizer.authorize_execution(&report).await,
        permissions::SEARCH_SQL,
    );

    sqlx::query(
        r#"UPDATE dashboards
           SET panels = $2
           WHERE id = $1"#,
    )
    .bind(dashboard.id)
    .bind(json!([{
        "title": "nPL panel",
        "queryMode": "piped",
        "query": "error",
        "visualizationType": "table"
    }]))
    .execute(&pool)
    .await
    .expect("replace SQL panel with nPL");
    let npl_authorization = authorizer
        .authorize_execution(&report)
        .await
        .expect("nPL panels remain available without search:sql");
    assert!(!npl_authorization.requires_search_sql());

    // The current dashboard is nPL, but the frozen historical artifact retains
    // its SQL requirement. Read authorization must use the run stamp above.
    assert!(report_run_requires_search_sql(
        report.source_type,
        artifact_scope.requires_search_sql,
        artifact_scope.search_sql_requirement_complete,
    ));
}

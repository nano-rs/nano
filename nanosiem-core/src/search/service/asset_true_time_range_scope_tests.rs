// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2072 — source-scoped true asset time ranges.
//!
//! Pure tests pin the production planner's aggregate/raw routing and the
//! byte-identical unrestricted SQL. The ignored PostgreSQL-backed regression
//! resolves real grants through `SourceScopeResolver`, then passes that exact
//! `ScopeSet` into the production planner. It deliberately does not reproduce
//! asset field classification or source-scope SQL in test code.

use super::*;
use crate::auth::ScopeSet;
use crate::schema::{OcsfProfile, UdmProfile};

fn denied(items: &[&str]) -> ScopeSet {
    ScopeSet::from_denied(items.iter().map(|item| item.to_string()).collect())
}

#[test]
fn unrestricted_query_is_legacy_aggregate_sql_byte_for_byte() {
    let profile = UdmProfile::new();
    let hosts = vec!["ws-01".to_string()];
    let (sql, binds) = build_asset_true_time_range_query(
        &profile,
        "nanosiem.logs",
        "nanosiem.entity_time_range_agg",
        &[],
        &hosts,
        &[],
        &ScopeSet::unrestricted(),
    )
    .expect("host produces a query");

    assert_eq!(
        sql,
        "SELECT formatDateTime(min(first_seen), '%Y-%m-%dT%H:%i:%sZ') as first_seen, \
         formatDateTime(max(last_seen), '%Y-%m-%dT%H:%i:%sZ') as last_seen \
         FROM nanosiem.entity_time_range_agg \
         WHERE ((entity_type = 'src_host' AND (entity_value = ? OR startsWith(entity_value, ?))))"
    );
    assert_eq!(binds, vec!["ws-01", "ws-01."]);
}

#[test]
fn restricted_query_uses_raw_logs_with_real_identity_and_scope_predicates() {
    let profile = UdmProfile::new();
    let hosts = vec!["ws-01".to_string()];
    let scope = denied(&["audit", "insider_threat"]);
    let (sql, binds) = build_asset_true_time_range_query(
        &profile,
        "nanosiem.logs",
        "nanosiem.entity_time_range_agg",
        &[],
        &hosts,
        &[],
        &scope,
    )
    .expect("host produces a query");

    assert!(sql.contains("min(timestamp)"));
    assert!(sql.contains("max(timestamp)"));
    assert!(sql.contains("FROM nanosiem.logs"));
    assert!(!sql.contains("entity_time_range_agg"));
    assert!(sql.contains(
        "WHERE ((lower(src_host) = ? OR startsWith(lower(src_host), ?))) \
         AND lower(source_type) NOT IN ('audit', 'insider_threat')"
    ));
    assert_eq!(binds, vec!["ws-01", "ws-01."]);
}

#[test]
fn implicit_audit_deny_alone_routes_to_raw_logs() {
    let profile = UdmProfile::new();
    let users = vec!["alice".to_string()];
    let (sql, binds) = build_asset_true_time_range_query(
        &profile,
        "nanosiem.logs",
        "nanosiem.entity_time_range_agg",
        &[],
        &[],
        &users,
        &denied(&["audit"]),
    )
    .expect("user produces a query");

    assert!(sql.contains("FROM nanosiem.logs"));
    assert!(sql.contains("lower(source_type) != 'audit'"));
    assert!(sql.contains("lower(\"user\") = ?"));
    assert_eq!(binds, vec!["alice"]);
}

#[test]
fn restricted_ocsf_host_uses_the_production_all_endpoint_predicate() {
    let profile = OcsfProfile::new();
    let hosts = vec!["ws-01".to_string()];
    let (sql, binds) = build_asset_true_time_range_query(
        &profile,
        "nanosiem.ocsf_events",
        "nanosiem.entity_time_range_agg",
        &[],
        &hosts,
        &[],
        &denied(&["insider_threat"]),
    )
    .expect("host produces a query");

    for column in [
        "\"src_endpoint.hostname\"",
        "\"device.hostname\"",
        "\"dst_endpoint.hostname\"",
    ] {
        assert!(
            sql.contains(column),
            "production OCSF asset predicate must include {column}: {sql}"
        );
    }
    assert_eq!(
        binds,
        vec!["ws-01", "ws-01.", "ws-01", "ws-01.", "ws-01", "ws-01."]
    );
}

mod pg {
    use super::*;
    use crate::auth::{permissions, SourceScopeResolver};
    use crate::db::repository::SourceScopeRepository;
    use sqlx::PgPool;
    use tokio::sync::OnceCell;
    use uuid::Uuid;

    const DEFAULT_URL: &str = "postgres://nanosiem:nanosiem@localhost:5432/nanosiem";
    static MIGRATED: OnceCell<()> = OnceCell::const_new();

    async fn migrated_pool() -> PgPool {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
        let pool = PgPool::connect(&url).await.unwrap_or_else(|error| {
            panic!(
                "connect to test Postgres at {url}: {error}\n\
                 (is `docker compose up -d postgres` running?)"
            )
        });
        MIGRATED
            .get_or_init(|| async {
                crate::db::run_postgres_migrations(&pool)
                    .await
                    .expect("apply Postgres migrations");
            })
            .await;
        pool
    }

    async fn create_user(pool: &PgPool) -> Uuid {
        let id = Uuid::now_v7();
        sqlx::query(
            r#"INSERT INTO users
               (id, email, name, password_hash, status, created_at, updated_at)
               VALUES ($1, $2, 'Asset Scope Test', 'x', 'active', NOW(), NOW())"#,
        )
        .bind(id)
        .bind(format!("asset-scope-{id}@example.test"))
        .execute(pool)
        .await
        .expect("create user");
        id
    }

    async fn create_group(pool: &PgPool, suffix: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            r#"INSERT INTO groups (name, description)
               VALUES ($1, 'asset true-range scope test')
               RETURNING id"#,
        )
        .bind(format!("asset-scope-{suffix}"))
        .fetch_one(pool)
        .await
        .expect("create group")
    }

    /// Live schema/grant regression: resolve two denied sources plus one granted
    /// source from PostgreSQL, and feed that real `ScopeSet` through the exact
    /// production query planner. This is the guard that a future refactor cannot
    /// accidentally send a restricted JWT/API-key principal back to the
    /// provenance-free aggregate.
    #[tokio::test]
    #[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
    async fn resolved_pg_scope_drives_the_production_raw_fallback() {
        let pool = migrated_pool().await;
        let repo = SourceScopeRepository::new(pool.clone());
        let resolver = SourceScopeResolver::new(pool.clone());
        let suffix = Uuid::now_v7().simple().to_string();
        let denied_a = format!("denied_a_{}", &suffix[..16]);
        let denied_b = format!("denied_b_{}", &suffix[..16]);
        let granted = format!("granted_{}", &suffix[..16]);

        for source in [&denied_a, &denied_b, &granted] {
            repo.add_restricted(source, None, None)
                .await
                .expect("register restricted source");
        }

        let user = create_user(&pool).await;
        let group = create_group(&pool, &suffix[..16]).await;
        sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
            .bind(user)
            .bind(group)
            .execute(&pool)
            .await
            .expect("add user to group");
        repo.add_grant(&granted, group, None)
            .await
            .expect("grant source");

        let scope = resolver
            .resolve(user, &[], &[])
            .await
            .expect("resolve source scope");
        assert!(scope.deny_set().contains(&denied_a));
        assert!(scope.deny_set().contains(&denied_b));
        assert!(!scope.deny_set().contains(&granted));

        let profile = UdmProfile::new();
        let hosts = vec!["pg-scoped-host".to_string()];
        let (restricted_sql, _) = build_asset_true_time_range_query(
            &profile,
            "nanosiem.logs",
            "nanosiem.entity_time_range_agg",
            &[],
            &hosts,
            &[],
            &scope,
        )
        .expect("restricted query");
        assert!(restricted_sql.contains("FROM nanosiem.logs"));
        assert!(!restricted_sql.contains("entity_time_range_agg"));
        assert!(restricted_sql.contains(&format!("'{denied_a}'")));
        assert!(restricted_sql.contains(&format!("'{denied_b}'")));
        assert!(
            !restricted_sql.contains(&format!("'{granted}'")),
            "a group-granted source must not be excluded: {restricted_sql}"
        );

        let bypass_scope = resolver
            .resolve(
                user,
                &[],
                &[permissions::SOURCE_SCOPES_VIEW_ALL.to_string()],
            )
            .await
            .expect("resolve explicit unrestricted scope");
        let (unrestricted_sql, _) = build_asset_true_time_range_query(
            &profile,
            "nanosiem.logs",
            "nanosiem.entity_time_range_agg",
            &[],
            &hosts,
            &[],
            &bypass_scope,
        )
        .expect("unrestricted query");
        assert!(unrestricted_sql.contains("FROM nanosiem.entity_time_range_agg"));
        assert!(!unrestricted_sql.contains("FROM nanosiem.logs"));

        for source in [&denied_a, &denied_b, &granted] {
            let _ = repo.remove_restricted(source).await;
        }
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group)
            .execute(&pool)
            .await;
    }
}

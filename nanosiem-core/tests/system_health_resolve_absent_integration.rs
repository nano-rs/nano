// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5738 review r5: `resolve_absent_by_prefix_on` only ever resolves the
//! calling producer's own alerts under one specific namespace.
//!
//! ```text
//! NANOSIEM_TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:<port>/postgres \
//!   cargo test -p nanosiem-core --test system_health_resolve_absent_integration -- --ignored
//! ```

use nanosiem_core::system_health::{
    HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthError, SystemHealthRepository,
};

async fn fresh_pg() -> sqlx::PgPool {
    let url = nanosiem_test_db::require_pg_url();
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("sh_{}", &uuid::Uuid::now_v7().simple().to_string()[18..]);
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.unwrap();
    let (base, _) = url.rsplit_once('/').unwrap();
    let pool = sqlx::PgPool::connect(&format!("{base}/{name}")).await.unwrap();
    nanosiem_core::db::run_postgres_migrations(&pool).await.unwrap();
    pool
}

fn event(key: &str, source: &str) -> PublishHealthEvent {
    PublishHealthEvent::new(key, HealthCategory::Integration, HealthSeverity::Medium, "t", "s", "thing", source)
}

async fn status(pool: &sqlx::PgPool, key: &str) -> String {
    sqlx::query_scalar("SELECT status FROM system_health_events WHERE dedup_key = $1 ORDER BY created_at DESC LIMIT 1")
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "needs NANOSIEM_TEST_DATABASE_URL (disposable PostgreSQL)"]
async fn resolve_absent_is_scoped_to_one_namespace_and_one_source() {
    let pool = fresh_pg().await;
    let repo = SystemHealthRepository::new(pool.clone());
    for (key, source) in [
        ("soar_pack_quarantined:okta", "soar_catalog"),
        ("soar_pack_quarantined:teams", "soar_catalog"),
        ("soar_pack_quarantined:foreign", "someone_else"),
        ("soar_pack_other:okta", "soar_catalog"),
        ("disk:root:pressure", "health"),
    ] {
        repo.publish(&event(key, source)).await.unwrap();
    }
    let mut conn = pool.acquire().await.unwrap();
    for bad in ["", "soar_pack", "soar_pack_quarantined"] {
        let err = repo.resolve_absent_by_prefix_on(&mut conn, bad, "soar_catalog", &[]).await.unwrap_err();
        assert!(matches!(err, SystemHealthError::Invalid(_)), "{bad:?}: {err:?}");
    }
    let err = repo.resolve_absent_by_prefix_on(&mut conn, "soar_pack_quarantined:", " ", &[]).await.unwrap_err();
    assert!(matches!(err, SystemHealthError::Invalid(_)));
    let resolved = repo
        .resolve_absent_by_prefix_on(
            &mut conn,
            "soar_pack_quarantined:",
            "soar_catalog",
            &["soar_pack_quarantined:okta".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(status(&pool, "soar_pack_quarantined:okta").await, "active", "kept");
    assert_eq!(status(&pool, "soar_pack_quarantined:teams").await, "resolved", "own and absent");
    assert_eq!(status(&pool, "soar_pack_quarantined:foreign").await, "active", "another producer's alert");
    assert_eq!(status(&pool, "soar_pack_other:okta").await, "active", "another namespace");
    assert_eq!(status(&pool, "disk:root:pressure").await, "active");
}

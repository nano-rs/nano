// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5077 against a real PostgreSQL: rules that load are enforced; a load
//! that fails refuses (it used to allow everyone); a blip stays off the
//! system-health bus, a sustained outage is raised once per instance and
//! resolved in place on recovery; leftovers from dead processes are cleared.
//!
//! Run: `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 DATABASE_URL=... cargo test -p
//! nanosiem-core --test ip_allowlist_fail_closed_integration -- --ignored
//! --test-threads=1`

mod common;

use nanosiem_core::ip_allowlist::{
    AllowlistDecision, CreateIpAllowlistEntry, IpAllowlistScope, IpAllowlistService,
    LOAD_FAILED_DEDUP_PREFIX,
};

const LISTED: &str = "203.0.113.9";
const UNLISTED: &str = "198.51.100.7";

async fn reset(pool: &sqlx::PgPool) {
    sqlx::query("DELETE FROM ip_allowlists").execute(pool).await.unwrap();
    sqlx::query("DELETE FROM system_health_events WHERE dedup_key LIKE 'ip_allowlist:%'")
        .execute(pool)
        .await
        .unwrap();
}

async fn seed(svc: &IpAllowlistService) {
    svc.create(
        CreateIpAllowlistEntry {
            scope: IpAllowlistScope::Global,
            cidr: "203.0.113.0/24".into(),
            description: Some("office".into()),
            enabled: true,
        },
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires DATABASE_URL (disposable Postgres)"]
async fn loaded_rules_are_enforced_and_loopback_still_passes() {
    let pool = common::migrated_pool().await;
    reset(&pool).await;
    let svc = IpAllowlistService::new(pool.clone()).with_component("itest-legit");

    // No rules: the allowlist is inactive (a SUCCESSFUL load said so).
    assert_eq!(
        svc.is_allowed_client(UNLISTED, false, IpAllowlistScope::Api).await,
        AllowlistDecision::Allowed
    );

    seed(&svc).await;
    assert_eq!(
        svc.is_allowed_client(LISTED, false, IpAllowlistScope::Api).await,
        AllowlistDecision::Allowed
    );
    assert_eq!(
        svc.is_allowed_client(UNLISTED, false, IpAllowlistScope::Api).await,
        AllowlistDecision::Denied
    );
    assert_eq!(
        svc.is_allowed_client("127.0.0.1", true, IpAllowlistScope::Api).await,
        AllowlistDecision::Allowed
    );
    reset(&pool).await;
}

async fn break_rules_table(pool: &sqlx::PgPool) {
    sqlx::query("ALTER TABLE ip_allowlists RENAME TO ip_allowlists_nan5077")
        .execute(pool)
        .await
        .unwrap();
}

async fn restore_rules_table(pool: &sqlx::PgPool) {
    sqlx::query("ALTER TABLE ip_allowlists_nan5077 RENAME TO ip_allowlists")
        .execute(pool)
        .await
        .unwrap();
}

/// (status, count) of the condition rows for `key`.
async fn condition_rows(pool: &sqlx::PgPool, key: &str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT status FROM system_health_events WHERE dedup_key = $1 ORDER BY created_at",
    )
    .bind(key)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Wait for the spawned health-bus writes to settle on `expected`.
async fn wait_for_rows(pool: &sqlx::PgPool, key: &str, expected: &[&str]) -> Vec<String> {
    let mut rows = Vec::new();
    for _ in 0..50 {
        rows = condition_rows(pool, key).await;
        if rows == expected {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    rows
}

fn key(component: &str, instance: &str) -> String {
    format!("{LOAD_FAILED_DEDUP_PREFIX}{component}:{instance}")
}

#[tokio::test]
#[ignore = "requires DATABASE_URL (disposable Postgres)"]
async fn a_failed_load_refuses_and_a_blip_pages_nobody() {
    let pool = common::migrated_pool().await;
    reset(&pool).await;
    seed(&IpAllowlistService::new(pool.clone())).await;
    let svc = IpAllowlistService::new(pool.clone())
        .with_component("itest")
        .with_instance("blip-0");

    break_rules_table(&pool).await;
    let during_outage = svc.is_allowed_client(UNLISTED, false, IpAllowlistScope::Api).await;
    let loopback = svc.is_allowed_client("127.0.0.1", true, IpAllowlistScope::Api).await;
    restore_rules_table(&pool).await;

    // Exploit regression: this used to be Allowed for everyone.
    assert_eq!(during_outage, AllowlistDecision::Unavailable);
    assert_eq!(loopback, AllowlistDecision::Allowed);

    // Recovery enforces again...
    svc.invalidate_cache().await;
    assert_eq!(
        svc.is_allowed_client(LISTED, false, IpAllowlistScope::Api).await,
        AllowlistDecision::Allowed
    );
    assert_eq!(
        svc.is_allowed_client(UNLISTED, false, IpAllowlistScope::Api).await,
        AllowlistDecision::Denied
    );
    // ...and one failed load never reached the health bus: no
    // triggered + resolved notification pair for a blip.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(condition_rows(&pool, &key("itest", "blip-0")).await.is_empty());
    reset(&pool).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL (disposable Postgres)"]
async fn a_sustained_outage_is_raised_once_and_recovery_only_resolves() {
    let pool = common::migrated_pool().await;
    reset(&pool).await;
    seed(&IpAllowlistService::new(pool.clone())).await;
    let a = IpAllowlistService::new(pool.clone())
        .with_component("itest")
        .with_instance("api-0");
    let b = IpAllowlistService::new(pool.clone())
        .with_component("itest")
        .with_instance("api-1");

    break_rules_table(&pool).await;
    for _ in 0..3 {
        for svc in [&a, &b] {
            svc.invalidate_cache().await; // skip the retry back-off
            assert_eq!(
                svc.is_allowed_client(UNLISTED, false, IpAllowlistScope::Api).await,
                AllowlistDecision::Unavailable
            );
        }
    }
    restore_rules_table(&pool).await;
    assert_eq!(wait_for_rows(&pool, &key("itest", "api-0"), &["active"]).await, ["active"]);
    assert_eq!(wait_for_rows(&pool, &key("itest", "api-1"), &["active"]).await, ["active"]);

    // api-0 recovers; api-1 has not loaded yet and keeps its own condition.
    a.invalidate_cache().await;
    assert_eq!(
        a.is_allowed_client(LISTED, false, IpAllowlistScope::Api).await,
        AllowlistDecision::Allowed
    );
    // Resolved in place — recovery never inserts a second (notifying) row.
    assert_eq!(wait_for_rows(&pool, &key("itest", "api-0"), &["resolved"]).await, ["resolved"]);
    assert_eq!(condition_rows(&pool, &key("itest", "api-1")).await, ["active"]);
    reset(&pool).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL (disposable Postgres)"]
async fn the_first_load_clears_leftover_and_orphaned_conditions() {
    use nanosiem_core::system_health::{
        HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthRepository,
    };
    let pool = common::migrated_pool().await;
    reset(&pool).await;
    let repo = SystemHealthRepository::new(pool.clone());
    let raise = |instance: &str| {
        PublishHealthEvent::new(
            key("itest", instance),
            HealthCategory::Service,
            HealthSeverity::Critical,
            "t",
            "s",
            "ip_allowlist",
            "itest",
        )
    };
    // This instance crashed mid-outage; a replaced pod went silent an hour
    // ago; a live replica is failing right now.
    for instance in ["api-0", "api-gone", "api-live"] {
        repo.publish(&raise(instance)).await.unwrap();
    }
    sqlx::query("UPDATE system_health_events SET last_seen_at = NOW() - interval '1 hour' WHERE dedup_key = $1")
        .bind(key("itest", "api-gone"))
        .execute(&pool)
        .await
        .unwrap();

    let svc = IpAllowlistService::new(pool.clone())
        .with_component("itest")
        .with_instance("api-0");
    assert_eq!(
        svc.is_allowed_client(UNLISTED, false, IpAllowlistScope::Api).await,
        AllowlistDecision::Allowed,
        "no rules seeded: allowlist inactive"
    );
    assert_eq!(wait_for_rows(&pool, &key("itest", "api-0"), &["resolved"]).await, ["resolved"]);
    assert_eq!(wait_for_rows(&pool, &key("itest", "api-gone"), &["resolved"]).await, ["resolved"]);
    assert_eq!(condition_rows(&pool, &key("itest", "api-live")).await, ["active"]);
    reset(&pool).await;
}

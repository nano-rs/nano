// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5285 (F3): the ingest install lease. The pure rules always run; the
//! lease store tests need a disposable PostgreSQL at
//! `NANOSIEM_TEST_DATABASE_URL` (each test gets its own schema) and are
//! skipped without one.

use super::*;

const MIGRATION: &str =
    include_str!("../../../../../migrations/postgres/380_vector_config_install_leases.sql");

#[test]
fn holder_identity_is_plain() {
    for ok in ["vm-1", "ingest-2", "nano-ingest-0.nano-ingest", "host_1:a"] {
        assert_eq!(validate_holder(ok), Ok(()), "{ok}");
    }
    let long = "a".repeat(129);
    for bad in ["", "vm 1", "vm-1;drop", "<script>", long.as_str()] {
        assert_eq!(validate_holder(bad), Err(LeaseRequestError::InvalidHolder), "{bad}");
    }
}

#[test]
fn ttl_is_bounded() {
    assert_eq!(clamp_ttl(Some(1)), MIN_LEASE_TTL_SECS);
    assert_eq!(clamp_ttl(Some(100_000)), MAX_LEASE_TTL_SECS);
    assert_eq!(clamp_ttl(Some(120)), 120);
    assert_eq!(clamp_ttl(None), MAX_LEASE_TTL_SECS / 2);
}

#[test]
fn drain_only_when_another_ingest_host_takes_the_traffic() {
    // A lone ingest host never drains: that would refuse every event.
    assert!(!should_drain(1, 1));
    assert!(!should_drain(0, 0));
    // Two hosts, the peer down (a hard reset): install in place.
    assert!(!should_drain(2, 1));
    assert!(should_drain(2, 2));
    assert!(should_drain(3, 2));
}

#[test]
fn outcomes_serialize_for_the_shell_consumer() {
    let granted = serde_json::to_string(&LeaseOutcome::Granted { drain: true, ttl_secs: 120 }).unwrap();
    assert_eq!(granted, r#"{"status":"granted","drain":true,"ttl_secs":120}"#);
    let busy = serde_json::to_string(&LeaseOutcome::Busy {
        holder: "vm-1".into(),
        generation: 7,
        expires_in_secs: 30,
    })
    .unwrap();
    assert_eq!(busy, r#"{"status":"busy","holder":"vm-1","generation":7,"expires_in_secs":30}"#);
}

async fn lease_pool() -> Option<PgPool> {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").ok()?;
    let schema = format!("nan5285_{}", uuid::Uuid::new_v4().simple());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect({
            let schema = schema.clone();
            move |conn, _| {
                let schema = schema.clone();
                Box::pin(async move {
                    sqlx::Executor::execute(conn, format!("SET search_path TO {schema}").as_str())
                        .await
                        .map(|_| ())
                })
            }
        })
        .connect(&url)
        .await
        .expect("connect");
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .expect("schema");
    sqlx::raw_sql(&MIGRATION.replace("public.", &format!("{schema}.")))
        .execute(&pool)
        .await
        .expect("migration 380");
    Some(pool)
}

#[tokio::test]
async fn one_host_installs_at_a_time() {
    let Some(pool) = lease_pool().await else { return };
    assert_eq!(acquire(&pool, "vm-1", 7, 60).await.unwrap(), None);
    let busy = acquire(&pool, "vm-2", 7, 60).await.unwrap().expect("vm-2 must wait");
    assert_eq!(busy.0, "vm-1");
    assert_eq!(busy.1, 7);
    assert!(busy.2 > 0 && busy.2 <= 60, "{busy:?}");
    // The holder renews (a lost response, or a long install).
    assert_eq!(acquire(&pool, "vm-1", 7, 60).await.unwrap(), None);
    // Only the holder releases it.
    assert!(!release(&pool, "vm-2").await.unwrap());
    assert!(release(&pool, "vm-1").await.unwrap());
    assert_eq!(acquire(&pool, "vm-2", 7, 60).await.unwrap(), None);
}

#[tokio::test]
async fn a_dead_holder_loses_the_lease_when_it_expires() {
    let Some(pool) = lease_pool().await else { return };
    assert_eq!(acquire(&pool, "vm-1", 8, 60).await.unwrap(), None);
    sqlx::query("UPDATE vector_config_install_leases SET expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(acquire(&pool, "vm-2", 8, 60).await.unwrap(), None);
    let busy = acquire(&pool, "vm-1", 8, 60).await.unwrap().expect("vm-1 lost it");
    assert_eq!(busy.0, "vm-2");
}

#[tokio::test]
async fn concurrent_requests_grant_exactly_one() {
    let Some(pool) = lease_pool().await else { return };
    let attempts = (0..8).map(|i| {
        let pool = pool.clone();
        async move { acquire(&pool, &format!("vm-{i}"), 9, 60).await.unwrap() }
    });
    let granted = futures::future::join_all(attempts)
        .await
        .into_iter()
        .filter(Option::is_none)
        .count();
    assert_eq!(granted, 1);
}

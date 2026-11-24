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
                    sqlx::Executor::execute(conn, sqlx::AssertSqlSafe(format!("SET search_path TO {schema}")))
                        .await
                        .map(|_| ())
                })
            }
        })
        .connect(&url)
        .await
        .expect("connect");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&pool)
        .await
        .expect("schema");
    sqlx::raw_sql(sqlx::AssertSqlSafe(&*MIGRATION.replace("public.", &format!("{schema}."))))
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

#[test]
fn the_vector_release_is_read_from_the_build_info_revision() {
    assert_eq!(parse_vector_release("nano 0.61.0-nano.14 0123456789ab"), Some((0, 61, 0, 14)));
    assert_eq!(parse_vector_release("nano 0.61.0-nano.13 a7bc4dc791f4"), Some((0, 61, 0, 13)));
    assert_eq!(parse_vector_release("nano 0.62.0-nano.1 b05ff8da88aa"), Some((0, 62, 0, 1)));
    assert_eq!(parse_vector_release("0.61.0-nano.14-debian"), Some((0, 61, 0, 14)));
    for none in ["", "nan5874-local", "nano", "0.61-nano.14", "1.2.3.4-nano.5", "0.61.0-nano.x"] {
        assert_eq!(parse_vector_release(none), None, "{none}");
    }
}

#[test]
fn only_a_vector_that_keeps_acked_events_on_a_repointing_reload_installs() {
    // A consumer from before v2.0.35 sends nothing; Vector's metrics not up yet sends "".
    assert!(!vector_release_allows_install(None));
    assert!(!vector_release_allows_install(Some("")));
    assert!(!vector_release_allows_install(Some("  ")));
    assert!(!vector_release_allows_install(Some("nano 0.61.0-nano.13 a7bc4dc791f4")));
    assert!(!vector_release_allows_install(Some("nano 0.60.9-nano.20 0")));
    assert!(vector_release_allows_install(Some("nano 0.61.0-nano.14 0123456789ab")));
    assert!(vector_release_allows_install(Some("nano 0.61.0-nano.15 0")));
    assert!(vector_release_allows_install(Some("nano 0.62.0-nano.1 0")));
    // A custom build names no fork release: the operator's own Vector.
    assert!(vector_release_allows_install(Some("nan5874-local")));
}

#[test]
fn a_refused_vector_reads_as_busy_to_every_consumer() {
    let busy = serde_json::to_string(&LeaseOutcome::Busy {
        holder: VECTOR_UPGRADE_HOLDER.into(),
        generation: 7,
        expires_in_secs: 0,
    })
    .unwrap();
    // Consumers from before v2.0.35 install only on `"status":"granted"` and
    // read the holder with `[A-Za-z0-9._:-]*`.
    assert!(!busy.contains("granted"), "{busy}");
    assert_eq!(validate_holder(VECTOR_UPGRADE_HOLDER), Ok(()));
    assert_eq!(validate_holder(LEGACY_FENCE_HOLDER), Ok(()));
    assert_ne!(LEASE_SCOPE, LEGACY_LEASE_SCOPE);
}

#[tokio::test]
async fn an_old_vector_is_refused_without_taking_the_lease() {
    let Some(pool) = lease_pool().await else { return };
    let outcome = request(&pool, "vm-1", 7, Some(60), Some("nano 0.61.0-nano.13 a7bc4dc791f4"))
        .await
        .unwrap();
    assert_eq!(
        outcome,
        LeaseOutcome::Busy { holder: VECTOR_UPGRADE_HOLDER.into(), generation: 7, expires_in_secs: 0 }
    );
    let outcome = request(&pool, "vm-1", 7, Some(60), None).await.unwrap();
    assert!(matches!(outcome, LeaseOutcome::Busy { ref holder, .. } if holder == VECTOR_UPGRADE_HOLDER));
    // Nobody holds the lease: a nano.14 host gets it at once.
    let outcome = request(&pool, "vm-2", 7, Some(60), Some("nano 0.61.0-nano.14 0")).await.unwrap();
    assert!(matches!(outcome, LeaseOutcome::Granted { .. }), "{outcome:?}");
}

/// An API from before v2.0.35 grants the `ingest` scope with this statement
/// (NAN-5285). While this version's API fences it, that answers busy for every
/// consumer, including one that held it.
#[tokio::test]
async fn an_api_from_before_v2_0_35_grants_no_install_while_fenced() {
    let Some(pool) = lease_pool().await else { return };
    async fn legacy_acquire(pool: &PgPool, holder: &str) -> bool {
        sqlx::query_as::<_, (String,)>(
            "INSERT INTO vector_config_install_leases \
                 (scope, holder, generation, acquired_at, expires_at) \
             VALUES ('ingest', $1, 7, now(), now() + make_interval(secs => 60)) \
             ON CONFLICT (scope) DO UPDATE SET \
                 holder = EXCLUDED.holder, generation = EXCLUDED.generation, \
                 acquired_at = now(), expires_at = EXCLUDED.expires_at \
             WHERE vector_config_install_leases.holder = EXCLUDED.holder \
                OR vector_config_install_leases.expires_at < now() \
             RETURNING holder",
        )
        .bind(holder)
        .fetch_optional(pool)
        .await
        .unwrap()
        .is_some()
    }
    assert!(legacy_acquire(&pool, "old-vector-0").await, "unfenced, an old API grants");
    fence_legacy_scope(&pool).await.unwrap();
    assert!(!legacy_acquire(&pool, "old-vector-0").await, "the old holder lost it to the fence");
    assert!(!legacy_acquire(&pool, "old-vector-1").await);
    // The fence leaves this version's own lease alone.
    assert_eq!(acquire(&pool, "vm-1", 8, 60).await.unwrap(), None);
    // A lease request refreshes the fence.
    sqlx::query("UPDATE vector_config_install_leases SET expires_at = now() - interval '1 second' WHERE scope = 'ingest'")
        .execute(&pool)
        .await
        .unwrap();
    request(&pool, "vm-1", 8, Some(60), Some("nano 0.61.0-nano.14 0")).await.unwrap();
    assert!(!legacy_acquire(&pool, "old-vector-1").await, "refreshed by the lease request");

    // Rollback to a version before v2.0.35: no v2.0.35 API refreshes the fence
    // any more, and once it lapses an old API grants the legacy scope again.
    let left: (f64,) = sqlx::query_as(
        "SELECT EXTRACT(EPOCH FROM (expires_at - now()))::float8 FROM vector_config_install_leases WHERE scope = 'ingest'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(left.0 <= LEGACY_FENCE_TTL_SECS as f64 + 1.0, "the fence lapses within its TTL: {left:?}");
    sqlx::query("UPDATE vector_config_install_leases SET expires_at = now() - interval '1 second' WHERE scope = 'ingest'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(legacy_acquire(&pool, "old-vector-1").await, "an old API grants again after a rollback");
}

#[test]
fn a_rollback_recovers_inside_the_consumer_and_healthcheck_budgets() {
    // The Compose consumer healthcheck allows 210 s and a consumer polls every 5 s; the
    // fence must lapse well inside that, and outlive several 5 s refresh ticks.
    assert!((15..=60).contains(&LEGACY_FENCE_TTL_SECS), "{LEGACY_FENCE_TTL_SECS}");
}

#[test]
fn a_custom_vector_build_is_allowed() {
    // The consumer reports `custom <version>` for a build_info with no revision label.
    assert!(vector_release_allows_install(Some("custom 0.61.0")));
    assert!(vector_release_allows_install(Some("custom ")));
}

/// NAN-5874 review: the legacy path on this version never grants, and still fences.
#[tokio::test]
async fn the_legacy_path_never_grants_on_this_version() {
    let Some(pool) = lease_pool().await else { return };
    let old = request_on_legacy_path(&pool, "vm-1", 7, None).await.unwrap();
    assert_eq!(
        old,
        LeaseOutcome::Busy { holder: VECTOR_UPGRADE_HOLDER.into(), generation: 7, expires_in_secs: 0 }
    );
    let new = request_on_legacy_path(&pool, "vm-1", 7, Some("nano 0.61.0-nano.14 0")).await.unwrap();
    assert_eq!(
        new,
        LeaseOutcome::Busy { holder: LEASE_V2_HOLDER.into(), generation: 7, expires_in_secs: 0 }
    );
    assert_eq!(validate_holder(LEASE_V2_HOLDER), Ok(()));
    // Nothing was granted: the v2 lease is free, and the legacy scope is fenced.
    assert_eq!(acquire(&pool, "vm-2", 7, 60).await.unwrap(), None);
    let fenced: (String,) =
        sqlx::query_as("SELECT holder FROM vector_config_install_leases WHERE scope = 'ingest'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(fenced.0, LEGACY_FENCE_HOLDER);
}

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
    assert_eq!(parse_vector_release("nano 0.62.0-nano.2 b05ff8da88aa"), Some((0, 62, 0, 2)));
    assert_eq!(parse_vector_release("0.61.0-nano.14-debian"), Some((0, 61, 0, 14)));
    for none in ["", "nan5874-local", "nano", "0.61-nano.14", "1.2.3.4-nano.5", "0.61.0-nano.x"] {
        assert_eq!(parse_vector_release(none), None, "{none}");
    }
}

#[test]
fn only_a_vector_that_loads_this_releases_config_installs() {
    // A consumer from before v2.0.35 sends nothing; Vector's metrics not up yet sends "".
    assert!(!vector_release_allows_install(None));
    assert!(!vector_release_allows_install(Some("")));
    assert!(!vector_release_allows_install(Some("  ")));
    // NAN-5874: drops acknowledged events on a re-pointing reload.
    assert!(!vector_release_allows_install(Some("nano 0.61.0-nano.13 a7bc4dc791f4")));
    assert!(!vector_release_allows_install(Some("nano 0.60.9-nano.20 0")));
    // NAN-5810: any 0.61 Vector cannot parse a 0.62-format generation (quoted
    // numeric placeholders), whatever its nano revision.
    assert!(!vector_release_allows_install(Some("nano 0.61.0-nano.14 0123456789ab")));
    assert!(!vector_release_allows_install(Some("nano 0.61.0-nano.15 0")));
    assert!(!vector_release_allows_install(Some("nano 0.61.0-nano.99 0")));
    assert!(!vector_release_allows_install(Some("nano 0.62.0-nano.0 0")));
    // nanosiem#10462: HEC record preservation needs the splunk_hec event_kind
    // marker first shipped in 0.62.0-nano.2.
    assert!(!vector_release_allows_install(Some("nano 0.62.0-nano.1 0123456789ab")));
    assert!(vector_release_allows_install(Some("nano 0.62.0-nano.2 0123456789ab")));
    assert!(vector_release_allows_install(Some("nano 0.62.0-nano.3 0")));
    assert!(vector_release_allows_install(Some("nano 0.62.1-nano.1 0")));
    assert!(vector_release_allows_install(Some("nano 0.63.0-nano.1 0")));
    assert_eq!(MIN_VECTOR_RELEASE, (0, 62, 0, 2));
    assert_eq!(VECTOR_UPGRADE_HOLDER, "vector-0.62.0-nano.2-required");
    // NAN-5891 review r3: a build that names no fork release (upstream or
    // custom) fails closed, unless the operator opted in.
    assert!(!vector_release_allows_install_with(Some("nan5874-local"), false));
    assert!(vector_release_allows_install_with(Some("nan5874-local"), true));
    // The opt-in never admits an old fork release or an unreported one.
    assert!(!vector_release_allows_install_with(Some("nano 0.62.0-nano.1 0"), true));
    assert!(!vector_release_allows_install_with(None, true));
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
    assert_eq!(validate_holder(LEASE_V3_HOLDER), Ok(()));
    assert_ne!(LEASE_SCOPE, LEGACY_LEASE_SCOPE);
}

/// NAN-5810 review P1-1: this version grants a scope no older API grants, and
/// fences every scope they do.
#[test]
fn the_lease_scope_moved_past_every_fenced_scope() {
    assert_eq!(LEASE_SCOPE, "ingest-v3");
    assert_eq!(FENCED_LEGACY_SCOPES, &["ingest", "ingest-v2"]);
    assert!(!FENCED_LEGACY_SCOPES.contains(&LEASE_SCOPE));
    assert_eq!(LEGACY_FENCE_HOLDER, "nano-2.0.36-upgrade");
    assert_eq!(LEASE_V3_HOLDER, "install-lease-v3-required");
    // The v2.0.35 consumer matches `vector-*-required` for its "upgrade
    // Vector" log; the v3 redirect must not read as one.
    assert!(VECTOR_UPGRADE_HOLDER.starts_with("vector-") && VECTOR_UPGRADE_HOLDER.ends_with("-required"));
    assert!(!LEASE_V3_HOLDER.starts_with("vector-"));
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
    // NAN-5810: a 0.61 host (nano.14, which NAN-5874 admitted) waits too, and
    // so does the first 0.62 image (no HEC event_kind marker).
    let outcome = request(&pool, "vm-1", 7, Some(60), Some("nano 0.61.0-nano.15 0")).await.unwrap();
    assert!(matches!(outcome, LeaseOutcome::Busy { ref holder, .. } if holder == VECTOR_UPGRADE_HOLDER));
    let outcome = request(&pool, "vm-1", 7, Some(60), Some("nano 0.62.0-nano.1 0")).await.unwrap();
    assert!(matches!(outcome, LeaseOutcome::Busy { ref holder, .. } if holder == VECTOR_UPGRADE_HOLDER));
    // Nobody holds the lease: a 0.62.0-nano.2 host gets it at once.
    let outcome = request(&pool, "vm-2", 7, Some(60), Some("nano 0.62.0-nano.2 0")).await.unwrap();
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
    request(&pool, "vm-1", 8, Some(60), Some("nano 0.62.0-nano.2 0")).await.unwrap();
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
fn a_custom_vector_build_is_refused_unless_opted_in() {
    // The consumer reports `custom <version>` for a build_info with no revision
    // label (an upstream or custom build). NAN-5891 review r3: refused by
    // default, since it does not mark HEC event kinds.
    for label in ["custom 0.61.0", "custom ", "custom 0.62.0", "0.62.0 (x86_64-unknown-linux-gnu 1a2b3c)"] {
        assert!(!vector_release_allows_install_with(Some(label), false), "{label}");
        assert!(vector_release_allows_install_with(Some(label), true), "{label}");
    }
    assert!(refusal_reason(Some("custom 0.62.0")).contains("custom or upstream Vector builds aren't supported"));
    assert!(refusal_reason(Some("nano 0.61.0-nano.15 0")).contains("predates 0.62.0-nano.2"));
    assert_eq!(ALLOW_CUSTOM_VECTOR_ENV, "NANO_ALLOW_CUSTOM_VECTOR");
}

async fn fence_holders(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT scope, holder FROM vector_config_install_leases \
         WHERE scope IN ('ingest', 'ingest-v2') ORDER BY scope",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// NAN-5874 review: the legacy path on this version never grants, and still fences.
/// NAN-5810 review P1-1: nor does the v2.0.35 path, and both fence both older scopes.
#[tokio::test]
async fn the_superseded_paths_never_grant_on_this_version() {
    let Some(pool) = lease_pool().await else { return };
    for (path, superseded) in [("legacy", true), ("v2", false)] {
        let ask = |release: Option<&'static str>| {
            let pool = pool.clone();
            async move {
                if superseded {
                    request_on_legacy_path(&pool, "vm-1", 7, release).await.unwrap()
                } else {
                    request_on_v2_path(&pool, "vm-1", 7, release).await.unwrap()
                }
            }
        };
        assert_eq!(
            ask(None).await,
            LeaseOutcome::Busy { holder: VECTOR_UPGRADE_HOLDER.into(), generation: 7, expires_in_secs: 0 },
            "{path}"
        );
        // Never a grant. A Vector this version could install on is sent to v3;
        // any other is told it must be upgraded (review r2: a v2.0.35 consumer
        // beside 0.61 logs that holder as the actionable reason).
        for release in ["nano 0.62.0-nano.2 0", "nano 0.62.1-nano.1 0", "custom 0.62.0"] {
            assert_eq!(
                ask(Some(release)).await,
                LeaseOutcome::Busy { holder: LEASE_V3_HOLDER.into(), generation: 7, expires_in_secs: 0 },
                "{path} {release}"
            );
        }
        for release in ["nano 0.61.0-nano.15 0", "nano 0.61.0-nano.14 0", "nano 0.62.0-nano.1 0", "", "  "] {
            assert_eq!(
                ask(Some(release)).await,
                LeaseOutcome::Busy { holder: VECTOR_UPGRADE_HOLDER.into(), generation: 7, expires_in_secs: 0 },
                "{path} {release:?}"
            );
        }
    }
    // Nothing was granted: the v3 lease is free, and both older scopes are fenced.
    assert_eq!(acquire(&pool, "vm-2", 7, 60).await.unwrap(), None);
    assert_eq!(
        fence_holders(&pool).await,
        vec![
            ("ingest".to_string(), LEGACY_FENCE_HOLDER.to_string()),
            ("ingest-v2".to_string(), LEGACY_FENCE_HOLDER.to_string()),
        ]
    );
}

/// The `ingest-v2` grant statement of a v2.0.35 API (`git show
/// v2.0.35:nanosiem-core/src/parsers/vector_config/remote_delivery/install_lease.rs`,
/// `acquire`), verbatim with its `LEASE_SCOPE` bound to `ingest-v2`. A v2.0.35
/// replica runs this for any Vector at or above 0.61.0-nano.14.
async fn v2_0_35_acquire(pool: &PgPool, holder: &str, generation: i64) -> Option<(String, i64, i64)> {
    let granted: Option<(String,)> = sqlx::query_as(
        "INSERT INTO vector_config_install_leases \
             (scope, holder, generation, acquired_at, expires_at) \
         VALUES ($1, $2, $3, now(), now() + make_interval(secs => $4)) \
         ON CONFLICT (scope) DO UPDATE SET \
             holder = EXCLUDED.holder, generation = EXCLUDED.generation, \
             acquired_at = now(), expires_at = EXCLUDED.expires_at \
         WHERE vector_config_install_leases.holder = EXCLUDED.holder \
            OR vector_config_install_leases.expires_at < now() \
         RETURNING holder",
    )
    .bind("ingest-v2")
    .bind(holder)
    .bind(generation)
    .bind(60_f64)
    .fetch_optional(pool)
    .await
    .unwrap();
    if granted.is_some() {
        return None;
    }
    let current: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT holder, generation, \
                GREATEST(0, CEIL(EXTRACT(EPOCH FROM (expires_at - now()))))::BIGINT \
         FROM vector_config_install_leases WHERE scope = $1",
    )
    .bind("ingest-v2")
    .fetch_optional(pool)
    .await
    .unwrap();
    Some(current.unwrap_or_else(|| (String::new(), 0, 0)))
}

/// NAN-5810 review P1-1: a v2.0.35 -> v2.0.36 rolling upgrade (both API
/// versions behind one Service, one database) never lets either API grant a
/// 0.61 Vector an install, and a rollback to v2.0.35 recovers once the fence
/// lapses.
#[tokio::test]
async fn a_v2_0_35_api_grants_no_install_while_a_v2_0_36_api_runs() {
    let Some(pool) = lease_pool().await else { return };
    // Before any v2.0.36 API runs, a v2.0.35 API grants (the baseline this fixes).
    assert_eq!(v2_0_35_acquire(&pool, "old-vector-0", 7).await, None, "unfenced, v2.0.35 grants");

    // A v2.0.36 API boots: its first reconcile tick fences before it publishes.
    fence_legacy_scope(&pool).await.unwrap();
    // The 0.61.0-nano.15 host's poll lands on the v2.0.35 replica: busy, even
    // for the host that held `ingest-v2` a moment ago.
    for holder in ["old-vector-0", "old-vector-1"] {
        let busy = v2_0_35_acquire(&pool, holder, 8).await.expect("fenced");
        assert_eq!(busy.0, LEGACY_FENCE_HOLDER, "{holder}");
        assert!(busy.2 > 0 && busy.2 <= LEGACY_FENCE_TTL_SECS as i64, "{busy:?}");
    }
    // The same host's poll lands on the v2.0.36 replica: v3 refuses its 0.61 Vector...
    assert_eq!(
        request(&pool, "old-vector-1", 8, Some(60), Some("nano 0.61.0-nano.15 0123456789ab")).await.unwrap(),
        LeaseOutcome::Busy { holder: VECTOR_UPGRADE_HOLDER.into(), generation: 8, expires_in_secs: 0 }
    );
    // ...and v2 on the v2.0.36 replica never grants.
    assert!(matches!(
        request_on_v2_path(&pool, "old-vector-1", 8, Some("nano 0.61.0-nano.15 0")).await.unwrap(),
        LeaseOutcome::Busy { .. }
    ));
    // An upgraded host (0.62.0-nano.2) gets the v3 lease from the v2.0.36 replica.
    assert!(matches!(
        request(&pool, "new-vector-0", 8, Some(60), Some("nano 0.62.0-nano.2 0123456789ab")).await.unwrap(),
        LeaseOutcome::Granted { .. }
    ));
    // That lease is not one v2.0.35 can see or hand out, and v2.0.35 stays fenced.
    assert_eq!(v2_0_35_acquire(&pool, "old-vector-1", 8).await.unwrap().0, LEGACY_FENCE_HOLDER);
    // The fence is refreshed while a v2.0.36 API runs (a tick, or any lease request).
    sqlx::query("UPDATE vector_config_install_leases SET expires_at = now() - interval '1 second' WHERE scope IN ('ingest', 'ingest-v2')")
        .execute(&pool)
        .await
        .unwrap();
    request(&pool, "new-vector-1", 8, Some(60), Some("nano 0.62.0-nano.2 0")).await.unwrap();
    assert_eq!(v2_0_35_acquire(&pool, "old-vector-1", 8).await.unwrap().0, LEGACY_FENCE_HOLDER);

    // Rollback to v2.0.35: no v2.0.36 API refreshes the fence; it lapses within
    // LEGACY_FENCE_TTL_SECS and v2.0.35 grants `ingest-v2` again.
    let left: (f64,) = sqlx::query_as(
        "SELECT MAX(EXTRACT(EPOCH FROM (expires_at - now())))::float8 FROM vector_config_install_leases WHERE scope IN ('ingest', 'ingest-v2')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(left.0 <= LEGACY_FENCE_TTL_SECS as f64 + 1.0, "the fence lapses within its TTL: {left:?}");
    sqlx::query("UPDATE vector_config_install_leases SET expires_at = now() - interval '1 second' WHERE scope IN ('ingest', 'ingest-v2')")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(v2_0_35_acquire(&pool, "old-vector-1", 9).await, None, "v2.0.35 grants again after a rollback");
}

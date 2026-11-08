// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence warming / partial / ready against a real migrated ClickHouse
//! (NAN-4902 lane E, changelog 10-16 "prevalence warming/stale states").
//!
//! A miss used to render `host_count 0`, the same as "seen on no host" (that
//! is, boring). The probe reads part metadata of the prevalence agg tables and
//! the logs table; this suite proves the real SQL against the real schema and
//! that a miss outside coverage comes back as `host_count: null`.
//!
//! `#[ignore]`d: point `NANOSIEM_TEST_CLICKHOUSE_URL` at a DISPOSABLE migrated
//! ClickHouse (the suite truncates the prevalence agg tables and `logs`).

use nanosiem_core::auth::{ArtifactScope, ScopeSet};
use nanosiem_core::db::TableNames;
use nanosiem_core::prevalence::coverage::{ArtifactKind, CoverageSource};
use std::collections::BTreeSet;
use nanosiem_core::prevalence::{
    invalidate_coverage_probe_cache, PrevalenceCoverageState, PrevalenceService, TimeWindow,
};

const SEEN_HASH: &str = "abababababababababababababababababababababababababababababababab";
const UNSEEN_HASH: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

async fn execute(client: &clickhouse::Client, sql: &str) {
    client
        .query(sql)
        .execute()
        .await
        .unwrap_or_else(|error| panic!("ClickHouse statement failed: {error}\n{sql}"));
}

async fn log_at(client: &clickhouse::Client, hours_ago: u64) {
    execute(
        client,
        &format!(
            "INSERT INTO nanosiem.logs (timestamp, source_type, message) \
             VALUES (now64(3) - INTERVAL {hours_ago} HOUR, 'coverage_test', 'coverage probe')"
        ),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable migrated ClickHouse"]
async fn misses_are_unknown_until_prevalence_covers_the_window() {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    // Uncompressed: some disposable server builds answer the client's LZ4
    // request with an unframed body ("incorrect magic number").
    let mut client = clickhouse::Client::default()
        .with_url(url)
        .with_database("nanosiem")
        .with_compression(clickhouse::Compression::None);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    for table in [
        "hash_prevalence_agg",
        "domain_prevalence_agg",
        "ip_prevalence_agg",
        "hash_prevalence_source_agg",
        "domain_prevalence_source_agg",
        "ip_prevalence_source_agg",
        "logs",
    ] {
        execute(&client, &format!("TRUNCATE TABLE nanosiem.{table}")).await;
    }
    let service = PrevalenceService::new(client.clone(), TableNames::new(false));
    let system = ArtifactScope::system();

    // Fresh install: no prevalence rows at all.
    invalidate_coverage_probe_cache();
    let empty = service
        .coverage_report(TimeWindow::TwentyFourHours, CoverageSource::Live, &system)
        .await
        .combined(&[]);
    assert_eq!(empty.state, PrevalenceCoverageState::Warming);
    assert_eq!(empty.covered_since, None);

    // Two days of events and prevalence.
    log_at(&client, 48).await;
    log_at(&client, 0).await;
    execute(
        &client,
        &format!(
            "INSERT INTO nanosiem.hash_prevalence_agg \
             SELECT '{SEEN_HASH}', 'sha256', toStartOfHour(now() - INTERVAL 48 HOUR), uniqState('host-a'), \
                    now64(6) - INTERVAL 48 HOUR, now64(6) - INTERVAL 48 HOUR, toUInt64(1)"
        ),
    )
    .await;
    invalidate_coverage_probe_cache();

    let day_report = service.coverage_report(TimeWindow::TwentyFourHours, CoverageSource::Live, &system).await;
    let day = day_report.kind(ArtifactKind::Hash).clone();
    assert_eq!(day.state, PrevalenceCoverageState::Ready, "{day:?}");
    assert!(day.covered_since.is_some() && day.ingest_head.is_some());
    // Only the hash table has rows: domain coverage is unknown, not borrowed.
    assert_eq!(day_report.kind(ArtifactKind::Domain).state, PrevalenceCoverageState::Warming);
    let week_report = service.coverage_report(TimeWindow::SevenDays, CoverageSource::Live, &system).await;
    let week = week_report.kind(ArtifactKind::Hash).clone();
    assert_eq!(week.state, PrevalenceCoverageState::Warming, "{week:?}");

    // The real lookup: a miss inside coverage is a definitive zero, a miss
    // outside it is unknown.
    let mut rows = service
        .get_bulk_prevalence(&[SEEN_HASH.to_string(), UNSEEN_HASH.to_string()], TimeWindow::SevenDays, &system)
        .await
        .expect("bulk lookup");
    rows.sort_by(|a, b| a.artifact.cmp(&b.artifact));
    assert_eq!(rows[0].artifact, SEEN_HASH);
    assert_eq!(rows[0].host_count, Some(1));
    assert_eq!(rows[1].host_count, Some(0), "service rows are raw; coverage applies at the edge");
    for row in &mut rows {
        week_report.apply(row);
    }
    assert_eq!(rows[0].host_count, Some(1), "found rows never change");
    assert_eq!(rows[1].host_count, None, "a miss while warming is unknown");
    assert!(!rows[1].is_rare);

    let scatter = service
        .get_scatter_data(&[UNSEEN_HASH.to_string()], &[], &[], TimeWindow::SevenDays, &system)
        .await
        .expect("scatter");
    assert_eq!(scatter.hash_points[0].host_count, None);
    assert_eq!(scatter.product_state.as_ref().map(|s| s.state), Some(PrevalenceCoverageState::Warming));
    let scatter_day = service
        .get_scatter_data(&[UNSEEN_HASH.to_string()], &[], &[], TimeWindow::TwentyFourHours, &system)
        .await
        .expect("scatter 24h");
    assert_eq!(scatter_day.hash_points[0].host_count, Some(0));

    // Events far older than prevalence: a prevalence gap, not a young install.
    log_at(&client, 24 * 200).await;
    invalidate_coverage_probe_cache();
    let gap = service
        .coverage_report(TimeWindow::SevenDays, CoverageSource::Live, &system)
        .await
        .kind(ArtifactKind::Hash)
        .clone();
    assert_eq!(gap.state, PrevalenceCoverageState::Partial, "{gap:?}");

    // The refreshed snapshot reports the refreshable views' last success.
    let refreshed = service
        .coverage_report(TimeWindow::TwentyFourHours, CoverageSource::Refreshed, &system)
        .await
        .kind(ArtifactKind::Hash)
        .clone();
    let views: u64 = client
        .query("SELECT count() FROM system.view_refreshes WHERE view LIKE '%_prevalence_final_refresh' AND last_success_time IS NOT NULL")
        .fetch_one()
        .await
        .expect("view_refreshes");
    assert_eq!(refreshed.refreshed_at.is_some(), views > 0, "{refreshed:?}");

    for table in ["hash_prevalence_agg", "logs"] {
        execute(&client, &format!("TRUNCATE TABLE nanosiem.{table}")).await;
    }
    invalidate_coverage_probe_cache();
}

async fn client_from_env() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    let mut client = clickhouse::Client::default()
        .with_url(url)
        .with_database("nanosiem")
        .with_compression(clickhouse::Compression::None);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    for table in [
        "hash_prevalence_agg",
        "domain_prevalence_agg",
        "ip_prevalence_agg",
        "hash_prevalence_source_agg",
        "domain_prevalence_source_agg",
        "ip_prevalence_source_agg",
        "logs",
    ] {
        execute(&client, &format!("TRUNCATE TABLE nanosiem.{table}")).await;
    }
    invalidate_coverage_probe_cache();
    client
}

/// P1-1: hash prevalence covers 60 days, the domain table is empty. A 30-day
/// lookup of an unseen domain is unknown (null); an unseen hash is a definitive 0.
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable migrated ClickHouse"]
async fn an_empty_kind_never_borrows_another_kinds_coverage() {
    let client = client_from_env().await;
    log_at(&client, 24 * 60).await;
    log_at(&client, 0).await;
    execute(
        &client,
        &format!(
            "INSERT INTO nanosiem.hash_prevalence_agg \
             SELECT '{SEEN_HASH}', 'sha256', toStartOfHour(now() - INTERVAL 60 DAY), uniqState('host-a'), \
                    now64(6) - INTERVAL 60 DAY, now64(6) - INTERVAL 60 DAY, toUInt64(1)"
        ),
    )
    .await;
    let service = PrevalenceService::new(client.clone(), TableNames::new(false));
    let system = ArtifactScope::system();
    let report = service.coverage_report(TimeWindow::ThirtyDays, CoverageSource::Live, &system).await;
    let mut rows = service
        .get_bulk_prevalence(&[UNSEEN_HASH.to_string(), "unseen-domain.example.com".to_string()], TimeWindow::ThirtyDays, &system)
        .await
        .expect("bulk");
    for row in &mut rows {
        report.apply(row);
    }
    let by = |artifact: &str| rows.iter().find(|r| r.artifact == artifact).expect("row").host_count;
    assert_eq!(by(UNSEEN_HASH), Some(0), "hash table covers 30 days: a definitive miss");
    assert_eq!(by("unseen-domain.example.com"), None, "domain table is empty: unknown");

    let scatter = service
        .get_scatter_data(&[], &["unseen-domain.example.com".to_string()], &[], TimeWindow::ThirtyDays, &system)
        .await
        .expect("scatter");
    assert_eq!(scatter.domain_points[0].host_count, None);
    invalidate_coverage_probe_cache();
}

/// P1-2: an upgraded install. The legacy global table covers 60 days, the
/// source-attributed table (never backfilled) only the last 2 days. A
/// restricted viewer's 30-day miss is unknown, and their state carries no
/// cross-source timestamps; an unrestricted viewer's miss is a definitive 0.
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable migrated ClickHouse"]
async fn restricted_viewers_get_coverage_from_their_attributed_rows() {
    let client = client_from_env().await;
    let profile = nanosiem_core::schema::active_log_telemetry_profile();
    log_at(&client, 24 * 60).await;
    log_at(&client, 0).await;
    execute(
        &client,
        &format!(
            "INSERT INTO nanosiem.hash_prevalence_agg \
             SELECT '{SEEN_HASH}', 'sha256', toStartOfHour(now() - INTERVAL 60 DAY), uniqState('host-a'), \
                    now64(6) - INTERVAL 60 DAY, now64(6) - INTERVAL 60 DAY, toUInt64(1)"
        ),
    )
    .await;
    for (source, days) in [("allowed", 2), ("secret", 40)] {
        execute(
            &client,
            &format!(
                "INSERT INTO nanosiem.hash_prevalence_source_agg \
                 SELECT '{profile}', '{source}', '{SEEN_HASH}', 'sha256', toStartOfHour(now() - INTERVAL {days} DAY), \
                        uniqState('host-{source}'), now64(6) - INTERVAL {days} DAY, now64(6) - INTERVAL {days} DAY, toUInt64(1)"
            ),
        )
        .await;
    }
    let service = PrevalenceService::new(client.clone(), TableNames::new(false));
    let restricted = ArtifactScope::from_scope(&ScopeSet::from_denied(
        ["secret".to_string()].into_iter().collect::<BTreeSet<_>>(),
    ));

    let unrestricted = service
        .coverage_report(TimeWindow::ThirtyDays, CoverageSource::Live, &ArtifactScope::system())
        .await;
    assert_eq!(unrestricted.kind(ArtifactKind::Hash).state, PrevalenceCoverageState::Ready);

    let scoped = service.coverage_report(TimeWindow::ThirtyDays, CoverageSource::Live, &restricted).await;
    let hash = scoped.kind(ArtifactKind::Hash);
    assert_eq!(hash.state, PrevalenceCoverageState::Partial, "{hash:?}");
    assert_eq!(hash.covered_since, None, "no coverage start derived from other sources");
    assert_eq!(hash.ingest_head, None, "no newest-event time from denied sources");

    let mut rows = service
        .get_bulk_prevalence(&[UNSEEN_HASH.to_string()], TimeWindow::ThirtyDays, &restricted)
        .await
        .expect("restricted bulk");
    scoped.apply(&mut rows[0]);
    assert_eq!(rows[0].host_count, None, "restricted miss before attribution covered the window: unknown");

    // The 24h window IS covered by the viewer's own attributed rows.
    let day = service.coverage_report(TimeWindow::TwentyFourHours, CoverageSource::Live, &restricted).await;
    assert_eq!(day.kind(ArtifactKind::Hash).state, PrevalenceCoverageState::Ready);
    // A different deny set is a different cache identity: denying `allowed`
    // leaves only the 40-day `secret` rows, which do cover 30 days.
    let other = ArtifactScope::from_scope(&ScopeSet::from_denied(
        ["allowed".to_string()].into_iter().collect::<BTreeSet<_>>(),
    ));
    let other_report = service.coverage_report(TimeWindow::ThirtyDays, CoverageSource::Live, &other).await;
    assert_eq!(other_report.kind(ArtifactKind::Hash).state, PrevalenceCoverageState::Ready);
    invalidate_coverage_probe_cache();
}

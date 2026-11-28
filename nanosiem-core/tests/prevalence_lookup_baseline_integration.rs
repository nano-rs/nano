// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5722 against a real ClickHouse: the Prevalence API lookups
//! (`POST /api/prevalence/bulk`, the single-artifact GETs, the rarity scatter)
//! report the same host count as `| prevalence enrich=true` and the
//! dictionaries for the same artifact and window.
//!
//! Scenario (the e2e seed's "14 vs 13 at 24h"): a binary ran on three hosts
//! 60 hours ago and on a fourth host an hour ago. At window=24h the search
//! decoration reads the 30-day baseline (4 hosts) while the bulk API used to
//! merge only the hourly buckets inside the window (1 host).
//!
//! The schema comes from `clickhouse/init.sql` and migration 170 (the agg
//! tables, the per-entity summaries and the agg -> summary MVs), so rows reach
//! the summary through the production MV chain. `#[ignore]`d: point
//! `NANOSIEM_TEST_CLICKHOUSE_URL` at a DISPOSABLE ClickHouse (the suite
//! truncates the prevalence tables):
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18923 \
//!   cargo test -p nanosiem-core --test prevalence_lookup_baseline_integration \
//!   -- --ignored --nocapture
//! ```

use nanosiem_core::auth::{ArtifactScope, ScopeSet};
use nanosiem_core::db::TableNames;
use nanosiem_core::prevalence::{PrevalenceData, PrevalenceService, TimeWindow};
use std::collections::BTreeSet;

const INIT_SQL: &str = include_str!("../../clickhouse/init.sql");
const SOURCE_SQL: &str = include_str!("../../clickhouse/170_prevalence_source_attribution.sql");

const COMMON_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OLD_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DOMAIN: &str = "updates.example.net";
const IP: &str = "198.51.100.23";

/// The `CREATE ...` statement for `object` in `sql` (statements end with `;`).
fn statement(sql: &str, create: &str, object: &str) -> String {
    let needle = format!("{create} nanosiem.{object}\n");
    let start = sql
        .find(&needle)
        .unwrap_or_else(|| panic!("no `{create} nanosiem.{object}` in the schema"));
    let end = sql[start..].find(';').expect("statement terminator") + start;
    sql[start..end].replace(" /* nano:skip-if-unknown-table */", "")
}

async fn execute(client: &clickhouse::Client, sql: &str) {
    client
        .query(sql)
        .execute()
        .await
        .unwrap_or_else(|error| panic!("ClickHouse statement failed: {error}\n{sql}"));
}

fn client() -> clickhouse::Client {
    let url = nanosiem_test_db::require_ch_url();
    let mut client = clickhouse::Client::default()
        .with_url(url)
        .with_compression(clickhouse::Compression::None);
    if let Some(user) = nanosiem_test_db::ch_user() {
        client = client.with_user(user);
    }
    if let Some(password) = nanosiem_test_db::ch_password() {
        client = client.with_password(password);
    }
    client
}

async fn ensure_schema(client: &clickhouse::Client) {
    execute(client, "CREATE DATABASE IF NOT EXISTS nanosiem").await;
    for kind in ["hash", "domain", "ip"] {
        for object in [format!("{kind}_prevalence_agg"), format!("{kind}_prevalence_summary")] {
            execute(client, &statement(INIT_SQL, "CREATE TABLE IF NOT EXISTS", &object)).await;
        }
        let mv = format!("{kind}_prevalence_summary_mv");
        execute(client, &statement(INIT_SQL, "CREATE MATERIALIZED VIEW IF NOT EXISTS", &mv)).await;
    }
    execute(
        client,
        &statement(SOURCE_SQL, "CREATE TABLE IF NOT EXISTS", "hash_prevalence_source_summary"),
    )
    .await;
    for table in [
        "hash_prevalence_agg",
        "hash_prevalence_summary",
        "domain_prevalence_agg",
        "domain_prevalence_summary",
        "ip_prevalence_agg",
        "ip_prevalence_summary",
        "hash_prevalence_source_summary",
    ] {
        execute(client, &format!("TRUNCATE TABLE nanosiem.{table}")).await;
    }
}

/// One host's sighting `hours_ago`, written to the hourly agg table exactly
/// as the ingest MVs do; the summary MV carries it into the baseline.
async fn sight(client: &clickhouse::Client, kind: &str, artifact: &str, host: &str, hours_ago: u64) {
    let at = format!("now64(6) - INTERVAL {hours_ago} HOUR");
    let bucket = format!("toStartOfHour(now() - INTERVAL {hours_ago} HOUR)");
    let sql = match kind {
        "hash" => format!(
            "INSERT INTO nanosiem.hash_prevalence_agg \
             SELECT '{artifact}', 'sha256', {bucket}, uniqState('{host}'), {at}, {at}, toUInt64(1)"
        ),
        "domain" => format!(
            "INSERT INTO nanosiem.domain_prevalence_agg \
             SELECT '{artifact}', toUInt8(1), 'example.net', {bucket}, uniqState('{host}'), {at}, {at}, toUInt64(1)"
        ),
        "ip" => format!(
            "INSERT INTO nanosiem.ip_prevalence_agg \
             SELECT '{artifact}', 'dest', toUInt8(0), {bucket}, uniqState('{host}'), {at}, {at}, toUInt64(1)"
        ),
        other => unreachable!("{other}"),
    };
    execute(client, &sql).await;
}

fn find<'a>(rows: &'a [PrevalenceData], artifact: &str) -> Option<&'a PrevalenceData> {
    rows.iter().find(|r| r.artifact.eq_ignore_ascii_case(artifact))
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn bulk_lookup_counts_the_same_baseline_as_the_search_decoration() {
    let client = client();
    ensure_schema(&client).await;

    for kind_artifact in [("hash", COMMON_HASH), ("domain", DOMAIN), ("ip", IP)] {
        let (kind, artifact) = kind_artifact;
        for host in ["host-1", "host-2", "host-3"] {
            sight(&client, kind, artifact, host, 60).await;
        }
        sight(&client, kind, artifact, "host-4", 1).await;
    }
    sight(&client, "hash", OLD_HASH, "host-1", 60).await;

    let system = ArtifactScope::system();
    let artifacts: Vec<String> =
        [COMMON_HASH, OLD_HASH, DOMAIN, IP].iter().map(|a| a.to_string()).collect();

    for window in [TimeWindow::TwentyFourHours, TimeWindow::SevenDays, TimeWindow::ThirtyDays] {
        // A fresh service per window: no cache carried between the two reads.
        let api = PrevalenceService::new(client.clone(), TableNames::new(false))
            .get_bulk_prevalence(&artifacts, window, &system)
            .await
            .expect("bulk prevalence");
        // What `| prevalence enrich=true` decorates with when the dict has not
        // loaded the key yet (NAN-1705 / NAN-5718): the dicts' own source.
        let decoration = PrevalenceService::new(client.clone(), TableNames::new(false))
            .get_bulk_summary_prevalence(&artifacts, window, &system)
            .await
            .expect("summary prevalence");

        for artifact in [COMMON_HASH, DOMAIN, IP] {
            let api_row = find(&api, artifact).expect("bulk row");
            let decorated = find(&decoration, artifact).expect("decoration row");
            assert_eq!(
                api_row.host_count,
                Some(4),
                "{window}: {artifact} bulk counts the 30-day baseline, not only in-window hosts"
            );
            assert_eq!(api_row.host_count, decorated.host_count, "{window}: {artifact}");
            assert_eq!(api_row.total_occurrences, decorated.total_occurrences, "{window}: {artifact}");
            assert_eq!(api_row.total_occurrences, 4, "{window}: {artifact}");
            assert_eq!(api_row.first_seen, decorated.first_seen, "{window}: {artifact}");
            assert_eq!(api_row.last_seen, decorated.last_seen, "{window}: {artifact}");
            assert_eq!(api_row.is_rare, decorated.is_rare, "{window}: {artifact}");
            assert_eq!(api_row.prevalence_score, decorated.prevalence_score, "{window}: {artifact}");
        }

        // The window gates recency the same way on both: last seen 60h ago is
        // out of a 24h window and inside 7d / 30d.
        let old = find(&api, OLD_HASH).expect("bulk returns every requested artifact");
        match window {
            TimeWindow::TwentyFourHours => {
                assert_eq!(old.host_count, Some(0), "not seen inside 24h");
                assert!(find(&decoration, OLD_HASH).is_none());
            }
            _ => {
                assert_eq!(old.host_count, Some(1), "{window}");
                assert_eq!(find(&decoration, OLD_HASH).and_then(|d| d.host_count), Some(1));
            }
        }
    }

    // The single-artifact GETs share the lookup.
    let service = PrevalenceService::new(client.clone(), TableNames::new(false));
    let single = service
        .get_hash_prevalence(COMMON_HASH, TimeWindow::TwentyFourHours, &system)
        .await
        .expect("single hash");
    assert_eq!(single.host_count, Some(4));
    let domain = service
        .get_domain_prevalence(&DOMAIN.to_uppercase(), TimeWindow::TwentyFourHours, &system)
        .await
        .expect("single domain");
    assert_eq!(domain.host_count, Some(4), "mixed-case input matches lowercased storage");
    let ip = service
        .get_ip_prevalence(IP, TimeWindow::TwentyFourHours, &system)
        .await
        .expect("single ip");
    assert_eq!(ip.host_count, Some(4));

    restricted_lookup_reads_the_attributed_baseline(&client).await;
}

/// Restricted viewers read the source-attributed summary with the deny filter
/// applied before the merge. Review P2: denied source names travel as a
/// server-side `Array(String)` parameter, so a `?`, `?fields` or quote in one
/// neither breaks the query ("unbound query argument") nor rewrites the deny
/// entry. On main every restricted prevalence read below failed or leaked.
/// (Run from the test above: both truncate the same tables.)
async fn restricted_lookup_reads_the_attributed_baseline(client: &clickhouse::Client) {
    const ODD: [&str; 2] = ["secret?", "o'brien?fields"];
    let profile = nanosiem_core::schema::active_log_telemetry_profile();
    for (source, host, hours_ago) in [
        ("allowed", "host-a", 60),
        ("allowed", "host-b", 1),
        (ODD[0], "host-c", 1),
        (ODD[1], "host-d", 1),
    ] {
        // `query_raw`: the seed itself must not be read as client binds.
        let sql = format!(
            "INSERT INTO nanosiem.hash_prevalence_source_summary \
             SELECT '{profile}', '{source}', '{COMMON_HASH}', 'sha256', uniqState('{host}'), \
             now64(6) - INTERVAL {hours_ago} HOUR, now64(6) - INTERVAL {hours_ago} HOUR, toUInt64(1)",
            source = source.replace('\'', "''"),
        );
        client
            .query_raw(&sql)
            .execute()
            .await
            .unwrap_or_else(|error| panic!("seed failed: {error}\n{sql}"));
    }
    let restricted = ArtifactScope::from_scope(&ScopeSet::from_denied(
        ODD.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>(),
    ));
    let service = || PrevalenceService::new(client.clone(), TableNames::new(false));

    let rows = service()
        .get_bulk_prevalence(&[COMMON_HASH.to_string()], TimeWindow::TwentyFourHours, &restricted)
        .await
        .expect("restricted bulk");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].host_count, Some(2), "the allowed source's baseline, both denied hosts excluded");
    assert_eq!(rows[0].total_occurrences, 2);

    // The restricted `| prevalence` decoration / filter source.
    let decoration = service()
        .get_bulk_summary_prevalence(&[COMMON_HASH.to_string()], TimeWindow::TwentyFourHours, &restricted)
        .await
        .expect("restricted summary prevalence");
    assert_eq!(decoration.first().and_then(|d| d.host_count), Some(2));

    // The rare / new explorer reads.
    let rare = service()
        .get_rare_artifacts(Some(nanosiem_core::prevalence::ArtifactType::HashSha256), TimeWindow::ThirtyDays, 10, &restricted)
        .await
        .expect("restricted rare artifacts");
    let rare_hit = find(&rare, COMMON_HASH).expect("2 allowed hosts is rare at threshold 3");
    assert_eq!(rare_hit.host_count, Some(2));
    let new = service()
        .get_new_artifacts(
            Some(nanosiem_core::prevalence::ArtifactType::HashSha256),
            chrono::Utc::now() - chrono::Duration::days(3),
            10,
            &restricted,
        )
        .await
        .expect("restricted new artifacts");
    assert!(find(&new, COMMON_HASH).is_some(), "{new:?}");
}

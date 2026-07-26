// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2053 ClickHouse regression.
//!
//! This intentionally exercises the production `PrevalenceService` and
//! `PrevalenceRepository` SQL. It is ignored in the default unit suite because
//! it truncates prevalence tables in the explicitly supplied disposable
//! ClickHouse instance:
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test prevalence_source_scope_integration \
//!   -- --ignored --nocapture
//! ```

use chrono::{Duration, Utc};
use nanosiem_core::auth::{ArtifactScope, ScopeSet};
use nanosiem_core::db::TableNames;
use nanosiem_core::prevalence::{ArtifactType, PrevalenceService, TimeWindow};
use std::collections::BTreeSet;

const MAIN_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ALLOWED_LIMIT_HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const DENIED_LIMIT_HASH: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const MIXED_DOMAIN: &str = "mixed.example.com";
const MIXED_IP: &str = "8.8.4.4";

#[test]
fn fresh_ocsf_boot_recreates_views_skipped_before_overlay() {
    const MIGRATION: &str = include_str!("../../clickhouse/170_prevalence_source_attribution.sql");
    const OCSF_OVERLAY: &str = include_str!("../../clickhouse/ocsf/init.sql");

    fn view_statement(sql: &str, view: &str) -> String {
        let needle = format!("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.{view}");
        let statement = sql
            .split(';')
            .find(|statement| statement.contains(&needle))
            .unwrap_or_else(|| panic!("missing materialized view {view}"));
        let start = statement
            .find(&needle)
            .expect("matched statement must contain its CREATE");
        statement[start..]
            .replace(" /* nano:skip-if-unknown-table */", "")
            .trim()
            .to_string()
    }

    for view in [
        "hash_prevalence_source_ocsf_mv",
        "domain_prevalence_source_ocsf_mv",
        "ip_prevalence_source_ocsf_mv",
    ] {
        let migration_create =
            format!("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.{view} /* nano:skip-if-unknown-table */");
        assert!(
            MIGRATION.contains(&migration_create),
            "numbered migration must skip {view} on fresh UDM/OCSF pre-overlay runs"
        );
        let overlay_create = format!("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.{view}");
        assert!(
            OCSF_OVERLAY.contains(&overlay_create),
            "fresh OCSF overlay must create {view} after ocsf_logs exists"
        );
        assert_eq!(
            view_statement(MIGRATION, view),
            view_statement(OCSF_OVERLAY, view),
            "upgrade and fresh-boot OCSF definitions must not drift for {view}"
        );
    }
}

fn scope(denied: &[&str]) -> ArtifactScope {
    ArtifactScope::from_scope(&ScopeSet::from_denied(
        denied
            .iter()
            .map(|value| value.to_string())
            .collect::<BTreeSet<_>>(),
    ))
}

async fn execute(client: &clickhouse::Client, sql: &str) {
    client.query(sql).execute().await.unwrap_or_else(|error| {
        panic!("ClickHouse statement failed: {error}\n{sql}");
    });
}

async fn insert_hash(
    client: &clickhouse::Client,
    hash: &str,
    source_type: &str,
    host: &str,
    seconds_ago: u64,
) {
    let profile = nanosiem_core::schema::active_log_telemetry_profile();
    let legacy = format!(
        "INSERT INTO nanosiem.hash_prevalence_agg
         SELECT '{hash}', 'sha256', toStartOfHour(now() - INTERVAL {seconds_ago} SECOND),
                uniqState('{host}'), now64(6) - INTERVAL {seconds_ago} SECOND,
                now64(6) - INTERVAL {seconds_ago} SECOND, toUInt64(1)"
    );
    execute(client, &legacy).await;

    let attributed = format!(
        "INSERT INTO nanosiem.hash_prevalence_source_agg
         SELECT '{profile}', '{source_type}', '{hash}', 'sha256',
                toStartOfHour(now() - INTERVAL {seconds_ago} SECOND),
                uniqState('{host}'), now64(6) - INTERVAL {seconds_ago} SECOND,
                now64(6) - INTERVAL {seconds_ago} SECOND, toUInt64(1)"
    );
    execute(client, &attributed).await;
}

async fn insert_domain(
    client: &clickhouse::Client,
    source_type: &str,
    host: &str,
    seconds_ago: u64,
) {
    let profile = nanosiem_core::schema::active_log_telemetry_profile();
    let legacy = format!(
        "INSERT INTO nanosiem.domain_prevalence_agg
         SELECT '{MIXED_DOMAIN}', toUInt8(1), '', toStartOfHour(now()),
                uniqState('{host}'), now64(6) - INTERVAL {seconds_ago} SECOND,
                now64(6) - INTERVAL {seconds_ago} SECOND, toUInt64(1)"
    );
    execute(client, &legacy).await;

    let attributed = format!(
        "INSERT INTO nanosiem.domain_prevalence_source_agg
         SELECT '{profile}', '{source_type}', '{MIXED_DOMAIN}', toUInt8(1),
                toStartOfHour(now()), uniqState('{host}'),
                now64(6) - INTERVAL {seconds_ago} SECOND,
                now64(6) - INTERVAL {seconds_ago} SECOND, toUInt64(1)"
    );
    execute(client, &attributed).await;
}

async fn insert_ip(
    client: &clickhouse::Client,
    source_type: &str,
    host: &str,
    seconds_ago: u64,
) {
    let profile = nanosiem_core::schema::active_log_telemetry_profile();
    let legacy = format!(
        "INSERT INTO nanosiem.ip_prevalence_agg
         SELECT '{MIXED_IP}', 'dest', toUInt8(0), toStartOfHour(now()),
                uniqState('{host}'), now64(6) - INTERVAL {seconds_ago} SECOND,
                now64(6) - INTERVAL {seconds_ago} SECOND, toUInt64(1)"
    );
    execute(client, &legacy).await;

    let attributed = format!(
        "INSERT INTO nanosiem.ip_prevalence_source_agg
         SELECT '{profile}', '{source_type}', '{MIXED_IP}', 'dest', toUInt8(0),
                toStartOfHour(now()), uniqState('{host}'),
                now64(6) - INTERVAL {seconds_ago} SECOND,
                now64(6) - INTERVAL {seconds_ago} SECOND, toUInt64(1)"
    );
    execute(client, &attributed).await;
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable migrated ClickHouse"]
async fn production_sql_filters_sources_before_merge_order_and_limit() {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    let mut client = clickhouse::Client::default()
        .with_url(url)
        .with_database("nanosiem");
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }

    for table in [
        "hash_prevalence_source_summary",
        "hash_prevalence_source_agg",
        "hash_prevalence_agg",
        "domain_prevalence_source_summary",
        "domain_prevalence_source_agg",
        "domain_prevalence_agg",
        "ip_prevalence_source_summary",
        "ip_prevalence_source_agg",
        "ip_prevalence_agg",
    ] {
        execute(&client, &format!("TRUNCATE TABLE nanosiem.{table}")).await;
    }

    // One visible contributor, two currently revocable contributors, audit,
    // and an unattributed legacy contribution. Restricted readers must see
    // exactly the visible contributor; SYSTEM retains the legacy fast path.
    insert_hash(&client, MAIN_HASH, "allowed", "host-allowed", 20).await;
    insert_hash(&client, MAIN_HASH, "secret", "host-secret-1", 15).await;
    insert_hash(&client, MAIN_HASH, "secret", "host-secret-2", 10).await;
    insert_hash(&client, MAIN_HASH, "audit", "host-audit", 5).await;
    insert_hash(&client, MAIN_HASH, "", "host-legacy-unattributed", 3).await;
    insert_hash(&client, MAIN_HASH, "unknown", "host-unknown-unattributed", 2).await;
    insert_domain(&client, "allowed", "domain-host-allowed", 10).await;
    insert_domain(&client, "secret", "domain-host-secret", 5).await;
    insert_ip(&client, "allowed", "ip-host-allowed", 10).await;
    insert_ip(&client, "secret", "ip-host-secret", 5).await;

    // The newest candidate is denied-only. LIMIT 1 must be applied after
    // source filtering so the older allowed candidate is still returned.
    insert_hash(
        &client,
        ALLOWED_LIMIT_HASH,
        "allowed",
        "host-allowed-limit",
        2,
    )
    .await;
    insert_hash(&client, DENIED_LIMIT_HASH, "secret", "host-denied-limit", 1).await;

    let service = PrevalenceService::new(client.clone(), TableNames::new(false));
    let system = ArtifactScope::system();
    let audit_denied = scope(&["audit"]);
    let revoked = scope(&["audit", "secret"]);

    let unrestricted = service
        .get_hash_prevalence(MAIN_HASH, TimeWindow::ThirtyDays, &system)
        .await
        .expect("SYSTEM prevalence");
    assert_eq!(
        unrestricted.host_count, 6,
        "default/system callers retain the legacy aggregate fast path, including unknown provenance"
    );

    let before_revocation = service
        .get_hash_prevalence(MAIN_HASH, TimeWindow::ThirtyDays, &audit_denied)
        .await
        .expect("audit-denied prevalence");
    assert_eq!(
        before_revocation.host_count, 3,
        "audit plus empty/unknown incomplete provenance are excluded before host aggregation"
    );

    let after_revocation = service
        .get_hash_prevalence(MAIN_HASH, TimeWindow::ThirtyDays, &revoked)
        .await
        .expect("revoked prevalence");
    assert_eq!(
        after_revocation.host_count, 1,
        "a later source revocation takes effect immediately and bypasses the system cache"
    );

    let scoped_domain = service
        .get_domain_prevalence(MIXED_DOMAIN, TimeWindow::ThirtyDays, &revoked)
        .await
        .expect("scoped domain prevalence");
    assert_eq!(
        scoped_domain.host_count, 1,
        "the domain lookup uses the same pre-aggregation source policy"
    );

    let unrestricted_ip = service
        .get_ip_prevalence(MIXED_IP, TimeWindow::ThirtyDays, &system)
        .await
        .expect("SYSTEM IP prevalence");
    assert_eq!(unrestricted_ip.host_count, 2);

    let scoped_ip = service
        .get_ip_prevalence(MIXED_IP, TimeWindow::ThirtyDays, &revoked)
        .await
        .expect("scoped IP prevalence");
    assert_eq!(
        scoped_ip.host_count, 1,
        "the IP lookup uses the same pre-aggregation source policy"
    );

    let bulk = service
        .get_bulk_prevalence(&[MAIN_HASH.to_string()], TimeWindow::ThirtyDays, &revoked)
        .await
        .expect("scoped bulk prevalence");
    assert_eq!(bulk.len(), 1);
    assert_eq!(bulk[0].host_count, 1);

    let rare = service
        .get_rare_artifacts(
            Some(ArtifactType::HashSha256),
            TimeWindow::ThirtyDays,
            1,
            &revoked,
        )
        .await
        .expect("scoped rare prevalence");
    assert_eq!(rare.len(), 1);
    assert_eq!(
        rare[0].artifact, ALLOWED_LIMIT_HASH,
        "denied-only newest row cannot consume the production query's LIMIT"
    );

    let new_artifacts = service
        .get_new_artifacts(
            Some(ArtifactType::HashSha256),
            Utc::now() - Duration::hours(1),
            10,
            &revoked,
        )
        .await
        .expect("scoped new artifacts");
    assert!(new_artifacts
        .iter()
        .any(|artifact| artifact.artifact == ALLOWED_LIMIT_HASH));
    assert!(
        new_artifacts
            .iter()
            .all(|artifact| artifact.artifact != DENIED_LIMIT_HASH),
        "new-artifact ordering/limit runs only over allowed contributions"
    );

    let explorer = service
        .get_artifact_explorer(
            Some(ArtifactType::HashSha256),
            TimeWindow::ThirtyDays,
            None,
            None,
            1,
            0,
            &revoked,
        )
        .await
        .expect("scoped explorer");
    assert_eq!(explorer.artifacts[0].artifact, ALLOWED_LIMIT_HASH);
    assert_eq!(
        explorer.artifacts[0].daily_counts.iter().sum::<u64>(),
        1,
        "the explorer heatmap must read the same source-filtered hourly aggregate"
    );

    let scatter = service
        .get_scatter_data(
            &[MAIN_HASH.to_string(), DENIED_LIMIT_HASH.to_string()],
            &[],
            &[],
            TimeWindow::ThirtyDays,
            &revoked,
        )
        .await
        .expect("scoped scatter");
    assert_eq!(scatter.hash_points.len(), 2);
    assert_eq!(scatter.hash_points[0].host_count, 1);
    assert_eq!(
        scatter.hash_points[1].host_count, 0,
        "a denied-only artifact remains an explicit zero in bounded scatter output"
    );
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2076 — source-safe cloud user-activity counters.
//!
//! These tests call the production routing/query builder directly. The ignored
//! ClickHouse regression seeds one shared principal across an allowed and a
//! denied source, constructs the base CTE with the canonical production scope
//! predicate, and proves every returned counter reflects allowed rows only.

use super::*;
use crate::auth::ScopeSet;
use crate::schema::{OcsfProfile, UdmProfile};
use chrono::{TimeZone, Utc};

fn range() -> TimeRange {
    TimeRange::new(
        Utc.with_ymd_and_hms(2026, 7, 25, 10, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 7, 25, 16, 0, 0).unwrap(),
    )
}

fn denied(items: &[&str]) -> ScopeSet {
    ScopeSet::from_denied(items.iter().map(|item| item.to_string()).collect())
}

#[test]
fn unrestricted_initial_view_keeps_legacy_aggregate_sql_byte_for_byte() {
    let sql = build_cloud_user_activity_sql(
        &UdmProfile::new(),
        "WITH cloud_base AS (SELECT * FROM nanosiem.logs)",
        "cloud_base",
        "nanosiem.cloud_user_activity_agg",
        &range(),
        &ScopeSet::unrestricted(),
        "            ",
    )
    .expect("UDM has a cloud principal");

    assert_eq!(
        sql,
        r#"WITH cloud_base AS (SELECT * FROM nanosiem.logs)
            SELECT
                cb.user AS user,
                sum(ua.event_count) AS event_count,
                uniqMerge(ua.distinct_services) AS distinct_services,
                uniqMerge(ua.distinct_regions) AS distinct_regions,
                uniqMerge(ua.distinct_ips) AS distinct_ips,
                sum(ua.fail_count) AS fail_count,
                sum(ua.permission_change_count) AS permission_change_count,
                sum(ua.delete_count) AS delete_count,
                sum(ua.mfa_count) AS mfa_count,
                sum(ua.no_mfa_count) AS no_mfa_count
            FROM nanosiem.cloud_user_activity_agg AS ua
            INNER JOIN (
                SELECT DISTINCT "user" AS user
                FROM cloud_base
                WHERE "user" != ''
            ) AS cb ON ua.user = cb.user
            WHERE ua.time_bucket >= toStartOfHour(toDateTime('2026-07-25 10:00:00'))
              AND ua.time_bucket <= '2026-07-25 16:00:00'
            GROUP BY cb.user
            ORDER BY event_count DESC
            LIMIT 200"#
    );
}

#[test]
fn unrestricted_filtered_refresh_keeps_legacy_aggregate_sql_byte_for_byte() {
    let sql = build_cloud_user_activity_sql(
        &UdmProfile::new(),
        "WITH cloud_base AS (SELECT * FROM nanosiem.logs), cloud_filtered AS (SELECT * FROM cloud_base WHERE cloud_region = ?)",
        "cloud_filtered",
        "nanosiem.cloud_user_activity_agg",
        &range(),
        &ScopeSet::unrestricted(),
        "                ",
    )
    .expect("UDM has a cloud principal");

    assert_eq!(
        sql,
        r#"WITH cloud_base AS (SELECT * FROM nanosiem.logs), cloud_filtered AS (SELECT * FROM cloud_base WHERE cloud_region = ?)
                SELECT
                    cb.user AS user,
                    sum(ua.event_count) AS event_count,
                    uniqMerge(ua.distinct_services) AS distinct_services,
                    uniqMerge(ua.distinct_regions) AS distinct_regions,
                    uniqMerge(ua.distinct_ips) AS distinct_ips,
                    sum(ua.fail_count) AS fail_count,
                    sum(ua.permission_change_count) AS permission_change_count,
                    sum(ua.delete_count) AS delete_count,
                    sum(ua.mfa_count) AS mfa_count,
                    sum(ua.no_mfa_count) AS no_mfa_count
                FROM nanosiem.cloud_user_activity_agg AS ua
                INNER JOIN (
                    SELECT DISTINCT "user" AS user
                    FROM cloud_filtered
                    WHERE "user" != ''
                ) AS cb ON ua.user = cb.user
                WHERE ua.time_bucket >= toStartOfHour(toDateTime('2026-07-25 10:00:00'))
                  AND ua.time_bucket <= '2026-07-25 16:00:00'
                GROUP BY cb.user
                ORDER BY event_count DESC
                LIMIT 200"#
    );
}

#[test]
fn nonempty_scope_uses_raw_scoped_cte_and_udm_mv_equivalent_counters() {
    let scope = denied(&["audit", "hidden_cloud"]);
    let scope_predicate = source_scope_sql_predicate("source_type", scope.deny_set())
        .expect("nonempty scope renders");
    let base_scan = build_cloud_fallback_scan_sql(
        "nanosiem.logs",
        "2026-07-25 10:00:00.000000",
        "2026-07-25 16:00:00.000000",
        Some(&scope_predicate),
    );
    let with_clause = format!("WITH cloud_base AS ({base_scan})");
    let sql = build_cloud_user_activity_sql(
        &UdmProfile::new(),
        &with_clause,
        "cloud_base",
        "nanosiem.cloud_user_activity_agg",
        &range(),
        &scope,
        "            ",
    )
    .expect("restricted raw query");

    assert!(sql.contains("FROM cloud_base"));
    assert!(!sql.contains("cloud_user_activity_agg"));
    assert!(sql.contains("lower(source_type) NOT IN ('audit', 'hidden_cloud')"));
    assert!(sql.contains("count() AS event_count"));
    assert!(sql.contains("uniq(cloud_service) AS distinct_services"));
    assert!(sql.contains("uniq(cloud_region) AS distinct_regions"));
    assert!(sql.contains("uniq(src_ip) AS distinct_ips"));
    assert!(sql.contains("countIf(http_status_code >= 400) AS fail_count"));
    assert!(sql.contains("countIf(change_type = 'permission_change') AS permission_change_count"));
    assert!(sql.contains("countIf(change_type = 'delete') AS delete_count"));
    assert!(sql.contains("countIf(mfa_used = 1) AS mfa_count"));
    assert!(sql.contains("WHERE cloud_provider != '' AND \"user\" != ''"));
}

#[test]
fn restricted_ocsf_raw_query_matches_ocsf_mv_counter_semantics() {
    let sql = build_cloud_user_activity_sql(
        &OcsfProfile::new(),
        "WITH cloud_base AS (SELECT * FROM nanosiem.ocsf_logs WHERE lower(source_type) != 'hidden_cloud')",
        "cloud_base",
        "nanosiem.cloud_user_activity_agg",
        &range(),
        &denied(&["hidden_cloud"]),
        "            ",
    )
    .expect("OCSF has a cloud principal");

    assert!(!sql.contains("cloud_user_activity_agg"));
    assert!(sql.contains("uniq(\"api.service.name\") AS distinct_services"));
    assert!(sql.contains("uniq(\"cloud.region\") AS distinct_regions"));
    assert!(sql.contains("uniq(\"src_endpoint.ip\") AS distinct_ips"));
    assert!(sql.contains("countIf((\"http_response.code\" >= 400 OR status_id = 2)) AS fail_count"));
    assert!(sql.contains("countIf(0) AS permission_change_count"));
    assert!(sql.contains("countIf((class_uid = 6003 AND activity_id = 4)) AS delete_count"));
    assert!(sql.contains("countIf(is_mfa = 1) AS mfa_count"));
    assert!(sql.contains("\"cloud.provider\" != ''"));
    assert!(sql.contains("if(\"actor.user.name\" != ''"));
}

mod live {
    use super::*;

    #[derive(Debug, clickhouse::Row, serde::Deserialize)]
    struct UserActivityRow {
        user: String,
        event_count: u64,
        distinct_services: u64,
        distinct_regions: u64,
        distinct_ips: u64,
        fail_count: u64,
        permission_change_count: u64,
        delete_count: u64,
        mfa_count: u64,
        no_mfa_count: u64,
    }

    fn nonce() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    }

    async fn local_clickhouse() -> Option<clickhouse::Client> {
        let client = clickhouse::Client::default()
            .with_url("http://localhost:8123")
            .with_database("nanosiem");
        match client.query("SELECT toUInt8(1)").fetch_one::<u8>().await {
            Ok(_) => Some(client),
            Err(error) => {
                eprintln!("Could not connect to local ClickHouse ({error}); is the stack up?");
                None
            }
        }
    }

    /// End-to-end counter regression against a real ClickHouse query: the same
    /// principal has allowed + denied contributions with deliberately different
    /// services, regions, IPs, failures, changes and MFA states. The production
    /// scope predicate and production user-activity builder must expose only the
    /// allowed contribution, while a denied-only principal stays absent.
    #[tokio::test]
    #[ignore = "requires local ClickHouse"]
    async fn shared_principal_counters_exclude_denied_source_contributions() {
        let Some(client) = local_clickhouse().await else {
            return;
        };

        let suffix = nonce();
        let table = format!("nanosiem.nan2076_cloud_scope_{suffix}");
        let shared_user = format!("nan2076-shared-{suffix}");
        let denied_only_user = format!("nan2076-denied-only-{suffix}");
        let create_sql = format!(
            r#"CREATE TABLE {table}
            (
                timestamp DateTime64(6, 'UTC'),
                source_type LowCardinality(String),
                `user` String,
                cloud_provider String,
                cloud_service String,
                cloud_region String,
                src_ip String,
                http_status_code UInt16,
                change_type String,
                mfa_used UInt8
            )
            ENGINE = MergeTree()
            ORDER BY timestamp"#
        );
        client
            .query(&create_sql)
            .execute()
            .await
            .expect("create isolated NAN-2076 fixture table");

        let insert_sql = format!(
            r#"INSERT INTO {table}
            (timestamp, source_type, `user`, cloud_provider, cloud_service, cloud_region, src_ip, http_status_code, change_type, mfa_used)
            VALUES
            ('2026-07-25 12:00:00.000000', 'allowed_cloud', '{shared_user}', 'aws', 'iam', 'us-east-1', '10.0.0.1', 200, 'permission_change', 1),
            ('2026-07-25 12:01:00.000000', 'allowed_cloud', '{shared_user}', 'aws', 's3', 'us-west-2', '10.0.0.2', 500, 'delete', 0),
            ('2026-07-25 12:02:00.000000', 'allowed_cloud', '{shared_user}', 'aws', 'iam', 'us-east-1', '10.0.0.1', 200, 'read', 1),
            ('2026-07-25 12:03:00.000000', 'hidden_cloud', '{shared_user}', 'aws', 'ec2', 'eu-west-1', '10.0.0.3', 503, 'delete', 0),
            ('2026-07-25 12:04:00.000000', 'hidden_cloud', '{shared_user}', 'aws', 'lambda', 'ap-south-1', '10.0.0.4', 500, 'permission_change', 0),
            ('2026-07-25 12:05:00.000000', 'hidden_cloud', '{denied_only_user}', 'aws', 'kms', 'eu-central-1', '10.0.0.5', 500, 'delete', 0)"#
        );
        client
            .query(&insert_sql)
            .execute()
            .await
            .expect("seed mixed-source cloud activity");

        let scope = denied(&["hidden_cloud"]);
        let scope_predicate = source_scope_sql_predicate("source_type", scope.deny_set())
            .expect("restricted scope predicate");
        let base_scan = build_cloud_fallback_scan_sql(
            &table,
            "2026-07-25 10:00:00.000000",
            "2026-07-25 16:00:00.000000",
            Some(&scope_predicate),
        );
        let with_clause = format!("WITH cloud_base AS ({base_scan})");
        let sql = build_cloud_user_activity_sql(
            &UdmProfile::new(),
            &with_clause,
            "cloud_base",
            "nanosiem.cloud_user_activity_agg",
            &range(),
            &scope,
            "",
        )
        .expect("build restricted production query");
        let rows = client
            .query(&sql)
            .fetch_all::<UserActivityRow>()
            .await
            .expect("execute restricted production query");

        client
            .query(&format!("DROP TABLE {table}"))
            .execute()
            .await
            .expect("drop isolated NAN-2076 fixture table");

        assert_eq!(rows.len(), 1, "denied-only principal must stay absent");
        let row = &rows[0];
        assert_eq!(row.user, shared_user);
        assert_eq!(row.event_count, 3);
        assert_eq!(row.distinct_services, 2);
        assert_eq!(row.distinct_regions, 2);
        assert_eq!(row.distinct_ips, 2);
        assert_eq!(row.fail_count, 1);
        assert_eq!(row.permission_change_count, 1);
        assert_eq!(row.delete_count, 1);
        assert_eq!(row.mfa_count, 2);
        assert_eq!(row.no_mfa_count, 1);
    }
}

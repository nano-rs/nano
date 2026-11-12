// SPDX-License-Identifier: AGPL-3.0-or-later

//! `table` projects every requested field under the name the user asked for
//! (NAN-5306).

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, QueryOptions, TimeRange};
use crate::schema::{OcsfProfile, UdmProfile};

fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-10-08T00:00:00Z".parse().unwrap(),
        end: "2026-10-08T01:00:00Z".parse().unwrap(),
    }
}

fn ocsf_sql(npl: &str) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&q, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

fn udm_sql(npl: &str) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(UdmProfile::new()))
        .generate(&q, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

/// The persona repro: `time` and `metadata.log_source` resolve to the
/// `timestamp` / `source_type` columns. They must come back under the
/// requested names, matching the response `column_order`.
#[test]
fn table_aliases_resolved_columns_back_to_the_requested_name() {
    let sql = ocsf_sql(
        r#"metadata.log_source="apache_access" | table time, metadata.log_source, http_request.url.path"#,
    );
    assert!(sql.contains("timestamp AS time"), "{sql}");
    assert!(sql.contains(r#"source_type AS "metadata.log_source""#), "{sql}");
    // A native column already carries its own name: no redundant alias.
    assert!(sql.contains(r#""http_request.url.path""#), "{sql}");
    assert!(!sql.contains(r#""http_request.url.path" AS"#), "{sql}");
    assert!(!sql.contains("PREWHERE"), "{sql}");
}

/// A UDM-named alias of an OCSF promoted column keeps the UDM name.
#[test]
fn table_keeps_the_udm_alias_name_on_ocsf() {
    let sql = ocsf_sql("* | table src_ip");
    assert!(sql.contains(r#""src_endpoint.ip" AS src_ip"#), "{sql}");
}

/// The re-aliased name is the column later stages read: they must reference
/// it, not re-resolve it to the physical column the table dropped.
#[test]
fn stages_after_table_read_the_requested_name() {
    let sql = ocsf_sql("* | table src_ip | stats count by src_ip");
    assert!(sql.contains("GROUP BY src_ip"), "{sql}");
    assert!(!sql.contains(r#"GROUP BY "src_endpoint.ip""#), "{sql}");

    let sql = ocsf_sql("* | table time, src_ip | sort -time");
    assert!(sql.contains("ORDER BY time DESC"), "{sql}");
    assert!(!sql.contains("ORDER BY timestamp"), "{sql}");

    let sql = ocsf_sql(r#"* | table src_ip | where src_ip="10.0.0.1""#);
    assert!(!sql.contains(r#"WHERE "src_endpoint.ip""#), "{sql}");
}

/// The folded final projection (sort then table) keeps ordering on the
/// source column while projecting under the requested names.
#[test]
fn folded_projection_orders_on_the_source_column() {
    let sql = ocsf_sql("* | sort -src_ip | table src_ip, time");
    assert!(sql.contains(r#""src_endpoint.ip" AS src_ip"#), "{sql}");
    assert!(sql.contains("timestamp AS time"), "{sql}");
    assert!(sql.contains(r#"ORDER BY "src_endpoint.ip" DESC"#), "{sql}");
}

/// UDM: names that are their own columns project bare, as before.
#[test]
fn udm_plain_columns_project_bare() {
    let sql = udm_sql("* | table src_ip, timestamp");
    assert!(sql.contains("SELECT src_ip, timestamp FROM"), "{sql}");
    let sql = ocsf_sql("* | table timestamp, source_type");
    assert!(sql.contains("SELECT timestamp, source_type FROM"), "{sql}");
}

/// The streaming path generates each day chunk (and its count companion)
/// with `table_view` options: the requested names must survive there too.
#[test]
fn streaming_table_view_options_keep_the_requested_names() {
    let npl = r#"metadata.log_source="apache_access" | table time, metadata.log_source, http_request.url.path"#;
    let q = parse_query(npl).unwrap();
    for options in [
        QueryOptions { table_view: true, limit: None, ..QueryOptions::default() },
        QueryOptions { table_view: true, limit: None, unordered: true, ..QueryOptions::default() },
    ] {
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate_with_options(&q, &time_range(), &options)
            .unwrap();
        assert!(sql.contains("timestamp AS time"), "{sql}");
        assert!(sql.contains(r#"source_type AS "metadata.log_source""#), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
    }
}

/// `resolve_identity` after a `table` that re-aliased its key joins on the
/// projected name (the golden corpus `table … src_ip | resolve_identity src_ip`).
#[test]
fn resolve_identity_after_table_joins_on_the_projected_key() {
    let sql = ocsf_sql("* | table first_seen as timestamp, src_ip, id | resolve_identity src_ip");
    assert!(sql.contains(r#""src_endpoint.ip" AS src_ip"#), "{sql}");
    assert!(sql.contains("ON main.src_ip = i.ip"), "{sql}");
    assert!(!sql.contains(r#"main."src_endpoint.ip""#), "{sql}");
}

/// Review follow-up: `table time, …` leaves the event time in scope as `time`
/// (the physical `timestamp` is gone), so later stages that read the event
/// time must read `time` — `timestamp` there is Code 47 on ClickHouse.
#[test]
fn stages_after_table_read_the_event_time_under_its_projected_name() {
    let sql = ocsf_sql("* | table time, src_ip | timechart span=1h count");
    assert!(sql.contains("toStartOfHour(time) AS time_bucket"), "{sql}");
    assert!(!sql.contains("toStartOfHour(timestamp)"), "{sql}");

    let sql = ocsf_sql("* | table time, user, process.name | dedup user");
    assert!(sql.contains(r#"ORDER BY "user", time DESC"#), "{sql}");

    let sql = ocsf_sql("* | table time, src_ip, user | stats earliest(src_ip) as e by user");
    assert!(sql.contains("argMin(src_ip, (time, toString(src_ip)))"), "{sql}");

    let sql = ocsf_sql("* | table time, src_ip | streamstats count as n by src_ip");
    assert!(sql.contains("ORDER BY time ROWS"), "{sql}");

    // An explicit alias and a second `table` carry the name through.
    let sql = ocsf_sql("* | table time as t, src_ip | timechart span=1h count");
    assert!(sql.contains("toStartOfHour(t) AS time_bucket"), "{sql}");
    let sql = ocsf_sql("* | table time, src_ip | table time, src_ip | timechart span=1h count");
    assert!(sql.contains("toStartOfHour(time) AS time_bucket"), "{sql}");
    // Row filters / dedup keep it in scope.
    let sql = ocsf_sql(r#"* | table time, src_ip | where src_ip="10.0.0.1" | dedup src_ip | timechart span=1h count"#);
    assert!(sql.contains("toStartOfHour(time) AS time_bucket"), "{sql}");
    assert!(!sql.contains("PREWHERE"), "{sql}");
}

/// `resolve_identity` after `table time, …` keys the ASOF join and the
/// confidence window on the projected `time`, and its user-registry fallback
/// reads the projected `user` (the physical `"user.name"` is out of scope).
#[test]
fn resolve_identity_after_table_reads_projected_time_and_user() {
    let sql = ocsf_sql("* | table time, src_ip, user | resolve_identity src_ip");
    assert!(sql.contains("AND main.time >= i.observed_at"), "{sql}");
    assert!(sql.contains("main.time - INTERVAL 1 HOUR"), "{sql}");
    assert!(!sql.contains("main.timestamp"), "{sql}");
    assert!(sql.contains(r#"COALESCE(i.user, main."user")"#), "{sql}");
    assert!(!sql.contains(r#"main."user.name""#), "{sql}");

    // No user in scope: fall back to the joined identity alone.
    let sql = ocsf_sql("* | table time, src_ip | resolve_identity src_ip");
    assert!(sql.contains("COALESCE(i.user, NULL)"), "{sql}");
}

/// Without a renaming `table`, the time column stays the physical one
/// (byte-identical), and a re-assignment of the name drops the mapping.
#[test]
fn time_column_unchanged_without_a_renaming_table() {
    let sql = ocsf_sql("* | table timestamp, src_ip | timechart span=1h count");
    assert!(sql.contains("toStartOfHour(timestamp) AS time_bucket"), "{sql}");
    let sql = ocsf_sql("* | timechart span=1h count");
    assert!(sql.contains("toStartOfHour(timestamp)"), "{sql}");
    let sql = ocsf_sql("* | table time, src_ip | eval time=1 | timechart span=1h count");
    assert!(sql.contains("toStartOfHour(timestamp)"), "{sql}");
    let sql = ocsf_sql("* | resolve_identity src_ip");
    assert!(sql.contains("AND main.timestamp >= i.observed_at"), "{sql}");
}

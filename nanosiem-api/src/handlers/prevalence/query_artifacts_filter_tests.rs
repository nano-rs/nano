//! NAN-5285 (v2.0.13 retest F2): `POST /api/prevalence/query-artifacts` built
//! its filter with the UDM generator on every deployment. On OCSF every field
//! filter became `ext.<field>` (ClickHouse Code 47), a keyword matched only
//! `message` (not `raw_data`, as search does), and the failed read was
//! swallowed into `200 {"hash_points":[],"domain_points":[]}`.

use std::sync::Arc;

use axum::http::StatusCode;
use nanosiem_core::query::ClickHouseSqlGenerator;
use nanosiem_core::schema::{OcsfProfile, UdmProfile};

use super::discovery::{candidate_read_error, query_artifacts_filter};

/// The generator search builds for an OCSF deployment
/// (`SearchService::ch_generator_for_pool` without the pool).
fn ocsf_generator() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::with_table("ocsf_logs").with_profile(Arc::new(OcsfProfile::new()))
}

fn udm_generator() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::with_table("logs").with_profile(Arc::new(UdmProfile::new()))
}

fn ocsf_filter(query: &str) -> String {
    query_artifacts_filter(query, &ocsf_generator())
        .unwrap_or_else(|e| panic!("{query}: {e:?}"))
}

#[test]
fn ocsf_field_filters_use_ocsf_columns_not_the_udm_ext_tail() {
    for query in [
        "class_uid=1007",
        r#"device.hostname="WS01""#,
        r#"class_uid=1007 device.hostname="WS01" | stats count by device.hostname"#,
    ] {
        let sql = ocsf_filter(query);
        assert!(
            !sql.contains("ext."),
            "{query}: an OCSF field must not fall through to the UDM ext tail: {sql}"
        );
    }
    assert!(ocsf_filter("class_uid=1007").contains("class_uid"));
    assert!(ocsf_filter(r#"device.hostname="WS01""#).contains("device"));
}

#[test]
fn ocsf_keyword_matches_raw_data_like_search() {
    let sql = ocsf_filter(r#""PRV2013""#);
    assert!(sql.contains("message"), "{sql}");
    assert!(
        sql.contains("raw_data"),
        "a keyword in an OCSF event's raw_data (Sysmon) must match, as search does: {sql}"
    );
}

#[test]
fn udm_filters_are_unchanged() {
    let sql = query_artifacts_filter(r#"src_ip="10.0.0.1""#, &udm_generator()).unwrap();
    assert!(sql.contains("src_ip"), "{sql}");
    assert!(!sql.contains("raw_data"), "{sql}");
}

#[test]
fn wildcard_matches_everything_and_bad_queries_are_400() {
    assert_eq!(ocsf_filter("*"), "1=1");
    assert_eq!(ocsf_filter("  "), "1=1");
    let (status, message) = query_artifacts_filter(r#"src_ip=""#, &ocsf_generator()).unwrap_err();
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(message.starts_with("Invalid query"), "{message}");
}

#[test]
fn a_failed_candidate_read_is_an_error_never_an_empty_200() {
    let (status, message) = candidate_read_error(
        "hash",
        // The shape the retest captured in system.query_log.
        "Code: 47. DB::Exception: Unknown expression or function identifier `ext.class_uid` \
         in scope SELECT DISTINCT x FROM nanosiem.ocsf_logs WHERE source_type NOT IN ('secret'). \
         (UNKNOWN_IDENTIFIER) (version 25.8.1.1)",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(message.contains("ext.class_uid"), "{message}");
    assert!(
        !message.contains("NOT IN"),
        "the message must not echo the SQL (NAN-5161): {message}"
    );

    // A query the caller can narrow is a 400 that says how.
    let (status, message) = candidate_read_error(
        "hash",
        "Code: 241. DB::Exception: Memory limit (for query) exceeded (MEMORY_LIMIT_EXCEEDED)",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(message.contains("memory limit"), "{message}");

    // Anything else is a 500 that names the failing read and leaks no detail.
    let (status, message) = candidate_read_error(
        "domain",
        "Code: 210. DB::NetException: Connection refused (clickhouse-proxy:8123)",
    );
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(message.contains("domain"), "{message}");
    assert!(!message.contains("clickhouse-proxy"), "{message}");
}

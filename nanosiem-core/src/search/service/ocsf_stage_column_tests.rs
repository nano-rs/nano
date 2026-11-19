// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5634: on OCSF, a later stage must read the columns earlier stages
//! produced, by the names they produced them under. Rendered through the real
//! `explain` path under both schema profiles;
//! `e2e/tests/test_ocsf_stage_columns.py` executes the shapes on a throwaway
//! stack.
//!
//! - `sort -ports | rename ports AS unique_ports | table …` ordered the final
//!   statement by `ports`, which the rename had removed ("Field 'ports' does
//!   not exist in the data"). The order now follows the column it renames.
//! - `bin bytes_in span=1024` read a bare `bytes_in`, a column `ocsf_logs`
//!   does not have (it is `traffic.bytes_in`).
//! - `append [… | rename dst_endpoint.ip AS src_endpoint.ip]` selected the
//!   renamed-away `dst_endpoint.ip` from its arm.

use super::npl_golden_corpus_tests::{render, sql_only_service};
use crate::auth::ScopeSet;
use crate::query::parse_query;
use crate::search::SearchError;

async fn sql(profile: &str, query: &str) -> String {
    let sql = render(&sql_only_service(profile), query, &ScopeSet::unrestricted()).await;
    assert!(!sql.starts_with("ERR:"), "{profile}: {query} -> {sql}");
    sql
}

/// The statement after the last CTE (the one ClickHouse returns rows from).
fn final_statement(sql: &str) -> &str {
    let tail = sql.rfind("\n)\n").map_or(sql, |at| &sql[at + 3..]);
    tail.split("\n\n-- Note").next().unwrap_or(tail)
}

#[tokio::test]
async fn sort_then_rename_orders_by_the_renamed_column() {
    let q = "* | where isnotnull(src_endpoint.ip) \
             | stats count() as events, dc(dst_endpoint.port) as ports by src_endpoint.ip \
             | where events > 10 | sort -ports | head 20 \
             | rename src_endpoint.ip as scanner, ports as unique_ports \
             | table scanner, events, unique_ports";
    for profile in ["ocsf", "udm"] {
        let s = sql(profile, q).await;
        let last = final_statement(&s);
        assert!(last.contains("ORDER BY unique_ports DESC"), "{profile}:\n{s}");
        assert!(!last.contains("ORDER BY ports"), "{profile}:\n{s}");
    }
}

#[tokio::test]
async fn sort_then_eval_and_rename_orders_by_the_renamed_column() {
    let q = "* | eval hour=strftime(time, \"%H\") | stats count() as events by hour | sort hour \
             | eval pct = round(events / 100, 2) | rename hour as h";
    for profile in ["ocsf", "udm"] {
        let s = sql(profile, q).await;
        let last = final_statement(&s);
        assert!(last.contains("ORDER BY h ASC"), "{profile}:\n{s}");
        assert!(!last.contains("ORDER BY hour"), "{profile}:\n{s}");
    }
}

#[tokio::test]
async fn rename_onto_the_order_key_drops_the_stale_order() {
    // `events` is overwritten by the old `ports`: neither name orders the rows
    // any more, so the final statement must not ORDER BY either of them.
    let q = "* | stats count() as events, dc(dst_endpoint.port) as ports by src_endpoint.ip \
             | sort -events | rename ports as events";
    for profile in ["ocsf", "udm"] {
        let s = sql(profile, q).await;
        let last = final_statement(&s);
        assert!(!last.contains("ORDER BY events") && !last.contains("ORDER BY ports"), "{profile}:\n{s}");
    }
}

#[tokio::test]
async fn numeric_bin_reads_the_profile_column() {
    let q = "* | bin bytes_in span=1024 | stats count() by bytes_in";
    let ocsf = sql("ocsf", q).await;
    assert!(ocsf.contains("floor(\"traffic.bytes_in\" / 1024) * 1024 AS bytes_in"), "{ocsf}");
    let udm = sql("udm", q).await;
    assert!(udm.contains("floor(bytes_in / 1024) * 1024 AS bytes_in"), "{udm}");
    // The native spelling bins the same column.
    let native = sql("ocsf", "* | bin traffic.bytes_in span=1024 | stats count() by traffic.bytes_in").await;
    assert!(native.contains("floor(\"traffic.bytes_in\" / 1024) * 1024 AS \"traffic.bytes_in\""), "{native}");
}

#[tokio::test]
async fn numeric_bin_of_an_eval_output_reads_the_stage_column() {
    let q = "* | eval kb = 2048 | bin kb span=1024 | stats count() by kb";
    for profile in ["ocsf", "udm"] {
        let s = sql(profile, q).await;
        assert!(s.contains("floor(kb / 1024) * 1024 AS kb"), "{profile}:\n{s}");
    }
}

#[tokio::test]
async fn append_arm_after_rename_does_not_select_the_old_name() {
    let q = "* | stats count() as events by src_endpoint.ip \
             | append [search * | stats count() as events by dst_endpoint.ip \
             | rename dst_endpoint.ip as src_endpoint.ip]";
    for profile in ["ocsf", "udm"] {
        let s = sql(profile, q).await;
        assert!(
            s.contains("SELECT \"src_endpoint.ip\", events FROM stage_"),
            "{profile}: the main arm selects exactly the shared columns:\n{s}"
        );
        assert!(
            !s.contains("NULL AS \"dst_endpoint.ip\"") && !s.contains("events, \"dst_endpoint.ip\" FROM"),
            "{profile}: no arm may select the renamed-away column:\n{s}"
        );
    }
}

#[test]
fn join_over_an_aggregating_subsearch_is_raw_rows() {
    let raw = |q: &str| super::join_returns_raw_rows(&parse_query(q).unwrap());
    assert!(raw("* | join type=inner src_endpoint.ip [search * | stats count() as c by src_endpoint.ip]"));
    assert!(raw("* | join src_ip [search * | stats count() as c by src_ip] | where c > 3 | table src_ip, c"));
    // An aggregation on the main side aggregates the output.
    assert!(!raw("* | join src_ip [search * | stats count() as c by src_ip] | stats count() by c"));
    // No join: the executor keeps its own decision.
    assert!(!raw("* | stats count() by src_ip"));
    assert!(!raw("* | where src_ip=\"10.0.0.1\""));
}

#[test]
fn unknown_udm_name_suggests_the_ocsf_field() {
    let ocsf = crate::schema::OcsfProfile::new();
    let err = super::suggest_native_field(
        SearchError::FieldNotFound {
            field: "bytes_in".into(),
            suggestions: vec![],
            message: "Field 'bytes_in' does not exist in the data.".into(),
        },
        &ocsf,
    );
    assert_eq!(
        crate::search::client_error_message(&err),
        "Field 'bytes_in' does not exist in the data. Did you mean: traffic.bytes_in"
    );
    // A native name, an unknown name, and UDM keep the error as it was.
    let keep = |field: &str, profile: &dyn crate::schema::SchemaProfile| {
        let err = super::suggest_native_field(
            SearchError::FieldNotFound { field: field.into(), suggestions: vec![], message: "m".into() },
            profile,
        );
        matches!(err, SearchError::FieldNotFound { suggestions, .. } if suggestions.is_empty())
    };
    assert!(keep("traffic.bytes_in", &ocsf));
    assert!(keep("no_such_field_nan5634", &ocsf));
    assert!(keep("bytes_in", &crate::schema::UdmProfile::new()));
}

#[test]
fn clickhouse_never_suggests_the_unknown_name_itself() {
    let err = crate::search::parse_clickhouse_error(
        "Code: 47. DB::Exception: Unknown expression identifier `bytes_in` in scope SELECT bytes_in. \
         Maybe you meant: ['bytes_in']. (UNKNOWN_IDENTIFIER)",
    );
    match &err {
        SearchError::FieldNotFound { field, suggestions, .. } => {
            assert_eq!(field, "bytes_in");
            assert!(suggestions.is_empty(), "{suggestions:?}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(crate::search::client_error_message(&err), "Field 'bytes_in' does not exist in the data.");

    // A real suggestion renders once.
    let err = crate::search::parse_clickhouse_error(
        "Code: 47. DB::Exception: Unknown expression identifier `prots` in scope SELECT prots. \
         Maybe you meant: ['ports']. (UNKNOWN_IDENTIFIER)",
    );
    assert_eq!(crate::search::client_error_message(&err), "Field 'prots' does not exist. Did you mean: ports");
}

#[tokio::test]
async fn a_multi_key_order_renames_only_the_moved_key() {
    let q = "* | stats count() as events, dc(dst_endpoint.port) as ports by src_endpoint.ip \
             | sort -events, ports | rename ports as unique_ports";
    for profile in ["ocsf", "udm"] {
        let s = sql(profile, q).await;
        assert!(final_statement(&s).contains("ORDER BY events DESC, unique_ports ASC"), "{profile}:\n{s}");
    }
}

#[tokio::test]
async fn numeric_bin_after_stats_reads_the_by_field_column() {
    let q = "* | stats count() by bytes_in | bin bytes_in span=1024";
    for profile in ["ocsf", "udm"] {
        let s = sql(profile, q).await;
        assert!(s.contains("floor(bytes_in / 1024) * 1024 AS bytes_in"), "{profile}:\n{s}");
    }
}

#[test]
fn cloud_must_end_the_search() {
    let check = |q: &str| super::cloud_view_is_last(&parse_query(q).unwrap());
    assert!(check("* | cloud service").is_ok());
    assert!(check("* | where class_uid=6003 | cloud service").is_ok());
    assert!(check("* | stats count() by src_ip").is_ok());
    let err = check("* | cloud service | stats count() by cloud_service").unwrap_err();
    assert!(
        matches!(&err, SearchError::SqlValidationError(m) if m.contains("must be the last command")),
        "{err:?}"
    );
}

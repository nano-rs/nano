// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5339: dc() / estdc() must not count a missing value as a distinct value.
//!
//! A field absent from a row reads as `''` (unknown / `ext.*` fields compile to
//! `toString(ext.x)`, OCSF `unmapped.*` reads default to `''`, non-Nullable
//! String columns default to `''`). The old `uniqExact(x)` counted that `''`,
//! so `dc(<field absent from every row>)` returned 1 — found on a v2.0.18
//! customer install, where `dc(unmapped.seq)` returned 1 for 209 events.
//! Every dc()/estdc() emission site must filter `''` (via the `-If`
//! combinator, which keeps the column type and still ignores NULL). The Rust
//! post-processing twin is pinned in `post_processing/dc_missing_value_tests.rs`.

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, TimeRange};
use crate::schema::{OcsfProfile, UdmProfile};

fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-10-08T00:00:00Z".parse().unwrap(),
        end: "2026-10-08T01:00:00Z".parse().unwrap(),
    }
}

fn udm_sql(npl: &str) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(UdmProfile::new()))
        .generate(&q, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

fn ocsf_sql(npl: &str) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&q, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

/// No unfiltered distinct-count aggregate may survive anywhere in the SQL.
fn assert_no_unfiltered_distinct(npl: &str, sql: &str) {
    for bare in [
        "uniqExact(",
        "uniqCombined64(",
        "uniqExactState(",
        "uniqCombined64State(",
        "uniqExactMerge(",
        "uniqCombined64Merge(",
        "count(DISTINCT",
    ] {
        assert!(!sql.contains(bare), "{npl}: unfiltered `{bare}` counts '' as a value:\n{sql}");
    }
}

/// The reported case: a field that exists on no row. It compiles to
/// `toString(ext.<f>)` = '' on every row, so dc() must filter it to 0.
#[test]
fn dc_of_a_field_absent_from_every_row_filters_the_empty_string() {
    let npl = "* | stats dc(nosuchfield)";
    let sql = udm_sql(npl);
    assert!(
        sql.contains("uniqExactIf(nosuchfield, toString(nosuchfield) != '') AS dc"),
        "{npl}:\n{sql}"
    );
    assert_no_unfiltered_distinct(npl, &sql);
}

/// The OCSF forms from the report: an `unmapped.*` tail read and the
/// non-Nullable promoted `message` column.
#[test]
fn ocsf_unmapped_and_promoted_string_columns_filter_the_empty_string() {
    for (npl, needle) in [
        (
            "* | stats dc(unmapped.seq)",
            "uniqExactIf(\"unmapped.seq\", toString(\"unmapped.seq\") != '')",
        ),
        ("* | stats dc(message)", "uniqExactIf(message, toString(message) != '')"),
        (
            "* | stats dc(src_endpoint.ip) by device.hostname",
            "uniqExactIf(\"src_endpoint.ip\", toString(\"src_endpoint.ip\") != '')",
        ),
    ] {
        let sql = ocsf_sql(npl);
        assert!(sql.contains(needle), "{npl}: expected `{needle}`:\n{sql}");
        assert_no_unfiltered_distinct(npl, &sql);
    }
}

/// Every surface that emits a distinct count: stats, timechart (plain and
/// dc-ranked top-N, both the state/merge and the subquery forms), eventstats
/// (grouped map attach and ungrouped whole-set), streamstats, and estdc.
#[test]
fn every_distinct_count_surface_filters_the_empty_string() {
    for npl in [
        "* | stats dc(user) by src_ip",
        "* | stats distinct_count(user)",
        "* | stats estdc(user) by src_ip",
        "* | timechart span=1h dc(user)",
        "* | timechart span=1h dc(user) by src_ip limit=5",
        "* | timechart span=1h estdc(user) by src_ip limit=5",
        "* | eventstats dc(user) by src_ip",
        "* | eventstats dc(user)",
        "* | eventstats estdc(user)",
        "* | streamstats dc(user)",
        "* | streamstats estdc(user) by src_ip",
    ] {
        let sql = udm_sql(npl);
        assert!(
            sql.contains("toString(\"user\") != ''"),
            "{npl}: distinct count must filter '':\n{sql}"
        );
        assert_no_unfiltered_distinct(npl, &sql);
    }
}

/// A dc()-ranked timechart carries `-IfState` through the aggregated stage;
/// it must be merged with `-IfMerge` (an `-If` state is not a plain state —
/// ClickHouse rejects `uniqExactMerge` over it with ILLEGAL_TYPE_OF_ARGUMENT).
#[test]
fn ranked_timechart_merges_if_states_with_if_merge() {
    let sql = udm_sql("* | timechart span=1h dc(user) by src_ip limit=5");
    assert!(
        sql.contains("uniqExactIfState(\"user\", toString(\"user\") != '') AS __rank_state"),
        "{sql}"
    );
    assert!(sql.contains("uniqExactIfMerge(__rank_state)"), "{sql}");
}

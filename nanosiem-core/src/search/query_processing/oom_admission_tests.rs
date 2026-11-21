// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5635: cost-based admission decisions for the OOM guard sites.

use super::*;
use crate::query::parse_query;
use crate::search::query_processing::oom_risk_sites;

fn classes(npl: &str) -> Vec<AdmissionClass> {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl}: {e:?}"));
    oom_risk_sites(&q).iter().map(admission_class).collect()
}

fn estimate_of(npl: &str) -> Option<String> {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl}: {e:?}"));
    let sites = oom_risk_sites(&q);
    let site = sites.first().unwrap_or_else(|| panic!("{npl}: no guard site"));
    estimate_query(site).map(|e| format!("{e:?}"))
}

fn debug_of(npl: &str) -> String {
    format!("{:?}", parse_query(npl).unwrap())
}

#[test]
fn spillable_shapes_are_admitted_without_an_estimate() {
    for npl in [
        "* | stats count() by command_line | head 10",
        "* | stats count by url",
        "* | stats dc(dst_endpoint.port) as ports, values(dst_endpoint.port) as p by src_endpoint.ip",
        "* | stats list(user.name) by src_endpoint.ip",
        "* | reverse",
    ] {
        assert_eq!(classes(npl), vec![AdmissionClass::Spillable], "{npl}");
    }
}

#[test]
fn non_spillable_state_is_cost_gated_per_command() {
    let keeps_rows = AdmissionClass::CostGated { bytes_per_row: ROW_PRESERVING_BYTES_PER_ROW };
    let collapses = AdmissionClass::CostGated { bytes_per_row: COLLAPSING_BYTES_PER_ROW };
    for (npl, want) in [
        // NAN-5657: a dedup whose output reaches the result is buffered by
        // the pagination wrapper (near-unique keys keep ~every row).
        ("* | dedup src_endpoint.ip", keeps_rows),
        ("* | dedup src_endpoint.ip | stats count", collapses),
        ("* | dedup src_endpoint.ip | head 100", collapses),
        ("* | eventstats count() as total", keeps_rows),
        ("* | sort timestamp | streamstats count() as n", keeps_rows),
        ("* | transaction user.name maxspan=30m", collapses),
        ("* | anomaly count() by src_endpoint.ip span=1h", collapses),
    ] {
        assert_eq!(classes(npl), vec![want], "{npl}");
    }
}

/// An OCSF class filter or any positive field predicate already narrows the
/// search: no guard site at all, no estimate query.
#[test]
fn class_uid_and_field_predicates_count_as_filters() {
    for npl in [
        "class_uid=4003 | dedup src_endpoint.ip",
        "class_uid=3002 | transaction user.name maxspan=30m",
        "src_endpoint.ip=\"10.0.0.1\" | eventstats count() as total",
        "source_type=zeek_conn | anomaly count() by src_endpoint.ip span=1h",
    ] {
        assert!(classes(npl).is_empty(), "{npl}");
    }
}

#[test]
fn estimate_carries_the_leading_where_run() {
    // Trailing eval after the last where changes nothing the count sees.
    assert_eq!(
        estimate_of("* | where isnotnull(user.name) | eval a = 1 | dedup user.name"),
        Some(debug_of("* | where isnotnull(user.name)"))
    );
    // A sort before the command is a pure reorder and is dropped.
    assert_eq!(
        estimate_of("* | sort timestamp | where bytes_in > 10 | streamstats count() as n"),
        Some(debug_of("* | where bytes_in > 10"))
    );
}

#[test]
fn estimate_is_the_search_stage_when_no_where_precedes() {
    assert_eq!(
        estimate_of("* | sort timestamp | streamstats count() as n"),
        Some(debug_of("*"))
    );
}

/// After an aggregation the command sees one row per group: the estimate
/// counts the pipeline through the last aggregation.
#[test]
fn estimate_counts_groups_after_an_aggregation() {
    assert_eq!(
        estimate_of("* | stats count() as events by src_endpoint.ip | eventstats avg(events) as a"),
        Some(debug_of("* | stats count() as events by src_endpoint.ip"))
    );
    assert_eq!(
        estimate_of(
            "* | bin timestamp span=1h | stats count() as events by timestamp | sort timestamp | streamstats window=24 avg(events) as m"
        ),
        Some(debug_of("* | bin timestamp span=1h | stats count() as events by timestamp"))
    );
}

#[test]
fn row_multiplying_stage_before_the_command_has_no_estimate() {
    assert_eq!(estimate_of("* | mvexpand tags | dedup tags"), None);
    // A hop bin emits one row per overlapping window.
    assert_eq!(estimate_of("* | bin span=1d hop=1m | dedup time_bucket"), None);
    assert_eq!(
        estimate_of("* | where bytes_in > 1 | bin span=1d hop=1s | eventstats count() as n"),
        None
    );
    // A gap-filled timechart emits rows for empty buckets too.
    assert_eq!(
        estimate_of("* | timechart span=1s cont=true count() | eventstats avg(count) as a"),
        None
    );
    // A tumbling bin labels each row once.
    assert_eq!(
        estimate_of("* | bin span=1h | dedup time_bucket"),
        Some(debug_of("*"))
    );
}

/// Grouping by an array field yields a group per element; the estimate runs
/// that aggregation, so it counts those groups, never the input events.
#[test]
fn group_by_array_field_is_counted_by_its_groups() {
    assert_eq!(
        estimate_of("* | stats count() as n by resources.type | eventstats avg(n) as a"),
        Some(debug_of("* | stats count() as n by resources.type"))
    );
}

#[test]
fn subsearch_site_is_estimated_on_its_own_search_stage() {
    let q = parse_query("source_type=a | append [search * | dedup user.name]").unwrap();
    let sites = oom_risk_sites(&q);
    assert_eq!(sites.len(), 1);
    assert!(!sites[0].foreign_dataset);
    assert_eq!(
        estimate_query(&sites[0]).map(|e| format!("{e:?}")),
        Some(debug_of("*"))
    );
}

#[test]
fn bounded_only_when_the_estimate_reads_rows() {
    let filter_free = parse_query("*").unwrap();
    assert!(!estimate_is_bounded(&filter_free));
    let filtered = parse_query("* | where isnotnull(user.name)").unwrap();
    assert!(estimate_is_bounded(&filtered));
}

#[test]
fn row_budget_scales_with_memory_and_has_a_floor() {
    const GIB: u64 = 1 << 30;
    assert_eq!(row_budget(1024, 4 * GIB), 4 * 1024 * 1024);
    assert_eq!(row_budget(4096, 4 * GIB), 1024 * 1024);
    assert_eq!(row_budget(4096, 1), MIN_ROW_BUDGET);
    assert!(row_budget(4096, 20 * GIB) > row_budget(4096, 2 * GIB));
}

#[test]
fn budget_is_half_the_smallest_known_ceiling() {
    const M: u64 = 1_000_000;
    assert_eq!(resolve_budget_bytes(None, Some(500 * M), Some(900 * M)), 250 * M);
    assert_eq!(resolve_budget_bytes(None, None, Some(900 * M)), 450 * M);
    assert_eq!(resolve_budget_bytes(None, Some(700 * M), None), 350 * M);
    assert_eq!(
        resolve_budget_bytes(None, None, None),
        DEFAULT_COST_GUARD_BUDGET_BYTES / 100 * BUDGET_SHARE_PCT
    );
    // The override replaces the share but never exceeds the ceiling; 0
    // turns cost admission off.
    assert_eq!(resolve_budget_bytes(Some(300 * M), Some(500 * M), Some(900 * M)), 300 * M);
    assert_eq!(resolve_budget_bytes(Some(9_000 * M), Some(500 * M), Some(900 * M)), 500 * M);
    assert_eq!(resolve_budget_bytes(Some(0), Some(500 * M), Some(900 * M)), 0);
}

#[test]
fn decision_admits_under_the_budget_and_refuses_with_the_number() {
    let risk = OomRisk::UnboundedDedup;
    assert!(decide(&risk, 1_000_000, false, 1_000_000).is_ok());
    assert!(decide(&risk, 10, true, 1_000_000).is_ok());

    let exact = decide(&risk, 12_345_678, false, 1_000_000).unwrap_err();
    assert!(exact.starts_with(&risk.message()), "{exact}");
    assert!(exact.contains("~12,345,678 events"), "{exact}");
    assert!(exact.contains("up to 1,000,000"), "{exact}");
    assert!(exact.contains("Narrow the time range or add filters"), "{exact}");

    let capped = decide(&risk, 1_000_001, true, 1_000_000).unwrap_err();
    assert!(capped.contains("more than 1,000,000 events"), "{capped}");
}

#[test]
fn thousands_grouping() {
    assert_eq!(group_thousands(0), "0");
    assert_eq!(group_thousands(999), "999");
    assert_eq!(group_thousands(1000), "1,000");
    assert_eq!(group_thousands(123_456_789), "123,456,789");
}

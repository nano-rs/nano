// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5632: the stages chained after the prevalence push-down
//! (`pv_stage_*` over `prevalence_results`) read the columns an earlier stage
//! produced (`time_bucket`, `count`, by-field and rename aliases) and the
//! columns `prevalence_results` adds (the decorations, eval outputs) as plain
//! columns. Before the fix each stage was generated on its own, so on OCSF
//! `timechart | sort time_bucket` (how the search service re-enters a
//! timechart) sorted on `unmapped."time_bucket"` and `stats count by f` (with
//! its implicit `sort -count`) sorted on `event."count"`: both 400 on a real
//! install. Rendered through the real `explain` path, both schema profiles;
//! `e2e/tests/test_prevalence_pipeline_ocsf.py` executes the shapes on a
//! throwaway stack.

use super::npl_golden_corpus_tests::{render, sql_only_service};
use crate::auth::ScopeSet;

async fn pushed_stages(profile: &str, query: &str) -> String {
    let sql = render(&sql_only_service(profile), query, &ScopeSet::unrestricted()).await;
    assert!(!sql.starts_with("ERR:"), "{profile}: {query} -> {sql}");
    let start = sql
        .find("pv_stage_0 AS")
        .unwrap_or_else(|| panic!("{profile}: no pushed-down stage for {query}:\n{sql}"));
    let stages = &sql[start..];
    stages.find("-- Note").map_or(stages, |end| &stages[..end]).to_string()
}

/// No stage reads a stage-produced or decoration column from the event JSON.
fn assert_no_event_json(profile: &str, stages: &str, names: &[&str]) {
    for name in names {
        for raw in [
            format!("unmapped.\"{name}\""),
            format!("unmapped.^\"{name}\""),
            format!("event.\"{name}\""),
            format!("event.^\"{name}\""),
            format!("'{name}')"),
        ] {
            assert!(!stages.contains(&raw), "{profile}: {name} read from the event JSON ({raw}):\n{stages}");
        }
    }
}

#[tokio::test]
async fn timechart_then_sort_on_time_bucket_reads_the_stage_column() {
    // How `complete_timechart` re-enters NAN-5632 query 1.
    let q = "class_uid=4003 | prevalence enrich=true window=24h | where host_count < 3 \
             | timechart span=1h count() | sort time_bucket";
    for profile in ["ocsf", "udm"] {
        let s = pushed_stages(profile, q).await;
        assert!(s.contains("pv_stage_1 AS (\n  SELECT * FROM pv_stage_0\n  ORDER BY time_bucket ASC\n)"), "{profile}:\n{s}");
        assert_no_event_json(profile, &s, &["time_bucket", "count"]);
    }
}

#[tokio::test]
async fn stats_implicit_sort_reads_the_count_column() {
    // NAN-5632 query 2.
    let q = "class_uid=4003 | prevalence enrich=true | eval risky=if(host_count < 3, 1, 0) \
             | where risky=1 | stats count by src_endpoint.ip";
    for profile in ["ocsf", "udm"] {
        let s = pushed_stages(profile, q).await;
        assert!(s.contains("ORDER BY count DESC"), "{profile}:\n{s}");
        assert_no_event_json(profile, &s, &["count"]);
    }
}

#[tokio::test]
async fn neighbouring_shapes_read_stage_and_decoration_columns() {
    let cases: &[(&str, &[&str], &[&str])] = &[
        (
            "class_uid=4003 | prevalence enrich=true | stats count by host_count | sort -count | table host_count, count",
            &["GROUP BY host_count", "ORDER BY count DESC", "SELECT host_count, count FROM pv_stage_1"],
            &["host_count", "count"],
        ),
        (
            "class_uid=4003 | prevalence enrich=true | eval risky=if(host_count < 3, 1, 0) \
             | stats count by risky, src_endpoint.ip | rename count as n | sort -n",
            &["SELECT risky AS risky", "count AS n FROM pv_stage_0", "ORDER BY n DESC"],
            &["risky", "count", "n"],
        ),
        (
            "class_uid=4003 | prevalence enrich=true | timechart span=1h count() by src_endpoint.ip | sort time_bucket",
            &["GROUP BY time_bucket", "ORDER BY time_bucket ASC"],
            &["time_bucket", "count"],
        ),
        (
            "class_uid=4003 | prevalence enrich=true | stats dc(dst_endpoint.ip) as dsts, avg(host_count) \
             by src_endpoint.ip | sort -dsts | head 5",
            &["avg(host_count) AS avg", "ORDER BY dsts DESC", "LIMIT 5"],
            &["dsts", "host_count"],
        ),
        (
            "class_uid=4003 | prevalence enrich=true | top src_endpoint.ip | sort -count",
            &["ORDER BY count DESC"],
            &["count", "percent"],
        ),
        (
            "class_uid=4003 | prevalence enrich=true | stats max(prevalence_score) as score by prevalence_type \
             | sort -score",
            &["max(prevalence_score) AS score", "GROUP BY prevalence_type", "ORDER BY score DESC"],
            &["prevalence_score", "prevalence_type", "score"],
        ),
    ];
    for (q, expected, names) in cases {
        for profile in ["ocsf", "udm"] {
            let s = pushed_stages(profile, q).await;
            for want in *expected {
                assert!(s.contains(want), "{profile}: {q}\nmissing {want:?} in:\n{s}");
            }
            assert_no_event_json(profile, &s, names);
        }
    }
}

/// The search service shares one generator between concurrent searches: the
/// chain runs on a private clone and leaves none of its scope on the shared
/// one (the stage-produced names, the decorations, the projected flag).
/// Rendering the push-down last means `generate_with_options` reset nothing
/// after it.
#[tokio::test]
async fn the_chain_scope_stays_off_the_shared_generator() {
    let svc = sql_only_service("ocsf");
    let s = render(
        &svc,
        "class_uid=4003 | prevalence enrich=true | eval risky=1 | stats count by host_count, risky | sort -count",
        &ScopeSet::unrestricted(),
    )
    .await;
    assert!(s.contains("ORDER BY count DESC"), "{s}");
    let gen = &svc.ch_sql_generator;
    for name in ["count", "host_count", "risky"] {
        assert!(!gen.is_computed_field(name), "{name} left in computed_fields");
        assert!(!gen.is_upstream_computed_field(name), "{name} left in the upstream scope");
    }
    assert!(!gen.is_upstream_projected(), "the stats stage's projection leaked");
}

/// `aggregated` carries across the chain: `tail` after `stats` numbers the
/// aggregated rows instead of ordering by the dropped event time.
#[tokio::test]
async fn tail_after_a_pushed_aggregation_does_not_order_by_event_time() {
    let q = "class_uid=4003 | prevalence enrich=true | stats count by src_endpoint.ip | tail 3";
    for profile in ["ocsf", "udm"] {
        let s = pushed_stages(profile, q).await;
        let tail = &s[s.find("pv_stage_1 AS").unwrap_or_else(|| panic!("{profile}:\n{s}"))..];
        assert!(!tail.contains("ORDER BY timestamp") && !tail.contains("ORDER BY time "), "{profile}:\n{s}");
        assert!(tail.contains("LIMIT 3"), "{profile}:\n{s}");
    }
}

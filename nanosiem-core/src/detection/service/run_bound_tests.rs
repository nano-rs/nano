// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5736: which rules are bounded, the expansion queries, merging.

use super::*;
use crate::query::parse_query;
use serde_json::json;

fn boundable(q: &str) -> bool {
    is_boundable_raw_query(&parse_query(q).expect("parse"))
}

#[test]
fn only_event_rows_of_the_base_search_are_bounded() {
    assert!(boundable("source_type=\"sysmon\" process_name=cmd.exe"));
    assert!(boundable("process_name=cmd.exe | where user!=\"system\""));
    assert!(boundable("process_name=cmd.exe | eval u=lower(user) | where u=\"x\""));
    // Output depends on every input row: never truncated.
    assert!(!boundable("process_name=cmd.exe | stats count by user"));
    assert!(!boundable("process_name=cmd.exe | stats count by src_ip | where count > 5"));
    assert!(!boundable("process_name=cmd.exe | timechart span=1h count"));
    assert!(!boundable("process_name=cmd.exe | dedup user"));
    assert!(!boundable("process_name=cmd.exe | table user, host"));
    assert!(!boundable("process_name=cmd.exe | sort -user"));
    assert!(!boundable("process_name=cmd.exe | head 10"));
}

#[test]
fn expansion_queries_parse() {
    let q = representatives_query("source_type=\"sysmon\"", "actor.user.name", 1001);
    assert_eq!(q, "source_type=\"sysmon\" | dedup actor.user.name | head 1001");
    parse_query(&q).expect("representatives query parses");
    let q = no_entity_query("source_type=\"sysmon\"", &["src_endpoint.ip".into(), "actor.user.name".into()]);
    parse_query(&q).expect("no-entity query parses");
    assert!(q.ends_with("| head 1"), "{q}");
}

#[test]
fn merge_keeps_each_event_once() {
    let mut kept = vec![json!({"log_id": "a"}), json!({"log_id": "b"})];
    let mut seen: HashSet<String> = kept.iter().map(super::super::helpers::matched_event_id).collect();
    let added = merge_unique(&mut kept, &mut seen, vec![json!({"log_id": "b"}), json!({"log_id": "c"})]);
    assert_eq!(added, 1);
    assert_eq!(kept.len(), 3);
}

#[test]
fn the_bound_is_configurable_and_never_clipped_by_the_search_ceiling() {
    assert_eq!(parse_max_matches_per_run(None), DEFAULT_MAX_MATCHES_PER_RUN);
    assert_eq!(parse_max_matches_per_run(Some("250")), 250);
    assert_eq!(parse_max_matches_per_run(Some("0")), 1);
    assert_eq!(parse_max_matches_per_run(Some("junk")), DEFAULT_MAX_MATCHES_PER_RUN);
    // `cap + 1` must stay within the search service's 1M ceiling, or a capped
    // run would read as exact (silent truncation).
    let max = parse_max_matches_per_run(Some("1000000"));
    assert!(max < crate::query::ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT);
    assert!(max + 1 <= crate::query::ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT);
}

#[test]
fn budgets_scale_with_the_cap() {
    assert_eq!(per_field_limit(2000), 1000);
    assert_eq!(per_field_limit(1), 1);
    assert_eq!(expansion_budget(2000), 8000);
}

#[test]
fn the_coverage_incomplete_row_is_stable_per_window_and_loud() {
    let rule = crate::detection::findings::tests::sample_rule();
    let end = chrono::Utc::now();
    let message = coverage_incomplete_message(10, &["actor.user.name".into()]);
    let a = coverage_incomplete_row(&rule, end, &message);
    let b = coverage_incomplete_row(&rule, end, &message);
    assert_eq!(a["log_id"], b["log_id"], "one alert per incomplete window");
    assert_eq!(a[COVERAGE_INCOMPLETE_MARKER], true);
    assert!(a.get("source_type").is_none(), "stamped by the window's companion, fail-closed");
    assert!(message.starts_with("DETECTION COVERAGE INCOMPLETE"));
}

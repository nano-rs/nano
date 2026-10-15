// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3256: the lean new-to-entity read is inverted — the current window's
//! values first, then a batched IN check of exactly those values against the
//! lookback. No result cap decides what is "new".

use super::*;
use chrono::{Duration, TimeZone, Utc};
use serde_json::json;
use std::sync::{Arc, Mutex};

type Reads = Arc<Mutex<Vec<(String, TimeRange, &'static str, usize)>>>;

fn plan(dims: Option<Vec<&str>>) -> LakeBaselinePlan {
    let end = Utc.with_ymd_and_hms(2026, 10, 7, 20, 0, 0).unwrap();
    LakeBaselinePlan::new(
        &BaselineCommandInfo {
            entity_type: Some("host".to_string()),
            entity_value: Some("ws-it-083.corp.local".to_string()),
            window: std::time::Duration::from_secs(7 * 86_400),
            dims: dims.map(|dims| dims.into_iter().map(str::to_string).collect()),
        },
        ("host".to_string(), "ws-it-083.corp.local".to_string()),
        &TimeRange::new(end - Duration::hours(1), end),
        false,
    )
    .unwrap()
}

fn ip(n: usize) -> String {
    format!("203.0.{}.{}", n / 250, n % 250 + 1)
}

/// IPs listed in the query's first IN list.
fn in_list_values(query: &str) -> Vec<String> {
    let start = query.find(" IN (").expect("IN list") + 5;
    let end = start + query[start..].find(')').unwrap();
    query[start..end]
        .split(", ")
        .map(|value| value.trim_matches('"').to_string())
        .collect()
}

/// A host whose window holds `window_ips` distinct destination IPs, of which
/// every one except `new_ips` was already contacted during the lookback.
async fn lake(
    reads: Reads,
    window_ips: usize,
    new_ips: &'static [usize],
    query: String,
    range: TimeRange,
    view: &'static str,
    limit: usize,
) -> Result<Vec<serde_json::Value>, SearchError> {
    reads
        .lock()
        .unwrap()
        .push((query.clone(), range.clone(), view, limit));
    Ok(match view {
        "baseline-activity" => {
            let mut rows = Vec::new();
            let mut hour = range.start;
            while hour < range.end {
                rows.push(json!({"time_bucket": hour.to_rfc3339(), "count": 50}));
                hour += Duration::hours(1);
            }
            rows
        }
        "baseline-window" if query.contains("dst_endpoint.ip") => (0..window_ips)
            .map(|n| {
                json!({
                    "dst_endpoint.ip": ip(n),
                    "count": 1 + (n % 3) as u64,
                    "first_seen": (range.start + Duration::seconds(n as i64)).to_rfc3339(),
                })
            })
            .collect(),
        "baseline-lookback" if query.contains("dst_endpoint.ip") => in_list_values(&query)
            .into_iter()
            .filter(|value| !new_ips.iter().any(|n| ip(*n) == *value))
            .map(|value| {
                json!({
                    "dst_endpoint.ip": value,
                    "first_seen": (range.start + Duration::days(1)).to_rfc3339(),
                })
            })
            .collect(),
        "baseline-history" => vec![json!({"time": range.start.to_rfc3339()})],
        _ => Vec::new(),
    })
}

#[test]
fn the_planner_emits_a_window_read_and_batched_in_lookback_checks() {
    let predicate = lake_baseline_entity_predicate("host", "ws-1", true).unwrap();
    let window = lake_baseline_window_query(&predicate, &["dst_endpoint.ip"]);
    crate::query::parse_query(&window).expect("window query parses");
    assert!(
        window.contains("| stats count,min(time) as first_seen by dst_endpoint.ip"),
        "{window}"
    );
    assert!(
        window.ends_with(&format!("| head {LAKE_BASELINE_WINDOW_ROW_CAP}")),
        "{window}"
    );

    let values = (0..1_200).map(ip).collect::<Vec<_>>();
    let batches = lake_baseline_batches(&values, &["dst_endpoint.ip"]);
    assert_eq!(
        batches.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![LAKE_BASELINE_IN_BATCH_VALUES, 200]
    );
    assert_eq!(batches.concat(), values);

    // Multi-field dimensions OR their per-field IN lists; quotes are escaped.
    let check = lake_baseline_lookback_query(
        &predicate,
        &["user.name", "actor.user.name"],
        &["alice".to_string(), "o\"brien".to_string()],
    );
    let parsed = crate::query::parse_query(&check).expect("lookback check parses");
    assert!(
        check.contains(
            r#"(user.name IN ("alice", 'o"brien') OR actor.user.name IN ("alice", 'o"brien'))"#
        ),
        "{check}"
    );
    assert!(
        check.ends_with("| stats min(time) as first_seen by user.name, actor.user.name"),
        "{check}"
    );
    let crate::query::Query::Piped { source, .. } = parsed else {
        panic!("piped");
    };
    let mut in_lists = 0;
    fn walk(expression: &crate::query::SearchExpr, in_lists: &mut usize) {
        use crate::query::SearchExpr;
        match expression {
            SearchExpr::InList {
                negated: false,
                values,
                ..
            } => {
                assert_eq!(values.len(), 2);
                *in_lists += 1;
            }
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                walk(left, in_lists);
                walk(right, in_lists);
            }
            SearchExpr::Group(inner) => walk(inner, in_lists),
            _ => {}
        }
    }
    if let crate::query::Query::Search(expression) = *source {
        walk(&expression, &mut in_lists);
    }
    assert_eq!(in_lists, 2, "{check}");

    // NAN-3260: the bound is the query text the lists cost across every
    // field (a two-field dimension repeats its list; a dotless hostname
    // adds its `startsWith`).
    let byte_heavy = (0..400).map(|n| format!("{n:0>300}")).collect::<Vec<_>>();
    for fields in [
        &["dst_endpoint.ip"][..],
        &["user.name", "actor.user.name"][..],
        &["src_endpoint.hostname", "device.hostname"][..],
    ] {
        let batches = lake_baseline_batches(&byte_heavy, fields);
        assert_eq!(batches.concat(), byte_heavy);
        assert!(batches.iter().all(|batch| batch
            .iter()
            .map(|value| lake_baseline_value_cost(value, fields))
            .sum::<usize>()
            <= LAKE_BASELINE_IN_QUERY_BYTES));
    }
    assert!(
        lake_baseline_value_cost("ws-1", &["src_endpoint.hostname"])
            > lake_baseline_value_cost("ws-1.corp", &["src_endpoint.hostname"])
    );
}

#[tokio::test]
async fn reads_scale_with_the_window_and_the_lookback_only_checks_window_values() {
    let plan = plan(Some(vec!["dst_endpoint.ip"]));
    let spans = plan.spans();
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan,
        |query, range, view, limit| lake(reads.clone(), 1_200, &[7], query, range, view, limit),
        None,
    )
    .await
    .unwrap();
    assert!(outcome.complete);
    let reads = reads.lock().unwrap();
    let window = reads
        .iter()
        .filter(|read| read.2 == "baseline-window")
        .collect::<Vec<_>>();
    assert_eq!(window.len(), 1);
    assert_eq!(
        (window[0].1.start, window[0].1.end),
        (spans.incident_start, spans.incident_end)
    );
    let checks = reads
        .iter()
        .filter(|read| read.2 == "baseline-lookback")
        .collect::<Vec<_>>();
    // NAN-3260: the newest lookback day checks all 1200 values (two
    // batches); only the one value it did not see goes on to the older
    // remainder of the lookback.
    assert_eq!(checks.len(), 3, "{checks:?}");
    let newest_day = spans.incident_start - Duration::days(1);
    for (query, range, _, _) in &checks[..2] {
        assert_eq!(range.start, newest_day);
        assert!(range.end < spans.incident_start, "{range:?}");
        assert!(!in_list_values(query).is_empty());
    }
    assert_eq!(in_list_values(&checks[2].0), vec![ip(7)]);
    assert_eq!(checks[2].1.start, spans.new_start);
    assert!(checks[2].1.end < newest_day);
    for (query, range, _, _) in &checks {
        assert!(
            range.start >= spans.new_start && range.end < spans.incident_start,
            "{range:?}"
        );
        assert!(in_list_values(query).len() <= LAKE_BASELINE_IN_BATCH_VALUES);
        assert!(
            !query.contains("sort") && !query.contains("head"),
            "{query}"
        );
    }
    // A value was known, so no history probe was needed.
    assert!(!reads.iter().any(|read| read.2 == "baseline-history"));
}

#[tokio::test]
async fn a_value_seen_in_the_lookback_is_not_new_even_past_the_old_cap() {
    // Far more distinct window values than NEW_TO_ENTITY_ROW_CAP: the old
    // `sort -first_seen | head CAP*4` kept only in-window values here.
    let window_ips = baseline::NEW_TO_ENTITY_ROW_CAP * 6;
    let plan = plan(Some(vec!["dst_endpoint.ip"]));
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan,
        |query, range, view, limit| {
            lake(
                reads.clone(),
                window_ips,
                &[3, 450],
                query,
                range,
                view,
                limit,
            )
        },
        None,
    )
    .await
    .unwrap();
    let new = outcome
        .rows
        .iter()
        .filter(|row| row["dimension"] == "destination IPs")
        .collect::<Vec<_>>();
    assert_eq!(
        new.iter()
            .map(|row| row["value"].as_str().unwrap())
            .collect::<Vec<_>>(),
        // Newest first sighting first.
        vec![ip(450), ip(3)]
    );
    for row in &new {
        assert_eq!(row["baseline_unknown"], false);
        assert_eq!(row["incomplete"], false);
    }
    assert!(outcome.rows.iter().all(|row| row["incomplete"] != true));
}

#[tokio::test]
async fn only_the_window_bound_makes_a_dimension_incomplete() {
    let plan = plan(Some(vec!["dst_endpoint.ip"]));
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan,
        |query, range, view, limit| {
            lake(
                reads.clone(),
                LAKE_BASELINE_WINDOW_ROW_CAP,
                &[1],
                query,
                range,
                view,
                limit,
            )
        },
        None,
    )
    .await
    .unwrap();
    assert!(outcome.complete);
    let value = outcome
        .rows
        .iter()
        .find(|row| row["value"] == ip(1))
        .unwrap();
    assert_eq!(value["incomplete"], true);
    let marker = outcome
        .rows
        .iter()
        .find(|row| row["dimension"].is_null())
        .unwrap();
    assert_eq!(marker["incomplete_dimensions"], json!(["destination IPs"]));
}

#[tokio::test]
async fn all_new_values_need_lookback_history_in_the_dimension() {
    let plan = plan(Some(vec!["dst_endpoint.ip"]));
    // Every window value is new: the history probe decides.
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan,
        |query, range, view, limit| lake(reads.clone(), 3, &[0, 1, 2], query, range, view, limit),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome
            .rows
            .iter()
            .filter(|row| row["dimension"] == "destination IPs")
            .count(),
        3
    );
    assert_eq!(
        reads
            .lock()
            .unwrap()
            .iter()
            .filter(|read| read.2 == "baseline-history")
            .count(),
        1
    );

    // Same window, but the dimension was never populated before: nothing is
    // claimed as new.
    let outcome = run_lake_baseline(
        &plan,
        |query, range, view, limit| async move {
            if view == "baseline-history" {
                return Ok(Vec::new());
            }
            lake(Arc::default(), 3, &[0, 1, 2], query, range, view, limit).await
        },
        None,
    )
    .await
    .unwrap();
    assert!(outcome.rows.iter().all(|row| row["dimension"].is_null()));
}

#[test]
fn a_dotless_hostname_counts_as_seen_through_its_fqdn() {
    let mut seen = std::collections::BTreeMap::new();
    let at = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
    seen.insert("ws-1.corp.local".to_string(), at);
    let host_fields = ["src_endpoint.hostname", "device.hostname"];
    assert_eq!(lake_baseline_seen(&seen, &host_fields, "WS-1"), Some(at));
    assert_eq!(lake_baseline_seen(&seen, &host_fields, "ws-10"), None);
    assert_eq!(lake_baseline_seen(&seen, &["user.name"], "ws-1"), None);
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure tests for the ClickHouse per-source health series (NAN-4922).

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, TimeZone, Utc};
use uuid::Uuid;

use super::health_series::*;
use super::types::LogSource;
use crate::auth::ScopeSet;

fn source(name: &str, match_values: Option<&[&str]>, enabled: bool) -> LogSource {
    let json = serde_json::json!({
        "id": Uuid::new_v4().to_string(),
        "name": name,
        "description": null,
        "source_type": "routed",
        "parser_vrl": "",
        "output_fields": null,
        "category": null, "vendor": null, "product": null, "icon": null, "color": null,
        "match_field": null, "match_pattern": null,
        "match_values": match_values.map(|v| v.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
        "validated": true, "validation_error": null,
        "deployed": true, "deployed_at": null, "enabled": enabled,
        "lifecycle_status": "active",
        "stale_alert_enabled": false, "stale_threshold_minutes": 60,
        "sampling_ratio": null, "sampling_exclude_condition": null,
        "source_parser_repository_id": null, "source_parser_path": null,
        "created_at": Utc::now(), "updated_at": Utc::now(),
    });
    serde_json::from_value(json).expect("log source fixture")
}

/// Wednesday 2026-11-04 12:30 UTC.
fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 4, 12, 30, 0).unwrap()
}

fn count(key: &str, hour: DateTime<Utc>, events: i64) -> HourlyCount {
    HourlyCount { route_key: key.into(), hour, events, last_event_at: Some(hour + Duration::minutes(59)) }
}

/// `events` every hour from `from` through the current hour.
fn steady(key: &str, from: DateTime<Utc>, events: i64) -> Vec<HourlyCount> {
    let mut out = Vec::new();
    let mut h = hour_floor(from);
    while h <= hour_floor(now()) {
        out.push(count(key, h, events));
        h += Duration::hours(1);
    }
    out
}

fn data_start() -> DateTime<Utc> {
    hour_floor(now()) - Duration::hours(read_hours(24))
}

#[test]
fn route_keys_follow_match_values_lowercased_else_safe_name() {
    assert_eq!(source_route_keys(&source("Fw", Some(&[" PAN ", "pan", "asa"]), true)), vec!["asa", "pan"]);
    assert_eq!(source_route_keys(&source("My Firewall", None, true)), vec![crate::vector_naming::safe_name("My Firewall")]);
}

#[test]
fn steady_source_with_a_week_of_history_is_healthy_with_a_band() {
    let counts = steady("pan", now() - Duration::days(7), 100);
    let s = build_series(Uuid::nil(), "pan", &["pan".into()], true, &counts, data_start(), 24, now(), &HealthPolicy::default());
    assert_eq!(s.state, SourceHealthState::Healthy);
    assert_eq!(s.points.len(), 24);
    assert_eq!(s.points.last().unwrap().hour, hour_floor(now()));
    assert!(s.points.last().unwrap().assessment.is_none(), "current hour is never judged");
    let judged = &s.points[s.points.len() - 2];
    assert_eq!(judged.expected, Some(100.0));
    assert_eq!(judged.assessment, Some(BucketAssessment::Normal));
    assert!(s.baseline_days >= 3);
    assert_eq!(s.baseline_days_required, 3);
    assert!(s.segments.is_empty() && !s.segments_available);
    assert_eq!(s.source_slugs, vec!["pan".to_string()]);
}

#[test]
fn new_source_is_learning_not_healthy() {
    let counts = steady("pan", now() - Duration::hours(10), 100);
    let s = build_series(Uuid::nil(), "pan", &["pan".into()], true, &counts, data_start(), 24, now(), &HealthPolicy::default());
    assert_eq!(s.state, SourceHealthState::Learning);
    assert_eq!(s.baseline_days, 0);
    // Hours before first-seen are unknown, reported as 0 events, no band.
    assert_eq!(s.points[0].events, 0);
    assert_eq!(s.points[0].expected, None);
}

#[test]
fn silent_source_is_stale_and_disabled_wins() {
    let counts: Vec<HourlyCount> = steady("pan", now() - Duration::days(7), 100)
        .into_iter()
        .filter(|c| c.hour < hour_floor(now()) - Duration::hours(3))
        .collect();
    let s = build_series(Uuid::nil(), "pan", &["pan".into()], true, &counts, data_start(), 24, now(), &HealthPolicy::default());
    assert_eq!(s.state, SourceHealthState::Stale);
    let d = build_series(Uuid::nil(), "pan", &["pan".into()], false, &counts, data_start(), 24, now(), &HealthPolicy::default());
    assert_eq!(d.state, SourceHealthState::Disabled);
}

#[test]
fn drop_below_band_is_degraded() {
    let judged = newest_judged_hour(now(), &HealthPolicy::default());
    let counts: Vec<HourlyCount> = steady("pan", now() - Duration::days(7), 1000)
        .into_iter()
        .map(|c| if c.hour >= judged { HourlyCount { events: 5, ..c } } else { c })
        .collect();
    let s = build_series(Uuid::nil(), "pan", &["pan".into()], true, &counts, data_start(), 24, now(), &HealthPolicy::default());
    assert_eq!(s.state, SourceHealthState::Degraded);
}

#[test]
fn never_seen_source_is_stale_with_zero_points() {
    let s = build_series(Uuid::nil(), "x", &["x".into()], true, &[], data_start(), 6, now(), &HealthPolicy::default());
    assert_eq!(s.state, SourceHealthState::Stale);
    assert_eq!(s.points.len(), 6);
    assert!(s.points.iter().all(|p| p.events == 0 && p.expected.is_none()));
    assert!(s.last_event_at.is_none());
}

#[test]
fn multiple_keys_sum_and_other_sources_are_ignored() {
    let h = hour_floor(now());
    let counts = vec![count("a", h, 3), count("b", h, 4), count("c", h, 100)];
    let s = build_series(Uuid::nil(), "ab", &["a".into(), "b".into()], true, &counts, data_start(), 2, now(), &HealthPolicy::default());
    assert_eq!(s.points.last().unwrap().events, 7);
}

#[test]
fn window_is_clamped() {
    let s = build_series(Uuid::nil(), "x", &["x".into()], true, &[], data_start(), 10_000, now(), &HealthPolicy::default());
    assert_eq!(s.window_hours, MAX_SERIES_HOURS);
    let s = build_series(Uuid::nil(), "x", &["x".into()], true, &[], data_start(), 0, now(), &HealthPolicy::default());
    assert_eq!(s.window_hours, 1);
}

#[test]
fn build_all_skips_enrichment_sources() {
    let mut e = source("enr", Some(&["enr"]), true);
    e.kind = "enrichment".into();
    let all = build_all_series(&[source("pan", Some(&["pan"]), true), e], &[], data_start(), 24, now(), &HealthPolicy::default());
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].log_source_name, "pan");
}

#[test]
fn sql_escapes_keys_and_applies_scope() {
    let sql = hourly_sql("nanosiem.logs_per_source_5m_v2", "ocsf", 192, &ScopeSet::unrestricted(), &["o'brien".into(), "PAN".into()]);
    assert!(sql.contains("source_type IN ('o''brien', 'pan')"), "{sql}");
    assert!(sql.contains("schema_profile = 'ocsf'"));
    assert!(sql.contains("INTERVAL 192 HOUR"));
    assert!(!sql.contains("scope_source_type_complete"));
    let denied = ScopeSet::from_denied(BTreeSet::from(["secret".to_string()]));
    let sql = hourly_sql("t", "ocsf", 24, &denied, &["pan".into()]);
    assert!(sql.contains("scope_source_type_complete = 1"), "{sql}");
    assert!(sql.contains("secret"), "{sql}");
}

#[test]
fn read_hours_cover_window_and_lookback_within_retention() {
    assert_eq!(read_hours(24), 169);
    assert_eq!(read_hours(1), 169);
}

#[test]
fn parses_json_each_row() {
    let body = "{\"route_key\":\"pan\",\"hour_s\":\"1793793600\",\"events\":\"42\",\"last_ms\":\"1793795000000\"}\n\
                {\"route_key\":\"x\",\"hour_s\":1793793600,\"events\":0,\"last_ms\":0}\n\ngarbage\n";
    let rows = parse_hourly_rows(body);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].events, 42);
    assert_eq!(rows[0].hour.timestamp(), 1793793600);
    assert!(rows[0].last_event_at.is_some());
    assert!(rows[1].last_event_at.is_none());
}

#[test]
fn json_shape_matches_web_contract() {
    let s = build_series(Uuid::nil(), "x", &["x".into()], true, &[], data_start(), 1, now(), &HealthPolicy::default());
    let v = serde_json::to_value(&s).unwrap();
    for key in ["log_source_id", "log_source_name", "source_slugs", "state", "window_hours", "last_event_at",
        "baseline_days", "baseline_days_required", "points", "segments", "segments_available"] {
        assert!(v.get(key).is_some(), "missing {key}");
    }
    assert!(v["log_source_id"].as_str().unwrap().starts_with("lsrc_"));
    assert_eq!(v["state"], "stale");
    let p = &v["points"][0];
    for key in ["hour", "events", "expected", "low", "high", "assessment"] {
        assert!(p.get(key).is_some(), "missing point {key}");
    }
}

#[test]
fn undeployed_draft_is_judged_on_data_not_disabled() {
    // Connect-first: a draft receives through its tokens before any parser is
    // deployed, so `enabled = false` must not read as disabled (connect_state's rule).
    let mut draft = source("vpn", Some(&["acme_vpn"]), false);
    draft.deployed = false;
    draft.lifecycle_status = "draft".into();
    let mut off = source("pan", Some(&["pan"]), false);
    off.deployed = true;
    let counts = vec![HourlyCount { route_key: "acme_vpn".into(), hour: hour_floor(now()), events: 3, last_event_at: Some(now()) }];
    let all = build_all_series(&[draft, off], &counts, data_start(), 6, now(), &HealthPolicy::default());
    assert_ne!(all[0].state, SourceHealthState::Disabled);
    assert_eq!(all[0].points.last().map(|p| p.events), Some(3));
    assert_eq!(all[1].state, SourceHealthState::Disabled);
}

#[test]
fn exact_last_event_age_is_authoritative_for_stale() {
    // 12:59, low-volume source last seen at 11:01: the 11:00 bucket has an
    // event, but the source has been silent 118 minutes, so it is stale.
    let at = Utc.with_ymd_and_hms(2026, 11, 4, 12, 59, 0).unwrap();
    let eleven = Utc.with_ymd_and_hms(2026, 11, 4, 11, 0, 0).unwrap();
    let counts = vec![HourlyCount { route_key: "vpn".into(), hour: eleven, events: 1, last_event_at: Some(eleven + Duration::minutes(1)) }];
    let s = build_series(Uuid::nil(), "vpn", &["vpn".into()], true, &counts, at - Duration::days(8), 24, at, &HealthPolicy::default());
    assert_eq!(s.state, SourceHealthState::Stale);
    // Last seen 12:01: 58 minutes, not stale.
    let fresh = vec![HourlyCount { route_key: "vpn".into(), hour: eleven + Duration::hours(1), events: 1, last_event_at: Some(eleven + Duration::minutes(61)) }];
    let s = build_series(Uuid::nil(), "vpn", &["vpn".into()], true, &fresh, at - Duration::days(8), 24, at, &HealthPolicy::default());
    assert_ne!(s.state, SourceHealthState::Stale);
}

#[test]
fn empty_judged_hour_with_a_baseline_is_source_silent() {
    let judged = newest_judged_hour(now(), &HealthPolicy::default());
    let counts: Vec<HourlyCount> = steady("pan", now() - Duration::days(7), 100)
        .into_iter()
        .filter(|c| c.hour != judged)
        .collect();
    let s = build_series(Uuid::nil(), "pan", &["pan".into()], true, &counts, data_start(), 24, now(), &HealthPolicy::default());
    let point = s.points.iter().find(|p| p.hour == judged).unwrap();
    assert_eq!(point.events, 0);
    assert_eq!(point.assessment, Some(BucketAssessment::SourceSilent));
    assert_eq!(assess(0, Some(Baseline { expected: 100.0, low: 50.0, high: 150.0, samples: 7 }), Some(0), &HealthPolicy::default()), BucketAssessment::SourceSilent);
}

#[test]
fn future_dated_events_cannot_keep_a_source_fresh() {
    let old = hour_floor(now()) - Duration::hours(5);
    let future = Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
    let counts = vec![
        HourlyCount { route_key: "pan".into(), hour: old, events: 10, last_event_at: Some(old + Duration::minutes(5)) },
        HourlyCount { route_key: "pan".into(), hour: future, events: 1, last_event_at: Some(future) },
        // A current-hour bucket whose max timestamp is ahead of now is clamped.
    ];
    let s = build_series(Uuid::nil(), "pan", &["pan".into()], true, &counts, data_start(), 24, now(), &HealthPolicy::default());
    assert_eq!(s.state, SourceHealthState::Stale);
    assert_eq!(s.last_event_at, Some(old + Duration::minutes(5)));
    let ahead = vec![HourlyCount { route_key: "pan".into(), hour: hour_floor(now()), events: 2, last_event_at: Some(future) }];
    let s = build_series(Uuid::nil(), "pan", &["pan".into()], true, &ahead, data_start(), 24, now(), &HealthPolicy::default());
    assert_eq!(s.last_event_at, Some(now()));
}

#[test]
fn sql_bounds_the_scan_above_in_the_same_where() {
    let sql = hourly_sql("t", "ocsf", 24, &ScopeSet::unrestricted(), &["pan".into()]);
    assert!(sql.contains("AND bucket_start < toStartOfHour(now()) + INTERVAL 1 HOUR"), "{sql}");
    assert_eq!(sql.matches("WHERE").count(), 1, "{sql}");
    assert!(!sql.to_uppercase().contains("PREWHERE"), "{sql}");
}

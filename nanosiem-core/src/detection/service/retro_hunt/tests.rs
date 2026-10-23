// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use uuid::Uuid;

fn rule_id() -> Uuid {
    Uuid::parse_str("00000000-0000-0000-0000-0000000000cc").unwrap()
}

fn candidate(value: &str, key_type: &str, feed: &str, fetched_ms: i64) -> RetroFeedCandidate {
    RetroFeedCandidate {
        value: value.to_string(),
        key_type: key_type.to_string(),
        enrichment_name: feed.to_string(),
        confidence: 75,
        fetched_at_ms: fetched_ms,
        feed_revision: None,
    }
}

fn hit(value: &str, field: &str, last_seen: Option<&str>) -> RetroHuntHit {
    RetroHuntHit {
        value: value.to_string(),
        indicator_type: "ip".to_string(),
        field: field.to_string(),
        hits: 3,
        hosts: 1,
        total_hosts: 100,
        first_seen: Some("2026-01-01T00:00:00Z".to_string()),
        last_seen: last_seen.map(str::to_string),
        verdict: "rare".to_string(),
    }
}

// ---------------------------------------------------------------------------
// plan_cursor — the keyset delta-cursor invariants
// ---------------------------------------------------------------------------

fn k(ms: i64, v: &str) -> (i64, String) {
    (ms, v.to_string())
}

#[test]
fn plan_cursor_no_candidates_keeps_prior() {
    // Nothing new landed → cursor unchanged (Some or None both preserved).
    assert_eq!(
        plan_cursor(&[], 5, Some(k(1000, "a"))),
        (false, Some(k(1000, "a")))
    );
    assert_eq!(plan_cursor(&[], 5, None), (false, None));
}

#[test]
fn plan_cursor_under_cap_drains_and_advances_to_newest() {
    // 3 candidates, cap 5 → not truncated; advance to the LAST candidate so the
    // scan window collapses forward.
    let c = vec![k(100, "a"), k(200, "b"), k(300, "c")];
    let (truncated, after) = plan_cursor(&c, 5, Some(k(50, "z")));
    assert!(!truncated);
    assert_eq!(after, Some(k(300, "c")));
}

#[test]
fn plan_cursor_exact_cap_not_truncated() {
    let c = vec![k(10, "a"), k(20, "b"), k(30, "c")];
    let (truncated, after) = plan_cursor(&c, 3, None);
    assert!(!truncated);
    assert_eq!(after, Some(k(30, "c")));
}

#[test]
fn plan_cursor_over_cap_advances_to_last_covered() {
    // cap+1 fetched (truncation): advance ONLY to the last COVERED candidate
    // (index cap-1). The overflow (index cap) is carried to the next run.
    let c = vec![k(10, "a"), k(20, "b"), k(30, "c"), k(40, "d")];
    let (truncated, after) = plan_cursor(&c, 3, Some(k(5, "_")));
    assert!(truncated);
    assert_eq!(
        after,
        Some(k(30, "c")),
        "must stop at the last covered candidate, not the overflow"
    );
}

/// REGRESSION (codex review): a feed sync bulk-stamps every indicator with the
/// SAME `fetched_at`. If that tie group is bigger than the per-run cap, a
/// timestamp-only cursor CANNOT drain it — advancing past the timestamp would
/// skip the tail, and refusing to advance means the capped ordered query returns
/// the same already-hunted rows forever, so the tail is NEVER hunted.
///
/// The keyset cursor must advance WITHIN the tie group (same ts, later value) so
/// the next run's strict `(ts, value) >` predicate reaches the tail.
#[test]
fn plan_cursor_advances_within_a_tie_group_so_the_tail_is_reachable() {
    const T: i64 = 1_700_000_000_000;
    // 5 indicators, all at the same fetched_at T. cap = 2.
    let all = ["a", "b", "c", "d", "e"];
    let cap = 2;

    // Run 1: candidates are the cap+1 lowest keys after no cursor.
    let probe1: Vec<(i64, String)> = all.iter().take(cap + 1).map(|v| k(T, v)).collect();
    let (trunc1, cur1) = plan_cursor(&probe1, cap, None);
    assert!(trunc1);
    // Cursor advanced INSIDE the tie group — same timestamp, second value.
    assert_eq!(cur1, Some(k(T, "b")));

    // Run 2: the strict keyset predicate `(fetched_at, value) > (T, "b")` selects
    // c, d, e — the tail is reachable. Simulate that slice.
    let probe2: Vec<(i64, String)> = all
        .iter()
        .filter(|v| **v > "b")
        .take(cap + 1)
        .map(|v| k(T, v))
        .collect();
    assert_eq!(probe2, vec![k(T, "c"), k(T, "d"), k(T, "e")]);
    let (trunc2, cur2) = plan_cursor(&probe2, cap, cur1.clone());
    assert!(trunc2);
    assert_eq!(cur2, Some(k(T, "d")));

    // Run 3: reaches the final element and drains.
    let probe3: Vec<(i64, String)> = all
        .iter()
        .filter(|v| **v > "d")
        .take(cap + 1)
        .map(|v| k(T, v))
        .collect();
    assert_eq!(probe3, vec![k(T, "e")]);
    let (trunc3, cur3) = plan_cursor(&probe3, cap, cur2.clone());
    assert!(!trunc3, "final batch is under cap → drained");
    assert_eq!(cur3, Some(k(T, "e")));

    // The cursor strictly advanced every run — no stall, nothing skipped.
    assert!(cur1 < cur2 && cur2 < cur3);
}

#[test]
fn plan_cursor_is_strictly_monotonic_across_runs() {
    // Whatever the batch shape, the cursor never moves backwards.
    let c = vec![k(10, "a"), k(10, "b"), k(20, "a")];
    let (_, after) = plan_cursor(&c, 10, Some(k(5, "z")));
    assert_eq!(after, Some(k(20, "a")));
    assert!(after > Some(k(5, "z")));
}

// ---------------------------------------------------------------------------
// hit_event_id — stable across re-runs, unique per (indicator, last-seen)
// ---------------------------------------------------------------------------

#[test]
fn hit_event_id_is_stable_and_specific() {
    let a1 = hit_event_id(rule_id(), "1.2.3.4", "2026-01-02T00:00:00Z");
    let a2 = hit_event_id(rule_id(), "1.2.3.4", "2026-01-02T00:00:00Z");
    assert_eq!(a1, a2, "same (rule, indicator, last-seen) must be stable");
    assert!(a1.starts_with("retro_"));

    // Different indicator → different id.
    assert_ne!(
        a1,
        hit_event_id(rule_id(), "5.6.7.8", "2026-01-02T00:00:00Z")
    );
    // A later last-seen (new activity) → different id (so it re-alerts).
    assert_ne!(
        a1,
        hit_event_id(rule_id(), "1.2.3.4", "2026-01-03T00:00:00Z")
    );
    // Different rule → different id.
    let other = Uuid::parse_str("00000000-0000-0000-0000-0000000000dd").unwrap();
    assert_ne!(a1, hit_event_id(other, "1.2.3.4", "2026-01-02T00:00:00Z"));
}

// ---------------------------------------------------------------------------
// build_hit_events — synthesized event shape the emission path consumes
// ---------------------------------------------------------------------------

#[test]
fn build_hit_events_carries_entity_window_and_context() {
    let cands = vec![candidate("1.2.3.4", "ip", "threatfox", 1000)];
    let cand_refs: Vec<&RetroFeedCandidate> = cands.iter().collect();
    let hits = vec![hit("1.2.3.4", "src_ip", Some("2026-01-05T10:00:00Z"))];

    let events = build_hit_events(rule_id(), &hits, &cand_refs);
    assert_eq!(events.len(), 1);
    let e = &events[0];

    // Entity is the indicator (risk_entity_field = "indicator").
    assert_eq!(e["indicator"], "1.2.3.4");
    // The matched observable column is populated too (realistic alert row).
    assert_eq!(e["src_ip"], "1.2.3.4");
    // Canonical activity window → aggregate dedup branch keys on _last_seen.
    assert_eq!(e["_last_seen"], "2026-01-05T10:00:00Z");
    assert_eq!(e["_first_seen"], "2026-01-01T00:00:00Z");
    // timestamp mirrors last_seen so record_matched_events stamps a real time.
    assert_eq!(e["timestamp"], "2026-01-05T10:00:00Z");
    // Retro context for the UI.
    assert_eq!(e["retro_feed"], "threatfox");
    assert_eq!(e["retro_verdict"], "rare");
    assert_eq!(e["retro_hits"], 3);
    // Stable id present for matched-event dedup.
    let id = e["id"].as_str().unwrap();
    assert_eq!(
        id,
        hit_event_id(rule_id(), "1.2.3.4", "2026-01-05T10:00:00Z")
    );
    // Human message mentions the indicator + feed.
    let msg = e["message"].as_str().unwrap();
    assert!(msg.contains("1.2.3.4") && msg.contains("threatfox"));
}

#[test]
fn build_hit_events_defaults_last_seen_when_absent() {
    // A hit with no last_seen must still get a usable window (falls back to now)
    // so the dedup identity + timestamp are well-formed.
    let cand_refs: Vec<&RetroFeedCandidate> = vec![];
    let hits = vec![hit("9.9.9.9", "dest_ip", None)];
    let events = build_hit_events(rule_id(), &hits, &cand_refs);
    assert_eq!(events.len(), 1);
    // last_seen absent → feed empty → "unknown" feed, but event still well-formed.
    assert!(events[0]["_last_seen"].as_str().is_some());
    assert_eq!(events[0]["indicator"], "9.9.9.9");
}

// ---------------------------------------------------------------------------
// NAN-4169: platform feed delta planning
// ---------------------------------------------------------------------------

fn platform_feed(feed: &str, revision: i64, changed: bool, values: &[(&str, &str)]) -> crate::enrichment::ioc::LakePlatformFeedDelta {
    crate::enrichment::ioc::LakePlatformFeedDelta {
        feed: feed.to_string(),
        display_name: if feed == "threatfox" { "ThreatFox".to_string() } else { String::new() },
        revision,
        changed,
        records: values
            .iter()
            .map(|(value, key_type)| crate::enrichment::ioc::LakePlatformRecord {
                value: value.to_string(),
                key_type: key_type.to_string(),
                confidence: 75,
                tags: vec![],
            })
            .collect(),
    }
}

fn known(pairs: &[(&str, i64)]) -> std::collections::BTreeMap<String, i64> {
    pairs.iter().map(|(f, r)| (f.to_string(), *r)).collect()
}

#[test]
fn platform_first_sight_baselines_instead_of_hunting_the_whole_feed() {
    let feeds = [platform_feed("threatfox", 3, true, &[("198.51.100.7", "ip"), ("198.51.100.9:443", "ip:port")])];
    let plan = plan_platform_delta(&feeds, &known(&[]), &Default::default(), 500, 1_000);
    assert!(plan.to_hunt.is_empty(), "a newly watched feed is never hunted whole");
    assert_eq!(plan.baseline.len(), 2);
    assert_eq!(plan.revisions_after, known(&[("threatfox", 3)]));
}

#[test]
fn platform_new_revision_hunts_only_the_added_indicators() {
    let feeds = [
        platform_feed("threatfox", 4, true, &[("198.51.100.7", "ip"), ("198.51.100.9:443", "ip:port"), ("evil.example", "domain")]),
        platform_feed("tor_exit_nodes", 9, false, &[]),
    ];
    let seen: std::collections::HashSet<String> = ["198.51.100.7".to_string()].into();
    let plan = plan_platform_delta(&feeds, &known(&[("threatfox", 3), ("tor_exit_nodes", 9)]), &seen, 500, 1_000);
    let hunted: Vec<_> = plan.to_hunt.iter().map(|c| (c.value.as_str(), c.key_type.as_str())).collect();
    assert_eq!(hunted, [("198.51.100.9:443", "ip:port"), ("evil.example", "domain")]);
    assert!(plan.to_hunt.iter().all(|c| c.feed_revision == Some(4) && c.enrichment_name == "ThreatFox" && c.fetched_at_ms == 1_000));
    assert!(plan.baseline.is_empty());
    assert_eq!(plan.revisions_after, known(&[("threatfox", 4), ("tor_exit_nodes", 9)]));
    assert_eq!((plan.considered, plan.overflow), (2, 0));
}

#[test]
fn platform_overflow_keeps_the_old_revision_so_the_next_run_resumes() {
    let feeds = [platform_feed("threatfox", 4, true, &[("a.example", "domain"), ("b.example", "domain"), ("c.example", "domain")])];
    let plan = plan_platform_delta(&feeds, &known(&[("threatfox", 3)]), &Default::default(), 2, 1_000);
    assert_eq!(plan.to_hunt.len(), 2);
    assert_eq!(plan.overflow, 1);
    assert_eq!(plan.revisions_after, known(&[("threatfox", 3)]), "revision must not advance past unhunted values");
    // Next run: the first two are now hunted; the remainder fits and the
    // revision advances.
    let seen: std::collections::HashSet<String> = ["a.example".to_string(), "b.example".to_string()].into();
    let next = plan_platform_delta(&feeds, &known(&[("threatfox", 3)]), &seen, 2, 2_000);
    assert_eq!(next.to_hunt.iter().map(|c| c.value.as_str()).collect::<Vec<_>>(), ["c.example"]);
    assert_eq!(next.revisions_after, known(&[("threatfox", 4)]));
}

#[test]
fn platform_feed_no_longer_granted_drops_out_and_rebaselines() {
    let feeds = [platform_feed("tor_exit_nodes", 9, false, &[])];
    let plan = plan_platform_delta(&feeds, &known(&[("threatfox", 3), ("tor_exit_nodes", 9)]), &Default::default(), 500, 1);
    assert_eq!(plan.revisions_after, known(&[("tor_exit_nodes", 9)]));
    assert_eq!(platform_delta_values(&feeds), Vec::<String>::new());
}

#[test]
fn build_hit_events_mark_the_retro_signal() {
    let mut c = candidate("198.51.100.9:443", "ip:port", "ThreatFox", 1_760_000_000_000);
    c.feed_revision = Some(4);
    let events = build_hit_events(rule_id(), &[hit("198.51.100.9:443", "dst_endpoint.ip", Some("2026-10-19T10:00:00Z"))], &[&c]);
    let e = &events[0];
    assert_eq!(e["retro"], true);
    assert_eq!(e["retro_ioc"], true);
    assert_eq!(e["retro_feed"], "ThreatFox");
    assert_eq!(e["retro_feed_revision"], 4);
    assert_eq!(e["retro_learned_at"], "2025-10-09T08:53:20Z");
    assert_eq!(e["retro_field"], "dst_endpoint.ip");
}

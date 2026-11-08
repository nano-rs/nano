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
// walk_candidates — the keyset delta-cursor invariants (driver run against
// an in-memory candidate source + hunted set)
// ---------------------------------------------------------------------------

fn k(ms: i64, v: &str) -> (i64, String) {
    (ms, v.to_string())
}

/// The candidate query's contract over a fixed delta: rows STRICTLY after the
/// cursor, ordered by `(fetched_at, value)`, at most `limit`.
fn source(all: &[(i64, &str)], cursor: Option<(i64, String)>, limit: usize) -> Vec<RetroFeedCandidate> {
    let mut rows: Vec<(i64, String)> = all.iter().map(|(ms, v)| (*ms, v.to_string())).collect();
    rows.sort();
    rows.into_iter()
        .filter(|row| cursor.as_ref().is_none_or(|c| row > c))
        .take(limit)
        .map(|(ms, v)| candidate(&v, "ip", "feed", ms))
        .collect()
}

/// Run the production walk over `all` with `hunted` as the rule's hunted set.
async fn walk(
    all: &[(i64, &str)],
    hunted: &[&str],
    cursor: Option<(i64, String)>,
    cap: usize,
    page: usize,
    budget: usize,
) -> CandidateWalk {
    let hunted: std::collections::HashSet<String> = hunted.iter().map(|v| v.to_string()).collect();
    let pages = std::cell::Cell::new(0usize);
    let out = walk_candidates(
        cursor,
        cap,
        page,
        budget,
        |c, limit| {
            pages.set(pages.get() + 1);
            let rows = source(all, c, limit);
            async move { Ok(rows) }
        },
        |values| {
            let found = values.into_iter().filter(|v| hunted.contains(v)).collect();
            async move { Ok(found) }
        },
    )
    .await
    .unwrap();
    assert!(pages.get() <= 1 + budget / page.max(1) + 1, "bounded page count");
    out
}

fn values(w: &CandidateWalk) -> Vec<&str> {
    w.to_hunt.iter().map(|c| c.value.as_str()).collect()
}

#[tokio::test]
async fn walk_no_candidates_keeps_prior_cursor() {
    let w = walk(&[], &[], Some(k(1000, "a")), 5, 10, 100).await;
    assert_eq!((w.truncated, w.cursor_after, w.covered), (false, Some(k(1000, "a")), 0));
    let w = walk(&[], &[], None, 5, 10, 100).await;
    assert_eq!(w.cursor_after, None);
}

#[tokio::test]
async fn walk_under_cap_drains_and_advances_to_newest() {
    let all = [(100, "a"), (200, "b"), (300, "c")];
    let w = walk(&all, &[], Some(k(50, "z")), 5, 10, 100).await;
    assert!(!w.truncated);
    assert_eq!(w.cursor_after, Some(k(300, "c")));
    assert_eq!(values(&w), vec!["a", "b", "c"]);
}

#[tokio::test]
async fn walk_exact_cap_is_not_truncated() {
    let all = [(10, "a"), (20, "b"), (30, "c")];
    let w = walk(&all, &[], None, 3, 10, 100).await;
    assert!(!w.truncated);
    assert_eq!(w.cursor_after, Some(k(30, "c")));
}

#[tokio::test]
async fn walk_over_cap_stops_at_the_last_covered_candidate() {
    let all = [(10, "a"), (20, "b"), (30, "c"), (40, "d")];
    let w = walk(&all, &[], Some(k(5, "_")), 3, 10, 100).await;
    assert!(w.truncated);
    assert_eq!(w.cursor_after, Some(k(30, "c")), "the overflow is carried, not skipped");
    assert_eq!(w.covered, 3);
}

/// NAN-4902 lane G: already-hunted candidates (a feed that restamps
/// `fetched_at` on every sync) are walked past without consuming the cap, so
/// genuinely new indicators behind them are hunted in the same run.
#[tokio::test]
async fn walk_skips_already_hunted_without_charging_the_cap() {
    let all: Vec<(i64, String)> = (0..20).map(|i| (100, format!("old{i:02}"))).collect();
    let mut all: Vec<(i64, &str)> = all.iter().map(|(ms, v)| (*ms, v.as_str())).collect();
    all.push((200, "new1"));
    all.push((200, "new2"));
    let hunted: Vec<String> = (0..20).map(|i| format!("old{i:02}")).collect();
    let hunted: Vec<&str> = hunted.iter().map(String::as_str).collect();
    // cap 2, page 5: the old cap-charging walk would have stopped after "old01".
    let w = walk(&all, &hunted, None, 2, 5, 1_000).await;
    assert_eq!(values(&w), vec!["new1", "new2"]);
    assert!(!w.truncated);
    assert_eq!(w.covered, 22);
    assert_eq!(w.cursor_after, Some(k(200, "new2")));
}

#[tokio::test]
async fn walk_scan_budget_bounds_a_run_and_carries_the_rest() {
    let all: Vec<(i64, String)> = (0..50).map(|i| (100, format!("v{i:02}"))).collect();
    let all: Vec<(i64, &str)> = all.iter().map(|(ms, v)| (*ms, v.as_str())).collect();
    let hunted: Vec<&str> = all.iter().map(|(_, v)| *v).collect();
    let w = walk(&all, &hunted, None, 5, 10, 20).await;
    assert!(w.truncated, "budget reached with candidates left");
    assert_eq!(w.covered, 20);
    assert_eq!(w.cursor_after, Some(k(100, "v19")));
    // The next run resumes strictly after the cursor.
    let w2 = walk(&all, &hunted, w.cursor_after.clone(), 5, 10, 20).await;
    assert_eq!(w2.cursor_after, Some(k(100, "v39")));
}

/// REGRESSION (codex review, NAN-1791): a feed sync bulk-stamps every
/// indicator with the SAME `fetched_at`. If that tie group exceeds the cap, a
/// timestamp-only cursor cannot drain it. The keyset cursor advances WITHIN
/// the tie group (same ts, later value) so the next run reaches the tail.
#[tokio::test]
async fn walk_advances_within_a_tie_group_so_the_tail_is_reachable() {
    const T: i64 = 1_700_000_000_000;
    let all = [(T, "a"), (T, "b"), (T, "c"), (T, "d"), (T, "e")];
    let w1 = walk(&all, &[], None, 2, 2, 100).await;
    assert!(w1.truncated);
    assert_eq!(w1.cursor_after, Some(k(T, "b")));
    let w2 = walk(&all, &[], w1.cursor_after.clone(), 2, 2, 100).await;
    assert!(w2.truncated);
    assert_eq!(values(&w2), vec!["c", "d"]);
    let w3 = walk(&all, &[], w2.cursor_after.clone(), 2, 2, 100).await;
    assert!(!w3.truncated, "final batch is under cap → drained");
    assert_eq!(values(&w3), vec!["e"]);
    assert!(w1.cursor_after < w2.cursor_after && w2.cursor_after < w3.cursor_after);
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
    assert_ne!(a1, hit_event_id(rule_id(), "5.6.7.8", "2026-01-02T00:00:00Z"));
    // A later last-seen (new activity) → different id (so it re-alerts).
    assert_ne!(a1, hit_event_id(rule_id(), "1.2.3.4", "2026-01-03T00:00:00Z"));
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
    assert_eq!(e["retro"], true);
    assert_eq!(e["retro_ioc"], true);
    assert_eq!(e["retro_learned_at"], "1970-01-01T00:00:01.000Z", "candidate fetched_at");
    assert_eq!(e["retro_feed"], "threatfox");
    assert_eq!(e["retro_verdict"], "rare");
    assert_eq!(e["retro_hits"], 3);
    // Stable id present for matched-event dedup.
    let id = e["id"].as_str().unwrap();
    assert_eq!(id, hit_event_id(rule_id(), "1.2.3.4", "2026-01-05T10:00:00Z"));
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
// effective_start_cursor — partition-prunable first run (NAN-4902 lane G)
// ---------------------------------------------------------------------------

#[test]
fn first_run_and_stale_cursors_start_at_the_lookback_floor() {
    let now = 10 * 86_400_000;
    let floor = (now - 5 * 86_400_000, String::new());
    assert_eq!(effective_start_cursor(None, now, 5), Some(floor.clone()));
    assert_eq!(effective_start_cursor(Some(k(1, "old")), now, 5), Some(floor));
    let recent = k(now - 3_600_000, "v");
    assert_eq!(effective_start_cursor(Some(recent.clone()), now, 5), Some(recent));
}

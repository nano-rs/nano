// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5736: a claim that died mid-run (OOM / crash) is recorded at the next
//! claim. A crash is attributed to a rule only when it died running ALONE;
//! a rule that died alongside others is a suspect: no failure, no gap, a
//! short jittered delay, and an isolated next run.

use super::*;
use crate::detection::findings::tests::sample_rule;

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

/// The CT122 rule: alerting, sliding 60-minute lookback.
fn sliding_rule(last_run_at: DateTime<Utc>) -> DetectionRule {
    DetectionRule { lookback_minutes: Some(60), last_run_at: Some(last_run_at), ..sample_rule() }
}

fn died(alone: bool) -> RuleFailureCounters {
    RuleFailureCounters { crashed_attempts: 1, isolated_claim: alone, ..Default::default() }
}

/// Apply one release to the simulated row, as the repository does.
fn apply(rule: &mut DetectionRule, counters: &mut RuleFailureCounters, fold: &CrashFold) {
    if let Some(mark) = fold.advance_last_run_to {
        rule.last_run_at = Some(mark);
    }
    *counters = fold.counters.clone();
}

#[test]
fn crash_backoff_doubles_and_caps() {
    assert_eq!(crash_backoff(1), Duration::minutes(5));
    assert_eq!(crash_backoff(2), Duration::minutes(10));
    assert_eq!(crash_backoff(3), Duration::minutes(20));
    assert_eq!(crash_backoff(7), Duration::minutes(320));
    assert_eq!(crash_backoff(8), Duration::hours(6));
    assert_eq!(crash_backoff(i16::MAX), Duration::hours(6));
}

#[test]
fn jitter_is_per_rule_bounded_and_stable() {
    let ids: Vec<Uuid> = (0..200).map(|_| Uuid::now_v7()).collect();
    let jitters: std::collections::BTreeSet<i64> = ids.iter().map(|id| crash_jitter(*id).num_seconds()).collect();
    assert!(jitters.iter().all(|j| (0..CRASH_JITTER_MAX_SECS as i64).contains(j)));
    assert!(jitters.len() > 20, "co-killed rules spread out: {jitters:?}");
    assert_eq!(crash_jitter(ids[0]), crash_jitter(ids[0]));
}

/// Innocent co-runners: nothing is counted against them.
#[test]
fn a_crash_alongside_other_rules_only_makes_a_suspect() {
    let now = t("2026-11-20T12:00:00Z");
    let rule = sliding_rule(now - Duration::minutes(6));
    let fold = fold_crashed_attempts(&rule, &died(false), &DistributedSchedulerConfig::default(), now);
    assert!(!fold.attributed);
    assert!(fold.counters.crash_suspect);
    assert_eq!(fold.counters.crash_streak, 0);
    assert_eq!(fold.counters.consecutive_failures, 0);
    assert_eq!(fold.counters.failure_class, None, "no failure streak starts");
    assert!(fold.coverage_gap.is_none());
    assert!(fold.advance_last_run_to.is_none());
    let wait = fold.next_run_at - now;
    assert!(wait >= Duration::seconds(CRASH_SUSPECT_RETRY_SECS));
    assert!(wait < Duration::seconds(CRASH_SUSPECT_RETRY_SECS + CRASH_JITTER_MAX_SECS as i64));
    assert!(crash_error_message(&fold, now).starts_with("[crash?]"));
}

/// An innocent rule killed by a neighbour again and again never accumulates
/// failures, a long back-off or a gap.
#[test]
fn repeated_ambiguous_crashes_never_punish_the_rule() {
    let config = DistributedSchedulerConfig::default();
    let mut now = t("2026-11-20T12:00:00Z");
    let rule = sliding_rule(now - Duration::minutes(6));
    let mut counters = RuleFailureCounters::default();
    for _ in 0..20 {
        counters.crashed_attempts = 1;
        counters.isolated_claim = false;
        let fold = fold_crashed_attempts(&rule, &counters, &config, now);
        assert!(!fold.attributed && fold.coverage_gap.is_none());
        assert_eq!((fold.counters.consecutive_failures, fold.counters.crash_streak), (0, 0));
        assert!(fold.next_run_at - now <= Duration::minutes(3));
        counters = fold.counters.clone();
        now = fold.next_run_at;
    }
}

#[test]
fn a_crash_while_running_alone_is_attributed_and_backs_off() {
    let now = t("2026-11-20T12:00:00Z");
    let rule = sliding_rule(now - Duration::minutes(6));
    let fold = fold_crashed_attempts(&rule, &died(true), &DistributedSchedulerConfig::default(), now);
    assert!(fold.attributed);
    assert_eq!(fold.counters.consecutive_failures, 1);
    assert_eq!(fold.counters.failure_class.as_deref(), Some("other"));
    assert_eq!(fold.counters.failing_since, Some(now));
    assert_eq!(fold.counters.crash_streak, 1);
    assert!(fold.counters.crash_suspect, "it keeps running in isolation");
    assert!(!fold.counters.isolated_claim);
    assert_eq!(fold.next_run_at, now + Duration::minutes(5) + crash_jitter(rule.id));
    assert!(crash_error_message(&fold, now).starts_with("[crash] the jobs process was killed while this rule ran ALONE"));
}

/// A culprit that always dies alone backs off exponentially, records a gap
/// once the NAN-5424 `other` budget is spent (5 attempts and 1 h), and keeps
/// backing off after the gap.
#[test]
fn a_culprit_that_always_crashes_backs_off_gaps_and_keeps_backing_off() {
    let config = DistributedSchedulerConfig::default();
    let mut now = t("2026-11-20T12:00:00Z");
    let mut rule = sliding_rule(now - Duration::minutes(1));
    let mut counters = RuleFailureCounters::default();
    let stale = Duration::seconds(config.effective_stale_claim_timeout_secs());
    let mut gaps = 0;
    let mut delays = Vec::new();
    for attempt in 1..=12 {
        counters.crashed_attempts = 1;
        counters.isolated_claim = true;
        let fold = fold_crashed_attempts(&rule, &counters, &config, now);
        assert_eq!(fold.counters.crash_streak, attempt, "every crash is counted");
        if fold.coverage_gap.is_some() {
            gaps += 1;
        } else {
            assert!(fold.counters.consecutive_failures > 0);
        }
        delays.push((fold.next_run_at - now).num_minutes());
        apply(&mut rule, &mut counters, &fold);
        // It runs at next_run_at and dies; the claim goes stale.
        now = fold.next_run_at + stale;
    }
    assert!(gaps >= 1, "the spent retry budget records a gap: {delays:?}");
    assert!(delays.windows(2).all(|w| w[1] >= w[0]), "{delays:?}");
    assert!(*delays.last().unwrap() >= 360, "{delays:?}");
}

/// A marker-driven culprit first narrows its slice (NAN-5424 ladder), so a
/// window that kills the process costs at most the minimum slice.
#[test]
fn a_marker_driven_culprit_narrows_before_gapping() {
    let config = DistributedSchedulerConfig::default();
    let mut now = t("2026-11-20T12:00:00Z");
    let mut rule = DetectionRule { last_run_at: Some(now - Duration::hours(30)), ..sample_rule() };
    let mut counters = RuleFailureCounters::default();
    let mut gap = None;
    for _ in 0..40 {
        counters.crashed_attempts = 1;
        counters.isolated_claim = true;
        let fold = fold_crashed_attempts(&rule, &counters, &config, now);
        apply(&mut rule, &mut counters, &fold);
        if let Some(g) = fold.coverage_gap {
            gap = Some(g);
            break;
        }
        now = fold.next_run_at + Duration::minutes(6);
    }
    let (gap_start, gap_end, _) = gap.expect("a gap after the budget");
    assert!(gap_end - gap_start <= Duration::minutes(MIN_CATCHUP_CHUNK_MINUTES) + Duration::seconds(5));
    assert_eq!(rule.last_run_at, Some(gap_end), "the marker moves past exactly the gap");
}

#[test]
fn suspects_are_recognised_from_every_crash_signal() {
    assert!(!RuleFailureCounters::default().crash_suspected());
    assert!(RuleFailureCounters { crashed_attempts: 1, ..Default::default() }.crash_suspected());
    assert!(RuleFailureCounters { crash_suspect: true, ..Default::default() }.crash_suspected());
    assert!(RuleFailureCounters { crash_streak: 2, ..Default::default() }.crash_suspected());
}

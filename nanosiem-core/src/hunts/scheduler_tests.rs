// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — hunt scheduler tests.
//!
//! The weight is on the catch-up arithmetic. A week of missed slots collapsing
//! to one sweep is the behaviour most likely to be silently wrong and the one
//! nobody notices until their laptop has been shut for a week — by which point
//! the failure mode (a queue of 168 sweeps) is indistinguishable from the
//! feature working, right up until the machine spends a day grinding through
//! them.

use super::*;
use chrono::{Datelike, TimeZone, Timelike};

fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, min, 0).single().unwrap()
}

fn ny() -> Tz {
    chrono_tz::America::New_York
}

/// Daily at 02:00, 5-field (the spelling an author writes in frontmatter).
const DAILY_2AM: &str = "0 2 * * *";
/// Hourly on the hour.
const HOURLY: &str = "0 * * * *";
/// Every minute — the pathological cadence the scan cap exists for.
const EVERY_MINUTE: &str = "* * * * *";

// =============================================================================
// next_slot_after — the primitive everything else is built on
// =============================================================================

#[test]
fn next_slot_is_strictly_after_the_anchor() {
    let anchor = utc(2026, 7, 30, 2, 0);
    let next = next_slot_after(DAILY_2AM, Tz::UTC, anchor).unwrap().unwrap();
    assert_eq!(
        next,
        utc(2026, 7, 31, 2, 0),
        "anchoring ON a slot must yield the NEXT one, not the same one again — \
         otherwise the catch-up walk never terminates"
    );
}

#[test]
fn five_field_cron_is_normalized_like_the_job_scheduler() {
    // Reuses `crate::scheduler::normalize_cron`, so a 5-field frontmatter cron
    // works without the author knowing about the seconds-padding contract
    // (NAN-1104).
    let five = next_slot_after("0 2 * * *", Tz::UTC, utc(2026, 7, 30, 1, 0)).unwrap();
    let six = next_slot_after("0 0 2 * * *", Tz::UTC, utc(2026, 7, 30, 1, 0)).unwrap();
    assert_eq!(five, six);
    assert_eq!(five.unwrap(), utc(2026, 7, 30, 2, 0));
}

#[test]
fn unparseable_cron_is_a_validation_error_not_a_panic() {
    let error = next_slot_after("not a cron", Tz::UTC, Utc::now()).unwrap_err();
    assert!(matches!(error, HuntError::Validation(_)));
}

#[test]
fn timezone_is_wall_clock_not_utc() {
    // 02:00 America/New_York in July is 06:00 UTC (EDT, UTC-4).
    let next = next_slot_after(DAILY_2AM, ny(), utc(2026, 7, 30, 0, 0))
        .unwrap()
        .unwrap();
    assert_eq!(next, utc(2026, 7, 30, 6, 0));
}

#[test]
fn unknown_timezone_falls_back_to_utc_rather_than_disabling_the_hunt() {
    assert_eq!(resolve_timezone("Mars/Olympus_Mons"), Tz::UTC);
    assert_eq!(resolve_timezone(""), Tz::UTC);
    assert_eq!(resolve_timezone("  UTC "), Tz::UTC);
    assert_eq!(resolve_timezone("America/New_York"), ny());
}

// =============================================================================
// Daylight saving — the two decisions, pinned
// =============================================================================

#[test]
fn spring_forward_skips_the_nonexistent_slot() {
    // 2026-03-08, America/New_York: 02:00 EST jumps to 03:00 EDT. A hunt on
    // "0 2 * * *" has no 02:00 that day.
    let before = utc(2026, 3, 7, 7, 0); // 2026-03-07 02:00 EST
    let next = next_slot_after(DAILY_2AM, ny(), before).unwrap().unwrap();

    // NOT 2026-03-08 anything: the next fire is 2026-03-09 02:00 EDT = 06:00Z.
    assert_eq!(
        next,
        utc(2026, 3, 9, 6, 0),
        "a 02:00 slot on the spring-forward day must be SKIPPED, not silently \
         relocated to 03:00 — see the DST section of the module docs"
    );

    // And nothing lands on 2026-03-08 at all.
    let local = next.with_timezone(&ny());
    assert_ne!(local.date_naive().day(), 8);
}

#[test]
fn fall_back_fires_once_at_the_earlier_occurrence() {
    // 2026-11-01, America/New_York: 02:00 EDT falls back to 01:00 EST, so
    // 01:30 local happens TWICE — 05:30Z (EDT) and 06:30Z (EST).
    let cron = "30 1 * * *";
    let before = utc(2026, 10, 31, 5, 30); // 2026-10-31 01:30 EDT

    let first = next_slot_after(cron, ny(), before).unwrap().unwrap();
    assert_eq!(
        first,
        utc(2026, 11, 1, 5, 30),
        "the ambiguous slot must resolve to the EARLIER (pre-transition) instant"
    );

    // The decisive assertion: walking on from the slot we just issued must NOT
    // return the second occurrence of the same wall-clock time. A duplicate
    // 01:30 sweep an hour later is a real cost paid for nothing.
    let second = next_slot_after(cron, ny(), first).unwrap().unwrap();
    assert_ne!(
        second,
        utc(2026, 11, 1, 6, 30),
        "the repeated wall-clock hour must NOT produce a second sweep"
    );
    assert_eq!(second, utc(2026, 11, 2, 6, 30), "next fire is the next day");
}

#[test]
fn fall_back_day_yields_exactly_one_slot_when_walked_through() {
    // Walk the whole DST night the way the catch-up planner does and count how
    // many slots land inside the repeated hour.
    let cron = "30 1 * * *";
    let mut cursor = utc(2026, 10, 31, 12, 0);
    let stop = utc(2026, 11, 2, 12, 0);
    let mut slots = Vec::new();
    while let Some(next) = next_slot_after(cron, ny(), cursor).unwrap() {
        if next > stop {
            break;
        }
        slots.push(next);
        cursor = next;
    }
    assert_eq!(
        slots,
        vec![utc(2026, 11, 1, 5, 30), utc(2026, 11, 2, 6, 30)],
        "one slot per calendar day across the fall-back boundary — never two"
    );
}

#[test]
fn spring_forward_day_contributes_no_slot_when_walked_through() {
    let mut cursor = utc(2026, 3, 6, 12, 0);
    let stop = utc(2026, 3, 10, 12, 0);
    let mut slots = Vec::new();
    while let Some(next) = next_slot_after(DAILY_2AM, ny(), cursor).unwrap() {
        if next > stop {
            break;
        }
        slots.push(next);
        cursor = next;
    }
    // 03-07 02:00 EST = 07:00Z, then 03-08 is skipped entirely, then
    // 03-09 02:00 EDT = 06:00Z, 03-10 02:00 EDT = 06:00Z.
    assert_eq!(
        slots,
        vec![
            utc(2026, 3, 7, 7, 0),
            utc(2026, 3, 9, 6, 0),
            utc(2026, 3, 10, 6, 0),
        ]
    );
}

#[test]
fn hourly_hunt_does_not_run_twice_in_the_repeated_hour() {
    // An hourly hunt has a slot inside the repeated hour by construction. It
    // must still produce one slot per wall-clock hour, not two.
    let mut cursor = utc(2026, 11, 1, 4, 0); // 00:00 EDT
    let stop = utc(2026, 11, 1, 8, 0); // 03:00 EST
    let mut slots = Vec::new();
    while let Some(next) = next_slot_after(HOURLY, ny(), cursor).unwrap() {
        if next > stop {
            break;
        }
        slots.push(next);
        cursor = next;
    }
    // Real-time hours 04:00Z..08:00Z span five wall-clock labels (01,01,02,03)
    // but the repeated 01:00 must appear once.
    let labels: Vec<u32> = slots
        .iter()
        .map(|s| s.with_timezone(&ny()).hour())
        .collect();
    let mut deduped = labels.clone();
    deduped.dedup();
    assert_eq!(
        labels, deduped,
        "no wall-clock hour may be scheduled twice across the fall-back transition; got {labels:?}"
    );
}

// =============================================================================
// plan_slots — seeding and the ordinary case
// =============================================================================

#[test]
fn an_unseeded_hunt_is_seeded_and_issues_nothing() {
    let now = utc(2026, 7, 30, 10, 0);
    let plan = plan_slots(DAILY_2AM, Tz::UTC, None, now).unwrap();
    assert_eq!(
        plan,
        SlotPlan::Seed {
            next_due: utc(2026, 7, 31, 2, 0)
        },
        "enabling a daily-at-02:00 hunt at 10:00 must not instantly fire an \
         02:00 sweep — the toggle means 'start on this cadence', not 'hunt now'"
    );
}

#[test]
fn a_future_watermark_is_not_due() {
    let now = utc(2026, 7, 30, 10, 0);
    let plan = plan_slots(DAILY_2AM, Tz::UTC, Some(utc(2026, 7, 31, 2, 0)), now).unwrap();
    assert_eq!(plan, SlotPlan::NotDue);
}

#[test]
fn an_on_time_slot_issues_one_sweep_with_no_coalescing() {
    let slot = utc(2026, 7, 30, 2, 0);
    let now = slot + Duration::seconds(30);
    let SlotPlan::Issue(issue) = plan_slots(DAILY_2AM, Tz::UTC, Some(slot), now).unwrap() else {
        panic!("expected an issue");
    };
    assert_eq!(issue.slot, slot);
    assert_eq!(issue.trigger, SlotTrigger::Schedule);
    assert_eq!(issue.skipped, 0);
    assert_eq!(
        issue.coalesced_through, None,
        "nothing was skipped, so the coalescing watermark must not move — a \
         watermark that mirrors next_due_slot records nothing"
    );
    assert_eq!(issue.next_due, Some(utc(2026, 7, 31, 2, 0)));
    assert!(!issue.scan_truncated);
}

#[test]
fn a_slot_exactly_at_now_is_due() {
    let slot = utc(2026, 7, 30, 2, 0);
    let SlotPlan::Issue(issue) = plan_slots(DAILY_2AM, Tz::UTC, Some(slot), slot).unwrap() else {
        panic!("a slot whose instant has arrived is due");
    };
    assert_eq!(issue.slot, slot);
}

#[test]
fn an_impossible_cron_never_comes_due() {
    // 30 February.
    assert_eq!(
        plan_slots("0 0 0 30 2 *", Tz::UTC, None, utc(2026, 7, 30, 10, 0)).unwrap(),
        SlotPlan::Never
    );
}

// =============================================================================
// Catch-up coalescing — the arithmetic that must not be silently wrong
// =============================================================================

#[test]
fn a_week_of_missed_daily_slots_collapses_to_one_sweep() {
    // The headline case. A laptop shut on the 23rd, opened on the 30th.
    let watermark = utc(2026, 7, 23, 2, 0);
    let now = utc(2026, 7, 30, 9, 15);

    let SlotPlan::Issue(issue) = plan_slots(DAILY_2AM, Tz::UTC, Some(watermark), now).unwrap()
    else {
        panic!("expected an issue");
    };

    // Due slots in [23rd 02:00 .. 30th 09:15] are the 23rd..30th inclusive = 8.
    // ONE sweep is issued, for the LATEST.
    assert_eq!(issue.slot, utc(2026, 7, 30, 2, 0), "issue the latest due slot");
    assert_eq!(issue.trigger, SlotTrigger::Catchup);
    assert_eq!(
        issue.skipped, 7,
        "seven earlier slots (23rd..29th) are collapsed into it"
    );
    assert_eq!(
        issue.coalesced_through,
        Some(utc(2026, 7, 29, 2, 0)),
        "the watermark advances PAST every skipped slot — the newest one \
         declined is the 29th, immediately before the slot we run"
    );
    assert_eq!(issue.next_due, Some(utc(2026, 7, 31, 2, 0)));
    assert!(!issue.scan_truncated);
}

#[test]
fn a_week_of_missed_hourly_slots_also_collapses_to_one() {
    let watermark = utc(2026, 7, 23, 0, 0);
    let now = utc(2026, 7, 30, 0, 0);
    let SlotPlan::Issue(issue) = plan_slots(HOURLY, Tz::UTC, Some(watermark), now).unwrap() else {
        panic!("expected an issue");
    };
    assert_eq!(issue.slot, now);
    // 07-23 00:00 .. 07-30 00:00 is 168 hours, so 169 slots INCLUSIVE of both
    // endpoints: one issued, 168 collapsed. (The off-by-one here is exactly the
    // kind of silent wrongness this file exists to catch — the first draft of
    // this assertion said 167.)
    assert_eq!(issue.skipped, 168);
    assert_eq!(issue.coalesced_through, Some(utc(2026, 7, 29, 23, 0)));
    assert_eq!(issue.next_due, Some(utc(2026, 7, 30, 1, 0)));
    assert!(!issue.scan_truncated);
}

#[test]
fn the_collapse_is_idempotent_across_ticks() {
    // Replay the loop the way the scheduler runs it: plan, apply the watermark
    // it returned, plan again. The second tick must have nothing to do.
    let mut watermark = Some(utc(2026, 7, 23, 2, 0));
    let now = utc(2026, 7, 30, 9, 15);

    let SlotPlan::Issue(first) = plan_slots(DAILY_2AM, Tz::UTC, watermark, now).unwrap() else {
        panic!("expected an issue");
    };
    watermark = first.next_due;

    assert_eq!(
        plan_slots(DAILY_2AM, Tz::UTC, watermark, now).unwrap(),
        SlotPlan::NotDue,
        "after the collapse the backlog is GONE — a second tick at the same \
         instant must not issue a second sweep"
    );
}

#[test]
fn catching_up_one_slot_at_a_time_never_double_issues() {
    // Drive the planner minute by minute across a two-day outage and assert the
    // total number of sweeps issued.
    let mut watermark = Some(utc(2026, 7, 28, 2, 0));
    let mut issued = Vec::new();
    let mut collapsed = 0u32;
    let mut clock = utc(2026, 7, 30, 9, 0);

    for _ in 0..120 {
        match plan_slots(DAILY_2AM, Tz::UTC, watermark, clock).unwrap() {
            SlotPlan::Issue(issue) => {
                issued.push(issue.slot);
                collapsed += issue.skipped;
                watermark = issue.next_due;
            }
            SlotPlan::NotDue => {}
            other => panic!("unexpected plan {other:?}"),
        }
        clock += Duration::minutes(1);
    }

    assert_eq!(
        issued,
        vec![utc(2026, 7, 30, 2, 0)],
        "a two-day backlog resolves in exactly one sweep no matter how often \
         the loop ticks"
    );
    assert_eq!(collapsed, 2, "28th and 29th collapsed into the 30th");
}

#[test]
fn the_scan_cap_truncates_but_still_converges() {
    // A per-minute hunt offline long enough to blow the scan cap. The planner
    // must not walk forever, and must leave a watermark that makes progress.
    let watermark = Some(utc(2026, 7, 1, 0, 0));
    let now = utc(2026, 7, 30, 0, 0); // 29 days = 41,760 minute slots

    let SlotPlan::Issue(issue) = plan_slots(EVERY_MINUTE, Tz::UTC, watermark, now).unwrap() else {
        panic!("expected an issue");
    };
    assert!(issue.scan_truncated, "the cap must be reported, not hidden");
    assert_eq!(issue.skipped, MAX_SLOT_SCAN);
    assert_eq!(
        issue.slot,
        utc(2026, 7, 1, 0, 0) + Duration::minutes(i64::from(MAX_SLOT_SCAN)),
        "the truncated walk issues the slot it reached"
    );
    assert!(
        issue.next_due.unwrap() > issue.slot,
        "the watermark must move forward or the next tick repeats this one"
    );

    // Converges: each tick collapses another MAX_SLOT_SCAN slots. In the real
    // scheduler the first sweep holds `uq_hunt_sweeps_in_flight`, so subsequent
    // ticks absorb rather than queue — this only checks the arithmetic ends.
    let mut watermark = issue.next_due;
    let mut ticks = 1;
    while let SlotPlan::Issue(next) = plan_slots(EVERY_MINUTE, Tz::UTC, watermark, now).unwrap() {
        watermark = next.next_due;
        ticks += 1;
        assert!(ticks < 100, "catch-up must terminate");
    }
    assert!(ticks > 1, "this case is supposed to need more than one pass");
    assert_eq!(
        plan_slots(EVERY_MINUTE, Tz::UTC, watermark, now).unwrap(),
        SlotPlan::NotDue
    );
}

#[test]
fn a_dst_spanning_outage_collapses_without_double_counting() {
    // Offline across the fall-back transition: the repeated wall-clock hour
    // must not inflate the skipped count or produce two sweeps.
    let watermark = Some(utc(2026, 10, 30, 6, 0)); // 02:00 EDT on the 30th
    let now = utc(2026, 11, 3, 7, 0); // 02:00 EST on the 3rd

    let SlotPlan::Issue(issue) = plan_slots(DAILY_2AM, ny(), watermark, now).unwrap() else {
        panic!("expected an issue");
    };
    // Slots: 10-30, 10-31, 11-01, 11-02, 11-03 → 5 due, 4 skipped, 1 issued.
    assert_eq!(issue.slot, utc(2026, 11, 3, 7, 0));
    assert_eq!(issue.skipped, 4);
    assert_eq!(issue.coalesced_through, Some(utc(2026, 11, 2, 7, 0)));
}

#[test]
fn a_dst_spanning_outage_across_spring_forward_loses_the_missing_day() {
    // The mirror case: 02:00 does not exist on 2026-03-08, so a four-day
    // outage yields one fewer slot. The count must reflect that rather than
    // pretending a run happened.
    let watermark = Some(utc(2026, 3, 6, 7, 0)); // 02:00 EST on the 6th
    let now = utc(2026, 3, 10, 6, 0); // 02:00 EDT on the 10th

    let SlotPlan::Issue(issue) = plan_slots(DAILY_2AM, ny(), watermark, now).unwrap() else {
        panic!("expected an issue");
    };
    // Slots: 03-06, 03-07, (03-08 does not exist), 03-09, 03-10 → 4 due.
    assert_eq!(issue.slot, utc(2026, 3, 10, 6, 0));
    assert_eq!(
        issue.skipped, 3,
        "the nonexistent 03-08 slot is not counted as skipped because it never existed"
    );
    assert_eq!(issue.coalesced_through, Some(utc(2026, 3, 9, 6, 0)));
}

// =============================================================================
// Window sizing — where max_catchup_lookback earns its keep
// =============================================================================

#[test]
fn an_on_time_sweep_gets_exactly_its_lookback() {
    let now = utc(2026, 7, 30, 2, 0);
    let window = sweep_window(now, Duration::hours(24), Duration::hours(72), now);
    assert_eq!(window.start, now - Duration::hours(24));
    assert_eq!(window.end, now);
    assert_eq!(window.shortfall(), Duration::zero());
}

#[test]
fn a_week_long_outage_is_capped_by_max_catchup_lookback() {
    let oldest_due = utc(2026, 7, 23, 2, 0);
    let now = utc(2026, 7, 30, 9, 0);
    let window = sweep_window(oldest_due, Duration::hours(24), Duration::hours(72), now);

    assert_eq!(
        window.granted,
        Duration::hours(72),
        "a laptop that slept for a week must not wake into a 7-day scan"
    );
    assert_eq!(window.start, now - Duration::hours(72));
    assert!(
        window.shortfall() > Duration::days(5),
        "the coverage the cap threw away must be reported, not hidden: {:?}",
        window.shortfall()
    );
}

#[test]
fn the_catch_up_window_reaches_back_to_the_first_missed_slot() {
    // A short outage inside the cap gets FULL coverage: from the first missed
    // slot minus the hunt's own lookback, so nothing between the last sweep and
    // this one is silently skipped.
    let oldest_due = utc(2026, 7, 30, 2, 0);
    let now = utc(2026, 7, 30, 14, 0);
    let window = sweep_window(oldest_due, Duration::hours(6), Duration::hours(72), now);
    assert_eq!(window.start, utc(2026, 7, 29, 20, 0));
    assert_eq!(window.granted, Duration::hours(18));
    assert_eq!(window.shortfall(), Duration::zero());
}

#[test]
fn a_max_catchup_smaller_than_the_lookback_never_narrows_an_ordinary_sweep() {
    // Misconfiguration: max_catchup_lookback (1h) < lookback_window (24h).
    // Honouring it literally would make every sweep narrower than the hunt asked.
    let now = utc(2026, 7, 30, 2, 0);
    let window = sweep_window(now, Duration::hours(24), Duration::hours(1), now);
    assert_eq!(window.granted, Duration::hours(24));
}

#[test]
fn the_window_always_ends_at_now_not_at_the_slot() {
    // A window ending at a slot in the past excludes everything that arrived
    // since — on a catch-up that is most of the interesting data.
    let slot = utc(2026, 7, 23, 2, 0);
    let now = utc(2026, 7, 30, 9, 0);
    let window = sweep_window(slot, Duration::hours(24), Duration::hours(72), now);
    assert_eq!(window.end, now);
}

#[test]
fn window_sizing_uses_the_hunt_configured_strings() {
    // The scheduler reads `lookback_window` / `max_catchup_lookback` as the
    // free-text values the schema stores, through the same parser the manual
    // trigger uses — so a hunt cannot get one window when swept manually and a
    // different one when swept on a schedule.
    assert_eq!(parse_lookback("24h"), Duration::hours(24));
    assert_eq!(parse_lookback("72h"), Duration::hours(72));
    assert_eq!(parse_lookback("7d"), Duration::days(7));
    // Garbage falls back to the schema default rather than erroring.
    assert_eq!(parse_lookback("nonsense"), Duration::hours(24));
}

// =============================================================================
// Configuration
// =============================================================================

#[test]
fn scheduled_cadence_is_on_by_default_and_switchable_off() {
    let defaults = HuntSchedulerConfig::default();
    assert!(defaults.enabled);
    assert_eq!(defaults.poll_interval_secs, DEFAULT_POLL_INTERVAL_SECS);
    assert_eq!(defaults.reclaim_grace_secs, DEFAULT_RECLAIM_GRACE_SECS);
}

#[test]
fn disabled_cadence_still_reclaims_expired_manual_sweeps() {
    // `enabled` is the cadence switch, not a lease-hygiene switch. Pin the
    // ordering so a future early return cannot leave manual-only deployments
    // with sweeps that say `leased` forever.
    let source = include_str!("scheduler.rs");
    let start = source.find("pub async fn tick(").unwrap();
    let end = source[start..].find("async fn process_hunt(").unwrap() + start;
    let tick = &source[start..end];
    let reclaim = tick.find("reclaim_expired_leases").unwrap();
    let cadence_gate = tick.find("if !self.config.enabled").unwrap();
    let due_hunts = tick.find("load_due_hunts").unwrap();
    assert!(reclaim < cadence_gate);
    assert!(cadence_gate < due_hunts);
}

#[test]
fn a_typo_in_the_enable_flag_keeps_the_default_rather_than_disabling() {
    // `HUNT_SCHEDULER_ENABLED=ture` must not quietly stop every hunt.
    // Scoped to a unique key so parallel tests cannot race the process env.
    let key = "NAN2238_TEST_FLAG_TYPO";
    std::env::set_var(key, "ture");
    assert!(env_flag(key, true));
    assert!(!env_flag(key, false));
    std::env::set_var(key, "off");
    assert!(!env_flag(key, true));
    std::env::set_var(key, "1");
    assert!(env_flag(key, false));
    std::env::remove_var(key);
}

#[test]
fn slot_trigger_values_match_the_schema_check() {
    // `hunt_sweeps_trigger_check` allows exactly schedule | manual | catchup.
    assert_eq!(SlotTrigger::Schedule.as_str(), "schedule");
    assert_eq!(SlotTrigger::Catchup.as_str(), "catchup");
}

#[tokio::test]
async fn a_cancelled_scheduler_stops_without_touching_postgres() {
    use sqlx::postgres::PgPoolOptions;

    // Port 9 is discard: any query would hang or fail. The loop must observe
    // cancellation first.
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:9/nanosiem")
        .unwrap();
    let scheduler = HuntScheduler::with_config(
        pool,
        HuntSchedulerConfig {
            enabled: false,
            ..HuntSchedulerConfig::default()
        },
    );
    let shutdown = ShutdownToken::new();
    shutdown.cancel();

    tokio::time::timeout(std::time::Duration::from_secs(2), scheduler.start(shutdown))
        .await
        .expect("a cancelled scheduler must return immediately")
        .expect("the task must not panic");
}

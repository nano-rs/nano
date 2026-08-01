// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — the hunt scheduler: the thing that actually reads the cron
//! columns.
//!
//! Migration 9000054 gave `hunt_specs` a full set of scheduling columns and
//! [`super::repository`] writes them, but until this module existed nothing
//! polled them: the only path to a sweep was the manual trigger. A `schedule:`
//! in frontmatter was recorded, rendered, and never honoured.
//!
//! # What "coalescing" means and why it is here rather than in an index
//!
//! The runner is a workstation. It sleeps, it travels, it gets shut for a week.
//! The interesting question is therefore not "how do we fire on time" but "what
//! happens when we could not".
//!
//! `uq_hunt_sweeps_slot` is UNIQUE on `(playbook_id, schedule_slot)`, which
//! dedupes an EXACT slot and nothing more. A week of missed hourly slots is 168
//! *distinct* slots, so that index would happily admit all 168 rows;
//! `uq_hunt_sweeps_in_flight` would then merely serialise them into a week-long
//! queue that a returning laptop grinds through. Both indexes are doing their
//! jobs — neither of them is a backlog collapser.
//!
//! Collapsing is arithmetic, and it lives here: on catch-up the scheduler
//! issues **exactly one** sweep, for the LATEST due slot, and advances
//! `hunt_specs.coalesced_through_slot` past every slot it declined to issue.
//! The watermark is what makes the collapse auditable — the skipped slots are
//! recorded as skipped rather than silently forgotten, so the UI can say "12
//! slots collapsed into this sweep" instead of implying the cadence was kept.
//!
//! There is a second, independent collapser that falls out of the schema: if a
//! sweep is already in flight for the hunt, the INSERT trips
//! `uq_hunt_sweeps_in_flight` and we absorb the due slot into the running sweep
//! instead — advancing the watermark, not queueing a second sweep. That is what
//! bounds the pathological cases (a per-minute cron, a scan that hit its cap, a
//! runner that never comes back) to one outstanding sweep per hunt, always.
//!
//! # Honest state
//!
//! The scheduler never writes anything that implies a schedule was KEPT.
//!
//! * `next_due_slot` is the next slot we intend to issue — a plan, not a promise.
//! * `coalesced_through_slot` is the newest slot we deliberately did not run.
//! * `last_attempt_at` moves only when an attempt CONCLUDES — a committed
//!   report ([`super::repository::HuntRepository::commit_sweep_report`]) or a
//!   lease we reclaimed here. Issuing a sweep is not an attempt: a queued sweep
//!   nobody claimed must keep reading as "never swept", which is what
//!   `summary_counts` renders from `last_attempt_at IS NULL`.
//! * `last_success_at` is never written here at all. A sweep the scheduler had
//!   to abandon is the opposite of a success, and on exactly those hunts an
//!   operator most needs "last successful sweep" to be true.
//!
//! # Daylight saving
//!
//! `schedule_cron` is WALL-CLOCK in `hunt_specs.schedule_timezone`, so twice a
//! year a slot is either impossible or duplicated. Both cases are decided here,
//! deliberately, and pinned by tests in `scheduler_tests.rs`:
//!
//! **Spring forward — the slot is SKIPPED.** On the US spring-forward day
//! 02:30 America/New_York does not exist; `TimeZone::with_ymd_and_hms` returns
//! [`chrono::LocalResult::None`] and the slot search moves to the next candidate,
//! which is the following day. We do NOT synthesise a 03:30 run. A hunt is a
//! sample of a rolling window, not a transaction that must post exactly once —
//! the next sweep's lookback covers the gap, and inventing a run at a wall-clock
//! time the operator never wrote is a worse lie than a documented skip.
//!
//! **Fall back — the slot fires ONCE, at the first occurrence.** On the
//! fall-back day 01:30 America/New_York happens twice, an hour apart in real
//! time; `with_ymd_and_hms` returns [`chrono::LocalResult::Ambiguous`]. We take
//! the EARLIER (pre-transition) instant and then advance the watermark past that
//! wall-clock time, so the repeat is never issued. A duplicate sweep is a real
//! cost — agent turns, tool calls, a second lead set over an overlapping window
//! — paid for nothing, since the two occurrences carry identical intent.
//!
//! Note the asymmetry is only apparent: in both cases the rule is *one sweep per
//! wall-clock slot the operator wrote, or none*. Never two.
//!
//! # Held hunts
//!
//! A hunt whose required source is unhealthy must be HELD rather than run
//! partial. The scheduler does NOT make that call, and the reason is that it
//! cannot make it cheaply or honestly: source health is measured from the log
//! store (ClickHouse), and this module holds a `PgPool` only —
//! `hunt_specs.required_source_types` next to `log_sources` tells you whether a
//! source is *configured*, which is a different question from whether it is
//! *flowing*. Issuing on a stale PG proxy and stamping `outcome = 'held'` would
//! be a fabricated diagnosis. The runner measures health at sweep time and
//! reports `held` through the normal report path, where the measurement is real.

use chrono::{DateTime, Duration, Utc};
use chrono_tz::Tz;
use sqlx::{PgPool, Row};
use std::str::FromStr;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::error::HuntError;
use super::service::parse_lookback;
use crate::scheduler::normalize_cron;
use crate::shutdown::ShutdownToken;

/// How many slots a single tick will walk forward per hunt.
///
/// The walk is pure CPU (one `cron` evaluation per step), so the cap exists to
/// bound a pathological definition rather than a realistic one: 5,000 steps
/// covers a 3.5-day outage of a per-minute hunt, 200 days of an hourly one, and
/// 13 years of a daily one. When a walk is truncated the scheduler issues the
/// slot it reached and leaves the rest for the next tick — and because the sweep
/// it just issued holds `uq_hunt_sweeps_in_flight`, those later ticks absorb
/// their slots into it instead of queueing more. A truncated scan therefore
/// still converges on ONE sweep.
pub const MAX_SLOT_SCAN: u32 = 5_000;

/// Poll cadence. A hunt cron has minute resolution at best, so a minute tick is
/// as often as it can possibly matter.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// How many due hunts one tick will consider.
pub const DEFAULT_BATCH_SIZE: i64 = 200;

/// How long past `lease_expires_at` a sweep is left alone before the scheduler
/// takes it away from its runner.
///
/// Not zero, and not for politeness: [`super::repository::HuntRepository::claim_next_sweep`]
/// already re-claims expired leases, so a runner that is merely slow to poll
/// gets to pick its own work back up and FINISH it. Reclaiming instantly would
/// win that race and convert recoverable sweeps into abandoned ones. The
/// scheduler is the backstop for the case no runner is coming.
pub const DEFAULT_RECLAIM_GRACE_SECS: i64 = 300;

/// How many expired leases one tick will reclaim.
pub const DEFAULT_RECLAIM_BATCH: i64 = 200;

/// Outcome recorded on a sweep the scheduler took away from a dead runner.
///
/// `hunt_sweeps_outcome_check` has no `abandoned` value — `abandoned` is a
/// STATUS. The outcome says why it ended, and a lease that ran out with no
/// report is an error, distinct from `cancelled` (which archiving uses for a
/// sweep a human deliberately stopped).
const RECLAIM_OUTCOME: &str = "error";

// =============================================================================
// Configuration
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HuntSchedulerConfig {
    /// Master switch. `HUNT_SCHEDULER_ENABLED=false` leaves hunts manual-only
    /// without having to disable each one.
    pub enabled: bool,
    pub poll_interval_secs: u64,
    pub batch_size: i64,
    pub reclaim_grace_secs: i64,
    pub reclaim_batch: i64,
}

impl Default for HuntSchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            batch_size: DEFAULT_BATCH_SIZE,
            reclaim_grace_secs: DEFAULT_RECLAIM_GRACE_SECS,
            reclaim_batch: DEFAULT_RECLAIM_BATCH,
        }
    }
}

impl HuntSchedulerConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            enabled: env_flag("HUNT_SCHEDULER_ENABLED", defaults.enabled),
            poll_interval_secs: env_parse("HUNT_SCHEDULER_POLL_INTERVAL_SECS", defaults.poll_interval_secs)
                .clamp(5, 3_600),
            batch_size: env_parse("HUNT_SCHEDULER_BATCH_SIZE", defaults.batch_size).clamp(1, 10_000),
            reclaim_grace_secs: env_parse(
                "HUNT_SCHEDULER_RECLAIM_GRACE_SECS",
                defaults.reclaim_grace_secs,
            )
            .clamp(0, 86_400),
            reclaim_batch: env_parse("HUNT_SCHEDULER_RECLAIM_BATCH", defaults.reclaim_batch)
                .clamp(1, 10_000),
        }
    }
}

fn env_parse<T: FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(default)
}

/// Parse a boolean switch. Anything unrecognised keeps the default rather than
/// silently reading as `false` — a typo'd `HUNT_SCHEDULER_ENABLED=ture` must not
/// quietly turn scheduling off.
pub fn env_flag(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            other => {
                warn!(key, value = other, default, "Unrecognised boolean; keeping default");
                default
            }
        },
        Err(_) => default,
    }
}

// =============================================================================
// Slot arithmetic — pure, and where all the interesting bugs would live
// =============================================================================

/// Which `hunt_sweeps.trigger` value an issued slot carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotTrigger {
    /// The slot came due and we issued it on its own.
    Schedule,
    /// Earlier slots were collapsed into this one.
    Catchup,
}

impl SlotTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            SlotTrigger::Schedule => "schedule",
            SlotTrigger::Catchup => "catchup",
        }
    }
}

/// One slot the scheduler intends to issue, plus everything the watermark write
/// needs to stay honest about what was collapsed to get here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotIssue {
    /// The slot the sweep is stamped with: the LATEST due slot, never the oldest.
    pub slot: DateTime<Utc>,
    pub trigger: SlotTrigger,
    /// The oldest slot that came due in this backlog. Only used to size the
    /// sweep window — the sweep is stamped with [`Self::slot`].
    pub oldest_due: DateTime<Utc>,
    /// New value for `hunt_specs.coalesced_through_slot`: the newest slot we
    /// declined to issue. `None` on an on-time slot, where nothing was skipped.
    pub coalesced_through: Option<DateTime<Utc>>,
    /// How many slots were collapsed into [`Self::slot`].
    pub skipped: u32,
    /// The walk hit [`MAX_SLOT_SCAN`]; `skipped` is a floor, not a count.
    pub scan_truncated: bool,
    /// New value for `hunt_specs.next_due_slot`. `None` when the cron has no
    /// further occurrence at all.
    pub next_due: Option<DateTime<Utc>>,
}

/// What a tick decided to do with one hunt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotPlan {
    /// A slot is materialized and has not come due.
    NotDue,
    /// The watermark is unset — a freshly enabled, freshly imported, or
    /// freshly re-pointed hunt. Materialize it and issue NOTHING.
    ///
    /// Enabling a daily-at-02:00 hunt at 10:00 must not instantly fire an 02:00
    /// sweep. The switch means "start hunting on this cadence", not "hunt now";
    /// the manual trigger is right there for "hunt now", and it is a separate,
    /// visible act.
    Seed { next_due: DateTime<Utc> },
    /// Issue one sweep.
    Issue(SlotIssue),
    /// The cron parses but has no future occurrence (`0 0 0 30 2 *`). Nothing
    /// will ever come due; the watermark is cleared so the poll stops
    /// re-examining it every tick.
    Never,
}

/// Resolve a `hunt_specs.schedule_timezone` value.
///
/// An unknown zone falls back to UTC rather than erroring, on the same
/// principle as [`parse_lookback`]: a typo in a text column must not make a hunt
/// permanently unrunnable. It is logged, and UTC is the schema default, so the
/// fallback is what an operator who never set one would have got.
pub fn resolve_timezone(raw: &str) -> Tz {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Tz::UTC;
    }
    match Tz::from_str(trimmed) {
        Ok(tz) => tz,
        Err(_) => {
            warn!(
                timezone = trimmed,
                "Unknown hunt schedule timezone; falling back to UTC"
            );
            Tz::UTC
        }
    }
}

/// The next wall-clock slot strictly after `after`, in `tz`.
///
/// Two DST decisions are implemented here (see the module docs):
///
/// * A **nonexistent** local time (spring forward) is skipped by the `cron`
///   crate itself — `with_ymd_and_hms` returns `LocalResult::None` and it moves
///   to the next candidate.
/// * An **ambiguous** local time (fall back) resolves to the EARLIER instant,
///   because a freshly-constructed `ScheduleIterator` yields the earlier half of
///   `LocalResult::Ambiguous` first and we take exactly one item. Relying on
///   that is subtle, so [`next_slot_after`] additionally enforces strict
///   monotonicity below: if the search returns something at or before `after`
///   (which is what a second visit to an ambiguous wall-clock time looks like),
///   the anchor is nudged forward a second and the search retried. That makes
///   "never the same wall-clock slot twice" an invariant of this function rather
///   than a property of the iterator we happen to be using.
pub fn next_slot_after(
    cron: &str,
    tz: Tz,
    after: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, HuntError> {
    let expression = normalize_cron(cron);
    let schedule = cron::Schedule::from_str(&expression)
        .map_err(|e| HuntError::Validation(format!("invalid cron '{cron}': {e}")))?;

    let mut anchor = after;
    // Two passes at most: the first result, and one retry from a nudged anchor
    // if that result was not strictly after `after`.
    for _ in 0..2 {
        let local = anchor.with_timezone(&tz);
        let Some(next) = schedule.after(&local).next() else {
            return Ok(None);
        };
        let next_utc = next.with_timezone(&Utc);
        if next_utc > after {
            return Ok(Some(next_utc));
        }
        anchor = anchor + Duration::seconds(1);
    }
    Ok(None)
}

/// Decide what to do with one hunt, given its materialized watermark and the
/// current time. Pure — every catch-up test drives this directly.
pub fn plan_slots(
    cron: &str,
    tz: Tz,
    watermark: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<SlotPlan, HuntError> {
    let Some(watermark) = watermark else {
        // Unseeded. Materialize from NOW, not from the epoch: seeding from a
        // NULL watermark by walking history would open with a catch-up sweep
        // for a hunt that has never run, which is the "enabling it hunts now"
        // behaviour the toggle explicitly is not.
        return Ok(match next_slot_after(cron, tz, now)? {
            Some(next_due) => SlotPlan::Seed { next_due },
            None => SlotPlan::Never,
        });
    };

    if watermark > now {
        return Ok(SlotPlan::NotDue);
    }

    // `watermark` is itself a slot, and it is due. Walk forward to find the
    // LATEST slot that is also due; everything between the two is collapsed.
    let oldest_due = watermark;
    let mut latest = watermark;
    let mut previous: Option<DateTime<Utc>> = None;
    let mut skipped = 0u32;
    let mut scan_truncated = false;
    let next_due: Option<DateTime<Utc>>;

    loop {
        let candidate = next_slot_after(cron, tz, latest)?;
        match candidate {
            Some(slot) if slot <= now => {
                if skipped >= MAX_SLOT_SCAN {
                    // Stop collapsing here and issue what we reached. The next
                    // tick continues, and the sweep we are about to issue holds
                    // `uq_hunt_sweeps_in_flight`, so those ticks absorb rather
                    // than queue.
                    scan_truncated = true;
                    next_due = Some(slot);
                    break;
                }
                previous = Some(latest);
                latest = slot;
                skipped += 1;
            }
            other => {
                next_due = other;
                break;
            }
        }
    }

    let trigger = if skipped > 0 {
        SlotTrigger::Catchup
    } else {
        SlotTrigger::Schedule
    };

    Ok(SlotPlan::Issue(SlotIssue {
        slot: latest,
        trigger,
        oldest_due,
        // Only advanced when something was actually skipped. On an on-time slot
        // there is no backlog to record, and overwriting the column with the
        // slot we DID run would turn "newest slot deliberately not run" into a
        // duplicate of `next_due_slot` — a watermark that means nothing.
        coalesced_through: previous,
        skipped,
        scan_truncated,
        next_due,
    }))
}

/// The window a sweep opens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Span the backlog actually left uncovered, before capping.
    pub requested: Duration,
    /// Span the sweep will really read.
    pub granted: Duration,
}

impl SweepWindow {
    /// Coverage the cap threw away. Non-zero means the sweep is knowingly
    /// looking at less than the outage left behind — the UI must say so rather
    /// than render a clean catch-up.
    pub fn shortfall(&self) -> Duration {
        let shortfall = self.requested - self.granted;
        if shortfall > Duration::zero() {
            shortfall
        } else {
            Duration::zero()
        }
    }
}

/// Size the window for an issued slot.
///
/// The end is `now`, not the slot: a window ending at a slot in the past would
/// exclude everything that arrived since, which on a catch-up is most of the
/// interesting data.
///
/// The start reaches back to `oldest_due - lookback` — the hunt's own lookback,
/// anchored at the FIRST slot the backlog left unrun, so a caught-up sweep
/// covers the outage rather than only the last `lookback` of it. That is
/// unbounded by construction, which is exactly what `max_catchup_lookback`
/// exists to stop: a laptop shut for a week must not wake into a 7-day scan.
/// The cap wins, and the shortfall is reported rather than hidden.
pub fn sweep_window(
    oldest_due: DateTime<Utc>,
    lookback: Duration,
    max_catchup: Duration,
    now: DateTime<Utc>,
) -> SweepWindow {
    let end = now;
    let requested = (end - (oldest_due - lookback)).max(lookback);
    // Never shrink below the hunt's own lookback: a `max_catchup_lookback`
    // configured smaller than `lookback_window` is a misconfiguration, and
    // honouring it literally would make every ordinary on-time sweep narrower
    // than the hunt asked for.
    let granted = requested.min(max_catchup.max(lookback));
    SweepWindow {
        start: end - granted,
        end,
        requested,
        granted,
    }
}

// =============================================================================
// The scheduler
// =============================================================================

/// A hunt the poll found due (or unseeded).
#[derive(Debug, Clone)]
struct DueHunt {
    playbook_id: Uuid,
    title: String,
    playbook_version: i32,
    schedule_cron: String,
    schedule_timezone: String,
    lookback_window: String,
    max_catchup_lookback: String,
    next_due_slot: Option<DateTime<Utc>>,
}

/// What happened to one issuance attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IssueOutcome {
    Issued(Uuid),
    /// A sweep is already in flight for this hunt; the due slots were absorbed
    /// into it and the watermark still advanced.
    AbsorbedInFlight,
    /// This exact slot already has a row. Idempotent replay; advance anyway.
    SlotAlreadyIssued,
    /// The watermark moved under us between the read and the write. Another
    /// issuer (only possible without leader election) got there first.
    WatermarkMoved,
}

/// Per-tick counters. Returned so tests and operators can assert on the
/// collapse rather than infer it from logs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HuntSchedulerTick {
    pub examined: usize,
    pub seeded: usize,
    pub issued: usize,
    pub catchup_issued: usize,
    pub absorbed: usize,
    pub already_issued: usize,
    pub watermark_moved: usize,
    /// Slots deliberately not run, summed across hunts. The number that must be
    /// visible: it is the difference between "we caught up" and "we skipped a
    /// week".
    pub slots_collapsed: u64,
    pub reclaimed: usize,
    pub errors: usize,
}

/// Polls `hunt_specs` for due schedules, issues coalesced sweeps, and reclaims
/// leases from runners that died.
///
/// # Single issuer
///
/// Start this from `AppState::start_leader_schedulers` — leadership
/// ([`crate::leader::LeaderElection`]) is what stops N API replicas each issuing
/// the same slot. The watermark write is nevertheless guarded with
/// `next_due_slot IS NOT DISTINCT FROM <the value we planned against>` inside
/// the same transaction as the INSERT, so a second issuer racing this one loses
/// its transaction outright rather than double-advancing. Leadership is the
/// design; the guard is the proof.
#[derive(Clone)]
pub struct HuntScheduler {
    pool: PgPool,
    config: HuntSchedulerConfig,
}

impl HuntScheduler {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            config: HuntSchedulerConfig::default(),
        }
    }

    pub fn with_config(pool: PgPool, config: HuntSchedulerConfig) -> Self {
        Self { pool, config }
    }

    pub fn from_env(pool: PgPool) -> Self {
        Self::with_config(pool, HuntSchedulerConfig::from_env())
    }

    pub fn config(&self) -> &HuntSchedulerConfig {
        &self.config
    }

    /// Whether the hunt tables exist in this database.
    ///
    /// Migration 9000054 lives in `migrations/postgres-enterprise/`, so an open
    /// deployment has no `hunt_specs` at all. Probing once at start and exiting
    /// quietly beats logging a relation-does-not-exist error every minute
    /// forever — the loop has nothing to schedule either way, and a noisy
    /// health signal that is expected trains operators to ignore it.
    pub async fn tables_present(&self) -> Result<bool, HuntError> {
        let present: bool =
            sqlx::query_scalar("SELECT to_regclass('public.hunt_specs') IS NOT NULL")
                .fetch_one(&self.pool)
                .await?;
        Ok(present)
    }

    /// One full pass: reclaim dead leases, then issue due slots.
    ///
    /// Reclaim runs FIRST on purpose. A sweep stuck `leased` with an expired
    /// lease holds `uq_hunt_sweeps_in_flight`, so until it is cleared every due
    /// slot for that hunt is absorbed into a sweep that will never finish.
    /// Clearing first means the same tick can issue a real one.
    pub async fn tick(&self) -> Result<HuntSchedulerTick, HuntError> {
        let now = Utc::now();
        let mut tick = HuntSchedulerTick::default();

        // A reclaim failure must not cost the tick its issuance pass. They are
        // independent duties and a transient error on one is not a reason to
        // let every hunt drift another poll interval.
        match self.reclaim_expired_leases(now).await {
            Ok(reclaimed) => tick.reclaimed = reclaimed,
            Err(error) => {
                tick.errors += 1;
                warn!(%error, "Hunt lease reclamation failed; continuing with slot issuance");
            }
        }

        let due = self.load_due_hunts(now).await?;
        tick.examined = due.len();

        for hunt in due {
            if let Err(error) = self.process_hunt(&hunt, now, &mut tick).await {
                tick.errors += 1;
                warn!(
                    playbook_id = %hunt.playbook_id,
                    hunt = %hunt.title,
                    %error,
                    "Hunt schedule tick failed for one hunt"
                );
            }
        }

        Ok(tick)
    }

    async fn process_hunt(
        &self,
        hunt: &DueHunt,
        now: DateTime<Utc>,
        tick: &mut HuntSchedulerTick,
    ) -> Result<(), HuntError> {
        let tz = resolve_timezone(&hunt.schedule_timezone);
        let plan = match plan_slots(&hunt.schedule_cron, tz, hunt.next_due_slot, now) {
            Ok(plan) => plan,
            Err(error) => {
                // A cron that will not parse cannot be scheduled, but it must
                // not stall the tick either. Leave the watermark alone (so the
                // state stays visibly wrong rather than silently reset) and
                // move on.
                warn!(
                    playbook_id = %hunt.playbook_id,
                    hunt = %hunt.title,
                    cron = %hunt.schedule_cron,
                    %error,
                    "Hunt has an unparseable cron; it will not be scheduled"
                );
                return Ok(());
            }
        };

        match plan {
            SlotPlan::NotDue => Ok(()),
            SlotPlan::Never => {
                warn!(
                    playbook_id = %hunt.playbook_id,
                    hunt = %hunt.title,
                    cron = %hunt.schedule_cron,
                    "Hunt cron has no future occurrence; clearing next_due_slot"
                );
                self.write_watermark(hunt.playbook_id, None, None, hunt.next_due_slot)
                    .await?;
                Ok(())
            }
            SlotPlan::Seed { next_due } => {
                let updated = self
                    .write_watermark(
                        hunt.playbook_id,
                        Some(next_due),
                        None,
                        hunt.next_due_slot,
                    )
                    .await?;
                if updated {
                    tick.seeded += 1;
                    info!(
                        playbook_id = %hunt.playbook_id,
                        hunt = %hunt.title,
                        next_due = %next_due,
                        "Hunt schedule seeded"
                    );
                }
                Ok(())
            }
            SlotPlan::Issue(issue) => self.apply_issue(hunt, issue, now, tick).await,
        }
    }

    async fn apply_issue(
        &self,
        hunt: &DueHunt,
        issue: SlotIssue,
        now: DateTime<Utc>,
        tick: &mut HuntSchedulerTick,
    ) -> Result<(), HuntError> {
        let window = sweep_window(
            issue.oldest_due,
            parse_lookback(&hunt.lookback_window),
            parse_lookback(&hunt.max_catchup_lookback),
            now,
        );

        let outcome = self.issue_slot(hunt, &issue, &window).await?;

        // Only count a collapse that actually committed. A rolled-back
        // issuance collapsed nothing, and a counter that says otherwise is the
        // same lie as a watermark that says otherwise.
        if outcome != IssueOutcome::WatermarkMoved {
            tick.slots_collapsed += u64::from(issue.skipped);
        }
        match outcome {
            IssueOutcome::Issued(sweep_id) => {
                tick.issued += 1;
                if issue.trigger == SlotTrigger::Catchup {
                    tick.catchup_issued += 1;
                }
                info!(
                    playbook_id = %hunt.playbook_id,
                    hunt = %hunt.title,
                    %sweep_id,
                    slot = %issue.slot,
                    trigger = issue.trigger.as_str(),
                    slots_collapsed = issue.skipped,
                    scan_truncated = issue.scan_truncated,
                    window_start = %window.start,
                    window_end = %window.end,
                    shortfall_secs = window.shortfall().num_seconds(),
                    "Issued hunt sweep"
                );
                if window.shortfall() > Duration::zero() {
                    warn!(
                        playbook_id = %hunt.playbook_id,
                        hunt = %hunt.title,
                        requested_hours = window.requested.num_minutes() as f64 / 60.0,
                        granted_hours = window.granted.num_minutes() as f64 / 60.0,
                        "Catch-up sweep capped by max_catchup_lookback; \
                         the sweep covers less than the outage left uncovered"
                    );
                }
            }
            IssueOutcome::AbsorbedInFlight => {
                tick.absorbed += 1;
                // The slot the in-flight sweep was NOT issued for still counts
                // as collapsed — it is the newest one we declined to run.
                tick.slots_collapsed += 1;
                info!(
                    playbook_id = %hunt.playbook_id,
                    hunt = %hunt.title,
                    slot = %issue.slot,
                    slots_collapsed = issue.skipped + 1,
                    "A sweep is already in flight; due slots absorbed into it"
                );
            }
            IssueOutcome::SlotAlreadyIssued => {
                tick.already_issued += 1;
                debug!(
                    playbook_id = %hunt.playbook_id,
                    slot = %issue.slot,
                    "Slot already has a sweep; watermark advanced"
                );
            }
            IssueOutcome::WatermarkMoved => {
                tick.watermark_moved += 1;
                warn!(
                    playbook_id = %hunt.playbook_id,
                    hunt = %hunt.title,
                    "Hunt watermark moved during issuance; another issuer is active"
                );
            }
        }
        Ok(())
    }

    /// Insert the sweep and advance the watermark in ONE transaction.
    ///
    /// Split across two transactions this would be a choice between losing a
    /// sweep (crash after the watermark moves) and issuing it forever (crash
    /// before). Together, either both land or neither does.
    async fn issue_slot(
        &self,
        hunt: &DueHunt,
        issue: &SlotIssue,
        window: &SweepWindow,
    ) -> Result<IssueOutcome, HuntError> {
        let mut tx = self.pool.begin().await?;

        // `ON CONFLICT DO NOTHING` rather than catching the unique violation:
        // a constraint error ABORTS the transaction, and the whole point of
        // this method is that the INSERT and the watermark advance share one.
        // Catching the error would leave every subsequent statement failing
        // with "current transaction is aborted" — the collapse would look like
        // it worked in code review and never advance a watermark in production.
        // Untargeted DO NOTHING covers both `uq_hunt_sweeps_in_flight` and
        // `uq_hunt_sweeps_slot`; the diagnosis follows below.
        let inserted: Option<Uuid> = sqlx::query_scalar(
            r#"
            INSERT INTO hunt_sweeps (playbook_id, playbook_version, schedule_slot,
                                     trigger, status, window_start, window_end)
            VALUES ($1, $2, $3, $4, 'queued', $5, $6)
            ON CONFLICT DO NOTHING
            RETURNING id
            "#,
        )
        .bind(hunt.playbook_id)
        .bind(hunt.playbook_version)
        .bind(issue.slot)
        .bind(issue.trigger.as_str())
        .bind(window.start)
        .bind(window.end)
        .fetch_optional(&mut *tx)
        .await?;

        let outcome = match inserted {
            Some(sweep_id) => IssueOutcome::Issued(sweep_id),
            None => {
                let diagnosis = sqlx::query(
                    r#"
                    SELECT EXISTS (
                               SELECT 1 FROM hunt_sweeps
                                WHERE playbook_id = $1
                                  AND status IN ('queued', 'leased', 'running')
                           ) AS in_flight,
                           EXISTS (
                               SELECT 1 FROM hunt_sweeps
                                WHERE playbook_id = $1 AND schedule_slot = $2
                           ) AS slot_taken
                    "#,
                )
                .bind(hunt.playbook_id)
                .bind(issue.slot)
                .fetch_one(&mut *tx)
                .await?;
                let in_flight: bool = diagnosis.try_get("in_flight")?;
                let slot_taken: bool = diagnosis.try_get("slot_taken")?;

                if in_flight {
                    // Absorb. A sweep that has not been claimed yet is still
                    // ours to correct, so extend its window to cover what we
                    // just computed — otherwise a queued sweep that waited a
                    // day for a runner opens with a day-old window and reads as
                    // a hunt that found nothing.
                    //
                    // Only ever WIDEN (`LEAST` / `GREATEST`), because a later
                    // tick's on-time window is narrower than the catch-up
                    // window it would otherwise overwrite — and then clamp the
                    // start to `now - cap`, so repeatedly widening across a long
                    // in-flight stretch cannot creep past `max_catchup_lookback`
                    // and reintroduce the week-long scan the cap exists to stop.
                    //
                    // A claimed sweep (leased/running) is left alone: its runner
                    // is already working against the window it was handed. A
                    // manual sweep is left alone too — that window was a human's
                    // choice.
                    sqlx::query(
                        r#"
                        UPDATE hunt_sweeps
                           SET window_start = GREATEST(
                                   LEAST(window_start, $2),
                                   $3::timestamptz - ($4 * INTERVAL '1 second')
                               ),
                               window_end = GREATEST(window_end, $3)
                         WHERE playbook_id = $1
                           AND status = 'queued'
                           AND trigger <> 'manual'
                        "#,
                    )
                    .bind(hunt.playbook_id)
                    .bind(window.start)
                    .bind(window.end)
                    .bind(window.granted.num_seconds() as f64)
                    .execute(&mut *tx)
                    .await?;
                    IssueOutcome::AbsorbedInFlight
                } else if slot_taken {
                    IssueOutcome::SlotAlreadyIssued
                } else {
                    // Neither unique index explains the conflict. Do not advance
                    // the watermark on a cause we cannot name — roll back and
                    // let the next tick retry with fresh state.
                    tx.rollback().await?;
                    return Err(HuntError::Internal(format!(
                        "hunt {} slot {} was rejected by an unrecognised constraint",
                        hunt.playbook_id, issue.slot
                    )));
                }
            }
        };

        // On absorb, the watermark still advances past the slot we did not run —
        // that IS the collapse. `coalesced_through` records the newest declined
        // slot, which on absorb is the slot itself.
        let coalesced_through = match outcome {
            IssueOutcome::AbsorbedInFlight => Some(issue.slot),
            _ => issue.coalesced_through,
        };

        // `AND enabled` is not decoration. `archive_hunt` and the toggle turn a
        // hunt off in their own transaction; without this the sweep we just
        // inserted could land on a hunt an operator disabled a millisecond ago,
        // and an unattended agent would run against a hunt the product no
        // longer shows. Failing the guard rolls the INSERT back with it.
        let advanced = sqlx::query(
            r#"
            UPDATE hunt_specs
               SET next_due_slot = $2,
                   coalesced_through_slot = COALESCE($3, coalesced_through_slot),
                   updated_at = NOW()
             WHERE playbook_id = $1
               AND enabled
               AND next_due_slot IS NOT DISTINCT FROM $4
            "#,
        )
        .bind(hunt.playbook_id)
        .bind(issue.next_due)
        .bind(coalesced_through)
        .bind(hunt.next_due_slot)
        .execute(&mut *tx)
        .await?;

        if advanced.rows_affected() == 0 {
            // Either somebody moved the watermark between our read and this
            // write, or the hunt was disabled underneath us. Roll the sweep
            // back with it rather than leave an orphan queued against a slot
            // the other issuer also issued — or against a hunt that is off.
            tx.rollback().await?;
            return Ok(IssueOutcome::WatermarkMoved);
        }

        tx.commit().await?;
        Ok(outcome)
    }

    /// Set `next_due_slot` (and optionally the coalescing watermark) without
    /// issuing anything. Returns whether the guarded write matched — `false`
    /// means the hunt was disabled or re-planned underneath us, and the caller
    /// must not report the write as having happened.
    async fn write_watermark(
        &self,
        playbook_id: Uuid,
        next_due: Option<DateTime<Utc>>,
        coalesced_through: Option<DateTime<Utc>>,
        expected: Option<DateTime<Utc>>,
    ) -> Result<bool, HuntError> {
        let result = sqlx::query(
            r#"
            UPDATE hunt_specs
               SET next_due_slot = $2,
                   coalesced_through_slot = COALESCE($3, coalesced_through_slot),
                   updated_at = NOW()
             WHERE playbook_id = $1
               AND enabled
               AND next_due_slot IS NOT DISTINCT FROM $4
            "#,
        )
        .bind(playbook_id)
        .bind(next_due)
        .bind(coalesced_through)
        .bind(expected)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn load_due_hunts(&self, now: DateTime<Utc>) -> Result<Vec<DueHunt>, HuntError> {
        // `idx_hunt_specs_due` is partial on `enabled AND schedule_cron IS NOT
        // NULL` and keyed on `next_due_slot`, so the two leading predicates are
        // free and the third is the index scan. NULLs sort first in a btree
        // ascending scan, which is what we want: an unseeded hunt is examined
        // before a due one.
        let rows = sqlx::query(
            r#"
            SELECT h.playbook_id,
                   p.title,
                   p.current_version,
                   h.schedule_cron,
                   h.schedule_timezone,
                   h.lookback_window,
                   h.max_catchup_lookback,
                   h.next_due_slot
              FROM hunt_specs h
              JOIN playbooks p ON p.id = h.playbook_id AND p.kind = 'hunt'
             WHERE h.enabled
               AND h.schedule_cron IS NOT NULL
               AND p.status <> 'archived'
               AND (h.next_due_slot IS NULL OR h.next_due_slot <= $1)
             ORDER BY h.next_due_slot ASC NULLS FIRST
             LIMIT $2
            "#,
        )
        .bind(now)
        .bind(self.config.batch_size)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| {
                Ok(DueHunt {
                    playbook_id: row.try_get("playbook_id")?,
                    title: row.try_get("title")?,
                    playbook_version: row.try_get("current_version")?,
                    schedule_cron: row.try_get("schedule_cron")?,
                    schedule_timezone: row.try_get("schedule_timezone")?,
                    lookback_window: row.try_get("lookback_window")?,
                    max_catchup_lookback: row.try_get("max_catchup_lookback")?,
                    next_due_slot: row.try_get("next_due_slot")?,
                })
            })
            .collect()
    }

    /// Take sweeps back from runners whose lease ran out.
    ///
    /// Covers `running` as well as `leased` — `idx_hunt_sweeps_expired_leases`
    /// is partial on both for exactly this reason. A runner can die at any point
    /// after it claims: mid-query, mid-narrative, or between the last tool call
    /// and the report. A sweep frozen in `running` with a dead lease is the row
    /// a recovering scheduler most needs to find, because it holds
    /// `uq_hunt_sweeps_in_flight` and silently stops the hunt forever.
    ///
    /// The reclaimed sweep goes to `abandoned` with `lease_expires_at = NULL`,
    /// which is what fences the dead runner out:
    /// [`super::repository::HuntRepository::commit_sweep_report`] requires
    /// `status IN ('leased','running') AND lease_expires_at > NOW()` under the
    /// row lock, so a runner that wakes up holding results for this sweep gets
    /// `LeaseLost` instead of appending to work that was already written off.
    pub async fn reclaim_expired_leases(&self, now: DateTime<Utc>) -> Result<usize, HuntError> {
        let cutoff = now - Duration::seconds(self.config.reclaim_grace_secs.max(0));

        let rows = sqlx::query(
            r#"
            WITH expired AS (
                SELECT id, playbook_id, runner_id, status AS prior_status, lease_expires_at
                  FROM hunt_sweeps
                 WHERE status IN ('leased', 'running')
                   AND lease_expires_at IS NOT NULL
                   AND lease_expires_at <= $1
                 ORDER BY lease_expires_at ASC
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
            ),
            reclaimed AS (
                UPDATE hunt_sweeps s
                   SET status = 'abandoned',
                       outcome = $3,
                       outcome_detail = left(
                           'Runner lease expired at '
                           || to_char(e.lease_expires_at, 'YYYY-MM-DD"T"HH24:MI:SSOF')
                           || ' while the sweep was ' || e.prior_status
                           || '; the scheduler reclaimed it. No results were reported, so'
                           || ' this sweep is not a successful run of the hunt.',
                           4000)
                  FROM expired e
                 WHERE s.id = e.id
                RETURNING s.id, s.playbook_id, e.prior_status
            ),
            attempted AS (
                -- An attempt CONCLUDED (unsuccessfully). `last_success_at` is
                -- deliberately untouched: recording a reclaimed sweep as a
                -- success would put a lie on exactly the hunts an operator
                -- needs to be able to trust.
                UPDATE hunt_specs h
                   SET last_attempt_at = NOW(), updated_at = NOW()
                  FROM reclaimed r
                 WHERE h.playbook_id = r.playbook_id
                RETURNING h.playbook_id
            )
            SELECT id, playbook_id, prior_status FROM reclaimed
            "#,
        )
        .bind(cutoff)
        .bind(self.config.reclaim_batch)
        .bind(RECLAIM_OUTCOME)
        .fetch_all(&self.pool)
        .await?;

        for row in &rows {
            let sweep_id: Uuid = row.try_get("id")?;
            let playbook_id: Uuid = row.try_get("playbook_id")?;
            let prior_status: String = row.try_get("prior_status")?;
            warn!(
                %sweep_id,
                %playbook_id,
                prior_status = %prior_status,
                grace_secs = self.config.reclaim_grace_secs,
                "Reclaimed a hunt sweep whose runner lease expired"
            );
        }

        Ok(rows.len())
    }

    /// Run until cancelled. Start from `start_leader_schedulers` — see the type
    /// docs on single-issuer.
    pub async fn run(&self, shutdown: &ShutdownToken) {
        if !self.config.enabled {
            info!("Hunt scheduler disabled (HUNT_SCHEDULER_ENABLED=false); hunts stay manual-only");
            return;
        }

        match self.tables_present().await {
            Ok(true) => {}
            Ok(false) => {
                info!(
                    "Hunt tables are not present (enterprise migration 9000054); \
                     hunt scheduler not starting"
                );
                return;
            }
            Err(error) => {
                warn!(%error, "Could not probe for hunt tables; starting the scheduler anyway");
            }
        }

        let interval = std::time::Duration::from_secs(self.config.poll_interval_secs.max(1));
        info!(
            poll_interval_secs = self.config.poll_interval_secs,
            batch_size = self.config.batch_size,
            reclaim_grace_secs = self.config.reclaim_grace_secs,
            "Hunt scheduler started (leader-only)"
        );

        loop {
            if shutdown.is_cancelled() {
                break;
            }

            match shutdown.run_until_cancelled(self.tick()).await {
                None => break,
                Some(Ok(tick)) => {
                    if tick.issued > 0
                        || tick.seeded > 0
                        || tick.reclaimed > 0
                        || tick.absorbed > 0
                        || tick.errors > 0
                    {
                        info!(
                            examined = tick.examined,
                            seeded = tick.seeded,
                            issued = tick.issued,
                            catchup = tick.catchup_issued,
                            absorbed = tick.absorbed,
                            slots_collapsed = tick.slots_collapsed,
                            reclaimed = tick.reclaimed,
                            errors = tick.errors,
                            "Hunt scheduler tick"
                        );
                    }
                }
                Some(Err(error)) => {
                    warn!(%error, "Hunt scheduler tick failed; will retry next poll");
                }
            }

            if shutdown
                .run_until_cancelled(tokio::time::sleep(interval))
                .await
                .is_none()
            {
                break;
            }
        }

        info!("Hunt scheduler stopped");
    }

    /// Spawn [`Self::run`] as a background task.
    pub fn start(&self, shutdown: ShutdownToken) -> tokio::task::JoinHandle<()> {
        let scheduler = self.clone();
        tokio::spawn(async move {
            scheduler.run(&shutdown).await;
        })
    }
}

#[cfg(test)]
#[path = "scheduler_tests.rs"]
mod scheduler_tests;

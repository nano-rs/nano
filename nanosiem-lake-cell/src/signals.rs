// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stall/lag signals in the lake pipeline alert shape (NAN-2780 pattern).
//!
//! Each signal is a (scope, tenant, stage, component, signal) key with a
//! value, warn/page thresholds and the resulting severity. The platform's
//! The supervisor evaluates thresholds. The private `GET /v1/lean-cell-alerts`
//! view carries stable keys and firing/resolved state so the platform can merge
//! cell observations into its `lake-pipeline-alerts:read` consumer.

use crate::contract::TenantId;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Ok,
    Warn,
    Page,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Ok => "ok",
            Severity::Warn => "warn",
            Severity::Page => "page",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    /// "tenant" or "cell".
    pub scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<TenantId>,
    pub stage: &'static str,
    pub component: &'static str,
    pub signal: &'static str,
    pub unit: &'static str,
    pub value: f64,
    #[serde(serialize_with = "finite_or_null")]
    pub warn_at: f64,
    #[serde(serialize_with = "finite_or_null")]
    pub page_at: f64,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

fn finite_or_null<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if v.is_finite() {
        s.serialize_f64(*v)
    } else {
        s.serialize_none()
    }
}

/// Retired as an alert (NAN-3701): raw L0 age is NOT a stall signal. A lone
/// L0 in its hour is never a minute-merge input and waits for the hour to
/// seal (10 min) and settle, so a healthy one routinely passed the old 5 min
/// warn / 15 min page (cell-us-1 every hour at about xx:06, tenant-a paged at 924 s
/// while its hour merge ran, 2026-10-12). Still reported, always resolved, so
/// a row a previous release left firing resolves; [`l0_merge_overdue`]
/// alerts instead.
pub fn unmerged_l0_age(tenant_id: Option<TenantId>, seconds: f64) -> Signal {
    let mut signal = Signal::evaluate(tenant_id, "ingest", "compaction", "oldest_unmerged_l0_age", "seconds",
        seconds, 5.0 * 60.0, 15.0 * 60.0, None);
    signal.severity = Severity::Ok;
    signal
}

/// NAN-3774: `prevalence_behind` warns after 10 min. Prevalence is derived
/// and never holds ingest, so its lag is its own signal: a state that is
/// opening, rotating (seconds) or catching up after a restart (tenant-a: about
/// a minute) clears well inside this, and an R2 stall reopens within
/// `prevalence_op_timeout` (45 s) plus the first retry backoff (30 s).
pub const PREVALENCE_BEHIND_WARN_SECS: f64 = 10.0 * 60.0;
/// NAN-3774: pages at 60 min: an hour of unstamped rows (and merges
/// waiting on the state) is an outage of the derived product.
pub const PREVALENCE_BEHIND_PAGE_SECS: f64 = 60.0 * 60.0;

/// NAN-3774: the tenant's prevalence state is behind the part log
/// (`detail` names how many committed entries). Ingest freshness is
/// reported separately by `ingest_lag`; this never feeds it.
pub fn prevalence_behind(tenant_id: Option<TenantId>, seconds: f64, entries: u64) -> Signal {
    Signal::evaluate(tenant_id, "ingest", "prevalence", "prevalence_behind", "seconds", seconds,
        PREVALENCE_BEHIND_WARN_SECS, PREVALENCE_BEHIND_PAGE_SECS,
        (seconds > 0.0).then(|| format!("prevalence state {entries} committed part-log entries behind")))
}

/// NAN-3781: `prevalence_degraded` warns after 2 min. Degraded means the
/// state could not be opened or used and rows go unstamped (ingest goes on).
/// A hosted R2 read stall reopens in about 10 s (tenant-a, 2026-10-13); a spell
/// past two minutes is a store that is not coming back by itself (CT 106: a
/// state stalled at SlateDB's L0 cap, 2026-10-13).
pub const PREVALENCE_DEGRADED_WARN_SECS: f64 = 2.0 * 60.0;
/// NAN-3781: pages at 15 min of unstamped rows.
pub const PREVALENCE_DEGRADED_PAGE_SECS: f64 = 15.0 * 60.0;

/// NAN-3781: the tenant's prevalence state is unavailable. Unlike
/// [`prevalence_behind`] (a state that works but lags) nothing is being
/// stamped at all.
pub fn prevalence_degraded(tenant_id: Option<TenantId>, seconds: f64) -> Signal {
    Signal::evaluate(tenant_id, "ingest", "prevalence", "prevalence_degraded", "seconds", seconds,
        PREVALENCE_DEGRADED_WARN_SECS, PREVALENCE_DEGRADED_PAGE_SECS,
        (seconds > 0.0).then(|| "prevalence state unavailable; rows go unstamped".to_string()))
}

/// NAN-3701: `l0_merge_overdue` warns at 15 min. The value counts from the
/// moment the merge policy makes the L0 a merge input, so it holds only merge
/// execution and lane queueing: the longest healthy one measured was 8 min 16 s
/// (tenant-a 2026-10-12, a 53-input, 1.25M-row hour merge at about 400 EPS while minute
/// merges kept running). That gives about 2x margin.
pub const L0_MERGE_OVERDUE_WARN_SECS: f64 = 15.0 * 60.0;
/// NAN-3701: pages at 60 min. A merge an hour past due is hung, failing or
/// quarantined. The rows stay searchable as L0 parts meanwhile, and ingest
/// stalls page on their own (`ingest_lag`, `ingest_progress_stalled`), so a
/// slow compaction is not worth waking anyone sooner.
pub const L0_MERGE_OVERDUE_PAGE_SECS: f64 = 60.0 * 60.0;

/// NAN-3701: how long the most overdue L0 part has waited past its merge
/// deadline under the tenant's merge policy (`l0_merge_overdue_ms` in the lake
/// worker). Independent of successful ingestion, so fresh commits cannot hide
/// a merge stall; a lone L0 waiting for its hour to seal is not overdue.
pub fn l0_merge_overdue(tenant_id: Option<TenantId>, seconds: f64) -> Signal {
    Signal::evaluate(tenant_id, "ingest", "compaction", "l0_merge_overdue", "seconds",
        seconds, L0_MERGE_OVERDUE_WARN_SECS, L0_MERGE_OVERDUE_PAGE_SECS, None)
}

/// `pooled_admission_refused` pages once a refusal has lasted this long,
/// continuously (it warns from the first second). Short enough that tenants'
/// queued data is noticed fast; long enough to ride out the boot race (5 s
/// adoption poll) and a delegator restart.
pub const POOLED_ADMISSION_REFUSED_PAGE: std::time::Duration = std::time::Duration::from_secs(30);

/// NAN-3523: a pooled cell refusing tenant processes because limits are
/// not kernel-enforced. `refused_for` is how long the refusal has lasted
/// continuously (`None` while admission is open): warns at once, pages after
/// [`POOLED_ADMISSION_REFUSED_PAGE`] (every placed tenant's data is queueing
/// upstream).
pub fn pooled_admission_refused(refused_for: Option<std::time::Duration>, reason: Option<String>) -> Signal {
    let secs = refused_for.map_or(0.0, |d| d.as_secs_f64().max(1.0));
    Signal::evaluate(None, "cell", "supervisor", "pooled_admission_refused", "seconds", secs, 1.0,
        POOLED_ADMISSION_REFUSED_PAGE.as_secs_f64(),
        refused_for.map(|_| format!("pooled cell starts no tenant process: limits not kernel-enforced ({})", reason.unwrap_or_default())))
}

/// NAN-3773: how many minutes an ingest has held pending input without
/// committing it (`ingest_progress_stalled`).
///
/// The old value was "minutes since the last commit, whenever the heartbeat
/// says busy". A quiet tenant that receives a batch every 10 min (tenant-b
/// on cell-us-1, 2026-10-13: 4 rows each ~10 min) is busy only for the few
/// seconds between a batch's arrival and its flush, and in exactly that
/// window the last commit is the previous batch's, ~10 min old: a reader that
/// landed there saw 9.7-10.8 min and paged (11:40, 12:30, 13:01, 13:20 EDT),
/// resolving at the next read. A stall is pending input that does not commit,
/// so the value is capped by how long the oldest pending input has waited
/// (`lag_seconds`, arrival of the oldest uncommitted notice). While a commit is
/// failing and retried (`retrying`) the heartbeat's lag is frozen at the last
/// good tick, so the time since the last commit is used as before.
pub fn ingest_stalled_minutes(now_ms: u64, busy: bool, retrying: bool, last_progress_unix_ms: u64, lag_seconds: f64) -> f64 {
    if !busy || last_progress_unix_ms == 0 {
        return 0.0;
    }
    let since_commit = now_ms.saturating_sub(last_progress_unix_ms) as f64 / 60_000.0;
    if retrying {
        return since_commit;
    }
    let pending = if lag_seconds.is_finite() { lag_seconds.max(0.0) / 60.0 } else { 0.0 };
    since_commit.min(pending)
}

/// NAN-3773: when a raw threshold breach becomes an alert, and when it stops
/// being one. `Signal::evaluate` is an instantaneous verdict; the lean-cell
/// feed is a snapshot that the platform turns into fire / resolve / re-fire
/// transitions (and Slack posts), so a value hovering at its threshold, or
/// a 5-minute window that one burst holds over it, posted WARN / RESOLVED
/// every few minutes (#lake-alerts, 2026-10-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hysteresis {
    /// The warn-level breach must hold this long before it fires.
    pub fire_after: std::time::Duration,
    /// The page-level breach must hold this long before it pages (it fires
    /// as warn meanwhile, once `fire_after` has passed).
    pub page_after: std::time::Duration,
    /// A firing alert resolves only after this long below its warn threshold;
    /// a breach inside the window keeps it firing (no re-fire).
    pub resolve_after: std::time::Duration,
}

impl Hysteresis {
    /// Most signals are ages, counts over a window or flags whose value
    /// already proves its own duration: they fire at once, as before, and
    /// only the resolve is debounced.
    pub const DEFAULT: Self = Self {
        fire_after: std::time::Duration::ZERO,
        page_after: std::time::Duration::ZERO,
        resolve_after: std::time::Duration::from_secs(5 * 60),
    };

    /// `query_throttled_5m` is a CPU-ceiling (capacity) signal, never a page.
    /// One heavy query (a 7d search fanned out to ~30 segment queries) puts a
    /// single minute of throttling into the 5-minute ratio window and holds it
    /// over 0.25 for exactly 5 minutes: tenant-a 2026-10-13 15:24Z (151 s throttled
    /// in one minute) and 15:40Z (94 s), each a 5-minute WARN then RESOLVE.
    /// It alerts only when throttling is sustained past the window: 10 min.
    pub const SUSTAINED_CAPACITY: Self = Self {
        fire_after: std::time::Duration::from_secs(10 * 60),
        page_after: std::time::Duration::from_secs(10 * 60),
        resolve_after: std::time::Duration::from_secs(10 * 60),
    };

    pub fn for_signal(signal: &str) -> Self {
        match signal {
            "query_throttled_5m" => Self::SUSTAINED_CAPACITY,
            _ => Self::DEFAULT,
        }
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Ok => 0,
        Severity::Warn => 1,
        Severity::Page => 2,
    }
}

#[derive(Debug, Clone, Copy)]
struct DebounceState {
    firing: Option<Severity>,
    breach_since: Option<std::time::Instant>,
    page_since: Option<std::time::Instant>,
    clear_since: Option<std::time::Instant>,
    seen_at: std::time::Instant,
}

type DebounceKey = (Option<String>, &'static str, &'static str, &'static str);

/// NAN-3773: applies [`Hysteresis`] to the supervisor's instantaneous
/// signals, per alert identity (tenant, stage, component, signal: the parts
/// of the lean-cell alert key). Time-based, so it does not matter how often
/// the feed or `/metrics` is read; a key not seen for an hour is forgotten.
/// In process memory: a new supervisor starts with nothing firing, so a
/// breach that persists across a roll fires again after its `fire_after`.
#[derive(Debug, Default)]
pub struct SignalDebouncer {
    states: std::collections::HashMap<DebounceKey, DebounceState>,
}

impl SignalDebouncer {
    const FORGET_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);

    pub fn apply_all(&mut self, now: std::time::Instant, signals: Vec<Signal>) -> Vec<Signal> {
        let out = signals.into_iter().map(|s| self.apply(now, s)).collect();
        self.states.retain(|_, st| now.saturating_duration_since(st.seen_at) < Self::FORGET_AFTER);
        out
    }

    pub fn apply(&mut self, now: std::time::Instant, mut signal: Signal) -> Signal {
        let h = Hysteresis::for_signal(signal.signal);
        let key = (signal.tenant_id.as_ref().map(|t| t.as_str().to_owned()), signal.stage, signal.component, signal.signal);
        let st = self.states.entry(key).or_insert(DebounceState {
            firing: None, breach_since: None, page_since: None, clear_since: None, seen_at: now,
        });
        st.seen_at = now;
        let held = |since: std::time::Instant, d: std::time::Duration| now.saturating_duration_since(since) >= d;
        if signal.severity == Severity::Ok {
            st.breach_since = None;
            st.page_since = None;
            if let Some(firing) = st.firing {
                let clear = *st.clear_since.get_or_insert(now);
                if held(clear, h.resolve_after) {
                    st.firing = None;
                    st.clear_since = None;
                } else {
                    signal.severity = firing;
                }
            }
            return signal;
        }
        st.clear_since = None;
        let breach = *st.breach_since.get_or_insert(now);
        let page_held = if signal.severity == Severity::Page {
            held(*st.page_since.get_or_insert(now), h.page_after)
        } else {
            st.page_since = None;
            false
        };
        let eligible = if page_held {
            Some(Severity::Page)
        } else if held(breach, h.fire_after) {
            Some(Severity::Warn)
        } else {
            None
        };
        // A firing alert keeps its highest severity until it resolves: a value
        // dipping from page to warn level is the same incident, not a new post.
        st.firing = match (st.firing, eligible) {
            (Some(f), Some(e)) => Some(if severity_rank(e) > severity_rank(f) { e } else { f }),
            (Some(f), None) => Some(f),
            (None, e) => e,
        };
        signal.severity = st.firing.unwrap_or(Severity::Ok);
        signal
    }
}

impl Signal {
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        tenant_id: Option<TenantId>,
        stage: &'static str,
        component: &'static str,
        signal: &'static str,
        unit: &'static str,
        value: f64,
        warn_at: f64,
        page_at: f64,
        detail: Option<String>,
    ) -> Self {
        let severity = if value >= page_at {
            Severity::Page
        } else if value >= warn_at {
            Severity::Warn
        } else {
            Severity::Ok
        };
        Self {
            scope: if tenant_id.is_some() { "tenant" } else { "cell" },
            tenant_id,
            stage,
            component,
            signal,
            unit,
            value,
            warn_at,
            page_at,
            severity,
            detail,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LeanCellAlertFeed {
    pub cell_id: String,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub alerts: Vec<LeanCellAlert>,
}

#[derive(Debug, Serialize)]
pub struct LeanCellAlert {
    pub alert_key: String,
    pub tenant_id: Option<TenantId>,
    pub cell_id: String,
    pub role: String,
    pub stage: &'static str,
    pub signal: &'static str,
    pub severity: &'static str,
    pub state: &'static str,
    pub value: f64,
    pub threshold: f64,
    pub unit: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl LeanCellAlertFeed {
    pub fn from_signals(cell_id: &str, signals: Vec<Signal>) -> Self {
        let alerts = signals.into_iter().map(|signal| {
            // Match NAN-2632's six-part key: cell in shard, role in producer.
            let role = signal.component.to_owned();
            let preimage = format!("lake-pipeline-alert/v1|{}|cell:{cell_id}|{role}|{}|{}",
                signal.tenant_id.as_ref().map(|t| t.as_str()).unwrap_or("*"), signal.stage, signal.signal);
            let alert_key = hex::encode(Sha256::digest(preimage.as_bytes()));
            let (severity, state, threshold) = match signal.severity {
                Severity::Ok => ("warn", "resolved", signal.warn_at),
                Severity::Warn => ("warn", "firing", signal.warn_at),
                Severity::Page => ("page", "firing", signal.page_at),
            };
            LeanCellAlert { alert_key, tenant_id: signal.tenant_id, cell_id: cell_id.to_owned(), role,
                stage: signal.stage, signal: signal.signal, severity, state, value: signal.value,
                threshold, unit: signal.unit, detail: signal.detail }
        }).collect();
        Self { cell_id: cell_id.to_owned(), evaluated_at: chrono::Utc::now(), alerts }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prevalence_behind_is_its_own_signal_never_ingest_lag() {
        // NAN-3774: a reopen or rotation (seconds) and a restart catch-up
        // (about a minute on tenant-a) stay quiet; an R2 stall that keeps the
        // state behind warns at 10 min and pages at an hour.
        let quiet = prevalence_behind(None, 0.0, 0);
        assert_eq!((quiet.signal, quiet.component, quiet.severity), ("prevalence_behind", "prevalence", Severity::Ok));
        assert!(quiet.detail.is_none());
        assert_eq!(prevalence_behind(None, 77.0, 3).severity, Severity::Ok, "tenant-a's post-roll catch-up");
        let warn = prevalence_behind(None, 10.0 * 60.0, 12);
        assert_eq!(warn.severity, Severity::Warn);
        assert_eq!(warn.detail.as_deref(), Some("prevalence state 12 committed part-log entries behind"));
        assert_eq!(prevalence_behind(None, 3_600.0, 120).severity, Severity::Page);
    }

    /// NAN-3781: tenant-a's ~10 s R2 read-stall reopen stays quiet; CT 106's
    /// state stuck at the L0 cap warns at 2 min and pages at 15.
    #[test]
    fn prevalence_degraded_warns_at_two_minutes_and_pages_at_fifteen() {
        let quiet = prevalence_degraded(None, 0.0);
        assert_eq!((quiet.signal, quiet.component, quiet.severity), ("prevalence_degraded", "prevalence", Severity::Ok));
        assert!(quiet.detail.is_none());
        assert_eq!(prevalence_degraded(None, 10.0).severity, Severity::Ok, "tenant-a's R2 stall reopen");
        assert_eq!(prevalence_degraded(None, 120.0).severity, Severity::Warn);
        assert_eq!(prevalence_degraded(None, 15.0 * 60.0).severity, Severity::Page);
    }

    /// NAN-3701: the merge-deadline signal alerts even when ingestion is
    /// healthy; raw L0 age is reported but never fires.
    #[test]
    fn l0_merge_overdue_alerts_raw_l0_age_never_fires() {
        assert_eq!(l0_merge_overdue(None, 0.0).severity, Severity::Ok);
        assert_eq!(l0_merge_overdue(None, 8.0 * 60.0 + 16.0).severity, Severity::Ok, "tenant-a's healthy hour merge");
        assert_eq!(l0_merge_overdue(None, 15.0 * 60.0).severity, Severity::Warn);
        assert_eq!(l0_merge_overdue(None, 3_601.0).severity, Severity::Page);
        assert_eq!(l0_merge_overdue(None, 110.0 * 60.0).severity, Severity::Page, "an unsorted L0 stuck 2 h (levels.rs test)");
        assert_eq!(l0_merge_overdue(None, 0.0).severity, Severity::Ok, "draining L0 resolves the signal");
        for raw in [0.0, 310.0, 924.0, 86_400.0] {
            let retired = unmerged_l0_age(None, raw);
            assert_eq!((retired.signal, retired.severity, retired.value), ("oldest_unmerged_l0_age", Severity::Ok, raw));
        }
        let feed = LeanCellAlertFeed::from_signals("cell-1", vec![unmerged_l0_age(None, 924.0), l0_merge_overdue(None, 3_601.0)]);
        assert_eq!((feed.alerts[0].signal, feed.alerts[0].state), ("oldest_unmerged_l0_age", "resolved"));
        assert_eq!((feed.alerts[1].signal, feed.alerts[1].severity, feed.alerts[1].threshold), ("l0_merge_overdue", "page", 3_600.0));
    }

    /// NAN-3523: a refused pooled admission warns at once, pages only
    /// after 30 s of continuous refusal, and resolves once reopened.
    #[test]
    fn pooled_admission_refused_warns_then_pages_after_grace() {
        use std::time::Duration;
        let first = pooled_admission_refused(Some(Duration::ZERO), Some("cgroup delegation not adopted yet".into()));
        assert_eq!((first.signal, first.severity, first.value), ("pooled_admission_refused", Severity::Warn, 1.0));
        assert!(first.detail.as_deref().is_some_and(|d| d.contains("not adopted")), "{:?}", first.detail);
        assert_eq!(pooled_admission_refused(Some(Duration::from_secs(29)), None).severity, Severity::Warn);
        let on = pooled_admission_refused(Some(Duration::from_secs(31)), None);
        assert_eq!(on.severity, Severity::Page);
        let off = pooled_admission_refused(None, None);
        assert_eq!((off.severity, off.detail.as_deref()), (Severity::Ok, None));
        let feed = LeanCellAlertFeed::from_signals("cell-1", vec![on]);
        assert_eq!((feed.alerts[0].severity, feed.alerts[0].state), ("page", "firing"));
        let feed = LeanCellAlertFeed::from_signals("cell-1", vec![off]);
        assert_eq!(feed.alerts[0].state, "resolved");
    }

    use std::time::{Duration, Instant};

    fn stalled(minutes: f64) -> Signal {
        // The unheld pages (`held_ingest_pages(None)`): warn 5 min, page 10 min.
        Signal::evaluate(Some(TenantId::new("4b7e2a91-5c3d-4f60-8e1b-9a2c7d4f6e30").unwrap()), "ingest", "ingest",
            "ingest_progress_stalled", "minutes", minutes, 5.0, 10.0, None)
    }

    /// Fire / resolve / page transitions of one alert's debounced stream.
    #[derive(Debug, Default, PartialEq)]
    struct Transitions { fires: usize, resolves: usize, pages: usize, raw_pages: usize, raw_fires: usize }

    impl Transitions {
        fn feed(&mut self, raw: Severity, alert: Severity, prev_raw: &mut Severity, prev: &mut Severity) {
            self.raw_fires += (*prev_raw == Severity::Ok && raw != Severity::Ok) as usize;
            self.raw_pages += (*prev_raw != Severity::Page && raw == Severity::Page) as usize;
            self.fires += (*prev == Severity::Ok && alert != Severity::Ok) as usize;
            self.resolves += (*prev != Severity::Ok && alert == Severity::Ok) as usize;
            self.pages += (*prev != Severity::Page && alert == Severity::Page) as usize;
            *prev_raw = raw;
            *prev = alert;
        }
    }

    /// NAN-3773: the value is pending input that does not commit.
    #[test]
    fn ingest_stalled_minutes_is_backlog_aware() {
        let commit = 1_000_000_000u64;
        let at = |min: f64| commit + (min * 60_000.0) as u64;
        assert_eq!(ingest_stalled_minutes(at(9.9), false, false, commit, 0.0), 0.0, "idle: nothing pending");
        assert_eq!(ingest_stalled_minutes(at(10.0), true, false, 0, 30.0), 0.0, "no commit yet");
        // The quiet tenant's next batch, 8 s after arrival: 8 s, not 10 min.
        assert!((ingest_stalled_minutes(at(10.0), true, false, commit, 8.0) - 8.0 / 60.0).abs() < 1e-9);
        // Input pending 12 min without a commit is a stall; the commit age bounds it.
        assert!((ingest_stalled_minutes(at(12.0), true, false, commit, 720.0) - 12.0).abs() < 1e-9);
        assert!((ingest_stalled_minutes(at(3.0), true, false, commit, 900.0) - 3.0).abs() < 1e-9, "held backlog that commits");
        // A failing commit freezes the heartbeat's lag: the commit age counts.
        assert!((ingest_stalled_minutes(at(11.0), true, true, commit, 5.0) - 11.0).abs() < 1e-9);
        assert_eq!(ingest_stalled_minutes(at(11.0), true, false, commit, f64::NAN), 0.0);
    }

    /// NAN-3773 replay: tenant-b (cell-us-1) commits on
    /// 2026-10-13, from the cell log (`ingest flush committed`, 1-5 rows
    /// each). Each batch is pending (busy) for the ~8 s before its commit;
    /// read every second for 2 h. The old value paged on these gaps; the
    /// new one never fires.
    #[test]
    fn tenant_replay_2026_10_13_never_pages() {
        const COMMITS: &str = "15:20:51 15:30:27 15:40:32 15:50:40 15:55:49 16:00:49 16:05:52 16:10:51 16:15:52 16:20:28 \
            16:30:34 16:40:38 16:50:44 17:02:48 17:03:04 17:06:21 17:10:24 17:20:31 17:21:53";
        let commits: Vec<u64> = COMMITS.split_whitespace().map(|t| {
            let v: Vec<u64> = t.split(':').map(|x| x.parse().unwrap()).collect();
            1_791_849_600_000 + (v[0] * 3600 + v[1] * 60 + v[2]) * 1000 // 2026-10-13T00:00Z
        }).collect();
        const PENDING_MS: u64 = 8_000;
        let t0 = Instant::now();
        let (start, end) = (commits[0], commits[commits.len() - 1] + 15 * 60_000);
        let (mut old, mut new) = (Transitions::default(), Transitions::default());
        let (mut old_raw, mut old_prev, mut new_raw, mut new_prev) = (Severity::Ok, Severity::Ok, Severity::Ok, Severity::Ok);
        let (mut old_debounce, mut new_debounce) = (SignalDebouncer::default(), SignalDebouncer::default());
        for now in (start..=end).step_by(1000) {
            let last = *commits.iter().filter(|c| **c <= now).max().unwrap();
            let arriving = commits.iter().find(|c| **c > now && **c - now <= PENDING_MS);
            let busy = arriving.is_some();
            let lag_s = arriving.map_or(0.0, |c| (PENDING_MS - (c - now)) as f64 / 1000.0);
            let instant = t0 + Duration::from_millis(now - start);
            let old_value = if busy { (now - last) as f64 / 60_000.0 } else { 0.0 };
            let raw = stalled(old_value);
            let alert = old_debounce.apply(instant, raw.clone());
            old.feed(raw.severity, alert.severity, &mut old_raw, &mut old_prev);
            let raw = stalled(ingest_stalled_minutes(now, busy, false, last, lag_s));
            let alert = new_debounce.apply(instant, raw.clone());
            new.feed(raw.severity, alert.severity, &mut new_raw, &mut new_prev);
        }
        assert!(old.raw_pages >= 3, "the fixture reproduces the pages: {old:?}");
        assert_eq!(new, Transitions::default(), "no tenant alert at all");
    }

    /// A real stall still alerts: input pending from minute 0 that never commits
    /// warns at 5 min and pages at 10 min, once each, and resolves once,
    /// 5 min after it drains.
    #[test]
    fn real_ingest_stall_warns_pages_and_resolves_once() {
        let t0 = Instant::now();
        let commit = 2_000_000_000u64;
        let mut debounce = SignalDebouncer::default();
        let (mut tr, mut raw_prev, mut prev) = (Transitions::default(), Severity::Ok, Severity::Ok);
        let mut first = (None, None);
        for s in 0..=40 * 60u64 {
            let draining = s >= 15 * 60;
            let now = commit + s * 1000;
            let value = if draining { 0.0 } else { ingest_stalled_minutes(now, true, false, commit, s as f64) };
            let raw = stalled(value);
            let alert = debounce.apply(t0 + Duration::from_secs(s), raw.clone());
            if alert.severity == Severity::Warn && first.0.is_none() { first.0 = Some(s); }
            if alert.severity == Severity::Page && first.1.is_none() { first.1 = Some(s); }
            tr.feed(raw.severity, alert.severity, &mut raw_prev, &mut prev);
        }
        assert_eq!(first, (Some(300), Some(600)));
        assert_eq!((tr.fires, tr.pages, tr.resolves), (1, 1, 1));
    }

    /// NAN-3773 replay: tenant-a's `ingest lag exceeds its alert threshold` peaks on
    /// 2026-10-13 (15:18:17Z 152 s after the r48 handover; 16:51:24Z 148 s and
    /// 17:04:12Z 126 s, R2 timeouts stalling the prevalence store). Real
    /// incidents: each still fires (at once, the lag proves its own age) and
    /// resolves once, with no re-fire inside an incident.
    #[test]
    fn b12_ingest_lag_replay_fires_once_per_incident() {
        let peaks = [(15 * 3600 + 18 * 60 + 17, 152.0), (16 * 3600 + 51 * 60 + 24, 148.0), (17 * 3600 + 4 * 60 + 12, 126.0)];
        let lag = |t: u64| -> f64 {
            for (peak, top) in peaks {
                let rise = top - 20.0;
                if t + rise as u64 >= peak && t <= peak { return 20.0 + (t + rise as u64 - peak) as f64; }
            }
            20.0
        };
        let t0 = Instant::now();
        let mut debounce = SignalDebouncer::default();
        let (mut tr, mut raw_prev, mut prev) = (Transitions::default(), Severity::Ok, Severity::Ok);
        let (start, end) = (15 * 3600 + 10 * 60, 17 * 3600 + 30 * 60);
        for t in (start..=end).step_by(15) {
            // A threshold-hovering read pattern: values jitter ±20 s around the trend.
            let jitter = if (t / 15) % 2 == 0 { 20.0 } else { -20.0 };
            let raw = Signal::evaluate(None, "ingest", "ingest", "ingest_lag", "seconds", lag(t) + jitter, 120.0, 300.0, None);
            let alert = debounce.apply(t0 + Duration::from_secs(t - start), raw.clone());
            tr.feed(raw.severity, alert.severity, &mut raw_prev, &mut prev);
        }
        assert!(tr.raw_fires > 3, "the jitter flaps the raw verdict: {tr:?}");
        assert_eq!((tr.fires, tr.resolves, tr.pages), (3, 3, 0), "{tr:?}");
    }

    #[test]
    fn hysteresis_holds_fire_resolve_and_page() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let throttled = |v: f64| Signal::evaluate(None, "cell", "query", "query_throttled_5m", "ratio", v, 0.25, f64::INFINITY, None);
        let mut d = SignalDebouncer::default();
        assert_eq!(d.apply(at(0), throttled(0.3)).severity, Severity::Ok, "pending");
        assert_eq!(d.apply(at(599), throttled(0.3)).severity, Severity::Ok, "pending");
        assert_eq!(d.apply(at(600), throttled(0.3)).severity, Severity::Warn, "held 10 min");
        assert_eq!(d.apply(at(700), throttled(0.1)).severity, Severity::Warn, "resolve debounced");
        assert_eq!(d.apply(at(800), throttled(0.3)).severity, Severity::Warn, "a breach inside the window is no re-fire");
        assert_eq!(d.apply(at(900), throttled(0.1)).severity, Severity::Warn);
        assert_eq!(d.apply(at(1500), throttled(0.1)).severity, Severity::Ok, "clear 10 min");
        // A breach that ends before fire_after never fires.
        assert_eq!(d.apply(at(1600), throttled(0.3)).severity, Severity::Ok);
        assert_eq!(d.apply(at(1900), throttled(0.1)).severity, Severity::Ok);
        assert_eq!(d.apply(at(2200), throttled(0.3)).severity, Severity::Ok, "the hold restarts after a clear read");

        // Default: fires at once, pages at once (age signals prove their age),
        // keeps the page through a dip to warn level, resolves 5 min after clear.
        let lag = |v: f64| Signal::evaluate(None, "ingest", "ingest", "ingest_lag", "seconds", v, 120.0, 300.0, None);
        assert_eq!(d.apply(at(0), lag(130.0)).severity, Severity::Warn);
        assert_eq!(d.apply(at(60), lag(310.0)).severity, Severity::Page);
        assert_eq!(d.apply(at(120), lag(200.0)).severity, Severity::Page, "same incident");
        assert_eq!(d.apply(at(180), lag(10.0)).severity, Severity::Page);
        assert_eq!(d.apply(at(479), lag(10.0)).severity, Severity::Page);
        assert_eq!(d.apply(at(480), lag(10.0)).severity, Severity::Ok);
        assert_eq!(d.apply(at(540), lag(130.0)).severity, Severity::Warn, "a new incident starts at warn");

        // Keys are per tenant and signal; forced-Ok (retired) signals stay Ok.
        let tenant = |t: &str| Signal::evaluate(Some(TenantId::new(t).unwrap()), "ingest", "ingest", "ingest_lag", "seconds", 130.0, 120.0, 300.0, None);
        let out = d.apply_all(at(600), vec![tenant("a"), tenant("b"), unmerged_l0_age(None, 9_999.0)]);
        assert_eq!(out.iter().map(|s| s.severity).collect::<Vec<_>>(), vec![Severity::Warn, Severity::Warn, Severity::Ok]);
        d.apply(at(5000), lag(10.0));
        d.apply_all(at(9000), vec![]);
        assert!(d.states.is_empty(), "keys unseen for an hour are forgotten");
    }

    #[test]
    fn thresholds() {
        let s = |v| Signal::evaluate(None, "ingest", "ingest", "ingest_lag", "seconds", v, 120.0, 300.0, None).severity;
        assert_eq!(s(10.0), Severity::Ok);
        assert_eq!(s(120.0), Severity::Warn);
        assert_eq!(s(301.0), Severity::Page);
        let never = Signal::evaluate(None, "cell", "supervisor", "x", "flag", 1.0, 1.0, f64::INFINITY, None);
        assert_eq!(never.severity, Severity::Warn);
        let j = serde_json::to_value(&never).unwrap();
        assert!(j["page_at"].is_null());
    }

    #[test]
    fn lean_cell_feed_has_stable_role_scoped_keys_and_resolution() {
        let signal = |value| Signal::evaluate(Some(TenantId::new("tenant-1").unwrap()), "cell", "query",
            "query_throttled_5m", "ratio", value, 0.25, f64::INFINITY, None);
        let firing = LeanCellAlertFeed::from_signals("cell-1", vec![signal(0.3)]);
        let resolved = LeanCellAlertFeed::from_signals("cell-1", vec![signal(0.1)]);
        assert_eq!(firing.alerts[0].alert_key, resolved.alerts[0].alert_key);
        assert_eq!(firing.alerts[0].state, "firing");
        assert_eq!(resolved.alerts[0].state, "resolved");
        assert_eq!(firing.alerts[0].role, "query");
    }
}

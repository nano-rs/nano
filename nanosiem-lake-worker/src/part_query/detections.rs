// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled detections over parts (design 3.2 "Detections").
//!
//! The detection scheduler (nanosiem-api / the enterprise shared runtime) is
//! unchanged: it decides windows and sends each rule's nPL as a `broad_npl`
//! query, which runs over parts exactly like an interactive search. This
//! module adds the part-log facts the scheduler needs so that:
//!
//! - a rule is **skipped** when no rows landed in its window since the rule
//!   last evaluated it (an idle tenant costs 0: no part fetch, no chDB work).
//!   "Landed since" is by event time as well as by log seq: rows for window
//!   N+1 that were already in the log when window N was planned (and so sit
//!   at or below the rule's committed seq) still make window N+1 run. The
//!   history therefore keeps every entry whose rows reach past some rule's
//!   `evaluated_through_us`, and is seeded with the live parts at start;
//! - **late parts re-run the windows they touch**: rows whose event time
//!   falls in an already evaluated window are reported as re-run windows
//!   (aligned to the rule's window grid), replacing the reader's
//!   `lake_detection_event_publications` late-arrival ledger.
//!
//! State per rule is a watermark `(log_seq, evaluated_through_us)`, persisted
//! in the process's private state dir so a respawned `query[T]` does not
//! re-run everything. Unknown state is conservative: the rule runs, and late
//! detection starts from that run.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;

use super::log_view::Advance;

/// New-data history kept for late-window detection. Entries older than the
/// oldest rule watermark are dropped; this is the hard cap.
const MAX_HISTORY: usize = 65_536;
const MAX_RERUN_WINDOWS: usize = 256;
const STATE_FILE: &str = "detection-watermarks.json";
/// Bounds on caller-supplied rule identity (the state file stays small).
const MAX_RULE_ID_BYTES: usize = 256;
/// NAN-3289 P2-1: junk rule ids must not be able to crowd out real rules
/// for long; the operator reset ([`DetectionGate::reset`]) clears them.
const MAX_RULES: usize = 20_000;
/// NAN-3289 P2-1: a commit may claim evaluation through at most this far
/// past the process clock (scheduler/cell clock skew), never years ahead.
pub const MAX_COMMIT_SKEW_US: i64 = 5 * 60 * 1_000_000;
/// Rule ids one reset may name.
const MAX_RESET_RULES: usize = 1_000;

/// A detection-gate write the gate refuses (a 400, not a server error).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct GateRefused(pub String);

fn refused(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(GateRefused(message.into()))
}

/// `POST /v1/detections/reset` (NAN-3289 P2-1): drop watermarks so the named
/// rules (or every rule) run again from scratch. Detect scope only (router).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetRequest {
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub all: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watermark {
    /// The verified log seq the rule's last committed run saw.
    pub log_seq: u64,
    /// Event time through which the rule has been evaluated (inclusive).
    pub evaluated_through_us: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRequest {
    pub rule_id: String,
    /// The window the scheduler is about to evaluate, inclusive µs.
    pub window_start_us: i64,
    pub window_end_us: i64,
    /// Width of the rule's evaluation grid (its lookback/interval), µs;
    /// re-run windows are aligned to it. Defaults to the window width.
    #[serde(default)]
    pub grid_us: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RerunWindow {
    pub start_us: i64,
    pub end_us: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    /// Run the requested window (false: nothing new landed in it).
    pub run: bool,
    pub reason: &'static str,
    /// The log seq the run must be committed at (the head seen now).
    pub log_seq: u64,
    /// Earlier, already evaluated windows that late rows landed in.
    pub rerun_windows: Vec<RerunWindow>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    pub rule_id: String,
    pub log_seq: u64,
    pub evaluated_through_us: i64,
}

#[derive(Default, Serialize, Deserialize)]
struct Persisted {
    rules: BTreeMap<String, Watermark>,
}

/// The per-tenant detection gate.
pub struct DetectionGate {
    state_path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    rules: BTreeMap<String, Watermark>,
    /// `(seq, min_time_us, max_time_us)` of new data, in seq order.
    history: VecDeque<(u64, i64, i64)>,
    /// Oldest seq whose new data is still in `history` (exclusive floor).
    history_floor: u64,
    head: u64,
    /// Newest event time among entries dropped at the [`MAX_HISTORY`] cap
    /// without proof that every rule had evaluated them.
    lost_max_time_us: Option<i64>,
}

impl DetectionGate {
    pub fn new(state_dir: Option<PathBuf>, head: u64) -> Result<Self> {
        let state_path = state_dir.map(|dir| dir.join(STATE_FILE));
        let rules = match &state_path {
            Some(path) if path.is_file() => {
                let persisted: Persisted = serde_json::from_slice(&std::fs::read(path)?).context("detection watermarks do not parse")?;
                persisted.rules
            }
            _ => BTreeMap::new(),
        };
        // Data before `head` is not in the history: rules whose watermark is
        // older than `head` cannot prove a skip and will simply run.
        Ok(Self { state_path, inner: Mutex::new(Inner { rules, history: VecDeque::new(), history_floor: head, head, lost_max_time_us: None }) })
    }

    /// Seed the history with the live parts' `(min, max)` event times at the
    /// start head. Rows already in the log before this process started may
    /// belong to windows no rule has evaluated yet; without the seed a
    /// persisted watermark at this head would skip them.
    pub fn seed(&self, ranges: impl IntoIterator<Item = (i64, i64)>) {
        let mut inner = self.inner.lock().expect("detection gate");
        let head = inner.head;
        for (min, max) in ranges {
            inner.history.push_back((head, min, max));
        }
        inner.cap_history();
    }

    /// Record a catch-up's new data (call after every `refresh`).
    pub fn observe(&self, head: u64, advance: &Advance) {
        let mut inner = self.inner.lock().expect("detection gate");
        for (min, max) in &advance.new_data {
            inner.history.push_back((head, *min, *max));
        }
        inner.head = inner.head.max(head);
        inner.cap_history();
    }

    /// Decide whether to run `request`'s window and which late windows to
    /// re-run, at the current head.
    pub fn plan(&self, request: &PlanRequest) -> Plan {
        let inner = self.inner.lock().expect("detection gate");
        let head = inner.head;
        let lost = inner.lost_max_time_us;
        let Some(mark) = inner.rules.get(&request.rule_id).copied() else {
            return Plan { run: true, reason: "no_watermark", log_seq: head, rerun_windows: Vec::new() };
        };
        if mark.log_seq < inner.history_floor {
            // The history no longer reaches this rule's last run: we cannot
            // prove nothing landed, and cannot bound late rows. Run, and
            // re-evaluate the rule's whole evaluated horizon conservatively.
            return Plan {
                run: true,
                reason: "history_truncated",
                log_seq: head,
                rerun_windows: vec![RerunWindow { start_us: request.window_start_us.min(mark.evaluated_through_us), end_us: mark.evaluated_through_us }]
                    .into_iter()
                    .filter(|window| window.start_us < request.window_start_us)
                    .collect(),
            };
        }
        // Data dropped at the history cap may reach past this rule's
        // evaluated horizon: it cannot prove a skip.
        let mut run = inner.lost_max_time_us.is_some_and(|lost| lost > mark.evaluated_through_us);
        let mut late: Vec<(i64, i64)> = Vec::new();
        for (seq, min, max) in &inner.history {
            let overlaps = *min <= request.window_end_us && *max >= request.window_start_us;
            // Unseen by seq, or seen but past what the rule evaluated.
            if overlaps && (*seq > mark.log_seq || *max > mark.evaluated_through_us) {
                run = true;
            }
            if *seq <= mark.log_seq {
                continue;
            }
            // Rows at or before what the rule already evaluated are late.
            let late_end = (*max).min(mark.evaluated_through_us).min(request.window_start_us - 1);
            if *min <= late_end {
                late.push((*min, late_end));
            }
        }
        let grid = request.grid_us.unwrap_or(request.window_end_us - request.window_start_us + 1).max(1);
        let mut windows: Vec<RerunWindow> = Vec::new();
        late.sort_unstable();
        for (min, max) in late {
            let start = min.div_euclid(grid) * grid;
            let end = (max.div_euclid(grid) + 1) * grid - 1;
            match windows.last_mut() {
                Some(last) if start <= last.end_us + 1 => last.end_us = last.end_us.max(end),
                _ => windows.push(RerunWindow { start_us: start, end_us: end }),
            }
        }
        if windows.len() > MAX_RERUN_WINDOWS {
            let start = windows.first().map(|window| window.start_us).unwrap_or_default();
            let end = windows.last().map(|window| window.end_us).unwrap_or_default();
            windows = vec![RerunWindow { start_us: start, end_us: end }];
        }
        let truncated = lost.is_some_and(|lost| lost > mark.evaluated_through_us);
        Plan {
            run,
            reason: if truncated { "history_truncated" } else if run { "new_data_in_window" } else { "no_new_data" },
            log_seq: head,
            rerun_windows: windows,
        }
    }

    /// Record a completed run (and its re-runs) at `log_seq`.
    pub fn commit(&self, request: &CommitRequest) -> Result<()> {
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX));
        self.commit_at(request, now_us)
    }

    /// [`Self::commit`] at process time `now_us`. NAN-3289 P2-1: a commit
    /// can only move a watermark to what this process has seen (`log_seq`
    /// at most the observed head, which every `plan` hands out) and to
    /// event time at most [`MAX_COMMIT_SKEW_US`] past now; anything further
    /// would permanently skip the rule's future windows.
    pub fn commit_at(&self, request: &CommitRequest, now_us: i64) -> Result<()> {
        if !valid_rule_id(&request.rule_id) {
            return Err(refused("detection rule id violates its bound"));
        }
        if request.evaluated_through_us > now_us.saturating_add(MAX_COMMIT_SKEW_US) {
            return Err(refused("detection commit evaluates past the present (evaluated_through_us is in the future)"));
        }
        let mut inner = self.inner.lock().expect("detection gate");
        if request.log_seq > inner.head {
            return Err(refused(format!(
                "detection commit log_seq {} is past the observed head {}", request.log_seq, inner.head
            )));
        }
        if !inner.rules.contains_key(&request.rule_id) && inner.rules.len() >= MAX_RULES {
            return Err(refused("detection gate tracks its maximum number of rules; reset stale rules"));
        }
        let mut next_rules = inner.rules.clone();
        let entry = next_rules
            .entry(request.rule_id.clone())
            .or_insert(Watermark { log_seq: request.log_seq, evaluated_through_us: request.evaluated_through_us });
        entry.log_seq = entry.log_seq.max(request.log_seq);
        entry.evaluated_through_us = entry.evaluated_through_us.max(request.evaluated_through_us);
        // Persist before changing the in-memory gate. If the private state
        // volume refuses the write, the caller must see the old head and
        // replay the late part again rather than silently forgetting it.
        if let Some(path) = &self.state_path {
            let bytes = serde_json::to_vec(&Persisted { rules: next_rules.clone() })?;
            let temporary = path.with_extension("json.tmp");
            std::fs::write(&temporary, bytes)?;
            std::fs::rename(temporary, path)?;
        }
        inner.rules = next_rules;
        // History every rule has seen by seq AND by event time is no longer
        // needed; rows reaching past some rule's horizon stay.
        let oldest = inner.rules.values().map(|mark| mark.log_seq).min().unwrap_or(inner.head);
        let horizon = inner.rules.values().map(|mark| mark.evaluated_through_us).min().unwrap_or(i64::MAX);
        inner.history.retain(|(seq, _, max)| *seq > oldest || *max > horizon);
        inner.history_floor = inner.history_floor.max(oldest.min(inner.head));
        Ok(())
    }
}

impl DetectionGate {
    /// Drop watermarks (operator reset): the named rules, or all with
    /// `all`. A dropped rule plans `no_watermark` (it runs). Returns how
    /// many were dropped. Persisted before the in-memory gate changes.
    pub fn reset(&self, request: &ResetRequest) -> Result<usize> {
        if request.all == !request.rule_ids.is_empty() {
            return Err(refused("reset names either rule_ids or all, not both or neither"));
        }
        if request.rule_ids.len() > MAX_RESET_RULES || !request.rule_ids.iter().all(|id| valid_rule_id(id)) {
            return Err(refused("reset rule ids violate their bound"));
        }
        let mut inner = self.inner.lock().expect("detection gate");
        let mut next_rules = inner.rules.clone();
        if request.all {
            next_rules.clear();
        } else {
            for id in &request.rule_ids {
                next_rules.remove(id);
            }
        }
        let dropped = inner.rules.len() - next_rules.len();
        if let Some(path) = &self.state_path {
            let bytes = serde_json::to_vec(&Persisted { rules: next_rules.clone() })?;
            let temporary = path.with_extension("json.tmp");
            std::fs::write(&temporary, bytes)?;
            std::fs::rename(temporary, path)?;
        }
        inner.rules = next_rules;
        Ok(dropped)
    }
}

fn valid_rule_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_RULE_ID_BYTES && !id.chars().any(char::is_control)
}

impl Inner {
    fn cap_history(&mut self) {
        while self.history.len() > MAX_HISTORY {
            if let Some((seq, _, max)) = self.history.pop_front() {
                self.history_floor = self.history_floor.max(seq);
                self.lost_max_time_us = Some(self.lost_max_time_us.map_or(max, |lost| lost.max(max)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advance(ranges: &[(i64, i64)]) -> Advance {
        Advance { entries: 1, new_data: ranges.to_vec(), newest_appended_at_ms: Some(0) }
    }

    fn plan(gate: &DetectionGate, start: i64, end: i64) -> Plan {
        gate.plan(&PlanRequest { rule_id: "r".into(), window_start_us: start, window_end_us: end, grid_us: Some(100) })
    }

    #[test]
    fn idle_rules_skip_and_late_rows_rerun_their_windows() {
        let gate = DetectionGate::new(None, 0).unwrap();
        // First run: no watermark.
        assert_eq!(plan(&gate, 0, 99).reason, "no_watermark");
        gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: 0, evaluated_through_us: 99 }).unwrap();
        // Nothing arrived: the next window is skipped.
        let skipped = plan(&gate, 100, 199);
        assert!(!skipped.run && skipped.rerun_windows.is_empty());
        // New in-window data plus a late row for [0, 99].
        gate.observe(1, &advance(&[(150, 160), (40, 45)]));
        let due = plan(&gate, 100, 199);
        assert!(due.run);
        assert_eq!(due.rerun_windows, vec![RerunWindow { start_us: 0, end_us: 99 }]);
        gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: due.log_seq, evaluated_through_us: 199 }).unwrap();
        // Everything seen: skip again, no re-runs.
        let idle = plan(&gate, 200, 299);
        assert!(!idle.run && idle.rerun_windows.is_empty());
    }

    /// #4611: rows for window N+1 that landed before window N was planned
    /// sit at or below the seq window N committed; window N+1 must still run.
    #[test]
    fn rows_for_the_next_window_that_landed_early_are_not_skipped() {
        let gate = DetectionGate::new(None, 0).unwrap();
        gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: 0, evaluated_through_us: 99 }).unwrap();
        // Seq 1 carries rows for window [100, 199] and for window [200, 299].
        gate.observe(1, &advance(&[(150, 250)]));
        let window_n = plan(&gate, 100, 199);
        assert!(window_n.run);
        gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: window_n.log_seq, evaluated_through_us: 199 }).unwrap();
        // Nothing new by seq, but seq 1's rows reach into [200, 299].
        let window_next = plan(&gate, 200, 299);
        assert!(window_next.run, "early rows for the next window were skipped");
        assert!(window_next.rerun_windows.is_empty());
        gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: window_next.log_seq, evaluated_through_us: 299 }).unwrap();
        // Now every row is evaluated: skip, and the history is pruned.
        assert!(!plan(&gate, 300, 399).run);
        assert!(gate.inner.lock().unwrap().history.is_empty());
    }

    /// Parts already live when the process starts can hold rows for windows
    /// a persisted watermark at the same head has not evaluated yet.
    #[test]
    fn seeded_live_parts_keep_unevaluated_windows_running() {
        let dir = tempfile::tempdir().unwrap();
        let gate = DetectionGate::new(Some(dir.path().to_path_buf()), 5).unwrap();
        gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: 5, evaluated_through_us: 99 }).unwrap();
        let respawned = DetectionGate::new(Some(dir.path().to_path_buf()), 5).unwrap();
        respawned.seed([(0, 50), (120, 130)]);
        assert!(respawned.plan(&PlanRequest { rule_id: "r".into(), window_start_us: 100, window_end_us: 199, grid_us: Some(100) }).run);
        assert!(!respawned.plan(&PlanRequest { rule_id: "r".into(), window_start_us: 200, window_end_us: 299, grid_us: Some(100) }).run);
    }

    #[test]
    fn history_cap_drops_cannot_prove_a_skip() {
        let gate = DetectionGate::new(None, 0).unwrap();
        gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: 0, evaluated_through_us: 99 }).unwrap();
        gate.observe(1, &advance(&[(150, 150)]));
        gate.observe(2, &advance(&vec![(0, 10); MAX_HISTORY]));
        let due = plan(&gate, 200, 299);
        assert!(due.run);
        assert_eq!(due.reason, "history_truncated");
    }

    #[test]
    fn watermarks_persist_across_a_respawn() {
        let dir = tempfile::tempdir().unwrap();
        let gate = DetectionGate::new(Some(dir.path().to_path_buf()), 5).unwrap();
        gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: 5, evaluated_through_us: 99 }).unwrap();
        let respawned = DetectionGate::new(Some(dir.path().to_path_buf()), 5).unwrap();
        assert!(!plan(&respawned, 100, 199).run);
        // A respawn at a later head cannot prove a skip for older watermarks.
        let later = DetectionGate::new(Some(dir.path().to_path_buf()), 9).unwrap();
        assert!(plan(&later, 100, 199).run);
    }

    #[test]
    fn failed_state_write_keeps_late_replay_watermark_uncommitted() {
        let dir = tempfile::tempdir().unwrap();
        let gate = DetectionGate::new(Some(dir.path().to_path_buf()), 1).unwrap();
        gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: 1, evaluated_through_us: 99 }).unwrap();
        gate.observe(2, &advance(&[(40, 45)]));
        assert_eq!(plan(&gate, 100, 199).rerun_windows.len(), 1);
        std::fs::remove_dir_all(dir.path()).unwrap();
        assert!(gate.commit(&CommitRequest { rule_id: "r".into(), log_seq: 2, evaluated_through_us: 199 }).is_err());
        let mark = gate.inner.lock().unwrap().rules["r"];
        assert_eq!((mark.log_seq, mark.evaluated_through_us), (1, 99));
        assert_eq!(plan(&gate, 100, 199).rerun_windows.len(), 1);
    }

    /// NAN-3289 P2-1: the blinding commit is refused, and a later window
    /// with new data still runs.
    #[test]
    fn commits_past_the_head_or_the_clock_are_refused() {
        let now = 1_000_000_000_000_i64;
        let gate = DetectionGate::new(None, 3).unwrap();
        let blind = CommitRequest { rule_id: "r".into(), log_seq: u64::MAX, evaluated_through_us: i64::MAX };
        assert!(gate.commit_at(&blind, now).unwrap_err().downcast_ref::<GateRefused>().is_some());
        let past_head = CommitRequest { rule_id: "r".into(), log_seq: 4, evaluated_through_us: now };
        assert!(gate.commit_at(&past_head, now).unwrap_err().downcast_ref::<GateRefused>().is_some());
        let future = CommitRequest { rule_id: "r".into(), log_seq: 3, evaluated_through_us: now + 86_400_000_000 };
        assert!(gate.commit_at(&future, now).unwrap_err().downcast_ref::<GateRefused>().is_some());
        // Nothing was recorded: the rule still runs.
        assert_eq!(gate.plan(&PlanRequest { rule_id: "r".into(), window_start_us: now, window_end_us: now + 99, grid_us: None }).reason,
            "no_watermark");
        // Within the skew, at the head: accepted.
        gate.commit_at(&CommitRequest { rule_id: "r".into(), log_seq: 3, evaluated_through_us: now + MAX_COMMIT_SKEW_US }, now).unwrap();
        // New data in the next window runs.
        gate.observe(4, &advance(&[(now + MAX_COMMIT_SKEW_US + 10, now + MAX_COMMIT_SKEW_US + 20)]));
        let next = gate.plan(&PlanRequest { rule_id: "r".into(), window_start_us: now + MAX_COMMIT_SKEW_US + 1,
            window_end_us: now + MAX_COMMIT_SKEW_US + 100, grid_us: None });
        assert!(next.run, "{next:?}");
    }

    #[test]
    fn rule_cap_refuses_new_ids_and_reset_clears_them() {
        let dir = tempfile::tempdir().unwrap();
        let gate = DetectionGate::new(Some(dir.path().to_path_buf()), 1).unwrap();
        {
            let mut inner = gate.inner.lock().unwrap();
            for i in 0..MAX_RULES {
                inner.rules.insert(format!("junk-{i}"), Watermark { log_seq: 1, evaluated_through_us: 0 });
            }
        }
        let real = CommitRequest { rule_id: "real".into(), log_seq: 1, evaluated_through_us: 99 };
        assert!(gate.commit(&real).unwrap_err().downcast_ref::<GateRefused>().is_some());
        // Reset validation.
        assert!(gate.reset(&ResetRequest { rule_ids: vec![], all: false }).is_err());
        assert!(gate.reset(&ResetRequest { rule_ids: vec!["x".into()], all: true }).is_err());
        assert!(gate.reset(&ResetRequest { rule_ids: vec![String::new()], all: false }).is_err());
        assert_eq!(gate.reset(&ResetRequest { rule_ids: vec!["junk-0".into(), "absent".into()], all: false }).unwrap(), 1);
        assert_eq!(gate.reset(&ResetRequest { rule_ids: vec![], all: true }).unwrap(), MAX_RULES - 1);
        gate.commit(&real).unwrap();
        // The reset persisted: a respawn sees only the real rule.
        let respawned = DetectionGate::new(Some(dir.path().to_path_buf()), 1).unwrap();
        assert_eq!(respawned.inner.lock().unwrap().rules.len(), 1);
        // A reset rule runs again.
        gate.reset(&ResetRequest { rule_ids: vec!["real".into()], all: false }).unwrap();
        assert_eq!(gate.plan(&PlanRequest { rule_id: "real".into(), window_start_us: 0, window_end_us: 99, grid_us: None }).reason,
            "no_watermark");
    }
}

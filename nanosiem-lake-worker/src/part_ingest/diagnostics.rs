// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded flush histories shared with the heartbeat, independently of ingest IO.
use super::timing::{ElapsedGuard, Timings};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Instant,
};

const HISTORY_LIMIT: usize = 32;

#[derive(Clone, Default)]
pub struct PipelineDiagnostics {
    pub(super) state: Arc<Mutex<PipelineSnapshot>>,
    stages: Timings,
    pub(super) operations: Timings,
}

#[derive(Default)]
pub(super) struct PipelineSnapshot {
    pub rows: usize,
    pub bytes: u64,
    pub buffered_since: Option<Instant>,
    pub flights: usize,
    pub oldest_flush_ms: Option<i64>,
    pub oldest_background: Option<Arc<Mutex<FlushStage>>>,
    pub foreground: Option<Arc<Mutex<FlushStage>>>,
    pub tracking_oldest: bool,
    pub stage: &'static str,
    pub stage_since: Option<Instant>,
    pub last_completed: Option<Value>,
    pub occupancy: Value,
    pub occupancy_observed: Option<Instant>,
    pub queue: Value,
    pub queue_observed: Option<Instant>,
}

pub(super) struct FlushStage {
    pub stage: &'static str,
    pub since: Instant,
    rows: usize,
    bytes: u64,
    parts: Option<usize>,
    part_rows: Option<u64>,
    part_file_bytes: Option<u64>,
    transitions: u64,
    history: VecDeque<Value>,
    timings: Timings,
    timer: Option<ElapsedGuard>,
}

impl FlushStage {
    pub(super) fn set(&mut self, stage: &'static str) {
        if self.stage == stage {
            return;
        }
        let us = u64::try_from(self.since.elapsed().as_micros()).unwrap_or(u64::MAX);
        if self.history.len() == HISTORY_LIMIT {
            self.history.pop_front();
        }
        self.history
            .push_back(json!({"stage": self.stage, "elapsed_us": us}));
        self.transitions = self.transitions.saturating_add(1);
        self.timer.take();
        self.stage = stage;
        self.since = Instant::now();
        if stage != "complete" {
            self.timer = Some(self.timings.start(stage));
        }
    }

    pub(super) fn built(&mut self, finished: &[super::writer::FinishedPart]) {
        self.parts = Some(finished.len());
        self.part_rows = Some(finished.iter().map(|p| p.record.rows).sum());
        self.part_file_bytes = Some(
            finished
                .iter()
                .flat_map(|p| p.record.files.all())
                .map(|(_, _, size)| size)
                .sum(),
        );
    }

    fn snapshot(&self) -> Value {
        json!({"stage": self.stage, "stage_age_seconds": if self.stage == "complete" { 0.0 } else { self.since.elapsed().as_secs_f64() },
            "rows": self.rows, "arrow_bytes": self.bytes, "parts": self.parts, "part_rows": self.part_rows,
            "part_file_bytes": self.part_file_bytes, "transitions_total": self.transitions,
            "history_dropped": self.transitions.saturating_sub(self.history.len() as u64), "history": self.history})
    }
}

impl PipelineDiagnostics {
    pub(super) fn new_flush(&self, rows: usize, bytes: u64) -> Arc<Mutex<FlushStage>> {
        let stage = "seal_rejections_and_skips";
        Arc::new(Mutex::new(FlushStage {
            stage,
            since: Instant::now(),
            rows,
            bytes,
            parts: None,
            part_rows: None,
            part_file_bytes: None,
            transitions: 0,
            history: VecDeque::new(),
            timings: self.stages.clone(),
            timer: Some(self.stages.start(stage)),
        }))
    }

    pub fn snapshot(&self) -> Value {
        let state = self.state.lock().expect("pipeline diagnostics");
        let background = state
            .oldest_background
            .as_ref()
            .map(|stage| stage.lock().expect("flush diagnostics"));
        let stage = background.as_ref().map_or(state.stage, |stage| stage.stage);
        let stage_age = background.as_ref().map_or_else(
            || {
                state
                    .stage_since
                    .map_or(0.0, |at| at.elapsed().as_secs_f64())
            },
            |stage| stage.since.elapsed().as_secs_f64(),
        );
        json!({"buffered_rows": state.rows, "buffered_bytes": state.bytes,
            "buffered_age_seconds": state.buffered_since.map_or(0.0, |at| at.elapsed().as_secs_f64()),
            "flushes_in_flight": state.flights,
            "oldest_flush_age_seconds": state.oldest_flush_ms.map_or(0.0, |ms| (chrono::Utc::now().timestamp_millis() - ms).max(0) as f64 / 1000.0),
            "oldest_flush_stage": (state.flights > 0).then_some(stage),
            "oldest_flush_stage_age_seconds": if state.flights > 0 { stage_age } else { 0.0 },
            "oldest_flush": background.as_ref().map(|stage| stage.snapshot()), "last_completed_flush": state.last_completed,
            "flush_stage_timings": self.stages.snapshot(), "operation_timings": self.operations.snapshot(),
            "occupancy": state.occupancy, "occupancy_age_seconds": state.occupancy_observed.map(|at| at.elapsed().as_secs_f64()), "queue_sample": state.queue,
            "queue_sample_age_seconds": state.queue_observed.map(|at| at.elapsed().as_secs_f64())})
    }

    pub(super) fn stage(&self, stage: &'static str) {
        let mut state = self.state.lock().expect("pipeline diagnostics");
        let progress = if state.tracking_oldest {
            &state.oldest_background
        } else {
            &state.foreground
        };
        if let Some(progress) = progress {
            progress.lock().expect("flush diagnostics").set(stage);
        }
        if state.stage != stage {
            state.stage = stage;
            state.stage_since = Some(Instant::now());
        }
    }

    pub(super) fn completed(&self, progress: &Arc<Mutex<FlushStage>>) {
        // Copy before taking state: never hold progress then state together.
        let snapshot = {
            let mut progress = progress.lock().expect("flush diagnostics");
            progress.set("complete");
            progress.snapshot()
        };
        self.state
            .lock()
            .expect("pipeline diagnostics")
            .last_completed = Some(snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_stage_history_is_bounded_across_retries() {
        let diagnostics = PipelineDiagnostics::default();
        let progress = diagnostics.new_flush(17, 4096);
        for index in 0..100 {
            progress.lock().unwrap().set(if index % 2 == 0 {
                "build_parts"
            } else {
                "publish_parts"
            });
        }
        diagnostics.completed(&progress);
        let snapshot = diagnostics.snapshot();
        let completed = &snapshot["last_completed_flush"];
        assert_eq!(
            completed["history"].as_array().unwrap().len(),
            HISTORY_LIMIT
        );
        assert_eq!(completed["transitions_total"], 101);
        assert_eq!(completed["history_dropped"], 101 - HISTORY_LIMIT);
        assert_eq!(completed["rows"], 17);
        assert_eq!(
            snapshot["flush_stage_timings"]["publish_parts"]["in_flight"],
            0
        );
    }
}

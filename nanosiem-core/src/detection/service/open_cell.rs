// SPDX-License-Identifier: AGPL-3.0-or-later

//! Open single-tenant scheduler adapter for the lean cell protocol.
//! Uses the existing cron claims, finding logger and durable alert dispatcher.

use super::{DetectionError, DetectionService};
use crate::models::{Alert, DetectionRule};
use crate::search::{LakeDetectionPlan, TimeRangeInput};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

impl DetectionService {
    /// Preserve dedicated PostgreSQL repositories and signal logging while
    /// routing scheduler queries and prevalence to the cell's detect leaf.
    /// Hosted callers use their independently provisioned tenant runtime.
    pub fn open_cell_scheduler_view(&self) -> Result<Self, DetectionError> {
        if !self.search_service.serves_lake_cell() {
            return Ok(self.clone());
        }
        if std::env::var("DEPLOYMENT_MODE").is_ok_and(|mode| mode == "enterprise_shared") {
            return Err(DetectionError::QueryExecutionError(
                "open detection adapter refuses shared mode".into(),
            ));
        }
        let mut service = self.clone();
        service.search_service = self
            .search_service
            .detection_lane_view()
            .map_err(|error| DetectionError::QueryExecutionError(error.to_string()))?;
        Ok(service)
    }

    /// Cell plans identify late part windows. Queue those durably before
    /// evaluating the current tick; gate commits follow successful side effects.
    /// Always evaluate the current tick, including after a rule edit or Live →
    /// Alerting promotion without a new part head. Risk also changes with time.
    pub(crate) async fn execute_scheduled_window(
        &self,
        rule: &DetectionRule,
        mut time_range: TimeRangeInput,
    ) -> Result<Option<Alert>, DetectionError> {
        if self.search_service.serves_lake_cell()
            && !rule.is_retro_hunt()
            && rule
                .dataset
                .as_deref()
                .is_some_and(|dataset| dataset.eq_ignore_ascii_case("risk"))
        {
            // Risk is a rolling seven-day entity aggregate, not events from
            // only this cron tick. Decay and clears still come from this
            // dedicated view's PostgreSQL configuration provider.
            time_range.start = time_range
                .end
                .checked_sub_signed(chrono::Duration::days(7))
                .ok_or_else(|| {
                    DetectionError::QueryExecutionError("risk window out of range".into())
                })?;
        }
        if !self.search_service.serves_lake_cell()
            || rule.is_retro_hunt()
            || rule
                .dataset
                .as_deref()
                .is_some_and(|dataset| !dataset.eq_ignore_ascii_case("logs"))
        {
            return self.execute_rule(rule, Some(time_range)).await;
        }
        let rule_id = rule.id.to_string();
        let plan = match self
            .search_service
            .lake_cell_detection_plan(
                &rule_id,
                time_range.start.timestamp_micros(),
                time_range.end.timestamp_micros(),
                None,
            )
            .await
        {
            Ok(plan) => plan,
            Err(error) => {
                tracing::warn!(%error, %rule_id, "Cell detection plan unavailable; evaluating current window");
                None
            }
        };
        if let Some(plan) = &plan {
            for replay in replay_windows(plan, &time_range)? {
                // Head is part of the repair identity: a second late Add for
                // the same time window must enqueue a new repair job.
                let identity = format!(
                    "open-cell:{}:{}:{}",
                    plan.log_seq,
                    replay.start.timestamp_micros(),
                    replay.end.timestamp_micros()
                );
                sqlx::query("INSERT INTO detection_late_replay_jobs \
                    (rule_id,tenant_id,bronze_store_id,batch_sha256,window_start,window_end) \
                    VALUES ($1,'scheduler','open-cell:late-part:v1',$2,$3,$4) ON CONFLICT DO NOTHING")
                    .bind(rule.id).bind(hex::encode(Sha256::digest(identity.as_bytes())))
                    .bind(replay.start).bind(replay.end).execute(&self.pg_pool).await?;
            }
        }
        let result = self.execute_rule(rule, Some(time_range.clone())).await?;
        if let (Some(plan), Some(committer)) =
            (plan, self.search_service.lake_cell_detection_committer())
        {
            // Failure is conservative: the next plan can report these windows
            // again. Alert/finding dedup and repair-job identities make retry safe.
            if let Err(error) = committer
                .commit(&rule_id, plan.log_seq, time_range.end.timestamp_micros())
                .await
            {
                tracing::warn!(%error, %rule_id, "Cell detection gate commit failed; replay remains eligible");
            }
        }
        Ok(result)
    }
}

fn replay_windows(
    plan: &LakeDetectionPlan,
    current: &TimeRangeInput,
) -> Result<Vec<TimeRangeInput>, DetectionError> {
    if plan.rerun_windows.len() > 128 {
        return Err(DetectionError::QueryExecutionError(
            "cell detection repair plan exceeds 128 windows".into(),
        ));
    }
    let mut windows = Vec::new();
    for window in &plan.rerun_windows {
        let end_us = window.end_us.min(current.start.timestamp_micros());
        if window.start_us >= end_us {
            continue;
        }
        let start = DateTime::<Utc>::from_timestamp_micros(window.start_us).ok_or_else(|| {
            DetectionError::QueryExecutionError("cell repair start out of range".into())
        })?;
        let end = DateTime::<Utc>::from_timestamp_micros(end_us).ok_or_else(|| {
            DetectionError::QueryExecutionError("cell repair end out of range".into())
        })?;
        windows.push(TimeRangeInput::new(start, end));
    }
    Ok(windows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::LakeDetectionRerunWindow;
    #[test]
    fn late_windows_are_clamped_and_bounded() {
        let current = TimeRangeInput::new(
            DateTime::from_timestamp_micros(100).unwrap(),
            DateTime::from_timestamp_micros(200).unwrap(),
        );
        let mut plan = LakeDetectionPlan {
            run: false,
            reason: "fixture".into(),
            log_seq: 3,
            rerun_windows: vec![
                LakeDetectionRerunWindow {
                    start_us: 50,
                    end_us: 150,
                },
                LakeDetectionRerunWindow {
                    start_us: 150,
                    end_us: 200,
                },
            ],
        };
        let windows = replay_windows(&plan, &current).unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].start.timestamp_micros(), 50);
        assert_eq!(windows[0].end.timestamp_micros(), 100);
        plan.rerun_windows = vec![
            LakeDetectionRerunWindow {
                start_us: 0,
                end_us: 1
            };
            129
        ];
        assert!(replay_windows(&plan, &current).is_err());
    }
}

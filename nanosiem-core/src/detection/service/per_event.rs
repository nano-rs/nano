// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5424: per-event persistence failures are handled per event.
//!
//! In the per-event paths (Live `detection_matches` rows, per-event alerts)
//! each event's writes are independent:
//!
//! - PostgreSQL refusing an event's DATA (SQLSTATE 22xxx / 54xxx) is handled
//!   for that event alone, and the batch continues, like `DuplicateAlert`.
//!   Retrying would write the same bytes and fail the same way. The event is
//!   never silently dropped:
//!   - a row in `detection_skipped_events` records the rule, the event's id
//!     and time, the window and the SQLSTATE (never the event's content);
//!   - in alerting mode, a minimal reference alert (event id, time, source
//!     type) is raised so an analyst still sees the match;
//!   - an event with no reference alert is NOT recorded as matched, so a
//!     later run (sliding lookback, retro re-hunt) can pick it up again.
//! - Any other error (connection lost mid-batch, ...) does not skip events
//!   silently: the batch continues, then the window fails as a whole and is
//!   retried by the scheduler. Alerts already created dedup on the retry.
//! - If every event in the batch was refused and none got a reference alert,
//!   the window fails as well, so the scheduler's bounded retry and
//!   coverage-gap accounting apply.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use metrics::counter;
use tracing::error;

use super::DetectionService;
use crate::detection::DetectionError;
use crate::models::{DetectionRule, NewAlert};

/// One event whose writes PostgreSQL refused for its data.
#[derive(Debug)]
struct SkippedEvent {
    event_id: String,
    event_timestamp: Option<DateTime<Utc>>,
    source_type: Option<String>,
    sqlstate: Option<String>,
}

/// Per-event failures collected over one batch.
#[derive(Debug, Default)]
pub(super) struct PerEventFailures {
    attempted: usize,
    window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    skipped: Vec<SkippedEvent>,
    first_skipped: Option<DetectionError>,
    first_retryable: Option<DetectionError>,
}

/// What a settled batch tells the caller.
#[derive(Debug, Default)]
pub(super) struct PerEventOutcome {
    /// Ids (`matched_event_id`) of events that must NOT be recorded as
    /// matched: refused and without a reference alert.
    pub unrecorded: HashSet<String>,
}

impl PerEventOutcome {
    /// `events` minus the ones that must not be recorded as matched.
    pub(super) fn recordable(&self, events: &[serde_json::Value]) -> Vec<serde_json::Value> {
        if self.unrecorded.is_empty() {
            return events.to_vec();
        }
        events
            .iter()
            .filter(|e| !self.unrecorded.contains(&super::helpers::matched_event_id(e)))
            .cloned()
            .collect()
    }
}

fn sqlstate(err: &DetectionError) -> Option<String> {
    match err {
        DetectionError::DatabaseError(sqlx::Error::Database(db)) => db.code().map(|c| c.into_owned()),
        _ => None,
    }
}

impl PerEventFailures {
    pub(super) fn new(window: Option<(DateTime<Utc>, DateTime<Utc>)>) -> Self {
        Self { window, ..Self::default() }
    }

    pub(super) fn attempt(&mut self) {
        self.attempted += 1;
    }

    /// Record a failed per-event write.
    pub(super) fn record(&mut self, rule: &DetectionRule, event: &serde_json::Value, err: DetectionError) {
        // Debug-formatted: the id can be event-controlled text.
        let event_id = super::helpers::matched_event_id(event);
        let detail = crate::db::pg_text::pg_safe_error_text(&err.to_string());
        if err.is_persistence_data_error() {
            counter!("nanosiem_detection_events_skipped_total").increment(1);
            error!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                event_id = ?event_id,
                "Matched event could not be persisted; recording it and continuing the batch: {}",
                detail
            );
            self.skipped.push(SkippedEvent {
                event_timestamp: DetectionService::event_field_time(event, "timestamp"),
                source_type: event.get("source_type").and_then(|v| v.as_str()).map(str::to_string),
                sqlstate: sqlstate(&err),
                event_id,
            });
            self.first_skipped.get_or_insert(err);
        } else {
            error!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                event_id = ?event_id,
                "Matched event write failed; the window will be retried: {}",
                detail
            );
            self.first_retryable.get_or_insert(err);
        }
    }

    /// Settle the batch. `reference_alerts` raises a minimal alert per
    /// refused event (alerting mode). `Err` when the window must be retried.
    pub(super) async fn finish(
        self,
        service: &DetectionService,
        rule: &DetectionRule,
        reference_alerts: bool,
    ) -> Result<PerEventOutcome, DetectionError> {
        let mut outcome = PerEventOutcome::default();
        let mut referenced = 0usize;
        let case_permissions = if reference_alerts && !self.skipped.is_empty() {
            service.get_case_permissions(rule).await
        } else {
            None
        };
        for skip in &self.skipped {
            let alert_id = if reference_alerts {
                service.reference_alert(rule, skip, case_permissions.clone()).await
            } else {
                None
            };
            referenced += usize::from(alert_id.is_some());
            if alert_id.is_none() {
                outcome.unrecorded.insert(skip.event_id.clone());
            }
            if let Err(e) = service
                .rule_repo
                .record_skipped_event(
                    rule.id,
                    &skip.event_id,
                    skip.event_timestamp,
                    self.window,
                    skip.sqlstate.as_deref(),
                    "data",
                    alert_id,
                )
                .await
            {
                error!(rule_id = %rule.id, "Failed to record a skipped matched event: {}", e);
            }
        }
        if let Some(err) = self.first_retryable {
            return Err(err);
        }
        let Some(first) = self.first_skipped else {
            return Ok(outcome);
        };
        if self.skipped.len() >= self.attempted && referenced == 0 {
            return Err(first);
        }
        let message = format!(
            "[data] {} of {} matched event(s) could not be stored ({}); recorded in detection_skipped_events{}",
            self.skipped.len(),
            self.attempted,
            first.redacted_summary(),
            if referenced > 0 { ", reference alerts raised" } else { "" }
        );
        if let Err(e) = service.rule_repo.record_rule_error(rule.id, &message).await {
            error!(rule_id = %rule.id, "Failed to record skipped-event error on the rule: {}", e);
        }
        Ok(outcome)
    }
}

impl DetectionService {
    /// A minimal alert for a matched event whose content could not be stored
    /// (NAN-5424): the event id, time and source type, so the match is still
    /// seen and the event can be opened from ClickHouse.
    async fn reference_alert(
        &self,
        rule: &DetectionRule,
        skip: &SkippedEvent,
        case_permissions: Option<crate::extensions::AlertCasePermissions>,
    ) -> Option<uuid::Uuid> {
        let mut event = serde_json::json!({
            "id": skip.event_id,
            "_nano_unstored_event": true,
            "_nano_unstored_reason": match &skip.sqlstate {
                Some(code) => format!("PostgreSQL refused the event content (SQLSTATE {code})"),
                None => "PostgreSQL refused the event content".to_string(),
            },
        });
        if let Some(ts) = skip.event_timestamp {
            event["timestamp"] = serde_json::Value::String(ts.to_rfc3339());
        }
        if let Some(source_type) = &skip.source_type {
            event["source_type"] = serde_json::Value::String(source_type.clone());
        }
        let new_alert = NewAlert {
            rule_id: rule.id,
            severity: rule.severity,
            matched_events: serde_json::Value::Array(vec![event]),
            event_hash: None,
            match_count: Some(1),
        };
        match self.alert_repo.create(&new_alert).await {
            Ok(alert) => {
                self.process_alert_post_create(rule, &alert, case_permissions).await;
                Some(alert.id)
            }
            // Raised by an earlier run of the same window: the match is seen.
            Err(crate::db::repository::alerts::AlertRepositoryError::DuplicateAlert(..)) => {
                Some(uuid::Uuid::nil())
            }
            Err(e) => {
                error!(rule_id = %rule.id, "Failed to raise a reference alert for an unstored event: {}", e);
                None
            }
        }
    }

    /// Live mode, per-event rules: one `detection_matches` row per event,
    /// with per-event failure isolation (NAN-5424).
    pub(super) async fn store_detection_matches_per_event(
        &self,
        rule: &DetectionRule,
        events: &[serde_json::Value],
        window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    ) -> Result<PerEventOutcome, DetectionError> {
        let mut failures = PerEventFailures::new(window);
        for event in events {
            failures.attempt();
            if let Err(e) = self.store_detection_match(rule, std::slice::from_ref(event)).await {
                failures.record(rule, event, e);
            }
        }
        failures.finish(self, rule, false).await
    }
}

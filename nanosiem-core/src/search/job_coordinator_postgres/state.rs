// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded lease transitions, compatible with the existing coordinator client.
use super::{DurableJobStoreError, HostedCoordinatorPolicy, identifier, rejected};
use crate::search::{
    SearchRequest,
    job_signing::DurableJobEnvelope,
    jobs::{DurableLakeTask, DurableQueryResourceClass, small_job_lane},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

const MAX_COUNTER: u64 = 9_007_199_254_740_991;
pub(super) const DEADLINE_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub id: Uuid,
    pub payload: String,
    pub status: String,
    pub created: i64,
    pub attempt: u32,
    pub fence: u64,
    pub owner: Option<String>,
    pub expires: Option<i64>,
    pub result: Option<String>,
    pub completed: Option<i64>,
    pub progress: u32,
    pub phase: Option<String>,
    pub error: Option<String>,
    pub execution_failures: u32,
    pub lease_recoveries: u32,
    pub resource_class: DurableQueryResourceClass,
}
impl Job {
    pub fn queued(id: Uuid, payload: String, now: i64) -> Self {
        Self {
            id,
            payload,
            status: "queued".into(),
            created: now,
            attempt: 0,
            fence: 0,
            owner: None,
            expires: None,
            result: None,
            completed: None,
            progress: 0,
            phase: None,
            error: None,
            execution_failures: 0,
            lease_recoveries: 0,
            resource_class: DurableQueryResourceClass::Medium,
        }
    }
    pub fn validate(&self) -> Result<(), DurableJobStoreError> {
        if self.id.is_nil()
            || self.payload.len() > 65_536
            || self.created <= 0
            || self.fence > MAX_COUNTER
            || self.created.checked_add(DEADLINE_MS).is_none()
            || self.progress > 100
            || self.result.as_ref().is_some_and(|r| r.len() > 65_536)
            || self.error.as_ref().is_some_and(|e| e.len() > 256)
            || !matches!(
                self.status.as_str(),
                "queued" | "running" | "completed" | "cancelled" | "failed"
            )
        {
            return Err(rejected());
        }
        Ok(())
    }
    pub fn small(&self) -> bool {
        let Ok(envelope) = serde_json::from_str::<DurableJobEnvelope>(&self.payload) else {
            return false;
        };
        let Ok(request) = serde_json::from_str::<SearchRequest>(&envelope.request_json) else {
            return false;
        };
        let Ok(task) = serde_json::from_str::<DurableLakeTask>(&envelope.task_json) else {
            return false;
        };
        small_job_lane(
            &task,
            request.time_range.start,
            request.time_range.end,
            self.resource_class == DurableQueryResourceClass::Large,
        )
    }
    fn advance_fence(&mut self) -> Result<(), DurableJobStoreError> {
        self.fence = self
            .fence
            .checked_add(1)
            .filter(|n| *n <= MAX_COUNTER)
            .ok_or_else(rejected)?;
        Ok(())
    }
    pub fn claim(&mut self, owner: &str, expires: i64) -> Result<(), DurableJobStoreError> {
        self.advance_fence()?;
        self.attempt = self.attempt.checked_add(1).ok_or_else(rejected)?;
        self.status = "running".into();
        self.owner = Some(owner.into());
        self.expires = Some(expires.min(self.created + DEADLINE_MS));
        self.error = None;
        self.progress = 0;
        self.phase = Some("claimed".into());
        self.completed = None;
        Ok(())
    }
    fn end(&mut self, status: &str, now: i64) {
        self.status = status.into();
        self.owner = None;
        self.expires = None;
        self.progress = 0;
        self.completed = if status == "queued" { None } else { Some(now) };
    }
    pub fn expire(
        &mut self,
        now: i64,
        policy: HostedCoordinatorPolicy,
    ) -> Result<(), DurableJobStoreError> {
        self.advance_fence()?;
        if now >= self.created + DEADLINE_MS {
            self.error = Some("Search job deadline exceeded".into());
            self.end("failed", now);
        } else {
            self.lease_recoveries = self.lease_recoveries.checked_add(1).ok_or_else(rejected)?;
            self.error = Some("runner lease expired".into());
            self.end(
                if self.lease_recoveries < policy.max_lease_recoveries {
                    "queued"
                } else {
                    "failed"
                },
                now,
            );
        }
        Ok(())
    }
    fn owned(&self, c: &Value, now: i64) -> bool {
        self.status == "running"
            && self.expires.is_some_and(|expires| expires > now)
            && now < self.created + DEADLINE_MS
            && self.owner.as_deref() == c["owner"].as_str()
            && c["attempt"].as_u64() == Some(u64::from(self.attempt))
            && c["fence"].as_u64() == Some(self.fence)
    }
    pub fn transition(
        &mut self,
        c: &Value,
        now: i64,
        policy: HostedCoordinatorPolicy,
    ) -> Result<bool, DurableJobStoreError> {
        let op = c["op"].as_str().ok_or_else(rejected)?;
        if op == "cancel" {
            if self.status == "cancelled" {
                return Ok(true);
            }
            if !matches!(self.status.as_str(), "queued" | "running") {
                return Ok(false);
            }
            self.advance_fence()?;
            self.end("cancelled", now);
            self.error = Some("Search job cancelled by request".into());
            return Ok(true);
        }
        if op == "complete"
            && self.status == "completed"
            && self.owner.as_deref() == c["owner"].as_str()
            && c["attempt"].as_u64() == Some(u64::from(self.attempt))
            && c["fence"].as_u64() == Some(self.fence)
        {
            if self.result.as_deref() != c["result"].as_str() {
                return Err(rejected());
            }
            return Ok(true);
        }
        if !self.owned(c, now) {
            return Ok(false);
        }
        match op {
            "renew" => self.expires = Some(lease(c, now)?.min(self.created + DEADLINE_MS)),
            "progress" => {
                self.progress = c["progress"]
                    .as_u64()
                    .filter(|p| *p <= 100)
                    .ok_or_else(rejected)? as u32;
                if let Some(phase) = c.get("phase") {
                    let phase = phase
                        .as_str()
                        .filter(|p| {
                            super::super::job_coordinator_client::HOSTED_PROGRESS_PHASES.contains(p)
                        })
                        .ok_or_else(rejected)?;
                    self.phase = Some(phase.into());
                }
            }
            "complete" => {
                let result = c["result"]
                    .as_str()
                    .filter(|r| r.len() <= 65_536)
                    .ok_or_else(rejected)?;
                self.result = Some(result.into());
                self.status = "completed".into();
                self.expires = None;
                self.completed = Some(now);
            }
            "fail" => {
                let retry = c["retryable"].as_bool().ok_or_else(rejected)?;
                let error = c["error"]
                    .as_str()
                    .filter(|e| {
                        !e.trim().is_empty() && e.len() <= 256 && !e.chars().any(char::is_control)
                    })
                    .ok_or_else(rejected)?;
                let promote = c["promote_resource_class"].as_bool().ok_or_else(rejected)?;
                self.advance_fence()?;
                self.execution_failures = self
                    .execution_failures
                    .checked_add(1)
                    .ok_or_else(rejected)?;
                self.end(
                    if retry && self.execution_failures < policy.max_execution_failures {
                        "queued"
                    } else {
                        "failed"
                    },
                    now,
                );
                self.error = Some(error.into());
                if promote && self.status == "queued" {
                    self.resource_class = DurableQueryResourceClass::Large;
                }
            }
            "release_claim" => {
                self.advance_fence()?;
                self.attempt = self.attempt.saturating_sub(1);
                self.end("queued", now);
            }
            "cancel_claim" => {
                self.advance_fence()?;
                self.end("cancelled", now);
                self.error = Some("Search authority revoked or changed".into());
            }
            _ => return Err(rejected()),
        }
        Ok(true)
    }
}
pub(super) fn lease(command: &Value, now: i64) -> Result<i64, DurableJobStoreError> {
    let owner = command["owner"]
        .as_str()
        .filter(|o| identifier(o))
        .ok_or_else(rejected)?;
    let _ = owner;
    let ms = command["lease_ms"]
        .as_i64()
        .filter(|n| (5_000..=3_600_000).contains(n))
        .ok_or_else(rejected)?;
    now.checked_add(ms).ok_or_else(rejected)
}

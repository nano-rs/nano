// SPDX-License-Identifier: AGPL-3.0-or-later

//! Normalized system-health lifecycle events and durable outbound delivery.
//!
//! Producers publish conditions here without knowing whether an owner chose a
//! generic webhook, Slack, Teams, or PagerDuty. The repository groups repeated
//! failures under a stable dedup key and transactionally fans lifecycle changes
//! into an outbox. The dispatcher rides the existing encrypted, HMAC-signed,
//! SSRF-pinned notification-channel delivery spine.

mod dispatcher;
mod repository;
mod types;

pub use dispatcher::SystemHealthDispatcher;
pub use repository::{SystemHealthError, SystemHealthRepository};
pub use types::{
    ClaimedHealthDelivery, HealthBusSummary, HealthCategory, HealthDelivery, HealthEventList,
    HealthSeverity, PublishHealthEvent, SystemHealthEvent, DEFAULT_TENANT_ID,
    SYSTEM_HEALTH_EVENT_TYPE,
};

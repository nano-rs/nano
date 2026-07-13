// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webhook / Notification Channels Module
//!
//! Sends provider-formatted HTTP POST notifications to external systems when
//! alerts (or case events) fire. A row is a typed **channel** (`generic` |
//! `slack` | `teams` | `pagerduty` | `email`): the delivery spine — custom
//! headers (encrypted at rest), HMAC-SHA256 signing for the generic channel,
//! SSRF-pinned client, bounded retries, delivery log — is shared, and a
//! per-type [`channels::ChannelFormatter`] renders the body (NAN-1790).

pub mod channels;
pub mod models;
pub mod repository;
pub mod service;

#[cfg(test)]
mod formatter_tests;
#[cfg(test)]
mod tests;

pub use channels::{ChannelType, VALID_CHANNEL_TYPES};
pub use models::{
    CreateWebhookRequest, UpdateWebhookRequest, Webhook, WebhookDeliveryLog, WebhookPayload,
    WebhookResponse, WebhookTestResult,
};
pub use repository::{WebhookRepository, WebhookRepositoryError};
pub use service::WebhookService;

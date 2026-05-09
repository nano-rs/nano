// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webhook Notifications Module
//!
//! Sends HTTP POST notifications to external systems when alerts are created.
//! Supports custom headers (encrypted at rest), HMAC-SHA256 signing, and severity filtering.

pub mod models;
pub mod repository;
pub mod service;

pub use models::{
    CreateWebhookRequest, UpdateWebhookRequest, Webhook, WebhookDeliveryLog, WebhookPayload,
    WebhookResponse, WebhookTestResult,
};
pub use repository::{WebhookRepository, WebhookRepositoryError};
pub use service::WebhookService;

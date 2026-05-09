// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webhook data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

/// A webhook configuration stored in the database
#[derive(Debug, Clone, FromRow)]
pub struct Webhook {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    /// Encrypted JSON headers (AES-256-GCM via EncryptionService)
    pub headers_encrypted: Option<Vec<u8>>,
    /// Encrypted HMAC secret
    pub secret_encrypted: Option<Vec<u8>>,
    /// Optional severity filter (NULL = all severities)
    pub severity_filter: Option<Vec<String>>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Webhook response for API consumers (secrets masked)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebhookResponse {
    #[serde(with = "typeid::webhook")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub url: String,
    /// Whether custom headers are configured (actual values never exposed)
    pub has_headers: bool,
    /// Whether an HMAC secret is configured
    pub has_secret: bool,
    pub severity_filter: Option<Vec<String>>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Webhook> for WebhookResponse {
    fn from(w: &Webhook) -> Self {
        Self {
            id: w.id,
            name: w.name.clone(),
            url: w.url.clone(),
            has_headers: w
                .headers_encrypted
                .as_ref()
                .map_or(false, |h| !h.is_empty()),
            has_secret: w.secret_encrypted.as_ref().map_or(false, |s| !s.is_empty()),
            severity_filter: w.severity_filter.clone(),
            enabled: w.enabled,
            created_at: w.created_at,
            updated_at: w.updated_at,
        }
    }
}

/// Request to create a new webhook
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub url: String,
    /// Custom HTTP headers as key-value pairs (stored encrypted)
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// HMAC-SHA256 secret for payload signing
    pub secret: Option<String>,
    /// Only fire for these severity levels (null = all)
    pub severity_filter: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

/// Request to update an existing webhook
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateWebhookRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    /// Set custom headers (pass empty map to clear)
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// Set HMAC secret (pass empty string to clear)
    pub secret: Option<String>,
    pub severity_filter: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

/// A delivery log entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct WebhookDeliveryLog {
    #[serde(with = "typeid::webhook")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::webhook")]
    #[schema(value_type = String)]
    pub webhook_id: Uuid,
    #[serde(default, with = "typeid::alert::opt")]
    #[schema(value_type = Option<String>)]
    pub alert_id: Option<Uuid>,
    pub event_type: String,
    pub status_code: Option<i32>,
    pub response_body: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub duration_ms: Option<i32>,
    pub delivered_at: DateTime<Utc>,
}

/// Webhook payload sent to the endpoint
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebhookPayload {
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::alert::opt")]
    #[schema(value_type = Option<String>)]
    pub alert_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::rule::opt")]
    #[schema(value_type = Option<String>)]
    pub rule_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_event_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_events: Option<Vec<serde_json::Value>>,
    pub created_at: DateTime<Utc>,
}

/// Result of a test delivery
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebhookTestResult {
    pub success: bool,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

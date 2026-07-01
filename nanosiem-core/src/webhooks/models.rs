// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webhook data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

/// Webhook subscribes to detection (SIEM) alerts — `alerts.kind = 'detection'`.
pub const EVENT_TYPE_SIEM_ALERT: &str = "siem_alert";
/// Webhook subscribes to observability alerts — `alerts.kind` in
/// (`metric_monitor`, `slo`, `synthetic`).
pub const EVENT_TYPE_OBS_ALERT: &str = "obs_alert";
/// Webhook subscribes to case lifecycle events (created / status changed).
pub const EVENT_TYPE_CASE: &str = "case";

/// Every valid `event_types` value. Used to validate create/update requests.
pub const VALID_EVENT_TYPES: [&str; 3] =
    [EVENT_TYPE_SIEM_ALERT, EVENT_TYPE_OBS_ALERT, EVENT_TYPE_CASE];

/// The default subscription for a new (or pre-column) webhook: both alert
/// streams, no cases. Mirrors migration 217's column default so the Rust default
/// and the SQL default never drift.
pub fn default_event_types() -> Vec<String> {
    vec![
        EVENT_TYPE_SIEM_ALERT.to_string(),
        EVENT_TYPE_OBS_ALERT.to_string(),
    ]
}

/// Map an `alerts.kind` discriminator to the webhook subscription category that
/// gates it. `detection` → SIEM; everything else (`metric_monitor`, `slo`,
/// `synthetic`) is observability. Centralized so the fire site and any future
/// alert kind agree on the mapping.
pub fn alert_kind_to_event_type(kind: &str) -> &'static str {
    match kind {
        "detection" => EVENT_TYPE_SIEM_ALERT,
        _ => EVENT_TYPE_OBS_ALERT,
    }
}

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
    /// Event streams this webhook subscribes to (see `VALID_EVENT_TYPES`).
    /// Empty is treated as "all streams" at the fire site (defensive; the
    /// column is NOT NULL DEFAULT {siem_alert, obs_alert}).
    #[sqlx(default)]
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Webhook {
    /// Whether this webhook should receive an event of the given category
    /// (one of `VALID_EVENT_TYPES`). An empty subscription set means "all".
    pub fn subscribes_to(&self, event_type: &str) -> bool {
        self.event_types.is_empty() || self.event_types.iter().any(|e| e == event_type)
    }
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
    /// Event streams this webhook fires for (see `VALID_EVENT_TYPES`).
    pub event_types: Vec<String>,
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
            event_types: w.event_types.clone(),
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
    /// Event streams to subscribe to (see `VALID_EVENT_TYPES`). Omit/null =
    /// default ({siem_alert, obs_alert}).
    pub event_types: Option<Vec<String>>,
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
    /// Replace the subscription set (omit = no change). Must be non-empty and
    /// contain only `VALID_EVENT_TYPES` values.
    pub event_types: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

impl CreateWebhookRequest {
    /// Validate `event_types`: see [`validate_event_types`].
    pub fn validate_event_types(&self) -> Result<(), String> {
        validate_event_types(self.event_types.as_deref())
    }
}

impl UpdateWebhookRequest {
    /// Validate `event_types`: see [`validate_event_types`].
    pub fn validate_event_types(&self) -> Result<(), String> {
        validate_event_types(self.event_types.as_deref())
    }
}

/// Shared validation for a request's `event_types`, consistent across create and
/// update. `None` is always allowed (create → falls back to the default set;
/// update → leaves the subscription unchanged). When a list IS provided it must
/// be non-empty and contain only [`VALID_EVENT_TYPES`] values: forcing an
/// explicit choice avoids the footgun where an empty list reads as "fire for
/// everything" (the runtime `subscribes_to` fallback) when the caller more
/// likely meant "none". "I didn't choose" is expressed by omitting the field.
fn validate_event_types(event_types: Option<&[String]>) -> Result<(), String> {
    if let Some(types) = event_types {
        if types.is_empty() {
            return Err(format!(
                "event_types cannot be empty; specify at least one of {VALID_EVENT_TYPES:?} (omit the field to keep the default)"
            ));
        }
        for t in types {
            if !VALID_EVENT_TYPES.contains(&t.as_str()) {
                return Err(format!(
                    "invalid event_type '{t}'; expected one of {VALID_EVENT_TYPES:?}"
                ));
            }
        }
    }
    Ok(())
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
    /// Alert-spine discriminator (`detection` | `metric_monitor` | `slo` |
    /// `synthetic`). Lets a consumer route SIEM vs observability without
    /// re-deriving it from the (subscription-level) category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
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
    /// The primary entity the alert is about (e.g. the src_ip / user / host the
    /// rule grouped on). Extracted from the matched events at fire time. `None`
    /// when the rule has no risk-entity field or the event lacks it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    /// Deep link back to the alert in the nano UI. Present only when
    /// `NANOSIEM_HOSTNAME` is configured (same source the OIDC issuer uses).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_url: Option<String>,
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

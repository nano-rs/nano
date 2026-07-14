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
/// Webhook subscribes to scheduled-report completion events (`report_ready`).
/// Opt-in (not in [`default_event_types`]) so existing webhooks are unaffected;
/// a future notification-channels layer can route this stream (NAN-1793).
pub const EVENT_TYPE_REPORT: &str = "report";

/// Every valid `event_types` value. Used to validate create/update requests.
pub const VALID_EVENT_TYPES: [&str; 4] = [
    EVENT_TYPE_SIEM_ALERT,
    EVENT_TYPE_OBS_ALERT,
    EVENT_TYPE_CASE,
    EVENT_TYPE_REPORT,
];

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
/// gates it. `detection` and `risk_notable` → SIEM (both are security-analyst
/// alert streams; risk notables aggregate detection-rule risk, NAN-1792);
/// everything else (`metric_monitor`, `slo`, `synthetic`) is observability.
/// Centralized so the fire site and any future alert kind agree on the mapping.
pub fn alert_kind_to_event_type(kind: &str) -> &'static str {
    match kind {
        "detection" | "risk_notable" => EVENT_TYPE_SIEM_ALERT,
        _ => EVENT_TYPE_OBS_ALERT,
    }
}

/// A webhook configuration stored in the database
#[derive(Debug, Clone, FromRow)]
pub struct Webhook {
    pub id: Uuid,
    pub name: String,
    /// The internal delivery URL. On the API read paths this may carry the raw
    /// value of the legacy plaintext `url` column; on the delivery read paths
    /// (`list_enabled` / `get`) it is hydrated from `url_encrypted`. It is NEVER
    /// serialized to API consumers — see [`WebhookResponse`] (F-39).
    pub url: String,
    /// F-39: encrypted destination URL (AES-256-GCM, same envelope as
    /// `headers_encrypted`). `None` only for legacy rows not yet lazy-migrated.
    #[sqlx(default)]
    pub url_encrypted: Option<Vec<u8>>,
    /// F-39: non-secret host label (e.g. `hooks.slack.com`) for UI display. The
    /// full URL — a bearer credential for Slack/Teams — is never exposed.
    #[sqlx(default)]
    pub url_host: Option<String>,
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
    /// Notification channel type (`generic` | `slack` | `teams` | `pagerduty` |
    /// `email`). Selects the payload formatter. Legacy rows default `generic`.
    #[sqlx(default)]
    pub channel_type: String,
    /// Non-secret provider config (JSON). Secrets live in `secret_encrypted`.
    #[sqlx(default)]
    pub channel_config: serde_json::Value,
    /// Optional detection-rule routing filter: fire only for these rule ids.
    /// `None`/empty = all rules.
    #[sqlx(default)]
    pub rule_filter: Option<Vec<Uuid>>,
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

    /// Whether this channel's optional detection-rule filter admits `rule_id`.
    /// An unset/empty filter admits everything; a set filter admits only its
    /// members. A `None` rule_id is NOT admitted by a set filter — a rule filter
    /// is inherently detection-scoped, so a rule-less alert (observability:
    /// metric_monitor / slo / synthetic) doesn't match a rule-scoped channel.
    ///
    /// Applied to ALERT routing only. Case events are a separate stream, gated
    /// solely by the `case` subscription — see `fire_case_event`. (The UI states
    /// this: "Restrict this channel to alerts from specific detection rules.")
    pub fn passes_rule_filter(&self, rule_id: Option<Uuid>) -> bool {
        match &self.rule_filter {
            None => true,
            Some(f) if f.is_empty() => true,
            Some(f) => rule_id.map(|id| f.contains(&id)).unwrap_or(false),
        }
    }

    /// The parsed channel type. An empty value (legacy row, or the column
    /// default) resolves to `Generic`. An UNKNOWN non-empty value is an ERROR,
    /// not a silent fallback to `Generic`: falling back would HMAC-sign this
    /// row's secret and POST the raw payload to its URL — and for any channel
    /// type whose secret is a provider token (a routing key, a future channel's
    /// API key) that leaks the token to the endpoint. Fail closed instead; the
    /// delivery is recorded as failed and nothing is sent.
    pub fn resolve_channel_type(&self) -> Result<super::channels::ChannelType, String> {
        let raw = self.channel_type.trim();
        if raw.is_empty() {
            return Ok(super::channels::ChannelType::Generic);
        }
        super::channels::ChannelType::parse(raw)
            .ok_or_else(|| format!("unknown channel_type '{raw}'; refusing to deliver"))
    }
}

/// Webhook response for API consumers (secrets masked)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebhookResponse {
    #[serde(with = "typeid::webhook")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    /// F-39: non-secret display host of the destination (e.g. `hooks.slack.com`).
    /// The full URL is NEVER returned — for a Slack/Teams incoming webhook the
    /// URL itself is the bearer credential. `None` for legacy rows without a
    /// parsed host label yet.
    pub url_host: Option<String>,
    /// F-39: whether a destination URL is configured (the URL is write-only).
    pub has_url: bool,
    /// Whether custom headers are configured (actual values never exposed)
    pub has_headers: bool,
    /// Whether an HMAC secret is configured
    pub has_secret: bool,
    pub severity_filter: Option<Vec<String>>,
    /// Event streams this webhook fires for (see `VALID_EVENT_TYPES`).
    pub event_types: Vec<String>,
    /// Channel type (`generic` | `slack` | `teams` | `pagerduty` | `email`).
    pub channel_type: String,
    /// Non-secret provider config echoed back for editing.
    pub channel_config: serde_json::Value,
    /// Optional detection-rule routing filter as `rule_…` typeids (null = all).
    pub rule_filter: Option<Vec<String>>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Webhook> for WebhookResponse {
    fn from(w: &Webhook) -> Self {
        let channel_type = if w.channel_type.is_empty() {
            "generic".to_string()
        } else {
            w.channel_type.clone()
        };
        Self {
            id: w.id,
            name: w.name.clone(),
            // F-39: expose only the non-secret host label, never the full URL.
            // Fall back to parsing the internal `url` for legacy rows whose
            // `url_host` column hasn't been populated by a delivery-path hydrate.
            url_host: w.url_host.clone().or_else(|| url_host(&w.url)),
            has_url: w.url_encrypted.as_ref().map_or(false, |u| !u.is_empty())
                || !w.url.is_empty(),
            has_headers: w
                .headers_encrypted
                .as_ref()
                .map_or(false, |h| !h.is_empty()),
            has_secret: w.secret_encrypted.as_ref().map_or(false, |s| !s.is_empty()),
            severity_filter: w.severity_filter.clone(),
            event_types: w.event_types.clone(),
            channel_type,
            channel_config: w.channel_config.clone(),
            rule_filter: w
                .rule_filter
                .as_ref()
                .map(|ids| ids.iter().map(encode_rule_id).collect()),
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
    /// Channel type (`generic` | `slack` | `teams` | `pagerduty`). Omit = generic.
    pub channel_type: Option<String>,
    /// Non-secret provider config (JSON object). Omit = `{}`.
    pub channel_config: Option<serde_json::Value>,
    /// Optional detection-rule routing filter (`rule_…` typeids or bare UUIDs).
    /// Omit/empty = all rules.
    pub rule_filter: Option<Vec<String>>,
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
    /// Change the channel type (omit = no change).
    pub channel_type: Option<String>,
    /// Replace the non-secret provider config (omit = no change).
    pub channel_config: Option<serde_json::Value>,
    /// Replace the detection-rule routing filter (omit = no change; pass `[]` to
    /// clear). `rule_…` typeids or bare UUIDs.
    pub rule_filter: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

impl CreateWebhookRequest {
    /// Validate `event_types`: see [`validate_event_types`].
    pub fn validate_event_types(&self) -> Result<(), String> {
        validate_event_types(self.event_types.as_deref())
    }

    /// Validate the channel type + its required fields for a create.
    pub fn validate_channel(&self) -> Result<(), String> {
        validate_channel(self.channel_type.as_deref(), Some(self.url.as_str()), true)
    }

    /// Decode the request's `rule_filter` typeids/UUIDs to raw UUIDs.
    pub fn decoded_rule_filter(&self) -> Result<Option<Vec<Uuid>>, String> {
        decode_rule_filter(self.rule_filter.as_deref())
    }
}

impl UpdateWebhookRequest {
    /// Validate `event_types`: see [`validate_event_types`].
    pub fn validate_event_types(&self) -> Result<(), String> {
        validate_event_types(self.event_types.as_deref())
    }

    /// Validate the channel type on update. `url` is only required at create
    /// time (an update that doesn't touch the URL keeps the stored one), so the
    /// required-URL check is relaxed here.
    pub fn validate_channel(&self) -> Result<(), String> {
        validate_channel(self.channel_type.as_deref(), self.url.as_deref(), false)
    }

    /// Decode the request's `rule_filter` typeids/UUIDs to raw UUIDs.
    pub fn decoded_rule_filter(&self) -> Result<Option<Vec<Uuid>>, String> {
        decode_rule_filter(self.rule_filter.as_deref())
    }
}

/// Encode a detection-rule UUID as a `rule_…` typeid for the API surface.
pub fn encode_rule_id(id: &Uuid) -> String {
    typeid::encode(typeid::rule::PREFIX, id)
}

/// F-39: parse the non-secret display host (e.g. `hooks.slack.com`) from a
/// destination URL. Returns `None` when the value is empty or has no host, so
/// callers never surface a malformed/partial URL as a "host". Never returns the
/// path/token portion — that is the secret for a Slack/Teams webhook.
pub(crate) fn url_host(url: &str) -> Option<String> {
    if url.trim().is_empty() {
        return None;
    }
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}

/// Decode an API `rule_filter` list (typeids or bare UUIDs) to raw UUIDs.
/// `None` stays `None` (no change); an empty list decodes to `Some(vec![])`
/// (clear the filter). A malformed id is a hard error naming the value.
fn decode_rule_filter(ids: Option<&[String]>) -> Result<Option<Vec<Uuid>>, String> {
    match ids {
        None => Ok(None),
        Some(list) => {
            let mut out = Vec::with_capacity(list.len());
            for raw in list {
                let id = typeid::decode(typeid::rule::PREFIX, raw)
                    .map_err(|_| format!("invalid rule id in rule_filter: '{raw}'"))?;
                out.push(id);
            }
            Ok(Some(out))
        }
    }
}

/// Shared channel validation for create/update. Checks the type is known and
/// creatable, and (when `require_url`) that URL-bearing channel types carry one.
/// The PagerDuty routing key requirement is enforced at the handler, which knows
/// whether a secret already exists on an update.
fn validate_channel(
    channel_type: Option<&str>,
    url: Option<&str>,
    require_url: bool,
) -> Result<(), String> {
    let ct = match channel_type {
        None => return Ok(()), // omitted → generic (create) / unchanged (update)
        Some(s) => s,
    };
    let parsed = super::channels::ChannelType::parse(ct).ok_or_else(|| {
        format!(
            "invalid channel_type '{ct}'; expected one of {:?}",
            super::channels::VALID_CHANNEL_TYPES
        )
    })?;

    if !parsed.supports_delivery() {
        return Err(format!(
            "channel_type '{ct}' is not yet available (formatter seam only); use generic, slack, teams, or pagerduty"
        ));
    }

    if require_url && parsed.user_supplies_url() {
        let has_url = url.map(|u| !u.trim().is_empty()).unwrap_or(false);
        if !has_url {
            return Err(format!("channel_type '{ct}' requires a destination URL"));
        }
    }

    Ok(())
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

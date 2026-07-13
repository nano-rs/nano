// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notification channel types and provider payload formatters (NAN-1790).
//!
//! A notification **channel** is a webhook row with a `channel_type`: the same
//! delivery spine (SSRF-pinned client, retries, delivery log, encrypted secret)
//! carries a provider-specific body produced by a [`ChannelFormatter`]. The
//! canonical event is the existing [`WebhookPayload`]; each formatter renders it
//! into the shape its receiver expects (Slack Block Kit, Teams Adaptive Card,
//! PagerDuty Events v2). The generic channel keeps posting the raw, HMAC-signed
//! `WebhookPayload` JSON unchanged, so existing webhooks are byte-identical.

use serde_json::{json, Value};

use super::models::WebhookPayload;
use crate::typeid;

/// PagerDuty Events API v2 enqueue endpoint. Fixed public host; the per-channel
/// secret carries the routing key, not the URL.
pub const PAGERDUTY_EVENTS_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// PagerDuty caps `payload.summary` at 1024 chars.
const PD_SUMMARY_MAX: usize = 1024;

/// The notification channel type. Selects the payload formatter and how the
/// per-channel URL / secret are interpreted. Stored as the string `as_str()` in
/// `webhooks.channel_type`; validated in the application layer so a new provider
/// needs no migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    /// Signed JSON POST of the raw `WebhookPayload` (the pre-NAN-1790 behavior).
    Generic,
    /// Slack incoming webhook — Block Kit payload.
    Slack,
    /// Microsoft Teams incoming webhook / workflow — Adaptive Card.
    Teams,
    /// PagerDuty Events API v2 — routing key in the encrypted secret.
    PagerDuty,
    /// SMTP email — formatter seam only in v1 (transport is a follow-up).
    Email,
}

/// Every channel type the DB may hold. `email` parses (so the seam round-trips)
/// even though creating one is rejected until SMTP transport lands.
pub const VALID_CHANNEL_TYPES: [&str; 5] = ["generic", "slack", "teams", "pagerduty", "email"];

impl ChannelType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelType::Generic => "generic",
            ChannelType::Slack => "slack",
            ChannelType::Teams => "teams",
            ChannelType::PagerDuty => "pagerduty",
            ChannelType::Email => "email",
        }
    }

    /// Parse a stored/requested value. Returns `None` for unknown strings.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "generic" => Some(ChannelType::Generic),
            "slack" => Some(ChannelType::Slack),
            "teams" => Some(ChannelType::Teams),
            "pagerduty" => Some(ChannelType::PagerDuty),
            "email" => Some(ChannelType::Email),
            _ => None,
        }
    }

    /// Whether the operator supplies the destination URL (Slack/Teams incoming
    /// webhook, generic endpoint). PagerDuty's URL is fixed server-side; email
    /// has no URL.
    pub fn user_supplies_url(&self) -> bool {
        matches!(self, ChannelType::Generic | ChannelType::Slack | ChannelType::Teams)
    }

    /// Whether the operator must supply a secret at create time (PagerDuty
    /// routing key). Generic's HMAC secret and Slack/Teams (URL *is* the secret)
    /// are optional / implicit.
    pub fn requires_secret(&self) -> bool {
        matches!(self, ChannelType::PagerDuty)
    }

    /// Whether the HTTP delivery spine can send this channel today. `Email` has
    /// no HTTP transport (SMTP is a follow-up); everything else rides reqwest.
    pub fn supports_delivery(&self) -> bool {
        !matches!(self, ChannelType::Email)
    }
}

/// The rendered request body plus whether the delivery path should HMAC-sign it.
/// Only the generic channel signs (its receiver verifies `X-NanoSIEM-Signature`);
/// provider channels authenticate by the secret URL / in-body routing key.
#[derive(Debug)]
pub struct FormattedBody {
    pub bytes: Vec<u8>,
    pub sign_hmac: bool,
}

/// Context a formatter may need beyond the payload — currently just the
/// decrypted PagerDuty routing key (never logged, never echoed to the UI).
pub struct FormatContext<'a> {
    pub routing_key: Option<&'a str>,
}

/// Provider payload renderer. The seam that makes adding a channel type a
/// formatter addition rather than a delivery-path rewrite (e.g. the pending
/// email/SMTP channel is an [`EmailFormatter`] impl).
pub trait ChannelFormatter {
    /// Render the provider-specific request body for this event.
    fn format(&self, payload: &WebhookPayload, ctx: &FormatContext) -> Value;
}

/// Build the outbound body for `channel_type`. The generic path serializes the
/// `WebhookPayload` struct directly to preserve byte-for-byte compatibility with
/// pre-NAN-1790 signatures; provider paths go through their formatter.
pub fn build_channel_body(
    channel_type: ChannelType,
    payload: &WebhookPayload,
    ctx: &FormatContext,
) -> Result<FormattedBody, String> {
    match channel_type {
        ChannelType::Generic => Ok(FormattedBody {
            bytes: serde_json::to_vec(payload).map_err(|e| e.to_string())?,
            sign_hmac: true,
        }),
        ChannelType::Slack => body(SlackFormatter.format(payload, ctx)),
        ChannelType::Teams => body(TeamsFormatter.format(payload, ctx)),
        ChannelType::PagerDuty => {
            if ctx.routing_key.map(str::trim).unwrap_or("").is_empty() {
                return Err("PagerDuty channel is missing its routing key".to_string());
            }
            body(PagerDutyFormatter.format(payload, ctx))
        }
        ChannelType::Email => Err(
            "email/SMTP channel delivery is not yet wired (formatter seam only)".to_string(),
        ),
    }
}

fn body(value: Value) -> Result<FormattedBody, String> {
    Ok(FormattedBody {
        bytes: serde_json::to_vec(&value).map_err(|e| e.to_string())?,
        sign_hmac: false,
    })
}

// ---------------------------------------------------------------------------
// Shared display helpers
// ---------------------------------------------------------------------------

fn title_of(payload: &WebhookPayload) -> String {
    payload
        .rule_name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "nano notification".to_string())
}

fn severity_of(payload: &WebhookPayload) -> &str {
    payload
        .severity
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("informational")
}

/// Whether this event is a scheduled-report completion (`report_ready`) rather
/// than an alert. Report payloads reuse the alert slots (`rule_name` = report
/// name, `severity` = run status, `entity` = source type), so rendering them
/// through the alert framing produces nonsense like "Severity: SUCCESS" —
/// report-kind events get their own card shape (NAN-1796).
fn is_report(payload: &WebhookPayload) -> bool {
    payload.kind.as_deref() == Some("report")
}

fn report_title(payload: &WebhookPayload) -> String {
    let name = payload
        .rule_name
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("scheduled report");
    format!("Report ready: {name}")
}

/// The run status riding in the payload's `severity` slot ("success"/"failed").
/// NOT an alert severity — never fed to the severity→color/enum mappings.
fn report_status(payload: &WebhookPayload) -> &str {
    payload
        .severity
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("success")
}

/// Run status → hex for the Slack attachment bar. Success is "good" green;
/// failure red; anything else the neutral gray.
fn report_status_hex(status: &str) -> &'static str {
    match status.to_lowercase().as_str() {
        "success" => "#16a34a",
        "failed" => "#dc2626",
        _ => "#6b7280",
    }
}

/// Run status → Adaptive Card color enum for Teams.
fn report_adaptive_color(status: &str) -> &'static str {
    match status.to_lowercase().as_str() {
        "success" => "Good",
        "failed" => "Attention",
        _ => "Default",
    }
}

/// Severity → hex color for the Slack attachment bar and any hex-driven UI.
pub fn severity_hex(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "#dc2626",
        "high" => "#ea580c",
        "medium" => "#d97706",
        "low" => "#2563eb",
        _ => "#6b7280",
    }
}

/// Severity → Adaptive Card color enum for Teams.
fn adaptive_color(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "Attention",
        "medium" => "Warning",
        "low" => "Accent",
        _ => "Good",
    }
}

/// Severity → PagerDuty Events v2 severity enum (`critical|error|warning|info`).
fn pagerduty_severity(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "error",
        "medium" => "warning",
        "low" | "informational" | "info" => "info",
        _ => "error",
    }
}

// ---------------------------------------------------------------------------
// Slack (Block Kit)
// ---------------------------------------------------------------------------

pub struct SlackFormatter;

impl ChannelFormatter for SlackFormatter {
    fn format(&self, payload: &WebhookPayload, _ctx: &FormatContext) -> Value {
        // Reports get their own card shape; the alert rendering below is
        // unchanged (NAN-1796).
        if is_report(payload) {
            return slack_report_card(payload);
        }

        let title = title_of(payload);
        let severity = severity_of(payload);

        // Section fields render as a two-column grid; mono (backtick) values
        // match nano's visual language for IDs / severities / entities.
        let mut fields = vec![json!({
            "type": "mrkdwn",
            "text": format!("*Severity*\n`{}`", severity.to_uppercase())
        })];
        if let Some(entity) = payload.entity.as_deref().filter(|s| !s.is_empty()) {
            fields.push(json!({ "type": "mrkdwn", "text": format!("*Entity*\n`{entity}`") }));
        }
        if let Some(kind) = payload.kind.as_deref().filter(|s| !s.is_empty()) {
            fields.push(json!({ "type": "mrkdwn", "text": format!("*Type*\n`{kind}`") }));
        }
        if let Some(count) = payload.matched_event_count {
            fields.push(json!({ "type": "mrkdwn", "text": format!("*Events*\n`{count}`") }));
        }

        let mut blocks = vec![
            json!({
                "type": "header",
                "text": { "type": "plain_text", "text": truncate(&title, 150), "emoji": true }
            }),
            json!({ "type": "section", "fields": fields }),
            json!({
                "type": "context",
                "elements": [ { "type": "mrkdwn", "text": format!("nano · {}", payload.created_at.to_rfc3339()) } ]
            }),
        ];

        if let Some(link) = payload.link_url.as_deref().filter(|s| !s.is_empty()) {
            blocks.push(json!({
                "type": "actions",
                "elements": [ {
                    "type": "button",
                    "text": { "type": "plain_text", "text": "View in nano", "emoji": true },
                    "url": link,
                    "style": "primary"
                } ]
            }));
        }

        json!({
            "text": format!("{} · {}", severity.to_uppercase(), title),
            "attachments": [ { "color": severity_hex(severity), "blocks": blocks } ]
        })
    }
}

/// Slack card for a `report_ready` event: "Report ready: <name>" with
/// Status / Rows / Source fields — no alert Severity/Type framing.
fn slack_report_card(payload: &WebhookPayload) -> Value {
    let title = report_title(payload);
    let status = report_status(payload);

    let mut fields = vec![json!({
        "type": "mrkdwn",
        "text": format!("*Status*\n`{}`", status.to_uppercase())
    })];
    if let Some(count) = payload.matched_event_count {
        fields.push(json!({ "type": "mrkdwn", "text": format!("*Rows*\n`{count}`") }));
    }
    if let Some(source) = payload.entity.as_deref().filter(|s| !s.is_empty()) {
        fields.push(json!({ "type": "mrkdwn", "text": format!("*Source*\n`{source}`") }));
    }

    let mut blocks = vec![
        json!({
            "type": "header",
            "text": { "type": "plain_text", "text": truncate(&title, 150), "emoji": true }
        }),
        json!({ "type": "section", "fields": fields }),
        json!({
            "type": "context",
            "elements": [ { "type": "mrkdwn", "text": format!("nano · {}", payload.created_at.to_rfc3339()) } ]
        }),
    ];

    if let Some(link) = payload.link_url.as_deref().filter(|s| !s.is_empty()) {
        blocks.push(json!({
            "type": "actions",
            "elements": [ {
                "type": "button",
                "text": { "type": "plain_text", "text": "View in nano", "emoji": true },
                "url": link,
                "style": "primary"
            } ]
        }));
    }

    json!({
        "text": title,
        "attachments": [ { "color": report_status_hex(status), "blocks": blocks } ]
    })
}

// ---------------------------------------------------------------------------
// Microsoft Teams (Adaptive Card via incoming webhook / workflow)
// ---------------------------------------------------------------------------

pub struct TeamsFormatter;

impl ChannelFormatter for TeamsFormatter {
    fn format(&self, payload: &WebhookPayload, _ctx: &FormatContext) -> Value {
        // Reports get their own card shape; the alert rendering below is
        // unchanged (NAN-1796).
        if is_report(payload) {
            return teams_report_card(payload);
        }

        let title = title_of(payload);
        let severity = severity_of(payload);

        let mut facts = vec![json!({ "title": "Severity", "value": severity.to_uppercase() })];
        if let Some(entity) = payload.entity.as_deref().filter(|s| !s.is_empty()) {
            facts.push(json!({ "title": "Entity", "value": entity }));
        }
        if let Some(kind) = payload.kind.as_deref().filter(|s| !s.is_empty()) {
            facts.push(json!({ "title": "Type", "value": kind }));
        }
        if let Some(count) = payload.matched_event_count {
            facts.push(json!({ "title": "Events", "value": count.to_string() }));
        }
        facts.push(json!({ "title": "Time", "value": payload.created_at.to_rfc3339() }));

        let body = vec![
            json!({
                "type": "TextBlock",
                "text": title,
                "weight": "Bolder",
                "size": "Large",
                "color": adaptive_color(severity),
                "wrap": true
            }),
            json!({ "type": "FactSet", "facts": facts }),
        ];

        let mut actions = Vec::new();
        if let Some(link) = payload.link_url.as_deref().filter(|s| !s.is_empty()) {
            actions.push(json!({ "type": "Action.OpenUrl", "title": "View in nano", "url": link }));
        }

        json!({
            "type": "message",
            "attachments": [ {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                    "actions": actions
                }
            } ]
        })
    }
}

/// Teams Adaptive Card for a `report_ready` event: "Report ready: <name>" with
/// Status / Rows / Source / Time facts — no alert Severity/Type framing.
fn teams_report_card(payload: &WebhookPayload) -> Value {
    let title = report_title(payload);
    let status = report_status(payload);

    let mut facts = vec![json!({ "title": "Status", "value": status.to_uppercase() })];
    if let Some(count) = payload.matched_event_count {
        facts.push(json!({ "title": "Rows", "value": count.to_string() }));
    }
    if let Some(source) = payload.entity.as_deref().filter(|s| !s.is_empty()) {
        facts.push(json!({ "title": "Source", "value": source }));
    }
    facts.push(json!({ "title": "Time", "value": payload.created_at.to_rfc3339() }));

    let body = vec![
        json!({
            "type": "TextBlock",
            "text": title,
            "weight": "Bolder",
            "size": "Large",
            "color": report_adaptive_color(status),
            "wrap": true
        }),
        json!({ "type": "FactSet", "facts": facts }),
    ];

    let mut actions = Vec::new();
    if let Some(link) = payload.link_url.as_deref().filter(|s| !s.is_empty()) {
        actions.push(json!({ "type": "Action.OpenUrl", "title": "View in nano", "url": link }));
    }

    json!({
        "type": "message",
        "attachments": [ {
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body,
                "actions": actions
            }
        } ]
    })
}

// ---------------------------------------------------------------------------
// PagerDuty (Events API v2)
// ---------------------------------------------------------------------------

pub struct PagerDutyFormatter;

impl ChannelFormatter for PagerDutyFormatter {
    fn format(&self, payload: &WebhookPayload, ctx: &FormatContext) -> Value {
        // A finished report is not a page-worthy incident — it maps to a fixed
        // `info` severity with a report-shaped summary. The alert rendering
        // below is unchanged (NAN-1796).
        if is_report(payload) {
            return pagerduty_report_event(payload, ctx);
        }

        let title = title_of(payload);
        let severity = severity_of(payload);
        let summary = truncate(
            &format!("{} — {}", title, severity.to_uppercase()),
            PD_SUMMARY_MAX,
        );
        let source = payload
            .entity
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "nano".to_string());

        let mut custom = serde_json::Map::new();
        custom.insert("event_type".into(), json!(payload.event_type));
        if let Some(kind) = &payload.kind {
            custom.insert("kind".into(), json!(kind));
        }
        if let Some(rule) = &payload.rule_name {
            custom.insert("rule".into(), json!(rule));
        }
        if let Some(entity) = &payload.entity {
            custom.insert("entity".into(), json!(entity));
        }
        if let Some(count) = payload.matched_event_count {
            custom.insert("matched_event_count".into(), json!(count));
        }
        custom.insert("created_at".into(), json!(payload.created_at.to_rfc3339()));
        if let Some(link) = &payload.link_url {
            custom.insert("link_url".into(), json!(link));
        }

        let mut event = json!({
            "routing_key": ctx.routing_key.unwrap_or_default(),
            "event_action": "trigger",
            "payload": {
                "summary": summary,
                "severity": pagerduty_severity(severity),
                "source": source,
                "component": title,
                "custom_details": Value::Object(custom),
            },
            "client": "nano SIEM",
        });

        // dedup_key strategy:
        //   - alert id (typeid) for real alerts — collapses repeats of the SAME
        //     alert on the PagerDuty side and is the anchor a future
        //     resolve-on-close would target.
        //   - a fixed `nano-test` key for test sends so repeated tests collapse
        //     into one incident instead of paging on-call N times.
        //   - none for rule-less non-test events (e.g. case events): PagerDuty
        //     auto-generates a unique key so each is its own incident, rather
        //     than every case event collapsing into one.
        let dedup_key = if let Some(alert_id) = payload.alert_id {
            Some(typeid::encode(typeid::alert::PREFIX, &alert_id))
        } else if payload.event_type == "webhook.test" {
            Some("nano-test".to_string())
        } else {
            None
        };
        if let Some(key) = dedup_key {
            event["dedup_key"] = json!(key);
        }
        if let Some(link) = payload.link_url.as_deref().filter(|s| !s.is_empty()) {
            event["client_url"] = json!(link);
            event["links"] = json!([ { "href": link, "text": "View in nano" } ]);
        }

        event
    }
}

/// PagerDuty event for a `report_ready` completion. Always `info` severity —
/// the run status is NOT an alert severity and a report never pages on-call.
/// No dedup_key: each run is its own (informational) event.
fn pagerduty_report_event(payload: &WebhookPayload, ctx: &FormatContext) -> Value {
    let title = report_title(payload);
    let status = report_status(payload);
    let summary = truncate(
        &format!("{} — {}", title, status.to_uppercase()),
        PD_SUMMARY_MAX,
    );
    let source = payload
        .entity
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nano".to_string());

    let mut custom = serde_json::Map::new();
    custom.insert("event_type".into(), json!(payload.event_type));
    if let Some(kind) = &payload.kind {
        custom.insert("kind".into(), json!(kind));
    }
    if let Some(name) = &payload.rule_name {
        custom.insert("report".into(), json!(name));
    }
    custom.insert("status".into(), json!(status));
    if let Some(source_type) = &payload.entity {
        custom.insert("source_type".into(), json!(source_type));
    }
    if let Some(count) = payload.matched_event_count {
        custom.insert("row_count".into(), json!(count));
    }
    custom.insert("created_at".into(), json!(payload.created_at.to_rfc3339()));
    if let Some(link) = &payload.link_url {
        custom.insert("link_url".into(), json!(link));
    }

    let mut event = json!({
        "routing_key": ctx.routing_key.unwrap_or_default(),
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "severity": "info",
            "source": source,
            "component": title,
            "custom_details": Value::Object(custom),
        },
        "client": "nano SIEM",
    });
    if let Some(link) = payload.link_url.as_deref().filter(|s| !s.is_empty()) {
        event["client_url"] = json!(link);
        event["links"] = json!([ { "href": link, "text": "View in nano" } ]);
    }

    event
}

// ---------------------------------------------------------------------------
// Email (SMTP) — formatter seam only; delivery is a follow-up (no HTTP transport)
// ---------------------------------------------------------------------------

pub struct EmailFormatter;

impl ChannelFormatter for EmailFormatter {
    fn format(&self, payload: &WebhookPayload, _ctx: &FormatContext) -> Value {
        let title = title_of(payload);
        let severity = severity_of(payload);
        let subject = format!("[nano · {}] {}", severity.to_uppercase(), title);

        let mut lines = vec![
            format!("Severity: {}", severity.to_uppercase()),
            format!("Rule: {}", title),
        ];
        if let Some(entity) = &payload.entity {
            lines.push(format!("Entity: {entity}"));
        }
        if let Some(count) = payload.matched_event_count {
            lines.push(format!("Events: {count}"));
        }
        lines.push(format!("Time: {}", payload.created_at.to_rfc3339()));
        if let Some(link) = &payload.link_url {
            lines.push(format!("View: {link}"));
        }

        json!({ "subject": subject, "text": lines.join("\n") })
    }
}

/// Truncate to `max` chars (char-boundary safe), appending an ellipsis marker.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let truncated: String = s.chars().take(keep).collect();
    format!("{truncated}…")
}

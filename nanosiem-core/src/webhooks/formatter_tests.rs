// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the notification channel formatters (NAN-1790): provider
//! payload shape (Slack Block Kit, Teams Adaptive Card, PagerDuty Events v2),
//! the generic byte-identity guarantee, severity mapping, and the email/PagerDuty
//! fail-closed seams. Pure JSON assertions — no network.

use super::channels::*;
use super::models::WebhookPayload;
use chrono::TimeZone;
use uuid::Uuid;

fn sample_alert() -> WebhookPayload {
    WebhookPayload {
        event_type: "alert.created".to_string(),
        kind: Some("detection".to_string()),
        alert_id: Some(Uuid::now_v7()),
        rule_id: Some(Uuid::now_v7()),
        rule_name: Some("Impossible travel".to_string()),
        severity: Some("high".to_string()),
        entity: Some("10.0.0.5".to_string()),
        link_url: Some("https://nano.example.com/alerts/alert_abc".to_string()),
        matched_event_count: Some(3),
        matched_events: Some(vec![]),
        created_at: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        health_event_id: None,
        health_status: None,
        health_category: None,
        health_resource_type: None,
        health_resource_id: None,
        health_summary: None,
        health_diagnostic_context: None,
        health_remediation: None,
        idempotency_key: None,
    }
}

/// A `report_ready` payload as `fire_report_ready` builds it: `rule_name`
/// carries the report name, `severity` the run status, `entity` the source
/// type, `matched_event_count` the row count.
fn sample_report() -> WebhookPayload {
    WebhookPayload {
        event_type: "report_ready".to_string(),
        kind: Some("report".to_string()),
        alert_id: None,
        rule_id: None,
        rule_name: Some("Weekly auth failures".to_string()),
        severity: Some("success".to_string()),
        entity: Some("search".to_string()),
        link_url: Some("https://nano.example.com/reports/report_abc".to_string()),
        matched_event_count: Some(1234),
        matched_events: None,
        created_at: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        health_event_id: None,
        health_status: None,
        health_category: None,
        health_resource_type: None,
        health_resource_id: None,
        health_summary: None,
        health_diagnostic_context: None,
        health_remediation: None,
        idempotency_key: None,
    }
}

fn sample_feed_health(status: &str) -> WebhookPayload {
    let mut payload = sample_alert();
    payload.event_type = format!("system_health.{status}");
    payload.kind = Some("system_health".to_string());
    payload.alert_id = None;
    payload.rule_id = None;
    payload.rule_name = Some(if status == "resolved" {
        "Resolved: Log source stopped sending: apache".to_string()
    } else {
        "Log source stopped sending: apache".to_string()
    });
    payload.severity = Some(if status == "resolved" { "informational" } else { "high" }.to_string());
    payload.entity = Some("apache".to_string());
    payload.health_event_id = Some(Uuid::parse_str("0198a822-d0e5-7692-8f76-b963afca5e23").unwrap());
    payload.health_status = Some(if status == "resolved" { "resolved" } else { "active" }.to_string());
    payload.health_category = Some("log_source".to_string());
    payload.health_resource_type = Some("log_source".to_string());
    payload.health_resource_id = Some("61321828-ed33-47fa-9701-e2d960573446".to_string());
    payload.health_summary = Some("No data received for 45 minutes".to_string());
    payload.health_remediation = Some("Check the upstream sender and network path.".to_string());
    payload.idempotency_key = Some(format!("0198a822-d0e5-7692-8f76-b963afca5e23:{status}"));
    payload
}

fn parse(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("channel body is valid JSON")
}

// ---------------------------------------------------------------------------
// ChannelType parsing
// ---------------------------------------------------------------------------

#[test]
fn channel_type_parse_roundtrip() {
    for s in VALID_CHANNEL_TYPES {
        let ct = ChannelType::parse(s).expect("known type parses");
        assert_eq!(ct.as_str(), s);
    }
    // An unknown type does NOT silently become generic — see
    // Webhook::resolve_channel_type: a generic fallback would HMAC-sign and ship
    // the row's secret to its endpoint.
    assert!(ChannelType::parse("nope").is_none());
}

#[test]
fn channel_type_delivery_and_secret_flags() {
    assert!(ChannelType::PagerDuty.requires_secret());
    assert!(!ChannelType::Slack.requires_secret());
    assert!(!ChannelType::Email.supports_delivery());
    assert!(ChannelType::Slack.supports_delivery());
    assert!(ChannelType::Generic.user_supplies_url());
    assert!(!ChannelType::PagerDuty.user_supplies_url());
}

// ---------------------------------------------------------------------------
// Generic — byte-identity + signing
// ---------------------------------------------------------------------------

#[test]
fn generic_preserves_payload_bytes_and_signs() {
    let payload = sample_alert();
    let ctx = FormatContext { routing_key: None };
    let out = build_channel_body(ChannelType::Generic, &payload, &ctx).unwrap();
    // Byte-for-byte identical to the pre-NAN-1790 signed body.
    assert_eq!(out.bytes, serde_json::to_vec(&payload).unwrap());
    assert!(out.sign_hmac, "generic channel signs its body");
}

// ---------------------------------------------------------------------------
// Slack Block Kit
// ---------------------------------------------------------------------------

#[test]
fn slack_block_kit_shape() {
    let payload = sample_alert();
    let ctx = FormatContext { routing_key: None };
    let out = build_channel_body(ChannelType::Slack, &payload, &ctx).unwrap();
    assert!(!out.sign_hmac, "provider channels are not HMAC-signed");
    let v = parse(&out.bytes);

    // Severity color bar on the attachment.
    assert_eq!(v["attachments"][0]["color"], severity_hex("high"));
    let blocks = v["attachments"][0]["blocks"].as_array().unwrap();

    // Header carries the alert title (rule name).
    assert_eq!(blocks[0]["type"], "header");
    assert_eq!(blocks[0]["text"]["text"], "Impossible travel");

    // Section fields carry mono (backtick) severity + entity.
    let fields = blocks[1]["fields"].as_array().unwrap();
    let joined: String = fields
        .iter()
        .map(|f| f["text"].as_str().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(joined.contains("*Severity*\n`HIGH`"), "mono severity: {joined}");
    assert!(joined.contains("*Entity*\n`10.0.0.5`"), "mono entity: {joined}");

    // A deep-link button when link_url is present.
    let actions = blocks.iter().find(|b| b["type"] == "actions").unwrap();
    assert_eq!(
        actions["elements"][0]["url"],
        "https://nano.example.com/alerts/alert_abc"
    );
}

#[test]
fn slack_report_card_is_kind_aware() {
    let payload = sample_report();
    let ctx = FormatContext { routing_key: None };
    let out = build_channel_body(ChannelType::Slack, &payload, &ctx).unwrap();
    let v = parse(&out.bytes);

    // Status-driven bar color — NOT the alert severity mapping ("success"
    // through severity_hex would be the gray fallback).
    assert_eq!(v["attachments"][0]["color"], "#16a34a");
    let blocks = v["attachments"][0]["blocks"].as_array().unwrap();

    // Report-appropriate title.
    assert_eq!(blocks[0]["type"], "header");
    assert_eq!(blocks[0]["text"]["text"], "Report ready: Weekly auth failures");

    // Status / Rows / Source fields — no Severity/Type framing.
    let fields = blocks[1]["fields"].as_array().unwrap();
    let joined: String = fields
        .iter()
        .map(|f| f["text"].as_str().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(joined.contains("*Status*\n`SUCCESS`"), "status field: {joined}");
    assert!(joined.contains("*Rows*\n`1234`"), "rows field: {joined}");
    assert!(joined.contains("*Source*\n`search`"), "source field: {joined}");
    assert!(!joined.contains("*Severity*"), "no alert severity framing: {joined}");
    assert!(!joined.contains("*Type*"), "no alert type framing: {joined}");

    // The deep-link button still renders when a link is present.
    let actions = blocks.iter().find(|b| b["type"] == "actions").unwrap();
    assert_eq!(
        actions["elements"][0]["url"],
        "https://nano.example.com/reports/report_abc"
    );
}

#[test]
fn slack_omits_button_without_link() {
    let mut payload = sample_alert();
    payload.link_url = None;
    let ctx = FormatContext { routing_key: None };
    let out = build_channel_body(ChannelType::Slack, &payload, &ctx).unwrap();
    let v = parse(&out.bytes);
    let has_actions = v["attachments"][0]["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["type"] == "actions");
    assert!(!has_actions, "no actions block without a deep link");
}

// ---------------------------------------------------------------------------
// Microsoft Teams Adaptive Card
// ---------------------------------------------------------------------------

#[test]
fn teams_adaptive_card_shape() {
    let payload = sample_alert();
    let ctx = FormatContext { routing_key: None };
    let out = build_channel_body(ChannelType::Teams, &payload, &ctx).unwrap();
    assert!(!out.sign_hmac);
    let v = parse(&out.bytes);

    let attachment = &v["attachments"][0];
    assert_eq!(
        attachment["contentType"],
        "application/vnd.microsoft.card.adaptive"
    );
    let content = &attachment["content"];
    assert_eq!(content["type"], "AdaptiveCard");

    // Title TextBlock + severity-mapped color.
    assert_eq!(content["body"][0]["text"], "Impossible travel");
    assert_eq!(content["body"][0]["color"], "Attention"); // high → Attention

    // FactSet includes the severity fact.
    let facts = content["body"][1]["facts"].as_array().unwrap();
    assert!(facts
        .iter()
        .any(|f| f["title"] == "Severity" && f["value"] == "HIGH"));

    // OpenUrl action to the deep link.
    assert_eq!(content["actions"][0]["type"], "Action.OpenUrl");
    assert_eq!(
        content["actions"][0]["url"],
        "https://nano.example.com/alerts/alert_abc"
    );
}

#[test]
fn teams_report_card_is_kind_aware() {
    let payload = sample_report();
    let ctx = FormatContext { routing_key: None };
    let out = build_channel_body(ChannelType::Teams, &payload, &ctx).unwrap();
    let v = parse(&out.bytes);

    let content = &v["attachments"][0]["content"];
    assert_eq!(content["type"], "AdaptiveCard");

    // Report-appropriate title, status-driven "Good" color (not the alert
    // severity→color enum).
    assert_eq!(content["body"][0]["text"], "Report ready: Weekly auth failures");
    assert_eq!(content["body"][0]["color"], "Good");

    // Status / Rows / Source facts — no Severity/Type framing.
    let facts = content["body"][1]["facts"].as_array().unwrap();
    assert!(facts.iter().any(|f| f["title"] == "Status" && f["value"] == "SUCCESS"));
    assert!(facts.iter().any(|f| f["title"] == "Rows" && f["value"] == "1234"));
    assert!(facts.iter().any(|f| f["title"] == "Source" && f["value"] == "search"));
    assert!(!facts.iter().any(|f| f["title"] == "Severity"), "no severity fact");
    assert!(!facts.iter().any(|f| f["title"] == "Type"), "no type fact");

    // The deep-link action still renders when a link is present.
    assert_eq!(content["actions"][0]["type"], "Action.OpenUrl");
    assert_eq!(
        content["actions"][0]["url"],
        "https://nano.example.com/reports/report_abc"
    );
}

// ---------------------------------------------------------------------------
// PagerDuty Events API v2
// ---------------------------------------------------------------------------

#[test]
fn pagerduty_events_v2_shape() {
    let payload = sample_alert();
    let ctx = FormatContext {
        routing_key: Some("R0UTINGKEY"),
    };
    let out = build_channel_body(ChannelType::PagerDuty, &payload, &ctx).unwrap();
    assert!(!out.sign_hmac);
    let v = parse(&out.bytes);

    assert_eq!(v["routing_key"], "R0UTINGKEY");
    assert_eq!(v["event_action"], "trigger");
    // dedup_key = the alert typeid.
    assert!(v["dedup_key"].as_str().unwrap().starts_with("alert_"));
    // Severity mapping high → error.
    assert_eq!(v["payload"]["severity"], "error");
    assert!(v["payload"]["summary"].as_str().unwrap().contains("Impossible travel"));
    assert_eq!(v["payload"]["source"], "10.0.0.5");
    assert_eq!(
        v["client_url"],
        "https://nano.example.com/alerts/alert_abc"
    );
}

#[test]
fn pagerduty_report_event_is_info_not_a_page() {
    let payload = sample_report();
    let ctx = FormatContext {
        routing_key: Some("R0UTINGKEY"),
    };
    let out = build_channel_body(ChannelType::PagerDuty, &payload, &ctx).unwrap();
    let v = parse(&out.bytes);

    // A "success" run status must NOT go through the alert severity mapping
    // (which would map unknown → "error" and page on-call): reports are info.
    assert_eq!(v["payload"]["severity"], "info");
    assert_eq!(
        v["payload"]["summary"],
        "Report ready: Weekly auth failures — SUCCESS"
    );
    assert_eq!(v["payload"]["source"], "search");
    assert_eq!(v["payload"]["custom_details"]["status"], "success");
    assert_eq!(v["payload"]["custom_details"]["row_count"], 1234);
    // No dedup key: each run is its own informational event.
    assert!(v.get("dedup_key").is_none(), "no dedup key for report events");
    // The deep link still rides along when present.
    assert_eq!(v["client_url"], "https://nano.example.com/reports/report_abc");
}

#[test]
fn pagerduty_feed_stale_and_recovery_share_incident_key() {
    let ctx = FormatContext { routing_key: Some("R0UTINGKEY") };
    let stale = parse(
        &build_channel_body(ChannelType::PagerDuty, &sample_feed_health("triggered"), &ctx)
            .unwrap()
            .bytes,
    );
    let recovered = parse(
        &build_channel_body(ChannelType::PagerDuty, &sample_feed_health("resolved"), &ctx)
            .unwrap()
            .bytes,
    );

    assert_eq!(stale["event_action"], "trigger");
    assert_eq!(recovered["event_action"], "resolve");
    assert_eq!(stale["dedup_key"], recovered["dedup_key"]);
    assert_eq!(stale["dedup_key"], "nano-health-0198a822-d0e5-7692-8f76-b963afca5e23");
    assert_eq!(stale["payload"]["custom_details"]["health_category"], "log_source");
    assert_eq!(stale["payload"]["custom_details"]["health_remediation"], "Check the upstream sender and network path.");
}

#[test]
fn slack_feed_health_card_is_actionable() {
    let payload = sample_feed_health("triggered");
    let ctx = FormatContext { routing_key: None };
    let card = parse(&build_channel_body(ChannelType::Slack, &payload, &ctx).unwrap().bytes);
    let blocks = card["attachments"][0]["blocks"].as_array().unwrap();
    let rendered = serde_json::to_string(blocks).unwrap();

    assert!(rendered.contains("No data received for 45 minutes"));
    assert!(rendered.contains("Suggested action"));
    assert!(rendered.contains("Check the upstream sender and network path"));
}

#[test]
fn pagerduty_missing_routing_key_fails_closed() {
    let payload = sample_alert();
    let ctx = FormatContext { routing_key: None };
    let err = build_channel_body(ChannelType::PagerDuty, &payload, &ctx).unwrap_err();
    assert!(err.contains("routing key"), "explains the missing key: {err}");
}

#[test]
fn pagerduty_dedup_key_strategy() {
    let ctx = FormatContext {
        routing_key: Some("k"),
    };

    // Test sends collapse into a single incident.
    let mut test = sample_alert();
    test.alert_id = None;
    test.event_type = "webhook.test".to_string();
    let v = parse(&build_channel_body(ChannelType::PagerDuty, &test, &ctx).unwrap().bytes);
    assert_eq!(v["dedup_key"], "nano-test");

    // Rule-less non-test events (e.g. case events) get no dedup key, so each is
    // its own incident rather than all collapsing together.
    let mut case = sample_alert();
    case.alert_id = None;
    case.event_type = "case.created".to_string();
    let v = parse(&build_channel_body(ChannelType::PagerDuty, &case, &ctx).unwrap().bytes);
    assert!(v.get("dedup_key").is_none(), "no dedup key for case events");
}

#[test]
fn pagerduty_severity_mapping() {
    let cases = [
        ("critical", "critical"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "info"),
        ("informational", "info"),
        ("weird", "error"),
    ];
    for (nano, pd) in cases {
        let mut payload = sample_alert();
        payload.severity = Some(nano.to_string());
        let ctx = FormatContext {
            routing_key: Some("k"),
        };
        let out = build_channel_body(ChannelType::PagerDuty, &payload, &ctx).unwrap();
        let v = parse(&out.bytes);
        assert_eq!(v["payload"]["severity"], pd, "nano '{nano}' → pd '{pd}'");
    }
}

// ---------------------------------------------------------------------------
// Email seam
// ---------------------------------------------------------------------------

#[test]
fn email_channel_not_deliverable_yet() {
    let payload = sample_alert();
    let ctx = FormatContext { routing_key: None };
    let err = build_channel_body(ChannelType::Email, &payload, &ctx).unwrap_err();
    assert!(err.contains("not yet wired"), "email deferred: {err}");
}

// ---------------------------------------------------------------------------
// Severity color helper
// ---------------------------------------------------------------------------

#[test]
fn severity_hex_is_distinct_per_level() {
    let colors = [
        severity_hex("critical"),
        severity_hex("high"),
        severity_hex("medium"),
        severity_hex("low"),
        severity_hex("informational"),
    ];
    // All five levels get a distinct color; an unknown level falls to the last.
    let unique: std::collections::HashSet<_> = colors.iter().collect();
    assert_eq!(unique.len(), 5);
    assert_eq!(severity_hex("nonsense"), severity_hex("informational"));
}

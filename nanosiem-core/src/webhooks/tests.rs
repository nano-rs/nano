// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for webhook subscription filtering, event-type validation, and
//! payload shape (NAN-1546). Delivery/HTTP paths are validated live against a
//! local receiver; these cover the pure logic that gates and shapes delivery.

use super::channels::ChannelType;
use super::models::*;
use super::service::parse_egress_allowlist;
use chrono::TimeZone;
use uuid::Uuid;

fn webhook_with(event_types: Vec<String>) -> Webhook {
    Webhook {
        id: Uuid::now_v7(),
        name: "test".to_string(),
        url: "https://example.com/hook".to_string(),
        headers_encrypted: None,
        secret_encrypted: None,
        severity_filter: None,
        event_types,
        channel_type: "generic".to_string(),
        channel_config: serde_json::json!({}),
        rule_filter: None,
        enabled: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// A generic webhook with an explicit rule filter, for routing tests.
fn webhook_with_rule_filter(rule_ids: Option<Vec<Uuid>>) -> Webhook {
    let mut w = webhook_with(default_event_types());
    w.rule_filter = rule_ids;
    w
}

// ---------------------------------------------------------------------------
// Subscription filtering
// ---------------------------------------------------------------------------

#[test]
fn subscribes_to_matches_membership() {
    let w = webhook_with(vec![EVENT_TYPE_SIEM_ALERT.to_string()]);
    assert!(w.subscribes_to(EVENT_TYPE_SIEM_ALERT));
    assert!(!w.subscribes_to(EVENT_TYPE_OBS_ALERT));
    assert!(!w.subscribes_to(EVENT_TYPE_CASE));
}

#[test]
fn empty_subscription_set_means_all() {
    // Defensive: an empty set (should not happen given the NOT NULL default)
    // is treated as "fire for everything" rather than "never fire".
    let w = webhook_with(vec![]);
    assert!(w.subscribes_to(EVENT_TYPE_SIEM_ALERT));
    assert!(w.subscribes_to(EVENT_TYPE_OBS_ALERT));
    assert!(w.subscribes_to(EVENT_TYPE_CASE));
}

#[test]
fn obs_only_webhook_rejects_detection_and_vice_versa() {
    // The acceptance criterion: an obs-only webhook must NOT get detection
    // alerts, and a SIEM-only webhook must NOT get observability alerts.
    let obs = webhook_with(vec![EVENT_TYPE_OBS_ALERT.to_string()]);
    let siem = webhook_with(vec![EVENT_TYPE_SIEM_ALERT.to_string()]);

    assert!(!obs.subscribes_to(alert_kind_to_event_type("detection")));
    assert!(obs.subscribes_to(alert_kind_to_event_type("synthetic")));

    assert!(siem.subscribes_to(alert_kind_to_event_type("detection")));
    assert!(!siem.subscribes_to(alert_kind_to_event_type("metric_monitor")));
}

// ---------------------------------------------------------------------------
// kind -> category mapping
// ---------------------------------------------------------------------------

#[test]
fn alert_kind_maps_to_correct_category() {
    assert_eq!(alert_kind_to_event_type("detection"), EVENT_TYPE_SIEM_ALERT);
    // Risk notables are a security-analyst stream (NAN-1792): they aggregate
    // detection-rule risk, so they gate on the SIEM subscription, not obs.
    assert_eq!(
        alert_kind_to_event_type("risk_notable"),
        EVENT_TYPE_SIEM_ALERT
    );
    assert_eq!(
        alert_kind_to_event_type("metric_monitor"),
        EVENT_TYPE_OBS_ALERT
    );
    assert_eq!(alert_kind_to_event_type("slo"), EVENT_TYPE_OBS_ALERT);
    assert_eq!(alert_kind_to_event_type("synthetic"), EVENT_TYPE_OBS_ALERT);
    // Unknown/future kinds fall to observability rather than silently dropping.
    assert_eq!(alert_kind_to_event_type("whatever"), EVENT_TYPE_OBS_ALERT);
}

#[test]
fn default_event_types_is_both_alert_streams() {
    assert_eq!(
        default_event_types(),
        vec![
            EVENT_TYPE_SIEM_ALERT.to_string(),
            EVENT_TYPE_OBS_ALERT.to_string()
        ]
    );
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

fn create_req(event_types: Option<Vec<String>>) -> CreateWebhookRequest {
    CreateWebhookRequest {
        name: "n".to_string(),
        url: "https://example.com".to_string(),
        headers: None,
        secret: None,
        severity_filter: None,
        event_types,
        channel_type: None,
        channel_config: None,
        rule_filter: None,
        enabled: None,
    }
}

fn update_req(event_types: Option<Vec<String>>) -> UpdateWebhookRequest {
    UpdateWebhookRequest {
        name: None,
        url: None,
        headers: None,
        secret: None,
        severity_filter: None,
        event_types,
        channel_type: None,
        channel_config: None,
        rule_filter: None,
        enabled: None,
    }
}

#[test]
fn create_accepts_valid_and_none_event_types() {
    assert!(create_req(None).validate_event_types().is_ok());
    assert!(create_req(Some(vec![EVENT_TYPE_CASE.to_string()]))
        .validate_event_types()
        .is_ok());
    assert!(create_req(Some(vec![
        EVENT_TYPE_SIEM_ALERT.to_string(),
        EVENT_TYPE_OBS_ALERT.to_string(),
        EVENT_TYPE_CASE.to_string(),
    ]))
    .validate_event_types()
    .is_ok());
}

#[test]
fn create_rejects_unknown_event_type() {
    let err = create_req(Some(vec!["not_a_stream".to_string()]))
        .validate_event_types()
        .unwrap_err();
    assert!(err.contains("not_a_stream"), "error names the bad value: {err}");
}

#[test]
fn update_rejects_empty_event_types() {
    // An explicit empty list would make the webhook silently never fire; the
    // backend rejects it (matched by the DB column being NOT NULL).
    let err = update_req(Some(vec![])).validate_event_types().unwrap_err();
    assert!(err.contains("empty"), "error explains emptiness: {err}");
}

#[test]
fn update_none_event_types_is_no_change_ok() {
    assert!(update_req(None).validate_event_types().is_ok());
}

// ---------------------------------------------------------------------------
// Payload shape / completeness
// ---------------------------------------------------------------------------

#[test]
fn alert_payload_carries_completeness_fields_and_omits_none() {
    let alert_id = Uuid::now_v7();
    let payload = WebhookPayload {
        event_type: "alert.created".to_string(),
        kind: Some("detection".to_string()),
        alert_id: Some(alert_id),
        rule_id: Some(Uuid::now_v7()),
        rule_name: Some("Impossible travel".to_string()),
        severity: Some("high".to_string()),
        entity: Some("10.0.0.5".to_string()),
        link_url: Some("https://nano.example/alerts/alert_x".to_string()),
        matched_event_count: Some(3),
        matched_events: Some(vec![]),
        created_at: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
    };

    let v = serde_json::to_value(&payload).unwrap();
    assert_eq!(v["event_type"], "alert.created");
    assert_eq!(v["kind"], "detection");
    assert_eq!(v["severity"], "high");
    assert_eq!(v["entity"], "10.0.0.5");
    assert_eq!(v["link_url"], "https://nano.example/alerts/alert_x");
    assert_eq!(v["matched_event_count"], 3);
    // alert_id is serialized as a `alert_…` typeid, not a bare UUID.
    let alert_str = v["alert_id"].as_str().expect("alert_id present");
    assert!(
        alert_str.starts_with("alert_"),
        "alert_id is a typeid: {alert_str}"
    );
}

// ---------------------------------------------------------------------------
// Egress allowlist parsing (NAN-1633)
// ---------------------------------------------------------------------------

#[test]
fn egress_allowlist_parses_valid_and_skips_garbage() {
    // Mixed valid CIDRs / bare IP + whitespace + one bad entry that's skipped.
    let cidrs = parse_egress_allowlist("10.0.0.0/8, 192.168.5.7 , nonsense/9, fd00::/8");
    assert_eq!(cidrs.len(), 3, "3 valid entries, garbage dropped");
    // Membership sanity on the parsed set.
    assert!(cidrs.iter().any(|c| c.contains("10.9.9.9".parse().unwrap())));
    assert!(cidrs
        .iter()
        .any(|c| c.contains("192.168.5.7".parse().unwrap())));
    assert!(!cidrs
        .iter()
        .any(|c| c.contains("172.16.0.1".parse().unwrap())));
}

#[test]
fn egress_allowlist_empty_is_empty() {
    assert!(parse_egress_allowlist("").is_empty());
    assert!(parse_egress_allowlist("   ,  , ").is_empty());
}

/// End-to-end through the real gate `WebhookService::validate_url` (the same
/// entry point create/update and delivery use): the allowlist opens exactly the
/// listed private range and nothing else. IP literals → no network needed.
#[tokio::test]
async fn validate_url_honors_egress_allowlist() {
    use super::service::WebhookService;

    // Baseline: private is blocked with no opt-in.
    std::env::remove_var("NANOSIEM_WEBHOOK_ALLOW_PRIVATE");
    std::env::remove_var("NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST");
    assert!(WebhookService::validate_url("http://10.0.0.5/hook")
        .await
        .is_err());

    // Allowlist opens the listed CIDR...
    std::env::set_var("NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST", "10.0.0.0/8");
    assert!(WebhookService::validate_url("http://10.0.0.5/hook")
        .await
        .is_ok());
    // ...but not other private ranges, never loopback, never metadata.
    assert!(WebhookService::validate_url("http://192.168.1.5/hook")
        .await
        .is_err());
    assert!(WebhookService::validate_url("http://127.0.0.1/hook")
        .await
        .is_err());
    assert!(WebhookService::validate_url("http://169.254.169.254/")
        .await
        .is_err());

    std::env::remove_var("NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST");
}

// ---------------------------------------------------------------------------
// Rule-filter routing (NAN-1790)
// ---------------------------------------------------------------------------

#[test]
fn rule_filter_none_or_empty_admits_all() {
    let none = webhook_with_rule_filter(None);
    let empty = webhook_with_rule_filter(Some(vec![]));
    let rid = Uuid::now_v7();
    assert!(none.passes_rule_filter(Some(rid)));
    assert!(none.passes_rule_filter(None));
    assert!(empty.passes_rule_filter(Some(rid)));
    assert!(empty.passes_rule_filter(None));
}

#[test]
fn rule_filter_set_admits_only_members() {
    let wanted = Uuid::now_v7();
    let other = Uuid::now_v7();
    let w = webhook_with_rule_filter(Some(vec![wanted]));
    assert!(w.passes_rule_filter(Some(wanted)));
    assert!(!w.passes_rule_filter(Some(other)));
    // A rule filter is detection-scoped; a rule-less alert/case is not admitted.
    assert!(!w.passes_rule_filter(None));
}

// ---------------------------------------------------------------------------
// Strict channel-type resolution at delivery (NAN-1790)
// ---------------------------------------------------------------------------

#[test]
fn resolve_channel_type_defaults_empty_to_generic() {
    // Legacy row / column default: an empty value is the generic channel.
    let mut w = webhook_with(default_event_types());
    w.channel_type = String::new();
    assert_eq!(w.resolve_channel_type().unwrap(), ChannelType::Generic);

    w.channel_type = "slack".to_string();
    assert_eq!(w.resolve_channel_type().unwrap(), ChannelType::Slack);
}

#[test]
fn resolve_channel_type_fails_closed_on_unknown() {
    // An unknown stored type must NOT fall back to generic: doing so would
    // HMAC-sign this row's secret (which for a provider channel is a provider
    // token) and POST it to the row's URL.
    let mut w = webhook_with(default_event_types());
    w.channel_type = "discord".to_string();
    let err = w.resolve_channel_type().unwrap_err();
    assert!(err.contains("discord"), "names the unknown type: {err}");
    assert!(err.contains("refusing to deliver"), "fails closed: {err}");
}

// ---------------------------------------------------------------------------
// Channel type + config validation (NAN-1790)
// ---------------------------------------------------------------------------

fn channel_create_req(channel_type: Option<&str>, url: &str) -> CreateWebhookRequest {
    CreateWebhookRequest {
        name: "n".to_string(),
        url: url.to_string(),
        headers: None,
        secret: None,
        severity_filter: None,
        event_types: None,
        channel_type: channel_type.map(str::to_string),
        channel_config: None,
        rule_filter: None,
        enabled: None,
    }
}

#[test]
fn validate_channel_accepts_generic_and_providers() {
    assert!(channel_create_req(None, "https://x").validate_channel().is_ok());
    assert!(channel_create_req(Some("generic"), "https://x").validate_channel().is_ok());
    assert!(channel_create_req(Some("slack"), "https://hooks.slack.com/x").validate_channel().is_ok());
    assert!(channel_create_req(Some("teams"), "https://outlook.office.com/x").validate_channel().is_ok());
    // PagerDuty doesn't require a user URL (server sets the Events endpoint).
    assert!(channel_create_req(Some("pagerduty"), "").validate_channel().is_ok());
}

#[test]
fn validate_channel_rejects_unknown_type() {
    let err = channel_create_req(Some("carrier_pigeon"), "https://x")
        .validate_channel()
        .unwrap_err();
    assert!(err.contains("carrier_pigeon"), "names the bad type: {err}");
}

#[test]
fn validate_channel_rejects_email_until_transport_lands() {
    let err = channel_create_req(Some("email"), "")
        .validate_channel()
        .unwrap_err();
    assert!(err.contains("not yet available"), "email deferred: {err}");
}

#[test]
fn validate_channel_requires_url_for_url_types() {
    for ct in ["generic", "slack", "teams"] {
        let err = channel_create_req(Some(ct), "  ")
            .validate_channel()
            .unwrap_err();
        assert!(err.contains("requires a destination URL"), "{ct}: {err}");
    }
}

#[test]
fn decoded_rule_filter_roundtrips_typeids_and_uuids() {
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let mut req = channel_create_req(Some("generic"), "https://x");
    // Mix a rule_… typeid with a bare UUID string — both must decode.
    req.rule_filter = Some(vec![encode_rule_id(&a), b.to_string()]);
    let decoded = req.decoded_rule_filter().unwrap().unwrap();
    assert_eq!(decoded, vec![a, b]);

    // A malformed id is a hard error naming the value.
    req.rule_filter = Some(vec!["not-an-id".to_string()]);
    assert!(req.decoded_rule_filter().unwrap_err().contains("not-an-id"));
}

#[test]
fn payload_omits_none_optional_fields() {
    let payload = WebhookPayload {
        event_type: "webhook.test".to_string(),
        kind: None,
        alert_id: None,
        rule_id: None,
        rule_name: None,
        severity: None,
        entity: None,
        link_url: None,
        matched_event_count: None,
        matched_events: None,
        created_at: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
    };
    let v = serde_json::to_value(&payload).unwrap();
    let obj = v.as_object().unwrap();
    // Only event_type + created_at survive; all None optionals are skipped.
    assert!(obj.contains_key("event_type"));
    assert!(obj.contains_key("created_at"));
    assert!(!obj.contains_key("kind"));
    assert!(!obj.contains_key("entity"));
    assert!(!obj.contains_key("link_url"));
    assert!(!obj.contains_key("alert_id"));
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for webhook subscription filtering, event-type validation, and
//! payload shape (NAN-1546). Delivery/HTTP paths are validated live against a
//! local receiver; these cover the pure logic that gates and shapes delivery.

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
        enabled: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
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

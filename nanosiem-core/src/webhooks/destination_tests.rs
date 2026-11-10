// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5224: a webhook update may not carry stored headers / secret to a new
//! destination, and a PagerDuty row is pinned by its STORED channel type.

use super::*;
use std::collections::HashMap;
use uuid::Uuid;

const OLD: &str = "https://hooks.vendor.example/notify";

fn webhook(channel_type: &str, url: &str, headers: bool, secret: bool) -> Webhook {
    Webhook {
        id: Uuid::now_v7(),
        name: "w".to_string(),
        url: url.to_string(),
        url_encrypted: None,
        url_host: None,
        headers_encrypted: headers.then(|| vec![1, 2, 3]),
        secret_encrypted: secret.then(|| vec![4, 5, 6]),
        severity_filter: None,
        event_types: vec![],
        channel_type: channel_type.to_string(),
        channel_config: serde_json::json!({}),
        rule_filter: None,
        health_category_filter: None,
        health_resource_filter: None,
        enabled: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn update(url: Option<&str>) -> UpdateWebhookRequest {
    UpdateWebhookRequest {
        name: None,
        url: url.map(str::to_string),
        headers: None,
        secret: None,
        severity_filter: None,
        event_types: None,
        channel_type: None,
        channel_config: None,
        rule_filter: None,
        health_category_filter: None,
        health_resource_filter: None,
        enabled: None,
    }
}

#[test]
fn pagerduty_url_pinned_by_stored_type_when_request_omits_channel_type() {
    let existing = webhook("pagerduty", PAGERDUTY_EVENTS_URL, false, true);
    let mut req = update(Some("https://collector.other.example/enqueue"));
    let err = resolve_update_destination(&existing, &mut req).unwrap_err();
    assert!(err.contains("PagerDuty"), "{err}");
}

#[test]
fn pagerduty_update_without_url_is_repinned() {
    let existing = webhook("pagerduty", PAGERDUTY_EVENTS_URL, false, true);
    let mut req = update(None);
    let change = resolve_update_destination(&existing, &mut req).unwrap();
    assert_eq!(req.url.as_deref(), Some(PAGERDUTY_EVENTS_URL));
    assert!(!change.origin_changed);

    let mut echoed = update(Some(PAGERDUTY_EVENTS_URL));
    assert!(resolve_update_destination(&existing, &mut echoed).is_ok());
}

#[test]
fn origin_change_with_stored_secret_requires_secret() {
    let existing = webhook("generic", OLD, false, true);
    let mut req = update(Some("https://collector.other.example/notify"));
    let err = resolve_update_destination(&existing, &mut req).unwrap_err();
    assert!(err.contains("secret") && !err.contains("headers"), "{err}");

    let mut cleared = update(Some("https://collector.other.example/notify"));
    cleared.secret = Some(String::new());
    assert!(resolve_update_destination(&existing, &mut cleared).unwrap().origin_changed);
}

#[test]
fn origin_change_with_stored_headers_requires_headers() {
    let existing = webhook("generic", OLD, true, true);
    let mut only_secret = update(Some("https://hooks.vendor.example:8443/notify"));
    only_secret.secret = Some("new".to_string());
    let err = resolve_update_destination(&existing, &mut only_secret).unwrap_err();
    assert!(err.contains("headers"), "{err}");

    let mut both = update(Some("http://hooks.vendor.example/notify"));
    both.secret = Some("new".to_string());
    both.headers = Some(HashMap::new());
    assert!(resolve_update_destination(&existing, &mut both).is_ok());
}

#[test]
fn same_origin_edit_keeps_stored_values() {
    let existing = webhook("generic", OLD, true, true);
    let mut req = update(Some("https://HOOKS.vendor.example/other/path?x=1"));
    let change = resolve_update_destination(&existing, &mut req).unwrap();
    assert!(!change.origin_changed);
    assert!(resolve_update_destination(&existing, &mut update(None)).is_ok());
}

#[test]
fn origin_change_without_stored_values_is_allowed() {
    let existing = webhook("slack", OLD, false, false);
    let mut req = update(Some("https://hooks.slack.com/services/T/B/new"));
    assert!(resolve_update_destination(&existing, &mut req).unwrap().origin_changed);
}

#[test]
fn unreadable_stored_url_fails_closed() {
    let existing = webhook("generic", "", false, true);
    let mut req = update(Some(OLD));
    assert!(resolve_update_destination(&existing, &mut req).is_err());
}

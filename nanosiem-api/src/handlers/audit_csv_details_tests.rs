// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5324: the audit CSV export keeps each event's `details`.

use super::*;
use serde_json::json;

fn entry(details: Option<serde_json::Value>) -> AuditLogEntry {
    AuditLogEntry {
        id: "evt_1".into(),
        timestamp: Utc::now(),
        user_id: None,
        user_name: Some("Dan".into()),
        action: Some("apikey_created".into()),
        source: Some("apikey".into()),
        resource_type: Some("api_key".into()),
        resource_id: None,
        resource_name: Some("pa-probe-key".into()),
        ip_address: None,
        user_agent: None,
        success: true,
        message: None,
        details,
        api_key_id: None,
        api_key_name: None,
    }
}

#[test]
fn header_ends_with_details() {
    let csv = generate_csv(&[]).unwrap();
    assert!(csv.lines().next().unwrap().ends_with(",message,details"));
}

#[test]
fn details_json_is_one_quoted_cell() {
    let csv = generate_csv(&[entry(Some(json!({"permissions": ["alerts:view", "rules:view"]})))]).unwrap();
    let row = csv.lines().nth(1).unwrap();
    assert!(
        row.ends_with(r#","{""permissions"":[""alerts:view"",""rules:view""]}""#),
        "row: {row}"
    );
}

#[test]
fn missing_details_is_an_empty_cell() {
    let csv = generate_csv(&[entry(None)]).unwrap();
    let row = csv.lines().nth(1).unwrap();
    assert!(row.ends_with(",true,,"), "row: {row}");
}

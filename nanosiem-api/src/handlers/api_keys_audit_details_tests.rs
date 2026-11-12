// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5324: API-key audit records carry the granted scopes and, on update,
//! what changed. They never carry the secret or its hash.

use super::{api_key_audit_snapshot, api_key_created_details};
use chrono::Utc;
use nanosiem_core::audit::changes::field_changes;
use nanosiem_core::auth::{ApiKey, CreateApiKeyRequest};
use serde_json::json;
use uuid::Uuid;

fn key(perms: &[&str], enabled: bool) -> ApiKey {
    ApiKey {
        id: Uuid::new_v4(),
        name: "pa-probe-key".into(),
        description: None,
        key_hash: "SECRET-HASH".into(),
        key_prefix: "nano_abc".into(),
        permissions: perms.iter().map(|s| s.to_string()).collect(),
        enabled,
        expires_at: None,
        rate_limit: Some(60),
        last_used_at: None,
        last_used_ip: None,
        created_by: Some(Uuid::new_v4()),
        created_at: Utc::now(),
    }
}

#[test]
fn created_details_list_the_granted_scopes_sorted() {
    let d = api_key_created_details(&CreateApiKeyRequest {
        name: "k".into(),
        description: None,
        permissions: vec!["search:execute".into(), "alerts:view".into(), "rules:view".into(), "cases:view".into()],
        expires_at: None,
        rate_limit: Some(100),
    });
    assert_eq!(d["permissions"], json!(["alerts:view", "cases:view", "rules:view", "search:execute"]));
    assert_eq!(d["rate_limit"], json!(100));
}

#[test]
fn snapshot_never_contains_the_hash_or_prefix() {
    let s = api_key_audit_snapshot(&key(&["search:execute"], true)).to_string();
    assert!(!s.contains("SECRET-HASH"));
    assert!(!s.contains("nano_abc"));
    assert!(s.contains("search:execute"));
}

#[test]
fn update_details_record_old_and_new_scopes() {
    let before = api_key_audit_snapshot(&key(&["search:execute"], true));
    let after = api_key_audit_snapshot(&key(&["rules:view", "search:execute"], false));
    let d = field_changes(&before, &after);
    assert_eq!(
        d["changes"]["permissions"],
        json!({"old": ["search:execute"], "new": ["rules:view", "search:execute"]})
    );
    assert_eq!(d["changes"]["enabled"], json!({"old": true, "new": false}));
    assert!(d["changes"].get("name").is_none(), "unchanged fields are omitted");
}

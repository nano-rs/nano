// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5329: the audit API and CSV emit `user_…` / `key_…` typeids (the form
//! `/api/auth/me` and `/api/api-keys` use) so exports join to those APIs.

use super::{as_typeid, generate_csv, AuditLogEntry};
use chrono::Utc;
use nanosiem_core::typeid::{api_key, encode, user};
use uuid::Uuid;

#[test]
fn raw_uuid_becomes_typeid() {
    let id = Uuid::now_v7();
    assert_eq!(as_typeid(user::PREFIX, Some(id.to_string())), Some(encode(user::PREFIX, &id)));
    assert_eq!(as_typeid(api_key::PREFIX, Some(id.to_string())), Some(encode(api_key::PREFIX, &id)));
}

#[test]
fn non_uuid_actor_passes_through() {
    assert_eq!(as_typeid(user::PREFIX, Some("system".into())), Some("system".into()));
    let tid = encode(user::PREFIX, &Uuid::now_v7());
    assert_eq!(as_typeid(user::PREFIX, Some(tid.clone())), Some(tid));
    assert_eq!(as_typeid(user::PREFIX, None), None);
}

#[test]
fn csv_carries_the_typeid() {
    let id = Uuid::now_v7();
    let entry = AuditLogEntry {
        id: "evt".into(),
        timestamp: Utc::now(),
        user_id: as_typeid(user::PREFIX, Some(id.to_string())),
        user_name: Some("pa".into()),
        action: Some("apikey_created".into()),
        source: Some("apikey".into()),
        resource_type: None,
        resource_id: None,
        resource_name: None,
        ip_address: None,
        user_agent: None,
        success: true,
        message: None,
        details: None,
        api_key_id: None,
        api_key_name: None,
    };
    let csv = generate_csv(&[entry]).unwrap();
    assert!(csv.contains(&encode(user::PREFIX, &id)), "{csv}");
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5900: the "admin" API-key preset is resolved server-side and is held to
//! the no-escalation rule: only a caller holding EVERY catalogue permission
//! can mint one.

use super::{api_key_created_details, resolve_create_preset, PresetRefusal, ADMIN_PRESET};
use chrono::{Duration, Utc};
use nanosiem_core::auth::CreateApiKeyRequest;
use serde_json::json;
use std::collections::HashSet;

fn catalogue() -> Vec<String> {
    ["users:view", "search:execute", "alerts:view", "apikeys:create", "roles:edit"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn holds<'a>(perms: &[&'a str]) -> HashSet<&'a str> {
    perms.iter().copied().collect()
}

#[test]
fn an_admin_holding_every_permission_gets_the_whole_catalogue() {
    let now = Utc::now();
    let cat = catalogue();
    let caller: HashSet<&str> = cat.iter().map(|s| s.as_str()).collect();
    let got = resolve_create_preset(
        Some(ADMIN_PRESET),
        &[],
        Some(now + Duration::days(90)),
        now,
        &cat,
        &caller,
    )
    .expect("admin may mint the admin preset")
    .expect("a preset resolves to a list");
    let mut want = cat.clone();
    want.sort();
    assert_eq!(got, want);
    // The two Dan had to add by hand on kestrel are in it.
    assert!(got.iter().any(|p| p == "users:view"));
    assert!(got.iter().any(|p| p == "search:execute"));
}

#[test]
fn a_non_admin_is_refused_and_told_what_they_lack() {
    let now = Utc::now();
    let err = resolve_create_preset(
        Some(ADMIN_PRESET),
        &[],
        Some(now + Duration::days(30)),
        now,
        &catalogue(),
        &holds(&["alerts:view", "apikeys:create", "search:execute"]),
    )
    .unwrap_err();
    assert_eq!(
        err,
        PresetRefusal::Escalation(vec!["roles:edit".into(), "users:view".into()])
    );
}

#[test]
fn a_caller_missing_one_permission_is_still_refused() {
    let now = Utc::now();
    let cat = catalogue();
    let caller: HashSet<&str> = cat.iter().map(|s| s.as_str()).filter(|p| *p != "roles:edit").collect();
    let err = resolve_create_preset(Some(ADMIN_PRESET), &[], Some(now + Duration::days(1)), now, &cat, &caller)
        .unwrap_err();
    assert_eq!(err, PresetRefusal::Escalation(vec!["roles:edit".into()]));
}

#[test]
fn the_admin_preset_needs_a_future_expiry() {
    let now = Utc::now();
    let cat = catalogue();
    let caller: HashSet<&str> = cat.iter().map(|s| s.as_str()).collect();
    for expires in [None, Some(now - Duration::minutes(1)), Some(now)] {
        assert_eq!(
            resolve_create_preset(Some(ADMIN_PRESET), &[], expires, now, &cat, &caller).unwrap_err(),
            PresetRefusal::ExpiryRequired
        );
    }
}

#[test]
fn a_preset_and_a_list_together_are_refused() {
    let now = Utc::now();
    let cat = catalogue();
    let caller: HashSet<&str> = cat.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        resolve_create_preset(
            Some(ADMIN_PRESET),
            &["alerts:view".to_string()],
            Some(now + Duration::days(1)),
            now,
            &cat,
            &caller
        )
        .unwrap_err(),
        PresetRefusal::WithPermissions
    );
}

#[test]
fn unknown_presets_and_an_empty_catalogue_are_refused() {
    let now = Utc::now();
    let caller = holds(&["*"]);
    assert_eq!(
        resolve_create_preset(Some("root"), &[], Some(now + Duration::days(1)), now, &catalogue(), &caller)
            .unwrap_err(),
        PresetRefusal::Unknown("root".into())
    );
    assert_eq!(
        resolve_create_preset(Some(ADMIN_PRESET), &[], Some(now + Duration::days(1)), now, &[], &caller)
            .unwrap_err(),
        PresetRefusal::EmptyCatalogue
    );
}

#[test]
fn a_literal_star_does_not_stand_in_for_every_permission() {
    // Server-side permissions are literal ids; a `*` entry must not unlock the preset.
    let now = Utc::now();
    let err = resolve_create_preset(
        Some(ADMIN_PRESET),
        &[],
        Some(now + Duration::days(1)),
        now,
        &catalogue(),
        &holds(&["*"]),
    )
    .unwrap_err();
    assert!(matches!(err, PresetRefusal::Escalation(m) if m.len() == 5));
}

#[test]
fn no_preset_keeps_the_hand_picked_path() {
    let now = Utc::now();
    assert_eq!(
        resolve_create_preset(None, &["alerts:view".to_string()], None, now, &catalogue(), &holds(&[])),
        Ok(None)
    );
}

#[test]
fn created_details_name_the_preset() {
    let d = api_key_created_details(&CreateApiKeyRequest {
        name: "kestrel-automation".into(),
        description: None,
        permissions: vec!["users:view".into(), "alerts:view".into()],
        expires_at: None,
        rate_limit: None,
        preset: Some(ADMIN_PRESET.into()),
    });
    assert_eq!(d["preset"], json!("admin"));
    assert_eq!(d["permissions"], json!(["alerts:view", "users:view"]));
}

#[test]
fn a_preset_only_body_deserializes_without_permissions() {
    let req: CreateApiKeyRequest = serde_json::from_value(json!({
        "name": "k",
        "preset": "admin",
        "expires_at": "2027-01-01T00:00:00Z",
    }))
    .unwrap();
    assert!(req.permissions.is_empty());
    assert_eq!(req.preset.as_deref(), Some("admin"));
}

#[test]
fn no_preset_and_no_permissions_is_refused() {
    // `permissions` defaults to [] so a preset-only body parses; that default
    // must not mint a key that can call nothing.
    let now = Utc::now();
    assert_eq!(
        resolve_create_preset(None, &[], None, now, &[], &holds(&["alerts:view"])),
        Err(PresetRefusal::PermissionsRequired)
    );
}

#[test]
fn a_mistyped_preset_field_is_refused_not_minted_empty() {
    let req: CreateApiKeyRequest = serde_json::from_value(json!({
        "name": "k",
        "presets": "admin",
        "expires_at": "2027-01-01T00:00:00Z",
    }))
    .unwrap();
    assert!(req.preset.is_none());
    assert_eq!(
        resolve_create_preset(
            req.preset.as_deref(),
            &req.permissions,
            req.expires_at,
            Utc::now(),
            &catalogue(),
            &holds(&["alerts:view"]),
        ),
        Err(PresetRefusal::PermissionsRequired)
    );
}

#[test]
fn permissions_required_is_a_400() {
    let (status, body) = PresetRefusal::PermissionsRequired.into_response();
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(body.error, "permissions_required");
}

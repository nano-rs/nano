// SPDX-License-Identifier: AGPL-3.0-or-later

//! G22: merge rules of connector identity rows over stored directory rows.

use super::*;

fn stored() -> UserRegistryRow {
    UserRegistryRow {
        provider_id: "cfeed_x".into(),
        external_id: "u1".into(),
        username: "alice".into(),
        upn: "alice@example.com".into(),
        email: "alice@example.com".into(),
        display_name: "Alice".into(),
        first_name: "Alice".into(),
        last_name: "A".into(),
        department: "Eng".into(),
        title: "SRE".into(),
        manager_upn: "boss@example.com".into(),
        manager_display_name: String::new(),
        company: String::new(),
        office_location: String::new(),
        city: "Paris".into(),
        country: "FR".into(),
        groups: vec!["admins".into()],
        account_enabled: 1,
        account_status: "active".into(),
        mfa_enabled: 1,
        last_sign_in_at: 1_700_000_000_000,
        created_in_directory_at: 1_600_000_000_000,
        phone: String::new(),
        employee_id: "42".into(),
        employee_type: String::new(),
        sync_hash: String::new(),
        last_synced_at: 0,
        version: 1,
    }
}

fn row(id: &str, text: &[(&str, &str)]) -> DirectoryRow {
    DirectoryRow {
        external_id: id.into(),
        text: text.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        ..Default::default()
    }
}

#[test]
fn a_patch_changes_only_what_it_sends() {
    let r = DirectoryRow { account_status: None, ..row("u1", &[("title", "Staff SRE")]) };
    let up = merge(&r, Some(&stored()), true);
    assert_eq!(up.title.as_deref(), Some("Staff SRE"));
    assert_eq!(up.department.as_deref(), Some("Eng"));
    assert_eq!(up.manager_upn.as_deref(), Some("boss@example.com"));
    assert_eq!(up.groups, vec!["admins".to_string()]);
    assert_eq!(up.account_status, "active");
    assert!(up.account_enabled);
    assert_eq!(up.mfa_enabled, Some(true));
}

#[test]
fn a_full_row_replaces_attributes_but_keeps_groups() {
    let r = DirectoryRow {
        account_status: Some("active".into()),
        account_enabled: Some(true),
        ..row("u1", &[("username", "alice"), ("upn", "alice@example.com")])
    };
    let up = merge(&r, Some(&stored()), false);
    assert_eq!(up.department, None, "absent in a full row = cleared");
    assert_eq!(up.manager_upn, None);
    assert_eq!(up.last_sign_in_at, None);
    assert_eq!(up.groups, vec!["admins".to_string()], "memberships come from their own streams");
}

#[test]
fn a_full_row_with_a_pending_manager_keeps_the_stored_one() {
    let r = DirectoryRow { keep_manager: true, ..row("u1", &[("upn", "alice@example.com")]) };
    let up = merge(&r, Some(&stored()), false);
    assert_eq!(up.manager_upn.as_deref(), Some("boss@example.com"));
}

#[test]
fn a_tombstone_keeps_the_record_and_marks_it_deleted() {
    let r = DirectoryRow { deleted: true, ..row("u1", &[]) };
    let up = merge(&r, Some(&stored()), true);
    assert_eq!(up.account_status, "deleted");
    assert!(!up.account_enabled);
    assert_eq!(up.upn.as_deref(), Some("alice@example.com"));
}

#[test]
fn a_tombstone_for_an_unknown_user_is_written_as_deleted() {
    let up = merge(&DirectoryRow { deleted: true, ..row("ghost", &[]) }, None, true);
    assert_eq!(up.external_id, "ghost");
    assert_eq!(up.account_status, "deleted");
}

#[test]
fn status_is_derived_from_enabled_and_back() {
    let up = merge(&DirectoryRow { account_enabled: Some(false), ..row("n", &[]) }, None, false);
    assert_eq!(up.account_status, "disabled");
    assert!(!up.account_enabled);
    let up = merge(&DirectoryRow { account_status: Some("active".into()), ..row("n", &[]) }, None, false);
    assert!(up.account_enabled);
    let up = merge(&row("n", &[]), None, false);
    assert_eq!(up.account_status, "unknown");
    assert!(!up.account_enabled);
}

#[test]
fn a_patch_without_status_revives_a_tombstoned_user_as_unknown() {
    let mut gone = stored();
    gone.account_status = "deleted".into();
    gone.account_enabled = 0;
    let up = merge(&row("u1", &[("title", "Back")]), Some(&gone), true);
    assert_eq!(up.account_status, "unknown");
}

#[test]
fn the_hash_changes_with_content() {
    let a = merge(&row("u1", &[("title", "A")]), Some(&stored()), true);
    let b = merge(&row("u1", &[("title", "B")]), Some(&stored()), true);
    assert_ne!(a.sync_hash, b.sync_hash);
    assert_eq!(a.sync_hash.len(), 64);
}

#[test]
fn provider_types_and_ids() {
    assert_eq!(provider_type_for_connector("entra_directory"), Some("entra_id"));
    assert_eq!(provider_type_for_connector("okta_users"), Some("okta"));
    assert_eq!(provider_type_for_connector("okta_system_log"), None);
    let id = provider_id_for_feed(Uuid::nil());
    assert!(id.starts_with("cfeed_") && id.len() <= 50, "{id}");
}

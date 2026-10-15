// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn users(feed: &str, id: &str, kind: SourceKind, version: i64) -> IdentityRow {
    let mut row = IdentityRow::new(&format!("{feed}:users"), id, kind, version);
    row.account_status = "active".into();
    row.account_enabled = Some(true);
    row
}

fn groups(feed: &str, member: &str, names: &[&str], admin: Option<bool>) -> IdentityRow {
    let mut row = IdentityRow::new(&format!("{feed}:groups"), member, SourceKind::Pull, 5);
    row.groups = names.iter().map(|name| name.to_string()).collect();
    row.is_admin = admin;
    row
}

fn s(value: &Option<Arc<str>>) -> Option<&str> {
    value.as_deref()
}

#[test]
fn users_and_groups_sub_feeds_of_one_provider_link_by_external_id() {
    let mut user = users("gws", "1001", SourceKind::Pull, 10);
    user.email = "Alice@Example.com".into();
    user.department = "Engineering".into();
    user.is_admin = Some(false);
    let membership = groups("gws", "1001", &["eng", "all-staff", "eng"], Some(true));
    let merged = merge_identity_rows([&membership, &user]);
    assert_eq!(merged.len(), 1);
    let person = &merged[0];
    assert_eq!(&*person.feed_id, "gws:users", "the users row is primary");
    assert_eq!(&*person.provider, "gws");
    assert_eq!(&*person.external_id, "1001");
    assert_eq!(s(&person.department), Some("Engineering"));
    assert_eq!(
        person.groups.iter().map(|g| &**g).collect::<Vec<_>>(),
        ["all-staff", "eng"],
        "sorted, de-duplicated union"
    );
    assert_eq!(person.is_admin, Some(true), "OR across the provider's sub-feeds");
    assert_eq!(person.account_enabled, Some(true));
    assert_eq!(&*person.address_keys, [Box::from("alice@example.com")]);
}

#[test]
fn membership_keyed_by_address_links_and_never_sets_account_state() {
    let mut user = users("okta", "00u1", SourceKind::Pull, 10);
    user.upn = "bob@corp.example".into();
    let mut membership = groups("okta", "BOB@corp.example", &["admins"], Some(true));
    membership.account_status = "disabled".into();
    membership.account_enabled = Some(false);
    let merged = merge_identity_rows([&user, &membership]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].is_admin, Some(true));
    assert_eq!(s(&merged[0].account_status), Some("active"));
    assert_eq!(merged[0].account_enabled, Some(true));
}

#[test]
fn precedence_is_pull_then_push_then_observed_then_newest_version() {
    let mut observed = users("obs", "o", SourceKind::Observed, 900);
    observed.email = "carol@example.com".into();
    observed.title = "Observed Title".into();
    observed.office_location = "Observed Office".into();
    observed.company = "Observed Co".into();
    let mut push = users("hr", "p", SourceKind::Push, 50);
    push.email = "carol@example.com".into();
    push.title = "Push Title".into();
    push.office_location = "Push Office".into();
    let mut old_pull = users("entra", "e", SourceKind::Pull, 1);
    old_pull.email = "carol@example.com".into();
    old_pull.title = "Old Pull Title".into();
    let mut new_pull = users("okta", "k", SourceKind::Pull, 2);
    new_pull.email = "CAROL@example.com".into();
    new_pull.title = "New Pull Title".into();
    let rows = [observed, push, old_pull, new_pull];
    // Input order never changes the result.
    let forward = merge_identity_rows(rows.iter());
    let backward = merge_identity_rows(rows.iter().rev());
    assert_eq!(forward, backward);
    assert_eq!(forward.len(), 1);
    let person = &forward[0];
    assert_eq!(s(&person.title), Some("New Pull Title"), "pull, then newest version");
    assert_eq!(s(&person.office_location), Some("Push Office"), "push beats observed");
    assert_eq!(s(&person.company), Some("Observed Co"), "observed fills what nothing else has");
    assert_eq!(&*person.feed_id, "okta:users");
}

#[test]
fn groups_come_from_the_winning_provider_only() {
    let mut a = users("okta", "1", SourceKind::Pull, 1);
    a.email = "dan@example.com".into();
    let mut b = users("entra", "2", SourceKind::Pull, 1);
    b.email = "dan@example.com".into();
    let okta_groups = {
        let mut row = groups("okta", "1", &["okta-group"], None);
        row.version = 3;
        row
    };
    let entra_groups = {
        let mut row = groups("entra", "2", &["entra-group"], Some(true));
        row.version = 9;
        row
    };
    let merged = merge_identity_rows([&a, &b, &okta_groups, &entra_groups]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].groups.iter().map(|g| &**g).collect::<Vec<_>>(), ["entra-group"]);
    assert_eq!(merged[0].is_admin, Some(true));
}

#[test]
fn distinct_people_and_username_only_linking() {
    let mut a = users("okta", "1", SourceKind::Pull, 1);
    a.email = "erin@example.com".into();
    a.username = "erin".into();
    let mut b = users("ad", "S-1", SourceKind::Push, 1);
    b.username = "ERIN".into();
    b.department = "Finance".into();
    let mut c = users("other", "S-2", SourceKind::Push, 1);
    c.username = "erin".into();
    let mut d = users("okta", "2", SourceKind::Pull, 1);
    d.email = "frank@example.com".into();
    let merged = merge_identity_rows([&a, &b, &c, &d]);
    // An addressed row never links on a bare username; two username-only
    // rows do.
    assert_eq!(merged.len(), 3);
    let erin_ad = merged.iter().find(|p| s(&p.department) == Some("Finance")).unwrap();
    assert_eq!(&*erin_ad.provider, "other", "ties break on the larger feed id");
    assert_eq!(s(&erin_ad.department), Some("Finance"));
    assert_eq!(&*erin_ad.username_keys, [Box::from("erin")]);
}

#[test]
fn a_late_row_joins_two_clusters() {
    let mut a = users("okta", "1", SourceKind::Pull, 1);
    a.email = "gail@example.com".into();
    a.title = "Engineer".into();
    let mut b = users("entra", "2", SourceKind::Pull, 1);
    b.upn = "gail@corp.example".into();
    b.department = "R&D".into();
    let mut bridge = users("hr", "3", SourceKind::Push, 1);
    bridge.email = "gail@example.com".into();
    bridge.upn = "gail@corp.example".into();
    let merged = merge_identity_rows([&a, &b, &bridge]);
    assert_eq!(merged.len(), 1);
    assert_eq!(s(&merged[0].title), Some("Engineer"));
    assert_eq!(s(&merged[0].department), Some("R&D"));
}

#[test]
fn widened_status_comes_from_the_users_row() {
    let mut user = users("entra", "oid", SourceKind::Pull, 1);
    user.upn = "h@example.com".into();
    user.account_status = "locked".into();
    let mut newer_membership = groups("entra", "oid", &["g"], None);
    newer_membership.version = 99;
    newer_membership.account_status = "deprovisioned".into();
    let merged = merge_identity_rows([&user, &newer_membership]);
    assert_eq!(s(&merged[0].account_status), Some("locked"));
}

#[test]
fn tombstones_are_ignored() {
    let mut row = users("okta", "1", SourceKind::Pull, 1);
    row.email = "x@example.com".into();
    row.deleted = true;
    assert!(merge_identity_rows([&row]).is_empty());
}

/// 500k users plus their membership rows. Run with
/// `cargo test --release -p nanosiem-lake-worker --lib bench_merge_500k -- --ignored --nocapture`.
#[test]
#[ignore = "sizing benchmark"]
fn bench_merge_500k_users_and_index_bytes() {
    const USERS: usize = 500_000;
    let make_user = |i: usize| {
        let mut row = users("gws", &format!("1{i:011}"), SourceKind::Pull, 1_700_000_000_000);
        row.email = format!("user{i}@corp.example.com");
        row.username = format!("user{i}@corp.example.com");
        row.display_name = format!("User {i}");
        row.department = format!("Dept {}", i % 50);
        row.title = format!("Title {}", i % 200);
        row.manager_upn = format!("mgr{}@corp.example.com", i % 5000);
        row.manager_display_name = format!("Manager {}", i % 5000);
        row.company = "Example Corp".into();
        row.office_location = format!("Office {}", i % 20);
        row.employee_id = format!("E{i}");
        row.employee_type = "member".into();
        row.is_admin = Some(i % 1000 == 0);
        row
    };
    let make_groups = |i: usize| {
        let mut row = groups(
            "gws",
            &format!("1{i:011}"),
            &[],
            Some(i % 997 == 0),
        );
        row.groups = vec![
            "all-staff".into(),
            format!("team-{}", i % 400),
            format!("dept-{}", i % 50),
        ];
        row
    };
    // Rows arrive in the merged file's (feed_id, external_id) order:
    // `gws:groups` sorts before `gws:users`.
    let started = std::time::Instant::now();
    let mut merger = IdentityMerger::default();
    for i in 0..USERS {
        merger.push(&make_groups(i));
    }
    for i in 0..USERS {
        merger.push(&make_user(i));
    }
    let merged = merger.finish();
    let merge_at = started.elapsed();
    assert_eq!(merged.len(), USERS);
    let directory = crate::identity_enrichment::IdentityDirectory::build(
        uuid::Uuid::new_v4(),
        uuid::Uuid::now_v7(),
        merged,
    )
    .unwrap();
    let total_at = started.elapsed();
    let person = directory.by_address("USER123456@corp.example.com").unwrap();
    assert_eq!(person.groups.len(), 3);
    eprintln!(
        "500k users + 500k membership rows: merge {merge_at:?}, merge+index {total_at:?}, \
         index ~{} MiB ({} bytes)",
        directory.approx_heap_bytes() / (1024 * 1024),
        directory.approx_heap_bytes()
    );
    assert!(total_at < std::time::Duration::from_secs(5), "{total_at:?}");
}

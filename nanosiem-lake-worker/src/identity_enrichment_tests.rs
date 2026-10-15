// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::lean_identity_merge::merge_identity_rows;
use crate::lean_identity_snapshot::{IdentityRow, SourceKind};

fn alice_rows() -> Vec<IdentityRow> {
    let mut user = IdentityRow::new("gws:users", "1001", SourceKind::Pull, 10);
    user.email = "alice@example.com".into();
    user.username = "alice@example.com".into();
    user.department = "Engineering".into();
    user.title = "Staff Engineer".into();
    user.manager_upn = "bob@example.com".into();
    user.manager_display_name = "Bob Boss".into();
    user.company = "Example Corp".into();
    user.office_location = "Montreal".into();
    user.employee_id = "E1001".into();
    user.employee_type = "member".into();
    user.account_status = "active".into();
    user.account_enabled = Some(true);
    user.is_admin = Some(false);
    let mut groups = IdentityRow::new("gws:groups", "1001", SourceKind::Pull, 10);
    groups.groups = vec!["eng@example.com".into(), "all@example.com".into()];
    vec![user, groups]
}

fn directory(rows: &[IdentityRow]) -> IdentityDirectory {
    IdentityDirectory::build(Uuid::new_v4(), Uuid::now_v7(), merge_identity_rows(rows)).unwrap()
}

fn enricher(rows: &[IdentityRow]) -> BronzeIngestEnricher {
    BronzeIngestEnricher::disabled().with_identity(Some(Arc::new(directory(rows))))
}

/// A Google Workspace login as the gws OCSF program emits it (class 3002).
fn gws_login(email: &str) -> Value {
    json!({
        "activity_id": 1,
        "category_uid": 3,
        "class_uid": 3002,
        "type_uid": 300201,
        "severity_id": 1,
        "status_id": 1,
        "time": chrono::Utc::now().timestamp_millis(),
        "metadata": {
            "product": {"name": "Google Workspace", "vendor_name": "Google"},
            "version": "1.9.0"
        },
        "service": {"name": "Google Workspace login"},
        "user": {"name": email.to_lowercase(), "email_addr": email, "uid": "1001", "domain": "example.com"}
    })
}

fn stamp(enricher: &BronzeIngestEnricher, event: &mut Value) -> IngestEnrichmentMetrics {
    let mut metrics = enricher.initial_metrics();
    enricher.enrich(event, &mut metrics).unwrap();
    metrics
}

fn assert_valid(event: &Value) {
    let result = nanosiem_core::parsers::validate_ocsf_event(event);
    assert!(result.valid, "{:?}", result.errors);
}

#[test]
fn gws_login_is_stamped_with_valid_ocsf_and_one_identity_entry() {
    let enricher = enricher(&alice_rows());
    let mut event = gws_login("alice@example.com");
    assert_valid(&event);
    let metrics = stamp(&enricher, &mut event);
    assert_valid(&event);
    let user = &event["user"];
    assert_eq!(user["org"], json!({"name": "Example Corp", "ou_name": "Engineering"}));
    assert_eq!(user["ldap_person"]["job_title"], "Staff Engineer");
    assert_eq!(user["ldap_person"]["employee_uid"], "E1001");
    assert_eq!(user["ldap_person"]["office_location"], "Montreal");
    assert_eq!(
        user["ldap_person"]["manager"],
        json!({"name": "bob@example.com", "email_addr": "bob@example.com", "full_name": "Bob Boss"})
    );
    assert_eq!(
        user["groups"],
        json!([{"name": "all@example.com"}, {"name": "eng@example.com"}])
    );
    assert!(user.get("type_id").is_none(), "not an admin");
    assert_eq!(
        event["enrichments"],
        json!([{
            "name": "user",
            "value": "alice@example.com",
            "type": "identity",
            "provider": "google_workspace",
            "data": {
                "department": "Engineering",
                "title": "Staff Engineer",
                "manager": "bob@example.com",
                "manager_name": "Bob Boss",
                "account_status": "active",
                "employee_type": "member",
                "groups": ["all@example.com", "eng@example.com"],
                "account_enabled": true,
                "is_admin": false,
                "feed_id": "gws:users",
                "matched_field": "user.email_addr"
            }
        }])
    );
    assert_eq!(
        (metrics.identity_candidates, metrics.identity_hits, metrics.identity_attached),
        (1, 1, 1)
    );
    assert_eq!(
        metrics.identity_revision,
        Some(enricher.identity().unwrap().revision().to_string())
    );
    // Re-enrichment (a replay) never stacks a second entry.
    let before = event.clone();
    stamp(&enricher, &mut event);
    assert_eq!(event, before);
}

#[test]
fn vendor_values_are_never_overwritten_and_match_is_case_insensitive() {
    let mut rows = alice_rows();
    rows[0].is_admin = Some(true);
    let enricher = enricher(&rows);
    let mut event = gws_login("ALICE@Example.COM");
    event["user"]["org"] = json!({"name": "Vendor Org", "ou_name": "Vendor Dept"});
    event["user"]["ldap_person"] = json!({"job_title": "Vendor Title", "manager": {"uid": "m-1"}});
    event["user"]["groups"] = json!([{"name": "vendor-group"}]);
    event["user"]["type_id"] = json!(1);
    event["user"]["type"] = json!("User");
    assert_valid(&event);
    stamp(&enricher, &mut event);
    assert_valid(&event);
    let user = &event["user"];
    assert_eq!(user["org"], json!({"name": "Vendor Org", "ou_name": "Vendor Dept"}));
    assert_eq!(user["ldap_person"]["job_title"], "Vendor Title");
    assert_eq!(user["ldap_person"]["employee_uid"], "E1001", "absent leaves are filled");
    assert_eq!(
        user["ldap_person"]["manager"],
        json!({"uid": "m-1"}),
        "a vendor manager is left exactly as it is"
    );
    assert_eq!(user["groups"], json!([{"name": "vendor-group"}]));
    assert_eq!((user["type_id"].clone(), user["type"].clone()), (json!(1), json!("User")));
    assert_eq!(event["enrichments"][0]["value"], "ALICE@Example.COM");
    assert_eq!(event["enrichments"][0]["data"]["is_admin"], true);
}

#[test]
fn guest_or_unknown_user_is_untouched() {
    let enricher = enricher(&alice_rows());
    let mut event = gws_login("guest@partner.example");
    let before = event.clone();
    let metrics = stamp(&enricher, &mut event);
    assert_eq!(event, before);
    assert_eq!((metrics.identity_candidates, metrics.identity_hits), (1, 0));
    // An event with no user objects is not even a candidate.
    let mut api = json!({"class_uid": 6003, "actor": {"process": {"pid": 1}}});
    let before = api.clone();
    let metrics = stamp(&enricher, &mut api);
    assert_eq!(api, before);
    assert_eq!(metrics.identity_candidates, 0);
}

#[test]
fn admin_from_users_row_role_membership_or_admin_group() {
    // Google: `isAdmin` on the users row.
    let mut google = alice_rows();
    google[0].is_admin = Some(true);
    // Entra: a privileged directory role arrives as a membership row.
    let mut entra_user = IdentityRow::new("entra:users", "oid-1", SourceKind::Pull, 1);
    entra_user.upn = "alice@example.com".into();
    let mut entra_role = IdentityRow::new("entra:groups", "oid-1", SourceKind::Pull, 1);
    entra_role.groups = vec!["role:User Administrator".into()];
    entra_role.is_admin = Some(true);
    // Okta: membership in an admin group, flagged privileged by the program.
    let mut okta_user = IdentityRow::new("okta:users", "00u1", SourceKind::Pull, 1);
    okta_user.email = "alice@example.com".into();
    let mut okta_admins = IdentityRow::new("okta:groups", "00u1", SourceKind::Pull, 1);
    okta_admins.groups = vec!["Okta Admins".into()];
    okta_admins.is_admin = Some(true);
    for rows in [google, vec![entra_user, entra_role], vec![okta_user, okta_admins]] {
        let enricher = enricher(&rows);
        let mut event = gws_login("alice@example.com");
        stamp(&enricher, &mut event);
        assert_valid(&event);
        assert_eq!(event["user"]["type_id"], 2, "{rows:?}");
        assert_eq!(event["user"]["type"], "Admin");
        assert_eq!(event["enrichments"][0]["data"]["is_admin"], true);
    }
    // A plain member is not an admin.
    let mut member = IdentityRow::new("okta:groups", "00u1", SourceKind::Pull, 1);
    member.groups = vec!["Everyone".into()];
    member.is_admin = Some(false);
    let mut okta_user = IdentityRow::new("okta:users", "00u1", SourceKind::Pull, 1);
    okta_user.email = "alice@example.com".into();
    let enricher = enricher(&[okta_user, member]);
    let mut event = gws_login("alice@example.com");
    stamp(&enricher, &mut event);
    assert!(event["user"].get("type_id").is_none());
    assert_eq!(event["enrichments"][0]["provider"], "okta_users");
}

#[test]
fn name_matches_an_address_or_an_exact_username_only() {
    let mut row = IdentityRow::new("ad:users", "S-1", SourceKind::Push, 1);
    row.username = "jsmith".into();
    row.email = "john.smith@example.com".into();
    row.title = "Analyst".into();
    let enricher = enricher(&[row]);
    let mut event = json!({"actor": {"user": {"name": "JSMITH"}}});
    stamp(&enricher, &mut event);
    assert_eq!(event["actor"]["user"]["ldap_person"]["job_title"], "Analyst");
    assert_eq!(event["enrichments"][0]["name"], "actor.user");
    assert_eq!(event["enrichments"][0]["data"]["matched_field"], "actor.user.name");
    assert_eq!(event["enrichments"][0]["provider"], "ad");
    // A name that is neither an address nor an exact username never matches
    // (no prefix or local-part guessing).
    for name in ["john.smith", "jsmit", "smith"] {
        let mut event = json!({"actor": {"user": {"name": name}}});
        let before = event.clone();
        stamp(&enricher, &mut event);
        assert_eq!(event, before, "{name}");
    }
    // uid_alt carries a UPN or a username.
    let mut event = json!({"actor": {"user": {"uid": "x", "uid_alt": "John.Smith@example.com"}}});
    stamp(&enricher, &mut event);
    assert_eq!(event["enrichments"][0]["data"]["matched_field"], "actor.user.uid_alt");
}

#[test]
fn ambiguous_username_never_matches() {
    let mut a = IdentityRow::new("ad:users", "S-1", SourceKind::Push, 1);
    a.username = "admin".into();
    let mut b = IdentityRow::new("ldap:users", "uid=admin", SourceKind::Push, 1);
    b.username = "admin".into();
    b.email = "admin@other.example".into();
    let enricher = enricher(&[a, b]);
    let mut event = json!({"user": {"name": "admin"}});
    let before = event.clone();
    stamp(&enricher, &mut event);
    assert_eq!(event, before);
}

#[test]
fn objects_that_would_break_ocsf_constraints_are_not_written() {
    let mut row = IdentityRow::new("gws:users", "1", SourceKind::Pull, 1);
    row.email = "alice@example.com".into();
    row.department = "Engineering".into();
    row.manager_display_name = "Only A Name".into();
    let enricher = enricher(&[row]);
    let mut event = gws_login("alice@example.com");
    stamp(&enricher, &mut event);
    assert_valid(&event);
    assert!(event["user"].get("org").is_none(), "no company: an org with only ou_name is invalid");
    assert!(event["user"].get("ldap_person").is_none(), "no manager UPN: no manager object");
    assert_eq!(event["enrichments"][0]["data"]["department"], "Engineering");
    assert_eq!(event["enrichments"][0]["data"]["manager_name"], "Only A Name");
    // A manager UPN that is not an OCSF email is kept as the manager's name.
    let mut row = IdentityRow::new("ad:users", "1", SourceKind::Push, 1);
    row.email = "alice@example.com".into();
    row.manager_upn = "CORP\\bob".into();
    let enricher = enricher_from(row);
    let mut event = gws_login("alice@example.com");
    stamp(&enricher, &mut event);
    assert_valid(&event);
    assert_eq!(event["user"]["ldap_person"]["manager"], json!({"name": "CORP\\bob"}));
}

fn enricher_from(row: IdentityRow) -> BronzeIngestEnricher {
    enricher(&[row])
}

#[test]
fn actor_and_subject_users_each_get_one_entry() {
    let mut rows = alice_rows();
    let mut bob = IdentityRow::new("gws:users", "1002", SourceKind::Pull, 10);
    bob.email = "bob@example.com".into();
    bob.department = "IT".into();
    bob.company = "Example Corp".into();
    rows.push(bob);
    let enricher = enricher(&rows);
    let mut event = json!({
        "actor": {"user": {"name": "bob@example.com", "email_addr": "bob@example.com"}},
        "user": {"name": "alice@example.com", "email_addr": "alice@example.com"},
        "enrichments": [{"name": "dst_endpoint.ip", "value": "1.2.3.4", "data": {}}]
    });
    let metrics = stamp(&enricher, &mut event);
    assert_eq!(metrics.identity_attached, 2);
    let entries = event["enrichments"].as_array().unwrap();
    assert_eq!(entries.len(), 3, "existing entries are kept, first");
    assert_eq!(entries[1]["name"], "actor.user");
    assert_eq!(entries[1]["data"]["department"], "IT");
    assert_eq!(entries[2]["name"], "user");
    assert_eq!(entries[2]["data"]["department"], "Engineering");
    assert_eq!(event["actor"]["user"]["org"]["ou_name"], "IT");
}

#[test]
fn without_a_directory_events_and_metrics_are_byte_identical() {
    let plain = BronzeIngestEnricher::disabled();
    let off = BronzeIngestEnricher::disabled().with_identity(None);
    let mut a = gws_login("alice@example.com");
    // NAN-3866: compare against this exact event, not a fresh `gws_login`,
    // whose `time` is a new `Utc::now()` that a loaded runner moves a ms on.
    let original = a.clone();
    let mut b = a.clone();
    let metrics_a = stamp(&plain, &mut a);
    let metrics_b = stamp(&off, &mut b);
    assert_eq!(serde_json::to_vec(&a).unwrap(), serde_json::to_vec(&b).unwrap());
    assert_eq!(a, original);
    assert_eq!(
        serde_json::to_vec(&metrics_a).unwrap(),
        serde_json::to_vec(&metrics_b).unwrap()
    );
    let recorded = serde_json::to_value(&metrics_b).unwrap();
    for key in ["identity_revision", "identity_candidates", "identity_hits", "identity_attached"] {
        assert!(recorded.get(key).is_none(), "{key} recorded with enrichment off");
    }
}

#[test]
fn ocsf_email_shape_matches_the_contract_regex() {
    for good in ["a@b.c", "first.last+tag@corp.example.com", "x_y@d-1.io"] {
        assert!(is_ocsf_email(good), "{good}");
    }
    for bad in ["CORP\\bob", "bob", "bob@localhost", "@x.com", "a b@x.com", "a@.com"] {
        assert!(!is_ocsf_email(bad), "{bad}");
    }
}

#[tokio::test]
async fn a_pinned_directory_is_rebuilt_at_most_every_interval() {
    use crate::lean_identity_snapshot::IdentityStore;
    use crate::parts::part_log::LocalObjectStore;
    let root = tempfile::tempdir().unwrap();
    let objects = LocalObjectStore::new(root.path().join("r2")).unwrap();
    let tenant = Uuid::new_v4();
    let writer = IdentityStore::new(tenant, &objects, &root.path().join("w")).unwrap();
    let first = writer.append_delta(None, alice_rows()).await.unwrap();
    let directories = LeanIdentityDirectories::new(tenant, &objects, &root.path().join("r")).unwrap();
    let pinned = directories.refresh(None).await.unwrap().unwrap();
    assert_eq!(pinned.revision(), first.manifest.revision);
    let mut changed = alice_rows();
    changed[0].version = 11;
    changed[0].title = "Principal Engineer".into();
    let second = writer
        .append_delta(Some(first.manifest.revision), changed)
        .await
        .unwrap();
    // Within the interval the pinned index is kept.
    let kept = directories.refresh(Some(&pinned)).await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&kept, &pinned));
    // Past it (zero here) the new revision is built.
    let eager = LeanIdentityDirectories::new(tenant, &objects, &root.path().join("r2-reader"))
        .unwrap()
        .with_min_rebuild_interval(std::time::Duration::ZERO);
    let rebuilt = eager.refresh(Some(&pinned)).await.unwrap().unwrap();
    assert_eq!(rebuilt.revision(), second.manifest.revision);
    assert_eq!(
        rebuilt.by_address("alice@example.com").unwrap().title.as_deref(),
        Some("Principal Engineer")
    );
    // A removed directory pointer stops stamping.
    objects.delete("identity/current.json").await.unwrap();
    assert!(eager.refresh(Some(&rebuilt)).await.unwrap().is_none());
}

#[test]
fn account_status_maps_onto_an_existing_ocsf_account_only() {
    // (status, account_enabled, expected is_disabled); the vendor's
    // is_locked below must survive.
    for (status, enabled, disabled) in [
        ("active", Some(true), Some(false)),
        ("disabled", Some(false), Some(true)),
        // Ambiguous with the v2 status set off: Okta LOCKED_OUT folds in.
        ("suspended", Some(false), None),
        ("deprovisioned", Some(false), Some(true)),
        ("locked", Some(true), None),
        ("staged", Some(false), None),
        ("", Some(false), Some(true)),
    ] {
        let mut rows = alice_rows();
        rows[0].account_status = status.into();
        rows[0].account_enabled = enabled;
        let enricher = enricher(&rows);
        // No account on the event: none is created (it needs name or uid).
        let mut event = gws_login("alice@example.com");
        stamp(&enricher, &mut event);
        assert_valid(&event);
        assert!(event["user"].get("account").is_none(), "{status}");
        if status.is_empty() {
            assert!(event["enrichments"][0]["data"].get("account_status").is_none());
        } else {
            assert_eq!(event["enrichments"][0]["data"]["account_status"], status, "raw value");
        }
        // A named account gets the flags it does not already carry.
        let mut event = gws_login("alice@example.com");
        event["user"]["account"] = json!({"uid": "1001", "is_locked": false});
        stamp(&enricher, &mut event);
        assert_valid(&event);
        let account = &event["user"]["account"];
        assert_eq!(account.get("is_disabled").and_then(Value::as_bool), disabled, "{status}");
        assert_eq!(account["is_locked"], false, "vendor value kept ({status})");
    }
    // `active` never implies is_locked = false (lockouts are reported
    // separately, e.g. by Entra).
    let enricher_active = enricher(&alice_rows());
    let mut event = gws_login("alice@example.com");
    event["user"]["account"] = json!({"name": "alice"});
    stamp(&enricher_active, &mut event);
    assert_eq!(event["user"]["account"], json!({"name": "alice", "is_disabled": false}));
    // locked sets is_locked when the vendor left it out.
    let mut rows = alice_rows();
    rows[0].account_status = "locked".into();
    let enricher = enricher(&rows);
    let mut event = gws_login("alice@example.com");
    event["user"]["account"] = json!({"name": "alice"});
    stamp(&enricher, &mut event);
    assert_valid(&event);
    assert_eq!(event["user"]["account"], json!({"name": "alice", "is_locked": true}));
}

#[test]
fn account_flags_only_for_events_near_ingest_time() {
    let mut rows = alice_rows();
    rows[0].account_status = "disabled".into();
    rows[0].account_enabled = Some(false);
    let enricher = enricher(&rows);
    let now = chrono::Utc::now().timestamp_millis();
    for (offset, stamped) in [
        (0, true),
        (-(ACCOUNT_STATE_WINDOW_MS - 60_000), true),
        (ACCOUNT_STATE_WINDOW_MS - 60_000, true),
        (-(ACCOUNT_STATE_WINDOW_MS + 60_000), false),
        (-30 * 24 * 3600 * 1000, false),
        (ACCOUNT_STATE_WINDOW_MS + 60_000, false),
    ] {
        let mut event = gws_login("alice@example.com");
        event["time"] = json!(now + offset);
        event["user"]["account"] = json!({"uid": "1001"});
        stamp(&enricher, &mut event);
        assert_valid(&event);
        assert_eq!(
            event["user"]["account"].get("is_disabled").is_some(),
            stamped,
            "offset {offset}"
        );
        // The raw status is always carried in the enrichment.
        assert_eq!(event["enrichments"][0]["data"]["account_status"], "disabled");
        // Department and the rest are not point-in-time gated.
        assert_eq!(event["user"]["org"]["ou_name"], "Engineering");
    }
    // Extreme integer times never overflow the window check.
    for time in [i64::MIN, i64::MAX] {
        let mut event = gws_login("alice@example.com");
        event["time"] = json!(time);
        event["user"]["account"] = json!({"uid": "1001"});
        stamp(&enricher, &mut event);
        assert!(event["user"]["account"].get("is_disabled").is_none(), "{time}");
    }
    // No usable time: never current.
    let mut event = gws_login("alice@example.com");
    event.as_object_mut().unwrap().remove("time");
    event["user"]["account"] = json!({"uid": "1001"});
    stamp(&enricher, &mut event);
    assert!(event["user"]["account"].get("is_disabled").is_none());
}

#[test]
fn vendor_manager_is_never_mixed_with_the_directory_manager() {
    let enricher = enricher(&alice_rows());
    for manager in [
        json!({"name": "carol@example.com"}),
        json!({"full_name": "Carol Vendor"}),
        json!({"email_addr": "carol@example.com"}),
    ] {
        let mut event = gws_login("alice@example.com");
        event["user"]["ldap_person"] = json!({"manager": manager.clone()});
        stamp(&enricher, &mut event);
        assert_eq!(event["user"]["ldap_person"]["manager"], manager);
        assert_eq!(event["user"]["ldap_person"]["job_title"], "Staff Engineer");
        assert_eq!(event["enrichments"][0]["data"]["manager"], "bob@example.com");
    }
}

#[test]
fn lookup_is_case_insensitive_on_both_paths() {
    let directory = directory(&alice_rows());
    for value in ["alice@example.com", " ALICE@example.COM ", "Alice@Example.com"] {
        assert!(directory.by_address(value).is_some(), "{value}");
    }
    assert!(directory.by_address("").is_none());
}

#[test]
fn a_v1_lockout_is_never_reported_as_a_disabled_account() {
    // Okta LOCKED_OUT with the v2 status set off arrives as `suspended` with
    // account_enabled = false (the program sets enabled = status == ACTIVE).
    let mut rows = alice_rows();
    rows[0].account_status = "suspended".into();
    rows[0].account_enabled = Some(false);
    let suspended = enricher(&rows);
    let mut event = gws_login("alice@example.com");
    event["user"]["account"] = json!({"uid": "1001"});
    stamp(&suspended, &mut event);
    assert_valid(&event);
    assert_eq!(event["user"]["account"], json!({"uid": "1001"}), "neither flag");
    assert_eq!(event["enrichments"][0]["data"]["account_status"], "suspended");
    // With v2 the same lockout is `locked`: is_locked, never is_disabled.
    rows[0].account_status = "locked".into();
    let locked = enricher(&rows);
    let mut event = gws_login("alice@example.com");
    event["user"]["account"] = json!({"uid": "1001"});
    stamp(&locked, &mut event);
    assert_eq!(event["user"]["account"], json!({"uid": "1001", "is_locked": true}));
}

#[test]
fn rfc3339_string_time_is_read_like_the_part_writer() {
    // Stamping runs before normalization: a source whose OCSF program emits
    // `time` as an RFC 3339 string still gets point-in-time state.
    let mut rows = alice_rows();
    rows[0].account_status = "disabled".into();
    rows[0].is_admin = Some(true);
    let enricher = enricher(&rows);
    let now = chrono::Utc::now();
    for (time, current) in [
        (now.to_rfc3339(), true),
        (now.format("%Y-%m-%d %H:%M:%S%.3f%:z").to_string(), true),
        ((now - chrono::Duration::hours(2)).to_rfc3339(), false),
        ("not a time".to_string(), false),
    ] {
        let mut event = gws_login("alice@example.com");
        event["time"] = json!(time);
        event["user"]["account"] = json!({"uid": "1001"});
        stamp(&enricher, &mut event);
        let user = &event["user"];
        assert_eq!(user["account"].get("is_disabled").is_some(), current, "{time}");
        assert_eq!(user.get("type_id").is_some(), current, "{time}");
        assert_eq!(event["enrichments"][0]["data"]["is_admin"], true, "{time}");
    }
}

#[test]
fn admin_type_is_point_in_time_like_the_account_flags() {
    let mut rows = alice_rows();
    rows[0].is_admin = Some(true);
    let enricher = enricher(&rows);
    let now = chrono::Utc::now().timestamp_millis();
    for (offset, stamped) in [
        (0, true),
        (-(ACCOUNT_STATE_WINDOW_MS - 60_000), true),
        (-(ACCOUNT_STATE_WINDOW_MS + 60_000), false),
        (ACCOUNT_STATE_WINDOW_MS + 60_000, false),
    ] {
        let mut event = gws_login("alice@example.com");
        event["time"] = json!(now + offset);
        stamp(&enricher, &mut event);
        assert_valid(&event);
        assert_eq!(event["user"].get("type_id").is_some(), stamped, "offset {offset}");
        // The raw role is always carried in the enrichment.
        assert_eq!(event["enrichments"][0]["data"]["is_admin"], true);
    }
}

#[test]
fn refresh_backs_off_exponentially_and_caps() {
    let every = IDENTITY_REFRESH_EVERY;
    assert_eq!(identity_refresh_delay(every, 0), every);
    assert_eq!(identity_refresh_delay(every, 1), every * 2);
    assert_eq!(identity_refresh_delay(every, 3), every * 8);
    assert_eq!(identity_refresh_delay(every, 5), IDENTITY_REFRESH_MAX_BACKOFF);
    assert_eq!(identity_refresh_delay(every, u64::MAX), IDENTITY_REFRESH_MAX_BACKOFF);
    // Never shorter than the healthy cadence.
    let slow = std::time::Duration::from_secs(3600);
    assert_eq!(identity_refresh_delay(slow, 4), slow);
}

#[test]
fn handle_status_reports_revision_age_and_failures() {
    let handle = IdentityDirectoryHandle::default();
    let empty = handle.status();
    assert_eq!((empty.revision, empty.refresh_failures), (None, 0));
    let directory = Arc::new(directory(&alice_rows()));
    handle.install(Some(directory.clone()));
    handle.record_refresh(false);
    handle.record_refresh(false);
    let status = handle.status();
    assert_eq!(status.revision, Some(directory.revision().to_string()));
    assert!((0.0..60.0).contains(&status.revision_age_seconds), "{}", status.revision_age_seconds);
    assert_eq!(status.refresh_failures, 2);
    handle.record_refresh(true);
    assert_eq!(handle.refresh_failures(), 0);
    // Age comes from the UUIDv7 timestamp.
    let then = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
    let ts = uuid::Timestamp::from_unix(uuid::NoContext, then.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 0);
    let age = revision_age_seconds(Uuid::new_v7(ts), std::time::SystemTime::now());
    assert!((599.0..=601.0).contains(&age), "{age}");
    assert_eq!(revision_age_seconds(Uuid::new_v4(), std::time::SystemTime::now()), 0.0);
}

/// A refresh that panics is caught, logged, counted, and the loop goes on.
#[tokio::test]
async fn a_panicking_refresh_never_kills_the_loop() {
    struct PanicStore(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl crate::parts::part_log::ObjectStore for PanicStore {
        async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("simulated store panic");
        }
        async fn put_if_absent(&self, _key: &str, _bytes: &[u8]) -> Result<bool> {
            unreachable!()
        }
        async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<()> {
            unreachable!()
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            unreachable!()
        }
        async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
            unreachable!()
        }
    }
    let scratch = tempfile::tempdir().unwrap();
    let store = PanicStore(Default::default());
    let tenant = Uuid::new_v4();
    let directories = LeanIdentityDirectories::new(tenant, &store, scratch.path()).unwrap();
    let handle = IdentityDirectoryHandle::default();
    let looped = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        run_identity_refresh(&directories, handle.clone(), tenant.to_string(), std::time::Duration::from_millis(1)),
    )
    .await;
    assert!(looped.is_err(), "the loop never returns");
    let calls = store.0.load(std::sync::atomic::Ordering::SeqCst);
    assert!(calls >= 3, "kept refreshing after a panic ({calls})");
    assert_eq!(handle.refresh_failures(), calls as u64, "every panic counted");
    assert!(handle.current().is_none());
}

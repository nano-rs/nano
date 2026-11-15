// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5443: lookup URL allowlist normalization, precedence and fetch audit.

use super::*;

#[test]
fn normalize_domain_canonicalizes_and_refuses_bad_entries() {
    assert_eq!(normalize_domain(" *.Feeds.Example.COM. ").unwrap(), "feeds.example.com");
    assert_eq!(normalize_domain(".intel.example.com").unwrap(), "intel.example.com");
    assert_eq!(normalize_domain("Bücher.example").unwrap(), "xn--bcher-kva.example");
    assert_eq!(normalize_domain("203.0.113.7").unwrap(), "203.0.113.7");
    assert_eq!(normalize_domain("").unwrap_err(), DomainError::Empty);
    assert_eq!(normalize_domain(" *. ").unwrap_err(), DomainError::Empty);
    // A bare TLD would allow every host under it.
    assert!(matches!(normalize_domain("com"), Err(DomainError::TopLevel(_))));
    // Schemes, ports, paths and spaces are not host names.
    for bad in ["https://example.com", "example.com:443", "example.com/feed", "exa mple.com"] {
        assert!(matches!(normalize_domain(bad), Err(DomainError::Invalid(_))), "{bad}");
    }
}

#[test]
fn normalize_domains_dedups_sorts_and_caps() {
    assert_eq!(
        normalize_domains(["b.example.com", "A.example.com", "b.example.com."]).unwrap(),
        vec!["a.example.com", "b.example.com"]
    );
    let too_many: Vec<String> = (0..=MAX_ADMIN_DOMAINS).map(|i| format!("h{i}.example.com")).collect();
    assert_eq!(normalize_domains(&too_many).unwrap_err(), DomainError::TooMany);
}

#[test]
fn host_allowed_matches_host_and_subdomains_only() {
    let entries = vec!["intel.example.com".to_string()];
    assert!(host_allowed("intel.example.com", &entries));
    assert!(host_allowed("FEEDS.intel.example.com.", &entries));
    assert!(!host_allowed("notintel.example.com", &entries));
    assert!(!host_allowed("intel.example.com.evil.test", &entries));
    assert!(!host_allowed("example.com", &entries));
}

#[test]
fn deployment_list_is_merged_unless_locked() {
    let admin = vec!["admin.example.com".to_string()];

    let merged = DeploymentAllowlist::from_values(Some("Ops.Example.com, admin.example.com"), None);
    assert!(!merged.locked);
    assert_eq!(merged.effective(&admin), vec!["admin.example.com", "ops.example.com"]);

    let locked = DeploymentAllowlist::from_values(Some("ops.example.com"), Some("true"));
    assert!(locked.locked);
    assert_eq!(locked.effective(&admin), vec!["ops.example.com"]);

    // Unset: the admin list alone; both empty = no restriction (unchanged default).
    let unset = DeploymentAllowlist::from_values(None, None);
    assert_eq!(unset.effective(&admin), admin);
    assert!(unset.effective(&[]).is_empty());

    for off in [None, Some(""), Some("false"), Some("0"), Some("nope")] {
        assert!(!DeploymentAllowlist::from_values(None, off).locked, "{off:?}");
    }
    for on in ["1", "TRUE", " yes ", "on"] {
        assert!(DeploymentAllowlist::from_values(None, Some(on)).locked, "{on}");
    }
}

#[test]
fn audit_host_never_carries_path_or_query() {
    assert_eq!(
        audit_host("https://User:pw@Feeds.Example.com.:8443/v1/1.2.3.4?key=secret#frag").as_deref(),
        Some("feeds.example.com")
    );
    assert_eq!(audit_host("not a url"), None);
}

#[test]
fn fetch_audit_event_records_host_class_and_outcome_only() {
    let actor = uuid::Uuid::new_v4();
    let event = fetch_audit_event(
        Some(actor),
        "agent",
        "feeds.example.com",
        FetchOutcome::RefusedAllowlist,
        None,
        Some("elsewhere.test"),
    );
    assert_eq!(event.action, actions::SEARCH_INPUTLOOKUP_FETCH);
    assert!(!event.success);
    let details = event.details.clone().unwrap();
    assert_eq!(details["host"], "feeds.example.com");
    assert_eq!(details["query_class"], "agent");
    assert_eq!(details["outcome"], "refused_allowlist");
    assert_eq!(details["refused_host"], "elsewhere.test");
    assert!(details.get("status").is_none());

    let ok = fetch_audit_event(None, "human", "feeds.example.com", FetchOutcome::Fetched, Some(200), None);
    assert!(ok.success);
    let details = ok.details.unwrap();
    assert_eq!(details["status"], 200);
    assert!(details.get("refused_host").is_none());
}

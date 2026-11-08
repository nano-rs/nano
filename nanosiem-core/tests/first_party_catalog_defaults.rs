// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4940: first-party content catalog reconcile decisions and the
//! profile-aware content channel. Pure (no database); the PostgreSQL path is
//! exercised on a running stack.

use nanosiem_core::content_catalog_defaults::{plan, CatalogPlan, ExistingCatalog, FirstPartyCatalog};
use nanosiem_core::schema::{
    content_branch_for, default_content_branch_for, is_first_party_content_url, is_known_content_channel,
    select_udm_root_layout, SchemaId,
};
use uuid::Uuid;

fn row(branch: &str, enabled: bool, auto: bool) -> ExistingCatalog {
    ExistingCatalog { id: Uuid::nil(), name: "x".into(), branch: branch.into(), enabled, auto_sync_enabled: auto }
}

#[test]
fn content_channel_follows_the_schema_profile() {
    assert_eq!(content_branch_for(SchemaId::Ocsf), "main");
    assert_eq!(content_branch_for(SchemaId::Udm), "legacy/clickhouse");
}

#[test]
fn fresh_install_registers_the_profile_channel() {
    assert_eq!(plan(None, "main", false), CatalogPlan::Create { branch: "main".into() });
    assert_eq!(
        plan(None, "legacy/clickhouse", false),
        CatalogPlan::Create { branch: "legacy/clickhouse".into() }
    );
}

#[test]
fn a_removed_catalog_is_not_recreated_after_adoption() {
    assert_eq!(plan(None, "main", true), CatalogPlan::Removed);
}

#[test]
fn a_disabled_catalog_is_left_alone_before_and_after_adoption() {
    for adopted in [false, true] {
        for branch in ["ocsf-1.9", "main", "legacy/clickhouse", ""] {
            assert_eq!(plan(Some(&row(branch, false, false)), "main", adopted), CatalogPlan::Disabled(Uuid::nil()));
        }
    }
}

#[test]
fn stale_first_party_channels_move_to_the_target() {
    // OCSF: the retired ocsf-1.9 default, an unset branch, or a UDM-channel row
    // left by a profile switch all move to main.
    for stored in ["ocsf-1.9", "", " ocsf-1.9 ", "legacy/clickhouse"] {
        assert_eq!(
            plan(Some(&row(stored, true, true)), "main", true),
            CatalogPlan::Update { id: Uuid::nil(), branch: Some("main".into()), enable_auto_sync: false },
            "{stored:?}"
        );
    }
    // UDM: a row on main (OCSF-only content since NAN-3897) moves to the legacy channel.
    assert_eq!(
        plan(Some(&row("main", true, true)), "legacy/clickhouse", true),
        CatalogPlan::Update { id: Uuid::nil(), branch: Some("legacy/clickhouse".into()), enable_auto_sync: false }
    );
}

#[test]
fn upgrade_switches_auto_sync_on_once() {
    // Before adoption (the old one-click add created rows with auto-sync off).
    assert_eq!(
        plan(Some(&row("main", true, false)), "main", false),
        CatalogPlan::Update { id: Uuid::nil(), branch: None, enable_auto_sync: true }
    );
    assert_eq!(
        plan(Some(&row("ocsf-1.9", true, false)), "main", false),
        CatalogPlan::Update { id: Uuid::nil(), branch: Some("main".into()), enable_auto_sync: true }
    );
    // After adoption the operator turned it off: kept off.
    assert_eq!(plan(Some(&row("main", true, false)), "main", true), CatalogPlan::Current(Uuid::nil()));
}

#[test]
fn pins_and_fork_branches_are_kept() {
    assert_eq!(plan(Some(&row("main", true, true)), "main", false), CatalogPlan::Current(Uuid::nil()));
    assert_eq!(plan(Some(&row("my-fork", true, true)), "main", true), CatalogPlan::Current(Uuid::nil()));
    assert_eq!(
        plan(Some(&row("release/2026-10", true, true)), "legacy/clickhouse", true),
        CatalogPlan::Current(Uuid::nil())
    );
    assert!(is_known_content_channel(" main "));
    assert!(!is_known_content_channel("my-fork"));
}

#[test]
fn catalog_urls_match_only_their_own_repository() {
    assert!(FirstPartyCatalog::Parsers.matches_url("https://github.com/nano-rs/parsers"));
    assert!(FirstPartyCatalog::Parsers.matches_url("https://github.com/NANO-RS/Parsers.git"));
    assert!(!FirstPartyCatalog::Parsers.matches_url("https://github.com/nano-rs/rules"));
    assert!(FirstPartyCatalog::Rules.matches_url("github.com/nano-rs/rules/"));
    assert!(!FirstPartyCatalog::Rules.matches_url("https://github.com/someone/rules"));
    assert!(!FirstPartyCatalog::Rules.matches_url("https://github.com/SigmaHQ/sigma"));
    assert!(!is_first_party_content_url("https://user:pw@github.com/nano-rs/rules"));
    assert!(!is_first_party_content_url("https://github.com/nano-rs/rules?x=1"));
    assert!(!is_first_party_content_url("https://github.com.evil.example/nano-rs/rules"));
}

#[test]
fn create_default_branch_is_profile_aware_only_for_first_party() {
    let rules = "https://github.com/nano-rs/rules";
    let sigma = "https://github.com/SigmaHQ/sigma";
    assert_eq!(default_content_branch_for(SchemaId::Ocsf, rules, None), "main");
    assert_eq!(default_content_branch_for(SchemaId::Udm, rules, None), "legacy/clickhouse");
    assert_eq!(default_content_branch_for(SchemaId::Udm, rules, Some("  ")), "legacy/clickhouse");
    assert_eq!(default_content_branch_for(SchemaId::Udm, rules, Some("my-pin")), "my-pin");
    assert_eq!(default_content_branch_for(SchemaId::Udm, sigma, None), "main");
}

#[test]
fn udm_root_layout_drops_ocsf_trees() {
    let paths: Vec<String> = ["execution/a.yml", "execution-ocsf/a.yml", "demo/b.yml", "demo-ocsf/b.yml", "README.yml"]
        .iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(select_udm_root_layout(&paths), vec!["execution/a.yml", "demo/b.yml", "README.yml"]);
}

/// NAN-4947: one URL matcher for every first-party catalog, so the enterprise
/// playbook catalog matches exactly like parsers and rules.
#[test]
fn github_repo_path_normalizes_and_rejects_like_the_first_party_matcher() {
    use nanosiem_core::content_catalog_defaults::CatalogSpec;
    use nanosiem_core::schema::github_repo_path;
    assert_eq!(github_repo_path("https://github.com/NANO-RS/Playbooks.git/").as_deref(), Some("nano-rs/playbooks"));
    assert_eq!(github_repo_path("www.github.com/nano-rs/playbooks").as_deref(), Some("nano-rs/playbooks"));
    for bad in [
        "https://user:pw@github.com/nano-rs/playbooks",
        "https://github.com/nano-rs/playbooks?x=1",
        "https://github.com/nano-rs/playbooks#readme",
        "https://github.com:8443/nano-rs/playbooks",
        "https://github.com.evil.example/nano-rs/playbooks",
        "ssh://github.com/nano-rs/playbooks",
    ] {
        assert_eq!(github_repo_path(bad), None, "{bad}");
    }
    static SPEC: CatalogSpec = CatalogSpec::new("playbooks", "nano-rs/playbooks", "n", "d", "t", "", 24);
    assert!(SPEC.matches_url("https://github.com/nano-rs/playbooks"));
    assert!(!SPEC.matches_url("https://github.com/nano-rs/playbooks-fork"));
    assert!(!SPEC.matches_url("https://github.com/nano-rs/parsers"));
    assert_eq!(SPEC.url(), "https://github.com/nano-rs/playbooks");
    // The open catalogs are unchanged by the generic spec.
    assert_eq!(FirstPartyCatalog::Parsers.url(), "https://github.com/nano-rs/parsers");
    assert_eq!(FirstPartyCatalog::from_url("github.com/nano-rs/rules.git"), Some(FirstPartyCatalog::Rules));
    assert_eq!(FirstPartyCatalog::from_url("https://github.com/nano-rs/playbooks"), None);
}

/// NAN-4947 (11-03 decision): only nano first-party repositories and the
/// signed air-gap bundle repository are admissible content sources.
#[test]
fn only_first_party_and_airgap_repositories_are_allowed() {
    use nanosiem_core::content_catalog_defaults::is_allowed_repository;
    let rules = ["nano-rs/rules"];
    assert!(is_allowed_repository("https://github.com/nano-rs/rules", &rules, "airgap://rules"));
    assert!(is_allowed_repository("github.com/Nano-RS/Rules.git", &rules, "airgap://rules"));
    assert!(is_allowed_repository(" airgap://rules ", &rules, "airgap://rules"));
    for bad in [
        "https://github.com/SigmaHQ/sigma",
        "https://github.com/nano-rs/rules-fork",
        "https://gitlab.com/nano-rs/rules",
        "https://github.com/nano-rs/rules?ref=evil",
        "airgap://parsers",
        "",
    ] {
        assert!(!is_allowed_repository(bad, &rules, "airgap://rules"), "{bad}");
    }
}

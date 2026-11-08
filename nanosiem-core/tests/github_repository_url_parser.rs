// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4947 (codex review P2): ONE GitHub repository URL parser. Admission
//! (`is_allowed_repository`), reconcile and sync (`GitHubClient::parse_url`)
//! must agree on every spelling, so an admitted URL is exactly the repository
//! that is synced.

use nanosiem_core::content_catalog_defaults::is_allowed_repository;
use nanosiem_core::rule_repository::GitHubClient;
use nanosiem_core::schema::{canonical_github_url, github_owner_repo, github_repo_path};

#[test]
fn admitted_spellings_parse_to_the_same_repository_everywhere() {
    for spelling in [
        "https://github.com/nano-rs/rules",
        "https://www.github.com/nano-rs/rules",
        "http://github.com/nano-rs/rules/",
        "github.com/nano-rs/rules.git",
        "www.github.com/NANO-RS/Rules",
        "  https://GitHub.com/nano-rs/rules.git/  ",
        "https://github.com:443/nano-rs/rules", // the default port is the same origin
    ] {
        assert!(is_allowed_repository(spelling, &["nano-rs/rules"], "airgap://rules"), "{spelling}");
        let (owner, repo) = GitHubClient::parse_url(spelling).unwrap();
        assert_eq!(format!("{owner}/{repo}").to_ascii_lowercase(), "nano-rs/rules", "{spelling}");
        assert_eq!(canonical_github_url(spelling).as_deref(), Some("https://github.com/nano-rs/rules"));
    }
}

#[test]
fn spellings_the_admission_refuses_are_refused_by_the_sync_parser_too() {
    for bad in [
        "https://nano-rs/playbooks",         // no github host
        "https://github.com/nano-rs",        // one segment
        "https://github.com/nano-rs/rules/tree/main", // deeper path
        "https://user:pw@github.com/nano-rs/rules",
        "https://github.com:8443/nano-rs/rules", // non-default port
        "https://github.com/nano-rs/rules?x=1",
        "https://github.com/nano-rs/rules#readme",
        "https://github.com.evil.example/nano-rs/rules",
        "ssh://github.com/nano-rs/rules",
        "https://github.com/nano-rs/..",
        "",
    ] {
        assert!(github_owner_repo(bad).is_none(), "{bad}");
        assert!(github_repo_path(bad).is_none(), "{bad}");
        assert!(GitHubClient::parse_url(bad).is_err(), "{bad}");
        assert!(!is_allowed_repository(bad, &["nano-rs/rules", "nano-rs/playbooks"], "airgap://rules"), "{bad}");
    }
}

#[test]
fn the_sync_parser_keeps_case_for_non_first_party_callers() {
    // e.g. the model catalog config URL: case is preserved, only the form is
    // normalized.
    assert_eq!(
        GitHubClient::parse_url("https://github.com/SigmaHQ/sigma").unwrap(),
        ("SigmaHQ".to_string(), "sigma".to_string())
    );
}

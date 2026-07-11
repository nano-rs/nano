// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    ensure_exact_operation_diff, pull_body_matches_operation, pull_state, ChangedFile,
    GitHubWriteClient, GitHubWriteError, PullHead, PullResponse,
};

#[test]
fn parses_standard_github_urls() {
    for url in [
        "https://github.com/acme/detections",
        "https://github.com/acme/detections.git",
        // Scheme-less is still accepted (the API host is always https://api.github.com).
        "github.com/acme/detections",
        "https://www.github.com/acme/detections",
        "https://github.com/acme/detections/",
    ] {
        let (owner, repo) = GitHubWriteClient::parse_github_repo(url)
            .unwrap_or_else(|e| panic!("{url} should parse: {e}"));
        assert_eq!(owner, "acme", "url={url}");
        assert_eq!(repo, "detections", "url={url}");
    }
}

#[test]
fn rejects_unsafe_repo_urls() {
    // NAN-1758: cleartext http, percent-encoded traversal, query-bearing repo,
    // extra path segments, and out-of-charset owner/repo must all be rejected.
    for url in [
        "http://github.com/acme/detections",
        "https://github.com/%2e%2e/repos",
        "https://github.com/acme/detections?ref=evil",
        "https://github.com/acme/detections#frag",
        "https://github.com/acme/detections/tree/main",
        "https://github.com/acme/det ections",
        "https://github.com/-acme/detections",
        "https://github.com/ac%20me/detections",
    ] {
        assert!(
            GitHubWriteClient::parse_github_repo(url).is_err(),
            "{url} must be rejected"
        );
    }
}

#[test]
fn rejects_non_github_hosts() {
    for url in [
        "https://gitlab.com/acme/detections",
        "https://github.company.com/acme/detections",
        // Embedded-host trick: host is evil.com, not github.com.
        "https://evil.com/github.com/acme/detections",
        "https://notgithub.com/acme/detections",
    ] {
        assert!(
            matches!(
                GitHubWriteClient::parse_github_repo(url),
                Err(GitHubWriteError::NotGitHub(_))
            ),
            "{url} must be rejected as non-github.com"
        );
    }
}

#[test]
fn rejects_urls_without_owner_repo() {
    for url in ["https://github.com/acme", "https://github.com/"] {
        assert!(
            GitHubWriteClient::parse_github_repo(url).is_err(),
            "{url} must be rejected (missing owner/repo)"
        );
    }
}

#[tokio::test]
async fn validate_endpoint_blocks_internal_targets() {
    // IP literals — no DNS, so this is network-free. Each is a blocked class
    // (cloud metadata, loopback, RFC1918, IPv6 loopback) and must be rejected.
    for url in [
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/",
        "https://10.0.0.5/",
        "https://[::1]/",
    ] {
        assert!(
            matches!(
                GitHubWriteClient::validate_endpoint(url).await,
                Err(GitHubWriteError::BlockedEndpoint(_))
            ),
            "{url} must be blocked by the SSRF guard"
        );
    }
}

#[test]
fn rejects_dot_segments() {
    // '.'/'..' owner or repo must never parse (path-traversal hardening).
    for url in [
        "https://github.com/../repo",
        "https://github.com/owner/..",
        "https://github.com/./repo",
        "https://github.com/owner/.",
    ] {
        assert!(
            GitHubWriteClient::parse_github_repo(url).is_err(),
            "{url} must be rejected (dot segment)"
        );
    }
}

#[test]
fn pull_reconciliation_distinguishes_open_closed_and_merged() {
    let response = |state: &str, merged: bool| PullResponse {
        html_url: "https://github.com/acme/detections/pull/1".to_string(),
        number: 1,
        body: None,
        state: state.to_string(),
        merged_at: merged.then(|| "2026-07-10T00:00:00Z".to_string()),
        head: PullHead {
            sha: "commit-sha".to_string(),
        },
    };
    assert_eq!(pull_state(&response("open", false)), "open");
    assert_eq!(pull_state(&response("closed", false)), "closed");
    assert_eq!(pull_state(&response("closed", true)), "merged");
}

#[test]
fn pull_reconciliation_requires_the_frozen_operation_identity() {
    let expected =
        "proposal 123\n\n<!-- nano-pr-operation: 123 -->\n\n<!-- nano-rule-id: abc -->\n";
    let legacy = "proposal 123\n\n<!-- nano-rule-id: abc -->\n";

    assert!(pull_body_matches_operation(Some(expected), expected));
    assert!(pull_body_matches_operation(Some(legacy), expected));
    assert!(pull_body_matches_operation(
        Some("analyst notes\n<!-- nano-pr-operation: 123 -->\n"),
        expected
    ));
    assert!(!pull_body_matches_operation(
        Some("proposal 456\n<!-- nano-pr-operation: 456 -->\n"),
        expected
    ));
    assert!(!pull_body_matches_operation(None, expected));
}

#[test]
fn reconciliation_rejects_unrelated_branch_or_pr_changes() {
    let expected = "detections/rule.npl";
    assert!(ensure_exact_operation_diff(
        &[ChangedFile {
            filename: expected.to_string(),
            status: "modified".to_string(),
            previous_filename: None,
        }],
        expected,
        "pull request",
    )
    .is_ok());

    for files in [
        vec![],
        vec![ChangedFile {
            filename: "detections/other.npl".to_string(),
            status: "modified".to_string(),
            previous_filename: None,
        }],
        vec![
            ChangedFile {
                filename: expected.to_string(),
                status: "modified".to_string(),
                previous_filename: None,
            },
            ChangedFile {
                filename: "deploy/production.yaml".to_string(),
                status: "modified".to_string(),
                previous_filename: None,
            },
        ],
    ] {
        assert!(matches!(
            ensure_exact_operation_diff(&files, expected, "pull request"),
            Err(GitHubWriteError::RemoteConflict(_))
        ));
    }

    for status in ["removed", "renamed", "copied"] {
        let file = ChangedFile {
            filename: expected.to_string(),
            status: status.to_string(),
            previous_filename: (status == "renamed").then(|| "deploy/production.yaml".to_string()),
        };
        assert!(ensure_exact_operation_diff(&[file], expected, "pull request").is_err());
    }
}

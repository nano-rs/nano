// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4955: the repository content reader serves first-party content only
//! and refuses every other owner before any I/O.

use super::*;

#[test]
fn test_parse_url() {
    let cases = vec![
        ("https://github.com/SigmaHQ/sigma", ("SigmaHQ", "sigma")),
        ("https://github.com/owner/repo.git", ("owner", "repo")),
        ("github.com/foo/bar", ("foo", "bar")),
        ("https://github.com/owner/repo/", ("owner", "repo")),
    ];

    for (url, expected) in cases {
        let (owner, repo) = GitHubClient::parse_url(url).unwrap();
        assert_eq!(owner, expected.0);
        assert_eq!(repo, expected.1);
    }
}

fn assert_refused<T: std::fmt::Debug>(result: Result<T, GitHubClientError>, what: &str) {
    match result {
        Err(GitHubClientError::NotFirstParty { owner, repo }) => {
            assert_eq!((owner.as_str(), repo.as_str()), ("SigmaHQ", "sigma"), "{what}");
        }
        other => panic!("{what}: expected NotFirstParty, got {other:?}"),
    }
}

/// Every read of a third-party repository is refused fail closed. There is
/// no network client to fall back to, so a refusal is the only outcome.
#[tokio::test]
async fn third_party_owner_is_refused_by_every_read() {
    let client = GitHubClient::new();
    let (o, r, b) = ("SigmaHQ", "sigma", "master");

    assert_refused(client.get_latest_commit(o, r, b).await, "get_latest_commit");
    assert_refused(client.get_tree(o, r, b, None).await, "get_tree");
    assert_refused(client.get_directory_contents_recursive(o, r, b, "rules").await, "get_directory_contents_recursive");
    assert_refused(client.get_file(o, r, "README.md", b).await, "get_file");
    assert_refused(client.get_raw_file(o, r, "README.md", b).await, "get_raw_file");

    let dir = tempfile::tempdir().unwrap();
    assert_refused(client.sparse_clone(o, r, b, &["rules".into()], dir.path()).await, "sparse_clone");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "a refused clone writes nothing");
}

/// A first-party owner never takes the refusal path; it is served from the
/// content channel store (whatever its state in this test process).
#[tokio::test]
async fn first_party_owner_reads_the_content_channel() {
    let client = GitHubClient::new();
    for owner in ["nano-rs", "nanos-sh"] {
        let result = client.get_latest_commit(owner, "parsers", "main").await;
        assert!(!matches!(result, Err(GitHubClientError::NotFirstParty { .. })), "{owner} refused as third party");
    }
}

/// A directory without the snapshot commit marker (e.g. a git checkout) is
/// not a content snapshot; nothing shells out to git.
#[tokio::test]
async fn local_commit_requires_the_snapshot_marker() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(GitHubClient::get_local_commit(dir.path()).await, Err(GitHubClientError::Parse(_))));

    std::fs::write(dir.path().join(crate::content_bundle::source::COMMIT_MARKER), "abc123\n").unwrap();
    assert_eq!(GitHubClient::get_local_commit(dir.path()).await.unwrap(), "abc123");
}

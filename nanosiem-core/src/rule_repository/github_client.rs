// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repository content reader for parser, rule, playbook and model
//! repositories (the name predates NAN-4955 and is kept for its callers).
//!
//! NAN-4955: no install talks to GitHub for content. First-party repositories
//! (`nano-rs/*`, `nanos-sh/*`) are served from the installed nano content
//! channel snapshot (`content_bundle::source`), which the app delivers as a
//! signed bundle. Every other owner is refused here, fail closed, with no
//! network request: third-party repositories can no longer be admitted
//! (NAN-4946/4947, PG 307/308), and this keeps a row that slips past
//! admission from reaching GitHub.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from GitHub API operations
#[derive(Debug, Error)]
pub enum GitHubClientError {
    #[error("GitHub API error ({status}): {message}")]
    Api { status: u16, message: String },

    /// NAN-4955: a repository outside the first-party owners. Content comes
    /// only from nano content channels, so it is never fetched.
    #[error("{owner}/{repo} is not a nano content channel; third-party repositories are not fetched")]
    NotFirstParty { owner: String, repo: String },

    #[error("Invalid GitHub URL: {0}")]
    InvalidUrl(String),

    #[error("Parse error: {0}")]
    Parse(String),

    /// NAN-4955: a first-party repository read served from nano content
    /// channels failed (channel not installed yet, unknown branch, ...).
    #[error("{0}")]
    ContentChannel(String),
}

/// Entry in a GitHub tree (file or directory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String, // "blob" or "tree"
    pub sha: String,
    pub size: Option<i64>,
    pub url: Option<String>,
}

/// Content of a file from GitHub
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContent {
    pub path: String,
    pub sha: String,
    pub content: String,
    pub encoding: String,
    pub size: i64,
}

fn content_error(e: crate::content_bundle::source::SourceError) -> GitHubClientError {
    use crate::content_bundle::source::SourceError;
    match e {
        SourceError::NotFound(_, path) => GitHubClientError::Api { status: 404, message: format!("File not found: {path}") },
        other => GitHubClientError::ContentChannel(other.to_string()),
    }
}

fn content_entries(rows: Vec<(String, &'static str, String, Option<i64>)>) -> Vec<TreeEntry> {
    rows.into_iter()
        .map(|(path, kind, sha, size)| TreeEntry { path, entry_type: kind.to_string(), sha, size, url: None })
        .collect()
}

/// First-party owners are served from content channels; anything else is
/// refused without a network request.
fn first_party(owner: &str, repo: &str) -> Result<(), GitHubClientError> {
    if crate::content_bundle::source::is_first_party(owner) {
        Ok(())
    } else {
        Err(GitHubClientError::NotFirstParty { owner: owner.to_string(), repo: repo.to_string() })
    }
}

/// Reader for first-party repository content, backed by the installed nano
/// content channel snapshots. Holds no network client.
#[derive(Clone, Default)]
pub struct GitHubClient;

impl GitHubClient {
    pub fn new() -> Self {
        Self
    }

    /// Parse owner and repo from a GitHub URL
    pub fn parse_url(url: &str) -> Result<(String, String), GitHubClientError> {
        // NAN-4947: the one parser admission, reconcile and sync share
        // (`https://github.com/owner/repo`, `www.`, `.git`, trailing slash;
        // never credentials, ports, queries or deeper paths).
        crate::schema::github_owner_repo(url).ok_or_else(|| GitHubClientError::InvalidUrl(url.to_string()))
    }

    /// The commit of the installed channel snapshot for `owner/repo@branch`.
    pub async fn get_latest_commit(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<String, GitHubClientError> {
        first_party(owner, repo)?;
        crate::content_bundle::source::commit(owner, repo, branch).await.map_err(content_error)
    }

    /// Every entry of the snapshot under `path` (all entries when `None`).
    pub async fn get_tree(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        path: Option<&str>,
    ) -> Result<Vec<TreeEntry>, GitHubClientError> {
        first_party(owner, repo)?;
        let rows = crate::content_bundle::source::tree_entries(owner, repo, branch, path.unwrap_or(""))
            .await
            .map_err(content_error)?;
        Ok(content_entries(rows))
    }

    /// Every entry below `path`, excluding `path` itself (the shape of the
    /// GitHub contents API this replaced).
    pub async fn get_directory_contents_recursive(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        path: &str,
    ) -> Result<Vec<TreeEntry>, GitHubClientError> {
        first_party(owner, repo)?;
        let rows = crate::content_bundle::source::tree_entries(owner, repo, branch, path)
            .await
            .map_err(content_error)?;
        let path = path.trim_matches('/');
        Ok(content_entries(rows).into_iter().filter(|e| e.path != path).collect())
    }

    /// One file of the snapshot.
    pub async fn get_file(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        branch: &str,
    ) -> Result<FileContent, GitHubClientError> {
        first_party(owner, repo)?;
        let (bytes, sha) = crate::content_bundle::source::file(owner, repo, branch, path)
            .await
            .map_err(content_error)?;
        let size = bytes.len() as i64;
        Ok(FileContent {
            path: path.trim_start_matches('/').to_string(),
            sha,
            content: String::from_utf8_lossy(&bytes).to_string(),
            encoding: "utf-8".to_string(),
            size,
        })
    }

    /// Materialize the snapshot's files under `paths` into `target_dir`,
    /// with a commit marker read by [`Self::get_local_commit`].
    pub async fn sparse_clone(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        paths: &[String],
        target_dir: &std::path::Path,
    ) -> Result<(), GitHubClientError> {
        first_party(owner, repo)?;
        crate::content_bundle::source::materialize(owner, repo, branch, paths, target_dir)
            .await
            .map_err(content_error)?;
        Ok(())
    }

    /// The commit of a directory written by [`Self::sparse_clone`].
    pub async fn get_local_commit(dir: &std::path::Path) -> Result<String, GitHubClientError> {
        let marker = dir.join(crate::content_bundle::source::COMMIT_MARKER);
        tokio::fs::read_to_string(&marker)
            .await
            .map(|commit| commit.trim().to_string())
            .map_err(|e| GitHubClientError::Parse(format!("no content snapshot commit in {}: {e}", dir.display())))
    }

    /// One file of the snapshot as text.
    pub async fn get_raw_file(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        branch: &str,
    ) -> Result<String, GitHubClientError> {
        first_party(owner, repo)?;
        let (bytes, _) = crate::content_bundle::source::file(owner, repo, branch, path)
            .await
            .map_err(content_error)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

#[cfg(test)]
#[path = "github_client_tests.rs"]
mod tests;

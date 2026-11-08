// SPDX-License-Identifier: AGPL-3.0-or-later
//! First-party repository reads served from installed content channels
//! (NAN-4955).
//!
//! Every repository sync (parsers, rules, playbooks, model catalog through
//! `GitHubClient`; the marketplace through its own working tree) asks this
//! module for first-party repositories instead of the network. A first-party
//! repository (`nano-rs/*`, `nanos-sh/*`) is NEVER fetched from GitHub: when
//! its channel is not installed yet the read fails with a clear error that is
//! recorded on the repository row, and the next sync after the channel
//! installs picks it up.
//!
//! The store is process-global because `GitHubClient` is constructed in many
//! places without a pool; the API and jobs processes install it at boot
//! ([`install`]). A process that never installs it (a CLI tool, a unit test)
//! gets a "not initialized" error for first-party repos, never a GitHub call.

use std::sync::OnceLock;

use super::channels::{self, Channel};
use super::store::{ContentStore, StoredFile};
use super::tree::{self, Files};

static STORE: OnceLock<ContentStore> = OnceLock::new();

/// Marker file `sparse_clone` writes into a materialized snapshot; read by
/// `GitHubClient::get_local_commit`.
pub const COMMIT_MARKER: &str = ".nano-content-commit";

/// Install the process-wide store (idempotent; the first pool wins).
pub fn install(pool: sqlx::PgPool) {
    let _ = STORE.set(ContentStore::new(pool));
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("{0} is not a published nano content channel; first-party content comes only from app.nano.rs")]
    UnknownChannel(String),
    #[error("nano content channel {0} is not installed yet (waiting for app.nano.rs); first-party content is never fetched from GitHub")]
    NotInstalled(String),
    #[error("file {1} is not in nano content channel {0}")]
    NotFound(String, String),
    #[error("nano content channel store is not initialized in this process")]
    Uninitialized,
    #[error("nano content channel store: {0}")]
    Database(#[from] sqlx::Error),
    #[error("nano content channel snapshot: {0}")]
    Io(String),
}

fn store() -> Result<&'static ContentStore, SourceError> {
    STORE.get().ok_or(SourceError::Uninitialized)
}

/// Whether reads of `owner/...` must come from content channels.
pub fn is_first_party(owner: &str) -> bool {
    channels::is_first_party_owner(owner)
}

/// The channel serving `owner/repo@branch`.
pub fn channel(owner: &str, repo: &str, branch: &str) -> Result<&'static Channel, SourceError> {
    channels::for_repo(owner, repo, branch)
        .ok_or_else(|| SourceError::UnknownChannel(format!("{owner}/{repo}@{branch}")))
}

/// The installed upstream commit of a channel.
pub async fn commit(owner: &str, repo: &str, branch: &str) -> Result<String, SourceError> {
    let ch = channel(owner, repo, branch)?;
    let row = store()?.get(ch.id).await?;
    match row.and_then(|r| r.upstream_commit.filter(|c| !c.is_empty()).zip(r.tree_sha256)) {
        Some((commit, _)) => Ok(commit),
        None => Err(SourceError::NotInstalled(ch.id.to_string())),
    }
}

/// A `GitHubClient`-shaped listing: every file under `prefix` as a `blob`
/// (sha = git blob SHA-1, as GitHub reports) plus each ancestor directory as
/// a `tree`, in path order.
pub async fn tree_entries(
    owner: &str,
    repo: &str,
    branch: &str,
    prefix: &str,
) -> Result<Vec<(String, &'static str, String, Option<i64>)>, SourceError> {
    let ch = channel(owner, repo, branch)?;
    commit(owner, repo, branch).await?;
    let files = store()?.list_files(ch.id, prefix).await?;
    Ok(with_dirs(&files, prefix))
}

/// Add directory entries for every ancestor of every file under `prefix`.
pub fn with_dirs(files: &[StoredFile], prefix: &str) -> Vec<(String, &'static str, String, Option<i64>)> {
    let prefix = prefix.trim_matches('/');
    let mut dirs = std::collections::BTreeSet::new();
    for f in files {
        let mut acc = String::new();
        let parts: Vec<&str> = f.path.split('/').collect();
        for part in &parts[..parts.len().saturating_sub(1)] {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            if prefix.is_empty() || acc == prefix || acc.starts_with(&format!("{prefix}/")) {
                dirs.insert(acc.clone());
            }
        }
    }
    let mut out: Vec<(String, &'static str, String, Option<i64>)> = dirs
        .into_iter()
        .map(|d| (d, "tree", String::new(), None))
        .chain(files.iter().map(|f| (f.path.clone(), "blob", f.blob_sha1.clone(), Some(f.size))))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// One file's bytes and blob id.
pub async fn file(owner: &str, repo: &str, branch_or_commit: &str, path: &str) -> Result<(Vec<u8>, String), SourceError> {
    let ch = resolve(owner, repo, branch_or_commit).await?;
    let path = path.trim_start_matches('/');
    let bytes = store()?
        .read_file(ch.id, path)
        .await?
        .ok_or_else(|| SourceError::NotFound(ch.id.to_string(), path.to_string()))?;
    let sha = tree::git_blob_sha1(&bytes);
    Ok((bytes, sha))
}

/// `branch_or_commit` is a branch, or the installed commit of one of this
/// repo's channels (syncs fetch files "at" the commit they just read).
async fn resolve(owner: &str, repo: &str, branch_or_commit: &str) -> Result<&'static Channel, SourceError> {
    if let Ok(ch) = channel(owner, repo, branch_or_commit) {
        return Ok(ch);
    }
    let candidates: Vec<&'static Channel> = channels::all()
        .filter(|c| channels::for_repo(owner, repo, c.branch).is_some_and(|m| m.id == c.id))
        .collect();
    for ch in candidates {
        if let Some(row) = store()?.get(ch.id).await? {
            if row.upstream_commit.as_deref() == Some(branch_or_commit) {
                return Ok(ch);
            }
        }
    }
    Err(SourceError::UnknownChannel(format!("{owner}/{repo}@{branch_or_commit}")))
}

/// The installed files of a channel under `prefixes` (empty = all).
pub async fn files(owner: &str, repo: &str, branch: &str, prefixes: &[String]) -> Result<(String, Files), SourceError> {
    let ch = channel(owner, repo, branch)?;
    let commit = commit(owner, repo, branch).await?;
    Ok((commit, store()?.read_tree(ch.id, prefixes).await?))
}

/// Write the installed snapshot (or the files under `prefixes`) into `dir`
/// with a [`COMMIT_MARKER`]. Returns the commit.
pub async fn materialize(
    owner: &str,
    repo: &str,
    branch: &str,
    prefixes: &[String],
    dir: &std::path::Path,
) -> Result<String, SourceError> {
    let (commit, files) = files(owner, repo, branch, prefixes).await?;
    let target = dir.to_path_buf();
    let marker = commit.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        tree::materialize(&files, &target)?;
        std::fs::write(target.join(COMMIT_MARKER), marker)
    })
    .await
    .map_err(|e| SourceError::Io(e.to_string()))?
    .map_err(|e| SourceError::Io(e.to_string()))?;
    Ok(commit)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! GitHub API client for fetching repository contents
//!
//! Public repositories only. Without a platform token every caller shares
//! GitHub's unauthenticated 60 requests/hour per egress IP; with the optional
//! platform token (`NANO_GITHUB_TOKEN_FILE` or `NANO_GITHUB_TOKEN`) API calls
//! are authenticated and get the token's quota.
//!
//! A rate-limit answer (403/429 with `x-ratelimit-remaining: 0`, `Retry-After`
//! or a secondary-limit body) trips a process-wide backoff for that API base:
//! until it expires every client short-circuits with
//! [`GitHubClientError::RateLimited`] instead of hammering GitHub.

use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};

/// Errors from GitHub API operations
#[derive(Debug, Error)]
pub enum GitHubClientError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("GitHub API error ({status}): {message}")]
    Api { status: u16, message: String },

    #[error("Rate limited, retry after {retry_after} seconds")]
    RateLimited { retry_after: u64 },

    #[error("Repository not found or not public: {owner}/{repo}")]
    NotFound { owner: String, repo: String },

    /// The repository exists but the requested branch does not (NAN-3236):
    /// a 404 from `/branches/{branch}` used to surface as `NotFound`, which
    /// sent the playbooks catalog mirror's `ocsf-1.9` miss down a
    /// "repo is private" rabbit hole.
    #[error("Branch not found: {owner}/{repo}@{branch} (the repository exists)")]
    BranchNotFound { owner: String, repo: String, branch: String },

    #[error("Invalid GitHub URL: {0}")]
    InvalidUrl(String),

    #[error("Parse error: {0}")]
    Parse(String),
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

/// GitHub API response for tree
#[derive(Debug, Deserialize)]
struct GitHubTreeResponse {
    #[allow(dead_code)]
    sha: String,
    #[allow(dead_code)]
    url: String,
    tree: Vec<GitHubTreeEntry>,
    truncated: bool,
}

#[derive(Debug, Deserialize)]
struct GitHubTreeEntry {
    path: String,
    #[serde(rename = "type")]
    entry_type: String,
    sha: String,
    size: Option<i64>,
    url: Option<String>,
}

/// GitHub API response for file content
#[derive(Debug, Deserialize)]
struct GitHubContentResponse {
    #[allow(dead_code)]
    name: String,
    path: String,
    sha: String,
    size: i64,
    content: Option<String>,
    encoding: Option<String>,
    #[allow(dead_code)]
    download_url: Option<String>,
}

/// GitHub API response for commit
#[derive(Debug, Deserialize)]
struct GitHubCommitResponse {
    sha: String,
}

/// GitHub API response for branch
#[derive(Debug, Deserialize)]
struct GitHubBranchResponse {
    commit: GitHubCommitResponse,
}

/// GitHub API response for contents (single entry)
#[derive(Debug, Deserialize)]
struct GitHubContentEntry {
    path: String,
    #[serde(rename = "type")]
    entry_type: String, // "file" or "dir"
    sha: String,
    size: Option<i64>,
    url: Option<String>,
}

const GITHUB_API_BASE_URL: &str = "https://api.github.com";
const GITHUB_RAW_BASE_URL: &str = "https://raw.githubusercontent.com";
/// Upper bound on a single backoff, whatever the upstream headers say.
const MAX_BACKOFF_SECS: u64 = 3600;
/// Backoff when GitHub signals a limit without saying for how long.
const DEFAULT_BACKOFF_SECS: u64 = 60;
/// Random extra delay so replicas and workers do not resume in lockstep.
const MAX_BACKOFF_JITTER_SECS: u64 = 30;

/// Process-wide rate-limit state for one API base URL. Shared by every
/// [`GitHubClient`] built for that base, because callers construct clients
/// per request and the upstream quota is per credential/egress IP, not per
/// client instance.
#[derive(Debug, Default)]
struct RateLimitGate {
    /// Unix milliseconds until which requests must not be sent; 0 = open.
    blocked_until_ms: AtomicI64,
}

impl RateLimitGate {
    fn for_base(base: &str) -> Arc<Self> {
        static GATES: OnceLock<Mutex<HashMap<String, Arc<RateLimitGate>>>> = OnceLock::new();
        let gates = GATES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut gates = gates.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        gates.entry(base.to_owned()).or_default().clone()
    }

    fn remaining(&self) -> Option<Duration> {
        let until = self.blocked_until_ms.load(Ordering::Relaxed);
        let now = now_millis();
        (until > now).then(|| Duration::from_millis((until - now) as u64))
    }

    /// Extend (never shorten) the backoff window.
    fn trip(&self, wait: Duration) {
        let until = now_millis().saturating_add(wait.as_millis().min(i64::MAX as u128) as i64);
        self.blocked_until_ms.fetch_max(until, Ordering::Relaxed);
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The optional platform GitHub token, read once per process. A mounted
/// secret file (`NANO_GITHUB_TOKEN_FILE`) wins over the plain environment
/// variable (`NANO_GITHUB_TOKEN`). The value is never logged.
pub fn platform_github_token() -> Option<Arc<str>> {
    static TOKEN: OnceLock<Option<Arc<str>>> = OnceLock::new();
    TOKEN
        .get_or_init(|| {
            let token = resolve_platform_token(
                std::env::var_os("NANO_GITHUB_TOKEN_FILE").map(std::path::PathBuf::from).as_deref(),
                std::env::var("NANO_GITHUB_TOKEN").ok(),
            );
            match &token {
                Some(_) => tracing::info!("GitHub API calls authenticated with the platform token"),
                None => tracing::info!("No platform GitHub token configured; GitHub API calls are unauthenticated (60/h per egress IP)"),
            }
            token
        })
        .clone()
}

fn resolve_platform_token(file: Option<&std::path::Path>, env: Option<String>) -> Option<Arc<str>> {
    let from_file = file.and_then(|path| match std::fs::read_to_string(path) {
        Ok(contents) => Some(contents),
        Err(error) => {
            // Path only: never the contents.
            warn!(path = %path.display(), kind = ?error.kind(), "NANO_GITHUB_TOKEN_FILE unreadable; ignoring it");
            None
        }
    });
    from_file
        .or(env)
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
        .map(Arc::from)
}

/// Client for interacting with GitHub API (public repos only)
#[derive(Clone)]
pub struct GitHubClient {
    api_base_url: String,
    /// Base for raw file content (`raw.githubusercontent.com` in production).
    raw_base_url: String,
    http_client: reqwest::Client,
    rate_limit_remaining: std::sync::Arc<AtomicU32>,
    /// Bearer token for `api_base_url` requests only; deliberately no Debug.
    token: Option<Arc<str>>,
    gate: Arc<RateLimitGate>,
}

impl Default for GitHubClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GitHubClient {
    /// Create a new GitHub client, authenticated with the platform token
    /// when one is configured.
    pub fn new() -> Self {
        Self::with_api_base_url(GITHUB_API_BASE_URL).with_token(platform_github_token())
    }

    /// Construct with a trusted API endpoint (also used by local HTTP fixtures).
    /// Unauthenticated unless [`Self::with_token`] is applied.
    pub fn with_api_base_url(api_base_url: &str) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        let api_base_url = api_base_url.trim_end_matches('/').to_owned();

        Self {
            gate: RateLimitGate::for_base(&api_base_url),
            api_base_url,
            raw_base_url: GITHUB_RAW_BASE_URL.to_owned(),
            http_client,
            rate_limit_remaining: std::sync::Arc::new(AtomicU32::new(60)),
            token: None,
        }
    }

    /// Serve raw file content from a trusted local fixture instead of
    /// `raw.githubusercontent.com` (tests only; production never calls it).
    pub fn with_raw_base_url(mut self, raw_base_url: &str) -> Self {
        self.raw_base_url = raw_base_url.trim_end_matches('/').to_owned();
        self
    }

    /// Send `Authorization: Bearer <token>` on API requests (never on
    /// `raw.githubusercontent.com` or git clones).
    pub fn with_token(mut self, token: Option<Arc<str>>) -> Self {
        self.token = token.filter(|t| !t.is_empty());
        self
    }

    /// Whether API requests carry the platform token.
    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    /// Time left on the process-wide rate-limit backoff for this API base,
    /// `None` when requests may be sent.
    pub fn backoff_remaining(&self) -> Option<Duration> {
        self.gate.remaining()
    }

    /// Build an API GET, refusing locally while the rate-limit backoff holds.
    fn api_get(&self, url: &str) -> Result<reqwest::RequestBuilder, GitHubClientError> {
        if let Some(wait) = self.gate.remaining() {
            return Err(GitHubClientError::RateLimited { retry_after: wait.as_secs().max(1) });
        }
        let request = self
            .http_client
            .get(url)
            .header(USER_AGENT, "NanoSIEM/1.0")
            .header(ACCEPT, "application/vnd.github.v3+json");
        Ok(match &self.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        })
    }

    /// Parse owner and repo from a GitHub URL
    pub fn parse_url(url: &str) -> Result<(String, String), GitHubClientError> {
        // Handle formats:
        // - https://github.com/owner/repo
        // - https://github.com/owner/repo.git
        // - github.com/owner/repo
        let url = url
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .replace("http://", "https://");

        let parts: Vec<&str> = url
            .trim_start_matches("https://")
            .trim_start_matches("github.com/")
            .split('/')
            .collect();

        if parts.len() >= 2 {
            Ok((parts[0].to_string(), parts[1].to_string()))
        } else {
            Err(GitHubClientError::InvalidUrl(url))
        }
    }

    /// Get current rate limit remaining
    pub fn rate_limit_remaining(&self) -> u32 {
        self.rate_limit_remaining.load(Ordering::Relaxed)
    }

    /// Get the latest commit SHA for a branch
    pub async fn get_latest_commit(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<String, GitHubClientError> {
        let url = format!(
            "{}/repos/{}/{}/branches/{}",
            self.api_base_url,
            owner, repo, branch
        );

        debug!("Fetching latest commit from {}", url);

        let response = self
            .api_get(&url)?
            .send()
            .await?;

        self.update_rate_limit(&response);

        if response.status() == 404 {
            return Err(self.branch_or_repo_not_found(owner, repo, branch).await);
        }

        if is_limit_status(response.status()) {
            return Err(self.rate_limit_error(response).await);
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            return Err(GitHubClientError::Api { status, message });
        }

        let branch_info: GitHubBranchResponse = response.json().await?;
        Ok(branch_info.commit.sha)
    }

    /// Classify a `/branches/{branch}` 404: GitHub answers 404 both for a
    /// missing repository and for a missing branch of a public one. One probe
    /// of `/repos/{owner}/{repo}` tells them apart; when the probe itself
    /// fails the conservative `NotFound` is kept. NAN-3236.
    async fn branch_or_repo_not_found(&self, owner: &str, repo: &str, branch: &str) -> GitHubClientError {
        let url = format!("{}/repos/{}/{}", self.api_base_url, owner, repo);
        let Ok(request) = self.api_get(&url) else {
            return GitHubClientError::NotFound { owner: owner.to_string(), repo: repo.to_string() };
        };
        let repo_exists = match request.send().await {
            Ok(response) => {
                self.update_rate_limit(&response);
                response.status().is_success()
            }
            Err(_) => false,
        };
        if repo_exists {
            GitHubClientError::BranchNotFound {
                owner: owner.to_string(),
                repo: repo.to_string(),
                branch: branch.to_string(),
            }
        } else {
            GitHubClientError::NotFound { owner: owner.to_string(), repo: repo.to_string() }
        }
    }

    /// Get the tree for a repository at a specific path
    pub async fn get_tree(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        path: Option<&str>,
    ) -> Result<Vec<TreeEntry>, GitHubClientError> {
        // First get the tree SHA for the branch
        let url = format!(
            "{}/repos/{}/{}/git/trees/{}?recursive=1",
            self.api_base_url,
            owner, repo, branch
        );

        debug!("Fetching tree from {}", url);

        let response = self
            .api_get(&url)?
            .send()
            .await?;

        self.update_rate_limit(&response);

        if response.status() == 404 {
            return Err(GitHubClientError::NotFound {
                owner: owner.to_string(),
                repo: repo.to_string(),
            });
        }

        if is_limit_status(response.status()) {
            return Err(self.rate_limit_error(response).await);
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            return Err(GitHubClientError::Api { status, message });
        }

        let tree_response: GitHubTreeResponse = response.json().await?;

        if tree_response.truncated {
            warn!(
                "GitHub tree response was truncated for {}/{}, some files may be missing. Consider selecting specific folders.",
                owner, repo
            );
        }

        // Filter by path prefix if specified
        let entries: Vec<TreeEntry> = tree_response
            .tree
            .into_iter()
            .filter(|e| {
                if let Some(prefix) = path {
                    let prefix = prefix.trim_start_matches('/').trim_end_matches('/');
                    // Empty prefix means root of repo - no filtering needed
                    if prefix.is_empty() {
                        return true;
                    }
                    // Must match exactly "rules/" not "rules-emerging/"
                    e.path == prefix || e.path.starts_with(&format!("{}/", prefix))
                } else {
                    true
                }
            })
            .map(|e| TreeEntry {
                path: e.path,
                entry_type: e.entry_type,
                sha: e.sha,
                size: e.size,
                url: e.url,
            })
            .collect();

        debug!("Found {} entries in tree", entries.len());
        Ok(entries)
    }

    /// Get the tree for a specific subdirectory using the Contents API
    /// This avoids truncation issues with large repos by fetching one directory at a time
    pub async fn get_directory_contents_recursive(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        path: &str,
    ) -> Result<Vec<TreeEntry>, GitHubClientError> {
        let mut all_entries = Vec::new();
        let mut dirs_to_process = vec![path.to_string()];

        while let Some(current_path) = dirs_to_process.pop() {
            let url = format!(
                "{}/repos/{}/{}/contents/{}?ref={}",
            self.api_base_url,
                owner, repo, current_path, branch
            );

            debug!("Fetching contents from {}", url);

            let response = self
                .api_get(&url)?
                .send()
                .await?;

            self.update_rate_limit(&response);

            if response.status() == 404 {
                // Directory doesn't exist, skip it
                continue;
            }

            if is_limit_status(response.status()) {
                return Err(self.rate_limit_error(response).await);
            }

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let message = response.text().await.unwrap_or_default();
                return Err(GitHubClientError::Api { status, message });
            }

            let contents: Vec<GitHubContentEntry> = response.json().await?;

            for entry in contents {
                if entry.entry_type == "dir" {
                    dirs_to_process.push(entry.path.clone());
                }
                all_entries.push(TreeEntry {
                    path: entry.path,
                    entry_type: if entry.entry_type == "file" {
                        "blob".to_string()
                    } else {
                        "tree".to_string()
                    },
                    sha: entry.sha,
                    size: entry.size,
                    url: entry.url,
                });
            }
        }

        debug!("Found {} entries via contents API", all_entries.len());
        Ok(all_entries)
    }

    /// Get the content of a file
    pub async fn get_file(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        branch: &str,
    ) -> Result<FileContent, GitHubClientError> {
        let url = format!(
            "{}/repos/{}/{}/contents/{}?ref={}",
            self.api_base_url,
            owner, repo, path, branch
        );

        debug!("Fetching file from {}", url);

        let response = self
            .api_get(&url)?
            .send()
            .await?;

        self.update_rate_limit(&response);

        if response.status() == 404 {
            return Err(GitHubClientError::Api {
                status: 404,
                message: format!("File not found: {}", path),
            });
        }

        if is_limit_status(response.status()) {
            return Err(self.rate_limit_error(response).await);
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            return Err(GitHubClientError::Api { status, message });
        }

        let content_response: GitHubContentResponse = response.json().await?;

        // Decode base64 content
        let content = if let Some(encoded) = content_response.content {
            // GitHub returns base64 with newlines, remove them
            let cleaned = encoded.replace('\n', "");
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cleaned) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                Err(e) => {
                    return Err(GitHubClientError::Parse(format!(
                        "Failed to decode base64 content: {}",
                        e
                    )))
                }
            }
        } else {
            return Err(GitHubClientError::Parse(
                "File content is empty or binary".to_string(),
            ));
        };

        Ok(FileContent {
            path: content_response.path,
            sha: content_response.sha,
            content,
            encoding: content_response
                .encoding
                .unwrap_or_else(|| "utf-8".to_string()),
            size: content_response.size,
        })
    }

    /// Clone a repository with sparse-checkout for specific paths
    /// This avoids API rate limits by using git protocol
    pub async fn sparse_clone(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        paths: &[String],
        target_dir: &std::path::Path,
    ) -> Result<(), GitHubClientError> {
        use tokio::process::Command;

        let repo_url = format!("https://github.com/{}/{}.git", owner, repo);

        debug!(
            "Sparse cloning {} to {:?} with paths: {:?}",
            repo_url, target_dir, paths
        );

        // Initialize empty repo
        let init_output = Command::new("git")
            .args(["init"])
            .current_dir(target_dir)
            .output()
            .await
            .map_err(|e| GitHubClientError::Parse(format!("Failed to run git init: {}", e)))?;

        if !init_output.status.success() {
            return Err(GitHubClientError::Parse(format!(
                "git init failed: {}",
                String::from_utf8_lossy(&init_output.stderr)
            )));
        }

        // Add remote
        let remote_output = Command::new("git")
            .args(["remote", "add", "origin", &repo_url])
            .current_dir(target_dir)
            .output()
            .await
            .map_err(|e| GitHubClientError::Parse(format!("Failed to add remote: {}", e)))?;

        if !remote_output.status.success() {
            return Err(GitHubClientError::Parse(format!(
                "git remote add failed: {}",
                String::from_utf8_lossy(&remote_output.stderr)
            )));
        }

        // Enable sparse-checkout
        let sparse_output = Command::new("git")
            .args(["sparse-checkout", "init", "--cone"])
            .current_dir(target_dir)
            .output()
            .await
            .map_err(|e| {
                GitHubClientError::Parse(format!("Failed to init sparse-checkout: {}", e))
            })?;

        if !sparse_output.status.success() {
            return Err(GitHubClientError::Parse(format!(
                "git sparse-checkout init failed: {}",
                String::from_utf8_lossy(&sparse_output.stderr)
            )));
        }

        // Set sparse-checkout paths
        let mut sparse_set_args = vec!["sparse-checkout", "set"];
        let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
        sparse_set_args.extend(path_refs);

        let set_output = Command::new("git")
            .args(&sparse_set_args)
            .current_dir(target_dir)
            .output()
            .await
            .map_err(|e| {
                GitHubClientError::Parse(format!("Failed to set sparse-checkout: {}", e))
            })?;

        if !set_output.status.success() {
            return Err(GitHubClientError::Parse(format!(
                "git sparse-checkout set failed: {}",
                String::from_utf8_lossy(&set_output.stderr)
            )));
        }

        // Fetch and checkout (shallow, single branch)
        let fetch_output = Command::new("git")
            .args(["fetch", "--depth=1", "origin", branch])
            .current_dir(target_dir)
            .output()
            .await
            .map_err(|e| GitHubClientError::Parse(format!("Failed to fetch: {}", e)))?;

        if !fetch_output.status.success() {
            return Err(GitHubClientError::Parse(format!(
                "git fetch failed: {}",
                String::from_utf8_lossy(&fetch_output.stderr)
            )));
        }

        // Checkout
        let checkout_output = Command::new("git")
            .args(["checkout", branch])
            .current_dir(target_dir)
            .output()
            .await
            .map_err(|e| GitHubClientError::Parse(format!("Failed to checkout: {}", e)))?;

        if !checkout_output.status.success() {
            return Err(GitHubClientError::Parse(format!(
                "git checkout failed: {}",
                String::from_utf8_lossy(&checkout_output.stderr)
            )));
        }

        // Get the commit SHA
        let rev_output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(target_dir)
            .output()
            .await
            .map_err(|e| GitHubClientError::Parse(format!("Failed to get commit: {}", e)))?;

        if !rev_output.status.success() {
            return Err(GitHubClientError::Parse(format!(
                "git rev-parse failed: {}",
                String::from_utf8_lossy(&rev_output.stderr)
            )));
        }

        debug!(
            "Sparse clone complete, commit: {}",
            String::from_utf8_lossy(&rev_output.stdout).trim()
        );

        Ok(())
    }

    /// Get the HEAD commit SHA from a local git repo
    pub async fn get_local_commit(dir: &std::path::Path) -> Result<String, GitHubClientError> {
        use tokio::process::Command;

        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(dir)
            .output()
            .await
            .map_err(|e| GitHubClientError::Parse(format!("Failed to get commit: {}", e)))?;

        if !output.status.success() {
            return Err(GitHubClientError::Parse(format!(
                "git rev-parse failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get raw file content directly (bypasses base64 encoding)
    /// More efficient for larger files
    pub async fn get_raw_file(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        branch: &str,
    ) -> Result<String, GitHubClientError> {
        let url = format!("{}/{}/{}/{}/{}", self.raw_base_url, owner, repo, branch, path);

        debug!("Fetching raw file from {}", url);

        let response = self
            .http_client
            .get(&url)
            .header(USER_AGENT, "NanoSIEM/1.0")
            .send()
            .await?;

        if response.status() == 404 {
            return Err(GitHubClientError::Api {
                status: 404,
                message: format!("File not found: {}", path),
            });
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            return Err(GitHubClientError::Api { status, message });
        }

        Ok(response.text().await?)
    }

    fn update_rate_limit(&self, response: &reqwest::Response) {
        if let Some(remaining) = response.headers().get("x-ratelimit-remaining") {
            if let Ok(remaining_str) = remaining.to_str() {
                if let Ok(remaining_num) = remaining_str.parse::<u32>() {
                    self.rate_limit_remaining
                        .store(remaining_num, Ordering::Relaxed);
                    if remaining_num < 10 {
                        warn!("GitHub API rate limit low: {} remaining", remaining_num);
                    }
                }
            }
        }
    }

    /// Classify a 403/429. A genuine rate limit (primary or secondary) trips
    /// the shared backoff with jitter; any other 403 is a plain API error.
    async fn rate_limit_error(&self, response: reqwest::Response) -> GitHubClientError {
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let message = response.text().await.unwrap_or_default();
        match rate_limit_wait(status, &headers, &message, now_millis() / 1000) {
            Some(wait) => {
                let jitter = rand::random_range(0..=MAX_BACKOFF_JITTER_SECS * 1000);
                let backoff = Duration::from_secs(wait) + Duration::from_millis(jitter);
                self.gate.trip(backoff);
                warn!(status, backoff_secs = backoff.as_secs(), authenticated = self.token.is_some(), "GitHub rate limit hit; backing off all GitHub API calls");
                GitHubClientError::RateLimited { retry_after: backoff.as_secs().max(1) }
            }
            None => GitHubClientError::Api { status, message: message.chars().take(500).collect() },
        }
    }
}

fn is_limit_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Seconds to back off for a GitHub limit answer, `None` when the 403 is not
/// a rate limit (e.g. a resource GitHub refuses). Order per GitHub docs:
/// `Retry-After`, then `x-ratelimit-remaining: 0` with `x-ratelimit-reset`,
/// then a secondary-limit body or a bare 429 (default wait).
fn rate_limit_wait(status: u16, headers: &reqwest::header::HeaderMap, body: &str, now_secs: i64) -> Option<u64> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim);
    let clamp = |secs: u64| secs.clamp(1, MAX_BACKOFF_SECS);
    if let Some(secs) = header("retry-after").and_then(|v| v.parse::<u64>().ok()) {
        return Some(clamp(secs));
    }
    if header("x-ratelimit-remaining") == Some("0") {
        let wait = header("x-ratelimit-reset")
            .and_then(|v| v.parse::<i64>().ok())
            .map(|reset| reset.saturating_sub(now_secs).max(0) as u64)
            .unwrap_or(DEFAULT_BACKOFF_SECS);
        return Some(clamp(wait));
    }
    if status == 429 || body.to_ascii_lowercase().contains("rate limit") {
        return Some(DEFAULT_BACKOFF_SECS);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-3236: a missing branch of an existing repo is not "repo not found".
    #[tokio::test]
    async fn latest_commit_404_distinguishes_missing_branch_from_missing_repo() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/nano-rs/playbooks/branches/ocsf-1.9"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/nano-rs/playbooks"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/nano-rs/missing/branches/main"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/nano-rs/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let client = GitHubClient::with_api_base_url(&server.uri());

        let branch = client.get_latest_commit("nano-rs", "playbooks", "ocsf-1.9").await.unwrap_err();
        assert!(
            matches!(&branch, GitHubClientError::BranchNotFound { branch, .. } if branch == "ocsf-1.9"),
            "got {branch:?}"
        );
        assert!(branch.to_string().contains("nano-rs/playbooks@ocsf-1.9"));

        let repo = client.get_latest_commit("nano-rs", "missing", "main").await.unwrap_err();
        assert!(matches!(repo, GitHubClientError::NotFound { .. }), "got {repo:?}");
    }

    fn branch_body() -> serde_json::Value {
        serde_json::json!({"commit": {"sha": "abc123"}})
    }

    /// Red-team NAN repo-sync: with a platform token every API call carries
    /// `Authorization: Bearer`; without one none does.
    #[tokio::test]
    async fn api_requests_carry_bearer_only_when_a_token_is_configured() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/branches/main"))
            .and(header("authorization", "Bearer fixture-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_body()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/branches/main"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let authed = GitHubClient::with_api_base_url(&server.uri()).with_token(Some(Arc::from("fixture-token")));
        assert!(authed.is_authenticated());
        assert_eq!(authed.get_latest_commit("o", "r", "main").await.unwrap(), "abc123");

        let anonymous = GitHubClient::with_api_base_url(&server.uri());
        assert!(!anonymous.is_authenticated());
        assert!(matches!(anonymous.get_latest_commit("o", "r", "main").await, Err(GitHubClientError::Api { status: 401, .. })));

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].headers.get("authorization").unwrap(), "Bearer fixture-token");
        assert!(requests[1].headers.get("authorization").is_none(), "no token, no header");
        // An empty token is no token.
        assert!(!GitHubClient::with_api_base_url(&server.uri()).with_token(Some(Arc::from(""))).is_authenticated());
    }

    #[test]
    fn platform_token_prefers_the_secret_file_and_ignores_blank_values() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, "  from-file\n").unwrap();
        assert_eq!(resolve_platform_token(Some(&file), Some("from-env".into())).as_deref(), Some("from-file"));
        assert_eq!(resolve_platform_token(None, Some(" from-env ".into())).as_deref(), Some("from-env"));
        assert_eq!(resolve_platform_token(Some(&dir.path().join("missing")), Some("from-env".into())).as_deref(), Some("from-env"));
        assert_eq!(resolve_platform_token(None, Some("   ".into())), None);
        assert_eq!(resolve_platform_token(None, None), None);
    }

    #[test]
    fn rate_limit_wait_honors_github_headers() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut retry_after = HeaderMap::new();
        retry_after.insert("retry-after", HeaderValue::from_static("120"));
        assert_eq!(rate_limit_wait(403, &retry_after, "", 1_000), Some(120));

        let mut exhausted = HeaderMap::new();
        exhausted.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        exhausted.insert("x-ratelimit-reset", HeaderValue::from_static("1300"));
        assert_eq!(rate_limit_wait(403, &exhausted, "", 1_000), Some(300));
        // A reset in the past still waits at least a second; a huge one is capped.
        assert_eq!(rate_limit_wait(403, &exhausted, "", 5_000), Some(1));
        assert_eq!(rate_limit_wait(403, &exhausted, "", -100_000), Some(MAX_BACKOFF_SECS));

        assert_eq!(rate_limit_wait(429, &HeaderMap::new(), "", 0), Some(DEFAULT_BACKOFF_SECS));
        assert_eq!(rate_limit_wait(403, &HeaderMap::new(), "You have exceeded a secondary rate limit", 0), Some(DEFAULT_BACKOFF_SECS));

        let mut remaining = HeaderMap::new();
        remaining.insert("x-ratelimit-remaining", HeaderValue::from_static("42"));
        assert_eq!(rate_limit_wait(403, &remaining, "Resource not accessible", 0), None, "a plain 403 is not a rate limit");
    }

    /// A rate-limit answer trips a backoff shared by every client of the same
    /// API base: later calls fail locally without reaching GitHub.
    #[tokio::test]
    async fn rate_limit_trips_shared_backoff_and_stops_requests() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-ratelimit-remaining", "0")
                    .insert_header("x-ratelimit-reset", (now_millis() / 1000 + 600).to_string()),
            )
            .mount(&server)
            .await;
        let client = GitHubClient::with_api_base_url(&server.uri());
        assert!(client.backoff_remaining().is_none());
        let first = client.get_latest_commit("o", "r", "main").await.unwrap_err();
        let GitHubClientError::RateLimited { retry_after } = first else { panic!("got {first:?}") };
        assert!((599..=600 + MAX_BACKOFF_JITTER_SECS + 1).contains(&retry_after), "retry_after={retry_after}");

        // A fresh client for the same base (callers build one per request)
        // sees the backoff and sends nothing.
        let other = GitHubClient::with_api_base_url(&server.uri());
        assert!(other.backoff_remaining().is_some_and(|d| d.as_secs() >= 590));
        assert!(matches!(other.get_tree("o", "r", "main", None).await, Err(GitHubClientError::RateLimited { .. })));
        assert!(matches!(other.get_file("o", "r", "x.yml", "main").await, Err(GitHubClientError::RateLimited { .. })));
        assert_eq!(server.received_requests().await.unwrap().len(), 1, "backoff must not hammer GitHub");

        // Another base (another upstream) is unaffected.
        let unrelated = MockServer::start().await;
        assert!(GitHubClient::with_api_base_url(&unrelated.uri()).backoff_remaining().is_none());
    }

    #[tokio::test]
    async fn plain_forbidden_does_not_trip_backoff() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).insert_header("x-ratelimit-remaining", "4999").set_body_string("Resource not accessible"))
            .mount(&server)
            .await;
        let client = GitHubClient::with_api_base_url(&server.uri());
        assert!(matches!(client.get_latest_commit("o", "r", "main").await, Err(GitHubClientError::Api { status: 403, .. })));
        assert!(client.backoff_remaining().is_none());
    }

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
}

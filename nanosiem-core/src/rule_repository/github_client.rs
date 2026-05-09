// SPDX-License-Identifier: AGPL-3.0-or-later

//! GitHub API client for fetching repository contents
//!
//! Uses unauthenticated access for public repositories only.
//! Rate limit: 60 requests/hour for unauthenticated requests.

use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
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

/// Client for interacting with GitHub API (public repos only)
#[derive(Clone)]
pub struct GitHubClient {
    http_client: reqwest::Client,
    rate_limit_remaining: std::sync::Arc<AtomicU32>,
}

impl Default for GitHubClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GitHubClient {
    /// Create a new GitHub client
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            http_client,
            rate_limit_remaining: std::sync::Arc::new(AtomicU32::new(60)),
        }
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
            "https://api.github.com/repos/{}/{}/branches/{}",
            owner, repo, branch
        );

        debug!("Fetching latest commit from {}", url);

        let response = self
            .http_client
            .get(&url)
            .header(USER_AGENT, "NanoSIEM/1.0")
            .header(ACCEPT, "application/vnd.github.v3+json")
            .send()
            .await?;

        self.update_rate_limit(&response);

        if response.status() == 404 {
            return Err(GitHubClientError::NotFound {
                owner: owner.to_string(),
                repo: repo.to_string(),
            });
        }

        if response.status() == 403 {
            return self.handle_rate_limit(&response).await;
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            return Err(GitHubClientError::Api { status, message });
        }

        let branch_info: GitHubBranchResponse = response.json().await?;
        Ok(branch_info.commit.sha)
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
            "https://api.github.com/repos/{}/{}/git/trees/{}?recursive=1",
            owner, repo, branch
        );

        debug!("Fetching tree from {}", url);

        let response = self
            .http_client
            .get(&url)
            .header(USER_AGENT, "NanoSIEM/1.0")
            .header(ACCEPT, "application/vnd.github.v3+json")
            .send()
            .await?;

        self.update_rate_limit(&response);

        if response.status() == 404 {
            return Err(GitHubClientError::NotFound {
                owner: owner.to_string(),
                repo: repo.to_string(),
            });
        }

        if response.status() == 403 {
            return self.handle_rate_limit(&response).await;
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
                "https://api.github.com/repos/{}/{}/contents/{}?ref={}",
                owner, repo, current_path, branch
            );

            debug!("Fetching contents from {}", url);

            let response = self
                .http_client
                .get(&url)
                .header(USER_AGENT, "NanoSIEM/1.0")
                .header(ACCEPT, "application/vnd.github.v3+json")
                .send()
                .await?;

            self.update_rate_limit(&response);

            if response.status() == 404 {
                // Directory doesn't exist, skip it
                continue;
            }

            if response.status() == 403 {
                return self.handle_rate_limit(&response).await;
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
            "https://api.github.com/repos/{}/{}/contents/{}?ref={}",
            owner, repo, path, branch
        );

        debug!("Fetching file from {}", url);

        let response = self
            .http_client
            .get(&url)
            .header(USER_AGENT, "NanoSIEM/1.0")
            .header(ACCEPT, "application/vnd.github.v3+json")
            .send()
            .await?;

        self.update_rate_limit(&response);

        if response.status() == 404 {
            return Err(GitHubClientError::Api {
                status: 404,
                message: format!("File not found: {}", path),
            });
        }

        if response.status() == 403 {
            return self.handle_rate_limit(&response).await;
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
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}/{}",
            owner, repo, branch, path
        );

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

    async fn handle_rate_limit<T>(
        &self,
        response: &reqwest::Response,
    ) -> Result<T, GitHubClientError> {
        let retry_after = response
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(|reset| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                reset.saturating_sub(now)
            })
            .unwrap_or(60);

        Err(GitHubClientError::RateLimited { retry_after })
    }
}

#[cfg(test)]
mod tests {
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
}

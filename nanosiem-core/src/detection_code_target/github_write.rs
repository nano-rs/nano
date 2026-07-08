// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authenticated GitHub write client for opening tuning Pull Requests.
//!
//! Unlike [`crate::rule_repository::GitHubClient`] (unauthenticated, read-only),
//! this client uses a customer-supplied fine-grained PAT to create a branch,
//! commit a file, and open a PR. All requests target the fixed `api.github.com`
//! host — the repo owner/name are only ever used as path segments, so there is
//! no user-controlled request host (no SSRF surface). Repo URLs are still
//! validated to be github.com in v1; GHES support is a follow-up.
//!
//! Defense-in-depth (NAN-1756): redirect-following is disabled (a `302` can't
//! leak the `Authorization: Bearer <PAT>` header or amplify into SSRF), and
//! every egress endpoint is checked with the shared [`SsrfValidator`] before use
//! — the seam GHES's user-supplied API host will plug into.

use base64::Engine;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

use crate::inputlookup::{SsrfConfig, SsrfValidator};

const GITHUB_API: &str = "https://api.github.com";
const API_VERSION: &str = "2022-11-28";

#[derive(Debug, Error)]
pub enum GitHubWriteError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("GitHub API error ({status}): {message}")]
    Api { status: u16, message: String },

    #[error("Only github.com repositories are supported: {0}")]
    NotGitHub(String),

    #[error("Invalid GitHub URL: {0}")]
    InvalidUrl(String),

    #[error("Head branch already exists: {0}")]
    BranchExists(String),

    #[error("Egress endpoint blocked by SSRF policy: {0}")]
    BlockedEndpoint(String),
}

/// The PR that was opened.
#[derive(Debug, Clone)]
pub struct OpenedPr {
    pub html_url: String,
    pub number: i64,
}

/// Result of a connectivity/permission probe against a target repo.
#[derive(Debug, Clone)]
pub struct RepoAccess {
    pub can_read: bool,
    pub can_write: bool,
    pub default_branch: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RefObject {
    sha: String,
}
#[derive(Debug, Deserialize)]
struct RefResponse {
    object: RefObject,
}
#[derive(Debug, Deserialize)]
struct ContentsFile {
    sha: String,
}
#[derive(Debug, Deserialize)]
struct PullResponse {
    html_url: String,
    number: i64,
}
#[derive(Debug, Deserialize)]
struct RepoPermissions {
    #[serde(default)]
    push: bool,
    #[serde(default)]
    pull: bool,
}
#[derive(Debug, Deserialize)]
struct RepoResponse {
    #[serde(default)]
    permissions: Option<RepoPermissions>,
    #[serde(default)]
    default_branch: Option<String>,
}

/// Authenticated GitHub write client bound to a single PAT.
#[derive(Clone)]
pub struct GitHubWriteClient {
    http: reqwest::Client,
    token: String,
}

impl GitHubWriteClient {
    pub fn new(token: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("nano-siem")
            // Never follow redirects: a 302 must not carry the PAT to another
            // host or bounce the request to an internal target (NAN-1756).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client");
        Self { http, token }
    }

    /// Reject the egress endpoint if its host resolves to a private, loopback,
    /// link-local, or cloud-metadata address (NAN-1756). Today the host is
    /// always the fixed public `api.github.com`, so this is defense-in-depth and
    /// the seam GHES (user-supplied API host) support plugs into — and it keeps
    /// the PAT from ever egressing anywhere but a publicly-routable GitHub host.
    async fn validate_endpoint(url: &str) -> Result<(), GitHubWriteError> {
        SsrfValidator::new(SsrfConfig::default())
            .validate_with_dns(url)
            .await
            .map(|_resolved_url| ())
            .map_err(|e| GitHubWriteError::BlockedEndpoint(e.to_string()))
    }

    /// Validate a repo URL is on github.com and return `(owner, repo)`.
    ///
    /// Strict (NAN-1758): the host must be exactly `github.com` (optionally
    /// `www.`), so lookalikes (`github.company.com`) and embedded-host tricks
    /// (`evil.com/github.com/...`) are rejected. Additionally rejects cleartext
    /// `http://`, percent-encoding (`%2e%2e`), query strings / fragments, extra
    /// path segments, and any owner/repo outside GitHub's charset — so the value
    /// can never be URL-normalized to alter the `api.github.com` path it is later
    /// interpolated into (`/repos/{owner}/{repo}/...`). A scheme-less
    /// `github.com/owner/repo` is still accepted (the API host is always the
    /// fixed `https://api.github.com`).
    pub fn parse_github_repo(repo_url: &str) -> Result<(String, String), GitHubWriteError> {
        let s = repo_url.trim();
        if s.strip_prefix("http://").is_some() {
            return Err(GitHubWriteError::InvalidUrl(format!(
                "{repo_url} (use https, not http)"
            )));
        }
        let s = s.strip_prefix("https://").unwrap_or(s);
        let s = s.strip_prefix("www.").unwrap_or(s);
        let rest = s
            .strip_prefix("github.com/")
            .ok_or_else(|| GitHubWriteError::NotGitHub(repo_url.to_string()))?;
        // Require the path to be exactly `owner/repo` (optional trailing `/` and
        // `.git`). Extra segments are rejected here; a `?`/`#`/`%` lands inside a
        // segment and fails the owner/repo charset check below.
        let parts: Vec<&str> = rest.trim_end_matches('/').split('/').collect();
        if parts.len() != 2 {
            return Err(GitHubWriteError::InvalidUrl(format!(
                "{repo_url} (expected github.com/<owner>/<repo>)"
            )));
        }
        let owner = parts[0];
        let repo = parts[1].strip_suffix(".git").unwrap_or(parts[1]);
        validate_gh_owner(owner)
            .and_then(|()| validate_gh_repo(repo))
            .map_err(|reason| GitHubWriteError::InvalidUrl(format!("{repo_url} ({reason})")))?;
        Ok((owner.to_string(), repo.to_string()))
    }

    fn auth<'a>(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
    }

    /// Parse a JSON body on success, or map a non-2xx into an `Api` error whose
    /// message is GitHub's `message` field when present.
    async fn parse<T: for<'de> Deserialize<'de>>(
        resp: reqwest::Response,
    ) -> Result<T, GitHubWriteError> {
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            let message = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
                .unwrap_or_else(|| text.chars().take(300).collect());
            return Err(GitHubWriteError::Api {
                status: status.as_u16(),
                message,
            });
        }
        serde_json::from_str::<T>(&text).map_err(|e| GitHubWriteError::Api {
            status: status.as_u16(),
            message: format!("failed to parse GitHub response: {e}"),
        })
    }

    /// Probe read + write access to a repo (used by "Test connection").
    pub async fn check_access(&self, repo_url: &str) -> Result<RepoAccess, GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        let url = format!("{GITHUB_API}/repos/{owner}/{repo}");
        let resp = self.auth(self.http.get(&url)).send().await?;
        let repo: RepoResponse = Self::parse(resp).await?;
        let (can_read, can_write) = match repo.permissions {
            Some(p) => (p.pull, p.push),
            // Authenticated repo reads return a `permissions` block; its absence
            // means we could read but can't infer write — treat as read-only.
            None => (true, false),
        };
        Ok(RepoAccess {
            can_read,
            can_write,
            default_branch: repo.default_branch,
        })
    }

    /// Fetch the raw UTF-8 content of a file at `git_ref`, or `None` if it does
    /// not exist. Used to splice the tuned query into an existing rule file.
    pub async fn get_file(
        &self,
        repo_url: &str,
        file_path: &str,
        git_ref: &str,
    ) -> Result<Option<String>, GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        let url = format!("{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}?ref={git_ref}");
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            // Raw media type returns the file body directly (not base64 JSON).
            .header("Accept", "application/vnd.github.raw")
            .header("X-GitHub-Api-Version", API_VERSION)
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            let message = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
                .unwrap_or_else(|| text.chars().take(300).collect());
            return Err(GitHubWriteError::Api {
                status: status.as_u16(),
                message,
            });
        }
        Ok(Some(text))
    }

    /// Create `head_branch` off `base_branch`, commit `file_content` at
    /// `file_path` (create or update), and open a PR into `base_branch`.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_pr(
        &self,
        repo_url: &str,
        base_branch: &str,
        head_branch: &str,
        file_path: &str,
        file_content: &str,
        commit_message: &str,
        pr_title: &str,
        pr_body: &str,
    ) -> Result<OpenedPr, GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;

        // 1. Resolve the base branch tip SHA.
        let base_sha = {
            let url = format!("{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{base_branch}");
            let resp = self.auth(self.http.get(&url)).send().await?;
            let r: RefResponse = Self::parse(resp).await?;
            r.object.sha
        };

        // 2. Create the head branch ref. A 422 means it already exists.
        {
            let url = format!("{GITHUB_API}/repos/{owner}/{repo}/git/refs");
            let body = json!({ "ref": format!("refs/heads/{head_branch}"), "sha": base_sha });
            let resp = self.auth(self.http.post(&url)).json(&body).send().await?;
            if resp.status() == StatusCode::UNPROCESSABLE_ENTITY {
                return Err(GitHubWriteError::BranchExists(head_branch.to_string()));
            }
            let _: serde_json::Value = Self::parse(resp).await?;
        }

        // 3. Look up the file's current blob SHA on the head branch (for update).
        let existing_sha = {
            let url = format!(
                "{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}?ref={head_branch}"
            );
            let resp = self.auth(self.http.get(&url)).send().await?;
            if resp.status() == StatusCode::NOT_FOUND {
                None
            } else {
                let f: ContentsFile = Self::parse(resp).await?;
                Some(f.sha)
            }
        };

        // 4. Commit the file (create or update) onto the head branch.
        {
            let url = format!("{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}");
            let encoded = base64::engine::general_purpose::STANDARD.encode(file_content.as_bytes());
            let mut body = json!({
                "message": commit_message,
                "content": encoded,
                "branch": head_branch,
            });
            if let Some(sha) = existing_sha {
                body["sha"] = json!(sha);
            }
            let resp = self.auth(self.http.put(&url)).json(&body).send().await?;
            let _: serde_json::Value = Self::parse(resp).await?;
        }

        // 5. Open the PR.
        let url = format!("{GITHUB_API}/repos/{owner}/{repo}/pulls");
        let body = json!({
            "title": pr_title,
            "head": head_branch,
            "base": base_branch,
            "body": pr_body,
        });
        let resp = self.auth(self.http.post(&url)).json(&body).send().await?;
        let pr: PullResponse = Self::parse(resp).await?;
        Ok(OpenedPr {
            html_url: pr.html_url,
            number: pr.number,
        })
    }
}

/// GitHub owner (user/org): 1–39 chars, ASCII alphanumeric or single hyphens,
/// no leading/trailing hyphen. Rejects `.`, `..`, `%`-encoding, and query chars.
fn validate_gh_owner(owner: &str) -> Result<(), String> {
    if owner.is_empty() || owner.len() > 39 {
        return Err("owner must be 1–39 characters".into());
    }
    if !owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("owner has an invalid character".into());
    }
    if owner.starts_with('-') || owner.ends_with('-') {
        return Err("owner must not start or end with '-'".into());
    }
    Ok(())
}

/// GitHub repo: 1–100 chars, ASCII alphanumeric plus `. _ -`; never `.`/`..`.
fn validate_gh_repo(repo: &str) -> Result<(), String> {
    if repo.is_empty() || repo.len() > 100 {
        return Err("repo must be 1–100 characters".into());
    }
    if !repo
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("repo has an invalid character".into());
    }
    if repo == "." || repo == ".." {
        return Err("repo must not be '.' or '..'".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;

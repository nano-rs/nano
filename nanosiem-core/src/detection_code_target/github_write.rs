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

    #[error("Egress endpoint blocked by SSRF policy: {0}")]
    BlockedEndpoint(String),

    #[error("Existing GitHub state conflicts with this PR operation: {0}")]
    RemoteConflict(String),
}

/// The PR that was opened.
#[derive(Debug, Clone)]
pub struct OpenedPr {
    pub html_url: String,
    pub number: i64,
    pub state: String,
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
    #[serde(default)]
    content: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
}
#[derive(Debug, Deserialize)]
struct CommitResponse {
    sha: String,
}
#[derive(Debug, Deserialize)]
struct ContentsUpdateResponse {
    commit: CommitResponse,
}
#[derive(Debug, Clone, Deserialize)]
struct PullHead {
    sha: String,
}
#[derive(Debug, Clone, Deserialize)]
struct PullResponse {
    html_url: String,
    number: i64,
    #[serde(default)]
    body: Option<String>,
    #[serde(default = "default_pull_state")]
    state: String,
    #[serde(default)]
    merged_at: Option<String>,
    head: PullHead,
}
#[derive(Debug, Deserialize)]
struct ChangedFile {
    filename: String,
    status: String,
    #[serde(default)]
    previous_filename: Option<String>,
}
#[derive(Debug, Deserialize)]
struct CompareResponse {
    #[serde(default)]
    files: Vec<ChangedFile>,
}
#[derive(Debug, Deserialize)]
struct CodeSearchItem {
    path: String,
}
#[derive(Debug, Deserialize)]
struct CodeSearchResponse {
    #[serde(default)]
    items: Vec<CodeSearchItem>,
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

    async fn find_pull_request(
        &self,
        owner: &str,
        repo: &str,
        base_branch: &str,
        head_branch: &str,
        expected_body: &str,
        file_path: &str,
        file_content: &str,
    ) -> Result<Option<(OpenedPr, String)>, GitHubWriteError> {
        let head = format!("{owner}:{head_branch}");
        let url = reqwest::Url::parse_with_params(
            &format!("{GITHUB_API}/repos/{owner}/{repo}/pulls"),
            &[
                ("state", "all"),
                ("base", base_branch),
                ("head", head.as_str()),
                ("per_page", "1"),
            ],
        )
        .map_err(|error| GitHubWriteError::InvalidUrl(error.to_string()))?;
        let response = self.auth(self.http.get(url)).send().await?;
        let pulls: Vec<PullResponse> = Self::parse(response).await?;
        let Some(pull) = pulls.into_iter().next() else {
            return Ok(None);
        };
        if !pull_body_matches_operation(pull.body.as_deref(), expected_body) {
            return Err(GitHubWriteError::RemoteConflict(format!(
                "pull request #{} on '{head_branch}' has no matching operation identity",
                pull.number
            )));
        }
        self.verify_pull_request_diff(owner, repo, pull.number, file_path)
            .await?;
        let head_sha = pull.head.sha.clone();
        let content_matches = self
            .get_contents_file(owner, repo, file_path, &head_sha)
            .await?
            .as_ref()
            .is_some_and(|file| Self::contents_match(file, file_content.as_bytes()));
        if !content_matches {
            return Err(GitHubWriteError::RemoteConflict(format!(
                "pull request #{} does not contain the frozen payload at head {head_sha}",
                pull.number
            )));
        }
        let state = pull_state(&pull);
        Ok(Some((
            OpenedPr {
                html_url: pull.html_url,
                number: pull.number,
                state,
            },
            head_sha,
        )))
    }

    async fn verify_branch_diff(
        &self,
        owner: &str,
        repo: &str,
        base_branch: &str,
        head_branch: &str,
        file_path: &str,
    ) -> Result<(), GitHubWriteError> {
        let mut url = reqwest::Url::parse(&format!("{GITHUB_API}/repos/{owner}/{repo}/compare/"))
            .map_err(|error| GitHubWriteError::InvalidUrl(error.to_string()))?;
        url.path_segments_mut()
            .map_err(|_| {
                GitHubWriteError::InvalidUrl(
                    "GitHub compare URL cannot hold path segments".to_string(),
                )
            })?
            .push(&format!("{base_branch}...{head_branch}"));
        let response = self.auth(self.http.get(url)).send().await?;
        let comparison: CompareResponse = Self::parse(response).await?;
        ensure_exact_operation_diff(&comparison.files, file_path, "operation branch")
    }

    async fn verify_pull_request_diff(
        &self,
        owner: &str,
        repo: &str,
        pr_number: i64,
        file_path: &str,
    ) -> Result<(), GitHubWriteError> {
        let url = reqwest::Url::parse_with_params(
            &format!("{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/files"),
            &[("per_page", "2")],
        )
        .map_err(|error| GitHubWriteError::InvalidUrl(error.to_string()))?;
        let response = self.auth(self.http.get(url)).send().await?;
        let files: Vec<ChangedFile> = Self::parse(response).await?;
        ensure_exact_operation_diff(&files, file_path, "pull request")
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

    /// Best-effort: locate the file carrying `rule_id` in its frontmatter by
    /// GitHub code search, returning its repo path. Used as the second rung of
    /// the push-target matching cascade (after provenance `source_path`, before
    /// the name template) so a rule nano previously wrote — or one the customer
    /// stamped with the id — is found even if it was moved/renamed.
    ///
    /// Caveats worth knowing at the call site: code search only indexes the
    /// **default branch** and lags commits, and returns nothing when the id was
    /// never written to a file. Treat `Ok(None)` and errors alike as "not found"
    /// and fall through to the template — this is an optimization, not a
    /// correctness guarantee (that's what `source_path` is for).
    pub async fn find_file_by_rule_id(
        &self,
        repo_url: &str,
        rule_id: &str,
    ) -> Result<Option<String>, GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        // Scope the search to this repo; quote the id so the hyphenated UUID is
        // matched as a unit rather than tokenized.
        let q = format!("\"{rule_id}\" repo:{owner}/{repo}");
        let url = reqwest::Url::parse_with_params(
            &format!("{GITHUB_API}/search/code"),
            &[("q", q.as_str()), ("per_page", "1")],
        )
        .map_err(|e| GitHubWriteError::InvalidUrl(e.to_string()))?;
        let resp = self.auth(self.http.get(url)).send().await?;
        // 422 (repo not indexed yet) / 403 (search rate limit) are expected
        // transient misses — not push-blocking. Surface only as "not found".
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body: CodeSearchResponse = match Self::parse(resp).await {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        Ok(body.items.into_iter().next().map(|i| i.path))
    }

    /// Best-effort: add `labels` to an already-opened PR (PRs are issues). Never
    /// push-blocking — a repo without the label, or a token lacking issues:write,
    /// just means the PR ships unlabeled; the `nano-rule-id` body marker is the
    /// reliable machine link.
    pub async fn add_labels(
        &self,
        repo_url: &str,
        pr_number: i64,
        labels: &[&str],
    ) -> Result<(), GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        let url = format!("{GITHUB_API}/repos/{owner}/{repo}/issues/{pr_number}/labels");
        let body = json!({ "labels": labels });
        let resp = self.auth(self.http.post(&url)).json(&body).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let message = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
                .unwrap_or_else(|| text.chars().take(200).collect());
            return Err(GitHubWriteError::Api { status, message });
        }
        Ok(())
    }

    async fn get_branch_ref(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<Option<String>, GitHubWriteError> {
        let url = format!("{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{branch}");
        let response = self.auth(self.http.get(&url)).send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let reference: RefResponse = Self::parse(response).await?;
        Ok(Some(reference.object.sha))
    }

    async fn get_contents_file(
        &self,
        owner: &str,
        repo: &str,
        file_path: &str,
        git_ref: &str,
    ) -> Result<Option<ContentsFile>, GitHubWriteError> {
        let url = format!("{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}?ref={git_ref}");
        let response = self.auth(self.http.get(&url)).send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::parse(response).await.map(Some)
    }

    fn contents_match(file: &ContentsFile, expected: &[u8]) -> bool {
        file.kind.as_deref() == Some("file")
            && file
                .content
                .as_deref()
                .and_then(|content| {
                    base64::engine::general_purpose::STANDARD
                        .decode(content.replace('\n', ""))
                        .ok()
                })
                .is_some_and(|decoded| decoded == expected)
    }

    /// Ensure the proposal's deterministic branch exists and return its head
    /// SHA. A `422` create response is ambiguous by design: re-read the exact
    /// ref and reuse it instead of surfacing `BranchExists`.
    pub(crate) async fn ensure_branch(
        &self,
        repo_url: &str,
        base_branch: &str,
        head_branch: &str,
    ) -> Result<String, GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        if let Some(sha) = self.get_branch_ref(&owner, &repo, head_branch).await? {
            return Ok(sha);
        }
        let base_sha = self
            .get_branch_ref(&owner, &repo, base_branch)
            .await?
            .ok_or_else(|| GitHubWriteError::Api {
                status: StatusCode::NOT_FOUND.as_u16(),
                message: format!("base branch '{base_branch}' was not found"),
            })?;

        let url = format!("{GITHUB_API}/repos/{owner}/{repo}/git/refs");
        let body = json!({ "ref": format!("refs/heads/{head_branch}"), "sha": base_sha });
        let response = self.auth(self.http.post(&url)).json(&body).send().await?;
        if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
            return self
                .get_branch_ref(&owner, &repo, head_branch)
                .await?
                .ok_or_else(|| GitHubWriteError::Api {
                    status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    message: format!(
                        "GitHub rejected branch creation and '{head_branch}' was not discoverable"
                    ),
                });
        }
        let reference: RefResponse = Self::parse(response).await?;
        Ok(reference.object.sha)
    }

    /// Ensure a deterministic operation branch is either still at the current
    /// base tip or already contains the exact frozen payload. This prevents a
    /// coincidentally named divergent branch from being overwritten and later
    /// attached to a tuning PR.
    pub(crate) async fn ensure_operation_branch(
        &self,
        repo_url: &str,
        base_branch: &str,
        head_branch: &str,
        file_path: &str,
        file_content: &str,
    ) -> Result<String, GitHubWriteError> {
        self.ensure_branch(repo_url, base_branch, head_branch)
            .await?;

        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        let head_sha = self
            .get_branch_ref(&owner, &repo, head_branch)
            .await?
            .ok_or_else(|| {
                GitHubWriteError::RemoteConflict(format!(
                    "operation branch '{head_branch}' disappeared during reconciliation"
                ))
            })?;
        let base_sha = self
            .get_branch_ref(&owner, &repo, base_branch)
            .await?
            .ok_or_else(|| GitHubWriteError::Api {
                status: StatusCode::NOT_FOUND.as_u16(),
                message: format!("base branch '{base_branch}' was not found"),
            })?;
        if head_sha == base_sha {
            return Ok(head_sha);
        }

        let content_matches = self
            .get_contents_file(&owner, &repo, file_path, head_branch)
            .await?
            .as_ref()
            .is_some_and(|file| Self::contents_match(file, file_content.as_bytes()));
        if content_matches {
            self.verify_branch_diff(&owner, &repo, base_branch, head_branch, file_path)
                .await?;
            return Ok(head_sha);
        }

        Err(GitHubWriteError::RemoteConflict(format!(
            "operation branch '{head_branch}' diverges from '{base_branch}' without the frozen payload"
        )))
    }

    /// Ensure the branch contains the exact frozen file payload and return the
    /// resulting commit SHA. Retries reuse matching content; conflicts are
    /// reconciled with a read in case GitHub committed before its response was
    /// lost.
    pub(crate) async fn ensure_commit(
        &self,
        repo_url: &str,
        head_branch: &str,
        file_path: &str,
        file_content: &str,
        commit_message: &str,
    ) -> Result<String, GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        let existing = self
            .get_contents_file(&owner, &repo, file_path, head_branch)
            .await?;
        if existing
            .as_ref()
            .is_some_and(|file| Self::contents_match(file, file_content.as_bytes()))
        {
            return self
                .get_branch_ref(&owner, &repo, head_branch)
                .await?
                .ok_or_else(|| GitHubWriteError::Api {
                    status: StatusCode::NOT_FOUND.as_u16(),
                    message: format!("head branch '{head_branch}' disappeared"),
                });
        }

        let url = format!("{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(file_content.as_bytes());
        let mut body = json!({
            "message": commit_message,
            "content": encoded,
            "branch": head_branch,
        });
        if let Some(blob_sha) = existing.map(|file| file.sha) {
            body["sha"] = json!(blob_sha);
        }
        let response = self.auth(self.http.put(&url)).json(&body).send().await?;
        if matches!(
            response.status(),
            StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY
        ) {
            let reconciled = self
                .get_contents_file(&owner, &repo, file_path, head_branch)
                .await?;
            if reconciled
                .as_ref()
                .is_some_and(|file| Self::contents_match(file, file_content.as_bytes()))
            {
                return self
                    .get_branch_ref(&owner, &repo, head_branch)
                    .await?
                    .ok_or_else(|| GitHubWriteError::Api {
                        status: StatusCode::NOT_FOUND.as_u16(),
                        message: format!("head branch '{head_branch}' disappeared"),
                    });
            }
            return Err(GitHubWriteError::RemoteConflict(format!(
                "operation branch '{head_branch}' changed before the frozen payload could be committed"
            )));
        }
        let update: ContentsUpdateResponse = Self::parse(response).await?;
        Ok(update.commit.sha)
    }

    /// Confirm that the durable commit checkpoint is still the exact head and
    /// still contains the frozen file. This is read-only: remote drift after a
    /// checkpoint must stop reconciliation instead of silently adding it to the
    /// pull request.
    pub(crate) async fn verify_commit(
        &self,
        repo_url: &str,
        base_branch: &str,
        head_branch: &str,
        file_path: &str,
        file_content: &str,
        expected_commit_sha: &str,
    ) -> Result<(), GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        let head_sha = self
            .get_branch_ref(&owner, &repo, head_branch)
            .await?
            .ok_or_else(|| {
                GitHubWriteError::RemoteConflict(format!(
                    "operation branch '{head_branch}' no longer exists"
                ))
            })?;
        if head_sha != expected_commit_sha {
            return Err(GitHubWriteError::RemoteConflict(format!(
                "operation branch '{head_branch}' moved from checkpoint {expected_commit_sha} to {head_sha}"
            )));
        }
        let content_matches = self
            .get_contents_file(&owner, &repo, file_path, head_branch)
            .await?
            .as_ref()
            .is_some_and(|file| Self::contents_match(file, file_content.as_bytes()));
        if !content_matches {
            return Err(GitHubWriteError::RemoteConflict(format!(
                "checkpointed commit {expected_commit_sha} no longer contains the frozen payload"
            )));
        }
        self.verify_branch_diff(&owner, &repo, base_branch, head_branch, file_path)
            .await?;
        Ok(())
    }

    /// Find a PR created by this operation and verify both its durable body
    /// marker and frozen file at the PR head. The head commit remains readable
    /// after a merged PR's branch is deleted, so recovery does not need to
    /// recreate remote state merely to finish its database checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn find_existing_pull_request(
        &self,
        repo_url: &str,
        base_branch: &str,
        head_branch: &str,
        file_path: &str,
        file_content: &str,
        pr_body: &str,
    ) -> Result<Option<(OpenedPr, String)>, GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        self.find_pull_request(
            &owner,
            &repo,
            base_branch,
            head_branch,
            pr_body,
            file_path,
            file_content,
        )
        .await
    }

    /// Ensure exactly one PR exists for the deterministic head/base pair.
    /// Closed and merged PRs are valid terminal remote markers and are reused.
    pub(crate) async fn ensure_pull_request(
        &self,
        repo_url: &str,
        base_branch: &str,
        head_branch: &str,
        file_path: &str,
        file_content: &str,
        pr_title: &str,
        pr_body: &str,
    ) -> Result<OpenedPr, GitHubWriteError> {
        Self::validate_endpoint(GITHUB_API).await?;
        let (owner, repo) = Self::parse_github_repo(repo_url)?;
        if let Some(existing) = self
            .find_pull_request(
                &owner,
                &repo,
                base_branch,
                head_branch,
                pr_body,
                file_path,
                file_content,
            )
            .await?
        {
            return Ok(existing.0);
        }

        let url = format!("{GITHUB_API}/repos/{owner}/{repo}/pulls");
        let body = json!({
            "title": pr_title,
            "head": head_branch,
            "base": base_branch,
            "body": pr_body,
        });
        let response = self.auth(self.http.post(&url)).json(&body).send().await?;
        if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
            if let Some(existing) = self
                .find_pull_request(
                    &owner,
                    &repo,
                    base_branch,
                    head_branch,
                    pr_body,
                    file_path,
                    file_content,
                )
                .await?
            {
                return Ok(existing.0);
            }
            return Err(GitHubWriteError::RemoteConflict(format!(
                "GitHub rejected PR creation and no matching operation PR was discoverable for '{head_branch}'"
            )));
        }
        let pull: PullResponse = Self::parse(response).await?;
        self.verify_pull_request_diff(&owner, &repo, pull.number, file_path)
            .await?;
        let content_matches = self
            .get_contents_file(&owner, &repo, file_path, &pull.head.sha)
            .await?
            .as_ref()
            .is_some_and(|file| Self::contents_match(file, file_content.as_bytes()));
        if !content_matches {
            return Err(GitHubWriteError::RemoteConflict(format!(
                "new pull request #{} does not contain the frozen payload",
                pull.number
            )));
        }
        Ok(OpenedPr {
            html_url: pull.html_url.clone(),
            number: pull.number,
            state: pull_state(&pull),
        })
    }

    /// Compatibility wrapper for callers that do not persist staged
    /// checkpoints. Tuning uses the durable reconciler in `push_service`.
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
        self.ensure_branch(repo_url, base_branch, head_branch)
            .await?;
        self.ensure_commit(
            repo_url,
            head_branch,
            file_path,
            file_content,
            commit_message,
        )
        .await?;
        self.ensure_pull_request(
            repo_url,
            base_branch,
            head_branch,
            file_path,
            file_content,
            pr_title,
            pr_body,
        )
        .await
    }
}

fn pull_body_matches_operation(actual: Option<&str>, expected: &str) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    if actual == expected {
        return true;
    }

    // NAN-1768 could leave an orphan PR immediately before NAN-1771 added the
    // explicit operation marker. Its full generated body still carries the
    // proposal and rule identities, so accept only that exact legacy body.
    let Some(marker) = expected
        .lines()
        .find(|line| line.starts_with("<!-- nano-pr-operation: "))
    else {
        return false;
    };
    if actual.lines().any(|line| line.trim() == marker) {
        return true;
    }
    actual == expected.replace(&format!("\n{marker}\n"), "")
}

fn ensure_exact_operation_diff(
    files: &[ChangedFile],
    expected_path: &str,
    remote_kind: &str,
) -> Result<(), GitHubWriteError> {
    if files.len() == 1
        && files[0].filename == expected_path
        && matches!(files[0].status.as_str(), "added" | "modified")
        && files[0].previous_filename.is_none()
    {
        return Ok(());
    }
    let paths = files
        .iter()
        .take(5)
        .map(|file| file.filename.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Err(GitHubWriteError::RemoteConflict(format!(
        "{remote_kind} changes paths outside the frozen destination '{expected_path}' (observed: {paths})"
    )))
}

fn default_pull_state() -> String {
    "open".to_string()
}

fn pull_state(pull: &PullResponse) -> String {
    if pull.merged_at.is_some() {
        "merged".to_string()
    } else {
        pull.state.clone()
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

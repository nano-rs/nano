// SPDX-License-Identifier: AGPL-3.0-or-later

//! Input validation for detection-as-code push-target write parameters (NAN-1758).
//!
//! `base_branch`, `pr_branch_prefix`, and `path_template` are persisted by the
//! manage endpoints and later interpolated — raw — into GitHub write API paths
//! and git refs by [`super::push_service`] / [`super::github_write`]:
//!
//! * `path_template` → `render_path()` → `GET/PUT /repos/{o}/{r}/contents/{path}`
//! * `base_branch`   → `GET /repos/{o}/{r}/git/ref/heads/{base}` + PR `base`
//! * `pr_branch_prefix` → the `refs/heads/{prefix}...` head branch
//!
//! Without validation a `detection_code_targets:manage` principal could store a
//! traversal template (`../../.github/workflows/pwn.yml` → a workflow file in the
//! opened PR → CI RCE if merged) or a malformed ref. These validators reject
//! unsafe values at the API boundary before persistence; `repo_url` is validated
//! separately by [`super::github_write::GitHubWriteClient::parse_github_repo`].

use thiserror::Error;

/// A push-target write parameter failed validation. Handlers map this to HTTP 400.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct TargetValidationError(pub String);

fn reject(msg: impl Into<String>) -> TargetValidationError {
    TargetValidationError(msg.into())
}

/// Characters permitted in a git ref name / ref prefix: ASCII alphanumeric plus
/// `.`, `_`, `/`, `-`. Excludes everything git forbids in a ref and everything
/// that could break out of a URL path segment — whitespace, control chars, and
/// `~ ^ : ? * [ \ % ; $ ( ) & | < > " '` and backtick.
fn is_ref_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-')
}

/// Reject a single `/`-separated ref component that git's `check-ref-format`
/// refuses: an empty component, a bare `.` or `..` component, or any component
/// ending in `.lock`. git enforces the `.lock` rule on EVERY path component (not
/// only the whole ref), so `feature.lock/x` is invalid even though its trailing
/// component (`x`) is not a `.lock` name.
///
/// Applied per-`/`-segment by both [`validate_git_ref`] and [`validate_ref_prefix`].
fn reject_ref_component(seg: &str) -> Result<(), TargetValidationError> {
    // F-38: reject git-invalid ref path components (empty, leading '.', '.lock' suffix).
    if seg.is_empty() {
        return Err(reject("branch ref must not contain an empty path segment"));
    }
    // git check-ref-format forbids any component that begins with '.' — this
    // covers the '.' and '..' segments as well as hidden-style names like '.foo'.
    if seg.starts_with('.') {
        return Err(reject(format!(
            "branch ref path segment must not begin with '.': {seg:?}"
        )));
    }
    if seg.ends_with(".lock") {
        return Err(reject(format!(
            "branch ref path segment must not end with '.lock': {seg:?}"
        )));
    }
    Ok(())
}

/// Validate a complete git ref (branch) name, e.g. `base_branch`.
///
/// A safe subset of `git check-ref-format`: restricted charset, no `..`, no
/// `//`, no leading `-`/`/`, no trailing `/`/`.`, no `.lock` suffix.
pub fn validate_git_ref(name: &str) -> Result<(), TargetValidationError> {
    if name.is_empty() {
        return Err(reject("branch name must not be empty"));
    }
    if name.len() > 255 {
        return Err(reject("branch name too long (max 255)"));
    }
    if let Some(bad) = name.chars().find(|c| !is_ref_char(*c)) {
        return Err(reject(format!(
            "branch name contains an unsafe character: {bad:?}"
        )));
    }
    if name.contains("..") {
        return Err(reject("branch name must not contain '..'"));
    }
    if name.contains("//") {
        return Err(reject("branch name must not contain '//'"));
    }
    if name.starts_with('-') || name.starts_with('/') {
        return Err(reject("branch name must not start with '-' or '/'"));
    }
    // F-38: reject the reserved `refs/` namespace. A fully-qualified ref is
    // double-prefixed by the GitHub write client (`git/ref/heads/{name}` and
    // `"ref": "refs/heads/{name}"`), so `refs/heads/main` becomes
    // `refs/heads/refs/heads/main` → 404 and `ensure_branch` fails. Require the
    // short branch name (`main`), never a fully-qualified ref.
    if name.starts_with("refs/") {
        return Err(reject(format!(
            "branch name must be a short ref (e.g. 'main'), not the fully-qualified '{name}'"
        )));
    }
    if name.ends_with('/') || name.ends_with('.') || name.ends_with(".lock") {
        return Err(reject("branch name must not end with '/', '.', or '.lock'"));
    }
    // F-38: git rejects an empty / `.` / `..` / `.lock` component on ANY path
    // segment, so check each `/`-split segment. The trailing-`.lock` check above
    // only inspects the whole name, letting `feature.lock/x` slip through.
    for seg in name.split('/') {
        reject_ref_component(seg)?;
    }
    Ok(())
}

/// Validate a `pr_branch_prefix`. The head branch is built as
/// `{prefix}{sanitized_rule_name}-{id}`, so the prefix need not be a complete
/// ref (it may legitimately end with `/` or `-`), but it must be charset-safe
/// with no traversal and no leading `-`/`/`. An empty prefix is allowed.
pub fn validate_ref_prefix(prefix: &str) -> Result<(), TargetValidationError> {
    if prefix.len() > 200 {
        return Err(reject("branch prefix too long (max 200)"));
    }
    if prefix.is_empty() {
        return Ok(());
    }
    if let Some(bad) = prefix.chars().find(|c| !is_ref_char(*c)) {
        return Err(reject(format!(
            "branch prefix contains an unsafe character: {bad:?}"
        )));
    }
    if prefix.contains("..") {
        return Err(reject("branch prefix must not contain '..'"));
    }
    if prefix.contains("//") {
        return Err(reject("branch prefix must not contain '//'"));
    }
    if prefix.starts_with('-') || prefix.starts_with('/') {
        return Err(reject("branch prefix must not start with '-' or '/'"));
    }
    // F-38: reject the reserved `refs/` namespace — a prefix that begins `refs/`
    // composes a fully-qualified head branch (`refs/heads/...-<id>`) that the
    // GitHub write client double-prefixes and GitHub's ref API rejects.
    if prefix.starts_with("refs/") {
        return Err(reject(format!(
            "branch prefix must not begin with the reserved 'refs/' namespace: {prefix:?}"
        )));
    }
    // F-38: apply the per-segment git-ref rules to each `/`-split component (a
    // `.lock` component makes git reject the composed head branch with a 422).
    // A prefix may legitimately end with '/' (the head branch appends more), so
    // drop a single trailing slash before splitting; interior '//' is already
    // rejected above, so no other empty segment can reach the loop.
    let core = prefix.strip_suffix('/').unwrap_or(prefix);
    for seg in core.split('/') {
        reject_ref_component(seg)?;
    }
    Ok(())
}

/// Validate a `path_template`: a repo-relative file path (with optional
/// `{rule_name}` / `{rule_id}` placeholders) under which tuned rules are written.
///
/// Rejects absolute paths, `..` traversal, empty segments, `.github` (the
/// CI-workflow injection sink), and any character outside a filename-safe set.
pub fn validate_path_template(template: &str) -> Result<(), TargetValidationError> {
    if template.is_empty() {
        return Err(reject("path template must not be empty"));
    }
    if template.len() > 255 {
        return Err(reject("path template too long (max 255)"));
    }
    if template.starts_with('/') {
        return Err(reject("path template must be relative (no leading '/')"));
    }
    if template.ends_with('/') {
        return Err(reject("path template must be a file path (no trailing '/')"));
    }
    // Filename-safe charset plus `{}` for the `{rule_name}`/`{rule_id}` placeholders.
    if let Some(bad) = template.chars().find(|c| {
        !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | '{' | '}'))
    }) {
        return Err(reject(format!(
            "path template contains an unsafe character: {bad:?}"
        )));
    }
    for seg in template.split('/') {
        if seg.is_empty() {
            return Err(reject("path template must not contain an empty path segment"));
        }
        if seg == ".." {
            return Err(reject("path template must not contain a '..' segment"));
        }
        // `.github` is the CI-workflow injection sink — never a rules directory.
        if seg.eq_ignore_ascii_case(".github") {
            return Err(reject("path template must not write under '.github'"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

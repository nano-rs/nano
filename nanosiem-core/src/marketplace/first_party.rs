// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4946: marketplace content comes only from nano's first-party catalogs.
//!
//! Dan, 2026-11-03: there is no way to add a third-party repository for any
//! content type. A marketplace repository URL is accepted (and synced) only
//! when it names a repository owned by a first-party GitHub organization,
//! checked by exact URL parse (scheme, host, owner), never by substring. URLs
//! never carry credentials.

use url::Url;

use super::MarketplaceError;

/// GitHub organizations that publish nano's first-party catalogs. `nanos-sh`
/// is the pre-rename organization (migration 178 moved rows to `nano-rs`).
pub const FIRST_PARTY_OWNERS: &[&str] = &["nano-rs", "nanos-sh"];
const FIRST_PARTY_HOST: &str = "github.com";

/// Why a repository URL is not an acceptable first-party catalog URL.
fn first_party_violation(raw: &str) -> Option<&'static str> {
    let Ok(url) = Url::parse(raw.trim()) else {
        return Some("not a valid URL");
    };
    if url.scheme() != "https" {
        return Some("only HTTPS URLs are allowed");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Some("credentials must not be embedded in the URL");
    }
    if url.port().is_some_and(|p| p != 443) {
        return Some("a non-standard port is not allowed");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Some("query strings and fragments are not allowed");
    }
    if url.host_str().map(str::to_ascii_lowercase).as_deref() != Some(FIRST_PARTY_HOST) {
        return Some("only nano's first-party GitHub catalogs are allowed");
    }
    let segments: Vec<&str> = url.path().trim_matches('/').split('/').collect();
    let [owner, repo] = segments.as_slice() else {
        return Some("the URL must name exactly one repository (https://github.com/<owner>/<repo>)");
    };
    if !FIRST_PARTY_OWNERS.iter().any(|o| o.eq_ignore_ascii_case(owner)) {
        return Some("only nano's first-party GitHub catalogs are allowed");
    }
    let name = repo.strip_suffix(".git").unwrap_or(repo);
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Some("invalid repository name");
    }
    None
}

/// Exact first-party check (scheme, host, owner; no credentials).
pub fn is_first_party_repo_url(raw: &str) -> bool {
    first_party_violation(raw).is_none()
}

/// Refuse any marketplace repository URL that is not a first-party catalog.
pub fn validate_first_party_repo_url(raw: &str) -> Result<(), MarketplaceError> {
    match first_party_violation(raw) {
        None => Ok(()),
        Some(reason) => Err(MarketplaceError::InvalidUrl(format!(
            "Marketplace content comes only from nano's first-party catalogs: {reason}"
        ))),
    }
}

/// A stored URL with any embedded credentials removed, for API responses.
pub fn redact_repo_url(raw: &str) -> String {
    match Url::parse(raw.trim()) {
        Ok(mut url) if !url.username().is_empty() || url.password().is_some() => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.to_string()
        }
        Ok(_) => raw.to_string(),
        // Not parseable: never echo something that might hold a secret.
        Err(_) if raw.contains('@') => "<redacted>".to_string(),
        Err(_) => raw.to_string(),
    }
}

#[cfg(test)]
#[path = "first_party_tests.rs"]
mod tests;

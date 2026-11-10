// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound-request safety for admin-configured AI provider settings
//! (NAN-5022).
//!
//! Every URL an operator can put in a provider's JSONB `config` is untrusted
//! input to an outbound request made by the API process (and, for the health
//! monitor, every ~5 minutes with the stored key attached). So:
//!
//! * every URL-bearing key ([`AI_PROVIDER_URL_KEYS`]) goes through the shared
//!   SSRF validator on write and is pinned to its validated address on use
//!   (`inputlookup::ai_base_url_validator`; private endpoints stay opt-in via
//!   `NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS` / `AIRGAP_MODE`);
//! * scalars that become URL path or query parts (`deployment`,
//!   `api_version`, `region`) must be plain identifiers, and URLs are built
//!   with [`url::Url`] segment / query builders, never string formatting;
//! * an upstream error body is never echoed verbatim to the caller (or stored
//!   in `provider_credentials.validation_error`, which GET returns): for an
//!   operator-set target only the status and a fixed hint are returned.

use std::sync::LazyLock;

use regex::Regex;

/// Every `config` key that names an outbound URL.
pub const AI_PROVIDER_URL_KEYS: &[&str] = &["base_url", "api_base"];

/// Azure OpenAI API version used when none is configured.
pub const DEFAULT_AZURE_API_VERSION: &str = "2024-10-21";

/// Azure deployment used by the probe when none is configured.
pub const DEFAULT_AZURE_DEPLOYMENT: &str = "gpt-5-nano";

/// The trimmed, non-empty URL stored under `key`, trailing `/` removed.
pub fn config_url(config: &serde_json::Value, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string())
}

/// Azure OpenAI `api-version` values: dated (`2024-10-21`,
/// `2025-01-01-preview`) and the v1 API's `preview` / `latest` / `v1`.
static API_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{4}-\d{2}-\d{2}(-preview)?|preview|latest|v1)$")
        .expect("static api_version regex")
});
static SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._:-]{1,200}$").expect("static segment regex"));

/// Whether `value` is safe as ONE URL path segment: a plain identifier
/// (letters, digits, `.`, `_`, `:`, `-`), never `.` / `..`.
pub fn is_safe_segment(value: &str) -> bool {
    SEGMENT.is_match(value) && value != "." && value != ".."
}

/// Whether `value` is an Azure OpenAI `api-version` (`YYYY-MM-DD[-preview]`,
/// `preview`, `latest` or `v1`).
pub fn is_api_version(value: &str) -> bool {
    API_VERSION.is_match(value)
}

/// Shape-check the scalars that become URL parts. Absent / blank values are
/// fine (defaults apply).
pub fn validate_config_scalars(config: &serde_json::Value) -> Result<(), String> {
    let get = |key: &str| {
        config
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    if let Some(v) = get("api_version") {
        if !is_api_version(v) {
            return Err(format!(
                "api_version {v:?} is not an API version (expected YYYY-MM-DD, YYYY-MM-DD-preview, preview, latest or v1)"
            ));
        }
    }
    for key in ["deployment", "region"] {
        if let Some(v) = get(key) {
            if !is_safe_segment(v) {
                return Err(format!(
                    "{key} {v:?} may only contain letters, digits, '.', '_', ':' and '-'"
                ));
            }
        }
    }
    Ok(())
}

/// Append `segments` to `base`'s path, each percent-encoded as one segment.
pub fn join_segments(base: &url::Url, segments: &[&str]) -> Result<url::Url, String> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| "base URL cannot carry a path".to_string())?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

/// The Azure OpenAI chat-completions URL for a validated `api_base`.
pub fn azure_chat_url(
    api_base: &url::Url,
    deployment: &str,
    api_version: &str,
) -> Result<url::Url, String> {
    if !is_safe_segment(deployment) {
        return Err(format!("deployment {deployment:?} is not a plain identifier"));
    }
    if !is_api_version(api_version) {
        return Err(format!("api_version {api_version:?} is not an API version"));
    }
    let mut url = join_segments(api_base, &["openai", "deployments", deployment, "chat", "completions"])?;
    url.set_query(None);
    url.set_fragment(None);
    url.query_pairs_mut().append_pair("api-version", api_version);
    Ok(url)
}

/// What a non-2xx answer tells the caller.
///
/// * `operator_host: Some(host)` — a target the operator configured (a direct
///   `base_url`, an Azure `api_base`). Only the status and a fixed hint are
///   returned: the body could be any internal service's response.
/// * `None` — a fixed vendor host (api.anthropic.com, …). The vendor's own
///   `error.message` is kept (it says e.g. "invalid x-api-key"), stripped of
///   control characters and capped at 200 characters.
pub fn summarize_upstream_error(status: u16, body: &str, operator_host: Option<&str>) -> String {
    let hint = match status {
        401 | 403 => "the API key was rejected",
        404 => "check the endpoint path, deployment and model",
        408 | 504 => "the endpoint timed out",
        429 => "the endpoint is rate limiting requests",
        500..=599 => "the endpoint returned a server error",
        _ => "unexpected response",
    };
    match operator_host {
        Some(host) => format!("{host} answered HTTP {status}: {hint}"),
        None => match vendor_error_message(body) {
            Some(message) => format!("API error (HTTP {status}): {message}"),
            None => format!("API error (HTTP {status}): {hint}"),
        },
    }
}

/// `error.message` / `message` / `error` (string) from a JSON error body.
fn vendor_error_message(body: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let message = json
        .pointer("/error/message")
        .or_else(|| json.get("message"))
        .or_else(|| json.get("error").filter(|e| e.is_string()))?
        .as_str()?;
    let clean: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let capped: String = clean.chars().take(200).collect();
    (!capped.is_empty()).then_some(capped)
}

/// A request error as text that never carries the request URL (which may
/// hold a key in its query string or credentials in its authority).
pub fn request_error(error: reqwest::Error) -> String {
    error.without_url().to_string()
}

/// NAN-5225: the stored API key was entered for one destination. Message for
/// an update that moves the provider elsewhere without re-supplying it.
pub const AI_KEY_DESTINATION_CHANGED: &str =
    "The provider endpoint (base_url / api_base scheme, host or port) changed, so the stored \
     API key is not carried over. Re-enter the API key for the new endpoint, or send an empty \
     api_key to remove it.";

/// Whether `new` sends requests somewhere other than `stored`. Every key in
/// [`AI_PROVIDER_URL_KEYS`] is compared by origin; adding a URL where none was
/// stored (vendor default endpoint → operator endpoint) or removing one (back
/// to the vendor default) is a change. An unparseable URL never matches.
pub fn ai_destination_changed(stored: &serde_json::Value, new: &serde_json::Value) -> bool {
    AI_PROVIDER_URL_KEYS.iter().any(|key| {
        match (config_url(stored, key), config_url(new, key)) {
            (None, None) => false,
            (Some(old), Some(new)) => !crate::scheduler::same_url_origin(&old, &new),
            _ => true,
        }
    })
}

/// NAN-5225: an update that replaces `config` (`new_config` is `Some`) with a
/// different destination while a key is stored must also carry `api_key` (a
/// new key, or blank to remove it); otherwise the stored key would follow the
/// new URL. Same-destination edits and providers without a key are unchanged.
pub fn ensure_api_key_follows_destination(
    stored_config: Option<&serde_json::Value>,
    new_config: Option<&serde_json::Value>,
    has_stored_key: bool,
    api_key_supplied: bool,
) -> Result<(), &'static str> {
    let Some(new_config) = new_config else {
        return Ok(());
    };
    if !has_stored_key || api_key_supplied {
        return Ok(());
    }
    let empty = serde_json::Value::Object(Default::default());
    if ai_destination_changed(stored_config.unwrap_or(&empty), new_config) {
        return Err(AI_KEY_DESTINATION_CHANGED);
    }
    Ok(())
}

#[cfg(test)]
#[path = "ai_provider_safety_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ai_provider_destination_tests.rs"]
mod destination_tests;

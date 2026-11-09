// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use serde_json::json;

#[test]
fn azure_url_is_built_from_segments() {
    let base = url::Url::parse("https://myres.openai.azure.com").unwrap();
    let url = azure_chat_url(&base, "gpt-4o", "2024-10-21").unwrap();
    assert_eq!(
        url.as_str(),
        "https://myres.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21"
    );
    // a base with a path keeps it
    let base = url::Url::parse("https://proxy.example/azure/").unwrap();
    let url = azure_chat_url(&base, "dep", "2025-01-01-preview").unwrap();
    assert_eq!(
        url.as_str(),
        "https://proxy.example/azure/openai/deployments/dep/chat/completions?api-version=2025-01-01-preview"
    );
}

/// NAN-5022 sibling: `deployment` / `api_version` were interpolated raw into
/// the probe URL path and query.
#[test]
fn path_and_query_injection_is_refused() {
    let base = url::Url::parse("https://myres.openai.azure.com").unwrap();
    for deployment in ["../../admin", "a/b", "x?y=1", "x#frag", "..", ""] {
        assert!(azure_chat_url(&base, deployment, "2024-10-21").is_err(), "{deployment}");
    }
    for version in ["2024-10-21&x=y", "1", "2024-10-21#", "latest?x", "v2", "Preview", ""] {
        assert!(azure_chat_url(&base, "dep", version).is_err(), "{version}");
    }
    assert!(validate_config_scalars(&json!({"api_version": "1&x=y"})).is_err());
    assert!(validate_config_scalars(&json!({"deployment": "../x"})).is_err());
    assert!(validate_config_scalars(&json!({"region": "us-east-1/../x"})).is_err());
}

#[test]
fn real_config_values_are_accepted() {
    validate_config_scalars(&json!({
        "api_base": "https://myres.openai.azure.com",
        "api_version": "2024-10-21",
        "deployment": "gpt-4o-mini_prod.v2",
        "region": "us-east-1",
    }))
    .unwrap();
    for version in ["2025-01-01-preview", "preview", "latest", "v1"] {
        validate_config_scalars(&json!({"api_version": version})).unwrap();
        assert!(is_api_version(version), "{version}");
    }
    validate_config_scalars(&json!({})).unwrap();
    assert!(is_safe_segment("us.anthropic.claude-sonnet-4-5-20250929-v1:0"));
}

#[test]
fn operator_target_bodies_are_never_echoed() {
    let body = r#"{"error":{"message":"SECRET-INTERNAL-BODY"}} and more SECRET"#;
    for status in [401, 404, 500, 502, 418] {
        let s = summarize_upstream_error(status, body, Some("10.0.0.5:8123"));
        assert!(!s.contains("SECRET"), "{s}");
        assert!(s.starts_with("10.0.0.5:8123 answered HTTP"), "{s}");
    }
}

#[test]
fn vendor_error_message_is_kept_short_and_clean() {
    let s = summarize_upstream_error(
        401,
        r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
        None,
    );
    assert_eq!(s, "API error (HTTP 401): invalid x-api-key");
    let long = format!(r#"{{"error":{{"message":"{}\u0007"}}}}"#, "x".repeat(500));
    let s = summarize_upstream_error(400, &long, None);
    assert!(s.len() < 240 && !s.contains('\u{7}'), "{s}");
    // not JSON: no body text at all
    let s = summarize_upstream_error(500, "<html>internal</html>", None);
    assert_eq!(s, "API error (HTTP 500): the endpoint returned a server error");
}

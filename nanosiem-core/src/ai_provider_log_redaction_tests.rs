// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5563: `redact_url_for_log` keeps only `scheme://host[:port]`.

use super::*;

#[test]
fn cloudflare_gateway_path_with_account_and_gateway_ids_is_dropped() {
    let shown = redact_url_for_log(
        "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/my-gateway",
    );
    assert_eq!(shown, "https://gateway.ai.cloudflare.com");
    assert!(!shown.contains("0123456789abcdef"));
    assert!(!shown.contains("my-gateway"));
}

#[test]
fn query_and_fragment_are_dropped() {
    let shown = redact_url_for_log("https://api.example.com/v1/models?key=sk-secret&x=1#frag");
    assert_eq!(shown, "https://api.example.com");
    assert!(!shown.contains("sk-secret"));
}

#[test]
fn userinfo_is_dropped() {
    let shown = redact_url_for_log("https://alice:hunter2@llm.internal:8443/v1");
    assert_eq!(shown, "https://llm.internal:8443");
    assert!(!shown.contains("alice"));
    assert!(!shown.contains("hunter2"));
}

#[test]
fn non_default_port_is_kept_and_default_port_is_implied() {
    assert_eq!(redact_url_for_log("http://10.0.0.5:11434/v1"), "http://10.0.0.5:11434");
    assert_eq!(redact_url_for_log("https://api.example.com:443/v1"), "https://api.example.com");
    assert_eq!(redact_url_for_log("http://[::1]:8080/x"), "http://[::1]:8080");
}

#[test]
fn surrounding_whitespace_is_ignored() {
    assert_eq!(redact_url_for_log("  https://api.example.com/v1  "), "https://api.example.com");
}

#[test]
fn blank_input_is_unset() {
    assert_eq!(redact_url_for_log(""), "<unset>");
    assert_eq!(redact_url_for_log("   "), "<unset>");
}

#[test]
fn garbage_input_is_a_placeholder_and_never_echoed() {
    for raw in [
        "not a url",
        "gateway.ai.cloudflare.com/v1/acct/gw",
        "https://",
        "mailto:ops@example.com",
        "data:text/plain,sk-secret",
        "file:///etc/secret",
    ] {
        let shown = redact_url_for_log(raw);
        assert_eq!(shown, "<invalid-url>", "input {raw:?}");
    }
}

#[test]
fn default_http_port_is_implied() {
    assert_eq!(redact_url_for_log("http://host:80/v1"), "http://host");
}

#[test]
fn non_special_scheme_with_a_host_is_invalid_by_design() {
    // `grpc://` has an opaque origin: no AI endpoint speaks it, so it is a
    // placeholder rather than a guess at what "host" means there.
    assert_eq!(redact_url_for_log("grpc://h:1/x"), "<invalid-url>");
    assert_eq!(redact_url_host("grpc://h:1/x"), None);
}

#[test]
fn host_sibling_follows_the_same_rule() {
    assert_eq!(
        redact_url_host("https://u:p@gateway.ai.cloudflare.com/v1/acct/gw?k=v").as_deref(),
        Some("gateway.ai.cloudflare.com")
    );
    assert_eq!(redact_url_host("http://10.0.0.5:8123/v1").as_deref(), Some("10.0.0.5:8123"));
    assert_eq!(redact_url_host("http://[::1]:8080/x").as_deref(), Some("[::1]:8080"));
    assert_eq!(redact_url_host("http://host:80/v1").as_deref(), Some("host"));
    assert_eq!(redact_url_host(""), None);
    assert_eq!(redact_url_host("not a url"), None);
}

#[tokio::test]
async fn request_error_keeps_the_cause_chain_without_the_url() {
    let url = "http://alice:hunter2@127.0.0.1:1/v1/ACCT-SENTINEL/gw?key=sk-secret";
    let error = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .expect_err("port 1 refuses connections");
    let text = request_error(error);
    for secret in ["ACCT-SENTINEL", "sk-secret", "hunter2", "alice"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    assert!(text.starts_with("error sending request: "), "no cause chain: {text}");
}

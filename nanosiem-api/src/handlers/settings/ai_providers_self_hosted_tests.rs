// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5136: self-hosted model discovery and the strict self-hosted
//! connection probe, against a loopback stand-in for Ollama.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FLAG: &str = "NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS";

/// A loopback server answering by request path: `routes` maps a path to
/// `(status, body)`; anything else is a 404.
async fn server(routes: &'static [(&'static str, u16, &'static str)]) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 16 * 1024];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]);
            let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
            let (status, body) = routes
                .iter()
                .find(|(p, _, _)| *p == path)
                .map(|(_, s, b)| (*s, *b))
                .unwrap_or((404, "{\"error\":\"not found\"}"));
            let response = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    format!("http://{addr}/v1")
}

#[tokio::test]
async fn discovers_models_from_v1_models() {
    let _guard = super::ssrf_tests::PRIVATE_FLAG.lock().await;
    std::env::set_var(FLAG, "true");
    let base = server(&[(
        "/v1/models",
        200,
        r#"{"object":"list","data":[{"id":"qwen2.5:0.5b","object":"model"}]}"#,
    )])
    .await;
    let (models, source) = discover_models(&base, "").await.unwrap();
    std::env::remove_var(FLAG);
    assert_eq!(models, vec!["qwen2.5:0.5b"]);
    assert_eq!(source, "openai");
}

#[tokio::test]
async fn falls_back_to_ollama_tags() {
    let _guard = super::ssrf_tests::PRIVATE_FLAG.lock().await;
    std::env::set_var(FLAG, "true");
    let base = server(&[("/api/tags", 200, r#"{"models":[{"name":"qwen2.5:0.5b"}]}"#)]).await;
    let (models, source) = discover_models(&base, "").await.unwrap();
    std::env::remove_var(FLAG);
    assert_eq!(models, vec!["qwen2.5:0.5b"]);
    assert_eq!(source, "ollama");
}

#[tokio::test]
async fn no_models_anywhere_explains_what_to_check() {
    let _guard = super::ssrf_tests::PRIVATE_FLAG.lock().await;
    std::env::set_var(FLAG, "true");
    let base = server(&[]).await;
    let err = discover_models(&base, "").await.unwrap_err();
    std::env::remove_var(FLAG);
    assert!(err.contains("HTTP 404"), "{err}");
    assert!(err.contains("/v1"), "{err}");
}

/// Without the opt-in, a LAN / loopback server is refused before any request,
/// and the message names the exact variable to set.
#[tokio::test]
async fn blocked_private_endpoint_names_the_switch() {
    let _guard = super::ssrf_tests::PRIVATE_FLAG.lock().await;
    std::env::remove_var(FLAG);
    let base = server(&[("/v1/models", 200, r#"{"data":[{"id":"x"}]}"#)]).await;
    let err = discover_models(&base, "").await.unwrap_err();
    assert!(err.contains("NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS=true"), "{err}");
    assert!(err.contains("restart"), "{err}");
}

/// The self-hosted Test connection is a real completion: it needs a model and
/// a 404 for it is a failure, not a pass.
#[tokio::test]
async fn self_hosted_probe_is_strict() {
    let _guard = super::ssrf_tests::PRIVATE_FLAG.lock().await;
    std::env::set_var(FLAG, "true");
    let ok = server(&[(
        "/v1/chat/completions",
        200,
        r#"{"choices":[{"message":{"role":"assistant","content":"OK"}}]}"#,
    )])
    .await;
    let missing = server(&[]).await;

    let no_model = serde_json::json!({ "base_url": ok, "api_style": "openai" });
    let err = test_provider_connection(SELF_HOSTED_PROVIDER, "", Some(&no_model))
        .await
        .unwrap_err();
    assert!(err.contains("Choose a model first"), "{err}");

    let good = serde_json::json!({ "base_url": ok, "api_style": "openai", "model": "qwen2.5:0.5b" });
    test_provider_connection(SELF_HOSTED_PROVIDER, "", Some(&good)).await.unwrap();

    let gone = serde_json::json!({ "base_url": missing, "model": "qwen2.5:0.5b" });
    let err = test_provider_connection(SELF_HOSTED_PROVIDER, "", Some(&gone))
        .await
        .unwrap_err();
    assert!(err.contains("HTTP 404"), "{err}");
    // The lenient vendor-row behaviour (4xx = reachable) is unchanged.
    test_provider_connection("openai", "k", Some(&gone)).await.unwrap();
    std::env::remove_var(FLAG);
}

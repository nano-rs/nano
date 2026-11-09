// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5022: every operator-set AI provider URL is SSRF-validated on write and
//! pinned on use; upstream error bodies are never echoed for those targets.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serializes the tests that flip the private-endpoint opt-in env var.
pub(super) static PRIVATE_FLAG: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const FLAG: &str = "NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS";

/// A one-shot HTTP server on loopback answering `status` with `body`, and a
/// counter of the requests it received.
async fn upstream(status: u16, body: &'static str) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = vec![0u8; 16 * 1024];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    (format!("http://{addr}"), hits)
}

#[tokio::test]
async fn api_base_is_ssrf_validated_on_write() {
    let _guard = PRIVATE_FLAG.lock().await;
    std::env::remove_var(FLAG);
    for api_base in [
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1:8123",
        "http://10.0.0.5",
        "file:///etc/passwd",
    ] {
        let config = serde_json::json!({ "api_base": api_base });
        let err = validate_config_urls(Some(&config)).await.unwrap_err();
        assert!(
            format!("{err:?}").contains("Invalid AI provider api_base"),
            "{api_base}: {err:?}"
        );
    }
    // base_url keeps its NAN-1368 check.
    let config = serde_json::json!({ "base_url": "http://127.0.0.1:4000/v1" });
    assert!(validate_config_urls(Some(&config)).await.is_err());
    // URL parts that are not plain identifiers.
    for config in [
        serde_json::json!({ "api_version": "2024-10-21&x=y" }),
        serde_json::json!({ "deployment": "../../admin" }),
    ] {
        assert!(validate_config_urls(Some(&config)).await.is_err(), "{config}");
    }
    // A normal public Azure config is accepted (IP literal: no DNS needed).
    let config = serde_json::json!({
        "api_base": "https://20.42.0.1",
        "api_version": "2024-10-21",
        "deployment": "gpt-4o",
    });
    validate_config_urls(Some(&config)).await.unwrap();
}

/// A legacy row already holding a loopback / internal `api_base`: the probe
/// (and the health monitor, which calls the same function) refuses before any
/// request, so the stored key is never sent.
#[tokio::test]
async fn stored_internal_api_base_is_never_contacted() {
    let (url, hits) = upstream(500, r#"{"error":{"message":"internal"}}"#).await;
    let _guard = PRIVATE_FLAG.lock().await;
    std::env::remove_var(FLAG);
    let config = serde_json::json!({ "api_base": url });
    let err = test_provider_connection("azure", "sk-stored-key", Some(&config))
        .await
        .unwrap_err();
    assert!(err.starts_with("api_base rejected"), "{err}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "no request may reach it");
}

/// BYO gateways on private addresses keep working through the opt-in flag
/// (NAN-2231 / NAN-2354), and their error bodies are not echoed.
#[tokio::test]
async fn private_endpoint_with_opt_in_works_and_does_not_echo_bodies() {
    let (azure, azure_hits) = upstream(500, r#"{"error":{"message":"SECRET-INTERNAL-BODY"}}"#).await;
    let (direct, _) = upstream(401, "SECRET-DIRECT-BODY").await;
    let (ok, _) = upstream(200, r#"{"choices":[]}"#).await;
    let _guard = PRIVATE_FLAG.lock().await;
    std::env::set_var(FLAG, "1");
    let azure_cfg = serde_json::json!({ "api_base": azure, "deployment": "gpt-4o" });
    let direct_cfg = serde_json::json!({ "base_url": direct });
    let ok_cfg = serde_json::json!({ "base_url": format!("{ok}/v1") });
    let results = (
        test_provider_connection("azure", "k", Some(&azure_cfg)).await,
        test_provider_connection("openai", "k", Some(&direct_cfg)).await,
        test_provider_connection("openai", "k", Some(&ok_cfg)).await,
    );
    std::env::remove_var(FLAG);
    let azure_err = results.0.unwrap_err();
    assert!(azure_err.contains("answered HTTP 500"), "{azure_err}");
    assert!(!azure_err.contains("SECRET"), "{azure_err}");
    assert_eq!(azure_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    let direct_err = results.1.unwrap_err();
    assert!(direct_err.contains("answered HTTP 401: the API key was rejected"), "{direct_err}");
    assert!(!direct_err.contains("SECRET"), "{direct_err}");
    results.2.expect("a healthy private gateway still validates");
}

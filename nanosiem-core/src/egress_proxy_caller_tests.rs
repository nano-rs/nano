// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5441: every user-set destination in nanosiem-core refuses a direct
//! connection to a public address under "proxy required" with no
//! destination proxy, and builds normally otherwise. A public IP literal
//! needs no DNS, and the refusal happens before anything is dialed.

use super::*;
use crate::inputlookup::{FetchError, InputLookupConfig, SsrfError, SsrfValidator, UrlFetcher};

const PUBLIC: &str = "http://93.184.216.34/hook";

fn required() -> EgressSettings {
    EgressSettings { required: true, ..EgressSettings::default() }
}

fn with_proxy() -> EgressSettings {
    EgressSettings::from_values(Some("true"), Some("http://proxy.corp.invalid:3128"), None, EnvProxy::NONE)
}

#[tokio::test]
async fn webhook_and_channel_delivery_refuses() {
    use crate::webhooks::service::WebhookService;
    let err = with_egress_settings(required(), WebhookService::ssrf_checked_client(PUBLIC)).await.unwrap_err();
    assert!(err.contains("NANO_EGRESS_PROXY_REQUIRED"), "{err}");
    assert!(with_egress_settings(with_proxy(), WebhookService::ssrf_checked_client(PUBLIC)).await.is_ok());
    assert!(WebhookService::ssrf_checked_client(PUBLIC).await.is_ok(), "default must be unchanged");
}

#[tokio::test]
async fn synthetic_check_refuses() {
    use crate::observability::synthetic_runner::SyntheticRunner;
    let err = with_egress_settings(required(), SyntheticRunner::ssrf_checked_client(PUBLIC)).await.unwrap_err();
    assert!(err.contains("NANO_EGRESS_PROXY_REQUIRED"), "{err}");
    assert!(with_egress_settings(with_proxy(), SyntheticRunner::ssrf_checked_client(PUBLIC)).await.is_ok());
    assert!(SyntheticRunner::ssrf_checked_client(PUBLIC).await.is_ok());
}

#[tokio::test]
async fn inputlookup_url_refuses() {
    let fetcher = UrlFetcher::new(InputLookupConfig { allow_http: true, ..InputLookupConfig::default() });
    let err = with_egress_settings(required(), fetcher.fetch(PUBLIC, Some(2), 0)).await.unwrap_err();
    assert!(
        matches!(err, FetchError::SsrfValidation(SsrfError::EgressProxyRequired(_))),
        "{err}"
    );
}

/// The scheduler fetch, AI provider base URL (gateway and settings test /
/// model listing), the meloD URL-fetch tool and the SOAR catalog all build
/// their client with `build_pinned_client(.., ProxyPolicy::Direct)`.
#[tokio::test]
async fn build_pinned_client_direct_refuses() {
    for validator in [SsrfValidator::http_allowed_validator(), crate::inputlookup::ai_base_url_validator()] {
        let r = with_egress_settings(
            required(),
            validator.build_pinned_client(PUBLIC, reqwest::Client::builder(), crate::inputlookup::ProxyPolicy::Direct),
        )
        .await;
        assert!(matches!(r, Err(SsrfError::EgressProxyRequired(_))), "{r:?}");
        let r = with_egress_settings(
            with_proxy(),
            validator.build_pinned_client(PUBLIC, reqwest::Client::builder(), crate::inputlookup::ProxyPolicy::Direct),
        )
        .await;
        assert!(r.is_ok(), "{r:?}");
    }
}

/// Operator-configured destinations (OIDC, identity sync, the signed
/// enrichment bundle) use the env proxy; under "proxy required" with no env
/// proxy they refuse too.
#[tokio::test]
async fn build_pinned_client_environment_refuses_without_env_proxy() {
    let r = with_egress_settings(
        required(),
        SsrfValidator::default_secure().build_pinned_client(
            "https://93.184.216.34/",
            reqwest::Client::builder(),
            crate::inputlookup::ProxyPolicy::Environment,
        ),
    )
    .await;
    assert!(matches!(r, Err(SsrfError::EgressProxyRequired(_))), "{r:?}");
}

/// The Entra Graph group lookup (operator-configured IdP, env proxy) refuses
/// before any request: membership stays unknown, so sign-in is refused.
#[cfg(feature = "enterprise")]
#[tokio::test]
async fn entra_graph_group_lookup_refuses_without_https_env_proxy() {
    let claims = || -> crate::auth::IdTokenClaims {
        serde_json::from_value(serde_json::json!({
            "iss": "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0",
            "tid": "11111111-1111-4111-8111-111111111111",
            "sub": "s", "aud": "c", "exp": 2_000_000_000i64, "iat": 1_900_000_000i64,
            "hasgroups": true
        }))
        .unwrap()
    };
    for env_proxy in [EnvProxy::NONE, EnvProxy { http: true, https: false }] {
        let mut c = claims();
        let s = EgressSettings { env_proxy, ..required() };
        let r = with_egress_settings(s, crate::auth::oidc::resolve_entra_groups(&mut c, "token")).await;
        assert!(matches!(r, Err(crate::auth::OidcError::GroupMembershipUnknown)), "{r:?}");
    }
}

/// SIEM forwarding (operator URL, env proxy) drops the batch under "proxy
/// required" with no env proxy, and sends it otherwise.
#[tokio::test]
async fn siem_forwarding_drops_batch_without_env_proxy() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/ingest", listener.local_addr().unwrap());
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 16 * 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        }
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut batch = vec!["{\"a\":1}".to_string()];
    with_egress_settings(required(), crate::telemetry::flush_batch(&client, &url, "", &mut batch)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing sent under proxy required");
    assert!(batch.is_empty());
    let mut batch = vec!["{\"a\":1}".to_string()];
    crate::telemetry::flush_batch(&client, &url, "", &mut batch).await;
    assert_eq!(hits.load(Ordering::SeqCst), 1, "default must be unchanged");
}

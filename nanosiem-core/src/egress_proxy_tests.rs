// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5441: the destination proxy relay and "proxy required" at the shared
//! pin (`pin_resolved_addrs_with`). Every pinned user-set destination builds
//! its client there, so these cover the transport; the per-caller tests next
//! to each caller prove the caller goes through it.

use super::*;
use crate::inputlookup::{pin_resolved_addrs_with, ProxyPolicy, SsrfError};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// An origin that answers one request with `body`.
async fn origin(body: &'static str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                let resp = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

/// A forward proxy that records each CONNECT target and tunnels every one
/// to `origin` (so a `.invalid` name works in hostname mode). `deny` answers
/// 403 instead.
async fn recording_proxy(origin: SocketAddr, deny: bool) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let Some((head, _)) = read_request_head(&mut socket).await else { return };
                let line = String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string();
                log.lock().unwrap().push(line);
                if deny {
                    let _ = socket.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                    return;
                }
                let Ok(mut up) = TcpStream::connect(origin).await else { return };
                let _ = socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                let _ = tokio::io::copy_bidirectional(&mut socket, &mut up).await;
            });
        }
    });
    (format!("http://{addr}"), seen)
}

/// Settings with loopback fixtures treated as public destinations.
fn settings(proxy: Option<&str>, mode: Option<&str>, required: bool) -> EgressSettings {
    EgressSettings {
        loopback_is_public: true,
        ..EgressSettings::from_values(Some(if required { "true" } else { "false" }), proxy, mode, EnvProxy::NONE)
    }
}

fn pinned(url: &url::Url, addrs: &[SocketAddr], s: &EgressSettings) -> Result<reqwest::Client, SsrfError> {
    pin_resolved_addrs_with(reqwest::Client::builder(), url, addrs, ProxyPolicy::Direct, s).map(|b| b.build().unwrap())
}

#[tokio::test]
async fn pinned_mode_connects_to_the_pinned_ip_never_the_name() {
    let server = origin("via-proxy").await;
    let (proxy, seen) = recording_proxy(server, false).await;
    // `.invalid` never resolves: reaching the origin proves nobody resolved
    // the name after validation (the DNS-rebinding guard holds via the proxy).
    let url = url::Url::parse(&format!("http://rebind.nano.invalid:{}/x", server.port())).unwrap();
    let client = pinned(&url, &[server], &settings(Some(&proxy), None, false)).unwrap();
    let body = client.get(url).send().await.unwrap().text().await.unwrap();
    assert_eq!(body, "via-proxy");
    assert_eq!(seen.lock().unwrap().as_slice(), [format!("CONNECT {server} HTTP/1.1")]);
}

#[tokio::test]
async fn hostname_mode_connects_to_the_name() {
    let server = origin("named").await;
    let (proxy, seen) = recording_proxy(server, false).await;
    let url = url::Url::parse(&format!("http://dest.nano.invalid:{}/", server.port())).unwrap();
    let client = pinned(&url, &[server], &settings(Some(&proxy), Some("hostname"), false)).unwrap();
    assert_eq!(client.get(url).send().await.unwrap().text().await.unwrap(), "named");
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [format!("CONNECT dest.nano.invalid:{} HTTP/1.1", server.port())]
    );
}

#[tokio::test]
async fn proxy_denial_fails_closed_never_direct() {
    let server = origin("direct").await;
    let (proxy, seen) = recording_proxy(server, true).await;
    let url = url::Url::parse(&format!("http://dest.nano.invalid:{}/", server.port())).unwrap();
    let client = pinned(&url, &[server], &settings(Some(&proxy), None, false)).unwrap();
    let resp = client.get(url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN, "denied tunnel must not reach the origin");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn relay_serves_only_the_validated_host() {
    let server = origin("x").await;
    let (proxy, seen) = recording_proxy(server, false).await;
    let url = url::Url::parse(&format!("http://dest.nano.invalid:{}/", server.port())).unwrap();
    let client = pinned(&url, &[server], &settings(Some(&proxy), None, false)).unwrap();
    let other = format!("http://other.nano.invalid:{}/", server.port());
    let resp = client.get(other).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(seen.lock().unwrap().is_empty(), "a second name reached the operator proxy");
}

#[tokio::test]
async fn relay_connect_path_requires_its_credential_and_tunnels() {
    let server = origin("tunnelled").await;
    let (proxy, seen) = recording_proxy(server, false).await;
    let dest = DestinationProxy { endpoint: ProxyEndpoint::parse(&proxy).unwrap(), mode: ProxyMode::PinnedIp };
    let target = RelayTarget {
        host: "dest.nano.invalid".into(),
        port: server.port(),
        addrs: vec![server],
        upstream: dest.endpoint.clone(),
        mode: dest.mode,
    };
    let relay = Relay::start(&tokio::runtime::Handle::current(), target).unwrap();
    let relay_addr = format!("127.0.0.1:{}", relay.proxy_url.port().unwrap());

    // No credential: refused before anything goes upstream.
    let mut s = TcpStream::connect(&relay_addr).await.unwrap();
    s.write_all(format!("CONNECT dest.nano.invalid:{} HTTP/1.1\r\n\r\n", server.port()).as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 407"));
    assert!(seen.lock().unwrap().is_empty());

    // With it: a CONNECT to the pinned ip upstream, then bytes flow.
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:x", relay.proxy_url.username()))
    );
    let mut s = TcpStream::connect(&relay_addr).await.unwrap();
    s.write_all(
        format!("CONNECT dest.nano.invalid:{} HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n", server.port()).as_bytes(),
    )
    .await
    .unwrap();
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    s.write_all(b"GET / HTTP/1.1\r\nHost: dest.nano.invalid\r\n\r\n").await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.ends_with("tunnelled"), "{out}");
    assert_eq!(seen.lock().unwrap().as_slice(), [format!("CONNECT {server} HTTP/1.1")]);
}

#[tokio::test]
async fn required_without_destination_proxy_refuses_direct() {
    let url = url::Url::parse("https://hooks.example.com/x").unwrap();
    let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let err = pinned(&url, &[addr], &settings(None, None, true)).unwrap_err();
    assert!(matches!(err, SsrfError::EgressProxyRequired(_)), "{err}");
    // IP-literal destinations too.
    let url = url::Url::parse("https://93.184.216.34/x").unwrap();
    assert!(matches!(pinned(&url, &[], &settings(None, None, true)), Err(SsrfError::EgressProxyRequired(_))));
}

#[tokio::test]
async fn required_with_destination_proxy_is_allowed() {
    let url = url::Url::parse("https://hooks.example.com/x").unwrap();
    let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
    assert!(pinned(&url, &[addr], &settings(Some("http://proxy.corp:3128"), None, true)).is_ok());
}

#[tokio::test]
async fn required_environment_policy_needs_an_env_proxy() {
    let url = url::Url::parse("https://idp.example.com/").unwrap();
    let no_env = settings(None, None, true);
    let err = pin_resolved_addrs_with(reqwest::Client::builder(), &url, &[], ProxyPolicy::Environment, &no_env).unwrap_err();
    assert!(matches!(err, SsrfError::EgressProxyRequired(_)));
    let with_env = EgressSettings { env_proxy: EnvProxy::ALL, ..no_env.clone() };
    assert!(pin_resolved_addrs_with(reqwest::Client::builder(), &url, &[], ProxyPolicy::Environment, &with_env).is_ok());
    // HTTP_PROXY alone never covers an https:// destination (reqwest uses it
    // for http:// only), so "required" still refuses.
    let http_only = EgressSettings { env_proxy: EnvProxy { http: true, https: false }, ..no_env };
    let err = pin_resolved_addrs_with(reqwest::Client::builder(), &url, &[], ProxyPolicy::Environment, &http_only).unwrap_err();
    assert!(matches!(err, SsrfError::EgressProxyRequired(_)));
    let plain = url::Url::parse("http://idp.example.com/").unwrap();
    assert!(pin_resolved_addrs_with(reqwest::Client::builder(), &plain, &[], ProxyPolicy::Environment, &http_only).is_ok());
}

#[tokio::test]
async fn invalid_destination_setting_refuses_never_direct() {
    let url = url::Url::parse("https://hooks.example.com/x").unwrap();
    for (proxy, mode) in [(Some("https://proxy:3128"), None), (Some("http://proxy:3128"), Some("bogus"))] {
        let err = pinned(&url, &[], &settings(proxy, mode, false)).unwrap_err();
        assert!(matches!(err, SsrfError::EgressProxyMisconfigured(_)), "{proxy:?} {mode:?}: {err}");
    }
}

#[tokio::test]
async fn internal_destinations_stay_direct_under_required_and_proxy() {
    // An internal address passes SSRF only via an operator opt-in (private
    // AI endpoints, webhook CIDR allowlist). The internet proxy cannot reach
    // it, so it stays direct even when a proxy is set or required.
    let server = origin("internal").await;
    let (proxy, seen) = recording_proxy(server, false).await;
    let url = url::Url::parse(&format!("http://ai.internal.invalid:{}/", server.port())).unwrap();
    let real = |s: EgressSettings| EgressSettings { loopback_is_public: false, ..s };
    for s in [real(settings(Some(&proxy), None, true)), real(settings(None, None, true))] {
        let client = pinned(&url, &[server], &s).unwrap();
        assert_eq!(client.get(url.clone()).send().await.unwrap().text().await.unwrap(), "internal");
    }
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn public_destination_classification() {
    for ip in ["93.184.216.34", "1.1.1.1", "2606:4700::1111"] {
        assert!(is_public_destination(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "fd00::1", "::1"] {
        assert!(!is_public_destination(ip.parse().unwrap()), "{ip}");
    }
}

#[tokio::test]
async fn defaults_are_unchanged() {
    // Nothing set: Direct dials the pinned addr, no relay, no refusal.
    let server = origin("direct").await;
    let url = url::Url::parse(&format!("http://dest.nano.invalid:{}/", server.port())).unwrap();
    let client = pinned(&url, &[server], &EgressSettings::default()).unwrap();
    assert_eq!(client.get(url).send().await.unwrap().text().await.unwrap(), "direct");
}

#[test]
fn required_flag_parsing_fails_closed() {
    for off in [None, Some(""), Some("false"), Some("0"), Some("off"), Some("NO")] {
        assert!(!parse_required(off), "{off:?}");
    }
    for on in [Some("true"), Some("1"), Some("ON"), Some("yes"), Some("ture")] {
        assert!(parse_required(on), "{on:?}");
    }
}

#[tokio::test]
async fn a_scope_cannot_relax_required_from_the_env() {
    // The env in this test process has the flag unset, so a scope sets it.
    let on = with_egress_settings(settings(None, None, true), async { proxy_required() }).await;
    assert!(on);
    assert!(!proxy_required());
}

#[test]
fn env_proxy_is_scheme_aware_like_reqwest() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        EnvProxy::from_lookup(move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()))
    };
    let http_only = env(&[("HTTP_PROXY", "http://p:3128")]);
    assert!(http_only.covers_url("http://x.example/") && !http_only.covers_url("https://x.example/"));
    let https = env(&[("https_proxy", "http://p:3128")]);
    assert!(https.covers("https") && !https.covers("http"));
    assert_eq!(env(&[("ALL_PROXY", "http://p:3128")]), EnvProxy::ALL);
    // The uppercase name wins even when empty, as in hyper-util.
    assert_eq!(env(&[("HTTPS_PROXY", ""), ("https_proxy", "http://p:3128")]), EnvProxy::NONE);
    // NO_PROXY=* and CGI disable the env proxy entirely.
    assert_eq!(env(&[("ALL_PROXY", "http://p:3128"), ("NO_PROXY", "localhost, *")]), EnvProxy::NONE);
    assert_eq!(env(&[("ALL_PROXY", "http://p:3128"), ("REQUEST_METHOD", "GET")]), EnvProxy::NONE);
    // Unknown schemes and unparseable URLs need both.
    assert!(!https.covers_url("not a url") && EnvProxy::ALL.covers_url("not a url"));
}

#[tokio::test]
async fn require_env_proxy_checks_the_url_scheme() {
    let s = EgressSettings { required: true, env_proxy: EnvProxy { http: true, https: false }, ..EgressSettings::default() };
    let r = with_egress_settings(s.clone(), async { require_env_proxy("https://api.example.com/") }).await;
    assert_eq!(r, Err(ProxyRefusal::Required));
    let r = with_egress_settings(s, async { require_env_proxy("http://api.example.com/") }).await;
    assert_eq!(r, Ok(()));
}

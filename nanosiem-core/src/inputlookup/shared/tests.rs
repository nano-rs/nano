use super::*;
use std::io::{Read, Write};

#[derive(Default)]
struct Authority {
    id: Uuid,
    settings: Mutex<StorageLookupSettings>,
    records: Mutex<Vec<FetchAudit>>,
    fail_audit: bool,
    settings_reads: std::sync::atomic::AtomicUsize,
}
#[async_trait]
impl StorageLookupAuthority for Authority {
    fn tenant_id(&self) -> Uuid {
        self.id
    }
    async fn settings(&self) -> Result<StorageLookupSettings, &'static str> {
        self.settings_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.settings.lock().unwrap().clone())
    }
    async fn audit_ready(&self) -> Result<(), &'static str> {
        if self.fail_audit { Err("audit unavailable") } else { Ok(()) }
    }
    async fn audit(&self, record: &FetchAudit) -> Result<(), &'static str> {
        if self.fail_audit { return Err("audit unavailable"); }
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }

}
fn service() -> (SharedStorageLookup, Arc<Authority>) {
    let authority = Arc::new(Authority {
        id: Uuid::new_v4(),
        ..Default::default()
    });
    authority.settings.lock().unwrap().entries.push(StorageLookupEntry {
        host: "storage.googleapis.com".into(), note: String::new(), created_by: authority.id, created_at: chrono::Utc::now(),
    });
    let mut lookup = SharedStorageLookup::new(authority.clone()).unwrap();
    lookup.route = Some(FetchRoute::Direct);
    (lookup, authority)
}
fn params() -> InputLookupParams {
    super::super::params_from_command(
        "https://storage.googleapis.com/bucket/feed.csv?sig=TEST_CREDENTIAL",
        super::super::InputLookupFormat::Csv,
        None,
        1,
        10,
        0,
    )
}

/// Loopback TLS fake GCS; only test builds replace dialing with this endpoint.
/// The production URL parser, policy, redirect loop, TLS/SNI/Host verification,
/// body parser, limits, cache, rate and audit paths remain under test.
fn fake_gcs(
    response: &'static [u8],
    drip: bool,
) -> (TestEndpoint, std::thread::JoinHandle<String>) {
    fake_gcs_hops(response, drip, 1)
}
fn fake_gcs_hops(
    response: &'static [u8],
    drip: bool,
    hops: usize,
) -> (TestEndpoint, std::thread::JoinHandle<String>) {
    let cert_der = include_bytes!("fixtures/test-cert.der").to_vec();
    let key_der = include_bytes!("fixtures/test-key.der").to_vec();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let mut last_request = String::new();
        let config = Arc::new(config);
        for _ in 0..hops {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(4)))
                .unwrap();
            let connection = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
            let mut tls = rustls::StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            loop {
                let mut buf = [0; 1024];
                let n = match tls.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => return String::new(),
                };
                if n == 0 {
                    return String::new();
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert_eq!(tls.conn.server_name(), Some("storage.googleapis.com"));
            let _ = tls.write_all(response);
            let _ = tls.flush();
            if drip {
                std::thread::sleep(Duration::from_millis(1500));
                let _ = tls.write_all(b"1\r\nx\r\n");
                let _ = tls.flush();
            }
            last_request = String::from_utf8(request).unwrap();
        }
        last_request
    });
    (
        TestEndpoint {
            addr,
            cert: reqwest::Certificate::from_der(&cert_der).unwrap(),
            answers: None,
        },
        thread,
    )
}

#[test]
fn all_dns_answers_private_cname_rebinding_and_ipv6_translation_blocked() {
    for raw in [
        "10.0.0.1:443",
        "127.0.0.1:443",
        "169.254.169.254:443",
        "100.64.0.1:443",
        "0.0.0.0:443",
        "192.0.0.1:443",
        "192.88.99.1:443",
        "198.18.0.1:443",
        "[::1]:443",
        "[fd00::1]:443",
        "[fe80::1]:443",
        "[::ffff:169.254.169.254]:443",
        "[64:ff9b::a00:1]:443",
        "[64:ff9b:1::a00:1]:443",
        "[2002:a00:1::]:443",
        "[2001::a00:1]:443",
        "[3fff::1]:443",
        "[3ffe::1]:443",
    ] {
        let addrs = ["8.8.8.8:443".parse().unwrap(), raw.parse().unwrap()];
        assert!(validate_addresses(&addrs).is_err(), "{raw}");
    }
    assert!(validate_addresses(&[]).is_err());
    assert!(validate_addresses(&[
        "8.8.8.8:443".parse().unwrap(),
        "[2606:4700:4700::1111]:443".parse().unwrap()
    ])
    .is_ok());
}
#[tokio::test]
async fn fake_gcs_tls_csv_fetch_audit_and_tenant_cache_isolation() {
    let (mut lookup, authority) = service();
    let (endpoint, server) = fake_gcs(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nB\r\nname\nweb01\n\r\n0\r\n\r\n", false);
    lookup.endpoint = Some(endpoint);
    let mut p = params();
    p.cache_ttl_secs = 900;
    let rows = lookup.fetch(&p).await.unwrap();
    assert_eq!(rows[0]["name"], "web01");
    let request = server.join().unwrap().to_lowercase();
    assert!(request.contains("host: storage.googleapis.com"));
    assert!(request.contains("accept-encoding: identity"));
    assert!(!request.contains("authorization:"));
    assert!(lookup.fetch(&p).await.is_ok(), "cached without a server");
    let records = authority.records.lock().unwrap();
    assert_eq!(records.len(), 2, "one event for the network fetch and one for the cached attempt");
    assert_eq!(records[0].http_status, Some(200));
    assert_eq!(records[0].tenant_id, lookup.tenant_id());
    assert_eq!(records[0].bytes, 11);
    assert_eq!(records[0].decision, "allowed");
    assert!(!format!("{records:?}").contains("TEST_CREDENTIAL"));
    drop(records);
    let (other, _) = service();
    assert!(other.state.cached(&p.url.template, 900).is_none());
    authority.settings.lock().unwrap().entries.clear();
    assert!(!Arc::ptr_eq(&lookup.state, &other.state));
}
#[tokio::test]
async fn redirect_disallowed_host_scheme_and_hop_limit() {
    for response in [
        &b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/x?sig=TEST_CREDENTIAL\r\nContent-Length: 0\r\n\r\n"[..],
        &b"HTTP/1.1 302 Found\r\nLocation: http://storage.googleapis.com/bucket/x\r\nContent-Length: 0\r\n\r\n"[..],
        &b"HTTP/1.1 302 Found\r\nLocation: https://storage.googleapis.com@evil.example/x\r\nContent-Length: 0\r\n\r\n"[..],
    ] {
        let (mut lookup, _) = service(); let (endpoint, server) = fake_gcs(response, false); lookup.endpoint = Some(endpoint);
        assert!(matches!(lookup.fetch(&params()).await.unwrap_err(), STORAGE_POLICY_ERROR | super::super::storage_policy::ALLOWLIST_ERROR));
        server.join().unwrap();
    }
}
#[tokio::test]
async fn content_length_compression_row_cap_and_slow_drip_deadline() {
    for (response, expected, drip) in [
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 52428801\r\n\r\n"[..],
            "inputlookup response exceeds byte limit",
            false,
        ),
        (
            &b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nxx"[..],
            "inputlookup compressed responses are not supported",
            false,
        ),
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nx\na\nb\nc\n"[..],
            "inputlookup response parse or row limit failure",
            false,
        ),
        (
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n"[..],
            "inputlookup deadline exceeded",
            true,
        ),
    ] {
        let (mut lookup, _) = service();
        let (endpoint, server) = fake_gcs(response, drip);
        lookup.endpoint = Some(endpoint);
        let mut p = params();
        p.max_rows = 1;
        assert_eq!(lookup.fetch(&p).await.unwrap_err(), expected);
        server.join().unwrap();
    }
}
#[tokio::test]
async fn templates_enrichment_audit_failure_and_tenant_limits_fail_closed() {
    let (lookup, authority) = service();
    let mut p = params();
    p.key_field = Some("user".into());
    assert!(lookup.fetch(&p).await.is_err());
    p = params();
    p.url = super::super::UrlTemplate::new("https://storage.googleapis.com/bucket/{user}");
    assert!(lookup.fetch(&p).await.is_err());
    let _one = lookup.state.concurrency.acquire().await.unwrap();
    let _two = lookup.state.concurrency.acquire().await.unwrap();
    assert!(lookup
        .fetch(&params())
        .await
        .unwrap_err()
        .contains("concurrency"));
    drop(_one);
    drop(_two);
    for _ in 0..10 {
        lookup.state.rate.check().unwrap();
    }
    assert!(lookup.fetch(&params()).await.unwrap_err().contains("rate"));
    assert!(!authority.records.lock().unwrap().is_empty());
    let broken = Arc::new(Authority {
        id: Uuid::new_v4(),
        fail_audit: true,
        ..Default::default()
    });
    assert_eq!(
        SharedStorageLookup::new(broken)
            .unwrap()
            .fetch(&params())
            .await
            .unwrap_err(),
        "audit unavailable"
    );
}
#[test]
fn cache_budget_and_ttl_and_same_tenant_state() {
    let (one, authority) = service();
    let two = SharedStorageLookup::new(authority).unwrap();
    assert!(Arc::ptr_eq(&one.state, &two.state));
    one.state.insert("a".into(), "cached".into(), 0);
    assert!(one.state.cached("a", 900).is_none());
    for n in 0..18 {
        one.state.insert(n.to_string(), "body".into(), 900);
    }
    assert!(one.state.cache.lock().unwrap().len() <= 16);
}

#[tokio::test]
async fn relative_redirects_are_revalidated_and_fourth_hop_denied() {
    let (mut lookup, _) = service();
    let (endpoint, server) = fake_gcs_hops(
        b"HTTP/1.1 302 Found\r\nLocation: /bucket/next.csv\r\nContent-Length: 0\r\n\r\n",
        false,
        4,
    );
    lookup.endpoint = Some(endpoint);
    assert_eq!(
        lookup.fetch(&params()).await.unwrap_err(),
        "inputlookup exceeded 3 redirects"
    );
    server.join().unwrap();
}
#[tokio::test]
async fn streaming_byte_cap_without_content_length() {
    let (endpoint, server) = fake_gcs(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nabcdef\r\n0\r\n\r\n", false);
    let response = client_builder()
        .add_root_certificate(endpoint.cert)
        .resolve_to_addrs("storage.googleapis.com", &[endpoint.addr])
        .build()
        .unwrap()
        .get(format!(
            "https://storage.googleapis.com:{}/bucket/x",
            endpoint.addr.port()
        ))
        .send()
        .await
        .unwrap();
    let mut bytes = 0;
    assert_eq!(
        read_body(response, &mut bytes, 4).await.unwrap_err(),
        "inputlookup response exceeds byte limit"
    );
    assert_eq!(bytes, 6);
    server.join().unwrap();
}
#[tokio::test]
async fn untrusted_tls_certificate_is_rejected() {
    let (endpoint, server) = fake_gcs(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false);
    let client = client_builder()
        .resolve_to_addrs("storage.googleapis.com", &[endpoint.addr])
        .build()
        .unwrap();
    assert!(client
        .get(format!(
            "https://storage.googleapis.com:{}/bucket/x",
            endpoint.addr.port()
        ))
        .send()
        .await
        .is_err());
    assert!(server.join().unwrap().is_empty());
}
#[tokio::test]
async fn removed_extra_host_revokes_cached_reads_and_limits_are_checked() {
    let (lookup, authority) = service();
    authority.settings.lock().unwrap().entries = vec![StorageLookupEntry { host: "feeds.example.com".into(), note: String::new(), created_by: authority.id, created_at: chrono::Utc::now() }];
    let mut p = params();
    p.url = super::super::UrlTemplate::new("https://feeds.example.com/feed.csv");
    p.cache_ttl_secs = 900;
    lookup
        .state
        .insert(p.url.template.clone(), "name\nweb01\n".into(), 900);
    assert!(lookup.fetch(&p).await.is_ok());
    authority.settings.lock().unwrap().entries.clear();
    assert_eq!(lookup.fetch(&p).await.unwrap_err(), super::super::storage_policy::ALLOWLIST_ERROR);
    p.max_rows = MAX_SHARED_ROWS + 1;
    assert!(lookup.fetch(&p).await.is_err());
    p.max_rows = 10;
    p.timeout_secs = 0;
    assert!(lookup.fetch(&p).await.is_err());
}
#[test]
fn ndjson_and_diagnostics_redact_credentials() {
    use super::super::{response_parser::parse_response, InputLookupFormat};
    assert_eq!(
        parse_response(
            "{\"name\":\"a\"}\n{\"name\":\"b\"}\n",
            InputLookupFormat::Ndjson,
            2
        )
        .unwrap()
        .len(),
        2
    );
    assert!(parse_response(
        "{\"name\":\"a\"}\n{\"name\":\"b\"}\n",
        InputLookupFormat::Ndjson,
        1
    )
    .is_err());
    let query = "| inputlookup url=\"https://storage.googleapis.com/bucket/feed?sig=TEST_CREDENTIAL\" format=ndjson";
    assert!(!format!("{:?}", crate::query::parse_query(query).unwrap()).contains("TEST_CREDENTIAL"));
    let error = crate::query::parse_query(&format!("{query} | invalidcommand")).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("TEST_CREDENTIAL"));
}

#[tokio::test]
async fn dns_resolves_once_pins_public_answer_and_redirect_rechecks_private_answer() {
    let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let private: SocketAddr = "169.254.169.254:443".parse().unwrap();
    let (mut lookup, _) = service();
    let (mut endpoint, server) = fake_gcs(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nx\na\n",
        false,
    );
    let answers = Arc::new(Mutex::new(vec![vec![public], vec![private]]));
    endpoint.answers = Some(answers.clone());
    lookup.endpoint = Some(endpoint);
    assert!(lookup.fetch(&params()).await.is_ok());
    server.join().unwrap();
    assert_eq!(
        answers.lock().unwrap().len(),
        1,
        "no second DNS lookup while dialing"
    );
    assert!(lookup
        .fetch(&params())
        .await
        .unwrap_err()
        .contains("non-public"));
    let (mut lookup, _) = service();
    let (mut endpoint, server) = fake_gcs(b"HTTP/1.1 302 Found\r\nLocation: /bucket/next.csv\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", false);
    endpoint.answers = Some(Arc::new(Mutex::new(vec![
        vec![public],
        vec![public, private],
    ])));
    lookup.endpoint = Some(endpoint);
    assert!(lookup
        .fetch(&params())
        .await
        .unwrap_err()
        .contains("non-public"));
    server.join().unwrap();
}
#[cfg(feature = "enterprise")]
#[test]
fn shared_query_guard_requires_tenant_fetcher_and_rejects_remote_enrichment() {
    use crate::search::query_processing::{
        validate_enterprise_shared_query_dependencies_with as validate,
        EnterpriseSharedQueryCapabilities,
    };
    let caps = EnterpriseSharedQueryCapabilities {
        tenant_storage_inputlookup: true,
        ..Default::default()
    };
    let parsed =
        crate::query::parse_query("| inputlookup url=\"https://storage.googleapis.com/bucket/x\"")
            .unwrap();
    assert!(validate(&parsed, Default::default()).is_err());
    assert!(validate(&parsed, caps).is_ok());
    for query in ["* | inputlookup url=\"https://storage.googleapis.com/bucket/{user}\" key=user", "* | inputlookup url=\"https://storage.googleapis.com/bucket/x\" key=user", "| inputlookup url=\"https://storage.googleapis.com:8443/bucket/x\"", "* | append [* | inputlookup url=\"https://storage.googleapis.com/bucket/{user}\" key=user]"] {
        assert!(validate(&crate::query::parse_query(query).unwrap(), caps).is_err());
    }
}

#[test]
fn rate_is_a_strict_rolling_minute_and_cache_honors_callers_ttl() {
    let rate = TenantRate::new();
    for _ in 0..10 {
        rate.check().unwrap();
    }
    assert!(rate.check().is_err());
    rate.requests.lock().unwrap().pop_front();
    rate.requests
        .lock()
        .unwrap()
        .push_front(Instant::now() - Duration::from_secs(61));
    assert!(rate.check().is_ok());
    assert!(rate.check().is_err());
    let (lookup, _) = service();
    lookup.state.insert("ttl".into(), "body".into(), 900);
    lookup
        .state
        .cache
        .lock()
        .unwrap()
        .get_mut("ttl")
        .unwrap()
        .created = Instant::now() - Duration::from_secs(2);
    assert!(lookup.state.cached("ttl", 1).is_none());
    assert!(lookup.state.cached("ttl", 900).is_some());
}
#[tokio::test]
async fn trusted_certificate_for_wrong_hostname_is_rejected() {
    let (endpoint, server) = fake_gcs(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false);
    let client = client_builder()
        .add_root_certificate(endpoint.cert)
        .resolve_to_addrs("account.blob.core.windows.net", &[endpoint.addr])
        .build()
        .unwrap();
    assert!(client
        .get(format!(
            "https://account.blob.core.windows.net:{}/x",
            endpoint.addr.port()
        ))
        .send()
        .await
        .is_err());
    assert!(server.join().unwrap().is_empty());
}

fn test_proxy(
    target: Option<SocketAddr>,
    reply: &'static [u8],
    hops: usize,
    delay: bool,
) -> (FetchRoute, std::thread::JoinHandle<Vec<String>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let route = FetchRoute::Proxy(
        Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap(),
    );
    let thread = std::thread::spawn(move || {
        let mut records = Vec::new();
        for _ in 0..hops {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(4)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            records.push(String::from_utf8(request).unwrap());
            if delay {
                std::thread::sleep(Duration::from_millis(1500));
            }
            if socket.write_all(reply).is_err() {
                continue;
            }
            if let Some(target) = target {
                let mut upstream = std::net::TcpStream::connect(target).unwrap();
                upstream
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                let mut socket_read = socket.try_clone().unwrap();
                let mut upstream_write = upstream.try_clone().unwrap();
                let forwarding = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut socket_read, &mut upstream_write);
                    let _ = upstream_write.shutdown(std::net::Shutdown::Write);
                });
                let _ = std::io::copy(&mut upstream, &mut socket);
                let _ = socket.shutdown(std::net::Shutdown::Both);
                forwarding.join().unwrap();
            }
        }
        records
    });
    (route, thread)
}

#[test]
fn explicit_proxy_configuration_fails_closed() {
    assert!(FetchRoute::from_config_mode(None, Some("1"), false).is_err());
    assert!(FetchRoute::from_config_mode(Some("http://squid.internal:3128"), Some("1"), false).unwrap().is_proxy());
    assert!(FetchRoute::from_config(None, None).is_err());
    assert!(FetchRoute::from_config(None, Some("true")).is_err());
    assert!(matches!(
        FetchRoute::from_config_mode(None, Some("1"), true),
        Ok(FetchRoute::Direct)
    ));
    for url in [
        "",
        "https://proxy:3128",
        "http://user:password@proxy",
        "http://proxy/path",
        "http://proxy?secret=x",
        "http://proxy#x",
    ] {
        assert!(FetchRoute::from_config(Some(url), Some("1")).is_err());
    }
    assert!(
        FetchRoute::from_config(Some("http://squid.internal:3128"), None)
            .unwrap()
            .is_proxy()
    );
}

#[tokio::test]
async fn proxy_connect_has_tenant_and_no_signed_url_or_origin_header_leak() {
    let (mut lookup, _) = service();
    let (endpoint, server) = fake_gcs(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nx\na\n",
        false,
    );
    let (route, proxy) = test_proxy(
        Some(endpoint.addr),
        b"HTTP/1.1 200 Connection established\r\n\r\n",
        1,
        false,
    );
    lookup.endpoint = Some(endpoint);
    lookup.route = Some(route);
    assert_eq!(lookup.fetch(&params()).await.unwrap()[0]["x"], "a");
    let origin = server.join().unwrap().to_lowercase();
    assert!(!origin.contains("x-nano-tenant"));
    assert!(origin.contains("sig=test_credential"));
    let records = proxy.join().unwrap();
    assert!(records[0].starts_with(&format!("CONNECT storage.googleapis.com:443 HTTP/1.1\r\nHost: storage.googleapis.com:443\r\nX-Nano-Tenant: {}\r\n", lookup.tenant_id())));
    assert!(records[0].contains("X-Nano-Egress-Token: "));
    assert!(records[0].contains("X-Nano-Egress-Exp: "));
    assert!(!origin.contains("x-nano-egress"));
}

#[tokio::test]
async fn proxy_redirects_create_separate_validated_connects() {
    let (mut lookup, _) = service();
    let (endpoint, server) = fake_gcs_hops(b"HTTP/1.1 302 Found\r\nLocation: /bucket/next.csv\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", false, 4);
    let (route, proxy) = test_proxy(Some(endpoint.addr), b"HTTP/1.1 200 OK\r\n\r\n", 4, false);
    lookup.endpoint = Some(endpoint);
    lookup.route = Some(route);
    assert_eq!(
        lookup.fetch(&params()).await.unwrap_err(),
        "inputlookup exceeded 3 redirects"
    );
    server.join().unwrap();
    let records = proxy.join().unwrap();
    assert_eq!(records.len(), 4);
    assert!(records.iter().all(|r| r
        .starts_with("CONNECT storage.googleapis.com:443 HTTP/1.1\r\n")
        && !r.contains("bucket")
        && !r.contains("sig=")));
}

#[tokio::test]
async fn proxy_failures_are_static_and_never_fall_back_to_direct() {
    for (reply, delay, expected) in [
        (
            &b"HTTP/1.1 403 Forbidden\r\nX-Internal: SECRET\r\n\r\n"[..],
            false,
            "inputlookup proxy denied destination",
        ),
        (
            &b"HTTP/1.1 503 Internal\r\n\r\n"[..],
            false,
            proxy::UNREACHABLE,
        ),
        (&b"HTTP/1.1 200 OK\r\n\r\n"[..], true, proxy::UNREACHABLE),
    ] {
        let (mut lookup, authority) = service();
        let (route, server) = test_proxy(None, reply, 1, delay);
        lookup.route = Some(route);
        // Synthetic public DNS answer prevents the test depending on internet.
        lookup.endpoint = Some(TestEndpoint {
            addr: "127.0.0.1:1".parse().unwrap(),
            cert: reqwest::Certificate::from_der(include_bytes!("fixtures/test-cert.der")).unwrap(),
            answers: None,
        });
        assert_eq!(lookup.fetch(&params()).await.unwrap_err(), expected);
        server.join().unwrap();
        let records = authority.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].via_proxy);
        if expected == "inputlookup proxy denied destination" {
            assert_eq!(records[0].decision, "proxy_denied");
            assert_eq!(records[0].http_status, Some(403));
        } else {
            assert_eq!(records[0].decision, "error_proxy");
            if reply.starts_with(b"HTTP/1.1 503") {
                assert_eq!(records[0].http_status, Some(503));
            }
        }
        assert!(!serde_json::to_string(&*records).unwrap().contains("SECRET"));
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (mut lookup, _) = service();
    lookup.route = Some(FetchRoute::Proxy(
        Url::parse(&format!("http://{addr}")).unwrap(),
    ));
    let direct_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    direct_listener.set_nonblocking(true).unwrap();
    lookup.endpoint = Some(TestEndpoint {
        addr: direct_listener.local_addr().unwrap(),
        cert: reqwest::Certificate::from_der(include_bytes!("fixtures/test-cert.der")).unwrap(),
        answers: None,
    });
    assert_eq!(
        lookup.fetch(&params()).await.unwrap_err(),
        proxy::UNREACHABLE
    );
    assert_eq!(
        direct_listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn proxy_tunnel_preserves_certificate_and_hostname_verification() {
    for (trusted, host) in [
        (false, "storage.googleapis.com"),
        (true, "account.blob.core.windows.net"),
    ] {
        let (endpoint, origin) = fake_gcs(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false);
        let (route, proxy) = test_proxy(Some(endpoint.addr), b"HTTP/1.1 200 OK\r\n\r\n", 1, false);
        let FetchRoute::Proxy(url) = route else {
            unreachable!()
        };
        let target = Url::parse(&format!("https://{host}/bucket/x")).unwrap();
        let mut http_status = None;
        assert!(super::proxy::request(
            &url,
            &target,
            Uuid::new_v4(),
            &mut http_status,
            if trusted { Some(&endpoint) } else { None }
        )
        .await
        .is_err());
        assert_eq!(http_status, Some(200));
        assert!(origin.join().unwrap().is_empty());
        proxy.join().unwrap();
    }
}

#[tokio::test]
async fn proxy_keeps_body_limits_and_compression_refusal() {
    for (response, expected) in [
        (&b"HTTP/1.1 200 OK\r\nContent-Length: 52428801\r\nConnection: close\r\n\r\n"[..], "inputlookup response exceeds byte limit"),
        (&b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\nConnection: close\r\n\r\nxx"[..], "inputlookup compressed responses are not supported"),
        (&b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..], "inputlookup remote HTTP error"),
    ] {
        let (mut lookup, _) = service();
        let (endpoint, origin) = fake_gcs(response, false);
        let (route, proxy) = test_proxy(Some(endpoint.addr), b"HTTP/1.1 200 OK\r\n\r\n", 1, false);
        lookup.endpoint = Some(endpoint);
        lookup.route = Some(route);
        assert_eq!(lookup.fetch(&params()).await.unwrap_err(), expected);
        origin.join().unwrap();
        assert_eq!(proxy.join().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn proxy_redirect_private_dns_answer_is_refused_before_connect() {
    let (mut lookup, _) = service();
    let (mut endpoint, origin) = fake_gcs(b"HTTP/1.1 302 Found\r\nLocation: /bucket/next.csv\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", false);
    endpoint.answers = Some(Arc::new(Mutex::new(vec![
        vec!["93.184.216.34:443".parse().unwrap()],
        vec!["169.254.169.254:443".parse().unwrap()],
    ])));
    let (route, proxy) = test_proxy(Some(endpoint.addr), b"HTTP/1.1 200 OK\r\n\r\n", 1, false);
    lookup.endpoint = Some(endpoint);
    lookup.route = Some(route);
    assert_eq!(
        lookup.fetch(&params()).await.unwrap_err(),
        "inputlookup DNS resolved to a non-public address"
    );
    origin.join().unwrap();
    assert_eq!(proxy.join().unwrap().len(), 1);
}

#[tokio::test]
async fn unset_proxy_refuses_fetch_and_cached_read() {
    // Isolate environment removal from parallel tests and never mutate the
    // process environment while other threads may be reading it.
    if std::env::var_os("NANO_TEST_INPUTLOOKUP_CONFIG_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inputlookup::shared::tests::unset_proxy_refuses_fetch_and_cached_read",
                "--test-threads=1",
            ])
            .env("NANO_TEST_INPUTLOOKUP_CONFIG_CHILD", "1")
            .env_remove("NANOSIEM_INPUTLOOKUP_PROXY_URL")
            .env_remove("NANOSIEM_INPUTLOOKUP_ALLOW_DIRECT_DEV")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }
    let (mut lookup, authority) = service();
    lookup.route = None;
    for cache_ttl_secs in [0, 900] {
        let mut p = params();
        p.cache_ttl_secs = cache_ttl_secs;
        lookup
            .state
            .insert(p.url.template.clone(), "x\na\n".into(), 900);
        let error = lookup.fetch(&p).await.unwrap_err();
        assert!(error.contains("requires NANOSIEM_INPUTLOOKUP_PROXY_URL"));
    }
    assert_eq!(authority.records.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn proxy_streaming_body_obeys_the_total_deadline() {
    let (mut lookup, _) = service();
    let (endpoint, origin) = fake_gcs(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n",
        true,
    );
    let (route, proxy) = test_proxy(Some(endpoint.addr), b"HTTP/1.1 200 OK\r\n\r\n", 1, false);
    lookup.endpoint = Some(endpoint);
    lookup.route = Some(route);
    let started = Instant::now();
    assert_eq!(
        lookup.fetch(&params()).await.unwrap_err(),
        proxy::UNREACHABLE
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    origin.join().unwrap();
    proxy.join().unwrap();
}

#[tokio::test]
async fn tenant_allowlist_never_grants_another_tenant_cached_data() {
    let (a, _) = service();
    let (b, authority_b) = service();
    authority_b.settings.lock().unwrap().entries.clear();
    let mut p = params(); p.cache_ttl_secs = 900;
    a.state.insert(p.url.template.clone(), "name\nweb01\n".into(), 900);
    assert!(a.fetch(&p).await.is_ok());
    // Even if a cache body exists in B's tenant partition, its policy is checked.
    b.state.insert(p.url.template.clone(), "name\nweb01\n".into(), 900);
    assert_eq!(b.fetch(&p).await.unwrap_err(), super::super::storage_policy::ALLOWLIST_ERROR);
}

#[tokio::test]
async fn removing_redirect_target_revokes_cached_body() {
    let (lookup, _) = service();
    let mut p = params(); p.cache_ttl_secs = 900;
    lookup.state.insert_with_hosts(p.url.template.clone(), "name\nweb01\n".into(), 900,
        vec!["storage.googleapis.com".into(), "removed.example.com".into()]);
    assert_eq!(lookup.fetch(&p).await.unwrap_err(), super::super::storage_policy::ALLOWLIST_ERROR);
}


#[tokio::test]
async fn every_denied_attempt_has_one_redacted_tenant_event() {
    let (lookup, authority) = service();
    let id = Uuid::new_v4();
    let mut p = params();
    p.key_field = Some("user".into());
    assert!(with_fetch_search_id(id, lookup.fetch(&p)).await.is_err());
    p.key_field = None;
    authority.settings.lock().unwrap().entries.clear();
    assert!(with_fetch_search_id(id, lookup.fetch(&p)).await.is_err());
    let records = authority.records.lock().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].decision, "denied_policy");
    assert_eq!(records[1].decision, "denied_allowlist");
    for record in records.iter() {
        assert_eq!(record.tenant_id, lookup.tenant_id());
        assert_eq!(record.search_id, Some(id));
        assert_eq!(record.host, "storage.googleapis.com");
        assert_eq!(record.http_status, None);
        assert_eq!(record.bytes, 0);
        assert!(record.via_proxy);
        let value = serde_json::to_string(record).unwrap();
        for secret in ["TEST_CREDENTIAL", "sig=", "bucket", "feed.csv", "?"] {
            assert!(
                !value.contains(secret),
                "URL parts must never enter audit metadata"
            );
        }
    }
    assert_eq!(audit_host("intel.example.com/path?sig=secret"), "invalid");
    assert_eq!(audit_host("INTEL.EXAMPLE.COM"), "intel.example.com");
    for raw in ["localhost", "127.0.0.1", "[::1]", "::1"] {
        let host = audit_host(raw);
        assert_ne!(host, "invalid");
        assert_eq!(audit_host(&host), host, "host normalization is idempotent at the repository boundary");
    }
    assert!(!audit_search_id("https://example.com/?sig=secret")
        .to_string()
        .contains("secret"));
}

#[tokio::test]
async fn caller_cancellation_does_not_drop_the_completion_audit() {
    let (mut lookup, authority) = service();
    let (endpoint, server) = fake_gcs(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n",
        true,
    );
    lookup.endpoint = Some(endpoint);
    let task = tokio::spawn(async move { lookup.fetch(&params()).await });
    // Wait until outbound work has started, then cancel just the caller.
    for _ in 0..100 {
        if authority
            .settings_reads
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(
        authority
            .settings_reads
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
    );
    task.abort();
    for _ in 0..200 {
        if !authority.records.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let records = authority.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, "error_timeout");
    assert_eq!(records[0].http_status, Some(200));
    assert_eq!(records[0].bytes, 1);
    drop(records);
    server.join().unwrap();
}

#[tokio::test]
async fn remote_http_error_preserves_status_and_audits_once() {
    let (mut lookup, authority) = service();
    let (endpoint, server) = fake_gcs(
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        false,
    );
    lookup.endpoint = Some(endpoint);
    assert_eq!(
        lookup.fetch(&params()).await.unwrap_err(),
        "inputlookup remote HTTP error"
    );
    server.join().unwrap();
    let records = authority.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].http_status, Some(404));
    assert_eq!(records[0].decision, "error_http");
}

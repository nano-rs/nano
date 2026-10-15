//! Test harness: a TLS mock that answers for any vendor host, a scripted
//! resolver, a dialer that maps pinned public addresses onto the mock, and
//! engine builders.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use nano_connector::auth::Credentials;
use nano_connector::broker::{BrokerConfig, Dialer, Resolver};
use nano_connector::engine::{self, EngineConfig, MemorySink, MemoryStore, RunInput, RunOutput};
use nano_connector::sandbox::{Enforce, SandboxPolicy};
use nano_connector::spec::ConnectorSpec;
use nano_connector::vrl_exec::PoolConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};

/// The public address every test name resolves to (example.com's). Nothing
/// ever connects there: the test dialer maps it to the local mock.
pub const PUBLIC_IP: &str = "93.184.215.14";

#[derive(Debug, Clone)]
pub struct MockReq {
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub raw_query: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MockResp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MockResp {
    pub fn json(v: Value) -> Self {
        Self { status: 200, headers: vec![("content-type".into(), "application/json".into())], body: v.to_string().into_bytes() }
    }
    pub fn status(status: u16, v: Value) -> Self {
        Self { status, ..Self::json(v) }
    }
    pub fn text(s: &str) -> Self {
        Self { status: 200, headers: vec![("content-type".into(), "text/plain".into())], body: s.as_bytes().to_vec() }
    }
    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
    /// Answer after `d`, without blocking the mock's runtime (the handler
    /// is sync; the server sleeps asynchronously before replying).
    pub fn delay(self, d: Duration) -> Self {
        self.header(MOCK_DELAY_HEADER, &d.as_millis().to_string())
    }
}

/// Internal: carries [`MockResp::delay`] from the handler to the server.
const MOCK_DELAY_HEADER: &str = "x-mock-delay-ms";

pub type Handler = Arc<dyn Fn(&MockReq) -> MockResp + Send + Sync>;

pub struct Pki {
    pub ca_der: CertificateDer<'static>,
    pub ca_pem: String,
    pub leaf_der: CertificateDer<'static>,
    pub leaf_key: Vec<u8>,
    pub leaf_cert_pem: String,
    pub leaf_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub client_ca_der: CertificateDer<'static>,
}

/// A CA, a server leaf for `names` (+127.0.0.1), and a client cert from a
/// separate CA (for mTLS).
pub fn pki(names: &[&str]) -> Pki {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    leaf_params.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let cca_key = KeyPair::generate().unwrap();
    let mut cca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    cca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cca = cca_params.self_signed(&cca_key).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_params = CertificateParams::new(vec!["nano-connector-client".to_string()]).unwrap();
    let cissuer = rcgen::Issuer::from_params(&cca_params, &cca_key);
    let client = client_params.signed_by(&client_key, &cissuer).unwrap();
    Pki {
        ca_der: ca.der().clone(),
        ca_pem: ca.pem(),
        leaf_der: leaf.der().clone(),
        leaf_key: leaf_key.serialize_der(),
        leaf_cert_pem: leaf.pem(),
        leaf_key_pem: leaf_key.serialize_pem(),
        client_cert_pem: client.pem(),
        client_key_pem: client_key.serialize_pem(),
        client_ca_der: cca.der().clone(),
    }
}

/// Every vendor name the test leaf certificate answers for.
pub const MOCK_NAMES: &[&str] = &[
    "*.okta.com", "acme.okta.com", "admin.googleapis.com", "oauth2.googleapis.com", "www.virustotal.com",
    "api.abuseipdb.com", "api.shodan.io", "threatfox-api.abuse.ch", "check.torproject.org", "slack.com", "api.slack.com",
    "api.example.com", "logs.example.com", "auth.example.com", "evil.example.com", "internal.example.com",
    "mb-api.abuse.ch", "urlhaus-api.abuse.ch", "api.greynoise.io", "otx.alienvault.com",
    "acme.goskope.com", "sts.amazonaws.com", "logs.us-east-1.amazonaws.com", "mtls.example.com", "pull-broker.nano.rs",
    "graph.microsoft.com", "login.microsoftonline.com",
];

/// A mock served by another process (the Deno MockOkta) on `port`, using
/// `pki`'s leaf.
pub fn external_mock(port: u16, pki: Arc<Pki>) -> Mock {
    Mock { port, log: Arc::new(Mutex::new(vec![])), pki }
}

pub struct Mock {
    pub port: u16,
    pub log: Arc<Mutex<Vec<MockReq>>>,
    pub pki: Arc<Pki>,
}

impl Mock {
    pub fn requests(&self) -> Vec<MockReq> {
        self.log.lock().unwrap().clone()
    }
}

/// Start a TLS mock on 127.0.0.1. `require_client_cert` turns on mTLS.
pub async fn start_mock(handler: Handler, require_client_cert: bool) -> Mock {
    let pki = Arc::new(pki(MOCK_NAMES));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().unwrap();
    let builder = if require_client_cert {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pki.client_ca_der.clone()).unwrap();
        let v = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
        builder.with_client_cert_verifier(v)
    } else {
        builder.with_no_client_auth()
    };
    let mut cfg = builder
        .with_single_cert(vec![pki.leaf_der.clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.leaf_key.clone())))
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            let handler = handler.clone();
            let log = log2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let handler = handler.clone();
                    let log = log.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body.collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
                        let headers: HashMap<String, String> = parts
                            .headers
                            .iter()
                            .map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or("").to_string()))
                            .collect();
                        let host = headers
                            .get("x-mock-host")
                            .or(headers.get("host"))
                            .cloned()
                            .unwrap_or_default()
                            .split(':')
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        let raw_query = parts.uri.query().unwrap_or("").to_string();
                        let query = url::form_urlencoded::parse(raw_query.as_bytes()).into_owned().collect();
                        let mreq = MockReq { method: parts.method.to_string(), host, path: parts.uri.path().to_string(), query, raw_query, headers, body };
                        log.lock().unwrap().push(mreq.clone());
                        let r = handler(&mreq);
                        let mut b = hyper::Response::builder().status(r.status);
                        for (k, v) in r.headers {
                            if k == MOCK_DELAY_HEADER {
                                tokio::time::sleep(Duration::from_millis(v.parse().unwrap_or(0))).await;
                                continue;
                            }
                            b = b.header(k, v);
                        }
                        Ok::<_, Infallible>(b.body(Full::new(Bytes::from(r.body))).unwrap())
                    }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await;
            });
        }
    });
    Mock { port, log, pki }
}

/// One step of a raw mock's reply.
#[derive(Clone)]
pub enum Raw {
    /// Wait this long, then continue.
    Sleep(Duration),
    /// Write these bytes.
    Write(Bytes),
    /// Write these bytes this many times (an endless body, in practice).
    Repeat(Bytes, usize),
    /// Accept TCP but never answer the TLS handshake.
    StallHandshake,
}

/// A TLS server that reads one request head per connection and replays a
/// byte-level script: slowloris, endless chunked bodies, header bombs.
pub async fn start_raw_mock(script: Vec<Raw>) -> Mock {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let pki = Arc::new(pki(MOCK_NAMES));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![pki.leaf_der.clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.leaf_key.clone())))
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let (acceptor, script, log) = (acceptor.clone(), script.clone(), log2.clone());
            tokio::spawn(async move {
                if matches!(script.first(), Some(Raw::StallHandshake)) {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    drop(tcp);
                    return;
                }
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut head = Vec::new();
                let mut b = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&b[..n]),
                    }
                }
                log.lock().unwrap().push(MockReq {
                    method: String::new(),
                    host: String::new(),
                    path: String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string(),
                    query: BTreeMap::new(),
                    raw_query: String::new(),
                    headers: HashMap::new(),
                    body: vec![],
                });
                for step in script {
                    let ok = match step {
                        Raw::Sleep(d) => {
                            tokio::time::sleep(d).await;
                            true
                        }
                        Raw::Write(bytes) => tls.write_all(&bytes).await.is_ok() && tls.flush().await.is_ok(),
                        Raw::Repeat(bytes, n) => {
                            let mut ok = true;
                            for _ in 0..n {
                                if tls.write_all(&bytes).await.is_err() {
                                    ok = false;
                                    break;
                                }
                            }
                            ok
                        }
                        Raw::StallHandshake => true,
                    };
                    if !ok {
                        return;
                    }
                }
                let _ = tls.shutdown().await;
            });
        }
    });
    Mock { port, log, pki }
}

/// Resolver with per-host answer sequences (the last answer repeats).
pub struct ScriptedResolver {
    pub answers: Mutex<HashMap<String, Vec<Vec<IpAddr>>>>,
    pub calls: Mutex<Vec<String>>,
}

impl ScriptedResolver {
    pub fn public_for_all() -> Arc<Self> {
        Arc::new(Self { answers: Mutex::new(HashMap::new()), calls: Mutex::new(vec![]) })
    }
    pub fn set(&self, host: &str, seq: Vec<Vec<&str>>) {
        self.answers
            .lock()
            .unwrap()
            .insert(host.into(), seq.into_iter().map(|a| a.into_iter().map(|s| s.parse().unwrap()).collect()).collect());
    }
    pub fn calls_for(&self, host: &str) -> usize {
        self.calls.lock().unwrap().iter().filter(|h| *h == host).count()
    }
}

#[async_trait::async_trait]
impl Resolver for ScriptedResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        self.calls.lock().unwrap().push(host.into());
        let mut map = self.answers.lock().unwrap();
        match map.get_mut(host) {
            Some(seq) if seq.len() > 1 => Ok(seq.remove(0)),
            Some(seq) => Ok(seq[0].clone()),
            None => Ok(vec![PUBLIC_IP.parse().unwrap()]),
        }
    }
}

/// Maps every dialed address to the mock and records what was dialed.
pub struct MockDialer {
    pub port: u16,
    pub dialed: Mutex<Vec<SocketAddr>>,
}

#[async_trait::async_trait]
impl Dialer for MockDialer {
    async fn dial(&self, addr: SocketAddr) -> std::io::Result<TcpStream> {
        self.dialed.lock().unwrap().push(addr);
        TcpStream::connect(("127.0.0.1", self.port)).await
    }
}

pub fn worker_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nano-connector"))
}

/// The suites run every VRL worker with seccomp REQUIRED, so a host where
/// the filter silently fails to install fails the tests instead of quietly
/// testing a degraded sandbox. `NANO_CONNECTOR_TEST_SECCOMP=prefer` opts out
/// on hosts without seccomp (the sandbox tests then say what is missing).
pub fn require_seccomp() -> SandboxPolicy {
    let seccomp = match std::env::var("NANO_CONNECTOR_TEST_SECCOMP").ok().as_deref().and_then(Enforce::parse) {
        Some(e) => e,
        None => Enforce::Require,
    };
    SandboxPolicy { seccomp, ..Default::default() }
}

pub struct Harness {
    pub cfg: EngineConfig,
    pub resolver: Arc<ScriptedResolver>,
    pub dialer: Arc<MockDialer>,
    pub now: Arc<Mutex<DateTime<Utc>>>,
}

pub fn harness(mock: &Mock) -> Harness {
    let resolver = ScriptedResolver::public_for_all();
    let dialer = Arc::new(MockDialer { port: mock.port, dialed: Mutex::new(vec![]) });
    let now = Arc::new(Mutex::new(Utc::now()));
    let now2 = now.clone();
    let mut cfg = EngineConfig::with_sandbox(worker_exe(), require_seccomp(), PoolConfig::default());
    cfg.broker = BrokerConfig {
        resolver: resolver.clone(),
        dialer: dialer.clone(),
        extra_roots: vec![mock.pki.ca_der.clone()],
        connect_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    cfg.clock = Arc::new(move || *now2.lock().unwrap());
    Harness { cfg, resolver, dialer, now }
}

pub fn spec(yaml: &str) -> ConnectorSpec {
    ConnectorSpec::from_yaml(yaml).unwrap_or_else(|e| panic!("spec: {e}\n{yaml}"))
}

pub fn load_spec(name: &str) -> ConnectorSpec {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/specs").join(name);
    spec(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
}

pub fn creds(pairs: &[(&str, &str)]) -> Credentials {
    Credentials::new(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
}

pub fn config(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

pub struct Ran {
    pub out: Result<RunOutput, engine::EngineError>,
    pub sink: Arc<MemorySink>,
    pub store: Arc<MemoryStore>,
}

pub async fn run(h: &Harness, spec: &ConnectorSpec, input: RunInput) -> Ran {
    let sink = Arc::new(MemorySink::default());
    let store = Arc::new(MemoryStore::default());
    let out = engine::run(&h.cfg, spec, input, sink.clone(), store.clone()).await;
    Ran { out, sink, store }
}

/// Counter helper for mocks.
#[derive(Default)]
pub struct Counter(pub AtomicUsize);
impl Counter {
    pub fn inc(&self) -> usize {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
    pub fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// Normalize for Deno-vs-engine diffs: null == absent, numbers compared as
/// f64 (JS has one number type).
pub fn normalize(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), normalize(v))).collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(normalize).collect()),
        Value::Number(n) => serde_json::json!(n.as_f64().unwrap_or_default()),
        other => other.clone(),
    }
}

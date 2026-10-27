//! The egress broker: the only code that opens sockets.
//!
//! Per hop: request caps -> allowlist and deny check -> resolve the name
//! ourselves -> refuse unless every answer is publicly routable and not
//! denied -> pin the first answer for the rest of the run -> TCP to the
//! pinned IP -> TLS with SNI and certificate name = the host -> HTTP/1.1 with
//! `Host` = the host. There is no second resolution, so DNS rebinding cannot
//! move a connection. Redirects are returned to the caller, which re-runs
//! every check for the next hop.
//!
//! Connections are reused within one run (one broker per run): an idle
//! connection is keyed by (host, pinned address), so a reused connection is
//! always the one that was dialed to the pinned IP and verified for that
//! host name. Nothing is shared across runs, so nothing is shared across
//! tenants.
//!
//! Timeouts: connect, TLS handshake, response headers, the gap between two
//! body frames (slowloris), and the whole exchange.
//!
//! Egress proxy (NAN-4369): with a [`crate::egress_proxy::ProxyDialer`] the
//! TCP leg is a CONNECT tunnel through the platform egress proxy, which
//! authorizes the exact host for the run's [`EgressGrant`]. Every check above
//! still runs in process first (allowlist, deny list, resolve-and-refuse
//! non-public answers); the proxy re-resolves and enforces its own private
//! range deny. TLS (SNI and certificate name = the host) runs inside the
//! tunnel, so the proxy never sees request headers or vendor credentials.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;

use crate::policy::{HostPolicy, PolicyError};

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("egress denied: {0}")]
    Policy(#[from] PolicyError),
    #[error("DNS lookup for {0} failed: {1}")]
    Dns(String, String),
    #[error("DNS for {host} returned a non-public address {ip}")]
    DnsBlocked { host: String, ip: IpAddr },
    #[error("connect to {0} failed: {1}")]
    Connect(SocketAddr, String),
    /// The egress proxy did not open a tunnel; nothing reached the vendor.
    #[error("{0}; the request was not sent")]
    EgressProxy(crate::egress_proxy::ProxyRefusal),
    #[error("TLS with {0} failed: {1}")]
    Tls(String, String),
    #[error("HTTP exchange failed: {0}")]
    Http(String),
    /// The transport attests that it refused before invoking request IO.
    #[error("request not sent: {0}")]
    NotSent(&'static str),
    /// Retryable admission pressure, before invoking request IO.
    #[error("request deferred before send: {0}")]
    Deferred(&'static str),
    #[error("timed out: {0}")]
    Timeout(&'static str),
    #[error("response body exceeds {0} bytes")]
    ResponseTooLarge(u64),
    #[error("decompressed body exceeds {0} bytes")]
    DecompressedTooLarge(u64),
    #[error("unsupported content-encoding {0}")]
    Encoding(String),
    #[error("client certificate is invalid: {0}")]
    ClientCert(String),
    #[error("request refused: {0}")]
    RequestTooLarge(String),
}

/// Name resolution. Production uses the system resolver; tests inject answers.
#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

pub struct SystemResolver;

#[async_trait::async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(tokio::net::lookup_host((host, 443)).await?.map(|a| a.ip()).collect())
    }
}

/// What a run's egress is authorized for, carried to the dialer. One broker
/// serves one run, so the grant is fixed for the broker's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressGrant {
    pub tenant: uuid::Uuid,
    pub connection: uuid::Uuid,
    pub revision: i64,
    pub purpose: GrantPurpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantPurpose {
    /// A native SOAR vendor call.
    Soar,
    SoarSmtp,
    Connector,
    ThreatIntel,
}

impl GrantPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Soar => "soar",
            Self::SoarSmtp => "soar_smtp",
            Self::Connector => "connector",
            Self::ThreatIntel => "threat_intel",
        }
    }
}

/// One new connection: the policy-checked host, the pinned address it
/// resolved to, and the run's grant (absent outside granted runs).
#[derive(Debug, Clone, Copy)]
pub struct DialTarget<'a> {
    pub host: &'a str,
    pub addr: SocketAddr,
    pub grant: Option<&'a EgressGrant>,
}

/// TCP connect for one new connection. Production connects directly to the
/// pinned address or tunnels through the egress proxy; tests map pinned
/// public addresses onto a local mock.
#[async_trait::async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(&self, target: DialTarget<'_>) -> std::io::Result<TcpStream>;
}

pub struct DirectDialer;

#[async_trait::async_trait]
impl Dialer for DirectDialer {
    async fn dial(&self, target: DialTarget<'_>) -> std::io::Result<TcpStream> {
        TcpStream::connect(target.addr).await
    }
}

/// A client certificate for mTLS auth plugins.
pub struct ClientIdentity {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl ClientIdentity {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, BrokerError> {
        use rustls_pki_types::pem::PemObject;
        let cert_chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::ClientCert(e.to_string()))?;
        if cert_chain.is_empty() {
            return Err(BrokerError::ClientCert("no certificate in PEM".into()));
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|e| BrokerError::ClientCert(e.to_string()))?;
        Ok(Self { cert_chain, key })
    }
}

#[derive(Clone)]
pub struct BrokerConfig {
    pub resolver: Arc<dyn Resolver>,
    pub dialer: Arc<dyn Dialer>,
    /// The run's egress grant, passed to the dialer (NAN-4369). Set per run
    /// by the caller that owns the tenant connection; never shared.
    pub egress_grant: Option<EgressGrant>,
    /// Extra trust anchors (tests). Production trusts webpki roots only.
    pub extra_roots: Vec<CertificateDer<'static>>,
    /// TCP connect, and separately the TLS handshake.
    pub connect_timeout: Duration,
    /// The whole exchange: request sent, headers and full body read.
    pub response_timeout: Duration,
    /// From request sent to response headers received.
    pub header_timeout: Duration,
    /// Longest gap between two body frames (a slowloris body).
    pub body_idle_timeout: Duration,
    /// How long an idle connection may wait in the pool.
    pub idle_timeout: Duration,
    /// Idle connections kept per (host, address).
    pub max_idle_per_host: usize,
    /// Outbound request body cap.
    pub max_request_body_bytes: usize,
    /// Outbound header count and per-value caps.
    pub max_request_headers: usize,
    pub max_header_value_bytes: usize,
    /// Response header count cap (hyper refuses more).
    pub max_response_headers: usize,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            resolver: Arc::new(SystemResolver),
            dialer: Arc::new(DirectDialer),
            egress_grant: None,
            extra_roots: Vec::new(),
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(60),
            header_timeout: Duration::from_secs(30),
            body_idle_timeout: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(30),
            max_idle_per_host: 4,
            max_request_body_bytes: 4 * 1024 * 1024,
            max_request_headers: 64,
            max_header_value_bytes: 8 * 1024,
            max_response_headers: 128,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub method: http::Method,
    pub url: url::Url,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

#[derive(Debug, Clone)]
pub struct InboundResponse {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl InboundResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// Body caps for one exchange.
#[derive(Debug, Clone, Copy)]
pub struct BodyCaps {
    pub max_response_bytes: u64,
    pub max_decompressed_bytes: u64,
}

/// An idle keep-alive connection, bound to the address it was dialed to.
struct IdleConn {
    sender: SendRequest<Full<Bytes>>,
    driver: tokio::task::JoinHandle<()>,
    since: Instant,
}

impl Drop for IdleConn {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

type PoolKey = (String, SocketAddr);

/// One broker per run: pins, pooled connections and TLS identity are per run.
pub struct Broker {
    cfg: BrokerConfig,
    tls: Arc<ClientConfig>,
    pins: Mutex<HashMap<String, IpAddr>>,
    pool: Mutex<HashMap<PoolKey, Vec<IdleConn>>>,
    /// (host, dialed address) per new connection, for audit and tests.
    pub dial_log: Mutex<Vec<(String, SocketAddr)>>,
    /// Exchanges served by a reused connection.
    pub reused: std::sync::atomic::AtomicU32,
}

impl Broker {
    pub fn new(cfg: BrokerConfig, identity: Option<ClientIdentity>) -> Result<Self, BrokerError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for r in &cfg.extra_roots {
            roots
                .add(r.clone())
                .map_err(|e| BrokerError::Tls("extra root".into(), e.to_string()))?;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| BrokerError::Tls("config".into(), e.to_string()))?
            .with_root_certificates(roots);
        let mut tls = match identity {
            Some(id) => builder
                .with_client_auth_cert(id.cert_chain, id.key)
                .map_err(|e| BrokerError::ClientCert(e.to_string()))?,
            None => builder.with_no_client_auth(),
        };
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            cfg,
            tls: Arc::new(tls),
            pins: Mutex::new(HashMap::new()),
            pool: Mutex::new(HashMap::new()),
            dial_log: Mutex::new(Vec::new()),
            reused: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// Resolve once per run and pin. Every answer must be public and not
    /// denied: a mixed answer is how rebinding attacks hide a private address.
    async fn pinned_ip(&self, host: &str, hosts: &HostPolicy) -> Result<IpAddr, BrokerError> {
        if let Some(ip) = self.pins.lock().expect("pins").get(host) {
            return Ok(*ip);
        }
        let answers = self
            .cfg
            .resolver
            .resolve(host)
            .await
            .map_err(|e| BrokerError::Dns(host.into(), e.to_string()))?;
        if answers.is_empty() {
            return Err(BrokerError::Dns(host.into(), "no addresses".into()));
        }
        for ip in &answers {
            if hosts.check_ip(*ip).is_err() {
                return Err(BrokerError::DnsBlocked { host: host.into(), ip: *ip });
            }
        }
        let ip = answers[0];
        let mut pins = self.pins.lock().expect("pins");
        Ok(*pins.entry(host.to_string()).or_insert(ip))
    }

    fn check_request(&self, req: &OutboundRequest) -> Result<(), BrokerError> {
        let c = &self.cfg;
        if req.body.len() > c.max_request_body_bytes {
            return Err(BrokerError::RequestTooLarge(format!("body exceeds {} bytes", c.max_request_body_bytes)));
        }
        if req.headers.len() > c.max_request_headers {
            return Err(BrokerError::RequestTooLarge(format!("more than {} headers", c.max_request_headers)));
        }
        for (k, v) in &req.headers {
            if v.len() > c.max_header_value_bytes {
                return Err(BrokerError::RequestTooLarge(format!("header {k} exceeds {} bytes", c.max_header_value_bytes)));
            }
            // CR/LF/NUL in a name or value would let a header split the request.
            if http::HeaderName::try_from(k.as_str()).is_err() || http::HeaderValue::try_from(v.as_str()).is_err() {
                return Err(BrokerError::RequestTooLarge(format!("header {k} is not a valid HTTP header")));
            }
        }
        Ok(())
    }

    fn take_idle(&self, key: &PoolKey) -> Option<IdleConn> {
        let mut pool = self.pool.lock().expect("pool");
        let list = pool.get_mut(key)?;
        while let Some(c) = list.pop() {
            if c.since.elapsed() < self.cfg.idle_timeout && c.sender.is_ready() && !c.sender.is_closed() {
                return Some(c);
            }
        }
        None
    }

    fn put_idle(&self, key: PoolKey, conn: IdleConn) {
        let mut pool = self.pool.lock().expect("pool");
        let list = pool.entry(key).or_default();
        if list.len() < self.cfg.max_idle_per_host {
            list.push(conn);
        }
    }

    async fn dial(&self, host: &str, addr: SocketAddr) -> Result<IdleConn, BrokerError> {
        self.dial_log.lock().expect("dial log").push((host.to_string(), addr));
        let target = DialTarget { host, addr, grant: self.cfg.egress_grant.as_ref() };
        let tcp = tokio::time::timeout(self.cfg.connect_timeout, self.cfg.dialer.dial(target))
            .await
            .map_err(|_| BrokerError::Timeout("connect"))?
            .map_err(|e| match crate::egress_proxy::ProxyRefusal::from_io(&e) {
                Some(refusal) => BrokerError::EgressProxy(refusal),
                None => BrokerError::Connect(addr, e.to_string()),
            })?;
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| BrokerError::Tls(host.to_string(), e.to_string()))?;
        let tls = tokio::time::timeout(
            self.cfg.connect_timeout,
            tokio_rustls::TlsConnector::from(self.tls.clone()).connect(server_name, tcp),
        )
        .await
        .map_err(|_| BrokerError::Timeout("tls handshake"))?
        .map_err(|e| BrokerError::Tls(host.to_string(), e.to_string()))?;
        let mut builder = hyper::client::conn::http1::Builder::new();
        builder.max_headers(self.cfg.max_response_headers).max_buf_size(256 * 1024);
        let (sender, conn) = tokio::time::timeout(self.cfg.connect_timeout, builder.handshake(TokioIo::new(tls)))
            .await
            .map_err(|_| BrokerError::Timeout("http handshake"))?
            .map_err(|e| BrokerError::Http(e.to_string()))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(IdleConn { sender, driver, since: Instant::now() })
    }

    fn build_request(&self, req: &OutboundRequest, host: &str) -> Result<http::Request<Full<Bytes>>, BrokerError> {
        let mut builder = http::Request::builder()
            .method(req.method.clone())
            .uri(match req.url.query() {
                Some(q) => format!("{}?{}", req.url.path(), q),
                None => req.url.path().to_string(),
            })
            .header(http::header::HOST, host)
            .header(http::header::ACCEPT_ENCODING, "gzip, deflate")
            .header(http::header::USER_AGENT, "nano-connector/0.1");
        for (k, v) in &req.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        if !req.body.is_empty() {
            builder = builder.header(http::header::CONTENT_LENGTH, req.body.len());
        }
        builder
            .body(Full::new(req.body.clone()))
            .map_err(|e| BrokerError::Http(e.to_string()))
    }

    /// One HTTP exchange, no redirect following.
    pub async fn send_once(
        &self,
        req: &OutboundRequest,
        hosts: &HostPolicy,
        caps: BodyCaps,
    ) -> Result<InboundResponse, BrokerError> {
        self.check_request(req)?;
        let (host, port) = hosts.check(&req.url)?;
        let ip = self.pinned_ip(&host, hosts).await?;
        // Defense in depth: the pinned address passed the same check above.
        hosts.check_ip(ip)?;
        let addr = SocketAddr::new(ip, port);
        let key: PoolKey = (host.clone(), addr);

        let deadline = Instant::now() + self.cfg.response_timeout;
        // A pooled connection can be closed by the server between our
        // readiness check and the write; that is retried once on a fresh
        // connection, which is safe because no byte of the request was sent.
        let (mut conn, resp) = loop {
            let (mut conn, pooled) = match self.take_idle(&key) {
                Some(c) => (c, true),
                None => (self.dial(&host, addr).await?, false),
            };
            let hreq = self.build_request(req, &host)?;
            let left = deadline.saturating_duration_since(Instant::now());
            let send = conn.sender.try_send_request(hreq);
            match tokio::time::timeout(self.cfg.header_timeout.min(left), send).await {
                Err(_) => return Err(BrokerError::Timeout("response headers")),
                Ok(Ok(r)) => {
                    if pooled {
                        self.reused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    break (conn, r);
                }
                Ok(Err(mut e)) => {
                    if pooled && e.take_message().is_some() {
                        continue;
                    }
                    return Err(BrokerError::Http(e.into_error().to_string()));
                }
            }
        };

        let status = resp.status().as_u16();
        let mut headers = resp.headers().clone();
        if let Some(len) = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            if len > caps.max_response_bytes {
                return Err(BrokerError::ResponseTooLarge(caps.max_response_bytes));
            }
        }
        let keep_alive = !headers
            .get(http::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("close"));
        let mut body = resp.into_body();
        let mut buf = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(BrokerError::Timeout("response"));
            }
            let frame = match tokio::time::timeout(self.cfg.body_idle_timeout.min(left), body.frame()).await {
                Err(_) if left <= self.cfg.body_idle_timeout => return Err(BrokerError::Timeout("response")),
                Err(_) => return Err(BrokerError::Timeout("response body stalled")),
                Ok(None) => break,
                Ok(Some(f)) => f.map_err(|e| BrokerError::Http(e.to_string()))?,
            };
            if let Some(data) = frame.data_ref() {
                if (buf.len() + data.len()) as u64 > caps.max_response_bytes {
                    return Err(BrokerError::ResponseTooLarge(caps.max_response_bytes));
                }
                buf.extend_from_slice(data);
            }
        }
        // The body was read to its end: the connection may serve the next
        // request of this run.
        if keep_alive {
            conn.since = Instant::now();
            self.put_idle(key, conn);
        }

        let body = match headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_ascii_lowercase())
        {
            None => Bytes::from(buf),
            Some(enc) if enc.is_empty() || enc == "identity" => Bytes::from(buf),
            Some(enc) if enc == "gzip" || enc == "x-gzip" => {
                decompress(flate2::read::MultiGzDecoder::new(&buf[..]), caps.max_decompressed_bytes)?
            }
            Some(enc) if enc == "deflate" => {
                decompress(flate2::read::ZlibDecoder::new(&buf[..]), caps.max_decompressed_bytes)?
            }
            // Stacked encodings ("gzip, gzip") and anything else are refused:
            // one bounded decode step only.
            Some(other) => return Err(BrokerError::Encoding(other)),
        };
        headers.remove(http::header::CONTENT_ENCODING);
        headers.remove(http::header::CONTENT_LENGTH);
        Ok(InboundResponse { status, headers, body })
    }
}

/// Inflate with a hard output cap; never trusts the compressed size.
fn decompress(mut r: impl Read, cap: u64) -> Result<Bytes, BrokerError> {
    let mut out = Vec::new();
    let n = (&mut r)
        .take(cap + 1)
        .read_to_end(&mut out)
        .map_err(|e| BrokerError::Http(format!("decompress: {e}")))?;
    if n as u64 > cap {
        return Err(BrokerError::DecompressedTooLarge(cap));
    }
    Ok(Bytes::from(out))
}

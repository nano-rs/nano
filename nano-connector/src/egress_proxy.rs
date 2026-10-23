//! CONNECT tunnels through the platform egress proxy (NAN-4369).
//!
//! The proxy (Squid in the region's `nano-egress-proxy` namespace) authorizes
//! every tunnel with an external check: the tenant, connection, revision and
//! exact host must be one the tenant's installed pack allows for that
//! connection, and the short-lived HMAC token must verify. The `X-Nano-*`
//! headers ride on the CONNECT request only; TLS to the vendor (and so every
//! vendor header and credential) is end to end inside the tunnel, and Squid
//! strips the headers before anything leaves.
//!
//! Fail closed: a proxy that cannot be reached, denies, or answers anything
//! but `200` ends the connection attempt with a [`ProxyRefusal`]. There is no
//! fallback to a direct connection.

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::broker::{DialTarget, Dialer, GrantPurpose};
use nanosiem_core::inputlookup::egress_auth::{self, EgressPurpose};

/// Token lifetime. The proxy accepts `now < exp <= now + 60`; ten seconds of
/// margin absorb clock skew between the caller and the proxy.
const TOKEN_TTL_SECS: i64 = 50;
/// Longest CONNECT response header block read from the proxy.
const MAX_PROXY_HEADER_BYTES: usize = 8192;

/// Why a tunnel was not opened. Nothing reached the vendor in any case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProxyRefusal {
    #[error("egress proxy is unreachable")]
    Unreachable,
    #[error("egress proxy denied the destination")]
    Denied,
    #[error("egress proxy refused the tunnel")]
    Refused,
    #[error("no egress grant for this run")]
    NoGrant,
    #[error("egress proxy is not configured")]
    Unconfigured,
}

impl ProxyRefusal {
    fn into_io(self) -> std::io::Error {
        std::io::Error::other(self)
    }

    /// The refusal a dialer returned, if the error is one.
    pub fn from_io(error: &std::io::Error) -> Option<Self> {
        error.get_ref().and_then(|e| e.downcast_ref::<Self>()).copied()
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProxyConfigError {
    #[error("egress proxy URL must be http://host:port with no path, userinfo or query")]
    Url,
    #[error("egress proxy HMAC key must be at least 32 bytes")]
    Key,
}

/// Dials every new connection as a CONNECT tunnel through the egress proxy.
pub struct ProxyDialer {
    host: String,
    port: u16,
    key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ProxyDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyDialer").field("host", &self.host).field("port", &self.port).finish_non_exhaustive()
    }
}

impl ProxyDialer {
    /// `proxy_url` is the rendered in-cluster proxy URL (`http://host:3128`).
    pub fn new(proxy_url: &str, key: &[u8]) -> Result<Self, ProxyConfigError> {
        let url = url::Url::parse(proxy_url).map_err(|_| ProxyConfigError::Url)?;
        if url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || proxy_url.contains(['@', '\\'])
            || proxy_url.chars().any(char::is_control)
        {
            return Err(ProxyConfigError::Url);
        }
        let host = match url.host() {
            Some(url::Host::Domain(d)) => d.to_string(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
            None => return Err(ProxyConfigError::Url),
        };
        let port = url.port_or_known_default().ok_or(ProxyConfigError::Url)?;
        if key.len() < 32 {
            return Err(ProxyConfigError::Key);
        }
        Ok(Self { host, port, key: Zeroizing::new(key.to_vec()) })
    }

    fn connect_request(&self, target: &DialTarget<'_>, now: i64) -> Result<String, ProxyRefusal> {
        let grant = target.grant.ok_or(ProxyRefusal::NoGrant)?;
        let purpose = match grant.purpose {
            GrantPurpose::Soar => EgressPurpose::Soar { connection: grant.connection, revision: grant.revision },
        };
        // The host passed the broker's allowlist check (a lowercase DNS
        // name); it is re-validated here because it is written into a
        // request line.
        let host = target.host;
        if host.is_empty()
            || host.len() > 253
            || !host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        {
            return Err(ProxyRefusal::Refused);
        }
        let port = target.addr.port();
        let exp = now + TOKEN_TTL_SECS;
        let token = egress_auth::sign_for(&self.key, purpose, grant.tenant, host, exp).ok_or(ProxyRefusal::NoGrant)?;
        Ok(format!(
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nX-Nano-Tenant: {tenant}\r\nX-Nano-Egress-Purpose: {purpose}\r\nX-Nano-Egress-Conn: {conn}\r\nX-Nano-Egress-Rev: {rev}\r\nX-Nano-Egress-Token: {token}\r\nX-Nano-Egress-Exp: {exp}\r\n\r\n",
            tenant = grant.tenant,
            purpose = grant.purpose.as_str(),
            conn = grant.connection,
            rev = grant.revision,
        ))
    }
}

/// Read exactly through the header terminator: never consume tunnel bytes,
/// trust a length, or allocate from proxy input.
async fn read_connect_status(stream: &mut TcpStream) -> Result<u16, ProxyRefusal> {
    let mut head = Vec::with_capacity(128);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_PROXY_HEADER_BYTES {
            return Err(ProxyRefusal::Refused);
        }
        head.push(stream.read_u8().await.map_err(|_| ProxyRefusal::Unreachable)?);
    }
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = std::str::from_utf8(line).map_err(|_| ProxyRefusal::Refused)?.trim_end_matches('\r');
    let mut parts = line.splitn(3, ' ');
    match (parts.next(), parts.next()) {
        (Some("HTTP/1.1" | "HTTP/1.0"), Some(code)) if code.len() == 3 => code.parse().map_err(|_| ProxyRefusal::Refused),
        _ => Err(ProxyRefusal::Refused),
    }
}

#[async_trait::async_trait]
impl Dialer for ProxyDialer {
    async fn dial(&self, target: DialTarget<'_>) -> std::io::Result<TcpStream> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| ProxyRefusal::Refused.into_io())?.as_secs() as i64;
        let request = self.connect_request(&target, now).map_err(ProxyRefusal::into_io)?;
        let mut stream = TcpStream::connect((self.host.trim_matches(['[', ']']), self.port))
            .await
            .map_err(|_| ProxyRefusal::Unreachable.into_io())?;
        stream.write_all(request.as_bytes()).await.map_err(|_| ProxyRefusal::Unreachable.into_io())?;
        match read_connect_status(&mut stream).await.map_err(ProxyRefusal::into_io)? {
            200 => Ok(stream),
            403 => Err(ProxyRefusal::Denied.into_io()),
            _ => Err(ProxyRefusal::Refused.into_io()),
        }
    }
}

/// The dialer for a release build with no rendered proxy: every connection
/// is refused. Never a direct connection.
pub struct RefusingDialer;

#[async_trait::async_trait]
impl Dialer for RefusingDialer {
    async fn dial(&self, _target: DialTarget<'_>) -> std::io::Result<TcpStream> {
        Err(ProxyRefusal::Unconfigured.into_io())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::EgressGrant;

    #[test]
    fn proxy_url_must_be_a_plain_http_origin() {
        let key = [7u8; 32];
        assert!(ProxyDialer::new("http://search-storage-proxy.nano-egress-proxy.svc.cluster.local:3128", &key).is_ok());
        for bad in ["https://proxy:3128", "http://u:p@proxy:3128", "http://proxy:3128/x", "http://proxy:3128?q", "proxy:3128", ""] {
            assert_eq!(ProxyDialer::new(bad, &key).unwrap_err(), ProxyConfigError::Url, "{bad}");
        }
        assert_eq!(ProxyDialer::new("http://proxy:3128", &[7u8; 31]).unwrap_err(), ProxyConfigError::Key);
    }

    #[test]
    fn connect_request_carries_a_verifiable_grant_and_no_vendor_bytes() {
        let key = [7u8; 32];
        let dialer = ProxyDialer::new("http://proxy:3128", &key).unwrap();
        let grant = EgressGrant { tenant: uuid::Uuid::new_v4(), connection: uuid::Uuid::new_v4(), revision: 2, purpose: GrantPurpose::Soar };
        let target = DialTarget { host: "acme.okta.com", addr: "93.184.215.14:443".parse().unwrap(), grant: Some(&grant) };
        let request = dialer.connect_request(&target, 1000).unwrap();
        assert!(request.starts_with("CONNECT acme.okta.com:443 HTTP/1.1\r\n"));
        let token = request.lines().find_map(|l| l.strip_prefix("X-Nano-Egress-Token: ")).unwrap();
        let purpose = EgressPurpose::Soar { connection: grant.connection, revision: 2 };
        assert!(egress_auth::verify_for(&key, purpose, grant.tenant, "acme.okta.com", token, 1050, 1000));
        assert!(request.contains("X-Nano-Egress-Purpose: soar\r\n"));
        assert!(!request.contains("93.184.215.14"));
        // No grant: refused before any socket is opened.
        let anonymous = DialTarget { grant: None, ..target };
        assert_eq!(dialer.connect_request(&anonymous, 1000).unwrap_err(), ProxyRefusal::NoGrant);
        // A host that could split the request line is refused.
        let split = DialTarget { host: "a.com\r\nX: y", ..target };
        assert_eq!(dialer.connect_request(&split, 1000).unwrap_err(), ProxyRefusal::Refused);
    }
}

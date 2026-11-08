// SPDX-License-Identifier: AGPL-3.0-or-later

//! How the broker reaches the network (NAN-4914).
//!
//! The default is [`crate::broker::DirectDialer`]: a TCP connect to the
//! address the broker already resolved, checked (spec allowlist, deny list,
//! the connector's reserved ranges and the shared SSRF validator) and pinned.
//!
//! An operator may route all outbound vendor traffic through a forward HTTP
//! proxy (a corporate egress proxy) with [`CONNECTOR_PROXY_ENV`] (pull feeds
//! and lookups) and choose what CONNECT names with [`CONNECTOR_PROXY_MODE_ENV`]. [`dialer_from_env`] takes the variable name, so an
//! embedding host (SOAR, in nanosiem-enterprise) reuses the implementation
//! under its own name.
//!
//! With a proxy in the default mode every in-process check still runs first. The tunnel is
//! opened with `CONNECT <pinned address>:<port>`, never the host name, so the
//! proxy cannot re-resolve the name to a different address: the broker's
//! single-resolution guarantee (no DNS rebinding) holds through the proxy.
//! TLS (SNI and certificate name = the vendor host) runs end to end inside
//! the tunnel; the proxy never sees request headers or vendor credentials.
//!
//! # Proxy mode ([`CONNECTOR_PROXY_MODE_ENV`])
//!
//! * `pinned_ip` (default, also when unset or empty): the behaviour above.
//!   The broker resolves, checks and pins; the proxy sees only
//!   `CONNECT <pinned ip>:<port>`. DNS-rebinding safe, but a proxy that
//!   filters by host name (Zscaler, Squid `dstdomain`) cannot match it.
//! * `hostname` (opt-in): `CONNECT <host>:<port>`, and **the proxy enforces
//!   egress**. The proxy resolves the name, so the broker does not resolve
//!   or pin it and does not check the resolved address: the connector's
//!   reserved-range and SSRF address checks do not apply to that hop, and
//!   what the name resolves to is the proxy's decision. The connector still
//!   applies its spec allowlist and the operator deny list to the host name,
//!   refuses literal IP destinations (private or public), and keeps TLS end
//!   to end (certificate verified for the host name).
//!
//! Any other mode value is a configuration error (fail closed: the caller
//! refuses to start or refuses every connection). The mode has no effect
//! without a proxy URL; direct connections always resolve, check and pin.
//!
//! Fail closed: a configured proxy that cannot be reached, denies, or
//! answers anything but `2xx` ends the attempt with a [`ProxyRefusal`].
//! There is no fallback to a direct connection, and an invalid proxy setting
//! is an error for the caller to refuse to start on, never "direct".
//!
//! The hosted platform's HMAC-granted per-tenant egress proxy (NAN-4369)
//! is not part of the ClickHouse product and is not implemented here.

use std::sync::Arc;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::broker::{BrokerConfig, DialTarget, Dialer, DirectDialer};

/// Pull feeds and threat-intel lookups.
pub const CONNECTOR_PROXY_ENV: &str = "CONNECTOR_EGRESS_PROXY_URL";
/// CONNECT target for [`CONNECTOR_PROXY_ENV`]: `pinned_ip` (default) or
/// `hostname` (see the module docs).
pub const CONNECTOR_PROXY_MODE_ENV: &str = "CONNECTOR_EGRESS_PROXY_MODE";

/// What a CONNECT request names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProxyMode {
    /// `CONNECT <pinned ip>:<port>`: the broker resolves, checks and pins.
    #[default]
    PinnedIp,
    /// `CONNECT <host>:<port>`: the proxy resolves and enforces egress.
    Hostname,
}

impl ProxyMode {
    /// Parse a mode setting. Unset or empty is [`ProxyMode::PinnedIp`]; any
    /// value other than `pinned_ip` / `hostname` is an error.
    pub fn parse(value: Option<&str>) -> Result<Self, ProxyConfigError> {
        match value.map(str::trim) {
            None | Some("") | Some("pinned_ip") => Ok(Self::PinnedIp),
            Some("hostname") => Ok(Self::Hostname),
            Some(_) => Err(ProxyConfigError::Mode),
        }
    }
}

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
    /// The operator's proxy setting is invalid: every connection is refused
    /// rather than sent direct.
    #[error("egress proxy setting is invalid; the request was refused")]
    Misconfigured,
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
    #[error("egress proxy URL must be http://[user:password@]host:port with no path, query or fragment")]
    Url,
    #[error("egress proxy mode must be `pinned_ip` or `hostname`")]
    Mode,
}

/// Dials every new connection as a CONNECT tunnel through a forward proxy.
pub struct ProxyDialer {
    host: String,
    port: u16,
    mode: ProxyMode,
    /// `Proxy-Authorization` value, from the URL's userinfo.
    authorization: Option<String>,
}

impl std::fmt::Debug for ProxyDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyDialer")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("mode", &self.mode)
            .field("authenticated", &self.authorization.is_some())
            .finish()
    }
}

impl ProxyDialer {
    /// `proxy_url` is `http://[user:password@]host:port`. Credentials, when
    /// present, are sent as `Proxy-Authorization: Basic` on CONNECT only.
    pub fn new(proxy_url: &str) -> Result<Self, ProxyConfigError> {
        if proxy_url.chars().any(char::is_control) || proxy_url.contains('\\') {
            return Err(ProxyConfigError::Url);
        }
        let url = url::Url::parse(proxy_url).map_err(|_| ProxyConfigError::Url)?;
        if url.scheme() != "http" || url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(ProxyConfigError::Url);
        }
        let host = match url.host() {
            Some(url::Host::Domain(d)) if !d.is_empty() => d.to_string(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            _ => return Err(ProxyConfigError::Url),
        };
        let port = url.port_or_known_default().ok_or(ProxyConfigError::Url)?;
        let decode = |s: &str| percent_encoding::percent_decode_str(s).decode_utf8().map(|c| c.into_owned()).map_err(|_| ProxyConfigError::Url);
        let authorization = match (url.username(), url.password()) {
            ("", None) => None,
            (user, password) => {
                let pair = format!("{}:{}", decode(user)?, decode(password.unwrap_or(""))?);
                if pair.chars().any(char::is_control) {
                    return Err(ProxyConfigError::Url);
                }
                Some(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair)))
            }
        };
        Ok(Self { host, port, mode: ProxyMode::PinnedIp, authorization })
    }

    /// [`ProxyDialer::new`] with an explicit [`ProxyMode`].
    pub fn with_mode(proxy_url: &str, mode: ProxyMode) -> Result<Self, ProxyConfigError> {
        Ok(Self { mode, ..Self::new(proxy_url)? })
    }

    pub fn mode(&self) -> ProxyMode {
        self.mode
    }

    /// The CONNECT request: the pinned address in `pinned_ip` mode, the
    /// policy-checked host name in `hostname` mode. `None` refuses the dial
    /// (a hostname-mode target that is not a plain DNS name).
    fn connect_request(&self, target: &DialTarget<'_>) -> Option<String> {
        let authority = match self.mode {
            // `SocketAddr` renders IPv6 as `[addr]:port`: a valid authority form.
            ProxyMode::PinnedIp => target.addr.to_string(),
            ProxyMode::Hostname => {
                // The broker only passes allowlisted names; re-check so a
                // literal IP or a header-splitting byte can never be sent.
                if target.host.parse::<std::net::IpAddr>().is_ok()
                    || !crate::policy::is_plain_hostname(target.host)
                {
                    return None;
                }
                format!("{}:{}", target.host, target.addr.port())
            }
        };
        let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(auth) = &self.authorization {
            req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        }
        req.push_str("\r\n");
        Some(req)
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
        let request = self.connect_request(&target).ok_or_else(|| ProxyRefusal::Refused.into_io())?;
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|_| ProxyRefusal::Unreachable.into_io())?;
        stream.write_all(request.as_bytes()).await.map_err(|_| ProxyRefusal::Unreachable.into_io())?;
        match read_connect_status(&mut stream).await.map_err(ProxyRefusal::into_io)? {
            200..=299 => Ok(stream),
            403 | 407 => Err(ProxyRefusal::Denied.into_io()),
            _ => Err(ProxyRefusal::Refused.into_io()),
        }
    }

    fn resolves_remotely(&self, _host: &str) -> bool {
        self.mode == ProxyMode::Hostname
    }
}

/// The dialer for `env_var`: a [`ProxyDialer`] when the variable is set and
/// non-empty, otherwise [`DirectDialer`]. An invalid value is an error (the
/// caller refuses to start); it never silently falls back to direct. Always
/// [`ProxyMode::PinnedIp`]; see [`dialer_from_env_with_mode`].
pub fn dialer_from_env(env_var: &str) -> Result<Arc<dyn Dialer>, ProxyConfigError> {
    dialer_from_value(std::env::var(env_var).ok().as_deref())
}

/// [`dialer_from_env`] with the CONNECT mode read from `mode_env_var`
/// ([`ProxyMode::parse`]). An invalid mode is an error even without a proxy.
pub fn dialer_from_env_with_mode(env_var: &str, mode_env_var: &str) -> Result<Arc<dyn Dialer>, ProxyConfigError> {
    dialer_from_values(
        std::env::var(env_var).ok().as_deref(),
        std::env::var(mode_env_var).ok().as_deref(),
    )
}

/// [`dialer_from_env`] on an already-read value (tests, config files).
pub fn dialer_from_value(value: Option<&str>) -> Result<Arc<dyn Dialer>, ProxyConfigError> {
    dialer_from_values(value, None)
}

/// [`dialer_from_env_with_mode`] on already-read values.
pub fn dialer_from_values(url: Option<&str>, mode: Option<&str>) -> Result<Arc<dyn Dialer>, ProxyConfigError> {
    let mode = ProxyMode::parse(mode)?;
    match url.map(str::trim) {
        None | Some("") => Ok(Arc::new(DirectDialer)),
        Some(url) => Ok(Arc::new(ProxyDialer::with_mode(url, mode)?)),
    }
}

/// Refuses every connection: what an invalid proxy setting becomes when the
/// caller cannot refuse to start ([`crate::engine::EngineConfig::new`]).
/// Never a direct connection.
pub struct RefusingDialer;

#[async_trait::async_trait]
impl Dialer for RefusingDialer {
    async fn dial(&self, _target: DialTarget<'_>) -> std::io::Result<TcpStream> {
        Err(ProxyRefusal::Misconfigured.into_io())
    }
}

/// Set `config.dialer` from `env_var` (see [`dialer_from_env`]).
pub fn configure_from_env(config: &mut BrokerConfig, env_var: &str) -> Result<(), ProxyConfigError> {
    config.dialer = dialer_from_env(env_var)?;
    Ok(())
}

/// Set `config.dialer` from `env_var` and `mode_env_var` (see
/// [`dialer_from_env_with_mode`]).
pub fn configure_from_env_with_mode(
    config: &mut BrokerConfig,
    env_var: &str,
    mode_env_var: &str,
) -> Result<(), ProxyConfigError> {
    config.dialer = dialer_from_env_with_mode(env_var, mode_env_var)?;
    Ok(())
}

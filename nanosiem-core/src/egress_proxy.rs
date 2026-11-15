// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator egress proxy settings shared by every outbound path (NAN-5441).
//!
//! Three things live here:
//!
//! * The forward-proxy CONNECT handshake ([`ProxyEndpoint`]) and its settings
//!   types ([`ProxyMode`], [`ProxyConfigError`], [`ProxyRefusal`]). The
//!   connector broker's `ProxyDialer` (pull feeds, SOAR, the enrichment
//!   sandbox) is built on them, and so is the destination proxy below.
//! * **Proxy required** ([`EGRESS_PROXY_REQUIRED_ENV`]). Off by default. When
//!   on, no outbound path may dial a public address directly: a path with no
//!   proxy configured refuses with a named error ([`ProxyRefusal::Required`],
//!   `SsrfError::EgressProxyRequired`) instead of falling back to direct.
//!   Internal addresses ([`is_public_destination`] false) stay direct: they
//!   pass the SSRF checks only through an explicit operator opt-in (private
//!   AI endpoints, the webhook CIDR allowlist, SOAR self-managed hosts), and
//!   an internet egress proxy cannot reach the customer's own network.
//! * **The destination proxy** ([`DESTINATION_PROXY_ENV`],
//!   [`DESTINATION_PROXY_MODE_ENV`]) for user- and admin-set destinations:
//!   webhooks and notification channels, AI provider URLs, `inputlookup url=`,
//!   scheduled fetches, synthetic checks, URL-fetch tools. These are pinned
//!   clients (`ProxyPolicy::Direct`): the SSRF validator resolves the host,
//!   checks every address and pins the client to them. Without a destination
//!   proxy they dial the pinned address directly, exactly as before.
//!
//! # Destination proxy modes
//!
//! The modes match the connector proxy (`CONNECTOR_EGRESS_PROXY_MODE`).
//!
//! * `pinned_ip` (default): the tunnel is `CONNECT <pinned ip>:<port>`. The
//!   proxy never resolves the name, so the SSRF pin and the DNS-rebinding
//!   guard hold through the proxy. TLS (SNI and certificate name = the
//!   destination host) runs end to end inside the tunnel.
//! * `hostname` (opt-in): `CONNECT <host>:<port>`, and **the proxy enforces
//!   egress**. The SSRF validator still checks the name and what it resolves
//!   to before the request, but the proxy resolves the name again for the
//!   actual connection, so the pin does not apply to that hop.
//!
//! reqwest cannot open a tunnel to an address other than the request's host,
//! so a pinned client gets a private loopback relay ([`destination_proxy`]):
//! reqwest talks to the relay as its proxy, and the relay opens the real
//! tunnel through the operator proxy to the pinned address. The relay serves
//! only the one validated host and port, only to the client that holds its
//! random credential, and stops when the client is dropped.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// `true` refuses every direct outbound connection (see the module docs).
pub const EGRESS_PROXY_REQUIRED_ENV: &str = "NANO_EGRESS_PROXY_REQUIRED";
/// Forward proxy for user- and admin-set destinations.
pub const DESTINATION_PROXY_ENV: &str = "DESTINATION_EGRESS_PROXY_URL";
/// CONNECT target for [`DESTINATION_PROXY_ENV`]: `pinned_ip` (default) or
/// `hostname`.
pub const DESTINATION_PROXY_MODE_ENV: &str = "DESTINATION_EGRESS_PROXY_MODE";

/// Longest CONNECT response header block read from a proxy, and longest
/// request header block the relay accepts.
const MAX_PROXY_HEADER_BYTES: usize = 8192;
/// Longest wait to open the TCP connection to the operator proxy.
const PROXY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Longest wait for a CONNECT answer from the proxy, or for a request head
/// on the relay: a stalled peer never holds a relay task open.
const PROXY_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// What a CONNECT request names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProxyMode {
    /// `CONNECT <pinned ip>:<port>`: nano resolves, checks and pins.
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

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PinnedIp => "pinned_ip",
            Self::Hostname => "hostname",
        }
    }
}

/// Why a tunnel was not opened. Nothing reached the destination in any case.
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
    /// [`EGRESS_PROXY_REQUIRED_ENV`] is on and this path has no proxy.
    #[error("an egress proxy is required (NANO_EGRESS_PROXY_REQUIRED) but none is configured for this path; the request was refused")]
    Required,
}

impl ProxyRefusal {
    /// Wrap as an I/O error (what a dialer returns).
    pub fn into_io(self) -> std::io::Error {
        std::io::Error::other(self)
    }

    /// The refusal a dialer returned, if the error is one.
    pub fn from_io(error: &std::io::Error) -> Option<Self> {
        error.get_ref().and_then(|e| e.downcast_ref::<Self>()).copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyConfigError {
    #[error("egress proxy URL must be http://[user:password@]host:port with no path, query or fragment")]
    Url,
    #[error("egress proxy mode must be `pinned_ip` or `hostname`")]
    Mode,
}

/// A forward HTTP proxy: where to connect, and the credentials to present.
#[derive(Clone)]
pub struct ProxyEndpoint {
    host: String,
    port: u16,
    /// `Proxy-Authorization` value, from the URL's userinfo.
    authorization: Option<String>,
}

impl std::fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyEndpoint")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("authenticated", &self.authorization.is_some())
            .finish()
    }
}

impl ProxyEndpoint {
    /// `proxy_url` is `http://[user:password@]host:port`. Credentials, when
    /// present, are sent as `Proxy-Authorization: Basic` on CONNECT only.
    pub fn parse(proxy_url: &str) -> Result<Self, ProxyConfigError> {
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
        let decode = |s: &str| {
            percent_encoding::percent_decode_str(s)
                .decode_utf8()
                .map(|c| c.into_owned())
                .map_err(|_| ProxyConfigError::Url)
        };
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
        Ok(Self { host, port, authorization })
    }

    /// Open `CONNECT <authority>` through the proxy and return the tunnel.
    /// `authority` is `host:port` or `ip:port` (`[v6]:port`); the caller has
    /// already checked it. Fail closed: anything but a `2xx` is a refusal.
    pub async fn connect_tunnel(&self, authority: &str) -> Result<TcpStream, ProxyRefusal> {
        if authority.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(ProxyRefusal::Refused);
        }
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(auth) = &self.authorization {
            request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        }
        request.push_str("\r\n");
        let mut stream = tokio::time::timeout(PROXY_CONNECT_TIMEOUT, TcpStream::connect((self.host.as_str(), self.port)))
            .await
            .map_err(|_| ProxyRefusal::Unreachable)?
            .map_err(|_| ProxyRefusal::Unreachable)?;
        let handshake = async {
            stream.write_all(request.as_bytes()).await.map_err(|_| ProxyRefusal::Unreachable)?;
            read_connect_status(&mut stream).await
        };
        let status = tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| ProxyRefusal::Unreachable)??;
        match status {
            200..=299 => Ok(stream),
            403 | 407 => Err(ProxyRefusal::Denied),
            _ => Err(ProxyRefusal::Refused),
        }
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

/// Parse a "proxy required" setting. Unset, empty, `false`, `0`, `off` and
/// `no` are off; `true`, `1`, `on` and `yes` are on. Any other value is on:
/// a typo in a fail-closed switch must not silently open direct egress.
pub fn parse_required(value: Option<&str>) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("false" | "0" | "off" | "no") => false,
        Some("true" | "1" | "on" | "yes") => true,
        Some(_) => true,
    }
}

/// The destination proxy for pinned user-set destinations.
#[derive(Debug, Clone)]
pub struct DestinationProxy {
    pub endpoint: ProxyEndpoint,
    pub mode: ProxyMode,
}

/// The egress settings in force for one outbound call.
#[derive(Debug, Clone)]
pub struct EgressSettings {
    /// [`EGRESS_PROXY_REQUIRED_ENV`].
    pub required: bool,
    /// [`DESTINATION_PROXY_ENV`] / [`DESTINATION_PROXY_MODE_ENV`]. `Err` is
    /// an invalid setting: every destination call refuses (never direct).
    pub destination: Result<Option<DestinationProxy>, ProxyConfigError>,
    /// Which schemes the installer-wide env proxy (`HTTPS_PROXY` and
    /// friends) covers, for operator-configured destinations
    /// (`ProxyPolicy::Environment`).
    pub env_proxy: EnvProxy,
    /// Unit tests route loopback fixtures as if they were public.
    #[cfg(test)]
    pub(crate) loopback_is_public: bool,
}

impl Default for EgressSettings {
    /// Nothing required, no destination proxy, no env proxy.
    fn default() -> Self {
        Self {
            required: false,
            destination: Ok(None),
            env_proxy: EnvProxy::NONE,
            #[cfg(test)]
            loopback_is_public: false,
        }
    }
}

impl EgressSettings {
    /// Read the settings from the process environment.
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok();
        Self::from_values(
            get(EGRESS_PROXY_REQUIRED_ENV).as_deref(),
            get(DESTINATION_PROXY_ENV).as_deref(),
            get(DESTINATION_PROXY_MODE_ENV).as_deref(),
            EnvProxy::from_env(),
        )
    }

    /// [`EgressSettings::from_env`] on already-read values.
    pub fn from_values(required: Option<&str>, url: Option<&str>, mode: Option<&str>, env_proxy: EnvProxy) -> Self {
        let destination = ProxyMode::parse(mode).and_then(|mode| match url.map(str::trim) {
            None | Some("") => Ok(None),
            Some(url) => Ok(Some(DestinationProxy { endpoint: ProxyEndpoint::parse(url)?, mode })),
        });
        Self { required: parse_required(required), destination, env_proxy, ..Self::default() }
    }

    /// [`is_public_destination`], under these settings.
    pub fn is_public(&self, ip: std::net::IpAddr) -> bool {
        #[cfg(test)]
        if self.loopback_is_public && ip.is_loopback() {
            return true;
        }
        is_public_destination(ip)
    }

    /// The settings for the current call: the process environment, unless a
    /// caller scoped others with [`with_egress_settings`]. A scope can never
    /// switch "proxy required" off when the environment has it on.
    pub fn current() -> Self {
        let env = Self::from_env();
        match SCOPED.try_with(|s| s.clone()) {
            Ok(mut scoped) => {
                scoped.required |= env.required;
                scoped
            }
            Err(_) => env,
        }
    }
}

tokio::task_local! {
    static SCOPED: EgressSettings;
}

/// Run `fut` with `settings` in force for every outbound client it builds on
/// this task. Used by tests (no process-env mutation under parallel tests)
/// and by hosts that load settings from somewhere other than the env. It can
/// only tighten "proxy required", never relax it.
pub async fn with_egress_settings<F: std::future::Future>(settings: EgressSettings, fut: F) -> F::Output {
    SCOPED.scope(settings, fut).await
}

/// Whether `ip` is a public (internet) address: one the default SSRF
/// validator admits. Private, loopback, link-local, CGNAT, ULA and the other
/// reserved ranges are not; "proxy required" applies only to public ones.
pub fn is_public_destination(ip: std::net::IpAddr) -> bool {
    crate::inputlookup::SsrfValidator::default_secure().validate_ip_address(ip).is_ok()
}

/// Whether "proxy required" is on for the current call.
pub fn proxy_required() -> bool {
    EgressSettings::current().required
}

/// For a client that honors the env proxy (operator-configured destinations
/// that do not pin: content channels, the license check-in, usage reports,
/// the managed AI gateway, SIEM forwarding): under "proxy required" with no
/// env proxy for `url`'s scheme, refuse instead of going direct. An
/// `https://` URL needs `HTTPS_PROXY` or `ALL_PROXY`; `HTTP_PROXY` alone
/// does not cover it (reqwest uses it for `http://` only).
pub fn require_env_proxy(url: &str) -> Result<(), ProxyRefusal> {
    let s = EgressSettings::current();
    if s.required && !s.env_proxy.covers_url(url) {
        Err(ProxyRefusal::Required)
    } else {
        Ok(())
    }
}

/// Which URL schemes the installer-wide env proxy covers, read the way
/// reqwest (hyper-util's proxy matcher) reads it: `HTTPS_PROXY` serves
/// `https://` only, `HTTP_PROXY` serves `http://` only, `ALL_PROXY` serves
/// both. For each, the uppercase name wins over the lowercase one even when
/// empty, and a CGI environment (`REQUEST_METHOD` set) disables all of them.
/// `NO_PROXY=*` exempts every host, so it counts as no proxy. Host-specific
/// `NO_PROXY` entries are operator intent and are not second-guessed here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct EnvProxy {
    pub http: bool,
    pub https: bool,
}

impl EnvProxy {
    pub const NONE: Self = Self { http: false, https: false };
    pub const ALL: Self = Self { http: true, https: true };

    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// [`EnvProxy::from_env`] over an arbitrary variable lookup.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        if get("REQUEST_METHOD").is_some() {
            return Self::NONE;
        }
        let first = |names: [&str; 2]| names.iter().find_map(|n| get(n)).unwrap_or_default();
        if first(["NO_PROXY", "no_proxy"]).split(',').any(|e| e.trim() == "*") {
            return Self::NONE;
        }
        let set = |names: [&str; 2]| !first(names).trim().is_empty();
        let all = set(["ALL_PROXY", "all_proxy"]);
        Self { http: all || set(["HTTP_PROXY", "http_proxy"]), https: all || set(["HTTPS_PROXY", "https_proxy"]) }
    }

    /// Whether a request with this scheme goes through the env proxy. Any
    /// scheme other than `http` / `https` needs both.
    pub fn covers(self, scheme: &str) -> bool {
        match scheme.to_ascii_lowercase().as_str() {
            "http" => self.http,
            "https" => self.https,
            _ => self.http && self.https,
        }
    }

    /// [`EnvProxy::covers`] for a URL; an unparseable URL needs both.
    pub fn covers_url(self, url: &str) -> bool {
        match url::Url::parse(url) {
            Ok(u) => self.covers(u.scheme()),
            Err(_) => self.http && self.https,
        }
    }
}

/// Settings summary for SIEM Health / startup logs. Never includes proxy
/// credentials.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EgressPosture {
    pub proxy_required: bool,
    pub destination_proxy: &'static str,
    pub destination_proxy_mode: Option<&'static str>,
    pub env_proxy: EnvProxy,
}

impl EgressPosture {
    pub fn from_env() -> Self {
        let s = EgressSettings::from_env();
        let (destination_proxy, destination_proxy_mode) = match &s.destination {
            Ok(Some(d)) => ("configured", Some(d.mode.as_str())),
            Ok(None) => ("none", None),
            Err(_) => ("invalid", None),
        };
        Self {
            proxy_required: s.required,
            destination_proxy,
            destination_proxy_mode,
            env_proxy: s.env_proxy,
        }
    }
}

/// Route a pinned client through the destination proxy, via a private
/// loopback relay that tunnels to `addrs` (pinned mode) or to the host name
/// (hostname mode). `validated` is the SSRF-validated URL; `addrs` its
/// validated resolved addresses (empty for an IP-literal host).
///
/// Must be called inside a Tokio runtime (the relay is a task on it). The
/// relay stops when the returned proxy, and so the client holding it, is
/// dropped.
pub fn destination_proxy(
    proxy: &DestinationProxy,
    validated: &url::Url,
    addrs: &[SocketAddr],
) -> Result<reqwest::Proxy, RelayError> {
    let handle = tokio::runtime::Handle::try_current().map_err(|_| RelayError::NoRuntime)?;
    let host = validated.host_str().ok_or(RelayError::MissingHost)?;
    let port = validated.port_or_known_default().ok_or(RelayError::MissingHost)?;
    let relay = Relay::start(
        &handle,
        RelayTarget {
            host: strip_brackets(host).to_ascii_lowercase(),
            port,
            addrs: addrs.to_vec(),
            upstream: proxy.endpoint.clone(),
            mode: proxy.mode,
        },
    )?;
    let proxy_url = relay.proxy_url.clone();
    let guard = Arc::new(relay);
    Ok(reqwest::Proxy::custom(move |_url| {
        // The guard lives as long as the client: dropping the client drops
        // this closure, which stops the relay.
        let _keep = &guard;
        Some(proxy_url.clone())
    }))
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("egress proxy relay needs a Tokio runtime")]
    NoRuntime,
    #[error("destination URL has no host")]
    MissingHost,
    #[error("egress proxy relay could not start: {0}")]
    Bind(String),
}

fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

struct RelayTarget {
    /// Lowercase, IPv6 without brackets.
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
    upstream: ProxyEndpoint,
    mode: ProxyMode,
}

impl RelayTarget {
    /// The CONNECT authorities to try upstream, in order.
    fn upstream_authorities(&self) -> Vec<String> {
        match self.mode {
            ProxyMode::PinnedIp if !self.addrs.is_empty() => {
                self.addrs.iter().map(|a| SocketAddr::new(a.ip(), self.port).to_string()).collect()
            }
            // An IP-literal destination (already validated) is its own pin.
            _ => vec![format_authority(&self.host, self.port)],
        }
    }
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

struct Relay {
    proxy_url: url::Url,
    _stop: tokio::sync::oneshot::Sender<()>,
}

impl Relay {
    fn start(handle: &tokio::runtime::Handle, target: RelayTarget) -> Result<Self, RelayError> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| RelayError::Bind(e.to_string()))?;
        listener.set_nonblocking(true).map_err(|e| RelayError::Bind(e.to_string()))?;
        let port = listener.local_addr().map_err(|e| RelayError::Bind(e.to_string()))?.port();
        let token = uuid::Uuid::new_v4().simple().to_string();
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{token}:x"))
        );
        let proxy_url = url::Url::parse(&format!("http://{token}:x@127.0.0.1:{port}/"))
            .map_err(|e| RelayError::Bind(e.to_string()))?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let target = Arc::new(target);
        let expected = Arc::new(expected);
        handle.spawn(async move {
            let Ok(listener) = tokio::net::TcpListener::from_std(listener) else { return };
            tokio::pin!(stopped);
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { continue };
                        let target = target.clone();
                        let expected = expected.clone();
                        tokio::spawn(async move { serve_relay_conn(socket, &target, &expected).await });
                    }
                }
            }
        });
        Ok(Self { proxy_url, _stop: stop })
    }
}

/// Read one request head (through `\r\n\r\n`), returning it and any bytes
/// read past it.
async fn read_request_head(socket: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Some((buf, rest));
        }
        if buf.len() >= MAX_PROXY_HEADER_BYTES {
            return None;
        }
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn reply(socket: &mut TcpStream, status: &str) {
    let _ = socket
        .write_all(format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").as_bytes())
        .await;
}

/// Split `host:port` (or `[v6]:port`) into a lowercase bracket-free host and
/// a port.
fn split_authority(authority: &str) -> Option<(String, u16)> {
    let (host, port) = authority.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some((strip_brackets(host).to_ascii_lowercase(), port))
}

async fn serve_relay_conn(mut client: TcpStream, target: &RelayTarget, expected_auth: &str) {
    let Ok(Some((head, rest))) = tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, read_request_head(&mut client)).await else {
        return;
    };
    let Ok(head_text) = std::str::from_utf8(&head) else {
        return reply(&mut client, "400 Bad Request").await;
    };
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(request_target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return reply(&mut client, "400 Bad Request").await;
    };
    let headers: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
    let authorized = headers.iter().any(|h| {
        h.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("proxy-authorization") && value.trim() == expected_auth
        })
    });
    if !authorized {
        return reply(&mut client, "407 Proxy Authentication Required").await;
    }

    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    let requested = if is_connect {
        split_authority(request_target)
    } else {
        url::Url::parse(request_target).ok().and_then(|u| {
            let host = u.host_str()?.to_string();
            let port = u.port_or_known_default()?;
            (u.scheme() == "http").then(|| (strip_brackets(&host).to_ascii_lowercase(), port))
        })
    };
    // Only the one validated host and port: a redirect or a second name on
    // this client never leaves through the relay.
    match requested {
        Some((host, port)) if host == target.host && port == target.port => {}
        _ => return reply(&mut client, "403 Forbidden").await,
    }

    let mut upstream = None;
    let mut last = ProxyRefusal::Unreachable;
    for authority in target.upstream_authorities() {
        match target.upstream.connect_tunnel(&authority).await {
            Ok(stream) => {
                upstream = Some(stream);
                break;
            }
            Err(e) => last = e,
        }
    }
    let Some(mut upstream) = upstream else {
        tracing::warn!(host = %target.host, mode = target.mode.as_str(), error = %last, "destination egress proxy refused the tunnel");
        let status = if last == ProxyRefusal::Denied { "403 Forbidden" } else { "502 Bad Gateway" };
        return reply(&mut client, status).await;
    };

    if is_connect {
        if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
            return;
        }
    } else {
        // Plain-http destination: forward the request (absolute-form is valid
        // to an origin server) without the relay credential.
        let mut forwarded = format!("{method} {request_target} {version}\r\n");
        for h in &headers {
            let name = h.split_once(':').map(|(n, _)| n.trim()).unwrap_or_default();
            if name.eq_ignore_ascii_case("proxy-authorization") || name.eq_ignore_ascii_case("proxy-connection") {
                continue;
            }
            forwarded.push_str(h);
            forwarded.push_str("\r\n");
        }
        forwarded.push_str("\r\n");
        if upstream.write_all(forwarded.as_bytes()).await.is_err() {
            return;
        }
    }
    if !rest.is_empty() && upstream.write_all(&rest).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

#[cfg(test)]
#[path = "egress_proxy_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "egress_proxy_caller_tests.rs"]
mod caller_tests;

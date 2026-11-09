//! HTTP header extraction helpers shared between open-core and enterprise
//! handlers.
//!
//! `extract_client_ip` carries non-trivial security semantics (trusted-proxy
//! CIDR enforcement) — the configuration is loaded once at process start
//! from the `TRUSTED_PROXY_CIDRS` environment variable. Keeping a single
//! implementation here avoids drift between handler tiers.

use axum::http::{header, HeaderMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;

/// A CIDR range parsed from `TRUSTED_PROXY_CIDRS`.
struct CidrRange {
    network: IpAddr,
    prefix_len: u8,
}

impl CidrRange {
    /// Parse a CIDR string like "10.0.0.0/8" or "::1/128".
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (addr_str, prefix_str) = s.split_once('/')?;
        let network: IpAddr = addr_str.parse().ok()?;
        let prefix_len: u8 = prefix_str.parse().ok()?;
        let max_bits = if network.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_bits {
            return None;
        }
        Some(Self {
            network,
            prefix_len,
        })
    }

    /// Check whether `addr` falls within this CIDR range.
    fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX
                    .checked_shl(32 - self.prefix_len as u32)
                    .unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX
                    .checked_shl(128 - self.prefix_len as u32)
                    .unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false, // v4/v6 mismatch
        }
    }
}

/// SECURITY: Trusted proxy CIDRs, loaded once from the `TRUSTED_PROXY_CIDRS`
/// environment variable (comma-separated, e.g. "10.0.0.0/8,172.16.0.0/12").
///
/// When this list is **non-empty**, proxy headers (`X-Forwarded-For`,
/// `CF-Connecting-IP`, `True-Client-IP`) are only trusted if the direct
/// connection IP (`connect_info`) falls within one of these CIDRs. If the
/// connection comes from an untrusted IP, we ignore all proxy headers and
/// use the socket address directly. This prevents attackers who connect
/// directly (bypassing the load balancer) from spoofing their IP via headers.
///
/// When **unset or empty**, proxy headers are NOT trusted — the socket
/// address is used directly. This is the secure default. Set this variable
/// to the CIDRs of your load balancer / reverse proxy (e.g. GKE, Cloudflare)
/// to enable proxy header trust in production.
static TRUSTED_PROXY_CIDRS: LazyLock<Vec<CidrRange>> = LazyLock::new(|| {
    std::env::var("TRUSTED_PROXY_CIDRS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            match CidrRange::parse(s) {
                Some(cidr) => Some(cidr),
                None => {
                    tracing::error!("Invalid CIDR in TRUSTED_PROXY_CIDRS: {:?} — skipping", s);
                    None
                }
            }
        })
        .collect()
});

/// Returns `true` if `addr` falls within at least one configured trusted
/// proxy CIDR. Returns `false` when no CIDRs are configured (secure default
/// — never trust proxy headers).
fn is_trusted_proxy(addr: Option<&SocketAddr>) -> bool {
    if TRUSTED_PROXY_CIDRS.is_empty() {
        return false; // No trusted proxies configured — never trust proxy headers
    }
    match addr {
        Some(sa) => {
            let ip = sa.ip();
            TRUSTED_PROXY_CIDRS.iter().any(|cidr| cidr.contains(ip))
        }
        None => false, // No socket info and trusted proxies are required — deny
    }
}

/// The forwarded-client headers an operator may choose to trust, in the order
/// they are consulted. Parsed once from `TRUSTED_CLIENT_IP_HEADERS`
/// (comma-separated, case-insensitive). NAN-5015.
///
/// Default: `x-forwarded-for` only. `CF-Connecting-IP` / `True-Client-IP` are
/// set by a CDN edge, and nano's own nginx edges pass them through from the
/// client untouched, so trusting them by default let anyone reaching a trusted
/// proxy claim any address (`CF-Connecting-IP: 127.0.0.1` got the loopback
/// allowlist pass and escaped per-IP lockout). A deployment that really sits
/// behind Cloudflare / Akamai opts in with e.g.
/// `TRUSTED_CLIENT_IP_HEADERS=cf-connecting-ip,x-forwarded-for`.
static TRUSTED_CLIENT_IP_HEADERS: LazyLock<Vec<ClientIpHeader>> =
    LazyLock::new(|| parse_trusted_client_ip_headers(std::env::var("TRUSTED_CLIENT_IP_HEADERS").ok().as_deref()));

/// A forwarded-client header [`extract_client_ip`] can be configured to trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientIpHeader {
    CfConnectingIp,
    TrueClientIp,
    /// Rightmost entry only (the one the trusted proxy appended).
    XForwardedFor,
    XRealIp,
}

impl ClientIpHeader {
    fn name(self) -> &'static str {
        match self {
            ClientIpHeader::CfConnectingIp => "CF-Connecting-IP",
            ClientIpHeader::TrueClientIp => "True-Client-IP",
            ClientIpHeader::XForwardedFor => "X-Forwarded-For",
            ClientIpHeader::XRealIp => "X-Real-IP",
        }
    }
}

/// Parse a `TRUSTED_CLIENT_IP_HEADERS` value. Unknown names are logged and
/// skipped; an unset or empty value (or one with no valid names) yields the
/// default, `x-forwarded-for` only.
pub fn parse_trusted_client_ip_headers(raw: Option<&str>) -> Vec<ClientIpHeader> {
    let mut out = Vec::new();
    for name in raw.unwrap_or_default().split(',') {
        let name = name.trim().to_ascii_lowercase();
        let header = match name.as_str() {
            "" => continue,
            "cf-connecting-ip" => ClientIpHeader::CfConnectingIp,
            "true-client-ip" => ClientIpHeader::TrueClientIp,
            "x-forwarded-for" => ClientIpHeader::XForwardedFor,
            "x-real-ip" => ClientIpHeader::XRealIp,
            other => {
                tracing::error!("Unknown header in TRUSTED_CLIENT_IP_HEADERS: {other:?} — skipping");
                continue;
            }
        };
        if !out.contains(&header) {
            out.push(header);
        }
    }
    if out.is_empty() {
        out.push(ClientIpHeader::XForwardedFor);
    }
    out
}

/// Where a client address came from (NAN-5015).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIp {
    pub ip: String,
    /// `true` when the address is the TCP peer itself, `false` when it was
    /// read from a forwarded header (an address a proxy vouched for, not one
    /// this process observed). Only a socket-derived loopback address is
    /// "local".
    pub from_socket: bool,
}

/// SECURITY: Extract the client IP (NAN-5015).
///
/// **Trust model**: forwarded-client headers are consulted only when the TCP
/// peer is inside `TRUSTED_PROXY_CIDRS`, and only the headers listed in
/// `TRUSTED_CLIENT_IP_HEADERS` (default: `X-Forwarded-For`), in that order.
/// With no trusted proxy CIDRs configured, no header is trusted and the
/// socket address is used — the secure default.
///
/// For `X-Forwarded-For` the RIGHTMOST entry is used: the leftmost entries are
/// client-controlled; the rightmost is the one the trusted proxy appended.
pub fn extract_client_ip_origin(
    headers: &HeaderMap,
    connect_info: Option<&SocketAddr>,
) -> Option<ClientIp> {
    extract_client_ip_with(headers, connect_info, &TRUSTED_CLIENT_IP_HEADERS, is_trusted_proxy(connect_info))
}

/// [`extract_client_ip_origin`] with explicit configuration (unit-testable).
pub fn extract_client_ip_with(
    headers: &HeaderMap,
    connect_info: Option<&SocketAddr>,
    trusted_headers: &[ClientIpHeader],
    peer_is_trusted_proxy: bool,
) -> Option<ClientIp> {
    if peer_is_trusted_proxy {
        for header in trusted_headers {
            let Some(value) = headers.get(header.name()).and_then(|v| v.to_str().ok()) else {
                continue;
            };
            let candidate = match header {
                ClientIpHeader::XForwardedFor => value.rsplit(',').next().unwrap_or(value),
                _ => value,
            }
            .trim();
            if !candidate.is_empty() {
                return Some(ClientIp {
                    ip: candidate.to_string(),
                    from_socket: false,
                });
            }
        }
    } else {
        tracing::debug!(
            "Connection from untrusted proxy — ignoring proxy headers, using socket IP"
        );
    }

    connect_info.map(|addr| ClientIp {
        ip: addr.ip().to_string(),
        from_socket: true,
    })
}

/// The client IP as a string (see [`extract_client_ip_origin`] for the trust
/// model). Kept for the many audit / rate-limit callers that need only the
/// address.
pub fn extract_client_ip(headers: &HeaderMap, connect_info: Option<&SocketAddr>) -> Option<String> {
    extract_client_ip_origin(headers, connect_info).map(|c| c.ip)
}

/// Extract user agent string from request headers.
pub fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
#[path = "headers_tests.rs"]
mod headers_tests;

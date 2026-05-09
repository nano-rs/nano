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

/// SECURITY: Extract client IP from headers with optional socket address fallback.
///
/// **Trust model**: Proxy headers (`CF-Connecting-IP`, `True-Client-IP`,
/// `X-Forwarded-For`) are only consulted when the direct connection originates
/// from a trusted proxy CIDR (see `TRUSTED_PROXY_CIDRS` env var). If no
/// trusted CIDRs are configured, all proxy headers are trusted for backward
/// compatibility.
///
/// Priority order (when proxy headers are trusted):
/// 1. CF-Connecting-IP  — set by Cloudflare edge, not client-controlled
/// 2. True-Client-IP    — set by Cloudflare Enterprise / Akamai edge
/// 3. X-Forwarded-For   — **rightmost** entry only (appended by trusted LB)
/// 4. Socket address    — direct connection, no proxy
///
/// IMPORTANT: The leftmost X-Forwarded-For entry is client-controlled and
/// trivially spoofable. We use the rightmost entry (appended by the trusted
/// GKE LB).
pub fn extract_client_ip(headers: &HeaderMap, connect_info: Option<&SocketAddr>) -> Option<String> {
    // Only trust proxy headers if the connection comes from a known proxy
    if is_trusted_proxy(connect_info) {
        // Prefer CF-Connecting-IP (Cloudflare sets this to the true client IP)
        if let Some(cf_ip) = headers.get("CF-Connecting-IP") {
            if let Ok(value) = cf_ip.to_str() {
                let ip = value.trim();
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }

        // True-Client-IP (Cloudflare Enterprise / Akamai — also edge-set)
        if let Some(true_ip) = headers.get("True-Client-IP") {
            if let Ok(value) = true_ip.to_str() {
                let ip = value.trim();
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }

        // X-Forwarded-For: use the rightmost (last) entry — appended by trusted GKE LB
        if let Some(forwarded) = headers.get("X-Forwarded-For") {
            if let Ok(value) = forwarded.to_str() {
                let ip = value.rsplit(',').next().unwrap_or(value).trim();
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }
    } else {
        tracing::debug!(
            "Connection from untrusted proxy — ignoring proxy headers, using socket IP"
        );
    }

    // Fall back to connection socket address (direct connection without proxy)
    connect_info.map(|addr| addr.ip().to_string())
}

/// Extract user agent string from request headers.
pub fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

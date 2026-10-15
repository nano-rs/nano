// SPDX-License-Identifier: AGPL-3.0-or-later

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

/// Returns `true` if `ip` falls within at least one of `trusted`. An empty
/// list trusts nothing (secure default — never trust proxy headers).
fn is_trusted(trusted: &[CidrRange], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    trusted.iter().any(|cidr| cidr.contains(ip))
}

/// Parse one client-address header value: a bare IPv4/IPv6 address, or an
/// `ip:port` / `[v6]:port` socket form some proxies emit. Anything else is
/// not an address and is never returned (a header value is attacker-shaped
/// until a trusted hop vouches for it).
fn parse_header_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() {
        return None;
    }
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
        .map(|ip| ip.to_canonical())
}

/// The single-value edge headers (`CF-Connecting-IP`, `True-Client-IP`) as an
/// address, when present and well-formed.
fn single_ip_header(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_header_ip)
}

/// SECURITY: Extract client IP from headers with optional socket address fallback.
///
/// **Trust model** (NAN-3460): proxy headers are only consulted when the
/// direct connection (`connect_info`) originates from a trusted proxy CIDR
/// (`TRUSTED_PROXY_CIDRS`). With no trusted CIDRs configured, or a peer
/// outside them, every proxy header is ignored and the socket address is the
/// client — a client that connects directly cannot spoof its address.
///
/// Priority order (when the peer is a trusted proxy):
/// 1. `CF-Connecting-IP` — set by the Cloudflare edge (hosted: CF → GKE).
/// 2. `True-Client-IP`   — Cloudflare Enterprise / Akamai edge.
/// 3. `X-Forwarded-For`  — walked right-to-left, skipping every hop inside a
///    trusted CIDR; the first untrusted hop is the client. Entries left of it
///    were written by the client (or an untrusted hop) and are never used.
///    When every hop is trusted (an internal caller), the leftmost one is.
///    A malformed entry stops the walk at the last hop that was vouched for.
/// 4. Socket address — direct connection, no proxy.
///
/// The edge-set headers are only meaningful when the trusted proxy in front
/// actually sets or strips them: open-core nginx clears both
/// (`config/nginx/nginx.opensource*.conf`), so a browser cannot inject them.
///
/// The result is a canonical address string (IPv4-mapped IPv6 unwrapped,
/// IPv6 compressed lowercase), never a raw header value.
pub fn extract_client_ip(headers: &HeaderMap, connect_info: Option<&SocketAddr>) -> Option<String> {
    resolve_client_ip(headers, connect_info, &TRUSTED_PROXY_CIDRS)
}

fn resolve_client_ip(
    headers: &HeaderMap,
    connect_info: Option<&SocketAddr>,
    trusted: &[CidrRange],
) -> Option<String> {
    let peer = connect_info.map(|addr| addr.ip().to_canonical())?;
    if !is_trusted(trusted, peer) {
        if headers.contains_key("X-Forwarded-For")
            || headers.contains_key("CF-Connecting-IP")
            || headers.contains_key("True-Client-IP")
        {
            tracing::debug!("Connection from untrusted peer — ignoring proxy headers, using socket IP");
        }
        return Some(peer.to_string());
    }
    if let Some(ip) = single_ip_header(headers, "CF-Connecting-IP")
        .or_else(|| single_ip_header(headers, "True-Client-IP"))
    {
        return Some(ip.to_string());
    }
    // All X-Forwarded-For header instances form one list, in order.
    let hops: Vec<&str> = headers
        .get_all("X-Forwarded-For")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|hop| !hop.is_empty())
        .collect();
    let mut client = peer;
    for hop in hops.iter().rev() {
        let Some(ip) = parse_header_ip(hop) else {
            break; // unvouched garbage: keep the last trusted hop
        };
        client = ip;
        if !is_trusted(trusted, ip) {
            break;
        }
    }
    Some(client.to_string())
}

/// The socket peer as an optional extractor (NAN-3797). Handlers take
/// `peer: PeerAddr` and resolve with [`peer_client_ip`]. Passing `None` as
/// `extract_client_ip`'s `connect_info` always yields `None` since NAN-3460,
/// which a tenant IP policy treats as denied (the hosted SSO callback and MFA
/// step-up returned 401). Absent `ConnectInfo` (a router served without
/// connect info) still resolves to `None`: fail closed, never the proxy.
pub type PeerAddr = Option<axum::Extension<axum::extract::ConnectInfo<SocketAddr>>>;

/// [`extract_client_ip`] for a handler's [`PeerAddr`].
pub fn peer_client_ip(headers: &HeaderMap, peer: &PeerAddr) -> Option<String> {
    let addr = peer
        .as_ref()
        .map(|axum::Extension(axum::extract::ConnectInfo(addr))| addr);
    extract_client_ip(headers, addr)
}

/// Extract user agent string from request headers.
pub fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-3797: the hosted renderer's trusted-proxy config (the platform
    /// hosted-shared-apps-render, staging `TRUSTED_PROXY_CIDRS=10.20.0.0/16`:
    /// Cloudflare edge -> GKE load balancer / ingress inside 10.20/16 -> api).
    /// A tenant IP allowlist must see the real client, never the proxy.
    #[test]
    fn hosted_trusted_proxy_config_resolves_the_real_client() {
        let hosted = cidrs(&["10.20.0.0/16"]);
        let ingress: SocketAddr = "10.20.3.17:41234".parse().unwrap();
        let resolve = |pairs: &[(&str, &str)], peer: Option<&SocketAddr>| {
            resolve_client_ip(&headers(pairs), peer, &hosted)
        };
        // Cloudflare's edge header through the trusted ingress.
        assert_eq!(
            resolve(&[("CF-Connecting-IP", "32.216.10.126")], Some(&ingress)).as_deref(),
            Some("32.216.10.126")
        );
        assert_eq!(
            resolve(
                &[("CF-Connecting-IP", "2605:d580:140c:23ec::5798")],
                Some(&ingress)
            )
            .as_deref(),
            Some("2605:d580:140c:23ec::5798")
        );
        // X-Forwarded-For: the first hop outside 10.20/16, never a
        // client-written entry to its left and never the ingress itself.
        assert_eq!(
            resolve(
                &[("X-Forwarded-For", "198.51.100.1, 32.216.10.126, 10.20.0.7")],
                Some(&ingress)
            )
            .as_deref(),
            Some("32.216.10.126")
        );
        // A request that reaches the pod from outside the proxy range cannot
        // pick its address with headers.
        let direct: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        assert_eq!(
            resolve(
                &[
                    ("CF-Connecting-IP", "10.20.0.1"),
                    ("X-Forwarded-For", "10.20.0.1")
                ],
                Some(&direct)
            )
            .as_deref(),
            Some("203.0.113.9")
        );
        // No peer (the bug: handlers passed `None`) resolves to nothing, which
        // the tenant IP policy denies; it never falls back to a header.
        assert_eq!(
            resolve(&[("CF-Connecting-IP", "32.216.10.126")], None),
            None
        );
    }

    #[test]
    fn peer_client_ip_uses_the_connect_info_extension() {
        let peer: PeerAddr = Some(axum::Extension(axum::extract::ConnectInfo(
            "198.51.100.23:443".parse().unwrap(),
        )));
        // No trusted CIDRs in the unit-test environment: the socket is the client.
        assert_eq!(
            peer_client_ip(&HeaderMap::new(), &peer).as_deref(),
            Some("198.51.100.23")
        );
        assert_eq!(peer_client_ip(&HeaderMap::new(), &None), None);
    }

    fn cidrs(list: &[&str]) -> Vec<CidrRange> {
        list.iter().map(|c| CidrRange::parse(c).unwrap()).collect()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    fn peer(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 41234)
    }

    /// The open-core shape (NAN-3460): browser → nginx (Docker network) → api.
    /// nginx overwrites X-Forwarded-For with the address it saw.
    #[test]
    fn trusted_nginx_hop_yields_the_browser_address() {
        let trusted = cidrs(&["172.16.0.0/12"]);
        let h = headers(&[("X-Forwarded-For", "203.0.113.7")]);
        assert_eq!(
            resolve_client_ip(&h, Some(&peer("172.18.0.26")), &trusted).as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn untrusted_peer_cannot_spoof_any_header() {
        let trusted = cidrs(&["172.16.0.0/12"]);
        let h = headers(&[
            ("X-Forwarded-For", "1.2.3.4"),
            ("CF-Connecting-IP", "5.6.7.8"),
            ("True-Client-IP", "9.9.9.9"),
        ]);
        assert_eq!(
            resolve_client_ip(&h, Some(&peer("198.51.100.20")), &trusted).as_deref(),
            Some("198.51.100.20")
        );
    }

    #[test]
    fn no_trusted_cidrs_means_socket_address() {
        let h = headers(&[("X-Forwarded-For", "1.2.3.4"), ("CF-Connecting-IP", "5.6.7.8")]);
        assert_eq!(
            resolve_client_ip(&h, Some(&peer("172.18.0.26")), &[]).as_deref(),
            Some("172.18.0.26")
        );
    }

    #[test]
    fn client_prepended_xff_entries_are_ignored() {
        // The client sent `X-Forwarded-For: 6.6.6.6`; a trusted appending
        // proxy added the real address on the right. Only the rightmost
        // untrusted hop counts.
        let trusted = cidrs(&["10.0.0.0/8"]);
        let h = headers(&[("X-Forwarded-For", "6.6.6.6, 203.0.113.9, 10.1.2.3")]);
        assert_eq!(
            resolve_client_ip(&h, Some(&peer("10.0.0.5")), &trusted).as_deref(),
            Some("203.0.113.9")
        );
    }

    #[test]
    fn multiple_xff_headers_form_one_chain() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let h = headers(&[
            ("X-Forwarded-For", "6.6.6.6"),
            ("X-Forwarded-For", "203.0.113.9, 10.9.9.9"),
        ]);
        assert_eq!(
            resolve_client_ip(&h, Some(&peer("10.0.0.5")), &trusted).as_deref(),
            Some("203.0.113.9")
        );
    }

    #[test]
    fn malformed_hop_stops_the_walk_at_the_last_vouched_hop() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let h = headers(&[("X-Forwarded-For", "6.6.6.6, not-an-ip, 10.1.2.3")]);
        assert_eq!(
            resolve_client_ip(&h, Some(&peer("10.0.0.5")), &trusted).as_deref(),
            Some("10.1.2.3")
        );
        let garbage = headers(&[("X-Forwarded-For", "<script>")]);
        assert_eq!(
            resolve_client_ip(&garbage, Some(&peer("10.0.0.5")), &trusted).as_deref(),
            Some("10.0.0.5")
        );
    }

    #[test]
    fn all_trusted_chain_returns_the_leftmost_hop() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let h = headers(&[("X-Forwarded-For", "10.4.4.4, 10.1.2.3")]);
        assert_eq!(
            resolve_client_ip(&h, Some(&peer("10.0.0.5")), &trusted).as_deref(),
            Some("10.4.4.4")
        );
    }

    /// Hosted (CF → GKE): the Google front end is the trusted peer and
    /// Cloudflare's CF-Connecting-IP names the client.
    #[test]
    fn edge_header_wins_from_a_trusted_peer_and_must_be_an_address() {
        let trusted = cidrs(&["35.191.0.0/16", "130.211.0.0/22", "10.0.0.0/8"]);
        let h = headers(&[
            ("CF-Connecting-IP", "2001:DB8::1"),
            ("X-Forwarded-For", "203.0.113.9, 162.158.1.1, 34.1.2.3"),
        ]);
        assert_eq!(
            resolve_client_ip(&h, Some(&peer("35.191.4.4")), &trusted).as_deref(),
            Some("2001:db8::1")
        );
        let bad = headers(&[("CF-Connecting-IP", "evil"), ("X-Forwarded-For", "203.0.113.9")]);
        assert_eq!(
            resolve_client_ip(&bad, Some(&peer("35.191.4.4")), &trusted).as_deref(),
            Some("203.0.113.9")
        );
    }

    #[test]
    fn socket_forms_and_mapped_addresses_are_canonical() {
        let trusted = cidrs(&["172.16.0.0/12"]);
        let h = headers(&[("X-Forwarded-For", "[2001:db8::2]:443")]);
        assert_eq!(
            resolve_client_ip(&h, Some(&peer("::ffff:172.18.0.26")), &trusted).as_deref(),
            Some("2001:db8::2")
        );
        let v4 = headers(&[("X-Forwarded-For", "203.0.113.7:51000")]);
        assert_eq!(
            resolve_client_ip(&v4, Some(&peer("172.18.0.26")), &trusted).as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn missing_socket_address_is_unknown() {
        let trusted = cidrs(&["0.0.0.0/0"]);
        let h = headers(&[("X-Forwarded-For", "203.0.113.7")]);
        assert_eq!(resolve_client_ip(&h, None, &trusted), None);
    }
}

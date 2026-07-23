// SPDX-License-Identifier: AGPL-3.0-or-later

//! SSRF (Server-Side Request Forgery) protection for inputlookup
//!
//! This module provides validation to prevent malicious URL access to internal
//! resources. It blocks:
//! - Private IP addresses (10.x, 172.16-31.x, 192.168.x)
//! - Localhost and loopback addresses
//! - Link-local addresses (169.254.x)
//! - Cloud metadata endpoints (169.254.169.254, etc.)
//! - Non-HTTP(S) schemes

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// Default timeout for the synchronous DNS resolution call run inside
/// `spawn_blocking`. Five seconds is the system-resolver default ceiling on
/// most platforms (musl/glibc retry budget); past this the resolver is
/// either down or being abused. Callers can override via `SsrfConfig`.
const DEFAULT_DNS_TIMEOUT_SECS: u64 = 5;

/// Errors that can occur during SSRF validation
#[derive(Debug, Error)]
pub enum SsrfError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Invalid URL scheme: {0}. Only http and https are allowed")]
    InvalidScheme(String),

    #[error("HTTP URLs are not allowed. Use https:// instead")]
    HttpNotAllowed,

    #[error("URL hostname is missing")]
    MissingHostname,

    #[error("Access to private IP address is blocked: {0}")]
    PrivateIpBlocked(IpAddr),

    #[error("Access to localhost is blocked")]
    LocalhostBlocked,

    #[error("Access to link-local address is blocked: {0}")]
    LinkLocalBlocked(IpAddr),

    #[error("Access to cloud metadata endpoint is blocked: {0}")]
    MetadataEndpointBlocked(String),

    #[error("DNS resolution failed for {0}: {1}")]
    DnsResolutionFailed(String, String),

    #[error("Domain is blocked: {0}")]
    DomainBlocked(String),

    #[error("Redirect to blocked destination: {0}")]
    BlockedRedirect(String),

    #[error("Failed to build outbound HTTP client: {0}")]
    ClientBuildFailed(String),
}

/// An IPv4/IPv6 CIDR block used for the SSRF egress allowlist. Parsed from
/// strings like `10.0.0.0/8`, `192.168.1.0/24`, `fd00::/8`, or a bare address
/// (`10.1.2.3` → `/32`, `fd00::1` → `/128`). Kept dependency-free (no `ipnet`).
#[derive(Debug, Clone)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    /// Parse `a.b.c.d/n`, `ipv6/n`, or a bare IP (implicit full-length prefix).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (ip_str, prefix_opt) = match s.split_once('/') {
            Some((ip, p)) => (ip.trim(), Some(p.trim())),
            None => (s, None),
        };
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| format!("invalid IP address in '{s}'"))?;
        let max: u8 = if ip.is_ipv4() { 32 } else { 128 };
        let prefix: u8 = match prefix_opt {
            Some(p) => p.parse().map_err(|_| format!("invalid prefix in '{s}'"))?,
            None => max,
        };
        if prefix > max {
            return Err(format!("prefix /{prefix} too large for {ip}"));
        }
        Ok(Self {
            network: ip,
            prefix,
        })
    }

    /// Whether `addr` falls inside this CIDR (family must match).
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix as u32);
                (u32::from(net) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix as u32);
                (u128::from(net) & mask) == (u128::from(a) & mask)
            }
            _ => false, // v4 CIDR never matches a v6 address or vice-versa
        }
    }
}

/// Configuration for SSRF validation
#[derive(Debug, Clone)]
pub struct SsrfConfig {
    /// Whether to allow plain HTTP (non-HTTPS) URLs
    pub allow_http: bool,
    /// Blocked domain patterns (e.g., "internal.company.com")
    /// These are explicitly blocked even if they resolve to public IPs
    pub blocked_domains: Vec<String>,
    /// Maximum number of redirects to follow
    pub max_redirects: u32,
    /// Timeout for the DNS resolution call inside `validate_with_dns`.
    /// Bounds the worst case when the system resolver is slow or
    /// unreachable so a single API request can't pin a runtime worker
    /// indefinitely. `None` means use the platform default
    /// (`DEFAULT_DNS_TIMEOUT_SECS`).
    pub dns_timeout: Option<Duration>,
    /// Allow loopback / RFC1918-private / link-local / IPv6-ULA targets.
    ///
    /// Default `false` (secure). Set this ONLY for endpoints an operator
    /// deliberately points at internal infrastructure (e.g. an on-prem /
    /// air-gapped LLM at a private address). Cloud-metadata endpoints
    /// (169.254.169.254 and metadata hostnames) and the unspecified/broadcast
    /// addresses stay blocked even when this is `true`, since they are never a
    /// legitimate target and are the highest-value SSRF objective.
    pub allow_private_networks: bool,
    /// Egress allowlist: specific private CIDRs that ARE permitted even though
    /// `allow_private_networks` is `false`. Rescues only the RFC1918 / CGNAT /
    /// IPv6-ULA ranges — loopback, link-local, cloud-metadata, and
    /// unspecified/broadcast/multicast stay blocked regardless (a resolved IP in
    /// one of those classes is never legitimate). Empty = no exceptions.
    pub allowed_cidrs: Vec<IpCidr>,
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            allow_http: false,
            blocked_domains: Vec::new(),
            max_redirects: 5,
            dns_timeout: None,
            allow_private_networks: false,
            allowed_cidrs: Vec::new(),
        }
    }
}

/// SSRF validator for URLs
pub struct SsrfValidator {
    config: SsrfConfig,
}

impl SsrfValidator {
    /// Create a new SSRF validator with the given configuration
    pub fn new(config: SsrfConfig) -> Self {
        Self { config }
    }

    /// Create a validator with default settings (blocks HTTP, private IPs, metadata endpoints)
    pub fn default_secure() -> Self {
        Self::new(SsrfConfig::default())
    }

    /// Validator for outbound fetches that may legitimately target a plain
    /// `http://` endpoint (internal/legacy threat feeds, on-prem S3-compatible
    /// object stores, IPinfo Lite mirrors, synthetic probes, scheduler feeds)
    /// while keeping every IP-class guard intact.
    ///
    /// Equivalent to `SsrfValidator::new(SsrfConfig { allow_http: true,
    /// ..Default::default() })`: loopback, RFC1918, link-local, CGNAT, IPv6
    /// loopback/ULA, and cloud-metadata targets stay blocked (no private-network
    /// opt-in here — see [`ai_base_url_validator`] for that). Use this instead
    /// of re-spelling the `allow_http: true` literal at every call site.
    pub fn http_allowed_validator() -> Self {
        Self::new(SsrfConfig {
            allow_http: true,
            ..Default::default()
        })
    }

    /// SSRF-validate `url_str` and resolve it to the exact socket addresses that
    /// are safe to pin into an outbound `reqwest` client.
    ///
    /// This is the shared form of the validate-then-pin sequence every
    /// SSRF-sensitive *fetcher* (not merely a pre-flight validator) needs, so
    /// the DNS-rebinding (TOCTOU) guard lives in exactly one place:
    ///
    /// 1. [`validate_with_dns`](Self::validate_with_dns) — parse, scheme /
    ///    blocked-domain / metadata-hostname checks, and a first DNS resolution
    ///    whose every answer must pass the IP-class checks. Rejects bad URLs
    ///    early.
    /// 2. If the host is an IP literal, it was already validated in step 1 and
    ///    `reqwest` dials it directly, so an **empty** addr vec is returned (no
    ///    `resolve_to_addrs` override is needed). `url::Url::host_str` returns
    ///    IPv6 literals without brackets (`::1`, not `[::1]`), so both forms are
    ///    caught here.
    /// 3. Otherwise re-resolve the host — bounded by the same DNS timeout as
    ///    `validate_with_dns` so a slow / poisoned resolver can't pin a worker —
    ///    and validate **every** address from this second lookup with
    ///    [`validate_ip_address`](Self::validate_ip_address). This catches a
    ///    resolver that flipped a public answer to an internal one between the
    ///    two lookups (the rebinding window).
    /// 4. Return the parsed [`Url`] plus the validated [`SocketAddr`]s. The
    ///    caller pins them into its client via
    ///    `ClientBuilder::resolve_to_addrs`, so the connection dials *these*
    ///    addresses and never a later, unvalidated DNS answer.
    ///
    /// The caller owns client construction and maps [`SsrfError`] to its own
    /// error type.
    pub async fn validate_and_resolve(
        &self,
        url_str: &str,
    ) -> Result<(Url, Vec<SocketAddr>), SsrfError> {
        // Step 1: full pre-flight validation incl. a first DNS resolution.
        let url = self.validate_with_dns(url_str).await?;

        let host = url.host_str().ok_or(SsrfError::MissingHostname)?;

        // Step 2: IP-literal hosts were already validated; reqwest dials them
        // directly, so no pinning override is required.
        if host.parse::<IpAddr>().is_ok() {
            return Ok((url, Vec::new()));
        }

        // Step 3: re-resolve and re-validate every address (rebinding guard).
        let port = url.port_or_known_default().unwrap_or(443);
        let host_owned = host.to_string();
        let resolve_target = format!("{}:{}", host_owned, port);
        let timeout = self
            .config
            .dns_timeout
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_DNS_TIMEOUT_SECS));

        let addrs: Vec<SocketAddr> =
            match tokio::time::timeout(timeout, tokio::net::lookup_host(resolve_target)).await {
                Ok(Ok(iter)) => iter.collect(),
                Ok(Err(e)) => {
                    return Err(SsrfError::DnsResolutionFailed(host_owned, e.to_string()));
                }
                Err(_elapsed) => {
                    return Err(SsrfError::DnsResolutionFailed(
                        host_owned,
                        format!("DNS resolution timed out after {:?}", timeout),
                    ));
                }
            };

        if addrs.is_empty() {
            return Err(SsrfError::DnsResolutionFailed(
                host_owned,
                "No addresses resolved".to_string(),
            ));
        }

        for addr in &addrs {
            self.validate_ip_address(addr.ip())?;
        }

        // Step 4: hand back the parsed URL + validated, pinnable addresses.
        Ok((url, addrs))
    }

    /// One-call form of [`validate_and_resolve`](Self::validate_and_resolve) +
    /// [`pin_resolved_addrs`]: SSRF-validate `url`, then build `builder` into a
    /// client PINNED to the validated resolved addresses (NAN-2018), returning
    /// the client and the parsed URL. The caller configures `builder`
    /// (timeout / redirect policy / TLS) and sets any auth headers per-request.
    /// Use this for per-request fetchers; long-lived clients over a stable host
    /// can pin once at construction via `pin_resolved_addrs` directly.
    pub async fn build_pinned_client(
        &self,
        url: &str,
        builder: reqwest::ClientBuilder,
    ) -> Result<(reqwest::Client, Url), SsrfError> {
        let (validated, addrs) = self.validate_and_resolve(url).await?;
        let client = pin_resolved_addrs(builder, &validated, &addrs)?
            .build()
            .map_err(|e| SsrfError::ClientBuildFailed(e.to_string()))?;
        Ok((client, validated))
    }

    /// Validate a URL string before fetching
    ///
    /// This performs URL parsing, scheme validation, and hostname validation.
    /// It does NOT perform DNS resolution - use `validate_with_dns` for that.
    pub fn validate_url(&self, url_str: &str) -> Result<Url, SsrfError> {
        // Parse the URL
        let url = Url::parse(url_str).map_err(|e| SsrfError::InvalidUrl(e.to_string()))?;

        // Validate scheme
        match url.scheme() {
            "https" => {}
            "http" => {
                if !self.config.allow_http {
                    return Err(SsrfError::HttpNotAllowed);
                }
            }
            other => return Err(SsrfError::InvalidScheme(other.to_string())),
        }

        // Check hostname exists
        let host = url.host_str().ok_or(SsrfError::MissingHostname)?;

        // Check for blocked domains
        self.check_blocked_domain(host)?;

        // Check for cloud metadata endpoints by hostname
        self.check_metadata_endpoint(host)?;

        // If the host is an IP address, validate it directly
        if let Some(ip) = self.parse_ip_from_host(host) {
            self.validate_ip(ip)?;
        }

        Ok(url)
    }

    /// Validate a URL with DNS resolution
    ///
    /// This resolves the hostname and validates all resolved IP addresses
    /// to prevent DNS rebinding attacks.
    ///
    /// `to_socket_addrs` is a blocking syscall, so we run it inside
    /// `tokio::task::spawn_blocking` to keep the runtime worker free, and
    /// wrap that in `tokio::time::timeout` so a slow/poisoned resolver can
    /// not pin a thread indefinitely. The timeout is configurable per
    /// validator via `SsrfConfig::dns_timeout`.
    pub async fn validate_with_dns(&self, url_str: &str) -> Result<Url, SsrfError> {
        let url = self.validate_url(url_str)?;

        let host = url.host_str().ok_or(SsrfError::MissingHostname)?;

        // If it's already an IP, we validated it in validate_url
        if self.parse_ip_from_host(host).is_some() {
            return Ok(url);
        }

        // Resolve hostname and validate all resolved IPs
        let port = url.port_or_known_default().unwrap_or(443);
        let host_with_port = format!("{}:{}", host, port);
        let host_owned = host.to_string();
        let timeout = self
            .config
            .dns_timeout
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_DNS_TIMEOUT_SECS));

        let resolve_fut = tokio::task::spawn_blocking(move || {
            host_with_port
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>())
        });

        let addrs: Vec<_> = match tokio::time::timeout(timeout, resolve_fut).await {
            Ok(Ok(Ok(addrs))) => addrs,
            Ok(Ok(Err(e))) => {
                return Err(SsrfError::DnsResolutionFailed(host_owned, e.to_string()));
            }
            Ok(Err(join_err)) => {
                return Err(SsrfError::DnsResolutionFailed(
                    host_owned,
                    format!("DNS task panicked: {}", join_err),
                ));
            }
            Err(_elapsed) => {
                return Err(SsrfError::DnsResolutionFailed(
                    host_owned,
                    format!("DNS resolution timed out after {:?}", timeout),
                ));
            }
        };

        if addrs.is_empty() {
            return Err(SsrfError::DnsResolutionFailed(
                host.to_string(),
                "No addresses resolved".to_string(),
            ));
        }

        // Validate each resolved IP
        for addr in &addrs {
            self.validate_ip(addr.ip())?;
        }

        Ok(url)
    }

    /// Validate a redirect target URL
    ///
    /// Used when following redirects to ensure we don't get redirected to a blocked destination.
    /// Resolves DNS and validates every resolved IP — same protections as `validate_with_dns` —
    /// so a redirect to a public-looking hostname that resolves to a private/link-local/metadata
    /// IP is rejected. Errors are wrapped as `BlockedRedirect` so callers can distinguish redirect
    /// rejections from initial-URL rejections.
    pub async fn validate_redirect(&self, redirect_url: &str) -> Result<Url, SsrfError> {
        self.validate_with_dns(redirect_url)
            .await
            .map_err(|e| SsrfError::BlockedRedirect(format!("{}: {}", redirect_url, e)))
    }

    /// Validate that an IP address is not loopback / private / link-local /
    /// IPv6 ULA / a known cloud metadata endpoint.
    ///
    /// Exposed so callers that resolve DNS themselves (e.g. to pin a
    /// connection to a specific IP and prevent DNS-rebinding between
    /// validation and connect) can re-validate the addresses they intend to
    /// use, using exactly the same rules as `validate_with_dns`.
    pub fn validate_ip_address(&self, ip: IpAddr) -> Result<(), SsrfError> {
        self.validate_ip(ip)
    }

    /// Parse an IP address from a hostname string
    fn parse_ip_from_host(&self, host: &str) -> Option<IpAddr> {
        // Try parsing as IPv4
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(IpAddr::V4(ip));
        }
        // Try parsing as IPv6 (may be in brackets)
        let host_clean = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host_clean.parse::<Ipv6Addr>() {
            return Some(IpAddr::V6(ip));
        }
        None
    }

    /// Validate an IP address is not private/blocked
    fn validate_ip(&self, ip: IpAddr) -> Result<(), SsrfError> {
        match ip {
            IpAddr::V4(ipv4) => self.validate_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.validate_ipv6(ipv6),
        }
    }

    /// Validate an IPv4 address
    fn validate_ipv4(&self, ip: Ipv4Addr) -> Result<(), SsrfError> {
        let octets = ip.octets();

        // Cloud metadata endpoint — ALWAYS blocked, even with allow_private_networks.
        // (169.254.169.254 is a subset of link-local but is never a legitimate target.)
        if octets == [169, 254, 169, 254] {
            return Err(SsrfError::MetadataEndpointBlocked(ip.to_string()));
        }

        // Unspecified (0.0.0.0) / broadcast — never a valid target, blocked always.
        if ip == Ipv4Addr::UNSPECIFIED || ip == Ipv4Addr::BROADCAST {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }

        // Multicast (224.0.0.0/4) and documentation / TEST-NET ranges
        // (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) — never a valid
        // outbound target, blocked always (even under allow_private_networks).
        if ip.is_multicast() || ip.is_documentation() {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }

        // The remaining loopback / private / link-local ranges are permitted
        // only when an operator has explicitly opted in (e.g. on-prem LLM on a
        // private network). Default is to block them.
        if self.config.allow_private_networks {
            return Ok(());
        }

        // A resolved IP inside an egress-allowlisted CIDR bypasses ONLY the
        // private-range blocks below (10/8, 172.16/12, 192.168/16, CGNAT).
        // Loopback and link-local are never allowlist-rescued, and the
        // metadata/unspecified/broadcast/multicast blocks above already returned.
        let allowlisted = self
            .config
            .allowed_cidrs
            .iter()
            .any(|c| c.contains(IpAddr::V4(ip)));

        // Localhost (127.0.0.0/8) — never allowlist-rescued.
        if octets[0] == 127 {
            return Err(SsrfError::LocalhostBlocked);
        }
        // 10.0.0.0/8
        if octets[0] == 10 && !allowlisted {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }
        // 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) && !allowlisted {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 && !allowlisted {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }
        // CGNAT / shared address space (100.64.0.0/10) — routes to carrier /
        // internal infrastructure, treat like private.
        if octets[0] == 100 && (octets[1] & 0xC0) == 64 && !allowlisted {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }
        // Link-local (169.254.0.0/16); metadata already handled above.
        // Never allowlist-rescued (metadata is a subset of this range).
        if octets[0] == 169 && octets[1] == 254 {
            return Err(SsrfError::LinkLocalBlocked(IpAddr::V4(ip)));
        }

        Ok(())
    }

    /// Validate an IPv6 address
    fn validate_ipv6(&self, ip: Ipv6Addr) -> Result<(), SsrfError> {
        // IPv4-mapped addresses (::ffff:x.x.x.x) — defer to the IPv4 rules so
        // metadata + allow_private_networks are handled in one place.
        if let Some(ipv4) = ip.to_ipv4_mapped() {
            return self.validate_ipv4(ipv4);
        }

        // Unspecified (::) / multicast (ff00::/8) — never a valid target, blocked always.
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V6(ip)));
        }

        // Loopback / link-local / ULA permitted only with explicit opt-in.
        if self.config.allow_private_networks {
            return Ok(());
        }

        let allowlisted = self
            .config
            .allowed_cidrs
            .iter()
            .any(|c| c.contains(IpAddr::V6(ip)));

        // Loopback (::1) — never allowlist-rescued.
        if ip.is_loopback() {
            return Err(SsrfError::LocalhostBlocked);
        }

        let segments = ip.segments();
        // Link-local (fe80::/10) — never allowlist-rescued.
        if (segments[0] & 0xffc0) == 0xfe80 {
            return Err(SsrfError::LinkLocalBlocked(IpAddr::V6(ip)));
        }
        // Unique local addresses (fc00::/7) — similar to private IPv4; rescuable
        // via the egress allowlist.
        if (segments[0] & 0xfe00) == 0xfc00 && !allowlisted {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V6(ip)));
        }

        Ok(())
    }

    /// Check if hostname matches a blocked domain pattern
    fn check_blocked_domain(&self, host: &str) -> Result<(), SsrfError> {
        let host_lower = host.to_lowercase();

        for blocked in &self.config.blocked_domains {
            let blocked_lower = blocked.to_lowercase();
            // Exact match or subdomain match
            if host_lower == blocked_lower || host_lower.ends_with(&format!(".{}", blocked_lower)) {
                return Err(SsrfError::DomainBlocked(host.to_string()));
            }
        }

        Ok(())
    }

    /// Check for cloud metadata endpoint hostnames
    fn check_metadata_endpoint(&self, host: &str) -> Result<(), SsrfError> {
        let host_lower = host.to_lowercase();

        // AWS metadata endpoint
        if host_lower == "169.254.169.254" {
            return Err(SsrfError::MetadataEndpointBlocked(host.to_string()));
        }

        // GCP metadata endpoint (and its short alias)
        if host_lower == "metadata.google.internal" || host_lower == "metadata.goog" {
            return Err(SsrfError::MetadataEndpointBlocked(host.to_string()));
        }

        // DNS-name aliases that resolve to the metadata IP (e.g. nip.io wildcard)
        if host_lower == "169.254.169.254.nip.io" {
            return Err(SsrfError::MetadataEndpointBlocked(host.to_string()));
        }

        // Azure metadata endpoint
        if host_lower == "169.254.169.254" {
            return Err(SsrfError::MetadataEndpointBlocked(host.to_string()));
        }

        // AWS EC2 metadata via hostname
        if host_lower == "instance-data" || host_lower == "instance-data." {
            return Err(SsrfError::MetadataEndpointBlocked(host.to_string()));
        }

        // Kubernetes metadata
        if host_lower == "kubernetes.default.svc" || host_lower.ends_with(".kubernetes.default.svc")
        {
            return Err(SsrfError::MetadataEndpointBlocked(host.to_string()));
        }

        Ok(())
    }
}

/// Env var that opts an operator into private/loopback AI provider endpoints.
pub const ALLOW_PRIVATE_AI_ENDPOINTS_ENV: &str = "NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS";

/// Whether the operator has opted into letting AI provider `base_url`s point at
/// private/loopback/internal addresses (on-prem / air-gapped LLM deployments,
/// NAN-1207). Off by default. Cloud-metadata endpoints stay blocked regardless.
///
/// This is read from the environment — deliberately NOT from per-provider config
/// — so that an admin who can set `base_url` through the API cannot also flip the
/// allowance and reach internal services.
pub fn private_ai_endpoints_allowed() -> bool {
    matches!(
        std::env::var(ALLOW_PRIVATE_AI_ENDPOINTS_ENV)
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Ok("1" | "true" | "on" | "yes")
    )
}

/// SSRF validator for an admin-configured AI provider `base_url`.
///
/// Secure by default: blocks loopback/private/link-local/metadata and non-http(s)
/// schemes. `allow_http` is on because on-prem LLM endpoints are commonly plain
/// HTTP behind a network boundary. Private targets are permitted only when
/// [`private_ai_endpoints_allowed`] is set; metadata endpoints are never allowed.
pub fn ai_base_url_validator() -> SsrfValidator {
    SsrfValidator::new(SsrfConfig {
        allow_http: true,
        allow_private_networks: private_ai_endpoints_allowed(),
        ..Default::default()
    })
}

/// Shared redirect policy for outbound clients (NAN-1369): follow at most a few
/// hops, and refuse to follow a redirect to a non-https target or to a
/// private/metadata IP literal — the common SSRF-via-redirect bypass of a
/// pre-request URL check. Hostname redirects are still followed (not re-resolved
/// here; documented residual). IP-literal checks reuse `SsrfValidator`. Used by
/// identity-sync and OIDC discovery/JWKS clients, which legitimately redirect by
/// hostname (so `Policy::none` would be too strict).
pub fn restricted_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 4 {
            return attempt.stop();
        }
        let url = attempt.url();
        if url.scheme() != "https" {
            return attempt.error("SSRF guard: refusing redirect to non-https target");
        }
        if let Some(host) = url.host_str() {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if SsrfValidator::default_secure()
                    .validate_ip_address(ip)
                    .is_err()
                {
                    return attempt.error("SSRF guard: refusing redirect to disallowed IP literal");
                }
            }
        }
        attempt.follow()
    })
}

/// Pin an outbound `reqwest` client builder to the SSRF-validated `addrs` for
/// `validated`'s host, closing the DNS-rebinding TOCTOU (NAN-2018): the built
/// client dials ONLY these pre-validated addresses instead of re-resolving the
/// hostname at connect time. The hostname is still used for TLS SNI and the
/// `Host` header. An empty `addrs` — an IP-literal host, already validated — is
/// a no-op: reqwest dials the literal directly with no rebinding window.
///
/// Pair with [`SsrfValidator::validate_and_resolve`] (or use the one-call
/// [`SsrfValidator::build_pinned_client`]):
/// ```ignore
/// let (url, addrs) = validator.validate_and_resolve(raw).await?;
/// let client = pin_resolved_addrs(reqwest::Client::builder().timeout(t), &url, &addrs)?
///     .build()?;
/// ```
pub fn pin_resolved_addrs(
    builder: reqwest::ClientBuilder,
    validated: &Url,
    addrs: &[SocketAddr],
) -> Result<reqwest::ClientBuilder, SsrfError> {
    if addrs.is_empty() {
        return Ok(builder);
    }
    let host = validated.host_str().ok_or(SsrfError::MissingHostname)?;
    Ok(builder.resolve_to_addrs(host, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator() -> SsrfValidator {
        SsrfValidator::default_secure()
    }

    fn validator_with_http() -> SsrfValidator {
        SsrfValidator::new(SsrfConfig {
            allow_http: true,
            ..Default::default()
        })
    }

    fn validator_allow_private() -> SsrfValidator {
        SsrfValidator::new(SsrfConfig {
            allow_http: true,
            allow_private_networks: true,
            ..Default::default()
        })
    }

    #[test]
    fn test_allow_private_permits_loopback_and_rfc1918() {
        // The on-prem / air-gapped opt-in (NAN-1207): private LLM endpoints are
        // reachable when an operator has explicitly allowed it.
        let v = validator_allow_private();
        assert!(v.validate_url("http://127.0.0.1:39999/v1").is_ok());
        assert!(v.validate_url("http://10.0.0.5:8000/v1").is_ok());
        assert!(v.validate_url("http://192.168.1.10/v1").is_ok());
    }

    #[test]
    fn test_allow_private_still_blocks_metadata() {
        // Cloud metadata is never a legitimate AI endpoint and stays blocked
        // even with the private-network opt-in — it's the highest-value target.
        let v = validator_allow_private();
        assert!(matches!(
            v.validate_url("http://169.254.169.254/latest/meta-data/"),
            Err(SsrfError::MetadataEndpointBlocked(_))
        ));
        assert!(matches!(
            v.validate_url("http://metadata.google.internal/"),
            Err(SsrfError::MetadataEndpointBlocked(_))
        ));
        // A non-metadata link-local address is allowed under the opt-in.
        assert!(v.validate_url("http://169.254.10.10/").is_ok());
    }

    #[test]
    fn test_default_still_blocks_private_after_restructure() {
        // Guard against regressions from the allow_private restructure: the
        // secure default must still reject loopback / private / link-local.
        let v = validator_with_http();
        assert!(matches!(
            v.validate_url("http://127.0.0.1/"),
            Err(SsrfError::LocalhostBlocked)
        ));
        assert!(matches!(
            v.validate_url("http://10.0.0.1/"),
            Err(SsrfError::PrivateIpBlocked(_))
        ));
        assert!(matches!(
            v.validate_url("http://169.254.10.10/"),
            Err(SsrfError::LinkLocalBlocked(_))
        ));
        assert!(matches!(
            v.validate_url("http://169.254.169.254/"),
            Err(SsrfError::MetadataEndpointBlocked(_))
        ));
    }

    #[test]
    fn test_cgnat_blocked_by_default_allowed_on_optin() {
        // 100.64.0.0/10 is shared/CGNAT space that routes to carrier/internal
        // infra — blocked like private by default (NAN-1369), allowed under opt-in.
        let v = validator_with_http();
        assert!(matches!(
            v.validate_url("http://100.64.0.1/"),
            Err(SsrfError::PrivateIpBlocked(_))
        ));
        assert!(matches!(
            v.validate_url("http://100.127.255.254/"),
            Err(SsrfError::PrivateIpBlocked(_))
        ));
        // 100.63.x and 100.128.x are public (outside /10) — not blocked.
        assert!(v.validate_url("http://100.63.0.1/").is_ok());
        assert!(v.validate_url("http://100.128.0.1/").is_ok());
        // Allowed under the on-prem opt-in.
        assert!(validator_allow_private()
            .validate_url("http://100.64.0.1/")
            .is_ok());
    }

    #[test]
    fn test_extra_metadata_hostnames_blocked() {
        let v = validator_with_http();
        for h in ["metadata.goog", "169.254.169.254.nip.io"] {
            assert!(
                matches!(
                    v.validate_url(&format!("http://{h}/")),
                    Err(SsrfError::MetadataEndpointBlocked(_))
                ),
                "expected {h} blocked"
            );
        }
    }

    #[test]
    fn test_ai_base_url_validator_blocks_loopback_by_default() {
        // With the opt-in env unset, the shared AI validator is secure: a
        // loopback base_url is rejected (this is the reported SSRF, NAN-1368).
        let v = ai_base_url_validator();
        assert!(v.validate_url("http://127.0.0.1:39999/v1").is_err());
        // A public endpoint is still fine.
        assert!(v.validate_url("https://api.openai.com/v1").is_ok());
    }

    #[test]
    fn test_valid_https_url() {
        let v = validator();
        assert!(v.validate_url("https://api.example.com/data.json").is_ok());
    }

    #[test]
    fn test_http_blocked_by_default() {
        let v = validator();
        let result = v.validate_url("http://api.example.com/data.json");
        assert!(matches!(result, Err(SsrfError::HttpNotAllowed)));
    }

    #[test]
    fn test_http_allowed_when_configured() {
        let v = validator_with_http();
        assert!(v.validate_url("http://api.example.com/data.json").is_ok());
    }

    #[test]
    fn test_invalid_scheme() {
        let v = validator();
        let result = v.validate_url("ftp://ftp.example.com/file.txt");
        assert!(matches!(result, Err(SsrfError::InvalidScheme(_))));
    }

    #[test]
    #[ignore = "localhost resolution behavior varies by environment"]
    fn test_localhost_blocked() {
        let v = validator_with_http();

        assert!(matches!(
            v.validate_url("http://localhost/"),
            Err(SsrfError::LocalhostBlocked)
                | Err(SsrfError::PrivateIpBlocked(_))
                | Err(SsrfError::DnsResolutionFailed(_, _))
        ));

        assert!(matches!(
            v.validate_url("http://127.0.0.1/"),
            Err(SsrfError::LocalhostBlocked)
        ));

        assert!(matches!(
            v.validate_url("http://127.0.0.55/"),
            Err(SsrfError::LocalhostBlocked)
        ));
    }

    #[test]
    fn test_private_ip_blocked() {
        let v = validator_with_http();

        // 10.x.x.x
        assert!(matches!(
            v.validate_url("http://10.0.0.1/"),
            Err(SsrfError::PrivateIpBlocked(_))
        ));

        // 172.16-31.x.x
        assert!(matches!(
            v.validate_url("http://172.16.0.1/"),
            Err(SsrfError::PrivateIpBlocked(_))
        ));
        assert!(matches!(
            v.validate_url("http://172.31.255.255/"),
            Err(SsrfError::PrivateIpBlocked(_))
        ));

        // 172.15 is NOT private
        assert!(v.validate_url("http://172.15.0.1/").is_ok());

        // 192.168.x.x
        assert!(matches!(
            v.validate_url("http://192.168.1.1/"),
            Err(SsrfError::PrivateIpBlocked(_))
        ));
    }

    #[test]
    fn test_link_local_blocked() {
        let v = validator_with_http();

        assert!(matches!(
            v.validate_url("http://169.254.1.1/"),
            Err(SsrfError::LinkLocalBlocked(_))
        ));
    }

    #[test]
    fn test_metadata_endpoint_blocked() {
        let v = validator_with_http();

        // AWS/Azure metadata IP
        assert!(matches!(
            v.validate_url("http://169.254.169.254/latest/meta-data/"),
            Err(SsrfError::MetadataEndpointBlocked(_))
        ));

        // GCP metadata hostname
        assert!(matches!(
            v.validate_url("http://metadata.google.internal/computeMetadata/v1/"),
            Err(SsrfError::MetadataEndpointBlocked(_))
        ));
    }

    #[test]
    fn test_blocked_domain() {
        let v = SsrfValidator::new(SsrfConfig {
            allow_http: true,
            blocked_domains: vec!["internal.company.com".to_string()],
            ..Default::default()
        });

        // Exact match
        assert!(matches!(
            v.validate_url("http://internal.company.com/"),
            Err(SsrfError::DomainBlocked(_))
        ));

        // Subdomain match
        assert!(matches!(
            v.validate_url("http://api.internal.company.com/"),
            Err(SsrfError::DomainBlocked(_))
        ));

        // Different domain is allowed
        assert!(v.validate_url("http://external.company.com/").is_ok());
    }

    #[test]
    fn test_ipv6_loopback() {
        let v = validator_with_http();
        assert!(matches!(
            v.validate_url("http://[::1]/"),
            Err(SsrfError::LocalhostBlocked)
        ));
    }

    #[test]
    fn test_public_ips_allowed() {
        let v = validator_with_http();

        // Google DNS
        assert!(v.validate_url("http://8.8.8.8/").is_ok());

        // Cloudflare DNS
        assert!(v.validate_url("http://1.1.1.1/").is_ok());
    }

    // NAN-654: validate_redirect previously called only validate_url, which does
    // not resolve DNS. A redirect to a public-looking hostname that resolved to
    // a private/link-local/metadata IP would slip through. The function now
    // delegates to validate_with_dns and wraps errors as BlockedRedirect.

    #[tokio::test]
    async fn test_redirect_private_ip_blocked() {
        let v = validator_with_http();

        // 10.0.0.0/8
        let result = v.validate_redirect("http://10.0.0.1/foo").await;
        assert!(
            matches!(result, Err(SsrfError::BlockedRedirect(_))),
            "expected BlockedRedirect, got {:?}",
            result
        );

        // 192.168.0.0/16
        let result = v.validate_redirect("http://192.168.1.5/").await;
        assert!(matches!(result, Err(SsrfError::BlockedRedirect(_))));

        // 172.16.0.0/12
        let result = v.validate_redirect("http://172.20.0.1/").await;
        assert!(matches!(result, Err(SsrfError::BlockedRedirect(_))));
    }

    #[tokio::test]
    async fn test_redirect_loopback_blocked() {
        let v = validator_with_http();

        let result = v.validate_redirect("http://127.0.0.1/").await;
        assert!(matches!(result, Err(SsrfError::BlockedRedirect(_))));

        let result = v.validate_redirect("http://[::1]/").await;
        assert!(matches!(result, Err(SsrfError::BlockedRedirect(_))));
    }

    #[tokio::test]
    async fn test_redirect_metadata_endpoint_blocked() {
        let v = validator_with_http();

        let result = v
            .validate_redirect("http://169.254.169.254/latest/meta-data/")
            .await;
        assert!(matches!(result, Err(SsrfError::BlockedRedirect(_))));
    }

    #[tokio::test]
    async fn test_redirect_link_local_blocked() {
        let v = validator_with_http();

        let result = v.validate_redirect("http://169.254.1.1/").await;
        assert!(matches!(result, Err(SsrfError::BlockedRedirect(_))));
    }

    #[tokio::test]
    async fn test_redirect_invalid_scheme_blocked() {
        let v = validator();

        let result = v.validate_redirect("ftp://ftp.example.com/").await;
        assert!(matches!(result, Err(SsrfError::BlockedRedirect(_))));
    }

    #[tokio::test]
    async fn test_redirect_error_wraps_inner() {
        // The wrapping format should make the inner cause discoverable in logs.
        let v = validator_with_http();
        let err = v
            .validate_redirect("http://10.0.0.1/")
            .await
            .expect_err("expected redirect rejection");
        let msg = err.to_string();
        assert!(
            msg.contains("10.0.0.1"),
            "expected redirect URL in error: {msg}"
        );
        assert!(
            msg.contains("private") || msg.contains("Private"),
            "expected inner cause referenced in error: {msg}"
        );
    }

    // NAN-654: this test exercises the DNS-resolution path that the old
    // implementation bypassed. localhost resolution behavior is environment-
    // dependent (matches existing `test_localhost_blocked`), so it's gated
    // behind #[ignore] for manual/CI-with-DNS verification.
    #[tokio::test]
    #[ignore = "requires DNS resolver that maps localhost -> 127.0.0.1; run manually"]
    async fn test_redirect_hostname_resolves_to_private_ip_blocked() {
        let v = validator_with_http();

        let result = v.validate_redirect("http://localhost/").await;
        assert!(
            matches!(result, Err(SsrfError::BlockedRedirect(_))),
            "expected BlockedRedirect for localhost, got {:?}",
            result
        );
    }

    // NAN-680: a misconfigured/poisoned resolver must not pin a runtime
    // worker indefinitely. Use `.invalid` (RFC 6761 reserved TLD that is
    // guaranteed never to resolve) and a tiny timeout — the validator must
    // return DnsResolutionFailed within that window. spawn_blocking works
    // on the current_thread runtime too (Tokio always provides a separate
    // blocking pool), so no special flavor is needed.
    #[tokio::test]
    async fn dns_resolution_timeout_returns_quickly() {
        let v = SsrfValidator::new(SsrfConfig {
            allow_http: true,
            blocked_domains: Vec::new(),
            max_redirects: 0,
            dns_timeout: Some(Duration::from_millis(50)),
            allow_private_networks: false,
            ..Default::default()
        });

        let start = std::time::Instant::now();
        let res = v
            .validate_with_dns("https://nanosiem-ssrf-test.invalid")
            .await;
        let elapsed = start.elapsed();

        assert!(
            matches!(res, Err(SsrfError::DnsResolutionFailed(_, _))),
            "expected DnsResolutionFailed, got {:?}",
            res
        );
        // 5s slack — we're really checking we don't pay the full system
        // resolver budget (~15s on most platforms).
        assert!(
            elapsed < Duration::from_secs(5),
            "validate_with_dns hung past timeout: took {:?}",
            elapsed
        );
    }

    // NAN-1617: the shared `validate_and_resolve` helper is the single
    // TOCTOU/SSRF guard behind every outbound fetcher (enrichment, synthetic
    // probes, tiering S3). These assert no IP-class check was lost when the
    // three hand-rolled copies were collapsed into it.
    #[tokio::test]
    async fn validate_and_resolve_rejects_blocked_ip_literals() {
        let v = SsrfValidator::http_allowed_validator();

        // Cloud metadata — the highest-value SSRF objective.
        assert!(
            matches!(
                v.validate_and_resolve("http://169.254.169.254/latest/meta-data/")
                    .await,
                Err(SsrfError::MetadataEndpointBlocked(_))
            ),
            "metadata endpoint must be rejected"
        );

        // Loopback.
        assert!(
            matches!(
                v.validate_and_resolve("http://127.0.0.1:8080/").await,
                Err(SsrfError::LocalhostBlocked)
            ),
            "loopback must be rejected"
        );

        // RFC1918 private.
        assert!(
            matches!(
                v.validate_and_resolve("http://10.0.0.5/internal").await,
                Err(SsrfError::PrivateIpBlocked(_))
            ),
            "RFC1918 private address must be rejected"
        );

        // Link-local (non-metadata).
        assert!(
            matches!(
                v.validate_and_resolve("http://169.254.1.1/").await,
                Err(SsrfError::LinkLocalBlocked(_))
            ),
            "link-local address must be rejected"
        );
    }

    #[tokio::test]
    async fn validate_and_resolve_allows_public_ip_literal_with_empty_pin() {
        // A public IP literal is allowed and needs no resolve_to_addrs override
        // (reqwest dials the literal): the documented empty-Vec contract.
        let v = SsrfValidator::http_allowed_validator();
        let (url, addrs) = v
            .validate_and_resolve("http://8.8.8.8/")
            .await
            .expect("public IP literal must be allowed");
        assert_eq!(url.host_str(), Some("8.8.8.8"));
        assert!(
            addrs.is_empty(),
            "IP-literal host must return no pinned addrs (reqwest dials the literal)"
        );
    }

    // Network-dependent: confirms an allowed *hostname* returns non-empty,
    // pre-validated pinned addrs (the rebinding guard's positive path). Ignored
    // by default because it needs a working resolver + egress.
    #[tokio::test]
    #[ignore = "requires DNS + egress; run manually"]
    async fn validate_and_resolve_pins_resolved_addrs_for_public_host() {
        let v = SsrfValidator::http_allowed_validator();
        let (_url, addrs) = v
            .validate_and_resolve("https://one.one.one.one/")
            .await
            .expect("public host must resolve and validate");
        assert!(!addrs.is_empty(), "expected pinned addrs for a hostname");
        for addr in &addrs {
            v.validate_ip_address(addr.ip())
                .expect("every pinned addr must pass the IP-class checks");
        }
    }

    // ---- Egress allowlist (NAN-1633) --------------------------------------

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn allowlisted(cidrs: &[&str]) -> SsrfValidator {
        SsrfValidator::new(SsrfConfig {
            allow_http: true,
            allowed_cidrs: cidrs.iter().map(|c| IpCidr::parse(c).unwrap()).collect(),
            ..Default::default()
        })
    }

    #[test]
    fn ipcidr_parse_and_contains() {
        let c = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(c.contains(ip("10.255.255.255")));
        assert!(!c.contains(ip("11.0.0.1")));
        // bare IP => host route
        let host = IpCidr::parse("192.168.5.7").unwrap();
        assert!(host.contains(ip("192.168.5.7")));
        assert!(!host.contains(ip("192.168.5.8")));
        // v4 CIDR never matches a v6 addr
        assert!(!c.contains(ip("::1")));
        // IPv6 ULA
        let ula = IpCidr::parse("fd00::/8").unwrap();
        assert!(ula.contains(ip("fd12:3456::1")));
        assert!(!ula.contains(ip("fe80::1")));
    }

    #[test]
    fn ipcidr_parse_rejects_garbage() {
        assert!(IpCidr::parse("not-an-ip").is_err());
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("::1/129").is_err());
    }

    #[test]
    fn allowlist_rescues_only_listed_private_ranges() {
        let v = allowlisted(&["10.0.0.0/8", "192.168.5.0/24"]);
        // In-allowlist private IPs are permitted...
        assert!(v.validate_ip_address(ip("10.1.2.3")).is_ok());
        assert!(v.validate_ip_address(ip("192.168.5.20")).is_ok());
        // ...but private IPs OUTSIDE the allowlist stay blocked.
        assert!(v.validate_ip_address(ip("192.168.9.9")).is_err());
        assert!(v.validate_ip_address(ip("172.16.0.1")).is_err());
    }

    #[test]
    fn allowlist_never_rescues_loopback_linklocal_or_metadata() {
        // Even if an operator (mistakenly) allowlists these ranges, the
        // higher-severity classes must stay blocked.
        let v = allowlisted(&["127.0.0.0/8", "169.254.0.0/16"]);
        assert!(matches!(
            v.validate_ip_address(ip("127.0.0.1")),
            Err(SsrfError::LocalhostBlocked)
        ));
        assert!(matches!(
            v.validate_ip_address(ip("169.254.1.1")),
            Err(SsrfError::LinkLocalBlocked(_))
        ));
        // Cloud metadata is always blocked.
        assert!(matches!(
            v.validate_ip_address(ip("169.254.169.254")),
            Err(SsrfError::MetadataEndpointBlocked(_))
        ));
    }

    #[test]
    fn allowlist_rescues_ipv6_ula_not_loopback() {
        let v = allowlisted(&["fd00::/8"]);
        assert!(v.validate_ip_address(ip("fd12:3456::99")).is_ok());
        assert!(matches!(
            v.validate_ip_address(ip("::1")),
            Err(SsrfError::LocalhostBlocked)
        ));
    }

    #[test]
    fn empty_allowlist_is_secure_default() {
        let v = SsrfValidator::http_allowed_validator();
        assert!(v.validate_ip_address(ip("10.1.2.3")).is_err());
        assert!(v.validate_ip_address(ip("192.168.1.1")).is_err());
    }

    // NAN-2018: shared IP-pinning helper.

    #[test]
    fn pin_resolved_addrs_empty_is_noop_and_builds() {
        // IP-literal host path: no addrs to pin, builder must still build.
        let url = Url::parse("https://93.184.216.34/").unwrap();
        let builder = pin_resolved_addrs(reqwest::Client::builder(), &url, &[]).unwrap();
        assert!(builder.build().is_ok());
    }

    #[test]
    fn pin_resolved_addrs_with_addrs_builds_pinned_client() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let url = Url::parse("https://example.com/").unwrap();
        let addrs = [SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443)];
        let builder = pin_resolved_addrs(reqwest::Client::builder(), &url, &addrs).unwrap();
        assert!(builder.build().is_ok());
    }

    #[tokio::test]
    async fn build_pinned_client_rejects_blocked_ip_literal() {
        // The validate step inside build_pinned_client must reject a blocked
        // literal before any client is built (no DNS needed).
        let v = validator();
        assert!(v
            .build_pinned_client("https://169.254.169.254/", reqwest::Client::builder())
            .await
            .is_err());
        assert!(v
            .build_pinned_client("https://127.0.0.1/", reqwest::Client::builder())
            .await
            .is_err());
    }
}

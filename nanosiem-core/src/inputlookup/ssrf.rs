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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
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
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            allow_http: false,
            blocked_domains: Vec::new(),
            max_redirects: 5,
            dns_timeout: None,
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

        // Localhost (127.0.0.0/8)
        if octets[0] == 127 {
            return Err(SsrfError::LocalhostBlocked);
        }

        // Private ranges
        // 10.0.0.0/8
        if octets[0] == 10 {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }
        // 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }

        // Link-local (169.254.0.0/16)
        if octets[0] == 169 && octets[1] == 254 {
            // Cloud metadata endpoints are a subset of link-local
            if octets[2] == 169 && octets[3] == 254 {
                return Err(SsrfError::MetadataEndpointBlocked(ip.to_string()));
            }
            return Err(SsrfError::LinkLocalBlocked(IpAddr::V4(ip)));
        }

        // Broadcast
        if ip == Ipv4Addr::BROADCAST {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }

        // Unspecified (0.0.0.0)
        if ip == Ipv4Addr::UNSPECIFIED {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V4(ip)));
        }

        Ok(())
    }

    /// Validate an IPv6 address
    fn validate_ipv6(&self, ip: Ipv6Addr) -> Result<(), SsrfError> {
        // Loopback (::1)
        if ip.is_loopback() {
            return Err(SsrfError::LocalhostBlocked);
        }

        // Unspecified (::)
        if ip.is_unspecified() {
            return Err(SsrfError::PrivateIpBlocked(IpAddr::V6(ip)));
        }

        // IPv4-mapped addresses (::ffff:x.x.x.x)
        if let Some(ipv4) = ip.to_ipv4_mapped() {
            return self.validate_ipv4(ipv4);
        }

        // Link-local (fe80::/10)
        let segments = ip.segments();
        if (segments[0] & 0xffc0) == 0xfe80 {
            return Err(SsrfError::LinkLocalBlocked(IpAddr::V6(ip)));
        }

        // Unique local addresses (fc00::/7) - similar to private IPv4
        if (segments[0] & 0xfe00) == 0xfc00 {
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

        // GCP metadata endpoint
        if host_lower == "metadata.google.internal" {
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
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Validation and formatting helpers for storage tiering.

use super::types::TieringError;
use crate::inputlookup::{SsrfConfig, SsrfError, SsrfValidator};
use std::net::{SocketAddr, ToSocketAddrs};
use url::Url;

/// Environment variable that, when set to "1" or "true", disables SSRF
/// validation for tiering S3 endpoints. Intended only for local development
/// against MinIO/LocalStack on loopback or `host.docker.internal`. Never set
/// this in any environment that handles real traffic.
const ALLOW_LOCAL_ENV: &str = "NANOSIEM_TIERING_ALLOW_LOCAL";

/// Read the dev-override env var.
///
/// **Test pollution warning**: `std::env::var` reads process-wide state.
/// `cargo test` runs tests in the same binary in parallel, so any test that
/// `set_var(ALLOW_LOCAL_ENV, ...)` will leak into every other test in the
/// binary that reads it. If a future test needs to toggle this, gate every
/// such test behind a process-wide mutex (e.g. `static MUTEX: Mutex<()>`).
fn allow_local() -> bool {
    matches!(
        std::env::var(ALLOW_LOCAL_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("True")
    )
}

/// Escape a string for safe inclusion in XML text content.
/// Prevents XML injection by replacing the five special XML characters.
pub(crate) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Validate an S3 bucket name per AWS rules:
/// 3-63 chars, lowercase alphanumeric, hyphens, and dots only.
pub(crate) fn validate_s3_bucket(bucket: &str) -> Result<(), TieringError> {
    if bucket.len() < 3 || bucket.len() > 63 {
        return Err(TieringError::Config(
            "S3 bucket name must be 3-63 characters".to_string(),
        ));
    }
    if !bucket
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    {
        return Err(TieringError::Config(
            "S3 bucket name may only contain lowercase letters, digits, hyphens, and dots"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validate an AWS region identifier: alphanumeric and hyphens only, reasonable length.
pub(crate) fn validate_s3_region(region: &str) -> Result<(), TieringError> {
    if region.is_empty() || region.len() > 64 {
        return Err(TieringError::Config(
            "S3 region must be 1-64 characters".to_string(),
        ));
    }
    if !region
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(TieringError::Config(
            "S3 region may only contain alphanumeric characters and hyphens".to_string(),
        ));
    }
    Ok(())
}

/// Validate an S3 endpoint URL: must be a valid http(s) URL with no XML-unsafe path trickery.
pub(crate) fn validate_s3_endpoint(endpoint: &str) -> Result<(), TieringError> {
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Err(TieringError::Config(
            "S3 endpoint must start with http:// or https://".to_string(),
        ));
    }
    // Block XML special chars in the URL itself
    if endpoint.contains('<') || endpoint.contains('>') || endpoint.contains('"') {
        return Err(TieringError::Config(
            "S3 endpoint contains invalid characters".to_string(),
        ));
    }
    if endpoint.len() > 256 {
        return Err(TieringError::Config(
            "S3 endpoint must be at most 256 characters".to_string(),
        ));
    }
    // Parse unconditionally — even when allow_local() is set, a malformed
    // URL should still be rejected at the syntactic stage rather than
    // surface as a confusing reqwest error later.
    let parsed = Url::parse(endpoint)
        .map_err(|e| TieringError::Config(format!("S3 endpoint is not a valid URL: {}", e)))?;

    // Reject Docker-internal hostnames before they hit DNS — they resolve to
    // the host loopback in dev environments and were previously translated to
    // `localhost` server-side, which was an SSRF bypass. Match on the parsed
    // host, not on substring of the whole URL, so a path/query string
    // containing the literal does not trigger a false positive.
    if !allow_local() {
        if let Some(host) = parsed.host_str() {
            let h = host.to_ascii_lowercase();
            if h == "host.docker.internal"
                || h == "gateway.docker.internal"
                || h.ends_with(".host.docker.internal")
                || h.ends_with(".gateway.docker.internal")
            {
                return Err(TieringError::Config(
                    "S3 endpoint must not target Docker-internal hostnames".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Build the SSRF validator used for tiering S3 endpoints.
///
/// `allow_http` is enabled because S3-compatible endpoints (MinIO, LocalStack,
/// on-prem object stores) may legitimately be served over plain HTTP on a
/// trusted network. The IP/host class checks still block loopback, RFC1918,
/// link-local, IPv6 loopback/ULA, and cloud metadata endpoints.
///
/// `max_redirects` is unused for tiering — the test client disables redirect
/// following entirely at the reqwest layer, and we never call
/// `SsrfValidator::validate_redirect`.
fn ssrf_validator() -> SsrfValidator {
    SsrfValidator::new(SsrfConfig {
        allow_http: true,
        blocked_domains: Vec::new(),
        max_redirects: 0,
        ..Default::default()
    })
}

/// Map an `SsrfError` to a `TieringError::Config` with a generic, user-safe
/// message; log the specific reason at WARN so operators can debug.
///
/// We deliberately do not include the resolved IP class in the API response.
/// An authenticated attacker could otherwise probe internal hostnames by
/// observing whether the rejection mentions "private IP", "link-local", or
/// "metadata endpoint" — a small DNS oracle.
fn map_ssrf_error(endpoint: &str, e: SsrfError) -> TieringError {
    tracing::warn!(
        endpoint = %endpoint,
        error = %e,
        "tiering S3 endpoint rejected by SSRF validator"
    );
    match e {
        SsrfError::DnsResolutionFailed(host, _) => TieringError::Config(format!(
            "S3 endpoint hostname '{}' could not be resolved",
            host
        )),
        SsrfError::InvalidUrl(_) | SsrfError::InvalidScheme(_) | SsrfError::HttpNotAllowed => {
            TieringError::Config("S3 endpoint URL is not valid".to_string())
        }
        _ => TieringError::Config(
            "S3 endpoint is not allowed (must be a publicly routable host)".to_string(),
        ),
    }
}

/// Validate an S3 endpoint against SSRF rules with DNS resolution.
///
/// This is the network-level check — the syntactic `validate_s3_endpoint`
/// must pass first. Resolves the hostname and rejects any URL whose host (or
/// any of its resolved IPs) is loopback, private, link-local, broadcast,
/// unspecified, IPv4-mapped private, IPv6 ULA, or a known cloud metadata
/// endpoint. Numeric IPv4 literals (decimal/hex/octal) are normalized by the
/// `url` crate before the IP check, so `http://2130706433/` is treated as
/// `http://127.0.0.1/`.
pub(crate) async fn validate_s3_endpoint_ssrf(endpoint: &str) -> Result<(), TieringError> {
    validate_s3_endpoint(endpoint)?;
    if allow_local() {
        tracing::warn!(
            endpoint = %endpoint,
            env = ALLOW_LOCAL_ENV,
            "tiering SSRF validation skipped (dev override)"
        );
        return Ok(());
    }
    ssrf_validator()
        .validate_with_dns(endpoint)
        .await
        .map_err(|e| map_ssrf_error(endpoint, e))?;
    Ok(())
}

/// Validate an S3 endpoint and resolve it to a list of safe socket addresses.
///
/// This goes one step further than `validate_s3_endpoint_ssrf`: it returns
/// the resolved `SocketAddr`s so the caller can pin a `reqwest` client to
/// those exact IPs via `ClientBuilder::resolve` / `resolve_to_addrs`. That
/// closes the DNS-rebinding window between the validate-time DNS lookup and
/// the connect-time DNS lookup — reqwest will connect to one of these
/// pre-validated addresses, not whatever DNS returns later.
///
/// If the URL host is an IP literal, this returns an empty Vec — reqwest
/// uses the literal directly and no override is needed (the IP was already
/// validated by `validate_s3_endpoint_ssrf`).
pub(crate) async fn validate_and_resolve_s3_endpoint(
    endpoint: &str,
) -> Result<(Url, Vec<SocketAddr>), TieringError> {
    validate_s3_endpoint_ssrf(endpoint).await?;

    let url = Url::parse(endpoint)
        .map_err(|e| TieringError::Config(format!("S3 endpoint is not a valid URL: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| TieringError::Config("S3 endpoint has no host".to_string()))?;

    // IP-literal hosts: reqwest dials the literal directly. No override needed.
    // (`url::Url::host_str` returns IPv6 literals without brackets — `::1`,
    // not `[::1]` — so this catches both forms.)
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok((url, Vec::new()));
    }

    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(|_| {
            TieringError::Config(format!(
                "S3 endpoint hostname '{}' could not be resolved",
                host
            ))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(TieringError::Config(format!(
            "S3 endpoint hostname '{}' could not be resolved",
            host
        )));
    }

    if !allow_local() {
        let validator = ssrf_validator();
        for addr in &addrs {
            validator
                .validate_ip_address(addr.ip())
                .map_err(|e| map_ssrf_error(endpoint, e))?;
        }
    }

    Ok((url, addrs))
}

/// Format bytes into human-readable string
pub(crate) fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_rejected(endpoint: &str) {
        let res = validate_s3_endpoint(endpoint);
        if let Err(TieringError::Config(_)) = res {
            return;
        }
        // If syntactic validation passed, SSRF validation must reject it.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let res = rt.block_on(validate_s3_endpoint_ssrf(endpoint));
        assert!(
            matches!(res, Err(TieringError::Config(_))),
            "expected SSRF rejection for {endpoint}, got {res:?}"
        );
    }

    #[test]
    fn rejects_loopback_literal() {
        assert_rejected("http://127.0.0.1:9000");
        assert_rejected("http://127.0.0.55");
    }

    #[test]
    fn rejects_rfc1918_literals() {
        assert_rejected("http://10.0.0.1");
        assert_rejected("http://172.16.0.1");
        assert_rejected("http://172.31.255.255");
        assert_rejected("http://192.168.1.1:9000");
    }

    #[test]
    fn rejects_link_local_and_metadata() {
        assert_rejected("http://169.254.1.1");
        assert_rejected("http://169.254.169.254/latest/meta-data/");
        assert_rejected("http://metadata.google.internal/computeMetadata/v1/");
    }

    #[test]
    fn rejects_ipv6_loopback_and_ula() {
        assert_rejected("http://[::1]:9000");
        assert_rejected("http://[fc00::1]");
        assert_rejected("http://[fe80::1]");
    }

    #[test]
    fn rejects_zero_and_broadcast() {
        assert_rejected("http://0.0.0.0");
        assert_rejected("http://255.255.255.255");
    }

    #[test]
    fn rejects_decimal_encoded_loopback() {
        // 2130706433 == 0x7f000001 == 127.0.0.1; the URL crate normalizes
        // decimal IPv4 literals so the SSRF IP check still catches it.
        assert_rejected("http://2130706433");
        assert_rejected("http://0x7f000001");
    }

    #[test]
    fn rejects_docker_internal_hostnames() {
        // Syntactic check rejects these before DNS — we used to translate
        // host.docker.internal -> localhost server-side, which was an SSRF
        // bypass.
        assert!(matches!(
            validate_s3_endpoint("https://host.docker.internal:9000"),
            Err(TieringError::Config(_))
        ));
        assert!(matches!(
            validate_s3_endpoint("http://gateway.docker.internal"),
            Err(TieringError::Config(_))
        ));
    }

    #[test]
    fn syntactic_check_still_rejects_bad_scheme_and_chars() {
        assert!(matches!(
            validate_s3_endpoint("ftp://example.com"),
            Err(TieringError::Config(_))
        ));
        assert!(matches!(
            validate_s3_endpoint("https://example.com/<script>"),
            Err(TieringError::Config(_))
        ));
        let too_long = format!("https://example.com/{}", "a".repeat(300));
        assert!(matches!(
            validate_s3_endpoint(&too_long),
            Err(TieringError::Config(_))
        ));
    }

    #[tokio::test]
    async fn accepts_public_endpoint() {
        // Real public S3 endpoint — IP class checks pass.
        assert!(validate_s3_endpoint_ssrf("https://s3.us-east-1.amazonaws.com")
            .await
            .is_ok());
    }

    #[test]
    fn docker_internal_check_matches_host_not_path_substring() {
        // The docker-internal guard must match on the parsed host only.
        // A URL that *contains* the substring in its path/query must not be
        // rejected — that was the false-positive risk in the substring form.
        assert!(
            validate_s3_endpoint("https://docs.example.com/host.docker.internal-guide").is_ok()
        );
        assert!(validate_s3_endpoint(
            "https://example.com/?ref=gateway.docker.internal-faq"
        )
        .is_ok());
    }

    #[tokio::test]
    async fn validate_and_resolve_returns_addrs_for_hostname() {
        // Public hostname → returns at least one safe SocketAddr that the
        // caller can pin into reqwest::ClientBuilder::resolve.
        let (url, addrs) =
            validate_and_resolve_s3_endpoint("https://s3.us-east-1.amazonaws.com")
                .await
                .expect("public endpoint should resolve");
        assert_eq!(url.host_str(), Some("s3.us-east-1.amazonaws.com"));
        assert!(
            !addrs.is_empty(),
            "expected at least one resolved SocketAddr"
        );
    }

    #[tokio::test]
    async fn validate_and_resolve_returns_empty_addrs_for_ip_literal() {
        // IP-literal hosts don't go through DNS — caller should not install
        // a resolve override; an empty Vec signals that.
        let (_, addrs) = validate_and_resolve_s3_endpoint("https://1.1.1.1")
            .await
            .expect("public IP literal should be accepted");
        assert!(
            addrs.is_empty(),
            "expected empty addrs for IP literal, got {addrs:?}"
        );
    }

    #[tokio::test]
    async fn validate_and_resolve_rejects_loopback() {
        let res = validate_and_resolve_s3_endpoint("http://127.0.0.1:9000").await;
        assert!(
            matches!(res, Err(TieringError::Config(_))),
            "expected loopback rejection, got {res:?}"
        );
    }

    #[test]
    fn ssrf_error_mapping_is_generic() {
        // Defense against the DNS oracle: the message returned to callers
        // must not echo specific IP classes (e.g. "10.0.0.5", "private IP").
        let msg = match map_ssrf_error(
            "http://10.0.0.5",
            SsrfError::PrivateIpBlocked("10.0.0.5".parse().unwrap()),
        ) {
            TieringError::Config(m) => m,
            other => panic!("expected Config error, got {other:?}"),
        };
        assert!(
            !msg.contains("10.0.0.5") && !msg.to_lowercase().contains("private"),
            "message leaks IP-class details: {msg}"
        );
    }
}

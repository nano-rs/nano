// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC parsing and normalization
//!
//! Handles extraction of IPs and domains from various IOC formats:
//! - "45.1.33.4:8892" -> IP "45.1.33.4"
//! - "http://malware.com/path" -> Domain "malware.com"
//! - URL IOCs -> extracted domain or IP

use super::types::{IocType, ParsedIoc, ThreatFoxIoc};
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use std::net::IpAddr;
use std::sync::OnceLock;

/// Compiled regex for IP:port pattern
fn ip_port_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?$").unwrap())
}

/// Parse a ThreatFox IOC into normalized ParsedIoc(s)
///
/// URL-type IOCs may produce IOCs with different types:
/// - Extract IP if URL contains IP address
/// - Extract domain if URL contains hostname
pub fn parse_threatfox_ioc(ioc: &ThreatFoxIoc, ttl_days: i64) -> Vec<ParsedIoc> {
    let mut results = Vec::new();

    match ioc.ioc_type.as_str() {
        "ip:port" => {
            // Extract IP from "ip:port" format
            if let Some(ip) = extract_ip_from_value(&ioc.ioc) {
                results.push(create_parsed_ioc(
                    ip,
                    IocType::Ip,
                    Some(ioc.ioc.clone()),
                    ioc,
                    ttl_days,
                ));
            }
        }
        "domain" => {
            let normalized = normalize_domain(&ioc.ioc);
            if !normalized.is_empty() {
                results.push(create_parsed_ioc(
                    normalized,
                    IocType::Domain,
                    None,
                    ioc,
                    ttl_days,
                ));
            }
        }
        "url" => {
            // Parse URL to extract domain/IP
            results.extend(parse_url_ioc(ioc, ttl_days));
        }
        "md5_hash" => {
            let hash = ioc.ioc.to_lowercase();
            if is_valid_md5(&hash) {
                results.push(create_parsed_ioc(
                    hash,
                    IocType::Md5Hash,
                    None,
                    ioc,
                    ttl_days,
                ));
            }
        }
        "sha256_hash" => {
            let hash = ioc.ioc.to_lowercase();
            if is_valid_sha256(&hash) {
                results.push(create_parsed_ioc(
                    hash,
                    IocType::Sha256Hash,
                    None,
                    ioc,
                    ttl_days,
                ));
            }
        }
        _ => {
            // Unknown type, skip
        }
    }

    results
}

/// Extract IP address from an "ip:port" format or plain IP
fn extract_ip_from_value(value: &str) -> Option<String> {
    // Try IPv4:port pattern first
    if let Some(caps) = ip_port_regex().captures(value) {
        if let Some(ip_match) = caps.get(1) {
            let ip_str = ip_match.as_str();
            // Validate it's a real IP
            if ip_str.parse::<IpAddr>().is_ok() {
                return Some(ip_str.to_string());
            }
        }
    }

    // Try plain IP without port
    if value.parse::<IpAddr>().is_ok() {
        return Some(value.to_string());
    }

    // Handle bracketed IPv6 with port: [::1]:8080
    if value.starts_with('[') {
        if let Some(end_bracket) = value.find(']') {
            let ip_str = &value[1..end_bracket];
            if ip_str.parse::<IpAddr>().is_ok() {
                return Some(ip_str.to_string());
            }
        }
    }

    None
}

/// Parse URL-type IOC, extracting domain or IP
fn parse_url_ioc(ioc: &ThreatFoxIoc, ttl_days: i64) -> Vec<ParsedIoc> {
    let mut results = Vec::new();
    let url_str = &ioc.ioc;

    // Try to parse as URL
    if let Ok(url) = url::Url::parse(url_str) {
        if let Some(host) = url.host_str() {
            // Check if host is an IP address
            if let Ok(_ip) = host.parse::<IpAddr>() {
                results.push(create_parsed_ioc(
                    host.to_string(),
                    IocType::Ip,
                    Some(url_str.clone()),
                    ioc,
                    ttl_days,
                ));
            } else {
                // It's a domain
                let normalized = normalize_domain(host);
                if !normalized.is_empty() {
                    results.push(create_parsed_ioc(
                        normalized,
                        IocType::Domain,
                        Some(url_str.clone()),
                        ioc,
                        ttl_days,
                    ));
                }
            }
        }
    } else {
        // Failed to parse as URL, try extracting host manually
        let value = url_str
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("ftp://")
            .split('/')
            .next()
            .unwrap_or(url_str)
            .split('?')
            .next()
            .unwrap_or(url_str);

        // Remove port if present
        let host = value.split(':').next().unwrap_or(value);

        if let Some(ip) = extract_ip_from_value(value) {
            results.push(create_parsed_ioc(
                ip,
                IocType::Ip,
                Some(url_str.clone()),
                ioc,
                ttl_days,
            ));
        } else if !host.is_empty() {
            let normalized = normalize_domain(host);
            if !normalized.is_empty() && looks_like_domain(&normalized) {
                results.push(create_parsed_ioc(
                    normalized,
                    IocType::Domain,
                    Some(url_str.clone()),
                    ioc,
                    ttl_days,
                ));
            }
        }
    }

    results
}

/// Create a ParsedIoc from source data
fn create_parsed_ioc(
    value: String,
    ioc_type: IocType,
    original: Option<String>,
    source: &ThreatFoxIoc,
    _ttl_days: i64,
) -> ParsedIoc {
    ParsedIoc {
        ioc_value: value,
        ioc_type,
        original_value: original,
        threat_type: Some(source.threat_type.clone()),
        threat_type_desc: Some(source.threat_type_desc.clone()),
        malware: source.malware.clone(),
        malware_alias: source.malware_alias.clone(),
        malware_printable: source.malware_printable.clone(),
        confidence_level: source.confidence_level,
        first_seen_at: parse_timestamp(&source.first_seen),
        last_seen_at: parse_timestamp(&source.last_seen),
        tags: source.tags.clone(),
        reference_url: source.reference.clone(),
        reporter: source.reporter.clone(),
    }
}

/// Normalize domain: lowercase, remove trailing dot
fn normalize_domain(domain: &str) -> String {
    domain
        .to_lowercase()
        .trim()
        .trim_end_matches('.')
        .to_string()
}

/// Check if a string looks like a domain (has at least one dot, valid chars)
fn looks_like_domain(s: &str) -> bool {
    if s.is_empty() || !s.contains('.') {
        return false;
    }

    // Simple validation: alphanumeric, hyphens, dots
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Validate MD5 hash format
fn is_valid_md5(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate SHA256 hash format
fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse timestamp from ThreatFox format
fn parse_timestamp(ts: &Option<String>) -> Option<DateTime<Utc>> {
    ts.as_ref().and_then(|s| {
        // ThreatFox uses "YYYY-MM-DD HH:MM:SS UTC" format
        chrono::NaiveDateTime::parse_from_str(s.trim_end_matches(" UTC"), "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|dt| dt.and_utc())
    })
}

/// Calculate expiration time from TTL days
pub fn calculate_expires_at(ttl_days: i64) -> DateTime<Utc> {
    Utc::now() + Duration::days(ttl_days)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ip_from_ip_port() {
        assert_eq!(
            extract_ip_from_value("45.1.33.4:8892"),
            Some("45.1.33.4".to_string())
        );
        assert_eq!(
            extract_ip_from_value("192.168.1.1:443"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            extract_ip_from_value("8.8.8.8"),
            Some("8.8.8.8".to_string())
        );
    }

    #[test]
    fn test_extract_ip_invalid() {
        assert_eq!(extract_ip_from_value("invalid"), None);
        assert_eq!(extract_ip_from_value("999.999.999.999:80"), None);
        assert_eq!(extract_ip_from_value("malware.com:443"), None);
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("MALWARE.COM"), "malware.com");
        assert_eq!(normalize_domain("evil.com."), "evil.com");
        assert_eq!(normalize_domain(" test.org "), "test.org");
    }

    #[test]
    fn test_is_valid_md5() {
        assert!(is_valid_md5("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(!is_valid_md5("too_short"));
        assert!(!is_valid_md5("d41d8cd98f00b204e9800998ecf8427z")); // invalid char
    }

    #[test]
    fn test_is_valid_sha256() {
        assert!(is_valid_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(!is_valid_sha256("too_short"));
    }
}

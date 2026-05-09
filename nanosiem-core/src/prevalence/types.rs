// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence Tracking Types
//!
//! Core types for prevalence tracking including data structures,
//! configuration, and enums for artifact types and time windows.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Prevalence data for an artifact (hash or domain)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrevalenceData {
    /// The artifact value (hash or domain)
    pub artifact: String,
    /// Type of artifact
    pub artifact_type: ArtifactType,
    /// Number of unique hosts that have seen this artifact
    pub host_count: u64,
    /// Total number of occurrences across all hosts
    pub total_occurrences: u64,
    /// First time this artifact was observed
    pub first_seen: DateTime<Utc>,
    /// Last time this artifact was observed
    pub last_seen: DateTime<Utc>,
    /// Whether this artifact is considered rare (below threshold)
    pub is_rare: bool,
    /// Prevalence score (0-100, lower = rarer)
    pub prevalence_score: u8,
}

impl PrevalenceData {
    /// Create a new PrevalenceData with zero counts (for missing artifacts)
    pub fn empty(artifact: String, artifact_type: ArtifactType) -> Self {
        let now = Utc::now();
        Self {
            artifact,
            artifact_type,
            host_count: 0,
            total_occurrences: 0,
            first_seen: now,
            last_seen: now,
            is_rare: true,
            prevalence_score: 0,
        }
    }
}

/// Type of artifact being tracked for prevalence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    /// MD5 hash (32 hex characters)
    HashMd5,
    /// SHA256 hash (64 hex characters)
    HashSha256,
    /// Unknown hash type
    HashUnknown,
    /// Root domain (e.g., "example.com")
    Domain,
    /// Subdomain (e.g., "evil.example.com")
    Subdomain,
    /// Public IP address
    IpAddress,
    /// Private IP address (RFC1918)
    IpAddressPrivate,
}

impl ArtifactType {
    /// Detect artifact type from a string value with strict validation
    ///
    /// Hash validation:
    /// - MD5: exactly 32 lowercase hex characters
    /// - SHA256: exactly 64 lowercase hex characters
    ///
    /// IP validation:
    /// - Must be a valid IPv4 or IPv6 address
    /// - Private IPs (RFC1918) are marked as IpAddressPrivate
    ///
    /// Domain validation:
    /// - Must contain at least one dot
    /// - Must not be an IP address
    /// - Must have valid domain characters (alphanumeric, hyphens, dots)
    /// - TLD must be at least 2 characters and not numeric-only
    pub fn detect(value: &str) -> Self {
        // Normalize to lowercase for consistent checking
        let value_lower = value.to_lowercase();

        // Check if it looks like a valid hash (all hex characters, correct length)
        if value_lower.len() == 32 || value_lower.len() == 64 {
            if value_lower.chars().all(|c| c.is_ascii_hexdigit()) {
                return match value_lower.len() {
                    32 => ArtifactType::HashMd5,
                    64 => ArtifactType::HashSha256,
                    _ => ArtifactType::HashUnknown,
                };
            }
        }

        // Check if it's an IP address
        if let Ok(ip) = value.parse::<std::net::IpAddr>() {
            return if Self::is_private_ip(&ip) {
                ArtifactType::IpAddressPrivate
            } else {
                ArtifactType::IpAddress
            };
        }

        // Check if it's a valid domain
        if Self::is_valid_domain(&value_lower) {
            let parts: Vec<&str> = value_lower.split('.').collect();
            if parts.len() > 2 {
                return ArtifactType::Subdomain;
            } else {
                return ArtifactType::Domain;
            }
        }

        ArtifactType::HashUnknown
    }

    /// Check if an IP address is private (RFC1918 for IPv4, or private ranges for IPv6)
    fn is_private_ip(ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 10.0.0.0/8
                octets[0] == 10
                // 172.16.0.0/12
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                // 192.168.0.0/16
                || (octets[0] == 192 && octets[1] == 168)
                // 127.0.0.0/8 (loopback)
                || octets[0] == 127
                // 169.254.0.0/16 (link-local)
                || (octets[0] == 169 && octets[1] == 254)
            }
            std::net::IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_unspecified()
                // fc00::/7 (unique local)
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 (link-local)
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    /// Validate if a string is a valid domain name
    fn is_valid_domain(value: &str) -> bool {
        // Must contain at least one dot
        if !value.contains('.') {
            return false;
        }

        // Must not be an IP address
        if value.parse::<std::net::IpAddr>().is_ok() {
            return false;
        }

        // Check for IPv4-like pattern (4 numeric octets)
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return false;
        }

        // Max domain length
        if value.len() > 253 {
            return false;
        }

        // TLD must be at least 2 characters
        if let Some(tld) = parts.last() {
            if tld.len() < 2 {
                return false;
            }
            // TLD must not be numeric-only
            if tld.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
        }

        // Each label must be valid
        for part in &parts {
            // Label must not be empty
            if part.is_empty() {
                return false;
            }
            // Label max length is 63
            if part.len() > 63 {
                return false;
            }
            // Label must start and end with alphanumeric
            if let (Some(first), Some(last)) = (part.chars().next(), part.chars().last()) {
                if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
                    return false;
                }
            }
            // Label must only contain alphanumeric and hyphens
            if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }
        }

        true
    }

    /// Check if a value is a valid hash (MD5 or SHA256)
    pub fn is_valid_hash(value: &str) -> bool {
        let value_lower = value.to_lowercase();
        (value_lower.len() == 32 || value_lower.len() == 64)
            && value_lower.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Check if a value is a valid domain
    pub fn is_valid_domain_value(value: &str) -> bool {
        Self::is_valid_domain(&value.to_lowercase())
    }

    /// Check if this is a hash type
    pub fn is_hash(&self) -> bool {
        matches!(
            self,
            ArtifactType::HashMd5 | ArtifactType::HashSha256 | ArtifactType::HashUnknown
        )
    }

    /// Check if this is a domain type
    pub fn is_domain(&self) -> bool {
        matches!(self, ArtifactType::Domain | ArtifactType::Subdomain)
    }

    /// Check if this is an IP address type
    pub fn is_ip(&self) -> bool {
        matches!(
            self,
            ArtifactType::IpAddress | ArtifactType::IpAddressPrivate
        )
    }

    /// Check if a value is a valid IP address
    pub fn is_valid_ip_value(value: &str) -> bool {
        value.parse::<std::net::IpAddr>().is_ok()
    }
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactType::HashMd5 => write!(f, "md5"),
            ArtifactType::HashSha256 => write!(f, "sha256"),
            ArtifactType::HashUnknown => write!(f, "unknown"),
            ArtifactType::Domain => write!(f, "domain"),
            ArtifactType::Subdomain => write!(f, "subdomain"),
            ArtifactType::IpAddress => write!(f, "ip"),
            ArtifactType::IpAddressPrivate => write!(f, "ip_private"),
        }
    }
}

/// Time window for prevalence calculations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimeWindow {
    /// Last 1 hour
    OneHour,
    /// Last 24 hours (default)
    #[default]
    TwentyFourHours,
    /// Last 7 days
    SevenDays,
    /// Last 30 days
    ThirtyDays,
}

impl TimeWindow {
    /// Get the number of hours in this time window
    pub fn hours(&self) -> i64 {
        match self {
            TimeWindow::OneHour => 1,
            TimeWindow::TwentyFourHours => 24,
            TimeWindow::SevenDays => 168,
            TimeWindow::ThirtyDays => 720,
        }
    }

    /// Parse a time window from a string (e.g., "1h", "24h", "7d", "30d")
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "1h" | "1hour" | "one_hour" => Some(TimeWindow::OneHour),
            "24h" | "24hours" | "twenty_four_hours" => Some(TimeWindow::TwentyFourHours),
            "7d" | "7days" | "seven_days" => Some(TimeWindow::SevenDays),
            "30d" | "30days" | "thirty_days" => Some(TimeWindow::ThirtyDays),
            _ => None,
        }
    }
}

impl std::fmt::Display for TimeWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeWindow::OneHour => write!(f, "1h"),
            TimeWindow::TwentyFourHours => write!(f, "24h"),
            TimeWindow::SevenDays => write!(f, "7d"),
            TimeWindow::ThirtyDays => write!(f, "30d"),
        }
    }
}

/// Configuration for prevalence tracking
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrevalenceConfig {
    /// Number of hosts below which an artifact is considered "rare"
    pub rarity_threshold: u64,
    /// Whether to track file hash prevalence
    pub enable_hash_tracking: bool,
    /// Whether to track domain prevalence
    pub enable_domain_tracking: bool,
    /// Whether to track IP address prevalence
    #[serde(default = "default_enable_ip_tracking")]
    pub enable_ip_tracking: bool,
    /// Number of days to retain prevalence data
    pub retention_days: u32,
    /// Cache TTL in seconds for prevalence queries
    pub cache_ttl_seconds: u64,
}

fn default_enable_ip_tracking() -> bool {
    true
}

impl Default for PrevalenceConfig {
    fn default() -> Self {
        Self {
            rarity_threshold: 3,
            enable_hash_tracking: true,
            enable_domain_tracking: true,
            enable_ip_tracking: true,
            retention_days: 90,
            cache_ttl_seconds: 60,
        }
    }
}

/// Filter options for prevalence queries
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrevalenceFilter {
    /// Filter by artifact type
    pub artifact_type: Option<ArtifactType>,
    /// Maximum prevalence (host count) to include
    pub max_prevalence: Option<u64>,
    /// Minimum prevalence (host count) to include
    pub min_prevalence: Option<u64>,
    /// Maximum number of results
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

/// Request for bulk prevalence lookup
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkPrevalenceRequest {
    /// List of artifacts to look up
    pub artifacts: Vec<String>,
    /// Time window for prevalence calculation
    #[serde(default)]
    pub time_window: TimeWindow,
}

/// Data point for scatter plot visualization
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrevalenceScatterPoint {
    /// The artifact value (hash or domain)
    pub artifact: String,
    /// Type of artifact
    pub artifact_type: ArtifactType,
    /// Number of unique hosts (Y-axis value)
    pub host_count: u64,
    /// First seen timestamp (X-axis value)
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Total occurrence count
    pub total_occurrences: u64,
    /// Whether this artifact is below the rarity threshold
    pub is_rare: bool,
    /// Prevalence score (0-100)
    pub prevalence_score: u8,
}

impl From<PrevalenceData> for PrevalenceScatterPoint {
    fn from(data: PrevalenceData) -> Self {
        Self {
            artifact: data.artifact,
            artifact_type: data.artifact_type,
            host_count: data.host_count,
            first_seen: data.first_seen,
            last_seen: data.last_seen,
            total_occurrences: data.total_occurrences,
            is_rare: data.is_rare,
            prevalence_score: data.prevalence_score,
        }
    }
}

/// Response for scatter plot data
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrevalenceScatterData {
    /// Hash prevalence points
    pub hash_points: Vec<PrevalenceScatterPoint>,
    /// Domain prevalence points
    pub domain_points: Vec<PrevalenceScatterPoint>,
    /// IP address prevalence points
    #[serde(default)]
    pub ip_points: Vec<PrevalenceScatterPoint>,
    /// Current rarity threshold
    pub rarity_threshold: u64,
}

/// Export format for prevalence data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
}

impl Default for ExportFormat {
    fn default() -> Self {
        ExportFormat::Csv
    }
}

/// Single day's artifact activity count for heatmap display
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactDailyCount {
    /// Date in YYYY-MM-DD format
    pub date: String,
    /// Number of occurrences on this day
    pub count: u64,
}

/// Extended artifact data with daily breakdown for explorer view
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactExplorerItem {
    /// The artifact value (hash, domain, or IP)
    pub artifact: String,
    /// Type of artifact
    pub artifact_type: ArtifactType,
    /// Number of unique hosts that have seen this artifact
    pub host_count: u64,
    /// Total number of occurrences across all hosts
    pub total_occurrences: u64,
    /// First time this artifact was observed
    pub first_seen: DateTime<Utc>,
    /// Last time this artifact was observed
    pub last_seen: DateTime<Utc>,
    /// Whether this artifact is considered rare (below threshold)
    pub is_rare: bool,
    /// Prevalence score (0-100, lower = rarer)
    pub prevalence_score: u8,
    /// Daily activity breakdown for heatmap rendering
    pub daily_counts: Vec<ArtifactDailyCount>,
}

impl ArtifactExplorerItem {
    /// Create from PrevalenceData with daily counts
    pub fn from_prevalence_data(
        data: PrevalenceData,
        daily_counts: Vec<ArtifactDailyCount>,
    ) -> Self {
        Self {
            artifact: data.artifact,
            artifact_type: data.artifact_type,
            host_count: data.host_count,
            total_occurrences: data.total_occurrences,
            first_seen: data.first_seen,
            last_seen: data.last_seen,
            is_rare: data.is_rare,
            prevalence_score: data.prevalence_score,
            daily_counts,
        }
    }
}

/// Response for the artifact explorer endpoint
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactExplorerResponse {
    /// Artifacts with daily breakdown data
    pub artifacts: Vec<ArtifactExplorerItem>,
    /// Total count of artifacts matching the query (before pagination)
    pub total: usize,
    /// Page size
    pub limit: i64,
    /// Page offset
    pub offset: i64,
    /// Whether more results are available
    pub has_more: bool,
    /// Current rarity threshold from configuration
    pub rarity_threshold: u64,
    /// Count of rare artifacts (below rarity threshold)
    pub rare_count: usize,
    /// Count of new artifacts (first seen within last 24h)
    pub new_count: usize,
    /// Count of high-risk assets (both rare AND active in last 24h)
    pub high_risk_asset_count: usize,
}

/// A host that observed an artifact, with occurrence count
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactHostEntry {
    pub host: String,
    pub count: u64,
    pub last_seen: DateTime<Utc>,
}

/// A user associated with an artifact
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactUserEntry {
    pub user: String,
    pub count: u64,
}

/// A source type that reported an artifact
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactSourceEntry {
    pub source_type: String,
    pub count: u64,
}

/// Process context for hash artifacts
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactProcessEntry {
    pub process_name: String,
    pub command_line: String,
    pub count: u64,
}

/// Network context for IP/domain artifacts
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactNetworkEntry {
    pub dest_port: u16,
    pub protocol: String,
    pub count: u64,
}

/// Geo/ASN context for IP artifacts
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactGeoEntry {
    pub country: String,
    pub asn: String,
    pub count: u64,
}

/// Detailed context for an artifact, fetched on demand when expanding a row
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactDetailResponse {
    pub artifact: String,
    pub artifact_type: ArtifactType,
    /// Top hosts that observed this artifact
    pub top_hosts: Vec<ArtifactHostEntry>,
    /// Top users associated with this artifact
    pub top_users: Vec<ArtifactUserEntry>,
    /// Source types that reported this artifact
    pub source_types: Vec<ArtifactSourceEntry>,
    /// Process context (hash artifacts only)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub processes: Vec<ArtifactProcessEntry>,
    /// Network context (IP/domain artifacts only)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub network: Vec<ArtifactNetworkEntry>,
    /// Geo/ASN context (IP artifacts only)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub geo: Vec<ArtifactGeoEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_type_detect_md5() {
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        assert_eq!(ArtifactType::detect(md5), ArtifactType::HashMd5);
    }

    #[test]
    fn test_artifact_type_detect_md5_uppercase() {
        let md5 = "D41D8CD98F00B204E9800998ECF8427E";
        assert_eq!(ArtifactType::detect(md5), ArtifactType::HashMd5);
    }

    #[test]
    fn test_artifact_type_detect_sha256() {
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(ArtifactType::detect(sha256), ArtifactType::HashSha256);
    }

    #[test]
    fn test_artifact_type_detect_domain() {
        assert_eq!(ArtifactType::detect("example.com"), ArtifactType::Domain);
        assert_eq!(
            ArtifactType::detect("evil.example.com"),
            ArtifactType::Subdomain
        );
    }

    #[test]
    fn test_artifact_type_detect_ip_not_domain() {
        // IP addresses should not be detected as domains
        assert_eq!(
            ArtifactType::detect("192.168.1.1"),
            ArtifactType::IpAddressPrivate
        );
    }

    #[test]
    fn test_artifact_type_invalid_hash_length() {
        // Wrong length - not a valid hash
        assert_eq!(ArtifactType::detect("abc123"), ArtifactType::HashUnknown);
        assert_eq!(
            ArtifactType::detect("d41d8cd98f00b204e9800998ecf8427"),
            ArtifactType::HashUnknown
        ); // 31 chars
    }

    #[test]
    fn test_artifact_type_invalid_hash_chars() {
        // Right length but invalid characters
        assert_eq!(
            ArtifactType::detect("d41d8cd98f00b204e9800998ecf8427g"),
            ArtifactType::HashUnknown
        ); // 'g' is invalid
    }

    #[test]
    fn test_artifact_type_invalid_domain_single_label() {
        // Single label without TLD
        assert_eq!(ArtifactType::detect("localhost"), ArtifactType::HashUnknown);
    }

    #[test]
    fn test_artifact_type_invalid_domain_numeric_tld() {
        // Numeric-only TLD is invalid
        assert_eq!(
            ArtifactType::detect("example.123"),
            ArtifactType::HashUnknown
        );
    }

    #[test]
    fn test_artifact_type_invalid_domain_short_tld() {
        // TLD too short
        assert_eq!(ArtifactType::detect("example.a"), ArtifactType::HashUnknown);
    }

    #[test]
    fn test_artifact_type_valid_domain_with_hyphen() {
        assert_eq!(ArtifactType::detect("my-domain.com"), ArtifactType::Domain);
        assert_eq!(
            ArtifactType::detect("sub.my-domain.com"),
            ArtifactType::Subdomain
        );
    }

    #[test]
    fn test_artifact_type_invalid_domain_starts_with_hyphen() {
        assert_eq!(
            ArtifactType::detect("-example.com"),
            ArtifactType::HashUnknown
        );
    }

    #[test]
    fn test_artifact_type_invalid_domain_ends_with_hyphen() {
        assert_eq!(
            ArtifactType::detect("example-.com"),
            ArtifactType::HashUnknown
        );
    }

    #[test]
    fn test_is_valid_hash() {
        assert!(ArtifactType::is_valid_hash(
            "d41d8cd98f00b204e9800998ecf8427e"
        ));
        assert!(ArtifactType::is_valid_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(!ArtifactType::is_valid_hash("not-a-hash"));
        assert!(!ArtifactType::is_valid_hash(
            "d41d8cd98f00b204e9800998ecf8427"
        )); // 31 chars
    }

    #[test]
    fn test_is_valid_domain_value() {
        assert!(ArtifactType::is_valid_domain_value("example.com"));
        assert!(ArtifactType::is_valid_domain_value("sub.example.com"));
        assert!(ArtifactType::is_valid_domain_value("deep.sub.example.com"));
        assert!(!ArtifactType::is_valid_domain_value("192.168.1.1"));
        assert!(!ArtifactType::is_valid_domain_value("localhost"));
        assert!(!ArtifactType::is_valid_domain_value("example.123"));
    }

    #[test]
    fn test_time_window_hours() {
        assert_eq!(TimeWindow::OneHour.hours(), 1);
        assert_eq!(TimeWindow::TwentyFourHours.hours(), 24);
        assert_eq!(TimeWindow::SevenDays.hours(), 168);
        assert_eq!(TimeWindow::ThirtyDays.hours(), 720);
    }

    #[test]
    fn test_time_window_from_str() {
        assert_eq!(TimeWindow::from_str("1h"), Some(TimeWindow::OneHour));
        assert_eq!(
            TimeWindow::from_str("24h"),
            Some(TimeWindow::TwentyFourHours)
        );
        assert_eq!(TimeWindow::from_str("7d"), Some(TimeWindow::SevenDays));
        assert_eq!(TimeWindow::from_str("30d"), Some(TimeWindow::ThirtyDays));
        assert_eq!(TimeWindow::from_str("invalid"), None);
    }

    #[test]
    fn test_prevalence_config_default() {
        let config = PrevalenceConfig::default();
        assert_eq!(config.rarity_threshold, 3);
        assert!(config.enable_hash_tracking);
        assert!(config.enable_domain_tracking);
        assert_eq!(config.retention_days, 90);
        assert_eq!(config.cache_ttl_seconds, 60);
    }

    #[test]
    fn test_prevalence_data_empty() {
        let data = PrevalenceData::empty("test".to_string(), ArtifactType::HashMd5);
        assert_eq!(data.artifact, "test");
        assert_eq!(data.host_count, 0);
        assert!(data.is_rare);
        assert_eq!(data.prevalence_score, 0);
    }
}

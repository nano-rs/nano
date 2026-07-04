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

/// Extended artifact data with daily breakdown for explorer view.
///
/// `daily_counts` is a packed, dense array of per-day counts in chronological
/// order; index 0 corresponds to `daily_start`, index `N-1` to today. Days with
/// no activity are 0. This replaces the prior `[{date, count}, ...]` shape to
/// roughly halve the wire size on large pages (50 artifacts × 30 days).
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
    /// Packed daily counts, oldest first; index `i` corresponds to
    /// `daily_start + i` days.
    pub daily_counts: Vec<u64>,
    /// Date of `daily_counts[0]` in YYYY-MM-DD format
    pub daily_start: String,
    /// Inline context fields populated for the list view so each row is
    /// scannable without expanding. All optional — clients render a fallback
    /// when missing. Populated by `PrevalenceService::enrich_explorer_items`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ArtifactInlineContext>,
}

/// Inline subtitle data shown beneath each prevalence list row. Tuned per
/// artifact type — see Prevalence.tsx for the rendering rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactInlineContext {
    /// Hash artifacts: top observed on-disk file name (`7zG.exe`,
    /// `tiledatamodelsvc.dll`, ...). Distinct from `top_process_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_file_name: Option<String>,
    /// Hash artifacts: top running image name (`svchost.exe`, `7zG.exe`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_process_name: Option<String>,
    /// Hash artifacts: short command-line excerpt for the top process.
    /// Useful when `top_process_name` is a wrapper (svchost, rundll32).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_command_line: Option<String>,
    /// Hash artifacts: true when `top_process_name` is a wrapper binary.
    #[serde(default)]
    pub top_process_is_wrapper: bool,
    /// IP artifacts: country name (e.g. "United States").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// IP artifacts: ASN number string (e.g. "15169").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    /// IP artifacts: AS organization (e.g. "Google LLC").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn_org: Option<String>,
    /// Total distinct users associated with the artifact (cheap count).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_count: Option<u64>,
    /// Top source_type by event count for the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_source_type: Option<String>,
}

impl ArtifactExplorerItem {
    /// Create from PrevalenceData with a packed daily-counts array.
    pub fn from_prevalence_data(
        data: PrevalenceData,
        daily_counts: Vec<u64>,
        daily_start: String,
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
            daily_start,
            context: None,
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
    /// The headline counts (`total`, `rare_count`, `new_count`,
    /// `high_risk_asset_count`) are computed over a bounded fetch buffer, not a
    /// full table scan. When any underlying per-type fetch hit that buffer cap,
    /// these counts are FLOORS (real values are higher) and the UI should render
    /// them as `N+` rather than an exact total (audit P6). `false` means the
    /// buffer was not capped and the counts are exact.
    #[serde(default)]
    pub counts_approximate: bool,
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

/// Process context for hash artifacts.
///
/// `is_wrapper` is set when the process_name is a well-known host/wrapper
/// (svchost.exe, rundll32.exe, powershell.exe, etc.). Wrapper rows are nearly
/// uninformative on their own — the command line is the real identity. The
/// UI groups consecutive wrapper rows under a single sub-heading so a hash
/// like svchost reads as "one service host, many command lines" rather than
/// 10 identical-looking rows.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactProcessEntry {
    pub process_name: String,
    pub command_line: String,
    pub count: u64,
    /// True when `process_name` is a well-known wrapper/host process whose
    /// identity is carried by `command_line`, not the image name itself.
    #[serde(default)]
    pub is_wrapper: bool,
}

/// On-disk file name observed for a hash artifact.
///
/// `file_name` is the on-disk identity (e.g. `7zG.exe`), distinct from the
/// running image (`process_name`). They differ when a binary is renamed or
/// loaded via a wrapper (rundll32.exe loading `evil.dll`, svchost.exe
/// hosting `tiledatamodelsvc.dll`, etc.). For hashes, file_name is usually
/// the truer answer to "what is this thing?"
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactFileNameEntry {
    pub file_name: String,
    pub count: u64,
}

/// Threat-intelligence verdict from an enrichment source (ThreatFox, TOR
/// exit nodes, etc.). Empty when no source returned a hit for the artifact.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactThreatIntelEntry {
    /// Enrichment source slug (e.g. `threatfox`, `tor_exit_nodes`)
    pub source: String,
    /// Human-readable verdict line (e.g. "Malware C2 — Cobalt Strike")
    pub verdict: String,
    /// Confidence/score 0-100 if the source provides one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// Raw details payload for the UI (tags, first_seen, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Well-known wrapper / process-hosting binaries. Hash hits whose top
/// `process_name` is one of these are almost always uninformative without
/// the command line, which is why we surface this flag to the UI.
///
/// Case-insensitive match against `process_name`.
pub const WRAPPER_PROCESSES: &[&str] = &[
    "svchost.exe",
    "rundll32.exe",
    "dllhost.exe",
    "conhost.exe",
    "regsvr32.exe",
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
];

/// True when `process_name` matches a known wrapper binary (case-insensitive).
pub fn is_wrapper_process(process_name: &str) -> bool {
    let lower = process_name.trim().to_ascii_lowercase();
    WRAPPER_PROCESSES.iter().any(|w| *w == lower.as_str())
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
    /// Top on-disk file names observed for this hash. Hash artifacts only.
    /// Distinct from `processes.process_name` — file_name is the on-disk
    /// identity and is usually the more interesting answer for hashes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub top_file_names: Vec<ArtifactFileNameEntry>,
    /// Network context (IP/domain artifacts only)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub network: Vec<ArtifactNetworkEntry>,
    /// Geo/ASN context (IP artifacts only)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub geo: Vec<ArtifactGeoEntry>,
    /// Threat-intel verdicts from configured enrichment sources. Empty when
    /// the artifact is not present in any feed (or no feeds are configured).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub threat_intel: Vec<ArtifactThreatIntelEntry>,
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

    // ------------------------------------------------------------------
    // NAN-849: wrapper-process detection and inline-context plumbing
    // ------------------------------------------------------------------

    #[test]
    fn test_is_wrapper_process_known_wrappers() {
        // Every listed wrapper should match, case-insensitively.
        for name in [
            "svchost.exe",
            "SVCHOST.EXE",
            "SvcHost.Exe",
            "rundll32.exe",
            "DLLHOST.EXE",
            "conhost.exe",
            "regsvr32.exe",
            "powershell.exe",
            "PowerShell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        ] {
            assert!(
                is_wrapper_process(name),
                "expected {name} to be flagged as a wrapper"
            );
        }
    }

    #[test]
    fn test_is_wrapper_process_negative() {
        // Ordinary binaries are not wrappers — the hash row should render
        // with `is_wrapper = false` and no grouping in the UI.
        for name in [
            "explorer.exe",
            "chrome.exe",
            "7zG.exe",
            "notepad.exe",
            "",
            "  ",
            "tiledatamodelsvc.dll",
        ] {
            assert!(
                !is_wrapper_process(name),
                "did not expect {name:?} to be flagged as a wrapper"
            );
        }
    }

    #[test]
    fn test_is_wrapper_process_trims_whitespace() {
        // Logs frequently carry trailing spaces in process_name. The flag
        // must still light up.
        assert!(is_wrapper_process("  svchost.exe  "));
        assert!(is_wrapper_process("\tpowershell.exe\n"));
    }

    #[test]
    fn test_artifact_process_entry_is_wrapper_flag() {
        // The flag is what the UI keys off of when collapsing rows under a
        // sub-heading. Smoke-test that the struct serializes the field and
        // that the wrapper helper produces the right answer.
        let entry = ArtifactProcessEntry {
            process_name: "svchost.exe".to_string(),
            command_line: "C:\\Windows\\System32\\svchost.exe -k netsvcs".to_string(),
            count: 42,
            is_wrapper: is_wrapper_process("svchost.exe"),
        };
        assert!(entry.is_wrapper);
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["is_wrapper"], serde_json::json!(true));
    }

    #[test]
    fn test_artifact_inline_context_optional_fields_omitted() {
        // Empty context should round-trip without exposing null fields —
        // the frontend differentiates "missing" from "explicitly null".
        let ctx = ArtifactInlineContext::default();
        let json = serde_json::to_value(&ctx).unwrap();
        // top_process_is_wrapper has #[serde(default)] but is a bool so it
        // stays in the payload as `false`. Everything else is optional and
        // should be absent.
        assert!(json.get("top_file_name").is_none());
        assert!(json.get("top_process_name").is_none());
        assert!(json.get("country").is_none());
        assert!(json.get("asn").is_none());
        assert!(json.get("user_count").is_none());
    }

    #[test]
    fn test_artifact_inline_context_populated_round_trip() {
        let ctx = ArtifactInlineContext {
            top_file_name: Some("tiledatamodelsvc.dll".to_string()),
            top_process_name: Some("svchost.exe".to_string()),
            top_command_line: Some("svchost.exe -k LocalServiceNetworkRestricted".to_string()),
            top_process_is_wrapper: true,
            user_count: Some(12),
            top_source_type: Some("microsoft_sysmon".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&ctx).unwrap();
        assert_eq!(json["top_file_name"], "tiledatamodelsvc.dll");
        assert_eq!(json["top_process_name"], "svchost.exe");
        assert_eq!(json["top_process_is_wrapper"], true);
        assert_eq!(json["user_count"], 12);
    }

    #[test]
    fn test_top_file_names_aggregation_pure() {
        // We can't hit ClickHouse in a unit test, but we can simulate the
        // aggregation that the repository does so the count + ordering
        // contract is locked in. Same input shape the CH query produces:
        // (file_name, count) rows sorted DESC by count.
        let raw: Vec<(&str, u64)> = vec![
            ("tiledatamodelsvc.dll", 1240),
            ("netman.dll", 410),
            ("WdiServiceHost.dll", 88),
        ];
        let entries: Vec<ArtifactFileNameEntry> = raw
            .into_iter()
            .map(|(n, c)| ArtifactFileNameEntry {
                file_name: n.to_string(),
                count: c,
            })
            .collect();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].file_name, "tiledatamodelsvc.dll");
        assert_eq!(entries[0].count, 1240);
        // The vec is in DESC order — counts strictly decrease.
        for w in entries.windows(2) {
            assert!(w[0].count >= w[1].count, "expected DESC ordering");
        }

        // Round-trips through the API JSON shape.
        let json = serde_json::to_value(&entries[0]).unwrap();
        assert_eq!(json["file_name"], "tiledatamodelsvc.dll");
        assert_eq!(json["count"], 1240);
    }

    #[test]
    fn test_artifact_detail_response_omits_empty_context_arrays() {
        // Backwards-compat: a hash with no process matches shouldn't push
        // empty `processes`/`top_file_names` keys onto the wire — old
        // clients that don't know about top_file_names mustn't break.
        let resp = ArtifactDetailResponse {
            artifact: "deadbeef".to_string(),
            artifact_type: ArtifactType::HashMd5,
            top_hosts: vec![],
            top_users: vec![],
            source_types: vec![],
            processes: vec![],
            top_file_names: vec![],
            network: vec![],
            geo: vec![],
            threat_intel: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("processes").is_none(), "empty vec should be skipped");
        assert!(
            json.get("top_file_names").is_none(),
            "empty top_file_names should be skipped"
        );
        assert!(json.get("threat_intel").is_none());
    }
}

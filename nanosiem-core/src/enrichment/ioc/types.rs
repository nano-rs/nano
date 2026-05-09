// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC (Indicators of Compromise) type definitions
//!
//! Supports multiple IOC types from threat intelligence feeds like ThreatFox

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// Deserialize null or missing values as an empty Vec
fn deserialize_null_to_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// IOC types supported by the system
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "ioc_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ip,
    Domain,
    Url,
    Md5Hash,
    Sha256Hash,
}

impl IocType {
    pub fn as_str(&self) -> &'static str {
        match self {
            IocType::Ip => "ip",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::Md5Hash => "md5_hash",
            IocType::Sha256Hash => "sha256_hash",
        }
    }

    /// Parse ThreatFox ioc_type string to our enum
    pub fn from_threatfox(s: &str) -> Option<Self> {
        match s {
            "ip:port" => Some(IocType::Ip),
            "domain" => Some(IocType::Domain),
            "url" => Some(IocType::Url),
            "md5_hash" => Some(IocType::Md5Hash),
            "sha256_hash" => Some(IocType::Sha256Hash),
            _ => None,
        }
    }
}

impl fmt::Display for IocType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// IOC enrichment record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct IocEnrichment {
    pub id: i64,
    pub source_id: String,
    pub ioc_value: String,
    pub ioc_type: IocType,
    pub original_value: Option<String>,
    pub threat_type: Option<String>,
    pub threat_type_desc: Option<String>,
    pub malware: Option<String>,
    pub malware_alias: Option<String>,
    pub malware_printable: Option<String>,
    pub confidence_level: Option<i32>,
    pub first_seen_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub reference_url: Option<String>,
    pub reporter: Option<String>,
    pub extra: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// IOC lookup result (simplified for API response)
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct IocLookupResult {
    pub found: bool,
    pub source_id: Option<String>,
    pub ioc_type: Option<String>,
    pub threat_type: Option<String>,
    pub malware: Option<String>,
    pub confidence_level: Option<i32>,
    pub first_seen_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub tags: Vec<String>,
}

/// Parsed IOC ready for database insertion
#[derive(Debug, Clone)]
pub struct ParsedIoc {
    pub ioc_value: String,
    pub ioc_type: IocType,
    pub original_value: Option<String>,
    pub threat_type: Option<String>,
    pub threat_type_desc: Option<String>,
    pub malware: Option<String>,
    pub malware_alias: Option<String>,
    pub malware_printable: Option<String>,
    pub confidence_level: i32,
    pub first_seen_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub reference_url: Option<String>,
    pub reporter: Option<String>,
}

/// IOC statistics by type
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IocStats {
    pub ip_count: i64,
    pub domain_count: i64,
    pub hash_count: i64,
    pub url_count: i64,
    pub total: i64,
}

// =============================================================================
// ThreatFox API Types
// =============================================================================

/// ThreatFox API response wrapper
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ThreatFoxResponse {
    pub query_status: String,
    #[serde(default)]
    pub data: Vec<ThreatFoxIoc>,
}

/// Individual IOC from ThreatFox API
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ThreatFoxIoc {
    pub id: String,
    pub ioc: String,
    /// IOC type: "ip:port", "domain", "url", "md5_hash", "sha256_hash"
    pub ioc_type: String,
    #[serde(default)]
    pub ioc_type_desc: Option<String>,
    pub threat_type: String,
    pub threat_type_desc: String,
    pub malware: Option<String>,
    pub malware_alias: Option<String>,
    pub malware_printable: Option<String>,
    #[serde(default)]
    pub malware_malpedia: Option<String>,
    pub confidence_level: i32,
    #[serde(default)]
    pub is_compromised: Option<bool>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub reference: Option<String>,
    pub reporter: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_to_vec")]
    pub tags: Vec<String>,
}

/// ThreatFox API client configuration
#[derive(Debug, Clone)]
pub struct ThreatFoxConfig {
    pub api_endpoint: String,
    pub api_key: Option<String>,
    pub query_days: i32,
    pub timeout_secs: u64,
}

impl Default for ThreatFoxConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "https://threatfox-api.abuse.ch/api/v1/".to_string(),
            api_key: None,
            query_days: 7,
            timeout_secs: 120,
        }
    }
}

// =============================================================================
// TOR Exit Nodes API Types
// =============================================================================

/// TOR Onionoo API response
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct OnionooResponse {
    pub version: String,
    #[serde(default)]
    pub build_revision: Option<String>,
    #[serde(default)]
    pub relays_published: Option<String>,
    #[serde(default)]
    pub relays: Vec<TorRelay>,
}

/// Individual TOR relay from Onionoo API
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct TorRelay {
    pub nickname: Option<String>,
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub or_addresses: Option<Vec<String>>,
    #[serde(default)]
    pub exit_addresses: Option<Vec<String>>,
    pub last_seen: Option<String>,
    pub first_seen: Option<String>,
    #[serde(default)]
    pub running: Option<bool>,
    #[serde(default)]
    pub flags: Option<Vec<String>>,
    pub country: Option<String>,
    pub country_name: Option<String>,
    #[serde(rename = "as")]
    pub as_number: Option<String>,
    pub as_name: Option<String>,
    #[serde(default)]
    pub consensus_weight: Option<i64>,
    pub version: Option<String>,
    pub platform: Option<String>,
    pub contact: Option<String>,
}

/// TOR Exit Nodes API client configuration
#[derive(Debug, Clone)]
pub struct TorConfig {
    pub api_endpoint: String,
    pub timeout_secs: u64,
    pub confidence_level: i32,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "https://onionoo.torproject.org/details?type=relay&flag=Exit".to_string(),
            timeout_secs: 120,
            confidence_level: 100, // 100% confidence - data comes directly from TOR project
        }
    }
}

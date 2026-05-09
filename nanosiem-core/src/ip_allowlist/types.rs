// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP Allowlist domain types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::typeid;

/// Scope of an IP allowlist rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum IpAllowlistScope {
    /// Applies to all services
    Global,
    /// Applies to the API service only (port 3000)
    Api,
    /// Applies to the Search service only (port 3002)
    Search,
    /// Applies to the Frontend only
    Frontend,
}

impl IpAllowlistScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Api => "api",
            Self::Search => "search",
            Self::Frontend => "frontend",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "global" => Some(Self::Global),
            "api" => Some(Self::Api),
            "search" => Some(Self::Search),
            "frontend" => Some(Self::Frontend),
            _ => None,
        }
    }
}

impl std::fmt::Display for IpAllowlistScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An IP allowlist entry
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IpAllowlistEntry {
    #[serde(with = "typeid::ip_allowlist")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub scope: IpAllowlistScope,
    /// CIDR notation (e.g. "10.0.0.0/8" or "192.168.1.1/32")
    pub cidr: String,
    pub description: Option<String>,
    pub enabled: bool,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new IP allowlist entry
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateIpAllowlistEntry {
    pub scope: IpAllowlistScope,
    /// CIDR notation (e.g. "10.0.0.0/8" or "192.168.1.1/32")
    pub cidr: String,
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Request to update an IP allowlist entry
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateIpAllowlistEntry {
    pub scope: Option<IpAllowlistScope>,
    pub cidr: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

/// Request to test an IP against the current allowlist
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TestIpRequest {
    /// IP address to test
    pub ip: String,
    /// Scope to test against (if omitted, tests all scopes)
    pub scope: Option<IpAllowlistScope>,
}

/// Response from testing an IP
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TestIpResponse {
    pub ip: String,
    pub allowed: bool,
    /// Which rules matched (if allowed)
    pub matched_rules: Vec<MatchedRule>,
    /// Whether the allowlist is active (has any enabled rules for this scope)
    pub allowlist_active: bool,
}

/// A rule that matched during IP testing
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MatchedRule {
    #[serde(with = "typeid::ip_allowlist")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub scope: IpAllowlistScope,
    pub cidr: String,
    pub description: Option<String>,
}

/// Summary of the allowlist state
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IpAllowlistStatus {
    pub active: bool,
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub rules_by_scope: std::collections::HashMap<String, usize>,
}

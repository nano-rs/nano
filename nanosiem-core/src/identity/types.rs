// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity Provider types
//!
//! Core types for the identity provider sync system. Supports Entra ID (Azure AD),
//! Google Workspace (Admin SDK), Okta (Users API), Workday (RaaS),
//! and on-prem Active Directory (push-based collector).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// =============================================================================
// Provider Type
// =============================================================================

/// Supported identity provider types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProviderType {
    /// Microsoft Entra ID (formerly Azure AD) — MS Graph API
    EntraId,
    /// Google Workspace — Admin SDK Directory API
    GoogleWorkspace,
    /// Okta — Users API with SSWS token auth
    Okta,
    /// Workday — RaaS (Report as a Service) with ISU basic auth
    Workday,
    /// On-premises Active Directory — push-based collector
    ActiveDirectory,
}

impl IdentityProviderType {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::EntraId => "entra_id",
            Self::GoogleWorkspace => "google_workspace",
            Self::Okta => "okta",
            Self::Workday => "workday",
            Self::ActiveDirectory => "active_directory",
        }
    }

    /// Default sync interval in hours for this provider type
    pub fn default_sync_interval_hours(&self) -> u64 {
        match self {
            Self::EntraId => 6,
            Self::GoogleWorkspace => 6,
            Self::Okta => 6,
            Self::Workday => 12,         // RaaS full sync only, less frequent
            Self::ActiveDirectory => 12, // Push-based, less frequent full syncs
        }
    }

    /// Whether this provider supports delta (incremental) sync
    pub fn supports_delta_sync(&self) -> bool {
        match self {
            Self::EntraId => true,          // MS Graph delta queries
            Self::GoogleWorkspace => true,  // updatedMin parameter
            Self::Okta => true,             // lastUpdated filter
            Self::Workday => false,         // RaaS doesn't support delta
            Self::ActiveDirectory => false, // Push-based, no pull delta
        }
    }
}

impl std::fmt::Display for IdentityProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_db_str())
    }
}

impl std::str::FromStr for IdentityProviderType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "entra_id" | "entraid" | "azure_ad" | "azuread" => Ok(Self::EntraId),
            "google_workspace" | "googleworkspace" | "gsuite" => Ok(Self::GoogleWorkspace),
            "okta" => Ok(Self::Okta),
            "workday" => Ok(Self::Workday),
            "active_directory" | "activedirectory" | "ad" => Ok(Self::ActiveDirectory),
            _ => Err(format!("Unknown identity provider type: {}", s)),
        }
    }
}

// =============================================================================
// Identity Provider (database row)
// =============================================================================

/// Identity provider configuration as stored in the database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct IdentityProvider {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    pub enabled: bool,
    #[sqlx(default)]
    #[serde(skip_serializing)]
    pub credentials_encrypted: Option<Vec<u8>>,
    #[sqlx(default)]
    pub config: Option<serde_json::Value>,
    pub sync_status: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
    pub last_sync_duration_ms: Option<i64>,
    pub user_count: Option<i32>,
    /// NAN-1124: users soft-deleted by mark-absent / the reconcile job for this provider.
    #[sqlx(default)]
    pub deprovisioned_count: Option<i64>,
    #[serde(skip_serializing)]
    pub delta_link: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl IdentityProvider {
    pub fn has_credentials(&self) -> bool {
        self.credentials_encrypted
            .as_ref()
            .map_or(false, |c| !c.is_empty())
    }

    pub fn get_provider_type(&self) -> Option<IdentityProviderType> {
        self.provider_type.parse().ok()
    }
}

// =============================================================================
// Summary (API response — no secrets)
// =============================================================================

/// Provider summary for API responses (credentials stripped)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IdentityProviderSummary {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    pub enabled: bool,
    pub has_credentials: bool,
    pub config: Option<serde_json::Value>,
    pub sync_status: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
    pub last_sync_duration_ms: Option<i64>,
    pub user_count: Option<i32>,
    pub deprovisioned_count: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<IdentityProvider> for IdentityProviderSummary {
    fn from(p: IdentityProvider) -> Self {
        Self {
            has_credentials: p.has_credentials(),
            id: p.id,
            name: p.name,
            provider_type: p.provider_type,
            enabled: p.enabled,
            config: p.config,
            sync_status: p.sync_status,
            last_sync_at: p.last_sync_at,
            last_sync_error: p.last_sync_error,
            last_sync_duration_ms: p.last_sync_duration_ms,
            user_count: p.user_count,
            deprovisioned_count: p.deprovisioned_count,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

// =============================================================================
// CRUD Request Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateIdentityProvider {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    #[serde(default)]
    pub enabled: bool,
    /// Provider-specific configuration (sync_interval_hours, domain_filter, etc.)
    #[serde(default)]
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateIdentityProvider {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateIdentityProviderCredentials {
    /// JSON object with provider-specific credential fields
    pub credentials: serde_json::Value,
}

// =============================================================================
// User Record (database row)
// =============================================================================

/// A unified user record from any identity provider.
///
/// NAN-1117: the `user_registry` payload moved from a PG OLTP table to a CH
/// ReplacingMergeTree. CH has no BIGSERIAL, so the synthetic `id: i64` is
/// replaced by a stable composite string key `"{provider_id}|{external_id}"`
/// (see [`UserRecord::composite_id`]) — this is the value `GET
/// /api/identity/users/{id}` now takes. CH also has no row triggers, so
/// `created_at` is dropped and `updated_at` is derived from `last_synced_at`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UserRecord {
    /// Stable composite key `"{provider_id}|{external_id}"` (replaces the old
    /// BIGSERIAL id). Used as the path param for GET /api/identity/users/{id}.
    pub id: String,
    pub provider_id: String,
    pub external_id: String,
    pub username: Option<String>,
    pub upn: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub department: Option<String>,
    pub title: Option<String>,
    pub manager_upn: Option<String>,
    pub manager_display_name: Option<String>,
    pub company: Option<String>,
    pub office_location: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub groups: Option<Vec<String>>,
    pub account_enabled: Option<bool>,
    pub account_status: Option<String>,
    pub mfa_enabled: Option<bool>,
    pub last_sign_in_at: Option<DateTime<Utc>>,
    pub created_in_directory_at: Option<DateTime<Utc>>,
    pub phone: Option<String>,
    pub employee_id: Option<String>,
    pub employee_type: Option<String>,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub sync_hash: Option<String>,
    /// Derived from `last_synced_at` (CH has no PG `updated_at` trigger).
    pub updated_at: Option<DateTime<Utc>>,
}

impl UserRecord {
    /// Build the stable composite id from its parts.
    pub fn composite_id(provider_id: &str, external_id: &str) -> String {
        format!("{provider_id}|{external_id}")
    }

    /// Split a composite id back into (provider_id, external_id). Returns None
    /// if the id is not in the expected `provider|external` shape.
    pub fn split_composite_id(id: &str) -> Option<(&str, &str)> {
        id.split_once('|')
    }
}

/// ClickHouse row for `nanosiem.user_registry`. Deserialized via the
/// `clickhouse` crate (RowBinary), then mapped into [`UserRecord`]. Non-nullable
/// CH columns deserialize into plain (non-Option) Rust types; empty strings map
/// back to None in the API shape to preserve the prior PG nullability contract.
#[derive(Debug, Clone, clickhouse::Row, Deserialize)]
pub struct UserRegistryRow {
    pub provider_id: String,
    pub external_id: String,
    pub username: String,
    pub upn: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub department: String,
    pub title: String,
    pub manager_upn: String,
    pub manager_display_name: String,
    pub company: String,
    pub office_location: String,
    pub city: String,
    pub country: String,
    pub groups: Vec<String>,
    pub account_enabled: u8,
    pub account_status: String,
    pub mfa_enabled: u8,
    /// Unix-ms epoch (CH DateTime64(3)); 0 = unset.
    pub last_sign_in_at: i64,
    pub created_in_directory_at: i64,
    pub phone: String,
    pub employee_id: String,
    pub employee_type: String,
    pub sync_hash: String,
    pub last_synced_at: i64,
    pub version: u64,
}

impl From<UserRegistryRow> for UserRecord {
    fn from(r: UserRegistryRow) -> Self {
        let opt = |s: String| if s.is_empty() { None } else { Some(s) };
        // CH DateTime64(3) values arrive as ms-epoch i64; 0 means unset.
        let opt_ts = |ms: i64| -> Option<DateTime<Utc>> {
            if ms == 0 {
                None
            } else {
                DateTime::<Utc>::from_timestamp_millis(ms)
            }
        };
        let id = UserRecord::composite_id(&r.provider_id, &r.external_id);
        UserRecord {
            id,
            provider_id: r.provider_id,
            external_id: r.external_id,
            username: opt(r.username),
            upn: opt(r.upn),
            email: opt(r.email),
            display_name: opt(r.display_name),
            first_name: opt(r.first_name),
            last_name: opt(r.last_name),
            department: opt(r.department),
            title: opt(r.title),
            manager_upn: opt(r.manager_upn),
            manager_display_name: opt(r.manager_display_name),
            company: opt(r.company),
            office_location: opt(r.office_location),
            city: opt(r.city),
            country: opt(r.country),
            groups: Some(r.groups),
            account_enabled: Some(r.account_enabled != 0),
            account_status: opt(r.account_status),
            mfa_enabled: Some(r.mfa_enabled != 0),
            last_sign_in_at: opt_ts(r.last_sign_in_at),
            created_in_directory_at: opt_ts(r.created_in_directory_at),
            phone: opt(r.phone),
            employee_id: opt(r.employee_id),
            employee_type: opt(r.employee_type),
            last_synced_at: opt_ts(r.last_synced_at),
            sync_hash: opt(r.sync_hash),
            updated_at: opt_ts(r.last_synced_at),
        }
    }
}

/// Fields written during a sync operation (no auto-generated IDs/timestamps)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecordUpsert {
    pub external_id: String,
    pub username: Option<String>,
    pub upn: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub department: Option<String>,
    pub title: Option<String>,
    pub manager_upn: Option<String>,
    pub manager_display_name: Option<String>,
    pub company: Option<String>,
    pub office_location: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub groups: Vec<String>,
    pub account_enabled: bool,
    pub account_status: String,
    pub mfa_enabled: Option<bool>,
    pub last_sign_in_at: Option<DateTime<Utc>>,
    pub created_in_directory_at: Option<DateTime<Utc>>,
    pub phone: Option<String>,
    pub employee_id: Option<String>,
    pub employee_type: Option<String>,
    pub sync_hash: String,
}

// =============================================================================
// Sync Result Types
// =============================================================================

/// Result of a sync operation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IdentitySyncResult {
    pub provider_id: String,
    pub users_synced: u64,
    pub users_created: u64,
    pub users_updated: u64,
    pub users_disabled: u64,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub is_delta: bool,
}

/// Result from a delta sync operation.
/// NAN-1151: `users` are RAW provider objects emitted onto the enrichment lane.
#[derive(Debug, Clone)]
pub struct DeltaSyncResult {
    pub users: Vec<serde_json::Value>,
    pub new_delta_link: Option<String>,
}

/// Result of testing a provider connection
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConnectionTestResult {
    pub success: bool,
    pub response_time_ms: Option<u64>,
    pub error: Option<String>,
    pub user_count_sample: Option<u64>,
}

/// Overall identity statistics
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IdentityStats {
    pub total_users: i64,
    pub active_users: i64,
    pub disabled_users: i64,
    pub providers: Vec<ProviderStatsSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProviderStatsSummary {
    pub provider_id: String,
    pub provider_name: String,
    pub provider_type: String,
    pub user_count: i64,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub sync_status: Option<String>,
}

// =============================================================================
// Credential Types (per provider type)
// =============================================================================

/// Entra ID credentials (MS Graph API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraIdCredentials {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
}

/// Google Workspace credentials (Admin SDK)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleWorkspaceCredentials {
    pub service_account_json: String,
    pub admin_email: String,
    pub domain: String,
}

/// Okta credentials (Users API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaCredentials {
    /// Okta org domain (e.g. dev-12345.okta.com)
    pub domain: String,
    /// SSWS API token
    pub api_token: String,
}

/// Workday credentials (RaaS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkdayCredentials {
    /// Published RaaS report URL
    pub report_url: String,
    /// Integration System User (ISU) username
    pub username: String,
    /// ISU password
    pub password: String,
}

/// Active Directory collector credentials (push-based)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveDirectoryCredentials {
    pub collector_token: String,
}

// NAN-1151 (3d): `PushUsersRequest` / `PushUserRecord` (the AD /push request
// types) and `into_upsert` (the hard-coded AD→user_registry field map) are all
// gone. AD identity now flows through the nano_enrich lane like every other
// source — the external collector POSTs nano_enrich records and the
// repo-sourced `enrichments/identity/ad` VRL maps them. No hard-coded identity
// mapping or in-app AD ingestion path remains anywhere in core.

// =============================================================================
// User list query params
// =============================================================================

#[derive(Debug, Clone, Deserialize, utoipa::IntoParams)]
pub struct ListUsersParams {
    /// Filter by provider ID
    pub provider_id: Option<String>,
    /// Search term (matches username, display_name, email, department)
    pub search: Option<String>,
    /// Filter by account status
    pub account_status: Option<String>,
    /// Page number (1-based)
    #[serde(default = "default_page")]
    pub page: i64,
    /// Page size
    #[serde(default = "default_page_size")]
    pub page_size: i64,
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    50
}

/// Paginated user list response
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UserListResponse {
    pub users: Vec<UserRecord>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

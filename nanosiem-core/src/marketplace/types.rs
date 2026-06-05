// SPDX-License-Identifier: AGPL-3.0-or-later

//! Type definitions for the enrichment marketplace

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

// =============================================================================
// Enums
// =============================================================================

/// Category of marketplace enrichment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum MarketplaceCategory {
    /// Bulk data feeds (IPinfo)
    Data,
    /// On-demand artifact lookups (VirusTotal, AbuseIPDB, GreyNoise)
    Agent,
    /// Identity provider sync (Entra ID, Google Workspace, AD)
    Identity,
    /// Threat-intel feeds (Tor Exit Nodes, MalwareBazaar, Shodan, URLhaus, ThreatFox)
    Security,
}

impl std::fmt::Display for MarketplaceCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MarketplaceCategory::Data => write!(f, "data"),
            MarketplaceCategory::Agent => write!(f, "agent"),
            MarketplaceCategory::Identity => write!(f, "identity"),
            MarketplaceCategory::Security => write!(f, "security"),
        }
    }
}

impl std::str::FromStr for MarketplaceCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "data" => Ok(MarketplaceCategory::Data),
            "agent" => Ok(MarketplaceCategory::Agent),
            "identity" => Ok(MarketplaceCategory::Identity),
            "security" => Ok(MarketplaceCategory::Security),
            _ => Err(format!("Invalid marketplace category: {}", s)),
        }
    }
}

/// Execution backend for a marketplace enrichment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionBackend {
    /// TypeScript code running in Deno sandbox
    Deno,
    /// Built-in Rust implementation (IPinfo, native agent providers)
    Native,
    /// Identity provider sync engine
    Identity,
}

impl std::fmt::Display for ExecutionBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionBackend::Deno => write!(f, "deno"),
            ExecutionBackend::Native => write!(f, "native"),
            ExecutionBackend::Identity => write!(f, "identity"),
        }
    }
}

impl std::str::FromStr for ExecutionBackend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "deno" => Ok(ExecutionBackend::Deno),
            "native" => Ok(ExecutionBackend::Native),
            "identity" => Ok(ExecutionBackend::Identity),
            _ => Err(format!("Invalid execution backend: {}", s)),
        }
    }
}

/// Where the enrichment comes from
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    /// Shipped with NanoSIEM
    System,
    /// Pulled from an external GitHub repository
    Repository,
    /// Created by the user
    Custom,
}

impl std::fmt::Display for SourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceType::System => write!(f, "system"),
            SourceType::Repository => write!(f, "repository"),
            SourceType::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for SourceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "system" => Ok(SourceType::System),
            "repository" => Ok(SourceType::Repository),
            "custom" => Ok(SourceType::Custom),
            _ => Err(format!("Invalid source type: {}", s)),
        }
    }
}

/// Credential requirement level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum CredentialRequirement {
    None,
    Optional,
    Required,
}

impl std::fmt::Display for CredentialRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialRequirement::None => write!(f, "none"),
            CredentialRequirement::Optional => write!(f, "optional"),
            CredentialRequirement::Required => write!(f, "required"),
        }
    }
}

impl std::str::FromStr for CredentialRequirement {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(CredentialRequirement::None),
            "optional" => Ok(CredentialRequirement::Optional),
            "required" => Ok(CredentialRequirement::Required),
            _ => Err(format!("Invalid credential requirement: {}", s)),
        }
    }
}

// =============================================================================
// Database Models
// =============================================================================

/// An enrichment marketplace repository (external GitHub repo)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct EnrichmentMarketplaceRepo {
    #[serde(with = "typeid::catalog")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub url: String,
    pub branch: String,
    pub enrichments_path: String,
    pub auto_sync_enabled: bool,
    pub sync_interval_hours: i32,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub last_sync_commit: Option<String>,
    pub last_sync_status: Option<String>,
    pub last_sync_error: Option<String>,
    pub enrichment_count: i32,
    pub enabled: bool,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A unified marketplace catalog entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct MarketplaceCatalogEntry {
    #[serde(with = "typeid::catalog")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub category: String,
    pub tags: Vec<String>,
    pub icon: Option<String>,
    pub author: Option<String>,

    // Source tracking
    pub source_type: String,
    #[serde(default, with = "typeid::catalog::opt")]
    #[schema(value_type = Option<String>)]
    pub repository_id: Option<Uuid>,
    pub repository_file_path: Option<String>,
    pub manifest_version: i32,

    // Execution backend
    pub execution_backend: String,

    // Links to underlying subsystems
    #[serde(default, with = "typeid::enrichment::opt")]
    #[schema(value_type = Option<String>)]
    pub custom_enrichment_id: Option<Uuid>,
    pub native_source_id: Option<String>,
    pub identity_provider_id: Option<String>,

    // Install state
    pub installed: bool,
    pub installed_at: Option<DateTime<Utc>>,
    pub installed_version: Option<i32>,

    // Credentials (self-contained, not linked to cloud_credentials)
    pub requires_credential: String,
    #[schema(value_type = serde_json::Value)]
    pub credential_fields: sqlx::types::Json<serde_json::Value>,
    #[serde(skip_serializing)]
    pub credentials_encrypted: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub credentials_nonce: Option<String>,

    // Computed: whether credentials are stored (for frontend display)
    #[sqlx(skip)]
    #[serde(default)]
    pub has_credentials: bool,

    // Code
    pub code: Option<String>,
    pub allowed_domains: Vec<String>,
    #[schema(value_type = serde_json::Value)]
    pub config: sqlx::types::Json<serde_json::Value>,

    // Status
    pub enabled: bool,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_status: Option<String>,
    pub last_error: Option<String>,
    pub record_count: i64,
    /// True when a sync is currently in flight for this entry (a row exists
    /// in `custom_enrichment_runs` with `status='running'` and a null
    /// `completed_at`). Lets the catalog card distinguish "actively fetching
    /// right now" from "configured and healthy" — both used to look the
    /// same as a green "running" pill (NAN-1108). Derived per-query in
    /// `hydrate_with_run_state`, not stored on `marketplace_catalog`.
    #[serde(default)]
    #[sqlx(default)]
    pub is_syncing: bool,

    // Changelog (from manifest, shown on update notifications)
    pub changelog: Option<String>,

    /// True when this entry's live install/sync path requires outbound internet
    /// (so it can't operate in an air-gapped install without an imported bundle).
    /// Computed in [`Self::compute_requires_network`] from the execution backend
    /// + allowed_domains — NOT a stored column — and populated in the
    /// repository's `hydrate`. The rule:
    ///   - `identity` providers always sync from an external IdP → true
    ///   - `deno` enrichments reach out only if they declare `allowed_domains`
    ///     (a pure-transform deno enrichment with no domains stays offline) → true iff non-empty
    ///   - `native` (IPinfo Lite) pulls a bulk feed over HTTP → true
    /// Offline-capable entries (custom transforms, empty `allowed_domains`) → false.
    #[serde(default)]
    #[sqlx(default)]
    pub requires_network: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl MarketplaceCatalogEntry {
    /// Derive [`Self::requires_network`] from the execution backend +
    /// allowed_domains. See the field doc for the rule. Called from the
    /// repository's `hydrate` so every returned entry carries the flag.
    pub fn compute_requires_network(&self) -> bool {
        match self.execution_backend.as_str() {
            "identity" => true,
            "native" => true,
            "deno" => !self.allowed_domains.is_empty(),
            _ => false,
        }
    }
}

// =============================================================================
// Request / Response types
// =============================================================================

/// Request to create a new marketplace repo
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateMarketplaceRepo {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default = "default_enrichments_path")]
    pub enrichments_path: String,
    #[serde(default)]
    pub auto_sync_enabled: bool,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_hours: i32,
}

fn default_branch() -> String {
    "main".to_string()
}

fn default_enrichments_path() -> String {
    "enrichments/".to_string()
}

fn default_sync_interval() -> i32 {
    24
}

/// Request to update a marketplace repo
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateMarketplaceRepo {
    pub name: Option<String>,
    pub description: Option<String>,
    pub branch: Option<String>,
    pub enrichments_path: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
    pub enabled: Option<bool>,
}

/// Request to install an enrichment from the catalog
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InstallRequest {
    /// Credential values for enrichments that require credentials
    #[serde(default)]
    pub credentials: Option<serde_json::Value>,
    /// Optional configuration overrides
    #[serde(default)]
    pub config: Option<serde_json::Value>,
}

/// Request to configure an installed enrichment
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConfigureRequest {
    /// Updated credentials (will be encrypted)
    #[serde(default)]
    pub credentials: Option<serde_json::Value>,
    /// Updated configuration
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    /// Enable or disable
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Filter for listing catalog entries
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::IntoParams)]
pub struct CatalogFilter {
    /// Filter by category (data, agent, identity)
    pub category: Option<String>,
    /// Filter by installed status
    pub installed: Option<bool>,
    /// Filter by tag
    pub tag: Option<String>,
    /// Search by name/description
    pub search: Option<String>,
    /// Filter by source type (system, repository, custom)
    pub source_type: Option<String>,
}

/// Summary response for catalog listing
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CatalogListResponse {
    pub entries: Vec<MarketplaceCatalogEntry>,
    pub total: i64,
    pub stats: CatalogStats,
}

/// Aggregate stats for the catalog
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CatalogStats {
    pub total_entries: i64,
    pub installed_count: i64,
    pub data_count: i64,
    pub agent_count: i64,
    pub identity_count: i64,
    pub security_count: i64,
}

/// Status response for a single enrichment
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EnrichmentStatus {
    pub slug: String,
    pub installed: bool,
    pub enabled: bool,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_status: Option<String>,
    pub last_error: Option<String>,
    pub record_count: i64,
}

/// Sync result for a repo sync operation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RepoSyncResult {
    #[serde(with = "typeid::catalog")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    pub status: String,
    pub commit: Option<String>,
    pub enrichment_count: i32,
    pub enrichments_added: i32,
    pub enrichments_updated: i32,
    pub enrichments_removed: i32,
    pub duration_ms: u64,
    pub error: Option<String>,
}

// =============================================================================
// Manifest types (parsed from YAML in external repos)
// =============================================================================

/// Manifest file format for enrichments in external repos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceManifest {
    pub name: String,
    pub slug: String,
    pub category: String,
    pub description: String,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default = "default_author")]
    pub author: String,
    #[serde(default = "default_manifest_version")]
    pub version: i32,

    #[serde(default = "default_credential_req")]
    pub requires_credential: String,
    #[serde(default)]
    pub credential_fields: Vec<CredentialFieldDef>,

    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub output_mapping: Option<serde_json::Value>,
    #[serde(default)]
    pub changelog: Option<String>,
}

fn default_author() -> String {
    "Community".to_string()
}

fn default_manifest_version() -> i32 {
    1
}

fn default_credential_req() -> String {
    "none".to_string()
}

/// Definition of a credential field in a manifest
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialFieldDef {
    pub name: String,
    pub label: String,
    #[serde(default = "default_field_type")]
    pub field_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub help: Option<String>,
}

fn default_field_type() -> String {
    "secret".to_string()
}

/// Tree entry when browsing a repo
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RepoBrowseEntry {
    pub path: String,
    pub name: String,
    pub entry_type: String,
    pub has_manifest: bool,
}

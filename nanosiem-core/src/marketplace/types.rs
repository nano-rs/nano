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
    /// Scheduled event pull from a SaaS API onto the ingest lane (Netskope).
    ///
    /// NAN-2189. Unlike the other three, a collector produces *log events*, not
    /// enrichment rows — it is configured per vendor tenant via
    /// `integration_instances` and its output is parsed by the parsers repo
    /// like any other source.
    Collector,
}

impl std::fmt::Display for MarketplaceCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MarketplaceCategory::Data => write!(f, "data"),
            MarketplaceCategory::Agent => write!(f, "agent"),
            MarketplaceCategory::Identity => write!(f, "identity"),
            MarketplaceCategory::Collector => write!(f, "collector"),
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
            "collector" => Ok(MarketplaceCategory::Collector),
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
    /// Sandboxed pull collector streaming events onto the ingest lane (NAN-2189)
    Collector,
}

impl std::fmt::Display for ExecutionBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionBackend::Deno => write!(f, "deno"),
            ExecutionBackend::Native => write!(f, "native"),
            ExecutionBackend::Identity => write!(f, "identity"),
            ExecutionBackend::Collector => write!(f, "collector"),
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
            "collector" => Ok(ExecutionBackend::Collector),
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
    // NOTE: `config` below is NOT `skip_serializing` like the two encrypted
    // fields above. New custom-enrichment publications strip the publisher's
    // secrets (NAN-2151), but installed entries may hold consumer-supplied
    // config and historical rows may predate that policy. Always use
    // `redacted()` before serializing into an API response — NAN-2069.

    // Code
    #[serde(skip_serializing_if = "Option::is_none")]
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
    /// NAN-2069: mask secret values in `config` before this entry is
    /// serialized into an API response.
    ///
    /// Historical publications copied cleartext `auth_config` into
    /// `marketplace_catalog`, and installed entries may contain a consumer's
    /// own configuration. The catalog list endpoint has no per-entry filter,
    /// so redaction remains a required defense even though NAN-2151 prevents
    /// new publications from duplicating the publisher's credentials.
    ///
    /// Applied at the API boundary, not in the repository: the installer
    /// (`install_service`) and the Deno provider may read consumer-supplied
    /// values from the same rows and need the real values.
    #[must_use]
    pub fn redacted(self) -> Self {
        self.redacted_with_code_access(false)
    }

    /// Redact secret config and conditionally include executable source.
    ///
    /// The default [`Self::redacted`] path is deliberately fail-closed. API
    /// handlers must make the composite `enrichments:view` +
    /// `enrichments:code` decision explicitly before returning source.
    #[must_use]
    pub fn redacted_with_code_access(mut self, include_code: bool) -> Self {
        crate::config_secrets::redact_config_secrets(&mut self.config.0);
        if !include_code {
            self.code = None;
        }
        self
    }

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

    // -------------------------------------------------------------------------
    // Collector fields (NAN-2189)
    //
    // All optional so the existing enrichment manifests in `nano-enrichments`
    // keep parsing byte-for-byte unchanged. A manifest that sets none of these
    // is an enrichment; one that sets `streams` is a collector.
    // -------------------------------------------------------------------------
    /// How nano injects credentials into the sandbox's outbound requests.
    /// Values match `custom_enrichment::AuthType` (`api_key_header`, `bearer`,
    /// `basic_auth`, `oauth2_client_credentials`, `none`).
    #[serde(default)]
    pub auth_type: Option<String>,

    /// Which credential fields feed the chosen `auth_type`, plus any static
    /// parameters it needs (header name, OAuth token URL, scope).
    #[serde(default)]
    pub auth: Option<ManifestAuth>,

    /// Non-secret operator config (tenant hostname, region, org id). Distinct
    /// from `credential_fields`: these are readable through the API and appear
    /// in logs, so nothing sensitive belongs here.
    #[serde(default)]
    pub config_fields: Vec<ConfigFieldDef>,

    /// Suffix allowlist admitting per-tenant hostnames supplied via
    /// `config_fields` (e.g. `.goskope.com`). Needed because a collector's host
    /// is not knowable at authoring time, unlike an enrichment's fixed API
    /// endpoint. Validated to at least two labels so `.com` can never be
    /// declared.
    #[serde(default)]
    pub allowed_domain_suffixes: Vec<String>,

    /// Independently toggleable feeds this collector can pull. Presence of a
    /// non-empty `streams` list is what makes a manifest a collector.
    #[serde(default)]
    pub streams: Vec<StreamDef>,
}

/// The inverse of `sync_service::effective_config`: pulls a collector's
/// manifest-level fields back out of a catalog row's `config` JSONB.
///
/// Sync flattens `streams` / `config_fields` / `allowed_domain_suffixes` /
/// `auth*` into `config` so no catalog columns were needed. Anything
/// reconstructing a manifest (export, round-trip tests) has to undo that, and
/// must also remove them from the leftover config — emitting them in both
/// places produces a manifest that re-imports as an enrichment with no streams.
#[derive(Debug, Clone, Default)]
pub struct CollectorManifestFields {
    pub auth_type: Option<String>,
    pub auth: Option<ManifestAuth>,
    pub config_fields: Vec<ConfigFieldDef>,
    pub allowed_domain_suffixes: Vec<String>,
    pub streams: Vec<StreamDef>,
    /// `config` with the lifted keys removed — what belongs under `config:` in
    /// the emitted manifest.
    pub remainder: serde_json::Value,
}

impl CollectorManifestFields {
    /// Keys sync writes into `config`. Kept in one place so lifting and
    /// stripping can never disagree about the set.
    const LIFTED_KEYS: [&'static str; 5] = [
        "streams",
        "config_fields",
        "allowed_domain_suffixes",
        "auth_type",
        "auth",
    ];

    pub fn take_from(config: &serde_json::Value) -> Self {
        let Some(map) = config.as_object() else {
            return Self {
                remainder: config.clone(),
                ..Default::default()
            };
        };

        let get = |key: &str| map.get(key).cloned();
        let mut remainder = map.clone();
        for key in Self::LIFTED_KEYS {
            remainder.remove(key);
        }

        Self {
            // Malformed values degrade to the default rather than failing the
            // export: a half-readable manifest is more useful to an operator
            // than a 500.
            auth_type: get("auth_type").and_then(|v| v.as_str().map(str::to_string)),
            auth: get("auth").and_then(|v| serde_json::from_value(v).ok()),
            config_fields: get("config_fields")
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default(),
            allowed_domain_suffixes: get("allowed_domain_suffixes")
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default(),
            streams: get("streams")
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default(),
            remainder: serde_json::Value::Object(remainder),
        }
    }
}

/// Auth parameters referenced from a collector manifest.
///
/// Field *names* rather than values — the secrets live in `credential_fields`
/// and are only ever materialized inside the sandbox process.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ManifestAuth {
    /// Header to carry the key, for `api_key_header`.
    #[serde(default)]
    pub header_name: Option<String>,
    /// Credential field holding the token/key, for `api_key_header` / `bearer`.
    #[serde(default)]
    pub credential_field: Option<String>,
    /// Credential fields for `basic_auth`.
    #[serde(default)]
    pub username_field: Option<String>,
    #[serde(default)]
    pub password_field: Option<String>,
    /// OAuth2 client-credentials parameters. `token_url` is shared with
    /// `service_account_jwt`, which posts its assertion to the same endpoint.
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub client_id_field: Option<String>,
    #[serde(default)]
    pub client_secret_field: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,

    // Service-account JWT (NAN-2198). Field *names*, resolved against the
    // instance's credentials/config at run time — a manifest never carries a key.
    /// Credential field holding the PEM-encoded PKCS#8 private key.
    #[serde(default)]
    pub private_key_field: Option<String>,
    /// Credential field holding the service account's address.
    #[serde(default)]
    pub client_email_field: Option<String>,
    /// Config field naming the user to impersonate. A config field rather than
    /// a credential because the admin's address is not a secret, and asking for
    /// it as one makes it unreadable in the UI for no benefit.
    #[serde(default)]
    pub subject_field: Option<String>,
}

/// A non-secret, operator-supplied configuration input.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConfigFieldDef {
    pub name: String,
    pub label: String,
    #[serde(default = "default_config_field_type")]
    pub field_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub help: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
}

fn default_config_field_type() -> String {
    "string".to_string()
}

/// One independently toggleable feed within a collector.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StreamDef {
    /// Stable id. Doubles as the cursor key — renaming resets the cursor.
    pub id: String,
    pub label: String,
    /// The `source_type` this stream's events are ingested under. Becomes the
    /// provisioned log source's match value.
    pub source_type: String,
    /// Repository parser (by its YAML `name`) that parses this stream.
    ///
    /// NAN-2248: when set, provisioning resolves the parser by name and the
    /// parser's `match_values` play no part in resolution. Before this field,
    /// the only way to find a stream's parser was a reverse lookup — index every
    /// repository parser's `match_values` and look up `source_type` — which
    /// forced a parser to claim one alias per stream (netskope carried nine)
    /// purely so collectors could find it. It also meant an unrelated edit in
    /// the parsers repo could silently unlink a collector, and
    /// `StreamProvisionOutcome::NoParser` is deliberately non-fatal, so the
    /// breakage surfaced only as events landing unparsed.
    ///
    /// Left optional: manifests written before this field, and third-party ones
    /// that never adopt it, keep resolving through the `match_values` fallback.
    #[serde(default)]
    pub parser: Option<String>,
    /// Pre-checked at install time.
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub description: Option<String>,
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

/// Determine the functional enrichment type (`"data"` vs `"agent"`) for a
/// marketplace entry from its `category` and manifest `config`.
///
/// `category` is a coarse *UI grouping*, not a functional type. The retired
/// (NAN-1998) `"security"` category once spanned BOTH bulk data feeds (ThreatFox,
/// Tor exit nodes — `enrich(context)`) and on-demand agent lookups (urlhaus,
/// shodan, malwarebazaar — `enrich(artifact, type, creds)`). Deriving the type
/// from category alone mislabeled the data feeds as `agent`, so they never got
/// scheduled, hid their "Sync now" button, and crashed preview (NAN-1585).
///
/// The manifest `config` carries the reliable signal:
/// - on-demand AGENT lookups declare `artifact_types`
/// - bulk DATA feeds declare `key_field`
///
/// Checked in that order so an entry declaring both is treated as an agent
/// lookup. Falls back to `category` for legacy entries whose config carries
/// neither marker — and stays robust to any lingering/legacy category value
/// (e.g. a pre-NAN-1998 `"security"` row) by resolving on the config markers.
pub fn infer_enrichment_type(category: &str, config: &serde_json::Value) -> &'static str {
    if config.get("artifact_types").is_some() {
        "agent"
    } else if config.get("key_field").is_some() {
        "data"
    } else if category == "data" {
        "data"
    } else {
        "agent"
    }
}

#[cfg(test)]
mod infer_type_tests {
    use super::infer_enrichment_type;
    use serde_json::json;

    #[test]
    fn data_feed_with_key_field_is_data_even_under_legacy_security_category() {
        // ThreatFox / Tor: a bulk feed. Config markers win even if a lingering
        // pre-NAN-1998 'security' category value is passed (robustness during
        // the retire-security migration window).
        assert_eq!(
            infer_enrichment_type("security", &json!({"key_field": "ioc", "key_type": "ip"})),
            "data"
        );
    }

    #[test]
    fn agent_lookup_with_artifact_types_is_agent_even_under_legacy_security_category() {
        // urlhaus / shodan / malwarebazaar: on-demand lookup — resolves on the
        // config marker regardless of a legacy 'security' category value.
        assert_eq!(
            infer_enrichment_type("security", &json!({"artifact_types": ["url"]})),
            "agent"
        );
    }

    #[test]
    fn artifact_types_wins_when_both_markers_present() {
        assert_eq!(
            infer_enrichment_type("legacy", &json!({"artifact_types": ["ip"], "key_field": "x"})),
            "agent"
        );
    }

    #[test]
    fn falls_back_to_category_without_config_markers() {
        assert_eq!(infer_enrichment_type("data", &json!({})), "data");
        assert_eq!(infer_enrichment_type("agent", &json!({})), "agent");
        // An unknown/legacy category with no config markers defaults to agent.
        assert_eq!(infer_enrichment_type("security", &json!({})), "agent");
    }
}

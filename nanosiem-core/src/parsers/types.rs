// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser types and data structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::typeid;

/// Source types for parsers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    File,
    Syslog,
    Http,
    Kafka,
    Stdin,
    /// Routed source type - receives logs from HTTP router based on X-Source-Type header
    Routed,
    /// AWS S3 bucket via SQS notifications
    AwsS3,
    /// AWS SQS consumed directly — the message body IS the log (NAN-2187)
    AwsSqs,
    /// GCP Pub/Sub subscription
    GcpPubSub,
}

impl SourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Syslog => "syslog",
            Self::Http => "http",
            Self::Kafka => "kafka",
            Self::Stdin => "stdin",
            Self::Routed => "routed",
            Self::AwsS3 => "aws_s3",
            Self::AwsSqs => "aws_sqs",
            Self::GcpPubSub => "gcp_pubsub",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "file" => Some(Self::File),
            "syslog" => Some(Self::Syslog),
            "http" => Some(Self::Http),
            "kafka" => Some(Self::Kafka),
            "stdin" => Some(Self::Stdin),
            "routed" => Some(Self::Routed),
            "aws_s3" | "s3" => Some(Self::AwsS3),
            "aws_sqs" | "sqs" => Some(Self::AwsSqs),
            "gcp_pubsub" | "pubsub" => Some(Self::GcpPubSub),
            _ => None,
        }
    }

    /// Get the list of all valid source type strings
    pub fn all_types() -> &'static [&'static str] {
        &[
            "file",
            "syslog",
            "http",
            "kafka",
            "stdin",
            "routed",
            "aws_s3",
            "aws_sqs",
            "gcp_pubsub",
        ]
    }
}

/// Cloud provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    AwsS3,
    GcpPubSub,
    Kafka,
}

impl CloudProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AwsS3 => "aws_s3",
            Self::GcpPubSub => "gcp_pubsub",
            Self::Kafka => "kafka",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "aws_s3" | "s3" => Some(Self::AwsS3),
            "gcp_pubsub" | "pubsub" | "gcp" => Some(Self::GcpPubSub),
            "kafka" => Some(Self::Kafka),
            _ => None,
        }
    }
}

/// Cloud credential metadata (for listing, excludes actual secrets)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudCredential {
    #[serde(with = "typeid::cloud_credential")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub provider: String,
    pub description: Option<String>,
    pub region: Option<String>,
    /// `sts:ExternalId` for a cross-account role assumption (NAN-2186).
    ///
    /// Stored and returned UNENCRYPTED, unlike the credential payload. An
    /// ExternalId is not a secret — it is an unguessable identifier the account
    /// owner must know to write the trust policy that lets us assume their
    /// role. Keeping it in the encrypted blob made it write-only, since this
    /// struct (what `GET /api/credentials` returns) carries no payload at all.
    /// `None` for static-key and ambient-identity credentials.
    pub external_id: Option<String>,
    /// Optional environment tag — one of "prod" / "staging" / "dev"
    pub environment: Option<String>,
    /// Optional rotation deadline — drives the Health badge in the UI
    pub expires_at: Option<DateTime<Utc>>,
    /// Timestamp of the most recent decrypt-for-deploy (best-effort, set by ParserService)
    pub last_used_at: Option<DateTime<Utc>>,
    /// Currently-active version number; matches `cloud_credential_versions.version_number` where `is_active = true`
    pub active_version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create cloud credentials
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateCloudCredential {
    pub name: String,
    pub provider: String,
    /// See [`CloudCredential::external_id`] — lifted out of `credentials` so it
    /// stays readable after creation.
    #[serde(default)]
    pub external_id: Option<String>,
    /// Provider-specific credential JSON (will be encrypted before storage)
    pub credentials: serde_json::Value,
    pub description: Option<String>,
    pub region: Option<String>,
    pub environment: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to update cloud credentials (metadata only — to replace secret
/// material use `rotate` which produces a new version row)
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateCloudCredential {
    pub name: Option<String>,
    pub description: Option<String>,
    pub region: Option<String>,
    pub environment: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to rotate a credential's secret material — creates a new active
/// version while preserving the prior version for rollback
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RotateCloudCredential {
    /// Provider-specific credential JSON (encrypted before storage)
    pub credentials: serde_json::Value,
    /// See [`CloudCredential::external_id`]. A rotation may change the auth
    /// POSTURE — static keys today, a cross-account role tomorrow — so this
    /// must be rewritten alongside the payload. `None` clears it, which is
    /// correct when rotating from a role back to static keys.
    #[serde(default)]
    pub external_id: Option<String>,
    pub note: Option<String>,
}

/// Request to roll back to a previous credential version
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RollbackCloudCredential {
    /// Version number to roll back to — must reference an existing version
    pub version: i32,
    pub note: Option<String>,
}

/// One row from a credential's version history
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudCredentialVersion {
    #[serde(with = "typeid::cloud_credential")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::cloud_credential")]
    #[schema(value_type = String)]
    pub credential_id: Uuid,
    pub version_number: i32,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    pub note: Option<String>,
    pub is_active: bool,
    /// Set when this version was created by a rollback — points at the source version_number
    pub reverted_from_version: Option<i32>,
}

/// AWS S3 credentials structure (stored encrypted)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AwsS3Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Optional session token for temporary credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    /// Optional role ARN for cross-account access
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assume_role_arn: Option<String>,
}

/// GCP Pub/Sub credentials structure (stored encrypted)
/// Uses service account JSON key for authentication
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GcpPubSubCredentials {
    /// Service account JSON key (full JSON content, not path)
    pub credentials_json: String,
}

/// Kafka credentials structure (stored encrypted)
/// Supports SASL/PLAIN, SASL/SCRAM, and SSL authentication
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct KafkaCredentials {
    /// SASL mechanism: "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512", or none for unauthenticated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sasl_mechanism: Option<String>,
    /// SASL username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sasl_username: Option<String>,
    /// SASL password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sasl_password: Option<String>,
    /// Enable TLS/SSL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_enabled: Option<bool>,
    /// CA certificate PEM (for self-signed certs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca_cert: Option<String>,
}

fn default_parser_kind() -> String {
    "log".to_string()
}

/// A parser definition
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Parser {
    #[serde(with = "typeid::parser")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_type: String,
    pub parser_vrl: String,
    pub output_fields: Option<serde_json::Value>,
    #[serde(default, with = "typeid::feed::opt")]
    #[schema(value_type = Option<String>)]
    pub feed_id: Option<Uuid>,
    /// NAN-928: dispatch source-configuration whose route this parser should
    /// consume from (set by the parser-import "DISPATCH FROM" picker).
    /// Surfaced here so the Vector config generator can read it without
    /// re-fetching the LogSource row.
    #[serde(default, with = "typeid::source_config::opt")]
    #[schema(value_type = Option<String>)]
    pub dispatch_source_config_id: Option<Uuid>,
    /// NAN-928: transient route name resolved from
    /// `dispatch_source_config_id` (format: `<safe_name>_route`). The
    /// LogSourceService stamps this just before passing parsers into the
    /// Vector generator so the kafka/aws_s3/gcp_pubsub branches can emit a
    /// `filter inputs = ["<dispatch_route_name>"]` instead of a parser-owned
    /// source. Not persisted; not part of the public API or wire format
    /// (`#[serde(skip)]` keeps it out of JSON in both directions).
    #[serde(default, skip)]
    pub dispatch_route_name: Option<String>,
    pub enabled: bool,
    pub validated: bool,
    pub validation_error: Option<String>,
    /// Category for ClickHouse (e.g., "network", "endpoint", "cloud")
    pub category: Option<String>,
    /// Vendor name (e.g., "Apache", "Microsoft", "Palo Alto")
    pub vendor: Option<String>,
    /// Product name (e.g., "Windows Event Log", "Firewall")
    pub product: Option<String>,
    /// NAN-1149: parser flavor. "log" (default) = a normal log-source parser;
    /// "enrichment" = a push-enrichment normalizer that carries `normalize_vrl`
    /// + `enrich_kind`/`enrich_source`/`target_table` instead of routing a
    /// `source_type`. The Vector config generator splits on this.
    #[serde(default = "default_parser_kind")]
    pub kind: String,
    /// Enrichment kind (identity | ip_context | asset | ioc); set when kind = "enrichment".
    #[serde(default)]
    pub enrich_kind: Option<String>,
    /// Per-source discriminator the enrichment lane routes `.source` by
    /// (e.g. "ad", "entra"); emitted as `enrichment_normalize_<enrich_source>`.
    #[serde(default)]
    pub enrich_source: Option<String>,
    /// Target ClickHouse table the enrichment writes (e.g. "user_registry").
    #[serde(default)]
    pub target_table: Option<String>,
    /// Per-source normalize VRL for enrichment parsers — the remap body emitted
    /// as `[transforms.enrichment_normalize_<enrich_source>]` (NAN-1149).
    #[serde(default)]
    pub normalize_vrl: Option<String>,
    /// Network namespace for identity resolution (from log_sources)
    pub namespace: String,
    /// IANA timezone for timestamps without offset info (e.g., "America/New_York")
    pub timezone: String,
    /// Source type values this parser handles (for routing).
    /// When set, the router matches `.source_type` against these values instead of the parser name.
    #[serde(default)]
    pub match_values: Option<Vec<String>>,
    /// Sample ratio 0.0-1.0 (e.g., 0.1 = keep 10%). None = no sampling (keep all).
    pub sampling_ratio: Option<f64>,
    /// VRL condition for events that are NEVER sampled (e.g., .action != "allow"). None = no exclusions.
    pub sampling_exclude_condition: Option<String>,
    /// Optional VRL overlay chained after _parse, before _output (NAN-874).
    /// Stub case: when parser_vrl is effectively empty and extension_vrl is set,
    /// the extension IS the parser for this source_type.
    #[serde(default)]
    pub extension_vrl: Option<String>,
    /// Toggle whether extension_vrl is deployed (NAN-874).
    #[serde(default)]
    pub extension_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new parser
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewParser {
    pub name: String,
    pub description: Option<String>,
    pub source_type: String,
    pub parser_vrl: String,
    pub output_fields: Option<serde_json::Value>,
    #[serde(default, with = "typeid::feed::opt")]
    #[schema(value_type = Option<String>)]
    pub feed_id: Option<Uuid>,
    /// Source configuration that owns transport connection and credentials.
    #[serde(default, with = "typeid::source_config::opt")]
    #[schema(value_type = Option<String>)]
    pub dispatch_source_config_id: Option<Uuid>,
}

/// Request to update a parser
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateParser {
    pub name: Option<String>,
    pub description: Option<String>,
    pub source_type: Option<String>,
    pub parser_vrl: Option<String>,
    pub output_fields: Option<serde_json::Value>,
    #[serde(default, with = "typeid::feed::opt")]
    #[schema(value_type = Option<String>)]
    pub feed_id: Option<Uuid>,
    /// Source configuration that owns transport connection and credentials.
    #[serde(default, with = "typeid::source_config::opt")]
    #[schema(value_type = Option<String>)]
    pub dispatch_source_config_id: Option<Uuid>,
    pub enabled: Option<bool>,
    /// Sample ratio 0.0-1.0 (e.g., 0.1 = keep 10%). None = no sampling (keep all).
    pub sampling_ratio: Option<f64>,
    /// VRL condition for events that are NEVER sampled.
    pub sampling_exclude_condition: Option<String>,
}

/// VRL validation result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VrlValidationResult {
    pub valid: bool,
    pub error: Option<String>,
    pub warnings: Vec<String>,
}

/// Vector configuration validation result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ValidationResult {
    pub success: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub raw_output: String,
}

/// Parser test result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ParserTestResult {
    pub success: bool,
    pub input: String,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Deployment action types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentAction {
    Deploy,
    Undeploy,
    Rollback,
}

impl DeploymentAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Undeploy => "undeploy",
            Self::Rollback => "rollback",
        }
    }
}

/// Deployment status types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Success,
    Failed,
    RolledBack,
}

impl DeploymentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// Parser deployment record
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ParserDeployment {
    #[serde(with = "typeid::parser")]
    #[schema(value_type = String)]
    pub id: uuid::Uuid,
    #[serde(with = "typeid::parser")]
    #[schema(value_type = String)]
    pub parser_id: uuid::Uuid,
    pub action: String,
    pub status: String,
    pub error_message: Option<String>,
    pub config_snapshot: Option<String>,
    pub deployed_at: chrono::DateTime<chrono::Utc>,
}

/// Result of a deployment operation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DeploymentResult {
    pub success: bool,
    #[serde(with = "typeid::parser")]
    #[schema(value_type = String)]
    pub parser_id: uuid::Uuid,
    pub action: String,
    pub message: String,
    pub validation_result: Option<ValidationResult>,
    #[serde(default, with = "typeid::parser::opt")]
    #[schema(value_type = Option<String>)]
    pub deployment_id: Option<uuid::Uuid>,
}

/// Parser category for library organization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParserCategory {
    Endpoint,    // Windows Event, Sysmon, EDR
    Network,     // Firewall, IDS/IPS, NetFlow
    Cloud,       // AWS, Azure, GCP
    Identity,    // Okta, Azure AD, LDAP
    Application, // Web servers, databases
    Security,    // AV, DLP, SIEM
}

impl ParserCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Network => "network",
            Self::Cloud => "cloud",
            Self::Identity => "identity",
            Self::Application => "application",
            Self::Security => "security",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "endpoint" => Some(Self::Endpoint),
            "network" => Some(Self::Network),
            "cloud" => Some(Self::Cloud),
            "identity" => Some(Self::Identity),
            "application" => Some(Self::Application),
            "security" => Some(Self::Security),
            _ => None,
        }
    }
}

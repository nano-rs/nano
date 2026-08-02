// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Source types and data structures
//!
//! Unified entity combining ingestion configuration (from parsers),
//! VRL transformation, and metadata (from feeds).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::typeid;

/// Source types for log sources
///
/// NanoSIEM requires every log event to have a `source_type` defined for routing.
/// Only sources that support source type identification are included here.
/// For sources that don't support this natively (syslog, OTLP, Fluent, files),
/// use a Vector aggregator on-premises to tag events before forwarding.
/// See documentation: /docs/reference/supported-sources
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    /// Receive via HTTP with X-Source-Type header (most common)
    Routed,
    /// Kafka consumer - source_type defined per feed
    Kafka,
    /// AWS S3 bucket via SQS - source_type defined per feed
    AwsS3,
    /// GCP Pub/Sub subscription - source_type defined per feed
    GcpPubSub,
    /// Splunk HTTP Event Collector - uses HEC sourcetype field
    SplunkHec,
    /// Vector-to-Vector forwarding - source_type field in event
    Vector,
}

impl SourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Routed => "routed",
            Self::Kafka => "kafka",
            Self::AwsS3 => "aws_s3",
            Self::GcpPubSub => "gcp_pubsub",
            Self::SplunkHec => "splunk_hec",
            Self::Vector => "vector",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "routed" | "http" => Some(Self::Routed),
            "kafka" => Some(Self::Kafka),
            "aws_s3" | "aws_sqs" | "s3" => Some(Self::AwsS3),
            "gcp_pubsub" | "pubsub" => Some(Self::GcpPubSub),
            "splunk_hec" | "splunk" | "hec" => Some(Self::SplunkHec),
            "vector" => Some(Self::Vector),
            _ => None,
        }
    }

    /// Get display label for UI
    pub fn label(&self) -> &'static str {
        match self {
            Self::Routed => "HTTP",
            Self::Kafka => "Kafka",
            Self::AwsS3 => "AWS S3",
            Self::GcpPubSub => "GCP Pub/Sub",
            Self::SplunkHec => "Splunk HEC",
            Self::Vector => "Vector",
        }
    }

    /// Get description for UI
    pub fn description(&self) -> &'static str {
        match self {
            Self::Routed => "Receive via HTTP with X-Source-Type header",
            Self::Kafka => "Consume logs from Kafka topics (source_type per feed)",
            Self::AwsS3 => "Ingest logs from AWS S3 via SQS (source_type per feed)",
            Self::GcpPubSub => "Subscribe to GCP Pub/Sub topics (source_type per feed)",
            Self::SplunkHec => "Receive logs via Splunk HEC (uses HEC sourcetype)",
            Self::Vector => "Receive from on-prem Vector aggregator (source_type in event)",
        }
    }

    /// Get all available source types
    pub fn all_types() -> &'static [Self] {
        &[
            Self::Routed,
            Self::Kafka,
            Self::AwsS3,
            Self::GcpPubSub,
            Self::SplunkHec,
            Self::Vector,
        ]
    }
}

impl std::fmt::Display for SourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Log source category
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogSourceCategory {
    Network,
    Endpoint,
    Cloud,
    Application,
    Security,
    System,
    Identity,
    Other,
}

impl LogSourceCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Endpoint => "endpoint",
            Self::Cloud => "cloud",
            Self::Application => "application",
            Self::Security => "security",
            Self::System => "system",
            Self::Identity => "identity",
            Self::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "network" => Some(Self::Network),
            "endpoint" => Some(Self::Endpoint),
            "cloud" => Some(Self::Cloud),
            "application" => Some(Self::Application),
            "security" => Some(Self::Security),
            "system" => Some(Self::System),
            "identity" => Some(Self::Identity),
            "other" => Some(Self::Other),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Network => "Network",
            Self::Endpoint => "Endpoint",
            Self::Cloud => "Cloud",
            Self::Application => "Application",
            Self::Security => "Security",
            Self::System => "System",
            Self::Identity => "Identity",
            Self::Other => "Other",
        }
    }
}

impl std::fmt::Display for LogSourceCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A unified log source definition
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LogSource {
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub id: Uuid,

    // Identity
    pub name: String,
    pub description: Option<String>,

    // Network namespace for identity resolution isolation
    // Format: {provider}:{account}:{network} (e.g., "aws:123456789012:vpc-abc", "onprem:dc-east")
    // Prevents cross-environment identity confusion with overlapping private IP spaces
    #[serde(default = "default_namespace")]
    pub namespace: String,

    /// IANA timezone for timestamps without offset info (e.g., "America/New_York")
    #[serde(default = "default_utc")]
    pub timezone: String,

    // Parser routing
    pub source_type: String,

    // Dispatch source (NAN-928): the deployed source-configuration whose
    // routing transform feeds events into this parser. Set when the user
    // picks a fetch-source config (Kafka / S3 / GCP Pub/Sub) in the
    // parser-import "DISPATCH FROM" UI. When `Some`, the parser generator
    // emits a `filter` on `<sc.safe_name>_route` instead of a brand-new
    // parser-owned source (which was the silent-failure pre-NAN-928).
    // Fetch parsers must carry this link; connection configuration and
    // credentials live exclusively on source_configurations.
    #[serde(default, with = "typeid::source_config::opt")]
    #[schema(value_type = Option<String>)]
    pub dispatch_source_config_id: Option<Uuid>,

    // NAN-1084: derived transport label resolved from the joined
    // source_configurations row (e.g. "gcp_pubsub", "kafka"). Populated by
    // list queries that LEFT JOIN source_configurations; left as None on
    // read paths that don't join, in which case the UI falls back to
    // `source_type`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_source_config_type: Option<String>,

    // Transformation
    pub parser_vrl: String,
    pub output_fields: Option<serde_json::Value>,

    // Parser extension (NAN-874): optional VRL overlay chained after _parse, before _output.
    // When extension_vrl is set and extension_enabled is true, parser_config emits an extra
    // {safe_name}_extension transform and rewires {safe_name}_output.inputs to consume it.
    // Stub case: parser_vrl empty + extension set → extension IS the parser for this source_type.
    #[serde(default)]
    pub extension_vrl: Option<String>,
    #[serde(default)]
    pub extension_enabled: bool,

    // Metadata
    pub category: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,

    // Matching criteria (for routing/discovery)
    pub match_field: Option<String>,
    pub match_pattern: Option<String>,
    pub match_values: Option<Vec<String>>,

    // Validation & Deployment
    pub validated: bool,
    pub validation_error: Option<String>,
    pub deployed: bool,
    pub deployed_at: Option<DateTime<Utc>>,

    // Status
    pub enabled: bool,

    // Lifecycle (NAN-1920): "draft" = created via the AddFeed wizard but not yet
    // deployed (survives navigation, shown as a Draft in the Log Sources list);
    // "active" = a normal, fully-owned feed. Flips draft → active on deploy.
    // Distinct from the parser working-copy "draft" (log_source_versions).
    #[serde(default = "default_lifecycle_status")]
    pub lifecycle_status: String,

    // Staleness monitoring
    pub stale_alert_enabled: bool,
    pub stale_threshold_minutes: i32,

    // Sampling
    /// Sample ratio 0.0-1.0 (e.g., 0.1 = keep 10%). None = no sampling (keep all).
    pub sampling_ratio: Option<f64>,
    /// VRL condition for events that are NEVER sampled (e.g., .action != "allow"). None = no exclusions.
    pub sampling_exclude_condition: Option<String>,

    // Enrichment-parser flavor (NAN-1149)
    /// "log" (default) = a normal log-source parser; "enrichment" = a
    /// push-enrichment normalizer that carries `normalize_vrl` +
    /// `enrich_kind`/`enrich_source`/`target_table` instead of routing a
    /// log `source_type`. The deploy path splits on this so an enrichment
    /// source is staged into the push enrichment lane, not the log pipeline.
    #[serde(default = "default_log_source_kind")]
    pub kind: String,
    /// Enrichment domain (identity | ip_context | asset | ioc); set when kind = "enrichment".
    #[serde(default)]
    pub enrich_kind: Option<String>,
    /// Per-source discriminator the enrichment lane routes on (e.g. "ad", "entra").
    #[serde(default)]
    pub enrich_source: Option<String>,
    /// Target ClickHouse table the enrichment writes (e.g. "user_registry").
    #[serde(default)]
    pub target_table: Option<String>,
    /// Per-source normalize VRL — the remap body emitted into the enrichment lane.
    #[serde(default)]
    pub normalize_vrl: Option<String>,

    // Parser repository tracking
    /// Parser repository this log source was imported from (if any)
    #[serde(with = "typeid::parser_repo::opt")]
    #[schema(value_type = Option<String>)]
    pub source_parser_repository_id: Option<Uuid>,
    /// Path within the source parser repository
    pub source_parser_path: Option<String>,
    /// Whether log source is linked for auto-updates from parser repo
    #[serde(default)]
    pub source_parser_linked: bool,

    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new log source
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewLogSource {
    pub name: String,
    pub description: Option<String>,
    /// Network namespace for identity resolution (e.g., "aws:123456789012:vpc-abc", "onprem:dc-east")
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// IANA timezone for timestamps without offset info (e.g., "America/New_York")
    #[serde(default = "default_utc")]
    pub timezone: String,
    pub source_type: String,
    pub parser_vrl: String,
    pub output_fields: Option<serde_json::Value>,
    /// NAN-928: dispatch source-configuration this parser should consume from.
    /// When set on a fetch-source parser (kafka/aws_s3/gcp_pubsub), the
    /// generator emits a filter on the source-config's routing transform
    /// instead of a parser-owned Vector source.
    #[serde(default, with = "typeid::source_config::opt")]
    #[schema(value_type = Option<String>)]
    pub dispatch_source_config_id: Option<Uuid>,
    pub category: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub match_field: Option<String>,
    pub match_pattern: Option<String>,
    pub match_values: Option<Vec<String>>,
    /// Sample ratio 0.0-1.0 (e.g., 0.1 = keep 10%). None = no sampling.
    pub sampling_ratio: Option<f64>,
    /// VRL condition for events that are NEVER sampled.
    pub sampling_exclude_condition: Option<String>,
    /// NAN-1920 lifecycle: "draft" | "active". Omitted → defaults to "active"
    /// in the repository INSERT, so pre-NAN-1920 callers are unaffected. The
    /// AddFeed wizard sends "draft" for its auto-persisted in-progress feed.
    #[serde(default)]
    pub lifecycle_status: Option<String>,
}

fn default_namespace() -> String {
    "default".to_string()
}

fn default_utc() -> String {
    "UTC".to_string()
}

fn default_log_source_kind() -> String {
    "log".to_string()
}

fn default_lifecycle_status() -> String {
    "active".to_string()
}

/// Request to update a log source (all fields optional)
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateLogSource {
    pub name: Option<String>,
    pub description: Option<String>,
    /// Network namespace for identity resolution
    pub namespace: Option<String>,
    /// IANA timezone for timestamps without offset info
    pub timezone: Option<String>,
    pub source_type: Option<String>,
    pub parser_vrl: Option<String>,
    /// NAN-1151: enrichment-parser mapping VRL. Lets the upstream-update/apply
    /// path refresh a linked enrichment parser (which carries `normalize_vrl`,
    /// not `parser_vrl`).
    #[serde(default)]
    pub normalize_vrl: Option<String>,
    pub output_fields: Option<serde_json::Value>,
    /// NAN-928: rebind dispatch source. `None` here means "no change"; use
    /// the dedicated null-clear path on the API if you need to unbind.
    #[serde(default, with = "typeid::source_config::opt")]
    #[schema(value_type = Option<String>)]
    pub dispatch_source_config_id: Option<Uuid>,
    pub category: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub match_field: Option<String>,
    pub match_pattern: Option<String>,
    pub match_values: Option<Vec<String>>,
    pub enabled: Option<bool>,
    // NAN-1920: lifecycle_status is intentionally NOT updatable via this generic
    // update path. It is server-controlled — set to 'draft'/'active' at create
    // and flipped to 'active' only by the deploy path (which enforces the tier
    // cap at the draft→active transition). Exposing it here would let a client
    // pre-flip a draft to 'active' and bypass that cap check.
    pub stale_alert_enabled: Option<bool>,
    pub stale_threshold_minutes: Option<i32>,
    /// Sample ratio 0.0-1.0 (e.g., 0.1 = keep 10%). None = no change.
    pub sampling_ratio: Option<f64>,
    /// VRL condition for events that are NEVER sampled. None = no change.
    pub sampling_exclude_condition: Option<String>,
    /// Optional VRL overlay (NAN-874). Tri-state semantics enforced by
    /// `repository::update`'s SQL CASE expression:
    ///   - `None`           → column unchanged
    ///   - `Some("")`       → column set to NULL (extension removed)
    ///   - `Some(content)`  → column set to `content`
    ///
    /// JSON callers must omit the field entirely to mean "no change"; sending
    /// an empty string is the explicit clear signal.
    pub extension_vrl: Option<String>,
    /// Toggle whether extension_vrl is included in deploys. None = no change.
    pub extension_enabled: Option<bool>,
    /// Optimistic-concurrency precondition: the caller's last-seen
    /// [`LogSource::updated_at`]. When present, the update succeeds only if
    /// the stored timestamp still matches. Optional so existing internal and
    /// API callers retain unconditional-update behavior.
    #[serde(default)]
    pub expected_updated_at: Option<DateTime<Utc>>,
}

/// Log source with health metrics for list views
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LogSourceWithHealth {
    #[serde(flatten)]
    pub log_source: LogSource,
    pub health: Option<LogSourceHealthSummary>,
}

/// Summary health metrics for list views
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LogSourceHealthSummary {
    pub total_events: i64,
    pub events_last_24h: i64,
    pub last_event_at: Option<DateTime<Utc>>,
    pub health_status: HealthStatus,
}

/// Detailed health metrics for a log source
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LogSourceHealth {
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    pub log_source_name: String,

    // Event counts. Detailed live-health metrics are bounded to the last 24h;
    // `total_events` is retained as a compatibility alias for that window.
    pub total_events: i64,
    pub events_last_24h: i64,
    pub events_last_hour: i64,
    pub avg_events_per_hour: f64,

    // Timing
    pub last_event_at: Option<DateTime<Utc>>,
    pub first_event_at: Option<DateTime<Utc>>,
    pub data_freshness_hours: Option<f64>,

    // Trends
    pub ingestion_rate_trend: IngestionTrend,

    // Health
    pub health_status: HealthStatus,

    // Storage
    pub total_size_bytes: i64,
    pub avg_event_size_bytes: f64,

    // Errors
    pub error_rate_24h: f64,
    pub parse_errors_24h: i64,
    /// Events evaluated by this parser in the last 24 hours, counted before
    /// optional log sampling.
    pub parse_attempts_24h: i64,
    /// Runtime parse success ratio over the last 24 hours. `None` means no
    /// production events were available; static VRL validation is not counted.
    pub parse_success_rate_24h: Option<f64>,

    // Collector errors (NAN-2196)
    //
    // Distinct from `parse_errors_24h` above, and the distinction is the whole
    // point. Parse errors mean data ARRIVED and we failed to understand it.
    // These mean data never arrived at all — the collector could not reach the
    // queue, assume the role, or authenticate. Before this, those two states
    // were indistinguishable from the outside: both looked like silence.
    /// Most recent collector failures attributed to this source, newest first.
    /// Empty when the collector is healthy — or when it has never reported,
    /// which is the same thing from here.
    #[serde(default)]
    pub collector_errors: Vec<CollectorError>,
    /// Count over the last 24 hours. Separate from `collector_errors.len()`,
    /// which is capped for display — a source failing every 15 seconds should
    /// read as thousands of failures, not as the handful we chose to show.
    #[serde(default)]
    pub collector_errors_24h: i64,
    /// A specific likely cause, when the error and the source's configuration
    /// together point at one. `None` means we will not guess: the raw error is
    /// in `collector_errors` and inventing a confident diagnosis on top of a
    /// generic message like `dispatch failure` would be worse than silence.
    #[serde(default)]
    pub collector_error_hint: Option<String>,
}

/// One collector failure, as reported by the collector itself.
///
/// Deliberately a near-verbatim record of what Vector said rather than a nano
/// abstraction over it. The value here is ground truth from the process that
/// actually failed; normalising it into our own taxonomy would discard the
/// detail that makes it diagnostic.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CollectorError {
    pub timestamp: DateTime<Utc>,
    /// `WARN` or `ERROR`. The collector filters anything lower before it
    /// reaches storage.
    pub level: String,
    /// Human-readable text, e.g. `Failed to fetch SQS events.`
    pub message: String,
    /// Stable machine-readable code, e.g. `failed_fetching_sqs_events`. Empty
    /// when the collector did not classify the failure.
    pub error_code: String,
    /// e.g. `request_failed`.
    pub error_type: String,
    /// Which end of the pipeline broke — `receiving`, `processing`, `sending`.
    pub stage: String,
    /// The collector driver — `aws_s3`, `kafka`, `gcp_pubsub`, … Distinguishes
    /// "this transport is broken everywhere" from "this one source is broken".
    pub component_type: String,
}

/// Health status of a log source
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Receiving events normally
    Healthy,
    /// Not received events recently
    Stale,
    /// Never received any events
    NoData,
    /// Log source is disabled
    Disabled,
    /// Validation errors
    Error,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Stale => "stale",
            Self::NoData => "no_data",
            Self::Disabled => "disabled",
            Self::Error => "error",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "healthy" => Some(Self::Healthy),
            "stale" => Some(Self::Stale),
            "no_data" => Some(Self::NoData),
            "disabled" => Some(Self::Disabled),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Ingestion rate trend
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IngestionTrend {
    Increasing,
    Stable,
    Decreasing,
    Unknown,
}

impl IngestionTrend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Increasing => "increasing",
            Self::Stable => "stable",
            Self::Decreasing => "decreasing",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "increasing" => Some(Self::Increasing),
            "stable" => Some(Self::Stable),
            "decreasing" => Some(Self::Decreasing),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

impl std::fmt::Display for IngestionTrend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A versioned snapshot of a log source's parser configuration
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct LogSourceVersion {
    pub id: i32,
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    pub version_number: i32,
    pub parser_vrl: String,
    pub output_fields: Option<serde_json::Value>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    #[serde(with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub change_reason: String,
    pub reverted_from_version: Option<i32>,
    /// Snapshot of extension_vrl at publish time (NAN-874).
    #[serde(default)]
    pub extension_vrl: Option<String>,
    /// Snapshot of extension_enabled at publish time (NAN-874).
    #[serde(default)]
    pub extension_enabled: bool,
}

/// Log source with draft status information for the UI
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LogSourceWithDraftStatus {
    #[serde(flatten)]
    pub log_source: LogSource,
    pub has_draft_changes: bool,
    pub active_version_number: Option<i32>,
    pub active_parser_vrl: Option<String>,
}

/// Deployment action types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
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

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "deploy" => Some(Self::Deploy),
            "undeploy" => Some(Self::Undeploy),
            "rollback" => Some(Self::Rollback),
            _ => None,
        }
    }
}

/// Deployment status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
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

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "success" => Some(Self::Success),
            "failed" => Some(Self::Failed),
            "rolled_back" => Some(Self::RolledBack),
            _ => None,
        }
    }
}

/// A deployment history record
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LogSourceDeployment {
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    pub action: String,
    pub status: String,
    pub error_message: Option<String>,
    pub config_snapshot: Option<String>,
    pub deployed_at: DateTime<Utc>,
}

/// Result of a deployment operation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
// Schema renamed for the spec only (NAN-2270): parsers + source_configs each have one, and the
// OpenAPI component registry is flat. The Rust name stays.
#[schema(as = LogSourceDeploymentResult)]
pub struct DeploymentResult {
    pub success: bool,
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    pub action: String,
    pub message: String,
    pub validation_result: Option<VrlValidationResult>,
    #[serde(with = "typeid::log_source::opt")]
    #[schema(value_type = Option<String>)]
    pub deployment_id: Option<Uuid>,
}

/// Structured VRL diagnostic, extracted from the VRL compiler when possible.
///
/// One diagnostic is emitted per error/warning. `line` and `col` are populated
/// when the VRL compiler exposes a span; otherwise they're left as `None`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VrlDiagnostic {
    /// "error" | "warn" | "info"
    pub severity: String,
    pub line: Option<u32>,
    pub col: Option<u32>,
    /// Optional rule code (e.g. "W003") if the compiler provides one
    pub code: Option<String>,
    pub message: String,
    pub hint: Option<String>,
}

/// VRL validation result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
// Schema renamed for the spec only (NAN-2270): parsers::types is canonical, and the
// OpenAPI component registry is flat. The Rust name stays.
#[schema(as = LogSourceVrlValidationResult)]
pub struct VrlValidationResult {
    pub valid: bool,
    /// Free-form error strings, kept for backward compatibility with existing
    /// frontend consumers. New consumers should prefer `diagnostics`.
    pub errors: Vec<String>,
    /// Structured diagnostics (errors + warnings) with optional line/col.
    #[serde(default)]
    pub diagnostics: Vec<VrlDiagnostic>,
}

/// Result of testing VRL against a sample log
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
// Schema renamed for the spec only (NAN-2270): parsers::types is canonical, and the
// OpenAPI component registry is flat. The Rust name stays.
#[schema(as = LogSourceParserTestResult)]
pub struct ParserTestResult {
    pub input: String,
    pub success: bool,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    /// Number of top-level fields in `output` (0 when output is None or not an object).
    #[serde(default)]
    pub extracted_field_count: u32,
}

/// Result of testing VRL against a real event, comparing current vs new parse
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LiveTestResult {
    /// Raw log message from ClickHouse
    pub input: String,
    /// Result of parsing with the new (edited) VRL
    pub new_parse: ParserTestResult,
    /// Result of parsing with the current (deployed) VRL, if available
    pub current_parse: Option<ParserTestResult>,
}

/// History data point for charting
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct HistoryPoint {
    pub timestamp: DateTime<Utc>,
    pub event_count: i64,
}

/// Ingestion history point for multi-source area chart
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IngestionHistoryPoint {
    pub source_type: String,
    pub timestamp: DateTime<Utc>,
    pub count: i64,
}

/// List parameters for filtering and pagination
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ListParams {
    pub category: Option<String>,
    pub source_type: Option<String>,
    pub vendor: Option<String>,
    pub enabled: Option<bool>,
    pub deployed: Option<bool>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ============================================================================
// Wizard Types
// ============================================================================

/// Wizard entry point options
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WizardEntry {
    /// User has sample logs - AI will detect source type
    WithSamples { sample_logs: Vec<String> },
    /// User knows source type - configure directly
    WithSourceType {
        source_type: String,
        vendor: Option<String>,
        product: Option<String>,
    },
}

/// Current wizard step
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum WizardStep {
    /// Entry point - choose path
    Start,
    /// AI detecting source type from samples
    DetectingSource,
    /// Configure source connection
    ConfigureSource {
        source_type: String,
        detected_vendor: Option<String>,
        detected_product: Option<String>,
    },
    /// Generate and refine VRL parser
    GenerateParser,
    /// Set metadata
    SetMetadata,
    /// Validate and test
    Validate,
    /// Deploy
    Deploy,
    /// Complete
    Complete {
        #[serde(with = "typeid::log_source")]
        #[schema(value_type = String)]
        log_source_id: Uuid,
    },
}

/// AI suggestions during wizard
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AiSuggestions {
    pub detected_format: Option<String>, // "json", "xml", "syslog", "cef", etc.
    pub suggested_name: Option<String>,
    pub suggested_category: Option<String>,
    pub suggested_vendor: Option<String>,
    pub suggested_product: Option<String>,
    /// Detected IANA timezone from sample timestamps (e.g., "America/New_York")
    pub suggested_timezone: Option<String>,
    pub confidence: f64,
}

/// Wizard session state
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WizardSession {
    pub session_id: String,
    pub current_step: WizardStep,
    pub log_source_draft: NewLogSource,
    pub sample_logs: Vec<String>,
    pub validation_result: Option<VrlValidationResult>,
    pub test_results: Vec<ParserTestResult>,
    pub ai_suggestions: Option<AiSuggestions>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Progress event for wizard (for streaming updates)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WizardProgressEvent {
    /// Started source detection
    DetectionStarted,
    /// Source detected
    DetectionComplete { suggestions: AiSuggestions },
    /// Parser generation started
    GeneratingParser { attempt: usize, max_attempts: usize },
    /// VRL syntax validation result
    SyntaxValidationResult { valid: bool, errors: Vec<String> },
    /// Testing parser against samples
    TestingParser {
        sample_index: usize,
        total_samples: usize,
    },
    /// Test results
    TestResults {
        passed: usize,
        failed: usize,
        total: usize,
    },
    /// Retrying with feedback
    RetryingWithFeedback {
        attempt: usize,
        max_attempts: usize,
        reason: String,
        error_details: Option<String>,
    },
    /// Stub parser detected
    StubDetected { reason: String },
    /// Parser generation complete
    GenerationComplete { success: bool, message: String },
    /// Deployment started
    DeploymentStarted,
    /// Deployment complete
    DeploymentComplete { success: bool, message: String },
}

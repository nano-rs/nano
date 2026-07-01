// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source Configuration types and data structures
//!
//! Source Configurations define infrastructure connections (Kafka, S3, etc.)
//! with routing rules that determine source_type for log routing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::typeid;

/// Source configuration type - what kind of infrastructure connection
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceConfigType {
    /// Native HTTP ingestion endpoint (system-level)
    Http,
    /// Apache Kafka consumer
    Kafka,
    /// AWS S3 via SQS notifications
    AwsS3,
    /// GCP Pub/Sub subscription
    GcpPubSub,
    /// Splunk HTTP Event Collector endpoint
    SplunkHec,
    /// Vector-to-Vector native protocol (system-level)
    Vector,
    /// OpenTelemetry (OTLP) over gRPC (:4317) / HTTP (:4318) (system-level)
    Otlp,
}

impl SourceConfigType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Kafka => "kafka",
            Self::AwsS3 => "aws_s3",
            Self::GcpPubSub => "gcp_pubsub",
            Self::SplunkHec => "splunk_hec",
            Self::Vector => "vector",
            Self::Otlp => "otlp",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "http" => Some(Self::Http),
            "kafka" => Some(Self::Kafka),
            "aws_s3" | "s3" => Some(Self::AwsS3),
            "gcp_pubsub" | "pubsub" => Some(Self::GcpPubSub),
            "splunk_hec" | "splunk" | "hec" => Some(Self::SplunkHec),
            "vector" => Some(Self::Vector),
            "otlp" | "opentelemetry" | "otel" => Some(Self::Otlp),
            _ => None,
        }
    }

    /// Whether this source type requires cloud credentials
    pub fn requires_credentials(&self) -> bool {
        matches!(self, Self::AwsS3 | Self::GcpPubSub | Self::Kafka)
    }

    /// Get display label for UI
    pub fn label(&self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Kafka => "Kafka",
            Self::AwsS3 => "AWS S3",
            Self::GcpPubSub => "GCP Pub/Sub",
            Self::SplunkHec => "Splunk HEC",
            Self::Vector => "Vector",
            Self::Otlp => "OpenTelemetry (OTLP)",
        }
    }

    /// Get description for UI
    pub fn description(&self) -> &'static str {
        match self {
            Self::Http => "Native HTTP ingestion with X-Source-Type header routing (system-level)",
            Self::Kafka => "Consume logs from Kafka topics with topic-based routing",
            Self::AwsS3 => "Ingest logs from AWS S3 via SQS with bucket/key-based routing",
            Self::GcpPubSub => "Subscribe to GCP Pub/Sub with attribute-based routing",
            Self::SplunkHec => "Receive logs via Splunk HEC with sourcetype-based routing",
            Self::Vector => "Receive from on-prem Vector aggregator (system-level)",
            Self::Otlp => {
                "Receive OpenTelemetry (OTLP) logs via gRPC (:4317) / HTTP (:4318) (system-level)"
            }
        }
    }

    /// Get all available source config types
    pub fn all_types() -> &'static [Self] {
        &[
            Self::Http,
            Self::Kafka,
            Self::AwsS3,
            Self::GcpPubSub,
            Self::SplunkHec,
            Self::Vector,
            Self::Otlp,
        ]
    }

    /// Get the default match field for this source type
    pub fn default_match_field(&self) -> &'static str {
        match self {
            Self::Http => "source_type",
            Self::Kafka => "topic",
            Self::AwsS3 => "bucket",
            Self::GcpPubSub => "subscription",
            Self::SplunkHec => "sourcetype",
            Self::Vector => "source_type",
            Self::Otlp => "source_type",
        }
    }

    /// Whether this is a "pull" source — i.e. the broker binds the source
    /// configuration to a single subscription/topic/queue/bucket and the
    /// publisher cannot label events via header. Multiplexing within a single
    /// pull source requires either publisher-set message attributes or
    /// content sniffing.
    ///
    /// HTTP and Vector are "push" sources: the sender labels each event
    /// in-band (e.g. via the `X-Source-Type` header), so one endpoint can
    /// host many source_types directly.
    pub fn is_pull_source(&self) -> bool {
        matches!(
            self,
            Self::Kafka | Self::AwsS3 | Self::GcpPubSub | Self::SplunkHec
        )
    }

    /// Per-driver preset list for `match_field` in the routing-rules UI.
    ///
    /// Push sources (HTTP, Vector) only ever use the in-band `source_type`
    /// header, so there's exactly one preset. Pull sources expose two or
    /// three meaningful options (publisher-set attribute vs. content
    /// sniffing), all of which are valid VRL paths emitted by Vector for
    /// the corresponding driver.
    pub fn match_field_presets(&self) -> Vec<MatchFieldPreset> {
        match self {
            Self::Http => vec![MatchFieldPreset {
                label: "Source type header".to_string(),
                path: "source_type".to_string(),
                description:
                    "Routes from the X-Source-Type header set by the sender on each request."
                        .to_string(),
            }],
            Self::Vector => vec![MatchFieldPreset {
                label: "Source type tag".to_string(),
                path: "source_type".to_string(),
                description:
                    "Routes from the .source_type tag set by the upstream Vector aggregator."
                        .to_string(),
            }],
            Self::Otlp => vec![MatchFieldPreset {
                label: "Source type tag".to_string(),
                path: "source_type".to_string(),
                description:
                    "Routes from the .source_type tag set by the OTLP logs preprocessor \
                     (otlp_logs_prep, config/vector/03-otlp-source.toml — `otlp_log` today; \
                     per-service source_types arrive with the OTLP-log envelope mapping)."
                        .to_string(),
            }],
            Self::GcpPubSub => vec![
                MatchFieldPreset {
                    label: "Message attribute (recommended)".to_string(),
                    path: "attributes.source_type".to_string(),
                    description:
                        "Set by the publisher via Pub/Sub message attributes. Cheapest match — no payload decode."
                            .to_string(),
                },
                MatchFieldPreset {
                    label: "Message body field".to_string(),
                    path: "message".to_string(),
                    description:
                        "Content sniffing — match on a JSON field inside the decoded payload. More expensive than attributes."
                            .to_string(),
                },
            ],
            Self::Kafka => vec![
                MatchFieldPreset {
                    label: "Header (recommended)".to_string(),
                    path: "headers.source_type".to_string(),
                    description:
                        "Set by the producer via Kafka record headers. Cheapest match — no payload decode."
                            .to_string(),
                },
                MatchFieldPreset {
                    label: "Topic name".to_string(),
                    path: "topic".to_string(),
                    description:
                        "Match on the Kafka topic the record was consumed from.".to_string(),
                },
                MatchFieldPreset {
                    label: "Message body field".to_string(),
                    path: "message".to_string(),
                    description:
                        "Content sniffing — match on a JSON field inside the decoded payload."
                            .to_string(),
                },
            ],
            Self::AwsS3 => vec![
                MatchFieldPreset {
                    label: "Bucket name (default)".to_string(),
                    path: "bucket".to_string(),
                    description: "Match on the S3 bucket the object was read from.".to_string(),
                },
                MatchFieldPreset {
                    label: "Object key".to_string(),
                    path: "key".to_string(),
                    description:
                        "Match on the S3 object key — useful for prefix-based routing within a single bucket."
                            .to_string(),
                },
            ],
            Self::SplunkHec => vec![
                MatchFieldPreset {
                    label: "Sourcetype (default)".to_string(),
                    path: "sourcetype".to_string(),
                    description:
                        "Splunk HEC `sourcetype` field — the canonical labelling for HEC events."
                            .to_string(),
                },
                MatchFieldPreset {
                    label: "Source".to_string(),
                    path: "source".to_string(),
                    description: "Splunk HEC `source` field.".to_string(),
                },
                MatchFieldPreset {
                    label: "Index".to_string(),
                    path: "index".to_string(),
                    description: "Splunk HEC `index` field.".to_string(),
                },
            ],
        }
    }
}

/// A preset entry for the routing-rule `match_field` dropdown.
///
/// The UI surfaces these per-driver to keep users out of the "which VRL
/// path do I type for Pub/Sub?" trap. `path` is exactly what gets stored
/// in the routing rule's `match_field` column and emitted as `.{path}`
/// in the generated VRL transform. Nested paths (e.g. `attributes.source_type`)
/// are supported and emit the obvious dotted access.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MatchFieldPreset {
    /// Short human-readable label for the dropdown row.
    pub label: String,
    /// VRL path stored as `match_field`. No leading dot — generator adds it.
    pub path: String,
    /// One-line description shown beneath the label.
    pub description: String,
}

/// Per-driver metadata for the source-config types API. Exposes the
/// information the frontend needs to render the routing-rule UI in
/// the right shape per driver (single-source vs. multi-source mode,
/// match_field presets, in-form binding-callout copy, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SourceConfigTypeInfo {
    /// Stable string identifier (matches `connection_config.config_type`).
    pub config_type: String,
    /// Display label for the type (e.g. "GCP Pub/Sub").
    pub label: String,
    /// One-line description shown beneath the label.
    pub description: String,
    /// True when this driver requires cloud credentials to connect.
    pub requires_credentials: bool,
    /// True when this is a pull (broker-bound) source — the UI uses this
    /// to switch between push-style "one config, N source_types via header"
    /// and pull-style "single vs. multi source_type per binding" modes.
    pub is_pull_source: bool,
    /// Default `match_field` value Vector emits / the generator falls back to.
    pub default_match_field: String,
    /// Available `match_field` presets shown in the dropdown.
    pub match_field_presets: Vec<MatchFieldPreset>,
}

impl SourceConfigTypeInfo {
    pub fn from_config_type(t: SourceConfigType) -> Self {
        Self {
            config_type: t.as_str().to_string(),
            label: t.label().to_string(),
            description: t.description().to_string(),
            requires_credentials: t.requires_credentials(),
            is_pull_source: t.is_pull_source(),
            default_match_field: t.default_match_field().to_string(),
            match_field_presets: t.match_field_presets(),
        }
    }
}

impl std::fmt::Display for SourceConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Match type for routing rules
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    /// Exact string match
    Exact,
    /// String prefix match (starts_with)
    Prefix,
    /// String suffix match (ends_with)
    Suffix,
    /// Regular expression match
    Regex,
    /// Substring match (contains)
    Contains,
    /// Default fallback (always matches)
    Default,
}

impl MatchType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Prefix => "prefix",
            Self::Suffix => "suffix",
            Self::Regex => "regex",
            Self::Contains => "contains",
            Self::Default => "default",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "exact" => Some(Self::Exact),
            "prefix" | "starts_with" => Some(Self::Prefix),
            "suffix" | "ends_with" => Some(Self::Suffix),
            "regex" => Some(Self::Regex),
            "contains" => Some(Self::Contains),
            "default" | "fallback" => Some(Self::Default),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Exact => "Equals",
            Self::Prefix => "Starts with",
            Self::Suffix => "Ends with",
            Self::Regex => "Regex",
            Self::Contains => "Contains",
            Self::Default => "Default (fallback)",
        }
    }
}

impl std::fmt::Display for MatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A routing rule that determines source_type based on message attributes
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RoutingRule {
    #[serde(with = "typeid::source_config")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::source_config")]
    #[schema(value_type = String)]
    pub source_configuration_id: Uuid,
    /// Lower = higher priority, 0 typically used for default
    pub priority: i32,
    /// Field to match on (bucket, topic, sourcetype, etc.)
    pub match_field: String,
    /// Type of match to perform
    pub match_type: String,
    /// Value to match (NULL for default type)
    pub match_value: Option<String>,
    /// Target source_type that activates the appropriate LogSource parser
    pub target_source_type: String,
    pub created_at: DateTime<Utc>,
    /// Approximate count of events credited to this rule in the last 24h.
    /// Best-effort ClickHouse enrichment; `None` when ClickHouse is unavailable
    /// or when telemetry was not requested.
    ///
    /// Per-rule attribution is approximate because Vector does not tag events
    /// with the routing rule id. The first rule per
    /// (source_configuration_id, target_source_type) is credited with the full
    /// count; later rules sharing the same target_source_type get `Some(0)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable)]
    pub fires_24h: Option<i64>,
    /// Approximate timestamp of the most recent event credited to this rule.
    /// Same best-effort + first-rule-wins semantics as `fires_24h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable)]
    pub last_fired_at: Option<DateTime<Utc>>,
}

/// Request to create a new routing rule
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewRoutingRule {
    pub priority: Option<i32>,
    pub match_field: String,
    pub match_type: String,
    pub match_value: Option<String>,
    pub target_source_type: String,
}

/// Request to update a routing rule
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateRoutingRule {
    pub priority: Option<i32>,
    pub match_field: Option<String>,
    pub match_type: Option<String>,
    pub match_value: Option<String>,
    pub target_source_type: Option<String>,
}

/// A source configuration for infrastructure connections
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SourceConfiguration {
    #[serde(with = "typeid::source_config")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub config_type: String,
    pub connection_config: serde_json::Value,
    #[serde(default, with = "typeid::cloud_credential::opt")]
    #[schema(value_type = Option<String>)]
    pub credential_id: Option<Uuid>,
    pub enabled: bool,
    pub deployed: bool,
    pub deployed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Best-effort sum of `events_last_24h` across log sources targeted by
    /// this config's routing rules. `None` when ClickHouse is unavailable
    /// or when enrichment is otherwise skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable)]
    pub events_24h: Option<i64>,
    /// Best-effort sum of received bytes (computed as
    /// `length(message) + length(metadata)` in ClickHouse) across log sources
    /// targeted by this config's routing rules over the last 24 hours.
    /// `None` when ClickHouse is unavailable or telemetry was not requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable)]
    pub bytes_per_day_24h: Option<i64>,
    /// Best-effort timestamp of the most recent event matched to any of this
    /// config's routing rules in the last 24h. `None` when ClickHouse is
    /// unavailable, telemetry was not requested, or no events match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable)]
    pub last_event_at: Option<DateTime<Utc>>,
}

/// Source configuration with its routing rules
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SourceConfigurationWithRules {
    #[serde(flatten)]
    pub config: SourceConfiguration,
    pub routing_rules: Vec<RoutingRule>,
}

/// Request to create a new source configuration
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewSourceConfiguration {
    pub name: String,
    pub description: Option<String>,
    pub config_type: String,
    pub connection_config: serde_json::Value,
    #[serde(default, with = "typeid::cloud_credential::opt")]
    #[schema(value_type = Option<String>)]
    pub credential_id: Option<Uuid>,
    /// Optional initial routing rules
    pub routing_rules: Option<Vec<NewRoutingRule>>,
}

/// Request to update a source configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateSourceConfiguration {
    pub name: Option<String>,
    pub description: Option<String>,
    pub config_type: Option<String>,
    pub connection_config: Option<serde_json::Value>,
    #[serde(default, with = "typeid::cloud_credential::opt")]
    #[schema(value_type = Option<String>)]
    pub credential_id: Option<Uuid>,
    pub enabled: Option<bool>,
}

// ============================================================================
// Deployment Types
// ============================================================================

/// A deployment history record
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SourceConfigDeployment {
    #[serde(with = "typeid::source_config")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::source_config")]
    #[schema(value_type = String)]
    pub source_configuration_id: Uuid,
    pub action: String,
    pub status: String,
    pub error_message: Option<String>,
    pub config_snapshot: Option<String>,
    pub deployed_at: DateTime<Utc>,
}

/// Result of a deployment operation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DeploymentResult {
    pub success: bool,
    #[serde(with = "typeid::source_config")]
    #[schema(value_type = String)]
    pub source_configuration_id: Uuid,
    pub action: String,
    pub message: String,
    #[serde(default, with = "typeid::source_config::opt")]
    #[schema(value_type = Option<String>)]
    pub deployment_id: Option<Uuid>,
}

/// List parameters for filtering source configurations
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ListParams {
    pub config_type: Option<String>,
    pub enabled: Option<bool>,
    pub deployed: Option<bool>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

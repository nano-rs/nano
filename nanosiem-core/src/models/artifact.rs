// SPDX-License-Identifier: AGPL-3.0-or-later

//! Artifact-analysis store model (NAN-1977).
//!
//! An `Artifact` is the persisted analysis REPORT for a dropped specimen — the
//! verdict, deobfuscation passes, IOCs, MITRE mapping, and the specimen text
//! itself (`original`). Binaries are reduced to printable strings before they
//! reach here, so no raw file bytes are ever stored. The store is SHARED: every
//! holder of `artifacts:view` sees the whole collection. JSON is snake_case,
//! matching every other resource in this API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

/// A fully-hydrated artifact-analysis report (includes the heavy specimen text).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Artifact {
    #[serde(with = "typeid::artifact")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    /// Lowercase hex SHA-256; empty while the client's async hash is still computing.
    pub sha256: String,
    pub size_bytes: i64,
    pub source: String,
    /// malicious | suspicious | analyzing | queued | clean (validated in the app layer).
    pub verdict: String,
    pub score: Option<f64>,
    /// The specimen text (printable strings for binaries).
    pub original: String,
    pub deobfuscated: Option<String>,
    /// Deobfuscation passes — `[{ "n", "title", "done" }]`.
    pub passes: serde_json::Value,
    /// Extracted IOCs — `[{ "kind", "value", "note?", "hits?", "hot?" }]`.
    pub iocs: serde_json::Value,
    /// MITRE ATT&CK technique ids — `["T1059.001", …]`.
    pub mitre: serde_json::Value,
    pub behavior: Option<String>,
    pub layer_chain: Option<String>,
    pub agent_note: Option<String>,
    pub entropy: Option<f64>,
    pub summary: Option<String>,
    pub status_line: Option<String>,
    /// Human display label for a linked investigation ("case-1043"), not an id.
    pub case_tag: Option<String>,
    pub correlation: Option<String>,
    pub analysis_secs: Option<f64>,
    /// Analysis engine that produced the report (claude/codex/agy), if known.
    pub engine: Option<String>,
    /// Opaque tool-findings passthrough (structured static analysis) — stored and
    /// returned verbatim; the store does not model its inner shape (see migration 262).
    pub static_analysis: Option<serde_json::Value>,
    /// Optional soft link to an investigation (bare UUID, no FK — see migration 261).
    #[serde(default, with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
    /// User who added the artifact (NULL if the account was later removed).
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// List projection — everything except the heavy `original` / `deobfuscated`
/// text bodies. The pane lazy-loads those via `GET /api/artifacts/{id}` when an
/// artifact is selected.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct ArtifactSummary {
    #[serde(with = "typeid::artifact")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub source: String,
    pub verdict: String,
    pub score: Option<f64>,
    pub passes: serde_json::Value,
    pub iocs: serde_json::Value,
    pub mitre: serde_json::Value,
    pub behavior: Option<String>,
    pub layer_chain: Option<String>,
    pub agent_note: Option<String>,
    pub entropy: Option<f64>,
    pub summary: Option<String>,
    pub status_line: Option<String>,
    pub case_tag: Option<String>,
    pub correlation: Option<String>,
    pub analysis_secs: Option<f64>,
    pub engine: Option<String>,
    /// Opaque tool-findings passthrough (structured static analysis) — carried in
    /// the list projection alongside the other structured analysis fields.
    pub static_analysis: Option<serde_json::Value>,
    #[serde(default, with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn empty_json_array() -> serde_json::Value {
    serde_json::Value::Array(Vec::new())
}

/// Input for adding an artifact. `created_by` is set from the authenticated
/// user by the handler, never accepted from the client.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewArtifact {
    pub name: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub size_bytes: i64,
    #[serde(default)]
    pub source: String,
    /// Defaults to "queued" when omitted.
    #[serde(default = "default_verdict")]
    pub verdict: String,
    #[serde(default)]
    pub score: Option<f64>,
    pub original: String,
    #[serde(default)]
    pub deobfuscated: Option<String>,
    #[serde(default = "empty_json_array")]
    pub passes: serde_json::Value,
    #[serde(default = "empty_json_array")]
    pub iocs: serde_json::Value,
    #[serde(default = "empty_json_array")]
    pub mitre: serde_json::Value,
    #[serde(default)]
    pub behavior: Option<String>,
    #[serde(default)]
    pub layer_chain: Option<String>,
    #[serde(default)]
    pub agent_note: Option<String>,
    #[serde(default)]
    pub entropy: Option<f64>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub status_line: Option<String>,
    #[serde(default)]
    pub case_tag: Option<String>,
    #[serde(default)]
    pub correlation: Option<String>,
    #[serde(default)]
    pub analysis_secs: Option<f64>,
    #[serde(default)]
    pub engine: Option<String>,
    /// Opaque tool-findings passthrough (structured static analysis).
    #[serde(default)]
    pub static_analysis: Option<serde_json::Value>,
    #[serde(default, with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
}

fn default_verdict() -> String {
    "queued".to_string()
}

/// Partial update (analysis write-back / sha256 patch). Only the provided fields
/// change; an omitted field leaves its column untouched. Fields cannot be
/// cleared to NULL in v1 — the write-back only sets values.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateArtifact {
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub deobfuscated: Option<String>,
    #[serde(default)]
    pub passes: Option<serde_json::Value>,
    #[serde(default)]
    pub iocs: Option<serde_json::Value>,
    #[serde(default)]
    pub mitre: Option<serde_json::Value>,
    #[serde(default)]
    pub behavior: Option<String>,
    #[serde(default)]
    pub layer_chain: Option<String>,
    #[serde(default)]
    pub agent_note: Option<String>,
    #[serde(default)]
    pub entropy: Option<f64>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub status_line: Option<String>,
    #[serde(default)]
    pub case_tag: Option<String>,
    #[serde(default)]
    pub correlation: Option<String>,
    #[serde(default)]
    pub analysis_secs: Option<f64>,
    #[serde(default)]
    pub engine: Option<String>,
    /// Opaque tool-findings passthrough (structured static analysis). Partial
    /// write-back like the other fields — omitted leaves the column untouched.
    #[serde(default)]
    pub static_analysis: Option<serde_json::Value>,
    #[serde(default, with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
}

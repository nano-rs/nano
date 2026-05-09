// SPDX-License-Identifier: AGPL-3.0-or-later

//! Incident models (NAN-417)
//!
//! An incident is a lightweight parent container that groups one or more
//! related cases into a single campaign (e.g. a login-spray across multiple
//! tenants). See migration `153_incidents_schema.sql` for the storage layout.
//!
//! Cases retain their identity — promoting a case to an incident does not
//! merge or close the case. Cases are attached via `cases.incident_id`
//! (nullable FK). A case without an incident is referred to as "loose" in
//! the Signal Inbox UI.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

// =============================================================================
// ENUMS
// =============================================================================

/// Incident lifecycle state.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Active,
    Resolved,
    Closed,
}

impl Default for IncidentStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Resolved => write!(f, "resolved"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Provenance of an incident — whether it was created manually by an analyst
/// or auto-grouped by an agent-detection rule.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum IncidentSource {
    Manual,
    AgentDetected,
}

impl Default for IncidentSource {
    fn default() -> Self {
        Self::Manual
    }
}

impl std::fmt::Display for IncidentSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manual => write!(f, "manual"),
            Self::AgentDetected => write!(f, "agent_detected"),
        }
    }
}

// =============================================================================
// INCIDENT MODEL
// =============================================================================

/// Full incident row (mirrors `public.incidents`).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Incident {
    #[serde(with = "typeid::incident")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub incident_number: i32,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub source: String,
    pub detector: Option<String>,
    pub confidence: Option<f64>,
    pub signature: Option<String>,
    pub tags: Vec<String>,
    pub opened_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub closed_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
}

/// Lightweight incident summary — embedded in `CaseWithDetails` when a case
/// is attached to an incident, so the Signal Inbox can show the parent chip
/// without a second round-trip.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct IncidentSummary {
    #[serde(with = "typeid::incident")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub incident_number: i32,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub source: String,
}

/// Internal input for creating an incident from one or more cases. The
/// service layer builds this after validating case visibility.
#[derive(Debug, Clone)]
pub struct NewIncident {
    pub title: String,
    pub severity: String,
    pub source: String,
    pub detector: Option<String>,
    pub confidence: Option<f64>,
    pub signature: Option<String>,
    pub tags: Vec<String>,
    pub created_by: Option<Uuid>,
    /// Cases to attach on creation (must be non-empty for manual promotion).
    pub case_ids: Vec<Uuid>,
}

/// API-facing request body for `POST /api/incidents`. The handler injects
/// `created_by` from the auth context.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateIncidentRequest {
    pub title: String,
    pub severity: String,
    pub source: String,
    pub detector: Option<String>,
    pub confidence: Option<f64>,
    pub signature: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(with = "typeid::case::vec")]
    #[schema(value_type = Vec<String>)]
    pub case_ids: Vec<Uuid>,
}

/// Response for `GET /api/incidents/{id}` — the incident plus its hydrated
/// child cases (as `CaseWithDetails`).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IncidentWithCases {
    pub incident: Incident,
    pub cases: Vec<super::case::CaseWithDetails>,
}

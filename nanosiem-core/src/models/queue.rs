// SPDX-License-Identifier: AGPL-3.0-or-later

//! Queue + queue routing-rule models (NAN-426 / NAN-427).
//!
//! A queue is a thin wrapper over an existing group — the backing group owns
//! membership (who's on the queue), while the queue row carries metadata
//! (kind, SLA tier, Slack channel, routing priority, icon / color,
//! description). Cases land in a queue via `cases.assigned_group`, so the
//! queue list surfaces "assigned to queue.group_id AND unclaimed" as the
//! primary pending-work indicator.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

// =============================================================================
// ENUMS
// =============================================================================

/// Queue kind — matches the CHECK constraint in migration 154.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum QueueKind {
    Triage,
    Tier1,
    Tier2,
    Tier3,
    Specialty,
}

impl std::fmt::Display for QueueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Triage => write!(f, "triage"),
            Self::Tier1 => write!(f, "tier1"),
            Self::Tier2 => write!(f, "tier2"),
            Self::Tier3 => write!(f, "tier3"),
            Self::Specialty => write!(f, "specialty"),
        }
    }
}

impl std::str::FromStr for QueueKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "triage" => Ok(Self::Triage),
            "tier1" => Ok(Self::Tier1),
            "tier2" => Ok(Self::Tier2),
            "tier3" => Ok(Self::Tier3),
            "specialty" => Ok(Self::Specialty),
            other => Err(format!("Unknown queue kind: {other}")),
        }
    }
}

// =============================================================================
// QUEUE MODEL
// =============================================================================

/// A queue row. Kept narrow — membership + permissions flow through the
/// backing `group_id`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Queue {
    #[serde(with = "typeid::queue")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::group")]
    #[schema(value_type = String)]
    pub group_id: Uuid,
    pub kind: String,
    pub default_sla_tier: Option<String>,
    pub slack_channel: Option<String>,
    pub routing_priority: i32,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub is_default_landing: bool,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Queue joined with the backing group's display name + system flag + member
/// and unclaimed-case counts. What the list / detail endpoints return.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueueWithMembership {
    #[serde(flatten)]
    pub queue: Queue,
    /// Display name lifted from `groups.name`.
    pub name: String,
    /// True when the backing group has `is_system=true`. Admin UI uses this
    /// to hide the "delete queue" control — removing the group would break
    /// seeded defaults.
    pub is_system: bool,
    /// Number of users on the backing group (who can claim work from this
    /// queue).
    pub member_count: i64,
    /// Count of cases currently sitting on this queue with no individual
    /// assignee. This is the primary "unclaimed work" indicator the
    /// SignalInbox sidebar renders against each queue.
    pub unclaimed_count: i64,
}

/// Row-shape for the joined list query. Not part of the public API surface —
/// converted into [`QueueWithMembership`] before returning.
#[derive(Debug, Clone, FromRow)]
pub struct QueueWithMembershipRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub kind: String,
    pub default_sla_tier: Option<String>,
    pub slack_channel: Option<String>,
    pub routing_priority: i32,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub is_default_landing: bool,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub is_system: bool,
    pub member_count: i64,
    pub unclaimed_count: i64,
}

impl From<QueueWithMembershipRow> for QueueWithMembership {
    fn from(row: QueueWithMembershipRow) -> Self {
        Self {
            queue: Queue {
                id: row.id,
                group_id: row.group_id,
                kind: row.kind,
                default_sla_tier: row.default_sla_tier,
                slack_channel: row.slack_channel,
                routing_priority: row.routing_priority,
                icon: row.icon,
                color: row.color,
                is_default_landing: row.is_default_landing,
                description: row.description,
                created_at: row.created_at,
                updated_at: row.updated_at,
            },
            name: row.name,
            is_system: row.is_system,
            member_count: row.member_count,
            unclaimed_count: row.unclaimed_count,
        }
    }
}

/// Input for creating a new queue. Callers supply a backing `group_id`
/// (admins pick or create the group through the existing groups UI), then
/// attach a queue to it.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewQueue {
    #[serde(with = "typeid::group")]
    #[schema(value_type = String)]
    pub group_id: Uuid,
    pub kind: QueueKind,
    pub default_sla_tier: Option<String>,
    pub slack_channel: Option<String>,
    #[serde(default = "default_routing_priority")]
    pub routing_priority: i32,
    pub icon: Option<String>,
    pub color: Option<String>,
    #[serde(default)]
    pub is_default_landing: bool,
    pub description: Option<String>,
}

fn default_routing_priority() -> i32 {
    100
}

/// Input for updating a queue. Only `kind` and `group_id` are immutable
/// (moving a queue to a different group would invalidate historical case
/// assignments, and changing kind would violate the CHECK-seeded invariants).
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueueUpdate {
    pub default_sla_tier: Option<String>,
    pub slack_channel: Option<String>,
    pub routing_priority: Option<i32>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub is_default_landing: Option<bool>,
    pub description: Option<String>,
}

// =============================================================================
// QUEUE ROUTING RULE MODEL
// =============================================================================

/// A rule evaluated on case-create to pick a landing queue.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct QueueRoutingRule {
    #[serde(with = "typeid::queue_routing_rule")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    #[serde(with = "typeid::queue")]
    #[schema(value_type = String)]
    pub queue_id: Uuid,
    /// See migration 155 comment for shape.
    pub conditions: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewQueueRoutingRule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rule_priority")]
    pub priority: i32,
    #[serde(with = "typeid::queue")]
    #[schema(value_type = String)]
    pub queue_id: Uuid,
    #[serde(default)]
    pub conditions: serde_json::Value,
}

fn default_true() -> bool {
    true
}

fn default_rule_priority() -> i32 {
    100
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueueRoutingRuleUpdate {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<i32>,
    #[serde(default, with = "typeid::queue::opt")]
    #[schema(value_type = Option<String>)]
    pub queue_id: Option<Uuid>,
    pub conditions: Option<serde_json::Value>,
}

/// Preview request — lets admins dry-run the evaluator against a synthetic
/// case shape. Returns the first-matched rule (or `None`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueueRoutingPreviewRequest {
    #[serde(default)]
    pub source_types: Vec<String>,
    pub severity: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    /// Optional grouping hash from the auto-grouper. Lets admins model
    /// "same hash prefix always lands here" rules.
    pub group_by_hash: Option<String>,
}

/// Preview response envelope. `matched_rule` is `None` when no rule fired
/// (which in production would mean the case lands on the default_landing
/// queue instead).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueueRoutingPreviewResponse {
    pub matched_rule: Option<QueueRoutingRule>,
    /// Resolved queue name — saves the UI a lookup. `None` when no rule
    /// matched.
    pub matched_queue_name: Option<String>,
}

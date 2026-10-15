// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-owned product entitlements for hosted shared tenants.
//!
//! This is deliberately separate from the legacy deployment-wide
//! `system_settings` tier row. A shared request resolves one exact tenant plan
//! assignment from PostgreSQL; missing, inactive, expired, incomplete, or
//! unknown contracts fail closed.

use crate::request_timing::RequestDb;
use std::{collections::BTreeMap, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::auth::tenant::TrustedTenantContext;

/// Every independently gated product/runtime surface in a shared tenant.
///
/// A plan revision contains an explicit row for every variant. Adding a new
/// component therefore makes older incomplete manifests fail closed until a
/// new reviewed plan revision declares it enabled or disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantComponent {
    Api,
    Ingest,
    ParserCells,
    LakeStorage,
    Search,
    Prevalence,
    Alerts,
    Detections,
    Dashboards,
    Reports,
    SiemHealth,
    Observability,
    Cases,
    Notebooks,
    Risk,
    Melod,
    CustomEnrichment,
    AgentEnrichment,
    AiTuning,
    Playbooks,
    Incidents,
    ObservabilityConvergence,
    Sso,
}

pub const TENANT_COMPONENTS: [TenantComponent; 23] = [
    TenantComponent::Api,
    TenantComponent::Ingest,
    TenantComponent::ParserCells,
    TenantComponent::LakeStorage,
    TenantComponent::Search,
    TenantComponent::Prevalence,
    TenantComponent::Alerts,
    TenantComponent::Detections,
    TenantComponent::Dashboards,
    TenantComponent::Reports,
    TenantComponent::SiemHealth,
    TenantComponent::Observability,
    TenantComponent::Cases,
    TenantComponent::Notebooks,
    TenantComponent::Risk,
    TenantComponent::Melod,
    TenantComponent::CustomEnrichment,
    TenantComponent::AgentEnrichment,
    TenantComponent::AiTuning,
    TenantComponent::Playbooks,
    TenantComponent::Incidents,
    TenantComponent::ObservabilityConvergence,
    TenantComponent::Sso,
];

impl TenantComponent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Ingest => "ingest",
            Self::ParserCells => "parser_cells",
            Self::LakeStorage => "lake_storage",
            Self::Search => "search",
            Self::Prevalence => "prevalence",
            Self::Alerts => "alerts",
            Self::Detections => "detections",
            Self::Dashboards => "dashboards",
            Self::Reports => "reports",
            Self::SiemHealth => "siem_health",
            Self::Observability => "observability",
            Self::Cases => "cases",
            Self::Notebooks => "notebooks",
            Self::Risk => "risk",
            Self::Melod => "melod",
            Self::CustomEnrichment => "custom_enrichment",
            Self::AgentEnrichment => "agent_enrichment",
            Self::AiTuning => "ai_tuning",
            Self::Playbooks => "playbooks",
            Self::Incidents => "incidents",
            Self::ObservabilityConvergence => "observability_convergence",
            Self::Sso => "sso",
        }
    }
}

impl fmt::Display for TenantComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TenantComponent {
    type Err = TenantEntitlementError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        TENANT_COMPONENTS
            .iter()
            .copied()
            .find(|component| component.as_str() == value)
            .ok_or_else(|| TenantEntitlementError::InvalidContract {
                reason: format!("unknown tenant component {value:?}"),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantComponentGrant {
    pub enabled: bool,
    pub configuration: serde_json::Value,
}

/// One immutable authorization snapshot returned by a single PostgreSQL
/// statement. Services may carry this snapshot through one request, but must
/// not combine it with another tenant or accept a client-supplied revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantEntitlementSnapshot {
    pub tenant_id: Uuid,
    pub plan_code: String,
    pub plan_revision: i64,
    pub assignment_revision: i64,
    pub retention_revision: i64,
    pub retention_option_revision: i64,
    pub retention_days: i16,
    pub irreversible_event_time_floor: DateTime<Utc>,
    pub limits: serde_json::Value,
    pub components: BTreeMap<TenantComponent, TenantComponentGrant>,
}

impl TenantEntitlementSnapshot {
    pub fn require_component(
        &self,
        tenant: &TrustedTenantContext,
        component: TenantComponent,
    ) -> Result<&TenantComponentGrant, TenantEntitlementError> {
        if self.tenant_id != tenant.tenant_id {
            return Err(TenantEntitlementError::AccessDenied);
        }
        let grant = self.components.get(&component).ok_or_else(|| {
            TenantEntitlementError::InvalidContract {
                reason: format!("plan manifest omitted {component}"),
            }
        })?;
        if !grant.enabled {
            return Err(TenantEntitlementError::ComponentDisabled { component });
        }
        Ok(grant)
    }

    /// The plan's API access level (`limits.api_access`), or `None` when the
    /// key is absent or not a recognised level.
    ///
    /// Callers must treat `None` as an invalid contract, never as "full": the
    /// SQL authority gates (`plan.limits->>'api_access'='full'`) already
    /// refuse anything that is not exactly `full`.
    pub fn api_access(&self) -> Option<crate::settings::tier::ApiAccessLevel> {
        self.limits
            .get("api_access")
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| match raw {
                // Exact spellings only — the SQL gates compare case-sensitively,
                // so a looser Rust parse would admit what the database refuses.
                "full" => Some(crate::settings::tier::ApiAccessLevel::Full),
                "readonly" => Some(crate::settings::tier::ApiAccessLevel::Readonly),
                "none" => Some(crate::settings::tier::ApiAccessLevel::None),
                _ => None,
            })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TenantEntitlementError {
    #[error("tenant plan access denied")]
    AccessDenied,
    #[error("tenant component {component} is not included in the active plan")]
    ComponentDisabled { component: TenantComponent },
    #[error("tenant plan contract is invalid: {reason}")]
    InvalidContract { reason: String },
    #[error("tenant plan lookup unavailable — failing closed")]
    Unavailable,
}

#[derive(Debug, FromRow, Deserialize)]
struct EntitlementRow {
    tenant_id: Uuid,
    tenant_status: String,
    plan_code: String,
    plan_revision: i64,
    plan_state: String,
    assignment_revision: i64,
    retention_revision: i64,
    retention_option_revision: i64,
    retention_days: i16,
    irreversible_event_time_floor: DateTime<Utc>,
    assignment_state: String,
    effective_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    limits: serde_json::Value,
    component_code: String,
    component_enabled: bool,
    component_configuration: serde_json::Value,
}

#[derive(Clone)]
pub struct TenantEntitlementResolver {
    pool: PgPool,
}

impl TenantEntitlementResolver {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Resolve an exact tenant assignment atomically. This method does not
    /// cache; a future cache must be keyed by `(tenant_id,
    /// assignment_revision)` and have an explicit revocation bound.
    pub async fn resolve(
        &self,
        tenant: &TrustedTenantContext,
    ) -> Result<TenantEntitlementSnapshot, TenantEntitlementError> {
    crate::request_timing::timed(crate::request_timing::Phase::Authority, async {

        let rows = sqlx::query_as::<_, EntitlementRow>(
            r#"
            SELECT
                t.id AS tenant_id,
                t.status AS tenant_status,
                a.plan_code,
                a.plan_revision,
                p.state AS plan_state,
                a.assignment_revision,
                a.state AS assignment_state,
                a.effective_at,
                a.expires_at,
                jsonb_set(
                    p.limits, '{retention_days}', to_jsonb(policy.retention_days), TRUE
                ) AS limits,
                policy.retention_revision,
                policy.retention_option_revision,
                policy.retention_days,
                policy.irreversible_event_time_floor,
                c.component_code,
                c.enabled AS component_enabled,
                c.configuration AS component_configuration
            FROM tenants t
            JOIN enterprise_shared_tenant_plan_assignments a
              ON a.tenant_id = t.id
            JOIN enterprise_shared_plan_versions p
              ON p.plan_code = a.plan_code
             AND p.revision = a.plan_revision
            JOIN enterprise_shared_plan_components c
              ON c.plan_code = p.plan_code
             AND c.plan_revision = p.revision
            JOIN enterprise_shared_retention_policy_heads retention_head
              ON retention_head.tenant_id = a.tenant_id
            JOIN enterprise_shared_retention_policy_revisions policy
              ON policy.tenant_id = retention_head.tenant_id
             AND policy.retention_revision = retention_head.retention_revision
             AND policy.assignment_revision = a.assignment_revision
             AND policy.plan_code = a.plan_code
             AND policy.plan_revision = a.plan_revision
            WHERE t.id = $1
            ORDER BY c.component_code
            "#,
        )
        .bind(tenant.tenant_id)
        .fetch_all(&self.pool).request_db()
        .await
        .map_err(|error| {
            tracing::error!(
                tenant_id = %tenant.tenant_id,
                error = %error,
                "tenant entitlement lookup failed — failing closed"
            );
            TenantEntitlementError::Unavailable
        })?;

        build_snapshot(tenant, rows, Utc::now())

    }).await
}
}

/// NAN-3231: build the snapshot from the rows `nano_shared.search_*_admission`
/// returned as one JSON array (the exact `resolve` join, one element per
/// component, ordered by component code). Same validation as `resolve`; a
/// malformed array is `Unavailable`, never a partial snapshot.
pub(crate) fn snapshot_from_admission_rows(
    tenant: &TrustedTenantContext,
    rows: serde_json::Value,
) -> Result<TenantEntitlementSnapshot, TenantEntitlementError> {
    let rows: Vec<EntitlementRow> = serde_json::from_value(rows).map_err(|error| {
        tracing::error!(
            tenant_id = %tenant.tenant_id,
            error = %error,
            "tenant entitlement admission rows did not decode — failing closed"
        );
        TenantEntitlementError::Unavailable
    })?;
    build_snapshot(tenant, rows, Utc::now())
}

fn build_snapshot(
    tenant: &TrustedTenantContext,
    rows: Vec<EntitlementRow>,
    now: DateTime<Utc>,
) -> Result<TenantEntitlementSnapshot, TenantEntitlementError> {
    let first = rows.first().ok_or(TenantEntitlementError::AccessDenied)?;
    if first.tenant_id != tenant.tenant_id
        || first.tenant_status != "active"
        || first.assignment_state != "active"
        || !matches!(first.plan_state.as_str(), "active" | "retired")
        || first.effective_at > now
        || first.expires_at.is_some_and(|expires_at| expires_at <= now)
        || first.plan_revision <= 0
        || first.assignment_revision <= 0
        || first.retention_revision <= 0
        || first.retention_option_revision <= 0
        || !matches!(first.retention_days, 30 | 90 | 180 | 365)
        || first.irreversible_event_time_floor.timestamp_micros() < 0
        || !first.limits.is_object()
    {
        return Err(TenantEntitlementError::AccessDenied);
    }

    let expected_identity = (
        first.tenant_id,
        first.plan_code.clone(),
        first.plan_revision,
        first.assignment_revision,
        first.retention_revision,
        first.retention_option_revision,
        first.retention_days,
        first.irreversible_event_time_floor,
    );
    let mut components = BTreeMap::new();
    for row in &rows {
        if (
            row.tenant_id,
            row.plan_code.clone(),
            row.plan_revision,
            row.assignment_revision,
            row.retention_revision,
            row.retention_option_revision,
            row.retention_days,
            row.irreversible_event_time_floor,
        ) != expected_identity
            || row.tenant_status != first.tenant_status
            || row.plan_state != first.plan_state
            || row.assignment_state != first.assignment_state
            || row.effective_at != first.effective_at
            || row.expires_at != first.expires_at
            || row.limits != first.limits
            || !row.component_configuration.is_object()
        {
            return Err(TenantEntitlementError::InvalidContract {
                reason: "one lookup returned mixed tenant plan identities".to_string(),
            });
        }
        let component = row.component_code.parse::<TenantComponent>()?;
        if components
            .insert(
                component,
                TenantComponentGrant {
                    enabled: row.component_enabled,
                    configuration: row.component_configuration.clone(),
                },
            )
            .is_some()
        {
            return Err(TenantEntitlementError::InvalidContract {
                reason: format!("duplicate tenant component {component}"),
            });
        }
    }

    for required in TENANT_COMPONENTS {
        if !components.contains_key(&required) {
            return Err(TenantEntitlementError::InvalidContract {
                reason: format!("plan manifest omitted {required}"),
            });
        }
    }

    let retention_days = first
        .limits
        .get("retention_days")
        .and_then(serde_json::Value::as_u64);
    if !matches!(retention_days, Some(30 | 90 | 180 | 365)) {
        return Err(TenantEntitlementError::InvalidContract {
            reason: "shared plan must declare one supported retention ceiling (30/90/180/365)"
                .to_string(),
        });
    }
    if retention_days != u64::try_from(first.retention_days).ok() {
        return Err(TenantEntitlementError::InvalidContract {
            reason: "shared plan retention limit is not the exact current policy".to_string(),
        });
    }

    Ok(TenantEntitlementSnapshot {
        tenant_id: first.tenant_id,
        plan_code: first.plan_code.clone(),
        plan_revision: first.plan_revision,
        assignment_revision: first.assignment_revision,
        retention_revision: first.retention_revision,
        retention_option_revision: first.retention_option_revision,
        retention_days: first.retention_days,
        irreversible_event_time_floor: first.irreversible_event_time_floor,
        limits: first.limits.clone(),
        components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_names_are_unique_and_round_trip() {
        let names = TENANT_COMPONENTS
            .into_iter()
            .map(TenantComponent::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), TENANT_COMPONENTS.len());
        for component in TENANT_COMPONENTS {
            assert_eq!(
                component.as_str().parse::<TenantComponent>().unwrap(),
                component
            );
        }
    }

    #[test]
    fn require_component_rejects_foreign_tenant_and_disabled_grant() {
        let tenant_a = TrustedTenantContext {
            tenant_id: Uuid::from_u128(0xa),
            tenant_slug: "a".to_string(),
        };
        let tenant_b = TrustedTenantContext {
            tenant_id: Uuid::from_u128(0xb),
            tenant_slug: "b".to_string(),
        };
        let snapshot = TenantEntitlementSnapshot {
            tenant_id: tenant_a.tenant_id,
            plan_code: "hobby".to_string(),
            plan_revision: 1,
            assignment_revision: 1,
            retention_revision: 1,
            retention_option_revision: 1,
            retention_days: 365,
            irreversible_event_time_floor: DateTime::UNIX_EPOCH,
            limits: serde_json::json!({"retention_days": 365}),
            components: BTreeMap::from([(
                TenantComponent::Search,
                TenantComponentGrant {
                    enabled: false,
                    configuration: serde_json::json!({}),
                },
            )]),
        };

        assert!(matches!(
            snapshot.require_component(&tenant_b, TenantComponent::Search),
            Err(TenantEntitlementError::AccessDenied)
        ));
        assert!(matches!(
            snapshot.require_component(&tenant_a, TenantComponent::Search),
            Err(TenantEntitlementError::ComponentDisabled { .. })
        ));
    }
}

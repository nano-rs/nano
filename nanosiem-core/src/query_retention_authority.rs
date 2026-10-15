// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query-time retention authority for tenant-scoped Search (NAN-3861).
//!
//! The read side of the per-tenant retention policy: the row Search admission
//! loads, the validation it applies, and the event-time cutoff it derives.
//! nanosiem-search authenticates tenant-scoped sessions in every build, so
//! this stays open. The owner-plane selection service that writes the policy
//! ledger is enterprise-only (`shared_retention_policy`).

use crate::request_timing::RequestDb;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// The discrete retention options a tenant plan may grant.
pub const RETENTION_DAYS: [i16; 4] = [30, 90, 180, 365];

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRow)]
pub struct QueryRetentionAuthority {
    pub tenant_id: Uuid,
    pub assignment_revision: i64,
    pub retention_revision: i64,
    pub retention_entitlement_revision: i64,
    pub retention_option_revision: i64,
    pub retention_days: i16,
    pub irreversible_event_time_floor: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
}

impl QueryRetentionAuthority {
    pub async fn load_current(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Self, RetentionSelectionError> {
        crate::request_timing::timed(crate::request_timing::Phase::Authority, async {
            let authority = sqlx::query_as::<_, Self>(
                r#"
            SELECT assignment.tenant_id, assignment.assignment_revision,
                   policy.retention_revision,
                   policy.retention_entitlement_revision,
                   policy.retention_option_revision,
                   policy.retention_days,
                   policy.irreversible_event_time_floor,
                   policy.effective_at
              FROM enterprise_shared_tenant_plan_assignments assignment
              JOIN enterprise_shared_retention_policy_heads head
                ON head.tenant_id = assignment.tenant_id
              JOIN enterprise_shared_retention_policy_revisions policy
                ON policy.tenant_id = head.tenant_id
               AND policy.retention_revision = head.retention_revision
               AND policy.assignment_revision = assignment.assignment_revision
               AND policy.plan_code = assignment.plan_code
               AND policy.plan_revision = assignment.plan_revision
              JOIN enterprise_shared_plan_retention_options option
                ON option.plan_code = policy.plan_code
               AND option.plan_revision = policy.plan_revision
               AND option.entitlement_revision = policy.retention_entitlement_revision
               AND option.option_revision = policy.retention_option_revision
               AND option.retention_days = policy.retention_days
               AND option.option_kind = policy.retention_option_kind
               AND option.sku_code IS NOT DISTINCT FROM policy.retention_sku_code
               AND option.sku_revision IS NOT DISTINCT FROM policy.retention_sku_revision
             WHERE assignment.tenant_id = $1
               AND assignment.state IN ('active', 'suspended')
               AND assignment.effective_at <= statement_timestamp()
               AND (assignment.expires_at IS NULL
                    OR assignment.expires_at > statement_timestamp())
               AND policy.effective_at <= statement_timestamp()
            "#,
            )
            .bind(tenant_id)
            .fetch_optional(pool)
            .request_db()
            .await
            .map_err(RetentionSelectionError::Database)?;
            Self::accept_current(authority, tenant_id)
        })
        .await
    }

    /// The validation `load_current` applies to its row, shared with the
    /// one-snapshot Search admission (NAN-3231): a missing row or any
    /// out-of-contract value is `Rejected`.
    pub fn accept_current(
        authority: Option<Self>,
        tenant_id: Uuid,
    ) -> Result<Self, RetentionSelectionError> {
        let authority = authority.ok_or(RetentionSelectionError::Rejected)?;
        if authority.tenant_id != tenant_id
            || authority.assignment_revision <= 0
            || authority.retention_revision <= 0
            || authority.retention_entitlement_revision <= 0
            || authority.retention_option_revision <= 0
            || !RETENTION_DAYS.contains(&authority.retention_days)
            || authority.irreversible_event_time_floor.timestamp_micros() < 0
        {
            return Err(RetentionSelectionError::Rejected);
        }
        Ok(authority)
    }

    #[cfg(feature = "enterprise")]
    pub fn search_scope(self) -> Result<crate::search::SearchTenantScope, RetentionSelectionError> {
        crate::search::SearchTenantScope::enterprise_shared_retained(
            self.tenant_id,
            self.retention_revision,
            u16::try_from(self.retention_days).map_err(|_| RetentionSelectionError::Rejected)?,
            self.irreversible_event_time_floor.timestamp_micros(),
        )
        .map_err(|_| RetentionSelectionError::Rejected)
    }

    pub fn cutoff_at(self, now: DateTime<Utc>) -> DateTime<Utc> {
        std::cmp::max(
            now - chrono::Duration::days(i64::from(self.retention_days)),
            self.irreversible_event_time_floor,
        )
    }

    pub fn is_same_policy(self, other: Self) -> bool {
        self == other
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RetentionSelectionError {
    #[error("enterprise_shared retention selection is disabled")]
    Disabled,
    #[error("invalid enterprise_shared retention selection request")]
    InvalidRequest,
    #[error("enterprise_shared retention selection was rejected")]
    Rejected,
    #[error("enterprise_shared retention selection database unavailable")]
    Database(#[source] sqlx::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "enterprise")]
    #[test]
    fn irreversible_floor_survives_a_later_retention_increase() {
        let now = DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let floor = now - chrono::Duration::days(30);
        let authority = QueryRetentionAuthority {
            tenant_id: Uuid::from_u128(0x2361),
            assignment_revision: 1,
            retention_revision: 3,
            retention_entitlement_revision: 1,
            retention_option_revision: 1,
            retention_days: 365,
            irreversible_event_time_floor: floor,
            effective_at: now,
        };
        assert_eq!(authority.cutoff_at(now), floor);
        assert_eq!(
            authority.search_scope().unwrap().event_time_cutoff(now),
            Some(floor)
        );
    }
}

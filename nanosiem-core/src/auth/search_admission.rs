// SPDX-License-Identifier: AGPL-3.0-or-later

//! One-snapshot enterprise-shared Search admission (NAN-3231).
//!
//! A cold Search admission used to run ~10 sequential PostgreSQL statements
//! for an interactive session (revocation, account status, membership,
//! entitlement, source version, scope re-read, deny set, retention, IP
//! policy). `nano_shared.search_session_admission` (migration 9011400) runs
//! the same statements in one STABLE definer under one snapshot, for the
//! private control login only. This module decodes its row into the exact
//! inputs the legacy resolvers produced, so the search middleware keeps every
//! decision (and its HTTP outcome) in the same order, with the same
//! validators.
//!
//! Fail-closed: the definer returns no tenant data unless revocation, account
//! and membership checks pass; a decode problem is an error (503), never a
//! partial or default context.

use std::collections::BTreeSet;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::auth::tenant::{ResolvedTenantMembership, TrustedTenantContext};
use crate::query_retention_authority::{
    QueryRetentionAuthority, RetentionSelectionError,
};
use crate::request_timing::RequestDb;
use crate::tenant_entitlements::{TenantEntitlementError, TenantEntitlementSnapshot};

/// SQLSTATE for an undefined function: the 9011400 definers are not installed
/// yet (search rolled ahead of the migration). Callers fall back to the legacy
/// multi-statement admission, which is equally fail-closed.
pub const UNDEFINED_FUNCTION: &str = "42883";

/// True when `error` says the admission definer does not exist.
pub fn is_missing_admission_function(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == UNDEFINED_FUNCTION)
}

/// The authority reads every admitted credential carries, decoded from one
/// definer row. Each field is exactly what the legacy resolver returned at the
/// same step; the middleware applies the same checks to it.
#[derive(Debug)]
pub struct AdmissionReads {
    /// `TenantEntitlementResolver::resolve`.
    pub entitlement: Result<TenantEntitlementSnapshot, TenantEntitlementError>,
    /// `SourceScopeResolver` membership / revision attestation.
    pub scope_member_active: bool,
    pub scope_authority_revision: i64,
    pub scope_assignment_revision: i64,
    /// Normalized deny set (member) or tenant restricted union (automation
    /// key). `None` when the positive `source_scopes:view_all` bypass applies,
    /// so the visibility reader was never consulted.
    pub restricted_sources: Option<BTreeSet<String>>,
    /// `QueryRetentionAuthority::load_current`.
    pub retention:
        Result<QueryRetentionAuthority, RetentionSelectionError>,
    /// `None`: the request carried no client address. `Some(Err(reason))`:
    /// the tenant IP policy is unavailable (503, never a decision).
    pub ip_allowed: Option<Result<bool, String>>,
    /// `source_scope_version` in the same snapshot. `None` fails closed.
    pub source_version: Option<i64>,
}

/// Raw retention columns shared by both admission definers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RetentionColumns {
    pub tenant_id: Option<Uuid>,
    pub assignment_revision: Option<i64>,
    pub retention_revision: Option<i64>,
    pub entitlement_revision: Option<i64>,
    pub option_revision: Option<i64>,
    pub days: Option<i16>,
    pub floor: Option<DateTime<Utc>>,
    pub effective_at: Option<DateTime<Utc>>,
}

impl RetentionColumns {
    pub(crate) fn accept(
        self,
        tenant_id: Uuid,
    ) -> Result<QueryRetentionAuthority, RetentionSelectionError>
    {
        let row = match self {
            Self {
                tenant_id: Some(row_tenant),
                assignment_revision: Some(assignment_revision),
                retention_revision: Some(retention_revision),
                entitlement_revision: Some(retention_entitlement_revision),
                option_revision: Some(retention_option_revision),
                days: Some(retention_days),
                floor: Some(irreversible_event_time_floor),
                effective_at: Some(effective_at),
            } => Some(QueryRetentionAuthority {
                tenant_id: row_tenant,
                assignment_revision,
                retention_revision,
                retention_entitlement_revision,
                retention_option_revision,
                retention_days,
                irreversible_event_time_floor,
                effective_at,
            }),
            // No current head (every column NULL) or an incomplete row.
            _ => None,
        };
        QueryRetentionAuthority::accept_current(row, tenant_id)
    }
}

pub(crate) fn ip_verdict(
    requested: bool,
    allowed: Option<bool>,
    unavailable_reason: Option<String>,
) -> Option<Result<bool, String>> {
    if !requested {
        return None;
    }
    Some(match allowed {
        Some(allowed) => Ok(allowed),
        None => Err(unavailable_reason.unwrap_or_else(|| {
            "nano_shared.check_tenant_ip_policy returned no verdict".to_string()
        })),
    })
}

#[derive(Debug, FromRow)]
struct SessionAdmissionRow {
    verdict: String,
    tenant_slug: Option<String>,
    member_roles: Option<Vec<String>>,
    member_permissions: Option<Vec<String>>,
    member_authority_revision: Option<i64>,
    entitlement_rows: Option<serde_json::Value>,
    scope_member_active: Option<bool>,
    scope_authority_revision: Option<i64>,
    scope_assignment_revision: Option<i64>,
    denied_sources: Option<Vec<String>>,
    ret_tenant_id: Option<Uuid>,
    ret_assignment_revision: Option<i64>,
    ret_retention_revision: Option<i64>,
    ret_entitlement_revision: Option<i64>,
    ret_option_revision: Option<i64>,
    ret_days: Option<i16>,
    ret_floor: Option<DateTime<Utc>>,
    ret_effective_at: Option<DateTime<Utc>>,
    ip_allowed: Option<bool>,
    ip_unavailable_reason: Option<String>,
    observed_source_version: Option<i64>,
}

/// Outcome of the session definer, in the legacy check order.
#[derive(Debug)]
pub enum SessionAdmission {
    /// Exact JTI revoked, or the user watermark postdates the credential.
    SessionRevoked,
    /// Missing / non-active account, or the JWT iat predates the watermark.
    UserInactive,
    /// No active bound membership, or a tenant/member watermark cut it off.
    MembershipDenied,
    Admitted {
        membership: ResolvedTenantMembership,
        reads: Box<AdmissionReads>,
    },
}

/// The interactive-session inputs the definer needs; all come from a token
/// whose signature, purpose and tenant envelope were already verified.
#[derive(Debug, Clone, Copy)]
pub struct SessionAdmissionRequest {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub jti: Uuid,
    pub credential_time_micros: i64,
    pub token_iat: i64,
    pub client_ip: Option<IpAddr>,
}

/// One round trip: `nano_shared.search_session_admission`.
pub async fn admit_search_session(
    pool: &PgPool,
    request: SessionAdmissionRequest,
) -> Result<SessionAdmission, sqlx::Error> {
    let row = sqlx::query_as::<_, SessionAdmissionRow>(
        "SELECT * FROM nano_shared.search_session_admission($1,$2,$3,$4,$5,$6::text::inet)",
    )
    .bind(request.tenant_id)
    .bind(request.user_id)
    .bind(request.jti)
    .bind(request.credential_time_micros)
    .bind(request.token_iat)
    .bind(request.client_ip.map(|ip| ip.to_string()))
    .fetch_one(pool)
    .request_db()
    .await?;
    decode_session(row, request)
}

fn decode_error(reason: &str) -> sqlx::Error {
    sqlx::Error::Protocol(format!("search admission row: {reason}"))
}

fn decode_session(
    row: SessionAdmissionRow,
    request: SessionAdmissionRequest,
) -> Result<SessionAdmission, sqlx::Error> {
    match row.verdict.as_str() {
        "session_revoked" => return Ok(SessionAdmission::SessionRevoked),
        "user_inactive" => return Ok(SessionAdmission::UserInactive),
        "membership_denied" => return Ok(SessionAdmission::MembershipDenied),
        "admitted" => {}
        _ => return Err(decode_error("unknown session verdict")),
    }
    let (Some(tenant_slug), Some(roles), Some(permissions), Some(authority_revision)) = (
        row.tenant_slug,
        row.member_roles,
        row.member_permissions,
        row.member_authority_revision,
    ) else {
        return Err(decode_error("admitted session without membership"));
    };
    let context = TrustedTenantContext {
        tenant_id: request.tenant_id,
        tenant_slug,
    };
    let entitlement = crate::tenant_entitlements::snapshot_from_admission_rows(
        &context,
        row.entitlement_rows.unwrap_or(serde_json::Value::Null),
    );
    let reads = AdmissionReads {
        entitlement,
        scope_member_active: row.scope_member_active.unwrap_or(false),
        scope_authority_revision: row.scope_authority_revision.unwrap_or(0),
        scope_assignment_revision: row.scope_assignment_revision.unwrap_or(0),
        restricted_sources: row
            .denied_sources
            .map(crate::auth::source_scope_resolver::normalize_tenant_visibility),
        retention: RetentionColumns {
            tenant_id: row.ret_tenant_id,
            assignment_revision: row.ret_assignment_revision,
            retention_revision: row.ret_retention_revision,
            entitlement_revision: row.ret_entitlement_revision,
            option_revision: row.ret_option_revision,
            days: row.ret_days,
            floor: row.ret_floor,
            effective_at: row.ret_effective_at,
        }
        .accept(request.tenant_id),
        ip_allowed: ip_verdict(
            request.client_ip.is_some(),
            row.ip_allowed,
            row.ip_unavailable_reason,
        ),
        source_version: row.observed_source_version,
    };
    Ok(SessionAdmission::Admitted {
        membership: ResolvedTenantMembership {
            context,
            roles,
            permissions,
            authority_revision,
        },
        reads: Box::new(reads),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(ip: Option<IpAddr>) -> SessionAdmissionRequest {
        SessionAdmissionRequest {
            tenant_id: Uuid::from_u128(3),
            user_id: Uuid::from_u128(1),
            jti: Uuid::from_u128(2),
            credential_time_micros: 1_700_000_000_000_000,
            token_iat: 1_700_000_000,
            client_ip: ip,
        }
    }

    fn refused(verdict: &str) -> SessionAdmissionRow {
        SessionAdmissionRow {
            verdict: verdict.into(),
            tenant_slug: None,
            member_roles: None,
            member_permissions: None,
            member_authority_revision: None,
            entitlement_rows: None,
            scope_member_active: None,
            scope_authority_revision: None,
            scope_assignment_revision: None,
            denied_sources: None,
            ret_tenant_id: None,
            ret_assignment_revision: None,
            ret_retention_revision: None,
            ret_entitlement_revision: None,
            ret_option_revision: None,
            ret_days: None,
            ret_floor: None,
            ret_effective_at: None,
            ip_allowed: None,
            ip_unavailable_reason: None,
            observed_source_version: None,
        }
    }

    #[test]
    fn refusals_carry_no_context_and_unknown_verdicts_fail_closed() {
        assert!(matches!(
            decode_session(refused("session_revoked"), request(None)),
            Ok(SessionAdmission::SessionRevoked)
        ));
        assert!(matches!(
            decode_session(refused("user_inactive"), request(None)),
            Ok(SessionAdmission::UserInactive)
        ));
        assert!(matches!(
            decode_session(refused("membership_denied"), request(None)),
            Ok(SessionAdmission::MembershipDenied)
        ));
        assert!(decode_session(refused("allowed"), request(None)).is_err());
        // "admitted" without the membership columns is malformed, not a default.
        assert!(decode_session(refused("admitted"), request(None)).is_err());
    }

    #[test]
    fn admitted_row_without_plan_retention_or_ip_verdict_never_defaults_open() {
        let mut row = refused("admitted");
        row.tenant_slug = Some("fixture".into());
        row.member_roles = Some(vec!["admin".into()]);
        row.member_permissions = Some(vec!["search:execute".into()]);
        row.member_authority_revision = Some(4);
        let Ok(SessionAdmission::Admitted { membership, reads }) =
            decode_session(row, request(Some("203.0.113.9".parse().unwrap())))
        else {
            panic!("admitted row must decode");
        };
        assert_eq!(membership.context.tenant_id, Uuid::from_u128(3));
        assert!(matches!(
            reads.entitlement,
            Err(TenantEntitlementError::Unavailable)
        ));
        assert!(matches!(
            reads.retention,
            Err(RetentionSelectionError::Rejected)
        ));
        assert!(!reads.scope_member_active);
        assert!(
            matches!(reads.ip_allowed, Some(Err(_))),
            "a missing IP verdict is unavailable, not allowed"
        );
        assert_eq!(reads.source_version, None);
    }

    #[test]
    fn no_client_address_is_reported_as_absent() {
        assert_eq!(ip_verdict(false, Some(true), None), None);
        assert_eq!(ip_verdict(true, Some(false), None), Some(Ok(false)));
        assert_eq!(
            ip_verdict(true, None, Some("tenant IP policy is unavailable".into())),
            Some(Err("tenant IP policy is unavailable".into()))
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tier-based API write access guard
//!
//! Blocks write operations (POST/PUT/DELETE/PATCH) for API key-authenticated
//! requests when the organization's plan restricts API access to read-only.
//! JWT-authenticated (UI) requests are always allowed so dashboard users
//! are never blocked.
//!
//! Where the limits come from depends on the deployment mode (NAN-2761):
//!
//! - **Dedicated / open-core**: the deployment-wide `system_settings` tier row.
//! - **hosted-shared**: the authenticated tenant's own plan assignment,
//!   resolved through [`TenantEntitlementResolver`] for exactly the
//!   `TrustedTenantContext` the auth middleware established. The shared
//!   runtime role cannot read `system_settings` (and must not: that row is the
//!   platform's, not the tenant's), so reading it there only ever produced a
//!   permission error.
//!
//! The guard fails **closed**: if the limits cannot be read, the write is
//! refused with 503 rather than waved through.

use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use nanosiem_core::{
    auth::TrustedTenantContext,
    settings::tier::{ApiAccessLevel, TierError, TierLimits},
    tenant_entitlements::{
        TenantComponent, TenantEntitlementError, TenantEntitlementResolver,
        TenantEntitlementSnapshot,
    },
};
use sqlx::PgPool;

use super::auth::AuthContext;
use crate::error::{ErrorDetail, ErrorResponse};

/// Counter incremented whenever the guard refuses a write because the limits
/// could not be read. Labelled by deployment mode and reason.
pub const TIER_GUARD_UNAVAILABLE_METRIC: &str = "nanosiem_api_write_guard_unavailable_total";

/// State for [`api_write_guard`].
#[derive(Clone)]
pub struct ApiWriteGuardState {
    /// Dedicated: the tenant database. Shared: the control pool that holds
    /// plan assignments (the same pool `TenantEntitlementResolver` uses
    /// everywhere else in the API).
    pub pool: PgPool,
    /// Resolve limits from the tenant plan assignment instead of
    /// `system_settings`.
    #[cfg(feature = "enterprise")]
    pub enterprise_shared: bool,
}

/// Safe HTTP methods that are always allowed regardless of tier.
fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Outcome of evaluating a write against the resolved limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteDecision {
    Allow,
    /// The plan does not include API writes → 403.
    Restricted,
    /// The limits could not be read or are malformed → 503 (fail closed).
    Unavailable(&'static str),
}

/// Dedicated mode: decide from the `system_settings` tier row.
pub(crate) fn decide_dedicated(resolved: Result<TierLimits, TierError>) -> WriteDecision {
    match resolved {
        Ok(limits) => {
            if !limits.is_enforced() {
                return WriteDecision::Allow;
            }
            match nanosiem_core::check_api_write_access(&limits) {
                Ok(()) => WriteDecision::Allow,
                Err(_) => WriteDecision::Restricted,
            }
        }
        Err(_) => WriteDecision::Unavailable("tier_settings_unreadable"),
    }
}

/// Shared mode: decide from the authenticated tenant's plan snapshot.
///
/// `tenant` is the context the auth middleware bound to this request; the
/// snapshot must belong to exactly that tenant or the write is refused.
pub(crate) fn decide_shared(
    tenant: &TrustedTenantContext,
    resolved: Result<TenantEntitlementSnapshot, TenantEntitlementError>,
) -> WriteDecision {
    let snapshot = match resolved {
        Ok(snapshot) => snapshot,
        // No active assignment / suspended / expired — the tenant has no
        // plan that includes writes.
        Err(TenantEntitlementError::AccessDenied)
        | Err(TenantEntitlementError::ComponentDisabled { .. }) => {
            return WriteDecision::Restricted
        }
        Err(TenantEntitlementError::InvalidContract { .. }) => {
            return WriteDecision::Unavailable("plan_contract_invalid")
        }
        Err(TenantEntitlementError::Unavailable) => {
            return WriteDecision::Unavailable("plan_lookup_failed")
        }
    };
    match snapshot.require_component(tenant, TenantComponent::Api) {
        Ok(_) => {}
        Err(TenantEntitlementError::InvalidContract { .. }) => {
            return WriteDecision::Unavailable("plan_contract_invalid")
        }
        // Foreign-tenant snapshot or API component disabled.
        Err(_) => return WriteDecision::Restricted,
    }
    match snapshot.api_access() {
        Some(ApiAccessLevel::Full) => WriteDecision::Allow,
        Some(ApiAccessLevel::Readonly) | Some(ApiAccessLevel::None) => WriteDecision::Restricted,
        None => WriteDecision::Unavailable("plan_api_access_missing"),
    }
}

fn restricted_response() -> Response {
    let body = ErrorResponse {
        error: ErrorDetail {
            code: "API_WRITE_RESTRICTED".to_string(),
            message: "Write API access is not available on your plan. Upgrade to Growth or higher."
                .to_string(),
            details: None,
        },
    };
    (StatusCode::FORBIDDEN, Json(body)).into_response()
}

fn unavailable_response() -> Response {
    let body = ErrorResponse {
        error: ErrorDetail {
            code: "API_WRITE_GUARD_UNAVAILABLE".to_string(),
            message: "Plan limits could not be verified, so this write was refused. Retry shortly."
                .to_string(),
            details: None,
        },
    };
    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}

/// Middleware that enforces API write access restrictions based on the
/// organization's plan. Only applies to API key-authenticated requests
/// using non-safe HTTP methods.
///
/// Must be layered **after** auth_middleware (inner to it) so that
/// `AuthContext` (and, in shared mode, `TrustedTenantContext`) is available in
/// request extensions.
pub async fn api_write_guard(
    State(guard): State<ApiWriteGuardState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Only check non-safe methods
    if is_safe_method(request.method()) {
        return Ok(next.run(request).await);
    }

    // Only restrict API key auth — JWT (UI) users are unrestricted
    let is_api_key = request
        .extensions()
        .get::<AuthContext>()
        .map(|auth| auth.is_api_key)
        .unwrap_or(false);

    if !is_api_key {
        return Ok(next.run(request).await);
    }

    #[cfg(feature = "enterprise")]
    let shared = guard.enterprise_shared;
    #[cfg(not(feature = "enterprise"))]
    let shared = false;
    let mode = if shared {
        "enterprise_shared"
    } else {
        "dedicated"
    };
    let tenant = request.extensions().get::<TrustedTenantContext>().cloned();
    let decision = if shared {
        match tenant.as_ref() {
            // Never fall back to the deployment-wide row: that would read the
            // platform's limits (or nothing) instead of this tenant's.
            None => WriteDecision::Unavailable("tenant_context_missing"),
            Some(tenant) => decide_shared(
                tenant,
                TenantEntitlementResolver::new(guard.pool.clone())
                    .resolve(tenant)
                    .await,
            ),
        }
    } else {
        let resolved = nanosiem_core::TierSettings::new(guard.pool.clone())
            .get_tier_limits()
            .await;
        if let Err(error) = &resolved {
            tracing::error!(error = %error, "tier settings unreadable for API write guard");
        }
        decide_dedicated(resolved)
    };

    match decision {
        WriteDecision::Allow => Ok(next.run(request).await),
        WriteDecision::Restricted => Err(restricted_response()),
        WriteDecision::Unavailable(reason) => {
            tracing::error!(
                mode,
                reason,
                tenant_id = ?tenant.as_ref().map(|t| t.tenant_id),
                "API write guard could not verify plan limits — refusing write (fail closed)"
            );
            ::metrics::counter!(
                TIER_GUARD_UNAVAILABLE_METRIC,
                "mode" => mode,
                "reason" => reason,
            )
            .increment(1);
            Err(unavailable_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use nanosiem_core::settings::tier::OrganizationTier;
    use nanosiem_core::tenant_entitlements::{TenantComponentGrant, TENANT_COMPONENTS};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn tenant(n: u128) -> TrustedTenantContext {
        TrustedTenantContext {
            tenant_id: Uuid::from_u128(n),
            tenant_slug: format!("t{n}"),
        }
    }

    fn snapshot(
        owner: &TrustedTenantContext,
        api_enabled: bool,
        api_access: Option<&str>,
    ) -> TenantEntitlementSnapshot {
        let mut limits = serde_json::json!({"retention_days": 365});
        if let Some(level) = api_access {
            limits["api_access"] = serde_json::json!(level);
        }
        TenantEntitlementSnapshot {
            tenant_id: owner.tenant_id,
            plan_code: "fixture".to_string(),
            plan_revision: 1,
            assignment_revision: 1,
            retention_revision: 1,
            retention_option_revision: 1,
            retention_days: 365,
            irreversible_event_time_floor: DateTime::UNIX_EPOCH,
            limits,
            components: TENANT_COMPONENTS
                .into_iter()
                .map(|component| {
                    (
                        component,
                        TenantComponentGrant {
                            enabled: component != TenantComponent::Api || api_enabled,
                            configuration: serde_json::json!({}),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        }
    }

    // ---- hosted-shared -------------------------------------------------

    #[test]
    fn shared_plan_with_full_api_allows_write() {
        let a = tenant(0xa);
        assert_eq!(
            decide_shared(&a, Ok(snapshot(&a, true, Some("full")))),
            WriteDecision::Allow
        );
    }

    #[test]
    fn shared_plan_over_limit_refuses_write() {
        let a = tenant(0xa);
        for level in ["readonly", "none"] {
            assert_eq!(
                decide_shared(&a, Ok(snapshot(&a, true, Some(level)))),
                WriteDecision::Restricted,
                "{level}"
            );
        }
        // API component switched off also refuses, even with api_access=full.
        assert_eq!(
            decide_shared(&a, Ok(snapshot(&a, false, Some("full")))),
            WriteDecision::Restricted
        );
    }

    #[test]
    fn shared_unreadable_or_malformed_limits_fail_closed() {
        let a = tenant(0xa);
        assert!(matches!(
            decide_shared(&a, Err(TenantEntitlementError::Unavailable)),
            WriteDecision::Unavailable(_)
        ));
        assert!(matches!(
            decide_shared(
                &a,
                Err(TenantEntitlementError::InvalidContract { reason: "x".into() })
            ),
            WriteDecision::Unavailable(_)
        ));
        // Missing or unknown api_access is never read as "full".
        for level in [None, Some("FULL"), Some("unlimited")] {
            assert!(matches!(
                decide_shared(&a, Ok(snapshot(&a, true, level))),
                WriteDecision::Unavailable(_)
            ));
        }
        // No active plan at all is a refusal, not "unrestricted".
        assert_eq!(
            decide_shared(&a, Err(TenantEntitlementError::AccessDenied)),
            WriteDecision::Restricted
        );
    }

    #[test]
    fn shared_never_applies_another_tenants_plan() {
        let a = tenant(0xa);
        let b = tenant(0xb);
        // Tenant A's permissive plan must not authorize a write by tenant B.
        assert_eq!(
            decide_shared(&b, Ok(snapshot(&a, true, Some("full")))),
            WriteDecision::Restricted
        );
    }

    // ---- dedicated ---------------------------------------------------------

    #[test]
    fn dedicated_unreadable_settings_fail_closed() {
        let denied = sqlx::Error::Protocol("permission denied for table system_settings".into());
        assert!(matches!(
            decide_dedicated(Err(TierError::Database(denied))),
            WriteDecision::Unavailable(_)
        ));
    }

    #[test]
    fn dedicated_tier_limits_are_enforced() {
        let mut limits = TierLimits::for_tier_unoverridden(OrganizationTier::Hobby);
        assert_eq!(decide_dedicated(Ok(limits.clone())), WriteDecision::Allow);
        limits.api_access = ApiAccessLevel::Readonly;
        assert_eq!(decide_dedicated(Ok(limits)), WriteDecision::Restricted);
        let unrestricted = TierLimits::for_tier_unoverridden(OrganizationTier::Unrestricted);
        assert_eq!(decide_dedicated(Ok(unrestricted)), WriteDecision::Allow);
    }
}

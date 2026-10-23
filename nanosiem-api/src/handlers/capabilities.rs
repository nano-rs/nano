// SPDX-License-Identifier: AGPL-3.0-or-later

//! Capabilities handler
//!
//! Returns the build edition and capability flags so the frontend can decide
//! which surfaces to render. Public — the SPA hits it on boot before login,
//! and the answer is not sensitive (open-core deployments advertise themselves
//! anyway via the absence of enterprise routes).
//!
//! In the final architecture (post Phase 5 of NAN-744 / NAN-745), the open
//! Vite build excludes enterprise chunks at build time; capabilities is then
//! mostly observability ("which edition is this deployment running?") plus
//! a soft handle for staging environments where one bundle talks to either
//! backend.

use std::collections::BTreeMap;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
#[cfg(feature = "enterprise")]
use nanosiem_core::enterprise_shared_feature_flags::{
    EnterpriseSharedFeatureFlagError, EnterpriseSharedFeatureFlagResolver,
};
use nanosiem_core::{
    auth::{
        EnterpriseSharedSessionAuthentication, ResolvedTenantMembership,
        TenantMembershipResolver, TenantResolutionError, TrustedTenantContext,
    },
    TenantComponent, TenantEntitlementError, TenantEntitlementResolver, TenantEntitlementSnapshot,
};
use serde::Serialize;
use utoipa::OpenApi;
use uuid::Uuid;

use crate::{config::IngestMode, middleware::AuthContext, state::AppState};

/// Per-surface capability flags.
///
/// In this commit every flag toggles with the `enterprise` Cargo feature so
/// they're effectively redundant with `edition`. The shape exists so that
/// later phases can gate individual capabilities behind license tier or
/// org-level config without changing the wire format — e.g., a "starter"
/// enterprise tier without `aiTuning`. Until that lands, treat the flags as
/// the canonical per-surface check (`capabilities.cases`) rather than reading
/// edition directly.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// Core nPL search. Always available in dedicated builds; shared tenants
    /// additionally require their exact authenticated component grant.
    pub search: bool,
    /// Cases lifecycle, queues, routing, playbooks, shadow investigation.
    pub cases: bool,
    /// Investigation notebooks + chat.
    pub notebooks: bool,
    /// Risk analytics, entity drawer, RiskLeaderboard, MyCases dashboard widgets.
    pub risk: bool,
    /// meloD AI agents — chat, parser, query, detection, dashboard, summarize.
    pub melod: bool,
    /// Narrow AI query-correction surface. Kept separate so shared Search can
    /// expose its audited tenant-bound correction path without opening meloD.
    pub query_correction: bool,
    /// Deno-sandbox custom enrichments + their AI codegen.
    pub custom_enrichment: bool,
    /// AI-powered IOC enrichment providers.
    pub agent_enrichment: bool,
    /// AI rule-tuning agents (rule version history stays open).
    pub ai_tuning: bool,
    /// SOC playbook authoring + repository sync.
    pub playbooks: bool,
    /// Multi-case incidents.
    pub incidents: bool,
    /// SIEM Health. Available in BOTH editions.
    ///
    /// This was `ENTERPRISE` on the reasoning that "the AI narrative + ranked
    /// recommendations anchor the page". They don't — they enrich it. The
    /// scheduler, the five dimension scores, the metrics, the findings and the
    /// recommendations are all `nanosiem-core` with no `cfg` gate, and
    /// `siem_health::analyzer` has a deterministic non-AI summary builder. A
    /// fresh open tenant with zero AI credentials produces a complete report in
    /// ~73ms, including real findings.
    ///
    /// Hiding it also never worked: the flag only suppressed the NAV ITEM, while
    /// the route (permission-gated only) and the footer status link stayed
    /// reachable — so open users found a page they were not supposed to have.
    /// The meloD-authored narrative is gated inside the page on `melod`.
    pub siem_health: bool,
    /// SAML / OIDC SSO providers. Local credentials still work in open builds.
    pub sso: bool,
    /// Observability ↔ Security convergence cross-link — the
    /// service-detail "security signals against this service's hosts/IPs"
    /// strip. Enterprise only; the FE hides the strip when false.
    pub observability_convergence: bool,
    /// Code-free IOC lists (`/api/ioc-lists`). Those routes are
    /// mounted only on the hosted-shared tenant substrate, so a dedicated
    /// build of either edition reports false and the SPA hides the nav item
    /// and page. Shared tenants read it from the tenant bootstrap.
    pub ioc_lists: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesResponse {
    /// Build edition — `"open"` or `"enterprise"`.
    pub edition: &'static str,
    /// API server semver, from `CARGO_PKG_VERSION`.
    pub version: &'static str,
    /// How logs reach this install: `"vector"` (default) or
    /// `"tenzir_only"` (`install.sh --tenzir`, no Vector). In `tenzir_only`
    /// the SPA disables push sources, pull connectors, directory sync, parser
    /// deploys and synthetic checks, and the API refuses their mutations.
    pub ingest_mode: &'static str,
    pub capabilities: Capabilities,
}

/// Exact server-owned tenant identity attached to this authorization snapshot.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantCapabilityIdentity {
    // Match /api/auth/me; the browser compares this exact authenticated ID.
    #[serde(with = "nanosiem_core::typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    /// Monotonic RBAC/membership authority generation used to reject a stale
    /// browser bootstrap even when its tenant identity still matches.
    pub authorization_revision: i64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TenantCapabilityTenant {
    #[schema(value_type = String)]
    pub id: Uuid,
    pub slug: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantCapabilityPlan {
    pub code: String,
    pub revision: i64,
    pub assignment_revision: i64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TenantComponentCapability {
    pub enabled: bool,
    #[schema(value_type = Object)]
    pub configuration: serde_json::Value,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TenantCapabilityFeatureFlags {
    /// Monotonic catalog/override/emergency generation.
    pub revision: i64,
    /// Exact code-reviewed rollout-only catalog. These booleans are never
    /// entitlements or permissions.
    pub flags: BTreeMap<String, bool>,
}

#[derive(Debug)]
struct ResolvedTenantFeatureFlags {
    tenant_id: Uuid,
    user_id: Uuid,
    authorization_revision: i64,
    assignment_revision: i64,
    revision: i64,
    flags: BTreeMap<String, bool>,
}

/// Authenticated enterprise-shared bootstrap. All fields are resolved from
/// PostgreSQL after the tenant-bound session is revalidated; no request field,
/// browser plan flag, or deployment environment variable contributes authority.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantCapabilitiesResponse {
    pub edition: &'static str,
    pub version: &'static str,
    pub deployment_mode: &'static str,
    pub tenant: TenantCapabilityTenant,
    pub identity: TenantCapabilityIdentity,
    pub plan: TenantCapabilityPlan,
    /// Public product limits. Plan documents reject credential-shaped keys.
    #[schema(value_type = Object)]
    pub limits: serde_json::Value,
    pub ha_enabled: bool,
    /// Explicit row for every shared product component. Missing rows make the
    /// entire plan invalid rather than inheriting a build-wide default.
    pub components: BTreeMap<String, TenantComponentCapability>,
    pub feature_flags: TenantCapabilityFeatureFlags,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TenantCapabilitiesError {
    pub error: &'static str,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

type TenantCapabilitiesResult =
    Result<Json<TenantCapabilitiesResponse>, (StatusCode, Json<TenantCapabilitiesError>)>;

#[cfg(feature = "enterprise")]
const EDITION: &str = "enterprise";
#[cfg(not(feature = "enterprise"))]
const EDITION: &str = "open";

#[cfg(feature = "enterprise")]
const ENTERPRISE: bool = true;
#[cfg(not(feature = "enterprise"))]
const ENTERPRISE: bool = false;

/// Whether the SAML/OIDC SSO surface is compiled into this build. The OIDC
/// handlers live in the enterprise crate, so open builds never mount
/// `/api/settings/oidc` or `/api/auth/oidc/*`. Shared by `/api/capabilities`
/// and `/api/settings/tier` so the two cannot contradict each other
/// (NAN-3378).
pub(crate) const SSO_AVAILABLE: bool = ENTERPRISE;

/// Get build edition + capability flags.
///
/// Public endpoint — no auth required. The SPA fetches this on app boot to
/// decide which surfaces to render.
#[utoipa::path(
    get,
    path = "/api/capabilities",
    tag = "system",
    responses(
        (status = 200, description = "Build edition and capability flags", body = CapabilitiesResponse),
    ),
    security(())
)]
pub async fn get_capabilities(State(state): State<AppState>) -> Json<CapabilitiesResponse> {
    Json(build_capabilities(state.config.ingest_mode))
}

/// The `/api/capabilities` body for this build and ingest mode.
pub(crate) fn build_capabilities(ingest_mode: IngestMode) -> CapabilitiesResponse {
    CapabilitiesResponse {
        edition: EDITION,
        version: env!("CARGO_PKG_VERSION"),
        ingest_mode: ingest_mode.as_str(),
        capabilities: Capabilities {
            search: true,
            cases: ENTERPRISE,
            notebooks: ENTERPRISE,
            risk: ENTERPRISE,
            melod: ENTERPRISE,
            query_correction: ENTERPRISE,
            custom_enrichment: ENTERPRISE,
            agent_enrichment: ENTERPRISE,
            ai_tuning: ENTERPRISE,
            playbooks: ENTERPRISE,
            incidents: ENTERPRISE,
            // Both editions — see the field doc. Deliberately not ENTERPRISE.
            siem_health: true,
            sso: SSO_AVAILABLE,
            observability_convergence: ENTERPRISE,
            // Never mounted outside hosted-shared — see the field doc.
            ioc_lists: false,
        },
    }
}

/// Resolve the current tenant's immutable plan and exact membership.
///
/// This is intentionally a separate authenticated route from the legacy
/// public `/api/capabilities`. The public route remains a build-edition probe
/// for dedicated/open-core deployments and is never tenant authorization.
#[utoipa::path(
    get,
    path = "/api/auth/tenant-bootstrap",
    tag = "auth",
    responses(
        (status = 200, description = "Exact active tenant identity and plan capabilities", body = TenantCapabilitiesResponse),
        (status = 401, description = "Tenant membership is not active", body = TenantCapabilitiesError),
        (status = 404, description = "Endpoint is unavailable outside enterprise_shared", body = TenantCapabilitiesError),
        (status = 503, description = "Tenant membership or plan lookup unavailable/invalid", body = TenantCapabilitiesError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_tenant_capabilities(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    // NAN-3463: optional so a deployment that is not hosted-shared (where
    // the tenant middleware never runs) reaches the 404 below. As required
    // extractors they rejected the request first with a 500 `Missing request
    // extension`.
    trusted_tenant: Option<Extension<TrustedTenantContext>>,
    authentication: Option<Extension<EnterpriseSharedSessionAuthentication>>,
) -> TenantCapabilitiesResult {
    #[cfg(feature = "enterprise")]
    let shared_profile = state.config.deployment_mode.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_profile = false;
    if !shared_profile {
        return Err(tenant_capabilities_error(
            StatusCode::NOT_FOUND,
            "tenant_bootstrap_unavailable",
            "Tenant bootstrap is unavailable for this deployment",
        ));
    }
    let (Some(Extension(trusted_tenant)), Some(Extension(authentication))) =
        (trusted_tenant, authentication)
    else {
        tracing::error!("enterprise_shared bootstrap reached without a tenant-bound session");
        return Err(tenant_capabilities_error(
            StatusCode::UNAUTHORIZED,
            "tenant_membership_inactive",
            "Tenant membership is not active",
        ));
    };
    if EDITION != "enterprise" {
        tracing::error!("enterprise_shared bootstrap requested from a non-enterprise build");
        return Err(tenant_capabilities_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant_bootstrap_unavailable",
            "Tenant bootstrap is temporarily unavailable",
        ));
    }
    if auth.is_api_key {
        return Err(tenant_capabilities_error(
            StatusCode::UNAUTHORIZED,
            "tenant_membership_inactive",
            "Tenant membership is not active",
        ));
    }

    // The middleware has already performed this lookup. Repeat it here so the
    // response's roles/permissions and plan are one fresh server-authoritative
    // bootstrap, rather than serializing possibly stale token claims.
    let membership = TenantMembershipResolver::new(state.pool.clone())
        .resolve_bound_slug_micros(
            auth.claims.sub,
            trusted_tenant.tenant_id,
            authentication.credential_time_micros,
            &trusted_tenant.tenant_slug,
        )
        .await
        .map_err(map_membership_error)?;
    let snapshot = TenantEntitlementResolver::new(state.pool.clone())
        .resolve(&membership.context)
        .await
        .map_err(map_entitlement_error)?;
    let feature_flags = resolve_tenant_feature_flags(
        state.pool.clone(),
        &membership.context,
        auth.claims.sub,
        membership.authority_revision,
        snapshot.assignment_revision,
    )
    .await?;

    build_tenant_capabilities_response(
        auth.claims.sub,
        &trusted_tenant,
        membership,
        snapshot,
        feature_flags,
    )
    .map(Json)
}

#[cfg(feature = "enterprise")]
async fn resolve_tenant_feature_flags(
    pool: sqlx::PgPool,
    tenant: &TrustedTenantContext,
    user_id: Uuid,
    authorization_revision: i64,
    assignment_revision: i64,
) -> Result<ResolvedTenantFeatureFlags, (StatusCode, Json<TenantCapabilitiesError>)> {
    let snapshot = EnterpriseSharedFeatureFlagResolver::new(pool, "enterprise_shared")
        .map_err(map_feature_flag_error)?
        .resolve(tenant, user_id, authorization_revision, assignment_revision)
        .await
        .map_err(map_feature_flag_error)?;
    Ok(ResolvedTenantFeatureFlags {
        tenant_id: snapshot.tenant_id,
        user_id: snapshot.user_id,
        authorization_revision: snapshot.grant_authority_revision,
        assignment_revision: snapshot.plan_assignment_revision,
        revision: snapshot.feature_flag_revision,
        flags: snapshot
            .flags
            .into_iter()
            .map(|(flag, enabled)| (flag.as_str().to_string(), enabled))
            .collect(),
    })
}

#[cfg(not(feature = "enterprise"))]
async fn resolve_tenant_feature_flags(
    _pool: sqlx::PgPool,
    _tenant: &TrustedTenantContext,
    _user_id: Uuid,
    _authorization_revision: i64,
    _assignment_revision: i64,
) -> Result<ResolvedTenantFeatureFlags, (StatusCode, Json<TenantCapabilitiesError>)> {
    Err(tenant_capabilities_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "tenant_feature_flags_unavailable",
        "Tenant rollout configuration is temporarily unavailable",
    ))
}

fn build_tenant_capabilities_response(
    user_id: Uuid,
    trusted_tenant: &TrustedTenantContext,
    membership: ResolvedTenantMembership,
    snapshot: TenantEntitlementSnapshot,
    feature_flags: ResolvedTenantFeatureFlags,
) -> Result<TenantCapabilitiesResponse, (StatusCode, Json<TenantCapabilitiesError>)> {
    if membership.context != *trusted_tenant
        || snapshot.tenant_id != trusted_tenant.tenant_id
        || feature_flags.tenant_id != trusted_tenant.tenant_id
        || feature_flags.user_id != user_id
        || feature_flags.authorization_revision != membership.authority_revision
        || feature_flags.assignment_revision != snapshot.assignment_revision
        || feature_flags.revision <= 0
    {
        return Err(tenant_capabilities_error(
            StatusCode::UNAUTHORIZED,
            "tenant_identity_mismatch",
            "Tenant identity could not be verified",
        ));
    }

    if contains_credential_shaped_key(&snapshot.limits)
        || snapshot
            .components
            .values()
            .any(|grant| contains_credential_shaped_key(&grant.configuration))
    {
        tracing::error!(
            tenant_id = %trusted_tenant.tenant_id,
            plan_code = %snapshot.plan_code,
            plan_revision = snapshot.plan_revision,
            "tenant plan contains credential-shaped public metadata — failing closed"
        );
        return Err(tenant_capabilities_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant_plan_invalid",
            "Tenant plan is temporarily unavailable",
        ));
    }

    let ha_enabled = snapshot
        .limits
        .get("ha_enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let components = snapshot
        .components
        .into_iter()
        .map(|(component, grant)| {
            (
                component.as_str().to_string(),
                TenantComponentCapability {
                    enabled: grant.enabled,
                    configuration: grant.configuration,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    if !ha_enabled
        || !components
            .get(TenantComponent::Sso.as_str())
            .is_some_and(|grant| grant.enabled)
    {
        return Err(tenant_capabilities_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant_plan_invalid",
            "Tenant plan is temporarily unavailable",
        ));
    }

    Ok(TenantCapabilitiesResponse {
        edition: EDITION,
        version: env!("CARGO_PKG_VERSION"),
        deployment_mode: "enterprise_shared",
        tenant: TenantCapabilityTenant {
            id: membership.context.tenant_id,
            slug: membership.context.tenant_slug,
        },
        identity: TenantCapabilityIdentity {
            user_id,
            roles: membership.roles,
            permissions: membership.permissions,
            authorization_revision: membership.authority_revision,
        },
        plan: TenantCapabilityPlan {
            code: snapshot.plan_code,
            revision: snapshot.plan_revision,
            assignment_revision: snapshot.assignment_revision,
        },
        limits: snapshot.limits,
        ha_enabled,
        components,
        feature_flags: TenantCapabilityFeatureFlags {
            revision: feature_flags.revision,
            flags: feature_flags.flags,
        },
    })
}

fn contains_credential_shaped_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(entries) => entries.iter().any(|(key, value)| {
            let normalized = key.to_ascii_lowercase();
            [
                "secret",
                "password",
                "credential",
                "private_key",
                "access_key",
                "api_key",
                "token",
            ]
            .iter()
            .any(|needle| normalized.contains(needle))
                || contains_credential_shaped_key(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(contains_credential_shaped_key),
        _ => false,
    }
}

fn map_membership_error(
    error: TenantResolutionError,
) -> (StatusCode, Json<TenantCapabilitiesError>) {
    match error {
        TenantResolutionError::AccessDenied => tenant_capabilities_error(
            StatusCode::UNAUTHORIZED,
            "tenant_membership_inactive",
            "Tenant membership is not active",
        ),
        TenantResolutionError::Unavailable => tenant_capabilities_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant_membership_unavailable",
            "Tenant membership is temporarily unavailable",
        ),
    }
}

fn map_entitlement_error(
    error: TenantEntitlementError,
) -> (StatusCode, Json<TenantCapabilitiesError>) {
    match error {
        TenantEntitlementError::AccessDenied | TenantEntitlementError::ComponentDisabled { .. } => {
            tenant_capabilities_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_plan_unavailable",
                "Tenant plan is temporarily unavailable",
            )
        }
        TenantEntitlementError::InvalidContract { .. } | TenantEntitlementError::Unavailable => {
            tenant_capabilities_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_plan_invalid",
                "Tenant plan is temporarily unavailable",
            )
        }
    }
}

#[cfg(feature = "enterprise")]
fn map_feature_flag_error(
    error: EnterpriseSharedFeatureFlagError,
) -> (StatusCode, Json<TenantCapabilitiesError>) {
    if nanosiem_core::db::contention::is_lock_contention(&error) {
        return tenant_capabilities_error(StatusCode::SERVICE_UNAVAILABLE, "resource_lock_contention", "Resource is locked; retry shortly");
    }
    match error {
        EnterpriseSharedFeatureFlagError::AccessDenied => tenant_capabilities_error(
            StatusCode::UNAUTHORIZED,
            "tenant_feature_flags_stale_authority",
            "Tenant authorization changed during bootstrap",
        ),
        EnterpriseSharedFeatureFlagError::Disabled
        | EnterpriseSharedFeatureFlagError::InvalidCatalog(_)
        | EnterpriseSharedFeatureFlagError::InvalidMutation(_)
        | EnterpriseSharedFeatureFlagError::IdempotencyConflict
        | EnterpriseSharedFeatureFlagError::Unavailable(_) => tenant_capabilities_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant_feature_flags_unavailable",
            "Tenant rollout configuration is temporarily unavailable",
        ),
    }
}

fn tenant_capabilities_error(
    status: StatusCode,
    error: &'static str,
    message: &'static str,
) -> (StatusCode, Json<TenantCapabilitiesError>) {
    (status, Json(TenantCapabilitiesError { error, message, retry_after_seconds: (error == "resource_lock_contention").then_some(1) }))
}

#[derive(OpenApi)]
#[openapi(
    paths(get_capabilities, get_tenant_capabilities),
    components(schemas(
        CapabilitiesResponse,
        Capabilities,
        TenantCapabilitiesResponse,
        TenantCapabilitiesError,
        TenantCapabilityTenant,
        TenantCapabilityIdentity,
        TenantCapabilityPlan,
        TenantComponentCapability,
        TenantCapabilityFeatureFlags
    ))
)]
pub struct CapabilitiesApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::TenantComponentGrant;

    #[test]
    fn tenant_bootstrap_user_identity_matches_auth_me_wire_format() {
        let user_id = Uuid::now_v7();
        let identity = TenantCapabilityIdentity {
            user_id,
            roles: vec![],
            permissions: vec![],
            authorization_revision: 1,
        };
        let current_user = crate::handlers::auth::CurrentUserResponse {
            id: user_id,
            email: "wire-contract@nano.test".to_string(),
            name: "Wire contract".to_string(),
            roles: vec![],
            permissions: vec![],
            is_api_key: false,
            preferred_query_mode: None,
            landing_page: None,
            deployment_mode: "enterprise_shared".to_string(),
            active_tenant: None,
            demo: None,
        };
        let bootstrap = serde_json::to_value(identity).unwrap();
        let auth_me = serde_json::to_value(current_user).unwrap();
        assert_eq!(bootstrap["userId"], auth_me["id"]);
        assert_eq!(bootstrap["userId"], nanosiem_core::typeid::encode("user", &user_id));
    }

    fn shared_contract(
        tenant_id: Uuid,
        tenant_slug: &str,
        assignment_revision: i64,
        cases: bool,
    ) -> (
        TrustedTenantContext,
        ResolvedTenantMembership,
        TenantEntitlementSnapshot,
        ResolvedTenantFeatureFlags,
    ) {
        let context = TrustedTenantContext {
            tenant_id,
            tenant_slug: tenant_slug.to_string(),
        };
        let membership = ResolvedTenantMembership {
            context: context.clone(),
            roles: vec!["analyst".to_string()],
            permissions: vec!["search:read".to_string()],
            authority_revision: 11,
        };
        let components = nanosiem_core::TENANT_COMPONENTS
            .into_iter()
            .map(|component| {
                (
                    component,
                    TenantComponentGrant {
                        enabled: component != TenantComponent::Cases || cases,
                        configuration: serde_json::json!({}),
                    },
                )
            })
            .collect();
        let snapshot = TenantEntitlementSnapshot {
            tenant_id,
            plan_code: "hobby".to_string(),
            plan_revision: 1,
            assignment_revision,
            retention_revision: 1,
            retention_option_revision: 1,
            retention_days: 365,
            irreversible_event_time_floor: chrono::DateTime::UNIX_EPOCH,
            limits: serde_json::json!({"ha_enabled": true, "retention_days": 365}),
            components,
        };
        let feature_flags = ResolvedTenantFeatureFlags {
            tenant_id,
            user_id: Uuid::from_u128(0x55),
            authorization_revision: 11,
            assignment_revision,
            revision: 13,
            flags: [
                ("oidc_group_role_reconciliation".to_string(), false),
                ("parser_cell_canary".to_string(), false),
                ("r2_archive_cache_read".to_string(), false),
                ("soc_ai_long_hunts".to_string(), false),
            ]
            .into_iter()
            .collect(),
        };
        (context, membership, snapshot, feature_flags)
    }

    #[test]
    fn returns_known_edition() {
        let body = build_capabilities(IngestMode::Vector);
        assert!(matches!(body.edition, "open" | "enterprise"));
        assert!(!body.version.is_empty());
        let encoded = serde_json::to_value(body).unwrap();
        let mut keys = encoded
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "capabilities".to_string(),
                "edition".to_string(),
                "ingestMode".to_string(),
                "version".to_string(),
            ]
        );
    }

    #[test]
    fn reports_tenzir_only_ingest_mode() {
        let vector = serde_json::to_value(build_capabilities(IngestMode::Vector)).unwrap();
        assert_eq!(vector["ingestMode"], "vector");
        let tenzir = serde_json::to_value(build_capabilities(IngestMode::TenzirOnly)).unwrap();
        assert_eq!(tenzir["ingestMode"], "tenzir_only");
        // The per-surface flags are build-wide and unaffected by ingest mode.
        assert_eq!(vector["capabilities"], tenzir["capabilities"]);
    }

    #[test]
    fn capabilities_match_feature_flag() {
        if cfg!(feature = "enterprise") {
            assert_eq!(EDITION, "enterprise");
            assert!(ENTERPRISE);
        } else {
            assert_eq!(EDITION, "open");
            assert!(!ENTERPRISE);
        }
    }

    #[test]
    fn tenant_bootstrap_rejects_same_user_cross_tenant_and_slug_mismatch() {
        let user_id = Uuid::from_u128(0x55);
        let (tenant_a, membership_a, snapshot_a, flags_a) =
            shared_contract(Uuid::from_u128(0xa), "tenant-a", 1, true);
        let (tenant_b, _, _, _) = shared_contract(Uuid::from_u128(0xb), "tenant-b", 1, true);
        let cross_tenant = build_tenant_capabilities_response(
            user_id,
            &tenant_b,
            membership_a.clone(),
            snapshot_a.clone(),
            flags_a,
        )
        .expect_err("tenant A must never bootstrap tenant B");
        assert_eq!(cross_tenant.0, StatusCode::UNAUTHORIZED);

        let mismatched_slug = TrustedTenantContext {
            tenant_id: tenant_a.tenant_id,
            tenant_slug: "tenant-b".to_string(),
        };
        let (_, _, _, flags_a) = shared_contract(Uuid::from_u128(0xa), "tenant-a", 1, true);
        let slug_error = build_tenant_capabilities_response(
            user_id,
            &mismatched_slug,
            membership_a,
            snapshot_a,
            flags_a,
        )
        .expect_err("matching UUID with a different slug must fail");
        assert_eq!(slug_error.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn disabled_component_and_assignment_revision_are_explicit() {
        let tenant_id = Uuid::from_u128(0xa);
        let (trusted, membership, snapshot, flags) =
            shared_contract(tenant_id, "tenant-a", 7, false);
        let response = build_tenant_capabilities_response(
            Uuid::from_u128(0x55),
            &trusted,
            membership,
            snapshot,
            flags,
        )
        .expect("valid bootstrap");
        assert_eq!(response.plan.assignment_revision, 7);
        assert!(!response.components["cases"].enabled);

        let (trusted, membership, snapshot, flags) =
            shared_contract(tenant_id, "tenant-a", 8, true);
        let changed = build_tenant_capabilities_response(
            Uuid::from_u128(0x55),
            &trusted,
            membership,
            snapshot,
            flags,
        )
        .expect("new assignment revision");
        assert_eq!(changed.plan.assignment_revision, 8);
        assert!(changed.components["cases"].enabled);
    }

    #[test]
    fn stale_flag_snapshot_cannot_cross_member_or_plan_authority() {
        let tenant_id = Uuid::from_u128(0xa);
        let user_id = Uuid::from_u128(0x55);
        let (trusted, membership, snapshot, mut flags) =
            shared_contract(tenant_id, "tenant-a", 7, true);
        flags.assignment_revision = 6;
        assert_eq!(
            build_tenant_capabilities_response(
                user_id,
                &trusted,
                membership.clone(),
                snapshot.clone(),
                flags,
            )
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );

        let (_, _, _, mut flags) = shared_contract(tenant_id, "tenant-a", 7, true);
        flags.authorization_revision = 10;
        assert_eq!(
            build_tenant_capabilities_response(
                user_id,
                &trusted,
                membership.clone(),
                snapshot.clone(),
                flags,
            )
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );

        let (_, _, _, mut flags) = shared_contract(tenant_id, "tenant-a", 7, true);
        flags.user_id = Uuid::from_u128(0x66);
        assert_eq!(
            build_tenant_capabilities_response(user_id, &trusted, membership, snapshot, flags)
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn revoked_membership_and_database_failure_fail_closed() {
        assert_eq!(
            map_membership_error(TenantResolutionError::AccessDenied).0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            map_membership_error(TenantResolutionError::Unavailable).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            map_entitlement_error(TenantEntitlementError::InvalidContract {
                reason: "missing component".to_string()
            })
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn tenant_bootstrap_refuses_to_serialize_credential_shaped_plan_metadata() {
        let (trusted, membership, mut snapshot, flags) =
            shared_contract(Uuid::from_u128(0xa), "tenant-a", 1, true);
        snapshot
            .components
            .get_mut(&TenantComponent::Search)
            .unwrap()
            .configuration = serde_json::json!({"worker": {"api_token": "must-never-render"}});
        let error = build_tenant_capabilities_response(
            Uuid::from_u128(0x55),
            &trusted,
            membership,
            snapshot,
            flags,
        )
        .expect_err("credential-shaped plan metadata must fail closed");
        assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!error.1.message.contains("token"));
    }
}

#[cfg(all(test, feature = "enterprise"))]
mod lock_contention_contract_tests {
    use super::*;
    #[test]
    fn feature_flag_lock_contention_has_a_retry_hint() {
        let database = crate::handlers::lock_contention_contract_tests::database_error("55P03");
        let (status, Json(body)) = map_feature_flag_error(EnterpriseSharedFeatureFlagError::Unavailable(database));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.error, "resource_lock_contention");
        assert_eq!(body.retry_after_seconds, Some(1));
    }
}

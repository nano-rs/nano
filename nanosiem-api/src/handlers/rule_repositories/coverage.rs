// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Query, State},
    Extension, Json,
};
#[cfg(feature = "enterprise")]
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, SIGMA_CONVERTED};
use nanosiem_core::auth::permissions;
use nanosiem_core::rule_repository::SigmaRule;
use nanosiem_core::{CoverageAnalysis, CoverageFilter};

use super::get_rule_repo_service;
#[cfg(feature = "enterprise")]
use super::types::FieldMappingResponse;
use super::types::{ConvertSigmaRequest, ConvertSigmaResponse, CoverageQuery};
#[cfg(feature = "enterprise")]
use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Authorize and validate a standalone Sigma conversion before any registry,
/// database-credit, or provider work.
///
/// `rule_repositories:view` deliberately is not part of this policy: the
/// request supplies the complete rule and the operation neither reads a
/// repository nor persists a detection. `melod:detection` is the seeded
/// capability for asking the detection authoring agent to produce rule code.
fn preflight_sigma_conversion(auth: &AuthContext, sigma_yaml: &str) -> Result<SigmaRule, ApiError> {
    ensure_permission(auth, permissions::MELOD_DETECTION)?;

    nanosiem_core::rule_repository::parse_sigma(sigma_yaml)
        .map_err(|e| ApiError::BadRequest(format!("Failed to parse Sigma rule: {}", e)))
}

/// Get coverage analysis
#[utoipa::path(
    get,
    path = "/api/rule-repositories/coverage",
    tag = "rule_repositories",
    params(CoverageQuery),
    responses(
        (status = 200, description = "Coverage analysis retrieved successfully", body = CoverageAnalysis),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn get_coverage(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<CoverageQuery>,
) -> Result<Json<CoverageAnalysis>, ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_VIEW)?;

    let service = get_rule_repo_service(&state)?;

    let filter = CoverageFilter {
        repository_id: query.repository_id,
        severity: query.severity,
        mitre_tactic: query.mitre_tactic,
        mitre_technique: query.mitre_technique,
    };

    // NAN-2081: coverage is computed from live ClickHouse telemetry and echoes
    // source types back through `most_missing_fields[].source_types_with_field`.
    // Same two gates as the import preview — live-data capability, then the
    // requester's effective per-source deny set.
    let scope = nanosiem_core::auth::ScopeSet::from_denied(auth.effective_source_deny_set());
    let access = super::rules::live_inventory_access(&auth, &scope);
    let analysis = service.get_coverage_analysis(filter, &access).await?;

    Ok(Json(analysis))
}

/// Refresh coverage data from ClickHouse
#[utoipa::path(
    post,
    path = "/api/rule-repositories/coverage/refresh",
    tag = "rule_repositories",
    responses(
        (status = 200, description = "Coverage data refreshed successfully"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn refresh_coverage(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<(), ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_SYNC)?;

    let service = get_rule_repo_service(&state)?;
    service.refresh_coverage_data().await?;

    Ok(())
}

/// Convert a Sigma rule to nPL (standalone, without importing)
#[utoipa::path(
    post,
    path = "/api/sigma/convert",
    tag = "rule_repositories",
    request_body = ConvertSigmaRequest,
    responses(
        (status = 200, description = "Sigma rule converted successfully", body = ConvertSigmaResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
#[cfg(feature = "enterprise")]
pub async fn convert_sigma(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<ConvertSigmaRequest>,
) -> Result<Json<ConvertSigmaResponse>, ApiError> {
    // NAN-2063: capability and caller-controlled syntax are decided before
    // registry reads, provider resolution, or reserving tenant AI credits.
    let sigma_rule = preflight_sigma_conversion(&auth, &req.sigma_yaml)?;

    // Resolve the service and the detection-specific client before charging.
    // This also keeps the billed model aligned with the provider actually used.
    let ai_client = {
        let melod_guard = state.melod_service.read().await;
        let melod_service = melod_guard
            .as_ref()
            .ok_or_else(|| ApiError::InternalError("AI service not configured".to_string()))?;
        melod_service.detection_agent().ai_client_arc()
    };
    let model_id = ai_client.model_id().to_string();
    let converter = nanosiem_enterprise::melod::SigmaConverterAgent::new(
        ai_client,
        state.config.schema_profile(),
    );

    // Resolve against the client that will actually make the call. If the
    // configured detection provider fell back at service construction, this
    // bills the fallback model rather than a stale registry selection.
    let cost = nanosiem_core::resolve_ai_request_cost(&state.pool, &model_id).await;

    // The request is fully authorized, parsed, and provider-ready. Reserve
    // exactly once at the last handler boundary before the actual AI call.
    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let tier_limits = tier_settings.get_tier_limits().await?;
    tier_settings
        .increment_ai_credits(cost, tier_limits.ai_credits_per_month)
        .await?;

    let context = nanosiem_enterprise::melod::ConversionContext::default();
    let conversion = converter.convert(&sigma_rule, context).await;

    // The gateway usage ledger records the detection agent and token counts.
    // This route audit adds the requesting JWT/API-key principal and outcome.
    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, SIGMA_CONVERTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("sigma_rule", None, Some(sigma_rule.title.clone()))
            .client_context(&client)
            .success(conversion.is_ok())
            .details(serde_json::json!({
                "agent": nanosiem_enterprise::melod::AgentId::Detection.as_str(),
                "credits_reserved": cost,
            }))
            .build(),
    );

    let result =
        conversion.map_err(|e| ApiError::InternalError(format!("Conversion failed: {}", e)))?;

    Ok(Json(ConvertSigmaResponse {
        npl_query: result.npl_query,
        confidence: result.confidence,
        field_mappings: result
            .field_mappings
            .into_iter()
            .map(|m| FieldMappingResponse {
                sigma_field: m.sigma_field,
                udm_field: m.udm_field,
                confidence: m.confidence,
                notes: m.notes,
            })
            .collect(),
        unmapped_fields: result.unmapped_fields,
        requires_fields: result.requires_fields,
        warnings: result.warnings,
        needs_review: result.needs_review,
    }))
}

/// Open-core stub: Sigma → nPL conversion is enterprise-only (depends on the
/// meloD detection agent). Endpoint stays registered; users must supply
/// `custom_npl` on the import endpoint instead.
#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    post,
    path = "/api/sigma/convert",
    tag = "rule_repositories",
    request_body = ConvertSigmaRequest,
    responses(
        (status = 400, description = "Enterprise-only endpoint"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn convert_sigma(
    State(_state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<ConvertSigmaRequest>,
) -> Result<Json<ConvertSigmaResponse>, ApiError> {
    // Keep authorization and caller-input handling byte-for-byte equivalent to
    // enterprise so an open-core deployment cannot become a policy side door.
    let _sigma_rule = preflight_sigma_conversion(&auth, &req.sigma_yaml)?;
    Err(ApiError::BadRequest(
        "Sigma → nPL conversion requires the enterprise build. \
        Provide `custom_npl` on the import endpoint instead."
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::api_key::ApiKeyInfo;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::TokenClaims;
    use uuid::Uuid;

    const VALID_SIGMA: &str = r#"
title: Suspicious PowerShell
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: Invoke-Expression
  condition: selection
"#;

    fn jwt_auth(values: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: values.iter().map(ToString::to_string).collect(),
            exp: chrono::Utc::now().timestamp() + 60,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn api_key_auth(values: &[&str]) -> AuthContext {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "sigma-probe".to_string(),
            permissions: values.iter().map(ToString::to_string).collect(),
            user_id: Some(Uuid::now_v7()),
        })
    }

    fn both_principals(values: &[&str]) -> [AuthContext; 2] {
        [jwt_auth(values), api_key_auth(values)]
    }

    fn assert_forbidden(result: Result<SigmaRule, ApiError>) {
        match result {
            Err(ApiError::Forbidden(message)) => {
                assert_eq!(
                    message,
                    format!("Missing permission: {}", permissions::MELOD_DETECTION)
                );
            }
            Err(other) => panic!("expected Forbidden, got {other:?}"),
            Ok(_) => panic!("expected Forbidden, got Ok"),
        }
    }

    #[test]
    fn jwt_and_api_keys_require_the_explicit_detection_capability() {
        // Zero, unrelated, and repository-view-only grants all fail identically.
        for permissions in [
            Vec::<&str>::new(),
            vec![permissions::SEARCH_EXECUTE],
            vec![permissions::RULE_REPOSITORIES_VIEW],
            vec![
                permissions::RULE_REPOSITORIES_VIEW,
                permissions::RULE_REPOSITORIES_SYNC,
            ],
        ] {
            for auth in both_principals(&permissions) {
                assert_forbidden(preflight_sigma_conversion(&auth, VALID_SIGMA));
            }
        }

        // The action capability is complete by itself: standalone conversion
        // consumes neither repository reads nor detection persistence.
        for auth in both_principals(&[permissions::MELOD_DETECTION]) {
            let rule = preflight_sigma_conversion(&auth, VALID_SIGMA)
                .expect("melod:detection should authorize valid Sigma");
            assert_eq!(rule.title, "Suspicious PowerShell");
        }
    }

    #[test]
    fn authorization_precedes_parsing_for_both_principal_kinds() {
        for auth in both_principals(&[permissions::RULE_REPOSITORIES_VIEW]) {
            // A malformed body must not turn an under-scoped caller's 403 into
            // a parser oracle (and the handler cannot reach credit/provider work).
            assert_forbidden(preflight_sigma_conversion(&auth, "not: [valid"));
        }

        for auth in both_principals(&[permissions::MELOD_DETECTION]) {
            assert!(matches!(
                preflight_sigma_conversion(&auth, "not: [valid"),
                Err(ApiError::BadRequest(_))
            ));
        }
    }

    fn region<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let tail = source
            .split_once(start)
            .unwrap_or_else(|| panic!("missing source marker: {start}"))
            .1;
        tail.split_once(end)
            .unwrap_or_else(|| panic!("missing source marker: {end}"))
            .0
    }

    #[test]
    fn denied_or_malformed_requests_cannot_reserve_credits_or_invoke_ai() {
        let source = include_str!("coverage.rs");
        let preflight = region(
            source,
            "fn preflight_sigma_conversion(",
            "/// Get coverage analysis",
        );
        let authorization = preflight
            .find("ensure_permission(auth, permissions::MELOD_DETECTION)")
            .expect("explicit action gate disappeared");
        let parsing = preflight
            .find("parse_sigma(sigma_yaml)")
            .expect("Sigma parsing disappeared");
        assert!(
            authorization < parsing,
            "caller input is parsed before the action capability is authorized"
        );

        let enterprise = region(
            source,
            "#[cfg(feature = \"enterprise\")]\npub async fn convert_sigma(",
            "/// Open-core stub:",
        );
        let gate = enterprise
            .find("preflight_sigma_conversion(&auth, &req.sigma_yaml)?")
            .expect("enterprise handler bypasses the shared preflight");
        let service = enterprise
            .find("state.melod_service.read().await")
            .expect("meloD service lookup disappeared");
        let cost_resolution = enterprise
            .find("resolve_ai_request_cost(&state.pool, &model_id).await")
            .expect("model cost resolution disappeared");
        let charge = enterprise
            .find(".increment_ai_credits(")
            .expect("credit reservation disappeared");
        let invoke = enterprise
            .find("converter.convert(&sigma_rule, context).await")
            .expect("Sigma conversion invocation disappeared");

        assert!(
            gate < service && gate < cost_resolution && gate < charge && gate < invoke,
            "authorization/parsing no longer precedes every service, credit, and provider effect"
        );
        assert!(
            service < charge && cost_resolution < charge && charge < invoke,
            "credits must be the final handler-side effect before conversion"
        );
        assert_eq!(
            enterprise.matches(".increment_ai_credits(").count(),
            1,
            "one accepted request must reserve credits exactly once"
        );
        assert!(
            enterprise.contains("detection_agent().ai_client_arc()"),
            "Sigma conversion no longer uses the detection agent's configured client"
        );
    }

    #[test]
    fn open_core_keeps_the_same_gate_and_documents_forbidden() {
        let source = include_str!("coverage.rs");
        let open_core = source
            .split_once("#[cfg(not(feature = \"enterprise\"))]")
            .expect("open-core Sigma handler disappeared")
            .1;
        assert!(
            open_core.contains("preflight_sigma_conversion(&auth, &req.sigma_yaml)?"),
            "open-core handler bypasses the shared action gate"
        );
        assert!(
            open_core.contains("(status = 403, description = \"Forbidden\")"),
            "open-core OpenAPI no longer advertises the authorization response"
        );
    }

    #[test]
    fn provider_attempt_audit_attributes_agent_and_principal() {
        let source = include_str!("coverage.rs");
        let enterprise = region(
            source,
            "#[cfg(feature = \"enterprise\")]\npub async fn convert_sigma(",
            "/// Open-core stub:",
        );
        for required in [
            "AuditSource::RuleRepo, SIGMA_CONVERTED",
            ".actor(Some(auth.user_id()), None)",
            ".api_key(auth.api_key_id, auth.api_key_name.clone())",
            "\"agent\": nanosiem_enterprise::melod::AgentId::Detection.as_str()",
            ".success(conversion.is_ok())",
        ] {
            assert!(
                enterprise.contains(required),
                "Sigma provider-attempt audit lost `{required}`"
            );
        }
    }
}

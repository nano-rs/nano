// SPDX-License-Identifier: AGPL-3.0-or-later

//! /health finding suppression API handlers (NAN-615).
//!
//! Operators mark recommendations on /health as "not an issue" with a reason;
//! the active suppressions are loaded by the scheduler and injected into the
//! AI system prompt so the same class doesn't reappear on the next run.
//!
//! Both reads and mutations require `settings:system` (NAN-2036). Suppression
//! records expose finding titles, operator rationale, and named system
//! weaknesses, so they must not be an auth-only side channel — they match the
//! /health admin gate that the manual trigger and mutations already use.

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::AuthContext;
use crate::state::AppState;
use nanosiem_core::auth::ArtifactScope;
use nanosiem_core::siem_health::finding_signature::signature_for_title;
use nanosiem_core::siem_health::{FindingSuppression, SuppressionRepository};
use nanosiem_core::typeid::TypeIdParam;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateSuppressionRequest {
    /// Display title of the suppressed finding, verbatim from the
    /// recommendation card. The backend derives the stable signature from
    /// this title so the frontend doesn't need to reimplement the hash.
    pub title: String,
    /// Operator's reason — fed to the AI on subsequent runs so it can judge
    /// whether the suppression still applies.
    pub reason: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListSuppressionsResponse {
    pub suppressions: Vec<FindingSuppression>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListSuppressionsParams {
    /// When true, include deactivated (undone) suppressions as well as active
    /// ones. Defaults to false.
    #[serde(default)]
    pub include_deactivated: bool,
}

const REASON_MAX_LEN: usize = 500;
const TITLE_MAX_LEN: usize = 500;

/// NAN-2219: the scope's per-source RBAC half. Suppression rows carry no source
/// provenance, so the question this gate asks is "does this principal have a
/// per-source boundary at all?" — the `audit:view` gate does not create one, and
/// folding it in made every non-Admin unable to read or manage suppressions on
/// tenants with no source scoping configured.
fn effective_artifact_scope(auth: &AuthContext) -> ArtifactScope {
    ArtifactScope::from_scope(&auth.effective_viewer_scope())
}

/// Suppression rows do not yet carry source provenance. A source-scoped
/// principal cannot safely create or mutate one because the response and
/// future AI prompt would contain an unattributed finding title/reason.
fn ensure_suppression_mutation_allowed(auth: &AuthContext) -> Result<(), ApiError> {
    if effective_artifact_scope(auth).is_unrestricted() {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "SIEM health suppressions require unrestricted source visibility".to_string(),
        ))
    }
}

/// Suppress a /health finding so the AI omits the same class on subsequent
/// report runs. Suppression rows have no source provenance, so mutations
/// require unrestricted source visibility.
#[utoipa::path(
    post,
    path = "/api/siem-health/findings/suppressions",
    tag = "siem_health",
    request_body = CreateSuppressionRequest,
    responses(
        (status = 201, description = "Suppression created (or refreshed if one already exists for this signature)", body = FindingSuppression),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("api_key" = []))
)]
pub async fn create_suppression(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateSuppressionRequest>,
) -> Result<(StatusCode, Json<FindingSuppression>), ApiError> {
    crate::middleware::ensure_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)?;
    ensure_suppression_mutation_allowed(&auth)?;

    let title = req.title.trim();
    let reason = req.reason.trim();
    if title.is_empty() {
        return Err(ApiError::BadRequest("title must not be empty".to_string()));
    }
    if reason.is_empty() {
        return Err(ApiError::BadRequest(
            "reason must not be empty — operators must explain why this is not an issue"
                .to_string(),
        ));
    }
    if title.len() > TITLE_MAX_LEN {
        return Err(ApiError::BadRequest(format!(
            "title exceeds {TITLE_MAX_LEN} chars"
        )));
    }
    if reason.len() > REASON_MAX_LEN {
        return Err(ApiError::BadRequest(format!(
            "reason exceeds {REASON_MAX_LEN} chars"
        )));
    }

    let signature = signature_for_title(title);
    let repo = SuppressionRepository::new(state.pool.clone());
    let suppression = repo
        .create(&signature, title, reason, auth.user_id())
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok((StatusCode::CREATED, Json(suppression)))
}

/// List /health finding suppressions. Restricted viewers receive an empty list
/// because legacy title/reason prose cannot be safely source-filtered.
#[utoipa::path(
    get,
    path = "/api/siem-health/findings/suppressions",
    tag = "siem_health",
    params(ListSuppressionsParams),
    responses(
        (status = 200, description = "List of suppressions, oldest-first when active-only, newest-first when including deactivated", body = ListSuppressionsResponse),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("api_key" = []))
)]
pub async fn list_suppressions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListSuppressionsParams>,
) -> Result<Json<ListSuppressionsResponse>, ApiError> {
    // NAN-2036: suppression rows expose finding titles + operator rationale, so
    // reads require settings:system too — matching create/deactivate and the rest
    // of the /health admin surface. This route was previously auth-only.
    crate::middleware::ensure_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)?;

    let repo = SuppressionRepository::new(state.pool.clone());
    let artifact_scope = effective_artifact_scope(&auth);
    let suppressions = if params.include_deactivated {
        repo.list_all_for_scope(&artifact_scope).await
    } else {
        repo.list_active_for_scope(&artifact_scope).await
    }
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(ListSuppressionsResponse { suppressions }))
}

/// Deactivate (undo) a suppression. Findings of this class will surface again
/// on the next report run. Suppression mutations require unrestricted source
/// visibility.
#[utoipa::path(
    delete,
    path = "/api/siem-health/findings/suppressions/{id}",
    tag = "siem_health",
    params(
        ("id" = String, Path, description = "Suppression typeid (hsupp_<base32>) or bare UUID"),
    ),
    responses(
        (status = 200, description = "Suppression deactivated", body = FindingSuppression),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Suppression not found or already deactivated"),
    ),
    security(("api_key" = []))
)]
pub async fn deactivate_suppression(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<FindingSuppression>, ApiError> {
    crate::middleware::ensure_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)?;
    ensure_suppression_mutation_allowed(&auth)?;

    let repo = SuppressionRepository::new(state.pool.clone());
    let suppression = repo
        .deactivate(*id, auth.user_id())
        .await
        .map_err(|e| match e {
            nanosiem_core::siem_health::SuppressionRepositoryError::NotFound(_) => {
                ApiError::NotFound("Suppression not found or already deactivated".to_string())
            }
            other => ApiError::DatabaseError(other.to_string()),
        })?;

    Ok(Json(suppression))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(create_suppression, list_suppressions, deactivate_suppression),
    components(schemas(
        CreateSuppressionRequest,
        ListSuppressionsResponse,
        FindingSuppression,
    ))
)]
pub struct SiemHealthSuppressionsApiDoc;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use nanosiem_core::auth::api_key::ApiKeyInfo;
    use nanosiem_core::auth::permissions;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::{ScopeSet, TokenClaims};
    use uuid::Uuid;

    use super::*;

    fn scope(denied: &[&str]) -> ScopeSet {
        ScopeSet::from_denied(
            denied
                .iter()
                .map(|source_type| source_type.to_string())
                .collect::<BTreeSet<_>>(),
        )
    }

    fn jwt_auth(denied: &[&str], audit_view: bool) -> AuthContext {
        let mut auth = AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: [
                Some(permissions::SETTINGS_SYSTEM.to_string()),
                audit_view.then(|| permissions::AUDIT_VIEW.to_string()),
            ]
            .into_iter()
            .flatten()
            .collect(),
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        });
        auth.denied_sources = scope(denied);
        auth
    }

    fn api_key_auth(denied: &[&str], audit_view: bool) -> AuthContext {
        let mut auth = AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "NAN-2089 suppression parity".to_string(),
            permissions: [
                Some(permissions::SETTINGS_SYSTEM.to_string()),
                audit_view.then(|| permissions::AUDIT_VIEW.to_string()),
            ]
            .into_iter()
            .flatten()
            .collect(),
            user_id: Some(Uuid::now_v7()),
        });
        auth.denied_sources = scope(denied);
        auth
    }

    fn forbidden_message(result: Result<(), ApiError>) -> String {
        match result {
            Err(ApiError::Forbidden(message)) => message,
            Err(other) => panic!("expected Forbidden, got {other:?}"),
            Ok(()) => panic!("expected Forbidden, got Ok"),
        }
    }

    #[test]
    fn suppression_mutations_require_unrestricted_scope_for_both_principals() {
        for auth in [
            jwt_auth(&["insider_threat"], true),
            api_key_auth(&["insider_threat"], true),
            // A registry-restricted `audit` is a real per-source boundary and
            // still blocks the mutation, with or without `audit:view`.
            jwt_auth(&["audit"], true),
            api_key_auth(&["audit"], false),
        ] {
            assert_eq!(
                forbidden_message(ensure_suppression_mutation_allowed(&auth)),
                "SIEM health suppressions require unrestricted source visibility"
            );
        }
    }

    #[test]
    fn unrestricted_jwt_and_api_key_principals_keep_suppression_behavior() {
        for auth in [jwt_auth(&[], true), api_key_auth(&[], true)] {
            assert!(effective_artifact_scope(&auth).is_unrestricted());
            ensure_suppression_mutation_allowed(&auth)
                .expect("unrestricted suppression mutation remains allowed");
        }
    }

    /// NAN-2219: lacking `audit:view` is not a per-source boundary. A caller
    /// with `settings:system` and no source grants restricting them must not be
    /// treated as source-restricted here — that blocked suppression management
    /// outright on every tenant with an empty `restricted_source_types`
    /// registry.
    #[test]
    fn missing_audit_view_alone_no_longer_blocks_suppression_mutations() {
        for auth in [jwt_auth(&[], false), api_key_auth(&[], false)] {
            assert!(effective_artifact_scope(&auth).is_unrestricted());
            ensure_suppression_mutation_allowed(&auth)
                .expect("an unscoped principal may manage suppressions (NAN-2219)");
            // The row-filter half still denies audit event rows everywhere else.
            assert!(auth.effective_viewer_scope().deny_set().contains("audit"));
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Onboarding wizard endpoints
//!
//! Implements:
//! - GET    /api/onboarding/progress       - Get current user's progress
//! - PUT    /api/onboarding/progress       - Update current step
//! - POST   /api/onboarding/complete-step  - Mark step completed
//! - POST   /api/onboarding/skip-step      - Mark step skipped
//! - POST   /api/onboarding/dismiss        - Dismiss entire wizard
//! - POST   /api/onboarding/reset          - Reset (re-run wizard)
//! - GET    /api/onboarding/status         - System config checklist

use axum::{extract::State, Extension, Json};
use nanosiem_core::onboarding::{
    OnboardingProgress, OnboardingStatus, OnboardingStep, StepActionRequest, UpdateProgressRequest,
};
use tracing::warn;

use crate::error::ApiError;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;
use nanosiem_core::auth::permissions;

// ============================================================================
// Handlers
// ============================================================================

/// Get the current user's onboarding progress
#[utoipa::path(
    get,
    path = "/api/onboarding/progress",
    tag = "onboarding",
    responses(
        (status = 200, description = "Onboarding progress (null if not started)", body = Option<OnboardingProgress>),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_onboarding_progress(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Option<OnboardingProgress>>, ApiError> {
    let progress = state
        .onboarding_repo
        .get_progress(auth.user_id())
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(progress))
}

/// Update the current step
#[utoipa::path(
    put,
    path = "/api/onboarding/progress",
    tag = "onboarding",
    request_body = UpdateProgressRequest,
    responses(
        (status = 200, description = "Updated progress", body = OnboardingProgress),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_onboarding_progress(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<UpdateProgressRequest>,
) -> Result<Json<OnboardingProgress>, ApiError> {
    let mut progress = state
        .onboarding_repo
        .get_progress(auth.user_id())
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?
        .unwrap_or_else(|| OnboardingProgress {
            user_id: auth.user_id(),
            current_step: OnboardingStep::AiSetup,
            completed_steps: vec![],
            skipped_steps: vec![],
            step_data: serde_json::json!({}),
            dismissed: false,
            completed_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });

    progress.current_step = body.current_step;

    state
        .onboarding_repo
        .upsert_progress(&progress)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(progress))
}

/// Mark a step as completed
#[utoipa::path(
    post,
    path = "/api/onboarding/complete-step",
    tag = "onboarding",
    request_body = StepActionRequest,
    responses(
        (status = 200, description = "Updated progress", body = OnboardingProgress),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn complete_onboarding_step(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<StepActionRequest>,
) -> Result<Json<OnboardingProgress>, ApiError> {
    let progress = state
        .onboarding_repo
        .complete_step(auth.user_id(), body.step, body.data)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(progress))
}

/// Mark a step as skipped
#[utoipa::path(
    post,
    path = "/api/onboarding/skip-step",
    tag = "onboarding",
    request_body = StepActionRequest,
    responses(
        (status = 200, description = "Updated progress", body = OnboardingProgress),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn skip_onboarding_step(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<StepActionRequest>,
) -> Result<Json<OnboardingProgress>, ApiError> {
    let progress = state
        .onboarding_repo
        .skip_step(auth.user_id(), body.step)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(progress))
}

/// Dismiss the onboarding wizard entirely
#[utoipa::path(
    post,
    path = "/api/onboarding/dismiss",
    tag = "onboarding",
    responses(
        (status = 200, description = "Wizard dismissed", body = OnboardingProgress),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn dismiss_onboarding(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<OnboardingProgress>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:view".to_string()))?;

    let progress = state
        .onboarding_repo
        .dismiss(auth.user_id())
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(progress))
}

/// Reset onboarding progress (re-run wizard)
#[utoipa::path(
    post,
    path = "/api/onboarding/reset",
    tag = "onboarding",
    responses(
        (status = 200, description = "Wizard reset", body = OnboardingProgress),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn reset_onboarding(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<OnboardingProgress>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:view".to_string()))?;

    let progress = state
        .onboarding_repo
        .reset(auth.user_id())
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(progress))
}

/// Get system configuration status for auto-detection of completed steps
#[utoipa::path(
    get,
    path = "/api/onboarding/status",
    tag = "onboarding",
    responses(
        (status = 200, description = "System config checklist", body = OnboardingStatus),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_onboarding_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<OnboardingStatus>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:view".to_string()))?;

    // Check if any AI provider is configured. AI providers live in the
    // enterprise meloD stack — open-core builds always report `false`.
    #[cfg(feature = "enterprise")]
    let has_ai_provider = {
        let melod = state.melod_service.read().await;
        melod.is_some()
    };
    #[cfg(not(feature = "enterprise"))]
    let has_ai_provider = false;

    // Helper: query a boolean status, log on failure
    let check = |pool: &sqlx::PgPool, label: &'static str, query: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(query)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| {
                    warn!(check = label, error = %e, "Onboarding status check failed");
                    false
                })
        }
    };

    let has_org_context = check(&state.pool, "org_context",
        "SELECT EXISTS(SELECT 1 FROM system_settings WHERE id = 'default' AND org_context_name IS NOT NULL AND org_context_name != '')").await;

    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "Onboarding user count check failed");
            0
        });
    let has_users = user_count > 1;

    let has_sso = check(
        &state.pool,
        "sso",
        "SELECT EXISTS(SELECT 1 FROM oidc_providers WHERE enabled = true)",
    )
    .await;

    let has_log_sources = check(
        &state.pool,
        "log_sources",
        "SELECT EXISTS(SELECT 1 FROM log_sources)",
    )
    .await;

    let has_parsers = check(
        &state.pool,
        "parsers",
        "SELECT EXISTS(SELECT 1 FROM parser_imports)",
    )
    .await;

    let has_search_history = check(
        &state.pool,
        "search_history",
        "SELECT EXISTS(SELECT 1 FROM search_history)",
    )
    .await;

    Ok(Json(OnboardingStatus {
        has_ai_provider,
        has_org_context,
        has_users,
        has_sso,
        has_log_sources,
        has_parsers,
        has_search_history,
    }))
}

// ============================================================================
// OpenAPI Doc
// ============================================================================

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_onboarding_progress,
        update_onboarding_progress,
        complete_onboarding_step,
        skip_onboarding_step,
        dismiss_onboarding,
        reset_onboarding,
        get_onboarding_status,
    ),
    components(schemas(
        OnboardingProgress,
        OnboardingStep,
        OnboardingStatus,
        UpdateProgressRequest,
        StepActionRequest,
    )),
    tags(
        (name = "onboarding", description = "Onboarding wizard progress and status"),
    )
)]
pub struct OnboardingApiDoc;

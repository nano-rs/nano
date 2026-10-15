// SPDX-License-Identifier: AGPL-3.0-or-later
//! Dedicated adapter; hosted routes are mounted by the signed enterprise port.
use super::AuditExt;
use crate::{
    error::ApiError,
    middleware::{ensure_permission, AuthContext},
    state::AppState,
};
use axum::{extract::State, Extension, Json};
use nanosiem_core::{
    audit::{AuditEvent, AuditSource, ClientContext, LOG_SOURCE_UPDATED},
    log_sources::source_labels,
    source_onboarding::{
        repository::SourceOnboardingRepository as Repo,
        service::{
            self, Action, CsvRequest, JoinedPlan, LiveSource, PreviewRow,
            SourceOnboardingService as Service,
        },
        LiveSignals, MatchCandidate,
    },
};
use uuid::Uuid;
const TENANT: Uuid = Uuid::from_u128(0x100);
fn error(e: service::Error) -> ApiError {
    match e {
        service::Error::NotFound => ApiError::NotFound("Planned source or wave not found".into()),
        service::Error::Invalid(s) => ApiError::BadRequest(s),
        service::Error::Database(e) => {
            tracing::error!(error = %e, "source onboarding storage query failed");
            ApiError::InternalError("Source onboarding storage unavailable".into())
        }
    }
}
async fn live(state: &AppState, auth: &AuthContext) -> Result<Vec<LiveSource>, ApiError> {
    let scope = auth.effective_viewer_scope();
    let mut result = vec![];
    for s in state.log_source_service.list(None).await? {
        let labels = source_labels(&s);
        if labels.iter().any(|l| scope.deny_set().contains(l)) {
            continue;
        }
        let health = super::log_sources::lake_log_source_health(state, &s, &scope).await;
        let (eps, last_event_at, status) = match health {
            Ok(h) => (
                Some(h.events_last_hour as f64 / 3600.0),
                h.last_event_at,
                if !s.enabled {
                    "paused"
                } else if s.validation_error.is_some() {
                    "error"
                } else if h
                    .last_event_at
                    .is_some_and(|t| t > chrono::Utc::now() - chrono::Duration::minutes(15))
                {
                    "healthy"
                } else {
                    "lagging"
                },
            ),
            Err(_) => (None, None, "unknown"),
        };
        result.push(LiveSource {
            source: MatchCandidate {
                id: s.id,
                name: s.name,
                source_type: labels.first().cloned().unwrap_or(s.source_type),
            },
            labels,
            signals: LiveSignals {
                eps,
                last_event_at,
                status: status.into(),
                parse_success_pct: None,
                refused24h: None,
                rules_using: 0,
            },
        });
    }
    Ok(result)
}
#[utoipa::path(get,path="/api/source-onboarding",tag="source_onboarding",responses((status=200,body=JoinedPlan),(status=403,description="Forbidden")),security(("api_key"=[])))]
pub async fn read(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<JoinedPlan>, ApiError> {
    ensure_permission(&auth, "log_sources:view")?;
    let live = live(&state, &auth).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::InternalError("Storage unavailable".into()))?;
    let plan = Repo::read(&mut tx, TENANT)
        .await
        .map_err(|e| error(e.into()))?;
    let mut rules = service::read_dedicated_rules(&mut tx)
        .await
        .map_err(|e| error(e.into()))?;
    rules.retain(|r| {
        !r.sources
            .iter()
            .any(|s| auth.effective_viewer_scope().deny_set().contains(s))
    });
    Ok(Json(Service::join(plan, live, &rules)))
}
#[utoipa::path(post,path="/api/source-onboarding/actions",tag="source_onboarding",request_body=Action,responses((status=200,description="Mutation committed"),(status=400,description="Invalid planning fields or gate"),(status=403,description="Forbidden"),(status=404,description="Not found")),security(("api_key"=[])))]
pub async fn mutate(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(action): Json<Action>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, "log_sources:edit")?;
    let live = live(&state, &auth).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::InternalError("Storage unavailable".into()))?;
    let mut rules = service::read_dedicated_rules(&mut tx)
        .await
        .map_err(|e| error(e.into()))?;
    rules.retain(|r| {
        !r.sources
            .iter()
            .any(|s| auth.effective_viewer_scope().deny_set().contains(s))
    });
    Service::apply(&mut tx, TENANT, auth.user_id(), &action, &live, &rules)
        .await
        .map_err(error)?;
    tx.commit()
        .await
        .map_err(|_| ApiError::InternalError("Storage unavailable".into()))?;
    state.emit_audit(AuditEvent::builder(AuditSource::LogSource,LOG_SOURCE_UPDATED).actor(Some(auth.user_id()),None).api_key(auth.api_key_id,auth.api_key_name.clone()).resource("source_onboarding",None,None::<String>).client_context(&client).details(serde_json::json!({"operation":serde_json::to_value(&action).ok().and_then(|v|v.get("action").cloned())})).build());
    Ok(Json(serde_json::json!({"ok":true})))
}
#[utoipa::path(post,path="/api/source-onboarding/import-preview",tag="source_onboarding",request_body=CsvRequest,responses((status=200,body=Vec<PreviewRow>),(status=400,description="Invalid CSV"),(status=403,description="Forbidden")),security(("api_key"=[])))]
pub async fn preview(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CsvRequest>,
) -> Result<Json<Vec<PreviewRow>>, ApiError> {
    ensure_permission(&auth, "log_sources:edit")?;
    let live = live(&state, &auth).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::InternalError("Storage unavailable".into()))?;
    let plan = Repo::read(&mut tx, TENANT)
        .await
        .map_err(|e| error(e.into()))?;
    Ok(Json(
        service::preview(&plan, &live, &body.csv).map_err(error)?,
    ))
}
#[utoipa::path(get,path="/api/source-onboarding/export",tag="source_onboarding",responses((status=200,body=String,content_type="text/csv"),(status=403,description="Forbidden")),security(("api_key"=[])))]
pub async fn export(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<([(axum::http::HeaderName, &'static str); 2], String), ApiError> {
    let Json(plan) = read(State(state), Extension(auth)).await?;
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=onboarding-plan.csv",
            ),
        ],
        service::export(&plan).map_err(error)?,
    ))
}
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(read, mutate, preview, export),
    components(schemas(
        Action,
        JoinedPlan,
        LiveSource,
        CsvRequest,
        PreviewRow,
        nanosiem_core::source_onboarding::PlannedSource,
        nanosiem_core::source_onboarding::Wave,
        nanosiem_core::source_onboarding::Progress,
        nanosiem_core::source_onboarding::Suggestion,
        nanosiem_core::source_onboarding::MatchCandidate,
        nanosiem_core::source_onboarding::LiveSignals,
        nanosiem_core::source_onboarding::repository::Settings,
        nanosiem_core::source_onboarding::service::PlanningFields,
        nanosiem_core::source_onboarding::service::JoinedSource,
        nanosiem_core::source_onboarding::service::RuleReference,
        nanosiem_core::source_onboarding::csv::ImportRow
    ))
)]
pub struct SourceOnboardingApiDoc;

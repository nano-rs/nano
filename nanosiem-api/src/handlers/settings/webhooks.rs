// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webhook CRUD, test, and delivery handlers

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, WEBHOOK_TESTED};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::webhooks::channels::PAGERDUTY_EVENTS_URL;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

// ============================================================================
// Handler Functions
// ============================================================================

/// List all webhooks
#[utoipa::path(
    get,
    path = "/api/settings/webhooks",
    tag = "settings",
    responses(
        (status = 200, description = "List of webhooks", body = Vec<nanosiem_core::webhooks::WebhookResponse>),
        (status = 403, description = "Missing permission", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_webhooks(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<nanosiem_core::webhooks::WebhookResponse>>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_WEBHOOKS)?;

    let repo = nanosiem_core::webhooks::WebhookRepository::new(state.pool.clone());
    let webhooks = repo
        .list()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    let responses: Vec<nanosiem_core::webhooks::WebhookResponse> = webhooks
        .iter()
        .map(nanosiem_core::webhooks::WebhookResponse::from)
        .collect();

    Ok(Json(responses))
}

/// Create a new webhook
#[utoipa::path(
    post,
    path = "/api/settings/webhooks",
    tag = "settings",
    request_body = nanosiem_core::webhooks::CreateWebhookRequest,
    responses(
        (status = 200, description = "Webhook created", body = nanosiem_core::webhooks::WebhookResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(mut request): Json<nanosiem_core::webhooks::CreateWebhookRequest>,
) -> Result<Json<nanosiem_core::webhooks::WebhookResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_WEBHOOKS)?;

    request.validate_channel().map_err(ApiError::BadRequest)?;
    normalize_pagerduty_create(&mut request)?;

    request
        .validate_event_types()
        .map_err(ApiError::BadRequest)?;

    nanosiem_core::webhooks::WebhookService::validate_url(&request.url)
        .await
        .map_err(|e| ApiError::BadRequest(e))?;

    let repo = nanosiem_core::webhooks::WebhookRepository::new(state.pool.clone());
    let webhook = repo
        .create(&request)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    state.emit_audit(
        nanosiem_core::audit::AuditEvent::builder(
            nanosiem_core::audit::AuditSource::Webhook,
            nanosiem_core::audit::WEBHOOK_CREATED,
        )
        .actor(Some(auth.user_id()), None)
        .api_key(auth.api_key_id, auth.api_key_name.clone())
        .resource("webhook", Some(webhook.id), Some(webhook.name.clone()))
        .build(),
    );

    Ok(Json(nanosiem_core::webhooks::WebhookResponse::from(
        &webhook,
    )))
}

/// Get a webhook by ID
#[utoipa::path(
    get,
    path = "/api/settings/webhooks/{id}",
    tag = "settings",
    params(("id" = String, Path, description = "Webhook ID")),
    responses(
        (status = 200, description = "Webhook details", body = nanosiem_core::webhooks::WebhookResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Webhook not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<nanosiem_core::webhooks::WebhookResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_WEBHOOKS)?;

    let repo = nanosiem_core::webhooks::WebhookRepository::new(state.pool.clone());
    let webhook = repo.get(*id).await.map_err(|e| match e {
        nanosiem_core::webhooks::WebhookRepositoryError::NotFound(_) => {
            ApiError::NotFound(format!("Webhook {} not found", *id))
        }
        _ => ApiError::InternalError(e.to_string()),
    })?;

    Ok(Json(nanosiem_core::webhooks::WebhookResponse::from(
        &webhook,
    )))
}

/// Update a webhook
#[utoipa::path(
    put,
    path = "/api/settings/webhooks/{id}",
    tag = "settings",
    params(("id" = String, Path, description = "Webhook ID")),
    request_body = nanosiem_core::webhooks::UpdateWebhookRequest,
    responses(
        (status = 200, description = "Webhook updated", body = nanosiem_core::webhooks::WebhookResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Webhook not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(mut request): Json<nanosiem_core::webhooks::UpdateWebhookRequest>,
) -> Result<Json<nanosiem_core::webhooks::WebhookResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_WEBHOOKS)?;

    request.validate_channel().map_err(ApiError::BadRequest)?;

    let repo = nanosiem_core::webhooks::WebhookRepository::new(state.pool.clone());

    // A channel's TYPE is immutable. The stored secret is type-specific: for a
    // generic channel it is an HMAC signing key, for PagerDuty it is an Events
    // API routing key. Re-typing a channel in place would reinterpret the
    // EXISTING secret under the new type's semantics — generic → pagerduty would
    // ship the HMAC secret to PagerDuty as a routing key (leaking it to a third
    // party), and pagerduty → generic would HMAC-sign with the routing key.
    // Reject the transition; create a new channel instead.
    let existing = repo.get(*id).await.map_err(|e| match e {
        nanosiem_core::webhooks::WebhookRepositoryError::NotFound(_) => {
            ApiError::NotFound(format!("Webhook {} not found", *id))
        }
        _ => ApiError::InternalError(e.to_string()),
    })?;
    if let Some(requested) = request.channel_type.as_deref() {
        let current = match existing.channel_type.trim() {
            "" => "generic", // legacy row / column default
            t => t,
        };
        if requested != current {
            return Err(ApiError::BadRequest(format!(
                "channel_type is immutable ('{current}' → '{requested}'); create a new channel instead"
            )));
        }
    }

    // PagerDuty's Events endpoint is pinned server-side.
    if request.channel_type.as_deref() == Some("pagerduty") {
        request.url = Some(PAGERDUTY_EVENTS_URL.to_string());
    }

    if let Some(ref url) = request.url {
        nanosiem_core::webhooks::WebhookService::validate_url(url)
            .await
            .map_err(|e| ApiError::BadRequest(e))?;
    }

    request
        .validate_event_types()
        .map_err(ApiError::BadRequest)?;

    let webhook = repo.update(*id, &request).await.map_err(|e| match e {
        nanosiem_core::webhooks::WebhookRepositoryError::NotFound(_) => {
            ApiError::NotFound(format!("Webhook {} not found", *id))
        }
        _ => ApiError::InternalError(e.to_string()),
    })?;

    state.emit_audit(
        nanosiem_core::audit::AuditEvent::builder(
            nanosiem_core::audit::AuditSource::Webhook,
            nanosiem_core::audit::WEBHOOK_UPDATED,
        )
        .actor(Some(auth.user_id()), None)
        .api_key(auth.api_key_id, auth.api_key_name.clone())
        .resource("webhook", Some(webhook.id), Some(webhook.name.clone()))
        .build(),
    );

    Ok(Json(nanosiem_core::webhooks::WebhookResponse::from(
        &webhook,
    )))
}

/// Delete a webhook
#[utoipa::path(
    delete,
    path = "/api/settings/webhooks/{id}",
    tag = "settings",
    params(("id" = String, Path, description = "Webhook ID")),
    responses(
        (status = 200, description = "Webhook deleted"),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Webhook not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_WEBHOOKS)?;

    // Get name for audit before deleting
    let repo = nanosiem_core::webhooks::WebhookRepository::new(state.pool.clone());
    let webhook_name = repo.get(*id).await.ok().map(|w| w.name);

    repo.delete(*id).await.map_err(|e| match e {
        nanosiem_core::webhooks::WebhookRepositoryError::NotFound(_) => {
            ApiError::NotFound(format!("Webhook {} not found", *id))
        }
        _ => ApiError::InternalError(e.to_string()),
    })?;

    state.emit_audit(
        nanosiem_core::audit::AuditEvent::builder(
            nanosiem_core::audit::AuditSource::Webhook,
            nanosiem_core::audit::WEBHOOK_DELETED,
        )
        .actor(Some(auth.user_id()), None)
        .api_key(auth.api_key_id, auth.api_key_name.clone())
        .resource("webhook", Some(*id), webhook_name)
        .build(),
    );

    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// Send a test delivery to a webhook
#[utoipa::path(
    post,
    path = "/api/settings/webhooks/{id}/test",
    tag = "settings",
    params(("id" = String, Path, description = "Webhook ID")),
    responses(
        (status = 200, description = "Test result", body = nanosiem_core::webhooks::WebhookTestResult),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Webhook not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn test_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<nanosiem_core::webhooks::WebhookTestResult>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_WEBHOOKS)?;

    let repo = nanosiem_core::webhooks::WebhookRepository::new(state.pool.clone());
    let svc = nanosiem_core::webhooks::WebhookService::new(repo);

    let result = svc
        .send_test(*id)
        .await
        .map_err(|e| ApiError::InternalError(e))?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, WEBHOOK_TESTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("webhook", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(result))
}

/// List recent deliveries for a webhook
#[utoipa::path(
    get,
    path = "/api/settings/webhooks/{id}/deliveries",
    tag = "settings",
    params(
        ("id" = String, Path, description = "Webhook ID"),
        ("limit" = Option<i64>, Query, description = "Max deliveries to return (default 50)"),
    ),
    responses(
        (status = 200, description = "Delivery log entries", body = Vec<nanosiem_core::webhooks::WebhookDeliveryLog>),
        (status = 403, description = "Missing permission", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_webhook_deliveries(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    axum::extract::Query(params): axum::extract::Query<WebhookDeliveryParams>,
) -> Result<Json<Vec<nanosiem_core::webhooks::WebhookDeliveryLog>>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_WEBHOOKS)?;

    let repo = nanosiem_core::webhooks::WebhookRepository::new(state.pool.clone());
    let limit = params.limit.unwrap_or(50).max(1).min(200);
    let logs = repo
        .list_deliveries(*id, limit)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(logs))
}

/// Query params for webhook delivery listing
#[derive(Debug, Deserialize)]
pub struct WebhookDeliveryParams {
    pub limit: Option<i64>,
}

/// PagerDuty's Events API endpoint is fixed; the operator supplies only the
/// routing key (stored as the channel secret). Pin the URL server-side at
/// create and require the routing key so the channel can actually deliver.
fn normalize_pagerduty_create(
    request: &mut nanosiem_core::webhooks::CreateWebhookRequest,
) -> Result<(), ApiError> {
    if request.channel_type.as_deref() == Some("pagerduty") {
        request.url = PAGERDUTY_EVENTS_URL.to_string();
        let has_key = request
            .secret
            .as_deref()
            .map(str::trim)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !has_key {
            return Err(ApiError::BadRequest(
                "PagerDuty channel requires an Events API v2 routing key".to_string(),
            ));
        }
    }
    Ok(())
}

// ============================================================================
// Notification config (deep-link base URL) — NAN-1790
// ============================================================================

/// Notification deep-link base URL configuration.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NotificationConfigResponse {
    /// The admin-configured base URL, or null when unset (env fallback in use).
    pub base_url: Option<String>,
    /// The base URL actually used for deep links (configured value, else the
    /// `NANOSIEM_HOSTNAME` env var, else null → links omitted).
    pub resolved_base_url: Option<String>,
}

/// Update the notification deep-link base URL. `null`/empty clears it (falls
/// back to `NANOSIEM_HOSTNAME`).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateNotificationConfigRequest {
    pub base_url: Option<String>,
}

/// Get the notification deep-link base URL config.
#[utoipa::path(
    get,
    path = "/api/settings/notifications/config",
    tag = "settings",
    responses(
        (status = 200, description = "Notification config", body = NotificationConfigResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_notification_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<NotificationConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_WEBHOOKS)?;

    let repo = nanosiem_core::webhooks::WebhookRepository::new(state.pool.clone());
    let base_url = repo
        .notification_base_url()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    let svc = nanosiem_core::webhooks::WebhookService::new(repo);
    let resolved_base_url = svc.resolve_base_url().await;

    Ok(Json(NotificationConfigResponse {
        base_url,
        resolved_base_url,
    }))
}

/// Set the notification deep-link base URL config.
#[utoipa::path(
    put,
    path = "/api/settings/notifications/config",
    tag = "settings",
    request_body = UpdateNotificationConfigRequest,
    responses(
        (status = 200, description = "Updated notification config", body = NotificationConfigResponse),
        (status = 400, description = "Invalid base URL", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_notification_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<UpdateNotificationConfigRequest>,
) -> Result<Json<NotificationConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_WEBHOOKS)?;

    // Validate a non-empty base URL is a well-formed http(s) origin before
    // storing it (a malformed value would silently break every deep link).
    if let Some(raw) = request.base_url.as_deref() {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let url = reqwest::Url::parse(trimmed)
                .map_err(|_| ApiError::BadRequest("base_url must be a valid URL".to_string()))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ApiError::BadRequest(
                    "base_url must use http or https".to_string(),
                ));
            }
        }
    }

    let repo = nanosiem_core::webhooks::WebhookRepository::new(state.pool.clone());
    repo.set_notification_base_url(request.base_url.as_deref())
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, nanosiem_core::audit::WEBHOOK_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("notification_config", None, Some("base_url".to_string()))
            .build(),
    );

    let base_url = repo
        .notification_base_url()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    let svc = nanosiem_core::webhooks::WebhookService::new(repo);
    let resolved_base_url = svc.resolve_base_url().await;

    Ok(Json(NotificationConfigResponse {
        base_url,
        resolved_base_url,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::typeid;
    use std::str::FromStr;
    use uuid::Uuid;

    /// Regression: webhook IDs returned by the API are `whook_<base32>`.
    /// The path extractor must accept that exact form so callers can reuse
    /// the create/list response ID against detail/test/delete/deliveries.
    #[test]
    fn typeid_param_accepts_webhook_prefixed_id() {
        let id = Uuid::now_v7();
        let encoded = typeid::encode(typeid::webhook::PREFIX, &id);
        assert!(encoded.starts_with("whook_"));

        let extracted = TypeIdParam::from_str(&encoded).expect("whook_ id should parse");
        assert_eq!(*extracted, id);
    }

    /// Backwards-compat: bare UUIDs still work for any internal callers.
    #[test]
    fn typeid_param_still_accepts_bare_uuid() {
        let id = Uuid::now_v7();
        let extracted = TypeIdParam::from_str(&id.to_string()).expect("bare uuid should parse");
        assert_eq!(*extracted, id);
    }
}

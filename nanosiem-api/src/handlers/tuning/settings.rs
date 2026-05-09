// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, SETTINGS_UPDATED};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;

use super::types::TuningSettings;
use crate::error::ApiError;
use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

/// GET /api/tuning/settings/:rule_id
///
/// Get tuning settings for a detection rule.
///
/// Requirements: 12.1
#[utoipa::path(
    get,
    path = "/api/tuning/settings/{rule_id}",
    tag = "tuning",
    params(
        ("rule_id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Settings retrieved", body = TuningSettings),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 404, description = "Rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn get_tuning_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<TypeIdParam>,
) -> Result<Json<TuningSettings>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    // Get tuning settings from detection_rules table
    let settings: Option<(bool, f64, bool, Option<chrono::DateTime<chrono::Utc>>, bool)> =
        sqlx::query_as(
            r#"
        SELECT
            COALESCE(auto_tuning_enabled, true) as auto_tuning_enabled,
            COALESCE(auto_tuning_min_confidence, 0.8) as auto_tuning_min_confidence,
            COALESCE(auto_tuning_critical, false) as auto_tuning_critical,
            auto_tuning_disabled_until,
            COALESCE(auto_apply_enabled, false) as auto_apply_enabled
        FROM detection_rules
        WHERE id = $1
        "#,
        )
        .bind(*rule_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to fetch tuning settings: {}", e)))?;

    if let Some((enabled, min_confidence, critical, disabled_until, auto_apply)) = settings {
        Ok(Json(TuningSettings {
            auto_tuning_enabled: enabled,
            auto_tuning_min_confidence: min_confidence,
            auto_tuning_critical: critical,
            auto_tuning_disabled_until: disabled_until,
            auto_apply_enabled: auto_apply,
        }))
    } else {
        Err(ApiError::NotFound("Rule not found".to_string()))
    }
}

/// PUT /api/tuning/settings/:rule_id
///
/// Update tuning settings for a detection rule.
///
/// Requirements: 12.1
#[utoipa::path(
    put,
    path = "/api/tuning/settings/{rule_id}",
    tag = "tuning",
    params(
        ("rule_id" = String, Path, description = "Detection rule ID")
    ),
    request_body = TuningSettings,
    responses(
        (status = 200, description = "Settings updated", body = TuningSettings),
        (status = 400, description = "Invalid confidence threshold"),
        (status = 403, description = "Missing permission: detections:edit"),
        (status = 404, description = "Rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn update_tuning_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path(rule_id): Path<TypeIdParam>,
    Json(settings): Json<TuningSettings>,
) -> Result<Json<TuningSettings>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:edit".to_string()))?;

    // Validate confidence threshold
    if settings.auto_tuning_min_confidence < 0.0 || settings.auto_tuning_min_confidence > 1.0 {
        return Err(ApiError::BadRequest(
            "Confidence threshold must be between 0.0 and 1.0".to_string(),
        ));
    }

    // 1. Fetch current state so we can field-gate weakening transitions, and
    // fold the existence check into the same query.
    let existing: Option<(bool, bool, Option<DateTime<Utc>>, bool)> = sqlx::query_as(
        r#"
        SELECT
            COALESCE(auto_tuning_enabled, true) as auto_tuning_enabled,
            COALESCE(auto_tuning_critical, false) as auto_tuning_critical,
            auto_tuning_disabled_until,
            COALESCE(auto_apply_enabled, false) as auto_apply_enabled
        FROM detection_rules
        WHERE id = $1
        "#,
    )
    .bind(*rule_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(format!("Failed to fetch tuning settings: {}", e)))?;

    let (old_enabled, old_critical, old_disabled_until, old_auto_apply) = match existing {
        Some(row) => row,
        None => return Err(ApiError::NotFound("Rule not found".to_string())),
    };

    // Weakening tuning guardrails (disabling auto-tuning, removing the critical
    // flag, enabling auto-apply, or extending the disabled window) is a
    // promote-class change and must require detections:promote.
    if requires_promote_for_tuning(
        old_enabled,
        old_critical,
        old_disabled_until,
        old_auto_apply,
        &settings,
    ) && !auth.has_permission(permissions::DETECTIONS_PROMOTE)
    {
        return Err(ApiError::Forbidden(
            "Missing permission: detections:promote".to_string(),
        ));
    }

    // 2. Update tuning settings
    sqlx::query(
        r#"
        UPDATE detection_rules
        SET
            auto_tuning_enabled = $1,
            auto_tuning_min_confidence = $2,
            auto_tuning_critical = $3,
            auto_tuning_disabled_until = $4,
            auto_apply_enabled = $5,
            updated_at = NOW()
        WHERE id = $6
        "#,
    )
    .bind(settings.auto_tuning_enabled)
    .bind(settings.auto_tuning_min_confidence)
    .bind(settings.auto_tuning_critical)
    .bind(settings.auto_tuning_disabled_until)
    .bind(settings.auto_apply_enabled)
    .bind(*rule_id)
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(format!("Failed to update tuning settings: {}", e)))?;

    // 3. Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Tuning, SETTINGS_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*rule_id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "auto_tuning_enabled": settings.auto_tuning_enabled,
                "auto_tuning_min_confidence": settings.auto_tuning_min_confidence,
                "auto_tuning_critical": settings.auto_tuning_critical,
                "auto_apply_enabled": settings.auto_apply_enabled,
            }))
            .build(),
    );

    Ok(Json(settings))
}

/// Returns true when the requested settings would weaken tuning guardrails in
/// a way that the lifecycle endpoints would gate on `detections:promote`.
fn requires_promote_for_tuning(
    old_enabled: bool,
    old_critical: bool,
    old_disabled_until: Option<DateTime<Utc>>,
    old_auto_apply: bool,
    new: &TuningSettings,
) -> bool {
    if old_enabled && !new.auto_tuning_enabled {
        return true;
    }
    if old_critical && !new.auto_tuning_critical {
        return true;
    }
    if !old_auto_apply && new.auto_apply_enabled {
        return true;
    }
    let now = Utc::now();
    match (old_disabled_until, new.auto_tuning_disabled_until) {
        (_, Some(new_until)) if new_until > now => match old_disabled_until {
            Some(old_until) if new_until <= old_until => false,
            _ => true,
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn baseline_settings() -> TuningSettings {
        TuningSettings {
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: true,
            auto_tuning_disabled_until: None,
            auto_apply_enabled: false,
        }
    }

    #[test]
    fn raising_min_confidence_does_not_require_promote() {
        let new = TuningSettings {
            auto_tuning_min_confidence: 0.95,
            ..baseline_settings()
        };
        assert!(!requires_promote_for_tuning(true, true, None, false, &new));
    }

    #[test]
    fn disabling_auto_tuning_requires_promote() {
        let new = TuningSettings {
            auto_tuning_enabled: false,
            ..baseline_settings()
        };
        assert!(requires_promote_for_tuning(true, true, None, false, &new));
    }

    #[test]
    fn enabling_auto_tuning_does_not_require_promote() {
        let new = baseline_settings();
        assert!(!requires_promote_for_tuning(false, true, None, false, &new));
    }

    #[test]
    fn clearing_critical_requires_promote() {
        let new = TuningSettings {
            auto_tuning_critical: false,
            ..baseline_settings()
        };
        assert!(requires_promote_for_tuning(true, true, None, false, &new));
    }

    #[test]
    fn enabling_auto_apply_requires_promote() {
        let new = TuningSettings {
            auto_apply_enabled: true,
            ..baseline_settings()
        };
        assert!(requires_promote_for_tuning(true, true, None, false, &new));
    }

    #[test]
    fn disabling_auto_apply_does_not_require_promote() {
        let new = TuningSettings {
            auto_apply_enabled: false,
            ..baseline_settings()
        };
        assert!(!requires_promote_for_tuning(true, true, None, true, &new));
    }

    #[test]
    fn extending_disabled_window_requires_promote() {
        let new = TuningSettings {
            auto_tuning_disabled_until: Some(Utc::now() + Duration::days(30)),
            ..baseline_settings()
        };
        assert!(requires_promote_for_tuning(true, true, None, false, &new));
    }

    #[test]
    fn shortening_disabled_window_does_not_require_promote() {
        let old_until = Utc::now() + Duration::days(30);
        let new = TuningSettings {
            auto_tuning_disabled_until: Some(Utc::now() + Duration::days(7)),
            ..baseline_settings()
        };
        assert!(!requires_promote_for_tuning(
            true,
            true,
            Some(old_until),
            false,
            &new,
        ));
    }

    #[test]
    fn clearing_disabled_window_does_not_require_promote() {
        let old_until = Utc::now() + Duration::days(30);
        let new = TuningSettings {
            auto_tuning_disabled_until: None,
            ..baseline_settings()
        };
        assert!(!requires_promote_for_tuning(
            true,
            true,
            Some(old_until),
            false,
            &new,
        ));
    }

    #[test]
    fn past_disabled_until_does_not_require_promote() {
        let new = TuningSettings {
            auto_tuning_disabled_until: Some(Utc::now() - Duration::days(1)),
            ..baseline_settings()
        };
        assert!(!requires_promote_for_tuning(true, true, None, false, &new));
    }
}

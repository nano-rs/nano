// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dashboard export/import handlers and validation

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use chrono::Utc;
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, DASHBOARD_EXPORTED, DASHBOARD_IMPORTED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{Dashboard, DashboardRepository, NewDashboard};

use super::types::{
    DashboardExport, DashboardExportData, ImportDashboardRequest, MAX_DESCRIPTION_LENGTH,
    MAX_IMPORT_PAYLOAD_SIZE, MAX_NAME_LENGTH, MAX_PANELS, MAX_PANEL_TITLE_LENGTH, MAX_QUERY_LENGTH,
    VALID_QUERY_MODES, VALID_VIZ_TYPES,
};
use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Export a dashboard as JSON
#[utoipa::path(
    post,
    path = "/api/dashboards/export/{id}",
    tag = "dashboards",
    params(
        ("id" = String, Path, description = "Dashboard ID")
    ),
    responses(
        (status = 200, description = "Dashboard exported successfully", body = DashboardExport),
        (status = 403, description = "Forbidden - access denied or missing dashboards:view permission"),
        (status = 404, description = "Dashboard not found"),
    ),
    security(("api_key" = []))
)]
pub async fn export_dashboard(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DashboardExport>, ApiError> {
    ensure_permission(&auth, permissions::DASHBOARDS_VIEW)?;

    let repo = DashboardRepository::new(state.pool.clone());
    // Use find_by_id_for_user to ensure user can only export dashboards they have access to
    let dashboard = repo.find_by_id_for_user(*id, auth.user_id()).await?;

    let export = DashboardExport {
        version: "1.0".to_string(),
        exported_at: Utc::now(),
        dashboard: DashboardExportData {
            name: dashboard.name.clone(),
            description: dashboard.description,
            layout: dashboard.layout,
            panels: dashboard.panels,
            refresh_interval: dashboard.refresh_interval,
        },
    };

    state.emit_audit(
        AuditEvent::builder(AuditSource::Dashboard, DASHBOARD_EXPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("dashboard", Some(*id), Some(dashboard.name))
            .client_context(&client)
            .build(),
    );

    Ok(Json(export))
}

/// Import a dashboard from JSON
#[utoipa::path(
    post,
    path = "/api/dashboards/import",
    tag = "dashboards",
    request_body = ImportDashboardRequest,
    responses(
        (status = 200, description = "Dashboard imported successfully", body = Dashboard),
        (status = 400, description = "Validation error - invalid JSON or dashboard structure"),
        (status = 403, description = "Forbidden - missing dashboards:create permission"),
    ),
    security(("api_key" = []))
)]
pub async fn import_dashboard(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<ImportDashboardRequest>,
) -> Result<Json<Dashboard>, ApiError> {
    ensure_permission(&auth, permissions::DASHBOARDS_CREATE)?;

    // Check payload size before parsing
    if request.json.len() > MAX_IMPORT_PAYLOAD_SIZE {
        return Err(ApiError::ValidationError(format!(
            "Import payload too large: {} bytes (max {} bytes)",
            request.json.len(),
            MAX_IMPORT_PAYLOAD_SIZE
        )));
    }

    // Parse the JSON
    let export: DashboardExport = serde_json::from_str(&request.json).map_err(|e| {
        tracing::debug!(error = %e, "Dashboard import JSON parse failure");
        ApiError::ValidationError("Invalid dashboard JSON".to_string())
    })?;

    // Validate the export structure
    validate_dashboard_export(&export)?;

    let repo = DashboardRepository::new(state.pool.clone());

    // Create the dashboard from the export - imported dashboards are private by default
    let new_dashboard = NewDashboard {
        name: export.dashboard.name,
        description: export.dashboard.description,
        layout: export.dashboard.layout,
        panels: export.dashboard.panels,
        refresh_interval: export.dashboard.refresh_interval,
        owner_id: Some(auth.user_id()),
        visibility: "private".to_string(),
    };

    let dashboard = repo.create(&new_dashboard).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Dashboard, DASHBOARD_IMPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "dashboard",
                Some(dashboard.id),
                Some(dashboard.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    // DSH17: mirror `create_dashboard` — register the imported dashboard for
    // demo-session cleanup / isolation. Without this, a demo user's imported
    // dashboards outlive the session and are invisible to the exclude-list.
    state.track_demo_resource(
        auth.user_id(),
        nanosiem_core::demo::DemoResourceType::Dashboard,
        dashboard.id,
    );

    Ok(Json(dashboard))
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validate a dashboard export structure
fn validate_dashboard_export(export: &DashboardExport) -> Result<(), ApiError> {
    // DSH44: reject a MAJOR-version mismatch so a newer export doesn't import as
    // the current schema with dropped/renamed fields (and `deny_unknown_fields`
    // on the export structs catches structural additions within the major).
    // Previously any non-empty string was accepted.
    const SUPPORTED_MAJOR_VERSION: u32 = 1;
    match export
        .version
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
    {
        Some(SUPPORTED_MAJOR_VERSION) => {}
        Some(_) => {
            return Err(ApiError::ValidationError(format!(
                "Unsupported export version '{}': this deployment imports version {}.x dashboards",
                export.version, SUPPORTED_MAJOR_VERSION
            )));
        }
        None => {
            return Err(ApiError::ValidationError(format!(
                "Invalid export version '{}'",
                export.version
            )));
        }
    }

    // Name + panels + layout share the create/update validators (DSH14).
    validate_dashboard_name(&export.dashboard.name)?;

    // Check description length
    if let Some(ref desc) = export.dashboard.description {
        if desc.len() > MAX_DESCRIPTION_LENGTH {
            return Err(ApiError::ValidationError(format!(
                "Dashboard description too long: {} chars (max {})",
                desc.len(),
                MAX_DESCRIPTION_LENGTH
            )));
        }
    }

    validate_layout(&export.dashboard.layout)?;
    validate_panels(&export.dashboard.panels)?;

    Ok(())
}

/// Validate a dashboard name (non-empty after trim, within `MAX_NAME_LENGTH`).
///
/// DSH14: shared by create / update / import so all three enforce the same
/// limits and the product's own export round-trips.
pub(super) fn validate_dashboard_name(name: &str) -> Result<(), ApiError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ApiError::ValidationError(
            "Dashboard name cannot be empty".to_string(),
        ));
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err(ApiError::ValidationError(format!(
            "Dashboard name too long: {} chars (max {})",
            name.len(),
            MAX_NAME_LENGTH
        )));
    }
    Ok(())
}

/// Validate the dashboard layout structurally (DSH14/DSH16).
///
/// The layout must be an object with an `items` array of `{i,x,y,w,h}` objects,
/// and `variables` (if present) must be an array — exactly what `DashboardView`
/// iterates/positions on. A malformed layout that passed the old
/// `is_object()`-only check (e.g. `{}` or `variables: {}`) crashed the page at
/// render time.
pub(super) fn validate_layout(layout: &serde_json::Value) -> Result<(), ApiError> {
    let obj = layout.as_object().ok_or_else(|| {
        ApiError::ValidationError("Dashboard layout must be an object".to_string())
    })?;

    let items = obj
        .get("items")
        .ok_or_else(|| {
            ApiError::ValidationError("Dashboard layout is missing 'items'".to_string())
        })?
        .as_array()
        .ok_or_else(|| {
            ApiError::ValidationError("Dashboard layout.items must be an array".to_string())
        })?;

    for (i, item) in items.iter().enumerate() {
        let item = item.as_object().ok_or_else(|| {
            ApiError::ValidationError(format!("Layout item {} must be an object", i))
        })?;
        for key in ["i", "x", "y", "w", "h"] {
            if !item.contains_key(key) {
                return Err(ApiError::ValidationError(format!(
                    "Layout item {} is missing '{}'",
                    i, key
                )));
            }
        }
    }

    if let Some(vars) = obj.get("variables") {
        if !vars.is_array() {
            return Err(ApiError::ValidationError(
                "Dashboard layout.variables must be an array".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate the dashboard panels array (DSH14/DSH43): array shape, count cap,
/// per-panel structure, and unique panel ids.
pub(super) fn validate_panels(panels: &serde_json::Value) -> Result<(), ApiError> {
    let panels = panels.as_array().ok_or_else(|| {
        ApiError::ValidationError("Dashboard panels must be an array".to_string())
    })?;

    // Check panel count
    if panels.len() > MAX_PANELS {
        return Err(ApiError::ValidationError(format!(
            "Too many panels: {} (max {})",
            panels.len(),
            MAX_PANELS
        )));
    }

    // DSH43: panel ids must be unique. `GridLayout` keys panels by id (last
    // wins) and `DashboardView` keys fetch state by id, so duplicates drop
    // panels / render the wrong panel in multiple slots.
    let mut seen_ids = std::collections::HashSet::new();
    for (i, panel) in panels.iter().enumerate() {
        let id = validate_panel(panel, i)?;
        if !seen_ids.insert(id.clone()) {
            return Err(ApiError::ValidationError(format!(
                "Duplicate panel id '{}'",
                id
            )));
        }
    }

    Ok(())
}

/// Validate an individual panel structure, returning its id (for the caller's
/// uniqueness check).
fn validate_panel(panel: &serde_json::Value, index: usize) -> Result<String, ApiError> {
    let obj = panel
        .as_object()
        .ok_or_else(|| ApiError::ValidationError(format!("Panel {} must be an object", index)))?;

    // Check required fields exist
    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::ValidationError(format!("Panel {} missing 'id' field", index)))?;

    if id.is_empty() {
        return Err(ApiError::ValidationError(format!(
            "Panel {} has empty 'id'",
            index
        )));
    }

    // Validate title if present
    if let Some(title) = obj.get("title").and_then(|v| v.as_str()) {
        if title.len() > MAX_PANEL_TITLE_LENGTH {
            return Err(ApiError::ValidationError(format!(
                "Panel {} title too long: {} chars (max {})",
                index,
                title.len(),
                MAX_PANEL_TITLE_LENGTH
            )));
        }
    }

    // Validate query if present
    if let Some(query) = obj.get("query").and_then(|v| v.as_str()) {
        if query.len() > MAX_QUERY_LENGTH {
            return Err(ApiError::ValidationError(format!(
                "Panel {} query too long: {} chars (max {})",
                index,
                query.len(),
                MAX_QUERY_LENGTH
            )));
        }
    }

    // DSH15: real panels are camelCase (`queryMode`/`visualizationType`). The
    // previous snake_case lookups (`query_mode`/`visualization_type`) never
    // matched any app-produced panel, so the whitelist was a dead no-op.
    if let Some(mode) = obj.get("queryMode").and_then(|v| v.as_str()) {
        if !VALID_QUERY_MODES.contains(&mode) {
            return Err(ApiError::ValidationError(format!(
                "Panel {} has invalid query_mode '{}'. Valid modes: {:?}",
                index, mode, VALID_QUERY_MODES
            )));
        }
    }

    if let Some(viz_type) = obj.get("visualizationType").and_then(|v| v.as_str()) {
        if !VALID_VIZ_TYPES.contains(&viz_type) {
            return Err(ApiError::ValidationError(format!(
                "Panel {} has invalid visualization_type '{}'. Valid types: {:?}",
                index, viz_type, VALID_VIZ_TYPES
            )));
        }
    }

    Ok(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::types::*;
    use super::*;

    fn make_valid_export(name: &str, panels: Vec<serde_json::Value>) -> DashboardExport {
        DashboardExport {
            version: "1.0".to_string(),
            exported_at: Utc::now(),
            dashboard: DashboardExportData {
                name: name.to_string(),
                description: None,
                // DSH16: layout must carry an `items` array.
                layout: serde_json::json!({ "items": [] }),
                panels: serde_json::Value::Array(panels),
                refresh_interval: None,
            },
        }
    }

    fn make_valid_panel(id: &str) -> serde_json::Value {
        // DSH15: panels the app produces are camelCase.
        serde_json::json!({
            "id": id,
            "title": "Test Panel",
            "query": "* | stats count()",
            "queryMode": "piped",
            "visualizationType": "bar"
        })
    }

    #[test]
    fn test_validate_export_valid() {
        let export = make_valid_export("Test Dashboard", vec![make_valid_panel("panel-1")]);
        assert!(validate_dashboard_export(&export).is_ok());
    }

    #[test]
    fn test_validate_export_empty_name() {
        let export = make_valid_export("", vec![make_valid_panel("panel-1")]);
        let result = validate_dashboard_export(&export);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("name cannot be empty"));
    }

    #[test]
    fn test_validate_export_name_too_long() {
        let long_name = "a".repeat(MAX_NAME_LENGTH + 1);
        let export = make_valid_export(&long_name, vec![make_valid_panel("panel-1")]);
        let result = validate_dashboard_export(&export);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("name too long"));
    }

    #[test]
    fn test_validate_export_description_too_long() {
        let mut export = make_valid_export("Test", vec![make_valid_panel("panel-1")]);
        export.dashboard.description = Some("a".repeat(MAX_DESCRIPTION_LENGTH + 1));
        let result = validate_dashboard_export(&export);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("description too long"));
    }

    #[test]
    fn test_validate_export_too_many_panels() {
        let panels: Vec<_> = (0..MAX_PANELS + 1)
            .map(|i| make_valid_panel(&format!("panel-{}", i)))
            .collect();
        let export = make_valid_export("Test", panels);
        let result = validate_dashboard_export(&export);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many panels"));
    }

    #[test]
    fn test_validate_panel_missing_id() {
        let panel = serde_json::json!({ "title": "No ID" });
        let result = validate_panel(&panel, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing 'id'"));
    }

    #[test]
    fn test_validate_panel_invalid_viz_type() {
        let panel = serde_json::json!({
            "id": "panel-1",
            "visualizationType": "invalid_type"
        });
        let result = validate_panel(&panel, 0);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid visualization_type"));
    }

    #[test]
    fn test_validate_panel_invalid_query_mode() {
        let panel = serde_json::json!({
            "id": "panel-1",
            "queryMode": "graphql"
        });
        let result = validate_panel(&panel, 0);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid query_mode"));
    }

    #[test]
    fn test_validate_panel_query_too_long() {
        let panel = serde_json::json!({
            "id": "panel-1",
            "query": "a".repeat(MAX_QUERY_LENGTH + 1)
        });
        let result = validate_panel(&panel, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("query too long"));
    }
}

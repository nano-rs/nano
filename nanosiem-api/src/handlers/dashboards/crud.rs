// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dashboard CRUD handlers: list, get, create, update, share, delete

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, DASHBOARD_CREATED, DASHBOARD_DELETED, DASHBOARD_SHARED,
    DASHBOARD_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{
    Dashboard, DashboardRepository, DashboardShareResult, DashboardWithContext, NewDashboard,
    ShareDashboardRequest, UpdateDashboard,
};

use super::types::{
    CreateDashboardRequest, DashboardSummary, ListDashboardsQuery, UpdateDashboardRequest,
};
use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// List dashboards
///
/// Query params:
/// - filter: "my" (default) for user's own dashboards, "all" for all accessible dashboards
#[utoipa::path(
    get,
    path = "/api/dashboards",
    tag = "dashboards",
    params(ListDashboardsQuery),
    responses(
        (status = 200, description = "List of dashboards", body = Vec<DashboardSummary>),
        (status = 403, description = "Forbidden - missing dashboards:view permission"),
    ),
    security(("api_key" = []))
)]
pub async fn list_dashboards(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListDashboardsQuery>,
) -> Result<Json<Vec<DashboardSummary>>, ApiError> {
    check_permission(&auth, permissions::DASHBOARDS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: dashboards:view".to_string()))?;

    let repo = DashboardRepository::new(state.pool.clone());

    let dashboards = match query.filter.as_str() {
        "all" => repo.list_for_user(auth.user_id()).await?,
        _ => repo.list_owned_by_user(auth.user_id()).await?, // "my" or default
    };

    let mut summaries: Vec<DashboardSummary> =
        dashboards.into_iter().map(DashboardSummary::from).collect();

    // Demo isolation: hide dashboards created by other demo users
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude = state
            .get_demo_exclude_ids(
                auth.user_id(),
                nanosiem_core::demo::DemoResourceType::Dashboard,
            )
            .await;
        if !exclude.is_empty() {
            summaries.retain(|d| !exclude.contains(&d.id));
        }
    }

    Ok(Json(summaries))
}

/// Create a new dashboard
#[utoipa::path(
    post,
    path = "/api/dashboards",
    tag = "dashboards",
    request_body = CreateDashboardRequest,
    responses(
        (status = 200, description = "Dashboard created successfully", body = Dashboard),
        (status = 400, description = "Validation error"),
        (status = 403, description = "Forbidden - missing dashboards:create permission"),
    ),
    security(("api_key" = []))
)]
pub async fn create_dashboard(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateDashboardRequest>,
) -> Result<Json<Dashboard>, ApiError> {
    check_permission(&auth, permissions::DASHBOARDS_CREATE)
        .map_err(|_| ApiError::Forbidden("Missing permission: dashboards:create".to_string()))?;

    // Validate request
    if request.name.trim().is_empty() {
        return Err(ApiError::ValidationError(
            "Dashboard name cannot be empty".to_string(),
        ));
    }

    // Validate visibility
    let visibility = request.visibility.as_str();
    if !["public", "group", "private"].contains(&visibility) {
        return Err(ApiError::ValidationError(format!(
            "Invalid visibility '{}'. Must be one of: public, group, private",
            visibility
        )));
    }

    let repo = DashboardRepository::new(state.pool.clone());

    let new_dashboard = NewDashboard {
        name: request.name,
        description: request.description,
        layout: request.layout,
        panels: request.panels,
        refresh_interval: request.refresh_interval,
        owner_id: Some(auth.user_id()),
        visibility: request.visibility,
    };

    let dashboard = repo.create(&new_dashboard).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Dashboard, DASHBOARD_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "dashboard",
                Some(dashboard.id),
                Some(dashboard.name.clone()),
            )
            .client_context(&client)
            .details(serde_json::json!({ "visibility": dashboard.visibility }))
            .build(),
    );

    // Track resource for demo session cleanup
    state.track_demo_resource(
        auth.user_id(),
        nanosiem_core::demo::DemoResourceType::Dashboard,
        dashboard.id,
    );

    Ok(Json(dashboard))
}

/// Get a dashboard by ID (checks access for private dashboards)
#[utoipa::path(
    get,
    path = "/api/dashboards/{id}",
    tag = "dashboards",
    params(
        ("id" = String, Path, description = "Dashboard ID")
    ),
    responses(
        (status = 200, description = "Dashboard details", body = DashboardWithContext),
        (status = 403, description = "Forbidden - access denied or missing dashboards:view permission"),
        (status = 404, description = "Dashboard not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_dashboard(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DashboardWithContext>, ApiError> {
    check_permission(&auth, permissions::DASHBOARDS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: dashboards:view".to_string()))?;

    let repo = DashboardRepository::new(state.pool.clone());
    let dashboard = repo.find_by_id_for_user(*id, auth.user_id()).await?;
    Ok(Json(dashboard))
}

/// Update a dashboard (checks access permissions)
#[utoipa::path(
    put,
    path = "/api/dashboards/{id}",
    tag = "dashboards",
    params(
        ("id" = String, Path, description = "Dashboard ID")
    ),
    request_body = UpdateDashboardRequest,
    responses(
        (status = 200, description = "Dashboard updated successfully", body = Dashboard),
        (status = 400, description = "Validation error"),
        (status = 403, description = "Forbidden - not owner or missing dashboards:edit permission"),
        (status = 404, description = "Dashboard not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_dashboard(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateDashboardRequest>,
) -> Result<Json<Dashboard>, ApiError> {
    check_permission(&auth, permissions::DASHBOARDS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: dashboards:edit".to_string()))?;

    // Validate name if provided
    if let Some(ref name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiError::ValidationError(
                "Dashboard name cannot be empty".to_string(),
            ));
        }
    }

    let repo = DashboardRepository::new(state.pool.clone());

    let update = UpdateDashboard {
        name: request.name,
        description: request.description,
        layout: request.layout,
        panels: request.panels,
        refresh_interval: request.refresh_interval,
    };

    // Use ownership-aware update
    let dashboard = repo.update_owned(*id, auth.user_id(), &update).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Dashboard, DASHBOARD_UPDATED)
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

    Ok(Json(dashboard))
}

/// Share a dashboard (owner only)
///
/// Changes the visibility of a dashboard and optionally shares with groups.
#[utoipa::path(
    post,
    path = "/api/dashboards/{id}/share",
    tag = "dashboards",
    params(
        ("id" = String, Path, description = "Dashboard ID")
    ),
    request_body = ShareDashboardRequest,
    responses(
        (status = 200, description = "Dashboard sharing updated successfully", body = DashboardShareResult),
        (status = 400, description = "Validation error"),
        (status = 403, description = "Forbidden - not owner or missing dashboards:edit permission"),
        (status = 404, description = "Dashboard not found"),
    ),
    security(("api_key" = []))
)]
pub async fn share_dashboard(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(dashboard_id): Path<TypeIdParam>,
    Json(request): Json<ShareDashboardRequest>,
) -> Result<Json<DashboardShareResult>, ApiError> {
    check_permission(&auth, permissions::DASHBOARDS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: dashboards:edit".to_string()))?;

    // Validate visibility
    let visibility = request.visibility.as_str();
    if !["public", "group", "private"].contains(&visibility) {
        return Err(ApiError::ValidationError(format!(
            "Invalid visibility '{}'. Must be one of: public, group, private",
            visibility
        )));
    }

    // Require group_ids when visibility is 'group'
    if visibility == "group" {
        let group_ids = request.group_ids.as_ref();
        if group_ids.is_none() || group_ids.map(|g| g.is_empty()).unwrap_or(true) {
            return Err(ApiError::ValidationError(
                "group_ids is required when visibility is 'group'".to_string(),
            ));
        }
    }

    let repo = DashboardRepository::new(state.pool.clone());

    // Check if user is admin (for share_as_admin)
    let is_admin = check_permission(&auth, permissions::SETTINGS_SYSTEM).is_ok();

    // Security: Defense-in-depth ownership check at handler level
    // Non-admins must own the dashboard to change its sharing settings
    if !is_admin {
        let dashboard = repo
            .find_by_id_for_user(*dashboard_id, auth.user_id())
            .await?;
        if dashboard.owner_id != Some(auth.user_id()) {
            return Err(ApiError::Forbidden(
                "Only the dashboard owner can change sharing settings".to_string(),
            ));
        }
    }

    let result = if is_admin {
        repo.share_as_admin(*dashboard_id, &request, auth.user_id())
            .await?
    } else {
        repo.share(*dashboard_id, &request, auth.user_id()).await?
    };

    state.emit_audit(
        AuditEvent::builder(AuditSource::Dashboard, DASHBOARD_SHARED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("dashboard", Some(*dashboard_id), None)
            .client_context(&client)
            .details(serde_json::json!({ "visibility": request.visibility }))
            .build(),
    );

    Ok(Json(result))
}

/// Delete a dashboard (only owner can delete their private dashboards)
#[utoipa::path(
    delete,
    path = "/api/dashboards/{id}",
    tag = "dashboards",
    params(
        ("id" = String, Path, description = "Dashboard ID")
    ),
    responses(
        (status = 200, description = "Dashboard deleted successfully"),
        (status = 403, description = "Forbidden - not owner or missing dashboards:delete permission"),
        (status = 404, description = "Dashboard not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_dashboard(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::DASHBOARDS_DELETE)
        .map_err(|_| ApiError::Forbidden("Missing permission: dashboards:delete".to_string()))?;

    let repo = DashboardRepository::new(state.pool.clone());
    repo.delete_owned(*id, auth.user_id()).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Dashboard, DASHBOARD_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("dashboard", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({ "success": true })))
}

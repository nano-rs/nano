// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup table row management handlers (list, add, update, delete).

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, LOOKUP_ROWS_ADDED, LOOKUP_ROWS_DELETED,
    LOOKUP_ROW_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::{LookupRepository, LookupRowsPage, LookupService};

use super::lookup_error_to_api;
use super::types::{
    AddRowsRequest, AddRowsResponse, DeleteRowsRequest, DeleteRowsResponse, RowListParams,
    UpdateRowRequest,
};
use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// List rows from a lookup table with pagination
#[utoipa::path(
    get,
    path = "/api/lookup-tables/{name}/rows",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name"),
        RowListParams
    ),
    responses(
        (status = 200, description = "Paginated rows", body = LookupRowsPage),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_lookup_rows(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
    Query(params): Query<RowListParams>,
) -> Result<Json<LookupRowsPage>, ApiError> {
    check_permission(&auth, permissions::LOOKUP_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: lookup:view".to_string()))?;

    let lookup_repo = LookupRepository::new(state.pool.clone());
    let lookup_service = LookupService::new(lookup_repo);

    let page = params.page.unwrap_or(1);
    let page_size = params.page_size.unwrap_or(50);

    let rows_page = lookup_service
        .list_rows(&name, page, page_size)
        .await
        .map_err(lookup_error_to_api)?;

    Ok(Json(rows_page))
}

/// Add one or more rows to a lookup table
#[utoipa::path(
    post,
    path = "/api/lookup-tables/{name}/rows",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    request_body = AddRowsRequest,
    responses(
        (status = 200, description = "Rows added successfully", body = AddRowsResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn add_lookup_rows(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(name): Path<String>,
    Json(req): Json<AddRowsRequest>,
) -> Result<Json<AddRowsResponse>, ApiError> {
    check_permission(&auth, permissions::LOOKUP_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: lookup:edit".to_string()))?;

    if req.rows.is_empty() {
        return Err(ApiError::BadRequest(
            "At least one row is required".to_string(),
        ));
    }
    if req.rows.len() > 1000 {
        return Err(ApiError::BadRequest(
            "Maximum 1000 rows per request".to_string(),
        ));
    }

    let lookup_repo = LookupRepository::new(state.pool.clone());
    let lookup_service = LookupService::new(lookup_repo);

    let row_ids = lookup_service
        .insert_rows(&name, req.rows)
        .await
        .map_err(lookup_error_to_api)?;

    let inserted = row_ids.len();

    state.emit_audit(
        AuditEvent::builder(AuditSource::Lookup, LOOKUP_ROWS_ADDED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("lookup_table", None, Some(name))
            .client_context(&client)
            .details(serde_json::json!({ "rows_added": inserted }))
            .build(),
    );

    Ok(Json(AddRowsResponse { inserted, row_ids }))
}

/// Update a single row in a lookup table
#[utoipa::path(
    put,
    path = "/api/lookup-tables/{name}/rows/{row_id}",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name"),
        ("row_id" = i64, Path, description = "Row ID to update")
    ),
    request_body = UpdateRowRequest,
    responses(
        (status = 200, description = "Row updated successfully"),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_lookup_row(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path((name, row_id)): Path<(String, i64)>,
    Json(req): Json<UpdateRowRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::LOOKUP_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: lookup:edit".to_string()))?;

    let lookup_repo = LookupRepository::new(state.pool.clone());
    let lookup_service = LookupService::new(lookup_repo);

    lookup_service
        .update_row(&name, row_id, req.fields)
        .await
        .map_err(lookup_error_to_api)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Lookup, LOOKUP_ROW_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("lookup_table", None, Some(name))
            .client_context(&client)
            .details(serde_json::json!({ "row_id": row_id }))
            .build(),
    );

    Ok(Json(serde_json::json!({"success": true})))
}

/// Delete a single row from a lookup table
#[utoipa::path(
    delete,
    path = "/api/lookup-tables/{name}/rows/{row_id}",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name"),
        ("row_id" = i64, Path, description = "Row ID to delete")
    ),
    responses(
        (status = 200, description = "Row deleted successfully"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_lookup_row(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path((name, row_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::LOOKUP_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: lookup:edit".to_string()))?;

    let lookup_repo = LookupRepository::new(state.pool.clone());
    let lookup_service = LookupService::new(lookup_repo);

    lookup_service
        .delete_row(&name, row_id)
        .await
        .map_err(lookup_error_to_api)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Lookup, LOOKUP_ROWS_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("lookup_table", None, Some(name))
            .client_context(&client)
            .details(serde_json::json!({ "row_id": row_id }))
            .build(),
    );

    Ok(Json(serde_json::json!({"success": true})))
}

/// Bulk delete rows from a lookup table
#[utoipa::path(
    delete,
    path = "/api/lookup-tables/{name}/rows",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    request_body = DeleteRowsRequest,
    responses(
        (status = 200, description = "Rows deleted successfully", body = DeleteRowsResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_lookup_rows(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(name): Path<String>,
    Json(req): Json<DeleteRowsRequest>,
) -> Result<Json<DeleteRowsResponse>, ApiError> {
    check_permission(&auth, permissions::LOOKUP_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: lookup:edit".to_string()))?;

    let lookup_repo = LookupRepository::new(state.pool.clone());
    let lookup_service = LookupService::new(lookup_repo);

    let deleted = lookup_service
        .delete_rows(&name, &req.row_ids)
        .await
        .map_err(lookup_error_to_api)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Lookup, LOOKUP_ROWS_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("lookup_table", None, Some(name))
            .client_context(&client)
            .details(serde_json::json!({ "rows_deleted": deleted }))
            .build(),
    );

    Ok(Json(DeleteRowsResponse { deleted }))
}

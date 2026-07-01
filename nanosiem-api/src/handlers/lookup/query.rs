// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup query handler (single and batch lookups).

use axum::{extract::State, Extension, Json};

use nanosiem_core::auth::permissions;
use nanosiem_core::{BatchLookupQuery, LookupQuery};

use super::lookup_error_to_api;
use super::types::{LookupQueryRequest, LookupQueryResponse};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Execute a lookup query
///
/// POST /api/lookup/query
#[utoipa::path(
    post,
    path = "/api/lookup-tables/query",
    tag = "lookup",
    request_body = LookupQueryRequest,
    responses(
        (status = 200, description = "Lookup query executed successfully", body = LookupQueryResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn lookup_query(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(query): Json<LookupQueryRequest>,
) -> Result<Json<LookupQueryResponse>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_VIEW)?;

    let lookup_service = state.lookup_service.clone();

    // Handle single or batch lookup
    if let Some(key_values) = query.key_values {
        // Batch lookup
        let batch_query = BatchLookupQuery {
            table_name: query.table_name,
            key_field: query.key_field,
            key_values,
            output_fields: query.output_fields,
            case_insensitive: query.case_insensitive.unwrap_or(false),
        };

        let result = lookup_service
            .lookup_batch(batch_query)
            .await
            .map_err(lookup_error_to_api)?;

        Ok(Json(LookupQueryResponse::Batch(result)))
    } else if let Some(key_value) = query.key_value {
        // Single lookup
        let single_query = LookupQuery {
            table_name: query.table_name,
            key_field: query.key_field,
            key_value,
            output_fields: query.output_fields,
            case_insensitive: query.case_insensitive.unwrap_or(false),
        };

        let result = lookup_service
            .lookup(single_query)
            .await
            .map_err(lookup_error_to_api)?;

        Ok(Json(LookupQueryResponse::Single(result)))
    } else {
        Err(ApiError::BadRequest(
            "Either key_value or key_values must be provided".to_string(),
        ))
    }
}

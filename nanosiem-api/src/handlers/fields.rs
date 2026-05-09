// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field metadata endpoint handlers
//!
//! Implements:
//! - GET /api/fields - List available fields
//! - GET /api/fields/:name/values - Top values for a field
//! - GET /api/udm/fields - Get all UDM fields with metadata

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::{Duration, Utc};
use nanosiem_core::auth::permissions;
use nanosiem_core::udm::UdmField;
use nanosiem_core::{TimeRangeInput, UdmFieldStats};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Query parameters for field endpoints
#[derive(Debug, Deserialize, IntoParams)]
pub struct FieldsQuery {
    /// Start of time range (defaults to 24 hours ago)
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// End of time range (defaults to now)
    pub end: Option<chrono::DateTime<chrono::Utc>>,
}

impl FieldsQuery {
    /// Get the time range, defaulting to last 24 hours
    pub fn time_range(&self) -> TimeRangeInput {
        let end = self.end.unwrap_or_else(Utc::now);
        let start = self.start.unwrap_or_else(|| end - Duration::hours(24));
        TimeRangeInput::new(start, end)
    }
}

/// Query parameters for field values endpoint
#[derive(Debug, Deserialize, IntoParams)]
pub struct FieldValuesQuery {
    /// Start of time range
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// End of time range
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Maximum number of values to return
    pub limit: Option<usize>,
}

impl FieldValuesQuery {
    /// Get the time range, defaulting to last 24 hours
    pub fn time_range(&self) -> TimeRangeInput {
        let end = self.end.unwrap_or_else(Utc::now);
        let start = self.start.unwrap_or_else(|| end - Duration::hours(24));
        TimeRangeInput::new(start, end)
    }
}

/// Response for field values
#[derive(Debug, Serialize, ToSchema)]
pub struct FieldValuesResponse {
    pub field: String,
    pub values: Vec<FieldValue>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FieldValue {
    pub value: String,
    pub count: u64,
}

/// List all available UDM fields with statistics
#[utoipa::path(
    get,
    path = "/api/fields",
    tag = "fields",
    params(FieldsQuery),
    responses(
        (status = 200, description = "List of UDM field statistics", body = Vec<UdmFieldStats>),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_fields(
    State(state): State<AppState>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Vec<UdmFieldStats>>, ApiError> {
    let time_range = query.time_range();
    let stats = state
        .search_service
        .get_udm_field_stats(&time_range)
        .await?;
    Ok(Json(stats))
}

/// Get top values for a specific field
#[utoipa::path(
    get,
    path = "/api/fields/{name}/values",
    tag = "fields",
    params(
        ("name" = String, Path, description = "Field name"),
        FieldValuesQuery
    ),
    responses(
        (status = 200, description = "Top values for the field", body = FieldValuesResponse),
        (status = 404, description = "Field not found"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_field_values(
    State(state): State<AppState>,
    Path(field_name): Path<String>,
    Query(query): Query<FieldValuesQuery>,
) -> Result<Json<FieldValuesResponse>, ApiError> {
    // Parse the field name
    let field: UdmField = field_name
        .parse()
        .map_err(|_| ApiError::NotFound(format!("Unknown field: {}", field_name)))?;

    let time_range = query.time_range();
    let values = state
        .search_service
        .get_udm_field_values(field, &time_range, query.limit)
        .await?;

    let values = values
        .into_iter()
        .map(|(value, count)| FieldValue { value, count })
        .collect();

    Ok(Json(FieldValuesResponse {
        field: field_name,
        values,
    }))
}

/// Get distinct source types from the logs table
#[utoipa::path(
    get,
    path = "/api/source-types",
    tag = "fields",
    params(FieldValuesQuery),
    responses(
        (status = 200, description = "List of source types with counts", body = Vec<(String, i64)>),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_source_types(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<FieldValuesQuery>,
) -> Result<Json<Vec<(String, i64)>>, ApiError> {
    check_permission(&auth, permissions::FEEDS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: search:view".to_string()))?;

    let time_range = query.time_range();

    // Check if we have a dual pool (ClickHouse enabled)
    if let Some(ref dual_pool) = state.dual_pool {
        // Query ClickHouse for source types
        let ch_client = dual_pool.clickhouse();

        let sql = format!(
            r#"
            SELECT source_type, count(*) as count
            FROM logs
            WHERE timestamp >= '{}'
              AND timestamp < '{}'
              AND source_type != ''
            GROUP BY source_type
            ORDER BY count DESC
            "#,
            time_range.start.format("%Y-%m-%d %H:%M:%S"),
            time_range.end.format("%Y-%m-%d %H:%M:%S")
        );

        // Use JSONEachRow format for dynamic results
        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes)
            .map_err(|e| ApiError::DatabaseError(format!("Invalid UTF-8: {}", e)))?;

        let rows: Vec<(String, i64)> = response_str
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                let json: serde_json::Value = serde_json::from_str(line).ok()?;
                let source_type = json.get("source_type")?.as_str()?.to_string();
                let count = json.get("count")?.as_u64()? as i64;
                Some((source_type, count))
            })
            .collect();

        Ok(Json(rows))
    } else {
        // Fallback to PostgreSQL
        let rows: Vec<(String, i64)> = sqlx::query_as::<_, (String, i64)>(
            r#"
            SELECT source_type, COUNT(*) as count
            FROM logs
            WHERE timestamp >= $1 AND timestamp < $2
              AND source_type IS NOT NULL
              AND source_type != ''
            GROUP BY source_type
            ORDER BY count DESC
            "#,
        )
        .bind(time_range.start)
        .bind(time_range.end)
        .fetch_all(&state.pool)
        .await
        .map_err(|e: sqlx::Error| ApiError::DatabaseError(e.to_string()))?;

        Ok(Json(rows))
    }
}

/// Response for UDM fields endpoint
#[derive(Debug, Serialize, ToSchema)]
pub struct UdmFieldsResponse {
    pub fields: Vec<UdmFieldInfo>,
}

/// Information about a single UDM field
#[derive(Debug, Serialize, ToSchema)]
pub struct UdmFieldInfo {
    pub name: String,
    pub column_name: String,
    pub data_type: String,
    pub category: String,
    pub description: String,
}

/// Get ext field names discovered in recent data (last 24h).
/// Used by the frontend to enable syntax highlighting for non-UDM fields.
#[utoipa::path(
    get,
    path = "/api/fields/ext",
    tag = "fields",
    responses(
        (status = 200, description = "List of ext field names", body = Vec<String>),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_ext_fields(State(state): State<AppState>) -> Result<Json<Vec<String>>, ApiError> {
    let names = state
        .search_service
        .get_ext_field_names()
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get ext field names: {}", e)))?;
    Ok(Json(names))
}

/// Get all UDM fields with their metadata
///
/// Returns JSON with all fields and their metadata including:
/// - Field name
/// - Column name
/// - Data type
/// - Category
/// - Description
///
/// Requirements: 2.5, 5.2
#[utoipa::path(
    get,
    path = "/api/udm/fields",
    tag = "fields",
    responses(
        (status = 200, description = "All UDM fields with metadata", body = UdmFieldsResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_udm_fields() -> Result<Json<UdmFieldsResponse>, ApiError> {
    let fields: Vec<UdmFieldInfo> = UdmField::all()
        .iter()
        .map(|field| {
            let metadata = field.metadata();
            UdmFieldInfo {
                name: metadata.name.to_string(),
                column_name: metadata.column_name.to_string(),
                data_type: format!("{:?}", metadata.data_type),
                category: format!("{:?}", metadata.category),
                description: metadata.description.to_string(),
            }
        })
        .collect();

    Ok(Json(UdmFieldsResponse { fields }))
}

// =============================================================================
// OpenAPI Documentation
// =============================================================================

#[derive(OpenApi)]
#[openapi(
    paths(
        list_fields,
        get_field_values,
        get_source_types,
        get_ext_fields,
        get_udm_fields,
    ),
    components(
        schemas(
            FieldValuesResponse,
            FieldValue,
            UdmFieldsResponse,
            UdmFieldInfo,
        )
    ),
    tags(
        (name = "fields", description = "Field metadata and value endpoints")
    )
)]
pub struct FieldsApiDoc;

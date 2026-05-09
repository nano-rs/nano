// SPDX-License-Identifier: AGPL-3.0-or-later

//! Upload API handlers
//!
//! Provides REST API endpoints for file upload operations including
//! file preview, upload history, and lookup table creation.
//!
//! Requirements: 1.1, 1.2, 1.3, 5.1, 5.2, 7.4

use axum::{
    extract::{Multipart, Query, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use nanosiem_core::auth::permissions;
use nanosiem_core::{
    FileFormat, PreviewResult, UploadFilter, UploadParserConfig, UploadRecord, UploadResult,
    UploadService,
};

use crate::middleware::{check_any_permission, check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Request body for upload configuration (sent as form field)
#[derive(Debug, Deserialize, ToSchema)]
pub struct UploadConfig {
    /// File format (csv, json, ndjson) - auto-detected if not provided
    pub format: Option<String>,
    /// Destination type: "logs" or "lookup"
    pub destination_type: String,
    /// Source type for logs, or table name for lookup
    pub destination_name: String,
    /// Parser ID for VRL transformations (logs only)
    #[serde(default, with = "nanosiem_core::typeid::parser::opt")]
    #[schema(value_type = Option<String>)]
    pub parser_id: Option<Uuid>,
    /// Primary key column (lookup only)
    pub primary_key: Option<String>,
    /// Update mode for lookup tables: "replace" or "append"
    pub mode: Option<String>,
    /// CSV delimiter character
    pub csv_delimiter: Option<String>,
    /// Whether CSV has headers
    pub csv_has_headers: Option<bool>,
}

/// Response for upload operations
#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResponse {
    #[serde(with = "nanosiem_core::typeid::upload")]
    #[schema(value_type = String)]
    pub upload_id: Uuid,
    pub records_processed: usize,
    pub records_ingested: usize,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

impl From<UploadResult> for UploadResponse {
    fn from(result: UploadResult) -> Self {
        Self {
            upload_id: result.upload_id,
            records_processed: result.records_processed,
            records_ingested: result.records_ingested,
            errors: result.errors,
            duration_ms: result.duration_ms,
        }
    }
}

/// Preview file contents before upload
///
/// POST /api/upload/preview
///
/// Accepts multipart form data with:
/// - file: The file to preview
/// - config: JSON configuration for parsing
/// - limit: Optional number of rows to preview (default: 10)
///
/// Requires: lookup:create permission
#[utoipa::path(
    post,
    path = "/api/upload/preview",
    tag = "upload",
    request_body(content = inline(UploadConfig), content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Preview generated successfully", body = PreviewResult),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn preview_upload(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    mut multipart: Multipart,
) -> Result<Json<PreviewResult>, ApiError> {
    // Allow preview for both log uploads and lookup table uploads
    check_any_permission(
        &auth,
        &[permissions::UPLOAD_LOGS, permissions::LOOKUP_CREATE],
    )
    .map_err(|_| {
        ApiError::Forbidden("Missing permission: upload:logs or lookup:create".to_string())
    })?;

    let mut file_content: Option<Vec<u8>> = None;
    let mut config: Option<UploadConfig> = None;
    let mut limit: Option<usize> = None;

    // Parse multipart form data
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "file" => {
                file_content = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| ApiError::BadRequest(format!("Failed to read file: {}", e)))?
                        .to_vec(),
                );
            }
            "config" => {
                let config_str = field
                    .text()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("Failed to read config: {}", e)))?;
                config =
                    Some(serde_json::from_str(&config_str).map_err(|e| {
                        ApiError::BadRequest(format!("Invalid config JSON: {}", e))
                    })?);
            }
            "limit" => {
                let limit_str = field
                    .text()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("Failed to read limit: {}", e)))?;
                limit = Some(
                    limit_str
                        .parse()
                        .map_err(|_| ApiError::BadRequest("Invalid limit value".to_string()))?,
                );
            }
            _ => {}
        }
    }

    let content =
        file_content.ok_or_else(|| ApiError::BadRequest("No file provided".to_string()))?;

    // Build parser config (config is optional for preview - we can auto-detect)
    let parser_config = if let Some(cfg) = config {
        build_parser_config(&cfg, &content)?
    } else {
        // Auto-detect format
        let format = nanosiem_core::FileParser::detect_format(&content).unwrap_or(FileFormat::Csv);
        UploadParserConfig {
            format,
            ..Default::default()
        }
    };

    // Create upload service and preview
    let upload_service = UploadService::new(state.pool.clone());
    let result = upload_service
        .preview(&content, &parser_config, limit)
        .await
        .map_err(|e| ApiError::BadRequest(format!("Preview failed: {}", e)))?;

    Ok(Json(result))
}

/// Query parameters for upload history
#[derive(Debug, Deserialize, IntoParams)]
pub struct UploadHistoryQuery {
    /// Filter by destination type (logs or lookup)
    pub destination_type: Option<String>,
    /// Filter by destination name (source_type or table_name)
    pub destination_name: Option<String>,
    /// Filter by status (processing, completed, failed)
    pub status: Option<String>,
    /// Filter by start date (ISO 8601)
    pub start_date: Option<String>,
    /// Filter by end date (ISO 8601)
    pub end_date: Option<String>,
    /// Maximum number of results
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

/// Get upload history
///
/// GET /api/upload/history
///
/// Requires: upload:history permission
#[utoipa::path(
    get,
    path = "/api/upload/history",
    tag = "upload",
    params(UploadHistoryQuery),
    responses(
        (status = 200, description = "Upload history retrieved successfully", body = Vec<UploadRecord>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn get_upload_history(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<UploadHistoryQuery>,
) -> Result<Json<Vec<UploadRecord>>, ApiError> {
    check_permission(&auth, permissions::UPLOAD_HISTORY)
        .map_err(|_| ApiError::Forbidden("Missing permission: upload:history".to_string()))?;

    let filter = UploadFilter {
        destination_type: query.destination_type,
        destination_name: query.destination_name,
        status: query.status,
        start_date: query
            .start_date
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
        end_date: query
            .end_date
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
        limit: query.limit,
        offset: query.offset,
    };

    let upload_service = UploadService::new(state.pool.clone());
    let history = upload_service
        .get_upload_history(&filter)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get upload history: {}", e)))?;

    Ok(Json(history))
}

/// Helper function to build parser config from upload config
fn build_parser_config(
    config: &UploadConfig,
    content: &[u8],
) -> Result<UploadParserConfig, ApiError> {
    // Determine format
    let format = if let Some(ref fmt) = config.format {
        FileFormat::from_str(fmt)
            .ok_or_else(|| ApiError::BadRequest(format!("Invalid format: {}", fmt)))?
    } else {
        // Auto-detect
        nanosiem_core::FileParser::detect_format(content).unwrap_or(FileFormat::Csv)
    };

    let mut parser_config = UploadParserConfig {
        format,
        ..Default::default()
    };

    // Apply CSV-specific options
    if let Some(ref delimiter) = config.csv_delimiter {
        if let Some(c) = delimiter.chars().next() {
            parser_config.csv_delimiter = c;
        }
    }

    if let Some(has_headers) = config.csv_has_headers {
        parser_config.csv_has_headers = has_headers;
    }

    Ok(parser_config)
}

/// OpenAPI documentation for upload endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(preview_upload, get_upload_history),
    components(schemas(UploadConfig, UploadResponse))
)]
pub struct UploadApiDoc;

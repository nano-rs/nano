// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup table CRUD handlers (create, list, get, sample, delete).

use axum::{
    extract::{Multipart, Path, Query, State},
    Extension, Json,
};
use std::collections::HashMap;
use tracing::info;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, LOOKUP_TABLE_CREATED, LOOKUP_TABLE_DELETED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::{
    sanitize_identifiers, ColumnType, FileFormat, FileParser, LookupColumn, LookupMode,
    LookupService, LookupTable, NewLookupTable, UploadParserConfig,
};

use super::lookup_error_to_api;
use super::types::{
    CreateLookupTableConfig, CreateLookupTableFromSchemaRequest, CreateLookupTableResponse,
    LookupDeleteResponse, RenamedColumn, SampleQueryParams, SampleRowsResponse,
};
use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Create a lookup table from file upload
///
/// POST /api/lookup/tables
///
/// Accepts multipart form data with:
/// - file: The file to upload
/// - config: JSON configuration for the lookup table
#[utoipa::path(
    post,
    path = "/api/lookup-tables",
    tag = "lookup",
    request_body(content = inline(CreateLookupTableConfig), content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Lookup table created successfully", body = CreateLookupTableResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn create_lookup_table(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    mut multipart: Multipart,
) -> Result<Json<CreateLookupTableResponse>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_CREATE)?;

    let mut file_content: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut config: Option<CreateLookupTableConfig> = None;

    // Parse multipart form data
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "file" => {
                filename = field.file_name().map(|s: &str| s.to_string());
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
            _ => {}
        }
    }

    let content =
        file_content.ok_or_else(|| ApiError::BadRequest("No file provided".to_string()))?;
    let filename = filename.unwrap_or_else(|| "upload.dat".to_string());
    let config = config.ok_or_else(|| ApiError::BadRequest("No config provided".to_string()))?;

    // Validate table name
    if config.name.is_empty() {
        return Err(ApiError::BadRequest("Table name is required".to_string()));
    }

    // Determine format
    let format = if let Some(ref fmt) = config.format {
        FileFormat::from_str(fmt)
            .ok_or_else(|| ApiError::BadRequest(format!("Invalid format: {}", fmt)))?
    } else {
        FileParser::detect_format(&content).unwrap_or(FileFormat::Csv)
    };

    // Build parser config
    let mut parser_config = UploadParserConfig {
        format,
        ..Default::default()
    };

    if let Some(ref delimiter) = config.csv_delimiter {
        if let Some(c) = delimiter.chars().next() {
            parser_config.csv_delimiter = c;
        }
    }

    if let Some(has_headers) = config.csv_has_headers {
        parser_config.csv_has_headers = has_headers;
    }

    // Parse the file
    let parser = FileParser::new();
    let parse_result = parser
        .parse(&content, &parser_config)
        .map_err(|e| ApiError::BadRequest(format!("Failed to parse file: {}", e)))?;

    // Lookup tables feed detections and enrichment — a partially imported
    // file means silently wrong reference data. Reject the whole upload if
    // any row failed to parse, with per-row diagnostics (NAN-1363).
    if !parse_result.errors.is_empty() {
        const MAX_REPORTED: usize = 10;
        let total = parse_result.errors.len();
        let detail: Vec<String> = parse_result
            .errors
            .iter()
            .take(MAX_REPORTED)
            .map(|e| format!("line {}: {}", e.line_number, e.error_message))
            .collect();
        let suffix = if total > MAX_REPORTED {
            format!("; and {} more", total - MAX_REPORTED)
        } else {
            String::new()
        };
        return Err(ApiError::BadRequest(format!(
            "File contains {} malformed record(s) — {}{}",
            total,
            detail.join("; "),
            suffix
        )));
    }

    if parse_result.records.is_empty() {
        return Err(ApiError::BadRequest(
            "No valid records found in file".to_string(),
        ));
    }

    // Convert parsed records to HashMap format
    let mut records: Vec<HashMap<String, serde_json::Value>> =
        parse_result.records.into_iter().map(|r| r.fields).collect();

    // Flatten nested JSON if requested
    if config.flatten_json {
        records = LookupService::flatten_records(records);
    }

    // Sanitize raw CSV/JSON headers to SQL-safe identifiers (NAN-513).
    // Real-world files use `Customer Id`, `First Name`, etc., which the
    // strict identifier validator rejects. We normalize them once here so
    // every downstream step (column detection, PK match, type overrides,
    // CREATE TABLE) sees the canonical names.
    let raw_headers: Vec<String> = records
        .iter()
        .flat_map(|r| r.keys().cloned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let rename_map = sanitize_identifiers(raw_headers);
    let renamed_columns: Vec<RenamedColumn> = rename_map
        .iter()
        .filter(|(orig, sanitized)| orig.as_str() != sanitized.as_str())
        .map(|(original, sanitized)| RenamedColumn {
            original: original.clone(),
            sanitized: sanitized.clone(),
        })
        .collect();
    if !renamed_columns.is_empty() {
        for record in records.iter_mut() {
            let original_keys: Vec<String> = record.keys().cloned().collect();
            for key in original_keys {
                if let Some(canonical) = rename_map.get(&key) {
                    if canonical != &key {
                        if let Some(value) = record.remove(&key) {
                            record.insert(canonical.clone(), value);
                        }
                    }
                }
            }
        }
    }

    // Sanitize the requested PK so the user can pass either the raw header
    // (`'Customer Id'`) or the sanitized name (`'customer_id'`) — both work.
    let primary_key_sanitized = config
        .primary_key
        .as_ref()
        .map(|pk| rename_map.get(pk).cloned().unwrap_or_else(|| {
            nanosiem_core::sanitize_identifier(pk)
        }));

    // Detect column types
    let type_overrides: Option<Vec<nanosiem_core::ColumnTypeOverride>> =
        config.column_types.map(|overrides| {
            overrides
                .into_iter()
                .filter_map(|o| {
                    ColumnType::from_str(&o.data_type).map(|dt| nanosiem_core::ColumnTypeOverride {
                        column: rename_map
                            .get(&o.column)
                            .cloned()
                            .unwrap_or_else(|| nanosiem_core::sanitize_identifier(&o.column)),
                        data_type: dt,
                    })
                })
                .collect()
        });

    let columns = LookupService::detect_column_types(&records, type_overrides.as_deref());

    // Validate primary key exists in columns (matches against sanitized name)
    if let Some(ref pk) = primary_key_sanitized {
        if !columns.iter().any(|c| &c.name == pk) {
            return Err(ApiError::BadRequest(format!(
                "Primary key column '{}' not found in data",
                config.primary_key.as_deref().unwrap_or(pk)
            )));
        }
    }

    info!(
        table_name = %config.name,
        filename = %filename,
        record_count = records.len(),
        column_count = columns.len(),
        "Creating lookup table"
    );

    // Create lookup service
    let lookup_service = state.lookup_service.clone();

    // Check if table exists
    let table_exists = lookup_service
        .table_exists(&config.name)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to check table existence: {}", e)))?;

    let mode = config
        .mode
        .as_deref()
        .map(|m| match m.to_lowercase().as_str() {
            "append" => LookupMode::Append,
            _ => LookupMode::Replace,
        })
        .unwrap_or(LookupMode::Replace);

    let (table, records_inserted) = if table_exists {
        match mode {
            LookupMode::Replace => {
                // NAN-1362: atomic staging + swap. A failed/malformed insert
                // leaves the existing table and its data intact, instead of the
                // old drop-then-recreate-then-insert that wiped data on failure.
                let new_table = NewLookupTable {
                    name: config.name.clone(),
                    description: config.description.clone(),
                    columns,
                    primary_key: primary_key_sanitized.clone(),
                };

                let record_count = records.len();
                let table = lookup_service
                    .replace_table(new_table, records)
                    .await
                    .map_err(lookup_error_to_api)?;

                (table, record_count)
            }
            LookupMode::Append => {
                // Append to existing table
                let _table = lookup_service
                    .get_table(&config.name)
                    .await
                    .map_err(lookup_error_to_api)?;

                let inserted = lookup_service
                    .insert_records(&config.name, records)
                    .await
                    .map_err(lookup_error_to_api)?;

                // Get updated table info
                let updated_table = lookup_service
                    .get_table(&config.name)
                    .await
                    .map_err(lookup_error_to_api)?;

                (updated_table, inserted)
            }
        }
    } else {
        // Create new table
        let new_table = NewLookupTable {
            name: config.name.clone(),
            description: config.description.clone(),
            columns,
            primary_key: primary_key_sanitized.clone(),
        };

        let _table = lookup_service
            .create_table(new_table, Some(auth.user_id()))
            .await
            .map_err(lookup_error_to_api)?;

        let inserted = lookup_service
            .insert_records(&config.name, records)
            .await
            .map_err(lookup_error_to_api)?;

        // Get updated table with row count
        let updated_table = lookup_service
            .get_table(&config.name)
            .await
            .map_err(lookup_error_to_api)?;

        (updated_table, inserted)
    };

    info!(
        table_name = %config.name,
        records_inserted,
        "Lookup table created successfully"
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::Lookup, LOOKUP_TABLE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("lookup_table", Some(table.id), Some(table.name.clone()))
            .client_context(&client)
            .details(serde_json::json!({ "records_inserted": records_inserted }))
            .build(),
    );

    Ok(Json(CreateLookupTableResponse {
        table,
        records_inserted,
        renamed_columns,
    }))
}

/// List all lookup tables
///
/// GET /api/lookup/tables
#[utoipa::path(
    get,
    path = "/api/lookup-tables",
    tag = "lookup",
    responses(
        (status = 200, description = "Lookup tables retrieved successfully", body = Vec<LookupTable>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_lookup_tables(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<LookupTable>>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_VIEW)?;

    let lookup_service = state.lookup_service.clone();

    let tables = lookup_service
        .list_tables()
        .await
        .map_err(lookup_error_to_api)?;

    Ok(Json(tables))
}

/// Get a specific lookup table by name
///
/// GET /api/lookup/tables/:name
#[utoipa::path(
    get,
    path = "/api/lookup-tables/{name}",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    responses(
        (status = 200, description = "Lookup table retrieved successfully", body = LookupTable),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_lookup_table(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<Json<LookupTable>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_VIEW)?;

    let lookup_service = state.lookup_service.clone();

    let table = lookup_service
        .get_table(&name)
        .await
        .map_err(lookup_error_to_api)?;

    Ok(Json(table))
}

/// Get sample rows from a lookup table
///
/// GET /api/lookup-tables/:name/sample
///
/// Query parameters:
/// - limit: Number of rows to return (default: 20, max: 100)
#[utoipa::path(
    get,
    path = "/api/lookup-tables/{name}/sample",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name"),
        SampleQueryParams
    ),
    responses(
        (status = 200, description = "Sample rows retrieved successfully", body = SampleRowsResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_lookup_table_sample(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
    Query(params): Query<SampleQueryParams>,
) -> Result<Json<SampleRowsResponse>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_VIEW)?;

    let lookup_service = state.lookup_service.clone();

    let limit = params.limit.unwrap_or(20).min(100);

    let rows = lookup_service
        .sample_rows(&name, limit)
        .await
        .map_err(lookup_error_to_api)?;

    Ok(Json(SampleRowsResponse { rows }))
}

/// Delete a lookup table
///
/// DELETE /api/lookup/tables/:name
#[utoipa::path(
    delete,
    path = "/api/lookup-tables/{name}",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    responses(
        (status = 200, description = "Lookup table deleted successfully", body = LookupDeleteResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_lookup_table(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(name): Path<String>,
) -> Result<Json<LookupDeleteResponse>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_DELETE)?;

    let lookup_service = state.lookup_service.clone();

    lookup_service
        .drop_table(&name)
        .await
        .map_err(lookup_error_to_api)?;

    info!(table_name = %name, "Lookup table deleted");

    state.emit_audit(
        AuditEvent::builder(AuditSource::Lookup, LOOKUP_TABLE_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("lookup_table", None, Some(name))
            .client_context(&client)
            .build(),
    );

    Ok(Json(LookupDeleteResponse { success: true }))
}

/// Create a lookup table from schema definition (no file upload)
#[utoipa::path(
    post,
    path = "/api/lookup-tables/schema",
    tag = "lookup",
    request_body = CreateLookupTableFromSchemaRequest,
    responses(
        (status = 200, description = "Lookup table created from schema", body = LookupTable),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn create_lookup_table_from_schema(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<CreateLookupTableFromSchemaRequest>,
) -> Result<Json<LookupTable>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_CREATE)?;

    if req.name.is_empty() {
        return Err(ApiError::BadRequest("Table name is required".to_string()));
    }
    if req.columns.is_empty() {
        return Err(ApiError::BadRequest(
            "At least one column is required".to_string(),
        ));
    }

    // Convert column defs
    let columns: Vec<LookupColumn> = req
        .columns
        .into_iter()
        .map(|c| {
            let col_type = ColumnType::from_str(&c.data_type).unwrap_or(ColumnType::Text);
            LookupColumn::new(c.name, col_type, c.nullable)
        })
        .collect();

    // Validate primary key
    if let Some(ref pk) = req.primary_key {
        if !columns.iter().any(|c| &c.name == pk) {
            return Err(ApiError::BadRequest(format!(
                "Primary key column '{}' not found in columns",
                pk
            )));
        }
    }

    info!(table_name = %req.name, column_count = columns.len(), "Creating lookup table from schema");

    let lookup_service = state.lookup_service.clone();

    let new_table = NewLookupTable {
        name: req.name,
        description: req.description,
        columns,
        primary_key: req.primary_key,
    };

    let created = lookup_service
        .create_table(new_table, Some(auth.user_id()))
        .await
        .map_err(lookup_error_to_api)?;

    // Re-fetch via get_table so the response includes the JOIN-populated
    // creator summary (register_table only returns the FK, not name/email).
    let table = lookup_service
        .get_table(&created.name)
        .await
        .map_err(lookup_error_to_api)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Lookup, LOOKUP_TABLE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("lookup_table", Some(table.id), Some(table.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(table))
}

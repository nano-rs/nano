// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup Table API handlers
//!
//! Provides REST API endpoints for lookup table management including
//! creating, listing, querying, and deleting lookup tables.
//!
//! Requirements: 2.1, 3.1, 5.3

mod history;
pub mod ingestion;
mod query;
mod rows;
mod tables;
mod types;
mod usage;

pub use history::*;
pub use ingestion::*;
pub use query::*;
pub use rows::*;
pub use tables::*;
pub use types::*;
pub use usage::*;

use super::AuditExt;
use crate::error::ApiError;
use nanosiem_core::LookupError;

/// Convert LookupError to ApiError
pub(crate) fn lookup_error_to_api(err: LookupError) -> ApiError {
    match err {
        LookupError::TableNotFound(name) => {
            ApiError::NotFound(format!("Lookup table not found: {}", name))
        }
        LookupError::TableAlreadyExists(name) => {
            ApiError::ValidationError(format!("Lookup table already exists: {}", name))
        }
        LookupError::InvalidTableName(msg) => ApiError::ValidationError(msg),
        LookupError::InvalidColumn(msg) => ApiError::ValidationError(msg),
        LookupError::RowLimitExceeded(max) => {
            ApiError::ValidationError(format!("Row limit exceeded: maximum {} rows allowed", max))
        }
        LookupError::PrimaryKeyNotFound(col) => {
            ApiError::ValidationError(format!("Primary key column not found: {}", col))
        }
        LookupError::RowNotFound(id) => ApiError::NotFound(format!("Row not found: {}", id)),
        LookupError::RepositoryError(e) => {
            tracing::error!(error = %e, "Lookup repository error");
            ApiError::InternalError("A database error occurred".to_string())
        }
    }
}

/// OpenAPI documentation for lookup endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_lookup_table,
        list_lookup_tables,
        get_lookup_table,
        get_lookup_table_sample,
        get_lookup_table_usage,
        get_lookup_table_ingestion_history,
        delete_lookup_table,
        lookup_query,
        create_lookup_table_from_schema,
        list_lookup_rows,
        add_lookup_rows,
        update_lookup_row,
        delete_lookup_row,
        delete_lookup_rows,
        ingestion::get_lookup_ingestion,
        ingestion::upsert_lookup_ingestion,
        ingestion::delete_lookup_ingestion,
        ingestion::trigger_lookup_ingestion,
        ingestion::enable_lookup_ingestion,
        ingestion::disable_lookup_ingestion,
        ingestion::validate_cron_expression,
    ),
    components(schemas(
        CreateLookupTableConfig,
        ColumnTypeOverrideRequest,
        CreateLookupTableResponse,
        RenamedColumn,
        SampleRowsResponse,
        LookupDeleteResponse,
        LookupQueryRequest,
        LookupQueryResponse,
        CreateLookupTableFromSchemaRequest,
        SchemaColumnDef,
        AddRowsRequest,
        AddRowsResponse,
        UpdateRowRequest,
        DeleteRowsRequest,
        DeleteRowsResponse,
        nanosiem_core::LookupRowsPage,
        nanosiem_core::LookupTableCreator,
        nanosiem_core::LookupUsage,
        nanosiem_core::LookupHistoryEntry,
        nanosiem_core::LookupHistoryKind,
        ingestion::UpsertLookupIngestionRequest,
        ingestion::ValidateCronRequest,
        ingestion::ValidateCronResponse,
        ingestion::IngestionDeleteResponse,
    ))
)]
pub struct LookupApiDoc;

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
        // NAN-1361: malformed-but-parseable upload data fails at the DB layer;
        // surface it as a 4xx validation error rather than a 500.
        LookupError::InvalidData(msg) => {
            ApiError::ValidationError(format!("Invalid upload data: {}", msg))
        }
        LookupError::RowLimitExceeded(max) => {
            ApiError::ValidationError(format!("Row limit exceeded: maximum {} rows allowed", max))
        }
        LookupError::PrimaryKeyNotFound(col) => {
            ApiError::ValidationError(format!("Primary key column not found: {}", col))
        }
        LookupError::RowNotFound(id) => ApiError::NotFound(format!("Row not found: {}", id)),
        LookupError::TableInUse(rules) => ApiError::Conflict(format!(
            "Lookup table is used by detection rules: {}. Remove those references before deleting it.", rules
        )),
        LookupError::ReferenceConflict => ApiError::Conflict(
            "Lookup table is still referenced by related records. Remove those references before deleting it.".to_string()
        ),
        LookupError::RepositoryError(e) => {
            if e.contains("Code: 497") && e.contains("ACCESS_DENIED")
                && e.contains("ALTER DELETE ON nanosiem.lookup_rows")
            {
                let grant = "ALTER DELETE ON nanosiem.lookup_rows";
                tracing::error!(error = %e, "ClickHouse permission missing: {grant}");
                ApiError::InternalError(format!("ClickHouse permission missing: {grant}"))
            } else {
                tracing::error!(error = %e, "Lookup repository error");
                ApiError::InternalError("A database error occurred".to_string())
            }
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
        nanosiem_core::UploadParserConfig,
        nanosiem_core::FileFormat,
    ))
)]
pub struct LookupApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referenced_lookup_is_a_conflict_with_rule_names() {
        let error = lookup_error_to_api(LookupError::TableInUse("Suspicious login".into()));
        assert!(matches!(error, ApiError::Conflict(message) if message.contains("Suspicious login")));
    }

    #[test]
    fn database_reference_conflict_is_not_a_server_error() {
        assert!(matches!(lookup_error_to_api(LookupError::ReferenceConflict), ApiError::Conflict(_)));
    }

    #[test]
    fn missing_lookup_rows_delete_grant_is_actionable() {
        let error = LookupError::RepositoryError(
            "Code: 497. DB::Exception: Not enough privileges. To execute this query, it's necessary to have the grant ALTER DELETE ON nanosiem.lookup_rows. (ACCESS_DENIED)".into(),
        );
        assert!(matches!(
            lookup_error_to_api(error),
            ApiError::InternalError(message)
                if message == "ClickHouse permission missing: ALTER DELETE ON nanosiem.lookup_rows"
        ));
    }
}

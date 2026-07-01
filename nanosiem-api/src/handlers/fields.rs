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
use nanosiem_core::TimeRangeInput;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

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
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;

    let time_range = query.time_range();

    {
        let ch_client = state.dual_pool.clickhouse();

        // Resolve the FROM table from the active schema profile (OCSF Phase 7,
        // NAN-1241) so the source picker queries `ocsf_logs` under the OCSF
        // profile and `logs` under UDM. The profile's fully-qualified
        // `table_name()` (`nanosiem.ocsf_logs` / `nanosiem.logs`) is reduced to
        // its bare key and re-resolved through the tenant/cluster-aware
        // `table_names` registry, so `_distributed` read routing applies
        // identically to both — same mechanism `SearchService` uses.
        let profile = state.config.schema_profile();
        let table = state
            .dual_pool
            .table_names()
            .read(profile.table_name().trim_start_matches("nanosiem."));

        // Both profiles expose `source_type` and a `timestamp` column, so only
        // the FROM target varies between schemas here.
        let sql = format!(
            r#"
            SELECT source_type, count(*) as count
            FROM {}
            WHERE timestamp >= '{}'
              AND timestamp < '{}'
              AND source_type != ''
            GROUP BY source_type
            ORDER BY count DESC
            "#,
            table,
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

/// Query parameters for the ext-field-names endpoint.
///
/// All optional. With `query` + both bounds, enumeration is scoped to that
/// search's predicate (the fields picker, NAN-1510) so listed keys match what a
/// field expand can return; with bounds only, the search window (NAN-1505);
/// absent, a bounded recent window (the syntax-highlighter path).
#[derive(Debug, Deserialize, IntoParams)]
pub struct ExtFieldsQuery {
    /// nPL search query to scope enumeration to (matches the per-field value fetch)
    pub query: Option<String>,
    /// Start of the search time range (ISO 8601)
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// End of the search time range (ISO 8601)
    pub end: Option<chrono::DateTime<chrono::Utc>>,
}

/// Get ext field names discovered in the data.
/// Used by the fields picker (scoped to the search query+window) and to enable
/// syntax highlighting for non-UDM fields (no params → recent window).
#[utoipa::path(
    get,
    path = "/api/fields/ext",
    tag = "fields",
    params(ExtFieldsQuery),
    responses(
        (status = 200, description = "List of ext field names", body = Vec<String>),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_ext_fields(
    State(state): State<AppState>,
    Query(params): Query<ExtFieldsQuery>,
) -> Result<Json<Vec<String>>, ApiError> {
    // Only scope when BOTH bounds are present; a half-specified range falls back
    // to the recent default rather than silently using "now" for the missing end.
    let time_range = match (params.start, params.end) {
        (Some(start), Some(end)) => Some(TimeRangeInput::new(start, end)),
        _ => None,
    };
    let names = state
        .search_service
        .get_ext_field_names(params.query.as_deref(), time_range.as_ref())
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get ext field names: {}", e)))?;
    Ok(Json(names))
}

/// A single field in the active schema profile's queryable universe.
///
/// Profile-agnostic (OCSF Phase 3b, NAN-1241): the shape is the same whether the
/// deployment runs UDM or OCSF — only the discriminator + the field set differ.
#[derive(Debug, Serialize, ToSchema)]
pub struct SchemaFieldInfo {
    /// Canonical field name as typed in nPL (e.g. `src_ip`, `src_endpoint.ip`).
    pub name: String,
    /// Value type (`string`, `ip_address`, `integer`, `uuid`, ...).
    pub r#type: String,
    /// Coarse category for grouping/UX (`network`, `authentication`, ...).
    pub category: String,
    /// Security entity the field denotes, if any (`ip`, `host`, `user`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    /// Whether the field is PREWHERE/index-eligible for the active profile.
    pub prewhere: bool,
    /// Whether the profile exposes a `_search`/`.search` full-text companion for
    /// this field (UDM today exposes none in the field universe; reserved for
    /// OCSF's declared search companions).
    pub search: bool,
}

/// Response for the profile-aware `GET /api/schema/fields` endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct SchemaFieldsResponse {
    /// The active schema discriminator (`udm` | `ocsf`) — lets the frontend
    /// hydrate its field universe and report the deployment's schema.
    pub schema: String,
    /// The active profile's full field universe.
    pub fields: Vec<SchemaFieldInfo>,
}

/// Get the active schema profile's field universe.
///
/// Profile-aware replacement for `/api/udm/fields` (OCSF Phase 3b, NAN-1241):
/// returns the field set of whatever schema the deployment booted with
/// (`NANO_SCHEMA_PROFILE`), so the frontend can discover fields and report the
/// active schema without assuming UDM. Additive — `/api/udm/fields` is retained
/// (Phase 7 retires it).
#[utoipa::path(
    get,
    path = "/api/schema/fields",
    tag = "fields",
    responses(
        (status = 200, description = "Active schema profile field universe", body = SchemaFieldsResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_schema_fields(
    State(state): State<AppState>,
) -> Result<Json<SchemaFieldsResponse>, ApiError> {
    Ok(Json(build_schema_fields_response(
        state.config.schema_profile().as_ref(),
    )))
}

/// Build the `/api/schema/fields` response from a schema profile.
///
/// Pure (no I/O) so it is unit-testable against any profile without a live
/// AppState/DualPool. The handler is a thin wrapper that resolves the active
/// profile from config and delegates here.
fn build_schema_fields_response(
    profile: &dyn nanosiem_core::schema::SchemaProfile,
) -> SchemaFieldsResponse {
    // PREWHERE-eligible set, looked up O(1) per field.
    let prewhere: std::collections::HashSet<&str> =
        profile.prewhere_fields().iter().copied().collect();
    // Field-universe set, so a `{name}_search` companion can be detected without
    // a dedicated trait method (the profile declares its own search companions as
    // fields; UDM declares none, OCSF may declare `.search` siblings).
    let universe: std::collections::HashSet<&str> =
        profile.fields().iter().map(|f| f.name).collect();

    let fields = profile
        .fields()
        .iter()
        .map(|f| {
            let search_companion = format!("{}_search", f.name);
            SchemaFieldInfo {
                name: f.name.to_string(),
                r#type: serde_field_value(&f.field_type),
                category: serde_field_value(&f.category),
                entity_type: f.entity_type.as_ref().map(serde_field_value),
                prewhere: prewhere.contains(f.name),
                search: universe.contains(search_companion.as_str()),
            }
        })
        .collect();

    SchemaFieldsResponse {
        schema: serde_field_value(&profile.id()),
        fields,
    }
}

/// Render a `#[serde(rename_all = "snake_case")]` enum to its wire string
/// (e.g. `FieldType::IpAddress` → `"ip_address"`) by reusing its `Serialize`
/// impl, so the API surface matches the schema-core vocabulary exactly and never
/// drifts from a hand-maintained `match`.
fn serde_field_value<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_string))
        .unwrap_or_default()
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
        get_field_values,
        get_source_types,
        get_ext_fields,
        get_udm_fields,
        get_schema_fields,
    ),
    components(
        schemas(
            FieldValuesResponse,
            FieldValue,
            UdmFieldsResponse,
            UdmFieldInfo,
            SchemaFieldsResponse,
            SchemaFieldInfo,
        )
    ),
    tags(
        (name = "fields", description = "Field metadata and value endpoints")
    )
)]
pub struct FieldsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::schema::{OcsfProfile, SchemaProfile, UdmProfile};

    #[test]
    fn schema_fields_returns_udm_universe_and_discriminator() {
        let profile = UdmProfile::new();
        let resp = build_schema_fields_response(&profile);

        assert_eq!(resp.schema, "udm");
        // Reports the full active-profile field universe.
        assert_eq!(resp.fields.len(), profile.fields().len());
        assert!(!resp.fields.is_empty());

        // A known UDM field is present with its entity type + a sane type string.
        let src_ip = resp
            .fields
            .iter()
            .find(|f| f.name == "src_ip")
            .expect("src_ip should be in the UDM universe");
        assert_eq!(src_ip.r#type, "ip_address");
        assert_eq!(src_ip.entity_type.as_deref(), Some("ip"));
        // src_ip is PREWHERE-eligible for UDM.
        assert!(src_ip.prewhere, "src_ip should be PREWHERE-eligible");

        // The `prewhere` flag tracks the profile's prewhere set exactly.
        let prewhere: std::collections::HashSet<&str> =
            profile.prewhere_fields().iter().copied().collect();
        for f in &resp.fields {
            assert_eq!(
                f.prewhere,
                prewhere.contains(f.name.as_str()),
                "prewhere flag disagreed with profile for {}",
                f.name
            );
        }
    }

    #[test]
    fn schema_fields_reports_ocsf_discriminator() {
        // The discriminator follows the active profile, not a hardcoded "udm".
        let resp = build_schema_fields_response(&OcsfProfile::new());
        assert_eq!(resp.schema, "ocsf");
        assert!(!resp.fields.is_empty());
    }
}

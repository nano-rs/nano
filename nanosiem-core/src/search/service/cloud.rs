// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SearchService {
    /// Cloud event page size for paginated events
    const CLOUD_EVENT_PAGE_SIZE: usize = 200;

    /// Build a parameterized IN clause for a cloud filter field.
    ///
    /// Pushes a `column IN (?, ?, ...)` condition into `conditions` and the
    /// corresponding values into `bind_values`.  No-ops when `vals` is None or empty.
    fn build_cloud_in_filter(
        column: &str,
        vals: &Option<Vec<String>>,
        conditions: &mut Vec<String>,
        bind_values: &mut Vec<String>,
    ) {
        if let Some(ref vs) = vals {
            if !vs.is_empty() {
                let placeholders = vec!["?"; vs.len()].join(",");
                conditions.push(format!("{} IN ({})", column, placeholders));
                bind_values.extend(vs.iter().cloned());
            }
        }
    }

    /// Build the base CTE string for cloud queries.
    ///
    /// Both `build_cloud_view()` and `query_cloud_events_paginated()` need the same
    /// CTE construction logic: parse the nPL query, generate SQL, wrap as a CTE.
    /// Returns `Ok(cte_string)` where cte_string is `"cloud_base AS (SELECT ...)"`,
    /// or `Err(SearchError)` if SQL generation fails.
    fn build_cloud_base_cte(
        &self,
        query_str: &str,
        time_range: &TimeRange,
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
                // Fallback: just use time range filter
                let logs_table = self.table_names.read("logs");
                format!(
                    "SELECT * FROM {logs_table} PREWHERE timestamp BETWEEN '{}' AND '{}' ORDER BY timestamp DESC",
                    time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                    time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                )
            }
        };

        // MATERIALIZED columns are excluded from SELECT * in ClickHouse.
        // Cloud user-timeline and entity-pivot queries need enrichment/IOC columns,
        // so inject them into the base SELECT.
        let materialized_cols = ", enriched_src_country, enriched_src_country_code, \
            enriched_src_asn, enriched_src_as_name, enriched_src_as_domain, \
            enriched_dest_country, enriched_dest_country_code, \
            enriched_dest_asn, enriched_dest_as_name, enriched_dest_as_domain, \
            ioc_src_ip_threat_type, ioc_src_ip_malware, ioc_src_ip_confidence, \
            ioc_dest_ip_threat_type, ioc_dest_ip_malware, ioc_dest_ip_confidence, \
            ioc_domain_threat_type, ioc_domain_malware, ioc_domain_confidence, \
            ioc_hash_threat_type, ioc_hash_malware, ioc_hash_confidence, \
            ioc_confidence, ioc_tags, ioc_source";
        let mut sql = base_sql.trim_end_matches(';').to_string();
        if !sql.contains("enriched_src_country_code") {
            sql = sql.replacen("SELECT *", &format!("SELECT *{}", materialized_cols), 1);
        }

        Ok(format!("cloud_base AS ({})", sql))
    }

    /// Maximum time-range duration for `| cloud` queries. Like asset view,
    /// cloud view does heavy faceted aggregation + resource activity rollups
    /// + MFA analysis across the full window — capping keeps it usable for
    /// focused investigation rather than bulk scans.
    pub(crate) const MAX_CLOUD_VIEW_HOURS: i64 = 6;

    /// Build a cloud investigation view with faceted summaries, resource activity, and MFA analysis
    pub(crate) async fn build_cloud_view(
        &self,
        _results: Vec<serde_json::Value>,
        cloud_info: &CloudCommandInfo,
        time_range: &TimeRange,
        cleaned_query: &str,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        use serde_json::json;

        // Reject overly-wide ranges before doing any expensive work.
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
        let base_cte = match self.build_cloud_base_cte(cleaned_query, time_range) {
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

        // 1. Facet summary query — UNION ALL for 6 dimensions
        let facet_dimensions = [
            ("cloud_provider", "cloud_provider"),
            ("cloud_service", "cloud_service"),
            ("cloud_region", "cloud_region"),
            ("cloud_account_id", "cloud_account_id"),
            ("resource_type", "resource_type"),
            ("change_type", "change_type"),
        ];
        let facet_unions: Vec<String> = facet_dimensions.iter().map(|(dim_name, col)| {
            format!(
                "SELECT '{}' AS dimension, toString({}) AS value, count() AS cnt FROM cloud_base WHERE {} != '' GROUP BY {} ORDER BY cnt DESC LIMIT 20",
                dim_name, col, col, col
            )
        }).collect();
        let facet_sql = format!("WITH {} {}", base_cte, facet_unions.join(" UNION ALL "));

        // 2. Paginated events query
        let events_sql = format!(
            r#"WITH {}
            SELECT timestamp, cloud_provider, cloud_service, cloud_region, cloud_account_id,
                   resource_id, resource_name, resource_type, change_type, mfa_used,
                   user, src_ip, http_user_agent, source_type, action AS event_type,
                   status, http_status_code
            FROM cloud_base
            ORDER BY timestamp DESC
            LIMIT {} OFFSET 0"#,
            base_cte,
            Self::CLOUD_EVENT_PAGE_SIZE
        );

        // 3. Total count query
        let count_sql = format!("WITH {} SELECT count() AS cnt FROM cloud_base", base_cte);

        // 4. Resource activity query
        let resources_sql = format!(
            r#"WITH {}
            SELECT resource_id, any(resource_name) AS resource_name, any(resource_type) AS resource_type,
                   count() AS event_count,
                   toString(min(timestamp)) AS first_seen,
                   toString(max(timestamp)) AS last_seen,
                   groupUniqArray(change_type) AS change_types
            FROM cloud_base
            WHERE resource_id != ''
            GROUP BY resource_id
            ORDER BY event_count DESC
            LIMIT 100"#,
            base_cte
        );

        // 5. Optional MFA analysis query
        let mfa_sql = if cloud_info.show_mfa {
            Some(format!(
                r#"WITH {}
                SELECT user, groupUniqArray(cloud_service) AS services,
                       countIf(mfa_used = 1) AS mfa_count,
                       countIf(mfa_used = 0) AS no_mfa_count
                FROM cloud_base
                WHERE user != '' AND (mfa_used = 0 OR mfa_used = 1)
                GROUP BY user
                HAVING no_mfa_count > 0
                ORDER BY no_mfa_count DESC
                LIMIT 50"#,
                base_cte
            ))
        } else {
            None
        };

        // Execute queries in parallel
        let facet_future = async {
            match clickhouse
                .query(&facet_sql)
                .fetch_all::<(String, String, u64)>()
                .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!("Cloud facet query failed: {}", e);
                    Vec::new()
                }
            }
        };

        let events_future = async {
            let mut events: Vec<serde_json::Value> = Vec::new();
            let mut cursor = match clickhouse.query(&events_sql).fetch_bytes("JSONEachRow") {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Cloud events query failed: {}", e);
                    return events;
                }
            };
            let mut response_bytes = Vec::new();
            while let Ok(Some(chunk)) = cursor.next().await {
                response_bytes.extend_from_slice(&chunk);
            }
            if let Ok(response_str) = String::from_utf8(response_bytes) {
                events = response_str
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
            }
            events
        };

        let count_future = async {
            match clickhouse.query(&count_sql).fetch_one::<u64>().await {
                Ok(cnt) => cnt,
                Err(e) => {
                    tracing::warn!("Cloud count query failed: {}", e);
                    0u64
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
                Ok(rows) => rows
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
                    .collect(),
                Err(e) => {
                    tracing::warn!("Cloud resource query failed: {}", e);
                    Vec::new()
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
                    Ok(rows) => Some(
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
                    ),
                    Err(e) => {
                        tracing::warn!("Cloud MFA query failed: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        };

        // 6. User activity query (from pre-aggregated MV)
        let user_activity_sql = format!(
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
                SELECT DISTINCT user
                FROM cloud_base
                WHERE user != ''
            ) AS cb ON ua.user = cb.user
            WHERE ua.time_bucket >= toStartOfHour(toDateTime('{}'))
              AND ua.time_bucket <= '{}'
            GROUP BY cb.user
            ORDER BY event_count DESC
            LIMIT 200"#,
            base_cte,
            time_range.start.format("%Y-%m-%d %H:%M:%S"),
            time_range.end.format("%Y-%m-%d %H:%M:%S"),
            cloud_user_activity_table = self.table_names.read("cloud_user_activity_agg"),
        );

        let user_activity_future = async {
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
                .query(&user_activity_sql)
                .fetch_all::<UserActivityRow>()
                .await
            {
                Ok(rows) => {
                    rows.into_iter()
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
                        .collect::<Vec<_>>()
                }
                Err(e) => {
                    tracing::warn!("Cloud user activity query failed: {}", e);
                    Vec::new()
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
        // Same cap as build_cloud_view — prevents bypassing the limit via the
        // pagination endpoint with offset 0.
        let max_secs = Self::MAX_CLOUD_VIEW_HOURS * 3600;
        if (time_range.end - time_range.start).num_seconds() > max_secs {
            return Err(SearchError::SqlValidationError(format!(
                "Cloud view queries are limited to {}h.",
                Self::MAX_CLOUD_VIEW_HOURS
            )));
        }

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok((Vec::new(), 0, CloudFacets::default(), None, None)),
        };

        // Build base CTE using shared helper
        let base_cte = match self.build_cloud_base_cte(query_str, time_range) {
            Ok(cte) => cte,
            Err(e) => {
                tracing::warn!("Cloud paginated CTE build failed: {}", e);
                return Ok((Vec::new(), 0, CloudFacets::default(), None, None));
            }
        };

        // Build filter conditions from CloudEventFilters
        let mut filter_conditions: Vec<String> = Vec::new();
        let mut filter_bind_values: Vec<String> = Vec::new();
        if let Some(f) = filters {
            Self::build_cloud_in_filter(
                "cloud_provider",
                &f.cloud_providers,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            Self::build_cloud_in_filter(
                "cloud_service",
                &f.cloud_services,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            Self::build_cloud_in_filter(
                "cloud_region",
                &f.cloud_regions,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            Self::build_cloud_in_filter(
                "cloud_account_id",
                &f.cloud_account_ids,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            Self::build_cloud_in_filter(
                "resource_type",
                &f.resource_types,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            Self::build_cloud_in_filter(
                "change_type",
                &f.change_types,
                &mut filter_conditions,
                &mut filter_bind_values,
            );
            if let Some(ref search_text) = f.search_text {
                if !search_text.is_empty() {
                    let lowered = search_text.to_lowercase();
                    // Use lower(message) with expression-based text index for the heaviest field.
                    // Other fields are short/sparse so position(lower(...)) is fine.
                    // Each ? is a separate positional bind, so we push the value 7 times.
                    filter_conditions.push(
                        "( \
                            position(lower(message), ?) > 0 \
                            OR position(lower(action), ?) > 0 \
                            OR position(lower(user), ?) > 0 \
                            OR position(lower(src_ip), ?) > 0 \
                            OR (resource_id != '' AND position(lower(resource_id), ?) > 0) \
                            OR (resource_name != '' AND position(lower(resource_name), ?) > 0) \
                            OR (http_user_agent != '' AND position(lower(http_user_agent), ?) > 0) \
                        )"
                        .to_string(),
                    );
                    for _ in 0..7 {
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
                ("cloud_provider", "cloud_provider"),
                ("cloud_service", "cloud_service"),
                ("cloud_region", "cloud_region"),
                ("cloud_account_id", "cloud_account_id"),
                ("resource_type", "resource_type"),
                ("change_type", "change_type"),
            ];
            let facet_unions: Vec<String> = facet_dimensions.iter().map(|(dim_name, col)| {
                format!(
                    "SELECT '{}' AS dimension, toString({}) AS value, count() AS cnt FROM {} WHERE {} != '' GROUP BY {} ORDER BY cnt DESC LIMIT 20",
                    dim_name, col, source_table, col, col
                )
            }).collect();
            Some(format!(
                "{} {}",
                filtered_cte,
                facet_unions.join(" UNION ALL ")
            ))
        } else {
            None
        };

        // 2. Paginated events query
        let events_sql = format!(
            r#"{}
            SELECT timestamp, cloud_provider, cloud_service, cloud_region, cloud_account_id,
                   resource_id, resource_name, resource_type, change_type, mfa_used,
                   user, src_ip, http_user_agent, source_type, action AS event_type,
                   status, http_status_code
            FROM {}
            ORDER BY timestamp DESC
            LIMIT {} OFFSET {}"#,
            filtered_cte, source_table, limit, offset
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

        let resources_sql = if include_panels {
            Some(format!(
                r#"{}
                SELECT resource_id, any(resource_name) AS resource_name, any(resource_type) AS resource_type,
                       count() AS event_count,
                       toString(min(timestamp)) AS first_seen,
                       toString(max(timestamp)) AS last_seen,
                       groupUniqArray(change_type) AS change_types
                FROM {}
                WHERE resource_id != ''
                GROUP BY resource_id
                ORDER BY event_count DESC
                LIMIT 100"#,
                filtered_cte, source_table
            ))
        } else {
            None
        };

        let cloud_user_activity_table = self.table_names.read("cloud_user_activity_agg");
        let user_activity_sql = if include_panels {
            Some(format!(
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
                    SELECT DISTINCT user
                    FROM {}
                    WHERE user != ''
                ) AS cb ON ua.user = cb.user
                WHERE ua.time_bucket >= toStartOfHour(toDateTime('{}'))
                  AND ua.time_bucket <= '{}'
                GROUP BY cb.user
                ORDER BY event_count DESC
                LIMIT 200"#,
                filtered_cte,
                source_table,
                time_range.start.format("%Y-%m-%d %H:%M:%S"),
                time_range.end.format("%Y-%m-%d %H:%M:%S"),
            ))
        } else {
            None
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
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::warn!("Cloud paginated facet query failed: {}", e);
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            }
        };

        let events_future = async {
            let mut events: Vec<serde_json::Value> = Vec::new();
            let mut q = clickhouse.query(&events_sql);
            for val in &filter_bind_values {
                q = q.bind(val);
            }
            let mut cursor = match q.fetch_bytes("JSONEachRow") {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Cloud paginated events query failed: {}", e);
                    return events;
                }
            };
            let mut response_bytes = Vec::new();
            while let Ok(Some(chunk)) = cursor.next().await {
                response_bytes.extend_from_slice(&chunk);
            }
            if let Ok(response_str) = String::from_utf8(response_bytes) {
                events = response_str
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
            }
            events
        };

        let count_future = async {
            let mut q = clickhouse.query(&count_sql);
            for val in &filter_bind_values {
                q = q.bind(val);
            }
            match q.fetch_one::<u64>().await {
                Ok(cnt) => cnt,
                Err(e) => {
                    tracing::warn!("Cloud paginated count query failed: {}", e);
                    0u64
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
                    Ok(rows) => Some(
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
                    ),
                    Err(e) => {
                        tracing::warn!("Cloud paginated resource query failed: {}", e);
                        None
                    }
                }
            } else {
                None
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
                    Ok(rows) => Some(
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
                    ),
                    Err(e) => {
                        tracing::warn!("Cloud paginated user activity query failed: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        };

        let (facet_rows, events, total_count, resources, user_activity) = tokio::join!(
            facet_future,
            events_future,
            count_future,
            resources_future,
            user_activity_future
        );

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

        let base_cte = self.build_cloud_base_cte(query_str, time_range)?;
        let user_bind = user.to_string();

        // 1. Events for this user (ASC order, limit 5000)
        let events_sql = format!(
            r#"WITH {}
            SELECT timestamp, cloud_provider, cloud_service, cloud_region, cloud_account_id,
                   resource_id, resource_name, resource_type, change_type, mfa_used,
                   user, src_ip, http_user_agent, source_type, action AS event_type,
                   status, http_status_code,
                   enriched_src_country_code, enriched_src_asn, enriched_src_as_name,
                   ioc_src_ip_threat_type, ioc_src_ip_malware, ioc_src_ip_confidence
            FROM cloud_base
            WHERE user = ?
            ORDER BY timestamp ASC
            LIMIT 5000"#,
            base_cte
        );

        // 2. Session summary aggregates
        let summary_sql = format!(
            r#"WITH {}
            SELECT
                groupUniqArray(cloud_service) AS services,
                groupUniqArray(cloud_region) AS regions,
                groupUniqArray(src_ip) AS ips,
                count() AS event_count,
                countIf(http_status_code >= 400) AS fail_count,
                countIf(change_type = 'permission_change') AS permission_change_count,
                countIf(change_type = 'delete') AS delete_count,
                countIf(mfa_used = 0) AS no_mfa_count
            FROM cloud_base
            WHERE user = ?"#,
            base_cte
        );

        let events_future = async {
            let mut events: Vec<serde_json::Value> = Vec::new();
            let mut cursor = match clickhouse
                .query(&events_sql)
                .bind(&user_bind)
                .fetch_bytes("JSONEachRow")
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Cloud user timeline events query failed: {}", e);
                    return events;
                }
            };
            let mut response_bytes = Vec::new();
            while let Ok(Some(chunk)) = cursor.next().await {
                response_bytes.extend_from_slice(&chunk);
            }
            if let Ok(response_str) = String::from_utf8(response_bytes) {
                events = response_str
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
            }
            events
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
            match clickhouse
                .query(&summary_sql)
                .bind(&user_bind)
                .fetch_optional::<SummaryRow>()
                .await
            {
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
                    CloudUserSessionSummary {
                        services: r.services,
                        regions: r.regions,
                        ips: r.ips,
                        event_count: r.event_count,
                        fail_count: r.fail_count,
                        permission_change_count: r.permission_change_count,
                        delete_count: r.delete_count,
                        has_no_mfa: r.no_mfa_count > 0,
                        risk_indicators,
                    }
                }
                _ => CloudUserSessionSummary {
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
            }
        };

        let (events, summary) = tokio::join!(events_future, summary_future);

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

        let base_cte = self.build_cloud_base_cte(query_str, time_range)?;
        let entity_val = entity_value.to_string();

        tracing::info!(
            entity_type = entity_type,
            entity_value = entity_value,
            "Cloud entity pivot: searching for entity"
        );

        // Build parameterized entity filter — returns (sql_fragment, bind_values)
        let (entity_filter, entity_binds) = match entity_type {
            "user" => ("user = ?".to_string(), vec![entity_val.clone()]),
            "ip" => ("src_ip = ?".to_string(), vec![entity_val.clone()]),
            "resource" => (
                "(lower(resource_id) = lower(?) OR lower(resource_name) = lower(?))".to_string(),
                vec![entity_val.clone(), entity_val.clone()],
            ),
            _ => unreachable!(),
        };

        // Cross-ref queries use the entity filter twice (two UNION ALL branches),
        // so we need the bind values repeated.
        let xref_binds: Vec<String> = entity_binds
            .iter()
            .chain(entity_binds.iter())
            .cloned()
            .collect();

        // 1. Events for this entity (ASC, limit 5000)
        let events_sql = format!(
            r#"WITH {}
            SELECT timestamp, cloud_provider, cloud_service, cloud_region, cloud_account_id,
                   resource_id, resource_name, resource_type, change_type, mfa_used,
                   user, src_ip, http_user_agent, source_type, action AS event_type,
                   status, http_status_code,
                   enriched_src_country_code, enriched_src_asn, enriched_src_as_name,
                   ioc_src_ip_threat_type, ioc_src_ip_malware, ioc_src_ip_confidence
            FROM cloud_base
            WHERE {}
            ORDER BY timestamp ASC
            LIMIT 5000"#,
            base_cte, entity_filter
        );

        // 2. Cross-references: find related entities
        let xref_sql = match entity_type {
            "user" => format!(
                r#"WITH {}
                SELECT 'ip' AS entity_type, src_ip AS entity_value, count() AS event_count
                FROM cloud_base WHERE {} AND src_ip != ''
                GROUP BY src_ip ORDER BY event_count DESC LIMIT 50
                UNION ALL
                SELECT 'resource' AS entity_type, resource_id AS entity_value, count() AS event_count
                FROM cloud_base WHERE {} AND resource_id != ''
                GROUP BY resource_id ORDER BY event_count DESC LIMIT 50"#,
                base_cte, entity_filter, entity_filter
            ),
            "ip" => format!(
                r#"WITH {}
                SELECT 'user' AS entity_type, user AS entity_value, count() AS event_count
                FROM cloud_base WHERE {} AND user != ''
                GROUP BY user ORDER BY event_count DESC LIMIT 50
                UNION ALL
                SELECT 'resource' AS entity_type, resource_id AS entity_value, count() AS event_count
                FROM cloud_base WHERE {} AND resource_id != ''
                GROUP BY resource_id ORDER BY event_count DESC LIMIT 50"#,
                base_cte, entity_filter, entity_filter
            ),
            "resource" => format!(
                r#"WITH {}
                SELECT 'user' AS entity_type, user AS entity_value, count() AS event_count
                FROM cloud_base WHERE {} AND user != ''
                GROUP BY user ORDER BY event_count DESC LIMIT 50
                UNION ALL
                SELECT 'ip' AS entity_type, src_ip AS entity_value, count() AS event_count
                FROM cloud_base WHERE {} AND src_ip != ''
                GROUP BY src_ip ORDER BY event_count DESC LIMIT 50"#,
                base_cte, entity_filter, entity_filter
            ),
            _ => unreachable!(),
        };

        // 3. Entity summary
        let summary_sql = format!(
            r#"WITH {}
            SELECT
                count() AS event_count,
                countIf(http_status_code >= 400) AS fail_count,
                toString(min(timestamp)) AS first_seen,
                toString(max(timestamp)) AS last_seen,
                groupUniqArray(change_type) AS change_types,
                groupUniqArray(cloud_service) AS services
            FROM cloud_base
            WHERE {}"#,
            base_cte, entity_filter
        );

        let events_future = async {
            let mut events: Vec<serde_json::Value> = Vec::new();
            let mut q = clickhouse.query(&events_sql);
            for val in &entity_binds {
                q = q.bind(val);
            }
            let mut cursor = match q.fetch_bytes("JSONEachRow") {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Cloud entity pivot events query failed: {}", e);
                    return events;
                }
            };
            let mut response_bytes = Vec::new();
            while let Ok(Some(chunk)) = cursor.next().await {
                response_bytes.extend_from_slice(&chunk);
            }
            if let Ok(response_str) = String::from_utf8(response_bytes) {
                events = response_str
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
            }
            events
        };

        let xref_future = async {
            let mut q = clickhouse.query(&xref_sql);
            for val in &xref_binds {
                q = q.bind(val);
            }
            match q.fetch_all::<(String, String, u64)>().await {
                Ok(rows) => rows
                    .into_iter()
                    .map(|(et, ev, ec)| EntityCrossReference {
                        entity_type: et,
                        entity_value: ev,
                        event_count: ec,
                    })
                    .collect(),
                Err(e) => {
                    tracing::warn!("Cloud entity pivot cross-ref query failed: {}", e);
                    Vec::new()
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
                Ok(Some(r)) => json!({
                    "event_count": r.event_count,
                    "fail_count": r.fail_count,
                    "first_seen": r.first_seen,
                    "last_seen": r.last_seen,
                    "change_types": r.change_types,
                    "services": r.services,
                }),
                _ => json!({}),
            }
        };

        let (events, cross_references, entity_summary) =
            tokio::join!(events_future, xref_future, summary_future);

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

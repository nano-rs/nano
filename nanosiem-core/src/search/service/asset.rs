// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SearchService {
    /// Default page size for asset events
    const ASSET_EVENT_PAGE_SIZE: usize = 200;

    /// Slim column list for asset timeline queries.
    /// Covers everything detect_event_type, build_event_summary, and getInlineFields need,
    /// avoiding the full 130+ column SELECT * to reduce payload size by ~80-90%.
    const ASSET_TIMELINE_COLUMNS: &'static str = "\
        id, timestamp, _inserted_at, ingest_time, source_type, vendor_product, namespace, \
        message, category, \
        src_ip, dest_ip, src_host, dest_host, src_port, dest_port, src_mac, \
        protocol, bytes_in, bytes_out, duration, user, action, status, severity, \
        auth_type, auth_result, \
        process_name, command_line, process_id, parent_command_line, \
        parent_process_name, parent_process_id, process_hash, process_path, \
        file_name, file_path, file_hash, file_action, \
        query, query_type, answer, url, url_domain, uri_path, \
        http_method, http_status_code, http_user_agent, http_content_type, \
        registry_path, registry_value_data, signature, signature_id, \
        rule_name, mitre_technique_id, \
        enriched_src_country, enriched_src_asn, enriched_dest_country, enriched_dest_asn, \
        prevalence_min";

    /// CASE WHEN expression that classifies log events into broad categories.
    /// Used by both the facet aggregation query and the event_type filter condition.
    /// Definition is shared with the asset-dossier lane classifier — see
    /// [`crate::search::classification`] for the single source of truth.
    const EVENT_TYPE_CASE_WHEN: &'static str = crate::search::classification::EVENT_TYPE_SQL;

    /// Build asset view from search results
    ///
    /// This method:
    /// 1. Detects or uses the specified identifier field (src_host, src_ip, user, mac)
    /// 2. Resolves all related identities using identity_observations table with time bounds
    /// 3. Queries first page of events with facet counts for filtering
    /// 4. Returns results with _display_type, _asset_profile, _asset_events (first page), and _asset_pagination
    /// Maximum time-range duration for `| asset` queries. Asset view does heavy
    /// per-event timeline + dossier aggregation + identity resolution, so we
    /// cap it to keep response times sane. Users hitting this should narrow
    /// their range or use the broader search/dashboard surfaces.
    pub(crate) const MAX_ASSET_VIEW_HOURS: i64 = 6;

    pub(crate) async fn build_asset_view(
        &self,
        results: Vec<serde_json::Value>,
        asset_info: &AssetCommandInfo,
        time_range: &TimeRange,
        pre_extracted_identifier: Option<(String, String)>,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        use serde_json::json;

        // Reject overly-wide ranges before doing any expensive work.
        let max_secs = Self::MAX_ASSET_VIEW_HOURS * 3600;
        if (time_range.end - time_range.start).num_seconds() > max_secs {
            return Err(SearchError::SqlValidationError(format!(
                "Asset view queries are limited to {}h. Reduce your time range — asset view runs heavy aggregation across the full window and is meant for focused investigation, not bulk scans.",
                Self::MAX_ASSET_VIEW_HOURS
            )));
        }

        let start_time = std::time::Instant::now();
        tracing::info!(
            "Asset view building started: {} events, identifier_field={:?}, pre_extracted={:?}",
            results.len(),
            asset_info.identifier_field,
            pre_extracted_identifier
        );

        // If no pre-extracted identifier and results are empty, return empty asset
        if results.is_empty() && pre_extracted_identifier.is_none() {
            return Ok(vec![json!({
                "_display_type": "asset",
                "_asset_profile": {
                    "primary_identifier": null,
                    "identities": [],
                    "first_seen": null,
                    "last_seen": null,
                },
                "_asset_events": [],
                "_asset_pagination": {
                    "total_count": 0,
                    "offset": 0,
                    "limit": Self::ASSET_EVENT_PAGE_SIZE,
                    "has_more": false,
                    "facets": {
                        "source_type": [],
                        "event_type": [],
                        "user": []
                    }
                }
            })]);
        }

        // Step 1: Use pre-extracted identifier or detect from results
        let (identifier_field, identifier_value) = if let Some(pre_id) = pre_extracted_identifier {
            pre_id
        } else {
            self.detect_asset_identifier(&results, asset_info)?
        };
        tracing::info!(
            "Asset identifier: {}={}",
            identifier_field,
            identifier_value
        );

        // Step 2: Resolve all related identities with time bounds
        let identities = self
            .resolve_asset_identities(
                &identifier_field,
                &identifier_value,
                time_range,
                asset_info.max_identity_age,
            )
            .await?;
        tracing::info!("Resolved {} identities for asset", identities.len());

        // Step 3: Query paginated events (facets + first page).
        // Artifact summary and true time range are fetched lazily by the frontend
        // via separate endpoints — they don't block the initial render.
        let (paginated_events, total_count, facets) = self
            .query_asset_events_paginated(
                &identifier_field,
                &identifier_value,
                &identities,
                time_range,
                0,
                Self::ASSET_EVENT_PAGE_SIZE,
                None,
            )
            .await?;
        tracing::info!(
            "Asset paginated query: {} events of {} total",
            paginated_events.len(),
            total_count
        );

        // Transform raw events into timeline-friendly format
        let asset_events: Vec<serde_json::Value> = paginated_events
            .iter()
            .enumerate()
            .map(|(i, event)| {
                let id = event
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("event-{}", i));

                let timestamp = event
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let source_type = event
                    .get("source_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                // Determine event_type based on fields present
                let event_type = self.detect_event_type(event);

                // Build summary from event fields
                let summary = self.build_event_summary(event, &event_type);

                json!({
                    "id": id,
                    "timestamp": timestamp,
                    "source_type": source_type,
                    "event_type": event_type,
                    "summary": summary,
                    "details": event,
                })
            })
            .collect();

        let has_more = asset_events.len() < total_count as usize;

        // Build the final asset view response with paginated events
        let asset_view = json!({
            "_display_type": "asset",
            "_asset_profile": {
                "primary_identifier": {
                    "field": identifier_field,
                    "value": identifier_value,
                },
                "identities": identities,
                "first_seen": null,
                "last_seen": null,
            },
            "_asset_events": asset_events,
            "_asset_pagination": {
                "total_count": total_count,
                "offset": 0,
                "limit": Self::ASSET_EVENT_PAGE_SIZE,
                "has_more": has_more,
                "facets": facets
            }
        });

        tracing::info!(
            "Asset view building completed in {:?}",
            start_time.elapsed()
        );
        Ok(vec![asset_view])
    }

    /// Collect unique IPs, hostnames, and users from identity data and the primary identifier.
    /// Returns (ips, hostnames, users) vectors, all lowercased where appropriate.
    pub(super) fn collect_asset_identifiers(
        identities: &[serde_json::Value],
        identifier_field: &str,
        identifier_value: &str,
    ) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut ips: Vec<String> = Vec::new();
        let mut hostnames: Vec<String> = Vec::new();
        let mut users: Vec<String> = Vec::new();

        for identity in identities {
            if let Some(ip) = identity
                .get("ip")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                if !ips.contains(&ip.to_string()) {
                    ips.push(ip.to_string());
                }
            }
            if let Some(hostname) = identity
                .get("hostname")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                if !hostnames.contains(&hostname.to_lowercase()) {
                    hostnames.push(hostname.to_lowercase());
                }
            }
            if let Some(user) = identity
                .get("user")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                if !users.contains(&user.to_lowercase()) {
                    users.push(user.to_lowercase());
                }
            }
        }

        match identifier_field {
            "src_ip" | "dest_ip" => {
                if !ips.contains(&identifier_value.to_string()) {
                    ips.push(identifier_value.to_string());
                }
            }
            "src_host" | "dest_host" => {
                if !hostnames.contains(&identifier_value.to_lowercase()) {
                    hostnames.push(identifier_value.to_lowercase());
                }
            }
            "user" => {
                if !users.contains(&identifier_value.to_lowercase()) {
                    users.push(identifier_value.to_lowercase());
                }
            }
            _ => {}
        }

        (ips, hostnames, users)
    }

    /// Build a SQL OR clause matching asset identifiers against log-table columns
    /// (src_ip, src_host, user). Returns None if no identifiers are present.
    /// Returns (sql_fragment_with_placeholders, bind_values).
    pub(super) fn build_log_identity_clause(
        ips: &[String],
        hostnames: &[String],
        users: &[String],
    ) -> Option<(String, Vec<String>)> {
        if ips.is_empty() && hostnames.is_empty() && users.is_empty() {
            return None;
        }
        let mut conditions: Vec<String> = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        for ip in ips {
            conditions.push("src_ip = ?".to_string());
            binds.push(ip.clone());
        }
        for hostname in hostnames {
            conditions.push("(lower(src_host) = ? OR startsWith(lower(src_host), ?))".to_string());
            binds.push(hostname.clone());
            binds.push(format!("{}.", hostname));
        }
        for user in users {
            conditions.push("lower(user) = ?".to_string());
            binds.push(user.clone());
        }
        Some((conditions.join(" OR "), binds))
    }

    /// Build a SQL OR clause matching asset identifiers against the entity_time_range_agg table
    /// (entity_type/entity_value columns). Returns None if no identifiers are present.
    /// Returns (sql_fragment_with_placeholders, bind_values).
    fn build_entity_identity_clause(
        ips: &[String],
        hostnames: &[String],
        users: &[String],
    ) -> Option<(String, Vec<String>)> {
        if ips.is_empty() && hostnames.is_empty() && users.is_empty() {
            return None;
        }
        let mut conditions: Vec<String> = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        for ip in ips {
            conditions.push("(entity_type = 'src_ip' AND entity_value = ?)".to_string());
            binds.push(ip.clone());
        }
        for hostname in hostnames {
            conditions.push(
                "(entity_type = 'src_host' AND (entity_value = ? OR startsWith(entity_value, ?)))"
                    .to_string(),
            );
            binds.push(hostname.clone());
            binds.push(format!("{}.", hostname));
        }
        for user in users {
            conditions.push("(entity_type = 'user' AND entity_value = ?)".to_string());
            binds.push(user.clone());
        }
        Some((conditions.join(" OR "), binds))
    }

    /// Query paginated asset events with count and facets
    ///
    /// This method returns:
    /// - A page of events (limited by offset/limit)
    /// - Total count of matching events
    /// - Facet counts for source_type, event_type, and user
    pub async fn query_asset_events_paginated(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[serde_json::Value],
        time_range: &TimeRange,
        offset: usize,
        limit: usize,
        filters: Option<&AssetEventFilters>,
    ) -> Result<(Vec<serde_json::Value>, u64, AssetFacets), SearchError> {
        // Same cap as build_asset_view — prevents bypassing the limit via the
        // pagination endpoint with an offset of 0.
        let max_secs = Self::MAX_ASSET_VIEW_HOURS * 3600;
        if (time_range.end - time_range.start).num_seconds() > max_secs {
            return Err(SearchError::SqlValidationError(format!(
                "Asset view queries are limited to {}h.",
                Self::MAX_ASSET_VIEW_HOURS
            )));
        }

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok((Vec::new(), 0, AssetFacets::default())),
        };

        let (ips, hostnames, users) =
            Self::collect_asset_identifiers(identities, identifier_field, identifier_value);
        let (identity_clause, bind_values) =
            match Self::build_log_identity_clause(&ips, &hostnames, &users) {
                Some(pair) => pair,
                None => return Ok((Vec::new(), 0, AssetFacets::default())),
            };

        let start_str = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let end_str = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f").to_string();

        // Build filter conditions if provided
        let mut filter_conditions: Vec<String> = Vec::new();
        let mut filter_binds: Vec<String> = Vec::new();
        if let Some(f) = filters {
            if let Some(ref source_types) = f.source_types {
                if !source_types.is_empty() {
                    let placeholders: Vec<&str> = source_types.iter().map(|_| "?").collect();
                    filter_conditions.push(format!(
                        "lower(source_type) IN ({})",
                        placeholders.join(",")
                    ));
                    for s in source_types {
                        filter_binds.push(s.to_lowercase());
                    }
                }
            }
            // Event type filter using CASE WHEN (same logic as facet query)
            if let Some(ref event_types) = f.event_types {
                if !event_types.is_empty() {
                    let placeholders: Vec<&str> = event_types.iter().map(|_| "?").collect();
                    filter_conditions.push(format!(
                        "{} IN ({})",
                        Self::EVENT_TYPE_CASE_WHEN,
                        placeholders.join(",")
                    ));
                    for s in event_types {
                        filter_binds.push(s.to_uppercase());
                    }
                }
            }
            if let Some(ref users) = f.users {
                if !users.is_empty() {
                    let placeholders: Vec<&str> = users.iter().map(|_| "?").collect();
                    filter_conditions.push(format!("user IN ({})", placeholders.join(",")));
                    for s in users {
                        filter_binds.push(s.clone());
                    }
                }
            }
            if let Some(ref search_text) = f.search_text {
                if !search_text.is_empty() {
                    // Search lower(message) with expression-based text index (ngrams(3)).
                    // This allows ClickHouse to use the text index to skip granules.
                    // IOC/enrichment/ext fields are excluded here — they defeat index usage via OR chains
                    // and analysts can use the main search bar (nPL) for those fields.
                    filter_conditions.push("position(lower(message), ?) > 0".to_string());
                    filter_binds.push(search_text.to_lowercase());
                }
            }
        }

        let where_clause = if filter_conditions.is_empty() {
            String::new()
        } else {
            format!("\n            WHERE ({})", filter_conditions.join(" AND "))
        };

        // Combine identity + filter bind values for queries that use both
        let events_binds: Vec<String> = bind_values
            .iter()
            .chain(filter_binds.iter())
            .cloned()
            .collect();

        // Helper: apply bind values to a ClickHouse query
        fn apply_binds(
            query: clickhouse::query::Query,
            binds: &[String],
        ) -> clickhouse::query::Query {
            let mut q = query;
            for val in binds {
                q = q.bind(val);
            }
            q
        }

        // Events query with pagination (slim columns for timeline view). We also
        // compute `event_type` server-side via the shared classifier so the
        // redesigned asset stream doesn't have to re-classify client-side —
        // same source of truth as the facet aggregation a few queries below.
        let logs_table = self.table_names.read("logs");
        let events_sql = format!(
            r#"SELECT {cols}, {event_type} AS event_type
            FROM {logs_table}
            PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT {limit} OFFSET {offset}"#,
            cols = Self::ASSET_TIMELINE_COLUMNS,
            event_type = Self::EVENT_TYPE_CASE_WHEN,
            start = start_str,
            end = end_str,
            ident = identity_clause,
            where_clause = where_clause.trim(),
            limit = limit,
            offset = offset,
        );

        let events_binds_clone = events_binds.clone();
        let events_future = async {
            let mut events: Vec<serde_json::Value> = Vec::new();
            let query = apply_binds(clickhouse.query(&events_sql), &events_binds_clone);
            let mut cursor = match query.fetch_bytes("JSONEachRow") {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Asset events query failed to start: {}", e);
                    return events;
                }
            };

            let mut response_bytes = Vec::new();
            loop {
                match cursor.next().await {
                    Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!("Asset events query error reading chunk: {}", e);
                        break;
                    }
                }
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

        let has_filters = !filter_conditions.is_empty();

        if has_filters {
            // Fast path: when filters are active, skip expensive facet GROUP BY recomputation.
            // Frontend caches initial facets from the unfiltered load; we only need
            // total_count (for pagination) + the events page.
            let count_sql = format!(
                r#"SELECT count()
                FROM {logs_table}
                PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({})
                {}"#,
                start_str,
                end_str,
                identity_clause,
                where_clause.trim()
            );

            let count_binds = events_binds.clone();
            let count_future = async {
                match apply_binds(clickhouse.query(&count_sql), &count_binds)
                    .fetch_one::<u64>()
                    .await
                {
                    Ok(count) => count,
                    Err(e) => {
                        tracing::warn!("Asset count query failed: {}", e);
                        0
                    }
                }
            };

            let (total_count, events) = tokio::join!(count_future, events_future);

            // Return empty facets — frontend keeps its cached initialFacets
            Ok((events, total_count, AssetFacets::default()))
        } else {
            // Initial load: run full facet aggregation + reliable count (4 queries)
            let combined_facet_sql = format!(
                "SELECT source_type, {} as event_type, count() as cnt \
                 FROM {} \
                 PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                 GROUP BY source_type, event_type \
                 ORDER BY cnt DESC",
                Self::EVENT_TYPE_CASE_WHEN,
                logs_table,
                start_str,
                end_str,
                identity_clause
            );

            let user_facet_sql = format!(
                r#"SELECT user, count() as cnt
                FROM {logs_table}
                PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({})
                WHERE user != ''
                GROUP BY user
                ORDER BY cnt DESC
                LIMIT 50"#,
                start_str, end_str, identity_clause
            );

            // Separate count query as fallback — the combined facet query can fail
            // (e.g. complex CASE WHEN in GROUP BY) while this simple count always works
            let count_sql = format!(
                "SELECT count() FROM {} PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({})",
                logs_table, start_str, end_str, identity_clause
            );

            // Facet/count queries only use identity binds (no filter binds)
            let facet_binds = bind_values.clone();
            let facet_binds2 = bind_values.clone();
            let count_binds = bind_values.clone();

            let combined_facets_future = async {
                match apply_binds(clickhouse.query(&combined_facet_sql), &facet_binds)
                    .fetch_all::<(String, String, u64)>()
                    .await
                {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::warn!("Asset combined facet query failed: {}", e);
                        Vec::new()
                    }
                }
            };

            let user_facets_future = async {
                let mut facets: Vec<(String, u64)> = Vec::new();
                match apply_binds(clickhouse.query(&user_facet_sql), &facet_binds2)
                    .fetch_all::<(String, u64)>()
                    .await
                {
                    Ok(rows) => {
                        for (user, count) in rows {
                            if !user.is_empty() {
                                facets.push((user, count));
                            }
                        }
                    }
                    Err(e) => tracing::warn!("Asset user facet query failed: {}", e),
                }
                facets
            };

            let count_future = async {
                match apply_binds(clickhouse.query(&count_sql), &count_binds)
                    .fetch_one::<u64>()
                    .await
                {
                    Ok(count) => count,
                    Err(e) => {
                        tracing::warn!("Asset count query failed: {}", e);
                        0
                    }
                }
            };

            // Run all queries concurrently (combined facets, user facets, count, events page)
            let (combined_facet_rows, user_facets, reliable_count, events) = tokio::join!(
                combined_facets_future,
                user_facets_future,
                count_future,
                events_future
            );

            // Aggregate combined facet rows into facet_total, source_type_facets, event_type_facets
            let mut facet_total: u64 = 0;
            let mut source_type_map: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            let mut event_type_map: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for (source_type, event_type, cnt) in &combined_facet_rows {
                facet_total += cnt;
                if !source_type.is_empty() {
                    *source_type_map.entry(source_type.clone()).or_insert(0) += cnt;
                }
                if !event_type.is_empty() {
                    *event_type_map.entry(event_type.clone()).or_insert(0) += cnt;
                }
            }

            // Use facet-derived total when available, fall back to reliable count query
            let total_count = if facet_total > 0 {
                facet_total
            } else {
                reliable_count
            };

            let mut source_type_facets: Vec<(String, u64)> = source_type_map.into_iter().collect();
            source_type_facets.sort_by(|a, b| b.1.cmp(&a.1));
            source_type_facets.truncate(50);

            let mut event_type_facets: Vec<(String, u64)> = event_type_map.into_iter().collect();
            event_type_facets.sort_by(|a, b| b.1.cmp(&a.1));

            let facets = AssetFacets {
                source_type: source_type_facets,
                event_type: event_type_facets,
                user: user_facets,
            };

            Ok((events, total_count, facets))
        }
    }

    /// Detect the asset identifier from search results
    fn detect_asset_identifier(
        &self,
        results: &[serde_json::Value],
        asset_info: &AssetCommandInfo,
    ) -> Result<(String, String), SearchError> {
        // If identifier_field is specified, use it
        if let Some(ref field) = asset_info.identifier_field {
            // Try to find a value for this field in the first result
            for result in results.iter().take(10) {
                if let Some(value) = result.get(field).and_then(|v| v.as_str()) {
                    if !value.is_empty() {
                        return Ok((field.clone(), value.to_string()));
                    }
                }
            }
            return Err(SearchError::SqlValidationError(format!(
                "Specified identifier field '{}' not found in results",
                field
            )));
        }

        // Auto-detect: check common identifier fields in priority order
        let identifier_fields = ["src_host", "dest_host", "src_ip", "dest_ip", "user", "mac"];

        for result in results.iter().take(10) {
            for field in &identifier_fields {
                if let Some(value) = result.get(*field).and_then(|v| v.as_str()) {
                    if !value.is_empty() {
                        return Ok((field.to_string(), value.to_string()));
                    }
                }
            }
        }

        Err(SearchError::SqlValidationError(
            "Could not auto-detect asset identifier. Use field= parameter to specify.".to_string(),
        ))
    }

    /// Resolve all related identities for an asset using identity_observations table
    async fn resolve_asset_identities(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        time_range: &TimeRange,
        max_age: std::time::Duration,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        use serde_json::json;

        // Need ClickHouse for identity resolution
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => {
                // Return just the primary identifier if no ClickHouse
                return Ok(vec![json!({
                    identifier_field: identifier_value,
                    "first_seen": null,
                    "last_seen": null,
                })]);
            }
        };

        // Determine the query column based on identifier type
        let (query_column, _is_ip_query) = match identifier_field {
            "src_ip" | "dest_ip" => ("ip", true),
            "src_host" | "dest_host" => ("hostname", false),
            "user" => ("user", false),
            "mac" => ("mac", false),
            _ => {
                // Unknown field type - just return the value
                return Ok(vec![json!({
                    identifier_field: identifier_value,
                    "first_seen": null,
                    "last_seen": null,
                })]);
            }
        };

        let max_age_secs = max_age.as_secs();
        let start_str = time_range.start.format("%Y-%m-%d %H:%M:%S").to_string();
        let end_str = time_range.end.format("%Y-%m-%d %H:%M:%S").to_string();

        let lower_identifier = identifier_value.to_lowercase();

        // For hostname queries, also match by short hostname (strip domain suffix)
        // e.g., "workstation-jsmith.corp.local" should also match "workstation-jsmith"
        let mut id_binds: Vec<String> = Vec::new();
        let hostname_condition = if query_column == "hostname" {
            let short_hostname = lower_identifier
                .split('.')
                .next()
                .unwrap_or(&lower_identifier)
                .to_string();
            id_binds.push(lower_identifier.clone()); // exact FQDN match
            id_binds.push(short_hostname.clone()); // short hostname match
            id_binds.push(format!("{}.", short_hostname)); // identity has FQDN, we have short
            format!(
                "(lower({}) = ? OR lower({}) = ? OR startsWith(lower({}), ?))",
                query_column, query_column, query_column
            )
        } else {
            id_binds.push(lower_identifier.clone());
            format!("lower({}) = ?", query_column)
        };

        // Query to resolve identities with time bounds (case-insensitive hostname match)
        let identity_observations_table = self.table_names.read("identity_observations");
        let sql = format!(
            r#"
            SELECT
                ip,
                hostname,
                mac,
                user,
                toString(min(observed_at)) as valid_from,
                toString(max(observed_at)) as valid_until,
                count() as observation_count
            FROM {identity_observations_table}
            WHERE {}
              AND observed_at >= '{}'
              AND observed_at <= '{}'
              AND observed_at >= now() - INTERVAL {} SECOND
            GROUP BY ip, hostname, mac, user
            ORDER BY max(observed_at) DESC
            LIMIT 100
            "#,
            hostname_condition, start_str, end_str, max_age_secs
        );

        // Execute the query with bind values
        let mut query = clickhouse.query(&sql);
        for val in &id_binds {
            query = query.bind(val);
        }

        let mut identities = Vec::new();

        // Process results (valid_from/valid_until are strings now)
        match query
            .fetch_all::<(String, String, String, String, String, String, u64)>()
            .await
        {
            Ok(rows) => {
                for (ip, hostname, mac, user, valid_from, valid_until, observation_count) in rows {
                    identities.push(json!({
                        "ip": if ip.is_empty() { serde_json::Value::Null } else { json!(ip) },
                        "hostname": if hostname.is_empty() { serde_json::Value::Null } else { json!(hostname) },
                        "mac": if mac.is_empty() { serde_json::Value::Null } else { json!(mac) },
                        "user": if user.is_empty() { serde_json::Value::Null } else { json!(user) },
                        "valid_from": valid_from,
                        "valid_until": valid_until,
                        "observation_count": observation_count,
                    }));
                }
            }
            Err(e) => {
                tracing::warn!("Failed to resolve asset identities: {}", e);
                // Return just the primary identifier on error
                return Ok(vec![json!({
                    identifier_field: identifier_value,
                    "first_seen": null,
                    "last_seen": null,
                })]);
            }
        }

        // If no identities found, return the primary identifier
        if identities.is_empty() {
            identities.push(json!({
                identifier_field: identifier_value,
                "first_seen": null,
                "last_seen": null,
            }));
        }

        Ok(identities)
    }

    /// Query true first/last seen across all retained data via ClickHouse
    pub async fn query_asset_true_time_range(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[serde_json::Value],
    ) -> (Option<String>, Option<String>) {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct AssetTimeRange {
            first_seen: String,
            last_seen: String,
        }

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return (None, None),
        };

        let (ips, hostnames, users) =
            Self::collect_asset_identifiers(identities, identifier_field, identifier_value);
        let (identity_clause, identity_binds) =
            match Self::build_entity_identity_clause(&ips, &hostnames, &users) {
                Some(pair) => pair,
                None => return (None, None),
            };

        let sql = format!(
            "SELECT \
                formatDateTime(min(first_seen), '%Y-%m-%dT%H:%i:%sZ') as first_seen, \
                formatDateTime(max(last_seen), '%Y-%m-%dT%H:%i:%sZ') as last_seen \
             FROM {} \
             WHERE ({})",
            self.table_names.read("entity_time_range_agg"),
            identity_clause
        );

        let mut query = clickhouse.query(&sql);
        for val in &identity_binds {
            query = query.bind(val);
        }
        match query.fetch_one::<AssetTimeRange>().await {
            Ok(tr) => {
                let first_seen =
                    if tr.first_seen.is_empty() || tr.first_seen == "1970-01-01T00:00:00Z" {
                        None
                    } else {
                        Some(tr.first_seen)
                    };
                let last_seen = if tr.last_seen.is_empty() || tr.last_seen == "1970-01-01T00:00:00Z"
                {
                    None
                } else {
                    Some(tr.last_seen)
                };
                (first_seen, last_seen)
            }
            Err(e) => {
                tracing::warn!("Failed to query true asset time range: {}", e);
                (None, None)
            }
        }
    }

    /// Query artifact (hash/domain) summaries with timestamps across the full search time range.
    /// Returns aggregated first_ts, last_ts, and count for each unique artifact.
    pub async fn query_asset_artifact_summary(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[serde_json::Value],
        time_range: &TimeRange,
    ) -> serde_json::Value {
        use serde_json::json;

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return json!({ "hashes": [], "domains": [] }),
        };

        let (ips, hostnames, users) =
            Self::collect_asset_identifiers(identities, identifier_field, identifier_value);
        let (identity_clause, identity_binds) =
            match Self::build_log_identity_clause(&ips, &hostnames, &users) {
                Some(pair) => pair,
                None => return json!({ "hashes": [], "domains": [] }),
            };

        let start_str = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let end_str = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f").to_string();

        // Hash query: file_hash + process_hash via UNION ALL
        // Includes max pre-computed prevalence (host_count) from event enrichment
        // The identity_clause appears twice (one per UNION ALL branch), so bind values are doubled
        let logs_table = self.table_names.read("logs");
        let hash_sql = format!(
            "SELECT artifact, \
                formatDateTime(min(first_ts), '%Y-%m-%dT%H:%i:%sZ') as first_ts, \
                formatDateTime(max(last_ts), '%Y-%m-%dT%H:%i:%sZ') as last_ts, \
                sum(cnt) as cnt, \
                max(host_count) as host_count \
             FROM ( \
                SELECT lower(file_hash) as artifact, min(timestamp) as first_ts, max(timestamp) as last_ts, count() as cnt, \
                    max(prevalence_file_hash) as host_count \
                FROM {logs_table} \
                PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                WHERE file_hash != '' AND length(file_hash) >= 32 AND match(file_hash, '^[a-fA-F0-9]+$') \
                GROUP BY lower(file_hash) \
                UNION ALL \
                SELECT lower(process_hash) as artifact, min(timestamp) as first_ts, max(timestamp) as last_ts, count() as cnt, \
                    max(prevalence_process_hash) as host_count \
                FROM {logs_table} \
                PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                WHERE process_hash != '' AND length(process_hash) >= 32 AND match(process_hash, '^[a-fA-F0-9]+$') \
                GROUP BY lower(process_hash) \
             ) GROUP BY artifact ORDER BY last_ts DESC LIMIT 50 \
              SETTINGS max_execution_time=30",
            start_str, end_str, identity_clause,
            start_str, end_str, identity_clause,
        );

        // Domain query: dest_host + query + url_domain via UNION ALL, exclude IPs
        // NOTE: Use `match(...) = 0` instead of `NOT match(...)` — ClickHouse query
        // optimizer mishandles `NOT match()` when PREWHERE contains OR conditions,
        // silently returning 0 rows. The `= 0` form prevents the bad optimization.
        // The identity_clause appears three times (one per UNION ALL branch), so bind values are tripled
        let ip_exclude = r"^\d+\.\d+\.\d+\.\d+$";
        let domain_sql = format!(
            "SELECT artifact, \
                formatDateTime(min(first_ts), '%Y-%m-%dT%H:%i:%sZ') as first_ts, \
                formatDateTime(max(last_ts), '%Y-%m-%dT%H:%i:%sZ') as last_ts, \
                sum(cnt) as cnt, \
                max(host_count) as host_count \
             FROM ( \
                SELECT lower(dest_host) as artifact, min(timestamp) as first_ts, max(timestamp) as last_ts, count() as cnt, \
                    max(prevalence_dest_domain) as host_count \
                FROM {logs_table} \
                PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                WHERE dest_host != '' AND position(dest_host, '.') > 0 AND match(dest_host, '{}') = 0 \
                GROUP BY lower(dest_host) \
                UNION ALL \
                SELECT lower(query) as artifact, min(timestamp) as first_ts, max(timestamp) as last_ts, count() as cnt, \
                    max(prevalence_dest_domain) as host_count \
                FROM {logs_table} \
                PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                WHERE query != '' AND position(query, '.') > 0 AND match(query, '{}') = 0 \
                GROUP BY lower(query) \
                UNION ALL \
                SELECT lower(url_domain) as artifact, min(timestamp) as first_ts, max(timestamp) as last_ts, count() as cnt, \
                    max(prevalence_dest_domain) as host_count \
                FROM {logs_table} \
                PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                WHERE url_domain != '' AND position(url_domain, '.') > 0 AND match(url_domain, '{}') = 0 \
                GROUP BY lower(url_domain) \
             ) GROUP BY artifact ORDER BY last_ts DESC LIMIT 50 \
              SETTINGS max_execution_time=30",
            start_str, end_str, identity_clause, ip_exclude,
            start_str, end_str, identity_clause, ip_exclude,
            start_str, end_str, identity_clause, ip_exclude,
        );

        // Hash SQL has identity_clause twice; domain SQL has it three times — repeat binds accordingly
        let hash_binds: Vec<String> = identity_binds
            .iter()
            .chain(identity_binds.iter())
            .cloned()
            .collect();
        let domain_binds: Vec<String> = identity_binds
            .iter()
            .chain(identity_binds.iter())
            .chain(identity_binds.iter())
            .cloned()
            .collect();

        // Run both queries in parallel
        let mut hash_query = clickhouse.query(&hash_sql);
        for val in &hash_binds {
            hash_query = hash_query.bind(val);
        }
        let hash_future = hash_query.fetch_all::<(String, String, String, u64, u16)>();

        let mut domain_query = clickhouse.query(&domain_sql);
        for val in &domain_binds {
            domain_query = domain_query.bind(val);
        }
        let domain_future = domain_query.fetch_all::<(String, String, String, u64, u16)>();

        let (hash_result, domain_result) = tokio::join!(hash_future, domain_future);

        let hashes: Vec<serde_json::Value> = match hash_result {
            Ok(rows) => rows.into_iter().map(|(artifact, first_ts, last_ts, count, host_count)| {
                json!({ "artifact": artifact, "first_ts": first_ts, "last_ts": last_ts, "count": count, "host_count": host_count })
            }).collect(),
            Err(e) => {
                tracing::warn!("Failed to query asset artifact hashes: {}", e);
                vec![]
            }
        };

        let domains: Vec<serde_json::Value> = match domain_result {
            Ok(rows) => rows.into_iter().map(|(artifact, first_ts, last_ts, count, host_count)| {
                json!({ "artifact": artifact, "first_ts": first_ts, "last_ts": last_ts, "count": count, "host_count": host_count })
            }).collect(),
            Err(e) => {
                tracing::warn!("Failed to query asset artifact domains: {}", e);
                vec![]
            }
        };

        json!({ "hashes": hashes, "domains": domains })
    }

    /// Query per-event artifact occurrences across the full search time range.
    /// Returns individual (artifact, timestamp) rows so the scatter chart can
    /// show one dot per event at its actual timestamp.
    /// Optional hash_filter/domain_filter restrict to only those artifact values.
    pub async fn query_asset_artifact_occurrences(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[serde_json::Value],
        time_range: &TimeRange,
        hash_filter: Option<&[String]>,
        domain_filter: Option<&[String]>,
    ) -> serde_json::Value {
        use serde_json::json;

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return json!({ "hashes": [], "domains": [] }),
        };

        let (ips, hostnames, users) =
            Self::collect_asset_identifiers(identities, identifier_field, identifier_value);
        let (identity_clause, identity_binds) =
            match Self::build_log_identity_clause(&ips, &hostnames, &users) {
                Some(pair) => pair,
                None => return json!({ "hashes": [], "domains": [] }),
            };

        let start_str = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let end_str = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let logs_table = self.table_names.read("logs");

        // Build artifact IN placeholders and collect bind values
        let build_in_placeholders = |artifacts: &[String]| -> (String, Vec<String>) {
            let placeholders: Vec<&str> = artifacts.iter().map(|_| "?").collect();
            (placeholders.join(", "), artifacts.to_vec())
        };

        // Hash occurrences: individual (artifact, timestamp) rows
        let (hash_sql, hash_binds) = if let Some(hashes) = hash_filter {
            if hashes.is_empty() {
                // No hashes passed the filter — skip query
                (String::new(), Vec::new())
            } else {
                let (in_placeholders, artifact_binds) = build_in_placeholders(hashes);
                // identity_clause appears twice, artifact IN appears twice
                let binds: Vec<String> = identity_binds
                    .iter()
                    .chain(artifact_binds.iter())
                    .chain(identity_binds.iter())
                    .chain(artifact_binds.iter())
                    .cloned()
                    .collect();
                let sql = format!(
                    "SELECT artifact, formatDateTime(ts, '%Y-%m-%dT%H:%i:%sZ') as timestamp \
                     FROM ( \
                        SELECT lower(file_hash) as artifact, timestamp as ts \
                        FROM {logs_table} \
                        PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                        WHERE file_hash != '' AND length(file_hash) >= 32 AND lower(file_hash) IN ({}) \
                        UNION ALL \
                        SELECT lower(process_hash) as artifact, timestamp as ts \
                        FROM {logs_table} \
                        PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                        WHERE process_hash != '' AND length(process_hash) >= 32 AND lower(process_hash) IN ({}) \
                     ) ORDER BY ts LIMIT 100 BY artifact \
                      SETTINGS max_execution_time=30",
                    start_str, end_str, identity_clause, in_placeholders,
                    start_str, end_str, identity_clause, in_placeholders,
                );
                (sql, binds)
            }
        } else {
            // No filter — return all hash occurrences (identity_clause appears twice)
            let binds: Vec<String> = identity_binds
                .iter()
                .chain(identity_binds.iter())
                .cloned()
                .collect();
            let sql = format!(
                "SELECT artifact, formatDateTime(ts, '%Y-%m-%dT%H:%i:%sZ') as timestamp \
                 FROM ( \
                    SELECT lower(file_hash) as artifact, timestamp as ts \
                    FROM {logs_table} \
                    PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                    WHERE file_hash != '' AND length(file_hash) >= 32 AND match(file_hash, '^[a-fA-F0-9]+$') \
                    UNION ALL \
                    SELECT lower(process_hash) as artifact, timestamp as ts \
                    FROM {logs_table} \
                    PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                    WHERE process_hash != '' AND length(process_hash) >= 32 AND match(process_hash, '^[a-fA-F0-9]+$') \
                 ) ORDER BY ts LIMIT 100 BY artifact \
                  SETTINGS max_execution_time=30",
                start_str, end_str, identity_clause,
                start_str, end_str, identity_clause,
            );
            (sql, binds)
        };

        // Domain occurrences: individual (artifact, timestamp) rows
        let ip_exclude = r"^\d+\.\d+\.\d+\.\d+$";
        let (domain_sql, domain_binds) = if let Some(domains) = domain_filter {
            if domains.is_empty() {
                (String::new(), Vec::new())
            } else {
                let (in_placeholders, artifact_binds) = build_in_placeholders(domains);
                // identity_clause appears three times, artifact IN appears three times
                let binds: Vec<String> = identity_binds
                    .iter()
                    .chain(artifact_binds.iter())
                    .chain(identity_binds.iter())
                    .chain(artifact_binds.iter())
                    .chain(identity_binds.iter())
                    .chain(artifact_binds.iter())
                    .cloned()
                    .collect();
                let sql = format!(
                    "SELECT artifact, formatDateTime(ts, '%Y-%m-%dT%H:%i:%sZ') as timestamp \
                     FROM ( \
                        SELECT lower(dest_host) as artifact, timestamp as ts \
                        FROM {logs_table} \
                        PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                        WHERE dest_host != '' AND position(dest_host, '.') > 0 AND lower(dest_host) IN ({}) \
                        UNION ALL \
                        SELECT lower(query) as artifact, timestamp as ts \
                        FROM {logs_table} \
                        PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                        WHERE query != '' AND position(query, '.') > 0 AND lower(query) IN ({}) \
                        UNION ALL \
                        SELECT lower(url_domain) as artifact, timestamp as ts \
                        FROM {logs_table} \
                        PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                        WHERE url_domain != '' AND position(url_domain, '.') > 0 AND lower(url_domain) IN ({}) \
                     ) ORDER BY ts LIMIT 100 BY artifact \
                      SETTINGS max_execution_time=30",
                    start_str, end_str, identity_clause, in_placeholders,
                    start_str, end_str, identity_clause, in_placeholders,
                    start_str, end_str, identity_clause, in_placeholders,
                );
                (sql, binds)
            }
        } else {
            // No filter (identity_clause appears three times)
            let binds: Vec<String> = identity_binds
                .iter()
                .chain(identity_binds.iter())
                .chain(identity_binds.iter())
                .cloned()
                .collect();
            let sql = format!(
                "SELECT artifact, formatDateTime(ts, '%Y-%m-%dT%H:%i:%sZ') as timestamp \
                 FROM ( \
                    SELECT lower(dest_host) as artifact, timestamp as ts \
                    FROM {logs_table} \
                    PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                    WHERE dest_host != '' AND position(dest_host, '.') > 0 AND match(dest_host, '{}') = 0 \
                    UNION ALL \
                    SELECT lower(query) as artifact, timestamp as ts \
                    FROM {logs_table} \
                    PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                    WHERE query != '' AND position(query, '.') > 0 AND match(query, '{}') = 0 \
                    UNION ALL \
                    SELECT lower(url_domain) as artifact, timestamp as ts \
                    FROM {logs_table} \
                    PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}) \
                    WHERE url_domain != '' AND position(url_domain, '.') > 0 AND match(url_domain, '{}') = 0 \
                 ) ORDER BY ts LIMIT 100 BY artifact \
                  SETTINGS max_execution_time=30",
                start_str, end_str, identity_clause, ip_exclude,
                start_str, end_str, identity_clause, ip_exclude,
                start_str, end_str, identity_clause, ip_exclude,
            );
            (sql, binds)
        };

        // Skip queries when SQL is empty (filter was empty slice = return nothing for that type)
        let hashes: Vec<serde_json::Value> = if hash_sql.is_empty() {
            vec![]
        } else {
            let mut query = clickhouse.query(&hash_sql);
            for val in &hash_binds {
                query = query.bind(val);
            }
            match query.fetch_all::<(String, String)>().await {
                Ok(rows) => rows.into_iter().map(|(artifact, timestamp)| {
                    json!({ "artifact": artifact, "timestamp": timestamp })
                }).collect(),
                Err(e) => {
                    tracing::warn!("Failed to query asset artifact hash occurrences: {}", e);
                    vec![]
                }
            }
        };

        let domains: Vec<serde_json::Value> = if domain_sql.is_empty() {
            vec![]
        } else {
            let mut query = clickhouse.query(&domain_sql);
            for val in &domain_binds {
                query = query.bind(val);
            }
            match query.fetch_all::<(String, String)>().await {
                Ok(rows) => rows.into_iter().map(|(artifact, timestamp)| {
                    json!({ "artifact": artifact, "timestamp": timestamp })
                }).collect(),
                Err(e) => {
                    tracing::warn!("Failed to query asset artifact domain occurrences: {}", e);
                    vec![]
                }
            }
        };

        json!({ "hashes": hashes, "domains": domains })
    }

    /// Detect event type from event fields for timeline display
    /// Classify an event into a type category.
    /// Ordering and logic mirrors the SQL CASE WHEN in the facet/filter queries
    /// and the frontend getEventType() to ensure consistent classification.
    fn detect_event_type(&self, event: &serde_json::Value) -> String {
        let source_type = event
            .get("source_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        let action = event
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        // Helper: check if a field exists AND is a non-empty string
        let has_non_empty = |field: &str| -> bool {
            event
                .get(field)
                .and_then(|v| v.as_str())
                .map_or(false, |s| !s.is_empty())
        };

        // Alert/Signal events
        if source_type == "signal" || source_type.contains("alert") {
            return "ALERT".to_string();
        }

        // DHCP / network info events (before auth/process to avoid misclassification
        // when ClickHouse returns empty strings for auth_result/process_name)
        if source_type.contains("dhcp")
            || action.contains("dhcp")
            || action == "network_info"
            || action == "networkinfo"
            || action.contains("network_adapter")
        {
            return "DHCP".to_string();
        }

        // DNS events
        let src_port = event.get("src_port").and_then(|v| v.as_u64()).unwrap_or(0);
        let dest_port = event.get("dest_port").and_then(|v| v.as_u64()).unwrap_or(0);
        if (source_type.contains("dns")
            || has_non_empty("query")
            || src_port == 53
            || dest_port == 53)
            && !source_type.contains("dhcp")
        {
            return "DNS".to_string();
        }

        // Authentication events - require non-empty auth_result or auth-related source/action
        if has_non_empty("auth_result")
            || source_type.contains("auth")
            || action.contains("login")
            || action.contains("logon")
        {
            let auth_result = event
                .get("auth_result")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            if auth_result.contains("fail") || action.contains("fail") {
                return "AUTH_FAILURE".to_string();
            }
            return "AUTH_SUCCESS".to_string();
        }

        // Image load events (DLL loads)
        if action == "image_load" || action == "imageload" {
            return "IMAGE_LOAD".to_string();
        }

        // Registry events
        let category = event
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        if action.contains("registry") || category == "registry" {
            return "REGISTRY".to_string();
        }

        // Pipe events (named pipe create/connect)
        if action.contains("pipe") || category == "pipe" {
            return "PIPE".to_string();
        }

        // Network events (action-based) — check BEFORE process so EDR events with
        // both process_name and dest_ip (e.g. "chrome.exe connected to ...") classify
        // as NETWORK when the action indicates a connection.
        if action.contains("connection")
            || source_type.contains("firewall")
            || source_type.contains("proxy")
        {
            return "NETWORK".to_string();
        }

        // Process events - require non-empty process_name
        if has_non_empty("process_name") || action.contains("process") || action.contains("exec") {
            return "PROCESS".to_string();
        }

        // File events - require non-empty file_action
        if has_non_empty("file_action") || action.contains("file") {
            return "FILE".to_string();
        }

        // Network events (fallback) - dest_ip present but no connection keyword
        if has_non_empty("dest_ip") {
            return "NETWORK".to_string();
        }

        "EVENT".to_string()
    }

    /// Build a human-readable summary for an event based on its type
    fn build_event_summary(&self, event: &serde_json::Value, event_type: &str) -> String {
        match event_type {
            "PROCESS" => {
                let proc_name = event
                    .get("process_name")
                    .or_else(|| event.get("command_line"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown process");
                let pid = event.get("process_id").and_then(|v| v.as_u64());
                match pid {
                    Some(p) => format!("{} ({})", proc_name, p),
                    None => proc_name.to_string(),
                }
            }
            "FILE" => event
                .get("file_name")
                .or_else(|| event.get("file_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown file")
                .to_string(),
            "NETWORK" => {
                let dest = event
                    .get("dest_host")
                    .or_else(|| event.get("dest_ip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let port = event.get("dest_port").and_then(|v| v.as_u64());
                match port {
                    Some(p) => format!("{}:{}", dest, p),
                    None => dest.to_string(),
                }
            }
            "DNS" => event
                .get("query")
                .or_else(|| event.get("dest_host"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown query")
                .to_string(),
            "ALERT" => event
                .get("rule_name")
                .or_else(|| event.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("Alert triggered")
                .to_string(),
            "AUTH_SUCCESS" | "AUTH_FAILURE" => {
                let user = event
                    .get("user")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let auth_type = event.get("auth_type").and_then(|v| v.as_str());
                match auth_type {
                    Some(t) => format!("{} via {}", user, t),
                    None => user.to_string(),
                }
            }
            _ => event
                .get("message")
                .or_else(|| event.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("Event")
                .to_string(),
        }
    }
}

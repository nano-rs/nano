// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::search::parse_clickhouse_error;

/// Parse an asset time-range timestamp (`query_asset_true_time_range` emits
/// RFC3339-ish `%Y-%m-%dT%H:%M:%SZ`) into a UTC instant. Returns None on any
/// parse failure so callers fall back to the requested window. NAN-1455.
fn parse_asset_timestamp(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

impl SearchService {
    /// Default page size for asset events
    const ASSET_EVENT_PAGE_SIZE: usize = 200;

    /// Canonical (UDM-semantic) timeline field names, in projection order.
    ///
    /// Slim column list for asset timeline queries — covers everything
    /// `detect_event_type`, `build_event_summary`, and the frontend
    /// `getInlineFields` need, avoiding the full 130+ column `SELECT *` to reduce
    /// payload size by ~80-90%.
    ///
    /// These are UDM-semantic names. The actual SELECT projection is built per
    /// the active schema profile by [`Self::asset_timeline_columns`], which
    /// resolves each name to its physical column and aliases it back to the
    /// canonical name so downstream JSON consumers (`detect_event_type`,
    /// `build_event_summary`) see a stable key set regardless of schema (NAN-1241).
    /// Fields the active schema does not map are skipped.
    const ASSET_TIMELINE_FIELDS: &'static [&'static str] = &[
        "id",
        "timestamp",
        "_inserted_at",
        "ingest_time",
        "source_type",
        "vendor_product",
        "namespace",
        "message",
        "category",
        "src_ip",
        "dest_ip",
        "src_host",
        "dest_host",
        "src_port",
        "dest_port",
        "src_mac",
        "protocol",
        "bytes_in",
        "bytes_out",
        "duration",
        "user",
        "action",
        "status",
        "severity",
        "auth_type",
        "auth_result",
        "process_name",
        "command_line",
        "process_id",
        "parent_command_line",
        "parent_process_name",
        "parent_process_id",
        "process_hash",
        "process_path",
        "file_name",
        "file_path",
        "file_hash",
        "file_action",
        "query",
        "query_type",
        "answer",
        "url",
        "url_domain",
        "uri_path",
        "http_method",
        "http_status_code",
        "http_user_agent",
        "http_content_type",
        "registry_path",
        "registry_value_data",
        "signature",
        "signature_id",
        "rule_name",
        "mitre_technique_id",
        "enriched_src_country",
        "enriched_src_asn",
        "enriched_dest_country",
        "enriched_dest_asn",
        "prevalence_min",
    ];

    /// Build the asset-timeline SELECT projection for the active schema profile.
    ///
    /// Each canonical field in [`Self::ASSET_TIMELINE_FIELDS`] is resolved to its
    /// physical column via `udm_column_sql` and aliased back to the canonical
    /// name (`col AS canonical`). For the UDM profile every field resolves to the
    /// same column name, so the emitted projection is byte-equivalent to the old
    /// const (modulo the seam's uniform reserved-word quoting) and the result rows
    /// are byte-identical. Fields the schema does not map (`udm_column_sql` →
    /// `None`) are skipped entirely so no unknown-column reference is emitted.
    fn asset_timeline_columns(&self) -> String {
        let profile = self.active_profile.as_ref();
        let is_ocsf = profile.id() == crate::schema::SchemaId::Ocsf;
        Self::ASSET_TIMELINE_FIELDS
            .iter()
            .filter_map(|field| {
                // Operational/physical columns present literally in BOTH schemas
                // (`id`, `source_type`, `timestamp`) must be projected by their own
                // name — NOT routed through `udm_column_sql`, whose OCSF manifest maps
                // the UDM semantics elsewhere:
                //   • `id` → `metadata.uid` (logical event uid, not the physical
                //     row key) → row-expand refetch-by-id found nothing
                //     ("Couldn't load full event", NAN-1316).
                //   • `source_type` → `class_uid` (a UInt32, e.g. 4001) → the asset
                //     stream emitted a NUMBER as source_type; the frontend then
                //     POSTed `{source_type: 4001}` to /api/search/log (Option<String>)
                //     → 422 "Invalid request body" (NAN-1317 row-expand).
                //   • `timestamp` → `time_dt` (an ALIAS column) → the row was keyed
                //     `time_dt`, so the per-event `event.get("timestamp")` read came
                //     back empty and the stream rendered a blank time column with a
                //     big left gutter (NAN-1324).
                // All three exist verbatim in `logs` and `ocsf_logs`, and the OCSF
                // profile's `resolve()` already special-cases them to the physical
                // column — so projecting them literally is correct under both
                // schemas (UDM's udm_column_sql already returned these names, so
                // UDM output is byte-identical).
                if matches!(*field, "id" | "source_type" | "timestamp") {
                    return Some(format!("{field} AS {field}"));
                }
                profile.udm_column_sql(field).map(|col| {
                    // Alias to the schema-NATIVE field name (NAN-1303): under OCSF
                    // the row is keyed by the promoted OCSF column (src_endpoint.ip,
                    // dst_endpoint.hostname, …) instead of UDM aliases, so the asset
                    // stream renders OCSF fields for OCSF deployments — matching the
                    // search results. `build_event_summary` reads the same
                    // display_field_name keys, so summary stays in lockstep. UDM's
                    // display_field_name is the identity, so UDM output is byte-identical.
                    let key = profile
                        .display_field_name(field)
                        .unwrap_or_else(|| field.to_string());
                    let key_sql = crate::query::escape_identifier(&key);
                    // ASN under OCSF maps to the numeric `autonomous_system.number`
                    // (UInt32) whereas UDM stores a String. Wrap the OCSF projection
                    // in `toString()` so the column carries the type downstream
                    // consumers expect. The UDM path is untouched (string column).
                    if is_ocsf && matches!(*field, "enriched_src_asn" | "enriched_dest_asn") {
                        format!("toString({col}) AS {key_sql}")
                    } else {
                        format!("{col} AS {key_sql}")
                    }
                })
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    // Event classification is profile-aware (NAN-1241): each call site uses
    // `crate::search::classification::event_type_sql(self.active_profile.as_ref())`
    // so UDM (`action`/`category`-based) and OCSF (`class_uid`/`category_uid`-based)
    // each get their correct CASE expression. See [`crate::search::classification`].

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
        let mut identities = self
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
        let (mut paginated_events, mut total_count, mut facets) = self
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

        // NAN-1455: re-anchor to the entity's last activity when the requested
        // window is empty. The asset view is capped at MAX_ASSET_VIEW_HOURS, so a
        // recent-window default (or data older than the window) renders an empty
        // dossier even though the entity is well-attested. When zero events match,
        // look up the entity's unbounded last-seen (entity_time_range_agg) and, if
        // it falls outside the requested window, re-run identity resolution + the
        // events query over `[last_seen - cap, last_seen]`. The effective window is
        // surfaced in `_asset_profile` so the frontend dossier/timeline align and
        // can show a notice. Click-from-event already centers the window (NAN-1451);
        // this only fires on a genuinely empty window.
        let mut effective_range: Option<TimeRange> = None;
        if total_count == 0 {
            let (_first_seen, last_seen) = self
                .query_asset_true_time_range(&identifier_field, &identifier_value, &identities)
                .await
                .unwrap_or((None, None));
            if let Some(ls) = last_seen.as_deref().and_then(parse_asset_timestamp) {
                if ls < time_range.start || ls > time_range.end {
                    let anchored = TimeRange::new(
                        ls - chrono::Duration::hours(Self::MAX_ASSET_VIEW_HOURS),
                        ls,
                    );
                    tracing::info!(
                        "Asset view empty for requested window; re-anchoring to last activity [{} .. {}]",
                        anchored.start, anchored.end
                    );
                    identities = self
                        .resolve_asset_identities(
                            &identifier_field,
                            &identifier_value,
                            &anchored,
                            asset_info.max_identity_age,
                        )
                        .await?;
                    let (ev, tc, fc) = self
                        .query_asset_events_paginated(
                            &identifier_field,
                            &identifier_value,
                            &identities,
                            &anchored,
                            0,
                            Self::ASSET_EVENT_PAGE_SIZE,
                            None,
                        )
                        .await?;
                    paginated_events = ev;
                    total_count = tc;
                    facets = fc;
                    effective_range = Some(anchored);
                }
            }
        }

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
                // NAN-1455: present only when the requested window was empty and we
                // re-anchored to the entity's last activity. The frontend uses this
                // for the dossier fetch + timeline and shows a notice.
                "reanchored": effective_range.is_some(),
                "effective_time_range": effective_range.as_ref().map(|r| json!({
                    "start": r.start.to_rfc3339(),
                    "end": r.end.to_rfc3339(),
                })),
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
        profile: &dyn crate::schema::SchemaProfile,
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

        // Classify the seed identifier into ip/host/user. Two name spaces reach
        // here: native fields the profile knows (`profile.entity_type` — under
        // OCSF `device.hostname`, `src_endpoint.ip`, `user.name`, … which the old
        // hardcoded UDM-name match dropped → empty dossier, NAN-1300) AND
        // UDM-CANONICAL names (`src_host`/`src_ip`/`user`) that the asset command
        // emits as the `primary_identifier` even under OCSF (resolved downstream
        // via `udm_column_sql`). The OCSF registry does NOT know the UDM-canonical
        // aliases, so `entity_type("src_host")` is None there — classifying by
        // `entity_type` alone regressed that common path to 0 results. Resolve via
        // the profile first, then fall back to the UDM-canonical names so BOTH
        // spaces bucket correctly under either schema.
        use crate::schema::EntityType;
        let entity_type = profile
            .entity_type(identifier_field)
            .or_else(|| match identifier_field {
                "src_ip" | "dest_ip" => Some(EntityType::Ip),
                "src_host" | "dest_host" => Some(EntityType::Host),
                "user" => Some(EntityType::User),
                _ => None,
            });
        match entity_type {
            Some(EntityType::Ip) => {
                if !ips.contains(&identifier_value.to_string()) {
                    ips.push(identifier_value.to_string());
                }
            }
            Some(EntityType::Host) => {
                if !hostnames.contains(&identifier_value.to_lowercase()) {
                    hostnames.push(identifier_value.to_lowercase());
                }
            }
            Some(EntityType::User) => {
                if !users.contains(&identifier_value.to_lowercase()) {
                    users.push(identifier_value.to_lowercase());
                }
            }
            _ => {}
        }

        (ips, hostnames, users)
    }

    /// Profile-aware identity-clause builder. Resolves the
    /// `src_ip` / `src_host` / `user` UDM-semantic columns through the active
    /// schema profile so the identity OR-clause targets the correct physical
    /// columns under OCSF. A UDM profile resolves each to its own column, so the
    /// emitted SQL is byte-identical to the legacy hardcoded form (modulo
    /// reserved-word quoting that the seam applies uniformly). Fields the schema
    /// does not map are skipped.
    pub(super) fn build_log_identity_clause_for(
        profile: &dyn crate::schema::SchemaProfile,
        ips: &[String],
        hostnames: &[String],
        users: &[String],
    ) -> Option<(String, Vec<String>)> {
        if ips.is_empty() && hostnames.is_empty() && users.is_empty() {
            return None;
        }
        let mut conditions: Vec<String> = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        if let Some(src_ip) = profile.udm_column_sql("src_ip") {
            for ip in ips {
                conditions.push(format!("{src_ip} = ?"));
                binds.push(ip.clone());
            }
        }
        // Host columns to match a hostname against. UDM: the single `src_host`
        // column (byte-identical). OCSF: a host shows up as the endpoint
        // (`device.hostname` — where sysmon PROCESS/FILE/REGISTRY events carry it),
        // the src endpoint, or the dst endpoint. Match ALL of them, or the asset
        // view only captures the subset where the host happens to be
        // `src_endpoint.hostname` (network events) and misses everything else
        // (NAN-1318; same device.hostname family as NAN-1295/1302).
        let host_cols: Vec<String> = if profile.id() == crate::schema::SchemaId::Ocsf {
            ["src_endpoint.hostname", "device.hostname", "dst_endpoint.hostname"]
                .iter()
                .map(|c| crate::query::escape_identifier(c))
                .collect()
        } else {
            profile.udm_column_sql("src_host").into_iter().collect()
        };
        for hostname in hostnames {
            for host_col in &host_cols {
                conditions.push(format!(
                    "(lower({host_col}) = ? OR startsWith(lower({host_col}), ?))"
                ));
                binds.push(hostname.clone());
                binds.push(format!("{}.", hostname));
            }
        }
        if let Some(user_col) = profile.udm_column_sql("user") {
            for user in users {
                conditions.push(format!("lower({user_col}) = ?"));
                binds.push(user.clone());
            }
        }
        if conditions.is_empty() {
            return None;
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
            Self::collect_asset_identifiers(identities, identifier_field, identifier_value, self.active_profile.as_ref());
        let (identity_clause, bind_values) = match Self::build_log_identity_clause_for(
            self.active_profile.as_ref(),
            &ips,
            &hostnames,
            &users,
        ) {
            Some(pair) => pair,
            None => return Ok((Vec::new(), 0, AssetFacets::default())),
        };

        let start_str = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let end_str = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f").to_string();

        // Physical column carrying the `user` UDM concept under the active schema.
        // UDM resolves to `"user"` (byte-identical to the prior hardcode modulo the
        // seam's reserved-word quoting); OCSF resolves to its promoted user column.
        // Falls back to the literal `user` when the schema doesn't map it so the
        // query still parses (it just yields no user facets).
        let user_col = self
            .active_profile
            .udm_column_sql("user")
            .unwrap_or_else(|| "user".to_string());

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
                        crate::search::classification::event_type_sql(self.active_profile.as_ref()),
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
                    filter_conditions
                        .push(format!("{user_col} IN ({})", placeholders.join(",")));
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
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let timeline_columns = self.asset_timeline_columns();
        let events_sql = format!(
            r#"SELECT {cols}, {event_type} AS event_type
            FROM {logs_table}
            PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT {limit} OFFSET {offset}"#,
            cols = timeline_columns,
            event_type = crate::search::classification::event_type_sql(self.active_profile.as_ref()),
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
                    return Err(parse_clickhouse_error(&e.to_string()));
                }
            };

            let mut response_bytes = Vec::new();
            loop {
                match cursor.next().await {
                    Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!("Asset events query error reading chunk: {}", e);
                        return Err(parse_clickhouse_error(&e.to_string()));
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
            Ok::<Vec<serde_json::Value>, SearchError>(events)
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
                    Ok(count) => Ok(count),
                    Err(e) => {
                        tracing::warn!("Asset count query failed: {}", e);
                        Err(parse_clickhouse_error(&e.to_string()))
                    }
                }
            };

            let (total_count, events) = tokio::join!(count_future, events_future);
            let total_count = total_count?;
            let events = events?;

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
                crate::search::classification::event_type_sql(self.active_profile.as_ref()),
                logs_table,
                start_str,
                end_str,
                identity_clause
            );

            let user_facet_sql = format!(
                r#"SELECT {user_col} AS user, count() as cnt
                FROM {logs_table}
                PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({})
                WHERE {user_col} != ''
                GROUP BY {user_col}
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
                    Ok(rows) => Ok(rows),
                    Err(e) => {
                        tracing::warn!("Asset combined facet query failed: {}", e);
                        Err(parse_clickhouse_error(&e.to_string()))
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
                    Err(e) => {
                        tracing::warn!("Asset user facet query failed: {}", e);
                        return Err(parse_clickhouse_error(&e.to_string()));
                    }
                }
                Ok::<Vec<(String, u64)>, SearchError>(facets)
            };

            let count_future = async {
                match apply_binds(clickhouse.query(&count_sql), &count_binds)
                    .fetch_one::<u64>()
                    .await
                {
                    Ok(count) => Ok(count),
                    Err(e) => {
                        tracing::warn!("Asset count query failed: {}", e);
                        Err(parse_clickhouse_error(&e.to_string()))
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
            let combined_facet_rows = combined_facet_rows?;
            let user_facets = user_facets?;
            let reliable_count = reliable_count?;
            let events = events?;

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

        // Auto-detect: check common identifier fields in priority order. The
        // priority list is UDM-semantic and fixed (preserving the legacy ordering
        // exactly); under OCSF each canonical field is resolved to the physical
        // column name the upstream result rows actually carry (e.g. `src_host` →
        // `src_endpoint.hostname`) for the JSON lookup, while the canonical name is
        // still returned as the identifier_field so identity resolution keeps
        // operating on UDM semantics (NAN-1241). For UDM the resolved key equals
        // the canonical name, so behavior is byte-identical.
        let profile = self.active_profile.as_ref();
        let identifier_fields = ["src_host", "dest_host", "src_ip", "dest_ip", "user", "mac"];

        // Map each canonical field to the raw result-row key(s) under the active
        // schema. UDM (and any field the schema maps to a plain column) → the
        // physical column name. Under OCSF a host can also be carried by
        // `device.hostname` (the sysmon endpoint), which no UDM canonical resolves
        // to — include it for the host concept so `device.hostname=… | asset`
        // auto-detects (NAN-1318). We still return the canonical `src_host` so
        // downstream identity resolution + the host clause (which now matches
        // device.hostname too) operate on host semantics.
        let is_ocsf = profile.id() == crate::schema::SchemaId::Ocsf;
        let result_keys = |canonical: &str| -> Vec<String> {
            let mut keys = match profile.resolve(canonical) {
                crate::schema::FieldResolution::ExplicitColumn(c) => vec![c],
                _ => vec![canonical.to_string()],
            };
            if is_ocsf && canonical == "src_host" {
                keys.push("device.hostname".to_string());
            }
            keys
        };

        for result in results.iter().take(10) {
            for field in &identifier_fields {
                for key in result_keys(field) {
                    if let Some(value) = result.get(&key).and_then(|v| v.as_str()) {
                        if !value.is_empty() {
                            return Ok((field.to_string(), value.to_string()));
                        }
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
    ) -> Result<(Option<String>, Option<String>), SearchError> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct AssetTimeRange {
            first_seen: String,
            last_seen: String,
        }

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok((None, None)),
        };

        let (ips, hostnames, users) =
            Self::collect_asset_identifiers(identities, identifier_field, identifier_value, self.active_profile.as_ref());
        let (identity_clause, identity_binds) =
            match Self::build_entity_identity_clause(&ips, &hostnames, &users) {
                Some(pair) => pair,
                None => return Ok((None, None)),
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
                Ok((first_seen, last_seen))
            }
            Err(e) => {
                tracing::warn!("Failed to query true asset time range: {}", e);
                Err(parse_clickhouse_error(&e.to_string()))
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
    ) -> Result<serde_json::Value, SearchError> {
        use serde_json::json;

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(json!({ "hashes": [], "domains": [] })),
        };

        let profile = self.active_profile.as_ref();
        let (ips, hostnames, users) =
            Self::collect_asset_identifiers(identities, identifier_field, identifier_value, self.active_profile.as_ref());
        let (identity_clause, identity_binds) =
            match Self::build_log_identity_clause_for(profile, &ips, &hostnames, &users) {
                Some(pair) => pair,
                None => return Ok(json!({ "hashes": [], "domains": [] })),
            };

        let start_str = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let end_str = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f").to_string();

        // Resolve every artifact source column + its prevalence companion through the
        // active schema profile (NAN-1241). Under UDM each resolves to its own name so
        // the emitted SQL is byte-identical to the legacy hardcode (modulo the seam's
        // reserved-word quoting); under OCSF they resolve to the promoted dotted
        // columns (e.g. `file_hash` → "file.hashes.sha256"). A branch whose source
        // column is unmapped is skipped entirely so no unknown-column reference is
        // emitted. `prevalence_*` are operational columns present in both schemas; if
        // a profile somehow doesn't map one we fall back to the literal `0` host_count.
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(profile));
        let ip_exclude = r"^\d+\.\d+\.\d+\.\d+$";

        // Build one UNION ALL branch for a hash artifact (file_hash / process_hash).
        // Returns None when the source column is unmapped under the active schema.
        let hash_branch = |udm_col: &str, prevalence_udm: &str| -> Option<String> {
            let col = profile.udm_column_sql(udm_col)?;
            let prev = profile
                .udm_column_sql(prevalence_udm)
                .unwrap_or_else(|| "0".to_string());
            Some(format!(
                "SELECT lower({col}) as artifact, min(timestamp) as first_ts, max(timestamp) as last_ts, count() as cnt, \
                    max({prev}) as host_count \
                FROM {logs_table} \
                PREWHERE timestamp BETWEEN '{start_str}' AND '{end_str}' AND ({identity_clause}) \
                WHERE {col} != '' AND length({col}) >= 32 AND match({col}, '^[a-fA-F0-9]+$') \
                GROUP BY lower({col})"
            ))
        };

        // Build one UNION ALL branch for a domain artifact (dest_host / query / url_domain).
        // NOTE: Use `match(...) = 0` instead of `NOT match(...)` — ClickHouse query
        // optimizer mishandles `NOT match()` when PREWHERE contains OR conditions,
        // silently returning 0 rows. The `= 0` form prevents the bad optimization.
        let domain_branch = |udm_col: &str| -> Option<String> {
            let col = profile.udm_column_sql(udm_col)?;
            let prev = profile
                .udm_column_sql("prevalence_dest_domain")
                .unwrap_or_else(|| "0".to_string());
            Some(format!(
                "SELECT lower({col}) as artifact, min(timestamp) as first_ts, max(timestamp) as last_ts, count() as cnt, \
                    max({prev}) as host_count \
                FROM {logs_table} \
                PREWHERE timestamp BETWEEN '{start_str}' AND '{end_str}' AND ({identity_clause}) \
                WHERE {col} != '' AND position({col}, '.') > 0 AND match({col}, '{ip_exclude}') = 0 \
                GROUP BY lower({col})"
            ))
        };

        let hash_branches: Vec<String> = ["file_hash", "process_hash"]
            .iter()
            .zip(["prevalence_file_hash", "prevalence_process_hash"])
            .filter_map(|(udm_col, prev)| hash_branch(udm_col, prev))
            .collect();
        let domain_branches: Vec<String> = ["dest_host", "query", "url_domain"]
            .iter()
            .filter_map(|udm_col| domain_branch(udm_col))
            .collect();

        // identity_clause is bound once per branch — repeat the binds accordingly.
        let repeat_binds = |n: usize| -> Vec<String> {
            let mut v = Vec::with_capacity(identity_binds.len() * n);
            for _ in 0..n {
                v.extend(identity_binds.iter().cloned());
            }
            v
        };
        let hash_binds = repeat_binds(hash_branches.len());
        let domain_binds = repeat_binds(domain_branches.len());

        let hash_sql = if hash_branches.is_empty() {
            String::new()
        } else {
            format!(
                "SELECT artifact, \
                    formatDateTime(min(first_ts), '%Y-%m-%dT%H:%i:%sZ') as first_ts, \
                    formatDateTime(max(last_ts), '%Y-%m-%dT%H:%i:%sZ') as last_ts, \
                    sum(cnt) as cnt, \
                    max(host_count) as host_count \
                 FROM ( {} ) GROUP BY artifact ORDER BY last_ts DESC LIMIT 50 \
                  SETTINGS max_execution_time=30",
                hash_branches.join(" UNION ALL ")
            )
        };
        let domain_sql = if domain_branches.is_empty() {
            String::new()
        } else {
            format!(
                "SELECT artifact, \
                    formatDateTime(min(first_ts), '%Y-%m-%dT%H:%i:%sZ') as first_ts, \
                    formatDateTime(max(last_ts), '%Y-%m-%dT%H:%i:%sZ') as last_ts, \
                    sum(cnt) as cnt, \
                    max(host_count) as host_count \
                 FROM ( {} ) GROUP BY artifact ORDER BY last_ts DESC LIMIT 50 \
                  SETTINGS max_execution_time=30",
                domain_branches.join(" UNION ALL ")
            )
        };

        // Run both queries in parallel (skip when a profile maps no source columns).
        let hash_future = async {
            if hash_sql.is_empty() {
                return Ok(Vec::new());
            }
            let mut hash_query = clickhouse.query(&hash_sql);
            for val in &hash_binds {
                hash_query = hash_query.bind(val);
            }
            hash_query
                .fetch_all::<(String, String, String, u64, u16)>()
                .await
        };

        let domain_future = async {
            if domain_sql.is_empty() {
                return Ok(Vec::new());
            }
            let mut domain_query = clickhouse.query(&domain_sql);
            for val in &domain_binds {
                domain_query = domain_query.bind(val);
            }
            domain_query
                .fetch_all::<(String, String, String, u64, u16)>()
                .await
        };

        let (hash_result, domain_result) = tokio::join!(hash_future, domain_future);

        let hashes: Vec<serde_json::Value> = match hash_result {
            Ok(rows) => rows.into_iter().map(|(artifact, first_ts, last_ts, count, host_count)| {
                json!({ "artifact": artifact, "first_ts": first_ts, "last_ts": last_ts, "count": count, "host_count": host_count })
            }).collect(),
            Err(e) => {
                tracing::warn!("Failed to query asset artifact hashes: {}", e);
                return Err(parse_clickhouse_error(&e.to_string()));
            }
        };

        let domains: Vec<serde_json::Value> = match domain_result {
            Ok(rows) => rows.into_iter().map(|(artifact, first_ts, last_ts, count, host_count)| {
                json!({ "artifact": artifact, "first_ts": first_ts, "last_ts": last_ts, "count": count, "host_count": host_count })
            }).collect(),
            Err(e) => {
                tracing::warn!("Failed to query asset artifact domains: {}", e);
                return Err(parse_clickhouse_error(&e.to_string()));
            }
        };

        Ok(json!({ "hashes": hashes, "domains": domains }))
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
    ) -> Result<serde_json::Value, SearchError> {
        use serde_json::json;

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(json!({ "hashes": [], "domains": [] })),
        };

        let profile = self.active_profile.as_ref();
        let (ips, hostnames, users) =
            Self::collect_asset_identifiers(identities, identifier_field, identifier_value, self.active_profile.as_ref());
        let (identity_clause, identity_binds) =
            match Self::build_log_identity_clause_for(profile, &ips, &hostnames, &users) {
                Some(pair) => pair,
                None => return Ok(json!({ "hashes": [], "domains": [] })),
            };

        let start_str = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let end_str = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(profile));
        let ip_exclude = r"^\d+\.\d+\.\d+\.\d+$";

        // Build artifact IN placeholders
        let in_placeholders = |artifacts: &[String]| -> String {
            artifacts.iter().map(|_| "?").collect::<Vec<_>>().join(", ")
        };

        // Build one UNION ALL branch for an artifact source column, resolving the
        // column through the active schema profile (NAN-1241). Returns the branch
        // SQL plus the binds it consumes, in clause order (identity binds first,
        // then artifact-IN binds when filtered). `None` when the column is unmapped
        // under the active schema so the branch is skipped entirely. `is_hash`
        // selects the hash length/hex predicate vs the domain dotted/IP-exclude one.
        // For UDM every column resolves to itself → byte-identical SQL.
        let branch = |udm_col: &str,
                      is_hash: bool,
                      filter: Option<&[String]>|
         -> Option<(String, Vec<String>)> {
            let col = profile.udm_column_sql(udm_col)?;
            let mut binds: Vec<String> = identity_binds.clone();
            let predicate = match filter {
                Some(values) => {
                    binds.extend(values.iter().cloned());
                    let placeholders = in_placeholders(values);
                    if is_hash {
                        format!(
                            "{col} != '' AND length({col}) >= 32 AND lower({col}) IN ({placeholders})"
                        )
                    } else {
                        format!(
                            "{col} != '' AND position({col}, '.') > 0 AND lower({col}) IN ({placeholders})"
                        )
                    }
                }
                None => {
                    if is_hash {
                        format!("{col} != '' AND length({col}) >= 32 AND match({col}, '^[a-fA-F0-9]+$')")
                    } else {
                        format!("{col} != '' AND position({col}, '.') > 0 AND match({col}, '{ip_exclude}') = 0")
                    }
                }
            };
            let sql = format!(
                "SELECT lower({col}) as artifact, timestamp as ts \
                 FROM {logs_table} \
                 PREWHERE timestamp BETWEEN '{start_str}' AND '{end_str}' AND ({identity_clause}) \
                 WHERE {predicate}"
            );
            Some((sql, binds))
        };

        // Wrap a set of UNION ALL branches into the final occurrences query.
        let wrap = |branches: Vec<(String, Vec<String>)>| -> (String, Vec<String>) {
            if branches.is_empty() {
                return (String::new(), Vec::new());
            }
            let mut binds: Vec<String> = Vec::new();
            let frags: Vec<String> = branches
                .into_iter()
                .map(|(frag, b)| {
                    binds.extend(b);
                    frag
                })
                .collect();
            let sql = format!(
                "SELECT artifact, formatDateTime(ts, '%Y-%m-%dT%H:%i:%sZ') as timestamp \
                 FROM ( {} ) ORDER BY ts LIMIT 100 BY artifact \
                  SETTINGS max_execution_time=30",
                frags.join(" UNION ALL ")
            );
            (sql, binds)
        };

        // Hash occurrences. An explicit empty filter slice means "return nothing".
        let (hash_sql, hash_binds) = match hash_filter {
            Some(hashes) if hashes.is_empty() => (String::new(), Vec::new()),
            _ => {
                let branches: Vec<(String, Vec<String>)> = ["file_hash", "process_hash"]
                    .iter()
                    .filter_map(|c| branch(c, true, hash_filter))
                    .collect();
                wrap(branches)
            }
        };

        // Domain occurrences. An explicit empty filter slice means "return nothing".
        let (domain_sql, domain_binds) = match domain_filter {
            Some(domains) if domains.is_empty() => (String::new(), Vec::new()),
            _ => {
                let branches: Vec<(String, Vec<String>)> = ["dest_host", "query", "url_domain"]
                    .iter()
                    .filter_map(|c| branch(c, false, domain_filter))
                    .collect();
                wrap(branches)
            }
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
                    return Err(parse_clickhouse_error(&e.to_string()));
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
                    return Err(parse_clickhouse_error(&e.to_string()));
                }
            }
        };

        Ok(json!({ "hashes": hashes, "domains": domains }))
    }

    /// Detect event type from event fields for timeline display
    /// Classify an event into a type category.
    /// Ordering and logic mirrors the SQL CASE WHEN in the facet/filter queries
    /// and the frontend getEventType() to ensure consistent classification.
    fn detect_event_type(&self, event: &serde_json::Value) -> String {
        // The paginated events query computes `event_type` server-side via the
        // profile-aware classifier (`classification::event_type_sql`), so under
        // OCSF — where the UDM key reads below would all be absent (those columns
        // aren't projected) — we trust the SQL classification. Falls through to the
        // UDM JSON-key heuristic only when the column is missing (e.g. callers that
        // pass raw rows without the computed column). This keeps UDM byte-identical
        // (the classifier and the heuristic agree on the UDM mapping) while making
        // OCSF correct (NAN-1241).
        if let Some(server_type) = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            return server_type.to_string();
        }

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

    /// Build a human-readable summary for an event based on its type.
    ///
    /// Profile-aware (NAN-1241/NAN-1303): the events fed here come from the
    /// timeline query, whose projection ([`Self::asset_timeline_columns`]) keys
    /// each column by its schema-NATIVE name via `display_field_name`. This reads
    /// the same `display_field_name` keys, so it works whether the row carries UDM
    /// canonical names (UDM — identity mapping, byte-identical) or native OCSF
    /// columns (`dst_endpoint.hostname`, …). Empty values are skipped so the
    /// fallback chain reaches a populated field (e.g. a NETWORK event with no
    /// hostname falls through to the IP instead of rendering `:port`).
    fn build_event_summary(&self, event: &serde_json::Value, event_type: &str) -> String {
        let profile = self.active_profile.as_ref();
        // Resolve a UDM-semantic concept → the native key the row carries, then
        // read it as a non-empty string / number.
        let s = |concept: &str| -> Option<&str> {
            let key = profile.display_field_name(concept)?;
            event
                .get(key.as_str())
                .and_then(|v| v.as_str())
                .filter(|x| !x.is_empty())
        };
        let n = |concept: &str| -> Option<u64> {
            let key = profile.display_field_name(concept)?;
            event.get(key.as_str()).and_then(|v| v.as_u64())
        };
        match event_type {
            "PROCESS" => {
                let proc_name = s("process_name")
                    .or_else(|| s("command_line"))
                    .unwrap_or("Unknown process");
                match n("process_id") {
                    Some(p) => format!("{} ({})", proc_name, p),
                    None => proc_name.to_string(),
                }
            }
            "FILE" => s("file_name")
                .or_else(|| s("file_path"))
                .unwrap_or("Unknown file")
                .to_string(),
            "NETWORK" => {
                let dest = s("dest_host").or_else(|| s("dest_ip")).unwrap_or("Unknown");
                match n("dest_port") {
                    Some(p) => format!("{}:{}", dest, p),
                    None => dest.to_string(),
                }
            }
            "DNS" => s("query")
                .or_else(|| s("dest_host"))
                .or_else(|| s("dest_ip"))
                .unwrap_or("Unknown query")
                .to_string(),
            "ALERT" => s("rule_name")
                .or_else(|| s("message"))
                .unwrap_or("Alert triggered")
                .to_string(),
            "AUTH_SUCCESS" | "AUTH_FAILURE" => {
                let user = s("user").unwrap_or("Unknown");
                match s("auth_type") {
                    Some(t) => format!("{} via {}", user, t),
                    None => user.to_string(),
                }
            }
            _ => s("message").or_else(|| s("action")).unwrap_or("Event").to_string(),
        }
    }
}

#[cfg(test)]
mod nan1300_tests {
    use crate::schema::{OcsfProfile, UdmProfile};
    use crate::search::service::SearchService;

    /// NAN-1300: native OCSF identifier fields must classify into the right
    /// ip/host/user bucket via the profile's EntityType, not be dropped by a
    /// hardcoded UDM-name match (which left asset dossier/view empty).
    #[test]
    fn ocsf_native_identifiers_classify_not_dropped() {
        let p = OcsfProfile::new();
        let cases = [
            // Native OCSF fields (the original NAN-1300 gap).
            ("device.hostname", "ws-eng-001.corp.local"),
            ("src_endpoint.hostname", "ws-eng-001.corp.local"),
            ("src_endpoint.ip", "89.248.167.131"),
            ("user.name", "msanchez"),
            ("actor.user.name", "msanchez"),
            // UDM-canonical names the asset command emits as primary_identifier
            // even under OCSF — the OCSF registry doesn't know them, so they must
            // bucket via the UDM-canonical fallback (regression guard: classifying
            // by entity_type alone dropped these → 0-result asset views).
            ("src_host", "ws-eng-001.corp.local"),
            ("src_ip", "89.248.167.131"),
            ("user", "msanchez"),
        ];
        for (field, value) in cases {
            let (ips, hosts, users) =
                SearchService::collect_asset_identifiers(&[], field, value, &p);
            assert!(
                ips.len() + hosts.len() + users.len() == 1,
                "OCSF native field {field} must classify into exactly one bucket (NAN-1300), \
                 got ips={ips:?} hosts={hosts:?} users={users:?}"
            );
        }
    }

    /// NAN-1300 parity: UDM names still bucket exactly as before (host/user
    /// lowercased, ip verbatim).
    #[test]
    fn udm_identifiers_unchanged() {
        let p = UdmProfile::new();
        let (ips, _, _) = SearchService::collect_asset_identifiers(&[], "src_ip", "10.0.0.1", &p);
        assert_eq!(ips, vec!["10.0.0.1".to_string()]);
        let (_, hosts, _) =
            SearchService::collect_asset_identifiers(&[], "src_host", "WS-ENG-001", &p);
        assert_eq!(hosts, vec!["ws-eng-001".to_string()]);
        let (_, _, users) = SearchService::collect_asset_identifiers(&[], "user", "MSanchez", &p);
        assert_eq!(users, vec!["msanchez".to_string()]);
    }
}

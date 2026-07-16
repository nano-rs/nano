// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use super::lateral::source_scope_sql_predicate;
use crate::auth::ScopeSet;
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

    /// NAN-1797/NAN-1799: `| asset` runs FRESH identity-clause queries against
    /// the logs table (and identity_observations) that do NOT inherit the base
    /// query's injected source-scope gate — on the fast path there is no base
    /// query at all. The caller's `ScopeSet` is threaded down here and its
    /// deny-set exclusion is ANDed into every scan those helpers issue (see
    /// [`source_scope_sql_predicate`]). An empty deny set emits nothing
    /// (byte-identical SQL to the pre-scoping form).
    pub(crate) async fn build_asset_view(
        &self,
        results: Vec<serde_json::Value>,
        asset_info: &AssetCommandInfo,
        time_range: &TimeRange,
        pre_extracted_identifier: Option<(String, String)>,
        scope: &ScopeSet,
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
                scope,
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
                scope,
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
                            scope,
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
                            scope,
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
    ///
    /// `scope` (NAN-1797/NAN-1799): the caller's source-scope deny-set. Every
    /// scan below is a fresh hand-built query that does not inherit the main
    /// search's injected gate, so the deny-set exclusion is ANDed into each of
    /// them here. An empty deny set emits nothing (byte-identical SQL).
    pub async fn query_asset_events_paginated(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[serde_json::Value],
        time_range: &TimeRange,
        offset: usize,
        limit: usize,
        filters: Option<&AssetEventFilters>,
        scope: &ScopeSet,
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

        let start_str = crate::sql_hygiene::format_ch_bound_micros(&time_range.start).to_string();
        let end_str = crate::sql_hygiene::format_ch_bound_micros(&time_range.end).to_string();

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

        // NAN-1797: render the caller's deny-set ONCE; ANDed into every logs
        // scan below — the events page, the filtered count, the combined
        // source_type/event_type facet (which otherwise enumerated exactly the
        // caller's hidden sources), the user facet, and the unfiltered count.
        // `None` (unrestricted) leaves every SQL string byte-identical to the
        // pre-scoping form.
        let scope_predicate = source_scope_sql_predicate("source_type", scope.deny_set());

        let where_clause =
            build_asset_events_where(&filter_conditions, scope_predicate.as_deref());

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
            let combined_facet_sql = build_asset_combined_facet_sql(
                crate::search::classification::event_type_sql(self.active_profile.as_ref()),
                &logs_table,
                &start_str,
                &end_str,
                &identity_clause,
                scope_predicate.as_deref(),
            );

            let user_facet_sql = build_asset_user_facet_sql(
                &user_col,
                &logs_table,
                &start_str,
                &end_str,
                &identity_clause,
                scope_predicate.as_deref(),
            );

            // Separate count query as fallback — the combined facet query can fail
            // (e.g. complex CASE WHEN in GROUP BY) while this simple count always works
            let count_sql = build_asset_count_sql(
                &logs_table,
                &start_str,
                &end_str,
                &identity_clause,
                scope_predicate.as_deref(),
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
    ///
    /// `scope` (NAN-1797): identity_observations is per-event data derived from
    /// logs — its `source` column IS the originating source_type (see
    /// `identity_observations_mv` in clickhouse/init.sql) — so a denied source
    /// must not contribute identity correlations (the user↔host↔ip rows shown
    /// in the asset profile, which also widen the events-scan identity clause)
    /// to a scoped caller. An empty deny set emits nothing (byte-identical SQL).
    async fn resolve_asset_identities(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        time_range: &TimeRange,
        max_age: std::time::Duration,
        scope: &ScopeSet,
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
        let start_str = crate::sql_hygiene::format_ch_bound(&time_range.start).to_string();
        let end_str = crate::sql_hygiene::format_ch_bound(&time_range.end).to_string();

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
        // NAN-1797: `source` is identity_observations' name for source_type
        // (stamped by identity_observations_mv). Empty deny set → empty splice
        // (byte-identical SQL).
        let scope_and = source_scope_sql_predicate("source", scope.deny_set())
            .map(|pred| format!("\n              AND {pred}"))
            .unwrap_or_default();
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
              AND observed_at >= now() - INTERVAL {} SECOND{scope_and}
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
    ///
    /// `scope` (NAN-1801): every UNION ALL branch below is a fresh hand-built
    /// scan over the logs table that bypasses the nPL injection gate, so the
    /// caller's deny-set predicate is ANDed into each branch's WHERE directly.
    /// An empty deny set emits nothing (byte-identical SQL).
    pub async fn query_asset_artifact_summary(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[serde_json::Value],
        time_range: &TimeRange,
        scope: &ScopeSet,
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

        let start_str = crate::sql_hygiene::format_ch_bound_micros(&time_range.start).to_string();
        let end_str = crate::sql_hygiene::format_ch_bound_micros(&time_range.end).to_string();

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

        // NAN-1801: caller's source-scope gate, ANDed into every branch's WHERE.
        // Empty deny set → empty splice (byte-identical SQL).
        let scope_and = source_scope_sql_predicate("source_type", scope.deny_set())
            .map(|pred| format!(" AND {pred}"))
            .unwrap_or_default();

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
                WHERE {col} != '' AND length({col}) >= 32 AND match({col}, '^[a-fA-F0-9]+$'){scope_and} \
                GROUP BY lower({col})"
            ))
        };

        // Build one UNION ALL branch for a domain artifact (dest_host / query / url_domain).
        // NOTE: Use `match(...) = 0` instead of `NOT match(...)` — ClickHouse query
        // optimizer mishandles `NOT match()` when PREWHERE contains OR conditions,
        // silently returning 0 rows. The `= 0` form prevents the bad optimization.
        let domain_branch = |udm_col: &str| -> Option<String> {
            let col = profile.udm_column_sql(udm_col)?;
            // Look the artifact's prevalence up in the shared domain dict keyed by
            // THIS branch's own column, not the `prevalence_dest_domain` materialized
            // stamp. That stamp only holds `dest_host`'s host_count, so attributing it
            // to the `query` / `url_domain` branches reported the wrong entity's
            // prevalence (a dest_host stamp on a DNS-query artifact). `dest_host`'s
            // own result is unchanged: `prevalence_dest_domain` is itself
            // `dictGetOrDefault(domain_prevalence_dict, host_count, lower(dest_host), 9999)`
            // and the IP-exclusion WHERE below drops the 65535 (IP) case the stamp
            // used. `max(...)` is a no-op collapse — the value is functionally
            // determined by the `lower({col})` group key.
            Some(format!(
                "SELECT lower({col}) as artifact, min(timestamp) as first_ts, max(timestamp) as last_ts, count() as cnt, \
                    max(dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower({col}), toUInt16(9999))) as host_count \
                FROM {logs_table} \
                PREWHERE timestamp BETWEEN '{start_str}' AND '{end_str}' AND ({identity_clause}) \
                WHERE {col} != '' AND position({col}, '.') > 0 AND match({col}, '{ip_exclude}') = 0{scope_and} \
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
    ///
    /// `scope` (NAN-1801): like the summary query, every UNION ALL branch is a
    /// hand-built logs scan outside the nPL injection gate — the deny-set
    /// predicate is ANDed into each branch. Empty deny set → byte-identical SQL.
    pub async fn query_asset_artifact_occurrences(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[serde_json::Value],
        time_range: &TimeRange,
        hash_filter: Option<&[String]>,
        domain_filter: Option<&[String]>,
        scope: &ScopeSet,
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

        let start_str = crate::sql_hygiene::format_ch_bound_micros(&time_range.start).to_string();
        let end_str = crate::sql_hygiene::format_ch_bound_micros(&time_range.end).to_string();
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(profile));
        let ip_exclude = r"^\d+\.\d+\.\d+\.\d+$";

        // NAN-1801: caller's source-scope gate, ANDed into every branch's WHERE.
        // Empty deny set → empty splice (byte-identical SQL).
        let scope_and = source_scope_sql_predicate("source_type", scope.deny_set())
            .map(|pred| format!(" AND {pred}"))
            .unwrap_or_default();

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
                 WHERE {predicate}{scope_and}"
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

    /// Hourly activity for one entity from `entity_time_range_agg` (NAN-1864).
    ///
    /// This is the cheap path that makes entity baselining viable at scale. The
    /// raw `logs` table is `ORDER BY (source_type, timestamp, src_host, …)`, so a
    /// per-entity query over it is a time-range SCAN — measured on a 2B-row Saturn
    /// tenant, a single 30-day baseline query for an ordinary workstation read
    /// 5.5 GiB in 32s, because the entity value is the third sort key and prunes
    /// nothing across time. `entity_time_range_agg` is `ORDER BY (entity_type,
    /// entity_value, time_bucket)`, so the same window is a keyed lookup: ~2.5 MiB
    /// in tens of milliseconds. The shadow investigator derives an entity's
    /// coverage, hour-of-day rhythm, and volume distribution from these buckets
    /// instead of scanning raw logs for them.
    ///
    /// `entity_type` is the BASELINE type (`host` / `ip` / `user`); it is mapped
    /// to the agg's own vocabulary (`src_host` / `src_ip` / `user`) here. Returns
    /// buckets in ascending time order, or an empty vec when the entity has no
    /// history in the window (which the caller MUST treat as "unknown", never as
    /// "clean" — see `baseline::BaselineCoverage`). Unsupported entity types and a
    /// missing ClickHouse client both yield an empty vec.
    ///
    /// `entity_value` is bound (it originates in log data); the timestamps and the
    /// mapped `entity_type` literal are our own and are inlined. The mapped type
    /// is matched exactly so the `(entity_type, entity_value)` sort-key prefix
    /// prunes — wrapping either side in `lower()` would defeat that and turn the
    /// lookup back into the scan this method exists to avoid.
    pub async fn entity_activity_buckets(
        &self,
        entity_type: &str,
        entity_value: &str,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<EntityActivityBucket>, SearchError> {
        let agg_entity_type = match entity_type {
            "host" => "src_host",
            "ip" => "src_ip",
            "user" => "user",
            // Artifacts (hash/domain/file) are not keyed in this table; the
            // artifact-prevalence stack covers them. Nothing to look up.
            _ => return Ok(Vec::new()),
        };

        // Match the agg's stored casing exactly — the lookup is an EQUALITY bind
        // (so the sort-key prefix prunes), not a case-insensitive `lower()`
        // compare. ALL THREE entity branches of `entity_time_range_agg` populate
        // `entity_value` through `lower(...)`: `lower(src_host)`, `lower(src_ip)`,
        // and `lower(user)` / `lower(user_unified)` (clickhouse/init.sql:1574-1609,
        // 128_entity_mv_split_and_ocsf_aggregation_mvs.sql). So a value extracted
        // with any other casing — `WS-FIN-001`, `Administrator`, `CORP\JSmith` —
        // must be lowered here or it silently misses its own lowercase row and the
        // entity is falsely reported as having NO history (a heavily-active
        // privileged account reads as dark). Verified on Saturn: 0 mixed-case rows
        // across all three entity types.
        let normalized_value = entity_value.to_lowercase();

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(Vec::new()),
        };

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct BucketRow {
            hour_start: String,
            event_count: u64,
        }

        // Timestamps are ours → inlined as DateTime64 literals so the comparison
        // stays on the `time_bucket` sort key and prunes. `entity_value` is
        // log-derived → bound.
        let sql = format!(
            "SELECT \
                formatDateTime(toStartOfHour(time_bucket), '%Y-%m-%dT%H:%i:%sZ') AS hour_start, \
                toUInt64(sum(event_count)) AS event_count \
             FROM {tbl} \
             WHERE entity_type = '{etype}' \
               AND entity_value = ? \
               AND time_bucket >= toDateTime64('{start}', 6) \
               AND time_bucket <  toDateTime64('{end}', 6) \
             GROUP BY hour_start \
             ORDER BY hour_start",
            tbl = self.table_names.read("entity_time_range_agg"),
            etype = agg_entity_type,
            start = start.format("%Y-%m-%d %H:%M:%S%.6f"),
            end = end.format("%Y-%m-%d %H:%M:%S%.6f"),
        );

        match clickhouse
            .query(&sql)
            .bind(&normalized_value)
            .fetch_all::<BucketRow>()
            .await
        {
            Ok(rows) => Ok(rows
                .into_iter()
                .filter_map(|r| {
                    parse_asset_timestamp(&r.hour_start).map(|hour_start| EntityActivityBucket {
                        hour_start,
                        event_count: r.event_count,
                    })
                })
                .collect()),
            Err(e) => {
                tracing::warn!(
                    entity_type = entity_type,
                    "entity_time_range_agg lookup failed: {}",
                    e
                );
                Err(parse_clickhouse_error(&e.to_string()))
            }
        }
    }

    /// Per-`(dimension, value)` first-seen for one entity over a window, in ONE
    /// scoped scan of the raw `logs` table (NAN-1864 follow-up).
    ///
    /// This replaces N separate per-dimension scans. `logs` has no entity
    /// pruning, so each per-dimension scan re-read the same ~767 MiB of granules;
    /// folding the dimensions into a single `ARRAY JOIN` reads those granules
    /// ONCE and groups every dimension in one pass (`LIMIT n BY dim` keeps each
    /// dimension's own top-n by first-seen, so the new-value guarantee survives
    /// per dimension). Measured on Saturn: ~1.1 GiB for three dimensions in one
    /// scan vs ~2.3 GiB for three separate.
    ///
    /// SECURITY (NAN-1801): this bypasses the nPL scope gate, so the caller's
    /// `ScopeSet` deny-set is ANDed into the WHERE directly via
    /// [`source_scope_sql_predicate`] — byte-identical to unscoped SQL when the
    /// deny set is empty. This is the SAME mechanism the asset artifact scans use.
    ///
    /// `source_side_only` picks the entity filter: `true` pins the entity to the
    /// actor (source) side — required for "what did X DO" dimensions so another
    /// host's actions aren't credited to it (see `baseline::DimScope`); `false`
    /// is bi-directional. `entity_value` is bound (log-derived); timestamps, the
    /// resolved columns, and the dimension labels are ours and inlined. Fields the
    /// active profile does not map are skipped.
    ///
    /// FAST PATH (NAN-1888): when the request matches what the
    /// `entity_dimension_day_agg` MVs bake in ([`agg_dimension_set`];
    /// private-RFC1918-only for `ip` entities) AND the caller's source scope is
    /// compatible ([`scope_within_agg_exclusions`], NAN-1895), the same answer
    /// is served from the day-grain first-seen aggregate — a sort-key-prefix
    /// lookup instead of a lookback-sized raw scan (~33.5s cold on a 2B-row
    /// tenant). The path SELF-ENABLES off the MV activation TIME: no env flag,
    /// no backfill required. The MVs accumulate from deploy-time forward, and
    /// `entity_dimension_firsts_from_agg` serves only when this query's whole
    /// lookback is at/after `baseline_agg_meta.active_since` (or the
    /// pre-activation days are backfill-markered); otherwise it returns None and
    /// this method transparently falls back to the raw scan — so a
    /// freshly-migrated tenant is correct from the first query, recent-window
    /// queries auto-speed-up ~max-lookback after deploy, and queries reaching
    /// before deploy-time stay on raw. Backfill is an OPTIONAL accelerator that
    /// only buys immediate historical-window speedup.
    #[allow(clippy::too_many_arguments)]
    pub async fn entity_dimension_firsts(
        &self,
        scope: &ScopeSet,
        entity_type: &str,
        entity_value: &str,
        source_side_only: bool,
        dim_udm_fields: &[&str],
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        per_dim_limit: usize,
    ) -> Result<Vec<DimensionFirst>, SearchError> {
        // Entity value is matched case-insensitively (`lower(col) = ?` on the
        // raw path, stored-lowercase equality on the agg path), so bind the
        // lowercased value.
        let value_lower = entity_value.to_lowercase();

        // FAST PATH (NAN-1888) — see the doc comment. Self-enabling off the MV
        // activation TIME: no env flag, no manual step, no backfill required.
        // The MVs accumulate from deploy-time forward, and
        // `entity_dimension_firsts_from_agg` serves only when this query's whole
        // lookback is at/after `baseline_agg_meta.active_since` (or the
        // pre-activation days are backfill-markered); otherwise it returns None
        // and we fall through to raw. So ~max-lookback after deploy, recent
        // baseline queries auto-speed-up while queries reaching before
        // deploy-time transparently use raw. The scope check
        // ([`scope_within_agg_exclusions`], NAN-1895) keeps the agg off-limits
        // to callers denied any source the agg still includes.
        // Fields the profile does not map are skipped, mirroring the raw path's
        // tuple filter, so both paths answer for the same dimension set.
        let mapped_fields: Vec<&str> = dim_udm_fields
            .iter()
            .copied()
            .filter(|f| self.active_profile.udm_column_sql(f).is_some())
            .collect();
        if scope_within_agg_exclusions(scope)
            && baseline_agg_can_serve(entity_type, &value_lower, source_side_only, &mapped_fields)
        {
            if let Some(rows) = self
                .entity_dimension_firsts_from_agg(
                    entity_type,
                    &value_lower,
                    &mapped_fields,
                    start,
                    end,
                    per_dim_limit,
                )
                .await
            {
                return Ok(rows);
            }
        }
        self.entity_dimension_firsts_raw(
            scope,
            entity_type,
            &value_lower,
            source_side_only,
            dim_udm_fields,
            start,
            end,
            per_dim_limit,
        )
        .await
    }

    /// The raw-logs lookback scan behind [`entity_dimension_firsts`] — the
    /// path every request took before NAN-1888, byte-identical SQL. Kept as
    /// its own method so the agg fast path can fall back to it and the local
    /// parity test can drive both paths independently. `value_lower` is the
    /// already-lowercased entity value.
    #[allow(clippy::too_many_arguments)]
    async fn entity_dimension_firsts_raw(
        &self,
        scope: &ScopeSet,
        entity_type: &str,
        value_lower: &str,
        source_side_only: bool,
        dim_udm_fields: &[&str],
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        per_dim_limit: usize,
    ) -> Result<Vec<DimensionFirst>, SearchError> {
        use crate::sql_hygiene::escape_sql_string;

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(Vec::new()),
        };
        let profile = self.active_profile.as_ref();

        // NEW-TO-ENTITY: match the account's whole footprint (not agg-aligned), so
        // a user's src_user/dest_user activity is not missed.
        let (entity_pred, entity_binds) = match baseline_entity_predicate(
            profile,
            entity_type,
            value_lower,
            source_side_only,
            false,
        ) {
            Some(p) => p,
            None => return Ok(Vec::new()),
        };

        // Resolve each dimension field to its physical column; skip unmapped.
        // `toString(...)` unifies the tuple element type (dest_port is numeric).
        let tuples: Vec<String> = dim_udm_fields
            .iter()
            .filter_map(|f| {
                profile
                    .udm_column_sql(f)
                    .map(|col| format!("('{}', toString({}))", escape_sql_string(f), col))
            })
            .collect();
        if tuples.is_empty() {
            return Ok(Vec::new());
        }

        let logs_table = self
            .table_names
            .read(Self::logs_table_key(profile));

        let scope_pred = source_scope_sql_predicate("source_type", scope.deny_set())
            .map(|p| format!(" AND {p}"))
            .unwrap_or_default();

        let sql = format!(
            "SELECT dim, val, toUInt64(count()) AS cnt, \
                    formatDateTime(min(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS first_seen \
             FROM ( \
               SELECT timestamp, d.1 AS dim, d.2 AS val \
               FROM {logs_table} \
               ARRAY JOIN [{tuples}] AS d \
               WHERE timestamp >= toDateTime64('{start}', 6) \
                 AND timestamp <  toDateTime64('{end}', 6) \
                 AND {entity_pred} \
                 AND lower(source_type) != 'audit'{scope_pred} \
             ) \
             WHERE trimBoth(val) != '' AND val != '-' AND val != '0' AND lower(val) != 'null' \
             GROUP BY dim, val \
             ORDER BY first_seen DESC \
             LIMIT {per_dim_limit} BY dim",
            tuples = tuples.join(", "),
            start = start.format("%Y-%m-%d %H:%M:%S%.6f"),
            end = end.format("%Y-%m-%d %H:%M:%S%.6f"),
        );

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct FirstRow {
            dim: String,
            val: String,
            cnt: u64,
            first_seen: String,
        }

        let mut query = clickhouse.query(&sql);
        for b in &entity_binds {
            query = query.bind(b);
        }
        match query.fetch_all::<FirstRow>().await {
            Ok(rows) => Ok(rows
                .into_iter()
                .filter_map(|r| {
                    parse_asset_timestamp(&r.first_seen).map(|first_seen| DimensionFirst {
                        dimension: r.dim,
                        value: r.val,
                        count: r.cnt,
                        first_seen,
                    })
                })
                .collect()),
            Err(e) => {
                tracing::warn!(entity_type, "entity_dimension_firsts scan failed: {}", e);
                Err(parse_clickhouse_error(&e.to_string()))
            }
        }
    }

    /// Serve `entity_dimension_firsts` from the day-grain first-seen aggregate
    /// (`entity_dimension_day_agg` / its OCSF twin, NAN-1888) instead of the
    /// raw lookback scan. Returns `None` whenever the raw path must answer — the
    /// lookback isn't fully within the MV-active period and isn't backfill-
    /// markered (the activation-time gate below), or the watermark / agg read
    /// fails (raw is a correct superset, so a degraded agg NEVER surfaces as an
    /// error or an empty "confidently nothing new") — and the caller falls
    /// through to the raw scan.
    ///
    /// Semantics match the raw scan: the FULL known+new (dim, val) set over
    /// `[start, end)` with the exact min first-seen and summed count, newest
    /// first, `LIMIT n BY dim` — the known/new split stays downstream in
    /// `baseline::parse_dimension_firsts`.
    ///
    /// Day-grain edge handling (P1-1). The scan reads whole days
    /// `[toDate(start), toDate(end - 1µs)]`, then a `HAVING min(first_seen) <
    /// end` DROPS any value whose earliest sighting is at/after `end` — without
    /// it, a `12:00–14:00` search would surface a value first-seen at 15:00 the
    /// same day as "new", i.e. genuinely outside the window. The HAVING is safe
    /// for the downstream known/new split: a known peer has `first_seen <
    /// incident_start < end`, so it always survives; only pure-after-window
    /// values are removed. Two accepted residuals of keeping day grain (the
    /// storage win; baseline is a heuristic): (a) no `>= start` lower HAVING —
    /// a value whose true min is just before `start` is left returned with a
    /// later `first_seen`, matching the raw scan and erring conservative
    /// (reads as known); (b) `cnt`/`event_count` on the two boundary days can
    /// include a few occurrences just outside `[start, end)` — first_seen (the
    /// only field the new/known split keys on) is exact, only the volume count
    /// is approximate at the edges.
    ///
    /// The caller pre-validates `entity_type` against [`agg_dimension_set`]
    /// (so it is one of host/user/ip) and lowercases + (for ip) RFC1918-gates
    /// `value_lower`; dates are ours — all inlined. `value_lower` is
    /// log-derived and bound. The keyed `(entity_type, entity_value)` prefix
    /// is why this is fast: match the agg's stored lowercase form exactly, no
    /// `lower()` wrapper (same reasoning as `entity_activity_buckets`).
    async fn entity_dimension_firsts_from_agg(
        &self,
        entity_type: &str,
        value_lower: &str,
        dim_fields: &[&str],
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        per_dim_limit: usize,
    ) -> Option<Vec<DimensionFirst>> {
        use crate::sql_hygiene::escape_sql_string;

        let clickhouse = self.ch_client.as_ref()?;
        let agg_table = self
            .table_names
            .read(Self::dimension_agg_table_key(self.active_profile.as_ref()));

        // `end` is exclusive in the raw path; the last day the agg may touch is
        // the date of the instant just before it, so a midnight `end` does not
        // drag in a whole extra day.
        let start_naive = start.date_naive();
        let end_naive = (end - chrono::Duration::microseconds(1)).date_naive();
        let start_day = start_naive.format("%Y-%m-%d");
        let end_day = end_naive.format("%Y-%m-%d");

        // MV-ACTIVATION-TIME GATE (NAN-1895). Day-presence can't tell a FULL day
        // from a PARTIAL one: because `day = toDate(timestamp)`, a single
        // late-arriving event (old timestamp) or a partial backfill makes a day
        // "present" while it is actually incomplete, so a value could read as
        // false-"new". No data-presence check can answer this. Instead gate on
        // WHEN the baseline-agg MVs went live — `baseline_agg_meta.active_since`,
        // which is data-INDEPENDENT. The comparison is at TIMESTAMP granularity,
        // not day: the activation day is itself PARTIAL (if the MVs went live at
        // noon, that morning's events are uncaptured), so a day-level check
        // would trust it wrongly.
        //   * lookback entirely within the MV-active period (`start >=
        //     active_since`, full DateTime) → every event of the lookback,
        //     including late arrivals, flowed through a LIVE MV → serve.
        //   * lookback reaches before activation (`start < active_since`) → the
        //     pre-activation portion `[start, active_since)` touches days
        //     `[start_day, active_day]` INCLUSIVE — active_day too, because its
        //     pre-`active_since` morning is uncaptured by the MVs and only a
        //     full-day backfill covers it. So require a completion marker for
        //     EVERY day in `[start_day, active_day]` inclusive for this lane →
        //     serve, else raw. (Safe re: double-count — the backfill is
        //     closed-days-only and clears-then-rescans, so a marker on active_day
        //     means it was fully re-scanned as a closed day, no live-MV overlap.)
        // A missing/unreadable watermark ⇒ `None` ⇒ raw scan (fail-safe).
        let active_since = self.baseline_agg_active_since(clickhouse).await?;
        if start < active_since {
            let active_day = active_since.date_naive();
            let marker_table = self
                .table_names
                .read("entity_dimension_day_agg_backfill_progress");
            let lane = Self::dimension_agg_lane(self.active_profile.as_ref());
            // Days in the INCLUSIVE pre-activation window [start_day, active_day].
            let needed = (active_day - start_naive).num_days() + 1;
            let marker_sql = format!(
                "SELECT toUInt64(count(DISTINCT day)) AS covered_days FROM {marker_table} \
                 WHERE lane = '{lane}' \
                   AND day >= toDate('{start_day}') AND day <= toDate('{active_day_s}')",
                active_day_s = active_day.format("%Y-%m-%d"),
            );

            #[derive(clickhouse::Row, serde::Deserialize)]
            struct CoverageRow {
                covered_days: u64,
            }

            match clickhouse.query(&marker_sql).fetch_all::<CoverageRow>().await {
                Ok(rows) if rows.first().is_some_and(|r| r.covered_days >= needed as u64) => {}
                Ok(_) => {
                    tracing::debug!(
                        entity_type,
                        "baseline agg lookback predates activation and the pre-activation \
                         window is not fully backfilled; using raw scan"
                    );
                    return None;
                }
                Err(e) => {
                    tracing::warn!(
                        entity_type,
                        "baseline agg backfill-marker probe failed; using raw scan: {}",
                        e
                    );
                    return None;
                }
            }
        }

        let dim_list = dim_fields
            .iter()
            .map(|f| format!("'{}'", escape_sql_string(f)))
            .collect::<Vec<_>>()
            .join(", ");

        // HAVING drops values whose earliest sighting is at/after the exclusive
        // `end` — same instant the raw path bounds `timestamp <` — so a value
        // first-seen later on the same boundary day is not surfaced as new
        // (P1-1). Timestamps are ours → inlined. The formatted output column is
        // aliased `fs`, NOT `first_seen`: aliasing it `first_seen` would SHADOW
        // the `first_seen` agg column, so `min(first_seen)` in HAVING/ORDER
        // would bind the formatted String instead of the timestamp (the
        // "alias shadows column" trap). The result struct maps by POSITION, so
        // the alias name is irrelevant to deserialization.
        let sql = format!(
            "SELECT dim, val, toUInt64(sum(event_count)) AS cnt, \
                    formatDateTime(min(first_seen), '%Y-%m-%dT%H:%i:%sZ') AS fs \
             FROM {agg_table} \
             WHERE entity_type = '{entity_type}' \
               AND entity_value = ? \
               AND day >= toDate('{start_day}') AND day <= toDate('{end_day}') \
               AND dim IN ({dim_list}) \
             GROUP BY dim, val \
             HAVING min(first_seen) < toDateTime64('{end_ts}', 6) \
             ORDER BY min(first_seen) DESC \
             LIMIT {per_dim_limit} BY dim",
            end_ts = end.format("%Y-%m-%d %H:%M:%S%.6f"),
        );

        // Field name matches the `fs` SQL alias — the clickhouse crate maps
        // result columns to struct fields BY NAME (not position).
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct FirstRow {
            dim: String,
            val: String,
            cnt: u64,
            fs: String,
        }

        match clickhouse
            .query(&sql)
            .bind(value_lower)
            .fetch_all::<FirstRow>()
            .await
        {
            Ok(rows) => Some(
                rows.into_iter()
                    .filter_map(|r| {
                        parse_asset_timestamp(&r.fs).map(|first_seen| DimensionFirst {
                            dimension: r.dim,
                            value: r.val,
                            count: r.cnt,
                            first_seen,
                        })
                    })
                    .collect(),
            ),
            Err(e) => {
                tracing::warn!(
                    entity_type,
                    "baseline day agg read failed; using raw scan: {}",
                    e
                );
                None
            }
        }
    }

    /// Read + memoize the baseline-agg MV activation watermark
    /// (`baseline_agg_meta.active_since`, NAN-1895) — the data-independent gate
    /// on the day agg's fast path. Written ONCE by migration 167 and immutable,
    /// so it is read lazily on the first `| baseline` query and cached for the
    /// life of the service (shared across the per-request clones via the `Arc`
    /// OnceCell). A CH READ ERROR is NOT cached (`get_or_try_init` retries next
    /// call); a MISSING/empty row caches `None`. `None` ⇒ the caller can't
    /// prove coverage ⇒ it returns the raw scan (fail-safe).
    async fn baseline_agg_active_since(
        &self,
        clickhouse: &clickhouse::Client,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        let meta_table = self.table_names.read("baseline_agg_meta");
        self.baseline_agg_active_since
            .get_or_try_init(|| async {
                #[derive(clickhouse::Row, serde::Deserialize)]
                struct MetaRow {
                    active_us: i64,
                    n: u64,
                }
                // MAX, not LIMIT 1 (NAN-1895 P2): the insert-once guard is not
                // atomic, so two concurrent migrators could race and leave TWO
                // rows with different timestamps (ReplacingMergeTree collapses
                // them only eventually). MAX is deterministic AND conservative —
                // the LATER activation trusts LESS of the lookback. `count()`
                // distinguishes an EMPTY table (n = 0 → None → raw) from a real
                // row, since `max()` over no rows returns the epoch default (not
                // NULL), which must NOT be read as "active since 1970".
                //
                // Read the FULL microsecond precision (P1, sub-second): the gate
                // compares `start >= active_since` at DateTime granularity, so
                // truncating to the second (via formatDateTime %s) would round the
                // watermark DOWN and let a `start` in the same second but before
                // the true activation serve the agg. `toUnixTimestamp64Micro`
                // preserves the DateTime64(6) exactly.
                let sql = format!(
                    "SELECT toInt64(toUnixTimestamp64Micro(max(active_since))) AS active_us, \
                            toUInt64(count()) AS n \
                     FROM {meta_table} WHERE k = 'active_since'"
                );
                match clickhouse.query(&sql).fetch_all::<MetaRow>().await {
                    Ok(rows) => Ok(rows
                        .first()
                        .filter(|r| r.n > 0)
                        .and_then(|r| chrono::DateTime::<chrono::Utc>::from_timestamp_micros(r.active_us))),
                    Err(e) => {
                        tracing::warn!(
                            "baseline_agg_meta read failed; agg fast path off this call: {}",
                            e
                        );
                        Err(())
                    }
                }
            })
            .await
            .ok()
            .copied()
            .flatten()
    }

    /// Hourly activity for one entity from a SCOPED scan of raw `logs` — the
    /// fallback coverage/rhythm/volume source for source-restricted
    /// investigations, where the agg (`entity_time_range_agg`, no source_type
    /// column) cannot be scoped and is off-limits (NAN-1864 follow-up).
    ///
    /// Deliberately source-side only (`source_side_only=true` semantics baked in
    /// via the actor predicate) so the counts are comparable to the agg's
    /// source-keyed distribution and to the agg-aligned incident volume. Scoped
    /// via [`source_scope_sql_predicate`]. Kept to a SHORT window by the caller —
    /// a scoped raw hourly scan over 30 days is the multi-GiB cost the agg exists
    /// to avoid, so restricted tenants get a bounded (7-day) baseline.
    pub async fn entity_hourly_activity_scoped(
        &self,
        scope: &ScopeSet,
        entity_type: &str,
        entity_value: &str,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<EntityActivityBucket>, SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(Vec::new()),
        };
        let profile = self.active_profile.as_ref();
        let value_lower = entity_value.to_lowercase();
        // ACTIVITY/VOLUME: agg-aligned (bare `user`, source-side host/ip) so these
        // counts are comparable to the incident-volume count and, for the
        // unrestricted path, to the agg's own source-keyed distribution.
        let (entity_pred, entity_binds) =
            match baseline_entity_predicate(profile, entity_type, &value_lower, true, true) {
                Some(p) => p,
                None => return Ok(Vec::new()),
            };
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(profile));
        let scope_pred = source_scope_sql_predicate("source_type", scope.deny_set())
            .map(|p| format!(" AND {p}"))
            .unwrap_or_default();

        let sql = format!(
            "SELECT formatDateTime(toStartOfHour(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS hour_start, \
                    toUInt64(count()) AS event_count \
             FROM {logs_table} \
             WHERE timestamp >= toDateTime64('{start}', 6) \
               AND timestamp <  toDateTime64('{end}', 6) \
               AND {entity_pred} \
               AND lower(source_type) != 'audit'{scope_pred} \
             GROUP BY hour_start \
             ORDER BY hour_start",
            start = start.format("%Y-%m-%d %H:%M:%S%.6f"),
            end = end.format("%Y-%m-%d %H:%M:%S%.6f"),
        );

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct BucketRow {
            hour_start: String,
            event_count: u64,
        }

        let mut query = clickhouse.query(&sql);
        for b in &entity_binds {
            query = query.bind(b);
        }
        match query.fetch_all::<BucketRow>().await {
            Ok(rows) => Ok(rows
                .into_iter()
                .filter_map(|r| {
                    parse_asset_timestamp(&r.hour_start).map(|hour_start| EntityActivityBucket {
                        hour_start,
                        event_count: r.event_count,
                    })
                })
                .collect()),
            Err(e) => {
                tracing::warn!(entity_type, "entity_hourly_activity_scoped scan failed: {}", e);
                Err(parse_clickhouse_error(&e.to_string()))
            }
        }
    }
}

/// The dimension set the `entity_dimension_day_agg` MVs bake in for one
/// `(entity_type, actor-anchoring)` pair — MUST mirror
/// `baseline::dimensions_for` + the MV bodies in
/// clickhouse/166_baseline_first_seen_agg.sql. The agg has no anchoring
/// column; each dim name is only ever WRITTEN with one anchoring (actor dims
/// by the src-side MVs, association dims by both sides), so the dim set IS
/// the anchoring contract. A request outside these sets must take the raw
/// scan, never a silently mis-anchored agg answer.
fn agg_dimension_set(entity_type: &str, source_side_only: bool) -> Option<&'static [&'static str]> {
    match (entity_type, source_side_only) {
        ("host", true) => Some(&["process_name", "dest_ip"]),
        ("host", false) => Some(&["user"]),
        ("user", true) => Some(&["src_host", "src_ip", "process_name"]),
        ("ip", false) => Some(&["src_host", "dest_port", "user"]),
        _ => None,
    }
}

/// True when `value_lower` is an RFC1918 IPv4 the day agg's ip MVs store.
/// MUST mirror the MV gate's regexes (`^10\.` / `^192\.168\.` /
/// `^172\.(1[6-9]|2[0-9]|3[01])\.`) EXACTLY — a value the MVs skip that this
/// admits would read as no-history and every peer would look new. Public,
/// loopback, link-local and IPv6 entities all route to the raw scan.
fn agg_covers_private_ip(value_lower: &str) -> bool {
    if value_lower.starts_with("10.") || value_lower.starts_with("192.168.") {
        return true;
    }
    if let Some(rest) = value_lower.strip_prefix("172.") {
        if let Some((octet, _)) = rest.split_once('.') {
            // Two digits, 16..=31 — anything else (incl. "016") the regex skips.
            if octet.len() == 2 {
                if let Ok(n) = octet.parse::<u8>() {
                    return (16..=31).contains(&n);
                }
            }
        }
    }
    false
}

/// Source types the baseline day agg's MVs already exclude at ingest
/// (`lower(source_type) != 'audit'`) — matching the raw new-to-entity scan's
/// unconditional audit exclusion. MUST stay in lockstep with the MV WHERE
/// clauses in `clickhouse/166_baseline_first_seen_agg.sql`.
const BASELINE_AGG_EXCLUDED_SOURCES: &[&str] = &["audit"];

/// Whether the caller's source deny-set is compatible with reading the agg
/// (NAN-1895). The agg has no `source_type` column, so it can only serve a
/// caller whose denied sources are ALL already excluded by the agg itself —
/// otherwise it would leak sources the caller must not see.
///
/// Crucially this is NOT `!scope.is_restricted()`: per-source RBAC (NAN-1801)
/// unions `audit` into the deny-set of every caller without `audit:view`, so an
/// empty-deny-set check would send ~every real query to the raw scan and the
/// fast path would never fire. Since the agg already excludes exactly `audit`, a
/// deny-set of `{audit}` sees precisely the agg's content and is safe; a deny-set
/// naming any OTHER source (which the agg includes) correctly falls back to raw.
fn scope_within_agg_exclusions(scope: &ScopeSet) -> bool {
    scope.deny_set().iter().all(|denied| {
        BASELINE_AGG_EXCLUDED_SOURCES
            .iter()
            .any(|excluded| denied.eq_ignore_ascii_case(excluded))
    })
}

/// Whether the day agg can answer this `entity_dimension_firsts` request
/// (NAN-1888): every profile-mapped dimension must be one the MVs bake in for
/// this `(entity_type, anchoring)` pair, and an `ip` entity must be RFC1918
/// (public IPs are not aggregated — unbounded cardinality). The source-scope
/// check ([`scope_within_agg_exclusions`]) and the coverage gate live at the
/// call sites. Pure so routing is unit-testable.
fn baseline_agg_can_serve(
    entity_type: &str,
    value_lower: &str,
    source_side_only: bool,
    mapped_fields: &[&str],
) -> bool {
    if mapped_fields.is_empty() {
        return false;
    }
    let Some(supported) = agg_dimension_set(entity_type, source_side_only) else {
        return false;
    };
    if !mapped_fields.iter().all(|f| supported.contains(f)) {
        return false;
    }
    entity_type != "ip" || agg_covers_private_ip(value_lower)
}

/// Build the case-insensitive entity WHERE predicate + its binds for the raw
/// baseline scans, resolving physical columns through the active profile
/// (NAN-1864). Returns `(predicate, binds)` where each `?` in the predicate is
/// paired with one bind — `value_lower` repeated per surviving term — or `None`
/// when no field resolves under this profile. Pass an already-lowercased value;
/// the compare is `lower(col) = ?`.
///
/// `source_side_only` drops the `dest_*` terms so a dimension can be pinned to
/// the actor side (see `baseline::DimScope`).
///
/// `agg_aligned` decides how a `user` entity is matched, and getting it wrong is
/// a real bug (NAN-1864 review): `entity_time_range_agg`'s user MV and
/// `baseline::agg_aligned_filter` (the incident-volume count) both key on the
/// BARE `user` field. So the activity/volume scan must match bare `user` too
/// (`agg_aligned = true`) or the historical distribution and the incident count
/// count different event sets and the z-score is biased. The NEW-TO-ENTITY scan,
/// by contrast, wants the account's whole footprint (`agg_aligned = false` →
/// `user`/`src_user`/`dest_user`), or a `dest_user`-only account is falsely blind.
/// `agg_aligned` has no effect on `host`/`ip`, whose source side is already the
/// bare `src_*` column under `source_side_only`.
fn baseline_entity_predicate(
    profile: &dyn crate::schema::SchemaProfile,
    entity_type: &str,
    value_lower: &str,
    source_side_only: bool,
    agg_aligned: bool,
) -> Option<(String, Vec<String>)> {
    let mut fields: Vec<&str> = Vec::new();
    match entity_type {
        "host" => {
            fields.push("src_host");
            if !source_side_only {
                fields.push("dest_host");
            }
        }
        "ip" => {
            fields.push("src_ip");
            if !source_side_only {
                fields.push("dest_ip");
            }
        }
        "user" => {
            fields.push("user");
            if !agg_aligned {
                fields.push("src_user");
                fields.push("dest_user");
            }
        }
        _ => return None,
    }

    let mut terms: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    for f in fields {
        if let Some(col) = profile.udm_column_sql(f) {
            terms.push(format!("lower({col}) = ?"));
            binds.push(value_lower.to_string());
        }
    }
    if terms.is_empty() {
        return None;
    }
    Some((format!("({})", terms.join(" OR ")), binds))
}

/// One hourly activity bucket for an entity (NAN-1864). Returned by
/// [`SearchService::entity_activity_buckets`] (from `entity_time_range_agg`) and
/// [`SearchService::entity_hourly_activity_scoped`] (from a scoped raw scan);
/// `event_count` is the summed activity in that clock hour.
#[derive(Debug, Clone)]
pub struct EntityActivityBucket {
    pub hour_start: chrono::DateTime<chrono::Utc>,
    pub event_count: u64,
}

/// One `(dimension, value)` first-seen row from
/// [`SearchService::entity_dimension_firsts`] (NAN-1864). `dimension` echoes the
/// UDM field name the caller passed; `first_seen` is the entity's earliest
/// sighting of `value` in that dimension within the scanned window.
#[derive(Debug, Clone)]
pub struct DimensionFirst {
    pub dimension: String,
    pub value: String,
    pub count: u64,
    pub first_seen: chrono::DateTime<chrono::Utc>,
}

/// Build the WHERE clause shared by the asset events-page and filtered-count
/// scans, combining the analyst's optional UI filters with the caller's
/// source-scope gate (NAN-1797/NAN-1799). Extracted into a free function so
/// the gating is unit-testable without a live ClickHouse (mirrors
/// `build_hop_sql` in `lateral.rs`).
///
/// Shape contract (leading `\n` + 12-space indent match the pre-scoping
/// inline `format!` byte-for-byte):
/// - no filters, no scope → `""` (byte-identical)
/// - filters only         → `"\n            WHERE (f1 AND f2)"` (byte-identical)
/// - scope only           → `"\n            WHERE <pred>"`
/// - both                 → `"\n            WHERE (f1 AND f2) AND <pred>"`
fn build_asset_events_where(
    filter_conditions: &[String],
    scope_predicate: Option<&str>,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !filter_conditions.is_empty() {
        parts.push(format!("({})", filter_conditions.join(" AND ")));
    }
    if let Some(pred) = scope_predicate {
        parts.push(pred.to_string());
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("\n            WHERE {}", parts.join(" AND "))
    }
}

/// Build the combined `GROUP BY source_type, event_type` facet scan
/// (NAN-1797): without the scope gate this facet enumerated EXACTLY the
/// denied sources — name and event count — for a scoped caller. With
/// `scope_predicate = None` the output is byte-identical to the pre-scoping
/// inline `format!`.
fn build_asset_combined_facet_sql(
    event_type_sql: &str,
    logs_table: &str,
    start: &str,
    end: &str,
    identity_clause: &str,
    scope_predicate: Option<&str>,
) -> String {
    let scope_and = scope_predicate
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    format!(
        "SELECT source_type, {} as event_type, count() as cnt \
         FROM {} \
         PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}){} \
         GROUP BY source_type, event_type \
         ORDER BY cnt DESC",
        event_type_sql, logs_table, start, end, identity_clause, scope_and
    )
}

/// Build the user facet scan for the asset view (NAN-1797: the scope gate is
/// ANDed against the existing `user != ''` WHERE; `None` → byte-identical to
/// the pre-scoping inline `format!`, leading whitespace included).
fn build_asset_user_facet_sql(
    user_col: &str,
    logs_table: &str,
    start: &str,
    end: &str,
    identity_clause: &str,
    scope_predicate: Option<&str>,
) -> String {
    let scope_and = scope_predicate
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    format!(
        r#"SELECT {user_col} AS user, count() as cnt
                FROM {logs_table}
                PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({identity_clause})
                WHERE {user_col} != ''{scope_and}
                GROUP BY {user_col}
                ORDER BY cnt DESC
                LIMIT 50"#
    )
}

/// Build the unfiltered total-count scan for the asset view (NAN-1797 scope
/// gate; `None` → byte-identical to the pre-scoping inline `format!`).
fn build_asset_count_sql(
    logs_table: &str,
    start: &str,
    end: &str,
    identity_clause: &str,
    scope_predicate: Option<&str>,
) -> String {
    let scope_and = scope_predicate
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    format!(
        "SELECT count() FROM {} PREWHERE timestamp BETWEEN '{}' AND '{}' AND ({}){}",
        logs_table, start, end, identity_clause, scope_and
    )
}

#[cfg(test)]
mod source_scope_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn deny(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// NAN-1797: with a nonempty deny-set, every logs scan `| asset` reaches
    /// must carry the source_type exclusion — most critically the
    /// `GROUP BY source_type` facet, which otherwise enumerated exactly the
    /// caller's hidden sources, and the events page, which returned their raw
    /// events.
    #[test]
    fn nonempty_deny_set_gates_every_asset_scan() {
        let pred = source_scope_sql_predicate(
            "source_type",
            &deny(&["audit", "insider_threat"]),
        )
        .expect("nonempty deny set must render");
        assert_eq!(
            pred,
            "lower(source_type) NOT IN ('audit', 'insider_threat')"
        );

        // Events page / filtered count (shared WHERE builder).
        assert_eq!(
            build_asset_events_where(&[], Some(&pred)),
            format!("\n            WHERE {pred}")
        );
        let filters = vec!["lower(source_type) IN (?)".to_string()];
        assert_eq!(
            build_asset_events_where(&filters, Some(&pred)),
            format!("\n            WHERE (lower(source_type) IN (?)) AND {pred}")
        );

        // The GROUP BY source_type facet — the gate must be ANDed into the
        // scan's PREWHERE conjunction, before the GROUP BY.
        let facet = build_asset_combined_facet_sql("ET", "logs", "S", "E", "src_ip = ?", Some(&pred));
        assert!(
            facet.contains(&format!("AND (src_ip = ?) AND {pred} GROUP BY source_type")),
            "source_type facet scan missing scope gate: {facet}"
        );

        let user_facet = build_asset_user_facet_sql("user", "logs", "S", "E", "src_ip = ?", Some(&pred));
        assert!(
            user_facet.contains(&format!("WHERE user != '' AND {pred}")),
            "user facet scan missing scope gate: {user_facet}"
        );

        let count = build_asset_count_sql("logs", "S", "E", "src_ip = ?", Some(&pred));
        assert!(
            count.ends_with(&format!("AND (src_ip = ?) AND {pred}")),
            "count scan missing scope gate: {count}"
        );
    }

    /// Empty deny set (unrestricted caller) → every scan's SQL byte-identical
    /// to the pre-scoping form (zero-restricted-sources back-compat).
    #[test]
    fn empty_deny_set_leaves_every_asset_scan_byte_identical() {
        assert_eq!(
            source_scope_sql_predicate("source_type", &BTreeSet::new()),
            None
        );

        assert_eq!(build_asset_events_where(&[], None), "");
        let filters = vec!["a = ?".to_string(), "b = ?".to_string()];
        assert_eq!(
            build_asset_events_where(&filters, None),
            "\n            WHERE (a = ? AND b = ?)"
        );

        assert_eq!(
            build_asset_combined_facet_sql("ET", "logs", "S", "E", "id", None),
            "SELECT source_type, ET as event_type, count() as cnt \
             FROM logs \
             PREWHERE timestamp BETWEEN 'S' AND 'E' AND (id) \
             GROUP BY source_type, event_type \
             ORDER BY cnt DESC"
        );

        assert_eq!(
            build_asset_user_facet_sql("user", "logs", "S", "E", "id", None),
            "SELECT user AS user, count() as cnt\n                \
             FROM logs\n                \
             PREWHERE timestamp BETWEEN 'S' AND 'E' AND (id)\n                \
             WHERE user != ''\n                \
             GROUP BY user\n                \
             ORDER BY cnt DESC\n                \
             LIMIT 50"
        );

        assert_eq!(
            build_asset_count_sql("logs", "S", "E", "id", None),
            "SELECT count() FROM logs PREWHERE timestamp BETWEEN 'S' AND 'E' AND (id)"
        );
    }

    /// The identity-resolution splice targets identity_observations' `source`
    /// column (that table's name for source_type, stamped by
    /// identity_observations_mv).
    #[test]
    fn identity_observation_gate_targets_source_column() {
        assert_eq!(
            source_scope_sql_predicate("source", &deny(&["audit"])).as_deref(),
            Some("lower(source) != 'audit'")
        );
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

#[cfg(test)]
mod baseline_predicate_tests {
    use super::*;
    use crate::schema::UdmProfile;
    use std::collections::BTreeSet;

    // The entity-filter guarantees the shadow baseline depends on (NAN-1864),
    // now that the nPL string builders were removed with the per-dimension path.
    // Under UDM the physical columns are the UDM names themselves.

    #[test]
    fn actor_scope_pins_host_and_ip_to_the_source_side() {
        let p = UdmProfile::new();
        // A host process/dest dimension MUST match src_host only — a remote host's
        // tooling must not be credited to (or poison the baseline of) its target.
        let (pred, binds) = baseline_entity_predicate(&p, "host", "ws-1", true, false).unwrap();
        assert_eq!(pred, "(lower(src_host) = ?)");
        assert!(!pred.contains("dest_host"));
        assert_eq!(binds, vec!["ws-1".to_string()]);

        let (pred, _) = baseline_entity_predicate(&p, "ip", "10.0.0.1", true, false).unwrap();
        assert_eq!(pred, "(lower(src_ip) = ?)");
        assert!(!pred.contains("dest_ip"));
    }

    #[test]
    fn association_scope_is_bidirectional_for_host_and_ip() {
        let p = UdmProfile::new();
        let (pred, binds) = baseline_entity_predicate(&p, "host", "ws-1", false, false).unwrap();
        assert_eq!(pred, "(lower(src_host) = ? OR lower(dest_host) = ?)");
        assert_eq!(binds.len(), 2, "one bind per OR term");

        let (pred, _) = baseline_entity_predicate(&p, "ip", "10.0.0.1", false, false).unwrap();
        assert_eq!(pred, "(lower(src_ip) = ? OR lower(dest_ip) = ?)");
    }

    #[test]
    fn new_to_entity_user_matches_all_three_fields() {
        let p = UdmProfile::new();
        // `agg_aligned = false` (the new-to-entity scan): match the account's whole
        // footprint. Omitting dest_user would give a dest_user-only account a false
        // NoHistory. Direction doesn't matter for a user.
        for source_side_only in [true, false] {
            let (pred, binds) =
                baseline_entity_predicate(&p, "user", "bob", source_side_only, false).unwrap();
            // `user` is a SQL reserved word, so the profile quotes it.
            assert_eq!(
                pred,
                "(lower(\"user\") = ? OR lower(src_user) = ? OR lower(dest_user) = ?)"
            );
            assert_eq!(binds, vec!["bob".to_string(); 3]);
        }
    }

    #[test]
    fn agg_aligned_user_matches_bare_user_only() {
        let p = UdmProfile::new();
        // `agg_aligned = true` (the activity/volume scan): match bare `user` only,
        // so the historical distribution counts the SAME events as the incident
        // volume (`agg_aligned_filter`, bare `user`) and the agg MV. Matching
        // src_user/dest_user here would bias the volume z-score (NAN-1864 review).
        let (pred, binds) = baseline_entity_predicate(&p, "user", "bob", true, true).unwrap();
        assert_eq!(pred, "(lower(\"user\") = ?)");
        assert!(!pred.contains("src_user"));
        assert!(!pred.contains("dest_user"));
        assert_eq!(binds, vec!["bob".to_string()]);
    }

    #[test]
    fn value_is_bound_never_inlined_so_it_cannot_break_out() {
        let p = UdmProfile::new();
        // An attacker-shaped value stays a bind — the predicate has only `?`, and
        // the value rides in the binds vec.
        // The caller passes an already-lowercased value; the predicate carries
        // only `?`, and the value rides in the binds vec (parameterized).
        let evil = "x' or '1'='1";
        let (pred, binds) = baseline_entity_predicate(&p, "host", evil, true, false).unwrap();
        assert!(!pred.contains(evil), "value must not be inlined into SQL");
        assert!(pred.contains('?'));
        assert_eq!(binds, vec![evil.to_string()]);
    }

    #[test]
    fn unsupported_entity_types_yield_no_predicate() {
        let p = UdmProfile::new();
        assert!(baseline_entity_predicate(&p, "hash", "abc", true, false).is_none());
        assert!(baseline_entity_predicate(&p, "domain", "x.com", true, true).is_none());
    }

    #[test]
    fn scope_predicate_is_anded_when_the_deny_set_is_nonempty() {
        // The NAN-1801 gate the scoped scans rely on. Empty deny → no predicate
        // (byte-identical unscoped SQL); nonempty → an exclusion to AND in.
        assert!(source_scope_sql_predicate("source_type", &BTreeSet::new()).is_none());
        let deny: BTreeSet<String> = ["insider_threat".to_string()].into_iter().collect();
        assert_eq!(
            source_scope_sql_predicate("source_type", &deny).unwrap(),
            "lower(source_type) != 'insider_threat'"
        );
    }
}

#[cfg(test)]
#[path = "asset_baseline_agg_tests.rs"]
mod asset_baseline_agg_tests;

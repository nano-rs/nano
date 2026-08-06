// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SearchService {
    /// Check if a search expression references _prevalence nested fields
    /// These fields are added by restructure_prevalence_fields_from_join and don't exist in SQL
    pub(crate) fn condition_references_prevalence_nested_fields(
        &self,
        expr: &crate::query::SearchExpr,
    ) -> bool {
        use crate::query::SearchExpr;

        match expr {
            SearchExpr::FieldFilter { field, .. } => field.starts_with("_prevalence."),
            SearchExpr::FunctionFilter { function, .. } => {
                self.eval_expr_references_prevalence_nested(function)
            }
            SearchExpr::FieldFunctionFilter {
                field, function, ..
            } => {
                field.starts_with("_prevalence.")
                    || self.eval_expr_references_prevalence_nested(function)
            }
            SearchExpr::InList { field, .. } => field.starts_with("_prevalence."),
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                self.condition_references_prevalence_nested_fields(left)
                    || self.condition_references_prevalence_nested_fields(right)
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
                self.condition_references_prevalence_nested_fields(inner)
            }
            SearchExpr::BooleanFunction(function) => {
                self.eval_expr_references_prevalence_nested(function)
            }
            SearchExpr::EvalPredicate(expression) => {
                self.eval_expr_references_prevalence_nested(expression)
            }
            SearchExpr::Keyword(_) => false,
            SearchExpr::LiteralComparison { .. } => false,
            SearchExpr::InSubsearch { .. } => false,
            // NAN-1580: the ioc term references observable columns, never the
            // `_prevalence.*` nested fields.
            SearchExpr::IocMatch { .. } => false,
        }
    }

    /// Check if an eval expression references _prevalence nested fields
    fn eval_expr_references_prevalence_nested(&self, expr: &crate::query::EvalExpression) -> bool {
        use crate::query::EvalExpression;

        match expr {
            EvalExpression::Field(field) => field.starts_with("_prevalence."),
            EvalExpression::Literal(_) => false,
            EvalExpression::FunctionCall { args, .. } => args
                .iter()
                .any(|arg| self.eval_expr_references_prevalence_nested(arg)),
            EvalExpression::BinaryOp { left, right, .. } => {
                self.eval_expr_references_prevalence_nested(left)
                    || self.eval_expr_references_prevalence_nested(right)
            }
        }
    }

    /// For each prevalence command, this method:
    /// 1. Extracts artifacts (hashes/domains) from the results
    /// 2. Queries PrevalenceService for prevalence data
    /// 3. Filters results based on threshold (filtering mode)
    /// 4. Adds _prevalence field to results (enrichment mode)
    ///
    /// Requirements: 5.3, 5.4
    pub(crate) async fn apply_prevalence_processing(
        &self,
        mut results: Vec<serde_json::Value>,
        prevalence_commands: &[PrevalenceCommandInfo],
        artifact_scope: &crate::auth::ArtifactScope,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let prevalence_service = match &self.prevalence_service {
            Some(service) => service,
            None => {
                warn!("Prevalence command found but no prevalence service configured");
                return Ok(results);
            }
        };

        for cmd in prevalence_commands {
            let time_window = ast_to_prevalence_time_window(cmd.time_window.as_ref())?;

            if cmd.enrich {
                // Enrichment mode: add _prevalence field to all results
                results = self
                    .apply_prevalence_enrichment(
                        results,
                        prevalence_service,
                        time_window,
                        artifact_scope,
                    )
                    .await?;
            } else if !cmd.conditions.is_empty() {
                // Filtering mode: filter results based on prevalence conditions
                // All conditions must be satisfied (AND logic)
                for condition in &cmd.conditions {
                    results = self
                        .apply_prevalence_filtering(
                            results,
                            prevalence_service,
                            &condition.field,
                            &condition.operator,
                            &condition.threshold,
                            time_window,
                            artifact_scope,
                        )
                        .await?;
                }
            }
        }

        Ok(results)
    }

    /// Apply prevalence filtering to search results
    ///
    /// Filters results based on prevalence threshold comparison.
    /// Requirements: 5.3, 5.4
    async fn apply_prevalence_filtering(
        &self,
        results: Vec<serde_json::Value>,
        prevalence_service: &PrevalenceService,
        field: &PrevalenceField,
        operator: &PrevalenceOperator,
        threshold: &PrevalenceThreshold,
        time_window: PrevalenceTimeWindow,
        artifact_scope: &crate::auth::ArtifactScope,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        if results.is_empty() {
            return Ok(results);
        }

        // Determine which result-row key(s) to extract artifacts from based on PrevalenceField.
        //
        // NAN-1241: these are the RESULT-ROW output field names (the keys serde produced from
        // the SELECT aliases), not raw SQL columns — so they follow the active schema's output
        // naming. Resolve the UDM-semantic concept(s) through the profile: UDM yields the same
        // `file_hash`/`process_hash`/`dest_host` literals (byte-identical), OCSF yields its
        // promoted output column names. If the active schema maps NONE of the concepts, the
        // filter cannot apply — short-circuit gracefully rather than scanning fields that never
        // exist.
        //
        // NAN-1691 LOCK-STEP: this residual in-memory path MUST agree with the WHERE pushdown
        // (`prevalence_filter_condition_to_sql`), which keys HashPrevalence on
        // `lower(COALESCE(file_hash, process_hash))` via the JOIN's `_hp_host_count` alias — so
        // a sysmon row carrying only a process_hash still matches. Hence hash lookups here try
        // `file_hash` first and fall back to `process_hash` (COALESCE semantics). DomainPrevalence
        // stays `dest_host`, matching the domain alias. Keep the two paths in lock-step or the
        // filter form returns different row sets depending on whether it pushed down.
        let profile = self.active_profile.as_ref();
        let udm_concepts = prevalence_filter_udm_concepts(field);
        // udm_column_sql returns the SQL-escaped column; strip the OCSF double-quotes so we index
        // the JSON result map by the bare output key. UDM is unquoted → unchanged (byte-identical).
        // TODO(OCSF): the result-row KEY equals the promoted column's serde name; if OCSF
        // serialization ever renames it (vs the bare dotted column), these keys must follow.
        let artifact_fields: Vec<String> = udm_concepts
            .iter()
            .filter_map(|concept| {
                profile
                    .udm_column_sql(concept)
                    .map(|col| col.trim_matches('"').to_string())
            })
            .collect();
        if artifact_fields.is_empty() {
            debug!(
                "Prevalence filtering: active schema has no column for {:?}; skipping filter",
                udm_concepts
            );
            return Ok(results);
        }

        // For timestamp-based fields, we need different handling
        if field.is_timestamp_field() {
            warn!("Timestamp-based prevalence filtering (first_seen) not yet implemented");
            return Ok(results);
        }

        // Extract unique artifacts from results
        let artifacts: Vec<String> = results
            .iter()
            .filter_map(|row| extract_prevalence_artifact(row, &artifact_fields))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if artifacts.is_empty() {
            debug!(
                "No artifacts found in fields {:?} for prevalence filtering",
                artifact_fields
            );
            return Ok(results);
        }

        debug!(
            "Querying prevalence for {} unique artifacts",
            artifacts.len()
        );

        // Single dict-based query handles all artifacts; map keys are
        // lowercase for hash/domain (raw for IP), so lookups below must
        // lowercase the row's artifact field for hash/domain.
        let mut prevalence_map: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        match prevalence_service
            .get_bulk_prevalence_via_dict(artifacts.as_slice(), time_window, artifact_scope)
            .await
        {
            Ok(prevalence_data) => {
                for data in prevalence_data {
                    prevalence_map.insert(data.artifact, data.host_count);
                }
            }
            Err(e) => {
                // Fail CLOSED. A prevalence-gated filter must NOT pass rows when the
                // dict/CH lookup fails. Returning the UNFILTERED set here meant a
                // prevalence-filtered detection rule (e.g. `… | prevalence host_count < 3`)
                // fired on EVERY row whenever the dict was momentarily unavailable —
                // the opposite of "signal over noise". Exclude all rows instead,
                // mirroring the JOIN path where an absent host_count is dropped.
                warn!(
                    "Prevalence filtering failed ({}); failing closed (excluding all rows)",
                    e
                );
                return Ok(Vec::new());
            }
        }

        // NAN-1705 (D4b): artifacts the dict could not resolve (miss or
        // window-masked → absent from the map) may be brand-new — their absence
        // is negative-cached at ingest for the dict's LIFETIME (15–30 min), so a
        // rarity filter is blind to them exactly while they're newest. Re-check
        // the misses against the real-time `*_prevalence_summary` (the dict's own
        // source, which applies the same host_count < 1000 + window-mask
        // contract), keeping this residual path in LOCK-STEP with the pushdown's
        // rescue branch. Rescue failure degrades to today's behavior (misses stay
        // excluded) — it must never fail the whole filter open OR closed.
        let missing: Vec<String> = artifacts
            .iter()
            .filter(|a| !prevalence_map.contains_key(&a.to_lowercase()))
            .cloned()
            .collect();
        // Restricted "dict" lookups are already rerouted to the attributed
        // summary because the dictionary has no source dimension. Their misses
        // are therefore terminal; rescuing them would repeat the identical
        // source-summary query. Unrestricted callers retain the real-time
        // summary rescue for dictionary negative-cache misses.
        if !missing.is_empty() && artifact_scope.is_unrestricted() {
            match prevalence_service
                .get_bulk_summary_prevalence(&missing, time_window, artifact_scope)
                .await
            {
                Ok(rescued) => {
                    debug!(
                        missed = missing.len(),
                        rescued = rescued.len(),
                        "Prevalence summary rescue for dict-missed artifacts"
                    );
                    for data in rescued {
                        prevalence_map.insert(data.artifact.clone(), data.host_count);
                    }
                }
                Err(e) => {
                    warn!(
                        "Prevalence summary rescue failed ({}); dict-missed artifacts stay excluded",
                        e
                    );
                }
            }
        }

        // Get threshold value
        let threshold_value = match threshold {
            PrevalenceThreshold::Count(n) => *n,
            PrevalenceThreshold::Duration(_) => {
                // Duration thresholds are for first_seen comparisons, not count-based filtering
                // For now, skip filtering for duration thresholds
                warn!("Duration-based prevalence filtering not yet implemented");
                return Ok(results);
            }
        };

        // Capture original count before consuming results
        let original_count = results.len();

        // Filter results based on prevalence
        let filtered_results: Vec<serde_json::Value> = results
            .into_iter()
            .filter(|row| {
                // COALESCE across the resolved fields (file_hash → process_hash for hashes),
                // matching the pushdown. A row with none of them is excluded (mirrors the JOIN
                // path where a NULL host_count is dropped by the WHERE).
                let artifact = match extract_prevalence_artifact(row, &artifact_fields) {
                    Some(a) => a,
                    None => return false,
                };
                let artifact = artifact.as_str();

                // Dict-based map keys are lowercase for hash/domain (the only
                // two artifact types this filter handles); lowercase the row's
                // value to match.
                //
                // A MISS is NOT host_count 0. The dict deliberately OMITS common
                // artifacts (entities on >=1000 hosts are absent, and the rest are
                // masked to the 9999 sentinel), so a lookup miss means "common /
                // not tracked". Treating a miss as 0 inverted the filter: a common
                // artifact absent from the dict PASSED `host_count < N` — the exact
                // opposite of rare. Mirror the JOIN path's NULL semantics: a miss
                // fails EVERY comparison (SQL `NULL <cmp> x` yields NULL → the row is
                // dropped by the WHERE).
                let prevalence = prevalence_map.get(&artifact.to_lowercase()).copied();
                prevalence_passes_filter(prevalence, operator, threshold_value)
            })
            .collect();

        debug!(
            "Prevalence filtering: {} -> {} results",
            original_count,
            filtered_results.len()
        );

        Ok(filtered_results)
    }

    /// Apply prevalence enrichment to search results
    ///
    /// Adds _prevalence field to all results containing prevalence data.
    /// Requirements: 5.1, 5.2
    async fn apply_prevalence_enrichment(
        &self,
        mut results: Vec<serde_json::Value>,
        prevalence_service: &PrevalenceService,
        time_window: PrevalenceTimeWindow,
        artifact_scope: &crate::auth::ArtifactScope,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        if results.is_empty() {
            tracing::debug!("Prevalence enrichment: no results to enrich");
            return Ok(results);
        }

        tracing::debug!(
            "Prevalence enrichment: processing {} results",
            results.len()
        );

        // Extract all unique hashes, domains, and IPs from results
        // Support multiple field names for hashes, domains, and IPs based on UDM fields.
        //
        // NAN-1241: these are RESULT-ROW output keys (the keys serde produced from the SELECT
        // aliases), not raw SQL columns — so they follow the active schema's output naming. Under
        // the OCSF profile the promoted columns serialize under their dotted names (e.g.
        // `dst_endpoint.hostname`, `file.hashes.sha256`), so the hardcoded UDM keys never match
        // and enrichment silently no-ops.
        //
        // The fix is SCHEMA-GATED, not blanket profile-resolution. Many of the UDM artifact field
        // names below are NOT in EXPLICIT_COLUMNS (service_hash, service_dll_hash, dest_nt_domain,
        // src_nt_domain, http_referrer_domain, src_user_domain, client_ip, server_ip, nat_dest_ip,
        // nat_src_ip) — for those the *default UDM profile's* `udm_column_sql` would resolve to
        // `ext.<name>`, which is the WRONG result-row key and would silently break UDM. So:
        //   - UDM (default): use the exact previous literal arrays, byte-for-byte unchanged. No
        //     profile resolution is applied — UDM result-row keys ARE these bare names.
        //   - OCSF: resolve the UDM-semantic concepts through `udm_column_sql` (quotes stripped to
        //     get the bare dotted result-row key); concepts OCSF doesn't map return `None` and are
        //     dropped. Legacy/common aliases (md5, domain, ip, …) are not UDM-semantic and have no
        //     OCSF mapping; they are kept verbatim (UDM-only — they may also coincidentally appear
        //     as raw `ext` keys on OCSF rows, where matching them is harmless).
        let profile = self.active_profile.as_ref();
        let is_ocsf = profile.id() == crate::schema::SchemaId::Ocsf;

        // OCSF only: resolve a UDM-semantic field to its dotted result-row key (quotes stripped),
        // mirroring `apply_prevalence_filtering` above. None → schema has no column → drop.
        let resolve_ocsf = |udm_field: &str| -> Option<String> {
            profile
                .udm_column_sql(udm_field)
                .map(|col| col.trim_matches('"').to_string())
        };

        // Build a field list. UDM: literal `udm_concepts` + `legacy` verbatim (byte-identical to
        // the prior hardcoded arrays). OCSF: profile-resolved `udm_concepts` (None dropped) +
        // `legacy` verbatim.
        let build = |udm_concepts: &[&str], legacy: &[&str]| -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            for f in udm_concepts {
                if is_ocsf {
                    if let Some(key) = resolve_ocsf(f) {
                        out.push(key);
                    }
                } else {
                    out.push((*f).to_string());
                }
            }
            for f in legacy {
                out.push((*f).to_string());
            }
            out
        };

        // UDM-semantic concepts (per-profile) + legacy aliases (UDM-only literals).
        // Under UDM these reduce to the exact previous arrays, byte-identical.
        let hash_fields = build(
            &[
                "file_hash",        // Generic file hash (any algorithm)
                "process_hash",     // Process/executable hash (Sysmon, EDR)
                "service_hash",     // Windows service executable hash
                "service_dll_hash", // Windows service DLL hash
            ],
            &["hash", "md5", "sha256", "sha1"],
        );
        let domain_fields = build(
            &[
                "dest_host",            // Destination hostname (most common)
                "src_host",             // Source hostname
                "dest_nt_domain",       // Windows NT domain (destination)
                "src_nt_domain",        // Windows NT domain (source)
                "http_referrer_domain", // HTTP referrer domain
                "recipient_domain",     // Email recipient domain
                "src_user_domain",      // Source user's domain
                "url_domain",           // Domain extracted from URL
            ],
            &["domain", "query_name", "dns_query", "hostname"],
        );
        let ip_fields = build(
            &[
                "dest_ip",     // Destination IP address (most common)
                "src_ip",      // Source IP address
                "client_ip",   // Client IP (web logs)
                "server_ip",   // Server IP
                "nat_dest_ip", // NAT destination IP
                "nat_src_ip",  // NAT source IP
            ],
            &["ip", "remote_ip", "target_ip"],
        );

        let mut hashes: Vec<String> = Vec::new();
        let mut domains: Vec<String> = Vec::new();
        let mut ips: Vec<String> = Vec::new();

        for row in &results {
            // Try multiple hash field names
            for field in &hash_fields {
                if let Some(hash) = row
                    .get(field.as_str())
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    hashes.push(hash.to_string());
                    break; // Only take first hash found
                }
            }

            // Try multiple domain field names (skip IP addresses, but collect them for IP prevalence)
            let mut found_domain = false;
            let mut found_ip_in_domain_field = false;
            for field in &domain_fields {
                if let Some(value) = row
                    .get(field.as_str())
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    if value.parse::<std::net::IpAddr>().is_ok() {
                        // It's an IP in a domain field (e.g., dest_host: 193.32.162.159)
                        if !found_ip_in_domain_field {
                            ips.push(value.to_string());
                            found_ip_in_domain_field = true;
                        }
                    } else if !found_domain {
                        domains.push(value.to_string());
                        found_domain = true;
                    }
                }
            }

            // Try multiple IP field names (if we didn't already find an IP in domain fields)
            if !found_ip_in_domain_field {
                for field in &ip_fields {
                    if let Some(ip) = row
                        .get(field.as_str())
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        // Validate it's an IP address
                        if ip.parse::<std::net::IpAddr>().is_ok() {
                            ips.push(ip.to_string());
                            break; // Only take first IP found
                        }
                    }
                }
            }
        }

        // Deduplicate
        let unique_hashes: Vec<String> = hashes
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let unique_domains: Vec<String> = domains
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let unique_ips: Vec<String> = ips
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        tracing::debug!(
            "Prevalence enrichment: {} unique hashes, {} unique domains, {} unique IPs to query",
            unique_hashes.len(),
            unique_domains.len(),
            unique_ips.len()
        );

        // One dict-based call covers all three artifact kinds (the service
        // categorizes by `ArtifactType::detect` internally). This replaces
        // the previous `ceil(N/100) × 3` fan-out against the
        // `*_prevalence_agg` MergeTree tables.
        //
        // Map keys: lowercase for hash/domain (matches dict storage), raw
        // for IP. Caller-side lookups must lowercase hash/domain values.
        let mut hash_prevalence: std::collections::HashMap<String, PrevalenceData> =
            std::collections::HashMap::new();
        let mut domain_prevalence: std::collections::HashMap<String, PrevalenceData> =
            std::collections::HashMap::new();
        let mut ip_prevalence: std::collections::HashMap<String, PrevalenceData> =
            std::collections::HashMap::new();

        let mut combined: Vec<String> =
            Vec::with_capacity(unique_hashes.len() + unique_domains.len() + unique_ips.len());
        combined.extend(unique_hashes.iter().cloned());
        combined.extend(unique_domains.iter().cloned());
        combined.extend(unique_ips.iter().cloned());

        if !combined.is_empty() {
            match prevalence_service
                .get_bulk_prevalence_via_dict(&combined, time_window, artifact_scope)
                .await
            {
                Ok(data) => {
                    for d in data {
                        if d.artifact_type.is_hash() {
                            hash_prevalence.insert(d.artifact.clone(), d);
                        } else if d.artifact_type.is_domain() {
                            domain_prevalence.insert(d.artifact.clone(), d);
                        } else if d.artifact_type.is_ip() {
                            ip_prevalence.insert(d.artifact.clone(), d);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Prevalence enrichment dict query failed: {}; rows will lack _prevalence",
                        e
                    );
                }
            }
        }

        tracing::debug!(
            "Prevalence enrichment: got {} hash, {} domain, {} IP prevalence entries",
            hash_prevalence.len(),
            domain_prevalence.len(),
            ip_prevalence.len()
        );

        // Count how many results will get enriched
        let mut enriched_count = 0;

        // Enrich each result with prevalence data
        for row in &mut results {
            if let Some(obj) = row.as_object_mut() {
                let mut prevalence_info = serde_json::Map::new();
                let mut found_hash: Option<String> = None;
                let mut found_domain: Option<String> = None;
                let mut found_ip: Option<String> = None;

                // Try to find hash in multiple possible fields
                for field in &hash_fields {
                    if let Some(hash) = obj
                        .get(field.as_str())
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        if let Some(data) = hash_prevalence.get(&hash.to_lowercase()) {
                            enriched_count += 1;
                            found_hash = Some(hash.to_string());
                            prevalence_info.insert(
                                "hash".to_string(),
                                serde_json::json!({
                                    "artifact": hash,
                                    "host_count": data.host_count,
                                    "total_occurrences": data.total_occurrences,
                                    "first_seen": data.first_seen.to_rfc3339(),
                                    "last_seen": data.last_seen.to_rfc3339(),
                                    "is_rare": data.is_rare,
                                    "prevalence_score": data.prevalence_score,
                                    "field_name": field, // Track which field the hash came from
                                }),
                            );
                            break;
                        }
                    }
                }

                // Try to find domain in multiple possible fields
                // If the field contains an IP address instead of a domain, fall back to IP prevalence
                for field in &domain_fields {
                    if let Some(value) = obj
                        .get(field.as_str())
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        // Check if this is an IP address in a domain field (e.g., dest_host: 185.220.101.35)
                        if value.parse::<std::net::IpAddr>().is_ok() {
                            // It's an IP - try IP prevalence instead
                            if let Some(data) = ip_prevalence.get(value) {
                                found_ip = Some(value.to_string());
                                prevalence_info.insert("ip".to_string(), serde_json::json!({
                                    "artifact": value,
                                    "host_count": data.host_count,
                                    "total_occurrences": data.total_occurrences,
                                    "first_seen": data.first_seen.to_rfc3339(),
                                    "last_seen": data.last_seen.to_rfc3339(),
                                    "is_rare": data.is_rare,
                                    "prevalence_score": data.prevalence_score,
                                    "field_name": field, // Track which field the IP came from (e.g., dest_host)
                                    "is_private": matches!(data.artifact_type, crate::prevalence::ArtifactType::IpAddressPrivate),
                                    "source": "domain_field_fallback", // Indicate this came from a domain field containing an IP
                                }));
                                enriched_count += 1;
                                break;
                            }
                        } else if let Some(data) =
                            domain_prevalence.get(&value.to_lowercase())
                        {
                            // It's a domain - use domain prevalence
                            found_domain = Some(value.to_string());
                            prevalence_info.insert(
                                "domain".to_string(),
                                serde_json::json!({
                                    "artifact": value,
                                    "host_count": data.host_count,
                                    "total_occurrences": data.total_occurrences,
                                    "first_seen": data.first_seen.to_rfc3339(),
                                    "last_seen": data.last_seen.to_rfc3339(),
                                    "is_rare": data.is_rare,
                                    "prevalence_score": data.prevalence_score,
                                    "field_name": field, // Track which field the domain came from
                                }),
                            );
                            enriched_count += 1;
                            break;
                        }
                    }
                }

                // Try to find IP in multiple possible fields (if not already found from domain field fallback)
                if found_ip.is_none() {
                    for field in &ip_fields {
                        if let Some(ip) = obj
                            .get(field.as_str())
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                        {
                            if let Some(data) = ip_prevalence.get(ip) {
                                found_ip = Some(ip.to_string());
                                prevalence_info.insert("ip".to_string(), serde_json::json!({
                                    "artifact": ip,
                                    "host_count": data.host_count,
                                    "total_occurrences": data.total_occurrences,
                                    "first_seen": data.first_seen.to_rfc3339(),
                                    "last_seen": data.last_seen.to_rfc3339(),
                                    "is_rare": data.is_rare,
                                    "prevalence_score": data.prevalence_score,
                                    "field_name": field, // Track which field the IP came from
                                    "is_private": matches!(data.artifact_type, crate::prevalence::ArtifactType::IpAddressPrivate),
                                }));
                                enriched_count += 1;
                                break;
                            }
                        }
                    }
                }

                // Only add _prevalence field if we have data
                if !prevalence_info.is_empty() {
                    // Determine which prevalence type(s) we have and what artifact
                    let mut prevalence_types = Vec::new();
                    let mut prevalence_artifacts = Vec::new();

                    if prevalence_info.get("domain").is_some() {
                        prevalence_types.push("domain");
                        if let Some(domain) = &found_domain {
                            prevalence_artifacts.push(domain.clone());
                        }
                    }
                    if prevalence_info.get("hash").is_some() {
                        prevalence_types.push("hash");
                        if let Some(hash) = &found_hash {
                            // Truncate long hashes for display
                            let display_hash = if hash.len() > 16 {
                                format!("{}...{}", &hash[..8], &hash[hash.len() - 8..])
                            } else {
                                hash.clone()
                            };
                            prevalence_artifacts.push(display_hash);
                        }
                    }
                    if prevalence_info.get("ip").is_some() {
                        prevalence_types.push("ip");
                        if let Some(ip) = &found_ip {
                            prevalence_artifacts.push(ip.clone());
                        }
                    }

                    // Add prevalence_type field to indicate what artifact is being tracked
                    let prevalence_type = if prevalence_types.len() > 1 {
                        format!("{}", prevalence_types.join(", "))
                    } else {
                        prevalence_types.first().unwrap_or(&"unknown").to_string()
                    };
                    obj.insert(
                        "prevalence_type".to_string(),
                        serde_json::Value::String(prevalence_type),
                    );

                    // Add prevalence_artifact field to show the actual artifact value(s)
                    if !prevalence_artifacts.is_empty() {
                        obj.insert(
                            "prevalence_artifact".to_string(),
                            serde_json::Value::String(prevalence_artifacts.join(", ")),
                        );
                    }

                    // Also add top-level convenience fields for easier filtering
                    // This allows queries like: | where host_count < 3
                    // Priority: domain > hash > ip
                    let convenience_source = prevalence_info
                        .get("domain")
                        .or_else(|| prevalence_info.get("hash"))
                        .or_else(|| prevalence_info.get("ip"));

                    if let Some(source_data) = convenience_source {
                        if let Some(host_count) = source_data.get("host_count") {
                            obj.insert("host_count".to_string(), host_count.clone());
                        }
                        if let Some(is_rare) = source_data.get("is_rare") {
                            obj.insert("is_rare".to_string(), is_rare.clone());
                        }
                        if let Some(prevalence_score) = source_data.get("prevalence_score") {
                            obj.insert("prevalence_score".to_string(), prevalence_score.clone());
                        }
                        if let Some(first_seen) = source_data.get("first_seen") {
                            obj.insert("prevalence_first_seen".to_string(), first_seen.clone());
                            // Also write first_seen for backward compat, but only if event doesn't already have one
                            if !obj.contains_key("first_seen") {
                                obj.insert("first_seen".to_string(), first_seen.clone());
                            }
                        }
                        if let Some(last_seen) = source_data.get("last_seen") {
                            obj.insert("prevalence_last_seen".to_string(), last_seen.clone());
                            if !obj.contains_key("last_seen") {
                                obj.insert("last_seen".to_string(), last_seen.clone());
                            }
                        }
                        if let Some(total_occurrences) = source_data.get("total_occurrences") {
                            obj.insert("total_occurrences".to_string(), total_occurrences.clone());
                        }
                    }

                    // Insert the _prevalence object after extracting convenience fields
                    obj.insert(
                        "_prevalence".to_string(),
                        serde_json::Value::Object(prevalence_info),
                    );
                }
            }
        }

        tracing::debug!(
            "Prevalence enrichment: enriched {} results with prevalence data",
            enriched_count
        );

        // Log a sample of what the enriched data looks like - find an ACTUALLY enriched result
        let enriched_sample = results.iter().find(|r| {
            r.as_object()
                .map(|obj| obj.contains_key("_prevalence"))
                .unwrap_or(false)
        });

        if let Some(sample) = enriched_sample {
            if let Some(obj) = sample.as_object() {
                let has_host_count = obj.contains_key("host_count");
                let has_prevalence = obj.contains_key("_prevalence");
                let host_count_val = obj
                    .get("host_count")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string());
                let prevalence_keys: Vec<String> = obj
                    .get("_prevalence")
                    .and_then(|p| p.as_object())
                    .map(|p_obj| p_obj.keys().cloned().collect())
                    .unwrap_or_default();
                tracing::debug!(
                    "Sample enriched result: has_host_count={}, has_prevalence={}, host_count={}, prevalence_keys={:?}",
                    has_host_count, has_prevalence, host_count_val, prevalence_keys
                );
            }
        } else {
            tracing::debug!(
                "No enriched results found in sample (all {} results lack prevalence data)",
                results.len()
            );
        }

        Ok(results)
    }

    /// Restructure flat prevalence fields from JOIN query into nested _prevalence structure
    ///
    /// This is a fast, local-only operation that transforms the flat fields returned by
    /// the prevalence JOIN query into the expected nested format. No network calls are made.
    ///
    /// The JOIN query returns:
    /// - host_count, prevalence_first_seen, prevalence_last_seen, total_occurrences
    /// - is_rare, prevalence_score, prevalence_type, prevalence_artifact
    ///
    /// This function restructures them into:
    /// - Top-level: host_count, first_seen, last_seen, total_occurrences, is_rare, prevalence_score
    /// - Nested: _prevalence.{domain|hash|ip}.{host_count, first_seen, last_seen, ...}
    pub(crate) fn restructure_prevalence_fields_from_join(
        mut results: Vec<serde_json::Value>,
    ) -> Vec<serde_json::Value> {
        for row in &mut results {
            if let Some(obj) = row.as_object_mut() {
                // Get prevalence type to determine which nested key to use
                let prevalence_type = obj
                    .get("prevalence_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // Skip if no prevalence data
                if prevalence_type.is_empty() {
                    continue;
                }

                // Extract values from flat fields
                let host_count = obj.get("host_count").cloned();
                let first_seen = obj.get("prevalence_first_seen").cloned();
                let last_seen = obj.get("prevalence_last_seen").cloned();
                let total_occurrences = obj.get("total_occurrences").cloned();
                let is_rare = obj.get("is_rare").cloned();
                let prevalence_score = obj.get("prevalence_score").cloned();
                let prevalence_artifact = obj.get("prevalence_artifact").cloned();

                // Keep prevalence_first_seen / prevalence_last_seen as-is (no rename)
                // but also write first_seen / last_seen as backward-compat aliases
                // if the event doesn't already have them
                if first_seen.is_some() && !obj.contains_key("first_seen") {
                    obj.insert("first_seen".to_string(), first_seen.clone().unwrap());
                }
                if last_seen.is_some() && !obj.contains_key("last_seen") {
                    obj.insert("last_seen".to_string(), last_seen.clone().unwrap());
                }

                // Build the nested _prevalence structure
                let mut prevalence_info = serde_json::Map::new();
                let mut type_obj = serde_json::Map::new();

                if let Some(hc) = &host_count {
                    type_obj.insert("host_count".to_string(), hc.clone());
                }
                if let Some(fs) = &first_seen {
                    type_obj.insert("first_seen".to_string(), fs.clone());
                }
                if let Some(ls) = &last_seen {
                    type_obj.insert("last_seen".to_string(), ls.clone());
                }
                if let Some(to) = &total_occurrences {
                    type_obj.insert("total_occurrences".to_string(), to.clone());
                }
                if let Some(ir) = &is_rare {
                    type_obj.insert("is_rare".to_string(), ir.clone());
                }
                if let Some(ps) = &prevalence_score {
                    type_obj.insert("prevalence_score".to_string(), ps.clone());
                }
                if let Some(pa) = &prevalence_artifact {
                    type_obj.insert("artifact".to_string(), pa.clone());
                }

                // Insert under the appropriate type key (domain, hash, or ip)
                if !type_obj.is_empty() {
                    prevalence_info
                        .insert(prevalence_type.clone(), serde_json::Value::Object(type_obj));
                    obj.insert(
                        "_prevalence".to_string(),
                        serde_json::Value::Object(prevalence_info),
                    );
                }
            }
        }

        results
    }

    /// Get prevalence artifacts for a search query
    ///
    /// This extracts distinct domains, hashes, and IPs from the logs matching the query,
    /// then looks up their prevalence data. This is more efficient than extracting from
    /// individual results since it queries distinct values directly from ClickHouse.
    ///
    /// `scope` (NAN-1799): the caller's source-scope deny-set is injected into
    /// the query text before SQL generation — the artifact scan below slices
    /// this query's WHERE out of the generated base SQL, so the exclusion
    /// rides along into the `matching_logs` CTE and a scoped caller cannot
    /// enumerate artifacts from denied sources.
    pub async fn get_prevalence_artifacts(
        &self,
        request: &SearchRequest,
        scope: &crate::auth::ScopeSet,
    ) -> Result<crate::prevalence::PrevalenceScatterData, SearchError> {
        use crate::prevalence::{PrevalenceScatterData, TimeWindow};
        // NAN-2219: the artifact half. The DISTINCT artifact extraction below
        // still runs under the full row-filter deny set via
        // `enforce_source_scope`, so a caller cannot enumerate artifacts out of
        // denied (or audit) LOG ROWS; only the prevalence numbers looked up for
        // the artifacts they legitimately extracted come from the artifact half.
        let artifact_scope = crate::auth::ArtifactScope::from_scope(scope);

        // Need ClickHouse for this operation
        let clickhouse = self.ch_client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "ClickHouse required for prevalence artifacts".to_string(),
            )
        })?;

        // NAN-1799: gate, then parse. Empty deny-set → text unchanged.
        let enforced_query = crate::search::query_processing::enforce_source_scope(
            &request.query,
            scope.deny_set(),
        )?;

        // Parse the query
        let query = parse_query(&enforced_query).map_err(convert_parse_error)?;
        let time_range = TimeRange::new(request.time_range.start, request.time_range.end);

        // Generate base WHERE clause using ClickHouse generator
        let base_sql = self
            .ch_sql_generator
            .generate(&query, &time_range)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // Extract the WHERE clause from the base SQL
        // NAN-2010 (F26/F27): ASCII-fold (length-preserving) so these offsets
        // stay valid for slicing the original strings; `to_lowercase()` is not
        // length-preserving and a multibyte user value could shift the offset
        // off a char boundary and panic.
        let where_clause = if let Some(where_pos) = base_sql.to_ascii_lowercase().find(" where ") {
            let after_where = &base_sql[where_pos + 7..];
            // Find end of WHERE (before ORDER BY or end of string)
            if let Some(order_pos) = after_where.to_ascii_lowercase().find(" order by") {
                after_where[..order_pos].to_string()
            } else {
                after_where.trim_end_matches(';').to_string()
            }
        } else {
            "1=1".to_string()
        };

        // Query to extract ALL distinct artifacts from matching logs
        // No limit on artifacts - batching handles any count
        // This ensures targeted searches (e.g., src_host="danslaptop") find all rare artifacts
        // NAN-1241: profile-aware table + column resolution. UDM resolves each UDM-semantic
        // field to the same bare literal (byte-identical SQL); OCSF resolves to the promoted
        // dotted column. Any concept the active schema doesn't map is skipped (its UNION-ALL
        // branch is dropped) rather than referencing a missing column (which 500s on OCSF).
        let profile = self.active_profile.as_ref();
        let logs_table = self.table_names.read(Self::logs_table_key(profile));

        let dest_host_col = profile.udm_column_sql("dest_host");
        let src_host_col = profile.udm_column_sql("src_host");
        let query_col = profile.udm_column_sql("query");
        let dest_ip_col = profile.udm_column_sql("dest_ip");
        let src_ip_col = profile.udm_column_sql("src_ip");
        let file_hash_col = profile.udm_column_sql("file_hash");
        let process_hash_col = profile.udm_column_sql("process_hash");

        // The matching_logs CTE projects each resolved artifact column under a
        // STABLE ALIAS (`_dest_host`, `_process_hash`, …); every DISTINCT branch
        // references that alias, never the raw resolved expression. Under OCSF the
        // resolved columns are class-split `if("a" != '', "a", "b")` expressions
        // over dotted columns the CTE does not otherwise expose, so re-referencing
        // them outside matching_logs threw `Code 47 UNKNOWN_IDENTIFIER`
        // (NAN-1301, same scope class as NAN-1306). UDM columns are bare, so the
        // alias is a harmless rename. `domain`/`hash`/`ip` stay the final
        // sub-select alias names the row reader expects.
        let dest_host_a = dest_host_col.as_ref().map(|_| "_dest_host");
        let src_host_a = src_host_col.as_ref().map(|_| "_src_host");
        let query_a = query_col.as_ref().map(|_| "_query");
        let dest_ip_a = dest_ip_col.as_ref().map(|_| "_dest_ip");
        let src_ip_a = src_ip_col.as_ref().map(|_| "_src_ip");
        let file_hash_a = file_hash_col.as_ref().map(|_| "_file_hash");
        let process_hash_a = process_hash_col.as_ref().map(|_| "_process_hash");

        let mut select_cols: Vec<String> = Vec::new();
        for (col, alias) in [
            (&dest_host_col, "_dest_host"),
            (&src_host_col, "_src_host"),
            (&query_col, "_query"),
            (&dest_ip_col, "_dest_ip"),
            (&src_ip_col, "_src_ip"),
            (&file_hash_col, "_file_hash"),
            (&process_hash_col, "_process_hash"),
        ] {
            if let Some(c) = col {
                select_cols.push(format!("{c} AS {alias}"));
            }
        }
        // Guard: nothing to extract under this schema → empty scatter data, no SQL.
        if select_cols.is_empty() {
            return Ok(PrevalenceScatterData {
                hash_points: Vec::new(),
                domain_points: Vec::new(),
                ip_points: Vec::new(),
                rarity_threshold: 3,
            });
        }

        // Unpivot every mapped artifact column in a SINGLE pass over `matching_logs`
        // via ARRAY JOIN. The prior shape ran one `SELECT DISTINCT … FROM matching_logs`
        // per artifact column (up to 7 branches). A ClickHouse `WITH … AS` CTE is INLINED,
        // not materialized, so each branch re-scanned the whole base query — ~7.5x read
        // amplification. arrayConcat of per-column conditional singleton arrays collapses
        // that to one scan; the outer `SELECT DISTINCT` dedups across columns.
        //
        // Domain columns (dest_host / src_host) now exclude ONLY actual IPv4 literals via
        // `isIPv4String`, not everything with >=3 dots. The old `NOT LIKE '%.%.%.%'` dropped
        // legit deep subdomains (e.g. `a.b.c.example.com`) along with IPs. The `query`
        // branch keeps its "must contain a dot" gate. Domain artifacts are lowercased to
        // match the dict keyspace; hash/ip stay raw (mirroring the union wrappers this
        // replaces: `lower(domain)`, raw `hash`, raw `ip`). Each `if(cond, [tuple], [])`
        // emits zero-or-one `(artifact_type, artifact)` tuple; the empty `[]` inherits the
        // `Array(Tuple(String, String))` type from the populated arm.
        let mut artifact_entries: Vec<String> = Vec::new();
        if let Some(c) = &dest_host_a {
            artifact_entries.push(format!(
                "if({c} != '' AND NOT isIPv4String({c}), [('domain', lower({c}))], [])"
            ));
        }
        if let Some(c) = &src_host_a {
            artifact_entries.push(format!(
                "if({c} != '' AND NOT isIPv4String({c}), [('domain', lower({c}))], [])"
            ));
        }
        if let Some(c) = &query_a {
            artifact_entries.push(format!(
                "if({c} != '' AND position({c}, '.') > 0, [('domain', lower({c}))], [])"
            ));
        }
        if let Some(c) = &file_hash_a {
            artifact_entries.push(format!(
                "if({c} != '' AND length({c}) >= 32, [('hash', {c})], [])"
            ));
        }
        if let Some(c) = &process_hash_a {
            artifact_entries.push(format!(
                "if({c} != '' AND length({c}) >= 32, [('hash', {c})], [])"
            ));
        }
        if let Some(c) = &dest_ip_a {
            artifact_entries.push(format!(
                "if({c} != '' AND isIPv4String({c}), [('ip', {c})], [])"
            ));
        }
        if let Some(c) = &src_ip_a {
            artifact_entries.push(format!(
                "if({c} != '' AND isIPv4String({c}), [('ip', {c})], [])"
            ));
        }

        // No artifact columns mapped under this schema → nothing to extract.
        if artifact_entries.is_empty() {
            return Ok(PrevalenceScatterData {
                hash_points: Vec::new(),
                domain_points: Vec::new(),
                ip_points: Vec::new(),
                rarity_threshold: 3,
            });
        }

        let artifacts_sql = format!(
            r#"
            WITH matching_logs AS (
                SELECT
                    {select_cols}
                FROM {logs_table}
                WHERE {where_clause}
                LIMIT 100000
            )
            SELECT DISTINCT artifact_type, artifact
            FROM (
                SELECT
                    tupleElement(pair, 1) AS artifact_type,
                    tupleElement(pair, 2) AS artifact
                FROM matching_logs
                ARRAY JOIN arrayConcat(
                    {entries}
                ) AS pair
            )
            WHERE artifact != ''
            "#,
            select_cols = select_cols.join(",\n                    "),
            logs_table = logs_table,
            where_clause = where_clause,
            entries = artifact_entries.join(",\n                    "),
        );

        tracing::debug!("Prevalence artifacts SQL: {}", artifacts_sql);

        // Execute the query
        let rows = clickhouse
            .query(&artifacts_sql)
            .fetch_all::<(String, String)>()
            .await
            .map_err(|e| SearchError::SqlGenError(format!("ClickHouse query error: {}", e)))?;

        // Separate by type
        let mut domains: Vec<String> = Vec::new();
        let mut hashes: Vec<String> = Vec::new();
        let mut ips: Vec<String> = Vec::new();

        for (artifact_type, artifact) in rows {
            match artifact_type.as_str() {
                "domain" => domains.push(artifact),
                "hash" => hashes.push(artifact),
                "ip" => ips.push(artifact),
                _ => {}
            }
        }

        tracing::info!(
            "Extracted {} domains, {} hashes, {} IPs from query",
            domains.len(),
            hashes.len(),
            ips.len()
        );

        // Use prevalence service to get scatter data
        // Batch in chunks of 100 to respect MAX_BULK_ARTIFACTS limit
        if let Some(prevalence) = &self.prevalence_service {
            use crate::prevalence::PrevalenceScatterPoint;

            let time_window = TimeWindow::TwentyFourHours;
            let batch_size = 100;

            // Process hashes in batches
            let mut hash_points: Vec<PrevalenceScatterPoint> = Vec::new();
            for chunk in hashes.chunks(batch_size) {
                let results = prevalence
                    .get_bulk_prevalence(chunk, time_window, &artifact_scope)
                    .await
                    .map_err(|e| SearchError::PrevalenceError(e.to_string()))?;
                hash_points.extend(results.into_iter().map(PrevalenceScatterPoint::from));
            }

            // Process domains in batches
            let mut domain_points: Vec<PrevalenceScatterPoint> = Vec::new();
            for chunk in domains.chunks(batch_size) {
                let results = prevalence
                    .get_bulk_prevalence(chunk, time_window, &artifact_scope)
                    .await
                    .map_err(|e| SearchError::PrevalenceError(e.to_string()))?;
                domain_points.extend(results.into_iter().map(PrevalenceScatterPoint::from));
            }

            // Process IPs in batches
            let mut ip_points: Vec<PrevalenceScatterPoint> = Vec::new();
            for chunk in ips.chunks(batch_size) {
                let results = prevalence
                    .get_bulk_prevalence(chunk, time_window, &artifact_scope)
                    .await
                    .map_err(|e| SearchError::PrevalenceError(e.to_string()))?;
                ip_points.extend(results.into_iter().map(PrevalenceScatterPoint::from));
            }

            let config = prevalence.get_config().await;

            Ok(PrevalenceScatterData {
                hash_points,
                domain_points,
                ip_points,
                rarity_threshold: config.rarity_threshold,
            })
        } else {
            // Return empty data if no prevalence service
            Ok(PrevalenceScatterData {
                hash_points: Vec::new(),
                domain_points: Vec::new(),
                ip_points: Vec::new(),
                rarity_threshold: 3,
            })
        }
    }
}

/// Decide whether a row whose looked-up prevalence host_count is `prevalence`
/// passes a `| prevalence <field> <op> <threshold>` filter condition.
///
/// `prevalence` is `None` when the artifact is ABSENT from the prevalence dict.
/// A dict miss means "common / not tracked" — the dict omits artifacts seen on
/// >=1000 hosts and masks the rest to the 9999 sentinel — it is NOT host_count
/// 0. A miss therefore fails EVERY comparison, mirroring the JOIN path where an
/// absent host_count (SQL NULL) is dropped by the WHERE. This keeps the
/// dict-path filter from inverting: a common artifact must never satisfy a
/// `host_count < N` rarity test just because it fell out of the dict.
pub(crate) fn prevalence_passes_filter(
    prevalence: Option<u64>,
    operator: &PrevalenceOperator,
    threshold: u64,
) -> bool {
    let Some(prevalence) = prevalence else {
        return false;
    };
    match operator {
        PrevalenceOperator::Lt => prevalence < threshold,
        PrevalenceOperator::Lte => prevalence <= threshold,
        PrevalenceOperator::Gt => prevalence > threshold,
        PrevalenceOperator::Gte => prevalence >= threshold,
        PrevalenceOperator::Eq => prevalence == threshold,
        PrevalenceOperator::Ne => prevalence != threshold,
    }
}

/// The ordered UDM-semantic concept list a prevalence FILTER keys on, in COALESCE
/// priority order.
///
/// NAN-1691 LOCK-STEP: hash filters try `file_hash` first, then `process_hash`, matching
/// the pushdown's `lower(COALESCE(file_hash, process_hash))` (the JOIN's `_hp_host_count`
/// alias) — so a sysmon row carrying ONLY a process_hash matches on BOTH the in-memory
/// path and the pushed-down path. Domain filters use `dest_host`, matching the domain
/// alias. If this diverges from `prevalence_filter_condition_to_sql`, the filter form
/// returns different row sets depending on whether it pushed down.
pub(crate) fn prevalence_filter_udm_concepts(
    field: &PrevalenceField,
) -> &'static [&'static str] {
    match field {
        PrevalenceField::HashPrevalence | PrevalenceField::HashFirstSeen => {
            &["file_hash", "process_hash"]
        }
        PrevalenceField::DomainPrevalence | PrevalenceField::DomainFirstSeen => &["dest_host"],
    }
}

/// COALESCE artifact extraction: the first non-empty string value across `fields`
/// (result-row output keys), in order. Mirrors the SQL `COALESCE(...)` the pushdown
/// emits — a hash row falls back from `file_hash` to `process_hash`.
pub(crate) fn extract_prevalence_artifact(
    row: &serde_json::Value,
    fields: &[String],
) -> Option<String> {
    fields.iter().find_map(|f| {
        row.get(f.as_str())
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    })
}

/// Map a single `| prevalence <field> <op> N` count condition to a SQL predicate over the
/// windowed, dict-masked host-count aliases the prevalence JOIN CTE computes
/// (`_hp_host_count` for hash, `_dp_host_count` for domain). Returns None for conditions
/// that don't push down (timestamp fields, Duration thresholds) — those stay on the
/// no-op in-memory path, preserving today's behavior.
///
/// NAN-1691: the `< 9999` presence guard makes a dict miss / out-of-window entry fail
/// every operator, mirroring `prevalence_passes_filter(None, …) == false` so the pushdown
/// yields the SAME row set as the in-memory filter.
///
/// NAN-1705 (D4b): this predicate is UNCHANGED — the rescue is applied one level
/// up, on the `_hp/_dp_host_count` projection aliases (see [`rescue_transform_sql`]).
/// A rescued dict-blind artifact's alias is rewritten to its TRUE fresh host_count
/// in-SQL, so `{alias} < 9999 AND {alias} {op} N` matches it directly here — and,
/// crucially, so does every downstream reference (the decoration CASEs, a user
/// `| where host_count < N`). No OR-branch, no post-query patch, no divergence.
pub(crate) fn prevalence_filter_condition_to_sql(
    cond: &crate::query::PrevalenceCondition,
) -> Option<String> {
    use crate::query::{PrevalenceField, PrevalenceOperator, PrevalenceThreshold};

    let alias = match cond.field {
        PrevalenceField::HashPrevalence => "_hp_host_count",
        PrevalenceField::DomainPrevalence => "_dp_host_count",
        // first_seen fields have no command-form SQL filter (in-memory no-ops them).
        PrevalenceField::HashFirstSeen | PrevalenceField::DomainFirstSeen => return None,
    };
    let n = match cond.threshold {
        PrevalenceThreshold::Count(n) => n,
        PrevalenceThreshold::Duration(_) => return None,
    };
    let op = match cond.operator {
        PrevalenceOperator::Lt => "<",
        PrevalenceOperator::Lte => "<=",
        PrevalenceOperator::Gt => ">",
        PrevalenceOperator::Gte => ">=",
        PrevalenceOperator::Eq => "=",
        PrevalenceOperator::Ne => "!=",
    };
    Some(format!("({alias} < 9999 AND {alias} {op} {n})"))
}

// ============================================================================
// NAN-1705 (D4b): fresh-prevalence rescue for dict-blind artifacts
// ============================================================================
//
// The prevalence dicts are COMPLEX_KEY_CACHE with LIFETIME(900–1800s)
// (clickhouse/130_memory_bound_dict_source_queries.sql). A brand-new artifact's
// FIRST dict lookup happens at ingest time — the `logs.prevalence_*`
// MATERIALIZED columns call dictGetOrDefault while the insert block's own
// summary-MV rows haven't landed yet — so the miss is negative-cached and every
// detection query for the next 15–30 minutes sees the 9999 sentinel. The `<
// 9999` presence guard then drops the row for every operator: a rarity rule is
// blind to an artifact exactly while it is newest (audit D4, scenario b).
//
// The rescue re-resolves the window's dict-missed keys against
// `*_prevalence_summary` — the dict's OWN source table, populated by
// insert-time MV chains (logs → *_prevalence_agg → *_prevalence_summary), i.e.
// real-time — using the dict source's exact contract:
//   - `host_count < 1000` (the dict source HAVING): common artifacts stay
//     excluded, so a masked-common artifact can never sneak into a rarity rule
//     (no behavior change for scenario-c style conditions);
//   - `last_seen >= <window cutoff>`: the same NAN-364 mask the dict path
//     applies at lookup time.
// A rescued artifact therefore behaves exactly as it would have if the dict
// had been refreshed at query time. Cold/empty summary ⇒ nothing rescued —
// identical to today (the D4a fail-loud dict monitor covers that scenario).
//
// This is deliberately NOT the full-universe agg JOIN (NAN-362 OOM,
// re-validated on Saturn 2026-07-06: 228M distinct IPs vs a 3 GiB per-query
// cap): the probe is bounded by the DISTINCT dict-missed keys of the base
// query's own window — structurally the common head + the brand-new trickle
// (Saturn: 400 distinct missed hashes in a 1h window; probe 0.5s) — and the
// summary GROUP BY is bounded by that IN-set.

/// Upper bound on DISTINCT missed keys the probe will consider. Bounds probe
/// work under pathological windows (e.g. a DGA storm producing an enormous
/// distinct-domain set). Artifacts beyond the cap are simply not rescued this
/// cycle — strictly no worse than the pre-NAN-1705 behavior (all dropped).
pub(crate) const PREVALENCE_RESCUE_MISS_KEY_CAP: usize = 50_000;

/// Upper bound on rescued artifacts inlined into the main query's IN-list.
/// Keeps the generated SQL far below CH's `max_query_size`. Exceeding it is
/// logged; the overflow is not rescued this cycle.
pub(crate) const PREVALENCE_RESCUE_MAX_ARTIFACTS: usize = 1_000;

/// Host-count cutoff above which the dict source deliberately does not track
/// entities ("common"). Mirrors `HAVING host_count < 1000` in
/// clickhouse/130_memory_bound_dict_source_queries.sql — keep in lock-step.
pub(crate) const PREVALENCE_DICT_HOST_COUNT_CUTOFF: u64 = 1000;

/// An artifact the rescue probe re-verified against the real-time summary.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RescuedArtifact {
    /// Lowercased lookup key — matches the `_hash_lookup` / `_domain_lookup`
    /// aliases the pushdown computes (both are `lower(...)` expressions).
    pub artifact: String,
    /// Fresh 30d host_count from the summary (always `< 1000` by construction).
    pub host_count: u64,
    /// Fresh first/last-seen from the summary, as the probe's `toString(...)`
    /// renders them (`YYYY-MM-DD HH:MM:SS[.ffffff]`), re-parsed into the
    /// projection via `toDateTime64('…', 6)` (see [`RescueAttr::literal`]).
    ///
    /// NAN-1723: the probe SELECTs these as `fs_raw`/`ls_raw` (NOT
    /// `first_seen`/`last_seen`) precisely so `execute_dynamic_query`'s
    /// `convert_timestamps_to_iso8601` leaves the space format untouched —
    /// otherwise `toDateTime64` chokes on the rewritten `T…Z` form.
    pub first_seen: String,
    pub last_seen: String,
    pub total_occurrences: u64,
}

/// Rescued artifacts per entity type. `hashes`/`domains` are reachable from the
/// `| prevalence <field> <op> N` FILTER form (which only supports hash/domain
/// count fields). `ips` is reachable ONLY via the `enrich=true` decoration —
/// `host_count = least(_dp, _ip, _hp)` includes the IP dimension, and there is
/// no `ip_prevalence` filter field — so an IP-rarity rule is necessarily
/// `... | prevalence enrich=true | where host_count < N` (NAN-1705 residual #2).
/// Empty by default — an empty rescue leaves the generated SQL byte-identical to
/// the pre-NAN-1705 output.
#[derive(Debug, Clone, Default)]
pub(crate) struct PrevalenceRescue {
    pub hashes: Vec<RescuedArtifact>,
    pub domains: Vec<RescuedArtifact>,
    pub ips: Vec<RescuedArtifact>,
}

/// Build the rescue-probe SQL for one entity type.
///
/// Shape (executed OUTSIDE the paginated executor, so its `GROUP BY` cannot
/// flip `is_aggregation_query` sniffing for the main query — the main query
/// only ever receives literal IN-lists):
///
/// 1. innermost: DISTINCT lookup keys over the rule's own base scan (bounded
///    by [`PREVALENCE_RESCUE_MISS_KEY_CAP`]), keeping only keys whose
///    dict-masked lookup is the 9999 sentinel (miss OR out-of-window — the
///    exact population the pushdown drops);
/// 2. middle: the dict source query scoped to those keys — summary GROUP BY
///    bounded by the IN-set;
/// 3. outer: the dict source's `host_count < 1000` contract plus the NAN-364
///    window mask on the FRESH `last_seen`, then rarest-first + capped so a
///    broad rule's rescue set stays bounded.
///
/// `dictGetOrDefault` here re-reads the same cache the main query will read
/// (poisoned negatives stay 9999 for their remaining LIFETIME), which is
/// exactly what makes the probe find them; it also pre-warms uncached keys for
/// the main query.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_prevalence_rescue_probe_sql(
    base_sql_no_order: &str,
    lookup_expr: &str,
    dict_name: &str,
    summary_table: &str,
    summary_key_col: &str,
    summary_host_count_col: &str,
    window_cutoff_sql: &str,
    // Extra summary predicate ANDed before the IN-clause (e.g. `is_private = 0`
    // for the IP summary, mirroring the ip dict source's `WHERE is_private = 0`).
    // Empty string for hash/domain. Must end with ` AND ` if non-empty.
    extra_summary_filter: &str,
) -> String {
    // NAN-1723: the outer alias names MUST NOT be `first_seen`/`last_seen`.
    // This probe's rows are read back through `execute_dynamic_query`, whose
    // `convert_timestamps_to_iso8601` post-processor rewrites any field literally
    // named `first_seen`/`last_seen` (among others) from CH's space format
    // `YYYY-MM-DD HH:MM:SS.ffffff` into rfc3339 `…T…Z`. `RescueAttr::literal`
    // then embeds the value into `toDateTime64('…', 6)`, which REJECTS the `T`/`Z`
    // form → the whole rescued detection query fails (CANNOT_PARSE_TEXT). Aliasing
    // to `fs_raw`/`ls_raw` (not in that normaliser's field list) keeps the space
    // format intact so the literal parses. The INNER `min(first_seen)` /
    // `max(last_seen)` below reference the summary table's real columns and stay.
    format!(
        r#"SELECT
    artifact,
    toUInt64(_hc) AS host_count,
    toString(_fs) AS fs_raw,
    toString(_ls) AS ls_raw,
    toUInt64(_occ) AS total_occurrences
FROM (
    SELECT
        {summary_key_col} AS artifact,
        toUInt16(least(9998, uniqMerge({summary_host_count_col}))) AS _hc,
        min(first_seen) AS _fs,
        max(last_seen) AS _ls,
        toUInt64(sum(total_count)) AS _occ
    FROM {summary_table}
    WHERE {extra_summary_filter}{summary_key_col} IN (
        SELECT _k FROM (
            SELECT DISTINCT {lookup_expr} AS _k FROM (
                {base_sql_no_order}
            )
            LIMIT {miss_key_cap}
        )
        WHERE _k IS NOT NULL AND _k != ''
          AND if(dictGetOrDefault('{dict_name}', 'last_seen', ifNull(_k, ''), toDateTime64(0, 6)) >= {window_cutoff_sql},
                 dictGetOrDefault('{dict_name}', 'host_count', ifNull(_k, ''), toUInt16(9999)),
                 toUInt16(9999)) = 9999
    )
    GROUP BY {summary_key_col}
)
WHERE _hc < {dict_cutoff} AND _ls >= {window_cutoff_sql}
ORDER BY _hc ASC
LIMIT {artifact_cap_plus_one}"#,
        summary_key_col = summary_key_col,
        summary_host_count_col = summary_host_count_col,
        summary_table = summary_table,
        extra_summary_filter = extra_summary_filter,
        lookup_expr = lookup_expr,
        base_sql_no_order = base_sql_no_order,
        miss_key_cap = PREVALENCE_RESCUE_MISS_KEY_CAP,
        dict_name = dict_name,
        window_cutoff_sql = window_cutoff_sql,
        dict_cutoff = PREVALENCE_DICT_HOST_COUNT_CUTOFF,
        // Rarest-first, capped IN-SQL so a broad rule's rescue set (Saturn: 6k+
        // rare IPs in a 1h `*|` window) can't blow past the artifact cap — and
        // the RAREST (most likely brand-new-malicious) win the slots, not
        // arbitrary ones. `+ 1` so `filter_rescued_artifacts` can SEE the
        // overflow and WARN (it truncates back to the cap), rather than the LIMIT
        // silently hiding that artifacts were dropped.
        artifact_cap_plus_one = PREVALENCE_RESCUE_MAX_ARTIFACTS + 1,
    )
}

/// NAN-1705 (D4b, residual #2): detect the `enrich=true | where <decorated> ...`
/// pattern that has the full blind spot but no `| prevalence` count condition to
/// drive the rescue, and derive the host_count threshold to bound the rescue set.
///
/// The `enrich=true` decoration exposes `host_count` / `is_rare` /
/// `prevalence_score` (all CASE expressions over `least(_dp, _ip, _hp)`). A
/// brand-new dict-blind row reads `least(9999,9999,9999)=9999`, so:
///   - `| where host_count < N` (or `<= N`, `= N`) → `9999 < N` false → DROPPED;
///   - `| where is_rare` / `is_rare = true` → CASE returns false → DROPPED.
/// Both silently lose the exact artifact the rule hunts.
///
/// Returns the count threshold to rescue up to (rescue artifacts whose real
/// count `<= threshold`, a superset — the in-SQL `| where` does the exact
/// filtering once the alias is transform-corrected). `None` ⇒ no such filter, so
/// NO probe runs and pure-decorate `enrich=true` stays byte-identical.
///
/// Deliberately NOT triggered by:
///   - `prevalence_score < X`: a masked row scores 0, and `0 < X` is TRUE, so the
///     row is KEPT (wrong score, not dropped) — no drop-bug, out of scope here;
///   - common-direction filters (`host_count > N`, `is_rare = false`): a masked
///     row passes those, a different (false-positive) bug, not this one.
pub(crate) fn decorated_filter_rescue_threshold(
    post_prevalence_commands: &[crate::query::Command],
    rarity_threshold: u64,
) -> Option<u64> {
    use crate::query::{Command, Comparator, EvalExpression, SearchExpr, Value};
    use std::collections::HashSet;

    fn decorated_field(field: &str) -> bool {
        matches!(
            field,
            "host_count"
                | "is_rare"
                | "prevalence_score"
                | "first_seen"
                | "last_seen"
                | "prevalence_first_seen"
                | "prevalence_last_seen"
                | "total_occurrences"
                | "prevalence_type"
                | "prevalence_artifact"
        )
    }

    fn eval_depends_on_decoration(
        expression: &EvalExpression,
        dependent_aliases: &HashSet<String>,
    ) -> bool {
        match expression {
            EvalExpression::Field(field) => {
                decorated_field(field) || dependent_aliases.contains(field)
            }
            EvalExpression::Literal(_) => false,
            EvalExpression::FunctionCall { args, .. } => args
                .iter()
                .any(|arg| eval_depends_on_decoration(arg, dependent_aliases)),
            EvalExpression::BinaryOp { left, right, .. } => {
                eval_depends_on_decoration(left, dependent_aliases)
                    || eval_depends_on_decoration(right, dependent_aliases)
            }
        }
    }

    let conservative_threshold = PREVALENCE_DICT_HOST_COUNT_CUTOFF.saturating_sub(1);

    // Walk a WHERE expression, collecting rescue thresholds from rare-direction
    // filters on decorated prevalence columns. AND/OR/Group are transparent —
    // rescuing a superset is safe, the in-SQL predicate filters exactly. `Not`
    // is OPAQUE (audit D4b, codex): it inverts the rare/common direction, so
    // descending into it would both fire spuriously on common-direction
    // negations (`NOT(host_count < N)` ⇒ `host_count >= N`, a masked row *passes*
    // — no drop-bug) and mis-handle rare-direction ones. Skipping `Not` keeps
    // the common-direction case byte-identical (no spurious probe). The
    // contrived rare-via-`Not` forms (`NOT(is_rare = false)`,
    // `NOT(host_count >= N)`) simply aren't rescued — write the un-negated form
    // (`is_rare`, `host_count < N`), which is fully covered.
    fn collect(
        expr: &SearchExpr,
        rarity_threshold: u64,
        conservative_threshold: u64,
        dependent_aliases: &HashSet<String>,
        out: &mut Vec<u64>,
    ) {
        match expr {
            SearchExpr::FieldFilter { field, op, value } => {
                match field.as_str() {
                    "host_count" => {
                        if matches!(op, Comparator::Lt | Comparator::Lte | Comparator::Eq) {
                            if let Value::Number(n) = value {
                                if *n >= 0.0 {
                                    // `< N` needs artifacts up to N-1; `<= N` / `= N` up to N.
                                    // Use ceil(N) as an inclusive upper bound (superset-safe).
                                    out.push(n.ceil() as u64);
                                }
                            }
                        }
                    }
                    "is_rare" => {
                        let truthy = match value {
                            Value::Bool(b) => *b,
                            Value::Number(n) => *n != 0.0,
                            Value::String(s) => {
                                let l = s.to_lowercase();
                                l == "true" || l == "1"
                            }
                            _ => false,
                        };
                        // is_rare = host_count < rarity_threshold, so rescue up to
                        // rarity_threshold - 1 (inclusive bound rarity_threshold-1).
                        if truthy && matches!(op, Comparator::Eq) {
                            out.push(rarity_threshold.saturating_sub(1).max(1));
                        }
                    }
                    // Timestamp/occurrence decorations become NULL/zero while
                    // a dict-negative artifact is masked. A direct predicate or
                    // an eval alias derived from any decoration therefore gets
                    // the conservative rarity-index superset; the outer WHERE
                    // still performs the exact arithmetic/comparison.
                    "first_seen"
                    | "last_seen"
                    | "prevalence_first_seen"
                    | "prevalence_last_seen"
                    | "total_occurrences" => out.push(conservative_threshold),
                    _ if dependent_aliases.contains(field) => out.push(conservative_threshold),
                    _ => {}
                }
            }
            SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                collect(
                    a,
                    rarity_threshold,
                    conservative_threshold,
                    dependent_aliases,
                    out,
                );
                collect(
                    b,
                    rarity_threshold,
                    conservative_threshold,
                    dependent_aliases,
                    out,
                );
            }
            SearchExpr::Group(inner) => collect(
                inner,
                rarity_threshold,
                conservative_threshold,
                dependent_aliases,
                out,
            ),
            SearchExpr::EvalPredicate(expression)
            | SearchExpr::BooleanFunction(expression)
            | SearchExpr::FunctionFilter {
                function: expression,
                ..
            } if eval_depends_on_decoration(expression, dependent_aliases) => {
                out.push(conservative_threshold)
            }
            SearchExpr::FieldFunctionFilter {
                field, function, ..
            } if decorated_field(field)
                || dependent_aliases.contains(field)
                || eval_depends_on_decoration(function, dependent_aliases) =>
            {
                out.push(conservative_threshold)
            }
            SearchExpr::InList { field, .. }
                if decorated_field(field) || dependent_aliases.contains(field) =>
            {
                out.push(conservative_threshold)
            }
            // `Not` is opaque — see the direction-inversion note above.
            SearchExpr::Not(_) => {}
            _ => {}
        }
    }

    let mut thresholds: Vec<u64> = Vec::new();
    let mut dependent_aliases = HashSet::new();
    for cmd in post_prevalence_commands {
        match cmd {
            Command::Eval { assignments } => {
                for assignment in assignments {
                    if eval_depends_on_decoration(&assignment.expression, &dependent_aliases) {
                        dependent_aliases.insert(assignment.field.clone());
                    } else {
                        // Reassignment shadows the earlier value and must not
                        // retain stale prevalence dependency.
                        dependent_aliases.remove(&assignment.field);
                    }
                }
            }
            Command::Where { condition } => collect(
                condition,
                rarity_threshold,
                conservative_threshold,
                &dependent_aliases,
                &mut thresholds,
            ),
            _ => {}
        }
    }
    // Rescue the SUPERSET covering the loosest filter (the in-SQL WHERE narrows
    // per-condition), so the transform arrays stay minimal yet complete.
    thresholds.into_iter().max()
}

/// Parse probe rows (JSONEachRow via `execute_dynamic_query`) and keep only
/// artifacts whose FRESH host_count satisfies EVERY count condition of the
/// probe's entity type — the same `prevalence_passes_filter` the in-memory
/// path uses, so pushdown and fallback can't diverge on operator semantics.
/// Caps the output at [`PREVALENCE_RESCUE_MAX_ARTIFACTS`].
pub(crate) fn filter_rescued_artifacts(
    rows: Vec<serde_json::Value>,
    conditions: &[&crate::query::PrevalenceCondition],
) -> Vec<RescuedArtifact> {
    use crate::query::PrevalenceThreshold;

    // Tolerant u64 extraction: CH JSON formats may quote 64-bit integers
    // (output_format_json_quote_64bit_integers) depending on server config.
    fn get_u64(row: &serde_json::Value, key: &str) -> Option<u64> {
        match row.get(key)? {
            serde_json::Value::Number(n) => n.as_u64(),
            serde_json::Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    let mut rescued: Vec<RescuedArtifact> = Vec::new();
    for row in rows {
        let Some(artifact) = row.get("artifact").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(host_count) = get_u64(&row, "host_count") else {
            continue;
        };
        let passes_all = conditions.iter().all(|cond| {
            let PrevalenceThreshold::Count(n) = cond.threshold else {
                // Non-count conditions never push down (prevalence_filter_condition_to_sql
                // returns None), so the rescue must not enforce them either.
                return true;
            };
            prevalence_passes_filter(Some(host_count), &cond.operator, n)
        });
        if !passes_all {
            continue;
        }
        if rescued.len() >= PREVALENCE_RESCUE_MAX_ARTIFACTS {
            tracing::warn!(
                cap = PREVALENCE_RESCUE_MAX_ARTIFACTS,
                "prevalence rescue: rescued-artifact cap hit; remaining dict-blind artifacts are not rescued this cycle"
            );
            break;
        }
        rescued.push(RescuedArtifact {
            artifact: artifact.to_string(),
            host_count,
            // NAN-1723: read `fs_raw`/`ls_raw`, NOT `first_seen`/`last_seen` —
            // the probe deliberately aliases them away from the names that
            // `execute_dynamic_query`'s timestamp normaliser would rewrite to
            // rfc3339 (which `toDateTime64` then rejects). See the probe SQL.
            first_seen: row
                .get("fs_raw")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            last_seen: row
                .get("ls_raw")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            total_occurrences: get_u64(&row, "total_occurrences").unwrap_or(0),
        });
    }
    rescued
}

/// Which fresh summary attribute a base_logs projection alias carries, so
/// [`rescue_transform_sql`] emits a type-matching `transform(...)` `to_array`
/// (element type must share a supertype with the dict-default it replaces).
#[derive(Debug, Clone, Copy)]
pub(crate) enum RescueAttr {
    /// `_*_host_count` — `UInt16` (dict default `toUInt16(9999)`).
    HostCount,
    /// `_*_first_seen` / `_*_last_seen` — `DateTime64(6)` (default `toDateTime64(0, 6)`).
    FirstSeen,
    LastSeen,
    /// `_*_total_occurrences` — `UInt64` (default `toUInt64(0)`).
    TotalOccurrences,
}

impl RescueAttr {
    /// Render one rescued artifact's value for this attribute as a CH literal
    /// with the exact type the wrapped dict default produces.
    fn literal(self, r: &RescuedArtifact) -> String {
        match self {
            // `host_count < 1000` by construction, so `toUInt16` never truncates.
            RescueAttr::HostCount => format!("toUInt16({})", r.host_count),
            RescueAttr::FirstSeen => format!(
                "toDateTime64('{}', 6)",
                crate::sql_hygiene::escape_sql_string(&r.first_seen)
            ),
            RescueAttr::LastSeen => format!(
                "toDateTime64('{}', 6)",
                crate::sql_hygiene::escape_sql_string(&r.last_seen)
            ),
            RescueAttr::TotalOccurrences => format!("toUInt64({})", r.total_occurrences),
        }
    }
}

/// Wrap a base_logs dict projection so NAN-1705 rescued keys resolve to their
/// FRESH value in-SQL.
///
/// `rescued` empty → `base_expr` is returned **unchanged** (byte-identical to
/// the pre-NAN-1705 projection, so an empty rescue leaves the whole generated
/// query byte-for-byte identical). Otherwise emits
/// `transform(<transform_key>, ['k1',…], [v1,…], <base_expr>)`:
///
/// - `transform_key` is the row's lookup key (`ifNull(_hash_lookup, '')` etc.);
///   a rescued key resolves to its fresh value, any other key falls through to
///   `base_expr` (the original dict-with-window-mask lookup), and an
///   empty/NULL key can never match a rescued (non-empty) key → default.
/// - the `to_array` is bounded by `rescued` (≤ [`PREVALENCE_RESCUE_MAX_ARTIFACTS`]),
///   so no OOM and the emitted literal stays small.
///
/// Because the ALIAS itself now carries the truth, the pushed predicate
/// (`{alias} < 9999 AND {alias} op N`), the decoration CASEs, AND any
/// downstream `| where host_count < N` all see the rescued host_count in
/// ClickHouse — no OR-branch and no post-query patch needed (NAN-1705 D4b, the
/// downstream-decoration gap).
pub(crate) fn rescue_transform_sql(
    base_expr: &str,
    transform_key: &str,
    rescued: &[RescuedArtifact],
    attr: RescueAttr,
) -> String {
    if rescued.is_empty() {
        return base_expr.to_string();
    }
    let keys = rescued
        .iter()
        .map(|r| format!("'{}'", crate::sql_hygiene::escape_sql_string(&r.artifact)))
        .collect::<Vec<_>>()
        .join(", ");
    let vals = rescued
        .iter()
        .map(|r| attr.literal(r))
        .collect::<Vec<_>>()
        .join(", ");
    format!("transform({transform_key}, [{keys}], [{vals}], {base_expr})")
}

#[cfg(test)]
mod tests;

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
                    .apply_prevalence_enrichment(results, prevalence_service, time_window)
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
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        if results.is_empty() {
            return Ok(results);
        }

        // Determine which result-row key to extract artifacts from based on PrevalenceField.
        //
        // NAN-1241: these are the RESULT-ROW output field names (the keys serde produced from
        // the SELECT aliases), not raw SQL columns — so they follow the active schema's output
        // naming. Resolve the UDM-semantic concept through the profile: UDM yields the same
        // `file_hash`/`dest_host` literal (byte-identical), OCSF yields its promoted output
        // column name. If the active schema has no column for the concept, the filter cannot
        // apply — short-circuit gracefully rather than scanning a field that never exists.
        let profile = self.active_profile.as_ref();
        let udm_concept = match field {
            PrevalenceField::HashPrevalence | PrevalenceField::HashFirstSeen => "file_hash",
            PrevalenceField::DomainPrevalence | PrevalenceField::DomainFirstSeen => "dest_host",
        };
        let artifact_field: String = match profile.udm_column_sql(udm_concept) {
            // udm_column_sql returns the SQL-escaped column; strip the OCSF double-quotes so we
            // index the JSON result map by the bare output key. UDM is unquoted → unchanged
            // (byte-identical). TODO(OCSF): the result-row KEY equals the promoted column's
            // serde name; if OCSF serialization ever renames it (vs the bare dotted column),
            // this lookup key must follow that renaming.
            Some(col) => col.trim_matches('"').to_string(),
            None => {
                debug!(
                    "Prevalence filtering: active schema has no column for '{}'; skipping filter",
                    udm_concept
                );
                return Ok(results);
            }
        };
        let artifact_field: &str = artifact_field.as_str();

        // For timestamp-based fields, we need different handling
        if field.is_timestamp_field() {
            warn!("Timestamp-based prevalence filtering (first_seen) not yet implemented");
            return Ok(results);
        }

        // Extract unique artifacts from results
        let artifacts: Vec<String> = results
            .iter()
            .filter_map(|row| {
                row.get(artifact_field)
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if artifacts.is_empty() {
            debug!(
                "No artifacts found in field '{}' for prevalence filtering",
                artifact_field
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
            .get_bulk_prevalence_via_dict(artifacts.as_slice(), time_window)
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
                let artifact = row
                    .get(artifact_field)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if artifact.is_empty() {
                    // Exclude rows without the artifact (matches JOIN path where NULL host_count is excluded by WHERE)
                    return false;
                }

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
                .get_bulk_prevalence_via_dict(&combined, time_window)
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
    pub async fn get_prevalence_artifacts(
        &self,
        request: &SearchRequest,
    ) -> Result<crate::prevalence::PrevalenceScatterData, SearchError> {
        use crate::prevalence::{PrevalenceScatterData, TimeWindow};

        // Need ClickHouse for this operation
        let clickhouse = self.ch_client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "ClickHouse required for prevalence artifacts".to_string(),
            )
        })?;

        // Parse the query
        let query = parse_query(&request.query).map_err(convert_parse_error)?;
        let time_range = TimeRange::new(request.time_range.start, request.time_range.end);

        // Generate base WHERE clause using ClickHouse generator
        let base_sql = self
            .ch_sql_generator
            .generate(&query, &time_range)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // Extract the WHERE clause from the base SQL
        let where_clause = if let Some(where_pos) = base_sql.to_lowercase().find(" where ") {
            let after_where = &base_sql[where_pos + 7..];
            // Find end of WHERE (before ORDER BY or end of string)
            if let Some(order_pos) = after_where.to_lowercase().find(" order by") {
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
                    .get_bulk_prevalence(chunk, time_window)
                    .await
                    .map_err(|e| SearchError::PrevalenceError(e.to_string()))?;
                hash_points.extend(results.into_iter().map(PrevalenceScatterPoint::from));
            }

            // Process domains in batches
            let mut domain_points: Vec<PrevalenceScatterPoint> = Vec::new();
            for chunk in domains.chunks(batch_size) {
                let results = prevalence
                    .get_bulk_prevalence(chunk, time_window)
                    .await
                    .map_err(|e| SearchError::PrevalenceError(e.to_string()))?;
                domain_points.extend(results.into_iter().map(PrevalenceScatterPoint::from));
            }

            // Process IPs in batches
            let mut ip_points: Vec<PrevalenceScatterPoint> = Vec::new();
            for chunk in ips.chunks(batch_size) {
                let results = prevalence
                    .get_bulk_prevalence(chunk, time_window)
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

#[cfg(test)]
mod tests;

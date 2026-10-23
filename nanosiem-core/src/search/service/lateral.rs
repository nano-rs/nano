// SPDX-License-Identifier: AGPL-3.0-or-later

use serde_json::json;
use std::collections::{BTreeSet, HashMap, HashSet};

use super::lateral_graph::{build_lateral_graph_payload, LateralRiskContext, RawEvent};
use super::*;
use crate::auth::ScopeSet;
use crate::query::{LateralMethod, LateralSeedType};
use crate::search::query_processing::LateralCommandInfo;

/// Maximum events to fetch per hop query to prevent runaway queries
const MAX_EVENTS_PER_HOP: usize = 10_000;
/// NAN-3295: rows one interactive lean hop may return. A lean hop row is a
/// per-minute edge group (see [`lake_lateral_hop_query`]), not a raw event, so
/// a busy host's 4-6 h of repeated logons fits; the old 10k raw-event cap
/// refused hop 0 of a 1 h trace on a ~60k events/h host.
const LAKE_MAX_ROWS_PER_HOP: usize = 25_000;
const LAKE_MAX_ROWS_PER_HOP_SENTINEL: usize = LAKE_MAX_ROWS_PER_HOP + 1;
/// Retained-edge envelope of one interactive lean trace (unchanged from the
/// pre-NAN-3295 `MAX_EVENTS_PER_HOP * max_hops(4) * 2`).
const LAKE_INTERACTIVE_EDGE_CAP: usize = 80_000;
/// Maximum entities encoded in one worker query. Larger exact frontiers are
/// split into disjoint query chunks and merged by the graph coordinator.
const MAX_LAKE_FRONTIER_ENTITIES: usize = 256;

/// Exact OCSF 1.9 fields projected by the primary object-lake lateral reader.
///
/// These are storage/query fields, not compatibility aliases. The special
/// lateral response remains a product view DTO, but every read sent to the
/// worker is expressed in canonical OCSF paths. NAN-3295: a hop read
/// groups on / carries exactly these (see [`lake_lateral_hop_query`]).
#[cfg(test)]
const LAKE_LATERAL_FIELDS: &[&str] = &[
    "time",
    "metadata.log_source",
    "user.name",
    "actor.user.name",
    "src_endpoint.hostname",
    "src_endpoint.ip",
    "src_endpoint.port",
    "dst_endpoint.hostname",
    "dst_endpoint.ip",
    "dst_endpoint.port",
    "device.hostname",
    "connection_info.protocol_num",
    "auth_protocol",
    "status",
    "process.name",
    "process.file.path",
    "activity_name",
    "category_name",
    "class_uid",
];

#[derive(Debug)]
struct LakeLateralSeed {
    /// Canonical OCSF field surfaced in view metadata.
    field: String,
    /// The graph's semantic node kind. This is a view concern, not a query alias.
    graph_kind: &'static str,
    value: String,
}

/// Canonical (UDM-semantic) field names selected for lateral-movement events,
/// in projection order. The physical SELECT projection is built per the active
/// schema profile by [`SearchService::lateral_columns`], which resolves each
/// name to its physical column and aliases it back to the canonical name so
/// `extract_edge` (which reads canonical JSON keys) works across UDM and OCSF.
/// Fields the active schema does not map are skipped (NAN-1241).
const LATERAL_FIELDS: &[&str] = &[
    "timestamp",
    "source_type",
    "user",
    "src_ip",
    "dest_ip",
    "src_host",
    "dest_host",
    "src_port",
    "dest_port",
    "protocol",
    "auth_type",
    "auth_result",
    "session_id",
    "process_name",
    "process_path",
    "action",
    "category",
];

impl SearchService {
    /// Build the lateral-movement product view through the tenant-pinned lake
    /// worker. Secondary hop scans use only exact OCSF 1.9 paths and inherit
    /// the caller's source deny-set through [`LakeQueryClient::search`].
    pub(crate) async fn build_lake_lateral_view(
        &self,
        results: Vec<serde_json::Value>,
        lateral_info: &LateralCommandInfo,
        explicit_seed: Option<(String, String)>,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        if time_range.end - time_range.start > chrono::Duration::hours(24) {
            return Err(SearchError::ResourceExhausted("Lateral windows beyond 24h require a durable job".into()));
        }
        let started = std::time::Instant::now();
        let seed = detect_lake_lateral_seed(&results, lateral_info, explicit_seed)?;
        tracing::info!(
            seed_field = %seed.field,
            seed_value = %seed.value,
            max_hops = lateral_info.max_hops,
            methods = ?lateral_info.methods,
            "Starting canonical OCSF lake lateral trace"
        );

        if crate::search::streaming::DEFER_LATERAL_VIEW
            .try_with(|value| *value)
            .unwrap_or(false)
        {
            return Ok(vec![json!({
                "_display_type": "lateral", "_lateral_pending": true,
                "_lateral_trace_id": uuid::Uuid::now_v7().to_string(),
                "_lateral_time_range": { "start": time_range.start, "end": time_range.end },
                "_lateral_config": { "seed_field": seed.field, "seed_value": seed.value,
                    "max_hops": lateral_info.max_hops,
                    "methods": lateral_info.methods.iter().map(LateralMethod::as_str).collect::<Vec<_>>() }
            })]);
        }
        let progress_tx = crate::search::streaming::LATERAL_VIEW_SINK
            .try_with(Clone::clone)
            .ok();
        let (seed_bindings, seed_identity_problem) = self
            .lake_lateral_seed_bindings(&seed, time_range, scope)
            .await;
        let seed_binding_npl = super::lake_host_identity::lake_host_binding_npl(&seed_bindings);
        let (mut all_edges, stopped_at_hop, completed_hops) = trace_lake_lateral(
            &seed, seed_binding_npl.as_deref(), lateral_info, started, Some(LAKE_LATERAL_WALL_BUDGET),
            LAKE_MAX_ROWS_PER_HOP, LAKE_INTERACTIVE_EDGE_CAP,
            |query, hop, method| self.execute_lake_lateral_query(query, time_range, scope, hop, method),
            progress_tx.is_some(), |mut partial_edges, completed_hops| {
                let tx = progress_tx.as_ref();
                let seed = &seed;
                async move {
                    partial_edges.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
                    let mut partial = self.lake_lateral_output(dedup_edges(partial_edges), seed, lateral_info, started, None, scope).await;
                    partial.truncate(1);
                    if let Some(tx) = tx {
                        tx.send(crate::search::streaming::SearchStreamEvent::ViewUpdate {
                            view: "lateral".into(), rows: partial, completed_hops, complete: false,
                        }).await.map_err(|_| SearchError::SqlValidationError("Lateral consumer disconnected".into()))?;
                    }
                    Ok(())
                }
            },
        ).await?;

        if stopped_at_hop.is_some() && progress_tx.is_none() {
            return Err(SearchError::ResourceExhausted("Lateral interactive wall budget ended before the complete traversal".into()));
        }
        all_edges.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
        let mut edges = dedup_edges(all_edges);
        self.resolve_lake_lateral_hostnames(&mut edges, scope).await;

        let mut output = self
            .lake_lateral_output(edges, &seed, lateral_info, started, stopped_at_hop, scope)
            .await;
        if let Some(marker) = output.first_mut().and_then(serde_json::Value::as_object_mut) {
            if !seed_bindings.is_empty() {
                marker.insert(
                    "_lateral_identities".to_string(),
                    json!(seed_bindings
                        .iter()
                        .map(|binding| json!({"host": binding.host, "ip": binding.ip.to_string(),
                            "start": binding.start, "end": binding.end}))
                        .collect::<Vec<_>>()),
                );
            }
            if let Some(note) = seed_identity_problem
                .or_else(|| super::lake_host_identity::lake_host_binding_note(&seed_bindings))
            {
                marker.insert("_lateral_identity_note".to_string(), json!(note));
            }
        }
        if let Some(tx) = &progress_tx {
            tx.send(crate::search::streaming::SearchStreamEvent::ViewUpdate {
                view: "lateral".to_string(),
                rows: vec![output[0].clone()],
                completed_hops,
                complete: stopped_at_hop.is_none(),
            })
            .await
            .map_err(|_| {
                SearchError::SqlValidationError("Lateral consumer disconnected".to_string())
            })?;
        }
        Ok(output)
    }

    async fn lake_lateral_output(
        &self,
        edges: Vec<LateralEdge>,
        seed: &LakeLateralSeed,
        lateral_info: &LateralCommandInfo,
        started: std::time::Instant,
        stopped_at_hop: Option<u32>,
        scope: &ScopeSet,
    ) -> Vec<serde_json::Value> {
        assemble_lake_lateral_output(edges, seed, lateral_info, started, stopped_at_hop, scope, self.risk_query_config.resolve().await).await
    }

    async fn execute_lake_lateral_query(
        &self,
        query: String,
        time_range: &TimeRange,
        scope: &ScopeSet,
        hop: u32,
        method: &str,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        let request_id = format!("lateral-{method}-{hop}-{}", uuid::Uuid::now_v7());
        let request = SearchRequest {
            query: format!("{query} | head {LAKE_MAX_ROWS_PER_HOP_SENTINEL}"),
            time_range: TimeRangeInput::new(time_range.start, time_range.end),
            limit: Some(LAKE_MAX_ROWS_PER_HOP_SENTINEL),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: true,
            table_view: false,
            request_id: Some(request_id.clone()),
            async_mode: false,
            priority: Some("interactive".to_string()),
            dataset: Some("logs".to_string()),
        };
        let response = client
            .search(&request, &request_id, None, scope.deny_set())
            .await?;
        if response.results.len() > LAKE_MAX_ROWS_PER_HOP {
            return Err(SearchError::ResourceExhausted(format!(
                "lateral {method} hop {hop} exceeded the {LAKE_MAX_ROWS_PER_HOP}-edge-group interactive envelope; a durable lateral job is required"
            )));
        }
        Ok(response.results)
    }

    /// NAN-3294: the IPs a host seed held over the trace window, so hop 0
    /// also reads events that name the host only by address. A resolution
    /// failure is reported (second value), never silently ignored.
    async fn lake_lateral_seed_bindings(
        &self,
        seed: &LakeLateralSeed,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> (Vec<super::lake_host_identity::LakeHostIpBinding>, Option<String>) {
        if seed.graph_kind == "user" || seed.value.is_empty() || seed.value.parse::<std::net::IpAddr>().is_ok() {
            return (Vec::new(), None);
        }
        let host = seed.value.to_ascii_lowercase();
        match self
            .resolve_lake_host_ip_bindings(&[host.clone()], time_range.start, time_range.end, scope.deny_set())
            .await
        {
            Ok(bindings) if bindings.len() <= super::lake_host_identity::LAKE_HOST_IP_MAX_BINDINGS => (bindings, None),
            Ok(bindings) => (
                Vec::new(),
                Some(format!(
                    "{host} held {} IP bindings in this window; events that name it only by IP are not traced. Narrow the time range.",
                    bindings.len()
                )),
            ),
            Err(error) => {
                tracing::warn!(error = %error, host = %host, "lateral seed host → IP resolution unavailable");
                (
                    Vec::new(),
                    Some(format!(
                        "Could not resolve {host} to IP addresses ({error}); events that name it only by IP are not traced."
                    )),
                )
            }
        }
    }

    /// Fill edge hostnames from the tenant's lake identity resolution
    /// (NAN-3058: the identity observation index, or the bounded event scan
    /// while it backfills). Best effort by design, like the ClickHouse
    /// lateral view: a resolution failure leaves the IPs as they are and is
    /// logged, it never fails the lateral view.
    async fn resolve_lake_lateral_hostnames(&self, edges: &mut [LateralEdge], scope: &ScopeSet) {
        let items = lateral_identity_items(edges);
        if items.is_empty() {
            return;
        }
        let answers = match self.resolve_lake_identity_ips(&items, scope.deny_set()).await {
            Ok(answers) => answers,
            Err(error) => {
                tracing::warn!(error = %error, "Lake lateral identity enrichment failed");
                return;
            }
        };
        let answers = answers.into_iter().map(|answer| answer.map(|observation| observation.hostname)).collect();
        apply_lateral_hostnames(edges, &items, answers);
    }

    /// Build the lateral-movement SELECT projection for the active schema profile.
    ///
    /// Each canonical field in [`LATERAL_FIELDS`] is resolved via `udm_column_sql`
    /// and aliased back to the canonical name (`col AS canonical`). For the UDM
    /// profile every field resolves to its own column, so the projection is
    /// byte-equivalent to the old const (modulo the seam's uniform reserved-word
    /// quoting) and the rows are byte-identical. Fields the schema does not map
    /// (`udm_column_sql` → `None`) are skipped so no unknown column is referenced.
    ///
    /// NAN-1892: `source_type` is the one exception. The hop WHERE (auth predicate
    /// + per-source RBAC gate) references `lower(source_type)` against the
    /// OPERATIONAL String column ([`LateralPredicateColumns::resolve`], NAN-1887).
    /// If we project `udm_column_sql("source_type") AS source_type` — which under
    /// OCSF is `class_uid AS source_type` (a `UInt32`) — ClickHouse binds the WHERE's
    /// bare `source_type` to that SELECT ALIAS, not the physical column, so
    /// `lower(class_uid)` errors (Code 43). Resolve it via `column_sql` (the physical
    /// `resolve()` path → operational `source_type` String) so projection and
    /// predicate agree on ONE column and the alias no longer shadows a different
    /// type. This also makes OCSF's lateral output `source_type` the operational
    /// log-type name (parity with UDM) instead of a bare class number. UDM: both
    /// resolvers return `source_type`, so byte-identical.
    fn lateral_columns(&self) -> String {
        build_lateral_columns(self.active_profile.as_ref())
    }

    /// Build lateral movement view by tracing hop-by-hop movement paths.
    ///
    /// This method:
    /// 1. Extracts the seed entity (user or host) from initial results
    /// 2. Iteratively expands hops via BFS, querying auth, network, and process events
    /// 3. Builds structured output rows with hop tracking
    /// 4. Returns results with `_display_type: "lateral"` metadata
    ///
    /// NAN-1797/NAN-1799: the hop expansion issues FRESH secondary queries
    /// against the logs table that do NOT inherit the base query's injected
    /// source-scope gate, so the caller's `ScopeSet` is threaded down here and
    /// its deny-set exclusion is appended to every secondary query's WHERE
    /// (see [`source_scope_sql_predicate`]). An empty deny set emits nothing
    /// (byte-identical SQL to the pre-scoping form).
    pub(crate) async fn build_lateral_view(
        &self,
        results: Vec<serde_json::Value>,
        lateral_info: &LateralCommandInfo,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let start_time = std::time::Instant::now();

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => {
                return Err(SearchError::SqlGenError(
                    "ClickHouse required for lateral movement analysis".into(),
                ));
            }
        };

        // Step 1: Extract seed entity from initial results or query context
        let (seed_field, seed_value) = self.detect_lateral_seed(&results, lateral_info)?;
        tracing::info!(
            "Lateral movement trace: seed {}={}, max_hops={}, methods={:?}",
            seed_field,
            seed_value,
            lateral_info.max_hops,
            lateral_info.methods
        );

        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let lateral_columns = self.lateral_columns();
        let start_str = crate::sql_hygiene::format_ch_bound_micros(&time_range.start).to_string();
        let end_str = crate::sql_hygiene::format_ch_bound_micros(&time_range.end).to_string();

        // Resolve the physical columns the hop predicates reference through the
        // active schema profile (NAN-1241). Under UDM each resolves to its own name
        // (byte-identical to the previous hardcodes modulo reserved-word quoting);
        // under OCSF they resolve to the promoted columns. A field the schema does
        // not map (`udm_column_sql` → None) yields `None`, and the predicate terms
        // that depend on it are dropped so no unknown column is referenced.
        let profile = self.active_profile.as_ref();
        let cols = LateralPredicateColumns::resolve(profile);

        // NAN-1797: render the caller's deny-set once; appended to every
        // secondary hop query's WHERE below. `None` (unrestricted) emits
        // byte-identical SQL to the pre-scoping form.
        let scope_predicate = source_scope_sql_predicate(&cols.source_type, scope.deny_set());

        // Step 2: BFS hop expansion
        let mut all_edges: Vec<LateralEdge> = Vec::new();
        let mut visited_hosts: HashSet<String> = HashSet::new();
        let mut frontier_hosts: HashSet<String> = HashSet::new();
        let mut seed_user: Option<String> = None;

        // Initialize frontier based on seed type. Host/IP seeds get FQDN-
        // stripped so `src_host="WS-SALES-002.corp.local"` and
        // `src_host="WS-SALES-002"` converge on the same frontier.
        match seed_field.as_str() {
            "user" => {
                seed_user = Some(seed_value.clone());
                // For user seeds, we first find hosts the user has been on
            }
            "src_ip" | "dest_ip" => {
                frontier_hosts.insert(seed_value.to_lowercase());
            }
            _ => {
                frontier_hosts.insert(normalize_host_for_compare(&seed_value));
            }
        }

        for hop in 0..lateral_info.max_hops {
            let mut hop_edges: Vec<LateralEdge> = Vec::new();

            // Build the parameterized WHERE clause for this hop
            // For user-seeded queries, ALL hops stay user-scoped so we only trace
            // that user's activity (not unrelated traffic on the same destinations).
            // For host-seeded queries, hops expand via the BFS frontier.
            let (entity_clause, entity_binds) = if let Some(ref user) = seed_user {
                (
                    format!("lower({}) = lower(?)", cols.user),
                    vec![user.clone()],
                )
            } else if frontier_hosts.is_empty() {
                break;
            } else {
                build_host_clause(&frontier_hosts, &cols)
            };

            // Build bind values: timestamp range + entity clause binds
            let mut base_binds = vec![start_str.clone(), end_str.clone()];
            base_binds.extend(entity_binds.iter().cloned());

            // Query each method type
            if lateral_info.methods.contains(&LateralMethod::Auth) {
                let auth_where = cols.auth_where();
                let auth_sql = build_hop_sql(
                    &lateral_columns,
                    &logs_table,
                    &entity_clause,
                    &auth_where,
                    scope_predicate.as_deref(),
                );

                let events = self
                    .execute_lateral_query(clickhouse, &auth_sql, &base_binds)
                    .await?;
                for event in events {
                    if let Some(edge) = extract_edge(&event, hop, "auth") {
                        hop_edges.push(edge);
                    }
                }
            }

            if lateral_info.methods.contains(&LateralMethod::Network) {
                // For user-seeded hop 0, network connections (SMB, DCOM, etc.) are often
                // attributed to SYSTEM rather than the actual user (e.g. the kernel's System
                // process handles SMB). So we also query by src_ip from hosts already discovered
                // via auth edges in this hop.
                let network_binds;
                let network_clause;
                if seed_user.is_some() {
                    let mut discovered_ips: HashSet<String> = HashSet::new();
                    for edge in &hop_edges {
                        if !edge.src_ip.is_empty() {
                            discovered_ips.insert(edge.src_ip.to_lowercase());
                        }
                    }
                    if !discovered_ips.is_empty() {
                        let mut combined_hosts = frontier_hosts.clone();
                        combined_hosts.extend(discovered_ips);
                        let (clause, binds) = build_host_clause(&combined_hosts, &cols);
                        // Use combined clause: original user clause OR host-based clause
                        network_clause = format!("({entity_clause}) OR ({clause})");
                        let mut nb = vec![start_str.clone(), end_str.clone()];
                        nb.extend(entity_binds.iter().cloned());
                        nb.extend(binds);
                        network_binds = nb;
                    } else {
                        network_clause = entity_clause.clone();
                        network_binds = base_binds.clone();
                    }
                } else {
                    network_clause = entity_clause.clone();
                    network_binds = base_binds.clone();
                };

                // Focus on lateral movement ports: RDP (3389), SSH (22), SMB (445), WinRM (5985/5986)
                let network_where = cols.network_where();
                let network_sql = build_hop_sql(
                    &lateral_columns,
                    &logs_table,
                    &network_clause,
                    &network_where,
                    scope_predicate.as_deref(),
                );

                let events = self
                    .execute_lateral_query(clickhouse, &network_sql, &network_binds)
                    .await?;
                for event in events {
                    if let Some(edge) = extract_edge(&event, hop, "network") {
                        hop_edges.push(edge);
                    }
                }
            }

            // The schema has no `process_name` column under OCSF → no remote-exec
            // edges are derivable, so skip the process method entirely for that
            // schema (`process_where()` returns None). UDM always yields a clause.
            if lateral_info.methods.contains(&LateralMethod::Process) {
                if let Some(process_where) = cols.process_where() {
                    // Look for remote execution tools — require a destination to filter
                    // out local process executions (svchost, wermgr, etc.) that aren't
                    // lateral movement.
                    let process_sql = build_hop_sql(
                        &lateral_columns,
                        &logs_table,
                        &entity_clause,
                        &process_where,
                        scope_predicate.as_deref(),
                    );

                    let events = self
                        .execute_lateral_query(clickhouse, &process_sql, &base_binds)
                        .await?;
                    for event in events {
                        if let Some(edge) = extract_edge(&event, hop, "process") {
                            hop_edges.push(edge);
                        }
                    }
                }
            }

            if hop_edges.is_empty() {
                break;
            }

            // Extract new hosts for next hop frontier — normalize FQDN →
            // short name so mixed-source traffic (chain events in FQDN,
            // ambient events in short form) lands on the same frontier key.
            let mut new_frontier: HashSet<String> = HashSet::new();
            for edge in &hop_edges {
                let dest = normalize_host_for_compare(&edge.dest_host);
                if !dest.is_empty() && !visited_hosts.contains(&dest) {
                    new_frontier.insert(dest);
                }
                let dest_ip = edge.dest_ip.to_lowercase();
                if !dest_ip.is_empty() && !visited_hosts.contains(&dest_ip) {
                    new_frontier.insert(dest_ip);
                }
            }

            // Update visited and frontier
            visited_hosts.extend(frontier_hosts.drain());
            // For user first hop, add all discovered source hosts to visited
            if hop == 0 && seed_user.is_some() {
                for edge in &hop_edges {
                    let src = normalize_host_for_compare(&edge.src_host);
                    if !src.is_empty() {
                        visited_hosts.insert(src);
                    }
                }
            }
            frontier_hosts = new_frontier;

            all_edges.extend(hop_edges);
        }

        // Step 3: Deduplicate edges (same src->dest->method within same minute)
        all_edges.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let mut deduped_edges = dedup_edges(all_edges);

        // Step 3.5: Identity resolution — resolve dest_ip → dest_host (and src_ip → src_host)
        // for edges missing hostname information
        self.resolve_lateral_hostnames(clickhouse, &mut deduped_edges, scope)
            .await;

        // Step 4: Build output
        let total_edges = deduped_edges.len();
        let mut output: Vec<serde_json::Value> = Vec::with_capacity(total_edges + 1);

        // Count unique hosts
        let unique_host_count = {
            let mut hosts: HashSet<&str> = HashSet::new();
            for e in &deduped_edges {
                if !e.src_host.is_empty() {
                    hosts.insert(&e.src_host);
                }
                if !e.dest_host.is_empty() {
                    hosts.insert(&e.dest_host);
                }
            }
            hosts.len()
        };
        let method_names: Vec<&str> = lateral_info.methods.iter().map(|m| m.as_str()).collect();

        // Build the rich graph payload (nodes / edges / critical-path / evidence
        // / summary) consumed by the redesigned `| lateral` view (NAN-396).
        let raw_events: Vec<RawEvent> = deduped_edges
            .iter()
            .map(|e| RawEvent {
                timestamp: e.timestamp.clone(),
                user: e.user.clone(),
                src_host: e.src_host.clone(),
                dest_host: e.dest_host.clone(),
                src_ip: e.src_ip.clone(),
                dest_ip: e.dest_ip.clone(),
                dest_port: e.dest_port.clone(),
                method: e.method.clone(),
                method_detail: e.method_detail.clone(),
                process_name: e.process_name.clone(),
                auth_type: e.auth_type.clone(),
                auth_result: e.auth_result.clone(),
            })
            .collect();
        // NAN-1798 P4: the node-band risk fan-out is ClickHouse-backed — the
        // same findings source and decay/cleared config (cached provider) the
        // Risk page binds, replacing the retired PG sweep-snapshot read.
        let risk_ctx = LateralRiskContext {
            ch_client: self.ch_client.as_ref(),
            findings_source: crate::risk::clickhouse_sql::RiskFindingsSource::resolve(
                self.table_names.is_clustered(),
            )
            .with_source_scope(scope),
            config: self.risk_query_config.resolve().await,
        };
        let graph_payload =
            build_lateral_graph_payload(&raw_events, &seed_field, &seed_value, &risk_ctx).await;

        // First row is metadata
        output.push(json!({
            "_display_type": "lateral",
            "_lateral_config": {
                "seed_field": seed_field,
                "seed_value": seed_value,
                "max_hops": lateral_info.max_hops,
                "methods": method_names,
                "total_edges": total_edges,
                "unique_hosts": unique_host_count,
                "elapsed_ms": start_time.elapsed().as_millis(),
            },
            "_lateral_graph": graph_payload,
        }));

        // Remaining rows are lateral movement edges
        for edge in deduped_edges {
            output.push(json!({
                "timestamp": edge.timestamp,
                "user": edge.user,
                "src_host": edge.src_host,
                "dest_host": edge.dest_host,
                "src_ip": edge.src_ip,
                "dest_ip": edge.dest_ip,
                "src_port": edge.src_port,
                "dest_port": edge.dest_port,
                "method": edge.method,
                "method_detail": edge.method_detail,
                "hop_number": edge.hop_number,
                "process_name": edge.process_name,
                "auth_type": edge.auth_type,
                "auth_result": edge.auth_result,
                "source_type": edge.source_type,
            }));
        }

        tracing::info!(
            "Lateral movement trace completed: {} edges, {} hosts visited, took {}ms",
            total_edges,
            visited_hosts.len(),
            start_time.elapsed().as_millis()
        );

        Ok(output)
    }

    /// Detect the seed entity for lateral movement tracing
    fn detect_lateral_seed(
        &self,
        results: &[serde_json::Value],
        lateral_info: &LateralCommandInfo,
    ) -> Result<(String, String), SearchError> {
        // Distinguish "your base search returned nothing" from "results came
        // back but the seed field wasn't populated" — analysts hit this and
        // assumed it was a syntax problem.
        if results.is_empty() {
            return Err(SearchError::ParseError(
                "Lateral: your base search returned no events in this time range, so there's nothing to seed the graph from. Widen your time range or check your filter — `| lateral` extracts its seed entity from the upstream rows."
                    .into(),
            ));
        }

        // Result rows are JSONEachRow with FLAT keys = the physical column names.
        // Under OCSF those are the promoted dotted names (src_endpoint.ip, user.name),
        // not the UDM tokens (src_ip, user) we auto-detect on, so resolve each UDM
        // field to its physical result-key(s) before the lookup. resolve() alone
        // returns only the class-split PRIMARY (`src_endpoint.hostname`), which is
        // empty on endpoint/sysmon events — their host lives in the FALLBACK
        // (`device.hostname`) and their user in `actor.user.name`, so `* | lateral`
        // found no seed on OCSF endpoint data (NAN-1348). Try the class-spanning
        // UNIFIED column first (materialized coalesce of primary+fallback, present
        // in result rows), then the resolved primary, then the raw name. UDM is
        // byte-identical: no class splits, resolve() returns the same name.
        let profile = self.active_profile.as_ref();
        let lookup = |udm: &str| -> Option<String> {
            lateral_seed_keys(profile, udm)
                .iter()
                .find_map(|key| extract_field_value(results, key))
        };

        // If entity_field is specified, use it directly
        if let Some(ref field) = lateral_info.entity_field {
            if let Some(value) = lookup(field) {
                return Ok((field.clone(), value));
            }
            return Err(SearchError::ParseError(format!(
                "Lateral: no value found for entity field '{}' across {} returned events. Either none of those events populate '{}', or the field name is misspelled.",
                field,
                results.len(),
                field,
            )));
        }

        // Auto-detect based on seed_type. For Auto, prefer host/ip over user
        // — if the user's base search filtered on a host (e.g. `src_host=X`),
        // they want the graph rooted there, not on a downstream user. User
        // seeds are still reachable via `| lateral seed=user` or when no
        // host fields are populated on the initial result set.
        let fields_to_try = match lateral_info.seed_type {
            LateralSeedType::User => vec!["user", "dest_user"],
            LateralSeedType::Host => vec!["src_host", "dest_host", "src_ip", "dest_ip"],
            LateralSeedType::Auto => vec!["src_host", "dest_host", "src_ip", "dest_ip", "user"],
        };

        for &field in &fields_to_try {
            if let Some(value) = lookup(field) {
                return Ok((field.to_string(), value));
            }
        }

        Err(SearchError::ParseError(format!(
            "Lateral: {} events returned but none populate any of {:?}. Use `entity=<field>` to point at a specific column, or `seed=user` / `seed=host` to switch the auto-detect priority.",
            results.len(),
            fields_to_try,
        )))
    }

    /// Execute a ClickHouse query with bind parameters and return parsed JSON rows
    ///
    /// NAN-1429 sweep: errors propagate — the old version treated a mid-stream
    /// ClickHouse error as EOF, silently truncating the edge set and producing
    /// an incomplete movement graph with no warning.
    async fn execute_lateral_query(
        &self,
        clickhouse: &clickhouse::Client,
        sql: &str,
        bind_values: &[String],
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let mut query = clickhouse.query(sql);
        for val in bind_values {
            query = query.bind(val);
        }
        let mut cursor = query.fetch_bytes("JSONEachRow").map_err(|e| {
            tracing::warn!("Lateral query failed to start: {}", e);
            parse_clickhouse_error(&e.to_string())
        })?;

        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!("Lateral query failed mid-stream: {}", e);
                    return Err(parse_clickhouse_error(&e.to_string()));
                }
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in lateral query response: {}",
                e
            )))
        })?;
        Ok(response_str
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect())
    }

    /// Batch-resolve IP addresses to hostnames using identity_observations.
    /// Fills in empty src_host/dest_host fields where possible.
    async fn resolve_lateral_hostnames(
        &self,
        clickhouse: &clickhouse::Client,
        edges: &mut [LateralEdge],
        scope: &ScopeSet,
    ) {
        // Collect all IPs that need resolution (where hostname is empty)
        let mut ips_to_resolve: HashSet<String> = HashSet::new();
        for edge in edges.iter() {
            if edge.src_host.is_empty() && !edge.src_ip.is_empty() {
                ips_to_resolve.insert(edge.src_ip.clone());
            }
            if edge.dest_host.is_empty() && !edge.dest_ip.is_empty() {
                ips_to_resolve.insert(edge.dest_ip.clone());
            }
        }

        if ips_to_resolve.is_empty() {
            return;
        }

        // Batch query identity_observations for all IPs at once
        let ip_vec: Vec<String> = ips_to_resolve.into_iter().collect();
        let placeholders = vec!["?"; ip_vec.len()].join(",");

        let identity_table = self.table_names.read("identity_observations");
        // NAN-2009 (F24): gate the identity_observations read by the caller's
        // source-scope deny-set (see `lateral_hostname_resolution_sql`).
        let sql = lateral_hostname_resolution_sql(&identity_table, &placeholders, scope.deny_set());

        let mut ip_to_hostname: HashMap<String, String> = HashMap::new();
        // Hostname resolution is best-effort enrichment — degrade gracefully
        // on error (already logged inside execute_lateral_query).
        let rows = self
            .execute_lateral_query(clickhouse, &sql, &ip_vec)
            .await
            .unwrap_or_default();
        for row in rows {
            let ip = get_str(&row, "ip");
            let hostname = get_str(&row, "hostname");
            if !ip.is_empty() && !hostname.is_empty() {
                ip_to_hostname.insert(ip, hostname);
            }
        }

        if ip_to_hostname.is_empty() {
            return;
        }

        tracing::debug!(
            "Lateral identity resolution: resolved {} IPs to hostnames",
            ip_to_hostname.len()
        );

        // Apply resolved hostnames to edges
        for edge in edges.iter_mut() {
            if edge.src_host.is_empty() {
                if let Some(hostname) = ip_to_hostname.get(&edge.src_ip) {
                    edge.src_host = hostname.clone();
                }
            }
            if edge.dest_host.is_empty() {
                if let Some(hostname) = ip_to_hostname.get(&edge.dest_ip) {
                    edge.dest_host = hostname.clone();
                }
            }
        }
    }
}

/// Validate the closed durable operation before admission or worker execution.
pub fn validate_lake_lateral_job(query: &str) -> Result<(), SearchError> {
    if query.is_empty() || query.len() > 65_536 || query.chars().any(char::is_control) {
        return Err(SearchError::SqlValidationError("Invalid durable Lateral query".into()));
    }
    let parsed = parse_query(query).map_err(convert_parse_error)?;
    validate_query_field_names(&parsed, &crate::schema::OcsfProfile::lake_1_9())?;
    if extract_lateral_command(&parsed).is_none() || !extract_post_lateral_commands(&parsed).is_empty() {
        return Err(SearchError::SqlValidationError("Durable Lateral requires a terminal | lateral command".into()));
    }
    // Base stages that depend on Nano-side state cannot run in the isolated
    // cell. The ordinary checked SQL-only compiler owns every seed read.
    let base = match &parsed {
        crate::query::Query::Piped { source, command: crate::query::Command::Lateral { .. } } => source.as_ref(),
        _ => return Err(SearchError::SqlValidationError("Durable Lateral requires one terminal | lateral command".into())),
    };
    validate_lateral_seed_query(base)?;
    super::core_search::validate_durable_lake_sql_only_query(&base.pretty_print())?;
    Ok(())
}

// The closed seed supports ordinary SQL pipelines. Correlation/subsearch
// seeds need their own complete semantic contract before durable admission.
fn validate_lateral_seed_query(query: &crate::query::Query) -> Result<(), SearchError> {
    fn expression(expr: &crate::query::SearchExpr) -> bool {
        use crate::query::SearchExpr;
        match expr {
            SearchExpr::InSubsearch { .. } => false,
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => expression(left) && expression(right),
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => expression(inner),
            _ => true,
        }
    }
    use crate::query::{Command, Query};
    let valid = match query {
        Query::Search(expr) => expression(expr),
        Query::Piped { source, command } => {
            validate_lateral_seed_query(source)?;
            match command {
                Command::Join { .. } | Command::Append { .. } | Command::Transaction { .. }
                    | Command::Sequence { .. } | Command::Funnel { .. }
                    | Command::Asset { .. } | Command::Cloud { .. } | Command::Lateral { .. }
                    | Command::Baseline { .. } | Command::Retro { .. } | Command::Tree { .. }
                    | Command::Ai { .. } => false,
                Command::Where { condition } => expression(condition),
                _ => true,
            }
        }
    };
    if valid { Ok(()) } else {
        Err(SearchError::SqlValidationError("Durable Lateral product/correlation/subsearch seeds are not supported yet".into()))
    }
}

/// Complete traversal with the same semantic frontier, classifiers, dedup and
/// graph assembler as the progressive view. The caller supplies fenced reads
/// and point-in-time identity answers, all on its isolated job lane.
pub async fn run_lake_lateral_job<R, RF, I, IF>(
    query: &str, window: &TimeRange, scope: &ScopeSet, edge_cap: usize,
    mut read: R, mut identity: I,
) -> Result<Vec<serde_json::Value>, SearchError>
where
    R: FnMut(String, usize) -> RF,
    RF: std::future::Future<Output = Result<Vec<serde_json::Value>, SearchError>>,
    I: FnMut(Vec<(std::net::IpAddr, chrono::DateTime<chrono::Utc>)>) -> IF,
    IF: std::future::Future<Output = Result<Vec<Option<String>>, SearchError>>,
{
    validate_lake_lateral_job(query)?;
    let parsed = parse_query(query).map_err(convert_parse_error)?;
    let info = extract_lateral_command(&parsed).expect("validated Lateral command");
    let base = strip_lateral_and_after(&parsed);
    let explicit = extract_lake_lateral_identifier_from_query(&base, &info);
    let seed_rows = if explicit.is_some() { Vec::new() } else { read(base.pretty_print(), 10).await? };
    let seed = detect_lake_lateral_seed(&seed_rows, &info, explicit)?;
    let started = std::time::Instant::now();
    let (mut edges, stopped, _) = trace_lake_lateral(
        &seed, None, &info, started, None, 1_000_000, edge_cap,
        |query, _, _| read(query, 1_000_000), false, |_, _| std::future::ready(Ok(())),
    ).await?;
    debug_assert!(stopped.is_none());
    edges.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
    let mut edges = dedup_edges(edges);
    let items = lateral_identity_items(&edges);
    if !items.is_empty() {
        let answers = identity(items.clone()).await?;
        if answers.len() != items.len() {
            return Err(SearchError::SqlValidationError("Lateral identity answer changed the batch binding".into()));
        }
        apply_lateral_hostnames(&mut edges, &items, answers);
    }
    let mut rows = assemble_lake_lateral_output(edges, &seed, &info, started, None, scope,
        crate::risk::clickhouse_sql::RiskQueryConfig::default()).await;
    rows[0]["_lateral_time_range"] = json!({"start": window.start, "end": window.end});
    Ok(rows)
}

fn lateral_identity_items(edges: &[LateralEdge]) -> Vec<(std::net::IpAddr, chrono::DateTime<chrono::Utc>)> {
    let mut pending = BTreeSet::new();
    for edge in edges {
        for (host, ip) in [(&edge.src_host, &edge.src_ip), (&edge.dest_host, &edge.dest_ip)] {
            if host.is_empty() {
                if let Ok(ip) = ip.trim().parse() {
                    pending.insert((ip, parse_lateral_reference_time(&edge.timestamp)));
                }
            }
        }
    }
    pending.into_iter().collect()
}

fn apply_lateral_hostnames(
    edges: &mut [LateralEdge], items: &[(std::net::IpAddr, chrono::DateTime<chrono::Utc>)], answers: Vec<Option<String>>,
) {
    let hostnames = items.iter().copied().zip(answers).filter_map(|(item, name)| {
        name.filter(|name| !name.is_empty()).map(|name| (item, name))
    }).collect::<HashMap<_, _>>();
    for edge in edges {
        let at = parse_lateral_reference_time(&edge.timestamp);
        for (host, ip) in [(&mut edge.src_host, &edge.src_ip), (&mut edge.dest_host, &edge.dest_ip)] {
            if host.is_empty() {
                if let Some(name) = ip.trim().parse().ok().and_then(|ip| hostnames.get(&(ip, at))) {
                    *host = normalize_host_for_compare(name);
                }
            }
        }
    }
}

impl SearchService {
    pub(crate) async fn try_enqueue_durable_lateral(
        &self, request: &SearchRequest, user_id: uuid::Uuid, scope: &ScopeSet,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<Option<String>, SearchError> {
        let (query, earliest, latest) = extract_time_bounds(&request.query)?;
        let Ok(mut parsed) = parse_query(&query) else { return Ok(None); };
        let profile = self.dataset_profile(request.dataset.as_deref());
        crate::search::query_processing::apply_profile_product_semantics(&mut parsed, profile.as_ref());
        if extract_lateral_command(&parsed).is_none() { return Ok(None); }
        // NAN-3295: durable Lateral rides the same durable view lane as
        // baseline/Asset/Cloud; it is on wherever that lane exists. The env
        // var is only a kill switch now (it used to be an opt-in that the
        // shared search deployment never set, so every multi-hour Lateral
        // ended in a generic 503).
        if let Some(reason) = self.durable_lateral_unavailable_reason(durable_lateral_kill_switch_set()) {
            return Err(SearchError::ResourceExhausted(format!(
                "this Lateral window needs a background job, but {reason}; narrow the time range or reduce maxhops"
            )));
        }
        let query = parsed.pretty_print();
        validate_lake_lateral_job(&query)?;
        let now = chrono::Utc::now();
        let start = earliest.unwrap_or(request.time_range.start);
        let end = latest.unwrap_or(request.time_range.end);
        let incident = self.retention_bound_input_range(&TimeRangeInput::new(start, end), now)?.ok_or(SearchError::InvalidTimeRange)?;
        // Identity enrichment uses the same 30-day latest-before horizon as
        // the interactive reader. Admit that contribution range explicitly.
        let contribution_start = incident.start.checked_sub_signed(chrono::Duration::days(30)).ok_or(SearchError::InvalidTimeRange)?;
        let contribution = TimeRange::new(contribution_start, incident.end);
        let (pin, range) = self.durable_view_admission("durable Lateral jobs", &contribution).await?;
        let mut request = request.clone();
        request.time_range = TimeRangeInput::new(range.start, range.end);
        request.async_mode = true;
        request.use_cache = false;
        request.priority = Some("analytics".into());
        let task = crate::search::DurableLakeTask::LateralV1 {
            query, start_micros: incident.start.timestamp_micros(), end_micros: incident.end.timestamp_micros(),
        };
        let id = self.job_control().create_durable_queued(request, &task, user_id,
            crate::search::QueryPriority::Analytics, scope, &pin, authority).await
            .map_err(|error| SearchError::ServiceUnavailable(format!("Durable Lateral admission failed: {error}")))?;
        Ok(Some(id))
    }
}

/// NAN-3295: `NANO_LAKE_DURABLE_LATERAL=0` (or `false`/`off`) turns durable
/// Lateral admission off. Unset, or any other value, leaves it on.
fn durable_lateral_kill_switch_set() -> bool {
    durable_lateral_kill_switch(std::env::var("NANO_LAKE_DURABLE_LATERAL").ok().as_deref())
}

fn durable_lateral_kill_switch(value: Option<&str>) -> bool {
    value.is_some_and(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off"))
}

/// What decides whether this service has the durable view lane
/// ([`SearchService::has_durable_view_lane`]), split out so the gate and its
/// analyst-facing reason are one pure decision.
#[derive(Debug, Clone, Copy)]
struct DurableLaneFacts {
    serves_lake_cell: bool,
    has_job_runner: bool,
    retention_bound: bool,
}

/// NAN-3295: `None` when a durable Lateral job may be queued, otherwise why
/// not, worded for the analyst. No opt-in: the durable view lane is enough.
fn durable_lateral_gate(kill_switch: bool, lane: DurableLaneFacts) -> Option<&'static str> {
    if kill_switch {
        Some("durable Lateral jobs are switched off on this deployment (NANO_LAKE_DURABLE_LATERAL=0)")
    } else if !lane.serves_lake_cell {
        Some("durable Lateral jobs run only on a lean lake cell, and this search service does not serve one")
    } else if !lane.has_job_runner {
        Some("this tenant's lean cell has no hosted job runner configured")
    } else if !lane.retention_bound {
        Some("this shared tenant has no current retention identity to bind a background job to")
    } else {
        None
    }
}

impl SearchService {
    fn durable_lane_facts(&self) -> DurableLaneFacts {
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, crate::search::tenant::SearchTenantScope::Dedicated);
        DurableLaneFacts {
            serves_lake_cell: self.serves_lake_cell(),
            has_job_runner: self.has_cell_job_runner(),
            retention_bound: !shared_scope
                || self.admission_scope.require_retention_identity().is_ok(),
        }
    }

    /// Why this service cannot queue a durable Lateral job; `None` when it can.
    pub(crate) fn durable_lateral_unavailable_reason(&self, kill_switch: bool) -> Option<&'static str> {
        let reason = durable_lateral_gate(kill_switch, self.durable_lane_facts());
        debug_assert_eq!(reason.is_none(), !kill_switch && self.has_durable_view_lane());
        reason
    }
}

/// One traversal for both lanes. Read admission, retention, byte limits and
/// cancellation belong to the caller; entity/method/frontier semantics stay here.
async fn trace_lake_lateral<R, RF, P, PF>(
    seed: &LakeLateralSeed, seed_ip_bindings: Option<&str>, lateral_info: &LateralCommandInfo,
    started: std::time::Instant, wall_budget: Option<std::time::Duration>,
    event_cap: usize, edge_cap: usize, mut read: R, paint_progress: bool, mut paint: P,
) -> Result<(Vec<LateralEdge>, Option<u32>, usize), SearchError>
where
    R: FnMut(String, u32, &'static str) -> RF,
    RF: std::future::Future<Output = Result<Vec<serde_json::Value>, SearchError>>,
    P: FnMut(Vec<LateralEdge>, usize) -> PF,
    PF: std::future::Future<Output = Result<(), SearchError>>,
{
        let mut all_edges = Vec::new();
        let mut edge_bytes = 0usize;
        let edge_budget = edge_cap.saturating_mul(4096);
        let mut visited = HashSet::new();
        let mut frontier = BTreeSet::new();
        let seed_user = (seed.graph_kind == "user").then(|| seed.value.clone());
        if seed_user.is_none() {
            frontier.insert(seed.value.clone());
        }

        let mut stopped_at_hop = None;
        let mut completed_hops = 0;
        for hop in 0..lateral_info.max_hops {
            // NAN-3059: a trace answers inside the interactive gateway window
            // (60 s). Each further hop is a multi-second cell scan, so once
            // the budget is spent the graph built so far is returned, flagged
            // as time-truncated, instead of the whole request timing out.
            if hop > 0 && wall_budget.is_some_and(|budget| started.elapsed() >= budget) {
                stopped_at_hop = Some(hop);
                break;
            }
            let base_entities = if let Some(user) = seed_user.as_deref() {
                vec![lake_user_predicate(user)?]
            } else if frontier.is_empty() {
                break;
            } else {
                let mut entities = lake_host_predicates(&frontier)?;
                // NAN-3294: hop 0 of a host seed also reads the events that
                // name the host only by the IP it held at the time (network
                // and proxy telemetry carry src_endpoint.ip, no hostname).
                if hop == 0 {
                    entities.extend(seed_ip_bindings.map(str::to_string));
                }
                entities
            };
            // NAN-3059: ONE scan per hop classifies each row into the selected
            // methods in Rust. The hop used to issue a separate auth, network
            // and process scan (three sequential cell round trips over the
            // same entities; live 1h host trace: 17 s for 4 hops).
            let wants_auth = lateral_info.methods.contains(&LateralMethod::Auth);
            let wants_network = lateral_info.methods.contains(&LateralMethod::Network);
            let wants_process = lateral_info.methods.contains(&LateralMethod::Process);
            let mut method_terms = Vec::new();
            if wants_auth {
                method_terms.push(LAKE_LATERAL_AUTH_PREDICATE.to_string());
            }
            if wants_network {
                method_terms.push(LAKE_LATERAL_NETWORK_PREDICATE.to_string());
            }
            if wants_process {
                method_terms.push(lake_lateral_process_predicate());
            }
            let mut hop_edges = Vec::new();
            // NAN-3258: per-hop / per-scan timings so a slow trace says which
            // hop and which scan spent the time.
            let hop_started = std::time::Instant::now();
            let frontier_entities = if seed_user.is_some() { 1 } else { frontier.len() };
            let (mut combined_ms, mut combined_rows) = (0u128, 0usize);
            let (mut network_ms, mut network_rows, mut network_entities) = (0u128, 0usize, 0usize);
            if !method_terms.is_empty() {
                let combined = format!("({})", method_terms.join(" OR "));
                let scan_started = std::time::Instant::now();
                let rows = read_lateral_frontier(
                        &base_entities,
                        &combined,
                        hop,
                        "combined", &mut read, event_cap,
                    )
                    .await?;
                combined_ms = scan_started.elapsed().as_millis();
                combined_rows = rows.len();
                for row in &rows {
                    let projected = lake_lateral_projection_row(row);
                    if wants_auth && lake_lateral_is_auth(row) {
                        retain_lateral_edge(&mut hop_edges, extract_edge(&projected, hop, "auth"), &mut edge_bytes, edge_budget)?;
                    }
                    if wants_network && lake_lateral_is_network(row) {
                        retain_lateral_edge(&mut hop_edges, extract_edge(&projected, hop, "network"), &mut edge_bytes, edge_budget)?;
                    }
                    if wants_process && lake_lateral_is_process(row) {
                        retain_lateral_edge(&mut hop_edges, extract_edge(&projected, hop, "process"), &mut edge_bytes, edge_budget)?;
                    }
                }
            }

            if wants_network {
                // Network telemetry is often attributed to SYSTEM rather than
                // the user that caused it. Once auth evidence exposes hosts,
                // include those endpoints in the same hop's network scan. Only
                // the endpoints the combined scan did not already cover need
                // a second (network-only) scan.
                let covered = frontier
                    .iter()
                    .map(|value| normalize_host_for_compare(value))
                    .collect::<HashSet<_>>();
                let mut extension = BTreeSet::new();
                for edge in hop_edges.iter().filter(|edge| edge.method == "auth") {
                    for value in [&edge.src_host, &edge.src_ip, &edge.dest_host, &edge.dest_ip] {
                        if !value.is_empty()
                            && !covered.contains(&normalize_host_for_compare(value))
                        {
                            extension.insert(value.clone());
                        }
                    }
                }
                if !extension.is_empty() {
                    let entities = lake_host_predicates(&extension)?;
                    network_entities = extension.len();
                    let scan_started = std::time::Instant::now();
                    let rows = read_lateral_frontier(
                            &entities,
                            LAKE_LATERAL_NETWORK_PREDICATE,
                            hop,
                            "network", &mut read, event_cap,
                        )
                        .await?;
                    network_ms = scan_started.elapsed().as_millis();
                    network_rows = rows.len();
                    for row in &rows {
                        retain_lateral_edge(&mut hop_edges, extract_edge(&lake_lateral_projection_row(row), hop, "network"), &mut edge_bytes, edge_budget)?;
                    }
                }
            }
            tracing::info!(
                hop,
                frontier_entities,
                combined_ms,
                combined_rows,
                network_extension_entities = network_entities,
                network_ms,
                network_rows,
                hop_edges = hop_edges.len(),
                hop_ms = hop_started.elapsed().as_millis(),
                total_ms = started.elapsed().as_millis(),
                "lake lateral hop timing"
            );

            completed_hops = (hop + 1) as usize;
            if hop_edges.is_empty() {
                break;
            }

            let mut next = BTreeSet::new();
            for edge in &hop_edges {
                for destination in [&edge.dest_host, &edge.dest_ip] {
                    let normalized = normalize_host_for_compare(destination);
                    // NAN-3295: an internet address stays in the graph as a
                    // leaf but is never expanded: its "next hop" is every
                    // other internal host that reached the same address,
                    // which is fan-in, not lateral movement. A busy
                    // workstation's 445/3389/5985 scan noise put ~2k public
                    // IPs/h into hop 1 (23 sequential 256-entity reads).
                    if is_external_ip_literal(destination) {
                        continue;
                    }
                    if !normalized.is_empty() && !visited.contains(&normalized) {
                        next.insert(destination.clone());
                    }
                }
            }
            for current in &frontier {
                visited.insert(normalize_host_for_compare(current));
            }
            frontier = next;
            if all_edges.len().saturating_add(hop_edges.len()) > edge_cap {
                return Err(SearchError::ResourceExhausted("Lateral trace exceeded its complete edge envelope".into()));
            }
            all_edges.extend(hop_edges);
            if paint_progress {
                paint(all_edges.clone(), (hop + 1) as usize).await?;
            }
        }

        Ok((all_edges, stopped_at_hop, completed_hops))
}

fn retain_lateral_edge(edges: &mut Vec<LateralEdge>, edge: Option<LateralEdge>, bytes: &mut usize, budget: usize) -> Result<(), SearchError> {
    if let Some(edge) = edge {
        let strings = [&edge.timestamp, &edge.user, &edge.src_host, &edge.dest_host, &edge.src_ip, &edge.dest_ip,
            &edge.src_port, &edge.dest_port, &edge.method, &edge.method_detail, &edge.process_name,
            &edge.auth_type, &edge.auth_result, &edge.source_type].iter().map(|value| value.capacity()).sum::<usize>();
        *bytes = bytes.saturating_add(4096usize.saturating_add(strings.saturating_mul(4)));
        if *bytes > budget {
            return Err(SearchError::ResourceExhausted("Lateral trace exceeded its complete heap envelope".into()));
        }
        edges.push(edge);
    }
    Ok(())
}

async fn read_lateral_frontier<R, RF>(
    entities: &[String], predicate: &str, hop: u32, method: &'static str,
    read: &mut R, cap: usize,
) -> Result<Vec<serde_json::Value>, SearchError>
where
    R: FnMut(String, u32, &'static str) -> RF,
    RF: std::future::Future<Output = Result<Vec<serde_json::Value>, SearchError>>,
{
    let mut rows = Vec::new();
    for entity in entities {
        let mut chunk = read(lake_lateral_hop_query(entity, predicate), hop, method).await?;
        chunk.iter_mut().for_each(restore_lake_lateral_carried_fields);
        if rows.len().saturating_add(chunk.len()) > cap {
            return Err(SearchError::ResourceExhausted(format!("Lateral {method} hop {hop} exceeded its complete event envelope")));
        }
        rows.append(&mut chunk);
    }
    Ok(rows)
}

/// NAN-3295: every field that decides an edge's dedup key
/// (`src | dest | method | method_detail | minute`, see [`dedup_edges`]), its
/// method classification, its user or its auth result. A hop read groups
/// on these plus the event minute, so it returns one row per distinct
/// per-minute edge instead of every repeated event.
const LAKE_LATERAL_GROUP_FIELDS: &[&str] = &[
    "src_endpoint.hostname",
    "device.hostname",
    "dst_endpoint.hostname",
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "dst_endpoint.port",
    "auth_protocol",
    "process.name",
    "class_uid",
    "activity_name",
    "user.name",
    "actor.user.name",
    "status",
];

/// Display-only fields, carried from one event of the group (`first()`
/// lowers to ClickHouse `any()`, so not necessarily the earliest; none of
/// these feed the edge dedup key or classification). `(field, stats alias)`:
/// stats aliases cannot be dotted paths, so the rows are renamed back by
/// [`restore_lake_lateral_carried_fields`].
const LAKE_LATERAL_CARRIED_FIELDS: &[(&str, &str)] = &[
    ("metadata.log_source", "lateral_log_source"),
    ("src_endpoint.port", "lateral_src_port"),
    ("connection_info.protocol_num", "lateral_protocol_num"),
    ("process.file.path", "lateral_process_path"),
    ("category_name", "lateral_category_name"),
];

/// One hop read. The traversal keeps the earliest edge per
/// `(src, dest, method, detail, minute)`; grouping on a superset of that key
/// per minute and keeping `min(time)` returns, for every key, the group that
/// holds its earliest event, so the deduplicated edges (and the graph) are
/// the same as from the raw rows. Live (NAN-3295, ws-it-083, 4 h): 32k raw
/// rows become ~7k groups, nearly all of them distinct public-IP scans.
fn lake_lateral_hop_query(entity: &str, predicate: &str) -> String {
    let carried = LAKE_LATERAL_CARRIED_FIELDS
        .iter()
        .map(|(field, alias)| format!(", first({field}) as {alias}"))
        .collect::<String>();
    format!(
        "({entity}) AND ({predicate}) | bin time span=1m as lateral_minute | stats min(time) as time{carried} by lateral_minute, {} | sort time",
        LAKE_LATERAL_GROUP_FIELDS.join(", ")
    )
}

fn restore_lake_lateral_carried_fields(row: &mut serde_json::Value) {
    if let Some(object) = row.as_object_mut() {
        object.remove("lateral_minute");
        for (field, alias) in LAKE_LATERAL_CARRIED_FIELDS {
            if let Some(value) = object.remove(*alias) {
                object.insert((*field).to_string(), value);
            }
        }
    }
}

/// An IP literal outside private, shared (CGNAT), loopback, link-local and
/// unique-local space. Hostnames are never external here.
fn is_external_ip_literal(value: &str) -> bool {
    match value.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            let [a, b, ..] = ip.octets();
            !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
                || ip.is_broadcast() || (a == 100 && (64..128).contains(&b)))
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            let first = ip.segments()[0];
            !(ip.is_loopback() || ip.is_unspecified() || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some_and(|v4| !is_external_ip_literal(&v4.to_string())))
        }
        Err(_) => false,
    }
}

async fn assemble_lake_lateral_output(
    edges: Vec<LateralEdge>, seed: &LakeLateralSeed, lateral_info: &LateralCommandInfo,
    started: std::time::Instant, stopped_at_hop: Option<u32>, scope: &ScopeSet,
    config: crate::risk::clickhouse_sql::RiskQueryConfig,
) -> Vec<serde_json::Value> {
        let total_edges = edges.len();
        let unique_hosts = edges
            .iter()
            .flat_map(|edge| [&edge.src_host, &edge.dest_host])
            .filter(|host| !host.is_empty())
            .collect::<HashSet<_>>()
            .len();
        let raw_events = edges
            .iter()
            .map(|edge| RawEvent {
                timestamp: edge.timestamp.clone(),
                user: edge.user.clone(),
                src_host: edge.src_host.clone(),
                dest_host: edge.dest_host.clone(),
                src_ip: edge.src_ip.clone(),
                dest_ip: edge.dest_ip.clone(),
                dest_port: edge.dest_port.clone(),
                method: edge.method.clone(),
                method_detail: edge.method_detail.clone(),
                process_name: edge.process_name.clone(),
                auth_type: edge.auth_type.clone(),
                auth_result: edge.auth_result.clone(),
            })
            .collect::<Vec<_>>();
        let risk_context = LateralRiskContext {
            ch_client: None,
            findings_source: crate::risk::clickhouse_sql::RiskFindingsSource::resolve(false)
                .with_source_scope(scope),
            config,
        };
        let graph =
            build_lateral_graph_payload(&raw_events, seed.graph_kind, &seed.value, &risk_context)
                .await;
        let method_names = lateral_info
            .methods
            .iter()
            .map(LateralMethod::as_str)
            .collect::<Vec<_>>();

        let mut output = Vec::with_capacity(total_edges + 1);
        output.push(json!({
            "_display_type": "lateral",
            "_lateral_config": {
                "seed_field": seed.field,
                "seed_value": seed.value,
                "max_hops": lateral_info.max_hops,
                "methods": method_names,
                "total_edges": total_edges,
                "unique_hosts": unique_hosts,
                "elapsed_ms": started.elapsed().as_millis(),
                "time_truncated_at_hop": stopped_at_hop,
                "storage_model": "ocsf-1.9-iceberg",
            },
            "_lateral_graph": graph,
        }));
        for edge in edges {
            // This is the existing lateral-view DTO consumed by the graph UI,
            // not a raw event or a query-facing field alias.
            output.push(json!({
                "timestamp": edge.timestamp,
                "user": edge.user,
                "src_host": edge.src_host,
                "dest_host": edge.dest_host,
                "src_ip": edge.src_ip,
                "dest_ip": edge.dest_ip,
                "src_port": edge.src_port,
                "dest_port": edge.dest_port,
                "method": edge.method,
                "method_detail": edge.method_detail,
                "hop_number": edge.hop_number,
                "process_name": edge.process_name,
                "auth_type": edge.auth_type,
                "auth_result": edge.auth_result,
                "log_source": edge.source_type,
            }));
        }
        output
}

fn detect_lake_lateral_seed(
    rows: &[serde_json::Value],
    info: &LateralCommandInfo,
    explicit_seed: Option<(String, String)>,
) -> Result<LakeLateralSeed, SearchError> {
    if let Some((field, value)) = explicit_seed {
        return Ok(LakeLateralSeed {
            graph_kind: if field == "user.name" || field == "actor.user.name" {
                "user"
            } else {
                "host"
            },
            field,
            value,
        });
    }
    if rows.is_empty() {
        return Err(SearchError::ParseError(
            "Lateral: the canonical OCSF base search returned no events in this time range"
                .to_string(),
        ));
    }
    if let Some(field) = info.entity_field.as_deref() {
        let value = rows
            .iter()
            .find_map(|row| lake_value_string(row, field))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                SearchError::ParseError(format!(
                    "Lateral: no value found for canonical entity field {field:?}"
                ))
            })?;
        return Ok(LakeLateralSeed {
            field: field.to_string(),
            graph_kind: if field == "user.name" || field == "actor.user.name" {
                "user"
            } else {
                "host"
            },
            value,
        });
    }

    const USERS: &[&str] = &["user.name", "actor.user.name"];
    const HOSTS: &[&str] = &[
        "src_endpoint.hostname",
        "device.hostname",
        "dst_endpoint.hostname",
        "src_endpoint.ip",
        "dst_endpoint.ip",
    ];
    let candidates: &[&str] = match info.seed_type {
        LateralSeedType::User => USERS,
        LateralSeedType::Host => HOSTS,
        LateralSeedType::Auto => &[
            "src_endpoint.hostname",
            "device.hostname",
            "dst_endpoint.hostname",
            "src_endpoint.ip",
            "dst_endpoint.ip",
            "user.name",
            "actor.user.name",
        ],
    };
    for field in candidates {
        if let Some(value) = rows
            .iter()
            .find_map(|row| lake_value_string(row, field))
            .filter(|value| !value.is_empty())
        {
            return Ok(LakeLateralSeed {
                field: (*field).to_string(),
                graph_kind: if USERS.contains(field) {
                    "user"
                } else {
                    "host"
                },
                value,
            });
        }
    }
    Err(SearchError::ParseError(format!(
        "Lateral: {} OCSF events returned, but none contained a usable canonical user, host, or IP entity",
        rows.len()
    )))
}

fn lake_user_predicate(user: &str) -> Result<String, SearchError> {
    let value = lake_lateral_literal(user)?;
    Ok(format!("(user.name={value} OR actor.user.name={value})"))
}

fn lake_host_predicate(hosts: &BTreeSet<String>) -> Result<String, SearchError> {
    if hosts.is_empty() {
        return Ok("class_uid=-1".to_string());
    }
    if hosts.len() > MAX_LAKE_FRONTIER_ENTITIES {
        return Err(SearchError::SqlValidationError(format!(
            "lateral expansion exceeded the {MAX_LAKE_FRONTIER_ENTITIES}-entity interactive frontier; a durable lateral job is required"
        )));
    }
    let mut ips = Vec::new();
    let mut host_patterns = BTreeSet::new();
    for host in hosts {
        lake_lateral_literal(host)?;
        if host.parse::<std::net::IpAddr>().is_ok() {
            ips.push(crate::query::npl_quoted_literal(host));
            continue;
        }
        let short = normalize_host_for_compare(host);
        lake_lateral_literal(&short)?;
        host_patterns.insert(regex::escape(&short).replace('/', "\\/"));
    }

    // A frontier may contain hundreds of entities. Expanding nine OR terms per host
    // creates a left-deep AST that exceeds ClickHouse's parser-depth limit even
    // though the query itself is bounded. Keep the same short-host/FQDN
    // semantics in one case-insensitive regex per hostname field, and one IN
    // predicate per IP field. This makes parser depth constant as the graph
    // frontier grows.
    let mut terms = Vec::new();
    if !ips.is_empty() {
        let values = ips.join(",");
        terms.push(format!("src_endpoint.ip IN ({values})"));
        terms.push(format!("dst_endpoint.ip IN ({values})"));
    }
    if !host_patterns.is_empty() {
        let pattern = format!(
            "(?i)^(?:{})(?:\\..*)?$",
            host_patterns.into_iter().collect::<Vec<_>>().join("|")
        );
        for field in [
            "src_endpoint.hostname",
            "dst_endpoint.hostname",
            "device.hostname",
        ] {
            terms.push(format!("{field}=/{pattern}/"));
        }
    }
    Ok(format!("({})", terms.join(" OR ")))
}

fn lake_host_predicates(hosts: &BTreeSet<String>) -> Result<Vec<String>, SearchError> {
    if hosts.is_empty() {
        return Ok(vec![lake_host_predicate(hosts)?]);
    }
    hosts
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .chunks(MAX_LAKE_FRONTIER_ENTITIES)
        .map(|chunk| lake_host_predicate(&chunk.iter().cloned().collect()))
        .collect()
}

fn lake_lateral_literal(value: &str) -> Result<String, SearchError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(SearchError::SqlValidationError(
            "lateral entity value is empty, too long, or contains control characters".to_string(),
        ));
    }
    if value.contains('"') && value.contains('\'') {
        return Err(SearchError::SqlValidationError(
            "lateral entity value contains both nPL quote delimiters".to_string(),
        ));
    }
    Ok(crate::query::npl_quoted_literal(value))
}

/// Wall-clock budget after which a lean lateral trace stops expanding hops
/// (NAN-3059). One more hop may still run, so this stays well below the 60 s
/// gateway timeout.
const LAKE_LATERAL_WALL_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

const LAKE_LATERAL_AUTH_PREDICATE: &str =
    "(class_uid=3002 OR activity_name=\"Logon\" OR auth_protocol!=\"\")";
const LAKE_LATERAL_NETWORK_PORTS: &[u64] = &[22, 135, 139, 445, 3389, 5985, 5986];
const LAKE_LATERAL_NETWORK_PREDICATE: &str =
    "dst_endpoint.port IN (22,135,139,445,3389,5985,5986)";
const LAKE_LATERAL_PROCESS_TOOLS: &[&str] = &[
    "psexe", "wmic", "winrs", "powershell", "pwsh", "mstsc", "ssh", "schtasks", "sc.exe",
];

fn lake_lateral_process_predicate() -> String {
    format!(
        "({})",
        LAKE_LATERAL_PROCESS_TOOLS
            .iter()
            .map(|tool| format!("process.name CONTAINS {}", crate::query::npl_quoted_literal(tool)))
            .collect::<Vec<_>>()
            .join(" OR ")
    )
}

/// Row-side twins of the three method predicates (case-insensitive like the
/// nPL comparisons they mirror), so one combined scan per hop can be split
/// back into auth / network / process evidence.
fn lake_lateral_is_auth(row: &serde_json::Value) -> bool {
    lake_value(row, "class_uid").and_then(serde_json::Value::as_u64) == Some(3002)
        || lake_value_string(row, "activity_name").is_some_and(|v| v.eq_ignore_ascii_case("logon"))
        || lake_value_string(row, "auth_protocol").is_some_and(|v| !v.is_empty())
}

fn lake_lateral_is_network(row: &serde_json::Value) -> bool {
    lake_value(row, "dst_endpoint.port")
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.trim().parse().ok()))
        .is_some_and(|port| LAKE_LATERAL_NETWORK_PORTS.contains(&port))
}

fn lake_lateral_is_process(row: &serde_json::Value) -> bool {
    lake_value_string(row, "process.name").is_some_and(|name| {
        let name = name.to_ascii_lowercase();
        LAKE_LATERAL_PROCESS_TOOLS.iter().any(|tool| name.contains(tool))
    })
}

#[cfg(test)]
fn format_lake_lateral_query(entity: &str, method: &str) -> String {
    format!("{} | head {LAKE_MAX_ROWS_PER_HOP_SENTINEL}", lake_lateral_hop_query(entity, method))
}

fn lake_value<'a>(row: &'a serde_json::Value, field: &str) -> Option<&'a serde_json::Value> {
    if let Some(value) = row.get(field) {
        return Some(value);
    }
    let mut value = row;
    for segment in field.split('.') {
        value = value.get(segment)?;
    }
    Some(value)
}

fn lake_value_string(row: &serde_json::Value, field: &str) -> Option<String> {
    match lake_value(row, field)? {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn first_lake_value(row: &serde_json::Value, fields: &[&str]) -> String {
    fields
        .iter()
        .find_map(|field| lake_value_string(row, field))
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
}

fn lake_lateral_projection_row(row: &serde_json::Value) -> serde_json::Value {
    json!({
        "timestamp": first_lake_value(row, &["time"]),
        "source_type": first_lake_value(row, &["metadata.log_source"]),
        "user": first_lake_value(row, &["user.name", "actor.user.name"]),
        "src_host": first_lake_value(row, &["src_endpoint.hostname", "device.hostname"]),
        "dest_host": first_lake_value(row, &["dst_endpoint.hostname"]),
        "src_ip": first_lake_value(row, &["src_endpoint.ip"]),
        "dest_ip": first_lake_value(row, &["dst_endpoint.ip"]),
        "src_port": first_lake_value(row, &["src_endpoint.port"]),
        "dest_port": first_lake_value(row, &["dst_endpoint.port"]),
        "protocol": first_lake_value(row, &["connection_info.protocol_num"]),
        "auth_type": first_lake_value(row, &["auth_protocol"]),
        "auth_result": first_lake_value(row, &["status"]),
        "process_name": first_lake_value(row, &["process.name"]),
        "process_path": first_lake_value(row, &["process.file.path"]),
        "action": first_lake_value(row, &["activity_name"]),
        "category": first_lake_value(row, &["category_name"]),
    })
}

fn parse_lateral_reference_time(value: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|value| value.and_utc())
        })
        .unwrap_or_else(chrono::Utc::now)
}

/// A single lateral movement edge (connection from one host to another)
#[derive(Debug, Clone)]
struct LateralEdge {
    timestamp: String,
    user: String,
    src_host: String,
    dest_host: String,
    src_ip: String,
    dest_ip: String,
    src_port: String,
    dest_port: String,
    method: String,        // "auth", "network", "process"
    method_detail: String, // e.g., "rdp", "ssh", "psexec", "smb"
    hop_number: u32,
    process_name: String,
    auth_type: String,
    auth_result: String,
    source_type: String,
}

/// Extract a lateral movement edge from a ClickHouse event row
fn extract_edge(event: &serde_json::Value, hop: u32, method: &str) -> Option<LateralEdge> {
    // Strip FQDN suffix at intake so BFS frontier + graph-aggregator node
    // collapse stay consistent. Matches the old frontend `normalizeHostname`.
    let src_host = normalize_host_for_compare(&get_str(event, "src_host"));
    let dest_host = normalize_host_for_compare(&get_str(event, "dest_host"));
    let src_ip = get_str(event, "src_ip");
    let dest_ip = get_str(event, "dest_ip");

    // Skip localhost sources — e.g. Kerberos TGT requests logged with src_ip=::1
    // on the DC itself. These are local operations, not lateral movement.
    if is_localhost(&src_ip) || is_localhost(&dest_ip) {
        return None;
    }

    // Must have both a source AND destination to form a lateral movement edge.
    // Events with only a source (local activity) are not lateral movement.
    let has_src = !src_host.is_empty() || !src_ip.is_empty();
    let has_dest = !dest_host.is_empty() || !dest_ip.is_empty();
    if !has_src || !has_dest {
        return None;
    }

    // Skip edges where source and destination are the same host (local activity, not lateral)
    let src_key = if !src_host.is_empty() {
        &src_host
    } else {
        &src_ip
    };
    let dest_key = if !dest_host.is_empty() {
        &dest_host
    } else {
        &dest_ip
    };
    if src_key.eq_ignore_ascii_case(dest_key) {
        return None;
    }

    let dest_port = get_str(event, "dest_port");
    let process_name = get_str(event, "process_name");
    let auth_type = get_str(event, "auth_type");

    // Determine method detail
    let method_detail = match method {
        "auth" => {
            if !auth_type.is_empty() {
                auth_type.to_lowercase()
            } else if dest_port == "3389" {
                "rdp".to_string()
            } else if dest_port == "22" {
                "ssh".to_string()
            } else {
                "logon".to_string()
            }
        }
        "network" => match dest_port.as_str() {
            "3389" => "rdp".to_string(),
            "22" => "ssh".to_string(),
            "445" | "139" => "smb".to_string(),
            "5985" | "5986" => "winrm".to_string(),
            "135" => "dcom".to_string(),
            _ => format!("port:{}", dest_port),
        },
        "process" => {
            let pname = process_name.to_lowercase();
            if pname.contains("psexe") {
                "psexec".to_string()
            } else if pname.contains("wmic") {
                "wmic".to_string()
            } else if pname.contains("winrs") {
                "winrs".to_string()
            } else if pname.contains("powershell") || pname.contains("pwsh") {
                "powershell_remoting".to_string()
            } else if pname.contains("mstsc") {
                "rdp".to_string()
            } else if pname.contains("ssh") {
                "ssh".to_string()
            } else if pname.contains("schtasks") {
                "scheduled_task".to_string()
            } else if pname.contains("sc.exe") {
                "service_creation".to_string()
            } else {
                process_name.clone()
            }
        }
        _ => method.to_string(),
    };

    Some(LateralEdge {
        timestamp: get_str(event, "timestamp"),
        user: get_str(event, "user"),
        src_host,
        dest_host,
        src_ip,
        dest_ip,
        src_port: get_str(event, "src_port"),
        dest_port,
        method: method.to_string(),
        method_detail,
        hop_number: hop,
        process_name,
        auth_type,
        auth_result: get_str(event, "auth_result"),
        source_type: get_str(event, "source_type"),
    })
}

/// Deduplicate edges: keep one edge per (src, dest, method, minute) combination
fn dedup_edges(edges: Vec<LateralEdge>) -> Vec<LateralEdge> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut result: Vec<LateralEdge> = Vec::new();

    for edge in edges {
        // Truncate timestamp to minute for dedup
        let ts_minute = if edge.timestamp.len() >= 16 {
            &edge.timestamp[..16]
        } else {
            &edge.timestamp
        };
        // Use hostname if available, fall back to IP for dedup key. FQDN
        // gets stripped so chain events (`ws-sales-002.corp.local`) and
        // ambient events (`ws-sales-002`) dedupe against each other.
        let src = if !edge.src_host.is_empty() {
            normalize_host_for_compare(&edge.src_host)
        } else {
            edge.src_ip.to_lowercase()
        };
        let dest = if !edge.dest_host.is_empty() {
            normalize_host_for_compare(&edge.dest_host)
        } else {
            edge.dest_ip.to_lowercase()
        };
        let key = format!(
            "{}|{}|{}|{}|{}",
            src, dest, edge.method, edge.method_detail, ts_minute
        );
        if seen.insert(key) {
            result.push(edge);
        }
    }
    result
}

/// Physical columns the hop predicates reference, resolved through the active
/// schema profile (NAN-1241). Built once per `| lateral` invocation by
/// [`LateralPredicateColumns::resolve`]. For the UDM profile each field resolves
/// to its own name (e.g. `user` → `"user"`), so the predicate SQL is byte-equivalent
/// to the previous hardcodes (modulo the seam's uniform reserved-word quoting);
/// under OCSF they resolve to the promoted columns. Fields the schema does not map
/// are `None`, and the predicate terms that depend on them are dropped.
struct LateralPredicateColumns {
    /// Active schema identity — gates value-semantics that differ between UDM and
    /// OCSF (e.g. auth columns are STRINGs under UDM but INTs under OCSF, so the
    /// `!= ''` predicate is a ClickHouse type error against OCSF). NAN-1241.
    schema_id: crate::schema::SchemaId,
    user: String,
    src_host: String,
    dest_host: String,
    src_ip: String,
    dest_ip: String,
    dest_port: String,
    auth_type: Option<String>,
    auth_result: Option<String>,
    action: Option<String>,
    source_type: String,
    process_name: Option<String>,
}

impl LateralPredicateColumns {
    fn resolve(profile: &dyn crate::schema::SchemaProfile) -> Self {
        // Entity/dedup columns always have a physical home in both schemas; fall
        // back to the literal name if a schema unexpectedly omits one so the query
        // still parses (rather than producing malformed SQL).
        let req = |udm: &str| -> String {
            profile
                .udm_column_sql(udm)
                .unwrap_or_else(|| udm.to_string())
        };
        LateralPredicateColumns {
            schema_id: profile.id(),
            user: req("user"),
            src_host: req("src_host"),
            dest_host: req("dest_host"),
            src_ip: req("src_ip"),
            dest_ip: req("dest_ip"),
            dest_port: req("dest_port"),
            // Optional predicate axes — dropped from the WHERE when unmapped.
            auth_type: profile.udm_column_sql("auth_type"),
            auth_result: profile.udm_column_sql("auth_result"),
            action: profile.udm_column_sql("action"),
            // NAN-1887: `source_type` is consumed ONLY by string ops against the
            // OPERATIONAL provenance/routing column — the auth predicate's
            // `lower(source_type) LIKE '%auth%'` and the per-source RBAC deny-set
            // gate's `lower(source_type) NOT IN (…)` (`resolve()` at line 124). It
            // must therefore resolve via the profile's field resolution
            // (`column_sql` → `resolve()`), NOT `udm_column_sql` (the UDM→OCSF
            // *taxonomy* map). Under OCSF the taxonomy map sends the UDM `source_type`
            // concept to `class_uid` (a `UInt32`), and `lower(class_uid)` is a
            // ClickHouse type error (Code 43, Illegal type UInt32 of argument of
            // function lower) — it broke every `| lateral` run on OCSF, and (latently)
            // the RBAC gate for any per-source-scoped caller. `resolve("source_type")`
            // returns the operational String `source_type` column under both UDM and
            // OCSF; for UDM this is byte-identical to `req` (the default
            // `udm_column_sql` IS `column_sql`).
            source_type: profile.column_sql("source_type"),
            process_name: profile.udm_column_sql("process_name"),
        }
    }

    /// WHERE body identifying authentication-style events for a hop.
    ///
    /// VALUE-SEMANTICS SPLIT (NAN-1241): under UDM, `auth_type`/`auth_result`
    /// resolve to STRING columns and "this is an auth event" is `col != ''`. Under
    /// OCSF those same UDM-semantic names resolve to INT taxonomy columns
    /// (`auth_protocol_id`, `status_id`, both `UInt32`), so `col != ''` is a
    /// ClickHouse type error (500) and yields zero auth edges. OCSF instead
    /// detects an auth event via the IAM category taxonomy (`category_uid = 3`,
    /// the shared `auth_predicate`) ORed with non-zero auth ints — never an
    /// `int != ''` comparison and never `lower()`/string ops on an int column.
    ///
    /// UDM output is byte-identical to the legacy predicate; terms whose column is
    /// unmapped are dropped (always leaves at least the source_type term).
    fn auth_where(&self) -> String {
        match self.schema_id {
            crate::schema::SchemaId::Ocsf => self.auth_where_ocsf(),
            crate::schema::SchemaId::Udm
            | crate::schema::SchemaId::Spans
            | crate::schema::SchemaId::Metrics
            | crate::schema::SchemaId::Risk => self.auth_where_udm(),
        }
    }

    /// UDM auth predicate — STRING columns, byte-identical to the legacy hardcode.
    fn auth_where_udm(&self) -> String {
        let mut terms: Vec<String> = Vec::new();
        if let Some(ref c) = self.auth_type {
            terms.push(format!("{c} != ''"));
        }
        if let Some(ref c) = self.auth_result {
            terms.push(format!("{c} != ''"));
        }
        if let Some(ref c) = self.action {
            terms.push(format!("position(lower({c}), 'login') > 0"));
            terms.push(format!("position(lower({c}), 'logon') > 0"));
        }
        terms.push(format!("lower({}) LIKE '%auth%'", self.source_type));
        terms.join(" OR ")
    }

    /// OCSF auth predicate — INT taxonomy columns, no string ops on the ints.
    fn auth_where_ocsf(&self) -> String {
        let mut terms: Vec<String> = Vec::new();
        // Primary signal: IAM category (`category_uid = 3`), the canonical OCSF
        // "this is an auth/identity event" flag — reuse the classification
        // module's existing `OCSF_AUTH_PREDICATE` so the two stay in lockstep.
        terms.push(crate::search::classification::OCSF_AUTH_PREDICATE.to_string());
        // Secondary: a populated auth protocol / outcome. These columns are INTs
        // under OCSF (auth_protocol_id, status_id) — compare to the int 0 sentinel,
        // never the empty string and never wrapped in lower().
        if let Some(ref c) = self.auth_type {
            terms.push(format!("{c} != 0"));
        }
        if let Some(ref c) = self.auth_result {
            terms.push(format!("{c} != 0"));
        }
        // NAN-1887: `self.source_type` is the OPERATIONAL String column under OCSF
        // (`resolve("source_type")`, LowCardinality(String)) — NOT the taxonomy
        // `class_uid`. The case-insensitive LIKE is a valid secondary signal (some
        // producers name the source `*_auth`); the primary recall is `category_uid = 3`.
        terms.push(format!("lower({}) LIKE '%auth%'", self.source_type));
        terms.join(" OR ")
    }

    /// WHERE body identifying network/lateral-port events for a hop. Mirrors the
    /// legacy UDM predicate; the `action` connection term is dropped when unmapped.
    fn network_where(&self) -> String {
        let mut port_or_action = format!(
            "{dest_port} IN (22, 445, 3389, 5985, 5986, 135, 139)",
            dest_port = self.dest_port
        );
        if let Some(ref c) = self.action {
            port_or_action.push_str(&format!(" OR position(lower({c}), 'connection') > 0"));
        }
        format!(
            "{dest_ip} != '' AND {dest_ip} != {src_ip} AND ({port_or_action})",
            dest_ip = self.dest_ip,
            src_ip = self.src_ip,
        )
    }

    /// WHERE body identifying remote-execution process events for a hop. Returns
    /// `None` when the schema has no `process_name` column (no edges derivable).
    fn process_where(&self) -> Option<String> {
        let process_name = self.process_name.as_ref()?;
        let mut tool_terms = vec![
            format!("position(lower({process_name}), 'psexe') > 0"),
            format!("position(lower({process_name}), 'wmic') > 0"),
            format!("position(lower({process_name}), 'winrs') > 0"),
            format!("position(lower({process_name}), 'powershell') > 0"),
            format!("position(lower({process_name}), 'pwsh') > 0"),
            format!("position(lower({process_name}), 'mstsc') > 0"),
            format!("position(lower({process_name}), 'ssh') > 0"),
            format!("position(lower({process_name}), 'schtasks') > 0"),
            format!("position(lower({process_name}), 'sc.exe') > 0"),
        ];
        if let Some(ref c) = self.action {
            tool_terms.push(format!("position(lower({c}), 'service') > 0"));
        }
        Some(format!(
            "{process_name} != '' \
             AND ({dest_ip} != '' OR {dest_host} != '') \
             AND ({tools})",
            dest_ip = self.dest_ip,
            dest_host = self.dest_host,
            tools = tool_terms.join(" OR "),
        ))
    }
}

/// Build a parameterized ClickHouse WHERE clause matching any of the given hosts.
/// Returns (sql_fragment with ? placeholders, bind values).
/// Each IN clause gets its own set of placeholders since ClickHouse binds are positional.
fn build_host_clause(
    hosts: &HashSet<String>,
    cols: &LateralPredicateColumns,
) -> (String, Vec<String>) {
    if hosts.is_empty() {
        return ("1=0".to_string(), vec![]);
    }

    // Normalize frontier entries to short hostnames (strip anything after the
    // first dot) before sending to ClickHouse. The SQL comparison also uses
    // `splitByChar('.', lower(col))[1]` so FQDN rows like
    // `ws-sales-002.corp.local` match a short frontier entry `ws-sales-002`.
    // Mirror of the old `normalizeHostname` in the frontend graph — keeps
    // both chain-generator (FQDN) and ambient (short) events in one node.
    let host_vec: Vec<String> = hosts
        .iter()
        .map(|h| normalize_host_for_compare(h))
        .collect();
    let placeholders = vec!["?"; host_vec.len()].join(",");

    // 4 IN clauses, each needs its own copy of bind values. Host columns get
    // FQDN-stripped at compare time; IP columns are compared as-is. Column names
    // resolve through the active schema profile (UDM → byte-identical names).
    let sql = format!(
        "(splitByChar('.', lower({src_host}))[1] IN ({placeholders}) \
         OR splitByChar('.', lower({dest_host}))[1] IN ({placeholders}) \
         OR lower({src_ip}) IN ({placeholders}) \
         OR lower({dest_ip}) IN ({placeholders}))",
        src_host = cols.src_host,
        dest_host = cols.dest_host,
        src_ip = cols.src_ip,
        dest_ip = cols.dest_ip,
    );

    // Repeat values 4 times (once per IN clause)
    let mut bind_values = Vec::with_capacity(host_vec.len() * 4);
    for _ in 0..4 {
        bind_values.extend(host_vec.iter().cloned());
    }

    (sql, bind_values)
}

/// Build the lateral-movement SELECT projection for `profile`. Free function so
/// the projection is unit-testable without constructing a `SearchService`; see
/// [`SearchService::lateral_columns`] for the resolution rules (and the NAN-1892
/// `source_type` exception that keeps the SELECT alias from shadowing the WHERE).
fn build_lateral_columns(profile: &dyn crate::schema::SchemaProfile) -> String {
    LATERAL_FIELDS
        .iter()
        .filter_map(|field| {
            // NAN-1892: `source_type` resolves to the OPERATIONAL String column
            // (`column_sql`), NOT the UDM→OCSF taxonomy `class_uid`
            // (`udm_column_sql`), so the projected `… AS source_type` alias matches
            // the physical column the hop WHERE filters on. Every other field uses
            // the taxonomy/unified resolution (class-split concepts need the unified
            // column; NAN-1348) and its WHERE references the physical name, not the
            // alias, so no shadow occurs.
            let col = if *field == "source_type" {
                Some(profile.column_sql(field))
            } else {
                profile.udm_column_sql(field)
            };
            // NAN-2211: alias to the profile's CANONICAL name, not the raw
            // resolution key — UDM's `action` projects as `event_type`, matching
            // what every other search read path emits since NAN-2208. Identity
            // for every other field and for OCSF (no renames), so the rest of
            // the projection is byte-identical.
            col.map(|col| format!("{col} AS {}", profile.canonical_field_name(field)))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Build one lateral-hop secondary query (auth / network / process — all three
/// share this exact shape). Extracted into a free function so the NAN-1797
/// source-scope gate is unit-testable without a live ClickHouse.
///
/// With `scope_predicate = None` the output is byte-identical to the
/// pre-scoping inline `format!` blocks. With a predicate, the method WHERE is
/// parenthesized (it is an OR-chain for auth) and the predicate is ANDed in,
/// so a scoped caller's hop expansion can never read a denied source_type.
fn build_hop_sql(
    lateral_columns: &str,
    logs_table: &str,
    entity_clause: &str,
    method_where: &str,
    scope_predicate: Option<&str>,
) -> String {
    let where_body = match scope_predicate {
        Some(pred) => format!("({method_where}) AND {pred}"),
        None => method_where.to_string(),
    };
    format!(
        r#"SELECT {lateral_columns}
                    FROM {logs_table}
                    PREWHERE timestamp BETWEEN ? AND ?
                        AND ({entity_clause})
                    WHERE {where_body}
                    ORDER BY timestamp ASC
                    LIMIT {MAX_EVENTS_PER_HOP}"#
    )
}

/// Build the lateral-view IP→hostname resolution SQL over `identity_observations`,
/// gated by the caller's source-scope deny-set.
///
/// NAN-2009 (F24): the lateral hostname enrichment reads a SEPARATE dataset the
/// hop queries' `source_type` gate does not cover — `identity_observations`,
/// whose source_type column is named `source` (NAN-1797). Without this gate a
/// scoped caller re-surfaces IP→hostname mappings observed only by a denied
/// source, exactly as `resolve_asset_identities` (asset.rs) already guards. An
/// empty deny-set renders no predicate → byte-identical SQL.
fn lateral_hostname_resolution_sql(
    identity_table: &str,
    placeholders: &str,
    deny_set: &BTreeSet<String>,
) -> String {
    let scope_and = source_scope_sql_predicate("source", deny_set)
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    format!(
        r#"SELECT ip, hostname
            FROM (
                SELECT ip, hostname,
                    ROW_NUMBER() OVER (PARTITION BY ip ORDER BY source_priority DESC, observed_at DESC) AS rn
                FROM {identity_table}
                WHERE ip IN ({placeholders}) AND hostname != ''{scope_and}
            )
            WHERE rn = 1"#
    )
}

/// Render a caller's source-scope deny-set as a ClickHouse WHERE predicate over
/// `column_expr` (NAN-1797/NAN-1799).
///
/// - Empty deny set → `None` (unrestricted callers pay nothing; callers must
///   emit byte-identical SQL to the pre-scoping form).
/// - Single member → `lower(col) != 'x'` — byte-identical to the legacy audit
///   gate string for `{"audit"}` (see `build_fetch_log_sql`, NAN-694).
/// - Multiple members → `lower(col) NOT IN ('a', 'b', …)` in BTreeSet
///   (lexicographic) order — mirrors how the nPL injector's negated `InList`
///   conjunct renders, and is case-safe on OCSF via the `lower()` wrap.
///
/// Values are lowercased and single-quote/backslash-escaped. Shared by the
/// hand-built SQL paths in this service (lateral hops, `fetch_log_by_id`,
/// `get_ext_field_names`, `query_udm_field`); nPL paths go through
/// `enforce_source_scope` instead — never both (no double gating).
///
/// Crate-public (NAN-1801, P3): the "side-door" hand-built SQL paths in other
/// crates (identity API, prevalence, telemetry, AI) reuse THIS single canonical
/// builder rather than re-deriving the predicate shape — any divergence from the
/// nPL injector's negated-`InList` rendering is the correctness risk. Re-exported
/// as `nanosiem_core::search::service::source_scope_sql_predicate`.
pub fn source_scope_sql_predicate(
    column_expr: &str,
    deny_set: &BTreeSet<String>,
) -> Option<String> {
    use crate::sql_hygiene::escape_sql_string;

    let mut values = deny_set
        .iter()
        .map(|v| escape_sql_string(&v.to_lowercase()));
    let first = values.next()?;
    if deny_set.len() == 1 {
        return Some(format!("lower({column_expr}) != '{first}'"));
    }
    let mut list = format!("'{first}'");
    for v in values {
        list.push_str(", '");
        list.push_str(&v);
        list.push('\'');
    }
    Some(format!("lower({column_expr}) NOT IN ({list})"))
}

/// Strip everything after the first dot and lowercase. Mirror of the old
/// `normalizeHostname` so `ws-sales-002.corp.local` and `ws-sales-002`
/// collapse to the same frontier key.
fn normalize_host_for_compare(h: &str) -> String {
    let lower = h.to_lowercase();
    match lower.find('.') {
        Some(idx) if idx > 0 => lower[..idx].to_string(),
        _ => lower,
    }
}

/// Extract a string field value from a JSON event.
/// Handles both string and numeric JSON values (ClickHouse JSONEachRow
/// returns integer columns like dest_port as numbers, not strings).
fn get_str(event: &serde_json::Value, field: &str) -> String {
    match event.get(field) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => {
            // Skip ClickHouse integer defaults (0) — treat as empty
            if let Some(i) = n.as_u64() {
                if i == 0 {
                    return String::new();
                }
            }
            n.to_string()
        }
        _ => String::new(),
    }
}

/// Check if an IP is a localhost/loopback address
fn is_localhost(ip: &str) -> bool {
    matches!(ip, "::1" | "127.0.0.1" | "0.0.0.0" | "0:0:0:0:0:0:0:1")
}

/// Physical result-row keys to try for a UDM seed candidate, in priority
/// order: the class-spanning UNIFIED column (OCSF materializes
/// coalesce(primary, fallback); present in result rows), the resolved
/// primary column, then the raw name. UDM yields just the raw name
/// (NAN-1348).
fn lateral_seed_keys(profile: &dyn crate::schema::SchemaProfile, udm: &str) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    if let Some(unified) = profile.class_split_column(udm) {
        keys.push(unified);
    }
    if let crate::schema::FieldResolution::ExplicitColumn(c) = profile.resolve(udm) {
        if !keys.contains(&c) {
            keys.push(c);
        }
    }
    if !keys.iter().any(|k| k == udm) {
        keys.push(udm.to_string());
    }
    keys
}

/// Extract the first non-empty value for a field from the result set
fn extract_field_value(results: &[serde_json::Value], field: &str) -> Option<String> {
    for result in results {
        if let Some(value) = result.get(field).and_then(|v| v.as_str()) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod source_scope_tests {
    use super::*;

    fn deny(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Build the three secondary hop SQLs (auth / network / process) exactly as
    /// `build_lateral_view` does for the UDM profile.
    fn secondary_sqls(scope_predicate: Option<&str>) -> Vec<String> {
        let profile = crate::schema::UdmProfile::new();
        let cols = LateralPredicateColumns::resolve(&profile);
        let entity_clause = "lower(user) = lower(?)";
        [
            cols.auth_where(),
            cols.network_where(),
            cols.process_where().expect("UDM maps process_name"),
        ]
        .iter()
        .map(|method_where| {
            build_hop_sql(
                "timestamp, source_type, user",
                "logs",
                entity_clause,
                method_where,
                scope_predicate,
            )
        })
        .collect()
    }

    /// NAN-1797: a nonempty deny-set must gate ALL THREE secondary queries —
    /// they are fresh scans that do not inherit the base query's injection.
    #[test]
    fn nonempty_deny_set_gates_all_three_secondary_queries() {
        let pred = source_scope_sql_predicate("source_type", &deny(&["audit", "windows_sysmon"]))
            .expect("nonempty deny set must render");
        assert_eq!(
            pred,
            "lower(source_type) NOT IN ('audit', 'windows_sysmon')"
        );
        for sql in secondary_sqls(Some(&pred)) {
            assert!(
                sql.contains("lower(source_type) NOT IN ('audit', 'windows_sysmon')"),
                "secondary query missing scope gate: {sql}"
            );
            // The method WHERE is an OR-chain (auth) — the gate must be ANDed
            // against the PARENTHESIZED method predicate, not the last OR term.
            assert!(
                sql.contains(") AND lower(source_type) NOT IN"),
                "scope gate must AND against the whole method WHERE: {sql}"
            );
        }
    }

    /// Empty deny set (unrestricted / SYSTEM caller) → predicate absent and the
    /// SQL byte-identical to the pre-scoping form.
    #[test]
    fn empty_deny_set_emits_no_gate_in_any_secondary_query() {
        assert_eq!(
            source_scope_sql_predicate("source_type", &BTreeSet::new()),
            None
        );
        for sql in secondary_sqls(None) {
            assert!(
                !sql.contains("NOT IN") && !sql.to_lowercase().contains("lower(source_type) !="),
                "unrestricted scope must not inject any source_type gate: {sql}"
            );
        }
    }

    /// Single-member deny set renders the `!=` form — byte-identical to the
    /// legacy audit gate for `{"audit"}`.
    #[test]
    fn single_member_deny_set_renders_inequality() {
        assert_eq!(
            source_scope_sql_predicate("source_type", &deny(&["audit"])).as_deref(),
            Some("lower(source_type) != 'audit'")
        );
    }

    /// Values are lowercased and escaped so the predicate is case-safe on OCSF
    /// and injection-safe on hostile source_type names.
    #[test]
    fn deny_values_are_lowercased_and_escaped() {
        assert_eq!(
            source_scope_sql_predicate("source_type", &deny(&["Weird'Name", "OTEL_TRACES"]))
                .as_deref(),
            Some("lower(source_type) NOT IN ('otel_traces', 'weird''name')")
        );
    }

    /// NAN-2009 (F24): the lateral IP→hostname enrichment reads
    /// `identity_observations` (source_type column = `source`). A scoped caller
    /// must gate it; an unrestricted caller must stay byte-identical.
    #[test]
    fn lateral_hostname_resolution_gates_identity_observations() {
        let scoped = lateral_hostname_resolution_sql(
            "identity_observations",
            "?,?",
            &deny(&["windows_dns"]),
        );
        assert!(
            scoped.contains("AND hostname != '' AND lower(source) != 'windows_dns'"),
            "scoped hostname resolution must gate on the source column:\n{scoped}"
        );

        let unscoped =
            lateral_hostname_resolution_sql("identity_observations", "?,?", &BTreeSet::new());
        assert!(
            !unscoped.contains("lower(source)"),
            "unrestricted caller must emit no gate:\n{unscoped}"
        );
        assert!(
            unscoped.contains("WHERE ip IN (?,?) AND hostname != ''"),
            "unrestricted SQL must be byte-identical to the pre-fix form:\n{unscoped}"
        );
    }

    /// NAN-1887: the per-source RBAC deny-set gate is built from
    /// `cols.source_type`, so under OCSF it must reference the OPERATIONAL String
    /// `source_type` column — NOT the `class_uid` UInt32 the UDM→OCSF taxonomy map
    /// resolves `source_type` to. `lower(class_uid) NOT IN (…)` is a ClickHouse type
    /// error (Code 43) that would break `| lateral` for any per-source-scoped caller
    /// on an OCSF tenant. Empirically confirmed against local `nanosiem.ocsf_logs`.
    #[test]
    fn ocsf_scope_gate_uses_operational_source_type_not_class_uid() {
        let profile = crate::schema::OcsfProfile::new();
        let cols = LateralPredicateColumns::resolve(&profile);
        let pred = source_scope_sql_predicate(&cols.source_type, &deny(&["audit"]))
            .expect("nonempty deny set must render");
        assert_eq!(pred, "lower(source_type) != 'audit'");
        assert!(
            !pred.contains("class_uid"),
            "OCSF scope gate must not reference the class_uid UInt32 column: {pred}"
        );
    }

    /// The empty-predicate hop SQL is byte-identical to the legacy inline
    /// `format!` block (whitespace and all) — regression guard for the
    /// extraction into `build_hop_sql`.
    #[test]
    fn hop_sql_without_scope_matches_legacy_shape() {
        let sql = build_hop_sql("a, b", "logs", "1=1", "x != ''", None);
        let expected = r#"SELECT a, b
                    FROM logs
                    PREWHERE timestamp BETWEEN ? AND ?
                        AND (1=1)
                    WHERE x != ''
                    ORDER BY timestamp ASC
                    LIMIT 10000"#;
        assert_eq!(sql, expected);
    }
}

#[cfg(test)]
mod lateral_seed_tests {
    use super::*;

    /// NAN-1348: OCSF seed candidates must include the class-split UNIFIED
    /// column — endpoint/sysmon events carry their host in the fallback
    /// (`device.hostname`) and user in `actor.user.name`, both of which only
    /// the unified column spans. resolve() alone (the primary) found nothing.
    #[test]
    fn ocsf_seed_keys_span_class_splits() {
        let p = crate::schema::OcsfProfile::new();
        let host_keys = lateral_seed_keys(&p, "src_host");
        assert_eq!(
            host_keys.first().map(String::as_str),
            Some("src_host_unified"),
            "unified column must be tried first: {host_keys:?}"
        );
        let user_keys = lateral_seed_keys(&p, "user");
        assert!(
            user_keys.iter().any(|k| k == "user_unified"),
            "user must span actor.user.name via the unified column: {user_keys:?}"
        );
        let ip_keys = lateral_seed_keys(&p, "src_ip");
        assert!(
            ip_keys.iter().any(|k| k == "src_endpoint.ip"),
            "non-split concepts resolve to their promoted column: {ip_keys:?}"
        );
    }

    /// UDM is byte-identical: no class splits, resolve() returns the name
    /// itself — exactly the raw-key lookup the code always did.
    #[test]
    fn udm_seed_keys_are_the_raw_names() {
        let p = crate::schema::UdmProfile::new();
        for f in ["src_host", "dest_host", "src_ip", "dest_ip", "user"] {
            assert_eq!(lateral_seed_keys(&p, f), vec![f.to_string()]);
        }
    }
}

#[cfg(test)]
mod auth_predicate_tests {
    use super::*;

    /// NAN-1887: on OCSF the auth predicate's `source_type` term must LIKE the
    /// OPERATIONAL String `source_type` column — NOT `class_uid`. The UDM
    /// `source_type` concept maps to the `class_uid` UInt32 taxonomy column via the
    /// manifest, so resolving it through `udm_column_sql` produced
    /// `lower(class_uid) LIKE '%auth%'`, a ClickHouse type error (Code 43, Illegal
    /// type UInt32 of argument of function lower) that broke every `| lateral` run
    /// on an OCSF tenant (web + desktop). Empirically reproduced against local
    /// `nanosiem.ocsf_logs` (class_uid = UInt32, source_type = LowCardinality(String)).
    #[test]
    fn ocsf_auth_where_likes_operational_source_type_not_class_uid() {
        let p = crate::schema::OcsfProfile::new();
        let sql = LateralPredicateColumns::resolve(&p).auth_where();
        // The fix: LIKE the operational String column.
        assert!(
            sql.contains("lower(source_type) LIKE '%auth%'"),
            "OCSF auth predicate must LIKE the operational source_type column: {sql}"
        );
        // The bug: never wrap the UInt32 taxonomy column in lower().
        assert!(
            !sql.contains("lower(class_uid)"),
            "OCSF auth predicate must not lower() the class_uid UInt32 column: {sql}"
        );
        // Primary recall is still the IAM category taxonomy.
        assert!(
            sql.contains(crate::search::classification::OCSF_AUTH_PREDICATE),
            "OCSF auth predicate must retain the category_uid=3 primary signal: {sql}"
        );
    }

    /// UDM stays byte-identical: `source_type` IS the operational String column, so
    /// the fix (routing through `column_sql` instead of `udm_column_sql`) is a no-op
    /// — the default `udm_column_sql` already delegates to `column_sql`.
    #[test]
    fn udm_auth_where_unchanged() {
        let p = crate::schema::UdmProfile::new();
        let sql = LateralPredicateColumns::resolve(&p).auth_where();
        assert!(
            sql.contains("lower(source_type) LIKE '%auth%'"),
            "UDM auth predicate must be byte-identical to the legacy form: {sql}"
        );
        assert!(
            sql.contains("auth_type != ''") && sql.contains("auth_result != ''"),
            "UDM auth predicate must keep the STRING `!= ''` axes: {sql}"
        );
    }

    /// NAN-1892: the SELECT projection must alias the OPERATIONAL `source_type`
    /// String column, NOT `class_uid`. Projecting `class_uid AS source_type` makes
    /// ClickHouse bind the hop WHERE's bare `source_type` to that UInt32 alias →
    /// `lower(class_uid)` → Code 43, even though the predicate (NAN-1887) already
    /// says `lower(source_type)`. Projection and predicate must resolve to ONE
    /// column.
    #[test]
    fn ocsf_projection_aliases_operational_source_type_not_class_uid() {
        let p = crate::schema::OcsfProfile::new();
        let projection = build_lateral_columns(&p);
        assert!(
            projection.contains("source_type AS source_type"),
            "OCSF projection must alias the operational source_type column: {projection}"
        );
        assert!(
            !projection.contains("class_uid"),
            "OCSF projection must not alias class_uid AS source_type: {projection}"
        );
    }

    /// End-to-end assembled auth hop query (projection + auth WHERE + RBAC gate) —
    /// the exact shape `build_lateral_view` runs. Guards the whole NAN-1887/1892
    /// chain: the assembled SQL must carry the operational `source_type` alias and
    /// contain NO `class_uid` anywhere (projection or predicate), so no `lower()`
    /// ever sees a `UInt32`. Empirically confirmed to execute against local
    /// `nanosiem.ocsf_logs`.
    #[test]
    fn ocsf_full_auth_hop_sql_has_no_class_uid_shadow() {
        let p = crate::schema::OcsfProfile::new();
        let cols = LateralPredicateColumns::resolve(&p);
        let sql = build_hop_sql(
            &build_lateral_columns(&p),
            "ocsf_logs",
            "1=1",
            &cols.auth_where(),
            Some("lower(source_type) != 'audit'"),
        );
        assert!(
            sql.contains("source_type AS source_type"),
            "assembled hop SQL must project the operational source_type: {sql}"
        );
        assert!(
            !sql.contains("class_uid"),
            "assembled hop SQL must not reference class_uid (would shadow → Code 43): {sql}"
        );
    }

    /// UDM projection is byte-identical: `source_type` resolves to itself under
    /// both resolvers, so the NAN-1892 exception is a no-op.
    #[test]
    fn udm_projection_unchanged() {
        let p = crate::schema::UdmProfile::new();
        let projection = build_lateral_columns(&p);
        assert!(
            projection.contains("source_type AS source_type"),
            "UDM projection must be byte-identical: {projection}"
        );
    }

    /// NAN-2211: the lateral projection was the last search view still handing
    /// the analyst the legacy `action` name. NAN-2208 made every other read path
    /// emit the canonical `event_type`; this one aliased the resolution key
    /// verbatim, so `| lateral` results disagreed with the event list.
    #[test]
    fn udm_projection_aliases_action_to_canonical_event_type() {
        let p = crate::schema::UdmProfile::new();
        let projection = build_lateral_columns(&p);
        assert!(
            projection.contains("action AS event_type"),
            "UDM lateral projection must emit the canonical name: {projection}"
        );
        assert!(
            !projection
                .split(", ")
                .any(|c| c.trim().ends_with("AS action")),
            "no column may still alias to the legacy `action`: {projection}"
        );
    }

    /// The rename is confined to the renamed field — every other alias keeps its
    /// canonical name, so the projection is otherwise byte-identical.
    #[test]
    fn udm_projection_rename_does_not_touch_other_fields() {
        let p = crate::schema::UdmProfile::new();
        let projection = build_lateral_columns(&p);
        for field in [
            "src_ip",
            "dest_ip",
            "user",
            "auth_result",
            "process_name",
            "category",
        ] {
            assert!(
                projection.contains(&format!("AS {field}")),
                "{field} must keep its canonical alias: {projection}"
            );
        }
    }

    /// OCSF declares no renames, so its projection is unchanged — and must not
    /// acquire a UDM-only name.
    #[test]
    fn ocsf_projection_has_no_udm_rename() {
        let p = crate::schema::OcsfProfile::new();
        let projection = build_lateral_columns(&p);
        assert!(
            !projection.contains("AS event_type"),
            "OCSF must not gain the UDM rename: {projection}"
        );
    }
}

#[cfg(test)]
mod lake_lateral_tests {
    use super::*;

    #[test]
    fn strict_lake_seed_uses_exact_ocsf_paths() {
        let rows = vec![json!({
            "src_endpoint": {"hostname": "WS-01.corp.local", "ip": "10.1.2.3"},
            "user": {"name": "alice"}
        })];
        let info = LateralCommandInfo {
            seed_type: LateralSeedType::Auto,
            entity_field: None,
            max_hops: 2,
            time_window: None,
            methods: LateralMethod::all(),
        };
        let seed = detect_lake_lateral_seed(&rows, &info, None).unwrap();
        assert_eq!(seed.field, "src_endpoint.hostname");
        assert_eq!(seed.graph_kind, "host");
        assert_eq!(seed.value, "WS-01.corp.local");
    }

    #[test]
    fn strict_lake_seed_does_not_scan_when_the_base_query_is_explicit() {
        let rows = Vec::new();
        let info = LateralCommandInfo {
            seed_type: LateralSeedType::Host,
            entity_field: None,
            max_hops: 2,
            time_window: None,
            methods: LateralMethod::all(),
        };
        let seed = detect_lake_lateral_seed(
            &rows,
            &info,
            Some((
                "device.hostname".to_string(),
                "lt-legal-001.corp.local".to_string(),
            )),
        )
        .unwrap();
        assert_eq!(seed.field, "device.hostname");
        assert_eq!(seed.value, "lt-legal-001.corp.local");
    }

    #[test]
    fn generated_hop_query_is_strict_ocsf_and_contains_no_udm_query_names() {
        let hosts = BTreeSet::from(["WS-01.corp.local".to_string()]);
        let entity = lake_host_predicate(&hosts).unwrap();
        let query = format_lake_lateral_query(&entity, "dst_endpoint.port IN (22,445,3389)");
        for legacy in ["source_type", "src_host", "dest_host", "src_ip", "dest_ip"] {
            assert!(
                !query
                    .split(|character: char| !character.is_alphanumeric() && character != '_')
                    .any(|token| token == legacy),
                "lake hop query leaked legacy field {legacy}: {query}"
            );
        }
        let parsed = crate::query::parse_query(&query).unwrap();
        validate_query_field_names(&parsed, &crate::schema::OcsfProfile::lake_1_9()).unwrap();
    }

    #[test]
    fn full_lake_frontier_keeps_query_parser_depth_constant() {
        let hosts = (0..MAX_LAKE_FRONTIER_ENTITIES - 1)
            .map(|index| format!("ws-{index:03}.corp.local"))
            .chain(["10.1.2.3".to_string()])
            .collect::<BTreeSet<_>>();
        let entity = lake_host_predicate(&hosts).unwrap();
        assert!(
            entity.matches(" OR ").count() <= 5,
            "frontier predicate must not grow a left-deep OR tree: {entity}"
        );
        let query = format_lake_lateral_query(&entity, "dst_endpoint.port IN (22,445,3389)");
        let parsed = crate::query::parse_query(&query).unwrap();
        validate_query_field_names(&parsed, &crate::schema::OcsfProfile::lake_1_9()).unwrap();
    }

    #[test]
    fn oversized_lake_frontier_is_split_without_truncation() {
        let hosts = (0..MAX_LAKE_FRONTIER_ENTITIES + 41)
            .map(|index| format!("ws-{index:03}.corp.local"))
            .collect::<BTreeSet<_>>();
        let predicates = lake_host_predicates(&hosts).unwrap();
        assert_eq!(predicates.len(), 2);
        for predicate in predicates {
            let query = format_lake_lateral_query(&predicate, "dst_endpoint.port IN (22,445,3389)");
            let parsed = crate::query::parse_query(&query).unwrap();
            validate_query_field_names(&parsed, &crate::schema::OcsfProfile::lake_1_9()).unwrap();
        }
    }

    #[test]
    fn lake_projection_adapter_reads_flat_worker_columns_without_mutating_event_contract() {
        let worker_row = json!({
            "time": "2026-08-11 01:02:03.000000",
            "metadata.log_source": "windows_event",
            "actor.user.name": "alice",
            "src_endpoint.hostname": "WS-01",
            "src_endpoint.ip": "10.1.2.3",
            "src_endpoint.port": 51234,
            "dst_endpoint.hostname": "DC-01",
            "dst_endpoint.ip": "10.1.2.4",
            "dst_endpoint.port": 445,
            "auth_protocol": "NTLM",
            "status": "Success"
        });
        let adapter = lake_lateral_projection_row(&worker_row);
        let edge = extract_edge(&adapter, 0, "auth").unwrap();
        assert_eq!(edge.user, "alice");
        assert_eq!(edge.src_host, "ws-01");
        assert_eq!(edge.dest_host, "dc-01");
        assert_eq!(edge.dest_port, "445");
        assert_eq!(edge.source_type, "windows_event");
        assert!(worker_row.get("src_host").is_none());
    }

    #[test]
    fn internally_constructed_literal_fails_closed_when_npl_cannot_represent_it() {
        assert!(lake_lateral_literal("host\"' | head 0").is_err());
        assert_eq!(
            lake_lateral_literal("DOMAIN\\alice").unwrap(),
            "\"DOMAIN\\\\alice\""
        );
    }
}

/// NAN-3058: lean lateral-movement hostname fill resolves edge IPs through
/// the tenant's identity observation index (one bounded batch request), and
/// only for edges that lack a hostname.
#[cfg(test)]
mod lake_lateral_identity_tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};
    use wiremock::{matchers::{method, path}, Mock, MockServer, ResponseTemplate};

    fn edge(src_ip: &str, dest_ip: &str, dest_host: &str) -> LateralEdge {
        LateralEdge {
            timestamp: "2026-09-29 23:40:00.000000".into(), user: "jhernandez".into(),
            src_host: String::new(), dest_host: dest_host.into(), src_ip: src_ip.into(), dest_ip: dest_ip.into(),
            src_port: String::new(), dest_port: "3389".into(), method: "auth".into(), method_detail: "rdp".into(),
            hop_number: 1, process_name: String::new(), auth_type: String::new(), auth_result: String::new(),
            source_type: "windows_event".into(),
        }
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn lean_lateral_edges_get_hostnames_from_the_identity_index() {
        let server = MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0x1a7);
        let token = tempfile::tempdir().unwrap();
        let token_file = token.path().join("router.token");
        std::fs::write(&token_file, "lateral-identity-router-token-1234567890").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let recorded = seen.clone();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/identity/resolve-batch")))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                recorded.lock().unwrap().push(body.clone());
                let rows = body["items"].as_array().unwrap().iter().enumerate()
                    .filter(|(_, item)| item["ip"] == "10.1.3.7")
                    .map(|(ordinal, item)| json!({"ordinal": ordinal, "ip": "10.1.3.7", "hostname": if item["reference_time"] == "2026-09-30T01:00:00+00:00" { "WS-NEW" } else { "WS-IT-052" },
                        "fqdn": "ws-it-052.corp.local", "user": "jhernandez", "mac": "", "source": "windows_sysmon",
                        "observed_at": "2026-09-29T23:30:00.000000Z", "nat_candidate": false}))
                    .collect::<Vec<_>>();
                ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "request_id": body["request_id"], "tenant_id": body["tenant_id"],
                    "route": "identity_batch", "identity_index": {"state": "complete"},
                    "result": {"result_rows": rows.len(), "rows": rows}
                }))
            })
            .mount(&server)
            .await;
        let pool = crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
            "postgres://unused:unused@127.0.0.1:1/nanosiem", "http://127.0.0.1:1", "nanosiem", "unused", "nanosiem",
        )).await.unwrap();
        let view = SearchService::with_dual_pool(&pool)
            .enterprise_shared_cell_tenant_view(
                &crate::search::LakeCellRoute {
                    tenant_id: tenant, assignment_generation: 1, part_log_writer_epoch: 1, worker_revision: 1,
                    assignment_fenced: true, cell_origin: server.uri(),
                    query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
                    router_token_file: token_file,
                },
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0).unwrap(),
                Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap();
        let mut edges = vec![edge("10.1.3.7", "10.1.8.119", ""), edge("10.1.3.7", "10.1.9.9", "dc01")];
        let mut later = edge("10.1.3.7", "10.1.8.119", "");
        later.timestamp = "2026-09-30T01:00:00Z".to_string();
        edges.push(later);
        let scope = ScopeSet::from_denied(BTreeSet::from(["audit".to_string()]));
        view.resolve_lake_lateral_hostnames(&mut edges, &scope).await;
        assert_eq!(edges[0].src_host, normalize_host_for_compare("WS-IT-052"));
        assert_eq!(edges[1].src_host, edges[0].src_host);
        assert_eq!(edges[2].src_host, "ws-new", "a later binding must not replace the earlier hostname");
        assert!(edges[0].dest_host.is_empty(), "an unresolved IP keeps an empty host");
        assert_eq!(edges[1].dest_host, "dc01", "an edge that has a host is not re-resolved");
        let calls = seen.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "one bounded batch for every pending edge IP");
        let ips = calls[0]["items"].as_array().unwrap().iter().map(|i| i["ip"].as_str().unwrap().to_string()).collect::<BTreeSet<_>>();
        assert_eq!(ips, BTreeSet::from(["10.1.3.7".to_string(), "10.1.8.119".to_string()]));
        assert_eq!(calls[0]["deny_source_types"], json!(["audit"]));
    }

    /// NAN-3059: one combined scan per hop is split back into methods in Rust;
    /// each classifier must agree with the nPL predicate it replaces.
    #[test]
    fn combined_hop_rows_classify_like_the_method_predicates() {
        let auth = serde_json::json!({"class_uid": 3002, "activity_name": "Logon", "dst_endpoint.port": null});
        let kerberos = serde_json::json!({"class_uid": 4001, "auth_protocol": "Kerberos"});
        let smb = serde_json::json!({"class_uid": 4001, "dst_endpoint": {"port": 445}});
        let web = serde_json::json!({"class_uid": 4001, "dst_endpoint.port": 443});
        let psexec = serde_json::json!({"class_uid": 1007, "process.name": "PsExec64.exe"});
        let pwsh = serde_json::json!({"class_uid": 1007, "process": {"name": "POWERSHELL.EXE"}});
        assert!(lake_lateral_is_auth(&auth) && lake_lateral_is_auth(&kerberos));
        assert!(!lake_lateral_is_auth(&smb) && !lake_lateral_is_auth(&psexec));
        assert!(lake_lateral_is_network(&smb) && !lake_lateral_is_network(&web));
        assert!(!lake_lateral_is_network(&auth));
        assert!(lake_lateral_is_process(&psexec) && lake_lateral_is_process(&pwsh));
        assert!(!lake_lateral_is_process(&web));
        // The combined predicate is the OR of exactly these three and parses.
        let combined = format!(
            "(({}) OR ({}) OR ({}))",
            LAKE_LATERAL_AUTH_PREDICATE,
            LAKE_LATERAL_NETWORK_PREDICATE,
            lake_lateral_process_predicate()
        );
        crate::query::parse_query(&format_lake_lateral_query("device.hostname=\"h\"", &combined))
            .expect("combined hop query parses");
    }

}

#[cfg(test)]
mod nan3295_tests {
    use super::*;

    const LANE: DurableLaneFacts = DurableLaneFacts { serves_lake_cell: true, has_job_runner: true, retention_bound: true };

    #[test]
    fn durable_lateral_is_on_wherever_the_view_lane_exists() {
        // The regression: the env var unset (as on the shared search
        // deployment) must not refuse a tenant whose durable lane exists.
        for value in [None, Some(""), Some("1"), Some("true"), Some("yes")] {
            assert!(!durable_lateral_kill_switch(value), "{value:?} must not switch durable Lateral off");
            assert_eq!(durable_lateral_gate(durable_lateral_kill_switch(value), LANE), None);
        }
        for value in ["0", "false", "OFF", " 0 "] {
            assert!(durable_lateral_kill_switch(Some(value)), "{value:?} is the kill switch");
            assert!(durable_lateral_gate(true, LANE).unwrap().contains("NANO_LAKE_DURABLE_LATERAL=0"));
        }
    }

    #[test]
    fn missing_lane_pieces_are_named() {
        let reason = |lane| durable_lateral_gate(false, lane).unwrap();
        assert!(reason(DurableLaneFacts { serves_lake_cell: false, ..LANE }).contains("lean lake cell"));
        assert!(reason(DurableLaneFacts { has_job_runner: false, ..LANE }).contains("job runner"));
        assert!(reason(DurableLaneFacts { retention_bound: false, ..LANE }).contains("retention identity"));
    }

    #[tokio::test]
    async fn unavailable_durable_lateral_is_a_specific_422_not_a_generic_503() {
        let pool = crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
            "postgres://unused:unused@127.0.0.1:1/nanosiem", "http://127.0.0.1:1", "nanosiem", "unused", "nanosiem",
        )).await.unwrap();
        let service = SearchService::with_dual_pool(&pool);
        assert!(!service.has_durable_view_lane());
        let now = chrono::Utc::now();
        let request = SearchRequest {
            query: "device.hostname=\"h0\" | lateral".into(),
            time_range: TimeRangeInput::new(now - chrono::Duration::hours(6), now),
            limit: None, offset: None, include_sql: None, skip_histogram: true, skip_field_stats: true,
            use_cache: false, table_view: false, request_id: None, async_mode: true, priority: None, dataset: None,
        };
        let error = service.try_enqueue_durable_lateral(&request, uuid::Uuid::nil(), &ScopeSet::default(), None)
            .await.unwrap_err();
        match error {
            SearchError::ResourceExhausted(message) => {
                assert!(message.contains("lean lake cell"), "{message}");
                assert!(!message.contains("retry shortly"), "{message}");
            }
            other => panic!("expected a specific ResourceExhausted, got {other:?}"),
        }
        // A non-Lateral query is not this gate's business.
        let mut plain = request.clone();
        plain.query = "device.hostname=\"h0\" | head 5".into();
        assert!(service.try_enqueue_durable_lateral(&plain, uuid::Uuid::nil(), &ScopeSet::default(), None).await.unwrap().is_none());
    }

    /// NAN-3492: a dedicated cell route alone (no hosted producer, flag
    /// absent: every hosted deployment) has no cell job runner and no durable
    /// view lane, exactly as before the trusted-local lane existed. Only the
    /// explicit trusted-local client adds the runner, and never under a
    /// shared scope.
    #[tokio::test]
    async fn cell_job_runner_needs_a_hosted_producer_or_the_explicit_trusted_local_flag() {
        let pool = crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
            "postgres://unused:unused@127.0.0.1:1/nanosiem", "http://127.0.0.1:1", "nanosiem", "unused", "nanosiem",
        )).await.unwrap();
        let mut service = SearchService::with_dual_pool(&pool);
        let dir = tempfile::tempdir().unwrap();
        let tenant = uuid::Uuid::from_u128(0x42);
        let route = crate::search::lake_cell::LakeCellRoute::for_test(
            tenant, "http://127.0.0.1:1", dir.path().join("router.token"));
        service.lake_query = crate::search::lake::LakeQueryRuntime::from_lake_cell_route(
            &route, std::time::Duration::from_secs(5)).unwrap();
        assert!(service.serves_lake_cell());
        #[cfg(feature = "enterprise")]
        assert!(!service.admission_scope.is_enterprise_shared());

        // Flag absent: unchanged hosted behaviour.
        assert!(!service.serves_trusted_local_cell());
        assert!(!service.has_cell_job_runner());
        assert!(!service.has_durable_view_lane());

        // The explicit trusted-local client: its own job store is the runner.
        service.lake_query.client = service.lake_query.client.take().map(|client| client.with_trusted_local(true));
        assert!(service.serves_trusted_local_cell());
        assert!(service.has_cell_job_runner());
        assert!(service.has_durable_view_lane());

        // Never under a shared scope, whatever the client says.
        service.admission_scope = crate::search::tenant::SearchTenantScope::EnterpriseShared(tenant);
        assert!(!service.serves_trusted_local_cell());
        assert!(!service.has_cell_job_runner());
    }

    #[test]
    fn hop_query_groups_and_carries_exactly_the_projected_fields() {
        let mut fields = LAKE_LATERAL_GROUP_FIELDS.iter().copied()
            .chain(LAKE_LATERAL_CARRIED_FIELDS.iter().map(|(field, _)| *field))
            .chain(["time"])
            .collect::<Vec<_>>();
        fields.sort_unstable();
        let mut expected = LAKE_LATERAL_FIELDS.to_vec();
        expected.sort_unstable();
        assert_eq!(fields, expected);
        let query = format_lake_lateral_query("device.hostname=\"h\"", LAKE_LATERAL_NETWORK_PREDICATE);
        let parsed = crate::query::parse_query(&query).unwrap();
        validate_query_field_names(&parsed, &crate::schema::OcsfProfile::lake_1_9()).unwrap();
        assert!(query.contains("| bin time span=1m as lateral_minute | stats min(time) as time"), "{query}");
    }

    #[test]
    fn carried_aliases_are_renamed_back_to_ocsf_paths() {
        let mut row = json!({"time": "2026-10-08 12:00:00.650000", "lateral_minute": "2026-10-08 12:00:00",
            "lateral_src_port": 55480, "lateral_log_source": "windows_event", "src_endpoint.hostname": "ws-mkt-083"});
        restore_lake_lateral_carried_fields(&mut row);
        assert_eq!(row, json!({"time": "2026-10-08 12:00:00.650000", "src_endpoint.port": 55480,
            "metadata.log_source": "windows_event", "src_endpoint.hostname": "ws-mkt-083"}));
    }

    /// Emulates the cell's `bin 1m | stats min(time), first(..) by <group>`.
    fn group_like_the_cell(raw: &[serde_json::Value]) -> Vec<serde_json::Value> {
        let mut groups: Vec<(String, serde_json::Value)> = Vec::new();
        let mut sorted = raw.to_vec();
        sorted.sort_by_key(|row| row["time"].as_str().unwrap().to_string());
        for row in sorted {
            let minute = row["time"].as_str().unwrap()[..16].to_string();
            let key = format!("{minute}|{}", LAKE_LATERAL_GROUP_FIELDS.iter().map(|f| row.get(*f).cloned().unwrap_or_default().to_string()).collect::<Vec<_>>().join("|"));
            if groups.iter().any(|(existing, _)| *existing == key) { continue; }
            let mut out = serde_json::Map::new();
            out.insert("time".into(), row["time"].clone());
            out.insert("lateral_minute".into(), json!(format!("{minute}:00")));
            for field in LAKE_LATERAL_GROUP_FIELDS {
                out.insert((*field).into(), row.get(*field).cloned().unwrap_or_default());
            }
            for (field, alias) in LAKE_LATERAL_CARRIED_FIELDS {
                out.insert((*alias).into(), row.get(*field).cloned().unwrap_or_default());
            }
            groups.push((key, serde_json::Value::Object(out)));
        }
        groups.into_iter().map(|(_, row)| row).collect()
    }

    fn deduped_edges(rows: &[serde_json::Value]) -> Vec<String> {
        let mut edges = Vec::new();
        for row in rows {
            let projected = lake_lateral_projection_row(row);
            for (wanted, method) in [(lake_lateral_is_auth(row), "auth"), (lake_lateral_is_network(row), "network"), (lake_lateral_is_process(row), "process")] {
                if wanted { edges.extend(extract_edge(&projected, 0, method)); }
            }
        }
        edges.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
        dedup_edges(edges).into_iter().map(|edge| format!("{edge:?}")).collect()
    }

    #[test]
    fn grouped_hop_rows_dedup_to_the_same_edges_as_raw_events() {
        let mut raw = Vec::new();
        for second in 0..150u32 {
            let time = format!("2026-10-08 12:0{}:{:02}.{:06}", second / 60, second % 60, second);
            let protocol = ["NTLM", "Kerberos", "Negotiate"][(second % 3) as usize];
            raw.push(json!({"time": time, "class_uid": 3002, "activity_name": "Logon", "auth_protocol": (protocol),
                "src_endpoint.hostname": "ws-mkt-083", "src_endpoint.ip": "10.1.4.64", "src_endpoint.port": 50000 + second,
                "dst_endpoint.hostname": "ws-it-083.corp.local", "device.hostname": "ws-it-083.corp.local",
                "user.name": if second % 7 == 0 { "svc" } else { "mtaylor" }, "status": if second % 11 == 0 { "Failure" } else { "Success" },
                "metadata.log_source": "windows_event", "category_name": "Identity & Access Management"}));
            raw.push(json!({"time": time, "class_uid": 3002, "activity_name": "Logoff",
                "dst_endpoint.hostname": "ws-it-083.corp.local", "device.hostname": "ws-it-083.corp.local"}));
            raw.push(json!({"time": time, "class_uid": 4001, "activity_name": "Open", "dst_endpoint.port": ([445, 3389, 5985][(second % 3) as usize]),
                "src_endpoint.hostname": "ws-it-083.corp.local", "src_endpoint.ip": "10.1.4.63", "src_endpoint.port": 40000 + second,
                "dst_endpoint.ip": format!("10.9.{}.{}", second % 2, second % 5), "device.hostname": "ws-it-083.corp.local"}));
            raw.push(json!({"time": time, "class_uid": 1007, "activity_name": "Launch", "process.name": "powershell.exe",
                "process.file.path": format!("C:\\p{second}"), "device.hostname": "ws-it-083.corp.local",
                "dst_endpoint.hostname": if second % 2 == 0 { "dc01" } else { "" }}));
        }
        let grouped = group_like_the_cell(&raw);
        assert!(grouped.len() * 2 < raw.len(), "grouping must collapse repeats: {} of {}", grouped.len(), raw.len());
        let mut restored = grouped;
        restored.iter_mut().for_each(restore_lake_lateral_carried_fields);
        assert_eq!(deduped_edges(&restored), deduped_edges(&raw));
    }

    #[test]
    fn external_ip_literals_are_recognized() {
        for external in ["8.8.8.8", "1.101.91.222", "199.99.3.99", "2001:4860::8888", "::ffff:8.8.8.8"] {
            assert!(is_external_ip_literal(external), "{external}");
        }
        for internal in ["10.1.4.63", "172.16.0.1", "192.168.144.230", "100.64.1.1", "127.0.0.1", "169.254.1.1",
            "fd00::1", "fe80::1", "::1", "::ffff:10.0.0.1", "ws-it-083", "dc01.corp.local", ""] {
            assert!(!is_external_ip_literal(internal), "{internal}");
        }
    }

    #[tokio::test]
    async fn public_destinations_stay_in_the_graph_but_never_join_the_frontier() {
        let seed = LakeLateralSeed { field: "device.hostname".into(), graph_kind: "host", value: "ws-it-083".into() };
        let info = LateralCommandInfo { seed_type: LateralSeedType::Host, entity_field: None, max_hops: 2,
            time_window: None, methods: vec![LateralMethod::Network] };
        let queries = std::sync::Mutex::new(Vec::new());
        let (edges, stopped, hops) = trace_lake_lateral(&seed, None, &info, std::time::Instant::now(), None, 1000, 1000,
            |query, hop, _| {
                queries.lock().unwrap().push(query);
                let rows = if hop == 0 {
                    vec![
                        json!({"time": "2026-10-08 12:00:01.000000", "class_uid": 4001, "dst_endpoint.port": 445,
                            "src_endpoint.hostname": "ws-it-083", "dst_endpoint.ip": "8.8.8.8"}),
                        json!({"time": "2026-10-08 12:00:02.000000", "class_uid": 4001, "dst_endpoint.port": 445,
                            "src_endpoint.hostname": "ws-it-083", "dst_endpoint.ip": "10.9.0.5"}),
                    ]
                } else { Vec::new() };
                std::future::ready(Ok(rows))
            }, false, |_, _| std::future::ready(Ok(()))).await.unwrap();
        assert_eq!((stopped, hops), (None, 2));
        assert_eq!(edges.len(), 2, "the public-IP edge is still evidence");
        let queries = queries.into_inner().unwrap();
        assert_eq!(queries.len(), 2);
        assert!(queries[1].contains("\"10.9.0.5\""), "{}", queries[1]);
        assert!(!queries[1].contains("8.8.8.8"), "{}", queries[1]);
    }
}

#[cfg(test)]
mod progressive_lateral_tests {
    use super::*;

    #[tokio::test]
    async fn deferred_lateral_returns_authorized_seed_without_scanning() {
        let pool = crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
            "postgres://unused:unused@127.0.0.1:1/nanosiem", "http://127.0.0.1:1", "nanosiem", "unused", "nanosiem",
        )).await.unwrap();
        let view = SearchService::with_dual_pool(&pool);
        let parsed = crate::query::parse_query("device.hostname=\"h0\" | lateral").unwrap();
        let info = crate::search::query_processing::extract_lateral_command(&parsed).unwrap();
        let range = TimeRange::new(chrono::Utc::now() - chrono::Duration::hours(1), chrono::Utc::now());
        let scope = ScopeSet::from_denied(BTreeSet::from(["audit".to_string()]));
        let output = crate::search::streaming::DEFER_LATERAL_VIEW.scope(true,
            view.build_lake_lateral_view(Vec::new(), &info, Some(("device.hostname".to_string(), "h0".to_string())), &range, &scope)).await.unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0]["_lateral_pending"], true);
        assert_eq!(output[0]["_lateral_config"]["seed_value"], "h0");
        assert!(output[0].get("_lateral_graph").is_none());
        assert_eq!(output[0]["_lateral_time_range"]["start"], serde_json::to_value(range.start).unwrap());
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn progressive_lateral_paints_before_the_next_hop_and_preserves_final_rows() {
        use wiremock::{matchers::{method, path}, Mock, MockServer, ResponseTemplate};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let server = MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0x3077);
        let temp = tempfile::tempdir().unwrap();
        let token_file = temp.path().join("router.token");
        std::fs::write(&token_file, "local-test-router-token-1234567890").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["deny_source_types"], json!(["audit"]));
                let hop = recorded.fetch_add(1, Ordering::SeqCst);
                let rows = vec![json!({"time": format!("2026-09-30T00:0{}:00Z", hop % 2),
                    "class_uid": 3002, "user.name": "alice", "status": "Success",
                    "src_endpoint.hostname": format!("h{}", hop % 2), "dst_endpoint.hostname": format!("h{}", hop % 2 + 1),
                    "dst_endpoint.port": 3389, "metadata.log_source": "windows_event"})];
                let answer = ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "schema_version": 1, "request_id": body["request_id"], "tenant_id": tenant,
                    "route": "broad_npl", "source_mode": "parts", "wall_seconds": 0.01,
                    "result": {"result_rows": rows.len(), "rows": rows, "page_has_more": false}
                }));
                if hop % 2 == 1 { answer.set_delay(std::time::Duration::from_millis(200)) } else { answer }
            }).mount(&server).await;
        let pool = crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
            "postgres://unused:unused@127.0.0.1:1/nanosiem", "http://127.0.0.1:1", "nanosiem", "unused", "nanosiem",
        )).await.unwrap();
        let view = SearchService::with_dual_pool(&pool).enterprise_shared_cell_tenant_view(
            &crate::search::LakeCellRoute { tenant_id: tenant, assignment_generation: 1, part_log_writer_epoch: 1,
                worker_revision: 1, assignment_fenced: true, cell_origin: server.uri(),
                query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()), router_token_file: token_file },
            crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0).unwrap(),
            Arc::new(crate::search::InMemoryJobStore::new()),
        ).unwrap();
        let parsed = crate::query::parse_query("device.hostname=\"h0\" | lateral").unwrap();
        let mut info = crate::search::query_processing::extract_lateral_command(&parsed).unwrap();
        info.max_hops = 2;
        info.methods = vec![LateralMethod::Auth];
        let range = TimeRange::new(chrono::DateTime::parse_from_rfc3339("2026-09-30T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
            chrono::DateTime::parse_from_rfc3339("2026-09-30T01:00:00Z").unwrap().with_timezone(&chrono::Utc));
        let scope = ScopeSet::from_denied(BTreeSet::from(["audit".to_string()]));
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let trace = crate::search::streaming::LATERAL_VIEW_SINK.scope(tx,
            view.build_lake_lateral_view(Vec::new(), &info, Some(("device.hostname".into(), "h0".into())), &range, &scope));
        tokio::pin!(trace);
        let first = tokio::select! { event = rx.recv() => event.unwrap(), result = &mut trace => panic!("finished before first hop: {result:?}") };
        match first { crate::search::streaming::SearchStreamEvent::ViewUpdate { completed_hops, complete, rows, .. } => {
            assert_eq!(completed_hops, 1); assert!(!complete); assert_eq!(rows.len(), 1); assert!(!rows[0]["_lateral_graph"]["edges"].as_array().unwrap().is_empty());
        }, other => panic!("wrong event: {other:?}") }
        let progressive = trace.await.unwrap();
        let atomic = view.build_lake_lateral_view(Vec::new(), &info, Some(("device.hostname".into(), "h0".into())), &range, &scope).await.unwrap();
        assert_eq!(&progressive[1..], &atomic[1..]);
        let mut hop = 0;
        let durable = run_lake_lateral_job("device.hostname=\"h0\" | lateral methods=auth maxhops=2", &range, &scope, 100,
            |_, limit| {
                assert_eq!(limit, 1_000_000);
                let rows = vec![json!({"time": format!("2026-09-30T00:0{hop}:00Z"),
                    "class_uid": 3002, "user.name": "alice", "status": "Success",
                    "src_endpoint.hostname": format!("h{hop}"), "dst_endpoint.hostname": format!("h{}", hop + 1),
                    "dst_endpoint.port": 3389, "metadata.log_source": "windows_event"})];
                hop += 1;
                std::future::ready(Ok(rows))
            }, |_| std::future::ready(Ok(Vec::new())),
        ).await.unwrap();
        assert_eq!(&durable[1..], &atomic[1..]);
        // Graph edge order comes from a HashMap; compare canonical graph content.
        let canonical_graph = |mut graph: serde_json::Value| {
            graph["edges"].as_array_mut().unwrap().sort_by_key(|edge| serde_json::to_string(edge).unwrap());
            graph
        };
        assert_eq!(canonical_graph(progressive[0]["_lateral_graph"].clone()), canonical_graph(atomic[0]["_lateral_graph"].clone()));
        assert_eq!(canonical_graph(durable[0]["_lateral_graph"].clone()), canonical_graph(atomic[0]["_lateral_graph"].clone()));
    }

    #[test]
    fn progressive_view_wire_keeps_graph_separate_from_raw_row_counts() {
        let event = crate::search::streaming::SearchStreamEvent::ViewUpdate {
            view: "lateral".to_string(), rows: vec![json!({"_lateral_graph": {"edges": []}})], completed_hops: 1, complete: false,
        };
        let wire = serde_json::to_value(event).unwrap();
        assert_eq!(wire["event"], "view_update");
        assert_eq!(wire["data"]["completed_hops"], 1);
        assert_eq!(wire["data"]["complete"], false);
        assert!(wire["data"].get("cumulative_count").is_none());
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later

use serde_json::json;
use std::collections::{HashMap, HashSet};

use super::lateral_graph::{build_lateral_graph_payload, RawEvent};
use super::*;
use crate::query::{LateralMethod, LateralSeedType};
use crate::search::query_processing::LateralCommandInfo;

/// Maximum events to fetch per hop query to prevent runaway queries
const MAX_EVENTS_PER_HOP: usize = 10_000;

/// Columns to select for lateral movement events
const LATERAL_COLUMNS: &str = "\
    timestamp, source_type, user, \
    src_ip, dest_ip, src_host, dest_host, src_port, dest_port, \
    protocol, auth_type, auth_result, session_id, \
    process_name, process_path, action, category";

impl SearchService {
    /// Build lateral movement view by tracing hop-by-hop movement paths.
    ///
    /// This method:
    /// 1. Extracts the seed entity (user or host) from initial results
    /// 2. Iteratively expands hops via BFS, querying auth, network, and process events
    /// 3. Builds structured output rows with hop tracking
    /// 4. Returns results with `_display_type: "lateral"` metadata
    pub(crate) async fn build_lateral_view(
        &self,
        results: Vec<serde_json::Value>,
        lateral_info: &LateralCommandInfo,
        time_range: &TimeRange,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let start_time = std::time::Instant::now();

        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => {
                return Err(SearchError::SqlGenError(
                    "ClickHouse required for lateral movement analysis".into(),
                ))
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

        let logs_table = self.table_names.read("logs");
        let start_str = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let end_str = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f").to_string();

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
                ("lower(user) = lower(?)".to_string(), vec![user.clone()])
            } else if frontier_hosts.is_empty() {
                break;
            } else {
                build_host_clause(&frontier_hosts)
            };

            // Build bind values: timestamp range + entity clause binds
            let mut base_binds = vec![start_str.clone(), end_str.clone()];
            base_binds.extend(entity_binds.iter().cloned());

            // Query each method type
            if lateral_info.methods.contains(&LateralMethod::Auth) {
                let auth_sql = format!(
                    r#"SELECT {LATERAL_COLUMNS}
                    FROM {logs_table}
                    PREWHERE timestamp BETWEEN ? AND ?
                        AND ({entity_clause})
                    WHERE auth_type != '' OR auth_result != ''
                        OR position(lower(action), 'login') > 0
                        OR position(lower(action), 'logon') > 0
                        OR lower(source_type) LIKE '%auth%'
                    ORDER BY timestamp ASC
                    LIMIT {MAX_EVENTS_PER_HOP}"#
                );

                let events = self
                    .execute_lateral_query(clickhouse, &auth_sql, &base_binds)
                    .await;
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
                        let (clause, binds) = build_host_clause(&combined_hosts);
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
                let network_sql = format!(
                    r#"SELECT {LATERAL_COLUMNS}
                    FROM {logs_table}
                    PREWHERE timestamp BETWEEN ? AND ?
                        AND ({network_clause})
                    WHERE dest_ip != '' AND dest_ip != src_ip
                        AND (dest_port IN (22, 445, 3389, 5985, 5986, 135, 139)
                             OR position(lower(action), 'connection') > 0)
                    ORDER BY timestamp ASC
                    LIMIT {MAX_EVENTS_PER_HOP}"#
                );

                let events = self
                    .execute_lateral_query(clickhouse, &network_sql, &network_binds)
                    .await;
                for event in events {
                    if let Some(edge) = extract_edge(&event, hop, "network") {
                        hop_edges.push(edge);
                    }
                }
            }

            if lateral_info.methods.contains(&LateralMethod::Process) {
                // Look for remote execution tools — require a destination to filter out
                // local process executions (svchost, wermgr, etc.) that aren't lateral movement
                let process_sql = format!(
                    r#"SELECT {LATERAL_COLUMNS}
                    FROM {logs_table}
                    PREWHERE timestamp BETWEEN ? AND ?
                        AND ({entity_clause})
                    WHERE process_name != ''
                        AND (dest_ip != '' OR dest_host != '')
                        AND (position(lower(process_name), 'psexe') > 0
                             OR position(lower(process_name), 'wmic') > 0
                             OR position(lower(process_name), 'winrs') > 0
                             OR position(lower(process_name), 'powershell') > 0
                             OR position(lower(process_name), 'pwsh') > 0
                             OR position(lower(process_name), 'mstsc') > 0
                             OR position(lower(process_name), 'ssh') > 0
                             OR position(lower(process_name), 'schtasks') > 0
                             OR position(lower(process_name), 'sc.exe') > 0
                             OR position(lower(action), 'service') > 0)
                    ORDER BY timestamp ASC
                    LIMIT {MAX_EVENTS_PER_HOP}"#
                );

                let events = self
                    .execute_lateral_query(clickhouse, &process_sql, &base_binds)
                    .await;
                for event in events {
                    if let Some(edge) = extract_edge(&event, hop, "process") {
                        hop_edges.push(edge);
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
        self.resolve_lateral_hostnames(clickhouse, &mut deduped_edges)
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
        let graph_payload =
            build_lateral_graph_payload(&raw_events, &seed_field, &seed_value, &self.pg_pool).await;

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

        // If entity_field is specified, use it directly
        if let Some(ref field) = lateral_info.entity_field {
            if let Some(value) = extract_field_value(results, field) {
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

        for field in &fields_to_try {
            if let Some(value) = extract_field_value(results, field) {
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
    async fn execute_lateral_query(
        &self,
        clickhouse: &clickhouse::Client,
        sql: &str,
        bind_values: &[String],
    ) -> Vec<serde_json::Value> {
        let mut events: Vec<serde_json::Value> = Vec::new();
        let mut query = clickhouse.query(sql);
        for val in bind_values {
            query = query.bind(val);
        }
        let mut cursor = match query.fetch_bytes("JSONEachRow") {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Lateral query failed to start: {}", e);
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
    }

    /// Batch-resolve IP addresses to hostnames using identity_observations.
    /// Fills in empty src_host/dest_host fields where possible.
    async fn resolve_lateral_hostnames(
        &self,
        clickhouse: &clickhouse::Client,
        edges: &mut [LateralEdge],
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
        let sql = format!(
            r#"SELECT ip, hostname
            FROM (
                SELECT ip, hostname,
                    ROW_NUMBER() OVER (PARTITION BY ip ORDER BY source_priority DESC, observed_at DESC) AS rn
                FROM {identity_table}
                WHERE ip IN ({placeholders}) AND hostname != ''
            )
            WHERE rn = 1"#
        );

        let mut ip_to_hostname: HashMap<String, String> = HashMap::new();
        let rows = self.execute_lateral_query(clickhouse, &sql, &ip_vec).await;
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

/// Build a parameterized ClickHouse WHERE clause matching any of the given hosts.
/// Returns (sql_fragment with ? placeholders, bind values).
/// Each IN clause gets its own set of placeholders since ClickHouse binds are positional.
fn build_host_clause(hosts: &HashSet<String>) -> (String, Vec<String>) {
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
    // FQDN-stripped at compare time; IP columns are compared as-is.
    let sql = format!(
        "(splitByChar('.', lower(src_host))[1] IN ({placeholders}) \
         OR splitByChar('.', lower(dest_host))[1] IN ({placeholders}) \
         OR lower(src_ip) IN ({placeholders}) \
         OR lower(dest_ip) IN ({placeholders}))"
    );

    // Repeat values 4 times (once per IN clause)
    let mut bind_values = Vec::with_capacity(host_vec.len() * 4);
    for _ in 0..4 {
        bind_values.extend(host_vec.iter().cloned());
    }

    (sql, bind_values)
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

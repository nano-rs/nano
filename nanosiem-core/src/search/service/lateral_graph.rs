// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lateral graph aggregation — turns the deduped raw lateral edges into the
//! node/edge/critical-path/evidence payload consumed by the redesigned
//! `| lateral` view (NAN-396).
//!
//! Inputs: the per-event edges produced by `build_lateral_view` (already
//! deduped + identity-resolved), plus the seed entity and a Postgres pool for
//! risk fan-out.
//!
//! Outputs: a single `serde_json::Value` attached to the `_lateral_graph`
//! field of the metadata row. The frontend reads it directly.

use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// Raw event fields the aggregator needs from each deduped lateral edge.
/// Mirror of `LateralEdge` in `service/lateral.rs` — kept narrow so this module
/// doesn't depend on the parent's private struct.
#[derive(Debug, Clone)]
pub(crate) struct RawEvent {
    pub timestamp: String,
    pub user: String,
    pub src_host: String,
    pub dest_host: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub dest_port: String,
    pub method: String, // "auth" | "network" | "process"
    pub method_detail: String,
    pub process_name: String,
    pub auth_type: String,
    pub auth_result: String,
}

/// Node in the rendered DAG.
#[derive(Debug, Clone, Serialize)]
struct Node {
    id: String,
    /// "host" | "user" | "ip" | "process"
    #[serde(rename = "type")]
    kind: &'static str,
    hop: u32,
    label: String,
    sub: String,
    /// "critical" | "high" | "medium" | "low"
    band: &'static str,
    /// "seed" | "identity" | "pivot" | "spread" | "tooling" | "crown" | "crown-jewel" | "dead-end" | "edge"
    role: &'static str,
    /// HH:MM (UTC) of the first event involving this node
    #[serde(rename = "firstSeen")]
    first_seen: String,
    /// Number of raw events involving this node
    events: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flags: Vec<String>,
}

/// Aggregated edge between two nodes.
#[derive(Debug, Clone, Serialize)]
struct Edge {
    from: String,
    to: String,
    /// Mockup taxonomy: auth-rdp | auth-smb | auth-kerberos | auth-winrm |
    /// network-smb | network-rdp | network-winrm | network-other |
    /// process-psexec | process-wmic | process-psrem
    method: String,
    detail: String,
    count: u64,
    #[serde(rename = "firstSeen")]
    first_seen: String,
    band: &'static str,
}

/// One row in a node's evidence drawer.
#[derive(Debug, Clone, Serialize)]
struct EvidenceRow {
    at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    user: String,
    #[serde(rename = "logonType", skip_serializing_if = "String::is_empty")]
    logon_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    result: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    peer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    port: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    proto: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    parent: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    cmd: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    host: String,
}

#[derive(Debug, Default, Serialize)]
struct PerNodeEvidence {
    auth: Vec<EvidenceRow>,
    network: Vec<EvidenceRow>,
    process: Vec<EvidenceRow>,
}

const EVIDENCE_PER_TAB: usize = 12;

/// Ceiling on nodes per hop before we prune. Tuned for the SVG renderer: any
/// more than this and the hop column stops being readable — and the JSON
/// payload starts measuring in megabytes.
const MAX_NODES_PER_HOP: usize = 30;

/// Total node ceiling, a secondary guard in case a deep graph spreads
/// pathological breadth across many hops without any single hop breaching
/// `MAX_NODES_PER_HOP`.
const MAX_TOTAL_NODES: usize = 200;

/// Build the full graph payload from deduped lateral events.
///
/// The seed entity's normalized id is whatever flows through from the existing
/// `detect_lateral_seed` call — for hosts that's the lowercased hostname/IP,
/// for users the lowercased username.
pub(crate) async fn build_lateral_graph_payload(
    raw: &[RawEvent],
    seed_field: &str,
    seed_value: &str,
    pg_pool: &PgPool,
) -> serde_json::Value {
    if raw.is_empty() {
        return json!({
            "nodes": [],
            "edges": [],
            "critical_path": [],
            "critical_edges": [],
            "evidence": {},
            "summary": empty_summary(seed_field, seed_value),
        });
    }

    let seed_id = normalize_id(seed_value);
    let seed_kind = if seed_field == "user" { "user" } else { "host" };

    // ─── Stage 1: collect node candidates + raw event references ────────────
    // Each node is keyed by its normalized id. We track per-node:
    //   - kind (host/user/ip/process)
    //   - earliest timestamp seen
    //   - event count
    //   - display label + sub
    let mut node_meta: HashMap<String, NodeMeta> = HashMap::new();
    // Edges keyed by (from, to, method, detail) for aggregation.
    let mut edge_acc: HashMap<EdgeKey, EdgeAcc> = HashMap::new();
    // Evidence buckets per node (capped after collection).
    let mut evidence: HashMap<String, PerNodeEvidence> = HashMap::new();
    // Adjacency for hop BFS (directed: src → dest).
    let mut adjacency: HashMap<String, BTreeSet<String>> = HashMap::new();
    // Users / processes only get a visible satellite edge from their FIRST-
    // seen host — otherwise each subsequent host emits another edge and we
    // end up with "loopback" curves (hop 1 host → hop 1 user where the user
    // was already attached via the seed). Keeps the graph a clean DAG.
    let mut users_attached: HashSet<String> = HashSet::new();

    // Make sure the seed exists even if no events touch it directly (rare but
    // possible — empty result set was handled above).
    ensure_node(
        &mut node_meta,
        &seed_id,
        seed_kind,
        seed_value,
        seed_kind_sub(seed_kind),
        "00:00",
        0,
    );

    for ev in raw {
        // Resolve the host endpoints (host wins over IP — match existing
        // `service/lateral.rs` dedup convention).
        let (src_host_id, src_host_kind, src_label, src_sub) = endpoint_node(&ev.src_host, &ev.src_ip);
        let (dest_host_id, dest_host_kind, dest_label, dest_sub) = endpoint_node(&ev.dest_host, &ev.dest_ip);
        if src_host_id.is_empty() || dest_host_id.is_empty() {
            continue;
        }

        let ts_short = format_hhmm(&ev.timestamp);

        ensure_node(
            &mut node_meta,
            &src_host_id,
            src_host_kind,
            &src_label,
            &src_sub,
            &ts_short,
            1,
        );
        ensure_node(
            &mut node_meta,
            &dest_host_id,
            dest_host_kind,
            &dest_label,
            &dest_sub,
            &ts_short,
            1,
        );

        // Method-detail → mockup-style "method" string ("auth-rdp", etc.).
        let method_full = mockup_method(&ev.method, &ev.method_detail);
        let detail_text = compose_detail(&ev.method, &ev.method_detail, &ev.user, &ev.auth_type);

        // Primary edge: src host → dest host. Captures the actual hop.
        accumulate_edge(
            &mut edge_acc,
            &src_host_id,
            &dest_host_id,
            &method_full,
            &detail_text,
            &ts_short,
        );
        adjacency
            .entry(src_host_id.clone())
            .or_default()
            .insert(dest_host_id.clone());

        // User node: when the user is non-empty, attach as a satellite of the
        // src host (the user is "discovered" at the src). This matches the
        // mockup which shows users (anna.kowalski, hrsvc$) hanging off the
        // host they authenticated at.
        if !ev.user.is_empty() {
            let user_id = normalize_id(&ev.user);
            ensure_node(
                &mut node_meta,
                &user_id,
                "user",
                &ev.user,
                &user_sub(&ev.user),
                &ts_short,
                1,
            );
            // Only emit ONE host→user satellite edge per user — the first
            // host we see them at. Without this, a user that authenticates
            // across the full chain gets an edge from every host, producing
            // same-hop loopback curves that dive below the column.
            if users_attached.insert(user_id.clone()) {
                accumulate_edge(
                    &mut edge_acc,
                    &src_host_id,
                    &user_id,
                    "auth-kerberos",
                    &format!("identity observed · {}", ev.user),
                    &ts_short,
                );
                adjacency
                    .entry(src_host_id.clone())
                    .or_default()
                    .insert(user_id.clone());
            }
        }

        // Process node: only for process-class edges, attach to dest host.
        if ev.method == "process" && !ev.process_name.is_empty() {
            let proc_id = normalize_id(&ev.process_name);
            ensure_node(
                &mut node_meta,
                &proc_id,
                "process",
                &ev.process_name,
                &process_sub(&ev.method_detail),
                &ts_short,
                1,
            );
            accumulate_edge(
                &mut edge_acc,
                &dest_host_id,
                &proc_id,
                &mockup_method("process", &ev.method_detail),
                &format!("{} on {}", ev.process_name, dest_label),
                &ts_short,
            );
            adjacency
                .entry(dest_host_id.clone())
                .or_default()
                .insert(proc_id.clone());
        }

        // ─── Evidence collection ────────────────────────────────────────────
        push_evidence(&mut evidence, &src_host_id, ev, "src", &dest_label);
        push_evidence(&mut evidence, &dest_host_id, ev, "dest", &src_label);
        if !ev.user.is_empty() {
            let user_id = normalize_id(&ev.user);
            push_evidence(&mut evidence, &user_id, ev, "user", &dest_label);
        }
        if ev.method == "process" && !ev.process_name.is_empty() {
            let proc_id = normalize_id(&ev.process_name);
            push_evidence(&mut evidence, &proc_id, ev, "process", &dest_label);
        }
    }

    // ─── Stage 2: hop assignment via BFS from seed ──────────────────────────
    let hops = compute_hops(&seed_id, &adjacency);

    // ─── Stage 3: risk fan-out ──────────────────────────────────────────────
    let risk_map = fetch_risk_for_nodes(pg_pool, node_meta.keys()).await;

    // ─── Stage 4: assemble nodes (band, role, hop) ──────────────────────────
    // Compute per-node degree first for role inference.
    let (in_deg, out_deg) = compute_degrees(&edge_acc);

    let mut nodes: Vec<Node> = Vec::with_capacity(node_meta.len());
    for (id, meta) in &node_meta {
        let hop = hops.get(id).copied().unwrap_or(u32::MAX);
        // Skip nodes that are unreachable from the seed — they're noise
        // (e.g. unrelated activity that happened to share a frontier IP).
        if hop == u32::MAX {
            continue;
        }
        let band = derive_band(meta, risk_map.get(id).copied(), id);
        let role = derive_role(
            id,
            meta.kind,
            *in_deg.get(id).unwrap_or(&0),
            *out_deg.get(id).unwrap_or(&0),
            id == &seed_id,
        );
        nodes.push(Node {
            id: meta.label.clone(), // display id = original casing
            kind: meta.kind,
            hop,
            label: meta.label.clone(),
            sub: meta.sub.clone(),
            band,
            role,
            first_seen: meta.first_seen.clone(),
            events: meta.events,
            flags: derive_flags(id, meta.kind, role, band),
        });
    }
    // Stable display ordering: hop ascending, then band severity, then label.
    nodes.sort_by(|a, b| {
        a.hop
            .cmp(&b.hop)
            .then_with(|| band_rank(b.band).cmp(&band_rank(a.band)))
            .then_with(|| a.label.cmp(&b.label))
    });

    // Build a quick id (display) lookup so edges can reference the same
    // capitalisation the nodes use.
    let id_to_display: HashMap<String, String> = node_meta
        .iter()
        .map(|(k, v)| (k.clone(), v.label.clone()))
        .collect();

    // ─── Stage 5: assemble edges with band ──────────────────────────────────
    let node_band: HashMap<String, &'static str> =
        nodes.iter().map(|n| (normalize_id(&n.id), n.band)).collect();
    let mut edges: Vec<Edge> = edge_acc
        .into_iter()
        .filter_map(|(key, acc)| {
            let from = id_to_display.get(&key.from)?.clone();
            let to = id_to_display.get(&key.to)?.clone();
            // Drop edges where either endpoint was pruned.
            if !node_band.contains_key(&key.from) || !node_band.contains_key(&key.to) {
                return None;
            }
            let band = max_band(
                *node_band.get(&key.from).unwrap_or(&"low"),
                *node_band.get(&key.to).unwrap_or(&"low"),
            );
            Some(Edge {
                from,
                to,
                method: key.method,
                detail: key.detail,
                count: acc.count,
                first_seen: acc.first_seen,
                band,
            })
        })
        .collect();
    edges.sort_by(|a, b| a.first_seen.cmp(&b.first_seen).then(a.from.cmp(&b.from)));

    // ─── Stage 6: critical path BFS — real progression from seed ────────────
    let (critical_path, critical_edges) = compute_critical_path(&seed_id, &nodes, &edges);

    // ─── Stage 6.5: cap graph breadth to protect renderer + payload ─────────
    // Keep the seed and everything on the critical path no matter what, then
    // per hop keep the top N by (band, role, events). The critical-path BFS
    // runs BEFORE pruning so the preserved set is guaranteed to include any
    // crown/critical node the walk actually reached.
    let original_node_count = nodes.len();
    let mut protected: HashSet<String> = HashSet::new();
    protected.insert(seed_id.clone());
    for id in &critical_path {
        protected.insert(normalize_id(id));
    }
    let truncated = prune_graph(&mut nodes, &mut edges, &protected);

    // ─── Stage 7: evidence cap + serialise ──────────────────────────────────
    // Map evidence keys back to display ids and trim to EVIDENCE_PER_TAB.
    let mut evidence_out: BTreeMap<String, PerNodeEvidence> = BTreeMap::new();
    for (id, mut ev) in evidence {
        let display = match id_to_display.get(&id) {
            Some(d) => d.clone(),
            None => continue,
        };
        ev.auth.truncate(EVIDENCE_PER_TAB);
        ev.network.truncate(EVIDENCE_PER_TAB);
        ev.process.truncate(EVIDENCE_PER_TAB);
        evidence_out.insert(display, ev);
    }

    // ─── Stage 8: summary ───────────────────────────────────────────────────
    let max_hop = nodes.iter().map(|n| n.hop).max().unwrap_or(0);
    let reach_critical = nodes.iter().filter(|n| n.band == "critical").count();
    let reach_crown = nodes
        .iter()
        .filter(|n| n.role == "crown" || n.role == "crown-jewel")
        .count();
    let dead_ends = nodes.iter().filter(|n| n.role == "dead-end").count();
    let (window_start, window_end) = window_bounds(raw);

    let summary = json!({
        "seed": { "kind": seed_kind, "id": seed_value },
        "method": "auto",
        "maxHops": max_hop,
        "windowLabel": format!("{} — {} · {}", window_start, window_end, window_duration_label(raw)),
        "windowStart": window_start,
        "windowEnd": window_end,
        "hops": max_hop,
        "nodes": nodes.len(),
        "edges": edges.len(),
        "reachCritical": reach_critical,
        "reachCrown": reach_crown,
        "deadEnds": dead_ends,
        "truncated": truncated,
        "originalNodes": original_node_count,
    });

    json!({
        "nodes": nodes,
        "edges": edges,
        "critical_path": critical_path,
        "critical_edges": critical_edges,
        "evidence": evidence_out,
        "summary": summary,
    })
}

// ─── Internals ───────────────────────────────────────────────────────────────

#[derive(Debug)]
struct NodeMeta {
    kind: &'static str,
    label: String,
    sub: String,
    first_seen: String,
    events: u64,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct EdgeKey {
    from: String,
    to: String,
    method: String,
    detail: String,
}

#[derive(Debug)]
struct EdgeAcc {
    count: u64,
    first_seen: String,
}

fn empty_summary(seed_field: &str, seed_value: &str) -> serde_json::Value {
    let seed_kind = if seed_field == "user" { "user" } else { "host" };
    json!({
        "seed": { "kind": seed_kind, "id": seed_value },
        "method": "auto",
        "maxHops": 0,
        "windowLabel": "",
        "windowStart": "",
        "windowEnd": "",
        "hops": 0,
        "nodes": 0,
        "edges": 0,
        "reachCritical": 0,
        "reachCrown": 0,
        "deadEnds": 0,
    })
}

fn endpoint_node(host: &str, ip: &str) -> (String, &'static str, String, String) {
    if !host.is_empty() {
        (
            normalize_id(host),
            "host",
            host.to_string(),
            host_sub(host),
        )
    } else if !ip.is_empty() {
        (normalize_id(ip), "ip", ip.to_string(), "internal address".to_string())
    } else {
        (String::new(), "host", String::new(), String::new())
    }
}

fn ensure_node(
    map: &mut HashMap<String, NodeMeta>,
    id: &str,
    kind: &'static str,
    label: &str,
    sub: &str,
    ts: &str,
    increment: u64,
) {
    if id.is_empty() {
        return;
    }
    let entry = map.entry(id.to_string()).or_insert_with(|| NodeMeta {
        kind,
        label: label.to_string(),
        sub: sub.to_string(),
        first_seen: ts.to_string(),
        events: 0,
    });
    // Prefer the longer label (FQDN over short, casing-preserved).
    if label.len() > entry.label.len() {
        entry.label = label.to_string();
    }
    if !sub.is_empty() && entry.sub.is_empty() {
        entry.sub = sub.to_string();
    }
    if ts < entry.first_seen.as_str() {
        entry.first_seen = ts.to_string();
    }
    entry.events += increment;
}

fn accumulate_edge(
    edges: &mut HashMap<EdgeKey, EdgeAcc>,
    from: &str,
    to: &str,
    method: &str,
    detail: &str,
    ts: &str,
) {
    if from.is_empty() || to.is_empty() || from == to {
        return;
    }
    let key = EdgeKey {
        from: from.to_string(),
        to: to.to_string(),
        method: method.to_string(),
        detail: detail.to_string(),
    };
    let acc = edges.entry(key).or_insert_with(|| EdgeAcc {
        count: 0,
        first_seen: ts.to_string(),
    });
    acc.count += 1;
    if ts < acc.first_seen.as_str() {
        acc.first_seen = ts.to_string();
    }
}

fn push_evidence(
    evidence: &mut HashMap<String, PerNodeEvidence>,
    node_id: &str,
    ev: &RawEvent,
    perspective: &str,
    counterpart: &str,
) {
    if node_id.is_empty() {
        return;
    }
    let bucket = evidence.entry(node_id.to_string()).or_default();
    let at = format_hhmm(&ev.timestamp);
    match ev.method.as_str() {
        "auth" => {
            if bucket.auth.len() >= EVIDENCE_PER_TAB * 2 {
                return;
            }
            bucket.auth.push(EvidenceRow {
                at,
                user: ev.user.clone(),
                logon_type: ev.auth_type.clone(),
                source: counterpart.to_string(),
                result: ev.auth_result.clone(),
                peer: String::new(),
                port: String::new(),
                proto: String::new(),
                name: String::new(),
                parent: String::new(),
                cmd: String::new(),
                host: String::new(),
            });
        }
        "network" => {
            if bucket.network.len() >= EVIDENCE_PER_TAB * 2 {
                return;
            }
            bucket.network.push(EvidenceRow {
                at,
                user: String::new(),
                logon_type: String::new(),
                source: String::new(),
                result: String::new(),
                peer: counterpart.to_string(),
                port: ev.dest_port.clone(),
                proto: ev.method_detail.clone(),
                name: String::new(),
                parent: String::new(),
                cmd: String::new(),
                host: String::new(),
            });
        }
        "process" => {
            if bucket.process.len() >= EVIDENCE_PER_TAB * 2 {
                return;
            }
            bucket.process.push(EvidenceRow {
                at,
                user: String::new(),
                logon_type: String::new(),
                source: String::new(),
                result: String::new(),
                peer: String::new(),
                port: String::new(),
                proto: String::new(),
                name: ev.process_name.clone(),
                parent: String::new(),
                cmd: String::new(),
                host: counterpart.to_string(),
            });
        }
        _ => {}
    }
    let _ = perspective; // currently unused; kept for future per-perspective tweaks
}

fn compute_hops(seed: &str, adjacency: &HashMap<String, BTreeSet<String>>) -> HashMap<String, u32> {
    let mut hops: HashMap<String, u32> = HashMap::new();
    if seed.is_empty() {
        return hops;
    }
    hops.insert(seed.to_string(), 0);
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(seed.to_string());
    while let Some(node) = queue.pop_front() {
        let cur = hops[&node];
        if let Some(neighbors) = adjacency.get(&node) {
            for n in neighbors {
                if !hops.contains_key(n) {
                    hops.insert(n.clone(), cur + 1);
                    queue.push_back(n.clone());
                }
            }
        }
    }
    hops
}

fn compute_degrees(edges: &HashMap<EdgeKey, EdgeAcc>) -> (HashMap<String, u32>, HashMap<String, u32>) {
    let mut in_deg: HashMap<String, u32> = HashMap::new();
    let mut out_deg: HashMap<String, u32> = HashMap::new();
    for key in edges.keys() {
        *out_deg.entry(key.from.clone()).or_default() += 1;
        *in_deg.entry(key.to.clone()).or_default() += 1;
    }
    (in_deg, out_deg)
}

/// BFS-derived critical path from the seed: at each frontier we pick the
/// highest-band reachable neighbour and follow until we hit a crown or
/// exhaust the graph. The result is the *real* progression of attack severity
/// observed in the data, not a hardcoded chain.
fn compute_critical_path(
    seed: &str,
    nodes: &[Node],
    edges: &[Edge],
) -> (Vec<String>, Vec<[String; 2]>) {
    if seed.is_empty() || nodes.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let band_of: HashMap<String, &'static str> = nodes
        .iter()
        .map(|n| (normalize_id(&n.id), n.band))
        .collect();
    let role_of: HashMap<String, &'static str> = nodes
        .iter()
        .map(|n| (normalize_id(&n.id), n.role))
        .collect();
    let display_of: HashMap<String, String> =
        nodes.iter().map(|n| (normalize_id(&n.id), n.id.clone())).collect();

    // Adjacency keyed by from id (normalized).
    let mut adj: HashMap<String, Vec<&Edge>> = HashMap::new();
    for e in edges {
        adj.entry(normalize_id(&e.from)).or_default().push(e);
    }

    let mut path: Vec<String> = Vec::new();
    let mut path_edges: Vec<[String; 2]> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut current = seed.to_string();
    if let Some(d) = display_of.get(&current) {
        path.push(d.clone());
    } else {
        return (Vec::new(), Vec::new());
    }
    visited.insert(current.clone());

    // Cap to 8 hops so the chain stays readable even on complex graphs.
    for _ in 0..8 {
        let neighbors = match adj.get(&current) {
            Some(n) => n,
            None => break,
        };

        // Pick the best next hop: prefer crown > critical > high > medium > low.
        let mut best: Option<&&Edge> = None;
        let mut best_rank: i32 = i32::MIN;
        for e in neighbors {
            let to_norm = normalize_id(&e.to);
            if visited.contains(&to_norm) {
                continue;
            }
            let role = *role_of.get(&to_norm).unwrap_or(&"edge");
            let band = *band_of.get(&to_norm).unwrap_or(&"low");
            let rank = role_rank(role) * 10 + band_rank(band);
            if rank > best_rank {
                best_rank = rank;
                best = Some(e);
            }
        }

        let chosen = match best {
            Some(c) => c,
            None => break,
        };
        let to_norm = normalize_id(&chosen.to);
        path.push(chosen.to.clone());
        path_edges.push([chosen.from.clone(), chosen.to.clone()]);
        visited.insert(to_norm.clone());
        // Stop once we've reached a crown / crown-jewel — that's the climax.
        if matches!(*role_of.get(&to_norm).unwrap_or(&"edge"), "crown" | "crown-jewel") {
            break;
        }
        current = to_norm;
    }

    // Only surface the chain when it actually traverses a critical-band or
    // crown node — otherwise we'd show a "critical path" that's really just
    // "best-available walk" and contradict the reasoning band's "reached no
    // critical assets" claim. Empty path hides the breadcrumb and the
    // critical-only toggle content.
    let reaches_something_critical = path.iter().skip(1).any(|id| {
        let n = normalize_id(id);
        matches!(*band_of.get(&n).unwrap_or(&"low"), "critical")
            || matches!(
                *role_of.get(&n).unwrap_or(&"edge"),
                "crown" | "crown-jewel"
            )
    });
    if !reaches_something_critical {
        return (Vec::new(), Vec::new());
    }

    (path, path_edges)
}

async fn fetch_risk_for_nodes<'a, I>(pg_pool: &PgPool, ids: I) -> HashMap<String, i32>
where
    I: IntoIterator<Item = &'a String>,
{
    let entities: Vec<String> = ids.into_iter().cloned().collect();
    if entities.is_empty() {
        return HashMap::new();
    }
    // entity_risk_scores stores `entity` verbatim from the firing rule
    // (arbitrary casing, may be FQDN). Our graph keys are `normalize_id`'d
    // (lowercased + FQDN-stripped), so a direct `entity = ANY($1)` silently
    // misses the majority of real risk rows. Match on both the raw lowered
    // form and the FQDN-stripped short form so either style of stored
    // entity still lights up the node's band.
    // Read the DECAYED score (maintained by the enterprise RiskDecayScheduler,
    // NAN-1675), not the cumulative accumulator — so node bands match the Risk
    // page's decayed view. It's a plain PG column, so core reads it without
    // reaching into the enterprise decay computation.
    let rows: Result<Vec<(String, i32)>, sqlx::Error> = sqlx::query_as(
        r#"
        SELECT entity, MAX(decayed_score)::int4
        FROM entity_risk_scores
        WHERE lower(entity) = ANY($1)
           OR lower(split_part(entity, '.', 1)) = ANY($1)
        GROUP BY entity
        "#,
    )
    .bind(&entities)
    .fetch_all(pg_pool)
    .await;

    match rows {
        Ok(r) => r
            .into_iter()
            .map(|(entity, score)| (normalize_id(&entity), score))
            .collect(),
        Err(e) => {
            tracing::warn!(
                subquery = "lateral_graph_risk",
                "lateral graph risk fan-out failed: {}",
                e
            );
            HashMap::new()
        }
    }
}

fn derive_band(_meta: &NodeMeta, risk: Option<i32>, id: &str) -> &'static str {
    // Hostname-derived "always crown" overrides — DC*, krbtgt, ntds.
    let lid = id.to_lowercase();
    if lid.contains("krbtgt") || lid.contains("ntds") {
        return "critical";
    }
    if lid.starts_with("dc0") || lid.starts_with("dc-") || lid == "dc" {
        return "critical";
    }
    match risk.unwrap_or(0) {
        s if s >= 80 => "critical",
        s if s >= 60 => "high",
        s if s >= 30 => "medium",
        _ => "low",
    }
}

fn derive_role(
    id: &str,
    kind: &'static str,
    in_deg: u32,
    out_deg: u32,
    is_seed: bool,
) -> &'static str {
    if is_seed {
        return "seed";
    }
    let lid = id.to_lowercase();
    // Crown jewels: krbtgt account, ntds.dit
    if lid == "krbtgt" || lid.contains("ntds.dit") {
        return "crown-jewel";
    }
    // Crown: domain controllers
    if (lid.starts_with("dc0") || lid.starts_with("dc-") || lid == "dc")
        && kind == "host"
    {
        return "crown";
    }
    match kind {
        "user" => "identity",
        "process" => "tooling",
        "ip" => "edge",
        _ => {
            if out_deg == 0 && in_deg > 0 {
                "dead-end"
            } else if out_deg >= 2 && in_deg >= 1 {
                "pivot"
            } else {
                "spread"
            }
        }
    }
}

fn derive_flags(
    id: &str,
    kind: &'static str,
    role: &'static str,
    band: &'static str,
) -> Vec<String> {
    let mut flags = Vec::new();
    let lid = id.to_lowercase();
    if role == "crown-jewel" {
        flags.push("golden-ticket-risk".into());
    }
    if role == "crown" && band == "critical" {
        flags.push("ntds-touched".into());
    }
    if kind == "user" && (lid.ends_with('$') || lid.starts_with("svc_") || lid.starts_with("svc-"))
    {
        flags.push("service-account".into());
    }
    flags
}

/// Maps the existing service/lateral.rs method+detail to the mockup's combined
/// "auth-rdp" / "network-smb" / "process-psexec" string.
fn mockup_method(method: &str, detail: &str) -> String {
    let d = detail.to_lowercase();
    match method {
        "auth" => match d.as_str() {
            "rdp" => "auth-rdp".into(),
            "ssh" => "auth-rdp".into(), // group ssh under rdp colour for auth (no auth-ssh in palette)
            "smb" => "auth-smb".into(),
            "kerberos" | "krb" => "auth-kerberos".into(),
            "winrm" => "auth-winrm".into(),
            // ntlm/network/logon → kerberos colour by default (auth-class)
            _ => "auth-kerberos".into(),
        },
        "network" => match d.as_str() {
            "rdp" => "network-rdp".into(),
            "smb" => "network-smb".into(),
            "winrm" => "network-winrm".into(),
            _ => "network-other".into(),
        },
        "process" => match d.as_str() {
            "psexec" => "process-psexec".into(),
            "wmic" => "process-wmic".into(),
            "powershell_remoting" | "winrs" => "process-psrem".into(),
            _ => "process-psrem".into(),
        },
        _ => format!("{}-other", method),
    }
}

fn compose_detail(method: &str, detail: &str, user: &str, auth_type: &str) -> String {
    let base = match method {
        "auth" => {
            if !auth_type.is_empty() {
                format!("{} · {}", detail, auth_type)
            } else {
                detail.to_string()
            }
        }
        "network" => detail.to_string(),
        "process" => detail.to_string(),
        _ => detail.to_string(),
    };
    if !user.is_empty() && method == "auth" {
        format!("{} · as {}", base, user)
    } else {
        base
    }
}

fn host_sub(host: &str) -> String {
    let lower = host.to_lowercase();
    if lower.starts_with("dc0") || lower.starts_with("dc-") {
        "domain controller".into()
    } else if lower.contains("backup") {
        "backup repo".into()
    } else if lower.contains("sql") {
        "database server".into()
    } else if lower.contains("web") {
        "web server".into()
    } else if lower.contains("fs") {
        "file server".into()
    } else if lower.contains("srv") || lower.contains("server") {
        "server".into()
    } else {
        "workstation".into()
    }
}

fn user_sub(user: &str) -> String {
    let lower = user.to_lowercase();
    if lower.ends_with('$') {
        "service account".into()
    } else if lower.starts_with("svc_") || lower.starts_with("svc-") {
        "service account".into()
    } else if lower.starts_with("adm_") || lower.starts_with("admin") {
        "admin · domain".into()
    } else if lower == "krbtgt" {
        "kerberos · tgt".into()
    } else {
        "domain user".into()
    }
}

fn process_sub(detail: &str) -> String {
    match detail.to_lowercase().as_str() {
        "psexec" => "remote service install".into(),
        "wmic" => "wmi remote exec".into(),
        "powershell_remoting" => "ps remoting · iex".into(),
        "winrs" => "winrs · cmd shell".into(),
        _ => "remote exec tool".into(),
    }
}

fn seed_kind_sub(kind: &str) -> &'static str {
    match kind {
        "user" => "domain user",
        _ => "workstation",
    }
}

fn normalize_id(id: &str) -> String {
    let lower = id.to_lowercase();
    // Strip FQDN suffix to merge dl-ws01 and dl-ws01.lab.local — same convention
    // as service/lateral.rs::normalizeHostname.
    if let Some((short, _)) = lower.split_once('.') {
        // …but only for names that look like hostnames (no slashes, no IPs).
        if !short.is_empty() && !short.parse::<std::net::IpAddr>().is_ok() {
            return short.to_string();
        }
    }
    lower
}

/// Prune `nodes` in place so no hop bucket exceeds `MAX_NODES_PER_HOP` and
/// the total stays within `MAX_TOTAL_NODES`. Anything in `protected` (seed +
/// critical-path nodes, keyed by `normalize_id`) is retained unconditionally
/// even if it would otherwise lose the cutoff. `edges` is re-filtered to
/// drop orphans whose endpoints were pruned. Returns `true` if anything was
/// dropped.
fn prune_graph(nodes: &mut Vec<Node>, edges: &mut Vec<Edge>, protected: &HashSet<String>) -> bool {
    let total = nodes.len();
    let hop_overflow = {
        let mut counts: HashMap<u32, usize> = HashMap::new();
        for n in nodes.iter() {
            *counts.entry(n.hop).or_insert(0) += 1;
        }
        counts.values().any(|&c| c > MAX_NODES_PER_HOP)
    };
    if total <= MAX_TOTAL_NODES && !hop_overflow {
        return false;
    }

    // Stage A — per-hop cap. Buckets are processed independently so each
    // hop column stays legible on its own.
    let mut by_hop: BTreeMap<u32, Vec<Node>> = BTreeMap::new();
    for n in nodes.drain(..) {
        by_hop.entry(n.hop).or_default().push(n);
    }
    let mut kept: Vec<Node> = Vec::new();
    for (_hop, bucket) in by_hop {
        let (mut preserved, mut rest): (Vec<_>, Vec<_>) = bucket
            .into_iter()
            .partition(|n| protected.contains(&normalize_id(&n.id)));
        rest.sort_by(|a, b| {
            band_rank(b.band)
                .cmp(&band_rank(a.band))
                .then_with(|| role_rank(b.role).cmp(&role_rank(a.role)))
                .then_with(|| b.events.cmp(&a.events))
                .then_with(|| a.label.cmp(&b.label))
        });
        let per_hop_budget = MAX_NODES_PER_HOP.saturating_sub(preserved.len());
        rest.truncate(per_hop_budget);
        kept.append(&mut preserved);
        kept.append(&mut rest);
    }

    // Stage B — total cap. Only bites when many hops are each at the
    // per-hop cap (e.g. 30 × 7+ hops > 200). Drop lowest-importance
    // non-protected nodes until we're under.
    if kept.len() > MAX_TOTAL_NODES {
        kept.sort_by(|a, b| {
            let ap = protected.contains(&normalize_id(&a.id));
            let bp = protected.contains(&normalize_id(&b.id));
            bp.cmp(&ap) // protected first
                .then_with(|| band_rank(b.band).cmp(&band_rank(a.band)))
                .then_with(|| role_rank(b.role).cmp(&role_rank(a.role)))
                .then_with(|| b.events.cmp(&a.events))
        });
        kept.truncate(MAX_TOTAL_NODES);
    }

    // Restore the display ordering the caller expects (hop asc, band desc,
    // label asc) — matches the sort at the end of Stage 4.
    kept.sort_by(|a, b| {
        a.hop
            .cmp(&b.hop)
            .then_with(|| band_rank(b.band).cmp(&band_rank(a.band)))
            .then_with(|| a.label.cmp(&b.label))
    });
    *nodes = kept;

    // Drop orphan edges.
    let surviving: HashSet<String> = nodes.iter().map(|n| normalize_id(&n.id)).collect();
    edges.retain(|e| {
        surviving.contains(&normalize_id(&e.from)) && surviving.contains(&normalize_id(&e.to))
    });

    nodes.len() < total
}

fn band_rank(band: &str) -> i32 {
    match band {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn role_rank(role: &str) -> i32 {
    match role {
        "crown-jewel" => 5,
        "crown" => 4,
        "pivot" => 3,
        "identity" => 2,
        "tooling" => 2,
        "spread" => 1,
        _ => 0,
    }
}

fn max_band(a: &'static str, b: &'static str) -> &'static str {
    if band_rank(a) >= band_rank(b) {
        a
    } else {
        b
    }
}

fn format_hhmm(ts: &str) -> String {
    // Input formats seen from ClickHouse JSONEachRow:
    //   "2026-04-20 14:32:11.000000"
    //   "2026-04-20T14:32:11Z"
    // We just want HH:MM for the graph chrome.
    let bytes = ts.as_bytes();
    if bytes.len() >= 16 && (bytes[10] == b' ' || bytes[10] == b'T') {
        // chars 11..16 = "HH:MM"
        return ts[11..16].to_string();
    }
    "—".into()
}

fn window_bounds(raw: &[RawEvent]) -> (String, String) {
    let mut min_ts = String::new();
    let mut max_ts = String::new();
    for ev in raw {
        if min_ts.is_empty() || ev.timestamp < min_ts {
            min_ts = ev.timestamp.clone();
        }
        if max_ts.is_empty() || ev.timestamp > max_ts {
            max_ts = ev.timestamp.clone();
        }
    }
    (format_hhmm(&min_ts), format_hhmm(&max_ts))
}

fn window_duration_label(raw: &[RawEvent]) -> String {
    let mut min_ts = String::new();
    let mut max_ts = String::new();
    for ev in raw {
        if min_ts.is_empty() || ev.timestamp < min_ts {
            min_ts = ev.timestamp.clone();
        }
        if max_ts.is_empty() || ev.timestamp > max_ts {
            max_ts = ev.timestamp.clone();
        }
    }
    if min_ts.is_empty() || max_ts.is_empty() {
        return "—".into();
    }
    // Parse as naive (timestamps lack tz); the diff is what we need.
    let parse = |s: &str| -> Option<chrono::NaiveDateTime> {
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ"))
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ"))
            .ok()
    };
    let (a, b) = match (parse(&min_ts), parse(&max_ts)) {
        (Some(a), Some(b)) => (a, b),
        _ => return "—".into(),
    };
    let secs = (b - a).num_seconds().max(0);
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    if h > 0 {
        format!("{}h {}m", h, m)
    } else {
        format!("{}m", m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, hop: u32, band: &'static str, role: &'static str, events: u64) -> Node {
        Node {
            id: id.to_string(),
            kind: "host",
            hop,
            label: id.to_string(),
            sub: String::new(),
            band,
            role,
            first_seen: "00:00".to_string(),
            events,
            flags: Vec::new(),
        }
    }

    fn edge(from: &str, to: &str) -> Edge {
        Edge {
            from: from.to_string(),
            to: to.to_string(),
            method: "auth-kerberos".to_string(),
            detail: String::new(),
            count: 1,
            first_seen: "00:00".to_string(),
            band: "low",
        }
    }

    #[test]
    fn prune_graph_under_cap_is_noop() {
        let mut nodes = vec![
            node("seed", 0, "low", "seed", 10),
            node("a", 1, "low", "edge", 5),
            node("b", 1, "low", "edge", 4),
        ];
        let mut edges = vec![edge("seed", "a"), edge("seed", "b")];
        let protected: HashSet<String> = ["seed".to_string()].into_iter().collect();
        let truncated = prune_graph(&mut nodes, &mut edges, &protected);
        assert!(!truncated);
        assert_eq!(nodes.len(), 3);
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn prune_graph_caps_per_hop_and_drops_orphan_edges() {
        let mut nodes = vec![node("seed", 0, "low", "seed", 100)];
        // Add MAX_NODES_PER_HOP + 5 low-importance hop-1 nodes.
        for i in 0..MAX_NODES_PER_HOP + 5 {
            nodes.push(node(&format!("n{}", i), 1, "low", "edge", (i as u64) + 1));
        }
        // One edge per hop-1 node — all will become orphans if the node is pruned.
        let mut edges: Vec<Edge> = (0..MAX_NODES_PER_HOP + 5)
            .map(|i| edge("seed", &format!("n{}", i)))
            .collect();
        let protected: HashSet<String> = ["seed".to_string()].into_iter().collect();

        let truncated = prune_graph(&mut nodes, &mut edges, &protected);
        assert!(truncated);
        // Seed + exactly MAX_NODES_PER_HOP hop-1 nodes survive.
        assert_eq!(nodes.len(), MAX_NODES_PER_HOP + 1);
        let hop1_count = nodes.iter().filter(|n| n.hop == 1).count();
        assert_eq!(hop1_count, MAX_NODES_PER_HOP);
        // Edges to pruned endpoints must be dropped.
        assert_eq!(edges.len(), MAX_NODES_PER_HOP);
        // Sort prefers higher event count — the highest-indexed nodes should
        // survive since their event count is largest.
        let kept_ids: HashSet<String> = nodes.iter().map(|n| n.id.clone()).collect();
        assert!(kept_ids.contains("n34")); // top of the pack
        assert!(!kept_ids.contains("n0")); // bottom of the pack, pruned
    }

    #[test]
    fn prune_graph_preserves_protected_nodes_even_when_unimportant() {
        let mut nodes = vec![node("seed", 0, "low", "seed", 100)];
        // Add MAX_NODES_PER_HOP high-event-count "popular" nodes…
        for i in 0..MAX_NODES_PER_HOP {
            nodes.push(node(&format!("popular{}", i), 1, "low", "edge", 1_000_000));
        }
        // …plus a low-event-count protected node that would normally lose.
        nodes.push(node("critical-chain", 1, "low", "edge", 1));
        let mut edges = vec![edge("seed", "critical-chain")];

        let protected: HashSet<String> = ["seed".to_string(), "critical-chain".to_string()]
            .into_iter()
            .collect();

        let truncated = prune_graph(&mut nodes, &mut edges, &protected);
        assert!(truncated);
        let kept_ids: HashSet<String> = nodes.iter().map(|n| n.id.clone()).collect();
        // Protected node survives even though it'd have lost on ranking.
        assert!(kept_ids.contains("critical-chain"));
        // One of the popular nodes gets dropped to make room.
        let popular_kept = nodes.iter().filter(|n| n.id.starts_with("popular")).count();
        assert_eq!(popular_kept, MAX_NODES_PER_HOP - 1);
    }
}

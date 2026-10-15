// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::search::query_processing::TreeKeyShape;

/// OCSF fields the parser had nothing to fill commonly carry the literal
/// placeholder `"-"` (or `"--"`) rather than being null/absent. Reject these
/// before admitting a value as a tree node/parent — otherwise `"-"` becomes a
/// plotted node and a catch-all parent. Mirrors the client-side
/// `isPlaceholderValue()` helper and the `value != "-"` filters in
/// `baseline.rs` / `asset_dossier.rs`.
fn is_placeholder_id(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || trimmed == "-" || trimmed == "--"
}

/// Read a (possibly dotted) field off a result row, tolerating BOTH row shapes.
///
/// NAN-2361: a plain `row.get("process.uid")` is a FLAT key lookup. Projected
/// stages (`| table process.uid`, `stats … by`) do return flat dotted keys, so
/// it worked there — but the tree command consumes raw full-event rows, which
/// the lake returns NESTED (`{"process": {"uid": …}}`). Every parent/child id
/// therefore read back empty and the tree rendered with ZERO nodes while still
/// returning HTTP 200 and a correct-looking `_tree_config`. Falls back to
/// walking the dotted path segment by segment, matching the same dual-shape
/// accessor `lake_asset.rs` / `lake_views.rs` / `lake_cloud.rs` each carry.
/// The parent-side twin of the label field (NAN-3059): the child and label
/// fields share a prefix (`process.` in `process.uid` / `process.name`); the
/// same suffix under the parent field's prefix names the parent's label
/// (`actor.process.uid` -> `actor.process.name`; UDM `parent_process_guid` ->
/// `parent_process_name`). `None` when the fields do not line up that way.
pub(crate) fn derived_parent_label_field(child: &str, parent: &str, label: &str) -> Option<String> {
    let prefix = |field: &str| -> Option<usize> { field.rfind(['.', '_']).map(|at| at + 1) };
    let child_prefix = &child[..prefix(child)?];
    let parent_prefix = &parent[..prefix(parent)?];
    let suffix = label.strip_prefix(child_prefix)?;
    (!suffix.is_empty() && parent_prefix != child_prefix)
        .then(|| format!("{parent_prefix}{suffix}"))
}

fn tree_field_exact<'a>(row: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    row.get(path)
        .or_else(|| path.split('.').try_fold(row, |value, part| value.get(part)))
}

fn present(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::String(text) => !is_placeholder_id(text),
        _ => true,
    }
}

/// NAN-3261: the value of one tree candidate. A composite `host+path`
/// candidate joins its parts into a `host/path` key (host lowercased) and is
/// absent unless every part is present.
fn tree_candidate_value(row: &serde_json::Value, candidate: &str) -> Option<serde_json::Value> {
    if !candidate.contains('+') {
        return tree_field_exact(row, candidate).cloned();
    }
    let mut joined = String::new();
    let parts = crate::search::query_processing::tree_candidate_parts(candidate);
    for (index, part) in parts.enumerate() {
        let text = tree_id(tree_field_exact(row, part).filter(|value| present(value)));
        if is_placeholder_id(&text) {
            return None;
        }
        if index == 0 {
            joined.push_str(&text.to_ascii_lowercase());
        } else {
            if !text.starts_with('/') {
                joined.push('/');
            }
            joined.push_str(&text);
        }
    }
    Some(serde_json::Value::String(joined))
}

/// NAN-3257: read a tree field, falling back to the OCSF sibling paths that
/// carry the same concept on other sources (`process.parent_process.uid` for
/// `actor.process.uid`, `dst_endpoint.hostname` for `http_request.url.hostname`,
/// …). UDM fields have no alternates, so this is the plain dual-shape read.
/// Also returns the [`TreeKeyShape`] of the candidate that supplied the value.
fn tree_field_with_shape(
    row: &serde_json::Value,
    path: &str,
) -> Option<(serde_json::Value, TreeKeyShape)> {
    let mut first = None;
    for candidate in crate::search::query_processing::tree_field_candidates(path) {
        if let Some(value) = tree_candidate_value(row, candidate) {
            let shape = crate::search::query_processing::tree_key_shape(candidate);
            if present(&value) {
                return Some((value, shape));
            }
            first.get_or_insert((value, shape));
        }
    }
    first
}

/// The flat `prevalence_*` keys the tree reads node prevalence from, most
/// specific first: hash > domain > dest_ip > url > min. The file hash sits
/// with the other hashes, the same position the stamped fallback gives it.
/// NAN-3451: the lake's narrow tree candidate projects these (when the
/// profile resolves them) so the builder sees them.
pub(crate) const TREE_PREVALENCE_FIELDS: [&str; 9] = [
    "prevalence_process_hash",
    "prevalence_file_hash",
    "prevalence_sha256",
    "prevalence_sha1",
    "prevalence_md5",
    "prevalence_dest_domain",
    "prevalence_dest_ip",
    "prevalence_url",
    "prevalence_min",
];

/// A flat prevalence value: a JSON integer, or one quoted as text.
fn prevalence_number(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

/// NAN-3451: an open-core lake row has no flat `prevalence_*` keys; its
/// ingest-time stamp lives in `enrichments[]`. Read it with the same artifact
/// rules and precedence as the flat keys: the tree's own `prevalence=` field
/// first, then hash > domain > dest_ip > min. Sentinels (N/A, common) are no
/// prevalence, exactly as for the flat keys.
fn stamped_prevalence(row: &serde_json::Value, prevalence_field: Option<&str>) -> Option<i64> {
    use crate::prevalence::stamped::{RowPrevalence, PREVALENCE_COMMON, PREVALENCE_NA};
    let valid = |value: u16| (value != PREVALENCE_NA && value != PREVALENCE_COMMON).then_some(i64::from(value));
    if let Some(value) = prevalence_field.and_then(|field| RowPrevalence::for_field(row, field)) {
        return valid(value);
    }
    let scalars = RowPrevalence::from_stamped_row(row)?;
    valid(scalars.process_hash)
        .or_else(|| valid(scalars.file_hash))
        .or_else(|| valid(scalars.dest_domain))
        .or_else(|| valid(scalars.dest_ip))
        .or_else(|| valid(scalars.min))
}

fn tree_field(row: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    tree_field_with_shape(row, path).map(|(value, _)| value)
}

/// Whether any candidate of `path` carries a real value on this row.
fn tree_field_present(row: &serde_json::Value, path: &str) -> bool {
    tree_field(row, path).is_some_and(|value| present(&value))
}

/// NAN-3261: normalize a parent value to the key shape of the child it links
/// to. A full-URL referrer (`https://app.example.com/dashboard?x=1`) becomes
/// `/dashboard` for a path-only child and `app.example.com/dashboard` for a
/// host+path child; a relative referrer borrows the child's host. Raw keys
/// (process uids, full URLs) are unchanged.
fn normalize_tree_parent_key(value: &str, shape: TreeKeyShape, child_key: &str) -> String {
    if shape == TreeKeyShape::Raw || is_placeholder_id(value) {
        return value.to_string();
    }
    let strip_query = |text: &str| -> String {
        let end = text.find(['?', '#']).unwrap_or(text.len());
        let path = &text[..end];
        if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        }
    };
    let (host, path) = match value.split_once("://") {
        Some((_, rest)) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let authority = &rest[..end];
            let host = authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host);
            (Some(host.to_ascii_lowercase()), strip_query(&rest[end..]))
        }
        None if value.starts_with('/') => (None, strip_query(value)),
        // Scheme-less `host/path` (some proxies log the referrer this way).
        None => {
            let end = value.find(['/', '?', '#']).unwrap_or(value.len());
            (
                Some(value[..end].to_ascii_lowercase()),
                strip_query(&value[end..]),
            )
        }
    };
    match shape {
        TreeKeyShape::Path => path,
        TreeKeyShape::HostPath => {
            let host = host.unwrap_or_else(|| {
                child_key
                    .find('/')
                    .map_or(child_key, |end| &child_key[..end])
                    .to_string()
            });
            format!("{host}{path}")
        }
        TreeKeyShape::Raw => value.to_string(),
    }
}

/// NAN-3261: roots for the components no existing root reaches. Such a
/// component is a cycle of parent links (each node keeps one parent) plus the
/// nodes hanging off it. Its root is the cycle member seen most often (ties:
/// smallest id); its parent link is dropped so it renders at the top. Returns
/// the new roots in a deterministic selection order.
fn break_unrooted_cycles(
    roots: &[String],
    nodes: &std::collections::HashSet<String>,
    parent_of: &mut std::collections::HashMap<String, String>,
    children_of: &std::collections::HashMap<String, std::collections::HashSet<String>>,
    occurrences: &std::collections::HashMap<String, usize>,
) -> Vec<String> {
    use std::collections::HashSet;
    fn reach(
        from: &str,
        children_of: &std::collections::HashMap<String, HashSet<String>>,
        reached: &mut HashSet<String>,
    ) {
        let mut stack = vec![from.to_string()];
        while let Some(id) = stack.pop() {
            if !reached.insert(id.clone()) {
                continue;
            }
            if let Some(children) = children_of.get(&id) {
                stack.extend(children.iter().filter(|c| !reached.contains(*c)).cloned());
            }
        }
    }
    let mut reached = HashSet::new();
    for root in roots {
        reach(root, children_of, &mut reached);
    }
    let count = |id: &String| occurrences.get(id).copied().unwrap_or(0);
    let mut pending = nodes
        .iter()
        .filter(|id| !reached.contains(*id))
        .collect::<Vec<_>>();
    pending.sort_by(|a, b| count(b).cmp(&count(a)).then_with(|| a.cmp(b)));
    let mut new_roots = Vec::new();
    for start in pending {
        if reached.contains(start) {
            continue;
        }
        // Follow parent links until one repeats: that suffix is the cycle.
        let mut walk: Vec<String> = Vec::new();
        let mut current = start.clone();
        let cycle = loop {
            if let Some(at) = walk.iter().position(|id| *id == current) {
                break walk.split_off(at);
            }
            match parent_of.get(&current) {
                Some(parent) if !reached.contains(parent) => {
                    walk.push(current);
                    current = parent.clone();
                }
                // Unreachable for a closed component; root here defensively.
                _ => break vec![current],
            }
        };
        let root = cycle
            .into_iter()
            .min_by(|a, b| count(b).cmp(&count(a)).then_with(|| a.cmp(b)))
            .expect("a cycle has a member");
        parent_of.remove(&root);
        reach(&root, children_of, &mut reached);
        new_roots.push(root);
    }
    new_roots
}

/// NAN-3261: name a field and its alternates for an analyst-facing note.
fn tree_field_description(field: &str) -> String {
    let alternates = crate::search::query_processing::tree_field_alternates(field);
    if alternates.is_empty() {
        field.to_string()
    } else {
        format!("{field} (or {})", alternates.join(", "))
    }
}

/// NAN-3261: why a tree came back without edges. Every empty (or edgeless)
/// tree names the field the events in range did not carry.
fn tree_empty_note(
    tree_info: &TreeCommandInfo,
    rows: usize,
    rows_with_child: usize,
    rows_with_parent: usize,
) -> String {
    let child = tree_field_description(&tree_info.child_field);
    let parent = tree_field_description(&tree_info.parent_field);
    if rows == 0 {
        format!(
            "No events in range carry both {child} and {parent}; a tree needs a child and its parent on the same event."
        )
    } else if rows_with_child == 0 {
        format!("No events in range carry {child}.")
    } else if rows_with_parent == 0 {
        format!("No events in range carry {parent}.")
    } else {
        format!(
            "No events in range link a {child} to a different {parent}; every parent equals its child."
        )
    }
}

/// NAN-3471: the API's rarity rule (`prevalence/lookup.rs`, the
/// `PrevalenceService` row mapping): rare strictly below the threshold.
/// `host_count` is already a valid (positive, non-sentinel) count here.
fn tree_is_rare(host_count: i64, rarity_threshold: u64) -> bool {
    u64::try_from(host_count).is_ok_and(|count| count < rarity_threshold)
}

fn tree_id(value: Option<&serde_json::Value>) -> String {
    value
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .or_else(|| value.and_then(|v| v.as_i64()).map(|n| n.to_string()))
        .or_else(|| value.and_then(|v| v.as_u64()).map(|n| n.to_string()))
        .unwrap_or_default()
}

impl SearchService {
    /// Build tree visualization from flat search results
    ///
    /// This method:
    /// 1. Builds a tree structure based on parent-child relationships
    /// 2. Optionally enriches nodes with prevalence data
    /// 3. Returns results with _display_type and _tree_config metadata
    pub(crate) async fn build_tree_visualization(
        &self,
        results: Vec<serde_json::Value>,
        tree_info: &TreeCommandInfo,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let rarity_threshold = self.tree_rarity_threshold().await;
        Self::assemble_tree_visualization(results, tree_info, rarity_threshold)
    }

    /// NAN-3471: the rarity threshold tree nodes are judged by: the same
    /// effective value every other prevalence read uses. On a lake that is
    /// the live Settings threshold (`RarityThresholdSetting`), falling back to
    /// `NANO_LAKE_PREVALENCE_RARITY_THRESHOLD`; on ClickHouse the
    /// hot-reloaded `PrevalenceService` config. With neither, the Settings
    /// default.
    async fn tree_rarity_threshold(&self) -> u64 {
        if let Some(lookup) = self.prevalence_lookup.as_ref() {
            return lookup.rarity_threshold().await;
        }
        match self.prevalence_service.as_ref() {
            Some(service) => service.rarity_threshold().await,
            None => crate::prevalence::PrevalenceConfig::default().rarity_threshold,
        }
    }

    /// The storage-independent tree assembly behind
    /// [`Self::build_tree_visualization`]; it reads nothing but its rows and
    /// the rarity threshold (`host_count < rarity_threshold` is rare, the
    /// rule every prevalence API applies).
    pub(crate) fn assemble_tree_visualization(
        results: Vec<serde_json::Value>,
        tree_info: &TreeCommandInfo,
        rarity_threshold: u64,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        use serde_json::json;
        use std::collections::{HashMap, HashSet};

        // NAN-3294: a web tree over a source that logs no referrer (conduit
        // proxy) has no parent links at all. Group by client instead of
        // returning an edgeless list.
        if tree_info.preset == Some(crate::query::TreePreset::Web)
            && !results.is_empty()
            && !results.iter().any(|row| tree_field_present(row, &tree_info.parent_field))
            && results.iter().any(|row| tree_field_present(row, &tree_info.child_field))
        {
            return Self::assemble_web_client_tree(results, tree_info, rarity_threshold);
        }

        let start_time = std::time::Instant::now();
        let result_count = results.len();
        tracing::info!(
            "Tree building started: {} events, parent={}, child={}",
            result_count,
            tree_info.parent_field,
            tree_info.child_field
        );

        if results.is_empty() {
            return Ok(vec![json!({
                "_display_type": "tree",
                "_tree_config": {
                    "parent_field": tree_info.parent_field,
                    "child_field": tree_info.child_field,
                    "label_field": tree_info.label_field,
                    "detail_field": tree_info.detail_field,
                    "prevalence_field": tree_info.prevalence_field,
                },
                "_tree_nodes": [],
                "_tree_note": tree_empty_note(tree_info, 0, 0, 0),
            })]);
        }
        let mut rows_with_child = 0usize;
        let mut rows_with_parent = 0usize;

        // Index all nodes by their child_id
        let mut nodes_by_id: HashMap<String, serde_json::Value> = HashMap::new();
        let mut parent_of: HashMap<String, String> = HashMap::new();
        let mut children_of: HashMap<String, HashSet<String>> = HashMap::new();
        let mut all_child_ids: HashSet<String> = HashSet::new();
        let mut all_parent_ids: HashSet<String> = HashSet::new();
        let mut occurrence_counts: HashMap<String, usize> = HashMap::new();
        let mut parent_labels: HashMap<String, serde_json::Value> = HashMap::new();

        // First pass: collect all nodes and relationships
        let index_start = std::time::Instant::now();
        tracing::debug!(
            "Tree building: processing {} results with child_field={}, parent_field={}",
            results.len(),
            tree_info.child_field,
            tree_info.parent_field
        );

        for (idx, row) in results.iter().enumerate() {
            // Debug: log first row's keys to understand structure
            if idx == 0 {
                if let Some(obj) = row.as_object() {
                    tracing::debug!(
                        "Tree building: first row keys: {:?}",
                        obj.keys().collect::<Vec<_>>()
                    );
                    tracing::debug!(
                        "Tree building: looking for child_field '{}' in row",
                        tree_info.child_field
                    );
                    if let Some(val) = obj.get(&tree_info.child_field) {
                        tracing::debug!("Tree building: found child_field value: {:?}", val);
                    } else {
                        tracing::debug!(
                            "Tree building: child_field '{}' NOT found in row",
                            tree_info.child_field
                        );
                    }
                } else {
                    tracing::debug!("Tree building: first row is not an object: {:?}", row);
                }
            }

            let (child_value, child_shape) = tree_field_with_shape(row, &tree_info.child_field)
                .map_or((None, TreeKeyShape::Raw), |(value, shape)| (Some(value), shape));
            let child_id = tree_id(child_value.as_ref());
            rows_with_child += usize::from(!is_placeholder_id(&child_id) && child_id != "0");
            rows_with_parent += usize::from(tree_field_present(row, &tree_info.parent_field));
            // NAN-3257: the parent is the first candidate path (the preset's
            // field, then its OCSF siblings) that names a real, different
            // process/page. Its label comes from the same path's twin.
            // NAN-3261: the parent is normalized to the child's key shape
            // first, so a full-URL referrer links to a path-only child.
            let (parent_id, parent_source) =
                crate::search::query_processing::tree_field_candidates(&tree_info.parent_field)
                    .map(|field| {
                        let raw = tree_id(tree_candidate_value(row, field).as_ref());
                        (normalize_tree_parent_key(&raw, child_shape, &child_id), field)
                    })
                    .find(|(id, _)| !is_placeholder_id(id) && id != "0" && *id != child_id)
                    .unwrap_or_default();

            if idx < 3 {
                tracing::debug!(
                    "Tree building row {}: child_id='{}', parent_id='{}'",
                    idx,
                    child_id,
                    parent_id
                );
            }

            // Skip empty/placeholder ("-") and zero child IDs (process_id=0 is the
            // default for events without a real PID, and would create a garbage
            // catch-all node)
            if !is_placeholder_id(&child_id) && child_id != "0" {
                all_child_ids.insert(child_id.clone());
                nodes_by_id.insert(child_id.clone(), row.clone());
                *occurrence_counts.entry(child_id.clone()).or_insert(0) += 1;

                // Skip self-loops (url == referrer) - these create duplicate tree nodes
                // Also skip parent_id=0 (treat as root node)
                if !is_placeholder_id(&parent_id) && parent_id != "0" && parent_id != child_id {
                    if !parent_labels.contains_key(&parent_id) {
                        let label = derived_parent_label_field(
                            &tree_info.child_field,
                            parent_source,
                            &tree_info.label_field,
                        )
                        .and_then(|field| tree_field_exact(row, &field))
                        .filter(|value| present(value))
                        .cloned();
                        if let Some(label) = label {
                            parent_labels.insert(parent_id.clone(), label);
                        }
                    }
                    all_parent_ids.insert(parent_id.clone());
                    parent_of.insert(child_id.clone(), parent_id.clone());
                    children_of.entry(parent_id).or_default().insert(child_id);
                }
            }
        }

        let unique_edges: usize = children_of.values().map(|v| v.len()).sum();
        tracing::info!(
            "Tree indexing: {} unique nodes, {} unique edges (from {} events) in {:?}",
            all_child_ids.len(),
            unique_edges,
            results.len(),
            index_start.elapsed()
        );

        // NAN-3059: a parent that is referenced but has no row of its own in
        // the result set (a Sysmon child launched in the window by an
        // `explorer.exe` that started days earlier) is still a real node. It
        // used to be dropped, which turned every such child into its own root
        // and rendered a process tree as a flat list with no edges. Synthesize
        // it from the child's row: its label comes from the parent-side twin
        // of the label field (`actor.process.name` for `process.name` under
        // `parent=actor.process.uid child=process.uid`).
        let mut synthesized_parents: HashMap<String, serde_json::Value> = HashMap::new();
        let mut parent_links = parent_of.iter().collect::<Vec<_>>();
        parent_links.sort_by(|left, right| left.0.cmp(right.0));
        for (_child, parent) in parent_links {
            if all_child_ids.contains(parent) || synthesized_parents.contains_key(parent) {
                continue;
            }
            let label = parent_labels
                .get(parent)
                .cloned()
                .unwrap_or_else(|| json!(parent));
            synthesized_parents.insert(
                parent.clone(),
                json!({"id": parent, "label": label, "children": [], "occurrences": 0, "_synthesized": true}),
            );
        }

        // Roots: nodes with no parent, plus the synthesized parents above.
        let mut root_ids: Vec<String> = all_child_ids
            .iter()
            .filter(|id| !parent_of.contains_key(*id))
            .cloned()
            .collect();
        root_ids.extend(synthesized_parents.keys().cloned());
        root_ids.sort();
        // NAN-3261: navigation graphs are cyclic (`/` -> `/dashboard` -> `/`),
        // so every page can have a parent and no node is a root: the live web
        // tree turned 10k edges into ZERO nodes. Give every component no
        // root reaches a root of its own, chosen from its cycle.
        let cycle_roots = break_unrooted_cycles(
            &root_ids,
            &all_child_ids,
            &mut parent_of,
            &children_of,
            &occurrence_counts,
        );
        root_ids.extend(cycle_roots);

        tracing::info!("Tree root nodes: {} identified", root_ids.len());

        // Prevalence is now extracted directly from row data in build_node
        // via inline prevalence_* fields (prevalence_dest_domain, prevalence_min, etc.)
        // from the materialized views - no expensive bulk lookup needed

        // Phase 1: Build flat node map (no children yet) - O(n)
        tracing::info!(
            "Tree building phase 1: creating {} flat nodes...",
            all_child_ids.len()
        );
        let phase1_start = std::time::Instant::now();

        // flat_nodes: id -> node JSON without children (just metadata)
        let mut flat_nodes: HashMap<String, serde_json::Value> = HashMap::new();

        for id in all_child_ids.iter() {
            let row = nodes_by_id.get(id);
            if row.is_none() {
                tracing::warn!(
                    "Tree building: child_id '{}' has no row data (key mismatch?)",
                    id
                );
            }

            let label = row
                .and_then(|r| tree_field(r, &tree_info.label_field))
                .unwrap_or(json!(id));

            let detail = tree_info
                .detail_field
                .as_ref()
                .and_then(|field| row.and_then(|r| tree_field(r, field)));

            // Extract inline prevalence, filtering out sentinel values
            // 65535 = UInt16 max (N/A), 9999 = common/unknown, 255 = UInt8 max
            fn valid_prevalence(v: Option<i64>) -> Option<i64> {
                v.filter(|&x| x > 0 && x != 255 && x != 9999 && x != 65535)
            }

            let prevalence = row.and_then(|r| {
                // The first flat scalar with a real value wins, in
                // `TREE_PREVALENCE_FIELDS` order (most specific first).
                let score = TREE_PREVALENCE_FIELDS
                    .iter()
                    .find_map(|key| valid_prevalence(r.get(*key).and_then(prevalence_number)))
                    .or_else(|| stamped_prevalence(r, tree_info.prevalence_field.as_deref()));

                score.map(|s| json!({"host_count": s, "is_rare": tree_is_rare(s, rarity_threshold)}))
            });

            let mut node = json!({
                "id": id,
                "label": label,
                "children": [],  // Will be filled in phase 2
            });

            if let Some(d) = detail {
                node.as_object_mut()
                    .unwrap()
                    .insert("detail".to_string(), d);
            }
            if let Some(p) = prevalence {
                node.as_object_mut()
                    .unwrap()
                    .insert("prevalence".to_string(), p);
            }
            // Add occurrence count (how many times this URL appeared in the results)
            if let Some(&count) = occurrence_counts.get(id) {
                node.as_object_mut()
                    .unwrap()
                    .insert("occurrences".to_string(), json!(count));
            }
            if let Some(r) = row {
                node.as_object_mut()
                    .unwrap()
                    .insert("_data".to_string(), r.clone());
            }

            flat_nodes.insert(id.clone(), node);
        }
        flat_nodes.extend(synthesized_parents);
        tracing::info!(
            "Tree building phase 1: {} flat nodes in {:?}",
            flat_nodes.len(),
            phase1_start.elapsed()
        );

        // Phase 2: Recursive assembly with depth limit and cycle detection
        // This builds actual tree structure but reuses flat_nodes as base
        tracing::info!(
            "Tree building phase 2: assembling trees for {} roots...",
            root_ids.len()
        );
        let phase2_start = std::time::Instant::now();

        fn assemble_tree(
            id: &str,
            flat_nodes: &HashMap<String, serde_json::Value>,
            children_of: &HashMap<String, HashSet<String>>,
            visited: &mut HashSet<String>,
            expanded: &mut HashSet<String>,
            depth: usize,
            node_count: &mut usize,
        ) -> serde_json::Value {
            const MAX_DEPTH: usize = 15; // Limit tree depth
            const MAX_NODES: usize = 10_000; // Limit total nodes in output

            *node_count += 1;

            // Cycle detection, depth limit, or node limit
            if visited.contains(id) || depth > MAX_DEPTH || *node_count > MAX_NODES {
                return json!({
                    "id": id,
                    "label": id,
                    "children": [],
                    "_truncated": true,
                });
            }
            // Get base node (clone without children)
            let mut node = flat_nodes
                .get(id)
                .cloned()
                .unwrap_or_else(|| json!({"id": id, "label": id, "children": []}));

            // NAN-3261: a node reached by several parents (a page with many
            // referrers) is expanded once; later sightings are leaf
            // references. Without this a dense navigation graph re-expands
            // the same pages down every path until the node cap.
            if !expanded.insert(id.to_string()) {
                if let Some(object) = node.as_object_mut() {
                    object.insert("children".to_string(), json!([]));
                    object.insert("_repeat".to_string(), json!(true));
                }
                return node;
            }
            visited.insert(id.to_string());

            // Build children recursively (stop if we hit node limit)
            if let Some(child_ids) = children_of.get(id) {
                if *node_count <= MAX_NODES {
                    let mut sorted_children = child_ids.iter().collect::<Vec<_>>();
                    sorted_children.sort();
                    let children: Vec<serde_json::Value> = sorted_children
                        .into_iter()
                        .map(|child_id| {
                            assemble_tree(
                                child_id,
                                flat_nodes,
                                children_of,
                                visited,
                                expanded,
                                depth + 1,
                                node_count,
                            )
                        })
                        .collect();
                    node.as_object_mut()
                        .unwrap()
                        .insert("children".to_string(), json!(children));
                }
            }

            visited.remove(id);
            node
        }

        let mut tree_nodes: Vec<serde_json::Value> = Vec::new();
        let mut total_node_count: usize = 0;
        let mut expanded: HashSet<String> = HashSet::new();
        for id in root_ids.iter() {
            let mut visited: HashSet<String> = HashSet::new();
            let node = assemble_tree(
                id,
                &flat_nodes,
                &children_of,
                &mut visited,
                &mut expanded,
                0,
                &mut total_node_count,
            );
            tree_nodes.push(node);
        }
        tracing::info!("Tree building: total {} output nodes", total_node_count);
        tracing::info!(
            "Tree building phase 2: {} root trees in {:?}",
            tree_nodes.len(),
            phase2_start.elapsed()
        );

        // If root_filter is specified, find and extract matching subtrees
        let tree_nodes = if let Some(ref root_pattern) = tree_info.root_filter {
            // Determine if this is a regex pattern (/pattern/) or wildcard pattern
            let is_regex = root_pattern.starts_with('/')
                && root_pattern.ends_with('/')
                && root_pattern.len() > 2;

            // Compile regex if needed, or prepare wildcard matcher
            let regex_matcher: Option<regex::Regex> = if is_regex {
                let regex_pattern = &root_pattern[1..root_pattern.len() - 1];
                // Make regex case-insensitive by default
                match regex::RegexBuilder::new(regex_pattern)
                    .case_insensitive(true)
                    .build()
                {
                    Ok(re) => Some(re),
                    Err(e) => {
                        tracing::warn!("Invalid regex pattern in root filter: {}", e);
                        None
                    }
                }
            } else {
                None
            };

            // Helper to check if a string matches a wildcard pattern
            fn matches_wildcard(text: &str, pattern: &str) -> bool {
                let pattern_lower = pattern.to_lowercase();
                let text_lower = text.to_lowercase();

                if pattern_lower.starts_with('*')
                    && pattern_lower.ends_with('*')
                    && pattern_lower.len() > 1
                {
                    // *contains*
                    let inner = &pattern_lower[1..pattern_lower.len() - 1];
                    text_lower.contains(inner)
                } else if pattern_lower.starts_with('*') {
                    // *endswith
                    let suffix = &pattern_lower[1..];
                    text_lower.ends_with(suffix)
                } else if pattern_lower.ends_with('*') {
                    // startswith*
                    let prefix = &pattern_lower[..pattern_lower.len() - 1];
                    text_lower.starts_with(prefix)
                } else {
                    // exact match (case-insensitive)
                    text_lower == pattern_lower
                }
            }

            // Recursively find nodes matching the root pattern, tracking ancestors
            fn find_matching_subtrees(
                nodes: &[serde_json::Value],
                pattern: &str,
                regex_matcher: &Option<regex::Regex>,
                ancestors: &[serde_json::Value],
            ) -> Vec<serde_json::Value> {
                let mut results = Vec::new();

                for node in nodes {
                    // Check if this node's label matches
                    let label = node.get("label").and_then(|l| l.as_str()).unwrap_or("");

                    let matches = if let Some(re) = regex_matcher {
                        re.is_match(label)
                    } else {
                        matches_wildcard(label, pattern)
                    };

                    if matches {
                        // This node matches - include it with ancestors showing the path here
                        let mut matched_node = node.clone();
                        if !ancestors.is_empty() {
                            // Add ancestors (without their children, just the path)
                            let ancestor_path: Vec<serde_json::Value> = ancestors
                                .iter()
                                .map(|a| {
                                    let mut ancestor = a.clone();
                                    // Remove children from ancestor to keep it lightweight
                                    if let Some(obj) = ancestor.as_object_mut() {
                                        obj.remove("children");
                                    }
                                    ancestor
                                })
                                .collect();
                            if let Some(obj) = matched_node.as_object_mut() {
                                obj.insert(
                                    "_ancestors".to_string(),
                                    serde_json::json!(ancestor_path),
                                );
                            }
                        }
                        results.push(matched_node);
                    } else {
                        // Check children recursively, adding this node to ancestors
                        if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
                            let mut new_ancestors = ancestors.to_vec();
                            new_ancestors.push(node.clone());
                            let matching_children = find_matching_subtrees(
                                children,
                                pattern,
                                regex_matcher,
                                &new_ancestors,
                            );
                            results.extend(matching_children);
                        }
                    }
                }

                results
            }

            find_matching_subtrees(&tree_nodes, root_pattern, &regex_matcher, &[])
        } else {
            tree_nodes
        };

        let elapsed = start_time.elapsed();
        tracing::info!(
            "Tree building completed: {} events -> {} root nodes in {:?}",
            result_count,
            tree_nodes.len(),
            elapsed
        );

        // NAN-3261: an empty or edgeless tree says which field was missing
        // instead of rendering a bare "no nodes".
        let note = if tree_nodes.is_empty() {
            Some(match tree_info.root_filter.as_deref() {
                Some(root) if !flat_nodes.is_empty() => {
                    format!("No tree node label matches root filter {root:?}.")
                }
                _ => tree_empty_note(tree_info, result_count, rows_with_child, rows_with_parent),
            })
        } else if unique_edges == 0 {
            Some(format!(
                "{} {} unconnected nodes shown.",
                tree_empty_note(tree_info, result_count, rows_with_child, rows_with_parent),
                tree_nodes.len()
            ))
        } else {
            None
        };

        // Return a single result with tree metadata
        let mut marker = json!({
            "_display_type": "tree",
            "_tree_config": {
                "parent_field": tree_info.parent_field,
                "child_field": tree_info.child_field,
                "label_field": tree_info.label_field,
                "detail_field": tree_info.detail_field,
                "prevalence_field": tree_info.prevalence_field,
                "root_filter": tree_info.root_filter,
            },
            "_tree_nodes": tree_nodes,
            "_tree_truncated": result_count >= 10000,
        });
        if let (Some(note), Some(object)) = (note, marker.as_object_mut()) {
            object.insert("_tree_note".to_string(), json!(note));
        }
        Ok(vec![marker])
    }
}

/// Synthetic tree columns of the web client layout (NAN-3294).
const WEB_NODE: &str = "_web_node";
const WEB_PARENT: &str = "_web_parent";
const WEB_LABEL: &str = "_web_label";
const WEB_DETAIL: &str = "_web_detail";

/// The client a web request came from: its host when the event names one,
/// else its address.
fn web_client(row: &serde_json::Value) -> String {
    let text = |path: &str| {
        tree_field_exact(row, path)
            .filter(|value| present(value))
            .map(|value| tree_id(Some(value)))
            .filter(|value| !is_placeholder_id(value))
    };
    let host = text("src_endpoint.hostname")
        .or_else(|| text("device.hostname"))
        .or_else(|| text("identity_hostname"));
    let ip = text("src_endpoint.ip");
    match (host, ip) {
        (Some(host), Some(ip)) => format!("{host} ({ip})"),
        (Some(host), None) => host,
        (None, Some(ip)) => ip,
        (None, None) => "unknown client".to_string(),
    }
}

impl SearchService {
    /// NAN-3294: the honest web tree for sources without referrers:
    /// client → domain → URL, each level ordered by first request time
    /// (node ids carry the first-seen time, and the builder sorts children
    /// by id). Built through the ordinary assembler on synthetic edge rows,
    /// so caps, paging and root filters behave exactly as for any tree.
    fn assemble_web_client_tree(
        results: Vec<serde_json::Value>,
        tree_info: &TreeCommandInfo,
        rarity_threshold: u64,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        use serde_json::json;
        use std::collections::HashMap;

        struct Request {
            client: String,
            domain: String,
            url: String,
            time: String,
            row: serde_json::Value,
        }
        let requests = results
            .into_iter()
            .filter_map(|row| {
                let url = tree_id(tree_field(&row, &tree_info.child_field).as_ref());
                if is_placeholder_id(&url) {
                    return None;
                }
                let domain = tree_id(tree_field(&row, &tree_info.label_field).as_ref());
                let domain = if is_placeholder_id(&domain) { "(no host)".to_string() } else { domain.to_ascii_lowercase() };
                let time = tree_id(tree_field_exact(&row, "time"));
                Some(Request { client: web_client(&row), domain, url, time, row })
            })
            .collect::<Vec<_>>();

        fn earliest<'a>(slot: &mut &'a str, time: &'a str) {
            if slot.is_empty() || (!time.is_empty() && time < *slot) {
                *slot = time;
            }
        }
        let mut first_domain: HashMap<(&str, &str), &str> = HashMap::new();
        let mut first_url: HashMap<(&str, &str, &str), &str> = HashMap::new();
        for request in &requests {
            let time = request.time.as_str();
            earliest(first_domain.entry((&request.client, &request.domain)).or_insert(""), time);
            earliest(first_url.entry((&request.client, &request.domain, &request.url)).or_insert(""), time);
        }

        let mut rows = Vec::with_capacity(requests.len() * 3);
        for request in &requests {
            let client_id = format!("client|{}", request.client);
            let domain_seen = first_domain[&(request.client.as_str(), request.domain.as_str())];
            let domain_id = format!("domain|{}|{domain_seen}|{}", request.client, request.domain);
            let url_seen = first_url[&(request.client.as_str(), request.domain.as_str(), request.url.as_str())];
            let url_id = format!("url|{}|{}|{url_seen}|{}", request.client, request.domain, request.url);
            rows.push(json!({WEB_NODE: client_id, WEB_LABEL: request.client, WEB_DETAIL: "client"}));
            rows.push(json!({WEB_NODE: domain_id, WEB_PARENT: client_id, WEB_LABEL: request.domain,
                WEB_DETAIL: format!("first request {domain_seen}")}));
            let mut url_row = request.row.clone();
            if let Some(object) = url_row.as_object_mut() {
                object.insert(WEB_NODE.to_string(), json!(url_id));
                object.insert(WEB_PARENT.to_string(), json!(domain_id));
                object.insert(WEB_LABEL.to_string(), json!(request.url));
                object.insert(WEB_DETAIL.to_string(), json!(format!("first request {url_seen}")));
            }
            rows.push(url_row);
        }

        let layout = TreeCommandInfo {
            parent_field: WEB_PARENT.to_string(),
            child_field: WEB_NODE.to_string(),
            label_field: WEB_LABEL.to_string(),
            detail_field: Some(WEB_DETAIL.to_string()),
            prevalence_field: None,
            root_filter: tree_info.root_filter.clone(),
            preset: None,
        };
        let request_count = requests.len();
        let mut out = Self::assemble_tree_visualization(rows, &layout, rarity_threshold)?;
        if let Some(marker) = out.first_mut().and_then(serde_json::Value::as_object_mut) {
            marker.insert(
                "_tree_config".to_string(),
                json!({
                    "parent_field": tree_info.parent_field,
                    "child_field": tree_info.child_field,
                    "label_field": tree_info.label_field,
                    "detail_field": tree_info.detail_field,
                    "prevalence_field": tree_info.prevalence_field,
                    "root_filter": tree_info.root_filter,
                    "layout": "client_domain_url",
                }),
            );
            marker.insert("_tree_truncated".to_string(), json!(request_count >= 10_000));
            let fallback = format!(
                "No events in range carry {} (this source does not log referrers), so this is not a navigation tree: {request_count} requests are grouped client → domain → URL, each level in order of first request.",
                tree_info.parent_field
            );
            // Keep a root-filter miss, drop the generic edgeless note.
            let note = match marker.get("_tree_note").and_then(serde_json::Value::as_str) {
                Some(existing) if existing.starts_with("No tree node label matches") => format!("{fallback} {existing}"),
                _ => fallback,
            };
            marker.insert("_tree_note".to_string(), json!(note));
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "tree_view_tests.rs"]
mod tree_view_tests;

#[cfg(test)]
#[path = "prevalence_tenant_isolation_tests.rs"]
mod prevalence_tenant_isolation_tests;

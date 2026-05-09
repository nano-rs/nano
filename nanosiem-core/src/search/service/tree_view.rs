// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

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
        use serde_json::json;
        use std::collections::{HashMap, HashSet};

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
            })]);
        }

        // Index all nodes by their child_id
        let mut nodes_by_id: HashMap<String, serde_json::Value> = HashMap::new();
        let mut parent_of: HashMap<String, String> = HashMap::new();
        let mut children_of: HashMap<String, HashSet<String>> = HashMap::new();
        let mut all_child_ids: HashSet<String> = HashSet::new();
        let mut all_parent_ids: HashSet<String> = HashSet::new();
        let mut occurrence_counts: HashMap<String, usize> = HashMap::new();

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

            let child_id = row
                .get(&tree_info.child_field)
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .or_else(|| {
                    row.get(&tree_info.child_field)
                        .and_then(|v| v.as_i64())
                        .map(|n| n.to_string())
                })
                .or_else(|| {
                    row.get(&tree_info.child_field)
                        .and_then(|v| v.as_u64())
                        .map(|n| n.to_string())
                })
                .unwrap_or_default();

            let parent_id = row
                .get(&tree_info.parent_field)
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .or_else(|| {
                    row.get(&tree_info.parent_field)
                        .and_then(|v| v.as_i64())
                        .map(|n| n.to_string())
                })
                .or_else(|| {
                    row.get(&tree_info.parent_field)
                        .and_then(|v| v.as_u64())
                        .map(|n| n.to_string())
                })
                .unwrap_or_default();

            if idx < 3 {
                tracing::debug!(
                    "Tree building row {}: child_id='{}', parent_id='{}'",
                    idx,
                    child_id,
                    parent_id
                );
            }

            // Skip empty and zero child IDs (process_id=0 is the default for events
            // without a real PID, and would create a garbage catch-all node)
            if !child_id.is_empty() && child_id != "0" {
                all_child_ids.insert(child_id.clone());
                nodes_by_id.insert(child_id.clone(), row.clone());
                *occurrence_counts.entry(child_id.clone()).or_insert(0) += 1;

                // Skip self-loops (url == referrer) - these create duplicate tree nodes
                // Also skip parent_id=0 (treat as root node)
                if !parent_id.is_empty() && parent_id != "0" && parent_id != child_id {
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

        // Identify root nodes (nodes with no parent in the result set)
        let root_ids: Vec<String> = all_child_ids
            .iter()
            .filter(|id| match parent_of.get(*id) {
                None => true,
                Some(parent) => !all_child_ids.contains(parent),
            })
            .cloned()
            .collect();

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
                .and_then(|r| r.get(&tree_info.label_field))
                .map(|v| v.clone())
                .unwrap_or(json!(id));

            let detail = tree_info
                .detail_field
                .as_ref()
                .and_then(|field| row.and_then(|r| r.get(field)).cloned());

            // Extract inline prevalence, filtering out sentinel values
            // 65535 = UInt16 max (N/A), 9999 = common/unknown, 255 = UInt8 max
            fn valid_prevalence(v: Option<i64>) -> Option<i64> {
                v.filter(|&x| x > 0 && x != 255 && x != 9999 && x != 65535)
            }

            let prevalence = row.and_then(|r| {
                let prev_domain =
                    valid_prevalence(r.get("prevalence_dest_domain").and_then(|v| v.as_i64()));
                let prev_dest_ip =
                    valid_prevalence(r.get("prevalence_dest_ip").and_then(|v| v.as_i64()));
                let prev_url = valid_prevalence(r.get("prevalence_url").and_then(|v| v.as_i64()));
                let prev_hash =
                    valid_prevalence(r.get("prevalence_process_hash").and_then(|v| v.as_i64()));
                let prev_sha256 =
                    valid_prevalence(r.get("prevalence_sha256").and_then(|v| v.as_i64()));
                let prev_sha1 = valid_prevalence(r.get("prevalence_sha1").and_then(|v| v.as_i64()));
                let prev_md5 = valid_prevalence(r.get("prevalence_md5").and_then(|v| v.as_i64()));
                let prev_min = valid_prevalence(r.get("prevalence_min").and_then(|v| v.as_i64()));

                // Prefer more specific: hash > domain > dest_ip > url > min
                let score = prev_hash
                    .or(prev_sha256)
                    .or(prev_sha1)
                    .or(prev_md5)
                    .or(prev_domain)
                    .or(prev_dest_ip)
                    .or(prev_url)
                    .or(prev_min);

                score.map(|s| json!({"host_count": s, "is_rare": s <= 3}))
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
            visited.insert(id.to_string());

            // Get base node (clone without children)
            let mut node = flat_nodes
                .get(id)
                .cloned()
                .unwrap_or_else(|| json!({"id": id, "label": id, "children": []}));

            // Build children recursively (stop if we hit node limit)
            if let Some(child_ids) = children_of.get(id) {
                if *node_count <= MAX_NODES {
                    let children: Vec<serde_json::Value> = child_ids
                        .iter()
                        .map(|child_id| {
                            assemble_tree(
                                child_id,
                                flat_nodes,
                                children_of,
                                visited,
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
        for id in root_ids.iter() {
            let mut visited: HashSet<String> = HashSet::new();
            let node = assemble_tree(
                id,
                &flat_nodes,
                &children_of,
                &mut visited,
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

        // Return a single result with tree metadata
        Ok(vec![json!({
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
        })])
    }
}

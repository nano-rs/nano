// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2361 — `| tree` field access across BOTH result-row shapes.
//!
//! The tree command consumes raw full-event rows, which the lake returns
//! NESTED (`{"process": {"uid": …}}`), while projected stages (`| table
//! process.uid`, `stats … by`) return FLAT dotted keys. A flat-only
//! `row.get("process.uid")` reads back `None` on every nested row, so every
//! parent/child id came out empty and the tree rendered with ZERO nodes —
//! while still returning HTTP 200 and a correct-looking `_tree_config`. That
//! is the dangerous shape: no error anywhere, just a silently empty tree.

use super::*;
use serde_json::json;

/// The Settings default rarity threshold (`PrevalenceConfig::default`).
const DEFAULT_RARITY: u64 = 3;

/// A realistic canonical-OCSF full event as the lake returns it: nested
/// objects, no flat dotted keys. This is what `tree process` actually gets.
fn nested_ocsf_row() -> serde_json::Value {
    json!({
        "process": {
            "uid": "{01a025a7-9158-78c3-a702-8741cd9fdeab}",
            "name": "MpCmdRun.exe",
            "cmd_line": "\"C:\\\\Program Files\\\\Windows Defender\\\\MpCmdRun.exe\"",
        },
        "actor": {
            "process": { "uid": "{01a025a7-9158-78c3-a702-873e2d92dbf5}" }
        },
        "device": { "hostname": "lt-eng-048.corp.local" },
    })
}

/// The same event as a projected stage returns it: flat dotted keys.
fn flat_projected_row() -> serde_json::Value {
    json!({
        "process.uid": "{01a025a7-9158-78c3-a702-8741cd9fdeab}",
        "process.name": "MpCmdRun.exe",
        "actor.process.uid": "{01a025a7-9158-78c3-a702-873e2d92dbf5}",
    })
}

#[test]
fn tree_field_reads_the_nested_full_event_row() {
    let row = nested_ocsf_row();

    // The exact reads `build_tree_visualization` makes for the `tree process`
    // preset under strict canonical OCSF.
    assert_eq!(
        tree_field(&row, "process.uid").as_ref().and_then(|v| v.as_str()),
        Some("{01a025a7-9158-78c3-a702-8741cd9fdeab}"),
        "child id must resolve on a nested row"
    );
    assert_eq!(
        tree_field(&row, "actor.process.uid").as_ref().and_then(|v| v.as_str()),
        Some("{01a025a7-9158-78c3-a702-873e2d92dbf5}"),
        "parent id must resolve on a nested row"
    );
    assert_eq!(
        tree_field(&row, "process.name").as_ref().and_then(|v| v.as_str()),
        Some("MpCmdRun.exe"),
        "label must resolve on a nested row"
    );
    assert!(
        tree_field(&row, "process.cmd_line").is_some(),
        "detail must resolve on a nested row"
    );
}

#[test]
fn tree_field_still_reads_the_flat_projected_row() {
    // Guards the shape that already worked — the nested fallback must not cost
    // the flat path, or `| table`-fed trees regress.
    let row = flat_projected_row();

    assert_eq!(
        tree_field(&row, "process.uid").as_ref().and_then(|v| v.as_str()),
        Some("{01a025a7-9158-78c3-a702-8741cd9fdeab}")
    );
    assert_eq!(
        tree_field(&row, "actor.process.uid").as_ref().and_then(|v| v.as_str()),
        Some("{01a025a7-9158-78c3-a702-873e2d92dbf5}")
    );
}

#[test]
fn tree_field_returns_none_for_a_genuinely_absent_path() {
    // The fallback walks segments, so it must not invent a value for a path
    // that partially matches (`process` exists, `process.missing` does not).
    let row = nested_ocsf_row();

    assert!(tree_field(&row, "process.missing").is_none());
    assert!(tree_field(&row, "nonexistent.path").is_none());
    assert!(tree_field(&row, "actor.process.pid").is_none());
}

#[test]
fn placeholder_ids_are_rejected_on_either_row_shape() {
    // A `"-"` parent must never become a catch-all node, regardless of shape.
    for row in [
        json!({ "process": { "uid": "-" } }),
        json!({ "process.uid": "-" }),
    ] {
        let value = tree_field(&row, "process.uid")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        assert!(
            is_placeholder_id(&value),
            "placeholder must be rejected: {row}"
        );
    }
}

fn sysmon_launch(child: &str, name: &str, parent: &str, parent_name: &str) -> serde_json::Value {
    json!({
        "process": { "uid": child, "name": name },
        "actor": { "process": { "uid": parent, "name": parent_name } },
        "device": { "hostname": "ws-support-086.corp.local" },
    })
}

/// NAN-3059: a parent referenced by children but launched before the window
/// (no row of its own) is synthesized, labelled from `actor.process.name`, so
/// a one-hour Sysmon tree has edges instead of a flat list of roots.
#[test]
fn tree_synthesizes_parents_launched_before_the_window() {
    let rows = vec![
        sysmon_launch("{c1}", "MpCmdRun.exe", "{explorer}", "explorer.exe"),
        sysmon_launch("{c2}", "cmd.exe", "{explorer}", "explorer.exe"),
        sysmon_launch("{c3}", "whoami.exe", "{c2}", "cmd.exe"),
    ];
    let info = crate::search::query_processing::TreeCommandInfo {
        parent_field: "actor.process.uid".to_string(),
        child_field: "process.uid".to_string(),
        label_field: "process.name".to_string(),
        detail_field: None,
        prevalence_field: None,
        root_filter: None,
        preset: None,
    };
    let out = SearchService::assemble_tree_visualization(rows, &info, DEFAULT_RARITY).unwrap();
    let roots = out[0]["_tree_nodes"].as_array().unwrap();
    assert_eq!(roots.len(), 1, "{roots:?}");
    let root = &roots[0];
    assert_eq!(root["id"], "{explorer}");
    assert_eq!(root["label"], "explorer.exe");
    assert_eq!(root["_synthesized"], true);
    let children = root["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    let cmd = children.iter().find(|c| c["id"] == "{c2}").unwrap();
    assert_eq!(cmd["children"][0]["label"], "whoami.exe");
}

#[test]
fn parent_label_field_is_the_parent_side_twin() {
    assert_eq!(
        derived_parent_label_field("process.uid", "actor.process.uid", "process.name").as_deref(),
        Some("actor.process.name")
    );
    assert_eq!(
        derived_parent_label_field("process_guid", "parent_process_guid", "process_name").as_deref(),
        Some("parent_process_name")
    );
    assert_eq!(derived_parent_label_field("url", "referrer", "url"), None);
}

#[test]
fn repeated_materialization_keeps_root_and_child_page_paths_stable() {
    let info = TreeCommandInfo { parent_field: "parent".into(), child_field: "child".into(), label_field: "label".into(), detail_field: None, prevalence_field: None, root_filter: None, preset: None };
    let rows = (0..80).rev().map(|i| json!({"child": format!("child-{i:03}"), "parent": format!("root-{:03}", i % 3), "label": format!("node-{i}")})).collect::<Vec<_>>();
    let expected = SearchService::assemble_tree_visualization(rows.clone(), &info, DEFAULT_RARITY).unwrap();
    for _ in 0..20 {
        let rebuilt = SearchService::assemble_tree_visualization(rows.clone(), &info, DEFAULT_RARITY).unwrap();
        assert_eq!(rebuilt, expected, "path cursors must remain stable across job-result reconstruction");
    }
    let roots = expected[0]["_tree_nodes"].as_array().unwrap();
    assert_eq!(roots.len(), 3);
    assert_eq!(roots[0]["id"], "root-000");
    assert_eq!(roots[0]["children"][0]["id"], "child-000");
}

#[test]
fn paged_root_filter_keeps_ancestor_paths_and_occurrence_counts() {
    let info = TreeCommandInfo { parent_field: "parent".into(), child_field: "child".into(), label_field: "label".into(), detail_field: None, prevalence_field: None, root_filter: Some("cmd*".into()), preset: None };
    let rows = vec![json!({"child":"root", "parent":"0", "label":"root.exe"}),
        json!({"child":"match", "parent":"root", "label":"cmd.exe"}),
        json!({"child":"match", "parent":"root", "label":"cmd.exe"}),
        json!({"child":"leaf", "parent":"match", "label":"leaf.exe"})];
    let out = SearchService::assemble_tree_visualization(rows, &info, DEFAULT_RARITY).unwrap();
    let root = &out[0]["_tree_nodes"][0];
    assert_eq!(root["id"], "match"); assert_eq!(root["occurrences"], 2);
    assert_eq!(root["_ancestors"][0]["id"], "root");
    assert_eq!(root["children"][0]["id"], "leaf");
}

#[test]
fn reachable_cycles_remain_explicitly_truncated_without_recursive_pages() {
    let info = TreeCommandInfo { parent_field: "parent".into(), child_field: "child".into(), label_field: "label".into(), detail_field: None, prevalence_field: None, root_filter: None, preset: None };
    let rows = vec![json!({"child":"root", "parent":"0", "label":"root"}),
        json!({"child":"a", "parent":"root", "label":"a"}),
        json!({"child":"b", "parent":"a", "label":"b"}),
        json!({"child":"a", "parent":"b", "label":"a"})];
    let out = SearchService::assemble_tree_visualization(rows, &info, DEFAULT_RARITY).unwrap();
    let cycle = &out[0]["_tree_nodes"][0]["children"][0]["children"][0]["children"][0];
    assert_eq!(cycle["id"], "a"); assert_eq!(cycle["_truncated"], true);
    assert_eq!(cycle["children"], json!([]));
}

/// NAN-3257: a process source that nests the parent under the process
/// (`process.parent_process.*`, e.g. osquery / EDR exports) instead of the
/// acting process builds the same tree as one that reports `actor.process.*`.
#[test]
fn process_tree_falls_back_to_parent_process_uid() {
    let info = crate::search::query_processing::TreeCommandInfo {
        parent_field: "actor.process.uid".to_string(),
        child_field: "process.uid".to_string(),
        label_field: "process.name".to_string(),
        detail_field: Some("process.cmd_line".to_string()),
        prevalence_field: None,
        root_filter: None,
        preset: None,
    };
    let rows = vec![
        // Parent nested under the process, flat projected keys.
        json!({"process.uid": "c1", "process.parent_process.uid": "p1", "process.name": "curl",
               "process.parent_process.name": "bash", "process.cmd_line": "curl -s x"}),
        // Actor-shaped source, nested row; the actor wins when present.
        json!({"process": {"uid": "c2", "name": "ls", "parent_process": {"uid": "ignored"}},
               "actor": {"process": {"uid": "p1", "name": "bash"}}}),
        // A self-loop actor falls back to the nested parent.
        json!({"process.uid": "c3", "actor.process.uid": "c3", "process.parent_process.uid": "p1",
               "process.name": "id"}),
    ];
    let out = SearchService::assemble_tree_visualization(rows, &info, DEFAULT_RARITY).unwrap();
    let roots = out[0]["_tree_nodes"].as_array().unwrap();
    assert_eq!(roots.len(), 1, "{roots:?}");
    assert_eq!(roots[0]["id"], "p1");
    assert_eq!(roots[0]["label"], "bash");
    let children = roots[0]["children"].as_array().unwrap();
    let ids = children.iter().map(|node| node["id"].as_str().unwrap()).collect::<Vec<_>>();
    assert_eq!(ids, ["c1", "c2", "c3"]);
    assert_eq!(children[0]["detail"], "curl -s x");
}

/// NAN-3257: a non-proxy HTTP source (web server / WAF / CDN) carrying the
/// host in `dst_endpoint.hostname` and the URL in `url.url_string`.
#[test]
fn web_tree_reads_alternate_http_paths() {
    let info = crate::search::query_processing::TreeCommandInfo {
        parent_field: "http_request.referrer".to_string(),
        child_field: "http_request.url.url_string".to_string(),
        label_field: "http_request.url.hostname".to_string(),
        detail_field: None,
        prevalence_field: None,
        root_filter: None,
        preset: None,
    };
    let rows = vec![
        json!({"url.url_string": "https://a.example/app.js", "http_request.referrer": "https://a.example/",
               "dst_endpoint.hostname": "a.example"}),
        json!({"http_request": {"url": {"url_string": "https://cdn.example/x.css"}, "referrer": "https://a.example/"},
               "url": {"hostname": "cdn.example"}}),
    ];
    let out = SearchService::assemble_tree_visualization(rows, &info, DEFAULT_RARITY).unwrap();
    let roots = out[0]["_tree_nodes"].as_array().unwrap();
    assert_eq!(roots.len(), 1, "{roots:?}");
    assert_eq!(roots[0]["id"], "https://a.example/");
    let children = roots[0]["children"].as_array().unwrap();
    let labels = children.iter().map(|node| node["label"].as_str().unwrap()).collect::<Vec<_>>();
    assert_eq!(labels, ["a.example", "cdn.example"]);
}

fn web_preset_info() -> TreeCommandInfo {
    TreeCommandInfo {
        parent_field: "http_request.referrer".to_string(),
        child_field: "http_request.url.url_string".to_string(),
        label_field: "http_request.url.hostname".to_string(),
        detail_field: None,
        prevalence_field: Some("http_request.url.hostname".to_string()),
        root_filter: None,
        preset: None,
    }
}

/// NAN-3261: an access log that records only the request path (no
/// `url_string`, no `url.hostname`) with full-URL referrers still builds a
/// web tree: the child key is the path, each referrer is normalized to its
/// path, and referrers with no row of their own become synthesized roots.
#[test]
fn web_tree_links_path_only_children_to_full_url_referrers() {
    let rows = vec![
        json!({"http_request": {"url": {"path": "/dashboard", "url_string": null, "hostname": null},
               "referrer": "https://app.example.com/login?next=%2Fdashboard"}}),
        json!({"http_request.url.path": "/settings", "http_request.referrer": "https://app.example.com/dashboard"}),
        json!({"http_request.url.path": "/reports", "http_request.referrer": "https://app.example.com/dashboard#top"}),
        // An external referrer at the site root.
        json!({"http_request.url.path": "/login", "http_request.referrer": "https://github.com/"}),
        // A self-referencing reload is not an edge.
        json!({"http_request.url.path": "/reports", "http_request.referrer": "https://app.example.com/reports"}),
    ];
    let out = SearchService::assemble_tree_visualization(rows, &web_preset_info(), DEFAULT_RARITY).unwrap();
    assert!(out[0].get("_tree_note").is_none(), "{:?}", out[0]["_tree_note"]);
    let roots = out[0]["_tree_nodes"].as_array().unwrap();
    assert_eq!(roots.len(), 1, "{roots:?}");
    let root = &roots[0];
    assert_eq!(root["id"], "/");
    assert_eq!(root["_synthesized"], true);
    let login = &root["children"][0];
    assert_eq!(login["id"], "/login");
    // The label falls back to the path when no hostname is set.
    assert_eq!(login["label"], "/login");
    let dashboard = &login["children"][0];
    assert_eq!(dashboard["id"], "/dashboard");
    let ids = dashboard["children"].as_array().unwrap().iter()
        .map(|node| node["id"].as_str().unwrap()).collect::<Vec<_>>();
    assert_eq!(ids, ["/reports", "/settings"]);
}

/// NAN-3261: when the host and path are both set (but no full URL), the key is
/// `host/path` and a full-URL referrer is matched on host+path, so pages on
/// different hosts with the same path stay distinct.
#[test]
fn web_tree_matches_host_and_path_when_both_are_set() {
    let rows = vec![
        json!({"http_request.url.hostname": "App.Example.com", "http_request.url.path": "/settings",
               "http_request.referrer": "https://app.example.com/dashboard"}),
        json!({"http_request.url.hostname": "app.example.com", "http_request.url.path": "/dashboard",
               "http_request.referrer": "https://other.example/dashboard"}),
        // A relative referrer borrows the child's host.
        json!({"http_request.url.hostname": "app.example.com", "http_request.url.path": "/reports",
               "http_request.referrer": "/dashboard"}),
    ];
    let out = SearchService::assemble_tree_visualization(rows, &web_preset_info(), DEFAULT_RARITY).unwrap();
    let roots = out[0]["_tree_nodes"].as_array().unwrap();
    assert_eq!(roots.len(), 1, "{roots:?}");
    assert_eq!(roots[0]["id"], "other.example/dashboard");
    assert_eq!(roots[0]["_synthesized"], true);
    let dashboard = &roots[0]["children"][0];
    assert_eq!(dashboard["id"], "app.example.com/dashboard");
    assert_eq!(dashboard["label"], "app.example.com");
    let ids = dashboard["children"].as_array().unwrap().iter()
        .map(|node| node["id"].as_str().unwrap()).collect::<Vec<_>>();
    assert_eq!(ids, ["app.example.com/reports", "app.example.com/settings"]);
}

#[test]
fn parent_keys_normalize_to_the_child_shape() {
    use crate::search::query_processing::TreeKeyShape::{HostPath, Path, Raw};
    let url = "https://user@App.Example.com:8443/a/b?q=1#f";
    assert_eq!(normalize_tree_parent_key(url, Raw, "x"), url);
    assert_eq!(normalize_tree_parent_key(url, Path, "/x"), "/a/b");
    assert_eq!(normalize_tree_parent_key(url, HostPath, "h/x"), "app.example.com:8443/a/b");
    assert_eq!(normalize_tree_parent_key("https://github.com", Path, "/x"), "/");
    assert_eq!(normalize_tree_parent_key("/a?x", HostPath, "h.example/x"), "h.example/a");
    assert_eq!(normalize_tree_parent_key("-", Path, "/x"), "-");
}

/// NAN-3261: every empty tree names the field the events did not carry.
#[test]
fn empty_trees_name_the_missing_field() {
    let info = web_preset_info();
    // Nothing matched the edge-filtered candidate fetch.
    let out = SearchService::assemble_tree_visualization(vec![], &info, DEFAULT_RARITY).unwrap();
    let note = out[0]["_tree_note"].as_str().expect("empty tree carries a note");
    assert!(note.contains("http_request.referrer"), "{note}");
    assert!(note.contains("http_request.url.url_string"), "{note}");
    assert_eq!(out[0]["_tree_nodes"], json!([]));

    // Pages but no referrer anywhere: a flat list, and the note names the referrer.
    let rows = vec![
        json!({"http_request.url.url_string": "https://a.example/x"}),
        json!({"http_request.url.url_string": "https://a.example/y", "http_request.referrer": "-"}),
    ];
    let out = SearchService::assemble_tree_visualization(rows, &info, DEFAULT_RARITY).unwrap();
    let note = out[0]["_tree_note"].as_str().expect("edgeless tree carries a note");
    assert!(note.starts_with("No events in range carry http_request.referrer."), "{note}");

    // Referrers but no page field at all: the child field is named.
    let rows = vec![json!({"http_request.referrer": "https://a.example/"})];
    let out = SearchService::assemble_tree_visualization(rows, &info, DEFAULT_RARITY).unwrap();
    assert_eq!(out[0]["_tree_nodes"], json!([]));
    let note = out[0]["_tree_note"].as_str().unwrap();
    assert!(note.starts_with("No events in range carry http_request.url.url_string (or "), "{note}");
    assert!(note.contains("http_request.url.path"), "{note}");

    // A root filter that matches nothing says so.
    let mut filtered = info.clone();
    filtered.root_filter = Some("nomatch*".into());
    let rows = vec![json!({"http_request.url.path": "/b", "http_request.referrer": "https://a.example/a"})];
    let out = SearchService::assemble_tree_visualization(rows, &filtered, DEFAULT_RARITY).unwrap();
    assert!(out[0]["_tree_note"].as_str().unwrap().contains("root filter"));
}

/// One lean `tree web` candidate row exactly as the live search returned it
/// (the load-test tenant, apache_access, 2026-10-08): flat dotted keys, every
/// alternate projected, only `http_request.url.path` and the referrer set.
fn live_apache_candidate_row(path: &str, referrer: &str) -> serde_json::Value {
    json!({
        "dst_endpoint.hostname": null,
        "http_request.referrer": referrer,
        "http_request.url.hostname": null,
        "http_request.url.path": path,
        "http_request.url.url_string": null,
        "time": "2026-10-08 04:24:13.000000",
        "url.hostname": null,
        "url.url_string": null,
    })
}

/// NAN-3261 (live follow-up): the live apache_access edges form cycles once
/// referrers are reduced to paths (`/` <- `/dashboard` <- `/`, `/login` <-
/// `/dashboard`). Every page then had a parent, no node was a root and 10k
/// edges rendered ZERO nodes. Each unrooted component now gets a root from
/// its cycle, and a page with many referrers is expanded once.
#[test]
fn cyclic_live_web_edges_still_build_a_rooted_tree() {
    let edges = [
        ("/api/v1/search", "https://github.com/"),
        ("/index.html", "https://www.google.com/"),
        ("/login", "https://app.example.com/dashboard"),
        ("/api/v1/status", "https://app.example.com/dashboard"),
        ("/reports/weekly", "https://app.example.com/"),
        ("/admin/users", "https://app.example.com/login"),
        ("/contact", "https://app.example.com/login"),
        ("/", "https://www.google.com/"),
        ("/", "https://app.example.com/dashboard"),
        ("/dashboard", "https://app.example.com/"),
        ("/index.html", "https://app.example.com/dashboard"),
        ("/contact", "https://app.example.com/"),
        ("/favicon.ico", "https://app.example.com/"),
        ("/favicon.ico", "https://www.google.com/"),
    ];
    let mut rows = Vec::new();
    for _ in 0..3 {
        rows.extend(edges.iter().map(|(path, referrer)| live_apache_candidate_row(path, referrer)));
    }
    let out = SearchService::assemble_tree_visualization(rows, &web_preset_info(), DEFAULT_RARITY).unwrap();
    let roots = out[0]["_tree_nodes"].as_array().unwrap();
    assert!(!roots.is_empty(), "cyclic web edges must not render an empty tree");

    // Every page appears exactly once as an expanded node; repeats and the
    // edge that closes a cycle back to its root are leaves.
    fn walk(node: &serde_json::Value, expanded: &mut Vec<String>) {
        if node["_repeat"] != true && node["_truncated"] != true {
            expanded.push(node["id"].as_str().unwrap().to_string());
        }
        for child in node["children"].as_array().unwrap() {
            walk(child, expanded);
        }
    }
    let mut expanded = Vec::new();
    roots.iter().for_each(|root| walk(root, &mut expanded));
    let mut unique = expanded.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), expanded.len(), "{expanded:?}");
    for page in ["/", "/dashboard", "/login", "/admin/users", "/api/v1/search", "/favicon.ico"] {
        assert!(expanded.iter().any(|id| id == page), "{page} missing from {expanded:?}");
    }
    assert!(out[0].get("_tree_note").is_none(), "{:?}", out[0]["_tree_note"]);

    // Deterministic for the paged view's child-index cursors.
    let again = SearchService::assemble_tree_visualization(
        edges.iter().cycle().take(edges.len() * 3)
            .map(|(path, referrer)| live_apache_candidate_row(path, referrer)).collect(),
        &web_preset_info(), DEFAULT_RARITY,
    ).unwrap();
    assert_eq!(again, out);
}

fn web_tree_info() -> TreeCommandInfo {
    TreeCommandInfo { preset: Some(crate::query::TreePreset::Web), ..web_preset_info() }
}

/// NAN-3294: conduit_proxy logged no referrer, so `tree web` had no parent
/// links and rendered nothing useful. With the web preset and no referrer
/// on any row, the tree groups client → domain → URL, ordered by first
/// request, and the note says why.
#[test]
fn web_tree_without_referrers_groups_client_domain_url_in_time_order() {
    let row = |time: &str, ip: &str, host: &str, url: &str| {
        json!({"time": time, "src_endpoint": {"ip": ip},
               "http_request": {"url": {"url_string": url, "hostname": host}}})
    };
    let rows = vec![
        row("2026-10-08 12:10:00.000000", "10.1.4.63", "b.example", "https://b.example/x"),
        row("2026-10-08 12:01:00.000000", "10.1.4.63", "a.example", "https://a.example/2"),
        row("2026-10-08 12:00:00.000000", "10.1.4.63", "a.example", "https://a.example/1"),
        row("2026-10-08 12:05:00.000000", "10.1.4.63", "a.example", "https://a.example/1"),
        row("2026-10-08 12:02:00.000000", "10.9.9.9", "a.example", "https://a.example/1"),
    ];
    let out = SearchService::assemble_tree_visualization(rows, &web_tree_info(), DEFAULT_RARITY).unwrap();
    let marker = &out[0];
    assert_eq!(marker["_tree_config"]["layout"], "client_domain_url");
    assert_eq!(marker["_tree_config"]["parent_field"], "http_request.referrer");
    let note = marker["_tree_note"].as_str().unwrap();
    assert!(note.contains("http_request.referrer") && note.contains("client → domain → URL"), "{note}");
    let roots = marker["_tree_nodes"].as_array().unwrap();
    let clients = roots.iter().map(|node| node["label"].as_str().unwrap()).collect::<Vec<_>>();
    assert_eq!(clients, ["10.1.4.63", "10.9.9.9"]);
    let domains = roots[0]["children"].as_array().unwrap();
    assert_eq!(domains.iter().map(|d| d["label"].as_str().unwrap()).collect::<Vec<_>>(), ["a.example", "b.example"],
        "domains in first-request order");
    let urls = domains[0]["children"].as_array().unwrap();
    assert_eq!(urls.iter().map(|u| u["label"].as_str().unwrap()).collect::<Vec<_>>(),
        ["https://a.example/1", "https://a.example/2"], "URLs in first-request order");
    assert_eq!(urls[0]["occurrences"], 2, "repeat requests count on one node");
    assert_eq!(roots[0]["occurrences"], 4, "client counts its requests");
}

/// NAN-3294: once the source sends referrers (conduit `referer`), the web
/// tree is the referrer → URL navigation tree, not the fallback.
#[test]
fn web_tree_with_referrers_keeps_the_navigation_tree() {
    let rows = vec![
        json!({"http_request": {"url": {"url_string": "https://app.example.com/api/search/jobs", "hostname": "app.example.com"},
               "referrer": "https://app.example.com/t/x/search"}, "src_endpoint": {"ip": "192.168.44.72"}}),
        json!({"http_request": {"url": {"url_string": "https://app.example.com/t/x/search", "hostname": "app.example.com"}},
               "src_endpoint": {"ip": "192.168.44.72"}}),
    ];
    let out = SearchService::assemble_tree_visualization(rows, &web_tree_info(), DEFAULT_RARITY).unwrap();
    assert!(out[0]["_tree_config"].get("layout").is_none());
    let roots = out[0]["_tree_nodes"].as_array().unwrap();
    assert_eq!(roots[0]["id"], "https://app.example.com/t/x/search");
    assert_eq!(roots[0]["children"][0]["id"], "https://app.example.com/api/search/jobs");
}

/// NAN-3451: an open-core lake row carries prevalence only in `enrichments[]`.
/// The tree reads it from the `prevalence=` field (the process preset's
/// `process.file.hashes.value`), falls back to the row scalars without one,
/// keeps flat `prevalence_*` keys (lean / ClickHouse) first, and never turns
/// an N/A or common stamp into a count.
#[test]
fn tree_reads_open_core_prevalence_from_enrichments() {
    let rare = "a".repeat(64);
    let common = "b".repeat(64);
    let stamp = |value: &str, hosts: u64, saturated: bool| {
        json!({"name": "prevalence", "provider": "nano", "value": value,
               "data": {"host_count": hosts, "host_count_saturated": saturated}})
    };
    let launch = |child: &str, hash: &str, entries: serde_json::Value| {
        let mut row = sysmon_launch(child, "x.exe", "{explorer}", "explorer.exe");
        row["process"]["file"] = json!({"hashes": [{"algorithm_id": 3, "value": hash}]});
        row["enrichments"] = entries;
        row
    };
    let mut lean = launch("{lean}", &rare, json!([stamp(&rare, 2, false)]));
    lean["prevalence_process_hash"] = json!(7);
    let rows = vec![
        launch("{rare}", &rare, json!([stamp(&rare, 2, false)])),
        launch("{common}", &common, json!([stamp(&common, 1000, true)])),
        launch("{unstamped}", &rare, json!([])),
        lean,
    ];
    let mut info = crate::search::query_processing::TreeCommandInfo {
        parent_field: "actor.process.uid".to_string(),
        child_field: "process.uid".to_string(),
        label_field: "process.name".to_string(),
        detail_field: None,
        prevalence_field: Some("process.file.hashes.value".to_string()),
        root_filter: None,
        preset: None,
    };
    let prevalence_of = |info: &crate::search::query_processing::TreeCommandInfo| {
        let out = SearchService::assemble_tree_visualization(rows.clone(), info, DEFAULT_RARITY).unwrap();
        let children = out[0]["_tree_nodes"][0]["children"].as_array().unwrap().clone();
        let get = move |id: &str| {
            children.iter().find(|c| c["id"] == id).unwrap().get("prevalence").cloned()
        };
        (get("{rare}"), get("{common}"), get("{unstamped}"), get("{lean}"))
    };
    let (rare_node, common_node, unstamped_node, lean_node) = prevalence_of(&info);
    assert_eq!(rare_node, Some(json!({"host_count": 2, "is_rare": true})));
    assert_eq!(common_node, None);
    assert_eq!(unstamped_node, None);
    assert_eq!(lean_node, Some(json!({"host_count": 7, "is_rare": false})));
    // Without a `prevalence=` field the row scalars answer (process hash first).
    info.prevalence_field = None;
    let (rare_node, common_node, _, _) = prevalence_of(&info);
    assert_eq!(rare_node, Some(json!({"host_count": 2, "is_rare": true})));
    assert_eq!(common_node, None);
}

/// NAN-3451 follow-up: on an open-core lake the tree reads the narrow NAN-3257
/// candidate, not full events. Build rows that carry ONLY the columns that
/// candidate projects (flat dotted keys, as a `| table` stage returns them)
/// and check every node still gets its prevalence: from the derived scalars
/// (file hash ranked with the hashes, a quoted integer accepted), and from
/// the `prevalence=` field matched against the projected stamp arrays.
#[test]
fn tree_over_the_projected_lake_candidate_carries_prevalence() {
    use crate::schema::FieldType;
    let inventory = crate::schema::LAKE_PREVALENCE_STAMP_ARRAYS
        .into_iter()
        .chain(["file.hashes.value", "process.file.hashes.value"])
        .map(|name| (name.to_string(), FieldType::Array))
        .chain(
            ["dst_endpoint.ip", "dst_endpoint.hostname", "query.hostname"]
                .into_iter()
                .map(|name| (name.to_string(), FieldType::String)),
        )
        .collect();
    let profile = crate::schema::OcsfProfile::try_lake_1_9_with_snapshot_field_types(inventory).unwrap();
    let query = "nanosmoke | tree parent=actor.user.name child=device.hostname \
                 label=device.hostname prevalence=file.hashes.value";
    let mut parsed = crate::query::parse_query(query).unwrap();
    crate::search::query_processing::apply_profile_product_semantics(&mut parsed, &profile);
    let candidate = crate::search::query_processing::lake_tree_candidate_query(&parsed, &profile)
        .expect("terminal lake tree projects");
    let crate::query::Query::Piped { command: crate::query::Command::Table { fields }, .. } = &candidate else {
        panic!("expected a terminal table");
    };
    let projected: Vec<String> = fields.iter().map(|field| field.name.clone()).collect();

    let rare = "a".repeat(64);
    let stamp_arrays = |value: &str, hosts: u64| {
        json!({
            "enrichments.name": ["prevalence"],
            "enrichments.provider": ["nano"],
            "enrichments.value": [value],
            "enrichments.data.host_count": [hosts.to_string()],
            "enrichments.data.host_count_saturated": [false],
        })
    };
    // Full rows as the lake holds them, flattened; the projection below drops
    // everything the candidate does not name.
    let full = |host: &str, extra: serde_json::Value| {
        let mut row = json!({
            "time": "2026-10-09T00:00:00Z",
            "actor.user.name": "alice",
            "device.hostname": host,
            "message": "not projected",
            "enrichments": "not projected either",
            "prevalence_sha256": 1,
        });
        for (key, value) in extra.as_object().unwrap() {
            row[key] = value.clone();
        }
        row
    };
    let mut via_stamp = full("ws-stamp", json!({
        "file.hashes.value": [rare.to_uppercase()],
        "prevalence_min": 9999,
        "prevalence_file_hash": 65535,
        "prevalence_process_hash": 65535,
        "prevalence_dest_domain": 65535,
        "prevalence_dest_ip": 65535,
    }));
    for (key, value) in stamp_arrays(&rare, 2).as_object().unwrap() {
        via_stamp[key] = value.clone();
    }
    let rows: Vec<serde_json::Value> = [
        full("ws-min", json!({"prevalence_min": "3", "prevalence_dest_ip": 65535})),
        full("ws-file", json!({"prevalence_file_hash": 5, "prevalence_dest_domain": 2, "prevalence_min": 2})),
        full("ws-common", json!({"prevalence_min": 9999, "prevalence_dest_ip": 65535})),
        via_stamp,
    ]
    .into_iter()
    .map(|row| {
        let row = row.as_object().unwrap();
        serde_json::Value::Object(
            row.iter()
                .filter(|(key, _)| projected.iter().any(|name| name == *key))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        )
    })
    .collect();
    assert!(rows.iter().all(|row| row.get("message").is_none() && row.get("enrichments").is_none()));
    assert!(rows.iter().all(|row| row.get("prevalence_sha256").is_none()), "unresolved scalar projected");

    let info = TreeCommandInfo {
        parent_field: "actor.user.name".into(),
        child_field: "device.hostname".into(),
        label_field: "device.hostname".into(),
        detail_field: None,
        prevalence_field: Some("file.hashes.value".into()),
        root_filter: None,
        preset: None,
    };
    let out = SearchService::assemble_tree_visualization(rows, &info, DEFAULT_RARITY).unwrap();
    let roots = out[0]["_tree_nodes"].as_array().unwrap();
    assert_eq!(roots.len(), 1, "{roots:?}");
    assert_eq!(roots[0]["id"], "alice");
    let children = roots[0]["children"].as_array().unwrap();
    let prevalence = |id: &str| {
        children.iter().find(|c| c["id"] == id).unwrap_or_else(|| panic!("{id} missing")).get("prevalence").cloned()
    };
    assert_eq!(prevalence("ws-min"), Some(json!({"host_count": 3, "is_rare": false})));
    // The file hash outranks the domain, as in the stamped fallback.
    assert_eq!(prevalence("ws-file"), Some(json!({"host_count": 5, "is_rare": false})));
    assert_eq!(prevalence("ws-common"), None);
    assert_eq!(prevalence("ws-stamp"), Some(json!({"host_count": 2, "is_rare": true})));
}

/// One-node trees whose node carries `prevalence_min = host_count`.
fn rarity_of(host_count: i64, rarity_threshold: u64) -> serde_json::Value {
    let info = TreeCommandInfo { parent_field: "parent".into(), child_field: "child".into(), label_field: "label".into(), detail_field: None, prevalence_field: None, root_filter: None, preset: None };
    let rows = vec![json!({"child": "c", "parent": "p", "label": "c", "prevalence_min": host_count})];
    let out = SearchService::assemble_tree_visualization(rows, &info, rarity_threshold).unwrap();
    out[0]["_tree_nodes"][0]["children"][0]["prevalence"].clone()
}

/// NAN-3471: `is_rare` follows the Settings rarity threshold with the API's
/// rule (`host_count < threshold`), not a hardcoded `<= 3`.
#[test]
fn tree_is_rare_uses_the_rarity_threshold_strictly() {
    assert_eq!(rarity_of(2, 3), json!({"host_count": 2, "is_rare": true}));
    assert_eq!(rarity_of(3, 3), json!({"host_count": 3, "is_rare": false}));
    assert_eq!(rarity_of(4, 5), json!({"host_count": 4, "is_rare": true}));
    assert_eq!(rarity_of(5, 5), json!({"host_count": 5, "is_rare": false}));
    assert_eq!(rarity_of(1, 1), json!({"host_count": 1, "is_rare": false}));
}

/// NAN-3471: the client → domain → URL web layout judges rarity by the same
/// threshold it was given.
#[test]
fn web_client_tree_passes_the_rarity_threshold_through() {
    let rows = vec![json!({
        "http_request": {"url": {"url_string": "https://a.example/1", "hostname": "a.example"}},
        "src_endpoint": {"ip": "10.0.0.1"},
        "time": "2026-10-09T00:00:00Z",
        "prevalence_dest_domain": 4,
    })];
    let rare = |threshold: u64| {
        let out = SearchService::assemble_tree_visualization(rows.clone(), &web_tree_info(), threshold).unwrap();
        assert_eq!(out[0]["_tree_config"]["layout"], "client_domain_url");
        let url = &out[0]["_tree_nodes"][0]["children"][0]["children"][0];
        url["prevalence"]["is_rare"].clone()
    };
    assert_eq!(rare(5), json!(true));
    assert_eq!(rare(3), json!(false));
}

/// A prevalence lookup whose threshold is the live Settings value.
struct SettingsThreshold(crate::prevalence::RarityThresholdSetting);

#[async_trait::async_trait]
impl crate::prevalence::PrevalenceLookup for SettingsThreshold {
    async fn rarity_threshold(&self) -> u64 {
        self.0.get().unwrap_or(3)
    }

    async fn lookup(
        &self,
        _artifacts: &[String],
        _time_window: crate::prevalence::TimeWindow,
        _scope: &crate::auth::ArtifactScope,
    ) -> Result<Vec<crate::prevalence::PrevalenceData>, crate::prevalence::PrevalenceError> {
        Ok(Vec::new())
    }
}

/// NAN-3471: the service resolves the tree threshold from its prevalence
/// lookup on every build, so a Settings change applies to the next tree.
#[tokio::test]
async fn tree_reads_the_live_settings_threshold() {
    let pool = crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
        "postgres://unused:unused@127.0.0.1:1/nanosiem",
        "http://127.0.0.1:1",
        "nanosiem",
        "unused",
        "nanosiem",
    ))
    .await
    .unwrap();
    let mut service = SearchService::with_dual_pool(&pool);
    // No prevalence wiring at all: the Settings default.
    service.prevalence_lookup = None;
    service.prevalence_service = None;
    assert_eq!(service.tree_rarity_threshold().await, 3);

    let setting = crate::prevalence::RarityThresholdSetting::fixed(3);
    service.set_prevalence_lookup(std::sync::Arc::new(SettingsThreshold(setting.clone())));
    let info = TreeCommandInfo { parent_field: "parent".into(), child_field: "child".into(), label_field: "label".into(), detail_field: None, prevalence_field: None, root_filter: None, preset: None };
    let rows = vec![json!({"child": "c", "parent": "p", "label": "c", "prevalence_min": 4})];
    let is_rare = |out: Vec<serde_json::Value>| out[0]["_tree_nodes"][0]["children"][0]["prevalence"]["is_rare"].clone();
    let out = service.build_tree_visualization(rows.clone(), &info).await.unwrap();
    assert_eq!(is_rare(out), json!(false));
    setting.set(5);
    let out = service.build_tree_visualization(rows, &info).await.unwrap();
    assert_eq!(is_rare(out), json!(true));
}

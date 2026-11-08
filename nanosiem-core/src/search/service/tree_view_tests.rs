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
        tree_field(&row, "process.uid").and_then(|v| v.as_str()),
        Some("{01a025a7-9158-78c3-a702-8741cd9fdeab}"),
        "child id must resolve on a nested row"
    );
    assert_eq!(
        tree_field(&row, "actor.process.uid").and_then(|v| v.as_str()),
        Some("{01a025a7-9158-78c3-a702-873e2d92dbf5}"),
        "parent id must resolve on a nested row"
    );
    assert_eq!(
        tree_field(&row, "process.name").and_then(|v| v.as_str()),
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
        tree_field(&row, "process.uid").and_then(|v| v.as_str()),
        Some("{01a025a7-9158-78c3-a702-8741cd9fdeab}")
    );
    assert_eq!(
        tree_field(&row, "actor.process.uid").and_then(|v| v.as_str()),
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
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            is_placeholder_id(value),
            "placeholder must be rejected: {row}"
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4933 (f6a341e5a / NAN-3466 on clickhouse/dev): a lookup keeps both
//! sides of its join in dev's deterministic grammar
//! `lookup <table> <event_field> [AS <lookup_key>]`, honours `OUTPUT a AS b` /
//! `OUTPUTNEW`, writes outputs under their documented names, and folds keys
//! under CASE_INSENSITIVE.
//!
//! On dev `lookup assets src_endpoint.ip AS ip` collapsed to key `ip` and read
//! the EVENT field `ip` (absent), so every lookup whose event field and table
//! column differ silently enriched nothing; matches were written as
//! `lookup_<column>`, which no documented query or the validator's derived
//! fields named; and `OUTPUTNEW` / `OUTPUT a AS b` did not parse.
use super::{insert_lookup_output, lookup_event_value, merge_lookup_batch};
use crate::query::{parse_query, Command, PrettyPrint, Query};
use crate::search::query_processing::extract_lookup_commands;
use serde_json::json;

fn command(q: &str) -> crate::search::query_processing::LookupCommandInfo {
    extract_lookup_commands(&parse_query(q).unwrap()).remove(0)
}

#[test]
fn the_event_field_comes_first_and_both_sides_are_kept() {
    // No schema-based guessing: computed and custom names keep their order.
    for (q, event, key) in [
        ("* | lookup assets src_endpoint.ip AS ip", "src_endpoint.ip", "ip"),
        ("* | lookup hr employee_id AS id", "employee_id", "id"),
        ("* | eval u=actor.user.name | lookup users u AS user", "u", "user"),
        ("* | lookup threat_intel dst_endpoint.ip as ip", "dst_endpoint.ip", "ip"),
        ("* | lookup users actor.user.name", "actor.user.name", "actor.user.name"),
        // UDM-compat alias as the event side.
        ("* | lookup assets src_ip AS ip", "src_ip", "ip"),
    ] {
        let c = command(q);
        assert_eq!((c.event_field.as_str(), c.key_field.as_str()), (event, key), "{q}");
        let query = parse_query(q).unwrap();
        assert_eq!(parse_query(&query.pretty_print()).unwrap(), query, "{q}");
    }
}

#[test]
fn output_renames_and_outputnew_parse_and_round_trip() {
    for clause in ["OUTPUT", "OUTPUTNEW"] {
        let q = format!("* | lookup assets src_endpoint.ip AS ip {clause} owner AS asset_owner, department CASE_INSENSITIVE");
        let query = parse_query(&q).unwrap();
        let Query::Piped { command: Command::Lookup { output_fields, output_renames, output_new, case_insensitive, .. }, .. } = &query else {
            panic!("lookup")
        };
        assert_eq!(output_fields.as_ref().unwrap(), &["owner", "department"]);
        assert_eq!((output_renames[0].from.as_str(), output_renames[0].to.as_str()), ("owner", "asset_owner"));
        assert_eq!(*output_new, clause == "OUTPUTNEW");
        assert!(*case_insensitive);
        assert_eq!(parse_query(&query.pretty_print()).unwrap(), query, "{}", query.pretty_print());
    }
}

#[test]
fn outputs_are_written_under_their_names_from_the_event_field() {
    let c = command("* | lookup assets src_endpoint.ip AS ip OUTPUT owner AS asset_owner, department");
    let mut row = json!({"src_endpoint.ip": "10.1.1.1"}).as_object().unwrap().clone();
    assert_eq!(lookup_event_value(&row, &c.event_field), Some(json!("10.1.1.1")));
    insert_lookup_output(&mut row, &c, "owner", json!("bob"));
    insert_lookup_output(&mut row, &c, "department", json!("it"));
    assert_eq!(row["asset_owner"], "bob");
    assert_eq!(row["department"], "it");
    assert!(!row.contains_key("lookup_owner") && !row.contains_key("owner"));

    // OUTPUTNEW keeps an existing non-null value.
    let c = command("* | lookup assets src_endpoint.ip AS ip OUTPUTNEW device.hostname");
    let mut row = json!({"src_endpoint.ip": "10.1.1.1", "device.hostname": "kept"}).as_object().unwrap().clone();
    insert_lookup_output(&mut row, &c, "device.hostname", json!("replacement"));
    assert_eq!(row["device.hostname"], "kept");

    // The key column never replaces the parent object of a dotted event field.
    let c = command("* | lookup users user.name AS user");
    let mut row = json!({"user": {"name": "alice"}}).as_object().unwrap().clone();
    assert_eq!(lookup_event_value(&row, &c.event_field), Some(json!("alice")));
    insert_lookup_output(&mut row, &c, "user", json!("alice"));
    assert_eq!(row["user"]["name"], "alice");
}

/// Codex P1: a CASE_INSENSITIVE batch returns the table's spelling (`Admin`);
/// the merge probed it with the event's (`admin`) and wrote null outputs.
#[test]
fn case_insensitive_lookup_merges_across_spellings() {
    let mut batch = crate::lookup::BatchLookupResult {
        results: Default::default(),
        matched_count: 1,
        total_count: 1,
    };
    batch.results.insert(
        "Admin".into(),
        [("dept".to_string(), json!("it"))].into_iter().collect(),
    );
    let c = command("* | lookup users actor.user.name AS user OUTPUT dept CASE_INSENSITIVE");
    let mut rows = vec![json!({"actor.user.name": "admin"}), json!({"actor.user.name": "ADMIN"})];
    merge_lookup_batch(&mut rows, &c, &batch);
    assert_eq!(rows[0]["dept"], "it");
    assert_eq!(rows[1]["dept"], "it");
    // Case-sensitive lookups keep exact matching.
    let c = command("* | lookup users actor.user.name AS user OUTPUT dept");
    let mut rows = vec![json!({"actor.user.name": "admin"})];
    merge_lookup_batch(&mut rows, &c, &batch);
    assert!(rows[0]["dept"].is_null());
}

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

fn owners_batch(with_key: bool) -> crate::lookup::BatchLookupResult {
    let mut batch = crate::lookup::BatchLookupResult {
        results: Default::default(),
        matched_count: 2,
        total_count: 3,
    };
    for (host, owner) in [("ws-01", "team-red"), ("ws-02", "team-blue")] {
        let mut fields: std::collections::HashMap<String, serde_json::Value> =
            [("owner".to_string(), json!(owner))].into_iter().collect();
        if with_key {
            fields.insert("hostname".into(), json!(host));
        }
        batch.results.insert(host.into(), fields);
    }
    batch
}

/// NAN-5694: `lookup owners device.hostname OUTPUT owner` (an OCSF dotted
/// event field, the table key `hostname`) enriches like the bare lookup, in
/// every OUTPUT form, and writes only the named outputs.
#[test]
fn output_clause_enriches_from_an_ocsf_dotted_event_field() {
    let rows = || {
        vec![
            json!({"device.hostname": "ws-01"}),
            json!({"device": {"hostname": "ws-02"}}),
            json!({"device.hostname": "ws-99"}),
        ]
    };
    for (q, target) in [
        ("* | lookup owners device.hostname", "owner"),
        ("* | lookup owners device.hostname OUTPUT owner", "owner"),
        ("* | lookup owners device.hostname OUTPUT owner AS team", "team"),
        ("* | lookup owners device.hostname OUTPUTNEW owner", "owner"),
        ("* | lookup owners device.hostname AS hostname OUTPUT owner", "owner"),
    ] {
        let c = command(q);
        let mut out = rows();
        merge_lookup_batch(&mut out, &c, &owners_batch(true));
        assert_eq!(out[0][target], "team-red", "{q}");
        assert_eq!(out[1][target], "team-blue", "{q}");
        assert!(out[2].get(target).is_none_or(|v| v.is_null()), "{q}");
        if c.output_fields.is_some() {
            // The batch's key column is not an asked-for output.
            assert!(out.iter().all(|r| r.get("hostname").is_none()), "{q}");
        }
    }
}

#[test]
fn output_clause_null_fills_named_columns_the_match_lacks() {
    let c = command("* | lookup owners device.hostname OUTPUT owner, site");
    let mut out = vec![json!({"device.hostname": "ws-01"})];
    merge_lookup_batch(&mut out, &c, &owners_batch(false));
    assert_eq!(out[0]["owner"], "team-red");
    assert!(out[0]["site"].is_null());
}

#[test]
fn outputnew_keeps_existing_values_under_an_ocsf_key() {
    let c = command("* | lookup owners device.hostname OUTPUTNEW owner");
    let mut out = vec![
        json!({"device.hostname": "ws-01", "owner": "kept"}),
        json!({"device.hostname": "ws-02"}),
    ];
    merge_lookup_batch(&mut out, &c, &owners_batch(true));
    assert_eq!(out[0]["owner"], "kept");
    assert_eq!(out[1]["owner"], "team-blue");
}

/// NAN-5714: `eval x="probe-a" | lookup t x AS account OUTPUT …` (an AS-renamed
/// key with an OUTPUT / OUTPUTNEW clause) enriches like the bare form.
#[test]
fn as_renamed_key_with_output_clauses_enriches() {
    let mut batch = crate::lookup::BatchLookupResult { results: Default::default(), matched_count: 1, total_count: 1 };
    batch.results.insert(
        "probe-a".into(),
        [("account", json!("probe-a")), ("owner", json!("finance")), ("dept", json!("fin"))]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    );
    for (clause, expect) in [
        ("", vec![("owner", "finance"), ("dept", "fin")]),
        (" OUTPUT owner", vec![("owner", "finance")]),
        (" OUTPUT owner AS o", vec![("o", "finance")]),
        (" OUTPUTNEW owner", vec![("owner", "finance")]),
        (" OUTPUT owner, dept", vec![("owner", "finance"), ("dept", "fin")]),
    ] {
        let c = command(&format!("* | lookup t x AS account{clause}"));
        assert_eq!((c.event_field.as_str(), c.key_field.as_str()), ("x", "account"));
        let mut rows = vec![json!({"x": "probe-a"})];
        merge_lookup_batch(&mut rows, &c, &batch);
        for (field, value) in &expect {
            assert_eq!(rows[0][*field], *value, "{clause}");
        }
        if c.output_fields.is_some() {
            let obj = rows[0].as_object().unwrap();
            assert_eq!(obj.len(), 1 + expect.len(), "only the listed outputs{clause}: {obj:?}");
        }
    }
}

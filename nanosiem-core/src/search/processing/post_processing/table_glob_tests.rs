// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3333 (ported to clickhouse/dev, NAN-4933): a Nano-side `table` expands
//! globs against the row's columns. On dev `resolve_identity | table time,
//! identity_*` dropped every `identity_*` column: the glob was looked up as a
//! literal field name.
use super::{apply_post_prevalence_commands, table_glob_matches};

#[test]
fn table_wildcards_expand_against_row_columns() {
    let rows = vec![serde_json::json!({
        "time": "2026-10-08 16:30:27",
        "identity_user": "mtaylor",
        "identity_hostname": "ws-it-083",
        "src_endpoint": {"ip": "10.1.7.249", "port": 5555},
        "user": {"name": "x"},
    })];
    let query = crate::query::parse_query("* | table time, identity_*, src_endpoint.*").unwrap();
    let crate::query::Query::Piped { command, .. } = query else { panic!() };
    let out = apply_post_prevalence_commands(rows, &[command]).unwrap().results;
    let row = out[0].as_object().unwrap();
    let mut keys: Vec<&String> = row.keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["identity_hostname", "identity_user", "src_endpoint.ip", "src_endpoint.port", "time"],
        "{row:?}"
    );
    assert!(table_glob_matches("a*b*c", "a-x-b-y-c") && !table_glob_matches("a*b", "ab-c"));
}

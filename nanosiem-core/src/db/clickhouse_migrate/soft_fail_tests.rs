// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4957: which failed migration statements are skipped.

use super::ClickHouseMigrator as M;

#[test]
fn dictionary_ddl_soft_fails_only_on_cloud() {
    for sql in [
        "CREATE DICTIONARY nanosiem.d (k String) PRIMARY KEY k SOURCE(CLICKHOUSE()) LIFETIME(0) LAYOUT(HASHED())",
        "CREATE OR REPLACE DICTIONARY nanosiem.d (k String) PRIMARY KEY k SOURCE(CLICKHOUSE()) LIFETIME(0) LAYOUT(HASHED())",
    ] {
        assert!(M::migration_statement_soft_fails(sql, true), "{sql}");
        assert!(!M::migration_statement_soft_fails(sql, false), "{sql}");
    }
}

#[test]
fn grants_and_revokes_soft_fail_everywhere() {
    for cloud in [true, false] {
        assert!(M::migration_statement_soft_fails("GRANT dictGet ON nanosiem.d TO u", cloud));
        assert!(M::migration_statement_soft_fails("REVOKE dictGet ON nanosiem.d FROM u", cloud));
    }
}

#[test]
fn fatal_marker_overrides_every_soft_fail() {
    let sql = "CREATE OR REPLACE DICTIONARY nanosiem.ip_enrichment_dict /* nano:fatal */ (k String)";
    assert!(!M::migration_statement_soft_fails(sql, true));
    assert!(!M::migration_statement_soft_fails(sql, false));
    assert!(!M::migration_statement_soft_fails("GRANT x ON y TO z /* nano:fatal */", false));
}

#[test]
fn other_statements_are_fatal() {
    assert!(!M::migration_statement_soft_fails("ALTER TABLE nanosiem.logs MODIFY COLUMN x String", true));
    assert!(!M::migration_statement_soft_fails("CREATE TABLE t (x UInt8) ENGINE = Memory", true));
}

/// Migration 185's dictionary statements must all be fatal: a skipped
/// re-issue of ip_enrichment_dict would leave its 1.32 GiB trie resident
/// with 185 recorded as applied.
#[test]
fn migration_185_dictionaries_are_fatal() {
    let sql = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse/185_ip_geo_dict_split.sql"));
    let dicts: Vec<&str> = sql
        .split(";\n")
        .map(str::trim)
        .filter(|s| s.lines().any(|l| l.starts_with("CREATE OR REPLACE DICTIONARY")))
        .collect();
    assert_eq!(dicts.len(), 3);
    for stmt in dicts {
        let body = stmt.lines().skip_while(|l| !l.starts_with("CREATE OR REPLACE DICTIONARY")).collect::<Vec<_>>().join("\n");
        assert!(!M::migration_statement_soft_fails(&body, true), "{body}");
    }
}

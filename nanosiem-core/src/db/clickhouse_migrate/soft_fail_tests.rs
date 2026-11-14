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

/// NAN-5338: the users.d read-only storage error is recognized (logged at
/// INFO, the XML carries the grant); any other GRANT failure is not.
#[test]
fn readonly_access_storage_error_is_recognized() {
    let e = "Code: 495. DB::Exception: Cannot update user `nanosiem_ingest` in users_xml \
             because this storage is readonly. (ACCESS_STORAGE_READONLY)";
    assert!(M::is_readonly_access_storage_error(e));
    assert!(!M::is_readonly_access_storage_error(
        "Code: 497. DB::Exception: nanosiem_admin: Not enough privileges. (ACCESS_DENIED)"
    ));
}

// --- NAN-5387: grants addressed only to users.d XML users are not sent ------

fn set(names: &[&str]) -> std::collections::HashSet<String> {
    names.iter().map(|n| n.to_string()).collect()
}

#[test]
fn grantees_are_read_from_grant_and_revoke() {
    assert_eq!(
        M::access_statement_grantees("GRANT SELECT ON nanosiem.t TO nanosiem_ingest"),
        Some(vec!["nanosiem_ingest".to_string()])
    );
    assert_eq!(
        M::access_statement_grantees("REVOKE dictGet ON nanosiem.d FROM `nanosiem`, \"other_user\""),
        Some(vec!["nanosiem".to_string(), "other_user".to_string()])
    );
    assert_eq!(
        M::access_statement_grantees(
            "GRANT ON CLUSTER 'c' SELECT(database, table) ON system.parts TO nanosiem WITH GRANT OPTION"
        ),
        Some(vec!["nanosiem".to_string()])
    );
    // A column literally named `to` inside the privilege list is not the split.
    assert_eq!(
        M::access_statement_grantees("GRANT SELECT(a, to, b) ON db.t TO u1"),
        Some(vec!["u1".to_string()])
    );
}

#[test]
fn unreadable_grantee_lists_are_not_guessed() {
    for sql in [
        "GRANT SELECT ON db.t TO ALL",
        "GRANT SELECT ON db.t TO CURRENT_USER",
        "GRANT SELECT ON db.t TO ALL EXCEPT u",
        "GRANT SELECT ON db.t TO 'u'@'host'",
        "GRANT SELECT ON db.t",
        "ALTER TABLE t DELETE WHERE 1",
    ] {
        assert_eq!(M::access_statement_grantees(sql), None, "{sql}");
    }
}

#[test]
fn only_all_xml_grantees_skip() {
    let xml = set(&["nanosiem", "nanosiem_ingest"]);
    assert!(M::grants_only_xml_users("GRANT SELECT ON db.t TO nanosiem_ingest", &xml));
    assert!(M::grants_only_xml_users("REVOKE dictGet ON db.d FROM nanosiem, nanosiem_ingest", &xml));
    // A SQL-created grantee (BYOC) still gets the statement.
    assert!(!M::grants_only_xml_users("GRANT SELECT ON db.t TO nanosiem, byoc_user", &xml));
    assert!(!M::grants_only_xml_users("GRANT SELECT ON db.t TO byoc_user", &xml));
    // Unknown XML users (the probe failed): execute as before.
    assert!(!M::grants_only_xml_users("GRANT SELECT ON db.t TO nanosiem", &set(&[])));
    // Not a grant at all.
    assert!(!M::grants_only_xml_users("ALTER TABLE nanosiem DELETE WHERE 1", &xml));
}

/// Every GRANT / REVOKE a shipped migration issues to an XML-defined user is
/// recognised, so none reaches ClickHouse on Compose or Helm.
#[test]
fn every_shipped_xml_user_grant_is_recognised() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let users_xml =
        std::fs::read_to_string(root.join("clickhouse/users.d/nanosiem-users.xml")).unwrap();
    let xml: std::collections::HashSet<String> = regex::Regex::new(r"<(nanosiem[a-z_]*)>")
        .unwrap()
        .captures_iter(&users_xml)
        .map(|c| c[1].to_string())
        .collect();
    assert!(xml.contains("nanosiem_ingest") && xml.contains("nanosiem"), "{xml:?}");
    let mut checked = 0;
    for dir in ["clickhouse", "clickhouse/ocsf/migrations"] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap().flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".sql") || !name.as_bytes()[0].is_ascii_digit() {
                continue;
            }
            let sql = M::strip_sql_line_comments(&std::fs::read_to_string(&path).unwrap())
                .replace("{grant_on_cluster}", "")
                .replace("{clickhouse_runtime_user}", "nanosiem");
            for stmt in sql.split(';').map(str::trim) {
                let upper = stmt.to_ascii_uppercase();
                if !(upper.starts_with("GRANT") || upper.starts_with("REVOKE")) {
                    continue;
                }
                let grantees = M::access_statement_grantees(stmt)
                    .unwrap_or_else(|| panic!("{name}: unreadable grantees in {stmt}"));
                if grantees.iter().all(|g| xml.contains(g)) {
                    assert!(M::grants_only_xml_users(stmt, &xml), "{name}: {stmt}");
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 0, "no XML-user grants found in shipped migrations");
}

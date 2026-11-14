// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5367: the hard-coded default self credentials in migrations 110/112/114
//! are rewritten to the `{clickhouse_self_*}` placeholders at apply time, so a
//! fresh install never loads a prevalence dictionary with the wrong password.

use super::ClickHouseMigrator;

fn numbered_migrations() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../clickhouse");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "sql")
                && p.file_name().unwrap().to_string_lossy().as_bytes()[0].is_ascii_digit()
        })
        .map(|p| (p.file_name().unwrap().to_string_lossy().to_string(), std::fs::read_to_string(&p).unwrap()))
        .collect();
    out.sort();
    out
}

#[test]
fn legacy_literal_becomes_placeholders() {
    let sql = "SOURCE(CLICKHOUSE(\n    HOST 'localhost'\n    PORT 9000\n    USER 'nanosiem'\n    PASSWORD 'nanosiem'\n    DB 'nanosiem'";
    let out = ClickHouseMigrator::rewrite_legacy_self_source_credentials(sql);
    assert_eq!(
        out,
        "SOURCE(CLICKHOUSE(\n    HOST '{clickhouse_self_host}'\n    PORT {clickhouse_self_port}\n    \
         USER '{clickhouse_self_user}'\n    PASSWORD '{clickhouse_self_password}'\n    DB 'nanosiem'"
    );
    // Placeholder sources and unrelated SQL are untouched.
    let modern = "SOURCE(CLICKHOUSE(HOST '{clickhouse_self_host}' PORT {clickhouse_self_port})) USER 'nanosiem'";
    assert_eq!(ClickHouseMigrator::rewrite_legacy_self_source_credentials(modern), modern);
}

#[test]
fn no_numbered_migration_applies_a_hard_coded_self_password() {
    let mut rewritten = 0;
    for (name, sql) in numbered_migrations() {
        let out = ClickHouseMigrator::rewrite_legacy_self_source_credentials(&sql);
        if out != sql {
            rewritten += 1;
        }
        let substituted = ClickHouseMigrator::substitute_clickhouse_self_vars_with(
            &out, "localhost", "9000", "nanosiem", "rotated-secret",
        );
        for block in substituted.split("SOURCE(CLICKHOUSE(").skip(1) {
            let head: String = block.chars().take(400).collect();
            assert!(
                !head.contains("PASSWORD 'nanosiem'"),
                "{name}: a ClickHouse self-source still applies the default password"
            );
        }
    }
    assert!(rewritten >= 3, "110/112/114 should be rewritten (got {rewritten})");
}

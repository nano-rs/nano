// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5470: dictionary-identity placeholder resolution and readiness probe.

use super::dict_source_user::{
    credentials_fingerprint, dictionary_is_stale, readiness_probe_sql, substitute_dict_source_vars,
    DICT_SOURCE_DICTIONARIES, SELF_FINGERPRINT,
    DICT_SOURCE_MIGRATION_FILE,
};
use super::ClickHouseMigrator;

const SOURCE: &str = "SOURCE(CLICKHOUSE(HOST '{clickhouse_self_host}' PORT {clickhouse_self_port} \
                      USER '{clickhouse_dict_user}' PASSWORD '{clickhouse_dict_password}' DB 'nanosiem'))";

#[test]
fn not_ready_falls_back_to_the_self_credentials() {
    let sql = substitute_dict_source_vars(SOURCE, None);
    assert!(sql.contains("USER '{clickhouse_self_user}' PASSWORD '{clickhouse_self_password}'"), "{sql}");
    let resolved =
        ClickHouseMigrator::substitute_clickhouse_self_vars_with(&sql, "localhost", "9000", "nanosiem", "app-pw");
    assert!(resolved.contains("USER 'nanosiem' PASSWORD 'app-pw'"), "{resolved}");
    assert!(!resolved.contains('{'), "{resolved}");
}

#[test]
fn ready_resolves_to_the_dictionary_identity_escaped() {
    let creds = ("nanosiem_dict".to_string(), "p'w\\x".to_string());
    let sql = substitute_dict_source_vars(SOURCE, Some(&creds));
    let resolved =
        ClickHouseMigrator::substitute_clickhouse_self_vars_with(&sql, "localhost", "9000", "nanosiem", "app-pw");
    assert!(resolved.contains("USER 'nanosiem_dict' PASSWORD 'p''w\\\\x'"), "{resolved}");
    assert!(!resolved.contains("app-pw"), "{resolved}");
}

#[test]
fn a_changed_password_or_an_auth_failure_makes_a_dictionary_stale() {
    let current = credentials_fingerprint("nanosiem_dict", "new-password");
    assert_ne!(current, credentials_fingerprint("nanosiem_dict", "old-password"));
    assert!(!current.contains("password"), "{current}");
    assert!(!dictionary_is_stale(&current, "", &current));
    // The old login, init.sql's (no comment) and the fallback are all stale.
    assert!(dictionary_is_stale(&credentials_fingerprint("nanosiem_dict", "old-password"), "", &current));
    assert!(dictionary_is_stale("", "", &current));
    assert!(dictionary_is_stale(SELF_FINGERPRINT, "", &current));
    // A load that failed authenticating, even with the right comment.
    assert!(dictionary_is_stale(
        &current,
        "Code: 516. DB::Exception: nanosiem_dict: Authentication failed (AUTHENTICATION_FAILED)",
        &current
    ));
}

#[test]
fn the_fingerprint_placeholder_follows_readiness() {
    let sql = "LAYOUT(HASHED())\nCOMMENT '{clickhouse_dict_fingerprint}'";
    let creds = ("nanosiem_dict".to_string(), "pw".to_string());
    assert!(substitute_dict_source_vars(sql, Some(&creds)).contains(&credentials_fingerprint("nanosiem_dict", "pw")));
    assert!(substitute_dict_source_vars(sql, None).contains(SELF_FINGERPRINT));
}

#[test]
fn readiness_probe_authenticates_for_real() {
    let sql = readiness_probe_sql("10.0.0.5", 9440, "nanosiem", "nanosiem_dict", "pw", true);
    assert!(sql.starts_with("SELECT count() FROM remoteSecure('10.0.0.5:9440', 'nanosiem', "), "{sql}");
    // Without this ClickHouse answers a local address in-process and never
    // checks the login (verified on 26.10).
    assert!(sql.ends_with("SETTINGS prefer_localhost_replica = 0"), "{sql}");
    assert!(sql.contains("WHERE 0"), "{sql}");
    let plain = readiness_probe_sql("::1", 9000, "nanosiem", "u", "p", false);
    assert!(plain.contains("remote('[::1]:9000'"), "{plain}");
}

/// Migration 202 defines every dictionary in the canonical list, each with
/// the dictionary placeholders and nothing else as its source login.
#[test]
fn migration_202_redefines_every_dictionary_with_the_dictionary_identity() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../clickhouse")
        .join(DICT_SOURCE_MIGRATION_FILE);
    let sql = std::fs::read_to_string(&path).expect("read migration 202");
    let body = ClickHouseMigrator::strip_sql_line_comments(&sql);
    for name in DICT_SOURCE_DICTIONARIES {
        assert!(
            body.contains(&format!("CREATE OR REPLACE DICTIONARY nanosiem.{name}")),
            "202 must define {name}"
        );
    }
    assert_eq!(body.matches("CREATE OR REPLACE DICTIONARY").count(), DICT_SOURCE_DICTIONARIES.len());
    assert_eq!(body.matches("USER '{clickhouse_dict_user}'").count(), DICT_SOURCE_DICTIONARIES.len());
    assert_eq!(body.matches("PASSWORD '{clickhouse_dict_password}'").count(), DICT_SOURCE_DICTIONARIES.len());
    assert_eq!(body.matches("COMMENT '{clickhouse_dict_fingerprint}'").count(), DICT_SOURCE_DICTIONARIES.len());
    assert!(!body.contains("{clickhouse_self_user}"), "no self login left in 202");
}

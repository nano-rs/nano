// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5271 (lane A): the OCSF prevalence producers must count hosts from the
//! class-correct host field.
//!
//! Endpoint classes (Sysmon file/process/module/registry) leave
//! `src_endpoint.*` empty and carry the host in `device.hostname`. The old host
//! key (src_endpoint.hostname, then src_endpoint.ip, then 'unknown') put every
//! endpoint row on the single host 'unknown', so every hash had prevalence 1.
//! The key now falls back to `src_host_unified` before 'unknown'.
//!
//! Pinned here:
//! 1. every OCSF prevalence MV in the overlay uses the fixed key, and none
//!    carries the old key;
//! 2. ocsf/196 re-applies byte-identical bodies to existing installs with
//!    `MODIFY QUERY` (no `AS`, NAN-1727), and covers every such MV;
//! 3. the key reads only columns the `nanosiem_ingest` direct-writer user is
//!    granted, so Tenzir-style writers do not start failing ACCESS_DENIED.

const OCSF_INIT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse/ocsf/init.sql"));
const MIGRATION_196: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/migrations/196_prevalence_host_key.sql"
));
const USERS_XML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/users.d/nanosiem-users.xml"
));

/// The producers whose host key is the source-side host.
const HOST_KEYED_MVS: &[&str] = &[
    "ocsf_hash_prevalence_summary_file_hash_mv",
    "ocsf_hash_prevalence_summary_process_hash_mv",
    "ocsf_domain_prevalence_summary_dest_host_mv",
    "ocsf_domain_prevalence_summary_query_mv",
    "ocsf_domain_prevalence_summary_url_mv",
    "ocsf_ip_prevalence_summary_dest_ip_mv",
    "hash_prevalence_source_ocsf_mv",
    "domain_prevalence_source_ocsf_mv",
    "ip_prevalence_source_ocsf_mv",
];

/// Producers created by ocsf/197 (NAN-5271 #23) with the fixed host key from
/// the start; tests/ocsf_prevalence_actor_http_guard.rs pins them.
const ADDED_IN_197: &[&str] = &[
    "ocsf_hash_prevalence_summary_actor_process_hash_mv",
    "ocsf_domain_prevalence_summary_http_url_mv",
    "hash_prevalence_source_ocsf_actor_process_mv",
    "domain_prevalence_source_ocsf_http_url_mv",
];

const OLD_TAIL: &str = "if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown')";
const NEW_TAIL: &str =
    "if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown'))";

fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The SELECT body of `CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.<mv>` in
/// the overlay, starting at `SELECT`, whitespace-normalized.
fn overlay_body(mv: &str) -> String {
    let needle = format!("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.{mv}\n");
    let start = OCSF_INIT
        .find(&needle)
        .unwrap_or_else(|| panic!("overlay is missing {mv}"));
    let stmt = &OCSF_INIT[start..start + OCSF_INIT[start..].find(';').expect("statement end")];
    let normalized = normalize(stmt);
    let at = normalized
        .find(" AS SELECT ")
        .unwrap_or_else(|| panic!("{mv}: no `AS SELECT` in overlay"));
    normalized[at + " AS ".len()..].to_string()
}

/// The `MODIFY QUERY` body for `<mv>` in ocsf/196, whitespace-normalized.
fn migration_body(mv: &str) -> String {
    let needle = format!("ALTER TABLE nanosiem.{mv}\nMODIFY QUERY ");
    let start = MIGRATION_196
        .find(&needle)
        .unwrap_or_else(|| panic!("ocsf/196 does not re-apply {mv}"))
        + needle.len();
    let end = start + MIGRATION_196[start..].find(';').expect("statement end");
    normalize(&MIGRATION_196[start..end])
}

#[test]
fn overlay_prevalence_mvs_use_the_class_correct_host_key() {
    for mv in HOST_KEYED_MVS {
        let body = overlay_body(mv);
        assert!(body.contains(NEW_TAIL), "{mv} must fall back to src_host_unified before 'unknown'");
        assert!(!body.contains(OLD_TAIL), "{mv} still has the src_endpoint-only host key");
    }
    // No producer anywhere in the overlay may keep the old key.
    assert!(
        !normalize(OCSF_INIT).contains(OLD_TAIL),
        "an OCSF MV still keys hosts on src_endpoint.* only (NAN-5271)"
    );
}

#[test]
fn every_overlay_mv_with_a_source_host_key_is_covered() {
    // A new producer that keys on src_endpoint.hostname must be in the list,
    // so the migration and this guard cover it.
    let norm = normalize(OCSF_INIT);
    for stmt in norm.split(';') {
        let Some(rest) = stmt.trim().strip_prefix("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.") else {
            continue;
        };
        if !stmt.contains("uniqState(if(`src_endpoint.hostname` != ''") {
            continue;
        }
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        assert!(
            HOST_KEYED_MVS.contains(&name.as_str()) || ADDED_IN_197.contains(&name.as_str()),
            "{name} is not covered by ocsf/196 (or created with the fixed key by ocsf/197)"
        );
    }
}

#[test]
fn migration_196_matches_the_overlay() {
    for mv in HOST_KEYED_MVS {
        assert_eq!(
            migration_body(mv),
            overlay_body(mv),
            "{mv}: ocsf/196 and clickhouse/ocsf/init.sql must stay byte-equivalent"
        );
    }
    let code = MIGRATION_196
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let statements: Vec<&str> = code
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(statements.len(), HOST_KEYED_MVS.len(), "ocsf/196 has statements outside the list");
    for s in statements {
        assert!(s.starts_with("ALTER TABLE nanosiem."), "ocsf/196 must only ALTER: {s}");
        assert!(!s.contains("MODIFY QUERY AS"), "MODIFY QUERY takes SELECT directly (NAN-1727)");
        assert!(!s.contains("INSERT INTO"), "no backfills in boot migrations");
    }
}

#[test]
fn host_key_columns_are_in_the_direct_writer_grant() {
    let section = USERS_XML
        .split("<nanosiem_ingest>")
        .nth(1)
        .and_then(|r| r.split("</nanosiem_ingest>").next())
        .expect("nanosiem_ingest section");
    let grant = section
        .lines()
        .find(|l| l.contains("ON nanosiem.ocsf_logs</query>") && l.contains("GRANT SELECT("))
        .expect("column-scoped SELECT grant on ocsf_logs");
    for col in ["`src_endpoint.hostname`", "`src_endpoint.ip`", "`src_host_unified`"] {
        assert!(grant.contains(col), "nanosiem_ingest lacks SELECT on {col}");
    }
    // device.hostname is reached through the granted alias, not named directly.
    for mv in HOST_KEYED_MVS {
        assert!(!overlay_body(mv).contains("`device.hostname`"), "{mv} reads an ungranted column");
    }
}

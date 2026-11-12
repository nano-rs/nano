// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5293: the canonical artifact list (`prevalence::artifact_fields`) drives
//! every prevalence key: the JOIN lookup keys, the drawer / row-context match,
//! the inline-context candidates, the scatter and the in-memory row reader.
//! Exercised on Sysmon process (1007) and DNS (4003) rows and HTTP (4002) rows.

use nanosiem_core::prevalence::artifact_fields::{
    first_row_artifact, row_values, scatter_artifacts_sql, ArtifactColumns, ArtifactKind,
};
use nanosiem_core::schema::{OcsfProfile, UdmProfile};
use serde_json::{json, Map, Value};

fn ocsf() -> ArtifactColumns {
    ArtifactColumns::resolve(&OcsfProfile::new())
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().expect("object").clone()
}

/// Columns an endpoint row fills with the workstation's own name. None may key
/// a domain: Sysmon DNS rows always carry `device.hostname`.
const WORKSTATION_COLUMNS: &[&str] = &["src_host", "device.hostname", "src_endpoint.hostname"];

#[test]
fn domain_lookup_key_never_reads_the_workstation() {
    for cols in [ocsf(), ArtifactColumns::resolve(&UdmProfile::new())] {
        let key = cols.lookup_key_sql(ArtifactKind::Domain).expect("domain key");
        for w in WORKSTATION_COLUMNS {
            assert!(!key.contains(w), "domain key reads {w}:\n{key}");
        }
    }
}

#[test]
fn ocsf_domain_key_covers_dns_and_http_in_baseline_order() {
    let key = ocsf().lookup_key_sql(ArtifactKind::Domain).unwrap();
    let pos = |c: &str| key.find(&format!("lower(\"{c}\")")).unwrap_or_else(|| panic!("{c}:\n{key}"));
    // The destination host wins (as in the `prevalence_dest_domain` column),
    // then the DNS query and the HTTP request host.
    assert!(pos("dst_endpoint.hostname") < pos("query.hostname"));
    assert!(pos("dst_endpoint.hostname") < pos("http_request.url.hostname"));
    // IPv4 literals in a hostname column never become a domain key.
    assert!(key.contains("match(\"dst_endpoint.hostname\", '^[0-9]+\\\\.[0-9]+"), "{key}");
}

#[test]
fn ocsf_hash_key_coalesces_file_process_then_parent() {
    let key = ocsf().lookup_key_sql(ArtifactKind::Hash).unwrap();
    assert!(key.starts_with("lower(COALESCE("), "{key}");
    let f = key.find("\"file.hashes.sha256\"").unwrap();
    let p = key.find("\"process.file.hashes.sha256\"").unwrap();
    let a = key.find("\"actor.process.file.hashes.sha256\"").unwrap();
    assert!(f < p && p < a, "{key}");
    // Arrays hold mixed algorithms: never a scalar lookup key.
    assert!(!key.contains("hashes.value"), "{key}");
}

#[test]
fn udm_hash_and_ip_keys_are_unchanged() {
    let cols = ArtifactColumns::resolve(&UdmProfile::new());
    assert_eq!(
        cols.lookup_key_sql(ArtifactKind::Hash).unwrap(),
        "lower(COALESCE(\n            nullIf(file_hash, ''),\n            nullIf(process_hash, '')\n        ))"
    );
    let ip = cols.lookup_key_sql(ArtifactKind::Ip).unwrap();
    assert!(ip.contains("nullIf(dest_ip, '')") && ip.contains("nullIf(src_ip, '')"), "{ip}");
    assert!(ip.contains("THEN dest_host ELSE"), "{ip}");
}

#[test]
fn drawer_match_reads_every_hash_and_domain_column() {
    // F4: the drawer matched only `file.hashes.sha256` / `dst_endpoint.hostname`.
    let cols = ocsf();
    let hash = cols.match_sql(ArtifactKind::Hash, "ABCDEF").unwrap();
    for c in ["process.file.hashes.sha256", "actor.process.file.hashes.sha256", "file.hashes.sha256"] {
        assert!(hash.contains(&format!("\"{c}\" = 'abcdef'")), "{c}: {hash}");
    }
    assert!(hash.contains("hasAny(\"process.file.hashes.value\", ['abcdef'])"), "{hash}");
    let domain = cols.match_sql(ArtifactKind::Domain, "GitHub.com").unwrap();
    for c in ["query.hostname", "http_request.url.hostname"] {
        assert!(domain.contains(&format!("\"{c}\")")) || domain.contains(&format!("\"{c}\" =")), "{c}: {domain}");
    }
    assert!(domain.contains("'github.com'"), "{domain}");
    let ip = cols.match_sql(ArtifactKind::Ip, "10.0.0.5").unwrap();
    assert!(ip.contains("\"src_endpoint.ip\" = '10.0.0.5'"), "{ip}");
}

#[test]
fn match_escapes_the_value() {
    let m = ocsf().match_sql(ArtifactKind::Domain, "a' OR 1=1 --").unwrap();
    assert!(m.contains("= 'a'' or 1=1 --'"), "{m}");
}

#[test]
fn inline_context_candidates_cover_every_column_once() {
    let c = ocsf().candidates_sql(ArtifactKind::Hash).unwrap();
    assert!(c.starts_with("arrayDistinct(arrayFilter(x -> x != '', "), "{c}");
    assert!(c.contains("lower(\"actor.process.file.hashes.sha256\")"), "{c}");
    assert!(c.contains("arrayMap(x -> lower(x), \"file.hashes.value\")"), "{c}");
    let d = ocsf().candidates_sql(ArtifactKind::Domain).unwrap();
    assert!(d.contains("lower(\"query.hostname\")"), "{d}");
}

#[test]
fn scatter_reads_dns_and_http_hosts_never_the_workstation() {
    // F8: the scatter read `src_host` as a domain and had no HTTP hosts.
    let sql = scatter_artifacts_sql(&ocsf(), "nanosiem.ocsf_logs", "class_uid = 4003", 100_000).unwrap();
    for w in WORKSTATION_COLUMNS.iter().chain(["src_host_unified"].iter()) {
        assert!(!sql.contains(w), "scatter reads {w}:\n{sql}");
    }
    assert!(sql.contains("[('domain', lower(\"query.hostname\"))]"), "{sql}");
    assert!(sql.contains("[('domain', lower(\"http_request.url.hostname\"))]"), "{sql}");
    assert!(sql.contains("[('hash', lower(\"actor.process.file.hashes.sha256\"))]"), "{sql}");
    assert!(sql.contains("WHERE class_uid = 4003\n    LIMIT 100000"), "{sql}");
    assert!(!sql.to_ascii_uppercase().contains("PREWHERE"), "{sql}");
}

#[test]
fn sysmon_process_row_yields_its_process_hash() {
    let row = obj(json!({
        "class_uid": 1007,
        "file.hashes.sha256": "",
        "process.file.hashes.sha256": "3b5b2092",
        "actor.process.file.hashes.sha256": "aaaa",
    }));
    assert_eq!(
        first_row_artifact(&row, ArtifactKind::Hash),
        Some(("process.file.hashes.sha256", "3b5b2092".to_string()))
    );
}

#[test]
fn sysmon_dns_row_yields_the_queried_domain() {
    let row = obj(json!({
        "class_uid": 4003,
        "device.hostname": "ws-ops-064.corp.local",
        "src_endpoint.hostname": "ws-ops-064.corp.local",
        "query.hostname": "login.microsoftonline.com",
    }));
    assert_eq!(
        first_row_artifact(&row, ArtifactKind::Domain),
        Some(("query.hostname", "login.microsoftonline.com".to_string()))
    );
}

#[test]
fn http_row_yields_host_and_ip_and_skips_ip_literal_hostnames() {
    let row = obj(json!({
        "class_uid": 4002,
        "dst_endpoint.hostname": "93.184.216.34",
        "dst_endpoint.ip": "93.184.216.34",
        "http_request.url.hostname": "example.org",
    }));
    assert_eq!(
        first_row_artifact(&row, ArtifactKind::Domain),
        Some(("http_request.url.hostname", "example.org".to_string()))
    );
    assert_eq!(
        first_row_artifact(&row, ArtifactKind::Ip),
        Some(("dst_endpoint.ip", "93.184.216.34".to_string()))
    );
}

#[test]
fn row_reader_handles_nested_objects_and_hash_arrays() {
    let row = obj(json!({
        "process": { "file": { "hashes": [ { "value": "" }, { "value": "cafe" } ] } },
        "file.hashes.value": ["", "beef"],
    }));
    assert_eq!(row_values(&row, "process.file.hashes.value"), vec!["cafe".to_string()]);
    assert_eq!(row_values(&row, "file.hashes.value"), vec!["beef".to_string()]);
    assert_eq!(
        first_row_artifact(&row, ArtifactKind::Hash),
        Some(("file.hashes.value", "beef".to_string()))
    );
}

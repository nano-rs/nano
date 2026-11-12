// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5280: query-artifact extraction reads every OCSF artifact column.

use super::*;
use crate::schema::{OcsfProfile, UdmProfile};

fn sqls(cols: &[ArtifactColumn]) -> Vec<&str> {
    cols.iter().map(|c| c.sql.as_str()).collect()
}

#[test]
fn ocsf_resolves_every_baseline_key_column() {
    let cols = ArtifactColumns::resolve(&OcsfProfile::new());
    let hashes = sqls(&cols.hashes);
    let domains = sqls(&cols.domains);
    // What the OCSF prevalence MVs key on — the regression: before NAN-5280
    // only `file.hashes.sha256` and `dst_endpoint.hostname` were read.
    for want in [
        "\"file.hashes.sha256\"",
        "\"process.file.hashes.sha256\"",
        "\"actor.process.file.hashes.sha256\"",
    ] {
        assert!(hashes.contains(&want), "hash column {want} missing from {hashes:?}");
    }
    for want in ["\"dst_endpoint.hostname\"", "\"query.hostname\"", "\"url.hostname\""] {
        assert!(domains.contains(&want), "domain column {want} missing from {domains:?}");
    }
    assert!(sqls(&cols.urls).contains(&"\"url.url_string\""));
}

#[test]
fn ocsf_hash_arrays_are_flagged_as_arrays() {
    let cols = ArtifactColumns::resolve(&OcsfProfile::new());
    let arr = cols
        .hashes
        .iter()
        .find(|c| c.sql == "\"process.file.hashes.value\"")
        .expect("process.file.hashes.value resolved");
    assert!(arr.is_array);
    assert!(cols.hashes.iter().filter(|c| c.sql.contains("sha256")).all(|c| !c.is_array));
}

#[test]
fn columns_are_deduplicated() {
    for cols in [
        ArtifactColumns::resolve(&OcsfProfile::new()),
        ArtifactColumns::resolve(&UdmProfile::new()),
    ] {
        for list in [&cols.hashes, &cols.domains, &cols.urls, &cols.ips] {
            let set: std::collections::HashSet<_> = list.iter().map(|c| &c.sql).collect();
            assert_eq!(set.len(), list.len(), "duplicate column in {list:?}");
        }
    }
}

#[test]
fn udm_reads_its_own_columns_and_never_ocsf_paths() {
    let cols = ArtifactColumns::resolve(&UdmProfile::new());
    let hashes = sqls(&cols.hashes);
    let domains = sqls(&cols.domains);
    assert!(hashes.contains(&"file_hash") && hashes.contains(&"process_hash"));
    assert!(domains.contains(&"dest_host"));
    for c in hashes.iter().chain(domains.iter()).chain(sqls(&cols.urls).iter()) {
        assert!(!c.contains('.'), "UDM must not emit a dotted OCSF column: {c}");
    }
}

#[test]
fn hash_sql_concatenates_scalars_and_arrays_and_lowercases() {
    let cols = ArtifactColumns {
        hashes: vec![
            ArtifactColumn::scalar("\"file.hashes.sha256\""),
            ArtifactColumn::scalar("\"process.file.hashes.sha256\""),
            ArtifactColumn { is_array: true, ..ArtifactColumn::scalar("\"file.hashes.value\"") },
        ],
        ..Default::default()
    };
    let sql = distinct_hash_candidates_sql(&cols, "nanosiem.ocsf_logs", "1=1", 501).unwrap();
    assert!(sql.contains(
        "ARRAY JOIN arrayConcat([lower(\"file.hashes.sha256\"), lower(\"process.file.hashes.sha256\")], \
         arrayMap(x -> lower(x), \"file.hashes.value\")) AS artifact_candidate"
    ), "{sql}");
    assert!(sql.contains(
        "(\"file.hashes.sha256\" != '' OR \"process.file.hashes.sha256\" != '' OR notEmpty(\"file.hashes.value\"))"
    ), "{sql}");
    assert!(sql.contains("length(artifact_candidate) IN (32, 40, 64)"));
    assert!(sql.ends_with("LIMIT 501"));
}

#[test]
fn domain_sql_reads_hostnames_and_url_hosts_and_excludes_internal_before_limit() {
    let cols = ArtifactColumns {
        domains: vec![ArtifactColumn::scalar("\"query.hostname\"")],
        urls: vec![ArtifactColumn::scalar("\"url.url_string\"")],
        ..Default::default()
    };
    let internal = InternalDomains::builtin();
    let sql = distinct_domain_candidates_sql(&cols, "t", "1=1", &internal, 7).unwrap();
    assert!(sql.contains("lower(\"query.hostname\")"), "{sql}");
    assert!(sql.contains("lower(domain(\"url.url_string\"))"), "{sql}");
    let not_internal = internal.sql_not_internal("artifact_candidate");
    let (before_limit, _) = sql.split_once("LIMIT 7").unwrap();
    assert!(before_limit.contains(&not_internal), "{sql}");
}

#[test]
fn no_columns_means_no_query() {
    let empty = ArtifactColumns::default();
    assert!(distinct_hash_candidates_sql(&empty, "t", "1=1", 1).is_none());
    assert!(distinct_domain_candidates_sql(&empty, "t", "1=1", &InternalDomains::builtin(), 1).is_none());
}

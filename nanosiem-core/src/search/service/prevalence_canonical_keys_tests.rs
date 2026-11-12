// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5293: every prevalence path keys on the canonical artifact list
//! (`prevalence::artifact_fields`), checked here end to end on Sysmon process
//! and DNS data plus HTTP data:
//!
//! - the JOIN pushdown's `_domain_lookup` / `_hash_lookup` (rendered through
//!   the real `explain` path, OCSF profile);
//! - the residual in-memory filter's row artifact;
//! - the SIEM-health IOC hit rate.

use super::npl_golden_corpus_tests::{render, sql_only_service};
use super::prevalence_processing::{extract_prevalence_artifact, prevalence_filter_kind};
use crate::auth::ScopeSet;
use crate::prevalence::artifact_fields::ArtifactKind;
use crate::query::PrevalenceField;
use serde_json::json;

/// The `logs_with_keys` CTE: the per-row lookup keys, and nothing else.
fn lookup_keys_cte(sql: &str) -> &str {
    let start = sql.find("logs_with_keys AS (").unwrap_or_else(|| panic!("no keys CTE:\n{sql}"));
    let end = sql[start..].find("base_logs AS (").expect("base_logs CTE") + start;
    &sql[start..end]
}

/// The `_domain_lookup` expression alone.
fn domain_key(keys: &str) -> &str {
    let end = keys.find("AS _domain_lookup").expect("_domain_lookup");
    &keys[..end]
}

async fn ocsf_sql(query: &str) -> String {
    let sql = render(&sql_only_service("ocsf"), query, &ScopeSet::unrestricted()).await;
    assert!(!sql.starts_with("ERR:"), "{query} -> {sql}");
    sql
}

#[tokio::test]
async fn sysmon_dns_domain_key_reads_the_query_not_the_workstation() {
    // F2: `COALESCE(dest_host, src_host, query)` resolved `src_host` to
    // `src_host_unified` = `device.hostname` on endpoint data, so every DNS
    // row was keyed on the workstation before `query.hostname` was reached.
    let sql = ocsf_sql("class_uid=4003 | prevalence domain_prevalence < 50").await;
    let key = domain_key(lookup_keys_cte(&sql));
    assert!(key.contains("lower(\"query.hostname\")"), "{key}");
    for workstation in ["src_host_unified", "device.hostname", "src_endpoint.hostname"] {
        assert!(!key.contains(workstation), "domain key reads {workstation}:\n{key}");
    }
    // The artifact shown is the key that was looked up.
    assert!(sql.contains("THEN l._domain_lookup"), "{sql}");
}

#[tokio::test]
async fn http_domain_key_reads_the_request_hostname() {
    let sql = ocsf_sql("source_type=conduit_proxy | prevalence domain_prevalence < 50").await;
    let key = domain_key(lookup_keys_cte(&sql));
    assert!(key.contains("lower(\"http_request.url.hostname\")"), "{key}");
    assert!(key.contains("lower(\"dst_endpoint.hostname\")"), "{key}");
}

#[tokio::test]
async fn sysmon_process_hash_key_reads_process_and_parent_hashes() {
    let sql = ocsf_sql("class_uid=1007 | prevalence hash_prevalence < 5").await;
    let keys = lookup_keys_cte(&sql);
    let hash = &keys[keys.find("AS _ip_lookup").expect("_ip_lookup")..];
    for col in [
        "\"file.hashes.sha256\"",
        "\"process.file.hashes.sha256\"",
        "\"actor.process.file.hashes.sha256\"",
    ] {
        assert!(hash.contains(col), "hash key misses {col}:\n{hash}");
    }
}

#[test]
fn in_memory_filter_reads_native_sysmon_process_columns() {
    // F3: the residual path read `process_hash_unified`, an ALIAS column no
    // `SELECT *` row carries, so every Sysmon process row was dropped.
    let row = json!({
        "class_uid": 1007,
        "process.file.hashes.sha256": "AAAA1111",
        "actor.process.file.hashes.sha256": "bbbb2222",
        "device.hostname": "ws-exec-128.corp.local",
    });
    let kind = prevalence_filter_kind(&PrevalenceField::HashFirstSeen);
    assert_eq!(extract_prevalence_artifact(&row, kind), Some("AAAA1111".into()));

    // Parent-only row (process access, image load) falls back to the actor.
    let parent_only = json!({ "class_uid": 1007, "actor.process.file.hashes.sha256": "bbbb2222" });
    assert_eq!(extract_prevalence_artifact(&parent_only, kind), Some("bbbb2222".into()));
}

#[test]
fn in_memory_filter_keys_sysmon_dns_on_the_query() {
    let row = json!({
        "class_uid": 4003,
        "device.hostname": "ws-exec-128.corp.local",
        "src_endpoint.hostname": "ws-exec-128.corp.local",
        "dst_endpoint.hostname": "",
        "query.hostname": "github.com",
    });
    let kind = prevalence_filter_kind(&PrevalenceField::DomainPrevalence);
    assert_eq!(extract_prevalence_artifact(&row, kind), Some("github.com".into()));
}

#[test]
fn in_memory_filter_keys_http_on_the_request_hostname() {
    let row = json!({
        "class_uid": 4002,
        "dst_endpoint.ip": "93.184.216.34",
        "http_request.url.hostname": "example.org",
        "http_request.url.url_string": "https://example.org/a",
    });
    let kind = prevalence_filter_kind(&PrevalenceField::DomainPrevalence);
    assert_eq!(extract_prevalence_artifact(&row, kind), Some("example.org".into()));
    assert_eq!(
        extract_prevalence_artifact(&row, ArtifactKind::Ip),
        Some("93.184.216.34".into())
    );
}

#[test]
fn health_ioc_hit_rate_reads_the_ocsf_enrichment_column() {
    // F7: OCSF used to report a constant `0.0`.
    let ocsf = crate::siem_health::collector::ioc_hit_pct_expr(true);
    assert!(ocsf.contains("`enrichments.ioc_confidence` > 0"), "{ocsf}");
    assert_eq!(
        crate::siem_health::collector::ioc_hit_pct_expr(false),
        "countIf(ioc_confidence > 0) * 100.0 / count()"
    );
}


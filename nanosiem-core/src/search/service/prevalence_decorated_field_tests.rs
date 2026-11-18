// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5568: an `eval` or `where` expression after `| prevalence` reads the
//! DECORATED prevalence fields (`host_count`, `first_seen`, `last_seen`,
//! `total_occurrences`, `is_rare`, `prevalence_score`), never the event's
//! unmapped/`ext` JSON. Before the fix `eval esc_very_rare_hash=(host_count < 3)`
//! rendered `unmapped."host_count"` on OCSF (`ext` on UDM), which is always
//! empty, so the flag was never set.
//!
//! Rendered through the real `explain` path, both schema profiles.

use super::npl_golden_corpus_tests::{render, sql_only_service};
use crate::auth::ScopeSet;

const LEAST: &str = "least(_dp_host_count, _ip_host_count, _hp_host_count)";

async fn sql(profile: &str, query: &str) -> String {
    let sql = render(&sql_only_service(profile), query, &ScopeSet::unrestricted()).await;
    assert!(!sql.starts_with("ERR:"), "{profile}: {query} -> {sql}");
    sql
}

/// The SELECT-list expression of eval output `alias`.
fn eval_column<'a>(sql: &'a str, alias: &str) -> &'a str {
    let end = sql
        .find(&format!(" AS `{alias}`"))
        .or_else(|| sql.find(&format!(" AS {alias}")))
        .unwrap_or_else(|| panic!("no eval column {alias}:\n{sql}"));
    let start = sql[..end].rfind("\n    ").unwrap();
    &sql[start..end]
}

fn assert_no_raw_json_read(fragment: &str, field: &str) {
    for raw in [
        format!("unmapped.\"{field}\""),
        format!("unmapped.^\"{field}\""),
        format!("'{field}'"),
        "JSONExtract".to_string(),
        "ext.".to_string(),
    ] {
        assert!(!fragment.contains(&raw), "{field} read from the event JSON ({raw}): {fragment}");
    }
}

#[tokio::test]
async fn eval_reads_the_decorated_host_count_on_both_profiles() {
    const RULE: &str = r#"metadata.log_source="windows_sysmon" | where class_uid=1007 AND activity_id=1 | prevalence process.file.hashes.value window=30d | where host_count < 5 AND prevalence_first_seen > now() - INTERVAL 24 HOUR | eval esc_very_rare_hash=(host_count < 3) | table time, process.name"#;
    let ocsf = sql("ocsf", RULE).await;
    let col = eval_column(&ocsf, "esc_very_rare_hash");
    assert!(col.contains(&format!("(CASE WHEN {LEAST} >= 9999 THEN NULL ELSE {LEAST} END)")), "{col}");
    assert_no_raw_json_read(col, "host_count");

    let udm = sql(
        "udm",
        "source_type=windows_sysmon | prevalence enrich=true window=30d | eval very_rare=(host_count < 3)",
    )
    .await;
    let col = eval_column(&udm, "very_rare");
    assert!(col.contains(&format!("{LEAST} >= 9999")), "{col}");
    assert_no_raw_json_read(col, "host_count");
}

#[tokio::test]
async fn every_decorated_field_resolves_in_eval() {
    let q = "source_type=windows_sysmon | prevalence enrich=true window=30d \
             | eval hc=host_count, fs=first_seen, ls=last_seen, pfs=prevalence_first_seen, \
             occ=total_occurrences, rare=is_rare, score=prevalence_score, \
             ptype=prevalence_type, part=prevalence_artifact";
    for profile in ["ocsf", "udm"] {
        let s = sql(profile, q).await;
        for (alias, field, marker) in [
            ("hc", "host_count", format!("{LEAST} >= 9999 THEN NULL")),
            ("fs", "first_seen", "THEN _dp_first_seen".to_string()),
            ("ls", "last_seen", "THEN _dp_last_seen".to_string()),
            ("pfs", "prevalence_first_seen", "THEN _dp_first_seen".to_string()),
            ("occ", "total_occurrences", "THEN _dp_total_occurrences".to_string()),
            ("rare", "is_rare", format!("{LEAST} < 3 ELSE false")),
            ("score", "prevalence_score", "toUInt8(round(".to_string()),
            ("ptype", "prevalence_type", "THEN 'domain' WHEN".to_string()),
            ("part", "prevalence_artifact", "THEN l._domain_lookup".to_string()),
        ] {
            let col = eval_column(&s, alias);
            assert!(col.contains(&marker), "{profile} {alias}: {col}");
            assert_no_raw_json_read(col, field);
        }
    }
}

#[tokio::test]
async fn where_expressions_read_the_decorated_fields() {
    let q = "source_type=windows_sysmon | prevalence enrich=true window=30d \
             | where (host_count * 1) < 3 OR total_occurrences < tonumber(\"10\")";
    for profile in ["ocsf", "udm"] {
        let s = sql(profile, q).await;
        let where_clause = &s[s.rfind("\nWHERE ").expect("pushed WHERE")..];
        assert!(where_clause.contains(&format!("{LEAST} >= 9999 THEN NULL")), "{profile}: {where_clause}");
        assert!(where_clause.contains("_dp_total_occurrences"), "{profile}: {where_clause}");
        assert!(!where_clause.contains("unmapped.\"host_count\""), "{profile}: {where_clause}");
        assert!(!where_clause.contains("'host_count'"), "{profile}: {where_clause}");
    }
}

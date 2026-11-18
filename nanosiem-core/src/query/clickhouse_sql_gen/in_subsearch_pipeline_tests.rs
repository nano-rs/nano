// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5620: a `field IN [ … ]` subsearch with stages compiles its WHOLE
//! pipeline. It used to apply only the search and `return`, silently
//! dropping `stats` / `where` / `sort` / `head` / `eval` / `dedup`, so
//! `src_ip IN [x | stats dc(user) as u by src_ip | where u >= 10 | head 3 |
//! return src_ip]` matched every `src_ip` that `x` matched.

use std::collections::BTreeSet;


use chrono::{TimeZone, Utc};

use super::{ClickHouseSqlGenerator, QueryOptions};
use crate::query::parser::parse_query;
use crate::query::TimeRange;
use crate::schema::{profile_for_id, SchemaId};

fn range() -> TimeRange {
    let start = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
    TimeRange::new(start, start + chrono::Duration::hours(24))
}

fn udm() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::with_table("logs")
}

fn ocsf() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::with_table("ocsf_logs").with_profile(profile_for_id(SchemaId::Ocsf))
}

fn gen(g: &ClickHouseSqlGenerator, npl: &str) -> Result<String, String> {
    let q = parse_query(npl).map_err(|e| format!("parse: {e}"))?;
    let opts = QueryOptions { omit_settings: true, ..QueryOptions::default() };
    g.generate_with_options(&q, &range(), &opts).map_err(|e| e.to_string())
}

/// The SQL of the IN subquery (from `IN (SELECT DISTINCT` to its close).
fn in_subquery(sql: &str) -> &str {
    let at = sql.find("IN (SELECT DISTINCT").unwrap_or_else(|| panic!("no IN subquery in:\n{sql}"));
    &sql[at..]
}

#[test]
fn the_whole_pipeline_runs_inside_the_in_subquery() {
    let sql = gen(
        &udm(),
        "src_ip IN [action=login | stats dc(user) as u by src_ip | where u >= 10 | sort -u | head 3 | return src_ip]",
    )
    .unwrap();
    let sub = in_subquery(&sql);
    assert!(sub.contains("GROUP BY"), "stats dropped:\n{sql}");
    assert!(sub.contains("uniqExact"), "dc dropped:\n{sql}");
    assert!(sub.contains(">= 10"), "where dropped:\n{sql}");
    assert!(sub.contains("ORDER BY u DESC") || sub.contains("ORDER BY `u` DESC"), "sort dropped:\n{sql}");
    assert!(sub.contains("LIMIT 3"), "head dropped:\n{sql}");
    // The 10,000 cap counts DISTINCT values, outside the pipeline.
    assert!(sub.contains("\n) LIMIT 10000)"), "{sql}");
}

#[test]
fn without_a_head_the_ten_thousand_cap_still_applies() {
    let sql = gen(&udm(), "src_ip IN [action=login | stats count() as n by src_ip | where n > 5 | return src_ip]").unwrap();
    let sub = in_subquery(&sql);
    assert!(sub.contains("LIMIT 10000"), "{sql}");
    assert!(sub.contains("> 5"), "{sql}");
}

#[test]
fn a_bare_search_subsearch_keeps_its_single_scan_form() {
    // Byte-compatible with the pre-NAN-5620 form (no pipeline to run).
    let sql = gen(&udm(), "src_ip IN [search error | return src_ip]").unwrap();
    assert!(sql.contains("IN (SELECT DISTINCT src_ip FROM logs WHERE"), "{sql}");
    assert!(sql.contains("LIMIT 10000)"), "{sql}");
    assert!(!sql.contains("_nano_in_value"), "{sql}");
}

#[test]
fn eval_and_dedup_compile_and_the_eval_alias_can_be_returned() {
    let sql = gen(&udm(), "user IN [action=login | eval who=lower(user) | dedup who | return who]").unwrap();
    let sub = in_subquery(&sql);
    assert!(sub.contains("lower("), "eval dropped:\n{sql}");
    assert!(sub.contains("LIMIT 1 BY") || sub.contains("LIMIT 1 BY who"), "dedup dropped:\n{sql}");
}

#[test]
fn ocsf_dotted_fields_compile_in_the_pipeline() {
    let sql = gen(
        &ocsf(),
        "class_uid=3002 src_endpoint.ip IN [class_uid=3002 status_id=2 | stats dc(user.name) as users by src_endpoint.ip | where users >= 10 | return src_endpoint.ip]",
    )
    .unwrap();
    let sub = in_subquery(&sql);
    assert!(sub.contains("GROUP BY"), "{sql}");
    assert!(sub.contains(">= 10"), "{sql}");
}

#[test]
fn a_stage_that_cannot_run_in_a_subsearch_is_refused_never_dropped() {
    for (npl, what) in [
        ("src_ip IN [action=login | timechart span=1h count | return src_ip]", "timechart"),
        ("src_ip IN [action=login | lookup assets ip as src_ip | return src_ip]", "lookup"),
        ("src_ip IN [action=login | return src_ip | head 3]", "last stage"),
        ("src_ip IN [action=login | stats count() as n by src_ip | return src_ip, n]", "return one"),
        // The pipeline no longer outputs the returned field.
        ("src_ip IN [action=login | stats count() as n by user | return src_ip]", "outputs only"),
    ] {
        let err = gen(&udm(), npl).expect_err(npl);
        assert!(err.contains(what), "{npl}: {err}");
    }
}

/// The source-scope gate the search service injects holds inside the
/// subquery's pipeline, not only on the outer scan.
#[test]
fn source_scoping_holds_inside_the_subquery_pipeline() {
    let deny: BTreeSet<String> = ["hr_payroll".to_string(), "audit".to_string()].into_iter().collect();
    let npl = "src_ip IN [action=login | stats dc(user) as u by src_ip | where u >= 10 | head 3 | return src_ip]";
    let scoped = crate::search::query_processing::enforce_source_scope(npl, &deny).expect("scoped");
    let sql = gen(&udm(), &scoped).unwrap();
    let sub = in_subquery(&sql);
    assert!(sub.contains("hr_payroll") && sub.contains("audit"), "the gate is missing inside the subquery:\n{sql}");
    // Inside the subquery's own scan, and on the outer scan too.
    assert_eq!(sql.matches("NOT IN ('audit', 'hr_payroll')").count(), 2, "{sql}");
}

/// join / append subsearches already compile every stage (they run through
/// `generate_subsearch_sql`); pinned so they stay that way.
#[test]
fn join_and_append_subsearches_keep_their_stages() {
    let sql = gen(&udm(), "action=login | join src_ip [search action=logout | stats count() as n by src_ip | where n > 2 | head 5]").unwrap();
    assert!(sql.contains("GROUP BY") && sql.contains("> 2") && sql.contains("LIMIT 5"), "{sql}");
    let sql = gen(&udm(), "action=login | stats count() as n by src_ip | append [search action=logout | stats count() as n by src_ip | where n > 2 | head 5]").unwrap();
    assert!(sql.contains("GROUP BY") && sql.contains("> 2") && sql.contains("LIMIT 5"), "{sql}");
}

/// The OOM guard now scans IN subsearch pipelines (they execute).
#[test]
fn the_memory_guard_scans_in_subsearch_pipelines() {
    let q = parse_query("src_ip IN [* | stats values(user) as v by src_ip | return src_ip]").unwrap();
    assert!(crate::search::query_processing::detect_oom_risk(&q).is_some());
    let q = parse_query("src_ip IN [action=login | stats values(user) as v by src_ip | return src_ip]").unwrap();
    assert!(crate::search::query_processing::detect_oom_risk(&q).is_none());
}

// --- independent review fixes ---

/// The cap counts distinct values outside the pipeline, so a large `head`
/// cannot turn it off and a `head` inside never cuts distinct values short.
#[test]
fn the_cap_is_on_distinct_values_outside_the_pipeline() {
    let sql = gen(&udm(), "src_ip IN [action=login | stats count() as n by src_ip | sort -n | head 50000 | return src_ip]").unwrap();
    let sub = in_subquery(&sql);
    assert!(sub.contains("LIMIT 50000"), "{sql}");
    assert!(sub.contains("\n) LIMIT 10000)"), "the cap must stay on even with a large head:\n{sql}");
}

/// `head` without `sort` keeps the newest N, exactly as at the top level;
/// `sort … | head N` keeps the sorted top N through the trailing eval.
#[test]
fn head_inside_keeps_the_top_level_order() {
    let sql = gen(&udm(), "src_ip IN [action=login | head 3 | return src_ip]").unwrap();
    let sub = in_subquery(&sql);
    assert!(sub.contains("ORDER BY timestamp DESC\n      LIMIT 3"), "{sql}");
    let sql = gen(&udm(), "src_ip IN [action=login | sort -bytes_out | head 3 | return src_ip]").unwrap();
    let sub = in_subquery(&sql);
    let order = sub.find("ORDER BY bytes_out DESC").unwrap_or_else(|| panic!("{sql}"));
    let limit = sub[order..].find("LIMIT 3").unwrap_or_else(|| panic!("{sql}")) + order;
    let eval = sub.find("AS _nano_in_value").unwrap_or_else(|| panic!("{sql}"));
    assert!(order < limit && limit < eval, "the eval must read the sorted, limited rows:\n{sql}");
}

/// `return N f` keeps N distinct values, in both forms; `return f` keeps
/// every value (up to the cap).
#[test]
fn return_n_keeps_n_distinct_values() {
    let sql = gen(&udm(), "src_ip IN [search error | return 5 src_ip]").unwrap();
    assert!(sql.contains("IN (SELECT DISTINCT src_ip FROM logs WHERE") && sql.contains("LIMIT 5)"), "{sql}");
    let sql = gen(&udm(), "src_ip IN [action=login | stats count() as n by src_ip | return 5 src_ip]").unwrap();
    assert!(in_subquery(&sql).contains("\n) LIMIT 5)"), "{sql}");
    let sql = gen(&udm(), "src_ip IN [search error | return 20000 src_ip]").unwrap();
    assert!(sql.contains("LIMIT 10000)"), "{sql}");
}

/// `stats values(f)` returns its values: the distinct non-empty `f`.
#[test]
fn stats_values_returns_its_values() {
    for npl in [
        "src_ip IN [search action=failed_login | stats values(src_ip)]",
        "src_ip IN [search action=failed_login | stats values(src_ip) as ips by user | return ips]",
    ] {
        let sql = gen(&udm(), npl).unwrap_or_else(|e| panic!("{npl}: {e}"));
        let sub = in_subquery(&sql);
        assert!(!sub.contains("groupUniqArray"), "{sql}");
        assert!(sub.contains("WHERE toString(_nano_in_value) != ''"), "{sql}");
    }
}

/// A UDM ext group-by key keeps its stage_0 alias (read by name, no eval).
#[test]
fn a_udm_ext_group_by_key_can_be_returned() {
    let sql = gen(&udm(), "src_ip IN [action=login | stats count() as n by foo_bar | return foo_bar]").unwrap();
    let sub = in_subquery(&sql);
    assert!(sub.contains("toString(ext.foo_bar) AS foo_bar"), "{sql}");
    assert!(sub.contains("SELECT DISTINCT toString(foo_bar) FROM"), "{sql}");
}

/// A `[dataset=signals …]` subsearch with stages still needs
/// detections:view (the gate reads the subsearch's dataset token) and keeps
/// the caller's source scoping inside the derived detections source.
#[test]
fn a_signals_subsearch_with_stages_keeps_its_permission_gate_and_scoping() {
    let npl = "class_uid=1007 id IN [dataset=signals risk_entity!=\"\" | stats count() as n by matched_log_id | where n >= 2 | return matched_log_id]";
    assert!(crate::search::touches_signals_dataset(None, npl), "detections:view must be required");
    let deny: BTreeSet<String> = ["hr_payroll".to_string()].into_iter().collect();
    let scoped = crate::search::query_processing::enforce_source_scope(npl, &deny).expect("scoped");
    let sql = gen(&ocsf(), &scoped).unwrap();
    let sub = in_subquery(&sql);
    assert!(sub.contains("GROUP BY matched_log_id") && sub.contains(">= 2"), "{sql}");
    // Both legs of the detections source, inside the subquery, carry the deny set.
    assert!(sub.contains("FROM signals AS s"), "{sql}");
    assert!(sub.contains("lower(trimBoth(s.source_type)) NOT IN (") && sub.contains("'hr_payroll')"), "real-time leg unscoped:\n{sql}");
    assert!(sub.contains("hasAny("), "scheduled leg unscoped:\n{sql}");
}

/// The memory guard reaches IN subsearches inside transaction / sequence /
/// funnel conditions too.
#[test]
fn the_memory_guard_reaches_subsearches_in_command_conditions() {
    let q = parse_query(
        "action=login | transaction src_ip startswith=(src_ip IN [* | stats values(user) as v by src_ip | return src_ip])",
    )
    .unwrap();
    assert!(crate::search::query_processing::detect_oom_risk(&q).is_some());
}

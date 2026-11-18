// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5628: an `IN [ … | <stages> ]` subsearch pipeline is emitted with its
//! own `WITH` inside the outer pipeline's `stage_0`. It used to name its CTEs
//! `stage_0, stage_1, …` too, so on ClickHouse 26.10
//! `src_endpoint.ip IN [ class_uid=4003 | stats count by src_endpoint.ip |
//! where count > 5 | return src_endpoint.ip ] | stats count by src_endpoint.ip`
//! failed with `Unknown table expression identifier 'stage_1'. In scope
//! stage_2` (HTTP 500). Every nested pipeline now carries a unique `sub<n>_`
//! CTE prefix; the top-level `stage_*` names are unchanged.

use std::collections::HashSet;

use chrono::{TimeZone, Utc};
use regex::Regex;

use super::{ClickHouseSqlGenerator, QueryOptions};
use crate::query::parser::parse_query;
use crate::query::TimeRange;
use crate::schema::{profile_for_id, SchemaId};

const FAILING_QUERY: &str = "src_endpoint.ip IN [ class_uid=4003 | stats count by src_endpoint.ip | where count > 5 \
                             | return src_endpoint.ip ] | stats count by src_endpoint.ip";

fn range() -> TimeRange {
    let start = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
    TimeRange::new(start, start + chrono::Duration::hours(24))
}

fn ocsf() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::with_table("ocsf_logs").with_profile(profile_for_id(SchemaId::Ocsf))
}

fn gen(g: &ClickHouseSqlGenerator, npl: &str) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("parse {npl}: {e}"));
    g.generate_with_options(&q, &range(), &QueryOptions::default())
        .unwrap_or_else(|e| panic!("generate {npl}: {e}"))
}

/// Every CTE name the SQL defines (`<name> AS (`), in emission order.
fn cte_names(sql: &str) -> Vec<String> {
    let re = Regex::new(r"(?m)(?:\bWITH\s+|,\s*\n\s*)([A-Za-z_][A-Za-z0-9_]*) AS \(").unwrap();
    re.captures_iter(sql).map(|c| c[1].to_string()).collect()
}

fn assert_unique_ctes(sql: &str) -> Vec<String> {
    let names = cte_names(sql);
    let mut seen = HashSet::new();
    for n in &names {
        assert!(seen.insert(n.clone()), "duplicate CTE name `{n}` in {names:?}:\n{sql}");
    }
    names
}

/// Every `FROM <cte>` reads a CTE the SQL defines (no dangling reference).
fn assert_cte_references_defined(sql: &str, names: &[String]) {
    let re = Regex::new(r"\bFROM ([A-Za-z0-9_]*stage_[0-9]+)\b").unwrap();
    for c in re.captures_iter(sql) {
        assert!(names.contains(&c[1].to_string()), "FROM `{}` names no CTE ({names:?}):\n{sql}", &c[1]);
    }
}

#[test]
fn the_reported_query_emits_no_duplicate_cte_names() {
    let sql = gen(&ocsf(), FAILING_QUERY);
    let names = assert_unique_ctes(&sql);
    assert_eq!(
        names,
        ["stage_0", "sub0_stage_0", "sub0_stage_1", "sub0_stage_2", "stage_1"],
        "{sql}"
    );
    assert_cte_references_defined(&sql, &names);
    // The inner pipeline reads its own CTEs; the outer stats reads the outer stage_0.
    assert!(sql.contains("FROM sub0_stage_0\n"), "{sql}");
    assert!(sql.contains("SELECT * FROM sub0_stage_2"), "{sql}");
    assert!(sql.contains("FROM stage_0\n  GROUP BY"), "{sql}");
}

/// The shape captured live: the search UI's `sort -count` after the stats adds
/// an outer `stage_2` that reads the outer `stage_1` (the reference ClickHouse
/// resolved against the inner pipeline's CTEs).
#[test]
fn the_reported_query_with_its_ui_sort_emits_no_duplicate_cte_names() {
    let sql = gen(&ocsf(), &format!("{FAILING_QUERY} | sort -count"));
    let names = assert_unique_ctes(&sql);
    assert_eq!(
        names,
        ["stage_0", "sub0_stage_0", "sub0_stage_1", "sub0_stage_2", "stage_1", "stage_2"],
        "{sql}"
    );
    assert_cte_references_defined(&sql, &names);
    assert!(sql.contains("SELECT * FROM stage_1\n  ORDER BY count DESC"), "{sql}");
}

#[test]
fn a_query_without_a_nested_pipeline_keeps_the_plain_stage_names() {
    let sql = gen(&ocsf(), "class_uid=4003 | stats count by src_endpoint.ip | where count > 5");
    assert_eq!(assert_unique_ctes(&sql), ["stage_0", "stage_1", "stage_2"], "{sql}");
    assert!(!sql.contains("sub0_"), "{sql}");
}

#[test]
fn two_subsearches_in_one_query_get_distinct_prefixes() {
    let sql = gen(
        &ocsf(),
        "src_endpoint.ip IN [ class_uid=4003 | stats count by src_endpoint.ip | where count > 5 \
         | return src_endpoint.ip ] dst_endpoint.ip IN [ class_uid=4001 | stats count by dst_endpoint.ip \
         | where count > 2 | return dst_endpoint.ip ] | stats count by src_endpoint.ip",
    );
    let names = assert_unique_ctes(&sql);
    assert!(names.iter().any(|n| n.starts_with("sub0_stage_")), "{names:?}");
    assert!(names.iter().any(|n| n.starts_with("sub1_stage_")), "{names:?}");
    assert_cte_references_defined(&sql, &names);
}

#[test]
fn a_subsearch_nested_inside_a_subsearch_gets_its_own_prefix() {
    let sql = gen(
        &ocsf(),
        "src_endpoint.ip IN [ class_uid=4003 src_endpoint.ip IN [ class_uid=4001 | stats count by src_endpoint.ip \
         | where count > 2 | return src_endpoint.ip ] | stats count by src_endpoint.ip | where count > 5 \
         | return src_endpoint.ip ] | stats count by src_endpoint.ip",
    );
    let names = assert_unique_ctes(&sql);
    assert!(names.iter().any(|n| n.starts_with("sub0_stage_")), "{names:?}");
    assert!(names.iter().any(|n| n.starts_with("sub1_stage_")), "{names:?}");
    assert_cte_references_defined(&sql, &names);
    // Each level reads its own CTEs: the innermost pipeline (sub1, inside
    // sub0_stage_0's WHERE) chains sub1_*, the middle one chains sub0_*.
    assert!(sql.contains("FROM sub1_stage_0\n"), "{sql}");
    assert!(sql.contains("SELECT * FROM sub1_stage_2"), "{sql}");
    assert!(sql.contains("FROM sub0_stage_0\n"), "{sql}");
    assert!(sql.contains("SELECT * FROM sub0_stage_2"), "{sql}");
    assert!(!sql.contains("sub0_sub"), "prefixes replace, never stack:\n{sql}");
}

#[test]
fn the_same_generator_numbers_every_generation_from_zero() {
    let g = ocsf();
    let first = gen(&g, FAILING_QUERY);
    let second = gen(&g, FAILING_QUERY);
    assert_eq!(first, second, "SQL must be deterministic across generations");
    let cloned = gen(&g.clone(), FAILING_QUERY);
    assert_eq!(first, cloned);
}

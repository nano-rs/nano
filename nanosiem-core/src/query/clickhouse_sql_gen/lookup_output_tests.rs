// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5694: `lookup … OUTPUT col` is a Nano-side enrichment. The ClickHouse
//! SQL must neither join a (non-existent) lookup table nor alias/project the
//! output column (an alias named like the output would shadow a real column,
//! see `feedback_ch_alias_shadows_column`), and the prefix sent to ClickHouse
//! must stop before the lookup so the suffix replays after enrichment.

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, PrettyPrint, TimeRange};
use crate::schema::OcsfProfile;
use crate::search::query_processing::lookup_boundary::{
    extract_post_enrichment_commands, lookup_boundary_plan, strip_enrichment_and_after,
};

fn ocsf() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()))
}

fn time_range() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

#[test]
fn lookup_output_forms_compile_to_the_same_pass_through_sql_as_the_bare_lookup() {
    let gen = ocsf();
    let bare = gen
        .generate(&parse_query("class_uid=3002 | lookup owners device.hostname").unwrap(), &time_range())
        .unwrap();
    for clause in [
        "OUTPUT owner",
        "OUTPUT owner AS team",
        "OUTPUTNEW owner",
        "OUTPUT owner, site",
        "OUTPUT owner CASE_INSENSITIVE",
    ] {
        let q = format!("class_uid=3002 | lookup owners device.hostname {clause}");
        let sql = gen.generate(&parse_query(&q).unwrap(), &time_range()).unwrap();
        assert_eq!(sql, bare, "{q}");
        assert!(!sql.contains("lookup_owners") && !sql.contains("JOIN"), "{q}: {sql}");
        assert!(!sql.contains("owner") && !sql.contains("team"), "{q}: {sql}");
        assert!(!sql.contains("PREWHERE"), "{q}: {sql}");
    }
}

#[test]
fn stats_by_an_output_column_runs_after_the_enrichment() {
    let gen = ocsf();
    for clause in ["", " OUTPUT owner", " OUTPUT owner AS owner", " OUTPUTNEW owner"] {
        let q = parse_query(&format!(
            "class_uid=3002 | lookup owners device.hostname{clause} | stats count by owner"
        ))
        .unwrap();
        assert_eq!(lookup_boundary_plan(&q), Ok(true), "{clause}");
        let prefix = strip_enrichment_and_after(&q);
        assert_eq!(prefix.pretty_print(), "class_uid=3002", "{clause}");
        let sql = gen.generate(&prefix, &time_range()).unwrap();
        // The ClickHouse prefix never groups by the not-yet-written output.
        assert!(!sql.contains("GROUP BY") && !sql.contains("owner"), "{clause}: {sql}");
        let suffix = extract_post_enrichment_commands(&q);
        assert_eq!(suffix.len(), 1, "{clause}");
    }
}

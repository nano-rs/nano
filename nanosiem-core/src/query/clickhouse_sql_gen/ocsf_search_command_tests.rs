// SPDX-License-Identifier: AGPL-3.0-or-later

//! nPL command shapes that failed on OCSF data (NAN-5277).

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, TimeRange};
use crate::schema::{OcsfProfile, UdmProfile};

fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-10-08T00:00:00Z".parse().unwrap(),
        end: "2026-10-08T01:00:00Z".parse().unwrap(),
    }
}

fn ocsf_sql(npl: &str) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&q, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

fn udm_sql(npl: &str) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(UdmProfile::new()))
        .generate(&q, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

/// The timechart OTHER-series query (`timechart … by <field>` with more than
/// ten series) is `eval … | where … | timechart … | sort +time_bucket`. On
/// OCSF the eval forces a wide `SELECT *` base stage, and the sort read
/// `time_bucket` as an unmapped-tail field: `unmapped."time_bucket"`, Code 47
/// "Unknown identifier". `timechart … by device.hostname` /
/// `src_endpoint.hostname` / `src_host` all failed this way.
#[test]
fn sort_after_timechart_references_the_bucket_column() {
    for npl in [
        r#"* | eval sel = if(coalesce(device.hostname == "a", false), 1, 0) | where sel=0 | timechart span=1h count() as count | sort +time_bucket"#,
        r#"* | eval sel = if(coalesce(src_endpoint.hostname == "", false), 1, 0) | where sel=0 | timechart span=1h count | sort +time_bucket"#,
        "* | eval x=1 | timechart span=1h count by user.name | sort -time_bucket",
    ] {
        let sql = ocsf_sql(npl);
        assert!(!sql.contains("unmapped.\"time_bucket\""), "{npl}: {sql}");
        assert!(
            sql.contains("ORDER BY time_bucket ASC") || sql.contains("ORDER BY time_bucket DESC"),
            "{npl}: {sql}"
        );
    }
}

/// OCSF promoted columns are non-Nullable (absent = '') and unmapped-tail reads
/// default to '', so a bare `isNull` matched nothing on OCSF data.
#[test]
fn isnull_treats_empty_string_as_absent_on_ocsf() {
    let sql = ocsf_sql("* | where isnull(user.name) | stats count");
    assert!(
        sql.contains(r#"(isNull("user.name") OR toString("user.name") = '')"#),
        "{sql}"
    );
    let sql = ocsf_sql("* | where isnotnull(src_endpoint.ip) | stats count");
    assert!(
        sql.contains(r#"(isNotNull("src_endpoint.ip") AND toString("src_endpoint.ip") != '')"#),
        "{sql}"
    );
    let sql = ocsf_sql("* | eval n=isnull(actor.user.name) | stats count by n");
    assert!(
        sql.contains(r#"(isNull("actor.user.name") OR toString("actor.user.name") = '')"#),
        "{sql}"
    );
    // An unmapped-tail field projects '' when absent: same treatment.
    let sql = ocsf_sql("* | where isnull(unmapped.foo) | stats count");
    assert!(sql.contains(r#"toString("unmapped.foo") = ''"#), "{sql}");
}

/// UDM keeps the plain `isNull` (its golden corpus is unchanged).
#[test]
fn isnull_on_udm_is_unchanged() {
    let sql = udm_sql("* | where isnull(user) | stats count");
    assert!(sql.contains("isNull("), "{sql}");
    assert!(!sql.contains("toString(user) = ''"), "{sql}");
}

/// `coalesce` and `fillnull` follow the OCSF `isnull` rule: '' is absent.
#[test]
fn coalesce_and_fillnull_treat_empty_string_as_absent_on_ocsf() {
    let sql = ocsf_sql(r#"* | eval who=coalesce(user.name, actor.user.name, "unknown") | stats count by who"#);
    assert!(
        sql.contains(r#"coalesce(if(toString("user.name") = '', NULL, "user.name"), if(toString("actor.user.name") = '', NULL, "actor.user.name"), 'unknown')"#),
        "{sql}"
    );
    let sql = ocsf_sql(r#"* | fillnull value="-" user.name | stats count by user.name"#);
    assert!(sql.contains(r#"ifNull(toString(nullIf(toString("#), "{sql}");
    // UDM is unchanged.
    let sql = udm_sql(r#"* | eval who=coalesce(user, src_user, "unknown") | stats count by who"#);
    assert!(!sql.contains("if(toString("), "{sql}");
    let sql = udm_sql(r#"* | fillnull value="-" user | stats count by user"#);
    assert!(!sql.contains("nullIf(toString("), "{sql}");
}

/// The NAN-5277 forms keep the CLAUDE.md ClickHouse rules: no explicit
/// PREWHERE and no JSONExtract on promoted OCSF columns.
#[test]
fn ocsf_null_forms_keep_clickhouse_rules() {
    for npl in [
        "* | where isnull(user.name) | stats count",
        "* | where isnotnull(src_endpoint.ip) | stats count",
        r#"* | eval who=coalesce(user.name, "x") | stats count by who"#,
        r#"* | fillnull value="-" device.hostname | stats count by device.hostname"#,
        "* | eval x=1 | timechart span=1h count by device.hostname | sort -time_bucket",
    ] {
        let sql = ocsf_sql(npl);
        assert!(!sql.to_uppercase().contains("PREWHERE"), "{npl}: {sql}");
        assert!(!sql.contains("JSONExtract"), "{npl}: {sql}");
    }
}

/// NAN-5285 (v2.0.13 retest F9): a piped `| search "kw"` on OCSF tokenizes
/// `message` OR `raw_data` (NAN-1828), so the pruned base stage must project
/// `raw_data`; it projected only `message` and ClickHouse answered "Field
/// 'raw_data' does not exist" (400). A keyword in the base search runs on the
/// table itself and must not widen the projection.
#[test]
fn piped_search_keyword_projects_raw_data_on_ocsf() {
    use crate::query::clickhouse_sql_gen::QueryOptions;
    let options = QueryOptions {
        table_view: true,
        ..QueryOptions::default()
    };
    let generate = |npl: &str| {
        let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
        ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate_with_options(&q, &time_range(), &options)
            .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
    };
    for npl in [
        r#"action=blocked | search "blk2013""#,
        r#"class_uid=4002 | search blk2013 | table src_endpoint.ip"#,
    ] {
        let sql = generate(npl);
        let base = sql.split("WHERE").next().unwrap_or_default().to_string();
        assert!(
            sql.contains("hasAllTokens(lower(raw_data)"),
            "{npl}: the keyword must also search raw_data: {sql}"
        );
        assert!(
            base.contains("raw_data") || base.contains("SELECT *"),
            "{npl}: the base stage must project raw_data for the piped keyword: {sql}"
        );
    }
    let base_only = generate(r#""blk2013" | table src_endpoint.ip"#);
    let select = base_only.split("FROM").next().unwrap_or_default();
    assert!(
        !select.contains("raw_data"),
        "a base-search keyword must not add raw_data to the projection: {base_only}"
    );
}

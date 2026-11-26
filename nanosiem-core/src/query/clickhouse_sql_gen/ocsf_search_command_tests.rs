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

/// NAN-5849: when one event spells a stored path twice, the ingest lane
/// stores the flat key with its dots escaped (`a.b` -> `a~1b`). The Field
/// Explorer's "Add to filter" emits `unmapped.a~1b="..."`: it must parse,
/// pass field validation, and reach SQL as a quoted JSON path segment.
#[test]
fn an_escaped_key_from_a_path_collision_is_queryable() {
    use crate::query::{Query, SearchExpr};
    use crate::query::validation::validate_field_name_format;

    match parse_query(r#"unmapped.a~1b="c1-flat""#).unwrap() {
        Query::Search(SearchExpr::FieldFilter { field, .. }) => assert_eq!(field, "unmapped.a~1b"),
        other => panic!("{other:?}"),
    }
    match parse_query(r#"unmapped.x~0y.a~1b~1c="v""#).unwrap() {
        Query::Search(SearchExpr::FieldFilter { field, .. }) => assert_eq!(field, "unmapped.x~0y.a~1b~1c"),
        other => panic!("{other:?}"),
    }
    // The regex operators are untouched.
    assert!(matches!(
        parse_query(r#"user=~"admin""#).unwrap(),
        Query::Search(SearchExpr::FieldFilter { ref field, .. }) if field == "user"
    ));
    assert!(validate_field_name_format("unmapped.a~1b").is_ok());
    assert!(validate_field_name_format("unmapped.a~0b~1c").is_ok());
    for bad in ["unmapped.a~2b", "unmapped.a~", "unmapped.a~b", "~1a"] {
        assert!(validate_field_name_format(bad).is_err(), "{bad}");
    }
    for npl in [
        r#"unmapped.a~1b="c1-flat""#,
        r#"* | where unmapped.a~1b="c1-flat""#,
        "* | stats count by unmapped.a~1b",
        "* | table unmapped.a~1b",
    ] {
        let sql = ocsf_sql(npl);
        assert!(sql.contains("\"a~1b\""), "{npl}: the segment is quoted: {sql}");
    }
}

/// NAN-5895: a numeric literal against an untyped JSON path (`unmapped.x`) in
/// a piped `where` / `search` / `eval` compares numbers, as the search term
/// does. Before, the stage value (the path's text) was compared bare with the
/// number: a ClickHouse NO_COMMON_TYPE error (String vs UInt8) that failed the
/// whole search. Strings keep their case-insensitive text compare.
#[test]
fn a_numeric_literal_against_a_json_path_in_a_piped_where_is_typed() {
    let base = |npl: &str| {
        let sql = ocsf_sql(npl);
        let at = sql.find("' AND ").unwrap() + 6;
        let at = at + sql[at..].find("' AND ").unwrap() + 6;
        sql[at..sql.find(" ORDER BY").unwrap()].to_string()
    };
    let piped = |npl: &str| {
        let sql = ocsf_sql(npl);
        let at = sql.rfind("WHERE ").unwrap() + 6;
        sql[at..at + sql[at..].find("\n)").unwrap()].to_string()
    };
    // While the stage carries the event: exactly the search-term predicate.
    for (op, n) in [("=", "5"), ("!=", "5"), (">", "5"), ("<", "6"), (">=", "5"), ("<=", "5"), ("=", "5.5")] {
        let term = format!("unmapped.x{op}{n}");
        let want = base(&term);
        assert!(want.contains("accurateCastOrNull(unmapped.\"x\", 'Float64')"), "{term}: {want}");
        for npl in [format!("* | where {term}"), format!("* | search {term}"), format!("* | eval y=1 | where {term}")] {
            // The search term's WHERE wraps it in one pair of parentheses.
            assert_eq!(format!("({})", piped(&npl)), want, "{npl}");
        }
    }
    // After a projection the stage column holds the path's text: cast it.
    let projected = piped("* | table unmapped.x | where unmapped.x>5");
    assert_eq!(projected, "accurateCastOrNull(toString(\"unmapped.x\"), 'Float64') > 5", "{projected}");
    // The typing follows the stage, not the whole query: a LATER stage that
    // groups on or recomputes the path does not change this one.
    for npl in [
        "* | where unmapped.x>5 | stats count by unmapped.x",
        "* | search unmapped.x>5 | eventstats count as c by unmapped.x",
        "* | where unmapped.x>5 | eval unmapped.x = 1",
        "* | eventstats count as c by unmapped.x | where unmapped.x>5",
    ] {
        let sql = ocsf_sql(npl);
        assert!(sql.contains("accurateCastOrNull(unmapped.\"x\", 'Float64') > 5"), "{npl}: {sql}");
    }
    // Columns that pass the path's text through: cast, under any name.
    let cast = |npl: &str, col: &str| {
        let got = piped(npl);
        let col = if col.contains('.') { format!("\"{col}\"") } else { col.to_string() };
        assert_eq!(got, format!("accurateCastOrNull(toString({col}), 'Float64') > 5"), "{npl}");
    };
    cast("* | stats count by unmapped.x | where unmapped.x>5", "unmapped.x");
    cast("* | chart count by unmapped.x | where unmapped.x>5", "unmapped.x");
    cast("* | table unmapped.x | stats count by unmapped.x | where unmapped.x>5", "unmapped.x");
    cast("* | table unmapped.x as y | where y>5", "y");
    cast("* | table unmapped.x | table unmapped.x as y | where y>5", "y");
    cast("* | table unmapped.x as y | table y as z | where z>5", "z");
    cast("* | rename unmapped.x as y | where y>5", "y");
    cast("* | eval y = unmapped.x | where y>5", "y");
    cast("* | eval y = unmapped.x | rename y as z | where z>5", "z");
    // Round 2: fields, top / rare / transaction grouping columns, text
    // rewrites in place, and the join / append subsearch hand-off.
    cast("* | fields unmapped.x | where unmapped.x>5", "unmapped.x");
    cast("* | eval y = unmapped.x | fields y* | where y>5", "y");
    cast("* | eval y = unmapped.x | fields - z | where y>5", "y");
    cast("* | top unmapped.x | where unmapped.x>5", "unmapped.x");
    cast("* | rare unmapped.x | where unmapped.x>5", "unmapped.x");
    cast("* | top unmapped.label by unmapped.x | where unmapped.x>5", "unmapped.x");
    cast("* | transaction unmapped.x | where unmapped.x>5", "unmapped.x");
    cast(r#"* | eval y = unmapped.x | fillnull value="0" y | where y>5"#, "y");
    cast(r#"* | eval y = unmapped.x | rex field=y mode=sed "s/a/b/" | where y>5"#, "y");
    cast("* | table unmapped.x | append [search * | table unmapped.x] | where unmapped.x>5", "unmapped.x");
    cast("* | join id [search * | table id, unmapped.x as y] | where y>5", "y");
    cast("* | eval y = unmapped.x | join id [search * | eval y = 10 | table id] | where y>5", "y");
    cast("* | join id [search * | eval y = unmapped.x] | where y>5", "y");
    cast("* | join id [search * | rename unmapped.x as y] | where y>5", "y");
    cast("* | table id, unmapped.label | join id [search * | eval message = unmapped.x] | where message>5", "message");
    cast("* | fields - message | join id [search * | eval message = unmapped.x] | where message>5", "message");
    cast("* | eval y = unmapped.x | spath output=y | where y>5", "y");
    // fillnull / rex sed replace the column a projection left under that
    // name (table, fields, top, rare, transaction), never add a second one.
    for projector in [
        "table unmapped.x",
        "fields unmapped.x",
        "top unmapped.label by unmapped.x",
        "rare unmapped.label by unmapped.x",
        "transaction unmapped.label, unmapped.x",
    ] {
        let filled = ocsf_sql(&format!(r#"* | {projector} | fillnull value="9" unmapped.x"#));
        assert!(filled.contains("SELECT * EXCEPT (\"unmapped.x\"), ifNull(toString(nullIf(toString(\"unmapped.x\"), '')), '9')"), "{projector}: {filled}");
        let sed = ocsf_sql(&format!(r#"* | {projector} | rex field=unmapped.x mode=sed "s/5/9/""#));
        assert!(sed.contains("SELECT * REPLACE(replaceRegexpAll(\"unmapped.x\"::String"), "{projector}: {sed}");
    }
    // bin reads a JSON-text column as a number.
    let binned = ocsf_sql("* | eval y = unmapped.x | bin y span=2");
    assert!(binned.contains("floor(toFloat64OrNull(toString(y)) / 2) * 2"), "{binned}");
    // fillnull replaces a stage column instead of duplicating its name.
    let filled = ocsf_sql(r#"* | table unmapped.x | fillnull value="9" unmapped.x"#);
    assert!(filled.contains("SELECT * EXCEPT (\"unmapped.x\"), ifNull("), "{filled}");
    let raw_fill = ocsf_sql(r#"* | fillnull value="9" unmapped.x"#);
    assert!(!raw_fill.contains("EXCEPT"), "{raw_fill}");
    // Names a stage computed keep the bare compare.
    for (npl, want) in [
        ("* | eval n = 10 | table n | where n>5", "n > 5"),
        ("* | eval n = 10 | table n as m | where m>5", "m > 5"),
        ("* | eval unmapped.x = 10 | where unmapped.x>5", "\"unmapped.x\" > 5"),
        ("* | eval y = unmapped.x | eval y = 10 | where y>5", "y > 5"),
        ("* | rename unmapped.x as y | eval y = 10 | where y>5", "y > 5"),
        ("* | stats count as unmapped.x by unmapped.label | where unmapped.x>5", "\"unmapped.x\" > 5"),
        ("* | transaction unmapped.x | where eventcount>5", "eventcount > 5"),
        ("* | top unmapped.x | where count>5", "count > 5"),
        ("* | eval y = unmapped.x | bin y span=10 | where y>5", "y > 5"),
        ("* | eval y = unmapped.x | join id [search * | eval y = 10 | table id, y] | where y>5", "y > 5"),
        ("* | table unmapped.x | append [search * | eval unmapped.x = 1 | table unmapped.x] | where unmapped.x>5", "\"unmapped.x\" > 5"),
    ] {
        assert_eq!(piped(npl), want, "{npl}");
    }
    // NAN-4276 String evals keep their text compare (on OCSF a bare name
    // resolves to an `unmapped` path, but `s` is no copy of one).
    let text_eval = piped("* | eval s = lower(status) | where s = 7");
    assert!(text_eval.contains("'7'") && !text_eval.contains("accurateCastOrNull"), "{text_eval}");

    // Strings, IN lists and typed columns are unchanged.
    let text = piped(r#"* | where unmapped.x="abc""#);
    assert!(text.contains("= 'abc'") && !text.contains("accurateCastOrNull"), "{text}");
    let list = piped("* | where unmapped.x IN (5, 7)");
    assert!(list.contains("IN (5, 7)") && !list.contains("accurateCastOrNull"), "{list}");
    let typed = piped("* | where src_endpoint.port>5");
    assert!(!typed.contains("accurateCastOrNull"), "{typed}");
    // A stage-computed name keeps the bare compare.
    let computed = piped("* | stats count by unmapped.x | where count>5");
    assert_eq!(computed, "count > 5", "{computed}");

    // eval: `==` / `!=` with a number casts like the ordered comparisons.
    let eq = ocsf_sql("* | eval eq=if(unmapped.x == 5, 1, 0)");
    assert!(eq.contains("(toFloat64OrNull(toString(multiIf(isNotNull(unmapped.\"x\")"), "{eq}");
    assert!(eq.contains("''))) = 5)"), "{eq}");
    let ne = ocsf_sql("* | eval ne=if(5 != unmapped.x, 1, 0)");
    assert!(ne.contains("''))) != 5)"), "{ne}");
    let text_eq = ocsf_sql(r#"* | eval t=if(unmapped.x == "abc", 1, 0)"#);
    assert!(text_eq.contains("= 'abc'") && !text_eq.contains("toFloat64OrNull"), "{text_eq}");
    for npl in [
        "* | table unmapped.x as y | eval eq=if(y == 5, 1, 0)",
        "* | stats count by unmapped.x | eval eq=if(unmapped.x == 5, 1, 0)",
        "* | eval eq=if(unmapped.x == 5, 1, 0) | stats count by unmapped.x",
        "* | rename unmapped.x as y | eval eq=if(y == 5, 1, 0)",
    ] {
        let sql = ocsf_sql(npl);
        assert!(sql.contains("(toFloat64OrNull(toString(") && sql.contains(")) = 5)"), "{npl}: {sql}");
    }
    let computed_eq = ocsf_sql("* | eval n = 10 | eval eq=if(n == 10, 1, 0)");
    assert!(!computed_eq.contains("toFloat64OrNull"), "{computed_eq}");
    let typed_eq = ocsf_sql("* | eval p=if(src_endpoint.port == 5, 1, 0)");
    assert!(!typed_eq.contains("toFloat64OrNull"), "{typed_eq}");
}

/// NAN-5895 live proof input for `scripts/tests/piped-where-json-numeric-ch.live.sh`:
/// each query's full SQL (read from table `t`) and the rows it must return.
/// Writes `NANO_JSON_NUMERIC_SQL_OUT` when set.
///
/// Rows: `n5`, `n5_0`, `n7`, `n5_5` hold numbers; `s5` / `s5_0` the text "5"
/// / "5.0", `sabc` "abc"; `none` no `x`. Each row's label is also
/// `unmapped.label`, so a query that projects or groups still names its rows.
/// The probe table's `id` is the label too: a typed key to `join` on (a join
/// on an `unmapped.*` key is a ClickHouse Dynamic-key error, a separate issue).
pub(crate) const JSON_NUMERIC_LIVE_ROWS: &str = r#"{"timestamp":"2026-10-08 00:30:00","label":"n5","unmapped":{"label":"n5","x":5}}
{"timestamp":"2026-10-08 00:30:00","label":"n5_0","unmapped":{"label":"n5_0","x":5.0}}
{"timestamp":"2026-10-08 00:30:00","label":"n7","unmapped":{"label":"n7","x":7}}
{"timestamp":"2026-10-08 00:30:00","label":"n5_5","unmapped":{"label":"n5_5","x":5.5}}
{"timestamp":"2026-10-08 00:30:00","label":"s5","unmapped":{"label":"s5","x":"5"}}
{"timestamp":"2026-10-08 00:30:00","label":"s5_0","unmapped":{"label":"s5_0","x":"5.0"}}
{"timestamp":"2026-10-08 00:30:00","label":"sabc","unmapped":{"label":"sabc","x":"abc"}}
{"timestamp":"2026-10-08 00:30:00","label":"none","unmapped":{"label":"none","y":1}}
"#;

/// The numeric terms and their rows; every stage shape must return exactly
/// these (the search term's rows).
const JSON_NUMERIC_TERMS: &[(&str, &str)] = &[
    ("=5", "n5,n5_0,s5,s5_0"),
    ("!=5", "n5_5,n7"),
    (">5", "n5_5,n7"),
    ("<6", "n5,n5_0,n5_5,s5,s5_0"),
    (">=5", "n5,n5_0,n5_5,n7,s5,s5_0"),
    ("<=5", "n5,n5_0,s5,s5_0"),
    ("=5.5", "n5_5"),
];

/// Every stage shape a numeric term is checked in. `{x}` is the operand name
/// in that shape; `{term}` the comparison.
const JSON_NUMERIC_SHAPES: &[&str] = &[
    "{x}{term}",
    "* | where {x}{term}",
    "* | search {x}{term}",
    "* | where NOT (NOT {x}{term})",
    // A later stage that names the same path must not change this stage.
    "* | where {x}{term} | stats count by unmapped.label, unmapped.x",
    "* | search {x}{term} | eventstats count as c by unmapped.x",
    "* | where {x}{term} | eval unmapped.x = 1",
    // A stage column that passes the path's text through.
    "* | table unmapped.label, timestamp, {x} | where {x}{term}",
    "* | table unmapped.label, timestamp, {x} as y | where y{term}",
    "* | table unmapped.label, timestamp, {x} | table unmapped.label, timestamp, {x} as y | where y{term}",
    "* | table unmapped.label, timestamp, {x} as y | table unmapped.label, timestamp, y as z | where z{term}",
    "* | rename {x} as y | where y{term}",
    "* | eval y = {x} | where y{term}",
    "* | eval y = {x} | rename y as z | where z{term}",
    "* | stats count by unmapped.label, {x} | where {x}{term}",
    "* | table unmapped.label, timestamp, {x} | stats count by unmapped.label, {x} | where {x}{term}",
    "* | eventstats count as c by {x} | where {x}{term}",
    // Round 2: fields (include, wildcard, exclude), top / rare / transaction
    // grouping columns, text rewrites in place, and subsearch hand-off.
    "* | fields unmapped.label, timestamp, {x} | where {x}{term}",
    "* | eval y = {x} | fields unmapped.label, timestamp, y* | where y{term}",
    "* | eval y = {x} | fields - z | where y{term}",
    "* | top limit=100 unmapped.label by {x} | where {x}{term}",
    "* | rare limit=100 unmapped.label by {x} | where {x}{term}",
    "* | transaction unmapped.label, {x} | where {x}{term}",
    r#"* | eval y = {x} | fillnull value="" y | where y{term}"#,
    r#"* | eval y = {x} | rex field=y mode=sed "s/zz/zz/" | where y{term}"#,
    "* | join id [search * | table id, {x} as y] | where y{term}",
    "* | eval y = {x} | join id [search * | eval y = 10 | where y > 5 | table id] | where y{term}",
];

#[test]
fn dump_json_numeric_queries_for_clickhouse() {
    let Ok(out) = std::env::var("NANO_JSON_NUMERIC_SQL_OUT") else { return };
    let gen = |npl: &str| {
        let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
        let sql = ClickHouseSqlGenerator::with_table("t")
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap_or_else(|e| panic!("{npl:?}: {e}"));
        // The probe table holds only timestamp, label and unmapped: drop the
        // profile's extra stage-0 columns (prevalence_*, *_unified, ...).
        let sql = regex::Regex::new(r"SELECT \*,[^()]*? FROM t\b").unwrap().replace_all(&sql, "SELECT * FROM t");
        sql.replace('\n', " ")
    };
    let mut tsv = String::new();
    for (term, want) in JSON_NUMERIC_TERMS {
        for shape in JSON_NUMERIC_SHAPES {
            let npl = shape.replace("{x}", "unmapped.x").replace("{term}", term);
            tsv.push_str(&format!("{npl}\t{want}\t{}\n", gen(&npl)));
        }
    }
    const ALL: &str = "n5,n5_0,n5_5,n7,none,s5,s5_0,sabc";
    for (npl, want) in [
        // Strings, IN lists and text copies keep their text compare.
        (r#"unmapped.x="abc""#, "sabc"),
        (r#"* | where unmapped.x="abc""#, "sabc"),
        (r#"* | where unmapped.x!="abc""#, "n5,n5_0,n5_5,n7,none,s5,s5_0"),
        (r#"* | table unmapped.label, timestamp, unmapped.x as y | where y="abc""#, "sabc"),
        (r#"* | eval y = unmapped.x | where y="abc""#, "sabc"),
        (r#"* | where unmapped.x IN ("abc", "5")"#, "n5,n5_0,s5,sabc"),
        ("* | where unmapped.x IN (5, 7)", "n5,n5_0,n7,s5"),
        // NOT around a numeric term.
        ("* | where NOT unmapped.x=5", "n5_5,n7"),
        ("* | where NOT unmapped.x>5", "n5,n5_0,s5,s5_0"),
        // eval == / != with a number, in every stage shape.
        ("* | eval big=if(unmapped.x > 5, 1, 0) | where big=1", "n5_5,n7"),
        ("* | eval eq=if(unmapped.x == 5, 1, 0) | where eq=1", "n5,n5_0,s5,s5_0"),
        ("* | eval ne=if(unmapped.x != 5, 1, 0) | where ne=1", "n5_5,n7"),
        ("* | eval eq=if(5 == unmapped.x, 1, 0) | where eq=1 | stats count by unmapped.label, unmapped.x", "n5,n5_0,s5,s5_0"),
        ("* | table unmapped.label, timestamp, unmapped.x as y | eval eq=if(y == 5, 1, 0) | where eq=1", "n5,n5_0,s5,s5_0"),
        ("* | stats count by unmapped.label, unmapped.x | eval eq=if(unmapped.x == 5, 1, 0) | where eq=1", "n5,n5_0,s5,s5_0"),
        ("* | rename unmapped.x as y | eval ne=if(y != 5, 1, 0) | where ne=1", "n5_5,n7"),
        (r#"* | eval t=if(unmapped.x == "abc", 1, 0) | where t=1"#, "sabc"),
        // Names a stage computed keep the bare numeric compare.
        ("* | eval n = 10 | table unmapped.label, n | where n > 5", ALL),
        ("* | eval n = 10 | table unmapped.label, n as m | where m > 5", ALL),
        ("* | stats count as n by unmapped.label | where n > 0", ALL),
        ("* | eval unmapped.x = 10 | where unmapped.x > 5", ALL),
        ("* | eval unmapped.x = 10 | table unmapped.label, unmapped.x | where unmapped.x > 5", ALL),
        ("* | eval y = unmapped.x | eval y = 10 | where y > 5", ALL),
        ("* | rename unmapped.x as y | eval y = 10 | where y > 5", ALL),
        // A text rewrite in place keeps the JSON-text typing.
        (r#"* | eval y = unmapped.x | fillnull value="99" y | where y > 50"#, "none"),
        (r#"* | table unmapped.label, timestamp, unmapped.x | fillnull value="99" unmapped.x | where unmapped.x > 50"#, "none"),
        (r#"* | eval y = unmapped.x | rex field=y mode=sed "s/5/9/" | where y > 8"#, "n5,n5_0,n5_5,s5,s5_0"),
        // append: a column is JSON text when every arm carrying it is.
        ("* | table unmapped.label, timestamp, unmapped.x | append [search * | table unmapped.label, timestamp, unmapped.x] | where unmapped.x > 5", "n5_5,n5_5,n7,n7"),
        ("* | table unmapped.label, timestamp, unmapped.x as y | append [search * | table unmapped.label, timestamp, unmapped.x as y] | where y > 5", "n5_5,n5_5,n7,n7"),
        // Computed outputs of grouping stages stay bare.
        ("* | transaction unmapped.label | where eventcount > 0", ALL),
        ("* | top limit=100 unmapped.label by unmapped.x | where count > 0", ALL),
        ("* | eval y = unmapped.x | join id [search * | eval y = 10 | table id, y] | where y > 5", ALL),
        // fillnull / rex sed after every projector: the value is replaced in
        // the one column of that name (an unfilled duplicate matched nothing).
        (r#"* | fields unmapped.label, timestamp, unmapped.x | fillnull value="99" unmapped.x | where unmapped.x > 50"#, "none"),
        (r#"* | top limit=100 unmapped.label by unmapped.x | fillnull value="99" unmapped.x | where unmapped.x > 50"#, "none"),
        (r#"* | rare limit=100 unmapped.label by unmapped.x | fillnull value="99" unmapped.x | where unmapped.x > 50"#, "none"),
        (r#"* | transaction unmapped.label, unmapped.x | fillnull value="99" unmapped.x | where unmapped.x > 50"#, "none"),
        (r#"* | fields unmapped.label, timestamp, unmapped.x | rex field=unmapped.x mode=sed "s/5/9/" | where unmapped.x > 8"#, "n5,n5_0,n5_5,s5,s5_0"),
        (r#"* | top limit=100 unmapped.label by unmapped.x | rex field=unmapped.x mode=sed "s/5/9/" | where unmapped.x > 8"#, "n5,n5_0,n5_5,s5,s5_0"),
        (r#"* | rare limit=100 unmapped.label by unmapped.x | rex field=unmapped.x mode=sed "s/5/9/" | where unmapped.x > 8"#, "n5,n5_0,n5_5,s5,s5_0"),
        (r#"* | transaction unmapped.label, unmapped.x | rex field=unmapped.x mode=sed "s/5/9/" | where unmapped.x > 8"#, "n5,n5_0,n5_5,s5,s5_0"),
        // bin: on the event path, on a JSON-text copy (in place and aliased),
        // and after a projection. 5, 5.0, 5.5, "5", "5.0" bin to 4; 7 to 6.
        ("* | bin unmapped.x span=2 | where unmapped.x > 5", "n7"),
        ("* | eval y = unmapped.x | bin y span=2 | where y > 5", "n7"),
        ("* | eval y = unmapped.x | bin y span=2 as b | where b > 5", "n7"),
        ("* | fields unmapped.label, timestamp, unmapped.x | bin unmapped.x span=2 | where unmapped.x > 5", "n7"),
        // A wide (unprojected) join subsearch hands its JSON-text columns over.
        ("* | join id [search * | eval y = unmapped.x] | where y > 5", "n5_5,n7"),
        ("* | join id [search * | rename unmapped.x as y] | where y > 5", "n5_5,n7"),
        // ...also under a schema column name the main side projected away.
        ("* | table id, unmapped.label, timestamp | join id [search * | eval message = unmapped.x] | where message > 5", "n5_5,n7"),
        ("* | fields id, unmapped.label, timestamp | join id [search * | eval message = unmapped.x] | where message > 5", "n5_5,n7"),
        ("* | fields - message | join id [search * | eval message = unmapped.x] | where message > 5", "n5_5,n7"),
        // spath without path= is a no-op and keeps the typing.
        ("* | eval y = unmapped.x | spath output=y | where y > 5", "n5_5,n7"),
    ] {
        tsv.push_str(&format!("{npl}\t{want}\t{}\n", gen(npl)));
    }
    std::fs::write(&out, tsv).unwrap();
    std::fs::write(format!("{out}.rows"), JSON_NUMERIC_LIVE_ROWS).unwrap();
}

/// NAN-5894: `unmapped.a~1b` is the one name for a flat key that clashed with
/// a nested path, on every ingest path. Rows a parser stored before NAN-5894
/// hold the same value as `unmapped.a.b_2`, so a filter on the escaped name
/// also matches that legacy spelling: OR for a positive filter, AND for a
/// negative one, in the base search and in a piped `where` alike.
#[test]
fn an_escaped_clash_name_also_matches_its_legacy_suffix_name() {
    use super::search_expr::legacy_clash_suffix_name;

    assert_eq!(legacy_clash_suffix_name("unmapped.a~1b").as_deref(), Some("unmapped.a.b_2"));
    assert_eq!(legacy_clash_suffix_name("unmapped.x.a~1b").as_deref(), Some("unmapped.x.a.b_2"));
    assert_eq!(legacy_clash_suffix_name("unmapped.x~1a.b").as_deref(), Some("unmapped.x.a.b_2"));
    for none in [
        "unmapped.a.b", "unmapped.a.b_2", "unmapped.a~0b~1c", "src_endpoint.ip", "a~1b", "event.a~1b",
        // An empty decoded segment (leading, trailing or doubled dot): no alias.
        "unmapped.~1b", "unmapped.a~1", "unmapped.a~1~1b", "unmapped.a~1.b", "unmapped.a.~1b",
    ] {
        assert_eq!(legacy_clash_suffix_name(none), None, "{none}");
    }

    let both = |sql: &str| sql.contains("\"a~1b\"") && sql.contains("\"b_2\"");
    for npl in [
        r#"unmapped.a~1b="v1""#,
        r#"unmapped.a~1b=v*"#,
        r#"unmapped.a~1b IN ("v1", "v2")"#,
        r#"* | where unmapped.a~1b="v1""#,
        r#"* | search unmapped.a~1b="v1""#,
        r#"* | where unmapped.a~1b IN ("v1", "v2")"#,
    ] {
        let sql = ocsf_sql(npl);
        assert!(both(&sql), "{npl}: both spellings: {sql}");
        assert!(sql.contains(" OR "), "{npl}: a positive filter ORs them: {sql}");
        assert!(!sql.contains("PREWHERE"), "{npl}: no explicit PREWHERE: {sql}");
    }
    for npl in [
        r#"unmapped.a~1b!="v1""#,
        r#"NOT unmapped.a~1b IN ("v1")"#,
        r#"* | where unmapped.a~1b!="v1""#,
    ] {
        let sql = ocsf_sql(npl);
        assert!(both(&sql), "{npl}: both spellings: {sql}");
    }
    // A negative comparator: the row is excluded when either spelling holds it.
    let ne = ocsf_sql(r#"unmapped.a~1b!="v1""#);
    let at = ne.find("\"a~1b\"").unwrap();
    assert!(ne[at..].contains(" AND "), "!= joins with AND: {ne}");

    // NULL-safe: a row holds one spelling, so a numeric leg on the absent one
    // is NULL. An absent leg is "no match" (OR, ifNull 0) for a positive
    // filter and "not equal" (AND, ifNull 1) for a negative one; NULL only when
    // both are absent. `scripts/tests/legacy-clash-alias-ch.live.sh` runs these
    // on ClickHouse against rows holding the new, the legacy, both or neither.
    for (npl, absent) in [
        ("unmapped.a~1b=5", "0) OR ifNull("),
        ("unmapped.a~1b>5", "0) OR ifNull("),
        ("NOT unmapped.a~1b=5", "0) OR ifNull("),
        ("unmapped.a~1b!=5", "1) AND ifNull("),
        (r#"* | where unmapped.a~1b!="v1""#, "1) AND ifNull("),
        (r#"unmapped.a~1b!="v1""#, "1) AND ifNull("),
    ] {
        let sql = ocsf_sql(npl);
        assert!(sql.contains("multiIf(isNull("), "{npl}: NULL only when both legs are: {sql}");
        assert!(sql.contains(absent), "{npl}: an absent leg reads as {absent:?}: {sql}");
        assert!(both(&sql), "{npl}: both spellings: {sql}");
    }

    for npl in [r#"unmapped.~1b="v""#, r#"unmapped.a~1="v""#, r#"unmapped.a~1~1b="v""#, r#"unmapped.a~1.b="v""#, r#"* | where unmapped.a.~1b="v""#] {
        let sql = ocsf_sql(npl);
        assert!(!sql.contains("\"\"") && !sql.contains("b_2"), "{npl}: no empty segment, no alias: {sql}");
    }

    // The legacy name alone is untouched, and so is every other field.
    for npl in [r#"unmapped.a.b_2="v1""#, r#"unmapped.a.b="v1""#] {
        let sql = ocsf_sql(npl);
        assert!(!sql.contains("~1"), "{npl}: no reverse alias: {sql}");
    }
    let plain = ocsf_sql(r#"unmapped.a.b="v1""#);
    assert!(!plain.contains("b_2"), "{plain}");

    // After a projection the legacy name is no stage column: no alias.
    let projected = ocsf_sql(r#"* | table unmapped.a~1b | where unmapped.a~1b="v1""#);
    let tail = projected.rsplit("WHERE").next().unwrap_or_default();
    assert!(!tail.contains("b_2"), "projected stage: {projected}");

    // UDM has no `unmapped` JSON column: no alias.
    let udm = udm_sql(r#"unmapped.a~1b="v1""#);
    assert!(!udm.contains("b_2"), "{udm}");
}

/// NAN-5894 live proof input: the generated alias predicates and the rows
/// each must return, for `scripts/tests/legacy-clash-alias-ch.live.sh` (which
/// runs them on ClickHouse). Writes `NANO_LEGACY_ALIAS_PREDS_OUT` when set.
///
/// Rows: `new_*` hold the NAN-5894 name (`a~1b`), `leg_*` the legacy one
/// (`a.b_2`), `both_5_7` both, `none` neither; `str_*` hold text.
pub(crate) const LEGACY_ALIAS_LIVE_ROWS: &str = r#"{"label":"new_5","unmapped":{"a~1b":5}}
{"label":"new_7","unmapped":{"a~1b":7}}
{"label":"leg_5","unmapped":{"a":{"b_2":5}}}
{"label":"leg_7","unmapped":{"a":{"b_2":7}}}
{"label":"both_5_7","unmapped":{"a~1b":5,"a":{"b_2":7}}}
{"label":"none","unmapped":{"x":1}}
{"label":"str_new","unmapped":{"a~1b":"flat"}}
{"label":"str_leg","unmapped":{"a":{"b_2":"flat"}}}
{"label":"str_other","unmapped":{"a~1b":"other"}}
{"label":"odd_lead","unmapped":{"~1b":"odd"}}
{"label":"odd_trail","unmapped":{"a~1":"odd"}}
{"label":"odd_double","unmapped":{"a~1~1b":"odd"}}
{"label":"odd_mixed","unmapped":{"a":{"~1b":"odd"}}}
"#;

#[test]
fn dump_legacy_alias_predicates_for_clickhouse() {
    let Ok(out) = std::env::var("NANO_LEGACY_ALIAS_PREDS_OUT") else { return };
    const ALL_BUT_FLAT: &str = "both_5_7,leg_5,leg_7,new_5,new_7,none,odd_double,odd_lead,odd_mixed,odd_trail,str_other";
    let cases: &[(&str, &str)] = &[
        ("unmapped.a~1b=5", "both_5_7,leg_5,new_5"),
        ("unmapped.a~1b!=5", "leg_7,new_7"),
        ("NOT unmapped.a~1b=5", "leg_7,new_7"),
        ("unmapped.a~1b>5", "both_5_7,leg_7,new_7"),
        ("NOT unmapped.a~1b>5", "leg_5,new_5"),
        ("unmapped.a~1b IN (5, 7)", "both_5_7,leg_5,leg_7,new_5,new_7"),
        (r#"unmapped.a~1b="flat""#, "str_leg,str_new"),
        (r#"unmapped.a~1b!="flat""#, ALL_BUT_FLAT),
        (r#"NOT unmapped.a~1b="flat""#, ALL_BUT_FLAT),
        (r#"NOT unmapped.a~1b IN ("flat")"#, ALL_BUT_FLAT),
        ("unmapped.a~1b=*", "both_5_7,leg_5,leg_7,new_5,new_7,str_leg,str_new,str_other"),
        // Escaped names that decode to an empty segment: no alias, no error.
        (r#"unmapped.~1b="odd""#, "odd_lead"),
        (r#"unmapped.a~1="odd""#, "odd_trail"),
        (r#"unmapped.a~1~1b="odd""#, "odd_double"),
        (r#"unmapped.a.~1b="odd""#, "odd_mixed"),
        (r#"* | where unmapped.a~1~1b="odd""#, "odd_double"),
        // A numeric literal in a piped `where` on an `unmapped.*` field is not
        // here: it is a ClickHouse type error (String vs UInt8) with or without
        // the alias, a separate bug.
        (r#"* | where unmapped.a~1b!="flat""#, ALL_BUT_FLAT),
    ];
    let mut tsv = String::new();
    for (npl, want) in cases {
        let sql = ocsf_sql(npl);
        let pred = if npl.starts_with("* |") {
            let at = sql.rfind("WHERE ").unwrap() + 6;
            let end = at + sql[at..].find("\n)").unwrap();
            sql[at..end].to_string()
        } else {
            let start = sql.find("' AND ").unwrap() + 6;
            let start = start + sql[start..].find("' AND ").unwrap() + 6;
            sql[start..sql.find(" ORDER BY").unwrap()].to_string()
        };
        assert!(!pred.contains('\t') && !pred.contains('\n'), "{npl}: {pred}");
        tsv.push_str(&format!("{npl}\t{want}\t{pred}\n"));
    }
    std::fs::write(&out, tsv).unwrap();
    std::fs::write(format!("{out}.rows"), LEGACY_ALIAS_LIVE_ROWS).unwrap();
}

/// NAN-5896: a `join` on an untyped JSON path (`unmapped.k`) compares the key
/// as text on both sides. ClickHouse refuses a `Dynamic` join key (Code 44),
/// which every join on an `unmapped.*` key used to hit.
#[test]
fn a_join_on_a_json_path_key_compares_text_on_both_sides() {
    let sql = ocsf_sql("* | join unmapped.k [search * | table unmapped.k, unmapped.label as other]");
    assert!(sql.contains("ON toString(main.\"unmapped.k\") = toString(sub.\"unmapped.k\")"), "{sql}");
    assert!(sql.contains("LIMIT 1 BY toString(\"unmapped.k\")"), "{sql}");
    assert!(sql.contains("toString(\"unmapped.k\") IN (SELECT DISTINCT toString(\"unmapped.k\") FROM"), "{sql}");
    // Multi-key: only the JSON-path key is cast, and a main row without it
    // stays out of the narrowing set (it can never match).
    let multi = ocsf_sql("* | join id, unmapped.k [search * | table id, unmapped.k]");
    assert!(multi.contains("main.id = sub.id AND toString(main.\"unmapped.k\") = toString(sub.\"unmapped.k\")"), "{multi}");
    assert!(multi.contains("SELECT DISTINCT id, toString(\"unmapped.k\") FROM stage_0 WHERE toString(\"unmapped.k\") != '' LIMIT"), "{multi}");
    // A stage the pipeline does not model keeps the event row: still cast.
    for npl in [
        "* | fields - message | join unmapped.k [search * | table unmapped.k]",
        "* | eventstats count as c | join unmapped.k [search * | table unmapped.k]",
        "* | table unmapped.k | join unmapped.k [search * | sample 10]",
    ] {
        let sql = ocsf_sql(npl);
        assert!(sql.contains("toString(main.\"unmapped.k\") = toString(sub.\"unmapped.k\")"), "{npl}: {sql}");
    }
    // Concrete keys on both sides (projected, computed, typed) are unchanged.
    for npl in [
        "* | table unmapped.label, unmapped.k | join unmapped.k [search * | table unmapped.k]",
        "* | join id [search * | table id, unmapped.label]",
        "* | eval kk = tostring(unmapped.k) | join kk [search * | eval kk = tostring(unmapped.k) | table kk]",
    ] {
        let sql = ocsf_sql(npl);
        assert!(!sql.contains("toString(main."), "{npl}: {sql}");
    }
    // UDM keys are unchanged.
    let udm = udm_sql("* | join src_ip [search * | table src_ip, user]");
    assert!(!udm.contains("toString(main."), "{udm}");
}

/// NAN-5896 live proof input for `scripts/tests/join-json-key-ch.live.sh`:
/// each query's full SQL (read from table `t`) and the rows it must return.
/// Writes `NANO_JOIN_KEY_SQL_OUT` when set. `(none)` = no rows. Rows: `a`
/// k=5, `b` k="5", `c` k="5.0", `d` k="abc", `f` k=7, `g` k={"z":1} (an
/// object), `h` k=0, `i` k="0.0", `e` no k; `a` and `b` also carry
/// `risk_score` 30 (stored as `unmapped.risk_score`). Labels are also
/// `unmapped.label`; `id` is the label (a typed key).
pub(crate) const JOIN_KEY_LIVE_ROWS: &str = r#"{"timestamp":"2026-10-08 00:30:00","label":"a","unmapped":{"label":"a","k":5,"risk_score":30}}
{"timestamp":"2026-10-08 00:30:00","label":"b","unmapped":{"label":"b","k":"5","risk_score":30}}
{"timestamp":"2026-10-08 00:30:00","label":"c","unmapped":{"label":"c","k":"5.0"}}
{"timestamp":"2026-10-08 00:30:00","label":"d","unmapped":{"label":"d","k":"abc"}}
{"timestamp":"2026-10-08 00:30:00","label":"e","unmapped":{"label":"e"}}
{"timestamp":"2026-10-08 00:30:00","label":"f","unmapped":{"label":"f","k":7}}
{"timestamp":"2026-10-08 00:30:00","label":"g","unmapped":{"label":"g","k":{"z":1}}}
{"timestamp":"2026-10-08 00:30:00","label":"h","unmapped":{"label":"h","k":0}}
{"timestamp":"2026-10-08 00:30:00","label":"i","unmapped":{"label":"i","k":"0.0"}}
"#;

/// Every row whose key reads as a non-empty scalar text.
const JOIN_KEYED: &str = "a,b,c,d,f,h,i";

pub(crate) const JOIN_KEY_LIVE_CASES: &[(&str, &str)] = &[
    // Text semantics: 5 and "5" share the key "5"; "5.0" is its own key.
    ("* | join unmapped.k [search * | table unmapped.k, unmapped.label as other]", JOIN_KEYED),
    (r#"* | join unmapped.k [search * | where unmapped.label="b" | table unmapped.k]"#, "a,b"),
    (r#"* | join unmapped.k [search * | where unmapped.label="a" | table unmapped.k]"#, "a,b"),
    (r#"* | join unmapped.k [search * | where unmapped.label="c" | table unmapped.k]"#, "c"),
    // A wide (unprojected) subsearch: both sides read the JSON path.
    (r#"* | join unmapped.k [search * | where unmapped.label="f"]"#, "f"),
    // left join: unmatched and key-less rows stay, with no subsearch value.
    (r#"* | join type=left unmapped.k [search * | where unmapped.label="b" | table unmapped.k, unmapped.label as m] | where m="b""#, "a,b"),
    (r#"* | join type=left unmapped.k [search * | where unmapped.label="b" | table unmapped.k, unmapped.label as m]"#, "a,b,c,d,e,f,g,h,i"),
    // Multi-key with a typed key.
    ("* | join id, unmapped.k [search * | table id, unmapped.k]", JOIN_KEYED),
    // A grouped subsearch: stats by the path groups by the same text.
    ("* | join unmapped.k [search * | stats count as n by unmapped.k] | where n > 1", "a,b"),
    // Projected main side (a concrete String already).
    (r#"* | table unmapped.label, timestamp, unmapped.k | join unmapped.k [search * | where unmapped.label="f" | table unmapped.k]"#, "f"),
    // Stages that keep the event row but the pipeline does not model (main
    // side and subsearch side): the key still reads the JSON path.
    (r#"* | fields - message | join unmapped.k [search * | where unmapped.label="f" | table unmapped.k]"#, "f"),
    (r#"* | rex field=message "(?<tag>\w+)" | join unmapped.k [search * | where unmapped.label="f" | table unmapped.k]"#, "f"),
    (r#"* | fillnull value="0" message | join unmapped.k [search * | where unmapped.label="f" | table unmapped.k]"#, "f"),
    (r#"* | bin timestamp span=1h | join unmapped.k [search * | where unmapped.label="f" | table unmapped.k]"#, "f"),
    (r#"* | sample 100 | join unmapped.k [search * | where unmapped.label="f" | table unmapped.k]"#, "f"),
    (r#"* | eventstats count as c | join unmapped.k [search * | where unmapped.label="f" | table unmapped.k]"#, "f"),
    (r#"* | table unmapped.label, timestamp, unmapped.k | join unmapped.k [search * | where unmapped.label="f" | fields - message]"#, "f"),
    (r#"* | table unmapped.label, timestamp, unmapped.k | join unmapped.k [search * | where unmapped.label="f" | eventstats count as c]"#, "f"),
    // Typed keys are unchanged.
    ("* | join id [search * | table id, unmapped.k as kk]", "a,b,c,d,e,f,g,h,i"),
    // A key holding a JSON OBJECT: on a side that reads the event it has no
    // scalar value, so it never matches...
    (r#"* | join unmapped.k [search * | where unmapped.label="g" | table unmapped.k]"#, "(none)"),
    // ...but when both sides project it first, it is its JSON text and matches.
    (r#"* | table unmapped.label, timestamp, unmapped.k | join unmapped.k [search * | where unmapped.label="g" | table unmapped.k]"#, "g"),
    // Documented workaround 1: a text copy on both sides (objects as JSON text).
    (r#"* | eval kk = tostring(unmapped.k) | join kk [search * | where unmapped.label="g" | eval kk = tostring(unmapped.k) | table kk]"#, "g"),
    ("* | eval kk = tostring(unmapped.k) | join kk [search * | eval kk = tostring(unmapped.k) | table kk, unmapped.label as other]", "a,b,c,d,f,g,h,i"),
    // Documented workaround 2: one number form on both sides, guarded so a
    // value that is no number (or is missing) never becomes a false "0" key.
    // Unfiltered: 5, "5", "5.0" share "5"; 0 and "0.0" share "0"; "abc",
    // the object and the missing key match nothing.
    (r#"* | eval kk = if(isnum(unmapped.k), tostring(tonumber(unmapped.k)), "") | join kk [search * | eval kk = if(isnum(unmapped.k), tostring(tonumber(unmapped.k)), "") | table kk, unmapped.label as other]"#, "a,b,c,f,h,i"),
    // Known limitation: `risk_score` (stored as `unmapped.risk_score`) is not
    // a join key (`join risk_score` is a ClickHouse error, also on main). The
    // documented workaround joins on the stored path. (A text copy of
    // `risk_score` is no workaround: a missing score reads as 0.)
    ("* | join unmapped.risk_score [search * | table unmapped.risk_score, unmapped.label as other]", "a,b"),
    ("* | join unmapped.risk_score [search * | table unmapped.risk_score]", "a,b"),
    // The unguarded form is the false match the docs warn against.
    ("* | eval kk = tostring(tonumber(unmapped.k)) | join kk [search * | eval kk = tostring(tonumber(unmapped.k)) | table kk, unmapped.label as other]", "a,b,c,d,e,f,g,h,i"),
];

#[test]
fn dump_join_json_key_queries_for_clickhouse() {
    let Ok(out) = std::env::var("NANO_JOIN_KEY_SQL_OUT") else { return };
    let mut tsv = String::new();
    for (npl, want) in JOIN_KEY_LIVE_CASES {
        let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
        let sql = ClickHouseSqlGenerator::with_table("t")
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap_or_else(|e| panic!("{npl:?}: {e}"));
        // The probe table holds only a few columns: drop the profile's extra
        // stage-0 columns (prevalence_*, *_unified, ...).
        let sql = regex::Regex::new(r"SELECT \*,[^()]*? FROM t\b").unwrap().replace_all(&sql, "SELECT * FROM t");
        tsv.push_str(&format!("{npl}\t{want}\t{}\n", sql.replace('\n', " ")));
    }
    std::fs::write(&out, tsv).unwrap();
    std::fs::write(format!("{out}.rows"), JOIN_KEY_LIVE_ROWS).unwrap();
}

/// NAN-5895: every nPL command has an explicit JSON-text rule. The rule
/// table (`json_text_rule`) has no wildcard arm, so adding a `Command`
/// variant fails to COMPILE until it gets one; this test pins the rule of
/// one command per kind so a wrong edit to the table fails here.
#[test]
fn every_command_kind_has_its_json_text_rule() {
    use super::json_text::{json_text_rule, JsonTextRule as R};
    let rule = |npl: &str| {
        let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
        let crate::query::Query::Piped { command, .. } = q else { panic!("{npl}") };
        format!("{:?}", json_text_rule(&command)).split(['(', ' ']).next().unwrap().to_string()
    };
    for (npl, want) in [
        ("* | where x=1", "Passthrough"),
        ("* | sort x", "Passthrough"),
        ("* | head 5", "Passthrough"),
        ("* | dedup x", "Passthrough"),
        ("* | eventstats count by x", "Passthrough"),
        ("* | rex field=x \"(?<y>\\d+)\"", "Passthrough"),
        (r#"* | fillnull value="0" x"#, "RewriteTextInPlace"),
        (r#"* | rex field=x mode=sed "s/a/b/""#, "RewriteTextInPlace"),
        ("* | bin x span=10", "RewriteNonText"),
        ("* | stats count by x", "GroupBy"),
        ("* | chart count by x", "GroupBy"),
        ("* | timechart span=1h count by x", "GroupBy"),
        ("* | top x by y", "GroupBy"),
        ("* | rare x", "GroupBy"),
        ("* | transaction x", "GroupBy"),
        ("* | table x as y", "Table"),
        ("* | fields x", "FieldsKeep"),
        ("* | fields - x", "FieldsRemove"),
        ("* | rename x as y", "Rename"),
        ("* | eval y = x", "Eval"),
        ("* | join id [search * | table id]", "Subsearch"),
        ("* | append [search * | table id]", "Subsearch"),
        ("* | bin x span=10 as b", "Passthrough"),
        (r#"* | fillnull value="0""#, "RewriteTextInPlace"),
        (r#"* | spath input=raw output=y path=a.b"#, "RewriteNonText"),
        (r#"* | spath output=y"#, "Passthrough"),
        (r#"* | spath input=raw"#, "Passthrough"),
        ("* | inputlookup assets", "Cleared"),
        ("* | stats count | format", "Cleared"),
    ] {
        assert_eq!(rule(npl), want, "{npl}");
    }
    // A bare fillnull (no field list) rewrites every column as text.
    let q = parse_query(r#"* | fillnull value="0""#).unwrap();
    let crate::query::Query::Piped { command, .. } = q else { panic!() };
    assert!(matches!(json_text_rule(&command), R::RewriteTextInPlace(None)));
}

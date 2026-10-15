// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3041: eval / `if()` / `where` parity, on both compilers.
//!
//! Rule authors found that the same predicate meant different things in
//! `| where` and inside `eval`/`if()` (the only place a conditional `risk`
//! escalation can live): eval `CONTAINS` was case-sensitive, `field=/re/i`
//! compared the field to the pattern TEXT and never matched, and `IN (...)` /
//! `in()` did not parse or did not compile. These tests pin one semantics and
//! run every expression through BOTH generators: gen1 (UDM ClickHouse) and the
//! lean lake profile (`lake_query_compile`'s OCSF 1.9 contract).

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, TimeRange};
use crate::schema::OcsfProfile;

fn time_range() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

fn gen1() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::new()
}

fn lean() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::with_table("__nano_lake_source__").with_profile(Arc::new(
        OcsfProfile::try_lake_1_9_with_snapshot_field_types(Default::default())
            .expect("lake profile"),
    ))
}

fn sql_with(generator: ClickHouseSqlGenerator, npl: &str) -> Result<String, String> {
    let query = parse_query(npl).map_err(|e| format!("parse: {e}"))?;
    generator
        .generate(&query, &time_range())
        .map_err(|e| format!("generate: {e:?}"))
}

/// `(gen1 SQL, lean SQL)`; panics with the query and engine on any failure.
fn both(npl: &str) -> [(&'static str, String); 2] {
    [
        (
            "gen1",
            sql_with(gen1(), npl).unwrap_or_else(|e| panic!("gen1 {npl:?}: {e}")),
        ),
        (
            "lean",
            sql_with(lean(), npl).unwrap_or_else(|e| panic!("lean {npl:?}: {e}")),
        ),
    ]
}

// --- 1. CONTAINS / LIKE are case-insensitive in eval, as in where/search -----

#[test]
fn eval_contains_is_case_insensitive_like_where() {
    for (engine, sql) in
        both(r#"* | eval x=if(process_name CONTAINS "EdgeUpdate", 1, 0) | table x"#)
    {
        assert!(
            sql.contains("positionCaseInsensitiveUTF8("),
            "{engine}: {sql}"
        );
        assert!(!sql.contains("(position("), "{engine}: {sql}");
    }
}

#[test]
fn eval_like_operator_and_function_are_case_insensitive_like_where() {
    for npl in [
        r#"* | eval x=if(process_name LIKE "%Edge%", 1, 0) | table x"#,
        r#"* | eval x=if(like(process_name, "%Edge%"), 1, 0) | table x"#,
        r#"* | where like(process_name, "%Edge%") | table process_name"#,
    ] {
        for (engine, sql) in both(npl) {
            assert!(sql.contains(" iLike '%Edge%'"), "{engine} {npl}: {sql}");
            assert!(!sql.contains(" LIKE '%Edge%'"), "{engine} {npl}: {sql}");
        }
    }
}

// --- 2. regex literals match in eval ----------------------------------------

#[test]
fn eval_regex_literal_compiles_to_a_case_insensitive_match() {
    for npl in [
        r#"* | eval x=if(process_name=/edge.*update/i, 1, 0) | table x"#,
        // Without the flag too: `| where f=/re/` is case-insensitive.
        r#"* | eval x=if(process_name=/edge.*update/, 1, 0) | table x"#,
        r#"* | eval x=if(process_name==/edge.*update/i, 1, 0) | table x"#,
    ] {
        for (engine, sql) in both(npl) {
            assert!(sql.contains("match(toString("), "{engine} {npl}: {sql}");
            assert!(sql.contains("'(?i)edge.*update')"), "{engine} {npl}: {sql}");
            // The old bug: the field compared to the pattern text.
            assert!(!sql.contains("= '(?i)"), "{engine} {npl}: {sql}");
            assert!(!sql.contains("= 'edge"), "{engine} {npl}: {sql}");
        }
    }
    for (engine, sql) in both(r#"* | eval x=if(process_name!=/edge/i, 1, 0) | table x"#) {
        assert!(sql.contains("NOT match(toString("), "{engine}: {sql}");
    }
}

#[test]
fn eval_string_equality_is_case_insensitive_like_where() {
    for (engine, sql) in both(
        r#"* | eval x=if(process_name="WINWORD.EXE", 1, 0), y=if(process_name!="Excel.exe", 1, 0) | table x y"#,
    ) {
        assert!(sql.contains(") = 'winword.exe')"), "{engine}: {sql}");
        assert!(sql.contains(") != 'excel.exe')"), "{engine}: {sql}");
        assert!(!sql.contains("= 'WINWORD.EXE'"), "{engine}: {sql}");
    }
    // Field-to-field and numeric comparisons keep their typed form.
    for (engine, sql) in both(
        r#"* | eval same=if(src_ip = dest_ip, 1, 0), web=if(dest_port = 443, 1, 0) | table same web"#,
    ) {
        assert!(!sql.contains("lower(toString("), "{engine}: {sql}");
    }
}

// --- 3. IN (...) / in() ------------------------------------------------------

#[test]
fn eval_in_list_operator_parses_and_is_case_insensitive() {
    for (engine, sql) in
        both(r#"* | eval x=if(process_name IN ("WINWORD.EXE", "excel.exe"), 1, 0) | table x"#)
    {
        assert!(
            sql.contains(") IN ('winword.exe', 'excel.exe')"),
            "{engine}: {sql}"
        );
    }
    for (engine, sql) in both(r#"* | eval x=if(process_name NOT IN ("a.exe"), 1, 0) | table x"#) {
        // `NOT IN` is null-safe like search `NOT`: a missing value is "not in".
        assert!(
            sql.contains("(NOT ifNull(((lower(toString("),
            "{engine}: {sql}"
        );
        assert!(sql.contains(") IN ('a.exe'))), false))"), "{engine}: {sql}");
    }
}

#[test]
fn eval_in_function_compiles_on_both_engines() {
    for (engine, sql) in
        both(r#"* | eval x=if(in(process_name, "A.exe", "b.exe"), 1, 0) | table x"#)
    {
        assert!(sql.contains(") IN ('a.exe', 'b.exe')"), "{engine}: {sql}");
    }
    // Numeric members compare as numbers, not lowered strings.
    for (engine, sql) in both(r#"* | eval x=if(in(dest_port, 80, 443), 1, 0) | table x"#) {
        assert!(sql.contains(" IN (80, 443)"), "{engine}: {sql}");
    }
}

#[test]
fn where_accepts_the_in_function_like_the_in_operator() {
    for (engine, sql) in
        both(r#"* | where in(process_name, "A.exe", "b.exe") | table process_name"#)
    {
        assert!(sql.contains(") IN ('a.exe', 'b.exe')"), "{engine}: {sql}");
    }
}

#[test]
fn eval_not_negates_a_predicate() {
    for (engine, sql) in both(r#"* | eval x=if(NOT process_name IN ("a.exe"), 1, 0) | table x"#) {
        assert!(sql.contains("NOT ifNull(("), "{engine}: {sql}");
    }
}

// --- 5. aliases resolve after a pipe -----------------------------------------

#[test]
fn lean_where_resolves_udm_aliases_like_the_search_term() {
    let search = sql_with(lean(), r#"user="x" | table user"#).unwrap();
    assert!(
        search.contains(r#"if("user.name" != '', "user.name", "actor.user.name")"#),
        "{search}"
    );
    for npl in [
        r#"* | where NOT user="x" | table user"#,
        r#"* | where user="x" | table user"#,
        r#"* | where user IN ("x", "y") | table user"#,
        r#"* | where user CONTAINS "x" | table user"#,
        r#"* | where user=/x.*/ | table user"#,
    ] {
        let sql = sql_with(lean(), npl).unwrap();
        assert!(
            sql.contains(r#"if("user.name" != '', "user.name", "actor.user.name")"#),
            "{npl}: {sql}"
        );
        assert!(!sql.contains(r#"toString("user")"#), "{npl}: {sql}");
        assert!(!sql.contains(r#"lower("user")"#), "{npl}: {sql}");
    }
    let sql = sql_with(lean(), r#"* | where src_ip="10.0.0.1" | table src_ip"#).unwrap();
    assert!(sql.contains(r#""src_endpoint.ip""#), "{sql}");
    assert!(!sql.contains("toString(src_ip)"), "{sql}");
}

#[test]
fn where_after_stats_still_reads_the_stats_column() {
    let sql = sql_with(lean(), r#"* | stats count by user | where user="x""#).unwrap();
    let tail = &sql[sql.rfind("stage_").unwrap()..];
    let last_where = &sql[sql.rfind("WHERE").unwrap()..];
    assert!(last_where.contains(r#"toString("user")"#), "{tail}\n{sql}");
    assert!(!last_where.contains("user.name"), "{sql}");
}

#[test]
fn gen1_where_on_a_udm_column_is_unchanged() {
    let sql = sql_with(gen1(), r#"* | where NOT user="x" | table user"#).unwrap();
    assert!(
        sql.contains(r#"NOT ifNull((lower("user") = 'x'), false)"#),
        "{sql}"
    );
}

// --- 6. term-prefix keywords -------------------------------------------------

#[test]
fn bare_prefix_keyword_matches_a_term_prefix_not_the_body_prefix() {
    for (engine, sql) in both("svch* | table message") {
        assert!(!sql.contains("iLike 'svch%'"), "{engine}: {sql}");
        // Index-servable substring guard, refined by a term-boundary regex.
        assert!(
            sql.contains("lower(message) iLike '%svch%'"),
            "{engine}: {sql}"
        );
        assert!(
            sql.contains(r"match(message, '(?i)(?:^|[^a-z0-9])svch')"),
            "{engine}: {sql}"
        );
    }
    // Suffix and infix wildcards get the same term semantics.
    for (engine, sql) in both("*host.exe | table message") {
        assert!(
            sql.contains(r"match(message, '(?i)host\\.exe(?:$|[^a-z0-9])')"),
            "{engine}: {sql}"
        );
    }
    for (engine, sql) in both("svc*exe | table message") {
        assert!(
            sql.contains(r"match(message, '(?i)(?:^|[^a-z0-9])svc\\S*exe(?:$|[^a-z0-9])')"),
            "{engine}: {sql}"
        );
    }
    // `*kw*` stays the plain substring search (NAN-3034).
    for (engine, sql) in both("*svch* | table message") {
        assert!(
            sql.contains("lower(message) iLike '%svch%'"),
            "{engine}: {sql}"
        );
        assert!(!sql.contains("match(message"), "{engine}: {sql}");
    }
    let lean_sql = sql_with(lean(), "svch* | table message").unwrap();
    assert!(
        lean_sql.contains(r"match(raw_data, '(?i)(?:^|[^a-z0-9])svch')"),
        "{lean_sql}"
    );
}

// --- 4. eval function sweep: every expression compiles on both engines -------

#[test]
fn eval_function_sweep_compiles_on_both_engines() {
    let expressions = [
        r#"if(process_name="a", 1, 0)"#,
        r#"case(dest_port=80, "http", dest_port=443, "https", "other")"#,
        r#"case(dest_port=80, "http")"#,
        r#"coalesce(user, src_host, "none")"#,
        r#"match(command_line, "(?i)-enc")"#,
        r#"like(command_line, "%enc%")"#,
        r#"lower(user)"#,
        r#"upper(user)"#,
        r#"len(command_line)"#,
        r#"tonumber("42")"#,
        r#"tostring(dest_port)"#,
        r#"cidrmatch("10.0.0.0/8", src_ip)"#,
        r#"cidr_match(src_ip, "10.0.0.0/8")"#,
        r#"is_private_ip(src_ip)"#,
        r#"is_public_ip(dest_ip)"#,
        r#"substr(command_line, 0, 5)"#,
        r#"replace(command_line, "a", "b")"#,
        r#"split(command_line, " ")"#,
        r#"trim(user)"#,
        r#"isnull(user)"#,
        r#"isnotnull(user)"#,
        r#"nullif(user, "")"#,
        r#"null()"#,
        r#"round(dest_port / 3, 2)"#,
        r#"abs(dest_port - 500)"#,
        r#"min(dest_port, src_port)"#,
        r#"max(dest_port, src_port)"#,
        r#"extract_domain(url)"#,
        r#"md5(command_line)"#,
        r#"sha256(command_line)"#,
        r#"base64_decode(command_line)"#,
        r#"defang(dest_ip)"#,
        r#"entropy(command_line)"#,
        r#"strftime(timestamp, "%Y-%m-%d")"#,
        r#"user . "@" . src_host"#,
        r#"in(process_name, "a.exe", "b.exe")"#,
        r#"process_name IN ("a.exe", "b.exe")"#,
        r#"process_name CONTAINS "a""#,
        r#"process_name=/a.*b/i"#,
        r#"NOT process_name="a""#,
        r#"if(process_name CONTAINS "x" OR command_line CONTAINS "y", 10, 0)"#,
        r#"if(match(command_line, "(?i)iex") AND like(process_name, "%power%"), 1, 0)"#,
    ];
    let mut failures = Vec::new();
    for expr in expressions {
        let npl = format!("* | eval r={expr} | table r");
        for (engine, generator) in [("gen1", gen1()), ("lean", lean())] {
            if let Err(error) = sql_with(generator, &npl) {
                failures.push(format!("{engine}: {npl}: {error}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn conditional_risk_escalation_uses_the_same_predicates() {
    for (engine, sql) in both(
        r#"* | risk score=if(command_line CONTAINS "IEX" OR process_name IN ("WINWORD.EXE"), 20, 0) factor=if(command_line=/invoke-expression/i, "iex", null())"#,
    ) {
        assert!(
            sql.contains("positionCaseInsensitiveUTF8("),
            "{engine}: {sql}"
        );
        assert!(sql.contains(") IN ('winword.exe')"), "{engine}: {sql}");
        assert!(sql.contains("'(?i)invoke-expression')"), "{engine}: {sql}");
    }
}

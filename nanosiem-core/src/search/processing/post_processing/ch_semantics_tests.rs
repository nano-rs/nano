// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902: execute production-generated predicates on the local ClickHouse stack.
//! SELECT-only fixtures: no metadata database, application data, credentials or schema changes.
use crate::query::ClickHouseSqlGenerator;
use crate::query::{parse_query, Command, Query, SearchExpr, TimeRange};
use super::apply_post_prevalence_commands;
use serde_json::{json, Value};

fn condition(predicate: &str) -> SearchExpr {
    match parse_query(&format!("* | where {predicate}")).expect("parse production nPL") {
        Query::Piped { command: Command::Where { condition }, .. } => condition,
        other => panic!("expected where stage, got {other:?}"),
    }
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'").replace('\n', "\\n").replace('\r', "\\r"))
}

fn ids(rows: Vec<Value>) -> Vec<u64> {
    let mut ids: Vec<_> = rows.iter().map(|r| r["row_id"].as_u64().unwrap()).collect(); ids.sort(); ids
}

fn regex_cases() -> Vec<Value> {
    let mut cases = Vec::new();
    let samples = ["ws-sales-131", "wks-eng-7", "WS-01", "admin", "administrator", "admin-extra", "error", "warning",
        "abc-1", "xyz-1", "corp-dc-01", "corporate-dc-01", "svchost.exe started", "svchost.exe stopped",
        "net user", "net1 user", "foo bar", "foo bazlong", "PowerShell -enc AAA", "powerſhell -enc AAA",
        "mimikatz sekurlsa", "mimiKatz ſekurlſa", "payload.exe", "payload.scr", "payload.ps1", "payload.pſ1",
        "acdef", "bcdef", "a\nb", "a-b", "abc7", "abcd", "ſystem", "SYSTEM", "Kelvin", "KELVIN", "nothing", "٧", "δ", " ", "\u{000b}", "foo", "bar", "abcd\n", "7", "aa", "bb", "aa|bb"];
    let rows: Vec<_> = samples.iter().enumerate().map(|(id, text)| json!({"row_id":id,"src_host":text})).collect();
    let generator = ClickHouseSqlGenerator::new();
    let patterns = ["^(ws|wks)", "^(wks|ws)", "^(abc|xyz)", "^(corp|corporate)", "(ws|wks)", "(error|warn.*)",
        "admin(istrator)?", "(mimikatz)*sekurlsa", r"\.(exe|scr)$", r"svchost\.exe (started|stopped)", "(net|net1) user",
        "foo.*(bar|bazlong)", "powershell.*-enc.*", ".*mimikatz.*sekurlsa.*", "[ab]cdef", "^admin$",
        r"\d$", r"(\d|admin)", r".*\.ps1$", "^system", "kelvin", "^a.b$", "(?-s)^a.b$", "(?i)^ws-", "(error|warning)", r"^\d$", r"^\w$", r"^\s$", r"^\D$", r"^\W$", r"^\S$", r"\bkelvin\b", r"[\d]", r"[^\d]", r"(aa\|bb|foo)"];
    for pattern in patterns {
        for negated in [false, true] {
            let predicate = format!("src_host{} /{pattern}/", if negated { "!=" } else { "=" });
            let condition = condition(&predicate);
            let generated = generator.generate_search_expr(&condition).unwrap();
            let oracle = format!("{}match(src_host, {})", if negated { "NOT " } else { "" }, quote(&format!("(?i){pattern}")));
            let post_ids = ids(apply_post_prevalence_commands(rows.clone(), &[Command::Where { condition }]).unwrap().results);
            let case = json!({"kind":"regex", "predicate":predicate, "rows":rows, "sql":generated, "oracle":oracle, "post_ids":post_ids});
            println!("NAN4902_CH_CASE {case}");
            cases.push(case);
        }
    }
    cases
}

fn function_cases() -> Vec<Value> {
    let mut cases = Vec::new();
    let rows: Vec<_> = ["10.1.5.1", "192.168.0.1", "172.16.0.1", "172.31.255.255", "172.32.0.1", "203.0.113.9", "8.8.8.8", "127.0.0.1"]
        .iter().enumerate().map(|(id, ip)| json!({"row_id":id,"src_ip":ip,"user": (["Alice", "BOB", "Älice", "äLICE"][id%4])})).collect();
    for predicate in ["is_private_ip(src_ip)", "NOT is_private_ip(src_ip)", "is_private_ip(src_ip) = true", "is_private_ip(src_ip) = false",
        "is_private_ip(src_ip) = 0", "is_private_ip(src_ip) != 0", "is_private_ip(src_ip) > 0", "is_private_ip(src_ip) <= 0",
        "is_public_ip(src_ip)", "is_private_ip(src_ip) != true", "len(user) >= 4", "lower(user) = \"alice\"", "upper(user) != \"ALICE\"",
        r#"lower(user) = "älice""#, r#"upper(user) = "älice""#,
        r#"lower(user) > "bob""#, r#"lower(user) >= "bob""#, r#"lower(user) < "bob""#, r#"lower(user) <= "bob""#,
        r#"lower(user) CONTAINS "li""#, r#"lower(user) NOT CONTAINS "li""#,
        r#"lower(user) LIKE "%li%""#, r#"lower(user) NOT LIKE "%li%""#,
        "len(user) = 3", "NOT is_public_ip(src_ip)", "is_private_ip(src_ip) >= true", "is_private_ip(src_ip) < true"] {
        let condition = condition(predicate);
        let sql = ClickHouseSqlGenerator::new().generate_search_expr(&condition).unwrap();
        let post_ids = ids(apply_post_prevalence_commands(rows.clone(), &[Command::Where { condition }]).unwrap().results);
        let case = json!({"kind":"function", "predicate":predicate, "rows":rows, "sql":sql, "oracle":sql, "post_ids":post_ids});
        println!("NAN4902_CH_CASE {case}");
        cases.push(case);
    }
    cases
}

/// Emit a transport-neutral fixture artifact so a farm build can be checked against the local CH stack.
/// scripts/verify-ch-sqlgen-cases.py consumes these records; every SQL/row result comes from production code.
#[test]
fn emit_clickhouse_equivalence_cases() {
    let cases: Vec<_> = regex_cases().into_iter().chain(function_cases()).collect();
    assert_eq!(cases.len(), 97);
    println!("NAN4902_CH_END {}", cases.len());
}

#[test]
fn single_where_no_prewhere_and_indexed_lower_forms_remain() {
    let generator = ClickHouseSqlGenerator::new();
    let query = parse_query(r#"src_host=/^admin.*/ AND command_line=/powershell.*-enc.*/"#).unwrap();
    let start = chrono::DateTime::parse_from_rfc3339("2026-11-02T00:00:00Z").unwrap().to_utc();
    let sql = generator.generate(&query, &TimeRange::new(start, start + chrono::Duration::hours(1))).unwrap();
    assert!(!sql.contains("PREWHERE"), "{sql}");
    assert_eq!(sql.matches("WHERE").count(), 1, "{sql}");
    assert!(sql.contains("lower(command_line) LIKE"), "{sql}");
    assert!(sql.contains("lower(src_host)"), "{sql}");
}

#[test]
fn invalid_regex_is_a_query_error_even_beneath_not_or_on_an_empty_page() {
    for predicate in ["src_host = /[/", "NOT src_host = /[/", "is_private_ip(src_ip) OR src_host = /[/"] {
        let condition = condition(predicate);
        for rows in [vec![], vec![json!({"src_host":"host", "user":"alice"})]] {
            assert!(apply_post_prevalence_commands(rows, &[Command::Where { condition: condition.clone() }]).is_err());
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Eval before and after a Nano-side stage must agree.
//!
//! Before `| prevalence` (or lookup / identity / ai) an eval expression runs
//! in the query engine as SQL from the lean generator; after it, the same
//! expression runs in [`super::eval`] over JSON rows. Rule authors found
//! `match()`, `is_private_ip()` and `tostring()` evaluating to NULL after
//! `prevalence`, which nulled whole `risk score=` sums.
//!
//! Every case below records the value ClickHouse returns for the expression
//! on the row (`expected`), and
//! - `rust_evaluator_matches_recorded_clickhouse_values` (always runs) checks
//!   the Rust evaluator against it;
//! - `recorded_values_match_clickhouse` (ignored; needs a `clickhouse local`)
//!   re-derives every expected value by compiling the expression with the
//!   lean generator and executing it:
//!
//! ```text
//! NANO_PARITY_CLICKHOUSE="docker exec -i <container> clickhouse local" \
//!   cargo test -p nanosiem-core --lib eval_parity_tests -- --ignored
//! ```

use super::eval::evaluate_eval_expression;
use crate::query::{parse_query, Command, Query, TimeRange};
use serde_json::{json, Value};

/// The event every case runs on, as native OCSF JSON (the lean row shape).
fn event() -> Value {
    json!({
        "time": "2026-09-27 05:04:03.000000",
        "class_uid": 4001,
        "dst_endpoint": {"ip": "10.1.2.3", "port": 8443, "hostname": "www.mail.Example.com"},
        "src_endpoint": {"ip": "203.0.113.9", "hostname": null},
        "process": {"name": "PowerShell.exe", "cmd_line": "powershell -enc SQBFAFgA /LogFile=x.log"},
        "http_request": {"url": {"url_string": "https://a.b.example.co.uk:8080/x/y?q=1#f"}},
        "module": {"file": {"signatures": [{"state": "Valid"}, {"state": "Expired"}]}},
        "traffic": {"bytes_out": 150000000},
    })
}

/// ClickHouse input schema for [`event`].
const SCHEMA: &str = "time DateTime64(6, 'UTC'), class_uid Nullable(Int64), \
    dst_endpoint Tuple(ip Nullable(String), port Nullable(Int64), hostname Nullable(String)), \
    src_endpoint Tuple(ip Nullable(String), hostname Nullable(String)), \
    process Tuple(name Nullable(String), cmd_line Nullable(String)), \
    http_request Tuple(url Tuple(url_string Nullable(String))), \
    module Tuple(file Tuple(signatures Array(Tuple(state Nullable(String))))), \
    traffic Tuple(bytes_out Nullable(Int64))";

/// `(eval expression, ClickHouse's value on [event])`. Booleans are
/// ClickHouse's 1/0.
fn cases() -> Vec<(&'static str, Value)> {
    vec![
        // --- the reported functions, on present and missing fields
        (r#"match(process.cmd_line, "(?i)-ENC\\s")"#, json!(1)),
        (r#"match(process.cmd_line, "-ENC")"#, json!(0)),
        (r#"match(src_endpoint.hostname, "x")"#, json!(null)),
        ("is_private_ip(dst_endpoint.ip)", json!(1)),
        ("is_private_ip(src_endpoint.ip)", json!(0)),
        ("is_private_ip(src_endpoint.hostname)", json!(0)),
        ("is_private_ip(process.name)", json!(0)),
        ("is_public_ip(src_endpoint.ip)", json!(1)),
        ("is_loopback(dst_endpoint.ip)", json!(0)),
        (r#"cidr_match(dst_endpoint.ip, "10.0.0.0/8")"#, json!(1)),
        (r#"cidr_match("10.0.0.0/8", dst_endpoint.ip)"#, json!(1)),
        (r#"cidr_match(src_endpoint.ip, "10.0.0.0/8", "203.0.113.0/24")"#, json!(1)),
        ("tostring(dst_endpoint.port)", json!("8443")),
        ("tostring(module.file.signatures.state)", json!("['Valid','Expired']")),
        ("tostring(1.0)", json!("1")),
        // --- NULL handling that decides a risk score
        ("if(is_private_ip(src_endpoint.hostname), 10, 0)", json!(0)),
        (r#"if(match(src_endpoint.hostname, "x"), 10, 0)"#, json!(0)),
        ("if(src_endpoint.hostname = \"a\", 10, 0)", json!(0)),
        ("min(100, 50 + if(dst_endpoint.port > 1024, 30, 0) + if(match(src_endpoint.hostname, \"x\"), 40, 0))", json!(80)),
        ("src_endpoint.hostname = \"a\" OR dst_endpoint.port > 1024", json!(1)),
        ("src_endpoint.hostname = \"a\" AND dst_endpoint.port > 99999", json!(0)),
        ("coalesce(src_endpoint.hostname, \"none\")", json!("none")),
        ("isnull(src_endpoint.hostname)", json!(1)),
        ("concat(\"a\", src_endpoint.hostname)", json!(null)),
        ("concat(\"port=\", dst_endpoint.port)", json!("port=8443")),
        // --- arrays compared with scalars (multivalue semantics)
        (r#"if(module.file.signatures.state = "valid", 1, 0)"#, json!(1)),
        (r#"if(module.file.signatures.state != "Valid", 1, 0)"#, json!(0)),
        (r#"if(module.file.signatures.state != "Revoked", 1, 0)"#, json!(1)),
        (r#"if(module.file.signatures.state CONTAINS "xpir", 1, 0)"#, json!(1)),
        (r#"if(module.file.signatures.state IN ("revoked", "expired"), 1, 0)"#, json!(1)),
        (r#"if(module.file.signatures.state=/^val/, 1, 0)"#, json!(1)),
        // --- predicates
        (r#"if(process.cmd_line CONTAINS "/LOGFILE=", 1, 0)"#, json!(1)),
        (r#"if(process.name LIKE "power%.EXE", 1, 0)"#, json!(1)),
        (r#"if(process.name IN ("powershell.exe", "cmd.exe"), 1, 0)"#, json!(1)),
        (r#"if(NOT process.name = "powershell.exe", 1, 0)"#, json!(0)),
        (r#"if(dst_endpoint.port NOT IN (80, 443), 1, 0)"#, json!(1)),
        // --- strings / encoding / hashing
        ("lower(process.name)", json!("powershell.exe")),
        ("upper(process.name)", json!("POWERSHELL.EXE")),
        ("len(process.name)", json!(14)),
        ("substr(process.name, 0, 5)", json!("Power")),
        (r#"replace(process.name, ".exe", "")"#, json!("PowerShell")),
        (r#"trim("  x  ")"#, json!("x")),
        ("reverse(\"abc\")", json!("cba")),
        (r#"split("a,b,c", ",")"#, json!(["a", "b", "c"])),
        (r#"split(process.name, ".")"#, json!(["PowerShell", "exe"])),
        (r#"split(src_endpoint.hostname, ".")"#, json!([])),
        (r#"base64_encode("hi")"#, json!("aGk=")),
        (r#"base64_decode("aGk=")"#, json!("hi")),
        (r#"hex_encode("hi")"#, json!("6869")),
        (r#"url_decode("a%20b")"#, json!("a b")),
        (r#"md5("abc")"#, json!("900150983cd24fb0d6963f7d28e17f72")),
        (r#"sha256("abc")"#, json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")),
        // --- URL / domain / security
        ("extract_domain(http_request.url.url_string)", json!("a.b.example.co.uk")),
        ("extract_tld(http_request.url.url_string)", json!("uk")),
        ("extract_path(http_request.url.url_string)", json!("/x/y")),
        ("extract_protocol(http_request.url.url_string)", json!("https")),
        ("extract_query_string(http_request.url.url_string)", json!("q=1")),
        ("domain_depth(dst_endpoint.hostname)", json!(3)),
        ("defang(dst_endpoint.hostname)", json!("www[.]mail[.]Example[.]com")),
        (r#"entropy("aab")"#, json!(0.9182958340544896)),
        ("entropy(process.name)", json!(3.09306920777189)),
        ("domain_depth(src_endpoint.hostname)", json!(null)),
        ("ip_version(dst_endpoint.ip)", json!(4)),
        ("ipv4_to_int(dst_endpoint.ip)", json!(167838211)),
        ("int_to_ipv4(167838211)", json!("10.1.2.3")),
        // --- regex / similarity / arrays
        (r#"regex_extract(process.cmd_line, "-enc (\\S+)")"#, json!("SQBFAFgA")),
        (r#"regex_replace(process.name, "(\\w+)\\.exe", "\\1.bin")"#, json!("PowerShell.bin")),
        (r#"regex_replace_all("aaa", "a", "b")"#, json!("bbb")),
        (r#"regex_extract(process.cmd_line, "(-enc) (\\S+)", 2)"#, json!("SQBFAFgA")),
        (r#"levenshtein("kitten", "sitting")"#, json!(3)),
        ("mvcount(module.file.signatures.state)", json!(2)),
        (r#"mvjoin(module.file.signatures.state, "|")"#, json!("Valid|Expired")),
        ("mvindex(module.file.signatures.state, 1)", json!("Expired")),
        (r#"mvfind(module.file.signatures.state, "^Exp")"#, json!(2)),
        (r#"array_contains(module.file.signatures.state, "valid")"#, json!(1)),
        // --- math / conversion
        ("round(2.5)", json!(2)),
        ("round(traffic.bytes_out / 1000000, 2)", json!(150)),
        ("abs(-3)", json!(3)),
        ("floor(2.7)", json!(2)),
        ("pow(2, 10)", json!(1024)),
        ("tonumber(\"12.5\")", json!(12.5)),
        ("tonumber(\"abc\")", json!(0)),
        ("toint(\"7\")", json!(7)),
        ("tolong(\"5.5\")", json!(null)),
        ("traffic.bytes_out > 100000000", json!(1)),
        ("traffic.bytes_out / 0", json!(null)),
        ("max(dst_endpoint.port, 9000)", json!(9000)),
        ("nullif(dst_endpoint.port, 8443)", json!(null)),
        // --- time (event time 2026-09-27 05:04:03 UTC, a Sunday)
        ("hour(time)", json!(5)),
        ("minute(time)", json!(4)),
        ("dayofweek(time)", json!(7)),
        ("dayofyear(time)", json!(270)),
        ("quarter(time)", json!(3)),
        ("week(time)", json!(39)),
        ("year(time)", json!(2026)),
        (r#"strftime(time, "%H:%M %Y-%m-%d")"#, json!("05:04 2026-09-27")),
        (r#"tonumber(strftime(time, "%w"))"#, json!(0)),
        ("epoch(time)", json!(1790485443)),
        ("start_of_hour(time)", json!("2026-09-27 05:00:00")),
        ("start_of_day(time)", json!("2026-09-27 00:00:00")),
        (r#"date_part("hour", time)"#, json!(5)),
    ]
}

fn eval_expr(expression: &str) -> crate::query::EvalExpression {
    match parse_query(&format!("* | eval v={expression}"))
        .unwrap_or_else(|e| panic!("{expression}: {e}"))
    {
        Query::Piped {
            command: Command::Eval { mut assignments },
            ..
        } => assignments.remove(0).expression,
        other => panic!("expected eval, got {other:?}"),
    }
}

/// ClickHouse JSON and the evaluator's JSON on one scale: booleans as 1/0,
/// numbers as f64.
fn normalize(value: &Value) -> Value {
    match value {
        Value::Bool(b) => json!(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => json!(n.as_f64().unwrap()),
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        other => other.clone(),
    }
}

fn same(left: &Value, right: &Value) -> bool {
    match (normalize(left), normalize(right)) {
        (Value::Number(l), Value::Number(r)) => {
            (l.as_f64().unwrap() - r.as_f64().unwrap()).abs() < 1e-9
        }
        (l, r) => l == r,
    }
}

#[test]
fn rust_evaluator_matches_recorded_clickhouse_values() {
    let row = event();
    let row = row.as_object().unwrap();
    let mut failures = Vec::new();
    for (expression, expected) in cases() {
        let actual = evaluate_eval_expression(&eval_expr(expression), row).unwrap_or(Value::Null);
        if !same(&actual, &expected) {
            failures.push(format!(
                "{expression}: rust {actual} != clickhouse {expected}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_case_uses_only_supported_functions() {
    for (expression, _) in cases() {
        assert_eq!(
            super::eval::unsupported_post_processing_function(&eval_expr(expression)),
            None,
            "{expression}"
        );
    }
}

#[test]
#[ignore = "needs NANO_PARITY_CLICKHOUSE (a `clickhouse local` command)"]
fn recorded_values_match_clickhouse() {
    use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
    use crate::schema::OcsfProfile;
    use std::io::Write;
    use std::sync::Arc;

    let command = std::env::var("NANO_PARITY_CLICKHOUSE").expect("NANO_PARITY_CLICKHOUSE");
    let generator = ClickHouseSqlGenerator::with_table("__nano_lake_source__").with_profile(
        Arc::new(OcsfProfile::try_lake_1_9_with_snapshot_field_types(Default::default()).unwrap()),
    );
    let range = TimeRange {
        start: "2026-09-27T00:00:00Z".parse().unwrap(),
        end: "2026-09-28T00:00:00Z".parse().unwrap(),
    };
    let row = event()
        .to_string()
        .replace('\\', "\\\\")
        .replace('\'', "\\'");
    let source = format!(
        "format(JSONEachRow, '{}', '{row}')",
        SCHEMA.replace('\'', "\\'")
    );
    let mut failures = Vec::new();
    for (expression, expected) in cases() {
        let query = parse_query(&format!("* | eval v={expression} | table v")).unwrap();
        let sql = generator
            .generate(&query, &range)
            .unwrap_or_else(|e| panic!("{expression}: {e:?}"))
            .replace("__nano_lake_source__", &source);
        let sql = format!("{sql} FORMAT JSONEachRow");
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "{command} --output_format_json_quote_64bit_integers=0"
            ))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(sql.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        if !output.status.success() {
            failures.push(format!(
                "{expression}: clickhouse error {}",
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .next()
                    .unwrap_or("")
            ));
            continue;
        }
        let text = String::from_utf8(output.stdout).unwrap();
        let actual = serde_json::from_str::<Value>(text.trim())
            .map(|row| row["v"].clone())
            .unwrap_or_else(|_| panic!("{expression}: unparsable output {text:?}"));
        if !same(&actual, &expected) {
            failures.push(format!(
                "{expression}: clickhouse {actual} != recorded {expected}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

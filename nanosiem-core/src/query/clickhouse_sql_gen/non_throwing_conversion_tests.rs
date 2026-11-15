// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5427: generated SQL must not apply a throwing ClickHouse conversion to
//! row data. One unparseable value (the text "nan", a non-date string, an
//! oversized string) used to abort the whole query: the search returned 500
//! and a scheduled rule failed every tick with its marker frozen.
//!
//! Every conversion of an untrusted value goes through a form that yields
//! NULL for that row instead: `accurateCastOrNull`, `parseDateTimeOrNull`,
//! `makeDate` over `*OrNull` parts, an `isFinite` guard on the risk clamp, and
//! a length guard on `editDistance`.

use std::sync::Arc;

use regex::Regex;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, TimeRange};
use crate::schema::{OcsfProfile, SchemaProfile, UdmProfile};

fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-11-13T00:00:00Z".parse().unwrap(),
        end: "2026-11-13T01:00:00Z".parse().unwrap(),
    }
}

fn generate(profile: Arc<dyn SchemaProfile>, npl: &str) -> String {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: parse: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(profile)
        .generate(&query, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

fn udm(npl: &str) -> String {
    generate(Arc::new(UdmProfile), npl)
}

fn ocsf(npl: &str) -> String {
    generate(Arc::new(OcsfProfile::new()), npl)
}

/// A throwing conversion applied directly to `field`. The `OrNull` / `OrZero`
/// / `64` variants do not match: `\(` must follow the bare name.
fn throwing_conversion_of(field: &str) -> Regex {
    Regex::new(&format!(
        r#"\b(toDateTime|toDate|parseDateTime|parseDateTimeBestEffort|toUnixTimestamp|toInt32|toInt64|toFloat64|toUInt8|toUInt16|base64Decode)\([`"]?{}"#,
        regex::escape(field)
    ))
    .unwrap()
}

#[test]
fn to_timestamp_one_arg_casts_without_throwing() {
    let sql = udm("* | eval t = to_timestamp(command_line) | table t");
    assert!(
        sql.contains("toDateTime(accurateCastOrNull(command_line, 'DateTime64(3)'))"),
        "{sql}"
    );
    assert!(!sql.contains("toDateTime(command_line)"), "{sql}");
}

/// A fractional epoch (`epoch_ms / 1000`) must still convert: the cast goes
/// through DateTime64(3), not straight to DateTime (which rejects decimals).
#[test]
fn to_timestamp_of_a_decimal_epoch_goes_through_datetime64() {
    let sql = udm("* | eval t = to_timestamp(bytes_out / 1000) | table t");
    assert!(sql.contains("toDateTime(accurateCastOrNull("), "{sql}");
    assert!(sql.contains("'DateTime64(3)'))"), "{sql}");
    assert!(!sql.contains("'DateTime')"), "{sql}");
    let epoch = udm("* | eval e = epoch(bytes_out / 1000) | table e");
    assert!(epoch.contains("toUnixTimestamp(toDateTime(accurateCastOrNull("), "{epoch}");
}

#[test]
fn to_timestamp_with_format_uses_or_null() {
    let sql = udm(r#"* | eval t = to_timestamp(command_line, "%Y") | table t"#);
    assert!(sql.contains("parseDateTimeOrNull(command_line, '%Y')"), "{sql}");
    assert!(!sql.contains("parseDateTime(command_line"), "{sql}");
}

#[test]
fn to_date_one_arg_casts_without_throwing() {
    let sql = udm("* | eval d = to_date(command_line) | table d");
    assert!(sql.contains("accurateCastOrNull(command_line, 'Date')"), "{sql}");
    assert!(!sql.contains("toDate(command_line)"), "{sql}");
}

#[test]
fn make_date_uses_numeric_constructor_and_rejects_rollover() {
    let sql = udm("* | eval d = make_date(src_port, dest_port, 1) | table d");
    let date = "makeDate(toUInt16OrNull(toString(src_port)), toUInt8OrNull(toString(dest_port)), \
                toUInt8OrNull(toString(1)))";
    assert!(sql.contains(&format!("if(toYear({date}) = toUInt16OrNull(toString(src_port))")), "{sql}");
    assert!(sql.contains(&format!(", {date}, NULL)")), "{sql}");
    assert!(!sql.contains("toDate(concat("), "{sql}");
}

#[test]
fn epoch_of_a_string_field_casts_without_throwing() {
    let sql = udm("* | eval e = epoch(command_line) | table e");
    assert!(
        sql.contains("toUnixTimestamp(toDateTime(accurateCastOrNull(command_line, 'DateTime64(3)')))"),
        "{sql}"
    );
}

#[test]
fn epoch_of_the_time_column_keeps_the_direct_form() {
    let sql = udm("* | eval e = epoch(timestamp) | table e");
    assert!(sql.contains("toUnixTimestamp(timestamp)"), "{sql}");
    assert!(!sql.contains("accurateCastOrNull(timestamp"), "{sql}");
}

#[test]
fn edit_distance_is_length_guarded() {
    let sql = udm(r#"* | eval d = levenshtein(dest_host, "example.com") | table d"#);
    assert!(
        sql.contains(
            "if(length(dest_host) > 65536 OR length('example.com') > 65536, NULL, \
             editDistance(dest_host, 'example.com'))"
        ),
        "{sql}"
    );
    let norm = udm(r#"* | eval d = levenshtein_normalized(dest_host, "example.com") | table d"#);
    assert!(norm.contains("NULL, editDistance(dest_host"), "{norm}");
}

const RISK_NAN: &str = "toInt32(least(100, greatest(0, ifNull(accurateCastOrNull(\
                        toFloat64OrZero(toString(command_line)), 'Float64'), 0))))";

#[test]
fn dynamic_risk_score_guards_nan_and_text() {
    let sql = udm("user=\"x\" | risk score=tonumber(command_line) entity=user");
    assert!(sql.contains(RISK_NAN), "{sql}");
    assert!(!sql.contains("greatest(0, toInt32("), "{sql}");
    // The value expression is read once per score expression (the score is
    // projected as both raw_risk_score and risk_score).
    assert_eq!(
        sql.matches("toFloat64OrZero(toString(command_line))").count(),
        sql.matches(RISK_NAN).count(),
        "{sql}"
    );
}

#[test]
fn dynamic_risk_score_of_a_bare_field_is_guarded() {
    let sql = ocsf("actor.user.name=\"x\" | risk score=process.cmd_line entity=actor.user.name");
    assert!(sql.contains("ifNull(accurateCastOrNull("), "{sql}");
    assert!(sql.contains("'Float64'), 0))))"), "{sql}");
}

/// A later pipe whose dynamic score is the attacker text "nan" contributes 0;
/// the earlier pipe's score survives in the running total (no NULL wipe).
#[test]
fn bad_dynamic_score_does_not_wipe_an_earlier_pipe() {
    let sql = udm(
        "user=\"x\" | risk score=40 entity=user | risk score=tonumber(command_line) entity=user",
    );
    assert!(
        sql.contains(&format!("least(100, greatest(0, risk_score + {RISK_NAN}))")),
        "{sql}"
    );
}

#[test]
fn literal_risk_score_is_unchanged() {
    let sql = udm("user=\"x\" | risk score=40 entity=user");
    assert!(!sql.contains("isFinite("), "{sql}");
}

#[test]
fn bin_hop_on_a_non_time_field_casts_without_throwing() {
    let sql = udm("* | bin command_line span=1h hop=30m | table command_line");
    assert!(
        sql.contains("toInt64(toDateTime(accurateCastOrNull(command_line, 'DateTime64(3)')))"),
        "{sql}"
    );
    assert!(!sql.contains("toDateTime(command_line)"), "{sql}");
}

#[test]
fn bin_hop_on_the_time_column_keeps_the_direct_form() {
    let sql = udm("* | bin timestamp span=1h hop=30m | table timestamp");
    assert!(sql.contains("toInt64(toDateTime(timestamp))"), "{sql}");
}

/// Tripwire: every conversion-style eval function applied to a string field,
/// on both profiles, emits no throwing conversion of that field.
#[test]
fn no_throwing_conversion_wraps_a_row_value() {
    let evals = [
        "to_timestamp(F)",
        r#"to_timestamp(F, "%Y-%m-%d")"#,
        "to_date(F)",
        r#"to_date(F, "%d-%m-%Y")"#,
        "make_date(F, F, F)",
        "make_timestamp(F, F, F, F, F, F)",
        "make_time(F, F, F)",
        "epoch(F)",
        "tonumber(F)",
        "toint(F)",
        "tolong(F)",
        "base64_decode(F)",
        r#"levenshtein(F, "x")"#,
        r#"levenshtein_normalized(F, "x")"#,
        "ipv4_to_int(F)",
        "cidr_match(F, \"10.0.0.0/8\")",
        "is_private_ip(F)",
    ];
    for (render, field) in [
        (udm as fn(&str) -> String, "command_line"),
        (ocsf as fn(&str) -> String, "process.cmd_line"),
    ] {
        for eval in evals {
            let npl = format!("* | eval v = {} | table v", eval.replace('F', field));
            let sql = render(&npl);
            if let Some(m) = throwing_conversion_of(field).find(&sql) {
                panic!("{npl:?} emits throwing `{}` on a row value:\n{sql}", m.as_str());
            }
            // editDistance only ever runs behind its length guard.
            assert_eq!(
                sql.matches("editDistance(").count(),
                sql.matches("NULL, editDistance(").count(),
                "{npl:?} emits an unguarded editDistance:\n{sql}"
            );
        }
    }
}

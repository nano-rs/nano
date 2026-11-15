// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5426: eval functions must not produce invalid UTF-8 from row text.
//! `substring` and `reverse` worked on bytes, and the decoders returned raw
//! bytes, so one multibyte or encoded value yielded a byte sequence that
//! failed the whole ClickHouse response (500 for a hunt, a pinned rule).
//!
//! Text functions now use the character-level forms (`substringUTF8`,
//! `reverseUTF8`) and every decoder is wrapped in `toValidUTF8`.

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

#[test]
fn substr_uses_character_offsets() {
    let sql = udm("* | eval s = substr(command_line, 0, 10) | table s");
    assert!(sql.contains("substringUTF8(toString(command_line), 0 + 1, 10)"), "{sql}");
    let two = udm("* | eval s = substr(command_line, 3) | table s");
    assert!(two.contains("substringUTF8(toString(command_line), 3 + 1)"), "{two}");
}

#[test]
fn reverse_of_text_is_character_level() {
    let sql = udm("* | eval r = reverse(command_line) | table r");
    assert!(sql.contains("reverseUTF8(toString(command_line))"), "{sql}");
}

#[test]
fn reverse_of_an_array_keeps_element_reverse() {
    let sql = udm(r#"* | eval r = reverse(split(command_line, " ")) | table r"#);
    assert!(sql.contains("reverse(splitByString("), "{sql}");
    assert!(!sql.contains("reverseUTF8("), "{sql}");
}

#[test]
fn reverse_of_an_eval_array_variable_in_a_later_eval_keeps_element_reverse() {
    let sql = udm(r#"* | eval parts = split(command_line, " ") | eval r = reverse(parts) | table r"#);
    assert!(sql.contains("reverse(parts)"), "{sql}");
    assert!(!sql.contains("reverseUTF8("), "{sql}");
}

#[test]
fn reverse_of_an_eval_array_variable_in_the_same_eval_keeps_element_reverse() {
    let sql = udm(r#"* | eval parts = split(command_line, " "), r = reverse(parts) | table r"#);
    assert!(sql.contains("reverse(parts)"), "{sql}");
    assert!(!sql.contains("reverseUTF8("), "{sql}");
}

#[test]
fn reverse_follows_eval_array_copies_and_reassignment() {
    let copy = udm(r#"* | eval parts = split(command_line, " ") | eval p2 = parts | eval r = reverse(p2) | table r"#);
    assert!(copy.contains("reverse(p2)") && !copy.contains("reverseUTF8("), "{copy}");
    // Reassigned to text: reverse by character again.
    let text = udm(r#"* | eval parts = split(command_line, " ") | eval parts = lower(command_line) | eval r = reverse(parts) | table r"#);
    assert!(text.contains("reverseUTF8(toString(parts))"), "{text}");
    // Overwritten by another command (rex): no longer an eval array.
    let rex = udm(r#"* | eval parts = split(command_line, " ") | rex field=command_line "(?<parts>\w+)" | eval r = reverse(parts) | table r"#);
    assert!(rex.contains("reverseUTF8(toString(parts))"), "{rex}");
}

#[test]
fn decoders_are_wrapped_in_to_valid_utf8() {
    let b64 = udm("* | eval d = base64_decode(command_line) | table d");
    assert!(
        b64.contains("toValidUTF8(nullIf(tryBase64Decode(toString(command_line)), ''))"),
        "{b64}"
    );
    let hex = udm("* | eval d = hex_decode(command_line) | table d");
    assert!(hex.contains("toValidUTF8(unhex(command_line))"), "{hex}");
    let url = udm("* | eval d = url_decode(command_line) | table d");
    assert!(url.contains("toValidUTF8(decodeURLComponent(command_line))"), "{url}");
}

/// Tripwire: no byte-level string function reaches generated SQL unguarded,
/// on either profile.
#[test]
fn no_byte_level_function_escapes_a_utf8_guard() {
    let byte_level = Regex::new(r"\b(substring|unhex|decodeURLComponent|tryBase64Decode|base64Decode)\(").unwrap();
    let evals = [
        "substr(F, 0, 10)",
        "substring(F, 2)",
        "reverse(F)",
        "base64_decode(F)",
        "base64decode(F)",
        "hex_decode(F)",
        "fromhex(F)",
        "url_decode(F)",
        "urldecode(F)",
    ];
    for (render, field) in [
        (udm as fn(&str) -> String, "command_line"),
        (ocsf as fn(&str) -> String, "process.cmd_line"),
    ] {
        for eval in evals {
            let npl = format!("* | eval v = {} | table v", eval.replace('F', field));
            let sql = render(&npl);
            for m in byte_level.find_iter(&sql) {
                let before = &sql[..m.start()];
                assert!(
                    before.ends_with("toValidUTF8(") || before.ends_with("toValidUTF8(nullIf("),
                    "{npl:?} emits unguarded `{}`:\n{sql}",
                    m.as_str()
                );
            }
            assert!(
                !Regex::new(r"\breverse\(").unwrap().is_match(&sql),
                "{npl:?} emits byte-level reverse on text:\n{sql}"
            );
        }
    }
}

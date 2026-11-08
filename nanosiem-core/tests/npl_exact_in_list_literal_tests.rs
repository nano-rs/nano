//! UI pivots must be able to express an EXACT value (NAN-4903).
//!
//! `field="v"` treats `*` and `?` inside the quotes as wildcards (and
//! `field="*"` is an existence test), so a pivot built from a log value such
//! as `https://example/a?id=1` or a hostile entity value `*` would broaden.
//! The web helper `nplExactEquals` (nanosiem-web/src/lib/npl-quote.ts) emits
//! `field IN ("v")` for such values; these tests pin that the IN-list compiles
//! to plain membership with no wildcard expansion, before and after a pipe,
//! under UDM and OCSF, including OCSF array fields.
//!
//! Run with: cargo test -p nanosiem-core --test npl_exact_in_list_literal_tests

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::OcsfProfile;

fn tr() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

fn udm(q: &str) -> String {
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
    ClickHouseSqlGenerator::new()
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

fn ocsf(q: &str) -> String {
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(std::sync::Arc::new(OcsfProfile::new()))
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

fn assert_literal(sql: &str, needle: &str) {
    assert!(sql.contains(needle), "expected literal {needle} in:\n{sql}");
    assert!(!sql.contains("LIKE") && !sql.contains("iLike"), "wildcard expansion leaked into:\n{sql}");
    assert!(!sql.contains("IS NOT NULL AND"), "existence test leaked into:\n{sql}");
}

#[test]
fn the_equals_form_does_expand_wildcards() {
    // The premise: `=` with `?`/`*` is a pattern, which is why pivots need IN.
    assert!(udm(r#"url="https://e.com/a?id=1""#).contains(" LIKE '"));
    assert!(udm(r#"user="*""#).contains("IS NOT NULL"));
}

#[test]
fn in_list_keeps_question_mark_and_star_literal_udm() {
    for prefix in ["", "* | where "] {
        assert_literal(&udm(&format!(r#"{prefix}url IN ("https://e.com/a?id=1")"#)), "'https://e.com/a?id=1'");
        assert_literal(&udm(&format!(r#"{prefix}user IN ("*")"#)), "('*')");
        assert_literal(&udm(&format!(r#"{prefix}src_host IN ("ws-*-01")"#)), "'ws-*-01'");
    }
}

#[test]
fn in_list_keeps_wildcards_literal_on_ocsf_dotted_columns() {
    for prefix in ["", "* | where "] {
        assert_literal(
            &ocsf(&format!(r#"{prefix}http_request.url.url_string IN ("https://e.com/a?id=1&b=*")"#)),
            "'https://e.com/a?id=1&b=*'",
        );
        assert_literal(&ocsf(&format!(r#"{prefix}actor.user.name IN ("*")"#)), "('*')");
    }
}

#[test]
fn in_list_backslashes_round_trip() {
    // The web helper doubles backslashes; `\\` collapses back to one on parse.
    let sql = udm(r#"file_path IN ("\\\\srv\\share\\a?.txt")"#);
    assert!(!sql.contains(" LIKE ") && !sql.contains("iLike"), "{sql}");
    // escape_string renders one literal backslash as `\\` in SQL.
    assert!(sql.contains(r"'\\\\srv\\share\\a?.txt'"), "{sql}");
}

#[test]
fn in_list_single_quoted_value_preserves_double_quotes() {
    // nplLiteral switches to '…' when the value carries a `"`.
    let sql = udm(r#"command_line IN ('powershell -Command "Get-Process *"')"#);
    assert!(!sql.contains(" LIKE ") && !sql.contains("iLike"), "{sql}");
    assert!(sql.contains(r#"powershell -command "get-process *""#), "{sql}");
}

#[test]
fn in_list_on_an_ocsf_array_field_is_element_membership() {
    for prefix in ["", "* | where "] {
        let sql = ocsf(&format!(r#"{prefix}http_request.url.categories IN ("ads?*")"#));
        assert!(sql.contains("arrayExists") || sql.contains("has("), "{sql}");
        assert!(sql.contains("'ads?*'"), "{sql}");
        assert!(!sql.contains(" LIKE ") && !sql.contains("iLike"), "{sql}");
    }
}

// --- Sigma converter output parses as intended (nanosiem-web sigma-convert.ts) ---

#[test]
fn sigma_quoted_command_line_literal_parses_and_keeps_its_quotes() {
    let sql = ocsf(r#"metadata.log_source="windows_security" process.cmd_line CONTAINS 'powershell -Command "Get-Process"'"#);
    assert!(sql.contains(r#"powershell -command "get-process""#), "{sql}");
}

#[test]
fn sigma_regex_operand_parses_with_quotes_and_escapes() {
    let sql = ocsf(r#"process.cmd_line =~ '(?i)cmd\\.exe /c "[a-z]+"'"#);
    assert!(sql.contains(r#"(?i)cmd\\.exe /c "[a-z]+""#), "{sql}");
}

#[test]
fn sigma_windows_4688_query_targets_ocsf_columns() {
    let sql = ocsf(r#"metadata.log_source="windows_security" (metadata.event_code=4688 AND process.file.path ENDSWITH "\\cmd.exe")"#);
    assert!(sql.contains("metadata.event_code"), "{sql}");
    assert!(sql.contains("process.file.path"), "{sql}");
    assert!(!sql.contains("event_id"), "{sql}");
}

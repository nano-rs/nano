// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2241: nPL string-literal quoting — what each delimiter carries, and the
//! diagnostic for the `\"` trap.
//!
//! The grammar deliberately has no backslash escape for quotes (NAN-1157), so
//! `"C:\Windows\System32\"` parses as a path rather than an unterminated
//! string. The cost is that `\"` looks like an escape and is not one. A regex
//! containing double quotes must therefore be written single-quoted.

use crate::query::{parse_query, Command, Query, SearchExpr, Value};

/// The rex pattern from a piped query, or a panic naming what was found.
fn rex_pattern(npl: &str) -> String {
    let parsed = parse_query(npl).unwrap_or_else(|e| panic!("{npl} must parse: {e:?}"));
    fn find(q: &Query) -> Option<String> {
        match q {
            Query::Piped { source, command } => match command {
                Command::Rex { pattern, .. } => Some(pattern.clone()),
                _ => find(source),
            },
            Query::Search(_) => None,
        }
    }
    find(&parsed).unwrap_or_else(|| panic!("no rex command in {npl}"))
}

// ---------------------------------------------------------------------------
// Single-quoted literals carry `"` verbatim
// ---------------------------------------------------------------------------

#[test]
fn single_quoted_rex_pattern_keeps_its_double_quotes() {
    // The reported repro. `[^"]+` is the load-bearing part: dropping the `"`
    // leaves `[^]+`, which is a legal regex that matches nothing.
    let pattern = r#""name":"app_name","value":"(?<app>[^"]+)""#;
    assert_eq!(
        rex_pattern(&format!(
            "source_type=gws_token | rex field=message '{pattern}' | head 1"
        )),
        pattern
    );
}

#[test]
fn single_quoted_values_keep_their_double_quotes() {
    match parse_query(r#"message='{"action":"delete"}'"#).unwrap() {
        Query::Search(SearchExpr::FieldFilter { value, .. }) => {
            assert_eq!(value, Value::String(r#"{"action":"delete"}"#.to_string()));
        }
        other => panic!("expected a FieldFilter, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// NAN-1157: double-quoted behaviour is deliberate and unchanged
// ---------------------------------------------------------------------------

#[test]
fn double_quoted_windows_path_with_trailing_backslash_still_parses() {
    match parse_query(r#"file_path="C:\Windows\System32\""#).unwrap() {
        Query::Search(SearchExpr::FieldFilter { value, .. }) => {
            assert_eq!(value, Value::String(r"C:\Windows\System32\".to_string()));
        }
        other => panic!("expected a FieldFilter, got {other:?}"),
    }
}

#[test]
fn double_quoted_string_still_ends_at_the_first_quote() {
    // The whole point of NAN-1157: the backslash is an ordinary character, so
    // the literal ends at the `"` right after it. Pinned so the NAN-2241
    // serializer work cannot quietly "fix" the grammar instead.
    match parse_query(r#"user="a\" "#.trim_end()).unwrap() {
        Query::Search(SearchExpr::FieldFilter { value, .. }) => {
            assert_eq!(value, Value::String(r"a\".to_string()));
        }
        other => panic!("expected a FieldFilter, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The `\"` diagnostic
// ---------------------------------------------------------------------------

#[test]
fn escaped_double_quotes_produce_a_diagnostic_naming_the_problem() {
    let npl = r#"source_type=gws_token | rex field=message "\"name\":\"app_name\"" | head 1"#;
    let err = parse_query(npl).expect_err("`\\\"` cannot parse — it is not an escape");

    // Before NAN-2241 this said: "Unknown command 'name'. Did you mean 'rename'?"
    let message = err.message.to_lowercase();
    assert!(
        message.contains(r#"\""#) && message.contains("escape"),
        "the message must name `\\\"` as a non-escape: {}",
        err.message
    );
    assert!(
        message.contains("single"),
        "the message must point at single-quoted strings: {}",
        err.message
    );

    // ...and hand back the corrected query text.
    assert!(
        err.suggestions.iter().any(|s| s.replacement
            == r#"'"name":"app_name"'"#),
        "expected a single-quoted rewrite, got {:?}",
        err.suggestions
    );
}

#[test]
fn escaped_quote_diagnostic_does_not_hijack_unrelated_syntax_errors() {
    // A trailing-backslash Windows path CONTAINS `\"` but is perfectly valid;
    // when such a query fails for an unrelated reason the error must describe
    // THAT reason, not the escape trap.
    let npl = r#"file_path="C:\Windows\System32\" | stas count"#;
    let err = parse_query(npl).expect_err("`stas` is not a command");
    assert!(
        !err.message.contains("escape"),
        "mislabelled an unrelated error as the `\\\"` trap: {}",
        err.message
    );
}

#[test]
fn valid_trailing_backslash_path_is_not_an_error_at_all() {
    assert!(parse_query(r#"file_path="C:\Windows\System32\""#).is_ok());
}

// ═════════════════════════════════════════════════════════════════════════════
// Bare emails (NAN-2271)
// ═════════════════════════════════════════════════════════════════════════════

/// An email is a first-class SIEM search term — an account, a phishing sender,
/// an OAuth grantee. Typing one bare is the obvious first move on a Workspace
/// or O365 estate, and it failed with `Unexpected token '@'` while
/// `admin.reports.audit.readonly` parsed fine, because `.` was in the bare-token
/// charset and `@` was not.
#[test]
fn a_bare_email_is_a_search_term() {
    for query in [
        "dan@nano.rs",
        "dan@nano.rs | stats count by source_type",
        "source_type=gws_login dan@nano.rs",
        "aws@nano.rs OR dan@nano.rs",
    ] {
        assert!(
            crate::query::parse_query(query).is_ok(),
            "bare email must parse: {query}"
        );
    }
}

/// The quoted form kept working the whole time — it is what an analyst falls
/// back to — and must keep working now that the bare form does too.
#[test]
fn the_quoted_form_still_parses() {
    for query in [r#""dan@nano.rs""#, r#"user="dan@nano.rs""#] {
        assert!(crate::query::parse_query(query).is_ok(), "{query}");
    }
}

/// `@` earns its place in the charset only because nothing else in the grammar
/// claims it. If a future operator does, this is where that collision surfaces.
#[test]
fn an_email_survives_into_the_parsed_term() {
    let parsed = crate::query::parse_query("dan@nano.rs").expect("parses");
    let rendered = format!("{parsed:?}");
    assert!(
        rendered.contains("dan@nano.rs"),
        "the whole address must reach the AST, not just `dan`: {rendered}"
    );
}

/// Every term type an analyst types bare (NAN-2272).
///
/// The charset accreted one character at a time without anyone asking what a
/// SIEM search actually looks like. Each of these was unsearchable without
/// quotes; IPv6 is the one a hunt agent hit in the field.
///
/// Asserts the WHOLE token survives, not merely that the query parses — that is
/// how `@` hid: `dan@nano.rs` parsed `dan` and then choked, so a laxer check
/// would have called it fine.
#[test]
fn the_bare_terms_a_siem_analyst_actually_types() {
    for (label, term) in [
        ("ipv6", "2605:d580:140c:23ec:f867:a0ba:cd2f:a493"),
        ("host:port", "10.0.0.1:443"),
        ("cidr", "10.0.0.0/8"),
        ("windows path", r"C:\Windows\System32\cmd.exe"),
        ("unc path", r"\\fileserver\share"),
        ("domain\\user", r"CORP\dlussier"),
        ("registry", r"HKLM\Software\Microsoft"),
        ("plus address", "dan+alerts@nano.rs"),
        ("email", "dan@nano.rs"),
        ("hash", "a1b2c3d4e5f60718293a4b5c6d7e8f90"),
        ("domain", "login.microsoftonline.com"),
        ("guid", "550e8400-e29b-41d4-a716-446655440000"),
    ] {
        let parsed = crate::query::parse_query(term)
            .unwrap_or_else(|e| panic!("{label} must parse bare: {term} — {e:?}"));
        let rendered = format!("{parsed:?}");
        // `Debug` escapes backslashes, so compare against the escaped form —
        // otherwise a Windows path looks like a truncation when it is intact.
        let expected = term.replace('\\', "\\\\");
        assert!(
            rendered.contains(&expected),
            "{label}: only part of the token reached the AST — {expected} not in {rendered}"
        );
    }
}

/// `/` is shared with regex literals. A LEADING slash must still be a regex,
/// which is what makes it safe to allow mid-token: `regex_filter` is registered
/// ahead of `keyword_search`.
#[test]
fn a_leading_slash_is_still_a_regex_not_a_keyword() {
    let parsed = crate::query::parse_query("user=/admin.*/").expect("regex filter parses");
    let rendered = format!("{parsed:?}");
    assert!(
        rendered.contains("Regex") || rendered.contains("regex"),
        "a leading / must remain a regex literal: {rendered}"
    );
}

/// The operators these characters could have shadowed still parse as operators.
#[test]
fn the_added_characters_did_not_swallow_an_operator() {
    for query in [
        "status=500",
        "count > 10",
        "source_type=gws_login AND user=dan",
        "NOT admin",
        "a OR b",
    ] {
        assert!(crate::query::parse_query(query).is_ok(), "{query}");
    }
}

/// The same terms, but as FIELD VALUES rather than bare keywords.
///
/// These went through a different path — `filter_value` tries the typed parsers
/// first, and each matched a prefix and *succeeded*, so `alt` never backtracked
/// to the widened string tokenizer. `src_ip=2605:d580:…` parsed the number 2605
/// and choked on the rest. This is the form an agent actually writes (NAN-2269).
#[test]
fn the_new_characters_work_as_field_values_too() {
    for (query, expected) in [
        ("src_ip=2605:d580:140c:23ec:f867:a0ba:cd2f:a493", "2605:d580:140c:23ec:f867:a0ba:cd2f:a493"),
        ("dest=10.0.0.1:443", "10.0.0.1:443"),
        ("net=10.0.0.0/8", "10.0.0.0/8"),
        ("user=dan+alerts@nano.rs", "dan+alerts@nano.rs"),
        ("sender=dan@nano.rs", "dan@nano.rs"),
        ("path=C:\\Windows\\System32", "C:\\Windows\\System32"),
        ("user=CORP\\dlussier", "CORP\\dlussier"),
        // Leading digits are the trap: the number parser grabs them.
        ("user=123+alerts@nano.rs", "123+alerts@nano.rs"),
    ] {
        let parsed = crate::query::parse_query(query)
            .unwrap_or_else(|e| panic!("{query} should parse: {e}"));
        let rendered = format!("{parsed:?}");
        // Debug-escapes backslashes, so escape the needle the same way.
        let needle = expected.replace('\\', "\\\\");
        assert!(
            rendered.contains(&needle),
            "{query}: whole value must reach the AST, got {rendered}"
        );
    }
}

/// The boundary check must not steal values the typed parsers should own.
#[test]
fn typed_values_are_still_typed() {
    for (query, expected) in [
        ("status=500", "Number(500.0)"),
        ("src_ip=192.168.1.1", "192.168.1.1"),
        ("enabled=true", "Bool(true)"),
    ] {
        let parsed = crate::query::parse_query(query)
            .unwrap_or_else(|e| panic!("{query} should parse: {e}"));
        let rendered = format!("{parsed:?}");
        assert!(rendered.contains(expected), "{query}: got {rendered}");
    }
}

/// `+` and `/` are value characters now, so the boundary check must not turn
/// eval arithmetic into a string. Asserting the AST rather than just `is_ok()`:
/// `1+2` parsing as the *string* `"1+2"` would still be Ok, and silently wrong.
#[test]
fn eval_arithmetic_is_still_arithmetic() {
    for (query, expected) in [
        (
            "* | eval total=1+2",
            "BinaryOp { left: Literal(Number(1.0)), op: Add, right: Literal(Number(2.0)) }",
        ),
        (
            "* | eval pct=bytes_in/bytes_out",
            "BinaryOp { left: Field(\"bytes_in\"), op: Div, right: Field(\"bytes_out\") }",
        ),
        // Inside a function call, where the argument list is comma-terminated.
        (
            "* | eval y=lower(1+2)",
            "BinaryOp { left: Literal(Number(1.0)), op: Add, right: Literal(Number(2.0)) }",
        ),
    ] {
        let parsed = crate::query::parse_query(query)
            .unwrap_or_else(|e| panic!("{query} should parse: {e}"));
        let rendered = format!("{parsed:?}");
        assert!(
            rendered.contains(expected),
            "{query}: expected arithmetic, got {rendered}"
        );
    }

    // Bare intervals (`eval d=5m`, `ttl=5m`) do not parse on main either — the
    // interval parser is reachable only from the commands that take a span.
    for query in ["* | timechart span=1h count", "* | head 100"] {
        assert!(crate::query::parse_query(query).is_ok(), "{query}");
    }
}

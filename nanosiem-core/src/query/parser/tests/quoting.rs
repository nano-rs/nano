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

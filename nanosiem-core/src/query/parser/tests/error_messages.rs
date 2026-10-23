// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for improved parser error messages

use crate::query::parse_query;

#[test]
fn test_trailing_token_after_head() {
    let result = parse_query("source_type = \"squid_proxy\" | head 10 foobar");
    assert!(result.is_err());
    let err = result.unwrap_err();

    // Should detect the trailing token
    assert!(err.message.contains("foobar"));
    assert!(err.token == Some("foobar".to_string()));

    // Should suggest search filter
    assert!(err
        .suggestions
        .iter()
        .any(|s| s.replacement.contains("search")));
}

#[test]
fn test_command_typo() {
    let result = parse_query("source_type = \"test\" | stas count()");
    assert!(result.is_err());
    let err = result.unwrap_err();

    // Should detect typo and suggest stats
    assert!(err
        .suggestions
        .iter()
        .any(|s| s.replacement.contains("stats")));
}

#[test]
fn test_missing_number_after_head() {
    let result = parse_query("source_type = \"test\" | head abc");
    assert!(result.is_err());
    let err = result.unwrap_err();

    // Should expect a number
    assert!(err.expected.contains(&"number".to_string()));
}

/// NAN-2361: this asserted an error, but the grammar deliberately changed —
/// a trailing bareword is now an implicit-AND keyword term, so
/// `message = hello world` parses as `message="hello" AND keyword("world")`.
/// Asserting the CURRENT contract keeps the case covered instead of leaving a
/// stale expectation behind (it is one of the two failures that had this whole
/// file switched off with `#![cfg(any())]`).
#[test]
fn unquoted_trailing_word_is_an_implicit_and_keyword() {
    use crate::query::{Query, SearchExpr, Value};

    match parse_query("message = hello world").expect("implicit-AND form parses") {
        Query::Search(SearchExpr::And(left, right)) => {
            match *left {
                SearchExpr::FieldFilter { field, value, .. } => {
                    assert_eq!(field, "message");
                    assert_eq!(value, Value::String("hello".to_string()));
                }
                other => panic!("expected the field filter on the left, got {other:?}"),
            }
            assert_eq!(*right, SearchExpr::Keyword("world".to_string()));
        }
        other => panic!("expected an implicit AND, got {other:?}"),
    }
}

#[test]
#[ignore = "NAN-2361: quoting suggestions are not produced for this shape; see \
            unquoted_trailing_word_is_an_implicit_and_keyword for the real contract"]
fn test_unquoted_string_with_spaces() {
    let result = parse_query("message = hello world");
    assert!(result.is_err());
    let err = result.unwrap_err();

    // Should suggest quotes
    assert!(err
        .suggestions
        .iter()
        .any(|s| s.replacement.contains("\"hello world\"")));
}

#[test]
fn test_formatted_error_display() {
    let result = parse_query("source_type = \"test\" | head 10 foobar");
    assert!(result.is_err());
    let err = result.unwrap_err();

    // Should have formatted display
    let formatted = format!("{}", err);
    assert!(formatted.contains("^")); // Should have pointer
    assert!(formatted.contains("foobar")); // Should show token
    assert!(formatted.contains("Did you mean:")); // Should have suggestions
}

#[test]
fn test_levenshtein_distance() {
    use crate::query::parser::error::find_similar_command;

    assert_eq!(find_similar_command("stas"), Some("stats"));
    assert_eq!(find_similar_command("tabl"), Some("table"));
    assert_eq!(find_similar_command("hed"), Some("head"));
    assert_eq!(find_similar_command("xyz"), None); // Too different
}

/// NAN-2361: a bare argument-taking command used to blame the PIPE.
///
/// `device.hostname="x" | tree` reported `Unexpected token '|'` with the caret
/// on the pipe — the one character that was correct. The parser consumes the
/// command name, needs whitespace-then-arguments, hits end-of-input, and
/// unwinds until only the pipe is left to point at.
#[test]
fn bare_command_names_the_command_not_the_pipe() {
    let err = parse_query(r#"device.hostname="lt-eng-048.corp.local" | tree"#)
        .expect_err("a bare `tree` cannot parse");
    let formatted = format!("{err}");

    assert!(
        formatted.contains("'tree' command needs arguments"),
        "must name the command: {formatted}"
    );
    assert!(
        !formatted.contains("Unexpected token '|'"),
        "must not blame the pipe: {formatted}"
    );
    assert!(
        formatted.contains("tree process"),
        "must show a usable form: {formatted}"
    );
}

/// The failure is shared by every argument-taking command, so the fix is too.
#[test]
fn every_argument_taking_command_reports_itself_when_bare() {
    for (command, _) in super::super::error::COMMANDS_REQUIRING_ARGUMENTS {
        let query = format!("* | {command}");
        let err = parse_query(&query)
            .err()
            .unwrap_or_else(|| panic!("`{query}` must not parse"));
        let formatted = format!("{err}");
        assert!(
            formatted.contains(&format!("'{command}' command needs arguments")),
            "`{query}` should name '{command}', got: {formatted}"
        );
    }
}

/// Commands that legitimately stand alone must keep parsing.
#[test]
fn commands_valid_without_arguments_still_parse_bare() {
    for command in [
        "head", "tail", "fillnull", "spath", "format", "asset", "retro",
    ] {
        let query = format!("* | {command}");
        assert!(
            parse_query(&query).is_ok(),
            "`{query}` is valid bare and must keep parsing"
        );
    }
}

/// A pipe inside a quoted literal is not a command boundary.
#[test]
fn quoted_pipes_do_not_trigger_the_bare_command_diagnostic() {
    let err = parse_query(r#"message="a | tree" | stats"#)
        .expect_err("the trailing bare `stats` is still an error");
    let formatted = format!("{err}");
    assert!(
        formatted.contains("'stats' command needs arguments"),
        "the quoted `| tree` must not be read as a command: {formatted}"
    );
}

/// NAN-4372: a prevalence FILTER name without a comparison used to fall
/// through to the positional enrichment shorthand (`artifact_fields =
/// ["domain_first_seen"]`), which decorated nothing and returned every row.
/// It is now a parse error that names the filter syntax.
#[test]
fn bare_prevalence_filter_field_is_a_parse_error() {
    for (query, field, example) in [
        ("* | prevalence domain_first_seen", "domain_first_seen", "domain_first_seen > now() - 24h"),
        ("* | prevalence hash_first_seen | head 5", "hash_first_seen", "hash_first_seen > now() - 24h"),
        ("* | prevalence Domain_First_Seen", "domain_first_seen", "domain_first_seen > now() - 24h"),
        ("* | prevalence domain_prevalence", "domain_prevalence", "domain_prevalence < 5"),
        ("* | prevalence hash_prevalence window=24h", "hash_prevalence", "hash_prevalence < 5"),
        ("* | prevalence prevalence_file_hash", "prevalence_file_hash", "prevalence_file_hash < 5"),
        ("* | prevalence src_ip, domain_first_seen", "domain_first_seen", "domain_first_seen > now() - 24h"),
        // A comparison that fails to parse no longer degrades to enrichment.
        ("* | prevalence domain_first_seen > yesterday", "domain_first_seen", "domain_first_seen > now() - 24h"),
    ] {
        let err = parse_query(query).expect_err(query);
        assert!(
            err.message.contains(&format!("`{field}` is a prevalence filter")),
            "{query}: {}",
            err.message
        );
        assert!(err.message.contains(example), "{query}: {}", err.message);
    }
}

/// NAN-4372: `threshold=rare|uncommon|common` was accepted and ignored, so a
/// stage that read as a rarity filter returned every row.
#[test]
fn prevalence_threshold_option_is_a_parse_error() {
    for query in [
        "* | prevalence src_ip threshold=rare",
        "* | prevalence dest_ip threshold=uncommon",
        "* | prevalence process_hash threshold=common | head 5",
    ] {
        let err = parse_query(query).expect_err(query);
        assert!(err.message.contains("threshold=") && err.message.contains("is_rare"), "{query}: {}", err.message);
    }
}

/// The supported forms still parse, including the documented first_seen
/// filter and the enrichment shorthand on ordinary artifact fields.
#[test]
fn supported_prevalence_forms_still_parse() {
    for query in [
        "* | prevalence domain_first_seen > now() - 24h",
        "* | prevalence hash_first_seen > now()-86400 window=7d",
        "* | prevalence domain_prevalence < 10 domain_first_seen > now() - 24h window=24h",
        "* | prevalence domain_first_seen > now() - 24h enrich=true",
        "* | prevalence src_ip",
        "* | prevalence src_ip, dest_ip window=24h",
        "* | prevalence src_ip | where is_rare=true",
        "* | prevalence enrich=true | where host_count < 3",
        "* | prevalence hash_prevalence_alias",
    ] {
        parse_query(query).unwrap_or_else(|err| panic!("{query}: {err}"));
    }
}

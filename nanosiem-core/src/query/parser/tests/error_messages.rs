// SPDX-License-Identifier: AGPL-3.0-or-later

#![cfg(any())]

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

#[test]
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

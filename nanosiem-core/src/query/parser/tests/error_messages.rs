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

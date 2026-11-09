// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests for the identifier-quoting and fragment helpers in `sql_hygiene`
//! (security review 2026-11-08).

use super::*;
use sqlparser::dialect::ClickHouseDialect;
use sqlparser::tokenizer::{Token, Tokenizer};

fn tokens(sql: &str) -> Vec<Token> {
    Tokenizer::new(&ClickHouseDialect {}, sql)
        .tokenize()
        .expect("tokenizes")
        .into_iter()
        .filter(|t| !matches!(t, Token::Whitespace(_)))
        .collect()
}

#[test]
fn barewords_are_unchanged() {
    for name in ["src_ip", "_x", "step1_user", "A1", "host_count"] {
        assert_eq!(quote_identifier(name), name);
    }
}

#[test]
fn reserved_words_are_quoted_case_insensitively() {
    assert_eq!(quote_identifier("user"), "\"user\"");
    assert_eq!(quote_identifier("Order"), "\"Order\"");
    assert!(is_reserved_identifier("group"));
    assert!(!is_reserved_identifier("users"));
}

#[test]
fn hostile_names_stay_one_identifier_token() {
    for name in [
        "a, (SELECT 1) AS leak",
        "x) OR (1",
        "a\\",
        "a\\\", 2 AS b",
        "a\"b",
        "a -- c",
        "a/**/b",
        "p95 latency",
        "src_endpoint.ip",
        "ünïcode",
        "",
    ] {
        let sql = format!("SELECT 1 AS {} FROM t", quote_identifier(name));
        let toks = tokens(&sql);
        // SELECT, 1, AS, <ident>, FROM, t
        assert_eq!(toks.len(), 6, "{name:?} -> {sql} -> {toks:?}");
        match &toks[3] {
            // sqlparser does not apply ClickHouse's backslash escapes inside
            // quoted identifiers, so compare the value only when there are none.
            // The token COUNT above is the breakout check either way.
            Token::Word(w) if !name.contains('\\') => assert_eq!(w.value, name, "{sql}"),
            Token::Word(_) => {}
            other => panic!("{name:?} produced {other:?} in {sql}"),
        }
    }
}

#[test]
fn quote_identifier_always_quotes_barewords_too() {
    assert_eq!(quote_identifier_always("src_ip"), "\"src_ip\"");
    assert_eq!(quote_identifier_always("a\\\"b"), "\"a\\\\\"\"b\"");
}

#[test]
fn alias_expr_quotes_only_the_alias() {
    assert_eq!(alias_expr("count()", "c"), "count() AS c");
    assert_eq!(alias_expr("(x + 1)", "p95 latency"), "(x + 1) AS \"p95 latency\"");
}

#[test]
fn qualified_column_keeps_structural_dots_bare() {
    assert_eq!(qualified_column("l", "src_ip"), "l.src_ip");
    assert_eq!(qualified_column("l", "src_endpoint.ip"), "l.src_endpoint.ip");
    assert_eq!(qualified_column("l", "p95 latency"), "l.\"p95 latency\"");
    assert_eq!(qualified_column("l", "a) OR 1=1 OR (1"), "l.\"a) OR 1=1 OR (1\"");
}

#[test]
fn string_literal_escapes_backslash_then_quote() {
    assert_eq!(string_literal("it's"), "'it''s'");
    assert_eq!(string_literal("C:\\x"), "'C:\\\\x'");
    let sql = format!("SELECT {} AS v", string_literal("') OR 1=1 --\\"));
    let toks = tokens(&sql);
    assert_eq!(toks.len(), 4, "{sql} -> {toks:?}");
    assert!(matches!(toks[1], Token::SingleQuotedString(_)), "{toks:?}");
}

#[test]
fn column_reference_quotes_only_unsafe_names() {
    assert_eq!(column_reference("bytes_out"), "bytes_out");
    assert_eq!(column_reference("metadata.time"), "metadata.time");
    assert_eq!(column_reference("a) OR (1"), "\"a) OR (1\"");
}

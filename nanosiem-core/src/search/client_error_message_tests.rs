// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5161: streamed search `Error` events and async job failure messages
//! carry `client_error_message(parse_clickhouse_error(raw))`. ClickHouse can
//! echo the executed statement, which for a source-scoped caller contains the
//! injected deny-list literals; none of that may reach the client.

use super::{client_error_message, parse_clickhouse_error, SearchError};

const DENIED: &str = "secret_src";

/// The message a streamed chunk error / failed job carries for a raw
/// ClickHouse error string (the exact composition both sinks use).
fn surfaced(raw: &str) -> String {
    client_error_message(&parse_clickhouse_error(raw))
}

fn assert_no_echo(msg: &str) {
    assert!(!msg.contains(DENIED), "deny-list literal leaked: {msg}");
    assert!(!msg.contains("SELECT"), "statement text leaked: {msg}");
    assert!(!msg.contains("NOT IN"), "statement text leaked: {msg}");
    assert!(!msg.contains("version 25"), "server version leaked: {msg}");
}

#[test]
fn analyzer_error_echoing_scoped_statement_is_masked() {
    let raw = "Code: 43. DB::Exception: Illegal type String of argument of function plus: \
        In scope SELECT count() FROM logs WHERE (timestamp >= '2026-11-09 00:00:00') \
        AND (source_type NOT IN ('secret_src', 'audit')). (ILLEGAL_TYPE_OF_ARGUMENT) \
        (version 25.8.13.73 (official build))";
    let msg = surfaced(raw);
    assert_no_echo(&msg);
    assert_eq!(msg, "A database error occurred");
}

#[test]
fn unknown_field_keeps_guidance_without_the_echo() {
    let raw = "Code: 47. DB::Exception: Unknown expression identifier `srcip` in scope \
        SELECT srcip FROM logs WHERE source_type NOT IN ('secret_src'). \
        Maybe you meant: ['src_ip']. (UNKNOWN_IDENTIFIER) (version 25.8.13.73 (official build))";
    let msg = surfaced(raw);
    assert_no_echo(&msg);
    assert!(msg.contains("srcip"), "field name must stay: {msg}");
    assert!(msg.contains("src_ip"), "suggestion must stay: {msg}");
}

#[test]
fn syntax_error_keeps_position_but_drops_the_quoted_excerpt() {
    let raw = "Code: 62. DB::Exception: Syntax error: failed at position 88 \
        ('secret_src') (line 1, col 88): 'secret_src', 'audit')) LIMIT 100. \
        Expected one of: token, Comma. (SYNTAX_ERROR) (version 25.8.13.73 (official build))";
    let msg = surfaced(raw);
    assert_no_echo(&msg);
    assert!(msg.contains("syntax error at position 88"), "got: {msg}");
}

#[test]
fn plain_syntax_error_stays_useful() {
    let msg = surfaced("Code: 62. DB::Exception: Syntax error (SYNTAX_ERROR)");
    assert!(msg.contains("Query syntax error"), "got: {msg}");
    assert!(msg.contains("missing commas"), "got: {msg}");
}

#[test]
fn user_actionable_errors_pass_through() {
    let parse = SearchError::ParseError("unexpected token '|'".to_string());
    assert!(client_error_message(&parse).contains("unexpected token"));

    let guardrail = SearchError::SqlGenError(
        "Invalid query: tree requires a parent field".to_string(),
    );
    assert_eq!(
        client_error_message(&guardrail),
        "Invalid query: tree requires a parent field"
    );

    let internal = SearchError::SqlGenError(format!(
        "failed to build stage: source_type NOT IN ('{DENIED}')"
    ));
    assert_eq!(client_error_message(&internal), "Query processing failed");

    let oom = surfaced("Code: 241. DB::Exception: Memory limit (total) exceeded: \
        In scope SELECT * FROM logs WHERE source_type NOT IN ('secret_src'). (MEMORY_LIMIT_EXCEEDED)");
    assert_no_echo(&oom);
    assert!(oom.contains("memory limit"), "got: {oom}");

    assert_eq!(client_error_message(&SearchError::Cancelled), "Query was cancelled");
}

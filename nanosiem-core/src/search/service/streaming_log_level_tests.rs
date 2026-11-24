// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5817: a user's query mistake on the streaming path must not log at
//! ERROR. With Sentry on, every tracing ERROR becomes a Sentry error event,
//! so `Invalid query: Unknown eval function 'nosuchfn'` from an e2e negative
//! test opened NANO-SERVER-7. Internal generation failures still log at ERROR.

use super::chunk_sql_gen_failure_event;
use crate::query::SqlGenError;
use crate::search::{SearchError, SearchStreamEvent};
use crate::search::log_capture::levels_logged;
use tracing::Level;

#[test]
fn user_query_error_on_stream_chunk_logs_warn_not_error() {
    let err = SqlGenError::InvalidQuery("Unknown eval function 'nosuchfn'".to_string());
    let (event, levels) = levels_logged(|| chunk_sql_gen_failure_event(&err));

    assert!(!levels.contains(&Level::ERROR), "user query error logged at ERROR: {levels:?}");
    assert!(levels.contains(&Level::WARN), "user query error not logged at all: {levels:?}");
    // The client-facing event is unchanged: code and verbatim guidance.
    match event {
        SearchStreamEvent::Error { code, message } => {
            assert_eq!(code, "SQL_GEN_ERROR");
            assert_eq!(message, "Invalid query: Unknown eval function 'nosuchfn'");
        }
        other => panic!("expected an Error event, got {other:?}"),
    }
}

#[test]
fn unsupported_operation_guardrail_logs_warn_not_error() {
    let err = SqlGenError::UnsupportedOperation("asset must be the last command".to_string());
    let (_, levels) = levels_logged(|| chunk_sql_gen_failure_event(&err));
    assert!(!levels.contains(&Level::ERROR), "guardrail logged at ERROR: {levels:?}");
}

#[test]
fn internal_sql_gen_failure_on_stream_chunk_still_logs_error() {
    let err = SqlGenError::Internal("stage collector lost its alias map".to_string());
    let (event, levels) = levels_logged(|| chunk_sql_gen_failure_event(&err));

    assert!(levels.contains(&Level::ERROR), "internal failure not logged at ERROR: {levels:?}");
    // Still masked for the client.
    match event {
        SearchStreamEvent::Error { code, message } => {
            assert_eq!(code, "SQL_GEN_ERROR");
            assert_eq!(message, "Query processing failed");
        }
        other => panic!("expected an Error event, got {other:?}"),
    }
}

#[test]
fn log_search_failure_splits_user_and_internal_errors() {
    let user = [
        SearchError::ParseError("unexpected token".to_string()),
        SearchError::SqlValidationError("Unknown function 'nosuchfn'".to_string()),
        SearchError::SqlGenError("Invalid query: bad".to_string()),
        SearchError::Cancelled,
        // Size limits from an oversized query are the caller's to narrow.
        SearchError::ResourceLimit("Query exceeded memory limit".to_string()),
        SearchError::ResponseTooLarge(200, 100),
    ];
    for err in user {
        let (_, levels) = levels_logged(|| crate::search::log_search_failure!(err, "probe"));
        assert_eq!(levels, vec![Level::WARN], "{err:?}");
    }
    let internal = [
        SearchError::SqlGenError("Internal error: boom".to_string()),
        SearchError::Unavailable("connection refused".to_string()),
        SearchError::DatabaseError(sqlx::Error::Protocol("bad".to_string())),
        SearchError::PrevalenceError("dict missing".to_string()),
        // A timeout can mean an overloaded or slow backend: keep it in Sentry.
        SearchError::Timeout(10_000),
    ];
    for err in internal {
        let (_, levels) = levels_logged(|| crate::search::log_search_failure!(err, "probe"));
        assert_eq!(levels, vec![Level::ERROR], "{err:?}");
    }
}

/// Review P2: nano's own post-processing / prevalence rejections of the
/// caller's query are masked for the client but are user errors: WARN.
#[test]
fn nano_side_user_rejections_are_not_internal() {
    for msg in [
        "Invalid rex pattern '(': regex parse error",
        "Invalid or unsupported post-processing regex",
        "Invalid or unsupported regex in match()",
        "Invalid CIDR 'nope' in cidr_match()",
        "Function 'nosuchfn' is not supported after a post-processing stage (e.g. prevalence, risk)",
        "len() requires 1 argument",
        "substr() requires 2 to 3 arguments",
        "coalesce() requires at least 1 argument",
        "Contains requires string value",
        "Regex requires string/regex value",
    ] {
        assert!(!SearchError::SqlGenError(msg.to_string()).is_internal(), "{msg}");
        // The client message is unchanged: still masked.
        assert_eq!(
            crate::search::client_error_message(&SearchError::SqlGenError(msg.to_string())),
            "Query processing failed",
            "{msg}"
        );
    }
    // Kept internal on purpose (NAN-5817 review round 1), plus generator gaps.
    for msg in [
        "Empty query",
        "Invalid field name: x",
        "Internal error: boom",
        "Unsupported value type",
        "Unsupported expression type: Foo",
        "requires 1 argument",
    ] {
        assert!(SearchError::SqlGenError(msg.to_string()).is_internal(), "{msg}");
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5817 review P1: ClickHouse rejecting SQL that nano generated is a
//! generator bug or schema drift and logs at ERROR, although it maps to a
//! caller-facing variant. Raw SQL the caller wrote, size limits, and the
//! recovered typed-row fallback do not.

use super::clickhouse_rejection::user_authored;
use super::log_capture::LevelCapture;
use super::{classify_clickhouse_failure, search_error_from_error, SearchError};
use tracing::Level;

fn ch(message: &str) -> clickhouse::error::Error {
    clickhouse::error::Error::BadResponse(message.to_string())
}

const UNKNOWN_FUNCTION: &str =
    "Code: 46. DB::Exception: Unknown function nosuchfn: While processing nosuchfn(x). (UNKNOWN_FUNCTION)";
const SYNTAX: &str = "Code: 62. DB::Exception: Syntax error: failed at position 12 (SYNTAX_ERROR)";
const MISSING_COLUMN: &str =
    "Code: 47. DB::Exception: Unknown expression identifier `srcip` in scope SELECT srcip. (UNKNOWN_IDENTIFIER)";
const ARITY: &str =
    "Code: 42. DB::Exception: Number of arguments for function lower doesn't match. (NUMBER_OF_ARGUMENTS_DOESNT_MATCH)";
const MEMORY: &str = "Code: 241. DB::Exception: Memory limit exceeded. (MEMORY_LIMIT_EXCEEDED)";

#[tokio::test(flavor = "current_thread")]
async fn rejection_of_generated_sql_logs_error() {
    for raw in [UNKNOWN_FUNCTION, SYNTAX, MISSING_COLUMN, ARITY] {
        let capture = LevelCapture::default();
        let parsed = {
            let _g = capture.install();
            search_error_from_error(&ch(raw))
        };
        assert!(!parsed.is_internal(), "still a caller-facing variant: {parsed:?}");
        assert!(capture.levels().contains(&Level::ERROR), "{raw}: {:?}", capture.levels());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rejection_of_user_authored_raw_sql_does_not_log_error() {
    let capture = LevelCapture::default();
    let _g = capture.install();
    for raw in [UNKNOWN_FUNCTION, SYNTAX, MISSING_COLUMN, ARITY] {
        let parsed = user_authored(async { search_error_from_error(&ch(raw)) }).await;
        assert!(!parsed.is_internal());
    }
    assert!(!capture.levels().contains(&Level::ERROR), "{:?}", capture.levels());
    // Outside the scope it reports again.
    let _ = search_error_from_error(&ch(SYNTAX));
    assert!(capture.levels().contains(&Level::ERROR));
}

#[test]
fn size_limits_and_cancel_are_not_reported() {
    let capture = LevelCapture::default();
    let _g = capture.install();
    assert!(matches!(search_error_from_error(&ch(MEMORY)), SearchError::ResourceLimit(_)));
    assert!(matches!(
        search_error_from_error(&ch("Code: 394. DB::Exception: Query was cancelled. (QUERY_WAS_CANCELLED)")),
        SearchError::Cancelled
    ));
    assert!(capture.levels().is_empty(), "{:?}", capture.levels());
}

#[test]
fn recovered_typed_fallback_is_not_reported() {
    let capture = LevelCapture::default();
    let _g = capture.install();
    let parsed = classify_clickhouse_failure(&ch(MISSING_COLUMN));
    assert!(matches!(parsed, SearchError::FieldNotFound { .. }), "{parsed:?}");
    assert!(capture.levels().is_empty(), "{:?}", capture.levels());
}

/// A failure the nPL validator caught before any SQL ran stays at WARN.
#[test]
fn pre_sql_validation_failure_logs_warn() {
    let err = SearchError::SqlGenError("Invalid query: Unknown eval function 'nosuchfn'".into());
    let (_, levels) = super::log_capture::levels_logged(|| super::log_search_failure!(err, "probe"));
    assert_eq!(levels, vec![Level::WARN]);
}

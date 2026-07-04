// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for the Search Service

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// Search service error type
#[derive(Debug, Error)]
pub enum SearchError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("{formatted}")]
    StructuredParseError {
        message: String,
        position: usize,
        line: usize,
        column: usize,
        token: Option<String>,
        expected: Vec<String>,
        suggestions: Vec<ErrorSuggestion>,
        formatted: String,
    },

    #[error("Query error: {0}")]
    QueryError(String),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Admission denied: {0}")]
    AdmissionDenied(String),

    /// The query was killed mid-flight (`DELETE /api/search/{request_id}` or
    /// an admin job cancel). Distinct from `InternalError` so the original
    /// caller of a cancelled search sees a deliberate 409/QUERY_CANCELLED
    /// instead of a misleading 500 (NAN-1436, follow-up to NAN-1435).
    #[error("Query was cancelled")]
    Cancelled,
}

/// A suggested fix for a parse error
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ErrorSuggestion {
    /// Description of the fix
    pub description: String,
    /// The corrected query snippet
    pub replacement: String,
}

/// Error response body
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

/// Error detail
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum ErrorDetail {
    Simple {
        code: String,
        message: String,
    },
    Structured {
        code: String,
        message: String,
        details: ParseErrorDetails,
    },
}

/// Detailed parse error information
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ParseErrorDetails {
    pub position: usize,
    pub line: usize,
    pub column: usize,
    pub token: Option<String>,
    pub expected: Vec<String>,
    pub suggestions: Vec<ErrorSuggestion>,
    pub formatted: String,
}

impl SearchError {
    /// Get the error code
    pub fn code(&self) -> &'static str {
        match self {
            SearchError::BadRequest(_) => "BAD_REQUEST",
            SearchError::NotFound(_) => "NOT_FOUND",
            SearchError::Forbidden(_) => "FORBIDDEN",
            SearchError::ParseError(_) => "PARSE_ERROR",
            SearchError::StructuredParseError { .. } => "PARSE_ERROR",
            SearchError::QueryError(_) => "QUERY_ERROR",
            SearchError::InternalError(_) => "INTERNAL_ERROR",
            SearchError::AdmissionDenied(_) => "ADMISSION_DENIED",
            SearchError::Cancelled => "QUERY_CANCELLED",
        }
    }

    /// Get the HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            SearchError::BadRequest(_) => StatusCode::BAD_REQUEST,
            SearchError::NotFound(_) => StatusCode::NOT_FOUND,
            SearchError::Forbidden(_) => StatusCode::FORBIDDEN,
            SearchError::ParseError(_) => StatusCode::BAD_REQUEST,
            SearchError::StructuredParseError { .. } => StatusCode::BAD_REQUEST,
            SearchError::QueryError(_) => StatusCode::BAD_REQUEST,
            SearchError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SearchError::AdmissionDenied(_) => StatusCode::TOO_MANY_REQUESTS,
            // 409: the request didn't fail — its lifecycle conflicted with a
            // deliberate cancel issued against it. Not 4xx-client-mistake, not
            // 5xx-server-fault; mirrors AdmissionDenied's "non-error outcome
            // gets a distinct, stable status" convention (429 there).
            SearchError::Cancelled => StatusCode::CONFLICT,
        }
    }
}

impl IntoResponse for SearchError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorResponse {
            error: match self {
                SearchError::StructuredParseError {
                    message,
                    position,
                    line,
                    column,
                    token,
                    expected,
                    suggestions,
                    formatted,
                } => {
                    let code = "PARSE_ERROR".to_string();
                    ErrorDetail::Structured {
                        code,
                        message,
                        details: ParseErrorDetails {
                            position,
                            line,
                            column,
                            token,
                            expected,
                            suggestions,
                            formatted,
                        },
                    }
                }
                _ => {
                    let code = self.code().to_string();
                    let message = self.to_string();
                    ErrorDetail::Simple { code, message }
                }
            },
        };

        (status, Json(body)).into_response()
    }
}

impl From<nanosiem_core::SearchError> for SearchError {
    fn from(err: nanosiem_core::SearchError) -> Self {
        match err {
            nanosiem_core::SearchError::ParseError(msg) => SearchError::ParseError(msg),
            // NAN-1354: input-side field validation rejections (a malformed or
            // typo'd field name). User-actionable → 400 with the message and any
            // "did you mean" suggestions, mirroring the field guidance the parse
            // path already returns.
            nanosiem_core::SearchError::FieldNotFound {
                message,
                suggestions,
                ..
            } => {
                let detail = if suggestions.is_empty() {
                    message
                } else {
                    format!("{message}. Did you mean: {}", suggestions.join(", "))
                };
                SearchError::BadRequest(detail)
            }
            nanosiem_core::SearchError::StructuredParseError {
                message,
                position,
                line,
                column,
                token,
                expected,
                suggestions,
                formatted,
            } => SearchError::StructuredParseError {
                message,
                position,
                line,
                column,
                token,
                expected,
                suggestions: suggestions
                    .into_iter()
                    .map(|s| ErrorSuggestion {
                        description: s.description,
                        replacement: s.replacement,
                    })
                    .collect(),
                formatted,
            },
            nanosiem_core::SearchError::SqlGenError(msg) => {
                tracing::error!(error = %msg, "SQL generation error");
                // InvalidQuery / UnsupportedOperation messages are written FOR
                // the user — guardrails with usage guidance ("tree requires a
                // parent field…", "asset … must be the last command", the
                // append shape-mismatch hint). Masking them behind "Query
                // processing failed" hides the very guidance they carry
                // (NAN-1339). Other SqlGenError variants are internal
                // generation failures and stay masked.
                if msg.starts_with("Invalid query:")
                    || msg.starts_with("Unsupported operation:")
                {
                    SearchError::QueryError(msg)
                } else {
                    SearchError::QueryError("Query processing failed".to_string())
                }
            }
            nanosiem_core::SearchError::InvalidTimeRange => {
                SearchError::BadRequest("Invalid time range: start must be before end".to_string())
            }
            nanosiem_core::SearchError::SqlValidationError(msg) => SearchError::QueryError(msg),
            nanosiem_core::SearchError::DatabaseError(e) => {
                tracing::error!(error = %e, "Database error in search");
                SearchError::InternalError("A database error occurred".to_string())
            }
            nanosiem_core::SearchError::AdmissionDenied(msg) => SearchError::AdmissionDenied(msg),
            // NAN-1436: a killed query (CH Code 394 via the cancel endpoint)
            // surfaces as a deliberate 409/QUERY_CANCELLED, not a 500.
            nanosiem_core::SearchError::Cancelled => SearchError::Cancelled,
            _ => {
                tracing::error!(error = %err, "Unhandled search error");
                SearchError::InternalError("An internal error occurred".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-1339: InvalidQuery / UnsupportedOperation generation guardrails are
    /// written FOR the user (usage guidance) — they must surface verbatim, while
    /// internal generation failures stay masked.
    #[test]
    fn sqlgen_guardrail_messages_surface_to_the_client() {
        let guardrail = nanosiem_core::SearchError::SqlGenError(
            "Invalid query: tree requires a parent field: use `tree <field> parent=<parent field>`"
                .to_string(),
        );
        match SearchError::from(guardrail) {
            SearchError::QueryError(msg) => assert!(
                msg.contains("tree requires a parent field"),
                "guardrail guidance must reach the client; got: {msg}"
            ),
            other => panic!("expected QueryError, got {other:?}"),
        }

        let unsupported = nanosiem_core::SearchError::SqlGenError(
            "Unsupported operation: append: the main search and the appended subsearch ..."
                .to_string(),
        );
        match SearchError::from(unsupported) {
            SearchError::QueryError(msg) => assert!(msg.contains("append")),
            other => panic!("expected QueryError, got {other:?}"),
        }

        let internal = nanosiem_core::SearchError::SqlGenError(
            "failed to build CTE stage 3: unexpected state".to_string(),
        );
        match SearchError::from(internal) {
            SearchError::QueryError(msg) => assert_eq!(
                msg, "Query processing failed",
                "internal generation failures must stay masked"
            ),
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    /// NAN-1436: a cancelled query (CH Code 394 → core `Cancelled`) must reach
    /// the client as 409/QUERY_CANCELLED, not the generic 500/INTERNAL_ERROR
    /// it used to fall into via the DatabaseError mapping.
    #[test]
    fn cancelled_query_maps_to_409_query_cancelled() {
        let mapped = SearchError::from(nanosiem_core::SearchError::Cancelled);
        assert!(matches!(mapped, SearchError::Cancelled));
        assert_eq!(mapped.status_code(), StatusCode::CONFLICT);
        assert_eq!(mapped.code(), "QUERY_CANCELLED");

        // End-to-end: the raw CH 394 string through the shared parser lands on
        // the same 409, while an unrecognized DB failure keeps the generic 500.
        let killed = SearchError::from(nanosiem_core::search::parse_clickhouse_error(
            "Code: 394. DB::Exception: Query was cancelled (QUERY_WAS_CANCELLED)",
        ));
        assert_eq!(killed.status_code(), StatusCode::CONFLICT);
        assert_eq!(killed.code(), "QUERY_CANCELLED");

        let db = SearchError::from(nanosiem_core::search::parse_clickhouse_error(
            "Code: 999. DB::Exception: something else entirely",
        ));
        assert_eq!(db.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(db.code(), "INTERNAL_ERROR");
    }

    /// NAN-1689: the `window=1h is not supported` rejection is user-actionable
    /// guidance. Both prevalence paths raise it as `SqlValidationError`, which
    /// must surface as a clean 400 carrying the real message. Operational
    /// `PrevalenceError`s (wrapped ClickHouse failures) stay masked as 500 — so
    /// the window rejection deliberately does NOT ride the PrevalenceError path.
    #[test]
    fn unsupported_prevalence_window_maps_to_400_with_message() {
        let mapped = SearchError::from(nanosiem_core::SearchError::SqlValidationError(
            "prevalence window=1h is not supported; use 24h, 7d, or 30d".to_string(),
        ));
        assert_eq!(mapped.status_code(), StatusCode::BAD_REQUEST);
        match mapped {
            SearchError::QueryError(msg) => assert!(
                msg.contains("use 24h, 7d, or 30d"),
                "the actionable guidance must reach the client; got: {msg}"
            ),
            other => panic!("expected QueryError, got {other:?}"),
        }

        // An operational prevalence failure (wrapped ClickHouse error) must NOT
        // become a 400 — it stays masked as a 500 via the catch-all.
        let operational = SearchError::from(nanosiem_core::SearchError::PrevalenceError(
            "ClickHouse error: connection refused".to_string(),
        ));
        assert_eq!(operational.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

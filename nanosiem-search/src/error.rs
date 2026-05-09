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

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Admission denied: {0}")]
    AdmissionDenied(String),
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
            SearchError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            SearchError::AdmissionDenied(_) => "ADMISSION_DENIED",
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
            SearchError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            SearchError::AdmissionDenied(_) => StatusCode::TOO_MANY_REQUESTS,
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
                SearchError::QueryError("Query processing failed".to_string())
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
            _ => {
                tracing::error!(error = %err, "Unhandled search error");
                SearchError::InternalError("An internal error occurred".to_string())
            }
        }
    }
}

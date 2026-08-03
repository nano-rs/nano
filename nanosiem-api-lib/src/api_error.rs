//! Shared `ApiError` type — lifted out of `nanosiem-api/src/error.rs` so that
//! enterprise handler modules in `nanosiem-enterprise` can return the same
//! error type without depending on `nanosiem-api` (which would create a
//! circular crate dependency).
//!
//! All `From` impls that involve only `nanosiem-core` types live here.
//! `From` impls for enterprise-tier error types
//! (e.g. `nanosiem_enterprise::CaseServiceError`) live in `nanosiem-enterprise`
//! to satisfy the orphan rule — the enterprise crate references both
//! `ApiError` (from this crate, on which it depends) and the enterprise error
//! type, so the impl is legal there.
//!
//! `nanosiem-api` re-exports `ApiError` at `crate::error::ApiError` so existing
//! handler imports continue to work unchanged.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// API error type
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Query parse error: {0}")]
    ParseError(String),

    #[error("SQL validation error: {0}")]
    SqlValidationError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Tier limit exceeded")]
    TierLimitExceeded(nanosiem_core::TierLimitExceeded),

    /// NAN-712: panel uses `| prevalence` but every filter is a wildcard.
    /// The Vec carries the list of `field=*` clauses found in the query so
    /// the frontend can name them in its panel-level "Apply a filter" empty
    /// state. Vec may be empty for the bare `*` case.
    #[error("Unscoped prevalence query")]
    UnscopedPrevalence(Vec<String>),
}

/// Error response body
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

/// Error detail
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    /// Get the error code
    pub fn code(&self) -> &'static str {
        match self {
            ApiError::NotFound(_) => "NOT_FOUND",
            ApiError::BadRequest(_) => "BAD_REQUEST",
            ApiError::Unauthorized(_) => "UNAUTHORIZED",
            ApiError::Forbidden(_) => "FORBIDDEN",
            ApiError::Conflict(_) => "CONFLICT",
            ApiError::TooManyRequests(_) => "TOO_MANY_REQUESTS",
            ApiError::PayloadTooLarge(_) => "PAYLOAD_TOO_LARGE",
            ApiError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            ApiError::ValidationError(_) => "VALIDATION_ERROR",
            ApiError::ParseError(_) => "PARSE_ERROR",
            ApiError::SqlValidationError(_) => "SQL_VALIDATION_ERROR",
            ApiError::DatabaseError(_) => "DATABASE_ERROR",
            ApiError::InternalError(_) => "INTERNAL_ERROR",
            ApiError::Timeout(_) => "TIMEOUT",
            ApiError::TierLimitExceeded(_) => "TIER_LIMIT_EXCEEDED",
            ApiError::UnscopedPrevalence(_) => "UNSCOPED_PREVALENCE",
        }
    }

    /// Get the HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::ValidationError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::ParseError(_) => StatusCode::BAD_REQUEST,
            ApiError::SqlValidationError(_) => StatusCode::BAD_REQUEST,
            ApiError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            ApiError::TierLimitExceeded(_) => StatusCode::FORBIDDEN,
            ApiError::UnscopedPrevalence(_) => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}

/// Render an error with its full `source()` chain, so a 5xx log line carries
/// the underlying cause (the PG constraint, the ClickHouse exception, the IO
/// error inside the driver error) rather than only the top frame.
pub fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut rendered = err.to_string();
    let mut current = err.source();
    while let Some(next) = current {
        rendered.push_str(": ");
        rendered.push_str(&next.to_string());
        current = next.source();
    }
    rendered
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        // NAN-2266: every 5xx must name its cause in the server log. Before
        // this, an internal error became a bare `500` status line and nothing
        // else — the sweep-report failure this ticket fixes had to be diagnosed
        // from the ClickHouse query log because the API recorded no reason.
        //
        // The response body stays exactly as it was (generic code + message);
        // the detail this line carries — plus the request id already on the
        // enclosing tracing span — goes to the log and only to the log.
        //
        // Expected 4xx (validation, not-found, forbidden, conflict, rate
        // limits) are deliberately NOT logged here: they are the caller's
        // mistake, not ours, and logging them at ERROR would bury the real
        // faults under noise.
        if status.is_server_error() {
            tracing::error!(
                status = status.as_u16(),
                code = self.code(),
                error = %self,
                "request failed with a server error"
            );
        }
        let details = match &self {
            ApiError::TierLimitExceeded(info) => {
                Some(serde_json::to_value(info).unwrap_or_default())
            }
            // NAN-712: surface the wildcard field list to the frontend so the
            // panel-level empty state can name them ("Set source_host or user
            // to a specific value").
            ApiError::UnscopedPrevalence(fields) => Some(serde_json::json!({
                "wildcard_fields": fields,
            })),
            _ => None,
        };
        // NAN-712: override the default Display text with a friendly message
        // for UnscopedPrevalence so the panel error UI reads sensibly even
        // when the frontend doesn't recognize the structured code.
        let message = match &self {
            ApiError::UnscopedPrevalence(fields) if fields.is_empty() => {
                "This panel uses `| prevalence` and won't run without a filter. Apply at least one variable (e.g. a hostname or username) and click Run.".to_string()
            }
            ApiError::UnscopedPrevalence(fields) => format!(
                "This panel uses `| prevalence` and won't run with all wildcards ({}). Set at least one to a specific value and click Run.",
                fields.iter().map(|f| format!("{}=*", f)).collect::<Vec<_>>().join(", ")
            ),
            _ => self.to_string(),
        };
        let body = ErrorResponse {
            error: ErrorDetail {
                code: self.code().to_string(),
                message,
                details,
            },
        };

        (status, Json(body)).into_response()
    }
}

// ----------------------------------------------------------------------------
// Conversion from nanosiem-core errors
// ----------------------------------------------------------------------------

impl From<nanosiem_core::SearchError> for ApiError {
    fn from(err: nanosiem_core::SearchError) -> Self {
        match err {
            nanosiem_core::SearchError::ParseError(msg) => ApiError::ParseError(msg),
            nanosiem_core::SearchError::StructuredParseError { formatted, .. } => {
                ApiError::ParseError(formatted)
            }
            nanosiem_core::SearchError::FieldNotFound { message, .. } => {
                // User-friendly field not found error - return as validation error with nice message
                ApiError::ValidationError(message)
            }
            nanosiem_core::SearchError::SqlGenError(msg) => {
                tracing::error!(error = %msg, "SQL generation error");
                ApiError::InternalError("Query processing failed".to_string())
            }
            nanosiem_core::SearchError::DatabaseError(e) => {
                tracing::error!(error = %e, "Database error in search");
                ApiError::DatabaseError("A database error occurred".to_string())
            }
            nanosiem_core::SearchError::Timeout(ms) => {
                ApiError::InternalError(format!("Query timeout after {}ms", ms))
            }
            nanosiem_core::SearchError::InvalidTimeRange => ApiError::ValidationError(
                "Invalid time range: start must be before end".to_string(),
            ),
            nanosiem_core::SearchError::SqlValidationError(msg) => {
                ApiError::SqlValidationError(msg)
            }
            nanosiem_core::SearchError::PrevalenceError(msg) => ApiError::InternalError(msg),
            nanosiem_core::SearchError::ResponseTooLarge(size, limit) => {
                ApiError::ValidationError(format!(
                    "Response too large: {} bytes exceeds limit of {} bytes",
                    size, limit
                ))
            }
            nanosiem_core::SearchError::AdmissionDenied(msg) => ApiError::TooManyRequests(msg),
            // NAN-1436: a deliberately killed query (CH 394 via search cancel)
            // is not a server fault — surface 409 instead of a generic 500.
            // (nanosiem-search has its own dedicated QUERY_CANCELLED code; the
            // api crate reuses its existing Conflict envelope.)
            nanosiem_core::SearchError::Cancelled => {
                ApiError::Conflict("Query was cancelled".to_string())
            }
        }
    }
}

impl From<nanosiem_core::DetectionError> for ApiError {
    fn from(err: nanosiem_core::DetectionError) -> Self {
        match &err {
            nanosiem_core::DetectionError::RuleNotFound(id) => {
                ApiError::NotFound(format!("Detection rule not found: {}", id))
            }
            nanosiem_core::DetectionError::AlertNotFound(id) => {
                ApiError::NotFound(format!("Alert not found: {}", id))
            }
            nanosiem_core::DetectionError::QueryParseError(msg) => {
                ApiError::ParseError(msg.clone())
            }
            nanosiem_core::DetectionError::InvalidQuery(msg) => {
                ApiError::ValidationError(msg.clone())
            }
            nanosiem_core::DetectionError::InvalidCronExpression(msg) => {
                ApiError::ValidationError(msg.clone())
            }
            nanosiem_core::DetectionError::InvalidMitreMapping(msg) => {
                ApiError::ValidationError(msg.clone())
            }
            nanosiem_core::DetectionError::ConcurrentModification(id) => {
                ApiError::Conflict(format!(
                    "Rule {} was modified by another request. Please refresh and try again.",
                    id
                ))
            }
            nanosiem_core::DetectionError::InvalidStateTransition(msg) => {
                ApiError::Conflict(format!("Invalid state transition: {}", msg))
            }
            _ => {
                tracing::error!(error = %err, "Unhandled detection error");
                ApiError::InternalError("An internal error occurred".to_string())
            }
        }
    }
}

impl From<nanosiem_core::TierError> for ApiError {
    fn from(err: nanosiem_core::TierError) -> Self {
        match err {
            nanosiem_core::TierError::LimitExceeded(msg) => {
                ApiError::Forbidden(format!("Tier limit exceeded: {}", msg))
            }
            nanosiem_core::TierError::FeatureNotAvailable(msg) => {
                ApiError::Forbidden(format!("Feature not available on your plan: {}", msg))
            }
            nanosiem_core::TierError::ApiAccessRestricted(msg) => {
                ApiError::Forbidden(format!("API access restricted: {}", msg))
            }
            nanosiem_core::TierError::AiRateLimitExceeded(msg) => ApiError::TooManyRequests(msg),
            nanosiem_core::TierError::AiModelNotAvailable(msg) => {
                ApiError::Forbidden(format!("AI model not available: {}", msg))
            }
            nanosiem_core::TierError::InvalidTier(msg) => {
                ApiError::ValidationError(format!("Invalid tier: {}", msg))
            }
            nanosiem_core::TierError::Validation(msg) => ApiError::ValidationError(msg),
            nanosiem_core::TierError::Database(e) => {
                tracing::error!(error = %e, "Tier settings database error");
                ApiError::DatabaseError("A database error occurred".to_string())
            }
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        // Log the actual error server-side for debugging, but return a generic
        // message to the client. `error_chain` walks `source()` so the line
        // names the database's own error (constraint, column, SQLSTATE context)
        // rather than sqlx's top frame alone.
        tracing::error!(error = %error_chain(&err), "Database error occurred");
        ApiError::DatabaseError("A database error occurred".to_string())
    }
}

impl From<nanosiem_core::FeedServiceError> for ApiError {
    fn from(err: nanosiem_core::FeedServiceError) -> Self {
        match &err {
            nanosiem_core::FeedServiceError::RepositoryError(repo_err) => {
                match repo_err {
                    nanosiem_core::feeds::FeedRepositoryError::NotFound(id) => {
                        ApiError::NotFound(format!("Feed not found: {}", id))
                    }
                    nanosiem_core::feeds::FeedRepositoryError::DuplicateName(name) => {
                        ApiError::ValidationError(format!("Feed name already exists: {}", name))
                    }
                    nanosiem_core::feeds::FeedRepositoryError::DatabaseError(e) => {
                        tracing::error!(error = %e, "Feed repository database error");
                        ApiError::DatabaseError("A database error occurred".to_string())
                    }
                    nanosiem_core::feeds::FeedRepositoryError::ClickHouseError(e) => {
                        ApiError::DatabaseError(format!("ClickHouse error: {}", e))
                    }
                }
            }
            nanosiem_core::FeedServiceError::InvalidPattern(msg) => {
                ApiError::ValidationError(format!("Invalid regex pattern: {}", msg))
            }
            nanosiem_core::FeedServiceError::NoMatchingCriteria => {
                ApiError::ValidationError("Feed must have at least one matching criteria (match_field with match_pattern or match_values)".to_string())
            }
        }
    }
}

impl From<nanosiem_core::ParserServiceError> for ApiError {
    fn from(err: nanosiem_core::ParserServiceError) -> Self {
        match &err {
            nanosiem_core::ParserServiceError::RepositoryError(repo_err) => match repo_err {
                nanosiem_core::parsers::ParserRepositoryError::NotFound(id) => {
                    ApiError::NotFound(format!("Parser not found: {}", id))
                }
                nanosiem_core::parsers::ParserRepositoryError::DuplicateName(name) => {
                    ApiError::ValidationError(format!("Parser name already exists: {}", name))
                }
                // NAN-2305: migration 283's unique index fired past the
                // service-level check (concurrent write, or the ASCII/Unicode
                // normalization gap). Same class as DuplicateName — the name
                // is unusable, pick another — so the same 400.
                nanosiem_core::parsers::ParserRepositoryError::GeneratedNameConflict(msg) => {
                    ApiError::ValidationError(msg.clone())
                }
                nanosiem_core::parsers::ParserRepositoryError::DatabaseError(e) => {
                    tracing::error!(error = %e, "Parser repository database error");
                    ApiError::DatabaseError("A database error occurred".to_string())
                }
            },
            nanosiem_core::ParserServiceError::InvalidVrl(msg) => {
                ApiError::ValidationError(format!("Invalid VRL code: {}", msg))
            }
            nanosiem_core::ParserServiceError::InvalidSourceType(t) => {
                ApiError::ValidationError(format!("Invalid source type: {}", t))
            }
            // NAN-2305: same class as `DuplicateName` above (the requested name
            // is unusable, pick another) so it gets the same 400 rather than
            // introducing a second status code for "rename and retry". The
            // message is already self-describing — no prefix.
            nanosiem_core::ParserServiceError::NameCollision(msg) => {
                ApiError::ValidationError(msg.clone())
            }
            nanosiem_core::ParserServiceError::NotValidated => {
                ApiError::ValidationError("Parser must be validated before enabling".to_string())
            }
            nanosiem_core::ParserServiceError::VectorConfigError(e) => {
                ApiError::InternalError(format!("Vector config error: {}", e))
            }
            nanosiem_core::ParserServiceError::VrlValidationFailed(msg) => {
                ApiError::ValidationError(format!("VRL validation failed: {}", msg))
            }
            nanosiem_core::ParserServiceError::VectorValidationFailed(msg) => {
                ApiError::ValidationError(format!("Vector validation failed: {}", msg))
            }
            nanosiem_core::ParserServiceError::DeploymentFailed(msg) => {
                ApiError::InternalError(format!("Deployment failed: {}", msg))
            }
            nanosiem_core::ParserServiceError::ReloadFailed => {
                ApiError::InternalError("Vector reload failed".to_string())
            }
            nanosiem_core::ParserServiceError::RollbackFailed(msg) => {
                ApiError::InternalError(format!("Rollback failed: {}", msg))
            }
        }
    }
}

impl From<nanosiem_core::LogSourceServiceError> for ApiError {
    fn from(err: nanosiem_core::LogSourceServiceError) -> Self {
        match &err {
            nanosiem_core::LogSourceServiceError::RepositoryError(repo_err) => match repo_err {
                nanosiem_core::log_sources::LogSourceRepositoryError::NotFound(id) => {
                    ApiError::NotFound(format!("Log source not found: {}", id))
                }
                nanosiem_core::log_sources::LogSourceRepositoryError::DuplicateName(name) => {
                    ApiError::ValidationError(format!("Log source name already exists: {}", name))
                }
                nanosiem_core::log_sources::LogSourceRepositoryError::StaleVersion(id) => {
                    ApiError::Conflict(format!(
                        "Log source {} was modified by another update. Please reload and try again.",
                        nanosiem_core::typeid::encode(
                            nanosiem_core::typeid::log_source::PREFIX,
                            id
                        )
                    ))
                }
                nanosiem_core::log_sources::LogSourceRepositoryError::DatabaseError(e) => {
                    tracing::error!(error = %e, "Log source repository database error");
                    ApiError::DatabaseError("A database error occurred".to_string())
                }
                nanosiem_core::log_sources::LogSourceRepositoryError::ClickHouseError(e) => {
                    ApiError::DatabaseError(format!("ClickHouse error: {}", e))
                }
            },
            nanosiem_core::LogSourceServiceError::InvalidVrl(msg) => {
                ApiError::ValidationError(format!("Invalid VRL code: {}", msg))
            }
            nanosiem_core::LogSourceServiceError::InvalidSourceType(t) => {
                ApiError::ValidationError(format!("Invalid source type: {}", t))
            }
            nanosiem_core::LogSourceServiceError::InvalidSourceConfig(msg) => {
                ApiError::ValidationError(format!("Invalid source config: {}", msg))
            }
            // NAN-2158: a rejected `match_field` is an injection payload, not a
            // server fault — 400 with the offending value named, so an operator
            // fixing a legacy row can see what to change.
            // NAN-2311: same class as the parser-side NameCollision — the
            // requested name is unusable, pick another. 400, not the 500 the
            // bare unique-violation used to produce.
            nanosiem_core::LogSourceServiceError::NameCollision(msg) => {
                ApiError::ValidationError(msg.clone())
            }
            nanosiem_core::LogSourceServiceError::InvalidMatchField(msg) => {
                ApiError::ValidationError(format!("Invalid match_field: {}", msg))
            }
            nanosiem_core::LogSourceServiceError::NotValidated => ApiError::ValidationError(
                "Log source must be validated before enabling".to_string(),
            ),
            nanosiem_core::LogSourceServiceError::VectorConfigError(e) => {
                ApiError::InternalError(format!("Vector config error: {}", e))
            }
            nanosiem_core::LogSourceServiceError::VrlValidationFailed(msg) => {
                ApiError::ValidationError(format!("VRL validation failed: {}", msg))
            }
            nanosiem_core::LogSourceServiceError::VectorValidationFailed(msg) => {
                ApiError::ValidationError(format!("Vector validation failed: {}", msg))
            }
            nanosiem_core::LogSourceServiceError::DeploymentFailed(msg) => {
                ApiError::InternalError(format!("Deployment failed: {}", msg))
            }
            nanosiem_core::LogSourceServiceError::ReloadFailed => {
                ApiError::InternalError("Vector reload failed".to_string())
            }
            nanosiem_core::LogSourceServiceError::RollbackFailed(msg) => {
                ApiError::InternalError(format!("Rollback failed: {}", msg))
            }
            nanosiem_core::LogSourceServiceError::VersionError(ver_err) => match ver_err {
                nanosiem_core::log_sources::LogSourceVersionError::VersionNotFound(id) => {
                    ApiError::NotFound(format!("Version not found: {}", id))
                }
                nanosiem_core::log_sources::LogSourceVersionError::LogSourceNotFound(id) => {
                    ApiError::NotFound(format!("Log source not found: {}", id))
                }
                _ => ApiError::InternalError(format!("Version error: {}", ver_err)),
            },
        }
    }
}

impl From<nanosiem_core::SourceConfigServiceError> for ApiError {
    fn from(err: nanosiem_core::SourceConfigServiceError) -> Self {
        match &err {
            nanosiem_core::SourceConfigServiceError::RepositoryError(repo_err) => match repo_err {
                nanosiem_core::source_configs::SourceConfigRepositoryError::NotFound(id) => {
                    ApiError::NotFound(format!("Source configuration not found: {}", id))
                }
                nanosiem_core::source_configs::SourceConfigRepositoryError::AlreadyExists(name) => {
                    ApiError::ValidationError(format!(
                        "Source configuration name already exists: {}",
                        name
                    ))
                }
                nanosiem_core::source_configs::SourceConfigRepositoryError::Conflict(msg) => {
                    ApiError::Conflict(msg.clone())
                }
                nanosiem_core::source_configs::SourceConfigRepositoryError::StaleVersion(id) => {
                    ApiError::Conflict(format!(
                        "Source configuration {} was modified by another update. Please reload and try again.",
                        nanosiem_core::typeid::encode(
                            nanosiem_core::typeid::source_config::PREFIX,
                            id
                        )
                    ))
                }
                nanosiem_core::source_configs::SourceConfigRepositoryError::CredentialChanged(_) => {
                    ApiError::Conflict(
                        "Source configuration credentials changed concurrently; retry the update"
                            .to_string(),
                    )
                }
                nanosiem_core::source_configs::SourceConfigRepositoryError::RuleNotFound(id) => {
                    ApiError::NotFound(format!("Routing rule not found: {}", id))
                }
                nanosiem_core::source_configs::SourceConfigRepositoryError::InvalidConfig(msg) => {
                    ApiError::ValidationError(format!("Invalid configuration: {}", msg))
                }
                nanosiem_core::source_configs::SourceConfigRepositoryError::DatabaseError(e) => {
                    tracing::error!(error = %e, "Source config repository database error");
                    ApiError::DatabaseError("A database error occurred".to_string())
                }
            },
            nanosiem_core::SourceConfigServiceError::NotFound(id) => {
                ApiError::NotFound(format!("Source configuration not found: {}", id))
            }
            nanosiem_core::SourceConfigServiceError::InvalidConfig(msg) => {
                ApiError::ValidationError(format!("Invalid configuration: {}", msg))
            }
            nanosiem_core::SourceConfigServiceError::Conflict(msg) => ApiError::Conflict(msg.clone()),
            nanosiem_core::SourceConfigServiceError::DeploymentFailed(msg) => {
                ApiError::InternalError(format!("Deployment failed: {}", msg))
            }
            nanosiem_core::SourceConfigServiceError::CredentialError(msg) => {
                ApiError::ValidationError(format!("Credential error: {}", msg))
            }
            nanosiem_core::SourceConfigServiceError::CredentialUseRequired => {
                ApiError::Forbidden("Missing permission: credentials:use".to_string())
            }
            nanosiem_core::SourceConfigServiceError::IoError(e) => {
                ApiError::InternalError(format!("IO error: {}", e))
            }
            nanosiem_core::SourceConfigServiceError::CredsBackendError(e) => {
                tracing::error!(error = %e, "Source-config credentials backend error");
                ApiError::InternalError("Credential storage error".to_string())
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Lifted from nanosiem-api/src/handlers/* — these From impls reference
// nanosiem-core types so they belong with `ApiError` (orphan rule). They
// were per-handler-module before the api-error lift.
// ----------------------------------------------------------------------------

impl From<nanosiem_core::RetentionError> for ApiError {
    fn from(err: nanosiem_core::RetentionError) -> Self {
        use nanosiem_core::RetentionError;
        match &err {
            RetentionError::InvalidPeriod(msg) => ApiError::ValidationError(msg.clone()),
            RetentionError::Config(msg) => ApiError::InternalError(msg.clone()),
            RetentionError::ClickHouse(msg) => {
                tracing::error!(error = %msg, "ClickHouse retention error");
                ApiError::InternalError("A storage error occurred".to_string())
            }
            RetentionError::Database(e) => {
                tracing::error!(error = %e, "Database retention error");
                ApiError::InternalError("A database error occurred".to_string())
            }
        }
    }
}

impl From<nanosiem_core::settings::TieringError> for ApiError {
    fn from(err: nanosiem_core::settings::TieringError) -> Self {
        use nanosiem_core::settings::TieringError;
        match &err {
            TieringError::Config(msg) => ApiError::ValidationError(msg.clone()),
            TieringError::NotConfigured => {
                ApiError::BadRequest("Tiering is not configured".to_string())
            }
            TieringError::S3Connection(msg) => {
                ApiError::BadRequest(format!("S3 connection failed: {}", msg))
            }
            TieringError::ClickHouse(_) => {
                tracing::error!(error = %err, "Tiering ClickHouse error");
                ApiError::InternalError("A ClickHouse error occurred".to_string())
            }
            TieringError::Encryption(_) => {
                tracing::error!(error = %err, "Tiering encryption error");
                ApiError::InternalError("An encryption error occurred".to_string())
            }
            TieringError::Database(_) => {
                tracing::error!(error = %err, "Tiering database error");
                ApiError::InternalError("A database error occurred".to_string())
            }
            TieringError::Io(_) => {
                tracing::error!(error = %err, "Tiering IO error");
                ApiError::InternalError("A storage configuration error occurred".to_string())
            }
        }
    }
}

impl From<nanosiem_core::settings::OrganizationalContextError> for ApiError {
    fn from(err: nanosiem_core::settings::OrganizationalContextError) -> Self {
        use nanosiem_core::settings::OrganizationalContextError;
        match &err {
            OrganizationalContextError::Database(e) => {
                // NAN-2266: log the driver detail, keep it out of the body.
                tracing::error!(error = %e, "Organizational context database error");
                ApiError::DatabaseError("A database error occurred".to_string())
            }
        }
    }
}

impl From<nanosiem_core::detection::risk::RiskError> for ApiError {
    fn from(err: nanosiem_core::detection::risk::RiskError) -> Self {
        use nanosiem_core::detection::risk::RiskError;
        match &err {
            RiskError::WeightOutOfBounds(w) => ApiError::ValidationError(format!(
                "Risk weight {} is out of bounds (must be 0.0-1.0)",
                w
            )),
            RiskError::ScoreOutOfBounds(s) => ApiError::ValidationError(format!(
                "Risk score {} is out of bounds (must be 0-100)",
                s
            )),
            RiskError::InvalidCondition(msg) => {
                ApiError::ValidationError(format!("Invalid modifier condition: {}", msg))
            }
        }
    }
}

impl From<nanosiem_core::identity::IdentityServiceError> for ApiError {
    fn from(err: nanosiem_core::identity::IdentityServiceError) -> Self {
        use nanosiem_core::identity::{IdentityRepositoryError, IdentityServiceError};
        match &err {
            IdentityServiceError::ProviderNotFound(id) => {
                ApiError::NotFound(format!("Identity provider not found: {}", id))
            }
            IdentityServiceError::InvalidProviderType(t) => {
                ApiError::ValidationError(format!("Invalid provider type: {}", t))
            }
            IdentityServiceError::SyncInProgress(id) => {
                ApiError::Conflict(format!("Sync already in progress for provider: {}", id))
            }
            IdentityServiceError::Repository(IdentityRepositoryError::ProviderNotFound(id)) => {
                ApiError::NotFound(format!("Identity provider not found: {}", id))
            }
            IdentityServiceError::Repository(IdentityRepositoryError::ProviderAlreadyExists(
                id,
            )) => ApiError::Conflict(format!("Identity provider already exists: {}", id)),
            IdentityServiceError::Repository(IdentityRepositoryError::InvalidProviderType(t)) => {
                ApiError::ValidationError(format!("Invalid provider type: {}", t))
            }
            IdentityServiceError::Repository(IdentityRepositoryError::EncryptionError(e)) => {
                ApiError::InternalError(format!("Encryption error: {}", e))
            }
            IdentityServiceError::Repository(IdentityRepositoryError::DatabaseError(e)) => {
                // NAN-2266: log the driver detail, keep it out of the body.
                tracing::error!(error = %e, "Identity repository database error");
                ApiError::DatabaseError("A database error occurred".to_string())
            }
            IdentityServiceError::Repository(IdentityRepositoryError::ClickHouse(e)) => {
                ApiError::DatabaseError(format!("ClickHouse error: {}", e))
            }
            IdentityServiceError::Sync(e) => ApiError::InternalError(format!("Sync error: {}", e)),
        }
    }
}

impl From<nanosiem_core::DashboardRepositoryError> for ApiError {
    fn from(err: nanosiem_core::DashboardRepositoryError) -> Self {
        use nanosiem_core::DashboardRepositoryError;
        // DSH42: render dashboard ids as `dash_<base32>` typeids (the form the
        // API exposes everywhere else) rather than leaking a bare UUID.
        fn dash_typeid(id: &uuid::Uuid) -> String {
            nanosiem_core::typeid::encode(nanosiem_core::typeid::dashboard::PREFIX, id)
        }
        match err {
            DashboardRepositoryError::NotFound(id) => {
                ApiError::NotFound(format!("Dashboard not found: {}", dash_typeid(&id)))
            }
            DashboardRepositoryError::AccessDenied(id) => {
                ApiError::Forbidden(format!("Access denied to dashboard: {}", dash_typeid(&id)))
            }
            DashboardRepositoryError::NotOwner => {
                ApiError::Forbidden("Only the dashboard owner can perform this action".to_string())
            }
            // DSH9: optimistic-concurrency precondition failed — the dashboard
            // changed on the server since the client last read it. 409 Conflict.
            DashboardRepositoryError::Conflict(id) => ApiError::Conflict(format!(
                "Dashboard {} was modified by another update. Please reload and try again.",
                dash_typeid(&id)
            )),
            DashboardRepositoryError::DatabaseError(e) => {
                // NAN-2266: log the driver detail, keep it out of the body.
                tracing::error!(error = %error_chain(&e), "Dashboard repository database error");
                ApiError::DatabaseError("A database error occurred".to_string())
            }
        }
    }
}

impl From<nanosiem_core::MarketplaceError> for ApiError {
    fn from(err: nanosiem_core::MarketplaceError) -> Self {
        use nanosiem_core::MarketplaceError;
        match &err {
            MarketplaceError::CatalogEntryNotFound(slug) => {
                ApiError::NotFound(format!("Catalog entry not found: {}", slug))
            }
            MarketplaceError::RepositoryNotFound(id) => {
                ApiError::NotFound(format!("Repository not found: {}", id))
            }
            MarketplaceError::SlugAlreadyExists(slug) => {
                ApiError::Conflict(format!("Slug already exists: {}", slug))
            }
            MarketplaceError::RepositoryAlreadyExists(name) => {
                ApiError::Conflict(format!("Repository already exists: {}", name))
            }
            MarketplaceError::NotInstalled(slug) => {
                ApiError::ValidationError(format!("Enrichment not installed: {}", slug))
            }
            MarketplaceError::AlreadyInstalled(slug) => {
                ApiError::Conflict(format!("Enrichment already installed: {}", slug))
            }
            MarketplaceError::CredentialRequired => {
                ApiError::ValidationError("Credential required for this enrichment".to_string())
            }
            MarketplaceError::SyncInProgress(id) => {
                ApiError::Conflict(format!("Sync already in progress for repository: {}", id))
            }
            MarketplaceError::InvalidUrl(url) => {
                ApiError::ValidationError(format!("Invalid URL: {}", url))
            }
            _ => ApiError::InternalError(err.to_string()),
        }
    }
}

impl From<nanosiem_core::ParserRepositoryError> for ApiError {
    fn from(err: nanosiem_core::ParserRepositoryError) -> Self {
        use nanosiem_core::ParserRepositoryError;
        match err {
            ParserRepositoryError::RepositoryNotFound(id) => {
                ApiError::NotFound(format!("Parser repository not found: {}", id))
            }
            ParserRepositoryError::ParserNotFound { repo_id, path } => {
                ApiError::NotFound(format!("Parser not found: {}/{}", repo_id, path))
            }
            ParserRepositoryError::ImportNotFound(id) => {
                ApiError::NotFound(format!("Import not found for log source: {}", id))
            }
            ParserRepositoryError::RepositoryAlreadyExists(name) => {
                ApiError::Conflict(format!("Parser repository already exists: {}", name))
            }
            ParserRepositoryError::AlreadyImported { import_type } => {
                ApiError::Conflict(format!("Parser already imported as {}", import_type))
            }
            ParserRepositoryError::InvalidUrl(url) => {
                ApiError::BadRequest(format!("Invalid repository URL: {}", url))
            }
            ParserRepositoryError::RepositoryNotAllowed(url) => {
                ApiError::Forbidden(format!("Repository not in allowlist: {}", url))
            }
            ParserRepositoryError::RateLimited(seconds) => ApiError::TooManyRequests(format!(
                "GitHub rate limit exceeded. Retry after {} seconds",
                seconds
            )),
            ParserRepositoryError::SyncInProgress(id) => {
                ApiError::Conflict(format!("Sync already in progress for repository: {}", id))
            }
            // NAN-2117/2111/2120: target-resource capability denied inside the
            // service (the fail-closed re-check at the mutation branch). Renders
            // the same body as the canonical log-source/source-config route.
            ParserRepositoryError::Forbidden(permission) => {
                ApiError::Forbidden(format!("Missing permission: {}", permission))
            }
            ParserRepositoryError::RepositoryDisabled => {
                ApiError::Forbidden("Parser repository is disabled".to_string())
            }
            ParserRepositoryError::GitHubApi(msg) => {
                ApiError::ServiceUnavailable(format!("GitHub API error: {}", msg))
            }
            ParserRepositoryError::YamlParse(msg) => {
                ApiError::BadRequest(format!("YAML parse error: {}", msg))
            }
            _ => ApiError::InternalError(err.to_string()),
        }
    }
}

impl From<nanosiem_core::PlaybookRepositoryError> for ApiError {
    fn from(err: nanosiem_core::PlaybookRepositoryError) -> Self {
        use nanosiem_core::PlaybookRepositoryError;
        match err {
            PlaybookRepositoryError::RepositoryNotFound(id) => {
                ApiError::NotFound(format!("Playbook repository not found: {}", id))
            }
            PlaybookRepositoryError::PlaybookNotFound { repo_id, path } => ApiError::NotFound(
                format!("Repository playbook not found: {}/{}", repo_id, path),
            ),
            PlaybookRepositoryError::ImportNotFound(id) => {
                ApiError::NotFound(format!("Import not found for playbook: {}", id))
            }
            PlaybookRepositoryError::RepositoryAlreadyExists(name) => {
                ApiError::Conflict(format!("Playbook repository already exists: {}", name))
            }
            PlaybookRepositoryError::AlreadyImported { import_type } => {
                ApiError::Conflict(format!("Playbook already imported as {}", import_type))
            }
            PlaybookRepositoryError::InvalidUrl(url) => {
                ApiError::BadRequest(format!("Invalid repository URL: {}", url))
            }
            PlaybookRepositoryError::RepositoryNotAllowed(key) => {
                ApiError::Forbidden(format!("Repository not in allowlist: {}", key))
            }
            PlaybookRepositoryError::Parse(msg) => {
                ApiError::BadRequest(format!("Playbook parse error: {}", msg))
            }
            PlaybookRepositoryError::RateLimited(seconds) => ApiError::TooManyRequests(format!(
                "GitHub rate limit exceeded. Retry after {} seconds",
                seconds
            )),
            PlaybookRepositoryError::SyncInProgress(id) => {
                ApiError::Conflict(format!("Sync already in progress for repository: {}", id))
            }
            PlaybookRepositoryError::RepositoryDisabled => {
                ApiError::Forbidden("Playbook repository is disabled".to_string())
            }
            PlaybookRepositoryError::GitHubApi(msg) => {
                ApiError::ServiceUnavailable(format!("GitHub API error: {}", msg))
            }
            // NAN-2119: already the canonical `Missing permission: <capability>`
            // text, so a denied repository alias is byte-identical to a denied
            // direct call.
            PlaybookRepositoryError::Forbidden(msg) => ApiError::Forbidden(msg),
            _ => ApiError::InternalError(err.to_string()),
        }
    }
}

/// NAN-2238. `LeaseLost` maps to 409 rather than 403 on purpose: the runner WAS
/// authorized, its work simply belongs to a generation that no longer exists.
/// A 403 would read as "fix your credentials" and invite a retry loop; a 409
/// tells the runner to stop.
impl From<nanosiem_core::hunts::HuntError> for ApiError {
    fn from(err: nanosiem_core::hunts::HuntError) -> Self {
        use nanosiem_core::hunts::HuntError;
        match err {
            HuntError::NotFound(id) => ApiError::NotFound(format!("Hunt not found: {id}")),
            HuntError::SweepNotFound(id) => ApiError::NotFound(format!("Sweep not found: {id}")),
            HuntError::LeadNotFound(id) => ApiError::NotFound(format!("Lead not found: {id}")),
            HuntError::RunnerNotFound(id) => ApiError::NotFound(format!("Runner not found: {id}")),
            HuntError::RuleIdeaNotFound(id) => {
                ApiError::NotFound(format!("Rule idea not found: {id}"))
            }
            HuntError::Validation(msg) => ApiError::BadRequest(msg),
            HuntError::Forbidden(msg) => ApiError::Forbidden(msg),
            HuntError::LeaseLost(msg) | HuntError::Conflict(msg) => ApiError::Conflict(msg),
            // NAN-2266: the 5xx variants used to flow their raw detail —
            // including sqlx's rendering of the database error — straight into
            // the response body. The detail goes to the log (with the request
            // id on the span); the client gets the same generic envelope every
            // other database fault produces.
            HuntError::Database(e) => {
                tracing::error!(error = %error_chain(&e), "Hunt database error");
                ApiError::DatabaseError("A database error occurred".to_string())
            }
            HuntError::LogStore(msg) => {
                tracing::error!(error = %msg, "Hunt log-store error");
                ApiError::InternalError("A log store error occurred".to_string())
            }
            HuntError::Internal(msg) => {
                tracing::error!(error = %msg, "Hunt internal error");
                ApiError::InternalError("An internal error occurred".to_string())
            }
        }
    }
}

impl From<nanosiem_core::playbooks::PlaybookError> for ApiError {
    fn from(err: nanosiem_core::playbooks::PlaybookError) -> Self {
        use nanosiem_core::playbooks::PlaybookError;
        match err {
            PlaybookError::NotFound(id) => {
                ApiError::NotFound(format!("Playbook not found: {}", id))
            }
            PlaybookError::VersionNotFound {
                playbook_id,
                version,
            } => ApiError::NotFound(format!(
                "Version not found for playbook {}: version {}",
                playbook_id, version
            )),
            PlaybookError::InvalidCategory(s) => {
                ApiError::BadRequest(format!("Invalid category: {}", s))
            }
            PlaybookError::InvalidStatus(s) => {
                ApiError::BadRequest(format!("Invalid status: {}", s))
            }
            PlaybookError::InvalidScope(s) => ApiError::BadRequest(format!("Invalid scope: {}", s)),
            PlaybookError::Parse(msg) => ApiError::BadRequest(format!("Parse error: {}", msg)),
            PlaybookError::Frontmatter(msg) => {
                ApiError::BadRequest(format!("Frontmatter parse error: {}", msg))
            }
            PlaybookError::Forbidden(msg) => ApiError::Forbidden(msg),
            PlaybookError::Validation(msg) => ApiError::BadRequest(msg),
            _ => ApiError::InternalError(err.to_string()),
        }
    }
}

impl From<nanosiem_core::db::repository::NotebookRepositoryError> for ApiError {
    fn from(err: nanosiem_core::db::repository::NotebookRepositoryError) -> Self {
        use nanosiem_core::db::repository::NotebookRepositoryError;
        match err {
            NotebookRepositoryError::NotFound(id) => {
                ApiError::NotFound(format!("Notebook not found: {}", id))
            }
            NotebookRepositoryError::AccessDenied(id) => {
                ApiError::Forbidden(format!("Access denied to notebook: {}", id))
            }
            NotebookRepositoryError::EntryNotFound(id) => {
                ApiError::NotFound(format!("Entry not found: {}", id))
            }
            NotebookRepositoryError::ShareNotFound(id) => {
                ApiError::NotFound(format!("Share not found: {}", id))
            }
            NotebookRepositoryError::ReferenceNotFound(id) => {
                ApiError::NotFound(format!("Reference not found: {}", id))
            }
            NotebookRepositoryError::ReferenceAlreadyExists => {
                ApiError::Conflict("Reference already exists".to_string())
            }
            NotebookRepositoryError::InvalidShareTarget => {
                ApiError::ValidationError("Must specify either user or group, not both".to_string())
            }
            NotebookRepositoryError::CaseAlreadyHasNotebook(id) => {
                ApiError::Conflict(format!("Case {} already has a notebook", id))
            }
            NotebookRepositoryError::NotebookAlreadyLinked => {
                ApiError::Conflict("Notebook is already linked to a case".to_string())
            }
            NotebookRepositoryError::TabNotFound(id) => {
                ApiError::NotFound(format!("Tab not found: {}", id))
            }
            NotebookRepositoryError::DatabaseError(e) => {
                tracing::error!(error = %e, "Notebook database error");
                ApiError::DatabaseError("A database error occurred".to_string())
            }
        }
    }
}

impl From<nanosiem_core::RuleRepositoryError> for ApiError {
    fn from(err: nanosiem_core::RuleRepositoryError) -> Self {
        use nanosiem_core::RuleRepositoryError;
        match err {
            RuleRepositoryError::RepositoryNotFound(id) => {
                ApiError::NotFound(format!("Repository not found: {}", id))
            }
            RuleRepositoryError::RuleNotFound { repo_id, path } => {
                ApiError::NotFound(format!("Rule not found: {}/{}", repo_id, path))
            }
            RuleRepositoryError::ImportNotFound(id) => {
                ApiError::NotFound(format!("Import not found for detection rule: {}", id))
            }
            RuleRepositoryError::RepositoryAlreadyExists(name) => {
                ApiError::Conflict(format!("Repository already exists: {}", name))
            }
            RuleRepositoryError::AlreadyImported { import_type } => {
                ApiError::Conflict(format!("Rule already imported as {}", import_type))
            }
            RuleRepositoryError::InvalidUrl(url) => {
                ApiError::BadRequest(format!("Invalid repository URL: {}", url))
            }
            RuleRepositoryError::SigmaParse(msg) => {
                ApiError::BadRequest(format!("Failed to parse Sigma rule: {}", msg))
            }
            RuleRepositoryError::ConversionFailed(msg) => {
                ApiError::ValidationError(format!("Rule import failed: {}", msg))
            }
            RuleRepositoryError::RateLimited(seconds) => ApiError::TooManyRequests(format!(
                "GitHub rate limit exceeded. Retry after {} seconds",
                seconds
            )),
            RuleRepositoryError::SyncInProgress(id) => {
                ApiError::Conflict(format!("Sync already in progress for repository: {}", id))
            }
            // NAN-2118: target-resource capability denied inside the service
            // (the fail-closed re-check at the create/update branch). Renders the
            // same body as the canonical detection route.
            RuleRepositoryError::Forbidden(permission) => {
                ApiError::Forbidden(format!("Missing permission: {}", permission))
            }
            RuleRepositoryError::RepositoryDisabled => {
                ApiError::Forbidden("Repository is disabled".to_string())
            }
            RuleRepositoryError::GitHubApi(msg) => {
                ApiError::ServiceUnavailable(format!("GitHub API error: {}", msg))
            }
            _ => ApiError::InternalError(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn stale_log_source_version_maps_to_conflict() {
        let error: ApiError = nanosiem_core::LogSourceServiceError::RepositoryError(
            nanosiem_core::log_sources::LogSourceRepositoryError::StaleVersion(Uuid::nil()),
        )
        .into();

        assert_eq!(error.status_code(), StatusCode::CONFLICT);
        assert_eq!(error.code(), "CONFLICT");
    }

    #[test]
    fn stale_source_configuration_version_maps_to_conflict() {
        let error: ApiError = nanosiem_core::SourceConfigServiceError::RepositoryError(
            nanosiem_core::source_configs::SourceConfigRepositoryError::StaleVersion(Uuid::nil()),
        )
        .into();

        assert_eq!(error.status_code(), StatusCode::CONFLICT);
        assert_eq!(error.code(), "CONFLICT");
    }

    #[test]
    fn credential_use_denial_maps_to_non_disclosing_forbidden() {
        let error = ApiError::from(nanosiem_core::SourceConfigServiceError::CredentialUseRequired);

        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(error.code(), "FORBIDDEN");
        assert_eq!(
            error.to_string(),
            "Forbidden: Missing permission: credentials:use"
        );
    }

    // NAN-2266: the hunts 5xx variants used to flow their raw detail — sqlx's
    // rendering of the database error, the ClickHouse exception text — into the
    // response body. The detail belongs in the server log; the client gets the
    // same generic envelope every other database fault produces.

    #[test]
    fn hunt_database_errors_keep_the_driver_detail_out_of_the_body() {
        let error = ApiError::from(nanosiem_core::hunts::HuntError::Database(
            sqlx::Error::PoolTimedOut,
        ));
        assert_eq!(error.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code(), "DATABASE_ERROR");
        assert_eq!(error.to_string(), "Database error: A database error occurred");
    }

    #[test]
    fn hunt_log_store_errors_keep_the_exception_text_out_of_the_body() {
        let error = ApiError::from(nanosiem_core::hunts::HuntError::LogStore(
            "Code: 47. DB::Exception: Unknown expression or function identifier `email_sender`"
                .to_string(),
        ));
        assert_eq!(error.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code(), "INTERNAL_ERROR");
        assert!(
            !error.to_string().contains("email_sender"),
            "the log-store exception leaked into the client-facing message: {error}"
        );
    }

    #[test]
    fn hunt_lease_and_validation_outcomes_keep_their_specific_bodies() {
        // The 4xx paths carry operator-facing detail on purpose; the NAN-2266
        // genericisation must not have swallowed them.
        let lease = ApiError::from(nanosiem_core::hunts::HuntError::LeaseLost(
            "sweep x was reassigned".to_string(),
        ));
        assert_eq!(lease.status_code(), StatusCode::CONFLICT);
        assert!(lease.to_string().contains("sweep x was reassigned"));

        let validation =
            ApiError::from(nanosiem_core::hunts::HuntError::Validation("bad turns".to_string()));
        assert_eq!(validation.status_code(), StatusCode::BAD_REQUEST);
        assert!(validation.to_string().contains("bad turns"));
    }

    /// Render everything the given closure logs, so a test can assert on it.
    fn captured_log(run: impl FnOnce()) -> String {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        let bytes = buffer.0.lock().unwrap().clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn a_server_error_logs_its_cause_at_error_level() {
        // NAN-2266 (bug 2): a 500 used to leave nothing but the status line in
        // the log — the sweep-report failure had to be diagnosed from the
        // ClickHouse query log. Every 5xx now records its code and message.
        let log = captured_log(|| {
            let _ = ApiError::InternalError("the actual cause of the failure".to_string())
                .into_response();
        });
        assert!(log.contains("ERROR"), "no ERROR event was emitted: {log}");
        assert!(
            log.contains("the actual cause of the failure"),
            "the 5xx log line lost the error detail: {log}"
        );
        assert!(log.contains("INTERNAL_ERROR"), "the code is missing: {log}");
    }

    #[test]
    fn expected_client_errors_stay_out_of_the_error_log() {
        // Validation, not-found, forbidden, conflict are the caller's mistake.
        // Logging them at ERROR would bury real faults under noise.
        let log = captured_log(|| {
            let _ = ApiError::NotFound("dashboard x".to_string()).into_response();
            let _ = ApiError::ValidationError("bad cron".to_string()).into_response();
            let _ = ApiError::Forbidden("missing permission".to_string()).into_response();
            let _ = ApiError::Conflict("stale version".to_string()).into_response();
        });
        assert!(
            log.is_empty(),
            "an expected 4xx produced ERROR log noise: {log}"
        );
    }

    #[test]
    fn error_chain_walks_every_source() {
        #[derive(Debug)]
        struct Outer(std::io::Error);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "outer failed")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let err = Outer(std::io::Error::other("inner cause"));
        assert_eq!(error_chain(&err), "outer failed: inner cause");
    }
}

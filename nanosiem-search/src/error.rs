// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for the Search Service

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
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

    #[error("Search authority is temporarily unavailable; retry shortly")]
    SearchAuthorityUnavailable,

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("{0}")]
    SearchAdmissionUnavailable(String),

    #[error("{0}")]
    TenantLakePublicationDegraded(String),

    /// NAN-2361 wave 8: the tenant's lake query worker did not answer its
    /// identity probe. A typed 503 (`tenant_lake_worker_not_ready`) so a
    /// client can distinguish "worker starting / rolling a generation" from
    /// a generic dependency outage and retry with the right expectation.
    #[error("Tenant lake worker is not ready: {0}")]
    TenantLakeWorkerNotReady(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Admission denied: {0}")]
    AdmissionDenied(String),
    #[error("Enterprise-shared search admission is unavailable")]
    AdmissionBackendUnavailable,

    /// NAN-3644: the reader's cold-read ceiling (an OOM safety net). A cold
    /// read under it queues and runs; it is never refused for being cold.
    #[error("{}", nanosiem_core::search::cold_scan_too_large_message(*needed_bytes, *ceiling_bytes, *background_ceiling_bytes))]
    ColdScanTooLarge { needed_bytes: u64, ceiling_bytes: u64, background_ceiling_bytes: Option<u64> },
    /// Payload is either a bare budget kind ("scan", "memory", "time",
    /// "resource") or an already-complete sentence from a lake producer, so the
    /// Display is the payload itself and the From impl below expands bare kinds.
    /// Framing an arbitrary payload as "exhausted its {0} budget" produced
    /// sentences like "exhausted its distributed stats exceeded the per-slice
    /// group bound of 500 budget" once these stopped being masked at the handler.
    #[error("{0}")]
    ResourceExhausted(String),

    /// The query was killed mid-flight (`DELETE /api/search/{request_id}` or
    /// an admin job cancel). Distinct from `InternalError` so the original
    /// caller of a cancelled search sees a deliberate 409/QUERY_CANCELLED
    /// instead of a misleading 500 (NAN-1436, follow-up to NAN-1435).
    #[error("Query was cancelled")]
    Cancelled,

    /// NAN-3282: a product view over its per-request memory budget. 413
    /// `VIEW_TOO_LARGE`; deterministic for the window, so not retryable.
    #[error("This {view} view is too large to assemble ({needed_mib} MiB needed, budget {budget_mib} MiB); narrow the time window and try again", needed_mib = needed_bytes.div_ceil(1024 * 1024), budget_mib = budget_bytes / (1024 * 1024))]
    ViewTooLarge { view: String, needed_bytes: u64, budget_bytes: u64 },

    /// NAN-3282: the process-wide view memory budget stayed full for the wait
    /// window. Retryable 503 `VIEW_MEMORY_BUSY` with `Retry-After`.
    #[error("Search is busy assembling other views; retry shortly")]
    ViewMemoryBusy,
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
    /// `COLD_SCAN_TOO_LARGE`, the reader's cold-read ceiling.
    ColdScan {
        code: String,
        message: String,
        reason: &'static str,
        needed_bytes: u64,
        ceiling_bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        background_ceiling_bytes: Option<u64>,
        retryable: bool,
    },
    Simple {
        code: String,
        message: String,
    },
    Structured {
        code: String,
        message: String,
        details: ParseErrorDetails,
    },
    /// A retryable dependency outage with a machine-readable dependency name
    /// ( `tenant_lake_worker_not_ready`).
    Dependency {
        code: String,
        message: String,
        dependency: &'static str,
        retryable: bool,
    },
    /// a product view refused for its memory budget
    /// (`reason: "view_too_large"`).
    ViewBudget {
        code: String,
        message: String,
        reason: &'static str,
        needed_bytes: u64,
        budget_bytes: u64,
        retryable: bool,
    },
}

/// The dependency name carried by the typed 503 for a tenant lake worker
/// that has not answered its identity probe.
pub const TENANT_LAKE_WORKER_NOT_READY: &str = "tenant_lake_worker_not_ready";

/// NAN-3282: the `reason` of a 413 for a product view over its memory budget.
pub const VIEW_TOO_LARGE: &str = "view_too_large";
/// NAN-3282: the `dependency` of the retryable 503 when concurrent views hold
/// the process-wide view memory budget.
pub const VIEW_MEMORY_BUSY: &str = "view_memory_busy";

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
            SearchError::SearchAdmissionUnavailable(_) => "SEARCH_ADMISSION_UNAVAILABLE",
            SearchError::TenantLakePublicationDegraded(_) => "TENANT_LAKE_PUBLICATION_DEGRADED",
            SearchError::SearchAuthorityUnavailable => "search_authority_unavailable",
            SearchError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            SearchError::TenantLakeWorkerNotReady(_) => "TENANT_LAKE_WORKER_NOT_READY",
            SearchError::Conflict(_) => "CONFLICT",
            SearchError::AdmissionBackendUnavailable => "ADMISSION_BACKEND_UNAVAILABLE",
            SearchError::AdmissionDenied(_) => "ADMISSION_DENIED",
            SearchError::ResourceExhausted(_) => "RESOURCE_EXHAUSTED",
            SearchError::ColdScanTooLarge { .. } => "COLD_SCAN_TOO_LARGE",
            SearchError::Cancelled => "QUERY_CANCELLED",
            SearchError::ViewTooLarge { .. } => "VIEW_TOO_LARGE",
            SearchError::ViewMemoryBusy => "VIEW_MEMORY_BUSY",
        }
    }

    /// The client-facing message.
    ///
    /// `ResourceExhausted` carries a machine-readable budget kind ("memory",
    /// "scan", ...) from the ClickHouse path and an already-complete sentence
    /// from the lake producers. The payload stays verbatim so callers can still
    /// switch on the kind; only the rendered message is expanded, which keeps
    /// "memory" from reaching a user as the entire explanation.
    pub fn public_message(&self) -> String {
        match self {
            SearchError::ResourceExhausted(kind)
                if matches!(kind.as_str(), "memory" | "scan" | "time" | "resource" | "concurrency") =>
            {
                format!("Interactive query exhausted its {kind} budget")
            }
            other => other.to_string(),
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
            SearchError::SearchAdmissionUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            SearchError::TenantLakePublicationDegraded(_) => StatusCode::SERVICE_UNAVAILABLE,
            SearchError::SearchAuthorityUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            SearchError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            SearchError::TenantLakeWorkerNotReady(_) => StatusCode::SERVICE_UNAVAILABLE,
            SearchError::Conflict(_) => StatusCode::CONFLICT,
            SearchError::AdmissionBackendUnavailable | SearchError::AdmissionDenied(_) => StatusCode::TOO_MANY_REQUESTS,
            SearchError::ResourceExhausted(_) => StatusCode::UNPROCESSABLE_ENTITY,
            SearchError::ColdScanTooLarge { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            // 409: the request didn't fail — its lifecycle conflicted with a
            // deliberate cancel issued against it. Not 4xx-client-mistake, not
            // 5xx-server-fault; mirrors AdmissionDenied's "non-error outcome
            // gets a distinct, stable status" convention (429 there).
            SearchError::Cancelled => StatusCode::CONFLICT,
            SearchError::ViewTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            SearchError::ViewMemoryBusy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for SearchError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let admission_unavailable = matches!(self, Self::AdmissionBackendUnavailable);
        if admission_unavailable {
            tracing::warn!(reason = "admission_backend_unavailable", "search admission failed closed");
            metrics::counter!("nanosiem_search_jobs_rejected_total", "reason" => "admission_backend_unavailable").increment(1);
        }
        let authority_unavailable = matches!(self, Self::SearchAuthorityUnavailable);
        let view_memory_busy = matches!(self, Self::ViewMemoryBusy);
        // NAN-2361: a 503 is an operator signal, never a client mistake, so it
        // must always leave a log line naming its reason. Handlers build
        // `ServiceUnavailable` directly (tenant runtime resolution, retention
        // identity, job store wiring) and most of those sites do not log; the
        // live shared tenant answered `GET /api/search/jobs` with a bare 503
        // and nothing but tower_http's "response failed" line. The message
        // here is the internal reason (it is also what the client sees), so
        // one line at the response boundary covers every construction site.
        if let SearchError::ServiceUnavailable(reason)
        | SearchError::SearchAdmissionUnavailable(reason)
        | SearchError::TenantLakePublicationDegraded(reason)
        | SearchError::TenantLakeWorkerNotReady(reason) = &self
        {
            tracing::error!(
                code = self.code(),
                reason = %reason,
                "search request refused with 503"
            );
        }
        let body = ErrorResponse {
            error: match self {
                SearchError::ColdScanTooLarge { needed_bytes, ceiling_bytes, background_ceiling_bytes } => ErrorDetail::ColdScan {
                    code: self.code().to_string(),
                    message: self.public_message(),
                    reason: "cold_scan_too_large",
                    needed_bytes,
                    ceiling_bytes,
                    background_ceiling_bytes,
                    retryable: false,
                },
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
                SearchError::AdmissionBackendUnavailable => ErrorDetail::Dependency {
                    code: self.code().to_string(),
                    message: self.public_message(),
                    dependency: "admission_backend_unavailable",
                    retryable: true,
                },
                SearchError::TenantLakeWorkerNotReady(_) => ErrorDetail::Dependency {
                    code: self.code().to_string(),
                    message: self.public_message(),
                    dependency: TENANT_LAKE_WORKER_NOT_READY,
                    retryable: true,
                },
                SearchError::ViewTooLarge { needed_bytes, budget_bytes, .. } => ErrorDetail::ViewBudget {
                    code: self.code().to_string(),
                    message: self.public_message(),
                    reason: VIEW_TOO_LARGE,
                    needed_bytes,
                    budget_bytes,
                    retryable: false,
                },
                SearchError::ViewMemoryBusy => ErrorDetail::Dependency {
                    code: self.code().to_string(),
                    message: self.public_message(),
                    dependency: VIEW_MEMORY_BUSY,
                    retryable: true,
                },
                _ => {
                    let code = self.code().to_string();
                    let message = self.public_message();
                    ErrorDetail::Simple { code, message }
                }
            },
        };

        let mut response = (status, Json(body)).into_response();
        if authority_unavailable || admission_unavailable || view_memory_busy {
            response.headers_mut().insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from_static("2"));
        }
        response
    }
}

/// Mask an internal read failure behind a stable operator-facing message without
/// swallowing the outcomes that carry their own HTTP contract.
///
/// Handlers deliberately hide the details of a failed event read so a query
/// engine error cannot leak through the API. Flattening EVERY error into
/// `QueryError`, however, turns a transient backend outage into HTTP 400: the
/// lake worker's fail-closed event-publication gate (a frozen or backlogged
/// signed hot tail) answers 503 / `DEPENDENCY_UNAVAILABLE`, and the client-side
/// mapping turns that into `ServiceUnavailable` -- which a fixed `QueryError`
/// then discards. A 400 renders in the UI as a malformed query and is retried by
/// no client retry policy, so an outage looks like the analyst's mistake.
///
/// Pass through the four classes whose status IS the contract (retryable
/// dependency outage, resource budget, deliberate cancel, admission control) and
/// mask everything else.
pub fn mask_query_failure(error: nanosiem_core::SearchError, message: &str) -> SearchError {
    match error {
        nanosiem_core::SearchError::ServiceUnavailable(_)
        | nanosiem_core::SearchError::SearchAdmissionUnavailable(_)
        | nanosiem_core::SearchError::TenantLakePublicationDegraded(_)
        | nanosiem_core::SearchError::LakeWorkerNotReady(_)
        | nanosiem_core::SearchError::ColdScanTooLarge { .. }
        | nanosiem_core::SearchError::ResourceExhausted(_)
        | nanosiem_core::SearchError::Cancelled
        | nanosiem_core::SearchError::AdmissionBackendUnavailable
        | nanosiem_core::SearchError::AdmissionDenied(_)
        | nanosiem_core::SearchError::ViewTooLarge { .. }
        | nanosiem_core::SearchError::ViewMemoryBusy { .. } => {
            // Converting these used to happen at the call site, which logged.
            // The From impl discards the payload for ServiceUnavailable, so
            // without this a lake-worker outage would leave no trace at all --
            // exactly the signal an operator needs during a publication freeze.
            tracing::warn!(error = %error, "{message}");
            error.into()
        }
        other => {
            tracing::error!(error = %other, "{message}");
            SearchError::QueryError(message.to_string())
        }
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
                if msg.starts_with("Invalid query:") || msg.starts_with("Unsupported operation:") {
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
            nanosiem_core::SearchError::AdmissionBackendUnavailable => SearchError::AdmissionBackendUnavailable,
            nanosiem_core::SearchError::AdmissionDenied(msg) => SearchError::AdmissionDenied(msg),
            nanosiem_core::SearchError::SearchAdmissionUnavailable(detail) => SearchError::SearchAdmissionUnavailable(detail),
            nanosiem_core::SearchError::TenantLakePublicationDegraded(detail) => SearchError::TenantLakePublicationDegraded(detail),
            nanosiem_core::SearchError::ServiceUnavailable(detail) => {
                // The client body is generic; the payload names the dependency
                // (lake worker, retention identity, worker assignment) and is
                // the only place that reason survives, so log it here.
                tracing::error!(error = %detail, "search dependency unavailable (503)");
                SearchError::ServiceUnavailable(
                    "A required search service is temporarily unavailable; retry shortly"
                        .to_string(),
                )
            }
            nanosiem_core::SearchError::ColdScanTooLarge { needed_bytes, ceiling_bytes, background_ceiling_bytes } =>
                SearchError::ColdScanTooLarge { needed_bytes, ceiling_bytes, background_ceiling_bytes },
            nanosiem_core::SearchError::ResourceExhausted(kind) => {
                SearchError::ResourceExhausted(kind)
            }
            // NAN-2361 wave 8: the identity probe timed out. The worker is
            // starting (bootstrap), rolling a generation, or saturated; the
            // client gets a typed, retryable 503 and the reason is logged
            // at the boundary that would otherwise erase it.
            nanosiem_core::SearchError::LakeWorkerNotReady(detail) => {
                tracing::warn!(error = %detail, "tenant lake worker not ready (503)");
                SearchError::TenantLakeWorkerNotReady(
                    "The tenant's lake query worker is not ready yet; retry shortly".to_string(),
                )
            }
            // NAN-1436: a killed query (CH Code 394 via the cancel endpoint)
            // surfaces as a deliberate 409/QUERY_CANCELLED, not a 500.
            nanosiem_core::SearchError::Cancelled => SearchError::Cancelled,
            // NAN-3282: product-view memory budgets keep their typed contract.
            nanosiem_core::SearchError::ViewTooLarge { view, needed_bytes, budget_bytes } => {
                SearchError::ViewTooLarge { view, needed_bytes, budget_bytes }
            }
            nanosiem_core::SearchError::ViewMemoryBusy { view, waited_ms } => {
                tracing::warn!(view = %view, waited_ms, "product view refused: view memory budget busy (503)");
                SearchError::ViewMemoryBusy
            }
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

    /// NAN-2361 wave 8: a tenant lake worker that does not answer its identity
    /// probe is a retryable 503 with a typed body, never the 500 "Query
    /// timeout after 2000ms" the shared tenant answered every search with.
    #[test]
    fn lake_worker_not_ready_maps_to_a_typed_503() {
        let mapped = SearchError::from(nanosiem_core::SearchError::LakeWorkerNotReady(
            "tenant t lake query worker did not answer its identity probe within 5000 ms"
                .to_string(),
        ));
        assert!(matches!(mapped, SearchError::TenantLakeWorkerNotReady(_)));
        assert_eq!(mapped.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mapped.code(), "TENANT_LAKE_WORKER_NOT_READY");
        let response = mapped.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = futures::executor::block_on(axum::body::to_bytes(
            response.into_body(),
            usize::MAX,
        ))
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "TENANT_LAKE_WORKER_NOT_READY");
        assert_eq!(body["error"]["dependency"], TENANT_LAKE_WORKER_NOT_READY);
        assert_eq!(body["error"]["retryable"], true);
        assert!(body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("retry shortly"));
        // The generic query timeout keeps its own (non-503) contract.
        let timeout = SearchError::from(nanosiem_core::SearchError::Timeout(2_000));
        assert_ne!(timeout.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        // And the masked-read boundary passes the typed outage through.
        let masked = mask_query_failure(
            nanosiem_core::SearchError::LakeWorkerNotReady("probe".to_string()),
            "event read failed",
        );
        assert!(matches!(masked, SearchError::TenantLakeWorkerNotReady(_)));
    }

    fn response_json(error: SearchError) -> (StatusCode, Option<String>, serde_json::Value) {
        let response = error.into_response();
        let status = response.status();
        let retry_after = response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .map(|value| value.to_str().unwrap().to_string());
        let body = futures::executor::block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
            .unwrap();
        (status, retry_after, serde_json::from_slice(&body).unwrap())
    }

    /// NAN-3282: a product view over its per-request memory budget is a typed
    /// 413 telling the user to narrow the window -- never a 500 or an OOM --
    /// and it survives the masked-read boundary the view handlers use.
    #[test]
    fn view_too_large_maps_to_a_typed_413() {
        let core = nanosiem_core::SearchError::ViewTooLarge {
            view: "asset-dossier".to_string(),
            needed_bytes: 200 * 1024 * 1024,
            budget_bytes: 136 * 1024 * 1024,
        };
        let masked = mask_query_failure(core, "Failed to fetch asset dossier");
        assert!(matches!(masked, SearchError::ViewTooLarge { .. }));
        assert_eq!(masked.code(), "VIEW_TOO_LARGE");
        let (status, retry_after, body) = response_json(masked);
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(retry_after, None);
        assert_eq!(body["error"]["code"], "VIEW_TOO_LARGE");
        assert_eq!(body["error"]["reason"], VIEW_TOO_LARGE);
        assert_eq!(body["error"]["retryable"], false);
        assert_eq!(body["error"]["budget_bytes"], 136 * 1024 * 1024);
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains("narrow the time window"), "{message}");
        assert!(message.contains("asset-dossier"), "{message}");
    }

    /// NAN-3282: concurrent views holding the process budget answer a
    /// retryable 503 with Retry-After, not a hang or an OOM.
    #[test]
    fn view_memory_busy_maps_to_a_retryable_503() {
        let masked = mask_query_failure(
            nanosiem_core::SearchError::ViewMemoryBusy { view: "asset-events".to_string(), waited_ms: 5_000 },
            "Failed to fetch asset events",
        );
        assert!(matches!(masked, SearchError::ViewMemoryBusy));
        let (status, retry_after, body) = response_json(masked);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after.as_deref(), Some("2"));
        assert_eq!(body["error"]["code"], "VIEW_MEMORY_BUSY");
        assert_eq!(body["error"]["dependency"], VIEW_MEMORY_BUSY);
        assert_eq!(body["error"]["retryable"], true);
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

    /// Both payload shapes must render as a sentence. Before this, the variant
    /// framed an arbitrary payload as "exhausted its {0} budget", which produced
    /// "exhausted its distributed stats exceeded the per-slice group bound of 500
    /// budget" once these errors stopped being masked at the handler.
    #[test]
    fn resource_exhaustion_renders_a_sentence_for_both_payload_shapes() {
        assert_eq!(
            SearchError::ResourceExhausted("concurrency".to_string()).public_message(),
            "Interactive query exhausted its concurrency budget"
        );
        let bare = SearchError::ResourceExhausted("memory".to_string());
        assert_eq!(
            bare.public_message(),
            "Interactive query exhausted its memory budget"
        );
        let sentence = SearchError::ResourceExhausted(
            "distributed stats exceeded the per-slice group bound of 500".to_string(),
        );
        assert_eq!(
            sentence.public_message(),
            "distributed stats exceeded the per-slice group bound of 500"
        );
    }

    #[test]
    fn resource_exhaustion_remains_machine_readable_for_escalation() {
        let mapped = SearchError::from(nanosiem_core::SearchError::ResourceExhausted(
            "memory".to_string(),
        ));
        assert!(matches!(mapped, SearchError::ResourceExhausted(ref kind) if kind == "memory"));
        assert_eq!(mapped.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(mapped.code(), "RESOURCE_EXHAUSTED");
    }

    /// NAN-2361: the `From` impl masks the core payload behind a generic
    /// client message. The payload is the only thing that names the failing
    /// dependency, so it must survive in the log, and the response boundary
    /// must log every 503 regardless of where it was constructed.
    #[test]
    fn every_503_leaves_an_error_log_line_naming_its_reason() {
        let (events, _guard) = crate::test_support::capture_logs();
        let mapped = SearchError::from(nanosiem_core::SearchError::ServiceUnavailable(
            "no exact tenant-pinned lake query worker is registered".to_string(),
        ));
        assert!(crate::test_support::logged_at_least(
            &events,
            tracing::Level::ERROR,
            "no exact tenant-pinned lake query worker is registered"
        ));
        let response = mapped.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(crate::test_support::logged_at_least(
            &events,
            tracing::Level::ERROR,
            "search request refused with 503"
        ));

        // A handler-built 503 (tenant runtime resolution, retention identity)
        // logs its own reason at the boundary even though no site logged it.
        let direct = SearchError::ServiceUnavailable(
            "Enterprise-shared search retention identity is unavailable".to_string(),
        );
        assert_eq!(direct.into_response().status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(crate::test_support::logged_at_least(
            &events,
            tracing::Level::ERROR,
            "reason=Enterprise-shared search retention identity is unavailable"
        ));

        // 4xx outcomes stay quiet at the boundary: they are the client's
        // signal, not the operator's.
        let before = events.lock().unwrap().len();
        let _ = SearchError::Forbidden("nope".to_string()).into_response();
        assert_eq!(events.lock().unwrap().len(), before);
    }

    #[test]
    fn durable_state_outage_is_retryable_and_machine_readable() {
        let mapped = SearchError::ServiceUnavailable(
            "Search job state is temporarily unavailable; retry shortly".to_string(),
        );
        assert_eq!(mapped.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mapped.code(), "SERVICE_UNAVAILABLE");
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

    /// The read handlers mask their failures behind a fixed operator-facing
    /// message. `mask_query_failure` must keep doing that for the failures a
    /// client cannot act on, while letting the four outcomes whose HTTP status
    /// IS their contract keep it — a lake-worker outage (503) that arrives as a
    /// 400 reads as "your query is malformed" and no retry policy retries it.
    #[test]
    fn mask_query_failure_passes_through_status_carrying_outcomes() {
        let outage = mask_query_failure(
            nanosiem_core::SearchError::ServiceUnavailable(
                "lake query worker is temporarily unavailable".to_string(),
            ),
            "Failed to fetch asset dossier",
        );
        assert_eq!(outage.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(outage.code(), "SERVICE_UNAVAILABLE");

        let exhausted = mask_query_failure(
            nanosiem_core::SearchError::ResourceExhausted("memory".to_string()),
            "Failed to fetch asset dossier",
        );
        assert_eq!(exhausted.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(exhausted.code(), "RESOURCE_EXHAUSTED");

        let cancelled = mask_query_failure(
            nanosiem_core::SearchError::Cancelled,
            "Failed to fetch asset dossier",
        );
        assert_eq!(cancelled.status_code(), StatusCode::CONFLICT);
        assert_eq!(cancelled.code(), "QUERY_CANCELLED");

        let denied = mask_query_failure(
            nanosiem_core::SearchError::AdmissionDenied("queue full".to_string()),
            "Failed to fetch asset dossier",
        );
        assert_eq!(denied.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(denied.code(), "ADMISSION_DENIED");

        // Everything else stays masked: the internal detail never reaches the
        // client, and the response carries the site's own message verbatim.
        let internal = mask_query_failure(
            nanosiem_core::SearchError::PrevalenceError(
                "ClickHouse error: connection refused".to_string(),
            ),
            "Failed to fetch asset dossier",
        );
        match internal {
            SearchError::QueryError(ref msg) => {
                assert_eq!(msg, "Failed to fetch asset dossier");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod dependency_contract_tests {
    use super::*;

    #[tokio::test]
    async fn actionable_search_dependencies_keep_their_codes_and_reasons() {
        let cases = [
            (
                nanosiem_core::SearchError::SearchAdmissionUnavailable(
                    "distributed search admission (Redis) is not configured for this deployment".into(),
                ),
                "SEARCH_ADMISSION_UNAVAILABLE",
                "distributed search admission (Redis) is not configured for this deployment",
            ),
            (
                nanosiem_core::SearchError::TenantLakePublicationDegraded(
                    "lake event publication is temporarily unavailable (bootstrap); retry the request".into(),
                ),
                "TENANT_LAKE_PUBLICATION_DEGRADED",
                "lake event publication is temporarily unavailable (bootstrap); retry the request",
            ),
        ];
        for (error, code, message) in cases {
            let mapped = mask_query_failure(error, "event read failed");
            assert_eq!(mapped.code(), code);
            assert_eq!(mapped.status_code(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(mapped.to_string(), message);
            let response = mapped.into_response();
            let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["error"]["code"], code);
            assert_eq!(body["error"]["message"], message);
        }
    }
}

#[cfg(test)]
mod cold_budget_tests {
    use super::*;

    /// NAN-3644: only the reader's ceiling is a 422 now (never a cold read
    /// under it); it keeps its bytes and is not retryable.
    #[tokio::test]
    async fn cold_ceiling_public_contract_is_actionable_non_retryable_422() {
        let mapped = mask_query_failure(nanosiem_core::SearchError::ColdScanTooLarge {
            needed_bytes: 14_800_000_000, ceiling_bytes: 9_600_000_000, background_ceiling_bytes: Some(9_600_000_000),
        }, "masked read failure");
        assert_eq!(mapped.code(), "COLD_SCAN_TOO_LARGE");
        let response = mapped.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!response.headers().contains_key(axum::http::header::RETRY_AFTER));
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["needed_bytes"], 14_800_000_000_u64);
        assert_eq!(body["error"]["ceiling_bytes"], 9_600_000_000_u64);
        assert_eq!(body["error"]["background_ceiling_bytes"], 9_600_000_000_u64);
        assert_eq!(body["error"]["reason"], "cold_scan_too_large");
        assert_eq!(body["error"]["retryable"], false);
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.starts_with("This search would read ~14.8 GB of uncached data in one pass"), "{message}");
        assert!(message.contains("Narrow the time range"), "{message}");
    }
}

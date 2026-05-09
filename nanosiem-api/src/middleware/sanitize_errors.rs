// SPDX-License-Identifier: AGPL-3.0-or-later

//! Middleware to sanitize framework-generated error responses.
//!
//! Axum's extractors (Json, Path, Query) return plain-text error responses that
//! leak internal details (serde errors, UUID parser messages, type expectations).
//! This middleware intercepts those responses and replaces them with our
//! standard JSON error format without internal details.

use axum::{
    body::{Body, Bytes},
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::error::{ErrorDetail, ErrorResponse};

/// Middleware that intercepts plain-text error responses from axum extractor
/// rejections and replaces them with sanitized JSON error responses.
///
/// Covers:
/// - 422 text/plain: Json<T> deserialization failures
/// - 400 text/plain: Path<T> / Query<T> parse failures
pub async fn sanitize_error_responses(req: Request<Body>, next: Next) -> Response {
    let response = next.run(req).await;

    let status = response.status();

    // Only intercept 400 and 422 responses with text/plain content type
    // (axum's default format for extractor rejections)
    if status != StatusCode::BAD_REQUEST && status != StatusCode::UNPROCESSABLE_ENTITY {
        return response;
    }

    let is_plain_text = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("text/plain"))
        .unwrap_or(false);

    if !is_plain_text {
        return response;
    }

    // Extract the original error message for diagnostics
    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 4096).await {
        Ok(b) => b,
        Err(_) => Bytes::new(),
    };
    let original_message = String::from_utf8_lossy(&body_bytes);

    // Log at warn level so validation errors are visible in server logs
    tracing::warn!(
        status = %status,
        error = %original_message,
        "Request validation failed"
    );

    // Sanitize for the client: strip internal type details but keep the field-level hint
    let sanitized_detail = sanitize_serde_error(&original_message);

    let message = if status == StatusCode::UNPROCESSABLE_ENTITY {
        "Invalid request body"
    } else {
        "Invalid request"
    };

    let error_body = ErrorResponse {
        error: ErrorDetail {
            code: "VALIDATION_ERROR".to_string(),
            message: message.to_string(),
            details: Some(serde_json::json!({ "validation": sanitized_detail })),
        },
    };

    // Build the sanitized response
    let mut sanitized = axum::Json(error_body).into_response();
    *sanitized.status_mut() = parts.status;
    // Preserve request-id header if present
    if let Some(req_id) = parts.headers.get("x-request-id") {
        sanitized
            .headers_mut()
            .insert("x-request-id", req_id.clone());
    }

    sanitized
}

/// Strip Rust-internal type names from serde error messages while keeping
/// the field name and the human-readable cause (e.g. "missing field `name`").
fn sanitize_serde_error(raw: &str) -> String {
    // Axum's Json rejection looks like:
    //   "Failed to deserialize the JSON body into the target type: <detail>"
    // Keep just the <detail> part, which is the serde_json error.
    if let Some(idx) = raw.find(": ") {
        let detail = &raw[idx + 2..];
        // Remove " at line N column N" suffix
        if let Some(pos) = detail.rfind(" at line ") {
            return detail[..pos].to_string();
        }
        return detail.to_string();
    }
    // Fallback: return as-is but truncated
    raw.chars().take(200).collect()
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity resolution endpoint: resolve IP → hostname/user/context
//!
//! Lightweight GET endpoint that resolves an IP address to its most recent
//! identity observation from the `identity_observations` ClickHouse table,
//! enriched with user registry data via `dictGetOrDefault`.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError};

/// Query parameters for identity resolution
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct IdentityResolveParams {
    /// IP address to resolve
    pub ip: String,
    /// Optional timestamp (ISO8601) for temporal context. Defaults to now.
    pub timestamp: Option<String>,
}

/// Response from identity resolution
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IdentityResolveResponse {
    /// The queried IP address
    pub ip: String,
    /// Resolved hostname
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Resolved user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Confidence level: high (<1hr), medium (<4hr), low (<24hr), stale (>24hr), none (not found)
    pub confidence: String,
    /// When the identity observation was recorded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    /// Source of the identity observation (e.g., DHCP, EDR, static)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Fully qualified domain name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    /// Display name from user registry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Department from user registry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// Email from user registry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Job title from user registry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Resolve an IP address to identity context
///
/// GET /api/identity/resolve?ip=10.0.1.42&timestamp=2024-01-15T12:00:00Z
///
/// Returns the most recent, highest-priority identity observation for the given IP,
/// enriched with user registry metadata (display name, department, email, title).
#[utoipa::path(
    get,
    path = "/api/identity/resolve",
    tag = "identity",
    params(IdentityResolveParams),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Identity resolution result", body = IdentityResolveResponse),
        (status = 400, description = "Invalid IP address", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn resolve_identity(
    State(state): State<SearchState>,
    axum::extract::Query(params): axum::extract::Query<IdentityResolveParams>,
) -> Result<Json<IdentityResolveResponse>, SearchError> {
    // Validate IP address (prevent injection — only valid IPs pass through)
    let ip = params.ip.trim().to_string();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(SearchError::BadRequest(format!(
            "Invalid IP address: {}",
            ip
        )));
    }

    // Parse timestamp or default to now
    let reference_time = if let Some(ref ts) = params.timestamp {
        // Validate ISO8601 timestamp
        if chrono::DateTime::parse_from_rfc3339(ts).is_err() {
            return Err(SearchError::BadRequest(format!(
                "Invalid timestamp: {}",
                ts
            )));
        }
        format!("toDateTime64('{}', 3, 'UTC')", ts)
    } else {
        "now64(3)".to_string()
    };

    // Query identity_observations for the most recent highest-priority observation.
    // IP is validated above as a valid IP address so it is safe to interpolate.
    let identity_table = state.dual_pool.table_names().read("identity_observations");
    let sql = format!(
        r#"SELECT
    ip,
    hostname,
    fqdn,
    user,
    source,
    source_priority,
    observed_at,
    dateDiff('second', observed_at, {reference_time}) AS age_seconds,
    dictGetOrDefault('nanosiem.user_registry_dict', 'display_name', lower(user), '') AS display_name,
    dictGetOrDefault('nanosiem.user_registry_dict', 'department', lower(user), '') AS department,
    dictGetOrDefault('nanosiem.user_registry_dict', 'email', lower(user), '') AS email,
    dictGetOrDefault('nanosiem.user_registry_dict', 'title', lower(user), '') AS title
FROM {identity_table}
PREWHERE ip = '{ip}'
    AND observed_at <= {reference_time}
ORDER BY source_priority DESC, observed_at DESC
LIMIT 1"#,
        identity_table = identity_table,
        ip = ip,
        reference_time = reference_time,
    );

    let ch_client = state.dual_pool.clickhouse();
    let mut cursor = ch_client
        .query(&sql)
        .fetch_bytes("JSONEachRow")
        .map_err(|e| {
            tracing::error!(error = %e, ip = %ip, "Identity resolution ClickHouse query error");
            SearchError::InternalError("Failed to query identity data".to_string())
        })?;

    let mut response_bytes = Vec::new();
    while let Ok(Some(chunk)) = cursor.next().await {
        response_bytes.extend_from_slice(&chunk);
    }

    let response_str = String::from_utf8(response_bytes).map_err(|e| {
        SearchError::InternalError(format!("Invalid UTF-8 in identity response: {}", e))
    })?;

    // Parse the first (and only) JSON line
    if let Some(line) = response_str.lines().next() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let age_seconds = json
                .get("age_seconds")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok())
                .or_else(|| json.get("age_seconds").and_then(|v| v.as_i64()))
                .unwrap_or(i64::MAX);

            let confidence = match age_seconds {
                s if s < 3600 => "high",
                s if s < 14400 => "medium",
                s if s < 86400 => "low",
                _ => "stale",
            };

            let opt_str = |key: &str| -> Option<String> {
                json.get(key)
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            };

            return Ok(Json(IdentityResolveResponse {
                ip: ip.clone(),
                hostname: opt_str("hostname"),
                user: opt_str("user"),
                confidence: confidence.to_string(),
                observed_at: opt_str("observed_at"),
                source: opt_str("source"),
                fqdn: opt_str("fqdn"),
                display_name: opt_str("display_name"),
                department: opt_str("department"),
                email: opt_str("email"),
                title: opt_str("title"),
            }));
        }
    }

    // No observation found
    Ok(Json(IdentityResolveResponse {
        ip,
        hostname: None,
        user: None,
        confidence: "none".to_string(),
        observed_at: None,
        source: None,
        fqdn: None,
        display_name: None,
        department: None,
        email: None,
        title: None,
    }))
}

// ============================================================================
// OpenAPI Sub-Doc
// ============================================================================

use utoipa::OpenApi;

/// OpenAPI sub-document for identity resolution endpoints
#[derive(OpenApi)]
#[openapi(paths(resolve_identity), components(schemas(IdentityResolveResponse)))]
pub struct IdentityApiDoc;

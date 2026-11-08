// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP enrichment lookup against the ingest-time IP dictionary.
//!
//! NAN-4959: IPinfo Lite geo/ASN comes only from nano's signed platform feed
//! bundle (`platform_feeds`); the native bring-your-own IPinfo configure and
//! sync endpoints that lived here are removed.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;

use super::types::*;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Lookup enrichment for a specific IP
#[utoipa::path(
    get,
    path = "/api/enrichment/lookup/{ip}",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    params(
        ("ip" = String, Path, description = "IP address to lookup")
    ),
    responses(
        (status = 200, description = "IP enrichment data", body = IpLookupResponse),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn lookup_ip(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(ip): Path<String>,
) -> Result<Json<IpLookupResponse>, ApiError> {
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;

    // Validate IP format before hitting the database
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::ValidationError(format!(
            "Invalid IP address: {}",
            ip
        )));
    }

    let enrichment = state.enrichment.read().await;
    let result = enrichment.lookup_ip(&ip).await.map_err(|e| {
        tracing::error!(error = %e, ip = %ip, "Enrichment lookup failed");
        ApiError::InternalError("Enrichment lookup failed".to_string())
    })?;

    match result {
        Some(r) => Ok(Json(IpLookupResponse {
            ip,
            found: true,
            country: r.country,
            country_code: r.country_code,
            continent: r.continent,
            continent_code: r.continent_code,
            asn: r.asn,
            as_name: r.as_name,
            as_domain: r.as_domain,
        })),
        None => Ok(Json(IpLookupResponse {
            ip,
            found: false,
            country: None,
            country_code: None,
            continent: None,
            continent_code: None,
            asn: None,
            as_name: None,
            as_domain: None,
        })),
    }
}

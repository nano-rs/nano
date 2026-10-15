// SPDX-License-Identifier: AGPL-3.0-or-later

//! Asset dossier endpoint — single aggregate for the redesigned Asset view.
//!
//! Returns identity + timeline + processes + network + auth + files + dns in
//! one round-trip. Alerts come from `entity_context` (nanosiem-api) and
//! prevalence dots from `asset-artifacts` — both are fetched lazily alongside
//! this endpoint by the frontend.

use axum::{extract::State, Json};
use nanosiem_core::search::AssetDossier;
use nanosiem_core::TimeRangeInput;
use serde::Deserialize;
use std::time::Instant;

use crate::error::ErrorResponse;
use crate::{error::SearchError, metrics::record_search_query, SearchState};

/// Request for the asset dossier aggregate
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssetDossierRequest {
    /// Identifier field (e.g., "src_host", "src_ip", "user")
    pub identifier_field: String,
    /// Identifier value (e.g., "WIN-HR11")
    pub identifier_value: String,
    /// Resolved identities from the initial asset query (may be empty)
    #[serde(default)]
    pub identities: Vec<serde_json::Value>,
    /// Time range for the aggregates
    pub time_range: TimeRangeInput,
}

/// Build the entity dossier for the redesigned Asset view.
///
/// Runs identity, timeline, and section-card aggregates (processes, network,
/// auth, files, dns) in parallel against ClickHouse.
#[utoipa::path(
    post,
    path = "/api/search/asset-dossier",
    tag = "search",
    request_body = AssetDossierRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Asset dossier aggregates", body = AssetDossier),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
    )
)]
pub async fn get_asset_dossier(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<AssetDossierRequest>,
) -> Result<(axum::http::HeaderMap, Json<AssetDossier>), SearchError> {
    // NAN-1801: this endpoint was bearer-only — it runs hand-built aggregates
    // over the logs table, so it needs the same execute gate as /api/search.
    if !auth
        .claims
        .has_permission(nanosiem_core::auth::permissions::SEARCH_EXECUTE)
    {
        return Err(SearchError::Forbidden(
            "Asset dossier queries require the search:execute permission".to_string(),
        ));
    }

    // NAN-1801: compose the caller's effective source-scope deny-set once —
    // it is ANDed into every dossier aggregate by the service AND folded into
    // the cache key below (the scope changes the executed SQL, so it is part
    // of result identity; two users with different scopes must not share a
    // cached dossier).
    let scope = super::search::effective_scope(&auth);
    let search = super::product_view_search(&state, &auth)?;

    // NAN-1593: the asset dossier fires on every Asset-view load / shared-link
    // follow and runs 8 parallel ClickHouse aggregates — cache it through the
    // same Dragonfly layer so reloads return instantly. Keyed on the
    // identifier, the resolved identities (they widen the match set), the
    // time range, and the caller's effective scope.
    let cache_key = crate::cache::SearchResultCache::companion_key_for(
        auth.tenant_scope,
        "adossier-v3",
        &[
            request.identifier_field.as_bytes(),
            request.identifier_value.as_bytes(),
            serde_json::to_string(&request.identities)
                .unwrap_or_default()
                .as_bytes(),
            request
                .time_range
                .start
                .timestamp_micros()
                .to_string()
                .as_bytes(),
            request
                .time_range
                .end
                .timestamp_micros()
                .to_string()
                .as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(mut cached) = cache.get_cached::<AssetDossier>(&cache_key).await {
                strip_unentitled_prevalence(&auth, &mut cached);
                record_search_query("asset_dossier_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                super::require_current_shared_authority(&state, &auth).await?;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let start = Instant::now();

    let time_range =
        nanosiem_core::query::TimeRange::new(request.time_range.start, request.time_range.end);

    let result = search
        .query_asset_dossier(
            &request.identifier_field,
            &request.identifier_value,
            &request.identities,
            &time_range,
            &scope,
            // NAN-3094: an explicit refresh rebuilds a finished lean snapshot;
            // polls of an incomplete one never send the bypass.
            bypass,
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    if matches!(
        &result,
        Err(nanosiem_core::SearchError::ResourceExhausted(_))
    ) {
        let job_id = search
            .enqueue_durable_asset_dossier(
                &request.identifier_field,
                &request.identifier_value,
                &request.identities,
                &time_range,
                &scope,
                auth.claims.sub,
                auth.durable_search_authority().as_ref(),
            )
            .await?;
        record_search_query("asset_dossier_queued", duration_ms, true);
        super::require_current_shared_authority(&state, &auth).await?;
        return Ok((
            crate::cache::cache_status_headers(false, None),
            Json(AssetDossier {
                durable_job: Some(nanosiem_core::search::AsyncSearchResponse {
                    job_id,
                    status: "queued".to_string(),
                }),
                ..Default::default()
            }),
        ));
    }
    record_search_query("asset_dossier", duration_ms, result.is_ok());

    let mut response =
        result.map_err(|e| crate::error::mask_query_failure(e, "Failed to fetch asset dossier"))?;

    if let Some(cache) = state.result_cache.as_ref().filter(|_| {
        response
            .progress
            .as_ref()
            // NAN-3271: a dossier finished without rarity is not cached.
            .is_none_or(|progress| progress.cacheable())
    }) {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    super::require_current_shared_authority(&state, &auth).await?;
    strip_unentitled_prevalence(&auth, &mut response);
    Ok((
        crate::cache::cache_status_headers(false, None),
        Json(response),
    ))
}

/// NAN-3286: the dossier itself needs only search:execute, but its process
/// card carries fleet prevalence (`top[].prev`, `rare`, `rare_list`) and the
/// network card's `new_domains` is a prevalence-derived rarity count. A shared
/// tenant without the prevalence plan component gets the dossier with those
/// fields cleared, the same answer `asset-artifacts` / `prevalence-artifacts`
/// gate behind `require_shared_prevalence_component`. Applied on release (not
/// before caching) so a cached entitled dossier is stripped too.
fn strip_unentitled_prevalence(auth: &crate::AuthContext, dossier: &mut AssetDossier) {
    if super::require_shared_prevalence_component(auth).is_ok() {
        return;
    }
    dossier.processes.rare = 0;
    dossier.processes.rare_list.clear();
    for process in &mut dossier.processes.top {
        process.prev = 0.0;
    }
    dossier.network.new_domains = 0;
}

#[cfg(all(test, feature = "enterprise"))]
mod prevalence_entitlement_tests {
    use super::*;
    use nanosiem_core::auth::TokenClaims;
    use nanosiem_core::search::{ProcessRare, ProcessTop, SearchTenantScope};

    fn auth(shared: bool, entitled: bool) -> crate::AuthContext {
        let mut auth = crate::AuthContext::from_jwt(TokenClaims {
            iss: "fixture".into(),
            aud: "nano-api".into(),
            sub: uuid::Uuid::from_u128(1),
            roles: vec![],
            permissions: vec!["search:execute".into()],
            iat: 0,
            exp: i64::MAX,
            jti: uuid::Uuid::new_v4(),
            purpose: "access".into(),
        });
        if shared {
            auth.tenant_scope =
                SearchTenantScope::enterprise_shared_retained(uuid::Uuid::from_u128(0xa), 1, 90, 0)
                    .unwrap();
        }
        auth.shared_prevalence_entitled = entitled;
        auth
    }

    fn dossier() -> AssetDossier {
        let mut dossier = AssetDossier::default();
        dossier.processes.unique = 3;
        dossier.processes.rare = 1;
        dossier.processes.top = vec![ProcessTop { name: "cmd.exe".into(), count: 4, prev: 87.5 }];
        dossier.processes.rare_list = vec![ProcessRare {
            name: "evil.exe".into(),
            hash: Some("abc".into()),
            prev: 0.1,
            cmd: None,
            flags: vec![],
        }];
        dossier.network.total_conns = 9;
        dossier.network.new_domains = 2;
        dossier
    }

    #[test]
    fn unentitled_shared_tenant_gets_the_dossier_without_prevalence() {
        let mut stripped = dossier();
        strip_unentitled_prevalence(&auth(true, false), &mut stripped);
        assert_eq!(stripped.processes.rare, 0);
        assert!(stripped.processes.rare_list.is_empty());
        assert_eq!(stripped.processes.top[0].prev, 0.0);
        assert_eq!(stripped.network.new_domains, 0);
        // The rest of the dossier still works.
        assert_eq!(stripped.processes.unique, 3);
        assert_eq!(stripped.processes.top[0].count, 4);
        assert_eq!(stripped.network.total_conns, 9);
    }

    #[test]
    fn entitled_shared_and_dedicated_callers_keep_prevalence() {
        for auth in [auth(true, true), auth(false, false)] {
            let mut kept = dossier();
            strip_unentitled_prevalence(&auth, &mut kept);
            assert_eq!(kept.processes.rare_list.len(), 1);
            assert_eq!(kept.processes.top[0].prev, 87.5);
            assert_eq!(kept.network.new_domains, 2);
        }
    }
}

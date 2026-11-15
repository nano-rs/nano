// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup URL allowlist settings (NAN-5443).
//!
//! `GET/PUT /api/settings/inputlookup-allowed-domains`: the hosts
//! `inputlookup url=...` may fetch from. The admin list is stored on
//! `system_settings.inputlookup_allowed_domains` (migration 387) and merged
//! with the deployment list `INPUTLOOKUP_ALLOWED_DOMAINS`, unless
//! `INPUTLOOKUP_ALLOWED_DOMAINS_LOCKED=true` makes the deployment list an
//! override (see [`nanosiem_core::inputlookup::allowlist`]). The api, jobs and
//! search processes re-read the list every 30 s; this process applies a save
//! at once.

use axum::{extract::State, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nanosiem_core::audit::{actions, AuditEvent, AuditSource, ClientContext};
use nanosiem_core::auth::permissions;
use nanosiem_core::inputlookup::allowlist::{
    self, DeploymentAllowlist, MAX_ADMIN_DOMAINS,
};

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// How the effective list restricts lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LookupAllowlistMode {
    /// The effective list is empty: any public host may be fetched (the SSRF
    /// guard still refuses private and internal addresses).
    AnyPublicHost,
    /// Only hosts on the effective list (and their subdomains) may be fetched.
    Allowlist,
}

/// `GET/PUT /api/settings/inputlookup-allowed-domains` response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupAllowlistSettings {
    /// Hosts added in Settings (normalized, sorted). Ignored while `locked`.
    pub domains: Vec<String>,
    /// Hosts from `INPUTLOOKUP_ALLOWED_DOMAINS` (cannot be removed here).
    pub deployment_domains: Vec<String>,
    /// `INPUTLOOKUP_ALLOWED_DOMAINS_LOCKED`: the deployment list overrides
    /// the admin list and this list is read-only.
    pub locked: bool,
    /// What applies now: the union of both lists, or the deployment list
    /// alone when `locked`.
    pub effective: Vec<String>,
    pub mode: LookupAllowlistMode,
    /// Most entries the admin list may hold.
    pub max_domains: usize,
    /// Seconds within which other processes pick up a change.
    pub refresh_interval_secs: u64,
}

impl LookupAllowlistSettings {
    fn new(domains: Vec<String>, deployment: &DeploymentAllowlist) -> Self {
        let effective = deployment.effective(&domains);
        let mode = if effective.is_empty() {
            LookupAllowlistMode::AnyPublicHost
        } else {
            LookupAllowlistMode::Allowlist
        };
        Self {
            domains,
            deployment_domains: deployment.domains.clone(),
            locked: deployment.locked,
            effective,
            mode,
            max_domains: MAX_ADMIN_DOMAINS,
            refresh_interval_secs: allowlist::REFRESH_INTERVAL.as_secs(),
        }
    }
}

/// `PUT /api/settings/inputlookup-allowed-domains` body.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateLookupAllowlistRequest {
    /// The full admin list. Entries are hosts or domains (`feeds.example.com`;
    /// a leading `*.` is accepted and dropped); each also allows its
    /// subdomains.
    pub domains: Vec<String>,
}

/// Get the lookup URL allowlist
///
/// The hosts `inputlookup url=...` may fetch from: the admin list, the
/// deployment list and the effective result. Requires `settings:view`.
#[utoipa::path(
    get,
    path = "/api/settings/inputlookup-allowed-domains",
    tag = "settings",
    responses(
        (status = 200, description = "Lookup URL allowlist", body = LookupAllowlistSettings),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_inputlookup_allowed_domains(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<LookupAllowlistSettings>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;
    let domains = allowlist::load_admin_domains(&state.pool)
        .await
        .map_err(|error| ApiError::DatabaseError(format!("read lookup URL allowlist: {error}")))?;
    Ok(Json(LookupAllowlistSettings::new(domains, &DeploymentAllowlist::from_env())))
}

/// Replace the lookup URL allowlist
///
/// Replaces the admin list. Entries are normalized (lowercase IDNA, leading
/// `*.` and trailing dot dropped); a bare top-level domain, a URL, a port or a
/// path is refused with `422`. Applies in this process at once and in every
/// other process within `refresh_interval_secs`. Refused with `409` while
/// `INPUTLOOKUP_ALLOWED_DOMAINS_LOCKED` is set. Audited as
/// `inputlookup_allowed_domains_updated`. Requires `settings:system`.
#[utoipa::path(
    put,
    path = "/api/settings/inputlookup-allowed-domains",
    tag = "settings",
    request_body = UpdateLookupAllowlistRequest,
    responses(
        (status = 200, description = "Lookup URL allowlist updated", body = LookupAllowlistSettings),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 409, description = "The deployment locks the list", body = ErrorResponse),
        (status = 422, description = "Invalid entry", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_inputlookup_allowed_domains(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateLookupAllowlistRequest>,
) -> Result<Json<LookupAllowlistSettings>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    let deployment = DeploymentAllowlist::from_env();
    if deployment.locked {
        return Err(ApiError::Conflict(format!(
            "the lookup URL allowlist is set by the deployment ({}) and cannot be changed here",
            allowlist::ENV_ALLOWED_DOMAINS_LOCKED
        )));
    }
    let domains = allowlist::normalize_domains(&request.domains)
        .map_err(|error| ApiError::ValidationError(error.to_string()))?;
    let previous = allowlist::store_admin_domains(&state.pool, &domains)
        .await
        .map_err(|error| ApiError::DatabaseError(format!("store lookup URL allowlist: {error}")))?;
    allowlist::set_admin_domains(domains.clone());

    let added: Vec<&String> = domains.iter().filter(|d| !previous.contains(d)).collect();
    let removed: Vec<&String> = previous.iter().filter(|d| !domains.contains(d)).collect();
    tracing::info!(
        count = domains.len(),
        added = added.len(),
        removed = removed.len(),
        "lookup URL allowlist updated"
    );
    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, actions::INPUTLOOKUP_ALLOWED_DOMAINS_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("inputlookup_allowed_domains".to_string()))
            .details(json!({
                "added": added,
                "removed": removed,
                "previous": previous,
                "domains": domains,
            }))
            .client_context(&client)
            .build(),
    );
    Ok(Json(LookupAllowlistSettings::new(domains, &deployment)))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_inputlookup_allowed_domains, update_inputlookup_allowed_domains),
    components(schemas(
        LookupAllowlistSettings,
        LookupAllowlistMode,
        UpdateLookupAllowlistRequest
    ))
)]
pub struct InputLookupAllowlistApiDoc;

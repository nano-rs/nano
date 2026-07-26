// SPDX-License-Identifier: AGPL-3.0-or-later

//! Saved search CRUD and sharing endpoints.

use axum::extract::Extension;
use axum::{
    Json,
    extract::{Path, State},
};
use nanosiem_core::{
    NewNotification, NewSavedSearch, SavedSearch, SavedSearchWithContext, ShareSavedSearchRequest,
    UpdateSavedSearch,
    audit::{AuditEvent, AuditSource, SAVED_SEARCH_SHARED},
    auth::{TokenClaims, permissions},
    models::notification::NotificationType as ModelNotificationType,
    typeid::TypeIdParam,
};

use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError};

/// NAN-2033: feature-capability gate for the saved-search surface. These handlers
/// extract `TokenClaims` (not `AuthContext`), so they gate on the claims directly.
/// This is ADDITIVE to the repository's per-record ownership/visibility checks:
/// the capability decides *whether* the caller may use the saved-search feature;
/// the repository decides *which* records they may touch. A valid token is not a
/// capability — an owner whose role lost the capability must still be refused.
fn require_capability(claims: &TokenClaims, permission: &str) -> Result<(), SearchError> {
    if claims.has_permission(permission) {
        Ok(())
    } else {
        Err(SearchError::Forbidden(format!(
            "Missing permission: {permission}"
        )))
    }
}

/// NAN-2145: the `users(id)` to write as the OWNER when CREATING a saved search.
///
/// For an API key, `claims.sub` is the KEY id (NAN-2043) — it can never satisfy
/// the `saved_searches.user_id` FK to `users(id)` (create 500'd on it), so the
/// create path stamps the key's OWNER instead. For a JWT session the owner IS
/// `claims.sub`, so behavior is unchanged. Fails closed (403) for an API key
/// with no recorded owner rather than writing a bad FK.
///
/// This is used ONLY for the create ownership FK. Every other path
/// (list/get/update/delete/share visibility, authorization, source-scope,
/// audit) keeps `claims.sub` so an API key does NOT inherit its owner's
/// group-shared searches (codex P1 on the first cut of this fix).
fn ownership_user_id(auth: &crate::AuthContext) -> Result<uuid::Uuid, SearchError> {
    auth.ownership_user_id().ok_or_else(|| {
        SearchError::Forbidden(
            "This API key has no owner account; saved searches are unavailable".to_string(),
        )
    })
}

/// List all saved searches visible to user
#[utoipa::path(
    get,
    path = "/api/search/saved",
    tag = "search",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "List of saved searches visible to user", body = Vec<SavedSearchWithContext>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:view permission", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn list_saved_searches(
    State(state): State<SearchState>,
    Extension(claims): Extension<TokenClaims>,
) -> Result<Json<Vec<SavedSearchWithContext>>, SearchError> {
    // NAN-2033: reading saved searches requires search:view, on top of the
    // per-record ownership/visibility filtering the repository already applies.
    require_capability(&claims, permissions::SEARCH_VIEW)?;

    use nanosiem_core::db::repository::SavedSearchRepository;

    let repo = SavedSearchRepository::new(state.dual_pool.postgres().clone());
    // NAN-2145: visibility keys off `claims.sub` (the KEY principal for API
    // keys), NOT the key owner — an API key must not inherit the owner's
    // group-shared searches. Owner id is used ONLY for the create ownership FK.
    let searches = repo
        .list_for_user(claims.sub)
        .await
        .map_err(|e| SearchError::InternalError(e.to_string()))?;

    // Demo isolation: hide saved searches created by other demo users
    let searches = if claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude = nanosiem_core::demo::get_other_demo_resource_ids_standalone(
            state.dual_pool.postgres(),
            claims.sub,
            "saved_search",
        )
        .await;
        if exclude.is_empty() {
            searches
        } else {
            let exclude_set: std::collections::HashSet<uuid::Uuid> =
                exclude.into_iter().collect();
            searches
                .into_iter()
                .filter(|s| !exclude_set.contains(&s.id))
                .collect()
        }
    } else {
        searches
    };

    Ok(Json(searches))
}

/// List searches shared with user (not owned by user)
#[utoipa::path(
    get,
    path = "/api/search/saved/shared",
    tag = "search",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "List of searches shared with user", body = Vec<SavedSearchWithContext>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:view permission", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn list_shared_searches(
    State(state): State<SearchState>,
    Extension(claims): Extension<TokenClaims>,
) -> Result<Json<Vec<SavedSearchWithContext>>, SearchError> {
    // NAN-2033: reading saved searches requires search:view.
    require_capability(&claims, permissions::SEARCH_VIEW)?;

    use nanosiem_core::db::repository::SavedSearchRepository;

    let repo = SavedSearchRepository::new(state.dual_pool.postgres().clone());
    // NAN-2145: group-share visibility keys off `claims.sub` (the key principal),
    // so an API key does not inherit its owner's group-shared searches.
    let searches = repo
        .list_shared_with_user(claims.sub)
        .await
        .map_err(|e| SearchError::InternalError(e.to_string()))?;

    // Demo isolation: hide saved searches created by other demo users
    let searches = if claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude = nanosiem_core::demo::get_other_demo_resource_ids_standalone(
            state.dual_pool.postgres(),
            claims.sub,
            "saved_search",
        )
        .await;
        if exclude.is_empty() {
            searches
        } else {
            let exclude_set: std::collections::HashSet<uuid::Uuid> =
                exclude.into_iter().collect();
            searches
                .into_iter()
                .filter(|s| !exclude_set.contains(&s.id))
                .collect()
        }
    } else {
        searches
    };

    Ok(Json(searches))
}

/// List user's own saved searches
#[utoipa::path(
    get,
    path = "/api/search/saved/mine",
    tag = "search",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "List of user's own saved searches", body = Vec<SavedSearchWithContext>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:view permission", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn list_my_saved_searches(
    State(state): State<SearchState>,
    Extension(claims): Extension<TokenClaims>,
) -> Result<Json<Vec<SavedSearchWithContext>>, SearchError> {
    // NAN-2033: reading saved searches requires search:view.
    require_capability(&claims, permissions::SEARCH_VIEW)?;

    use nanosiem_core::db::repository::SavedSearchRepository;

    let repo = SavedSearchRepository::new(state.dual_pool.postgres().clone());
    // NAN-2145: ownership keys off `claims.sub` (the key principal for API keys).
    let searches = repo
        .list_owned_by_user(claims.sub)
        .await
        .map_err(|e| SearchError::InternalError(e.to_string()))?;
    Ok(Json(searches))
}

/// Get a saved search by ID
#[utoipa::path(
    get,
    path = "/api/search/saved/{id}",
    tag = "search",
    params(
        ("id" = String, Path, description = "Saved search ID")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Saved search details", body = SavedSearchWithContext),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Access denied", body = ErrorResponse),
        (status = 404, description = "Saved search not found", body = ErrorResponse),
    )
)]
pub async fn get_saved_search(
    State(state): State<SearchState>,
    Extension(claims): Extension<TokenClaims>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<SavedSearchWithContext>, SearchError> {
    // NAN-2033: reading a saved search requires search:view, on top of the
    // repository's per-record ownership/visibility check below.
    require_capability(&claims, permissions::SEARCH_VIEW)?;

    use nanosiem_core::db::repository::{SavedSearchRepository, SavedSearchRepositoryError};

    let repo = SavedSearchRepository::new(state.dual_pool.postgres().clone());
    // NAN-2145: visibility keys off `claims.sub` (the key principal), so a key
    // does not inherit its owner's group-shared searches.
    let search = repo
        .find_by_id_for_user(*id, claims.sub)
        .await
        .map_err(|e| match e {
            SavedSearchRepositoryError::NotFound(_) => {
                SearchError::NotFound(format!("Saved search not found: {}", *id))
            }
            SavedSearchRepositoryError::AccessDenied => {
                SearchError::Forbidden("You don't have access to this saved search".to_string())
            }
            _ => SearchError::InternalError(e.to_string()),
        })?;
    Ok(Json(search))
}

/// Create a new saved search
#[utoipa::path(
    post,
    path = "/api/search/saved",
    tag = "search",
    request_body = NewSavedSearch,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Created saved search", body = SavedSearch),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing permission: search:save", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn create_saved_search(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Json(request): Json<NewSavedSearch>,
) -> Result<Json<SavedSearch>, SearchError> {
    if !auth.claims.has_permission(permissions::SEARCH_SAVE) {
        return Err(SearchError::Forbidden(format!(
            "Missing permission: {}",
            permissions::SEARCH_SAVE
        )));
    }
    // NAN-2145: own the record under the OWNER user id. For an API key,
    // `claims.sub` is the KEY id, which violates the `saved_searches.user_id`
    // FK to `users(id)` (this path returned 500). A JWT session is unchanged.
    let user_id = ownership_user_id(&auth)?;

    use nanosiem_core::db::repository::SavedSearchRepository;

    let repo = SavedSearchRepository::new(state.dual_pool.postgres().clone());
    let search = repo
        .create(&request, user_id)
        .await
        .map_err(|e| SearchError::InternalError(e.to_string()))?;

    // Track for demo session cleanup
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let pool = state.dual_pool.postgres().clone();
        let search_id = search.id;
        tokio::spawn(async move {
            nanosiem_core::demo::track_demo_resource_standalone(
                &pool, user_id, "saved_search", search_id,
            )
            .await;
        });
    }

    Ok(Json(search))
}

/// Update a saved search (owner only)
#[utoipa::path(
    put,
    path = "/api/search/saved/{id}",
    tag = "search",
    params(
        ("id" = String, Path, description = "Saved search ID")
    ),
    request_body = UpdateSavedSearch,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Updated saved search", body = SavedSearch),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only the owner can update", body = ErrorResponse),
        (status = 404, description = "Saved search not found", body = ErrorResponse),
    )
)]
pub async fn update_saved_search(
    State(state): State<SearchState>,
    Extension(claims): Extension<TokenClaims>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateSavedSearch>,
) -> Result<Json<SavedSearch>, SearchError> {
    // NAN-2033: mutating a saved search requires search:save, on top of the
    // repository's owner-only enforcement below.
    require_capability(&claims, permissions::SEARCH_SAVE)?;

    use nanosiem_core::db::repository::{SavedSearchRepository, SavedSearchRepositoryError};

    let repo = SavedSearchRepository::new(state.dual_pool.postgres().clone());
    // NAN-2145: owner-only enforcement keys off `claims.sub` (the key principal).
    let search = repo
        .update(*id, &request, claims.sub)
        .await
        .map_err(|e| match e {
            SavedSearchRepositoryError::NotFound(_) => {
                SearchError::NotFound(format!("Saved search not found: {}", *id))
            }
            SavedSearchRepositoryError::AccessDenied => {
                SearchError::Forbidden("Only the owner can update this saved search".to_string())
            }
            _ => SearchError::InternalError(e.to_string()),
        })?;
    Ok(Json(search))
}

/// Delete a saved search (owner only)
#[utoipa::path(
    delete,
    path = "/api/search/saved/{id}",
    tag = "search",
    params(
        ("id" = String, Path, description = "Saved search ID")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Deletion confirmation", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only the owner can delete", body = ErrorResponse),
        (status = 404, description = "Saved search not found", body = ErrorResponse),
    )
)]
pub async fn delete_saved_search(
    State(state): State<SearchState>,
    Extension(claims): Extension<TokenClaims>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<serde_json::Value>, SearchError> {
    // NAN-2033: deleting a saved search requires search:save, on top of the
    // repository's owner-only enforcement below.
    require_capability(&claims, permissions::SEARCH_SAVE)?;

    use nanosiem_core::db::repository::{SavedSearchRepository, SavedSearchRepositoryError};

    let repo = SavedSearchRepository::new(state.dual_pool.postgres().clone());
    // NAN-2145: owner-only enforcement keys off `claims.sub` (the key principal).
    repo.delete(*id, claims.sub).await.map_err(|e| match e {
        SavedSearchRepositoryError::NotFound(_) => {
            SearchError::NotFound(format!("Saved search not found: {}", *id))
        }
        SavedSearchRepositoryError::AccessDenied => {
            SearchError::Forbidden("Only the owner can delete this saved search".to_string())
        }
        _ => SearchError::InternalError(e.to_string()),
    })?;
    Ok(Json(serde_json::json!({"deleted": true})))
}

/// Share a saved search (change visibility and groups)
#[utoipa::path(
    post,
    path = "/api/search/saved/{id}/share",
    tag = "search",
    params(
        ("id" = String, Path, description = "Saved search ID")
    ),
    request_body = ShareSavedSearchRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Updated saved search with sharing context", body = SavedSearchWithContext),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only the owner can share", body = ErrorResponse),
        (status = 404, description = "Saved search not found", body = ErrorResponse),
    )
)]
pub async fn share_saved_search(
    State(state): State<SearchState>,
    Extension(claims): Extension<TokenClaims>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<ShareSavedSearchRequest>,
) -> Result<Json<SavedSearchWithContext>, SearchError> {
    // NAN-2033: sharing a saved search requires search:share, on top of the
    // repository's owner-only enforcement below.
    require_capability(&claims, permissions::SEARCH_SHARE)?;

    use nanosiem_core::db::repository::{
        NotificationRepository, SavedSearchRepository, SavedSearchRepositoryError,
    };

    let repo = SavedSearchRepository::new(state.dual_pool.postgres().clone());
    // NAN-2145: owner-only enforcement keys off `claims.sub` (the key principal).
    let share_result = repo
        .share(*id, &request, claims.sub)
        .await
        .map_err(|e| match e {
            SavedSearchRepositoryError::NotFound(_) => {
                SearchError::NotFound(format!("Saved search not found: {}", *id))
            }
            SavedSearchRepositoryError::AccessDenied => {
                SearchError::Forbidden("Only the owner can share this saved search".to_string())
            }
            _ => SearchError::InternalError(e.to_string()),
        })?;

    // Emit audit event (actor name omitted - JWT no longer contains PII)
    state.emit_audit(
        AuditEvent::builder(AuditSource::Search, SAVED_SEARCH_SHARED)
            .actor(Some(claims.sub), None)
            .resource(
                "saved_search",
                Some(*id),
                Some(share_result.search.name.clone()),
            )
            .details(serde_json::json!({
                "visibility": request.visibility,
                "group_ids": request.group_ids,
                "users_affected": share_result.users_who_lost_access.len(),
            }))
            .build(),
    );

    // Send notifications to users who lost access
    if !share_result.users_who_lost_access.is_empty() {
        let notification_repo = NotificationRepository::new(state.dual_pool.postgres().clone());
        let search_name = share_result.search.name.clone();
        // Fetch user name from database (JWT no longer contains PII)
        let user_repo =
            nanosiem_core::auth::UserRepository::new(state.dual_pool.postgres().clone());
        let owner_name = user_repo
            .get_user_by_id(claims.sub)
            .await
            .map(|u| u.name)
            .unwrap_or_else(|_| "Unknown User".to_string());

        for affected_user in &share_result.users_who_lost_access {
            let notification = NewNotification {
                user_id: affected_user.user_id,
                notification_type: ModelNotificationType::SearchAccessRemoved,
                title: format!("Access removed: {}", search_name),
                message: Some(format!(
                    "{} has changed sharing settings for the saved search '{}'. You no longer have access to this search.",
                    owner_name, search_name
                )),
                link: None,
                metadata: serde_json::json!({
                    "search_id": *id,
                    "search_name": search_name,
                    "changed_by": claims.sub,
                    "changed_by_name": owner_name,
                }),
            };

            // Fire and forget - don't fail the share if notification fails
            if let Err(e) = notification_repo.create(&notification).await {
                tracing::warn!(
                    user_id = %affected_user.user_id,
                    error = %e,
                    "Failed to create access removal notification"
                );
            }
        }
    }

    Ok(Json(share_result.search))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::typeid;
    use std::str::FromStr;
    use uuid::Uuid;

    /// Regression: SavedSearch responses serialize `id` as `search_<base32>`.
    /// The four detail/update/delete/share extractors must accept that exact
    /// form so callers can reuse the list/create response ID without manually
    /// decoding the base32 suffix to a raw UUID.
    #[test]
    fn typeid_param_accepts_saved_search_prefixed_id() {
        let id = Uuid::now_v7();
        let encoded = typeid::encode(typeid::saved_search::PREFIX, &id);
        assert!(encoded.starts_with("search_"));

        let extracted = TypeIdParam::from_str(&encoded).expect("search_ id should parse");
        assert_eq!(*extracted, id);
    }

    /// Backwards-compat: bare UUIDs still work for any internal callers.
    #[test]
    fn typeid_param_still_accepts_bare_uuid() {
        let id = Uuid::now_v7();
        let extracted = TypeIdParam::from_str(&id.to_string()).expect("bare uuid should parse");
        assert_eq!(*extracted, id);
    }

    fn claims_with(perms: &[&str]) -> TokenClaims {
        TokenClaims {
            iss: "test".to_string(),
            aud: "test".to_string(),
            sub: Uuid::nil(),
            roles: Vec::new(),
            permissions: perms.iter().map(|s| s.to_string()).collect(),
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::nil(),
            purpose: "access".to_string(),
        }
    }

    /// NAN-2033: the saved-search capability gate refuses under-scoped callers
    /// (zero-permission and wrong-permission) and admits only the exact
    /// capability — this is what stops an owner whose role lost the capability,
    /// and any zero-permission key, from reading/mutating saved searches.
    #[test]
    fn require_capability_enforces_exact_permission() {
        // Zero permissions → refused.
        assert!(matches!(
            require_capability(&claims_with(&[]), permissions::SEARCH_VIEW),
            Err(SearchError::Forbidden(_))
        ));
        // Holds an unrelated saved-search capability (save) but not the one
        // required for reads (view) → still refused.
        assert!(matches!(
            require_capability(&claims_with(&[permissions::SEARCH_SAVE]), permissions::SEARCH_VIEW),
            Err(SearchError::Forbidden(_))
        ));
        // Exact capability → allowed.
        assert!(
            require_capability(&claims_with(&[permissions::SEARCH_VIEW]), permissions::SEARCH_VIEW)
                .is_ok()
        );
    }
}

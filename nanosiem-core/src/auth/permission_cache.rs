// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cached permission resolver
//!
//! Loads user permissions from PostgreSQL with a short-lived in-memory cache
//! to avoid hitting the DB on every request. Used by auth middleware to populate
//! permissions on TokenClaims after JWT validation.
//!
//! Demo users (role `demo_analyst`) get permissions from the hardcoded
//! `DEMO_PERMISSIONS` list instead of querying the DB, since ephemeral demo
//! users are not assigned to any groups.

use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use super::permissions::DEMO_PERMISSIONS;

/// Cached permission resolver -- loads user permissions from PostgreSQL
/// with a short-lived in-memory cache to avoid hitting the DB on every request.
#[derive(Clone)]
pub struct PermissionResolver {
    pool: PgPool,
    cache: Arc<DashMap<Uuid, CachedPermissions>>,
}

struct CachedPermissions {
    permissions: Vec<String>,
    cached_at: Instant,
}

const CACHE_TTL_SECS: u64 = 60;

impl PermissionResolver {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Arc::new(DashMap::new()),
        }
    }

    /// Resolve permissions for a user, returning cached results when available.
    ///
    /// Demo users (with `demo_analyst` role) get the hardcoded `DEMO_PERMISSIONS`
    /// list since they aren't assigned to database groups.
    pub async fn resolve(&self, user_id: Uuid) -> Vec<String> {
        self.resolve_with_roles(user_id, &[]).await
    }

    /// Resolve permissions with role context — allows short-circuiting for demo users.
    pub async fn resolve_with_roles(&self, user_id: Uuid, roles: &[String]) -> Vec<String> {
        // Demo users: return hardcoded permissions (they have no DB group assignments)
        if roles.iter().any(|r| r == "demo_analyst") {
            return DEMO_PERMISSIONS.iter().map(|s| s.to_string()).collect();
        }

        // Check cache first
        if let Some(cached) = self.cache.get(&user_id) {
            if cached.cached_at.elapsed().as_secs() < CACHE_TTL_SECS {
                return cached.permissions.clone();
            }
        }

        // Query DB
        let permissions = match sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT rp.permission_id
            FROM user_groups ug
            INNER JOIN group_roles gr ON ug.group_id = gr.group_id
            INNER JOIN role_permissions rp ON gr.role_id = rp.role_id
            WHERE ug.user_id = $1
            ORDER BY rp.permission_id
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        {
            Ok(perms) => perms,
            Err(e) => {
                tracing::warn!(user_id = %user_id, error = %e, "Failed to resolve permissions from DB — user will have no permissions until cache expires");
                Vec::new()
            }
        };

        // Cache the result
        self.cache.insert(
            user_id,
            CachedPermissions {
                permissions: permissions.clone(),
                cached_at: Instant::now(),
            },
        );

        permissions
    }
}

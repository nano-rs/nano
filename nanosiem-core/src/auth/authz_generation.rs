// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-user authorization generation (NAN-3904 / NAN-4902 lane H).
//!
//! `users.authz_generation` (open migration 296) is bumped in the writing
//! transaction by a trigger on every effective `user_groups` INSERT/DELETE —
//! the SSO sign-in reconciler, an IdP-group mapping replacement, and admin
//! membership edits alike. The permission, user-status and source-scope caches
//! of EVERY process (api and search replicas) record the generation an entry
//! was computed at and compare it with the current one on each cache hit, so a
//! group shrink takes effect on the next request everywhere instead of at the
//! cache TTL. The check is one primary-key lookup; process-local eviction
//! alone could not reach the other replicas.
use sqlx::PgPool;
use uuid::Uuid;

/// The user's current authorization generation; `None` for an unknown user.
pub async fn current_authz_generation(pool: &PgPool, user_id: Uuid) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT authz_generation FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

/// Whether a cache entry computed at `cached` may serve a request whose
/// current generation read returned `current`. Any read failure or unknown
/// user is a miss (the caller reloads and applies its own fail-closed rule).
pub fn generation_still_current(cached: Option<i64>, current: &Result<Option<i64>, sqlx::Error>) -> bool {
    matches!((cached, current), (Some(c), Ok(Some(now))) if c == *now)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed source-scope resolver (NAN-1789 / NAN-1797).
//!
//! Resolves the per-user denied `source_type` set:
//!
//! ```text
//! denied = restricted_source_types − (source_type_grants of the user's groups)
//! ```
//!
//! Structurally mirrors `PermissionResolver` (PgPool + short-TTL in-memory
//! caches) but INVERTS its failure behavior. `PermissionResolver` returns —
//! and caches — an empty permission set on PG error; for a DENY set that
//! would be fail-OPEN and sticky. Here, on ANY PG error:
//!
//! - If the global restricted set has ever loaded, return deny-ALL-restricted
//!   (`ScopeSet::from_denied(<full restricted set>)`) and do NOT cache it, so
//!   recovery is immediate once PG is back.
//! - If the restricted set has NEVER loaded, return
//!   `Err(SourceScopeError::Unavailable)` so the caller can 503.
//!
//! A fail-open (empty/partial) deny set is never returned on error and never
//! cached. Demo users (`demo_analyst`) are always deny-all-restricted — they
//! have no DB group assignments, so they can never hold a grant.

use crate::request_timing::RequestDb;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::permissions::SOURCE_SCOPES_VIEW_ALL;
use super::scope::ScopeSet;

/// Errors from source-scope resolution.
#[derive(Debug, thiserror::Error)]
pub enum SourceScopeError {
    /// The restricted-source registry has never been loaded and PostgreSQL is
    /// unreachable — there is no safe deny set to fall back to. Callers must
    /// fail closed (e.g. respond 503), never proceed unscoped.
    #[error("source-scope registry unavailable — failing closed")]
    Unavailable,

    /// Underlying database error.
    #[error("source-scope database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// TTL for the global restricted-source-type registry cache. Short, because a
/// newly restricted source must start being denied quickly on every replica
/// (grant/registry mutations also call [`SourceScopeResolver::invalidate`]).
const RESTRICTED_TTL_SECS: u64 = 30;

/// TTL for per-user denied-set cache entries (mirrors `PermissionResolver`).
const USER_TTL_SECS: u64 = 60;

/// Last-known restricted registry, keyed by owning tenant (NAN-2361: the
/// registry is tenant-scoped; dedicated deployments hold one compatibility
/// tenant). The value is retained PAST its TTL: expiry only forces a refresh
/// attempt, it never evicts, so a stale value is always available as the
/// fail-closed (deny-all-restricted) fallback.
#[derive(Default)]
struct RestrictedCache {
    /// `None` only if the registry has never successfully loaded.
    registry: Option<BTreeMap<Uuid, BTreeSet<String>>>,
    /// `None` forces a refresh on next resolve while keeping `set` as the
    /// fail-closed fallback (see [`SourceScopeResolver::invalidate`]).
    fetched_at: Option<Instant>,
}

struct CachedDenied {
    denied: BTreeSet<String>,
    cached_at: Instant,
    /// Defense in depth beside the exact revisioned cache key: the resolved
    /// role/permission set must still be byte-equivalent before reuse.
    authority_fingerprint: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SourceScopeCacheKey {
    tenant_id: Option<Uuid>,
    user_id: Uuid,
    /// Dedicated compatibility entries use zero. Shared entries always carry
    /// the positive server-owned grant-authority and plan-assignment revisions.
    authority_revision: i64,
    assignment_revision: i64,
    /// `source_scope_version` the caller observed BEFORE this resolve (NAN-3231).
    /// An entry stored under version V was read after V was observed, so it
    /// reflects state at V or newer; a caller that labels its own cache with V
    /// may reuse it. Zero for callers that do not pin a version (they still
    /// converge through `sync_version`). This replaces the global
    /// `invalidate()` the search service used to run on every cold admission.
    source_version: i64,
}

/// How often each resolver re-reads the cross-process invalidation counter.
/// Bounds cross-process propagation of a scope change to roughly this interval
/// (plus one resolve), independent of the longer per-cache TTLs. One cheap PK
/// lookup per interval per process (NAN-1807).
///
/// F-35 (ACCEPTED LIMITATION): after a grant is revoked on the api process, a
/// denied user can keep seeing the just-revoked source on ANOTHER process (e.g.
/// the search service) for up to this many seconds — the poll-convergence
/// window, NOT an unbounded TTL leak. The revoke handler
/// (`nanosiem-api` `source_scopes::*` → `SourceScopeResolver::invalidate`) drops
/// caches synchronously on the LOCAL process; remote processes converge on the
/// next `sync_version` read. This bounded (~3s) staleness is knowingly accepted;
/// a synchronous cross-process fix (PG LISTEN/NOTIFY on the version bump, or an
/// authenticated api→search push) is deferred — see the F-35 recommendation.
const VERSION_CHECK_SECS: u64 = 3;

/// Tracks the last-seen value of the PG `source_scope_version` counter and when
/// it was last read, so the check is throttled to at most once per
/// [`VERSION_CHECK_SECS`].
#[derive(Default)]
struct VersionSync {
    last: Option<i64>,
    checked_at: Option<Instant>,
}

/// Which tenant's restrictions a lookup selects.
#[derive(Debug, Clone, Copy)]
enum RestrictedScope {
    /// Every tenant's restrictions (dedicated deployments: the compatibility
    /// tenant only). Used by the dedicated resolver and the write-side
    /// redaction consumers that have no tenant context.
    Union,
    /// Exactly one hosted-shared tenant's restrictions.
    Tenant(Uuid),
}

/// Registry key for rows with no `tenant_id`: the open schema (migration 244)
/// has no such column; only the enterprise overlay (9000420) adds it, NOT NULL.
const UNTENANTED_REGISTRY_KEY: Uuid = Uuid::nil();

fn select_restricted(registry: &BTreeMap<Uuid, BTreeSet<String>>, scope: RestrictedScope) -> BTreeSet<String> {
    match scope {
        RestrictedScope::Union => registry.values().flatten().cloned().collect(),
        // An untenanted row restricts every tenant: it can never make a
        // tenant's set smaller, only larger (fail closed).
        RestrictedScope::Tenant(tenant_id) => registry
            .get(&tenant_id)
            .into_iter()
            .chain(registry.get(&UNTENANTED_REGISTRY_KEY))
            .flatten()
            .cloned()
            .collect(),
    }
}

/// Outcome of a restricted-registry lookup.
enum RestrictedLookup {
    /// Loaded from cache-within-TTL or a successful refresh.
    Fresh(BTreeSet<String>),
    /// PG refresh FAILED; this is the last-known value. Callers must go
    /// deny-all-restricted with it and must not cache the result.
    FallbackAfterError(BTreeSet<String>),
}

/// Cached, fail-closed resolver of per-user source scopes.
///
/// Cheap to clone (Arc-backed) so it can live in `AuthState`.
#[derive(Clone)]
pub struct SourceScopeResolver {
    pool: PgPool,
    delegated_job: bool,
    restricted: Arc<RwLock<RestrictedCache>>,
    user_cache: Arc<DashMap<SourceScopeCacheKey, CachedDenied>>,
    version: Arc<RwLock<VersionSync>>,
}

impl SourceScopeResolver {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            delegated_job: false,
            restricted: Arc::new(RwLock::new(RestrictedCache::default())),
            user_cache: Arc::new(DashMap::new()),
            version: Arc::new(RwLock::new(VersionSync::default())),
        }
    }

    /// Use the tenant-bound job reader; the control-login reader deliberately
    /// refuses lake data-path credentials. PostgreSQL enforces tenant/capability.
    pub fn for_durable_jobs(pool: PgPool) -> Self {
        let mut resolver = Self::new(pool);
        resolver.delegated_job = true;
        resolver
    }

    /// Resolve the [`ScopeSet`] for a user.
    ///
    /// FAIL-CLOSED: on PG error this never returns an empty (= fail-open)
    /// scope and never caches an error-path value. If the restricted registry
    /// is known (even stale), errors degrade to deny-all-restricted; if it has
    /// never loaded, returns [`SourceScopeError::Unavailable`].
    ///
    /// ADMIN / full-visibility bypass (NAN-1841 / F-34): a caller whose
    /// `permissions` include [`SOURCE_SCOPES_VIEW_ALL`] resolves to an EMPTY
    /// (unrestricted) deny set — it sees every source. This is a POSITIVE
    /// permission check on the already-resolved permission set; it short-circuits
    /// BEFORE any PostgreSQL access, so it neither depends on nor weakens the
    /// fail-closed paths below for non-bypass callers, and it is never a
    /// fail-OPEN path (only an explicit grant reaches it). It is applied here —
    /// the single chokepoint every consumer reads `denied_sources` from — so the
    /// bypass is consistent across search, alerts, fields, dashboards, detection
    /// stats, and cases without patching each handler.
    ///
    /// Demo users (`demo_analyst` role) are always deny-all-restricted. They are
    /// granted [`DEMO_PERMISSIONS`](crate::auth::permissions::DEMO_PERMISSIONS),
    /// which never includes [`SOURCE_SCOPES_VIEW_ALL`], so they can never reach
    /// the bypass.
    pub async fn resolve(
        &self,
        user_id: Uuid,
        roles: &[String],
        permissions: &[String],
    ) -> Result<ScopeSet, SourceScopeError> {
        // ADMIN / full-visibility bypass — POSITIVE permission check, evaluated
        // FIRST and WITHOUT any PostgreSQL access. An admin is therefore never
        // locked out by a scope-registry outage, and the fail-closed posture for
        // everyone else (below) is untouched. Demo users never hold this
        // permission (see DEMO_PERMISSIONS), so they cannot bypass here.
        if grants_unrestricted_source_visibility(permissions) {
            return Ok(ScopeSet::unrestricted());
        }

        // Cross-process: if another process mutated the registry/grants, drop
        // our caches so the change is reflected here within VERSION_CHECK_SECS
        // rather than only at the longer per-cache TTLs (NAN-1807).
        self.sync_version().await;

        let restricted = match self.restricted_set(RestrictedScope::Union).await? {
            RestrictedLookup::Fresh(set) => set,
            RestrictedLookup::FallbackAfterError(set) => {
                // Registry refresh failed: deny everything restricted (per the
                // last-known registry). Not cached — recovery is immediate.
                tracing::warn!(
                    user_id = %user_id,
                    denied = set.len(),
                    "source-scope registry refresh failed — failing closed to deny-all-restricted"
                );
                return Ok(ScopeSet::from_denied(set));
            }
        };

        // Demo users have no group assignments and therefore no grants:
        // always deny-all-restricted, never unrestricted.
        if roles.iter().any(|r| r == "demo_analyst") {
            return Ok(ScopeSet::from_denied(restricted));
        }

        // Nothing restricted => nothing to deny for anyone.
        if restricted.is_empty() {
            return Ok(ScopeSet::unrestricted());
        }

        // Per-user cache.
        let cache_key = SourceScopeCacheKey {
            tenant_id: None,
            user_id,
            authority_revision: 0,
            assignment_revision: 0,
            source_version: 0,
        };
        if let Some(cached) = self.user_cache.get(&cache_key) {
            if cached.cached_at.elapsed().as_secs() < USER_TTL_SECS {
                return Ok(ScopeSet::from_denied(cached.denied.clone()));
            }
        }

        // Load the user's granted set via group membership.
        let granted: BTreeSet<String> = match sqlx::query_scalar::<_, String>(
            r#"
            SELECT g.source_type
            FROM source_type_grants g
            JOIN user_groups ug ON ug.group_id = g.group_id
            WHERE ug.user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool).request_db()
        .await
        {
            Ok(rows) => rows.into_iter().map(normalize_source_type).collect(),
            Err(e) => {
                // FAIL-CLOSED: deny everything restricted; do NOT cache.
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "failed to load source-type grants — failing closed to deny-all-restricted"
                );
                return Ok(ScopeSet::from_denied(restricted));
            }
        };

        let denied = compute_denied(&restricted, &granted);

        self.user_cache.insert(
            cache_key,
            CachedDenied {
                denied: denied.clone(),
                cached_at: Instant::now(),
                authority_fingerprint: None,
            },
        );

        Ok(ScopeSet::from_denied(denied))
    }

    /// Resolve source visibility for one exact enterprise-shared membership.
    ///
    /// Unlike the dedicated compatibility method above, this path never uses
    /// `user_groups` as authority. It revalidates the active tenant/member row
    /// and derives grants only from the exact tenant+role restricted-source
    /// registry in one PostgreSQL snapshot. Cache identity is structurally
    /// `(tenant_id,user_id,authority_revision,assignment_revision)` and the
    /// current server-resolved authority fingerprint must also match before
    /// reuse. A user-only or `(tenant,user)` shared cache is never constructed.
    pub async fn resolve_for_tenant(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        authority_revision: i64,
        assignment_revision: i64,
        roles: &[String],
        permissions: &[String],
    ) -> Result<ScopeSet, SourceScopeError> {
        self.resolve_for_tenant_at_source_version(
            tenant_id, user_id, authority_revision, assignment_revision, roles, permissions, None,
        )
        .await
    }

    /// [`resolve_for_tenant`](Self::resolve_for_tenant) for a caller that
    /// observed `source_scope_version` BEFORE calling and labels its own cache
    /// with it (the search admission cache). The deny-set entry is keyed by
    /// that version, so a new version can never reuse an older entry and no
    /// global `invalidate()` is needed (NAN-3231).
    #[allow(clippy::too_many_arguments)]
    pub async fn resolve_for_tenant_at_source_version(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        authority_revision: i64,
        assignment_revision: i64,
        roles: &[String],
        permissions: &[String],
        source_version: Option<i64>,
    ) -> Result<ScopeSet, SourceScopeError> {
    crate::request_timing::timed(crate::request_timing::Phase::Scope, async {

        if authority_revision <= 0 || assignment_revision <= 0 {
            tracing::error!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                authority_revision,
                assignment_revision,
                "enterprise-shared source-scope authority revision is invalid"
            );
            return Err(SourceScopeError::Unavailable);
        }
        self.sync_version().await;

        let (
            membership_active,
            current_authority_revision,
            current_assignment_revision,
            granted_rows,
        ) = sqlx::query_as::<_, (bool, i64, i64, Vec<String>)>(
            r#"
                WITH current_authority AS (
                    SELECT
                        gav.version AS authority_revision,
                        assignment.assignment_revision
                    FROM grant_authority_version gav
                    JOIN enterprise_shared_tenant_plan_assignments assignment
                      ON assignment.tenant_id = $1
                     AND assignment.state = 'active'
                     AND assignment.effective_at <= NOW()
                     AND (assignment.expires_at IS NULL OR assignment.expires_at > NOW())
                    WHERE gav.singleton = TRUE
                ),
                active_membership AS (
                    SELECT 1
                    FROM tenants t
                    JOIN tenant_members tm ON tm.tenant_id = t.id
                    WHERE t.id = $1
                      AND tm.user_id = $2
                      AND t.status = 'active'
                      AND tm.status = 'active'
                ),
                granted AS (
                    -- NAN-2361 wave 8: role grants are no longer the model
                    -- (visibility is group-based, read below); the column
                    -- is kept so the row shape is unchanged.
                    SELECT NULL::text AS source_type WHERE FALSE
                )
                SELECT
                    EXISTS (SELECT 1 FROM active_membership),
                    COALESCE((SELECT authority_revision FROM current_authority), 0),
                    COALESCE((SELECT assignment_revision FROM current_authority), 0),
                    COALESCE(array_agg(granted.source_type), ARRAY[]::text[])
                FROM granted
                "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&self.pool).request_db()
        .await
        .map_err(|error| {
            tracing::error!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                error = %error,
                "enterprise-shared source-scope membership lookup failed"
            );
            SourceScopeError::Unavailable
        })?;
        if !membership_active
            || current_authority_revision != authority_revision
            || current_assignment_revision != assignment_revision
        {
            tracing::warn!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                expected_authority_revision = authority_revision,
                current_authority_revision,
                expected_assignment_revision = assignment_revision,
                current_assignment_revision,
                "enterprise-shared source-scope membership or authority revision changed"
            );
            return Err(SourceScopeError::Unavailable);
        }

        // Shared administrators still require the active membership check
        // above. A stale/foreign positive permission must never bypass tenant
        // revocation merely because it was carried into this function.
        if grants_unrestricted_source_visibility(permissions) {
            return Ok(ScopeSet::unrestricted());
        }

        let authority_fingerprint = source_authority_fingerprint(roles, permissions);
        let cache_key = SourceScopeCacheKey {
            tenant_id: Some(tenant_id),
            user_id,
            authority_revision,
            assignment_revision,
            source_version: source_version.unwrap_or(0),
        };
        if let Some(cached) = self.user_cache.get(&cache_key) {
            if cached.cached_at.elapsed().as_secs() < USER_TTL_SECS
                && cached.authority_fingerprint == Some(authority_fingerprint)
            {
                return Ok(ScopeSet::from_denied(cached.denied.clone()));
            }
        }

        // NAN-2361 wave 8: the member's effective deny set — union of the
        // member's tenant groups' restrictions ∪ direct `restrict`
        // exceptions − direct `allow` exceptions — as ONE bounded
        // control-login read (`nano_shared.read_tenant_source_visibility`,
        // 9001000). The legacy `restricted_source_types` registry is not
        // consulted for a shared tenant. Fail closed: an unreadable model is
        // `Unavailable`, never an empty set.
        let _ = granted_rows;
        let (denied, _all_restricted) = self.read_tenant_source_visibility(tenant_id, user_id).await?;
        self.user_cache.insert(
            cache_key,
            CachedDenied {
                denied: denied.clone(),
                cached_at: Instant::now(),
                authority_fingerprint: Some(authority_fingerprint),
            },
        );
        Ok(ScopeSet::from_denied(denied))

    }).await
}

    /// Resolve SOURCE visibility for a tenant-bound automation credential.
    ///
    /// The owner is revalidated only as the exact active tenant membership;
    /// the credential does not inherit that owner's tenant-role source grants.
    /// Its explicit `source_scopes:view_all` permission is the sole positive
    /// bypass, evaluated only after the current authority revisions match.
    /// Cache identity uses the credential id, never the owner alone.
    pub async fn resolve_for_tenant_credential(
        &self,
        tenant_id: Uuid,
        owner_user_id: Uuid,
        credential_id: Uuid,
        authority_revision: i64,
        assignment_revision: i64,
        permissions: &[String],
    ) -> Result<ScopeSet, SourceScopeError> {
        self.resolve_for_tenant_credential_at_source_version(
            tenant_id, owner_user_id, credential_id, authority_revision, assignment_revision,
            permissions, None,
        )
        .await
    }

    /// Credential counterpart of
    /// [`resolve_for_tenant_at_source_version`](Self::resolve_for_tenant_at_source_version).
    #[allow(clippy::too_many_arguments)]
    pub async fn resolve_for_tenant_credential_at_source_version(
        &self,
        tenant_id: Uuid,
        owner_user_id: Uuid,
        credential_id: Uuid,
        authority_revision: i64,
        assignment_revision: i64,
        permissions: &[String],
        source_version: Option<i64>,
    ) -> Result<ScopeSet, SourceScopeError> {
    crate::request_timing::timed(crate::request_timing::Phase::Scope, async {

        if authority_revision <= 0 || assignment_revision <= 0 {
            return Err(SourceScopeError::Unavailable);
        }
        let (active, current_authority, current_assignment) =
            sqlx::query_as::<_, (bool, i64, i64)>(
                r#"
                SELECT
                    EXISTS (
                        SELECT 1 FROM tenants t
                        JOIN tenant_members tm ON tm.tenant_id=t.id
                        JOIN users u ON u.id=tm.user_id
                        WHERE t.id=$1 AND tm.user_id=$2
                          AND t.status='active' AND tm.status='active'
                          AND u.status='active'
                    ),
                    COALESCE((SELECT version FROM grant_authority_version
                              WHERE singleton=TRUE),0),
                    COALESCE((SELECT assignment_revision
                              FROM enterprise_shared_tenant_plan_assignments
                              WHERE tenant_id=$1 AND state='active'
                                AND effective_at<=NOW()
                                AND (expires_at IS NULL OR expires_at>NOW())),0)
                "#,
            )
            .bind(tenant_id)
            .bind(owner_user_id)
            .fetch_one(&self.pool).request_db()
            .await
            .map_err(|error| {
                tracing::error!(tenant_id=%tenant_id, owner_user_id=%owner_user_id,
                    credential_id=%credential_id, error=%error,
                    "tenant automation credential source-scope revalidation failed");
                SourceScopeError::Unavailable
            })?;
        if !active
            || current_authority != authority_revision
            || current_assignment != assignment_revision
        {
            return Err(SourceScopeError::Unavailable);
        }
        if grants_unrestricted_source_visibility(permissions) {
            return Ok(ScopeSet::unrestricted());
        }
        self.sync_version().await;
        let fingerprint = source_authority_fingerprint(&[], permissions);
        let cache_key = SourceScopeCacheKey {
            tenant_id: Some(tenant_id),
            user_id: credential_id,
            authority_revision,
            assignment_revision,
            source_version: source_version.unwrap_or(0),
        };
        if let Some(cached) = self.user_cache.get(&cache_key) {
            if cached.cached_at.elapsed().as_secs() < USER_TTL_SECS
                && cached.authority_fingerprint == Some(fingerprint)
            {
                return Ok(ScopeSet::from_denied(cached.denied.clone()));
            }
        }
        // NAN-2361 wave 8: a tenant automation key never inherits its
        // owner's groups or exceptions — it is denied every slug restricted
        // for anybody in the tenant (the union half of the 9001000 reader).
        let (_owner_denied, restricted) = self.read_tenant_source_visibility(tenant_id, owner_user_id).await?;
        self.user_cache.insert(
            cache_key,
            CachedDenied {
                denied: restricted.clone(),
                cached_at: Instant::now(),
                authority_fingerprint: Some(fingerprint),
            },
        );
        Ok(ScopeSet::from_denied(restricted))

    }).await
}

    /// NAN-3218: a tenant member's member-level deny set (groups ∪ `restrict`
    /// exceptions − `allow` exceptions) for a DELIVERY decision about a third
    /// party — may an inbox row that names or links a source be written for,
    /// or shown to, `user_id`. Uncached (delivery is rare and must see the
    /// current model) and without the `source_scopes:view_all` bypass: the
    /// resolver holds no authority context for someone other than the caller,
    /// so the caller proves the bypass inside its signed transaction
    /// (`nano_shared.tenant_member_holds`). Fails closed: `Unavailable`.
    pub async fn member_denied_sources_for_delivery(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<BTreeSet<String>, SourceScopeError> {
        if tenant_id.is_nil() || user_id.is_nil() {
            return Err(SourceScopeError::Unavailable);
        }
        let (denied, _all_restricted) = self.read_tenant_source_visibility(tenant_id, user_id).await?;
        Ok(denied)
    }

    /// The 9001000 control-login reader: `(member effective deny set,
    /// tenant-wide restricted union)` for one `(tenant, user)`. Slugs come
    /// back canonical (lowercase, lake alphabet); normalized again here so a
    /// registry value can never weaken the row filter by case, and expanded
    /// over the Unattributed aliases (`default` ⇔ `unknown`, NAN-2602).
    async fn read_tenant_source_visibility(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>), SourceScopeError> {
    crate::request_timing::timed(crate::request_timing::Phase::Scope, async {

        let query = if self.delegated_job {
            "SELECT denied, all_restricted FROM nano_shared.read_job_source_visibility($1, $2)"
        } else {
            "SELECT denied, all_restricted FROM nano_shared.read_tenant_source_visibility($1, $2)"
        };
        let (denied, all_restricted) = sqlx::query_as::<_, (Vec<String>, Vec<String>)>(query)
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&self.pool).request_db()
        .await
        .map_err(|error| {
            tracing::error!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                error = %error,
                "enterprise-shared source visibility read failed — failing closed"
            );
            SourceScopeError::Unavailable
        })?;
        // NAN-2602: `default` / `unknown` are ONE Unattributed label on the
        // lake. Expand here as well as in the 9001600 derivation so the row
        // filter fails closed even against a control plane that predates it.
        Ok((normalize_tenant_visibility(denied), normalize_tenant_visibility(all_restricted)))

    }).await
}

    /// Drop all cached state so the next `resolve` re-reads PostgreSQL.
    ///
    /// Call after any restricted-source registry or grant mutation
    /// (create/update/delete), mirroring the invalidate-after-CRUD pattern.
    /// The last-known restricted set is kept (only marked stale) so the
    /// fail-closed fallback survives invalidation.
    pub fn invalidate(&self) {
        self.user_cache.clear();
        // Keep `set` as the fail-closed fallback; force a refresh attempt.
        self.restricted.write().unwrap_or_else(std::sync::PoisonError::into_inner).fetched_at = None;
    }

    /// Snapshot of the global restricted-`source_type` set, for write-side
    /// redaction (NAN-1800).
    ///
    /// Returns the same set [`resolve`](Self::resolve) uses: a fresh copy
    /// within TTL, or the stale last-known set when a PG refresh fails
    /// (fail-closed-to-stale — reuses [`restricted_set`](Self::restricted_set)'s
    /// existing fallback). Propagates [`SourceScopeError::Unavailable`] ONLY
    /// when the registry has never loaded and PostgreSQL is unreachable, so the
    /// caller can fail closed.
    ///
    /// `Ok(set)` is always usable; an empty set means nothing is restricted.
    pub async fn restricted_snapshot(&self) -> Result<BTreeSet<String>, SourceScopeError> {
        // Converge with cross-process mutations like resolve() does, so the
        // write-side redaction consumers (webhook / findings, which use their
        // own long-lived resolver instance) pick up a newly-restricted source
        // within VERSION_CHECK_SECS (~3s) instead of only at the 30s TTL —
        // otherwise a just-restricted source would egress to webhooks for up to
        // 30s (NAN-1800 review / NAN-1807).
        self.sync_version().await;
        match self.restricted_set(RestrictedScope::Union).await? {
            RestrictedLookup::Fresh(set) | RestrictedLookup::FallbackAfterError(set) => Ok(set),
        }
    }

    /// [`restricted_snapshot`](Self::restricted_snapshot) for exactly one
    /// hosted-shared tenant (NAN-2361): another tenant's restrictions never
    /// redact — or fail to redact — this tenant's data.
    pub async fn restricted_snapshot_for_tenant(&self, tenant_id: Uuid) -> Result<BTreeSet<String>, SourceScopeError> {
        self.sync_version().await;
        match self.restricted_set(RestrictedScope::Tenant(tenant_id)).await? {
            RestrictedLookup::Fresh(set) | RestrictedLookup::FallbackAfterError(set) => Ok(set),
        }
    }

    /// [`any_restricted`](Self::any_restricted) against one tenant's registry
    /// (same unresolved-origin and fail-closed policy).
    pub async fn any_restricted_for_tenant(&self, tenant_id: Uuid, source_types: &[String]) -> bool {
        if super::scope::is_unresolved_provenance(source_types) {
            return true;
        }
        match self.restricted_snapshot_for_tenant(tenant_id).await {
            Ok(set) => any_in_restricted(source_types, &set),
            Err(_) => true,
        }
    }

    /// True if ANY of `source_types` is currently restricted — THE place the
    /// write-side redaction fail-closed policy lives (NAN-1800).
    ///
    /// Inputs are normalized (`trim` + `lowercase`) before comparison because
    /// OCSF `source_type` is not ingest-lowercased. FAIL-CLOSED: if the registry
    /// is unavailable (never loaded and PostgreSQL is unreachable) this returns
    /// `true` (treat as restricted) so redaction errs toward hiding.
    ///
    /// NAN-2155: an UNRESOLVED origin
    /// ([`UNRESOLVED_SOURCE_SENTINEL`](super::scope::UNRESOLVED_SOURCE_SENTINEL))
    /// is restricted unconditionally, checked BEFORE any registry access. The
    /// sentinel is deliberately not a registry member, so a plain membership
    /// test would report it as unrestricted. Without this, a "fully attributed"
    /// engine stamp could EGRESS the matched-event sample, which is strictly
    /// worse than the unstamped behaviour it replaced.
    ///
    /// NAN-2207: the `audit` origin is NOT checked here. This predicate is
    /// shared by finding storage and webhook egress, and those two boundaries
    /// no longer agree about audit:
    ///
    /// * Finding storage keeps the hard-wire, applied by its OWN short-circuit
    ///   in [`FindingLogger::origin_restricted`](crate::detection::FindingLogger)
    ///   before it ever calls this method — so moving the check out of here
    ///   leaves finding redaction byte-identical.
    /// * Webhook egress deliberately dropped it (see
    ///   [`is_always_restricted_origin`](super::scope::is_always_restricted_origin)):
    ///   an audit-sourced alert now egresses its evidence unless an admin has
    ///   registered `audit` as restricted, which the registry branch below
    ///   handles like any other source.
    ///
    /// Keeping the audit test inside a SHARED predicate is what made NAN-2155
    /// change both boundaries at once; each caller now states its own policy.
    pub async fn any_restricted(&self, source_types: &[String]) -> bool {
        if super::scope::is_unresolved_provenance(source_types) {
            return true;
        }
        match self.restricted_snapshot().await {
            Ok(set) => any_in_restricted(source_types, &set),
            // FAIL-CLOSED: registry unavailable => treat as restricted.
            Err(_) => true,
        }
    }

    /// Throttled read of the cross-process invalidation counter. At most once
    /// per [`VERSION_CHECK_SECS`], read `source_scope_version`; if it changed
    /// since we last saw it, [`invalidate`](Self::invalidate) our caches so a
    /// mutation made on another process (e.g. the api's admin CRUD) takes effect
    /// on this process (e.g. the search service) promptly.
    ///
    /// Best-effort: on any error (PG down, table absent on a pre-migration DB)
    /// this is a no-op — the resolver's own fail-closed paths handle PG being
    /// unreachable, and the per-cache TTLs remain as the backstop.
    async fn sync_version(&self) {
        // Throttle: skip if we checked within the interval.
        {
            let guard = self
                .version
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(checked_at) = guard.checked_at {
                if checked_at.elapsed().as_secs() < VERSION_CHECK_SECS {
                    return;
                }
            }
        }

        // Read the counter outside any lock. `fetch_optional` + `.ok()` so a
        // missing row / absent table / transient error is a silent no-op.
        let fetched: Option<i64> =
            sqlx::query_scalar::<_, i64>("SELECT version FROM source_scope_version")
                .fetch_optional(&self.pool).request_db()
                .await
                .ok()
                .flatten();

        let changed = {
            let mut guard = self
                .version
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.checked_at = Some(Instant::now());
            match fetched {
                // Counter moved since we last saw a value: invalidate.
                Some(v) if guard.last.is_some() && guard.last != Some(v) => {
                    guard.last = Some(v);
                    true
                }
                // First observation (or unchanged): record, don't invalidate.
                Some(v) => {
                    guard.last = Some(v);
                    false
                }
                // Read failed: leave `last` untouched, just throttle.
                None => false,
            }
        };

        if changed {
            self.invalidate();
        }
    }

    /// Get the restricted set for `scope`, refreshing the tenant-keyed
    /// registry from PostgreSQL when the cached copy is missing or past TTL.
    /// The cached value is never evicted, only refreshed, so it remains
    /// available as the fail-closed fallback.
    async fn restricted_set(&self, scope: RestrictedScope) -> Result<RestrictedLookup, SourceScopeError> {
        // Fast path: cached and fresh.
        {
            let guard = self
                .restricted
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let (Some(registry), Some(fetched_at)) = (&guard.registry, guard.fetched_at) {
                if fetched_at.elapsed().as_secs() < RESTRICTED_TTL_SECS {
                    return Ok(RestrictedLookup::Fresh(select_restricted(registry, scope)));
                }
            }
        }

        // Refresh from PG (outside the lock). One statement for every tenant:
        // the registry is small and the union view needs it all anyway.
        //
        // `tenant_id` is read through `to_jsonb(row)` because the column only
        // exists once the enterprise overlay (9000420) has run. Naming it
        // directly (d43d78c8d) failed with 42703 on every open-edition
        // database, so the registry never loaded: every search answered
        // Unavailable and every webhook withheld its evidence.
        match sqlx::query_as::<_, (Option<Uuid>, String)>(
            "SELECT (to_jsonb(registry) ->> 'tenant_id')::uuid, registry.source_type \
               FROM restricted_source_types registry",
        )
            .fetch_all(&self.pool).request_db()
            .await
        {
            Ok(rows) => {
                let mut registry: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
                for (tenant_id, source_type) in rows {
                    registry
                        .entry(tenant_id.unwrap_or(UNTENANTED_REGISTRY_KEY))
                        .or_default()
                        .insert(normalize_source_type(source_type));
                }
                let selected = select_restricted(&registry, scope);
                let mut guard = self
                    .restricted
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.registry = Some(registry);
                guard.fetched_at = Some(Instant::now());
                Ok(RestrictedLookup::Fresh(selected))
            }
            Err(e) => {
                let guard = self
                    .restricted
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match &guard.registry {
                    // Stale-but-known registry: fail closed against it.
                    Some(registry) => Ok(RestrictedLookup::FallbackAfterError(select_restricted(registry, scope))),
                    // Never loaded: there is no safe deny set — surface an
                    // error the caller must 503 on.
                    None => {
                        tracing::error!(
                            error = %e,
                            "source-scope registry has never loaded and PostgreSQL is unreachable — unavailable (fail closed)"
                        );
                        Err(SourceScopeError::Unavailable)
                    }
                }
            }
        }
    }
}

/// Canonicalize slugs read from the 9001000 visibility reader exactly as the
/// resolver does (trim + lowercase, then the NAN-2602 Unattributed expansion).
/// Shared with the one-snapshot Search admission (NAN-3231).
pub fn normalize_tenant_visibility(values: Vec<String>) -> BTreeSet<String> {
    super::source_visibility::expand_unattributed_sources(values.into_iter().map(normalize_source_type))
}

fn normalize_source_type(raw: String) -> String {
    raw.trim().to_lowercase()
}

fn source_authority_fingerprint(roles: &[String], permissions: &[String]) -> [u8; 32] {
    let mut roles = roles.iter().map(String::as_str).collect::<Vec<_>>();
    roles.sort_unstable();
    roles.dedup();
    let mut permissions = permissions.iter().map(String::as_str).collect::<Vec<_>>();
    permissions.sort_unstable();
    permissions.dedup();
    let mut digest = Sha256::new();
    digest.update(b"nano-enterprise-shared-source-authority-v1\0");
    for role in roles {
        digest.update((role.len() as u64).to_be_bytes());
        digest.update(role.as_bytes());
    }
    digest.update(b"\0permissions\0");
    for permission in permissions {
        digest.update((permission.len() as u64).to_be_bytes());
        digest.update(permission.as_bytes());
    }
    digest.finalize().into()
}

/// True if `permissions` grant the ADMIN / full-visibility bypass
/// ([`SOURCE_SCOPES_VIEW_ALL`]) — the caller sees every source regardless of the
/// restricted registry. Pure so the bypass decision is unit-testable without a
/// database, and so it can be asserted to be a POSITIVE check (never fail-open).
fn grants_unrestricted_source_visibility(permissions: &[String]) -> bool {
    permissions.iter().any(|p| p == SOURCE_SCOPES_VIEW_ALL)
}

/// `denied = restricted − granted`, computed in Rust. Pure so it is unit-testable
/// without a database. Grants for sources that are not (or no longer)
/// restricted are inert.
fn compute_denied(restricted: &BTreeSet<String>, granted: &BTreeSet<String>) -> BTreeSet<String> {
    restricted.difference(granted).cloned().collect()
}

/// True if any of `source_types` (after normalization) is in `restricted`.
/// Pure so the match semantics of [`SourceScopeResolver::any_restricted`] are
/// unit-testable without a database.
fn any_in_restricted(source_types: &[String], restricted: &BTreeSet<String>) -> bool {
    source_types
        .iter()
        .any(|s| restricted.contains(&normalize_source_type(s.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn untenanted_registry_rows_restrict_every_tenant() {
        let tenant_a = Uuid::from_u128(0xa);
        let tenant_b = Uuid::from_u128(0xb);
        let registry = BTreeMap::from([
            (tenant_a, set(&["a_only"])),
            (tenant_b, set(&["b_only"])),
            (UNTENANTED_REGISTRY_KEY, set(&["open_schema_row"])),
        ]);
        assert_eq!(
            select_restricted(&registry, RestrictedScope::Tenant(tenant_a)),
            set(&["a_only", "open_schema_row"])
        );
        assert_eq!(
            select_restricted(&registry, RestrictedScope::Union),
            set(&["a_only", "b_only", "open_schema_row"])
        );
        // Tenant isolation is unchanged for tenant-keyed rows.
        assert!(!select_restricted(&registry, RestrictedScope::Tenant(tenant_a)).contains("b_only"));
    }

    #[test]
    fn denied_is_restricted_minus_granted() {
        let restricted = set(&["insider_threat", "hr_feed", "audit"]);
        let granted = set(&["hr_feed"]);
        assert_eq!(
            compute_denied(&restricted, &granted),
            set(&["audit", "insider_threat"])
        );
    }

    #[test]
    fn shared_cache_identity_is_tenant_user_and_role_order_independent() {
        let user_id = Uuid::from_u128(7);
        let tenant_a = SourceScopeCacheKey {
            tenant_id: Some(Uuid::from_u128(0xa)),
            user_id,
            authority_revision: 11,
            assignment_revision: 7,
            source_version: 3,
        };
        let tenant_b = SourceScopeCacheKey {
            tenant_id: Some(Uuid::from_u128(0xb)),
            user_id,
            authority_revision: 11,
            assignment_revision: 7,
            source_version: 3,
        };
        let dedicated = SourceScopeCacheKey {
            tenant_id: None,
            user_id,
            authority_revision: 0,
            assignment_revision: 0,
            source_version: 0,
        };
        assert_ne!(tenant_a, tenant_b);
        assert_ne!(tenant_a, dedicated);
        assert_eq!(
            source_authority_fingerprint(
                &["analyst".into(), "admin".into()],
                &["search:execute".into()]
            ),
            source_authority_fingerprint(
                &["admin".into(), "analyst".into(), "admin".into()],
                &["search:execute".into()]
            )
        );
        assert_ne!(
            source_authority_fingerprint(&["analyst".into()], &[]),
            source_authority_fingerprint(&["admin".into()], &[])
        );
        assert_ne!(
            SourceScopeCacheKey {
                assignment_revision: 8,
                ..tenant_a
            },
            tenant_a
        );
        assert_ne!(
            SourceScopeCacheKey {
                authority_revision: 12,
                ..tenant_a
            },
            tenant_a
        );
        // NAN-3231: a deny set read under an older source version is never
        // reused by a caller that observed a newer one.
        assert_ne!(
            SourceScopeCacheKey {
                source_version: 4,
                ..tenant_a
            },
            tenant_a
        );
    }

    #[test]
    fn no_grants_denies_everything_restricted() {
        let restricted = set(&["insider_threat", "hr_feed"]);
        assert_eq!(compute_denied(&restricted, &BTreeSet::new()), restricted);
    }

    #[test]
    fn full_grants_deny_nothing() {
        let restricted = set(&["insider_threat", "hr_feed"]);
        let denied = compute_denied(&restricted, &restricted);
        assert!(denied.is_empty());
        assert!(!ScopeSet::from_denied(denied).is_restricted());
    }

    #[test]
    fn grants_outside_restricted_set_are_inert() {
        let restricted = set(&["insider_threat"]);
        let granted = set(&["syslog", "otlp_logs"]);
        assert_eq!(
            compute_denied(&restricted, &granted),
            set(&["insider_threat"])
        );
    }

    #[test]
    fn empty_restricted_set_denies_nothing() {
        let denied = compute_denied(&BTreeSet::new(), &set(&["anything"]));
        assert!(denied.is_empty());
    }

    #[test]
    fn normalize_lowercases_and_trims() {
        assert_eq!(
            normalize_source_type("  Insider_Threat ".to_string()),
            "insider_threat"
        );
        assert_eq!(normalize_source_type("audit".to_string()), "audit");
    }

    #[test]
    fn normalized_sets_difference_correctly() {
        // Mixed-case grant rows must still cancel their restricted counterpart.
        let restricted: BTreeSet<String> = ["Insider_Threat".to_string(), "hr_feed".to_string()]
            .into_iter()
            .map(normalize_source_type)
            .collect();
        let granted: BTreeSet<String> = ["INSIDER_THREAT ".to_string()]
            .into_iter()
            .map(normalize_source_type)
            .collect();
        assert_eq!(compute_denied(&restricted, &granted), set(&["hr_feed"]));
    }

    fn strs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn any_in_restricted_true_when_one_matches() {
        let restricted = set(&["insider_threat", "hr_feed"]);
        assert!(any_in_restricted(
            &strs(&["syslog", "hr_feed"]),
            &restricted
        ));
    }

    #[test]
    fn any_in_restricted_false_when_none_match() {
        let restricted = set(&["insider_threat", "hr_feed"]);
        assert!(!any_in_restricted(
            &strs(&["syslog", "otlp_logs"]),
            &restricted
        ));
    }

    #[test]
    fn any_in_restricted_empty_inputs_is_false() {
        let restricted = set(&["insider_threat"]);
        assert!(!any_in_restricted(&[], &restricted));
    }

    #[test]
    fn any_in_restricted_empty_registry_is_false() {
        // Nothing restricted => nothing is ever matched. Back-compat: pre-feature.
        assert!(!any_in_restricted(
            &strs(&["insider_threat"]),
            &BTreeSet::new()
        ));
    }

    #[test]
    fn any_in_restricted_normalizes_inputs() {
        // OCSF source_type is not ingest-lowercased; mixed-case/whitespace input
        // must still match a (normalized) restricted entry.
        let restricted = set(&["insider_threat"]);
        assert!(any_in_restricted(
            &strs(&["  Insider_Threat "]),
            &restricted
        ));
    }

    // --- ADMIN / full-visibility bypass (NAN-1841 / F-34) ---------------------

    #[test]
    fn bypass_permission_grants_unrestricted_visibility() {
        // (a) A caller holding `source_scopes:view_all` bypasses per-source RBAC.
        assert!(grants_unrestricted_source_visibility(&strs(&[
            "search:view",
            SOURCE_SCOPES_VIEW_ALL,
            "cases:view",
        ])));
    }

    #[test]
    fn non_bypass_permissions_do_not_grant_visibility() {
        // (b) A non-bypass caller is unchanged. Notably `source_scopes:manage`
        // (config administration) does NOT confer data visibility — the bypass
        // is a distinct, positive grant.
        assert!(!grants_unrestricted_source_visibility(&strs(&[
            "search:view",
            "source_scopes:view",
            "source_scopes:manage",
        ])));
        // No permissions at all => no bypass (fail-closed for the empty set).
        assert!(!grants_unrestricted_source_visibility(&[]));
    }

    #[test]
    fn bypass_yields_empty_deny_set_that_gates_nothing() {
        // (a)+(c) The bypass resolves to `unrestricted()`: an EMPTY deny set that
        // is NOT restricted. Downstream, an empty deny set is the byte-identical
        // "no gate" path (`enforce_source_scope` returns the query verbatim; the
        // cases F-34 404 block is `!deny.is_empty()`-guarded), so a bypass caller
        // sees everything and pays no query-rewrite cost — same as a SYSTEM caller.
        assert!(grants_unrestricted_source_visibility(&strs(&[
            SOURCE_SCOPES_VIEW_ALL
        ])));
        let scope = ScopeSet::unrestricted();
        assert!(!scope.is_restricted());
        assert!(scope.deny_set().is_empty());
    }

    /// A pool that can NEVER connect (nothing listens on the TCP discard port).
    /// Mirrors the fail-closed pool pattern in the integration suite and
    /// `leader.rs`; used to prove the bypass needs no PG and that non-bypass
    /// callers still fail closed when PG is unreachable.
    fn unreachable_pool() -> sqlx::PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect_lazy("postgres://nanosiem:nanosiem@127.0.0.1:9/nanosiem")
            .expect("build lazy pool")
    }

    #[tokio::test]
    async fn resolve_bypasses_without_touching_postgres() {
        // (a) A bypass caller resolves to an EMPTY deny set even when the registry
        // and grants could never load — the bypass short-circuits BEFORE any PG
        // access, so "sources are restricted" and "holds no grant" are moot: the
        // resolver never even reads them. Proven by a pool that can't connect.
        let resolver = SourceScopeResolver::new(unreachable_pool());
        let scope = resolver
            .resolve(Uuid::now_v7(), &[], &[SOURCE_SCOPES_VIEW_ALL.to_string()])
            .await
            .expect("bypass caller must resolve with no PG access");
        assert!(!scope.is_restricted(), "bypass caller must be unrestricted");
        assert!(scope.deny_set().is_empty());
    }

    #[tokio::test]
    async fn resolve_fails_closed_for_non_bypass_when_registry_never_loaded() {
        // (b) A NON-bypass caller is unchanged: with the registry never loaded and
        // PG unreachable, resolve() must Err(Unavailable) — NEVER an empty
        // (fail-open) scope. Confirms the bypass is a POSITIVE check, not a
        // fail-open path that a permission-less caller could ride through.
        let resolver = SourceScopeResolver::new(unreachable_pool());
        let err = resolver
            .resolve(Uuid::now_v7(), &[], &["search:view".to_string()])
            .await
            .expect_err("non-bypass caller must fail closed, not return a scope");
        assert!(
            matches!(err, SourceScopeError::Unavailable),
            "non-bypass + never-loaded registry + PG down must be Unavailable, got {err:?}"
        );
    }

    #[tokio::test]
    async fn unresolved_sentinel_short_circuits_without_postgres() {
        // The sentinel must redact with NO PostgreSQL access at all: it is not a
        // registry member, so if this fell through to the registry branch it
        // would depend on the snapshot being loadable — exactly the dependency
        // NAN-2155 removed.
        let resolver = SourceScopeResolver::new(unreachable_pool());

        assert!(
            resolver
                .any_restricted(&[crate::auth::UNRESOLVED_SOURCE_SENTINEL.to_string()])
                .await
        );
    }

    #[tokio::test]
    async fn audit_origin_no_longer_short_circuits() {
        // NAN-2207: `audit` is no longer hard-wired into this predicate — it is
        // an ordinary registry lookup now. This pool can never connect, so the
        // registry branch fails CLOSED and the result is still `true`; the point
        // of the test is the ROUTE, not the verdict. Proven by the pure
        // predicate: nothing in `any_restricted`'s short-circuit matches audit.
        assert!(!crate::auth::is_unresolved_provenance(&[
            "audit".to_string()
        ]));

        let resolver = SourceScopeResolver::new(unreachable_pool());
        assert!(
            resolver.any_restricted(&[" Audit ".to_string()]).await,
            "registry unavailable must still fail closed for any source"
        );
    }
}

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

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use dashmap::DashMap;
use sqlx::PgPool;
use uuid::Uuid;

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

/// Last-known global restricted set. The value is retained PAST its TTL:
/// expiry only forces a refresh attempt, it never evicts, so a stale value is
/// always available as the fail-closed (deny-all-restricted) fallback.
#[derive(Default)]
struct RestrictedCache {
    /// `None` only if the registry has never successfully loaded.
    set: Option<BTreeSet<String>>,
    /// `None` forces a refresh on next resolve while keeping `set` as the
    /// fail-closed fallback (see [`SourceScopeResolver::invalidate`]).
    fetched_at: Option<Instant>,
}

struct CachedDenied {
    denied: BTreeSet<String>,
    cached_at: Instant,
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
    restricted: Arc<RwLock<RestrictedCache>>,
    user_cache: Arc<DashMap<Uuid, CachedDenied>>,
    version: Arc<RwLock<VersionSync>>,
}

impl SourceScopeResolver {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            restricted: Arc::new(RwLock::new(RestrictedCache::default())),
            user_cache: Arc::new(DashMap::new()),
            version: Arc::new(RwLock::new(VersionSync::default())),
        }
    }

    /// Resolve the [`ScopeSet`] for a user.
    ///
    /// FAIL-CLOSED: on PG error this never returns an empty (= fail-open)
    /// scope and never caches an error-path value. If the restricted registry
    /// is known (even stale), errors degrade to deny-all-restricted; if it has
    /// never loaded, returns [`SourceScopeError::Unavailable`].
    ///
    /// Demo users (`demo_analyst` role) are always deny-all-restricted.
    pub async fn resolve(
        &self,
        user_id: Uuid,
        roles: &[String],
    ) -> Result<ScopeSet, SourceScopeError> {
        // Cross-process: if another process mutated the registry/grants, drop
        // our caches so the change is reflected here within VERSION_CHECK_SECS
        // rather than only at the longer per-cache TTLs (NAN-1807).
        self.sync_version().await;

        let restricted = match self.restricted_set().await? {
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
        if let Some(cached) = self.user_cache.get(&user_id) {
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
        .fetch_all(&self.pool)
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
            user_id,
            CachedDenied {
                denied: denied.clone(),
                cached_at: Instant::now(),
            },
        );

        Ok(ScopeSet::from_denied(denied))
    }

    /// Drop all cached state so the next `resolve` re-reads PostgreSQL.
    ///
    /// Call after any restricted-source registry or grant mutation
    /// (create/update/delete), mirroring the invalidate-after-CRUD pattern.
    /// The last-known restricted set is kept (only marked stale) so the
    /// fail-closed fallback survives invalidation.
    pub fn invalidate(&self) {
        self.user_cache.clear();
        if let Ok(mut guard) = self.restricted.write() {
            // Keep `set` as the fail-closed fallback; force a refresh attempt.
            guard.fetched_at = None;
        }
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
        match self.restricted_set().await? {
            RestrictedLookup::Fresh(set) | RestrictedLookup::FallbackAfterError(set) => Ok(set),
        }
    }

    /// True if ANY of `source_types` is currently restricted — THE place the
    /// write-side redaction fail-closed policy lives (NAN-1800).
    ///
    /// Inputs are normalized (`trim` + `lowercase`) before comparison because
    /// OCSF `source_type` is not ingest-lowercased. FAIL-CLOSED: if the registry
    /// is unavailable (never loaded and PostgreSQL is unreachable) this returns
    /// `true` (treat as restricted) so redaction errs toward hiding.
    pub async fn any_restricted(&self, source_types: &[String]) -> bool {
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
                .fetch_optional(&self.pool)
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

    /// Get the global restricted set, refreshing from PostgreSQL when the
    /// cached copy is missing or past TTL. The cached value is never evicted,
    /// only refreshed, so it remains available as the fail-closed fallback.
    async fn restricted_set(&self) -> Result<RestrictedLookup, SourceScopeError> {
        // Fast path: cached and fresh.
        {
            let guard = self
                .restricted
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let (Some(set), Some(fetched_at)) = (&guard.set, guard.fetched_at) {
                if fetched_at.elapsed().as_secs() < RESTRICTED_TTL_SECS {
                    return Ok(RestrictedLookup::Fresh(set.clone()));
                }
            }
        }

        // Refresh from PG (outside the lock).
        match sqlx::query_scalar::<_, String>(
            "SELECT source_type FROM restricted_source_types",
        )
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => {
                let set: BTreeSet<String> =
                    rows.into_iter().map(normalize_source_type).collect();
                let mut guard = self
                    .restricted
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.set = Some(set.clone());
                guard.fetched_at = Some(Instant::now());
                Ok(RestrictedLookup::Fresh(set))
            }
            Err(e) => {
                let guard = self
                    .restricted
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match &guard.set {
                    // Stale-but-known registry: fail closed against it.
                    Some(set) => Ok(RestrictedLookup::FallbackAfterError(set.clone())),
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

/// Normalize a `source_type` for set comparison. Ingest lowercases
/// `source_type`; normalizing both the restricted and granted sets defends
/// against case/whitespace drift between the two registry tables.
fn normalize_source_type(raw: String) -> String {
    raw.trim().to_lowercase()
}

/// `denied = restricted − granted`, computed in Rust. Pure so it is unit-testable
/// without a database. Grants for sources that are not (or no longer)
/// restricted are inert.
fn compute_denied(
    restricted: &BTreeSet<String>,
    granted: &BTreeSet<String>,
) -> BTreeSet<String> {
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
    fn denied_is_restricted_minus_granted() {
        let restricted = set(&["insider_threat", "hr_feed", "audit"]);
        let granted = set(&["hr_feed"]);
        assert_eq!(
            compute_denied(&restricted, &granted),
            set(&["audit", "insider_threat"])
        );
    }

    #[test]
    fn no_grants_denies_everything_restricted() {
        let restricted = set(&["insider_threat", "hr_feed"]);
        assert_eq!(
            compute_denied(&restricted, &BTreeSet::new()),
            restricted
        );
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
        assert_eq!(normalize_source_type("  Insider_Threat ".to_string()), "insider_threat");
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
        assert!(any_in_restricted(&strs(&["syslog", "hr_feed"]), &restricted));
    }

    #[test]
    fn any_in_restricted_false_when_none_match() {
        let restricted = set(&["insider_threat", "hr_feed"]);
        assert!(!any_in_restricted(&strs(&["syslog", "otlp_logs"]), &restricted));
    }

    #[test]
    fn any_in_restricted_empty_inputs_is_false() {
        let restricted = set(&["insider_threat"]);
        assert!(!any_in_restricted(&[], &restricted));
    }

    #[test]
    fn any_in_restricted_empty_registry_is_false() {
        // Nothing restricted => nothing is ever matched. Back-compat: pre-feature.
        assert!(!any_in_restricted(&strs(&["insider_threat"]), &BTreeSet::new()));
    }

    #[test]
    fn any_in_restricted_normalizes_inputs() {
        // OCSF source_type is not ingest-lowercased; mixed-case/whitespace input
        // must still match a (normalized) restricted entry.
        let restricted = set(&["insider_threat"]);
        assert!(any_in_restricted(&strs(&["  Insider_Threat "]), &restricted));
    }
}

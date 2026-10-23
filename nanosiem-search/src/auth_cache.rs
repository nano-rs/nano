// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded admission cache; credentials are SHA-256 digests, never plaintext.
use std::{collections::HashMap, sync::Mutex, time::{Duration, Instant}};
use sha2::{Digest, Sha256};
use nanosiem_core::request_timing::{timed, Phase, RequestDb};
use crate::middleware::{AuthContext, SharedSearchCredentialAuthority};

/// NAN-4215: how long a cold admission's identity is reused. Every reuse is
/// re-proven by [`check`] (one statement covering every revocation input), so
/// this bounds memory and the age of cosmetic fields, never revocation. At
/// the old 30 s an analyst's next search usually missed and paid the cold
/// admission (live: 250 ms of round trips, plus ~200 ms bcrypt for a key).
pub(crate) const IDENTITY_LIFETIME: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub(crate) struct Entry {
    pub context: AuthContext,
    pub source_version: i64,
    /// End of the cached identity's reuse ([`IDENTITY_LIFETIME`]).
    pub deadline: Instant,
    /// End of the proof's freshness: the last complete authority proof (cold
    /// admission or a passed [`check`]) plus the proof window. Only this
    /// lets a request skip the pre-release revalidation ([`current`]).
    pub proven_until: Instant,
}

pub(crate) struct AuthCache {
    entries: Mutex<HashMap<[u8; 32], Entry>>,
    /// Proof freshness window (`NANO_SEARCH_AUTH_CACHE_SECONDS`, default 30).
    proof: Duration,
    lifetime: Duration,
    capacity: usize,
}

impl Default for AuthCache {
    fn default() -> Self {
        let seconds = std::env::var("NANO_SEARCH_AUTH_CACHE_SECONDS").ok()
            .and_then(|value| value.parse::<u64>().ok()).unwrap_or(30).min(300);
        Self::new(Duration::from_secs(seconds), IDENTITY_LIFETIME, 8192)
    }
}

impl AuthCache {
    fn new(proof: Duration, lifetime: Duration, capacity: usize) -> Self {
        Self { entries: Mutex::new(HashMap::new()), proof, lifetime: lifetime.max(proof), capacity }
    }
    /// A cached entry whose [`check`] (started at `started`) just passed: its
    /// proof is fresh again; its identity lifetime is unchanged.
    pub fn proven(&self, mut entry: Entry, started: Instant) -> Entry {
        entry.proven_until = (started + self.proof).min(entry.deadline);
        entry
    }
    pub fn key(kind: u8, credential: &str) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update([kind]);
        hash.update(credential.as_bytes());
        hash.finalize().into()
    }
    pub fn get(&self, key: &[u8; 32]) -> Option<Entry> {
        let mut entries = self.entries.lock().unwrap_or_else(|error| error.into_inner());
        let entry = entries.get(key)?;
        if entry.deadline <= Instant::now() || !credential_unexpired(&entry.context) {
            entries.remove(key);
            return None;
        }
        Some(entry.clone())
    }
    pub fn remove(&self, key: &[u8; 32]) {
        self.entries.lock().unwrap_or_else(|error| error.into_inner()).remove(key);
    }
    /// Test clock: every entry admitted `by` earlier (identity and proof).
    #[cfg(test)]
    pub(crate) fn age_for_test(&self, by: Duration) {
        for entry in self.entries.lock().unwrap().values_mut() {
            entry.deadline -= by;
            entry.proven_until -= by;
        }
    }
    pub fn insert(&self, key: [u8; 32], context: AuthContext, source_version: i64, started: Instant) -> Entry {
        let entry = Entry { context, source_version, deadline: started + self.lifetime, proven_until: started + self.proof };
        if self.capacity == 0 || entry.deadline <= Instant::now() { return entry; }
        let mut entries = self.entries.lock().unwrap_or_else(|error| error.into_inner());
        entries.retain(|_, value| value.deadline > Instant::now());
        if entries.len() >= self.capacity {
            if let Some(oldest) = entries.iter().min_by_key(|(_, value)| value.deadline).map(|(key, _)| *key) {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, entry.clone());
        entry
    }
}

fn credential_unexpired(context: &AuthContext) -> bool {
    let now = chrono::Utc::now();
    if context.claims.exp <= now.timestamp() { return false; }
    #[cfg(feature = "enterprise")]
    if let Some(authority) = &context.shared_request_authority {
        if let SharedSearchCredentialAuthority::TenantAutomationKey(key) = &authority.credential {
            return key.expires_at.is_none_or(|expiry| expiry > now);
        }
    }
    true
}

pub(crate) async fn source_version(pool: &sqlx::PgPool) -> Result<i64, sqlx::Error> {
    timed(Phase::Auth, sqlx::query_scalar("SELECT version FROM source_scope_version")
        .fetch_one(pool).request_db()).await
}

/// One SQL statement checks epochs, exact credential revocation, active plan,
/// retention and current IP policy. False means evict and run full
/// authentication; SQL failure is a 503.
///
/// NAN-3231: sessions and automation keys are separate statements. The session
/// statement is read-only (no data-modifying CTE, no row locks, no WAL); only
/// the key statement charges the two distributed rate budgets, and it charges
/// nothing when the cached authority or IP is stale.
pub(crate) async fn check(pool: &sqlx::PgPool, entry: &Entry, ip: Option<std::net::IpAddr>)
    -> Result<(bool, bool, bool), sqlx::Error>
{
    tokio::time::timeout(Duration::from_secs(2), timed(Phase::Auth, async {
        let Some(authority) = &entry.context.shared_request_authority else { return Ok((false, false, false)); };
        if !credential_unexpired(&entry.context) { return Ok((false, false, false)); }
        match &authority.credential {
            SharedSearchCredentialAuthority::Session { access_jti, credential_time_micros } =>
                check_session(pool, entry, authority, *access_jti, *credential_time_micros, ip).await,
            #[cfg(feature = "enterprise")]
            SharedSearchCredentialAuthority::TenantAutomationKey(key) =>
                check_key(pool, entry, authority, key, ip).await,
        }
    })).await.map_err(|_| sqlx::Error::Protocol("cached Search admission timed out".into()))?
}

/// Read-only warm check for an interactive session: the third (rate) verdict
/// is always true because sessions carry no distributed request budget.
async fn check_session(
    pool: &sqlx::PgPool,
    entry: &Entry,
    authority: &crate::middleware::SharedSearchRequestAuthority,
    jti: uuid::Uuid,
    credential_time_micros: i64,
    ip: Option<std::net::IpAddr>,
) -> Result<(bool, bool, bool), sqlx::Error> {
    sqlx::query_as::<_, (bool, bool, bool)>(r#"
        WITH current AS MATERIALIZED (
            SELECT t.id
              FROM tenants t
              JOIN tenant_members tm ON tm.tenant_id=t.id AND tm.user_id=$2
              JOIN users u ON u.id=tm.user_id
              JOIN grant_authority_version gav ON gav.singleton=TRUE AND gav.version=$3
              JOIN source_scope_version sv ON sv.version=$4
              JOIN enterprise_shared_tenant_plan_assignments a ON a.tenant_id=t.id
              JOIN enterprise_shared_plan_versions p ON p.plan_code=a.plan_code AND p.revision=a.plan_revision
              JOIN enterprise_shared_retention_policy_heads h ON h.tenant_id=t.id
             WHERE t.id=$1 AND t.status='active' AND tm.status='active' AND u.status='active'
               AND a.assignment_revision=$5 AND a.state='active' AND p.state IN ('active','retired')
               AND a.effective_at<=NOW() AND (a.expires_at IS NULL OR a.expires_at>NOW())
               AND h.retention_revision=$6
               AND (u.tokens_valid_from IS NULL OR FLOOR(EXTRACT(EPOCH FROM u.tokens_valid_from)*1000000)::bigint<$8)
               AND (t.tokens_valid_from IS NULL OR FLOOR(EXTRACT(EPOCH FROM t.tokens_valid_from)*1000000)::bigint<$8)
               AND (tm.tokens_valid_from IS NULL OR FLOOR(EXTRACT(EPOCH FROM tm.tokens_valid_from)*1000000)::bigint<$8)
               AND NOT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti=$7)
        ), policy AS MATERIALIZED (
            SELECT nano_shared.check_tenant_ip_policy($1,$9::text::inet,'search') allowed
            WHERE $9::text IS NOT NULL AND EXISTS(SELECT 1 FROM current)
        )
        SELECT EXISTS(SELECT 1 FROM current), COALESCE((SELECT allowed FROM policy),FALSE), TRUE
    "#)
    .bind(authority.tenant.tenant_id).bind(entry.context.ownership_user_id())
    .bind(authority.membership_authority_revision).bind(entry.source_version)
    .bind(authority.entitlement_assignment_revision).bind(authority.retention.retention_revision)
    .bind(jti).bind(credential_time_micros).bind(ip.map(|value| value.to_string()))
    .fetch_one(pool).request_db().await
}

/// Warm check for a tenant automation key. Charges BOTH existing distributed
/// rate budgets; no rate write occurs when the cached authority or IP is stale.
#[cfg(feature = "enterprise")]
async fn check_key(
    pool: &sqlx::PgPool,
    entry: &Entry,
    authority: &crate::middleware::SharedSearchRequestAuthority,
    key: &nanosiem_core::enterprise_shared_automation_keys::AuthenticatedTenantAutomationKey,
    ip: Option<std::net::IpAddr>,
) -> Result<(bool, bool, bool), sqlx::Error> {
    sqlx::query_as::<_, (bool, bool, bool)>(r#"
        WITH current AS MATERIALIZED (
            SELECT t.id, k.id key_id,
                   LEAST(k.rate_limit_per_minute, limits.max_requests_per_minute) key_limit,
                   limits.max_requests_per_minute tenant_limit
              FROM tenants t
              JOIN tenant_members tm ON tm.tenant_id=t.id AND tm.user_id=$2
              JOIN users u ON u.id=tm.user_id
              JOIN grant_authority_version gav ON gav.singleton=TRUE AND gav.version=$3
              JOIN source_scope_version sv ON sv.version=$4
              JOIN enterprise_shared_tenant_plan_assignments a ON a.tenant_id=t.id
              JOIN enterprise_shared_plan_versions p ON p.plan_code=a.plan_code AND p.revision=a.plan_revision
              JOIN enterprise_shared_retention_policy_heads h ON h.tenant_id=t.id
              JOIN enterprise_shared_automation_keys k ON k.tenant_id=t.id AND k.id=$7 AND k.owner_user_id=u.id
              LEFT JOIN enterprise_shared_plan_automation_key_limits limits
                ON limits.plan_code=p.plan_code AND limits.plan_revision=p.revision
             WHERE t.id=$1 AND t.status='active' AND tm.status='active' AND u.status='active'
               AND a.assignment_revision=$5 AND a.state='active' AND p.state IN ('active','retired')
               AND a.effective_at<=NOW() AND (a.expires_at IS NULL OR a.expires_at>NOW())
               AND h.retention_revision=$6
               AND (u.tokens_valid_from IS NULL OR FLOOR(EXTRACT(EPOCH FROM u.tokens_valid_from)*1000000)::bigint<$9)
               AND (t.tokens_valid_from IS NULL OR FLOOR(EXTRACT(EPOCH FROM t.tokens_valid_from)*1000000)::bigint<$9)
               AND (tm.tokens_valid_from IS NULL OR FLOOR(EXTRACT(EPOCH FROM tm.tokens_valid_from)*1000000)::bigint<$9)
               AND k.status='active' AND k.key_revision=$8 AND (k.expires_at IS NULL OR k.expires_at>NOW())
        ), policy AS MATERIALIZED (
            SELECT nano_shared.check_tenant_ip_policy($1,$10::text::inet,'search') allowed
            WHERE $10::text IS NOT NULL AND EXISTS(SELECT 1 FROM current)
        ), key_budget AS (
            INSERT INTO enterprise_shared_automation_key_rate_buckets (tenant_id,key_id,window_start,request_count)
            SELECT id,key_id,date_trunc('minute',NOW()),1 FROM current
             WHERE key_limit>0 AND (SELECT allowed FROM policy)
            ON CONFLICT (tenant_id,key_id,window_start) DO UPDATE
              SET request_count=enterprise_shared_automation_key_rate_buckets.request_count+1
              WHERE enterprise_shared_automation_key_rate_buckets.request_count < (SELECT key_limit FROM current)
            RETURNING request_count
        ), tenant_budget AS (
            INSERT INTO enterprise_shared_automation_key_tenant_rate_buckets (tenant_id,window_start,request_count)
            SELECT id,date_trunc('minute',NOW()),1 FROM current
             WHERE EXISTS(SELECT 1 FROM key_budget) AND tenant_limit>0
            ON CONFLICT (tenant_id,window_start) DO UPDATE
              SET request_count=enterprise_shared_automation_key_tenant_rate_buckets.request_count+1
              WHERE enterprise_shared_automation_key_tenant_rate_buckets.request_count < (SELECT tenant_limit FROM current)
            RETURNING request_count
        )
        SELECT EXISTS(SELECT 1 FROM current), COALESCE((SELECT allowed FROM policy),FALSE),
               EXISTS(SELECT 1 FROM key_budget) AND EXISTS(SELECT 1 FROM tenant_budget)
    "#)
    .bind(authority.tenant.tenant_id).bind(entry.context.ownership_user_id())
    .bind(authority.membership_authority_revision).bind(entry.source_version)
    .bind(authority.entitlement_assignment_revision).bind(authority.retention.retention_revision)
    .bind(key.info.id).bind(key.key_revision).bind(key.issued_at.timestamp_micros())
    .bind(ip.map(|value| value.to_string()))
    .fetch_one(pool).request_db().await
}

// Only the admitted context can reuse the proof, and never beyond the proof
// window after its last complete authority proof (NAN-4215: not the identity
// lifetime). Background jobs inherit no task local and revalidate fully.
tokio::task_local! { static ADMISSION: Entry; }
pub(crate) async fn admitted<F: std::future::Future>(entry: Entry, future: F) -> F::Output {
    ADMISSION.scope(entry, future).await
}
pub(crate) fn current(context: &AuthContext) -> bool {
    ADMISSION.try_with(|entry| context.shared_request_authority.is_some()
        && entry.proven_until > Instant::now()
        && credential_unexpired(context)
        && entry.context.shared_request_authority == context.shared_request_authority
        && entry.context.tenant_scope == context.tenant_scope
        && entry.context.shared_search_entitlement_revision == context.shared_search_entitlement_revision
        && entry.context.shared_prevalence_entitled == context.shared_prevalence_entitled
        && entry.context.claims.roles == context.claims.roles
        && entry.context.denied_sources == context.denied_sources
        && entry.context.claims.sub == context.claims.sub
        && entry.context.claims.permissions == context.claims.permissions).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::TokenClaims;
    pub(super) fn context() -> AuthContext {
        let mut context = AuthContext::from_jwt(TokenClaims { iss: "test".into(), aud: "test".into(), sub: uuid::Uuid::from_u128(1),
            roles: vec![], permissions: vec!["search:execute".into()], exp: i64::MAX, iat: 0,
            jti: uuid::Uuid::from_u128(2), purpose: "access".into() });
        let tenant = nanosiem_core::auth::TrustedTenantContext { tenant_id: uuid::Uuid::from_u128(3), tenant_slug: "fixture".into() };
        let retention = nanosiem_core::query_retention_authority::QueryRetentionAuthority {
            tenant_id: tenant.tenant_id, assignment_revision: 1, retention_revision: 1,
            retention_entitlement_revision: 1, retention_option_revision: 1, retention_days: 365,
            irreversible_event_time_floor: chrono::DateTime::UNIX_EPOCH, effective_at: chrono::DateTime::UNIX_EPOCH,
        };
        #[cfg(feature = "enterprise")]
        let scope = retention.search_scope().unwrap();
        // Open builds have no shared-scope constructor; build the same variant.
        #[cfg(not(feature = "enterprise"))]
        let scope = nanosiem_core::search::SearchTenantScope::EnterpriseSharedRetained {
            tenant_id: retention.tenant_id,
            retention_revision: retention.retention_revision,
            retention_days: u16::try_from(retention.retention_days).unwrap(),
            irreversible_event_time_floor_micros: retention.irreversible_event_time_floor.timestamp_micros(),
        };
        context.tenant_scope = scope;
        context.shared_request_authority = Some(crate::middleware::SharedSearchRequestAuthority {
            tenant, credential: SharedSearchCredentialAuthority::Session { access_jti: context.claims.jti, credential_time_micros: 1_700_000_000_000_000 },
            membership_authority_revision: 1, entitlement_assignment_revision: 1, retention,
        });
        context

    }
    #[test]
    fn cache_miss_hit_expiry_eviction_and_explicit_revocation() {
        let cache = AuthCache::new(Duration::from_secs(30), Duration::from_secs(900), 2);
        let key = AuthCache::key(0, "session-one");
        assert!(cache.get(&key).is_none());
        let started = Instant::now();
        cache.insert(key, context(), 1, started);
        assert_eq!(cache.get(&key).unwrap().deadline, started + Duration::from_secs(900));
        assert_eq!(cache.get(&key).unwrap().proven_until, started + Duration::from_secs(30));
        assert_ne!(key, AuthCache::key(1, "session-one"));
        cache.remove(&key);
        assert!(cache.get(&key).is_none());
        cache.insert(key, context(), 1, started - Duration::from_secs(901));
        assert!(cache.get(&key).is_none());
        for n in 0..3 { cache.insert(AuthCache::key(0, &n.to_string()), context(), 1, Instant::now()); }
        assert_eq!(cache.entries.lock().unwrap().len(), 2);
        assert!(cache.get(&AuthCache::key(0, "0")).is_none());
        let mut expired = context(); expired.claims.exp = 0;
        cache.insert(key, expired, 1, started);
        assert!(cache.get(&key).is_none());
    }
    #[tokio::test]
    async fn admission_proof_expires_and_is_not_inherited_by_background_work() {
        let mut auth = context();
        // No shared proof can be constructed by a request outside middleware.
        assert!(!current(&auth));
        let entry = Entry { context: auth.clone(), source_version: 1, deadline: Instant::now() + Duration::from_secs(900), proven_until: Instant::now() + Duration::from_secs(1) };
        admitted(entry, async {
            assert!(current(&auth));
            let background = auth.clone();
            assert!(!tokio::spawn(async move { current(&background) }).await.unwrap());
            auth.claims.permissions.clear();
            assert!(!current(&auth));
        }).await;
        // NAN-4215: a live identity whose proof is stale is not current.
        let entry = Entry { context: auth.clone(), source_version: 1, deadline: Instant::now() + Duration::from_secs(900), proven_until: Instant::now() - Duration::from_secs(1) };
        admitted(entry, async { assert!(!current(&auth)); }).await;
    }

    /// NAN-4215: an identity admitted 45 s ago (past the old 30 s TTL) is
    /// still served from the cache, and a passed check re-arms only the
    /// proof window, never past the identity lifetime.
    #[test]
    fn identity_outlives_the_proof_window_and_a_passed_check_rearms_only_the_proof() {
        let cache = AuthCache::new(Duration::from_secs(30), Duration::from_secs(900), 4);
        let key = AuthCache::key(1, "nan_tak_fixture");
        let admitted_at = Instant::now() - Duration::from_secs(45);
        cache.insert(key, context(), 7, admitted_at);
        let entry = cache.get(&key).expect("identity reused after 45 s");
        assert!(entry.proven_until <= Instant::now(), "the cold proof itself is stale");
        let check_started = Instant::now();
        let proven = cache.proven(entry, check_started);
        assert_eq!(proven.proven_until, check_started + Duration::from_secs(30));
        assert_eq!(proven.deadline, admitted_at + Duration::from_secs(900), "lifetime is never renewed");
        let near_end = Entry { deadline: Instant::now() + Duration::from_secs(5), ..proven };
        assert!(cache.proven(near_end.clone(), Instant::now()).proven_until <= near_end.deadline);
    }
    #[tokio::test]
    async fn unavailable_epoch_check_fails_closed() {
        let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://unused:unused@127.0.0.1:1/unused").unwrap();
        pool.close().await;
        assert!(source_version(&pool).await.is_err());
    }
}

#[cfg(all(test, feature = "enterprise"))]
mod enterprise_shared_tests;

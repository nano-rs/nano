// SPDX-License-Identifier: AGPL-3.0-or-later
//! Internal helper endpoint, mounted outside interactive/user auth middleware.
use crate::SearchState;
use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use nanosiem_core::inputlookup::{egress_auth, storage_policy::host_allowed};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, SemaphorePermit};
use uuid::Uuid;

// Cold authority + signed policy reads fit inside the helper's 2s deadline.
const POLICY_DEADLINE: Duration = Duration::from_millis(500);
const POLICY_LOAD_BUDGET: Duration = Duration::from_millis(400);
const POLICY_FRESHNESS: Duration = Duration::from_secs(25);
const POLICY_CACHE_CAPACITY: usize = 1024;

type PolicyResult = Result<Vec<String>, &'static str>;
#[derive(Default)]
struct PolicySlot {
    snapshot: Option<(Instant, PolicyResult)>,
}

// Router-owned: never share snapshots between different SearchState runtimes.
// The map lock covers admission only; each tenant has its own single-flight lock.
#[derive(Default)]
pub struct PolicyCache {
    entries: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<PolicySlot>>>>,
}
impl PolicyCache {
    async fn hosts<F, Fut>(&self, tenant: Uuid, load: F) -> PolicyResult
    where
        F: FnOnce(Uuid) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<String>, StatusCode>>,
    {
        let slot = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(slot) = entries.get(&tenant) {
                Arc::clone(slot)
            } else {
                // Reclaim only idle expired slots; in-flight slots cannot be
                // evicted and recreated, which would break single-flight.
                entries.retain(|_, slot| {
                    Arc::strong_count(slot) > 1
                        || slot.try_lock().map_or(true, |slot| {
                            slot.snapshot
                                .as_ref()
                                .is_some_and(|(at, _)| at.elapsed() < POLICY_FRESHNESS)
                        })
                });
                if entries.len() >= POLICY_CACHE_CAPACITY {
                    return Err("policy_unavailable");
                }
                let slot = Arc::new(tokio::sync::Mutex::new(PolicySlot::default()));
                entries.insert(tenant, Arc::clone(&slot));
                slot
            }
        };
        let mut slot = slot.lock().await;
        if let Some((at, result)) = &slot.snapshot {
            if at.elapsed() < POLICY_FRESHNESS {
                return result.clone();
            }
        }
        // Age from BEFORE authority selection, never from completion: cached
        // authority revocation and policy mutations become visible within 25s.
        // No stale allow is served during refresh or on a dependency failure.
        let started = Instant::now();
        let result = match tokio::time::timeout(POLICY_LOAD_BUDGET, load(tenant)).await {
            Ok(Ok(hosts)) => Ok(hosts),
            Ok(Err(_)) => Err("policy_unavailable"),
            Err(_) => Err("policy_timeout"),
        };
        slot.snapshot = Some((started, result.clone()));
        result
    }
}

// Bound work before JSON extraction or authentication, without attacker-controlled
// tenant keys. Shared by every router in this process; overload fails closed.
struct Admission {
    concurrent: Semaphore,
    arrivals: Mutex<VecDeque<Instant>>,
}
impl Admission {
    fn new() -> Self {
        Self {
            concurrent: Semaphore::new(32),
            arrivals: Mutex::new(VecDeque::new()),
        }
    }
    fn enter(&self, now: Instant) -> Result<SemaphorePermit<'_>, StatusCode> {
        let permit = self
            .concurrent
            .try_acquire()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        let mut arrivals = self
            .arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while arrivals
            .front()
            .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(1))
        {
            arrivals.pop_front();
        }
        if arrivals.len() >= 128 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        arrivals.push_back(now);
        Ok(permit)
    }
}
static ADMISSION: LazyLock<Admission> = LazyLock::new(Admission::new);

/// Each tenant/host/reason gets one aggregate record per minute. Pending
/// keys own one bounded timer; the final count includes quiet periods too.
#[derive(Default)]
struct DenialRate {
    entries: HashMap<(Uuid, String, &'static str), u64>,
}
impl DenialRate {
    fn count(&mut self, tenant: Uuid, host: &str, reason: &'static str) -> bool {
        let key = (tenant, host.to_owned(), reason);
        if let Some(count) = self.entries.get_mut(&key) {
            *count = count.saturating_add(1);
            return false;
        }
        if self.entries.len() >= 4096 {
            return false;
        }
        self.entries.insert(key, 1);
        true
    }
    fn take(&mut self, tenant: Uuid, host: &str, reason: &'static str) -> Option<u64> {
        self.entries.remove(&(tenant, host.to_owned(), reason))
    }
}
static DENIAL_AUDIT_BUDGET: Semaphore = Semaphore::const_new(32);
static DENIAL_RATE: LazyLock<Arc<Mutex<DenialRate>>> =
    LazyLock::new(|| Arc::new(Mutex::new(DenialRate::default())));

fn queue_denial<F, Fut>(
    rate: Arc<Mutex<DenialRate>>,
    tenant: Uuid,
    host: String,
    reason: &'static str,
    window: Duration,
    emit: F,
) where
    F: FnOnce(u64) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), StatusCode>> + Send,
{
    if !rate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .count(tenant, &host, reason)
    {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(window).await;
        let permit =
            tokio::time::timeout(Duration::from_secs(5), DENIAL_AUDIT_BUDGET.acquire()).await;
        let count = rate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(tenant, &host, reason)
            .unwrap_or(0);
        let result = match permit {
            Ok(Ok(_permit)) => tokio::time::timeout(Duration::from_secs(5), emit(count)).await,
            _ => Ok(Err(StatusCode::SERVICE_UNAVAILABLE)),
        };
        if !matches!(result, Ok(Ok(()))) {
            tracing::warn!("inputlookup egress denial audit unavailable");
        }
    });
}

fn denial_reason(request: &EgressCheckRequest, key: &[u8], now: i64) -> &'static str {
    if egress_auth::verify(
        key,
        request.tenant_id,
        &request.host,
        &request.token,
        request.exp,
        now,
    ) {
        "not_listed"
    } else if request.exp <= now
        && egress_auth::verify(
            key,
            request.tenant_id,
            &request.host,
            &request.token,
            request.exp,
            request.exp.saturating_sub(1),
        )
    {
        "expired"
    } else {
        "bad_token"
    }
}

async fn admit(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let _permit = match ADMISSION.enter(Instant::now()) {
        Ok(permit) => permit,
        Err(status) => return status.into_response(),
    };
    // Includes slow body extraction and the uniform denial delay.
    match tokio::time::timeout(Duration::from_secs(2), next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressCheckRequest {
    pub tenant_id: Uuid,
    pub host: String,
    pub token: String,
    pub exp: i64,
}
#[derive(Serialize, utoipa::ToSchema)]
pub struct EgressCheckResponse {
    pub allow: bool,
}

// The Squid helper reads these bytes literally and requires Content-Length.
// Keep this independent of serializer or middleware framing choices.
impl IntoResponse for EgressCheckResponse {
    fn into_response(self) -> Response {
        let body = if self.allow {
            "{\"allow\":true}"
        } else {
            "{\"allow\":false}"
        };
        (
            [
                (axum::http::header::CONTENT_TYPE, "application/json"),
                (
                    axum::http::header::CONTENT_LENGTH,
                    if self.allow { "14" } else { "15" },
                ),
            ],
            body,
        )
            .into_response()
    }
}

#[utoipa::path(post, path = "/internal/inputlookup/egress-check", tag = "internal-egress",
    request_body = EgressCheckRequest,
    responses((status = 200, body = EgressCheckResponse), (status = 401, description = "Invalid helper credential"), (status = 408, description = "Request deadline exceeded; helper must deny"), (status = 429, description = "Helper admission limit exceeded; helper must deny"), (status = 503, description = "Unavailable; helper must deny")),
    security(("egress_service_bearer" = [])))]
pub async fn check(
    State(state): State<SearchState>,
    Extension(cache): Extension<Arc<PolicyCache>>,
    headers: HeaderMap,
    Json(request): Json<EgressCheckRequest>,
) -> Result<EgressCheckResponse, StatusCode> {
    let expected = std::env::var("NANOSIEM_INPUTLOOKUP_EGRESS_CHECK_TOKEN")
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let supplied = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if !egress_auth::service_token_matches(expected.as_bytes(), supplied.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let key = std::env::var("NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY")
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let now = chrono::Utc::now().timestamp();
    let (response, reason) = decide_policy_with_clock(
        &request,
        key.as_bytes(),
        now,
        |tenant| cache.hosts(tenant, |tenant| current_hosts(&state, tenant)),
        || chrono::Utc::now().timestamp(),
    )
    .await?;
    if !response.allow {
        let host = nanosiem_core::inputlookup::shared::audit_host(&request.host);
        let tenant = request.tenant_id;
        // Do not extend helper latency or expose tenant discovery timing.
        // The bounded task retains only sanitized metadata, never the token.
        queue_denial(
            Arc::clone(&DENIAL_RATE),
            tenant,
            host.clone(),
            reason,
            Duration::from_secs(60),
            move |count| async move { audit_denial(&state, tenant, &host, reason, count).await },
        );
    }
    Ok(response)
}

#[cfg(test)]
async fn decide<F, Fut>(
    request: &EgressCheckRequest,
    key: &[u8],
    now: i64,
    load: F,
) -> Result<EgressCheckResponse, StatusCode>
where
    F: FnOnce(Uuid) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<String>, StatusCode>>,
{
    decide_policy(request, key, now, |tenant| async move {
        load(tenant).await.map_err(|_| "policy_unavailable")
    })
    .await
    .map(|(response, _)| response)
}

#[cfg(test)]
async fn decide_policy<F, Fut>(
    request: &EgressCheckRequest,
    key: &[u8],
    now: i64,
    load: F,
) -> Result<(EgressCheckResponse, &'static str), StatusCode>
where
    F: FnOnce(Uuid) -> Fut,
    Fut: std::future::Future<Output = PolicyResult>,
{
    decide_policy_with_clock(request, key, now, load, || now).await
}

async fn decide_policy_with_clock<F, Fut, Clock>(
    request: &EgressCheckRequest,
    key: &[u8],
    now: i64,
    load: F,
    clock: Clock,
) -> Result<(EgressCheckResponse, &'static str), StatusCode>
where
    F: FnOnce(Uuid) -> Fut,
    Fut: std::future::Future<Output = PolicyResult>,
    Clock: FnOnce() -> i64,
{
    let reason = denial_reason(request, key, now);
    if reason != "not_listed" {
        return Ok((EgressCheckResponse { allow: false }, reason));
    }
    let deadline = tokio::time::Instant::now() + POLICY_DEADLINE;
    let (mut allow, mut reason) =
        match tokio::time::timeout_at(deadline, load(request.tenant_id)).await {
            Ok(Ok(hosts)) => (host_allowed(&request.host, &hosts), "not_listed"),
            Ok(Err(reason)) => (false, reason),
            Err(_) => (false, "policy_timeout"),
        };
    // A cold read can cross the token's expiry second. Cache freshness never
    // extends the caller's capability; recheck before publishing a positive.
    if allow && request.exp <= clock() {
        allow = false;
        reason = "expired";
    }
    if !allow {
        // Identical deadline and frame for absent authority, empty policy,
        // forbidden hosts and dependency failures, on cold AND warm paths.
        tokio::time::sleep_until(deadline).await;
    }
    Ok((EgressCheckResponse { allow }, reason))
}

#[cfg(feature = "enterprise")]
async fn current_hosts(state: &SearchState, tenant: Uuid) -> Result<Vec<String>, StatusCode> {
    use nanosiem_core::enterprise_shared_lookup_store::TenantLookupActor;
    use nanosiem_core::inputlookup::shared::StorageLookupAuthority;
    if !state.auth_state.enterprise_shared {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let runtime = state
        .tenant_lookup_runtime
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    // Match the existing discovery-actor pattern: RLS requires a live tenant
    // member. Borrow an admin only for this read after verifying the service
    // capability; callers cannot choose an actor and no writes are exposed.
    let actor = state
        .auth_state
        .tenant_resolver
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .active_system_settings_actor(tenant)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let Some(actor) = actor else {
        return Ok(Vec::new());
    };
    let store = runtime
        .tenant_lookup_store(tenant, TenantLookupActor::Fixed(actor))
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(store
        .settings()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .hosts())
}
#[cfg(not(feature = "enterprise"))]
async fn current_hosts(_state: &SearchState, _tenant: Uuid) -> Result<Vec<String>, StatusCode> {
    Err(StatusCode::SERVICE_UNAVAILABLE)
}

#[cfg(feature = "enterprise")]
async fn audit_denial(
    state: &SearchState,
    tenant: Uuid,
    host: &str,
    reason: &'static str,
    count: u64,
) -> Result<(), StatusCode> {
    use nanosiem_core::enterprise_shared_lookup_store::TenantLookupActor;
    if !state.auth_state.enterprise_shared {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let actor = state
        .auth_state
        .tenant_resolver
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .active_system_settings_actor(tenant)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    // Unknown tenants have no signed audit boundary; never invent an identity.
    let Some(actor) = actor else {
        return Ok(());
    };
    state
        .tenant_lookup_runtime
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .tenant_lookup_store(tenant, TenantLookupActor::Fixed(actor))
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .audit_egress_denial(host, reason, count)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
#[cfg(not(feature = "enterprise"))]
async fn audit_denial(
    _state: &SearchState,
    _tenant: Uuid,
    _host: &str,
    _reason: &'static str,
    _count: u64,
) -> Result<(), StatusCode> {
    Err(StatusCode::SERVICE_UNAVAILABLE)
}

pub fn router() -> Router<SearchState> {
    Router::new()
        .route("/internal/inputlookup/egress-check", post(check))
        .layer(Extension(Arc::new(PolicyCache::default())))
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .layer(axum::middleware::from_fn(admit))
}
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(check),
    components(schemas(EgressCheckRequest, EgressCheckResponse))
)]
pub struct EgressApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    fn signed_request(tenant: Uuid) -> EgressCheckRequest {
        EgressCheckRequest {
            tenant_id: tenant,
            host: "raw.githubusercontent.com".into(),
            token: egress_auth::sign(&[42; 32], tenant, "raw.githubusercontent.com", 1060).unwrap(),
            exp: 1060,
        }
    }

    #[tokio::test]
    async fn realistic_slow_valid_authority_is_cached_and_tenant_isolated() {
        let cache = PolicyCache::default();
        let tenant = Uuid::new_v4();
        let request = signed_request(tenant);
        let started = Instant::now();
        let (response, _) = decide_policy(&request, &[42; 32], 1000, |id| {
            cache.hosts(id, |_| async {
                // Models control actor resolution plus signed tenant settings.
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(vec!["raw.githubusercontent.com".into()])
            })
        })
        .await
        .unwrap();
        assert!(response.allow);
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < POLICY_DEADLINE);
        eprintln!(
            "NAN-3111 simulated cold allow elapsed: {:?}",
            started.elapsed()
        );
        let started = Instant::now();
        for _ in 0..100 {
            assert!(
                decide_policy(&request, &[42; 32], 1000, |id| {
                    cache.hosts(id, |_| async {
                        panic!("warm policy must not read databases")
                    })
                })
                .await
                .unwrap()
                .0
                .allow
            );
        }
        assert!(started.elapsed() < Duration::from_millis(20));
        eprintln!(
            "NAN-3111 100 warm decisions total elapsed: {:?}",
            started.elapsed()
        );
        let other = signed_request(Uuid::new_v4());
        assert!(
            !decide_policy(&other, &[42; 32], 1000, |id| {
                cache.hosts(id, |_| async { Ok(vec![]) })
            })
            .await
            .unwrap()
            .0
            .allow
        );
        assert!(
            !decide_policy(&request, &[42; 32], 1060, |_| async {
                panic!("expired capability must not access even cached authority")
            })
            .await
            .unwrap()
            .0
            .allow
        );
    }

    #[tokio::test]
    async fn capability_expiring_during_cold_read_cannot_allow() {
        let started = Instant::now();
        let (response, reason) = decide_policy_with_clock(
            &signed_request(Uuid::new_v4()),
            &[42; 32],
            1059,
            |_| async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(vec!["raw.githubusercontent.com".into()])
            },
            || 1060,
        )
        .await
        .unwrap();
        assert!(!response.allow);
        assert_eq!(reason, "expired");
        assert!(started.elapsed() >= POLICY_DEADLINE);
    }

    async fn expire(cache: &PolicyCache, tenant: Uuid) {
        let slot = cache.entries.lock().unwrap().get(&tenant).unwrap().clone();
        slot.lock().await.snapshot.as_mut().unwrap().0 = Instant::now() - POLICY_FRESHNESS;
    }

    #[tokio::test]
    async fn expired_authority_refresh_never_serves_stale_allow() {
        let cache = PolicyCache::default();
        let tenant = Uuid::new_v4();
        for outcome in [Ok(vec![]), Err(StatusCode::SERVICE_UNAVAILABLE)] {
            cache
                .hosts(tenant, |_| async {
                    Ok(vec!["raw.githubusercontent.com".into()])
                })
                .await
                .unwrap();
            expire(&cache, tenant).await;
            let request = signed_request(tenant);
            let started = Instant::now();
            let (response, reason) = decide_policy(&request, &[42; 32], 1000, |id| {
                cache.hosts(id, |_| async { outcome.clone() })
            })
            .await
            .unwrap();
            assert!(
                !response.allow,
                "revoked admin/empty settings/error must revoke cached allow"
            );
            assert_eq!(
                reason,
                if outcome.is_ok() {
                    "not_listed"
                } else {
                    "policy_unavailable"
                }
            );
            assert!(started.elapsed() >= POLICY_DEADLINE);
            expire(&cache, tenant).await;
        }
        cache
            .hosts(tenant, |_| async {
                Ok(vec!["raw.githubusercontent.com".into()])
            })
            .await
            .unwrap();
        expire(&cache, tenant).await;
        let (response, reason) = decide_policy(&signed_request(tenant), &[42; 32], 1000, |id| {
            cache.hosts(id, |_| async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(vec!["raw.githubusercontent.com".into()])
            })
        })
        .await
        .unwrap();
        assert!(!response.allow);
        assert_eq!(reason, "policy_timeout");
    }

    #[tokio::test]
    async fn concurrent_cold_and_expired_refresh_are_single_flight() {
        let cache = Arc::new(PolicyCache::default());
        let tenant = Uuid::new_v4();
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for round in 0..2 {
            let mut tasks = Vec::new();
            for _ in 0..32 {
                let cache = cache.clone();
                let reads = reads.clone();
                tasks.push(tokio::spawn(async move {
                    cache
                        .hosts(tenant, |_| async {
                            reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            Ok(vec!["raw.githubusercontent.com".into()])
                        })
                        .await
                        .unwrap()
                }));
            }
            for task in tasks {
                assert_eq!(task.await.unwrap(), vec!["raw.githubusercontent.com"]);
            }
            assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), round + 1);
            expire(&cache, tenant).await;
        }
    }

    #[tokio::test]
    async fn concurrent_endpoint_timeouts_are_cached_and_cancellation_recovers() {
        let cache = Arc::new(PolicyCache::default());
        let tenant = Uuid::new_v4();
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let cache = cache.clone();
            let reads = reads.clone();
            tasks.push(tokio::spawn(async move {
                decide_policy(&signed_request(tenant), &[42; 32], 1000, |id| {
                    cache.hosts(id, |_| async {
                        reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        Ok(vec!["raw.githubusercontent.com".into()])
                    })
                })
                .await
                .unwrap()
            }));
        }
        for task in tasks {
            let (response, reason) = task.await.unwrap();
            assert!(!response.allow);
            assert_eq!(reason, "policy_timeout");
        }
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            cache
                .hosts(tenant, |_| async {
                    panic!("timeout snapshot must suppress retries")
                })
                .await,
            Err("policy_timeout")
        );
        expire(&cache, tenant).await;
        let cancel_cache = cache.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            cancel_cache
                .hosts(tenant, |_| async {
                    started.send(()).unwrap();
                    std::future::pending::<Result<Vec<String>, StatusCode>>().await
                })
                .await
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        // Cancellation drops the slot lock; the old expired value cannot allow.
        assert_eq!(
            cache.hosts(tenant, |_| async { Ok(vec![]) }).await.unwrap(),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn cache_cardinality_is_bounded_and_expired_slots_are_reclaimed() {
        let cache = PolicyCache::default();
        let first = Uuid::new_v4();
        cache.hosts(first, |_| async { Ok(vec![]) }).await.unwrap();
        for _ in 1..POLICY_CACHE_CAPACITY {
            cache
                .hosts(Uuid::new_v4(), |_| async { Ok(vec![]) })
                .await
                .unwrap();
        }
        assert_eq!(
            cache
                .hosts(Uuid::new_v4(), |_| async { panic!("full cache must deny") })
                .await,
            Err("policy_unavailable")
        );
        expire(&cache, first).await;
        cache
            .hosts(Uuid::new_v4(), |_| async { Ok(vec![]) })
            .await
            .unwrap();
        assert_eq!(cache.entries.lock().unwrap().len(), POLICY_CACHE_CAPACITY);
        assert!(!cache.entries.lock().unwrap().contains_key(&first));
    }

    #[test]
    fn denial_aggregation_is_scoped_bounded_and_counts_quiet_windows() {
        let mut rate = DenialRate::default();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(rate.count(a, "intel.example.com", "bad_token"));
        for _ in 0..100 {
            assert!(!rate.count(a, "intel.example.com", "bad_token"));
        }
        assert!(rate.count(b, "intel.example.com", "bad_token"));
        assert!(rate.count(a, "intel.example.com", "expired"));
        assert!(rate.count(a, "other.example.com", "bad_token"));
        // The minute timer drains even without another incoming request.
        assert_eq!(rate.take(a, "intel.example.com", "bad_token"), Some(101));
        assert_eq!(rate.take(a, "intel.example.com", "bad_token"), None);
        assert_eq!(rate.take(b, "intel.example.com", "bad_token"), Some(1));
        assert!(rate.count(a, "intel.example.com", "bad_token"));
        while rate.entries.len() < 4096 {
            assert!(rate.count(Uuid::new_v4(), "intel.example.com", "not_listed"));
        }
        assert!(!rate.count(Uuid::new_v4(), "intel.example.com", "not_listed"));
        assert_eq!(rate.entries.len(), 4096);
    }

    #[tokio::test]
    async fn denial_timer_writes_one_counted_event_even_when_traffic_stops() {
        let rate = Arc::new(Mutex::new(DenialRate::default()));
        let tenant = Uuid::new_v4();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        for _ in 0..10 {
            let sender = sender.clone();
            queue_denial(
                rate.clone(),
                tenant,
                "intel.example.com".into(),
                "not_listed",
                Duration::from_millis(20),
                move |count| async move {
                    sender.send(count).unwrap();
                    Ok(())
                },
            );
        }
        assert!(receiver.try_recv().is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .unwrap(),
            Some(10)
        );
        assert!(
            receiver.try_recv().is_err(),
            "repeats schedule only one writer"
        );
        assert!(rate.lock().unwrap().entries.is_empty());
        queue_denial(
            rate.clone(),
            tenant,
            "intel.example.com".into(),
            "not_listed",
            Duration::from_millis(20),
            move |count| async move {
                sender.send(count).unwrap();
                Ok(())
            },
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .unwrap(),
            Some(1)
        );
    }

    #[test]
    fn denial_reason_distinguishes_authenticated_expiry_without_logging_tokens() {
        let key = [42; 32];
        let tenant = Uuid::new_v4();
        let mut request = EgressCheckRequest {
            tenant_id: tenant,
            host: "intel.example.com".into(),
            token: egress_auth::sign(&key, tenant, "intel.example.com", 1060).unwrap(),
            exp: 1060,
        };
        assert_eq!(denial_reason(&request, &key, 1000), "not_listed");
        assert_eq!(denial_reason(&request, &key, 1060), "expired");
        request.token = "invalid".into();
        assert_eq!(denial_reason(&request, &key, 1060), "bad_token");
        request.host = "intel.example.com/?signature=secret".into();
        assert_eq!(
            nanosiem_core::inputlookup::shared::audit_host(&request.host),
            "invalid"
        );
    }

    #[test]
    fn helper_admission_bounds_rate_and_concurrency() {
        let gate = Admission::new();
        let now = Instant::now();
        let permits: Vec<_> = (0..32).map(|_| gate.enter(now).unwrap()).collect();
        assert_eq!(gate.enter(now).unwrap_err(), StatusCode::TOO_MANY_REQUESTS);
        drop(permits);
        for _ in 32..128 {
            drop(gate.enter(now).unwrap());
        }
        assert_eq!(gate.enter(now).unwrap_err(), StatusCode::TOO_MANY_REQUESTS);
        assert!(gate.enter(now + Duration::from_secs(1)).is_ok());
        assert_eq!(gate.arrivals.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn endpoint_tenant_binding_current_policy_and_expiry() {
        let key = [42; 32];
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        for tenant in [a, b] {
            let request = EgressCheckRequest {
                tenant_id: tenant,
                host: "intel.example.com".into(),
                token: egress_auth::sign(&key, tenant, "intel.example.com", 1060).unwrap(),
                exp: 1060,
            };
            let result = decide(&request, &key, 1000, |id| async move {
                Ok(if id == a {
                    vec!["*.example.com".into()]
                } else {
                    vec![]
                })
            })
            .await
            .unwrap();
            assert_eq!(result.allow, tenant == a);
            assert!(
                !decide(&request, &key, 1000, |_| async { Ok(vec![]) })
                    .await
                    .unwrap()
                    .allow,
                "removed entry revokes authorization"
            );
            assert!(
                !decide(&request, &key, 1060, |_| async {
                    panic!("expired token must not read DB")
                })
                .await
                .unwrap()
                .allow
            );
        }
        let request = EgressCheckRequest {
            tenant_id: b,
            host: "intel.example.com".into(),
            token: egress_auth::sign(&key, a, "intel.example.com", 1060).unwrap(),
            exp: 1060,
        };
        assert!(
            !decide(&request, &key, 1000, |_| async {
                panic!("spoofed tenant must not read DB")
            })
            .await
            .unwrap()
            .allow
        );
    }
    #[tokio::test]
    async fn denied_policy_reads_have_uniform_deadline() {
        let key = [42; 32];
        let tenant = Uuid::new_v4();
        let request = EgressCheckRequest {
            tenant_id: tenant,
            host: "intel.example.com".into(),
            token: egress_auth::sign(&key, tenant, "intel.example.com", 1060).unwrap(),
            exp: 1060,
        };
        for delay_ms in [0, 5, 30] {
            let started = tokio::time::Instant::now();
            let result = decide(&request, &key, 1000, |_| async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                Ok(vec![])
            })
            .await
            .unwrap();
            assert!(!result.allow);
            assert!(
                started.elapsed() >= POLICY_DEADLINE,
                "unknown tenants and disallowed hosts must share the denial deadline"
            );
        }
    }

    #[tokio::test]
    async fn failed_or_slow_policy_reads_deny_without_an_oracle() {
        let key = [42; 32];
        let tenant = Uuid::new_v4();
        let request = EgressCheckRequest {
            tenant_id: tenant,
            host: "intel.example.com".into(),
            token: egress_auth::sign(&key, tenant, "intel.example.com", 1060).unwrap(),
            exp: 1060,
        };
        let started = tokio::time::Instant::now();
        let result = decide(&request, &key, 1000, |_| async {
            Err(StatusCode::SERVICE_UNAVAILABLE)
        })
        .await
        .unwrap();
        assert!(!result.allow);
        assert!(started.elapsed() >= POLICY_DEADLINE);
        let result = decide(&request, &key, 1000, |_| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(vec!["intel.example.com".into()])
        })
        .await
        .unwrap();
        assert!(!result.allow, "a late positive policy must not authorize");
    }

    #[tokio::test]
    async fn helper_http1_response_has_exact_bytes_and_content_length() {
        let app = Router::new()
            .route(
                "/allow",
                post(|| async { EgressCheckResponse { allow: true } }),
            )
            .route(
                "/deny",
                post(|| async { EgressCheckResponse { allow: false } }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .build()
            .unwrap();
        for (path, body) in [("allow", "{\"allow\":true}"), ("deny", "{\"allow\":false}")] {
            let response = client
                .post(format!("http://{addr}/{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.version(), reqwest::Version::HTTP_11);
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[axum::http::header::CONTENT_LENGTH],
                body.len().to_string()
            );
            assert!(!response
                .headers()
                .contains_key(axum::http::header::TRANSFER_ENCODING));
            assert_eq!(response.bytes().await.unwrap().as_ref(), body.as_bytes());
        }
        server.abort();
    }

    #[test]
    fn internal_openapi_contract() {
        use utoipa::OpenApi;
        let spec = EgressApiDoc::openapi();
        let json = serde_json::to_value(spec).unwrap();
        let post = &json["paths"]["/internal/inputlookup/egress-check"]["post"];
        assert_eq!(
            post["security"][0],
            serde_json::json!({"egress_service_bearer":[]})
        );
        assert!(post["responses"].get("200").is_some());
        for status in ["401", "408", "429", "503"] {
            assert!(post["responses"].get(status).is_some());
        }
    }
}

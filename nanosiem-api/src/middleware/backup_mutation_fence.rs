// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cluster-wide API mutation fence for consistent cross-store backups.

use axum::{
    body::Body,
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::Response,
};
use futures::StreamExt;
use nanosiem_api_lib::ApiError;
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Session/xact advisory lock shared with `scripts/nano-upgrade.py`.
const BACKUP_MUTATION_LOCK_ID: i64 = 5_000_003;
const BACKUP_MUTATION_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock_shared($1)";

/// One connection per API process, independent of concurrent request count.
/// The previous per-request pool had four connections, so request five waited
/// for an entire earlier handler (including uploads and streams) to finish.
const FENCE_LOCK_POOL_CONNECTIONS: u32 = 1;
const FENCE_LOCK_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct FenceState {
    in_flight: usize,
    transaction: Option<Transaction<'static, Postgres>>,
}

struct FenceInner {
    check_pool: PgPool,
    lock_pool: PgPool,
    state: Mutex<FenceState>,
}

/// Process-local admission counter backed by one cluster-visible shared lock.
///
/// The first accepted mutation acquires the PostgreSQL advisory lock. Later
/// mutations share that lock and only perform a short flag read on the normal
/// handler pool. The last mutation releases it. Thus the coordinator still
/// drains every in-flight mutation on every API replica, without holding one
/// dedicated database connection per request.
#[derive(Clone)]
pub struct BackupMutationFence {
    inner: Arc<FenceInner>,
}

impl BackupMutationFence {
    pub fn new(check_pool: PgPool, database_url: &str) -> Self {
        let lock_pool = PgPoolOptions::new()
            .max_connections(FENCE_LOCK_POOL_CONNECTIONS)
            .acquire_timeout(FENCE_LOCK_ACQUIRE_TIMEOUT)
            .connect_lazy(database_url)
            .expect("validated DATABASE_URL must create the backup mutation lock pool");
        Self {
            inner: Arc::new(FenceInner {
                check_pool,
                lock_pool,
                state: Mutex::new(FenceState::default()),
            }),
        }
    }

    async fn enter(&self) -> Result<Option<MutationLease>, sqlx::Error> {
        let mut state = self.inner.state.lock().await;

        if state.transaction.is_some() {
            // The shared advisory lock is already held, so this flag read is
            // the linearization point against the coordinator setting active.
            if fence_active_on_pool(&self.inner.check_pool).await? {
                return Ok(None);
            }
            state.in_flight += 1;
            return Ok(Some(MutationLease::new(self.clone())));
        }

        let mut transaction = self.inner.lock_pool.begin().await?;
        if fence_active_in_transaction(&mut transaction).await? {
            return Ok(None);
        }
        sqlx::query(BACKUP_MUTATION_LOCK_SQL)
            .bind(BACKUP_MUTATION_LOCK_ID)
            .execute(&mut *transaction)
            .await?;
        // The coordinator sets the flag before taking its exclusive lock. If
        // it won the advisory-lock race, this recheck rejects the request.
        if fence_active_in_transaction(&mut transaction).await? {
            return Ok(None);
        }

        state.in_flight = 1;
        state.transaction = Some(transaction);
        Ok(Some(MutationLease::new(self.clone())))
    }

    async fn release_one(&self) {
        let mut state = self.inner.state.lock().await;
        if state.in_flight == 0 {
            tracing::error!("backup mutation fence lease accounting underflow");
            return;
        }
        state.in_flight -= 1;
        if state.in_flight != 0 {
            return;
        }

        let Some(transaction) = state.transaction.take() else {
            tracing::error!("backup mutation fence lost its shared-lock transaction");
            return;
        };
        // Rollback is intentional: this transaction only owns the shared xact
        // lock. Hold the local mutex until release completes so the next first
        // mutation cannot queue behind the one-connection lock pool.
        if let Err(error) = transaction.rollback().await {
            tracing::error!(%error, "backup mutation fence transaction rollback failed");
        }
    }
}

struct MutationLease {
    fence: Option<BackupMutationFence>,
}

impl MutationLease {
    fn new(fence: BackupMutationFence) -> Self {
        Self { fence: Some(fence) }
    }

    async fn release(mut self) {
        if let Some(fence) = self.fence.take() {
            fence.release_one().await;
        }
    }
}

impl Drop for MutationLease {
    fn drop(&mut self) {
        if let Some(fence) = self.fence.take() {
            // Request cancellation must not strand the process-wide shared
            // lock. The normal response path awaits release directly.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move { fence.release_one().await });
            } else {
                tracing::error!(
                    "backup mutation fence lease dropped outside a Tokio runtime; pool shutdown must release the lock"
                );
            }
        }
    }
}

fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn is_oidc_callback(path: &str) -> bool {
    let Some(suffix) = path.strip_prefix("/api/auth/oidc/") else {
        return false;
    };
    let mut segments = suffix.split('/');
    matches!(
        (segments.next(), segments.next(), segments.next()),
        (Some(provider), Some("callback"), None) if !provider.is_empty()
    )
}

fn is_authentication_lifecycle(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::POST, "/api/auth/login")
            | (&Method::POST, "/api/auth/logout")
            | (&Method::POST, "/api/auth/refresh")
            | (&Method::POST, "/api/auth/mfa/challenge")
            | (&Method::POST, "/api/auth/mfa/setup")
            | (&Method::POST, "/api/auth/mfa/verify-setup")
            | (&Method::POST, "/api/auth/mfa/backup-codes")
            | (&Method::DELETE, "/api/auth/mfa")
    ) || (*method == Method::POST && is_oidc_callback(path))
}

fn is_fence_exempt(method: &Method, path: &str) -> bool {
    // Authentication remains available during backup. Its authoritative
    // credential/session/MFA state is PostgreSQL-only, and its audit events
    // are append-only records with no PG-to-CH pointer invariant. Landing
    // those writes on either side of a snapshot boundary cannot create a torn
    // business object in the recovery set.
    is_safe_method(method) || is_authentication_lifecycle(method, path)
}

async fn fence_active_on_pool(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT active FROM backup_mutation_fence WHERE singleton = true")
        .fetch_one(pool)
        .await
}

async fn fence_active_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT active FROM backup_mutation_fence WHERE singleton = true")
        .fetch_one(&mut **transaction)
        .await
}

fn unavailable() -> ApiError {
    ApiError::ServiceUnavailable(
        "API mutations are temporarily paused for a consistent backup".to_string(),
    )
}

fn response_with_lease(response: Response, lease: MutationLease) -> Response {
    let (parts, body) = response.into_parts();
    let mut data = body.into_data_stream();
    let guarded = async_stream::stream! {
        while let Some(chunk) = data.next().await {
            yield chunk;
        }
        lease.release().await;
    };
    Response::from_parts(parts, Body::from_stream(guarded))
}

/// Reject new cross-store mutations while a recovery-set snapshot is active.
/// Database errors remain fail-closed and retain their cause in error logs.
pub async fn backup_mutation_fence(
    State(fence): State<BackupMutationFence>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if is_fence_exempt(&method, &path) {
        return Ok(next.run(request).await);
    }

    let Some(lease) = fence.enter().await.map_err(|error| {
        tracing::error!(%error, %method, %path, "backup mutation fence database unavailable; failing closed");
        unavailable()
    })? else {
        return Err(unavailable());
    };

    // Keep the lease until the response body finishes, not merely until the
    // handler constructs a Response. SSE handlers continue doing PG/CH work
    // after returning their headers, so releasing here would let a backup cut
    // through an active notebook/meloD stream.
    Ok(response_with_lease(next.run(request).await, lease))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_methods_bypass_the_mutation_fence() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(is_fence_exempt(&method, "/api/rules"));
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(!is_fence_exempt(&method, "/api/rules"));
        }
    }

    #[test]
    fn exact_authentication_lifecycle_routes_bypass_the_fence() {
        for (method, path) in [
            (Method::POST, "/api/auth/login"),
            (Method::POST, "/api/auth/logout"),
            (Method::POST, "/api/auth/refresh"),
            (Method::POST, "/api/auth/mfa/challenge"),
            (Method::POST, "/api/auth/mfa/setup"),
            (Method::POST, "/api/auth/mfa/verify-setup"),
            (Method::POST, "/api/auth/mfa/backup-codes"),
            (Method::DELETE, "/api/auth/mfa"),
            (Method::POST, "/api/auth/oidc/acme/callback"),
        ] {
            assert!(is_fence_exempt(&method, path), "{method} {path}");
        }
    }

    #[test]
    fn auth_prefixes_and_admin_security_mutations_remain_fenced() {
        for (method, path) in [
            (Method::POST, "/api/auth/login/extra"),
            (Method::PUT, "/api/auth/password"),
            (Method::DELETE, "/api/admin/users/id/mfa"),
            (Method::PUT, "/api/settings/mfa-required"),
            (Method::POST, "/api/auth/oidc/acme/callback/extra"),
        ] {
            assert!(!is_fence_exempt(&method, path), "{method} {path}");
        }
    }

    #[tokio::test]
    async fn concurrent_mutations_use_one_dedicated_lock_connection_per_process() {
        let check_pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1/unused")
            .unwrap();
        let fence = BackupMutationFence::new(check_pool, "postgres://unused@127.0.0.1/unused");
        assert_eq!(
            fence.inner.lock_pool.options().get_max_connections(),
            FENCE_LOCK_POOL_CONNECTIONS
        );
        assert_eq!(
            fence.inner.lock_pool.options().get_acquire_timeout(),
            FENCE_LOCK_ACQUIRE_TIMEOUT
        );
        assert_eq!(FENCE_LOCK_POOL_CONNECTIONS, 1);
    }

    #[tokio::test]
    async fn response_body_owns_the_lease_until_stream_completion() {
        let check_pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1/unused")
            .unwrap();
        let fence = BackupMutationFence::new(check_pool, "postgres://unused@127.0.0.1/unused");
        // No database transaction is needed for this ownership test. The
        // missing transaction deliberately exercises only the counter path.
        fence.inner.state.lock().await.in_flight = 1;
        let response = response_with_lease(
            Response::new(Body::from("complete")),
            MutationLease::new(fence.clone()),
        );

        assert_eq!(fence.inner.state.lock().await.in_flight, 1);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"complete");
        assert_eq!(fence.inner.state.lock().await.in_flight, 0);
    }

    #[test]
    fn accepted_mutations_use_the_shared_cluster_drain_lock() {
        assert_eq!(
            BACKUP_MUTATION_LOCK_SQL,
            "SELECT pg_advisory_xact_lock_shared($1)"
        );
    }
}

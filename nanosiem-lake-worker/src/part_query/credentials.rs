// SPDX-License-Identifier: AGPL-3.0-or-later

//! `query[T]` credential refresh (NAN-3017).
//!
//! The query role used to exchange its bootstrap token once at startup and
//! hold the resulting R2 read credential for the life of the process. Since
//! NAN-3008 query is resident, so after the credential's TTL (6 h) every R2
//! read failed with `PermissionDenied` and search returned 503 until the
//! process was restarted by hand.
//!
//! Now:
//! - [`R2ReadAuthority`] holds the tenant read operator behind an atomic
//!   swap; every reader (`LayeredStore`'s part-log reads, the verified cache's
//!   ranged GETs) takes the current operator per request.
//! - [`QueryCredentialSwap`] runs the re-exchange when the supervisor answers
//!   a refresh request and swaps the operator (and the IOC store) in place.
//! - The shared [`CredentialRefresher`] schedules refreshes at 2/3 of the
//!   TTL; a `PermissionDenied` read asks for one immediately
//!   ([`R2ReadAuthority::recover`]) and is retried once on the new operator.
//! - A read still refused is [`CredentialStale`], which the engine maps to a
//!   retryable 503, never a permanent 500.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use arc_swap::ArcSwap;
use nanosiem_lake_cell::contract::Role;

use crate::cell_refresh::{is_permission_denied, CredentialRefresher};
use crate::part_ingest::s3_store::S3ObjectStore;

use super::server::{ioc_location, r2_operator, resolve_bootstrap, QueryBootstrap};

/// How long a refused read waits for a refreshed credential before it
/// fails retryably (covers the supervisor's 60 s mint rate limit only
/// partly on purpose: a search should not hang for a minute).
pub const RECOVER_WAIT: Duration = Duration::from_secs(30);

/// Marker text of [`CredentialStale`]; errors that lose their type through a
/// cache or a string boundary are still classified by it.
pub const CREDENTIAL_STALE: &str = "object-store credential refused (stale; refresh pending)";

/// A read refused by the store even after a refresh attempt.
#[derive(Debug, thiserror::Error)]
#[error("{CREDENTIAL_STALE}: {0}")]
pub struct CredentialStale(pub String);

/// Is this error a refused (expired/revoked) storage credential?
pub fn is_credential_stale(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CredentialStale>().is_some() || is_permission_denied(error)
}

/// The text form, for errors already flattened to a string.
pub fn text_is_credential_stale(text: &str) -> bool {
    text.contains(CREDENTIAL_STALE) || text.contains("PermissionDenied")
}

/// One installed operator and its swap generation.
pub struct Installed {
    pub generation: u64,
    pub operator: opendal::Operator,
}

/// The tenant bucket read operator, swappable in place.
pub struct R2ReadAuthority {
    bucket: String,
    current: ArcSwap<Installed>,
    refresher: Option<Arc<CredentialRefresher>>,
}

impl R2ReadAuthority {
    /// `refresher: None` (labs, tests): a refused read fails at once.
    pub fn new(bucket: impl Into<String>, operator: opendal::Operator, refresher: Option<Arc<CredentialRefresher>>) -> Arc<Self> {
        Arc::new(Self {
            bucket: bucket.into(),
            current: ArcSwap::from_pointee(Installed { generation: 0, operator }),
            refresher,
        })
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn current(&self) -> Arc<Installed> {
        self.current.load_full()
    }

    /// Install a refreshed operator; in-flight readers keep theirs, every
    /// later read takes this one.
    pub fn replace(&self, operator: opendal::Operator) {
        let generation = self.current.load().generation + 1;
        self.current.store(Arc::new(Installed { generation, operator }));
    }

    /// A read on generation `seen` was refused. Returns a newer operator,
    /// asking for (and waiting up to [`RECOVER_WAIT`] for) a refresh when
    /// none is installed yet; `None` when no newer credential arrived.
    pub async fn recover(&self, seen: u64) -> Option<Arc<Installed>> {
        self.recover_within(seen, RECOVER_WAIT).await
    }

    pub async fn recover_within(&self, seen: u64, wait: Duration) -> Option<Arc<Installed>> {
        let refresher = self.refresher.as_ref();
        // Read the refresh generation before the operator: a swap installs
        // the operator first, then bumps the generation.
        let generation = refresher.map(|r| r.generation());
        let current = self.current();
        if current.generation != seen {
            return Some(current);
        }
        let (refresher, generation) = (refresher?, generation?);
        tracing::warn!(bucket = %self.bucket, "object-store read refused; refreshing the query credential");
        refresher.request_now();
        refresher.wait_newer(generation, wait).await;
        let current = self.current();
        (current.generation != seen).then_some(current)
    }
}

/// Everything the query process swaps when a refresh secret arrives.
pub struct QueryCredentialSwap {
    pub tenant_id: String,
    pub cell_id: String,
    pub control_url: Option<String>,
    pub role: Role,
    pub bucket: String,
    pub r2: Option<Arc<R2ReadAuthority>>,
    pub ioc: Option<Arc<S3ObjectStore>>,
    /// The `job_results` grant (NAN-3042): swapped, installed (a grant that
    /// appears on refresh) or withdrawn with the other credentials.
    pub job_results: Option<Arc<super::job_results::JobResultStore>>,
    pub refresher: Arc<CredentialRefresher>,
}

impl QueryCredentialSwap {
    /// Swap a validated bootstrap into the live stores; returns its expiry.
    pub fn apply(&self, boot: &QueryBootstrap) -> Result<chrono::DateTime<chrono::Utc>> {
        ensure!(boot.tenant_id == self.tenant_id && boot.bucket == self.bucket,
            "refreshed query credential names another tenant or bucket");
        let expires = boot.expires_at.context("refreshed query exchange carries no expiry")?;
        // Build every operator before installing any (all or nothing).
        let r2 = match (&self.r2, &boot.r2) {
            (Some(authority), Some(credentials)) => Some((authority, r2_operator(&boot.bucket, credentials)?)),
            (None, None) => None,
            _ => bail!("refreshed query exchange changed read-credential presence"),
        };
        let ioc = match (&self.ioc, &boot.enrichment_r2) {
            (Some(store), Some(credentials)) => Some((store, ioc_location(boot, credentials))),
            (Some(_), None) => {
                tracing::warn!("refreshed query exchange has no enrichment_reader; the IOC reader keeps its old credential until it expires");
                None
            }
            (None, _) => None,
        };
        let job_results = match (&self.job_results, &boot.job_results_r2) {
            (Some(store), Some(credentials)) => Some((store, Some(store.operator_for(credentials)?))),
            (Some(store), None) => {
                if store.is_granted() {
                    tracing::warn!("refreshed query exchange has no job_results; durable search jobs are unavailable until it returns");
                }
                Some((store, None))
            }
            (None, _) => None,
        };
        if let Some((authority, operator)) = r2 {
            authority.replace(operator);
        }
        if let Some((store, location)) = ioc {
            store.replace(&location)?;
        }
        if let Some((store, operator)) = job_results {
            store.install(operator);
        }
        Ok(expires)
    }

    /// `TenantService::secrets` for query: exchange, swap, reschedule.
    pub async fn on_secret(&self, secret: &[u8]) {
        let result = async {
            let boot = resolve_bootstrap(secret, &self.tenant_id, &self.cell_id, self.control_url.as_deref(), self.role).await?;
            self.apply(&boot)
        }.await;
        match result {
            Ok(expires_at) => {
                self.refresher.refreshed(expires_at);
                tracing::info!(%expires_at, "query credentials refreshed");
            }
            Err(error) => {
                let is_final = error
                    .downcast_ref::<crate::part_ingest::cell::ExchangeRefused>()
                    .is_some_and(crate::part_ingest::cell::ExchangeRefused::is_final);
                let retrying = self.refresher.failed(is_final);
                tracing::error!(error = %format!("{error:#}"), retrying, "query credential refresh failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell_refresh::SecretRequester;
    use crate::parts::part_log::ObjectStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// An S3 stand-in that accepts exactly one access key: requests signed
    /// with any other key get R2's 403 `AccessDenied` (an expired key).
    struct FakeR2 {
        endpoint: String,
        valid: Arc<Mutex<String>>,
        served: Arc<AtomicUsize>,
        denied: Arc<AtomicUsize>,
    }

    async fn fake_r2(valid: &str) -> FakeR2 {
        use axum::{http::{HeaderMap, StatusCode}, response::IntoResponse, Router};
        let valid = Arc::new(Mutex::new(valid.to_string()));
        let (served, denied) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let state = (valid.clone(), served.clone(), denied.clone());
        let app = Router::new().fallback(move |headers: HeaderMap| {
            let (valid, served, denied) = state.clone();
            async move {
                let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                let key = valid.lock().unwrap().clone();
                if auth.contains(&format!("Credential={key}/")) {
                    served.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, b"entry-bytes".to_vec()).into_response()
                } else {
                    denied.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::FORBIDDEN, [("content-type", "application/xml")],
                        b"<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>".to_vec()).into_response()
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        FakeR2 { endpoint, valid, served, denied }
    }

    fn operator(endpoint: &str, key: &str) -> opendal::Operator {
        let builder = opendal::services::S3::default()
            .bucket("nano-shared-r2-test").region("auto").endpoint(endpoint)
            .access_key_id(key).secret_access_key("secret")
            .disable_config_load().disable_ec2_metadata();
        opendal::Operator::new(builder).unwrap().finish()
    }

    /// Stands in for supervisor + exchange: every request mints the next
    /// key, makes it the only one the store accepts, installs it and
    /// reports it refreshed (what `QueryCredentialSwap::on_secret` does).
    struct Rotating {
        fake_valid: Arc<Mutex<String>>,
        endpoint: String,
        authority: Mutex<Option<Arc<R2ReadAuthority>>>,
        refresher: Arc<CredentialRefresher>,
        ttl: chrono::Duration,
        requests: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SecretRequester for Arc<Rotating> {
        async fn request_secrets(&self) -> std::io::Result<()> {
            let n = self.requests.fetch_add(1, Ordering::SeqCst) + 2;
            let key = format!("key{n}");
            *self.fake_valid.lock().unwrap() = key.clone();
            let authority = self.authority.lock().unwrap().clone().unwrap();
            authority.replace(operator(&self.endpoint, &key));
            self.refresher.refreshed(chrono::Utc::now() + self.ttl);
            Ok(())
        }
    }

    fn rotating(fake: &FakeR2, refresher: &Arc<CredentialRefresher>, ttl: chrono::Duration) -> (Arc<R2ReadAuthority>, Arc<Rotating>) {
        let authority = R2ReadAuthority::new("nano-shared-r2-test", operator(&fake.endpoint, "key1"), Some(refresher.clone()));
        let rotating = Arc::new(Rotating {
            fake_valid: fake.valid.clone(), endpoint: fake.endpoint.clone(),
            authority: Mutex::new(Some(authority.clone())), refresher: refresher.clone(), ttl,
            requests: AtomicUsize::new(0),
        });
        (authority, rotating)
    }

    const KEY: &str = "lake/parts/v1/tenant=6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00/log/entries/00000000000000000001.json";

    /// The live bug: a short-TTL credential expires under a resident query
    /// process. The refresher re-exchanges before expiry, so a read after the
    /// original key is dead still succeeds, and never sees a 403.
    #[tokio::test]
    async fn query_keeps_reading_after_its_short_ttl_credential_expires() {
        let fake = fake_r2("key1").await;
        let ttl = chrono::Duration::seconds(2);
        let refresher = CredentialRefresher::new(chrono::Utc::now() + ttl);
        refresher.set_poll(Duration::from_millis(50));
        let (authority, rotating) = rotating(&fake, &refresher, chrono::Duration::hours(6));
        let store = super::super::fetch::R2ReadStore::new(authority.clone());
        assert_eq!(store.get(KEY).await.unwrap().as_deref(), Some(&b"entry-bytes"[..]));
        let task = tokio::spawn(refresher.clone().run(rotating.clone()));
        // Past the original expiry: key1 is no longer accepted anywhere.
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_ne!(*fake.valid.lock().unwrap(), "key1", "the key rotated before the old one expired");
        assert_eq!(store.get(KEY).await.unwrap().as_deref(), Some(&b"entry-bytes"[..]));
        assert_eq!(rotating.requests.load(Ordering::SeqCst), 1, "one scheduled refresh");
        assert_eq!(fake.denied.load(Ordering::SeqCst), 0, "no read ever used the dead key");
        assert!(authority.current().generation >= 1);
        task.abort();
    }

    /// A key revoked early (or a lost refresh) surfaces as PermissionDenied:
    /// the read asks for a refresh at once and retries once on the new key.
    #[tokio::test]
    async fn permission_denied_triggers_a_refresh_and_one_retry() {
        let fake = fake_r2("key1").await;
        let refresher = CredentialRefresher::new(chrono::Utc::now() + chrono::Duration::hours(6));
        refresher.set_poll(Duration::from_millis(50));
        let (authority, rotating) = rotating(&fake, &refresher, chrono::Duration::hours(6));
        let task = tokio::spawn(refresher.clone().run(rotating.clone()));
        let store = super::super::fetch::R2ReadStore::new(authority.clone());
        // Revoke key1 behind the process's back.
        *fake.valid.lock().unwrap() = "revoked-everything".into();
        // The fake's rotation installs key2 and makes the store accept it.
        let bytes = tokio::time::timeout(Duration::from_secs(10), store.get(KEY)).await.unwrap().unwrap();
        assert_eq!(bytes.as_deref(), Some(&b"entry-bytes"[..]));
        assert_eq!(rotating.requests.load(Ordering::SeqCst), 1, "exactly one urgent refresh");
        assert_eq!(fake.denied.load(Ordering::SeqCst), 1, "one refused read, then the retry succeeded");
        assert_eq!(fake.served.load(Ordering::SeqCst), 1);
        task.abort();
    }

    /// No refreshed credential arrives: the refusal is a typed, retryable
    /// `CredentialStale` (503), never `internal` (500).
    #[tokio::test]
    async fn refused_read_without_a_refresh_is_retryable_not_internal() {
        let fake = fake_r2("someone-else").await;
        let refresher = CredentialRefresher::new(chrono::Utc::now() + chrono::Duration::hours(6));
        let authority = R2ReadAuthority::new("nano-shared-r2-test", operator(&fake.endpoint, "key1"), Some(refresher.clone()));
        assert!(authority.recover_within(0, Duration::from_millis(100)).await.is_none());
        let store = super::super::fetch::R2ReadStore::new(R2ReadAuthority::new("b", operator(&fake.endpoint, "key1"), None));
        let error = store.get(KEY).await.unwrap_err();
        assert!(error.downcast_ref::<CredentialStale>().is_some(), "{error:#}");
        assert!(is_credential_stale(&error));
        let mapped = super::super::engine::internal_text(format!("{error:#}"));
        assert_eq!(mapped.status(), 503, "{mapped}");
        assert_eq!(super::super::engine::internal_text("boom".into()).status(), 500);
    }

    fn exchange(expiry: &str, bucket: &str) -> QueryBootstrap {
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let response: super::super::server::QueryExchangeResponse = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "tenant_id": tenant, "role": "query",
            "credentials": [{"credential_class": "lake_part_read", "endpoint": "https://objects.invalid", "region": "auto",
                "bucket": bucket, "permission": "object-read-only", "prefixes": [format!("lake/parts/v1/tenant={tenant}/")],
                "access_key_id": "fresh", "secret_access_key": "s", "session_token": "t", "expires_at": expiry}],
            "trusted_keys": [],
            "query_engine": {"chdb_library": "/l", "chdb_sha256": "0", "compiler": "/c"},
        })).unwrap();
        super::super::server::bootstrap_from_exchange(response, tenant, Role::Query).unwrap()
    }

    #[test]
    fn swap_installs_the_refreshed_operator_and_reports_its_expiry() {
        let boot = exchange("2026-09-29T15:00:00Z", "nano-shared-r2-t");
        assert_eq!(boot.expires_at.unwrap().to_rfc3339(), "2026-09-29T15:00:00+00:00");
        let refresher = CredentialRefresher::new(chrono::Utc::now() + chrono::Duration::hours(6));
        let authority = R2ReadAuthority::new("nano-shared-r2-t", operator("http://127.0.0.1:1", "old"), Some(refresher.clone()));
        let swap = QueryCredentialSwap {
            tenant_id: boot.tenant_id.clone(), cell_id: "c".into(), control_url: None, role: Role::Query,
            bucket: "nano-shared-r2-t".into(), r2: Some(authority.clone()), ioc: None, job_results: None, refresher,
        };
        assert_eq!(swap.apply(&boot).unwrap(), boot.expires_at.unwrap());
        assert_eq!(authority.current().generation, 1);
        let other = exchange("2026-09-29T15:00:00Z", "another-bucket");
        assert!(swap.apply(&other).is_err(), "a refresh never moves the process to another bucket");
        assert_eq!(authority.current().generation, 1);
    }
}

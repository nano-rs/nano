// SPDX-License-Identifier: AGPL-3.0-or-later

//! `query[T]` durable job-result storage (NAN-3042).
//!
//! The cell supervisor clears every child's environment, so query[T] cannot
//! be handed result-storage settings through `NANO_LAKE_CELL_RESULT_ROOT` /
//! `NANO_LAKE_RESULT_S3_*` (it used to fall back to `file://` and
//! `lake_job_runner` refused every such manifest). The grant now rides in the
//! credential exchange like every other per-tenant grant:
//!
//! - class `job_results`, optional for role `query`, declared in `accepts`;
//! - `object-read-write`, bucket EXACTLY `nano-shared-r2-<T>`, prefixes
//!   EXACTLY `["<T>/durable-query-result/v1/"]` (the runner's result root);
//! - refreshed with the other query credentials by the shared
//!   [`CredentialRefresher`] and swapped in place ([`JobResultStore::install`]).
//!
//! Without the grant, job routes fail with the typed
//! [`JobResultStorageUnavailable`] (503 `result_storage_unavailable`); there
//! is no local-filesystem fallback.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use arc_swap::ArcSwapOption;

use super::credentials::{is_credential_stale, CredentialStale, RECOVER_WAIT};
use super::server::{ExchangedCredential, R2Credentials};
use crate::cell_refresh::CredentialRefresher;

/// The exchange credential class carrying query[T]'s job-result grant.
pub const JOB_RESULTS_CLASS: &str = "job_results";

/// The tenant's own bucket (the only bucket any lean credential names).
pub fn job_results_bucket(tenant_id: &str) -> String {
    format!("nano-shared-r2-{tenant_id}")
}

/// The single object prefix the grant covers.
pub fn job_results_prefix(tenant_id: &str) -> String {
    format!("{tenant_id}/durable-query-result/v1/")
}

/// The result root, identical to `lake_job_runner --result-root` (which
/// refuses any other value for a hosted tenant).
pub fn job_results_root(tenant_id: &str) -> String {
    format!("s3://{}/{}", job_results_bucket(tenant_id), job_results_prefix(tenant_id).trim_end_matches('/'))
}

/// The exact `job_results` scope: read-write, the tenant's own bucket, and
/// exactly the tenant's durable-result prefix.
pub fn validate_job_results_credential(credential: &ExchangedCredential, tenant_id: &str) -> Result<()> {
    if credential.credential_class != JOB_RESULTS_CLASS
        || credential.permission != "object-read-write"
        || credential.bucket != job_results_bucket(tenant_id)
        || credential.prefixes != [job_results_prefix(tenant_id)]
    {
        bail!("job_results credential is not read-write for exactly this tenant's durable-result prefix");
    }
    Ok(())
}

/// No `job_results` grant is installed: the cell image or the tenant's
/// release does not provision job-result storage (the platform renders it only
/// for images reporting `lean_job_results_v1`).
#[derive(Debug, thiserror::Error)]
#[error("query[T] has no job_results credential from the cell credential exchange; durable search jobs are unavailable")]
pub struct JobResultStorageUnavailable;

/// One installed operator and its swap generation.
pub struct InstalledResults {
    pub generation: u64,
    pub operator: opendal::Operator,
}

/// The tenant's job-result operator, installed, swapped or withdrawn in place.
pub struct JobResultStore {
    tenant_id: String,
    bucket: String,
    root: String,
    current: ArcSwapOption<InstalledResults>,
    refresher: Option<Arc<CredentialRefresher>>,
    /// NAN-3492: built by [`Self::new_trusted_local`] (a dedicated
    /// single-tenant install without hosted control).
    trusted_local: bool,
}

impl JobResultStore {
    /// An empty store; `refresher: None` (labs, tests) never waits for a refresh.
    pub fn new(tenant_id: &str, refresher: Option<Arc<CredentialRefresher>>) -> Arc<Self> {
        Arc::new(Self {
            tenant_id: tenant_id.to_string(),
            bucket: job_results_bucket(tenant_id),
            root: job_results_root(tenant_id),
            current: ArcSwapOption::empty(),
            refresher,
            trusted_local: false,
        })
    }

    /// Dedicated bootstrap only. Hosted callers retain the grant-only constructor.
    pub fn new_trusted_local(tenant_id: &str, location: &crate::part_ingest::s3_store::S3Location) -> Result<Arc<Self>> {
        let tenant = uuid::Uuid::parse_str(tenant_id)?;
        if tenant.get_version_num() != 4 || tenant.to_string() != tenant_id
            || location.bucket != job_results_bucket(tenant_id)
            || location.prefix != job_results_prefix(tenant_id)
            || location.access_key_id.is_empty() || location.secret_access_key.is_empty()
        {
            bail!("trusted-local job storage must name the UUID tenant's exact result bucket and prefix");
        }
        let endpoint = reqwest::Url::parse(&location.endpoint)?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none()
            || !endpoint.username().is_empty() || endpoint.password().is_some()
            || endpoint.query().is_some() || endpoint.fragment().is_some()
        { bail!("invalid trusted-local result endpoint"); }
        let mut builder = opendal::services::S3::default()
            .endpoint(&location.endpoint).region(&location.region).bucket(&location.bucket)
            .root("/").access_key_id(&location.access_key_id).secret_access_key(&location.secret_access_key)
            .disable_config_load().disable_ec2_metadata();
        if let Some(token) = &location.session_token { builder = builder.session_token(token); }
        let operator = opendal::Operator::new(builder)?
            .layer(opendal::layers::TimeoutLayer::new().with_timeout(Duration::from_secs(60)).with_io_timeout(Duration::from_secs(30)))
            .layer(opendal::layers::RetryLayer::new().with_max_times(3)).finish();
        let store = Arc::new(Self {
            tenant_id: tenant_id.to_string(),
            bucket: job_results_bucket(tenant_id),
            root: job_results_root(tenant_id),
            current: ArcSwapOption::empty(),
            refresher: None,
            trusted_local: true,
        });
        store.install(Some(operator));
        Ok(store)
    }

    /// Whether this store belongs to a trusted-local (dedicated, single-tenant)
    /// install: no hosted runner signs a retention proof there.
    pub fn is_trusted_local(&self) -> bool {
        self.trusted_local
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// `s3://nano-shared-r2-<T>/<T>/durable-query-result/v1`.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Build the operator for a (validated) grant without installing it.
    pub fn operator_for(&self, credentials: &R2Credentials) -> Result<opendal::Operator> {
        super::server::r2_operator(&self.bucket, credentials)
    }

    /// Install `operator` (a fresh grant) or withdraw the grant (`None`).
    pub fn install(&self, operator: Option<opendal::Operator>) {
        let generation = self.current.load().as_ref().map_or(0, |installed| installed.generation) + 1;
        self.current.store(operator.map(|operator| Arc::new(InstalledResults { generation, operator })));
    }

    pub fn is_granted(&self) -> bool {
        self.current.load().is_some()
    }

    /// The current operator, or the typed "no grant" error.
    pub fn current(&self) -> std::result::Result<Arc<InstalledResults>, JobResultStorageUnavailable> {
        self.current.load_full().ok_or(JobResultStorageUnavailable)
    }

    /// An operation on generation `seen` was refused: a newer operator,
    /// asking for (and waiting up to [`RECOVER_WAIT`] for) a refresh.
    pub async fn recover(&self, seen: u64) -> Option<Arc<InstalledResults>> {
        self.recover_within(seen, RECOVER_WAIT).await
    }

    pub async fn recover_within(&self, seen: u64, wait: Duration) -> Option<Arc<InstalledResults>> {
        let refresher = self.refresher.as_ref();
        let generation = refresher.map(|r| r.generation());
        let current = self.current.load_full()?;
        if current.generation != seen {
            return Some(current);
        }
        let (refresher, generation) = (refresher?, generation?);
        tracing::warn!(bucket = %self.bucket, "job-result storage refused; refreshing the query credential");
        refresher.request_now();
        refresher.wait_newer(generation, wait).await;
        let current = self.current.load_full()?;
        (current.generation != seen).then_some(current)
    }

    /// Run `op` on the current operator; a refused credential triggers one
    /// refresh and one retry, then fails as the retryable [`CredentialStale`].
    pub async fn with_operator<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: Fn(opendal::Operator) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let installed = self.current()?;
        match op(installed.operator.clone()).await {
            Err(error) if is_credential_stale(&error) => match self.recover(installed.generation).await {
                Some(newer) => op(newer.operator.clone()).await
                    .map_err(|error| if is_credential_stale(&error) { CredentialStale(format!("{error:#}")).into() } else { error }),
                None => Err(CredentialStale(format!("{error:#}")).into()),
            },
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{expected_manifest_uri, LakeQueryJobRequest, LakeQueryJobSpec, ResourceClass, ResultExecutionMetadata, JOB_SCHEMA_VERSION};
    use crate::part_query::credentials::{QueryCredentialSwap, R2ReadAuthority};
    use crate::part_query::server::{bootstrap_from_exchange, r2_operator, resolve_bootstrap, role_credential_set, QueryExchangeResponse};
    use nanosiem_lake_cell::contract::Role;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";

    #[tokio::test]
    async fn trusted_local_results_commit_and_page_from_rustfs_without_a_hosted_exchange() {
        let fake = fake_r2().await;
        *fake.valid.lock().unwrap() = "local-key".into();
        let mut location = crate::part_ingest::s3_store::S3Location {
            endpoint: fake.endpoint.clone(), region: "us-east-1".into(), bucket: job_results_bucket(TENANT),
            prefix: job_results_prefix(TENANT), access_key_id: "local-key".into(), secret_access_key: "local-secret".into(), session_token: None,
        };
        let store = JobResultStore::new_trusted_local(TENANT, &location).unwrap();
        let artifact = commit(&store, "attempt-local").await.unwrap();
        assert!(artifact.manifest_uri.starts_with(store.root()));
        assert!(!fake.objects.lock().unwrap().is_empty());
        let page = super::super::jobs::result_page(&store, &artifact, "019fe-job", TENANT, 0).await.unwrap();
        assert_eq!(page["rows"].as_array().unwrap().len(), 2);
        let mut foreign = artifact;
        foreign.manifest_uri = foreign.manifest_uri.replace(TENANT, "foreign");
        assert!(super::super::jobs::result_page(&store, &foreign, "019fe-job", TENANT, 0).await.is_err());
        location.prefix = "foreign/".into();
        assert!(JobResultStore::new_trusted_local(TENANT, &location).is_err());
        assert!(!JobResultStore::new(TENANT, None).is_granted());
    }

    /// An in-process S3 stand-in holding objects in memory. It accepts
    /// exactly one access key (the most recently minted grant); any other key
    /// gets R2's 403 `AccessDenied`, as an expired or revoked key would.
    #[derive(Clone)]
    struct FakeR2 {
        endpoint: String,
        valid: Arc<Mutex<String>>,
        objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        /// `(access key, object path)` of every accepted PUT, in order.
        puts: Arc<Mutex<Vec<(String, String)>>>,
        denied: Arc<AtomicUsize>,
    }

    async fn fake_r2() -> FakeR2 {
        use axum::{body::Bytes, http::{HeaderMap, Method, StatusCode, Uri}, response::IntoResponse, Router};
        let fake = FakeR2 {
            endpoint: String::new(), valid: Arc::new(Mutex::new(String::new())),
            objects: Arc::default(), puts: Arc::default(), denied: Arc::default(),
        };
        let state = fake.clone();
        let app = Router::new().fallback(move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
            let state = state.clone();
            async move {
                let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                let key = state.valid.lock().unwrap().clone();
                if key.is_empty() || !auth.contains(&format!("Credential={key}/")) {
                    state.denied.fetch_add(1, Ordering::SeqCst);
                    return (StatusCode::FORBIDDEN, [("content-type", "application/xml")],
                        b"<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>".to_vec()).into_response();
                }
                let path = uri.path().trim_start_matches('/').to_string();
                match method {
                    Method::PUT => {
                        state.objects.lock().unwrap().insert(path.clone(), body.to_vec());
                        state.puts.lock().unwrap().push((key, path));
                        (StatusCode::OK, [("etag", "\"e\"")]).into_response()
                    }
                    Method::GET => match state.objects.lock().unwrap().get(&path) {
                        Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
                        None => (StatusCode::NOT_FOUND, [("content-type", "application/xml")],
                            b"<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code></Error>".to_vec()).into_response(),
                    },
                    _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        FakeR2 { endpoint, ..fake }
    }

    /// The control plane's credential exchange (the platform stand-in): every
    /// exchange mints a fresh key pair and makes it the only one the store
    /// accepts; `grant` switches the `job_results` class on or off.
    struct FakeControl {
        url: String,
        exchanges: Arc<AtomicUsize>,
        grant: Arc<AtomicBool>,
    }

    fn exchange_body(r2: &FakeR2, n: usize, grant: bool) -> serde_json::Value {
        let bucket = job_results_bucket(TENANT);
        let expires = (chrono::Utc::now() + chrono::Duration::hours(6)).to_rfc3339();
        let mut credentials = vec![serde_json::json!({
            "credential_class": "lake_part_read", "endpoint": r2.endpoint, "region": "auto", "bucket": bucket,
            "permission": "object-read-only", "prefixes": [format!("lake/parts/v1/tenant={TENANT}/")],
            "access_key_id": format!("read-key{n}"), "secret_access_key": "s", "session_token": "", "expires_at": expires,
        })];
        if grant {
            credentials.push(serde_json::json!({
                "credential_class": "job_results", "endpoint": r2.endpoint, "region": "auto", "bucket": bucket,
                "permission": "object-read-write", "prefixes": [job_results_prefix(TENANT)],
                "access_key_id": format!("jr-key{n}"), "secret_access_key": "s", "session_token": "", "expires_at": expires,
            }));
        }
        serde_json::json!({
            "schema_version": 1, "tenant_id": TENANT, "role": "query", "credentials": credentials,
            "trusted_keys": [], "query_engine": {"chdb_library": "/l", "chdb_sha256": "0", "compiler": "/c"},
        })
    }

    async fn fake_control(r2: &FakeR2, grant: bool) -> FakeControl {
        fake_control_with(r2, grant, false).await
    }

    /// `legacy`: a control plane predating `job_results`, whose request
    /// schema refuses the unknown `accepts` class as 400 `bad_request`
    /// without consuming the token.
    async fn fake_control_with(r2: &FakeR2, grant: bool, legacy: bool) -> FakeControl {
        use axum::{body::Bytes, http::{StatusCode, Uri}, response::IntoResponse, Json, Router};
        let (exchanges, grant) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicBool::new(grant)));
        let (r2, count, granting) = (r2.clone(), exchanges.clone(), grant.clone());
        let app = Router::new().fallback(move |uri: Uri, body: Bytes| {
            let (r2, count, granting) = (r2.clone(), count.clone(), granting.clone());
            async move {
                if uri.path() != "/v1/lake/cells/cell-1/credential-exchange" {
                    return StatusCode::NOT_FOUND.into_response();
                }
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request["role"], "query");
                let declares = request["accepts"].as_array().unwrap().iter().any(|c| c == JOB_RESULTS_CLASS);
                if legacy {
                    if declares {
                        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "bad_request"}))).into_response();
                    }
                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                    return Json(exchange_body(&r2, n, false)).into_response();
                }
                assert!(request["accepts"].as_array().unwrap().iter().any(|c| c == JOB_RESULTS_CLASS),
                    "query declares job_results in accepts: {request}");
                let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                let grant = granting.load(Ordering::SeqCst);
                if grant {
                    *r2.valid.lock().unwrap() = format!("jr-key{n}");
                }
                Json(exchange_body(&r2, n, grant)).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        FakeControl { url, exchanges, grant }
    }

    /// The spec `lake_job_runner::run_cell_claim` sends for attempt 1, fence 7.
    fn spec(attempt_id: &str) -> LakeQueryJobSpec {
        LakeQueryJobSpec {
            schema_version: JOB_SCHEMA_VERSION,
            job_id: "019fe-job".into(),
            attempt_id: attempt_id.into(),
            fence_token: format!("019fe-job:1:7:{}", "f".repeat(36)),
            tenant_id: TENANT.into(),
            generation_id: "parts-v1-42-aaaaaaaaaaaaaaaa".into(),
            event_config_sha256: "a".repeat(64),
            snapshot_id: 42,
            compiler_sha256: "b".repeat(64),
            native_artifact_sha256: "c".repeat(64),
            hot_tail_manifest_sha256: None,
            hot_tail_snapshot_id: None,
            hot_tail_id: None,
            resource_class: ResourceClass::Medium,
            scan_budget_bytes: 1 << 30,
            submitted_at: chrono::Utc::now(),
            scope_deny: BTreeSet::new(),
            task: nanosiem_core::search::DurableLakeTask::SearchNplV1,
            request: LakeQueryJobRequest {
                dataset: "logs".into(),
                query: "*".into(),
                start: "2026-09-29T00:00:00Z".into(),
                end: "2026-09-29T01:00:00Z".into(),
                limit: 100,
                offset: 0,
                table_view: false,
                anchor_us: None,
                decay: None,
                clear_boundaries: Default::default(),
                minimum_clear_revision: None,
            },
            result_page_rows: 2,
            retention_proof: None,
        }
    }

    /// The Parquet spool query[T]'s `INSERT INTO FUNCTION file(...)` leaves.
    fn spool(dir: &std::path::Path) -> std::path::PathBuf {
        use arrow_array::{ArrayRef, Int64Array, RecordBatch, StringArray};
        let batch = RecordBatch::try_from_iter([
            ("message", Arc::new(StringArray::from(vec!["a", "b", "c"])) as ArrayRef),
            ("n", Arc::new(Int64Array::from(vec![1, 2, 3])) as ArrayRef),
        ]).unwrap();
        let path = dir.join("search-result.parquet");
        let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), batch.schema(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        path
    }

    async fn commit(store: &JobResultStore, attempt_id: &str) -> Result<crate::job::ResultArtifactRef> {
        let dir = tempfile::tempdir().unwrap();
        super::super::jobs::commit_job_result(store, &spec(attempt_id), &spool(dir.path()), &BTreeSet::new(),
            &ResultExecutionMetadata::default()).await
    }

    /// What `lake_job_runner` checks before completing a cell claim: its
    /// hosted `--result-root` is exactly this literal (R: "hosted runner
    /// requires the exact tenant-scoped R2 result root") and the returned
    /// manifest is exactly the fenced attempt's.
    fn runner_accepts(reference: &crate::job::ResultArtifactRef, attempt_id: &str) -> bool {
        let runner_root = format!("s3://nano-shared-r2-{TENANT}/{TENANT}/durable-query-result/v1");
        reference.manifest_uri == expected_manifest_uri(&runner_root, TENANT, "019fe-job", attempt_id)
    }

    /// End to end: exchange (mock control plane) → `job_results` grant →
    /// query[T] commits the job's pages then manifest to the exchanged R2
    /// prefix (mock R2) → the runner's manifest check accepts the reference →
    /// the result-page route reads it back with the same grant.
    #[tokio::test]
    async fn exchanged_grant_commits_results_the_runner_accepts_and_reads_them_back() {
        let r2 = fake_r2().await;
        let control = fake_control(&r2, true).await;
        let boot = resolve_bootstrap(b"bootstrap-token", TENANT, "cell-1", Some(&control.url), Role::Query).await.unwrap();
        let store = JobResultStore::new(TENANT, None);
        assert!(matches!(store.current(), Err(JobResultStorageUnavailable)));
        store.install(Some(store.operator_for(boot.job_results_r2.as_ref().unwrap()).unwrap()));
        assert_eq!(store.root(), format!("s3://nano-shared-r2-{TENANT}/{TENANT}/durable-query-result/v1"));

        let attempt = "attempt-1-fence-7";
        let reference = commit(&store, attempt).await.unwrap();
        assert!(runner_accepts(&reference, attempt), "runner refuses {}", reference.manifest_uri);
        assert!(!runner_accepts(&reference, "attempt-2-fence-8"));
        assert_eq!((reference.rows, reference.parts), (3, 2));

        // Every object is under the granted prefix, written with the grant,
        // and the manifest (the commit pointer) is written last.
        let puts = r2.puts.lock().unwrap().clone();
        let prefix = format!("{}/{}", job_results_bucket(TENANT), job_results_prefix(TENANT));
        assert_eq!(puts.len(), 3, "{puts:?}");
        assert!(puts.iter().all(|(key, path)| key == "jr-key1" && path.starts_with(&prefix)), "{puts:?}");
        assert!(puts.last().unwrap().1.ends_with(&format!("/job-019fe-job/attempt-{attempt}/manifest.json")));

        let mut rows = Vec::new();
        for page in 0..reference.parts {
            let page = super::super::jobs::result_page(&store, &reference, "019fe-job", TENANT, page).await.unwrap();
            rows.extend(page["rows"].as_array().unwrap().iter().map(|row| row["message"].as_str().unwrap().to_string()));
        }
        assert_eq!(rows, ["a", "b", "c"]);
        // A reference into another bucket is refused before any read.
        let mut foreign = reference.clone();
        foreign.manifest_uri = foreign.manifest_uri.replace(&job_results_bucket(TENANT), "nano-shared-r2-other");
        assert!(super::super::jobs::result_page(&store, &foreign, "019fe-job", TENANT, 0).await.is_err());
        assert_eq!(r2.denied.load(Ordering::SeqCst), 0);
    }

    /// No `job_results` in the exchange: the job fails with the typed
    /// error before anything is written, never falling back to `file://`.
    #[tokio::test]
    async fn missing_grant_fails_typed_and_writes_nothing() {
        let r2 = fake_r2().await;
        let control = fake_control(&r2, false).await;
        let boot = resolve_bootstrap(b"bootstrap-token", TENANT, "cell-1", Some(&control.url), Role::Query).await.unwrap();
        assert!(boot.job_results_r2.is_none());
        let store = JobResultStore::new(TENANT, None);
        assert!(!store.is_granted());
        let error = commit(&store, "attempt-1-fence-7").await.unwrap_err();
        assert!(error.downcast_ref::<JobResultStorageUnavailable>().is_some(), "{error:#}");
        assert!(r2.puts.lock().unwrap().is_empty());
        assert_eq!(r2.denied.load(Ordering::SeqCst), 0, "no request reached storage");
    }

    /// The shared refresh path (`QueryCredentialSwap::on_secret`, driven by
    /// `CredentialRefresher`) re-exchanges and swaps the `job_results`
    /// operator in place: the old key is dead afterwards and the next commit
    /// uses the new one. A refresh without the grant withdraws it (typed).
    #[tokio::test]
    async fn refresh_swaps_the_job_results_credential() {
        let r2 = fake_r2().await;
        let control = fake_control(&r2, true).await;
        let boot = resolve_bootstrap(b"bootstrap-token", TENANT, "cell-1", Some(&control.url), Role::Query).await.unwrap();
        let refresher = CredentialRefresher::new(boot.expires_at.unwrap());
        let store = JobResultStore::new(TENANT, Some(refresher.clone()));
        store.install(Some(store.operator_for(boot.job_results_r2.as_ref().unwrap()).unwrap()));
        let read = R2ReadAuthority::new(boot.bucket.clone(), r2_operator(&boot.bucket, boot.r2.as_ref().unwrap()).unwrap(), Some(refresher.clone()));
        let swap = QueryCredentialSwap {
            tenant_id: TENANT.into(), cell_id: "cell-1".into(), control_url: Some(control.url.clone()), role: Role::Query,
            bucket: boot.bucket.clone(), r2: Some(read), ioc: None, job_results: Some(store.clone()), refresher: refresher.clone(),
        };
        commit(&store, "attempt-1-fence-7").await.unwrap();
        let before = store.current().unwrap().generation;
        let refreshed = refresher.generation();

        swap.on_secret(b"refresh-token").await;
        assert_eq!(control.exchanges.load(Ordering::SeqCst), 2);
        assert!(refresher.generation() > refreshed, "the refresh was recorded");
        assert_eq!(store.current().unwrap().generation, before + 1, "the operator was swapped in place");
        // The fake now accepts only jr-key2: a commit on the old operator
        // would be refused; the swapped store succeeds.
        let reference = commit(&store, "attempt-2-fence-8").await.unwrap();
        assert!(runner_accepts(&reference, "attempt-2-fence-8"));
        assert_eq!(r2.puts.lock().unwrap().last().unwrap().0, "jr-key2");
        assert_eq!(r2.denied.load(Ordering::SeqCst), 0);

        control.grant.store(false, Ordering::SeqCst);
        swap.on_secret(b"refresh-token").await;
        let error = commit(&store, "attempt-3-fence-9").await.unwrap_err();
        assert!(error.downcast_ref::<JobResultStorageUnavailable>().is_some(), "{error:#}");
    }

    /// Rollout safety: against a control plane that does not know
    /// `job_results` yet, query[T] still boots (search keeps working) and
    /// jobs fail typed, instead of every query[T] failing its exchange.
    #[tokio::test]
    async fn legacy_control_plane_still_boots_query_without_the_grant() {
        let r2 = fake_r2().await;
        let control = fake_control_with(&r2, true, true).await;
        let boot = resolve_bootstrap(b"bootstrap-token", TENANT, "cell-1", Some(&control.url), Role::Query).await.unwrap();
        assert!(boot.r2.is_some() && boot.job_results_r2.is_none());
        assert_eq!(control.exchanges.load(Ordering::SeqCst), 1);
    }

    fn response(credentials: serde_json::Value, role: &str) -> QueryExchangeResponse {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "tenant_id": TENANT, "role": role, "credentials": credentials,
            "trusted_keys": [], "query_engine": {"chdb_library": "/l", "chdb_sha256": "0", "compiler": "/c"},
        })).unwrap()
    }

    fn with_job_results(edit: impl FnOnce(&mut serde_json::Value)) -> serde_json::Value {
        let r2 = FakeR2 { endpoint: "https://objects.invalid".into(), valid: Arc::default(), objects: Arc::default(),
            puts: Arc::default(), denied: Arc::default() };
        let mut body = exchange_body(&r2, 1, true);
        edit(&mut body["credentials"][1]);
        body["credentials"].clone()
    }

    #[test]
    fn job_results_scope_is_exact() {
        let ok = bootstrap_from_exchange(response(with_job_results(|_| {}), "query"), TENANT, Role::Query).unwrap();
        assert!(ok.job_results_r2.is_some());
        for edit in [
            |c: &mut serde_json::Value| c["permission"] = "object-read-only".into(),
            |c: &mut serde_json::Value| c["prefixes"] = serde_json::json!([format!("{TENANT}/")]),
            |c: &mut serde_json::Value| c["prefixes"] = serde_json::json!([job_results_prefix(TENANT), format!("{TENANT}/other/")]),
            |c: &mut serde_json::Value| c["prefixes"] = serde_json::json!([job_results_prefix("7a2d2f3b-6c9f-4e5d-8b4f-1f3c8d0e2a11")]),
            |c: &mut serde_json::Value| c["bucket"] = "nano-shared-r2-7a2d2f3b-6c9f-4e5d-8b4f-1f3c8d0e2a11".into(),
            |c: &mut serde_json::Value| c["endpoint"] = "https://elsewhere.invalid".into(),
        ] {
            assert!(bootstrap_from_exchange(response(with_job_results(edit), "query"), TENANT, Role::Query).is_err());
        }
        // detect never receives it: undeclared for its role.
        assert!(!role_credential_set(Role::Detect).unwrap().1.contains(&JOB_RESULTS_CLASS));
    }

    #[test]
    fn job_results_expiry_bounds_the_refresh_schedule() {
        let soon = (chrono::Utc::now() + chrono::Duration::minutes(20)).to_rfc3339();
        let boot = bootstrap_from_exchange(response(with_job_results(|c| c["expires_at"] = soon.clone().into()), "query"),
            TENANT, Role::Query).unwrap();
        assert_eq!(boot.expires_at.unwrap(), chrono::DateTime::parse_from_rfc3339(&soon).unwrap());
    }

    #[test]
    fn cell_feature_lean_job_results_v1_is_backed() {
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"lean_job_results_v1"));
        assert!(role_credential_set(Role::Query).unwrap().1.contains(&JOB_RESULTS_CLASS));
        let body = crate::part_query::server::exchange_request_body(TENANT, Role::Query).unwrap();
        assert!(body["accepts"].as_array().unwrap().iter().any(|c| c == JOB_RESULTS_CLASS));
    }
}

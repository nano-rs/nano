// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process-local provider attempts, counted below OpenDAL pagination/retry.
//! No keys, credentials, tenant IDs, or query strings enter telemetry.
use axum::http::{Request, Response};
use opendal::{
    Buffer,
    layers::HttpClientLayer,
    raw::{HttpBody, HttpClient, HttpFetch},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

type Labels = (&'static str, &'static str, &'static str, &'static str);
struct Counters {
    started: Instant,
    last: Instant,
    total: BTreeMap<Labels, u64>,
    previous: BTreeMap<Labels, u64>,
}
static COUNTERS: OnceLock<Mutex<Counters>> = OnceLock::new();

fn counters() -> &'static Mutex<Counters> {
    COUNTERS.get_or_init(|| {
        // A thread also covers binaries using short-lived Tokio runtimes.
        // Telemetry never schedules provider requests or keeps a process alive.
        let _ = std::thread::Builder::new().name("r2-ops".into()).spawn(|| {
            loop {
                std::thread::sleep(Duration::from_secs(60));
                let line = interval_snapshot();
                use std::io::Write;
                let _ = writeln!(std::io::stderr().lock(), "{line}");
            }
        });
        Mutex::new(Counters {
            started: Instant::now(),
            last: Instant::now(),
            total: BTreeMap::new(),
            previous: BTreeMap::new(),
        })
    })
}

pub fn prefix_class(key: &str) -> &'static str {
    let parts: Vec<_> = key.split('/').collect();
    if parts.contains(&"bronze-v2") {
        "bronze-v2"
    } else if parts.iter().any(|p| {
        matches!(
            *p,
            "hot-tail"
                | "hot_tail"
                | "staged-tail"
                | "staged-hot-tail"
                | "committed-hot-tail"
                | "tail"
        )
    }) {
        "hot-tail"
    } else if parts.iter().any(|p| {
        matches!(
            *p,
            "derivatives"
                | "prevalence"
                | "risk"
                | "enrichment"
                | "ioc"
                | "ipinfo"
                | "prevalence-artifact"
                | "risk-artifact"
                | "detection-artifact"
                | "ai-hunt-artifact"
        )
    }) {
        "derivatives"
    } else if parts.iter().any(|p| {
        matches!(
            *p,
            "generations" | "generation-bundles" | "retained-generation"
        )
    }) {
        "generations"
    } else if parts.iter().any(|p| matches!(*p, "catalog" | "metadata")) || key.ends_with(".avro") {
        "catalog"
    } else {
        "other"
    }
}

pub fn operation(method: &str, query: &str) -> (&'static str, &'static str) {
    let names: Vec<_> = query
        .split('&')
        .map(|p| p.split('=').next().unwrap_or(""))
        .collect();
    if names.iter().any(|p| matches!(*p, "uploadId" | "uploads")) {
        return (if method == "DELETE" { "free" } else { "A" }, "multipart");
    }
    match method {
        "GET"
            if names
                .iter()
                .any(|p| matches!(*p, "list-type" | "prefix" | "versions")) =>
        {
            ("A", "LIST")
        }
        "GET" => ("B", "GET"),
        "HEAD" => ("B", "HEAD"),
        "DELETE" => ("free", "DELETE"),
        "POST" if names.contains(&"delete") => ("free", "DELETE"),
        "PUT" => ("A", "PUT"),
        _ => ("A", "other"),
    }
}

fn record(method: &str, key: &str, query: &str, host: &str) {
    let unit = if host.ends_with(".r2.cloudflarestorage.com")
        || host.ends_with(".r2.cloudflarestorage.com.cn")
    {
        "r2"
    } else if host.ends_with(".ingest.nano.rs") || host == "r2.internal" {
        "bridge"
    } else {
        "s3"
    };
    let (class, kind) = operation(method, query);
    let mut counters = counters().lock().unwrap_or_else(|e| e.into_inner());
    *counters
        .total
        .entry((class, kind, prefix_class(key), unit))
        .or_default() += 1;
}
fn render(c: &Counters, interval: bool) -> Value {
    let seconds = if interval {
        c.last.elapsed()
    } else {
        c.started.elapsed()
    }
    .as_secs_f64()
    .max(0.001);
    let counts: Vec<_> = c.total.iter().map(|(&(class, kind, prefix, unit), &total)| {
        let count = if interval { total - c.previous.get(&(class, kind, prefix, unit)).copied().unwrap_or(0) } else { total };
        json!({"class":class,"kind":kind,"prefix":prefix,"backend":unit,"count":count,"total":total,"rate":count as f64 / seconds})
    }).collect();
    json!({"event":"r2_ops","schema_version":1,"scope":"process","pid":std::process::id(),
        "component":std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        "seconds":seconds,"uptime_seconds":c.started.elapsed().as_secs_f64(),"counts":counts,
        "unit":"http_attempts"})
}
pub fn snapshot() -> Value {
    render(&counters().lock().unwrap_or_else(|e| e.into_inner()), false)
}
fn interval_snapshot() -> Value {
    let mut c = counters().lock().unwrap_or_else(|e| e.into_inner());
    let result = render(&c, true);
    c.previous = c.total.clone();
    c.last = Instant::now();
    result
}
#[derive(Default)]
pub(crate) struct GcHttpObservation {
    #[cfg(test)]
    pub attempt_times: Mutex<Vec<Instant>>,
    pub attempts: std::sync::atomic::AtomicU64,
    pub body_bytes: std::sync::atomic::AtomicU64,
    pub peak_body: std::sync::atomic::AtomicUsize,
    pub peak_chunk: std::sync::atomic::AtomicUsize,
}

/// Private to the sanctioned GC operator. A refresh invalidates every old
/// attempt, including waits and response bodies; no request task is spawned.
pub(crate) struct GcHttpGuard {
    pub pacer: std::sync::Arc<crate::part_ingest::part_gc_cell::ReadPacer>,
    pub current: Box<dyn Fn() -> opendal::Result<Duration> + Send + Sync>,
    pub generation: tokio::sync::watch::Sender<u64>,
    pub observation: std::sync::Arc<GcHttpObservation>,
}

impl GcHttpGuard {
    /// Only an explicit exchange suspension may wait for a usable generation.
    /// It cannot retry an old operation or wait through withdrawal/expiry.
    pub async fn wait_refresh(&self) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut generation = self.generation.subscribe();
        for _ in 0..32 {
            match (self.current)() {
                Ok(_) => return Ok(()),
                Err(error) => {
                    let error = anyhow::Error::from(error);
                    if !crate::part_ingest::part_gc_cell::is_refresh_suspended(&error) {
                        return Err(error);
                    }
                    tokio::time::timeout_at(deadline, generation.changed()).await??;
                }
            }
        }
        anyhow::bail!("GC credential suspension notification budget exhausted")
    }

    fn cancelled(&self, message: &str) -> opendal::Error {
        // The replacement can already be installed when this select runs.
        // Preserve the refresh cause even after current() becomes usable.
        (self.current)().err().unwrap_or_else(|| gc_generation_changed(message))
    }

    /// Also own the OpenDAL operation: invalidation drops RetryLayer's delay,
    /// so an old credential generation cannot retry after a route refresh.
    pub async fn run<T>(
        &self,
        work: impl std::future::Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        let mut generation = self.generation.subscribe();
        let remaining = (self.current)()?;
        tokio::select! {
            biased;
            _ = generation.changed() => Err(self.cancelled("GC operation generation changed").into()),
            _ = tokio::time::sleep(remaining) => Err(gc_refusal("GC operation grant expired").into()),
            result = work => result,
        }
    }
}

tokio::task_local! {
    static GC_LIST_ATTEMPTS: std::cell::Cell<u32>;
}

pub(crate) async fn bounded_gc_list<T>(future: impl std::future::Future<Output = T>) -> T {
    GC_LIST_ATTEMPTS
        .scope(std::cell::Cell::new(0), future)
        .await
}

fn gc_generation_changed(message: &str) -> opendal::Error {
    gc_refusal(message).set_source(anyhow::Error::from(crate::part_ingest::part_gc_cell::RefreshSuspended))
}

fn gc_refusal(message: &str) -> opendal::Error {
    opendal::Error::new(opendal::ErrorKind::PermissionDenied, message)
}

struct GcHttp {
    inner: HttpClient,
    guard: std::sync::Arc<GcHttpGuard>,
    epoch: tokio::sync::watch::Sender<u64>,
    expected_epoch: u64,
}

impl HttpFetch for GcHttp {
    async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        use opendal::raw::oio::Read;
        // Subscribe before inspecting permission, closing the update race.
        let mut generation = self.guard.generation.subscribe();
        let mut epoch = self.epoch.subscribe();
        if *epoch.borrow() != self.expected_epoch {
            return Err(self.guard.cancelled("GC operator credential generation changed"));
        }
        let remaining = (self.guard.current)()?;
        let expiry = tokio::time::sleep(remaining);
        tokio::pin!(expiry);
        let observed = generation.clone();
        let observed_epoch = epoch.clone();
        let work = async {
            if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
                return Err(gc_refusal("GC store transport is read-only"));
            }
            let is_list =
                operation(req.method().as_str(), req.uri().query().unwrap_or("")).1 == "LIST";
            if is_list {
                let exhausted = GC_LIST_ATTEMPTS
                    .try_with(|count| {
                        let attempts = count.get();
                        count.set(attempts + 1);
                        attempts >= 16
                    })
                    .unwrap_or(false);
                if exhausted {
                    return Err(gc_refusal("GC checkpoint list attempt limit"));
                }
            }
            (self.guard.current)()?;
            self.guard.pacer.acquire(1).await;
            (self.guard.current)()?;
            if observed.has_changed().unwrap_or(true)
                || *observed_epoch.borrow() != self.expected_epoch {
                return Err(self.guard.cancelled("GC transport generation changed"));
            }
            // Immediately before CountingHttp, below OpenDAL's RetryLayer.
            (self.guard.current)()?;
            self.guard
                .observation
                .attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let provenance = req.uri().path().ends_with("/provenance.json");
            // Record the actual production HttpFetch start, not provider handler
            // scheduling time (which can coalesce independently on a busy CPU).
            #[cfg(test)]
            self.guard.observation.attempt_times.lock().unwrap().push(Instant::now());
            let response = self.inner.fetch(req).await?;
            let (parts, mut body) = response.into_parts();
            let cap = if provenance { crate::parts::provenance::MAX_PROVENANCE_BYTES }
                else { crate::parts::format::MAX_LOG_OBJECT_BYTES };
            let range = parts.headers.get(axum::http::header::CONTENT_RANGE);
            let full_range_length = if range.is_some() || parts.status == axum::http::StatusCode::PARTIAL_CONTENT {
                let range = range.and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("bytes "))
                    .and_then(|v| v.split_once('/'))
                    .and_then(|(bounds, total)| bounds.split_once('-').map(|(start, end)| (start, end, total)))
                    .and_then(|(start, end, total)| Some((start.parse::<u64>().ok()?, end.parse::<u64>().ok()?, total.parse::<u64>().ok()?)));
                let Some((start, end, total)) = range else { return Err(gc_refusal("GC response has no full-object range")); };
                if start != 0 || end.checked_add(1) != Some(total) || total > cap as u64 {
                    return Err(gc_refusal("GC response is a truncated or overlarge object range"));
                }
                Some(total)
            } else { None };
            if parts
                .headers
                .get(axum::http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|length| length > cap as u64)
            {
                return Err(gc_refusal(
                    "GC response advertised length exceeds byte limit",
                ));
            }
            let mut bytes = Vec::new();
            loop {
                (self.guard.current)()?;
                let chunk = body.read().await?;
                if chunk.is_empty() {
                    break;
                }
                self.guard
                    .observation
                    .body_bytes
                    .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
                self.guard
                    .observation
                    .peak_chunk
                    .fetch_max(chunk.len(), std::sync::atomic::Ordering::Relaxed);
                self.guard.observation.peak_body.fetch_max(
                    bytes.len().saturating_add(chunk.len()),
                    std::sync::atomic::Ordering::Relaxed,
                );
                if chunk.len() > cap || bytes.len().saturating_add(chunk.len()) > cap {
                    return Err(gc_refusal("GC response actual length exceeds byte limit"));
                }
                // Keep only one transport chunk alive; reserve exactly the cap
                // once instead of Vec's geometrically growing capacity.
                if bytes.capacity() == 0 {
                    bytes.reserve_exact(cap);
                }
                for part in chunk {
                    bytes.extend_from_slice(&part);
                }
            }
            (self.guard.current)()?;
            if full_range_length.is_some_and(|length| length != bytes.len() as u64) {
                return Err(gc_refusal("GC response did not contain the full object range"));
            }
            if is_list {
                // Bound OpenDAL's subsequent XML object graph, even if a
                // provider ignores max-keys or fills a page with tiny elements.
                let elements = bytes.iter().filter(|&&byte| byte == b'<').count();
                if bytes.len().saturating_mul(4).saturating_add(elements.saturating_mul(512)) > 32 * 1024 * 1024 {
                    return Err(gc_refusal("GC list exceeds parsed allocation reservation"));
                }
            }
            let length = bytes.len() as u64;
            Ok(Response::from_parts(
                parts,
                HttpBody::new(
                    futures::stream::iter([Ok(Buffer::from(bytes))]),
                    Some(length),
                ),
            ))
        };
        tokio::select! {
            biased;
            _ = generation.changed() => Err(self.guard.cancelled("GC transport generation changed")),
            _ = epoch.changed() => Err(self.guard.cancelled("GC operator credential generation changed")),
            _ = &mut expiry => Err(gc_refusal("GC transport grant expired")),
            result = work => result,
        }
    }
}

pub(crate) fn gc_layer(
    guard: std::sync::Arc<GcHttpGuard>,
    epoch: tokio::sync::watch::Sender<u64>,
    expected_epoch: u64,
) -> opendal::Result<HttpClientLayer> {
    // HTTP/1 has Hyper's bounded read buffer (417792 bytes in the pinned
    // dependency). Disable decompression, which can expand a small wire chunk
    // without a bound, redirects (extra unpaced HTTP) and idle connections.
    let client = reqwest::Client::builder()
        .http1_only()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .pool_max_idle_per_host(0)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| {
            opendal::Error::new(opendal::ErrorKind::Unexpected, "GC HTTP client").set_source(error)
        })?;
    Ok(HttpClientLayer::new(HttpClient::with(GcHttp {
        inner: HttpClient::with(CountingHttp(HttpClient::with(client))),
        guard, epoch, expected_epoch,
    })))
}
struct CountingHttp(HttpClient);
impl HttpFetch for CountingHttp {
    async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        let uri = req.uri();
        // Percent decoding is only for bounded labels; never retain the URL.
        let parsed = reqwest::Url::parse(&uri.to_string()).ok();
        let prefix = parsed.as_ref().and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "prefix")
                .map(|(_, v)| v.into_owned())
        });
        record(
            req.method().as_str(),
            prefix.as_deref().unwrap_or(uri.path()),
            uri.query().unwrap_or(""),
            uri.host().unwrap_or(""),
        );
        // NAN-2596: whatever built this request, it may not delete a
        // the platform-owned `tenants/` key from the tenant bucket.
        let body = matches!(req.method().as_str(), "POST").then(|| req.body().to_bytes());
        if let Some(refusal) = nanosiem_core::r2_prefix_guard::wire_delete_refusal(
            req.method().as_str(),
            uri.path(),
            uri.query().unwrap_or(""),
            body.as_deref(),
        ) {
            return Err(opendal::Error::new(opendal::ErrorKind::PermissionDenied, refusal.to_string()));
        }
        #[cfg(test)]
        let req = test_origin::rewrite(req);
        let started = std::time::Instant::now();
        let response = self.0.fetch(req).await;
        note_attempt(&response, started.elapsed());
        response
    }
}

/// NAN-3772: wire attempts, and those that strained R2 (failed, 429/5xx, or
/// no response headers within [`SLOW_ATTEMPT`]), process-wide. The count
/// backfill backs off on them: R2 timeouts stalled tenant-a's prevalence store
/// and ingest flushes while a rewrite was moving parts (2026-10-13).
static ATTEMPTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static STRAINED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
const SLOW_ATTEMPT: Duration = Duration::from_secs(5);

fn note_attempt<T>(response: &opendal::Result<Response<T>>, elapsed: Duration) {
    ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let strained = elapsed >= SLOW_ATTEMPT || match response {
        Ok(response) => response.status().is_server_error() || response.status().as_u16() == 429,
        Err(_) => true,
    };
    if strained {
        STRAINED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Cumulative (attempts, strained attempts) since process start.
pub fn strain_counters() -> (u64, u64) {
    (ATTEMPTS.load(std::sync::atomic::Ordering::Relaxed), STRAINED.load(std::sync::atomic::Ordering::Relaxed))
}
fn shared_http_client() -> HttpClient {
    static CLIENT: OnceLock<HttpClient> = OnceLock::new();
    // HttpClient::default also shares OpenDAL's GLOBAL_REQWEST_CLIENT pool.
    CLIENT.get_or_init(|| HttpClient::with(CountingHttp(HttpClient::default()))).clone()
}
pub fn install_iceberg_http_client() {
    let _ = counters();
    let _ = iceberg_storage_opendal::install_http_client(shared_http_client());
}
/// Test seam: within [`test_origin::R2_ORIGIN`]'s scope, requests for a
/// production-shaped `https://<account>.r2.cloudflarestorage.com` endpoint go
/// to a loopback fake instead. Everything above the wire (credential
/// validation, operators, SigV4, per-key credential routing) is production.
#[cfg(test)]
pub(crate) mod test_origin {
    tokio::task_local! {
        pub(crate) static R2_ORIGIN: String;
    }
    /// The same rewrite for the checksummed PUT path's own client, so no
    /// test request can leave the loopback fake.
    pub(crate) fn rewrite_url(url: String) -> String {
        let Ok(origin) = R2_ORIGIN.try_with(Clone::clone) else { return url };
        let Some(rest) = url.strip_prefix("https://") else { return url };
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        if !host.ends_with(".r2.cloudflarestorage.com") {
            return url;
        }
        format!("{}/{path}", origin.trim_end_matches('/'))
    }
    pub(super) fn rewrite(mut req: super::Request<opendal::Buffer>) -> super::Request<opendal::Buffer> {
        let Ok(origin) = R2_ORIGIN.try_with(Clone::clone) else { return req };
        let uri = req.uri();
        if uri.scheme_str() != Some("https") || !uri.host().is_some_and(|h| h.ends_with(".r2.cloudflarestorage.com")) {
            return req;
        }
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        *req.uri_mut() = format!("{}{path}", origin.trim_end_matches('/')).parse().expect("loopback R2 origin");
        req
    }
}

pub fn layer() -> HttpClientLayer {
    let _ = counters();
    HttpClientLayer::new(shared_http_client())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// NAN-3772: failed, refused and slow attempts feed backfill backoff.
    #[test]
    fn strained_attempts_are_counted() {
        let ok = |status: u16| Ok::<_, opendal::Error>(Response::builder().status(status).body(()).unwrap());
        let (attempts, strained) = strain_counters();
        note_attempt(&ok(200), Duration::from_millis(20));
        note_attempt(&ok(503), Duration::from_millis(20));
        note_attempt(&ok(429), Duration::from_millis(20));
        note_attempt(&ok(200), SLOW_ATTEMPT);
        note_attempt(&Err::<Response<()>, _>(opendal::Error::new(opendal::ErrorKind::Unexpected, "timeout")), Duration::ZERO);
        let (after_attempts, after_strained) = strain_counters();
        assert!(after_attempts >= attempts + 5);
        assert!(after_strained >= strained + 4);
    }
    #[test]
    fn billing_classes_include_lists_and_free_deletes() {
        assert_eq!(operation("GET", "list-type=2&prefix=x"), ("A", "LIST"));
        assert_eq!(operation("HEAD", ""), ("B", "HEAD"));
        assert_eq!(operation("GET", "versionId=x"), ("B", "GET"));
        assert_eq!(
            operation("PUT", "partNumber=1&uploadId=x"),
            ("A", "multipart")
        );
        assert_eq!(operation("DELETE", "uploadId=x"), ("free", "multipart"));
        assert_eq!(operation("DELETE", ""), ("free", "DELETE"));
    }
    #[test]
    fn bounded_prefix_labels_do_not_expose_keys() {
        for (key, expected) in [
            ("/bucket/bronze-v2/tenant_id=x/secret", "bronze-v2"),
            ("hot-tail/x", "hot-tail"),
            ("warehouse/t/metadata/x.json", "catalog"),
            ("generations/x", "generations"),
            ("risk/x", "derivatives"),
            ("untrusted/random/key", "other"),
        ] {
            assert_eq!(prefix_class(key), expected);
        }
    }
    #[tokio::test]
    async fn r2_iceberg_fileio_uses_the_counted_wire_transport() {
        use iceberg::io::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 4096];
            let length = socket.read(&mut bytes).await.unwrap();
            assert!(
                String::from_utf8_lossy(&bytes[..length])
                    .starts_with("GET /bucket/derivatives/probe ")
            );
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata")
                .await
                .unwrap();
        });
        install_iceberg_http_client();
        let before = snapshot()["counts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["kind"] == "GET" && v["prefix"] == "derivatives")
            .map(|v| v["total"].as_u64().unwrap())
            .sum::<u64>();
        let io = FileIOBuilder::new(std::sync::Arc::new(
            iceberg_storage_opendal::OpenDalStorageFactory::S3 {
                customized_credential_load: None,
            },
        ))
        .with_prop(S3_ENDPOINT, endpoint)
        .with_prop(S3_REGION, "auto")
        .with_prop(S3_ACCESS_KEY_ID, "test")
        .with_prop(S3_SECRET_ACCESS_KEY, "test")
        .with_prop(S3_PATH_STYLE_ACCESS, "true")
        .with_prop(S3_DISABLE_EC2_METADATA, "true")
        .with_prop(S3_DISABLE_CONFIG_LOAD, "true")
        .build();
        let body = tokio::time::timeout(Duration::from_secs(10), async {
            io.new_input("s3://bucket/derivatives/probe")
                .unwrap()
                .read()
                .await
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(body.as_ref(), b"data");
        server.await.unwrap();
        let after = snapshot()["counts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["kind"] == "GET" && v["prefix"] == "derivatives")
            .map(|v| v["total"].as_u64().unwrap())
            .sum::<u64>();
        assert!(after > before);
    }

    #[tokio::test]
    async fn failed_wire_attempts_and_retries_are_counted() {
        struct Failed;
        impl HttpFetch for Failed {
            async fn fetch(&self, _: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
                Err(opendal::Error::new(
                    opendal::ErrorKind::Unexpected,
                    "injected",
                ))
            }
        }
        let client = CountingHttp(HttpClient::with(Failed));
        let before = counters()
            .lock()
            .unwrap()
            .total
            .get(&("B", "GET", "bronze-v2", "s3"))
            .copied()
            .unwrap_or(0);
        for _ in 0..2 {
            assert!(
                client
                    .fetch(
                        Request::get("https://example.invalid/bronze-v2/x")
                            .body(Buffer::new())
                            .unwrap()
                    )
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            counters().lock().unwrap().total[&("B", "GET", "bronze-v2", "s3")],
            before + 2
        );
    }

    /// A fixture provider that answers every delete successfully and records the
    /// request line, so a test can prove which deletes reached the wire.
    pub(super) async fn recording_provider_for_lanes() -> (String, std::sync::Arc<Mutex<Vec<String>>>) {
        recording_provider().await
    }

    async fn recording_provider() -> (String, std::sync::Arc<Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let mut request = Vec::new();
                let mut chunk = vec![0; 65_536];
                loop {
                    let length = socket.read(&mut chunk).await.unwrap_or(0);
                    request.extend_from_slice(&chunk[..length]);
                    let text = String::from_utf8_lossy(&request);
                    let complete = text.starts_with("POST ") && text.contains("</Delete>")
                        || !text.starts_with("POST ") && text.contains("\r\n\r\n");
                    if length == 0 || complete {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request).into_owned();
                log.lock().unwrap().push(text.lines().next().unwrap_or("").to_string());
                // OpenDAL expects 204 for DELETE; object_store sends even one
                // delete as a DeleteObjects POST and wants each key echoed back.
                let reply = if text.starts_with("POST ") {
                    let deleted: String = text
                        .split("<Key>")
                        .skip(1)
                        .filter_map(|rest| rest.split_once("</Key>"))
                        .map(|(key, _)| format!("<Deleted><Key>{key}</Key></Deleted>"))
                        .collect();
                    let body = format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{deleted}</DeleteResult>"
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                };
                let _ = socket.write_all(reply.as_bytes()).await;
            }
        });
        (endpoint, seen)
    }

    #[tokio::test]
    async fn opendal_deletes_of_tenants_keys_never_reach_the_provider() {
        let (endpoint, seen) = recording_provider().await;
        let operator = opendal::Operator::new(
            opendal::services::S3::default()
                .bucket("nano-shared-r2-u")
                .region("auto")
                .endpoint(&endpoint)
                .access_key_id("test")
                .secret_access_key("test")
                .disable_config_load()
                .disable_ec2_metadata(),
        )
        .unwrap()
        .layer(layer())
        .finish();
        let error = operator
            .delete("tenants/u/parser-bundles/a.tar.gz")
            .await
            .expect_err("single delete of a tenants/ key must be refused");
        assert_eq!(error.kind(), opendal::ErrorKind::PermissionDenied, "{error}");
        assert!(operator
            .delete_iter(["bronze-v2/shard=0/a", "tenants/u/parser-bundles/b.tar.gz"])
            .await
            .is_err());
        assert!(seen.lock().unwrap().is_empty(), "{:?}", seen.lock().unwrap());
        // Control: an ordinary nanosiem key still reaches the provider.
        operator.delete("bronze-v2/shard=0/a").await.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].starts_with("DELETE /nano-shared-r2-u/bronze-v2/shard%3D0/a "), "{seen:?}");
    }
}

/// The UID ledger uses object_store rather than OpenDAL. Keep its existing
/// connector/options and count each actual HTTP attempt, including retries.
///
/// Where the HTTP I/O runs matters. reqwest spawns each keep-alive
/// connection's I/O task onto whichever Tokio runtime opened it, and the pool
/// hands that connection to any later caller. A store driven from several
/// runtimes that are not always polled -- the platform-stamping journal lanes
/// are one private current-thread runtime each, driven only inside their own
/// block_on -- then parks a request on a connection whose runtime nobody is
/// driving, until the caller's deadline fires (NAN-2361, 2026-09-22: every
/// `claims`/`flush_batch` at exec_ms=20001 while PostgreSQL sat idle).
#[derive(Debug)]
pub struct UidLedgerConnector {
    io: Option<tokio::runtime::Handle>,
}
impl UidLedgerConnector {
    /// I/O runs on the runtime that issues each request. Only for a store used
    /// from a single, always-driven runtime (the publisher's main runtime).
    pub fn caller_runtime() -> Self {
        Self { io: None }
    }
    /// I/O runs on a process-wide runtime that is always driven, so the store
    /// is safe to share across runtimes that are only polled intermittently.
    /// Required for the stamping journal store shared by the journal lanes.
    pub fn dedicated_io() -> std::io::Result<Self> {
        Ok(Self { io: Some(journal_io_runtime()?) })
    }
}
/// Built once and never dropped: dropping a runtime from async context panics,
/// and its worker threads must outlive every store handed its handle.
fn journal_io_runtime() -> std::io::Result<tokio::runtime::Handle> {
    static IO: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();
    match IO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("r2-journal-io")
            .enable_all()
            .build()
            .map_err(|error| error.to_string())
    }) {
        Ok(runtime) => Ok(runtime.handle().clone()),
        Err(error) => Err(std::io::Error::other(error.clone())),
    }
}
impl slatedb::object_store::client::HttpConnector for UidLedgerConnector {
    fn connect(
        &self,
        options: &slatedb::object_store::ClientOptions,
    ) -> slatedb::object_store::Result<slatedb::object_store::client::HttpClient> {
        use slatedb::object_store::client::{ReqwestConnector, SpawnedReqwestConnector};
        let inner = match &self.io {
            None => ReqwestConnector::default().connect(options)?,
            Some(io) => SpawnedReqwestConnector::new(io.clone()).connect(options)?,
        };
        Ok(slatedb::object_store::client::HttpClient::new(UidLedgerHttp(inner)))
    }
}
#[derive(Debug)]
struct UidLedgerHttp(slatedb::object_store::client::HttpClient);
#[async_trait::async_trait]
impl slatedb::object_store::client::HttpService for UidLedgerHttp {
    async fn call(
        &self,
        req: slatedb::object_store::client::HttpRequest,
    ) -> Result<slatedb::object_store::client::HttpResponse, slatedb::object_store::client::HttpError>
    {
        record(
            req.method().as_str(),
            req.uri().path(),
            req.uri().query().unwrap_or(""),
            req.uri().host().unwrap_or(""),
        );
        // NAN-2596: SlateDB GC and compaction deletes go through here too.
        if let Some(refusal) = nanosiem_core::r2_prefix_guard::wire_delete_refusal(
            req.method().as_str(),
            req.uri().path(),
            req.uri().query().unwrap_or(""),
            req.body().as_bytes().map(|bytes| bytes.as_ref()),
        ) {
            return Err(slatedb::object_store::client::HttpError::new(
                slatedb::object_store::client::HttpErrorKind::Unknown,
                refusal,
            ));
        }
        self.0.execute(req).await
    }
}

#[cfg(test)]
mod lane_runtime_tests {
    use super::*;
    use slatedb::object_store::{ObjectStore, ObjectStoreExt, path::Path};
    use std::sync::Arc;
    use std::sync::mpsc::sync_channel;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A keep-alive HTTP/1.1 fixture that answers every request with a tiny
    /// S3-shaped object. It runs on its own always-driven runtime, like R2.
    fn keep_alive_fixture() -> (String, tokio::runtime::Runtime) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        runtime.spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Ok(read) = socket.read(&mut chunk).await else { return };
                        if read == 0 { return; }
                        buffer.extend_from_slice(&chunk[..read]);
                        while let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                            buffer.drain(..end + 4);
                            let response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\
                                last-modified: Tue, 22 Sep 2026 18:00:00 GMT\r\netag: \"fixture\"\r\n\
                                connection: keep-alive\r\n\r\nok";
                            if socket.write_all(response.as_bytes()).await.is_err() { return; }
                        }
                    }
                });
            }
        });
        (endpoint, runtime)
    }

    fn store(endpoint: &str, connector: UidLedgerConnector) -> Arc<dyn ObjectStore> {
        Arc::new(
            slatedb::object_store::aws::AmazonS3Builder::new()
                .with_bucket_name("fixture")
                .with_region("auto")
                .with_endpoint(endpoint)
                .with_allow_http(true)
                .with_access_key_id("fixture")
                .with_secret_access_key("fixture")
                .with_http_connector(connector)
                .build()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn slatedb_object_store_deletes_of_tenants_keys_never_reach_the_provider() {
        let (endpoint, seen) = super::tests::recording_provider_for_lanes().await;
        let store = store(&endpoint, UidLedgerConnector::caller_runtime());
        assert!(store.delete(&Path::from("tenants/u/parser-bundles/a.tar.gz")).await.is_err());
        assert!(seen.lock().unwrap().is_empty(), "{:?}", seen.lock().unwrap());
        store.delete(&Path::from("bronze-uid-ledger-v1/a")).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    /// Mirrors PgLane: one thread per journal lane, each with a private
    /// current-thread runtime that is only driven inside its own block_on.
    /// Lane A reads first, then parks on its queue exactly as an idle lane does
    /// in serve_lane; lane B then reads through the same shared store.
    /// Returns whether lane B's read finished inside `deadline`.
    fn sibling_lane_read_completes(store: Arc<dyn ObjectStore>, deadline: Duration) -> bool {
        let lane = |store: Arc<dyn ObjectStore>| {
            let (sender, receiver) = sync_channel::<std::sync::mpsc::SyncSender<bool>>(1);
            let handle = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                while let Ok(reply) = receiver.recv() {
                    let finished = runtime.block_on(async {
                        tokio::time::timeout(deadline, async {
                            store.get(&Path::from("sidecar")).await?.bytes().await
                        })
                        .await
                    });
                    let _ = reply.send(matches!(finished, Ok(Ok(_))));
                }
            });
            (sender, handle)
        };
        let (lane_a, a) = lane(Arc::clone(&store));
        let (lane_b, b) = lane(store);
        let ask = |lane: &std::sync::mpsc::SyncSender<std::sync::mpsc::SyncSender<bool>>| {
            let (reply, answer) = sync_channel(1);
            lane.send(reply).unwrap();
            answer.recv().unwrap()
        };
        assert!(ask(&lane_a), "the first lane's read must succeed");
        let completed = ask(&lane_b);
        drop((lane_a, lane_b));
        a.join().unwrap();
        b.join().unwrap();
        completed
    }

    /// NAN-2361 (2026-09-22): bronze shards stopped publishing with every
    /// journal `claims`/`flush_batch` failing at exactly exec_ms=20001 while
    /// PostgreSQL sat idle. The offload journal's R2 store is one reqwest
    /// client shared by every journal lane, and each lane is a private
    /// current-thread runtime that only runs inside its own block_on. A pooled
    /// keep-alive connection's I/O task lives on whichever lane opened it, so
    /// when another lane reuses it the request waits for a runtime nobody is
    /// driving -- until JOURNAL_TIMEOUT. The journal store must run its I/O on
    /// a runtime that is always driven.
    #[test]
    fn journal_store_serves_a_sibling_lane_after_the_opening_lane_goes_idle() {
        let (endpoint, _server) = keep_alive_fixture();
        let store = store(&endpoint, UidLedgerConnector::dedicated_io().unwrap());
        assert!(
            sibling_lane_read_completes(store, Duration::from_secs(3)),
            "a read from lane B stalled on a connection whose I/O task lives on idle lane A"
        );
    }
}

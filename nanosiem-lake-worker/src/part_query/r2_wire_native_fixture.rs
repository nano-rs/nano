// SPDX-License-Identifier: AGPL-3.0-or-later
use std::sync::Arc;
/// Loopback S3 transport: the actual production reader issues its HTTP ranges.
/// Provenance still uses LocalObjectStore (one remote GET per cold part in the
/// cost model); counts here deliberately exclude that separate metadata path.
pub(super) struct WireStore {
    pub(super) source: Arc<dyn crate::reader_object_cache::ReaderObjectSource>,
    requests: Arc<std::sync::Mutex<Vec<(String, String, u64)>>>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for WireStore {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl WireStore {
    pub(super) async fn open(root: std::path::PathBuf) -> Self {
        use axum::{
            body::Body,
            extract::{Path, State},
            http::{HeaderMap, Method, Response},
            routing::get,
            Router,
        };
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        type Requests = Arc<std::sync::Mutex<Vec<(String, String, u64)>>>;
        async fn read(
            State((root, requests)): State<(std::path::PathBuf, Requests)>,
            Path(key): Path<String>,
            method: Method,
            headers: HeaderMap,
        ) -> Response<Body> {
            let mut file = tokio::fs::File::open(root.join(key.strip_prefix("bucket/").unwrap()))
                .await
                .unwrap();
            let bytes = file.metadata().await.unwrap().len();
            let range = headers
                .get("range")
                .unwrap()
                .to_str()
                .unwrap()
                .strip_prefix("bytes=")
                .unwrap();
            let (start, end) = range.split_once('-').unwrap();
            let start: u64 = start.parse().unwrap();
            let end = end.parse::<u64>().unwrap() + 1;
            assert!(start < end && end <= bytes);
            requests
                .lock()
                .unwrap()
                .push((method.to_string(), key, end - start));
            file.seek(std::io::SeekFrom::Start(start)).await.unwrap();
            let mut body = vec![0; (end - start) as usize];
            file.read_exact(&mut body).await.unwrap();
            Response::builder()
                .status(206)
                .header(
                    "content-range",
                    format!("bytes {start}-{}/{bytes}", end - 1),
                )
                .header("content-length", body.len())
                .body(Body::from(body))
                .unwrap()
        }
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/{*key}", get(read))
            .with_state((root, requests.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let service = opendal::services::S3::default()
            .bucket("bucket")
            .region("auto")
            .endpoint(&format!("http://{addr}"))
            .access_key_id("fixture")
            .secret_access_key("fixture");
        let operator = opendal::Operator::new(service)
            .unwrap()
            .layer(crate::r2_ops::layer())
            .finish();
        Self {
            source: Arc::new(crate::reader_object_cache::R2ReaderObjectSource::new(
                operator, "bucket",
            )),
            requests,
            server,
        }
    }
    pub(super) fn snapshot(&self) -> (usize, usize, usize, u64) {
        let requests = self.requests.lock().unwrap();
        assert!(
            requests.iter().all(|(method, _, _)| method == "GET"),
            "bounded ranges must not HEAD"
        );
        let manifests = requests
            .iter()
            .filter(|(_, key, _)| key.ends_with(".json"))
            .count();
        (
            requests.len(),
            manifests,
            requests.len() - manifests,
            requests.iter().map(|(_, _, bytes)| bytes).sum(),
        )
    }
}

/// Control-metadata reads are separate from the reader-cache HTTP transport.
/// Count their GET equivalents and returned bytes without attributing them to
/// the production reader's range traffic.
pub(super) struct MetadataStore {
    inner: crate::parts::part_log::LocalObjectStore,
    gets: std::sync::atomic::AtomicU64,
    bytes: std::sync::atomic::AtomicU64,
    heads: std::sync::atomic::AtomicU64,
    lists: std::sync::atomic::AtomicU64,
}
impl MetadataStore {
    pub(super) fn new(root: std::path::PathBuf) -> Self {
        Self {
            inner: crate::parts::part_log::LocalObjectStore::new(root).unwrap(),
            gets: 0.into(),
            bytes: 0.into(),
            heads: 0.into(),
            lists: 0.into(),
        }
    }
    pub(super) fn snapshot(&self) -> (u64, u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.gets.load(Relaxed),
            self.bytes.load(Relaxed),
            self.heads.load(Relaxed),
            self.lists.load(Relaxed),
        )
    }
}
#[async_trait::async_trait]
impl crate::parts::part_log::ObjectStore for MetadataStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        use std::sync::atomic::Ordering::Relaxed;
        self.gets.fetch_add(1, Relaxed);
        let value = self.inner.get(key).await?;
        self.bytes
            .fetch_add(value.as_ref().map_or(0, |v| v.len() as u64), Relaxed);
        Ok(value)
    }
    async fn get_range(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        use std::sync::atomic::Ordering::Relaxed;
        self.gets.fetch_add(1, Relaxed);
        let value = self.inner.get_range(key, range).await?;
        self.bytes
            .fetch_add(value.as_ref().map_or(0, |v| v.len() as u64), Relaxed);
        Ok(value)
    }
    async fn object_size(&self, key: &str) -> anyhow::Result<Option<u64>> {
        self.heads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.object_size(key).await
    }
    async fn object_identity(&self, key: &str) -> anyhow::Result<Option<(String, u64)>> {
        self.heads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.object_identity(key).await
    }
    async fn modified_ms(&self, key: &str) -> anyhow::Result<Option<i64>> {
        self.heads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.modified_ms(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> anyhow::Result<bool> {
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        self.lists
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.list(prefix).await
    }
}

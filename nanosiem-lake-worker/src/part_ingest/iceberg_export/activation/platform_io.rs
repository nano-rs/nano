// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only S3 FileIO with immutable writes through the platform. Neither a
//! provider catalog bearer nor an object-write credential enters this adapter.
use crate::part_ingest::platform_tls::PlatformCatalogClient;
use anyhow::{ensure, Result};
use bytes::{Bytes, BytesMut};
use futures::stream::BoxStream;
use iceberg::io::{
    FileMetadata, FileRead, FileWrite, InputFile, OutputFile, Storage, StorageConfig,
    StorageFactory,
};
use iceberg::{Error, ErrorKind};
use iceberg_storage_opendal::OpenDalStorageFactory;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
fn refused() -> Error {
    Error::new(
        ErrorKind::Unexpected,
        "platform catalog metadata operation refused",
    )
}

struct Authority {
    endpoint: String,
    activation: uuid::Uuid,
    token: String,
    tls: Arc<PlatformCatalogClient>,
    journal: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PlatformMetadataFactory {
    tenant: String,
    bucket: String,
    prefix: String,
    #[serde(skip)]
    authority: Option<Arc<Authority>>,
}
impl fmt::Debug for PlatformMetadataFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlatformMetadataFactory")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}
impl PlatformMetadataFactory {
    pub(crate) fn new(
        tenant: &str,
        bucket: &str,
        prefix: &str,
        endpoint: &str,
        activation: uuid::Uuid,
        token: String,
        tls: Arc<PlatformCatalogClient>,
        work: &Path,
    ) -> Result<Self> {
        crate::parts::format::validate_tenant_uuid(tenant)?;
        ensure!(
            bucket == crate::lake_part_gc::request::tenant_bucket(tenant)
                && super::is_platform_metadata_prefix(tenant, prefix),
            "foreign platform metadata scope"
        );
        ensure!(
            !activation.is_nil() && token.len() >= 32 && !token.chars().any(char::is_control),
            "invalid platform metadata capability"
        );
        let url = reqwest::Url::parse(endpoint)?;
        ensure!(
            (url.scheme() == "https"
                || (cfg!(test) && url.scheme() == "http" && url.host_str() == Some("127.0.0.1")))
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid platform metadata endpoint"
        );
        let journal = work.join(format!("metadata-uploads-{activation}"));
        std::fs::create_dir_all(&journal)?;
        ensure!(
            std::fs::symlink_metadata(&journal)?.is_dir(),
            "metadata journal must be a directory"
        );
        Ok(Self {
            tenant: tenant.into(),
            bucket: bucket.into(),
            prefix: prefix.into(),
            authority: Some(Arc::new(Authority {
                endpoint: endpoint.trim_end_matches('/').into(),
                activation,
                token,
                tls,
                journal,
            })),
        })
    }
    // A response may be lost after an immutable upload commits. Keep only the
    // metadata bytes and URI, never credentials, so restart can replay exactly.
    pub(crate) async fn replay(&self) -> Result<()> {
        let a = self
            .authority
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("metadata authority absent"))?;
        let entries: Vec<_> = std::fs::read_dir(&a.journal)?.collect::<std::io::Result<_>>()?;
        ensure!(entries.len() <= 8, "metadata journal bound exceeded");
        for entry in entries {
            ensure!(
                entry.file_type()?.is_file(),
                "unsafe metadata journal entry"
            );
            let name = entry.file_name();
            let name = name.to_str().unwrap_or("");
            // atomic_write's uncommitted tempfiles are never replayed.
            if !name.ends_with(".pending") {
                ensure!(name.starts_with('.'), "invalid metadata journal entry");
                continue;
            }
            let data = Self::read_pending(&entry.path())?;
            let n = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
            ensure!(
                n > 0 && n <= 4096 && 4 + n <= data.len(),
                "invalid metadata journal header"
            );
            let uri = std::str::from_utf8(&data[4..4 + n])?;
            ensure!(
                name == format!("{}.pending", crate::parts::sha256_hex(uri.as_bytes())),
                "metadata journal identity differs"
            );
            self.identity(uri)?;
            self.upload(uri, Bytes::copy_from_slice(&data[4 + n..]), true)
                .await?;
        }
        Ok(())
    }
    fn read_pending(path: &Path) -> Result<Vec<u8>> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        ensure!(
            file.metadata()?.is_file()
                && file.metadata()?.len() <= MAX_METADATA_BYTES as u64 + 4100,
            "metadata journal bound exceeded"
        );
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes)?;
        ensure!(
            bytes.len() >= 4 && bytes.len() <= MAX_METADATA_BYTES + 4100,
            "invalid metadata journal"
        );
        Ok(bytes)
    }
    async fn upload(&self, path: &str, bytes: Bytes, replay: bool) -> iceberg::Result<()> {
        let (table, file) = self.identity(path)?;
        if !file.ends_with(".avro") || bytes.len() > MAX_METADATA_BYTES {
            return Err(refused());
        }
        let a = self.authority.as_ref().ok_or_else(refused)?;
        let pending = a.journal.join(format!(
            "{}.pending",
            crate::parts::sha256_hex(path.as_bytes())
        ));
        let mut data = Vec::with_capacity(4 + path.len() + bytes.len());
        data.extend_from_slice(&(path.len() as u32).to_be_bytes());
        data.extend_from_slice(path.as_bytes());
        data.extend_from_slice(&bytes);
        if pending.exists() {
            if Self::read_pending(&pending).map_err(|_| refused())? != data {
                return Err(refused());
            }
        } else {
            crate::part_ingest::export::atomic_write(&pending, &data, true)
                .map_err(|_| refused())?;
        }
        let digest = crate::parts::sha256_hex(&bytes);
        let response = a
            .tls
            .client()
            .put(format!(
                "{}/{}/{}/objects/{table}/{file}",
                a.endpoint, self.tenant, a.activation
            ))
            .bearer_auth(&a.token)
            .header("content-type", "application/octet-stream")
            .body(bytes)
            .send()
            .await
            .map_err(|_| refused())?;
        let retired = response.status() == reqwest::StatusCode::GONE;
        if !response.status().is_success() && !retired {
            return Err(refused());
        }
        let receipt: serde_json::Value = response.json().await.map_err(|_| refused())?;
        if receipt["tenant_id"] != self.tenant
            || receipt["activation_id"] != a.activation.to_string()
            || receipt["table"] != table
            || receipt["file"] != file
            || receipt["sha256"] != digest
            || retired && receipt["retired"] != true
        {
            return Err(refused());
        }
        std::fs::remove_file(&pending).map_err(|_| refused())?;
        std::fs::File::open(&a.journal)
            .and_then(|f| f.sync_all())
            .map_err(|_| refused())?;
        // A permanently retired key cannot be resurrected, even by replay. A
        // normal writer must choose a fresh nonce; replay can discard its blob.
        if retired && !replay {
            return Err(refused());
        }
        Ok(())
    }
    fn identity(&self, path: &str) -> iceberg::Result<(String, String)> {
        let root = format!("s3://{}/{}", self.bucket, self.prefix);
        let relative = path.strip_prefix(&root).ok_or_else(refused)?;
        let pieces: Vec<_> = relative.split('/').collect();
        if pieces.len() != 3
            || pieces[1] != "metadata"
            || pieces[2].is_empty()
            || pieces[2].len() > 255
            || !pieces[2]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || pieces[2].starts_with('.')
            || !pieces[2].ends_with(".avro") && !pieces[2].ends_with(".json")
        {
            return Err(refused());
        }
        let table = pieces[0];
        if table != "events_v1"
            && !(table.starts_with("events_")
                && table.ends_with("_v1")
                && table.len() == 42
                && table[7..39].bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(refused());
        }
        Ok((table.into(), pieces[2].into()))
    }
}
#[typetag::serde(name = "nano_agent_catalog_platform_v2")]
impl StorageFactory for PlatformMetadataFactory {
    fn build(&self, config: &StorageConfig) -> iceberg::Result<Arc<dyn Storage>> {
        if self.authority.is_none() {
            return Err(refused());
        }
        let inner = OpenDalStorageFactory::S3 {
            customized_credential_load: None,
        }
        .build(config)?;
        Ok(Arc::new(PlatformMetadata {
            factory: self.clone(),
            inner,
        }))
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct PlatformMetadata {
    factory: PlatformMetadataFactory,
    inner: Arc<dyn Storage>,
}
impl fmt::Debug for PlatformMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlatformMetadata")
            .field("tenant", &self.factory.tenant)
            .finish_non_exhaustive()
    }
}
#[async_trait::async_trait]
#[typetag::serde(name = "nano_agent_catalog_platform_metadata_v2")]
impl Storage for PlatformMetadata {
    async fn exists(&self, path: &str) -> iceberg::Result<bool> {
        self.factory.identity(path)?;
        self.inner.exists(path).await.map_err(|_| refused())
    }
    async fn metadata(&self, path: &str) -> iceberg::Result<FileMetadata> {
        self.factory.identity(path)?;
        self.inner.metadata(path).await.map_err(|_| refused())
    }
    async fn read(&self, path: &str) -> iceberg::Result<Bytes> {
        self.factory.identity(path)?;
        if self.inner.metadata(path).await.map_err(|_| refused())?.size > MAX_METADATA_BYTES as u64
        {
            return Err(refused());
        }
        let bytes = self.inner.read(path).await.map_err(|_| refused())?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(refused());
        }
        Ok(bytes)
    }
    async fn reader(&self, path: &str) -> iceberg::Result<Box<dyn FileRead>> {
        self.factory.identity(path)?;
        Ok(Box::new(MetadataReader {
            store: self.clone(),
            path: path.into(),
        }))
    }
    async fn write(&self, path: &str, bytes: Bytes) -> iceberg::Result<()> {
        self.factory.upload(path, bytes, false).await
    }
    async fn writer(&self, path: &str) -> iceberg::Result<Box<dyn FileWrite>> {
        self.factory.identity(path)?;
        Ok(Box::new(MetadataWriter {
            store: self.clone(),
            path: path.into(),
            bytes: BytesMut::new(),
            closed: false,
        }))
    }
    async fn delete(&self, _path: &str) -> iceberg::Result<()> {
        Err(refused())
    }
    async fn delete_prefix(&self, _path: &str) -> iceberg::Result<()> {
        Err(refused())
    }
    async fn delete_stream(&self, _paths: BoxStream<'static, String>) -> iceberg::Result<()> {
        Err(refused())
    }
    fn new_input(&self, path: &str) -> iceberg::Result<InputFile> {
        self.factory.identity(path)?;
        Ok(InputFile::new(Arc::new(self.clone()), path.into()))
    }
    fn new_output(&self, path: &str) -> iceberg::Result<OutputFile> {
        self.factory.identity(path)?;
        Ok(OutputFile::new(Arc::new(self.clone()), path.into()))
    }
}
struct MetadataReader {
    store: PlatformMetadata,
    path: String,
}
#[async_trait::async_trait]
impl FileRead for MetadataReader {
    async fn read(&self, range: std::ops::Range<u64>) -> iceberg::Result<Bytes> {
        if range.start > range.end || range.end - range.start > MAX_METADATA_BYTES as u64 {
            return Err(refused());
        }
        let bytes = self.store.read(&self.path).await?;
        if range.end > bytes.len() as u64 {
            return Err(refused());
        }
        Ok(bytes.slice(range.start as usize..range.end as usize))
    }
}
struct MetadataWriter {
    store: PlatformMetadata,
    path: String,
    bytes: BytesMut,
    closed: bool,
}
#[async_trait::async_trait]
impl FileWrite for MetadataWriter {
    async fn write(&mut self, bytes: Bytes) -> iceberg::Result<()> {
        if self.closed || self.bytes.len().saturating_add(bytes.len()) > MAX_METADATA_BYTES {
            return Err(refused());
        }
        self.bytes.extend_from_slice(&bytes);
        Ok(())
    }
    async fn close(&mut self) -> iceberg::Result<()> {
        if self.closed {
            return Err(refused());
        }
        self.closed = true;
        self.store
            .write(&self.path, self.bytes.split().freeze())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        extract::State,
        http::{Request, Response},
        routing::any,
        Router,
    };
    use iceberg::io::{
        FileIOBuilder, S3_ACCESS_KEY_ID, S3_DISABLE_CONFIG_LOAD, S3_DISABLE_EC2_METADATA,
        S3_ENDPOINT, S3_REGION, S3_SECRET_ACCESS_KEY,
    };
    use std::sync::Mutex;
    const TENANT: &str = "00000000-0000-0000-0000-000000000001";
    const TOKEN: &str = "tenant-scoped-control-fixture-only-123456789";
    struct Wire {
        calls: Vec<Vec<u8>>,
        fail: bool,
        retired: bool,
    }
    async fn handle(
        State(wire): State<Arc<Mutex<Wire>>>,
        request: Request<Body>,
    ) -> Response<Body> {
        assert_eq!(request.method(), "PUT");
        assert_eq!(
            request.headers()["authorization"],
            format!("Bearer {TOKEN}")
        );
        let path = request.uri().path().to_string();
        let parts: Vec<_> = path.split('/').collect();
        assert_eq!(parts[1], TENANT);
        assert_eq!(parts[3], "objects");
        assert_eq!(parts[4], "events_v1");
        let bytes = to_bytes(request.into_body(), MAX_METADATA_BYTES)
            .await
            .unwrap();
        let mut wire = wire.lock().unwrap();
        wire.calls.push(bytes.to_vec());
        if wire.fail {
            return Response::builder().status(503).body(Body::empty()).unwrap();
        }
        let receipt = serde_json::json!({"tenant_id":TENANT,"activation_id":parts[2],"table":"events_v1","file":parts[5],"sha256":crate::parts::sha256_hex(&bytes),"retired":wire.retired});
        Response::builder()
            .status(if wire.retired { 410 } else { 200 })
            .header("content-type", "application/json")
            .body(Body::from(receipt.to_string()))
            .unwrap()
    }
    async fn setup() -> (
        tempfile::TempDir,
        Arc<Mutex<Wire>>,
        tokio::task::JoinHandle<()>,
        PlatformMetadataFactory,
        iceberg::io::FileIO,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let wire = Arc::new(Mutex::new(Wire {
            calls: vec![],
            fail: false,
            retired: false,
        }));
        let app = Router::new().fallback(any(handle)).with_state(wire.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let factory = PlatformMetadataFactory::new(
            TENANT,
            &crate::lake_part_gc::request::tenant_bucket(TENANT),
            &format!("__r2_data_catalog/agent/v2/tenant={TENANT}/agent/"),
            &endpoint,
            uuid::Uuid::new_v4(),
            TOKEN.into(),
            Arc::new(PlatformCatalogClient::new(&endpoint, std::time::Duration::from_secs(5), Default::default()).unwrap()),
            dir.path(),
        )
        .unwrap();
        let io = FileIOBuilder::new(Arc::new(factory.clone()))
            .with_props([
                (S3_ACCESS_KEY_ID, "read-only-child"),
                (S3_SECRET_ACCESS_KEY, "read-only-child"),
                (S3_REGION, "auto"),
                (S3_ENDPOINT, &endpoint),
                (S3_DISABLE_CONFIG_LOAD, "true"),
                (S3_DISABLE_EC2_METADATA, "true"),
            ])
            .build();
        (dir, wire, server, factory, io)
    }
    fn path() -> String {
        format!("s3://nano-shared-r2-{TENANT}/__r2_data_catalog/agent/v2/tenant={TENANT}/agent/events_v1/metadata/export-00000000-0000-4000-8000-000000000001.avro")
    }
    #[tokio::test]
    async fn production_file_io_uploads_through_control_and_refuses_foreign_paths_and_direct_deletes(
    ) {
        let (_dir, wire, server, factory, io) = setup().await;
        let output = io.new_output(path()).unwrap();
        let mut writer = output.writer().await.unwrap();
        writer
            .write(Bytes::from_static(b"production metadata fixture"))
            .await
            .unwrap();
        writer.close().await.unwrap();
        assert_eq!(wire.lock().unwrap().calls.len(), 1);
        assert!(io
            .new_output(path().replace(TENANT, "00000000-0000-0000-0000-000000000002"))
            .is_err());
        assert!(io.delete(path()).await.is_err());
        assert!(io.delete_prefix(path()).await.is_err());
        let serialized = serde_json::to_string(&factory).unwrap();
        assert!(
            !serialized.contains(TOKEN)
                && !serialized.contains("journal")
                && !format!("{factory:?}").contains(TOKEN)
        );
        let restored: PlatformMetadataFactory = serde_json::from_str(&serialized).unwrap();
        assert!(restored.build(&StorageConfig::new()).is_err());
        assert_eq!(
            std::fs::read_dir(&factory.authority.as_ref().unwrap().journal)
                .unwrap()
                .count(),
            0
        );
        server.abort();
    }
    #[tokio::test]
    async fn lost_upload_receipt_is_replayed_after_restart_without_a_credential_file() {
        let (dir, wire, server, factory, io) = setup().await;
        wire.lock().unwrap().fail = true;
        assert!(io
            .new_output(path())
            .unwrap()
            .write(Bytes::from_static(b"pending immutable metadata"))
            .await
            .is_err());
        let a = factory.authority.as_ref().unwrap();
        let pending = std::fs::read_dir(&a.journal)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert!(!std::fs::read(pending.path())
            .unwrap()
            .windows(TOKEN.len())
            .any(|b| b == TOKEN.as_bytes()));
        wire.lock().unwrap().fail = false;
        let restarted = PlatformMetadataFactory::new(
            TENANT,
            &factory.bucket,
            &factory.prefix,
            &a.endpoint,
            a.activation,
            TOKEN.into(),
            a.tls.clone(),
            dir.path(),
        )
        .unwrap();
        restarted.replay().await.unwrap();
        assert_eq!(
            wire.lock().unwrap().calls,
            vec![b"pending immutable metadata".to_vec(); 2]
        );
        assert_eq!(std::fs::read_dir(&a.journal).unwrap().count(), 0);
        server.abort();
    }
    #[tokio::test]
    async fn permanently_retired_upload_is_discarded_on_replay_but_cannot_be_reused() {
        let (_dir, wire, server, factory, io) = setup().await;
        wire.lock().unwrap().fail = true;
        assert!(io
            .new_output(path())
            .unwrap()
            .write(Bytes::from_static(b"old metadata"))
            .await
            .is_err());
        {
            let mut w = wire.lock().unwrap();
            w.fail = false;
            w.retired = true;
        }
        factory.replay().await.unwrap();
        assert!(io
            .new_output(path())
            .unwrap()
            .write(Bytes::from_static(b"new metadata"))
            .await
            .is_err());
        assert_eq!(
            std::fs::read_dir(&factory.authority.as_ref().unwrap().journal)
                .unwrap()
                .count(),
            0
        );
        server.abort();
    }
}

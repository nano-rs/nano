// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`ObjectStore`] over an S3-compatible bucket (R2), scoped to one prefix.
//! Conditional create is `If-None-Match: *`.

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use futures::TryStreamExt;
use opendal::layers::RetryLayer;
use opendal::services::S3;
use opendal::{ErrorKind, Operator};
use serde::Deserialize;
use std::time::Duration;

use crate::parts::part_log::ObjectStore;

/// Where and how to reach one tenant-scoped bucket prefix.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Location {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Key prefix inside the bucket (no leading slash); may be empty.
    pub prefix: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
}

impl std::fmt::Debug for S3Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Location")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// Credentials are short-lived (cell exchange TTL); [`Self::replace`] swaps
/// in refreshed ones without rebuilding the store's users.
struct ScopedOperator {
    operator: Operator,
    scope: String,
    scope_epoch: u64,
}

impl std::ops::Deref for ScopedOperator {
    type Target = Operator;
    fn deref(&self) -> &Self::Target {
        &self.operator
    }
}

pub struct S3ObjectStore {
    op: arc_swap::ArcSwap<ScopedOperator>,
    gc_guard: std::sync::RwLock<Option<std::sync::Arc<crate::r2_ops::GcHttpGuard>>>,
    gc_epoch: tokio::sync::watch::Sender<u64>,
    replacement: std::sync::Mutex<()>,
}

impl S3ObjectStore {
    pub fn new(location: &S3Location) -> Result<Self> {
        Ok(Self {
            op: arc_swap::ArcSwap::from_pointee(Self::scoped_operator(location, None)?),
            gc_guard: std::sync::RwLock::new(None),
            gc_epoch: tokio::sync::watch::channel(0).0,
            replacement: std::sync::Mutex::new(()),
        })
    }

    /// Swap in refreshed credentials.
    pub fn replace(&self, location: &S3Location) -> Result<()> {
        let _replacement = self.replacement.lock().expect("S3 replacement lock");
        let guard = self.gc_guard.read().expect("GC guard lock").clone();
        self.replace_locked(location, guard)
    }

    fn replace_locked(&self, location: &S3Location, guard: Option<std::sync::Arc<crate::r2_ops::GcHttpGuard>>) -> Result<()> {
        let epoch = self.gc_epoch.borrow().checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("S3 request epoch exhausted"))?;
        let transport = guard.map(|guard| (guard, self.gc_epoch.clone(), epoch));
        let mut next = Self::scoped_operator(location, transport)?;
        let previous = self.op.load_full();
        next.scope_epoch = if previous.scope == next.scope {
            previous.scope_epoch
        } else {
            previous.scope_epoch.checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("S3 scope epoch exhausted"))?
        };
        self.gc_epoch.send_replace(epoch);
        self.op.store(std::sync::Arc::new(next));
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn gc_operator_snapshot(&self) -> std::sync::Arc<Operator> {
        std::sync::Arc::new(self.op.load().operator.clone())
    }

    /// Storage identity only: credential rotation can retain observations,
    /// while endpoint/bucket/prefix/region replacement must invalidate them.
    pub fn inventory_scope(&self) -> String {
        let op = self.op.load();
        format!("{}:{}", op.scope_epoch, op.scope)
    }

    fn scoped_operator(location: &S3Location, guard: Option<(std::sync::Arc<crate::r2_ops::GcHttpGuard>, tokio::sync::watch::Sender<u64>, u64)>) -> Result<ScopedOperator> {
        Ok(ScopedOperator {
            operator: Self::operator(location, guard)?,
            scope_epoch: 0,
            scope: serde_json::to_string(&(
                &location.endpoint,
                &location.region,
                &location.bucket,
                location.prefix.trim_matches('/'),
            ))?,
        })
    }

    pub(crate) fn guard_gc(
        &self,
        location: &S3Location,
        guard: std::sync::Arc<crate::r2_ops::GcHttpGuard>,
    ) -> Result<()> {
        let _replacement = self.replacement.lock().expect("S3 replacement lock");
        self.replace_locked(location, Some(guard.clone()))?;
        *self.gc_guard.write().expect("GC guard lock") = Some(guard);
        Ok(())
    }

    fn operator(location: &S3Location,
        guard: Option<(std::sync::Arc<crate::r2_ops::GcHttpGuard>, tokio::sync::watch::Sender<u64>, u64)>,
    ) -> Result<Operator> {
        let mut builder = S3::default()
            .bucket(&location.bucket)
            .region(&location.region)
            .endpoint(&location.endpoint)
            .root(&format!("/{}", location.prefix.trim_matches('/')))
            .access_key_id(&location.access_key_id)
            .secret_access_key(&location.secret_access_key)
            .disable_config_load()
            .disable_ec2_metadata();
        if let Some(token) = &location.session_token {
            builder = builder.session_token(token);
        }
        let retry = RetryLayer::new()
            .with_min_delay(Duration::from_millis(200))
            .with_max_delay(Duration::from_secs(5))
            .with_max_times(5)
            .with_jitter();
        // OpenDAL's HTTP client has no timeout of its own: one stalled R2
        // connection once parked the whole ingest loop forever. Every
        // attempt is bounded (and retried by the outer layer).
        let timeout = opendal::layers::TimeoutLayer::new()
            .with_timeout(Duration::from_secs(60))
            .with_io_timeout(Duration::from_secs(30));
        let http = match guard {
            Some((guard, epoch, expected)) => crate::r2_ops::gc_layer(guard, epoch, expected)?,
            None => crate::r2_ops::layer(),
        };
        Ok(Operator::new(builder)?.layer(http).layer(timeout).layer(retry).finish())
    }

    /// Resume an ordered S3 listing after credential rotation using the last
    /// accepted key. Every range must finish; no partial result escapes. New
    /// immutable objects inserted before the cursor are conservatively deferred.
    /// A storage-contract change (including A -> B -> A) permanently ends it.
    async fn next_listing_entry(
        &self,
        prefix: &str,
        op: &mut std::sync::Arc<ScopedOperator>,
        entries: &mut opendal::Lister,
        cursor: &mut Option<String>,
        restarts: &mut usize,
    ) -> Result<Option<opendal::Entry>> {
        loop {
            let current = self.op.load_full();
            if !std::sync::Arc::ptr_eq(op, &current) {
                ensure!(
                    op.scope == current.scope && op.scope_epoch == current.scope_epoch,
                    "S3 listing storage scope replaced"
                );
                *restarts += 1;
                ensure!(
                    *restarts <= 32,
                    "S3 listing credential restart budget exhausted"
                );
                *op = current;
                let list = op.lister_with(prefix).recursive(true).limit(GC_LIST_PAGE_KEYS);
                *entries = match cursor.as_deref() {
                    Some(key) => list.start_after(key).await?,
                    None => list.await?,
                };
                continue;
            }
            let guard = self.gc_guard.read().expect("GC guard lock").clone();
            let read = async { Ok(entries.try_next().await?) };
            let entry: Result<Option<opendal::Entry>> = match guard {
                Some(guard) => guard.run(read).await,
                None => read.await,
            };
            if !std::sync::Arc::ptr_eq(op, &self.op.load_full()) {
                // Discard an obsolete response or transport cancellation. The
                // replacement operator signs the remaining range with current
                // credentials, without relisting already accepted pages.
                continue;
            }
            if entry.as_ref().is_err_and(|error| {
                crate::part_ingest::part_gc_cell::is_refresh_suspended(error)
            }) {
                // The operation was dropped before replacement publication.
                // Await only the typed closed suspension, then require a new
                // immutable operator before resuming the unaccepted range.
                let guard = self.gc_guard.read().expect("GC guard lock").clone()
                    .ok_or_else(|| anyhow::anyhow!("GC suspension without a guarded operator"))?;
                guard.wait_refresh().await?;
                ensure!(!std::sync::Arc::ptr_eq(op, &self.op.load_full()),
                    "GC suspended listing has no replacement operator");
                continue;
            }
            let Some(entry) = entry? else { return Ok(None) };
            ensure!(
                entry.path().starts_with(prefix),
                "S3 listing escaped prefix"
            );
            ensure!(
                cursor.as_deref().is_none_or(|key| entry.path() > key),
                "S3 listing is not strictly ordered"
            );
            *cursor = Some(entry.path().to_string());
            return Ok(Some(entry));
        }
    }

    /// Up to `limit` objects under `prefix` with keys strictly after
    /// `start_after`, in key order, with their ETag (unquoted), size and
    /// upload time: the trusted-local bronze listing queue's input
    /// (NAN-3492). Directories are skipped.
    pub async fn list_page_after(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<super::bronze_list::ListedBronze>> {
        let mut op = self.op.load_full();
        let list = op.lister_with(prefix).recursive(true).limit(limit.clamp(1, GC_LIST_PAGE_KEYS));
        let mut entries = match start_after {
            Some(key) => list.start_after(key).await?,
            None => list.await?,
        };
        let (mut cursor, mut restarts) = (start_after.map(str::to_string), 0);
        let mut out = Vec::with_capacity(limit.min(GC_LIST_PAGE_KEYS));
        while out.len() < limit {
            let Some(entry) = self
                .next_listing_entry(prefix, &mut op, &mut entries, &mut cursor, &mut restarts)
                .await?
            else {
                break;
            };
            let meta = entry.metadata();
            if !meta.is_file() {
                continue;
            }
            out.push(super::bronze_list::ListedBronze {
                key: entry.path().to_string(),
                etag: meta.etag().unwrap_or_default().trim_start_matches("W/").trim_matches('"').to_string(),
                bytes: meta.content_length(),
                last_modified_ms: meta.last_modified().and_then(|modified| {
                    std::time::SystemTime::from(modified)
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_millis() as i64)
                }),
            });
        }
        Ok(out)
    }

    /// Bounded trusted-local bronze selection. Streams the listing without
    /// retaining unconsumed keys; scope rotation invalidates the entire result.
    pub(crate) async fn list_local_gc_candidates<F>(&self, prefix: &str, eligible: F) -> Result<Vec<String>>
    where F: Fn(&str) -> bool + Send {
        let mut op = self.op.load_full();
        let mut entries = op.lister_with(prefix).recursive(true).limit(GC_LIST_PAGE_KEYS).await?;
        let (mut cursor, mut restarts) = (None, 0);
        let mut out = Vec::with_capacity(512);
        while let Some(entry) = self.next_listing_entry(prefix, &mut op, &mut entries, &mut cursor, &mut restarts).await? {
            if entry.metadata().is_file() && eligible(entry.path()) {
                out.push(entry.path().to_string());
                if out.len() == 512 { break; }
            }
        }
        ensure!(op.scope == self.op.load().scope && op.scope_epoch == self.op.load().scope_epoch, "local GC listing storage scope replaced");
        Ok(out)
    }

    /// List every object under `prefix` with its strong ETag (quoted, as
    /// R2 reports it), size and upload time: the lake-part GC planner's
    /// input. This legacy full materialization rejects oversized inventories;
    /// the cell uses `list_selected_with_metadata` to stream a complete scan.
    /// An object whose listing lacks an ETag or upload time is left
    /// out (never planned), so a partial listing can only keep objects.
    pub async fn list_with_metadata(&self, prefix: &str) -> Result<Vec<crate::lake_part_gc::ListedPartObject>> {
        self.scan_metadata(prefix, None).await
    }

    pub(crate) async fn list_selected_with_metadata(
        &self, prefix: &str,
        selection: &crate::lake_part_gc::planner::InventorySelection<'_>,
    ) -> Result<Vec<crate::lake_part_gc::ListedPartObject>> {
        self.scan_metadata(prefix, Some(selection)).await
    }

    async fn scan_metadata(
        &self, prefix: &str,
        selection: Option<&crate::lake_part_gc::planner::InventorySelection<'_>>,
    ) -> Result<Vec<crate::lake_part_gc::ListedPartObject>> {
        let mut op = self.op.load_full();
        let mut entries = op.lister_with(prefix).recursive(true).limit(GC_LIST_PAGE_KEYS).await?;
        let (mut cursor, mut restarts) = (None, 0);
        let mut out = Vec::with_capacity(selection.map_or(0, |selection| selection.limit()));
        let (mut count, mut bytes) = (0_usize, 0_usize);
        while let Some(entry) = self
            .next_listing_entry(prefix, &mut op, &mut entries, &mut cursor, &mut restarts)
            .await?
        {
            count = count.saturating_add(1);
            bytes = bytes.saturating_add(
                entry.path().len()
                    + entry.metadata().etag().map_or(0, str::len)
                    + std::mem::size_of::<crate::lake_part_gc::ListedPartObject>(),
            );
            ensure!(
                selection.is_some() || (count <= MAX_GC_LIST_OBJECTS && bytes <= MAX_GC_LIST_BYTES),
                "GC full listing exceeds inventory budget"
            );
            let Some(object) = listed_object(entry.path(), entry.metadata()) else { continue };
            if selection.is_none_or(|selection| out.len() < selection.limit() && selection.eligible(&object)) {
                out.push(object);
                if selection.is_some() { check_gc_inventory_capacity(&out, out.capacity())?; }
            }
        }
        ensure!(
            op.scope == self.op.load().scope && op.scope_epoch == self.op.load().scope_epoch,
            "GC listing storage scope replaced"
        );
        check_gc_inventory_capacity(&out, out.capacity())?;
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }
}

impl S3ObjectStore {
    /// The stored object's quoted strong ETag and length (one HEAD);
    /// `None` when it does not exist.
    pub async fn stat_strong(&self, key: &str) -> Result<Option<(String, u64)>> {
        match self.op.load().stat(key).await {
            Ok(meta) => {
                let etag = meta.etag().context("stored object has no ETag")?;
                Ok(Some((quoted_etag(etag), meta.content_length())))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

fn listed_object(key: &str, meta: &opendal::Metadata) -> Option<crate::lake_part_gc::ListedPartObject> {
    if !meta.is_file() { return None; }
    let (Some(etag), Some(modified)) = (meta.etag(), meta.last_modified()) else {
        tracing::debug!(key, "listed part object has no etag or upload time; not planned");
        return None;
    };
    let uploaded = std::time::SystemTime::from(modified)
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Some(crate::lake_part_gc::ListedPartObject {
        key: key.to_string(), strong_etag: quoted_etag(etag),
        content_length: meta.content_length(), uploaded_at_ms: uploaded,
    })
}

/// Includes keys, ETags and per-object storage; reject, never truncate.
/// Keys requested per S3 ListObjectsV2 page by the GC inventory scan
/// (NAN-3359). 1000 is the S3/R2 maximum: every page is one R2 Class A
/// operation, so 256-key pages cost ~3.9x the LIST calls for the same scan of
/// `lake/parts/v1/tenant=…/parts/` (run every <=10 min). A 1000-key page is
/// ~0.5 MiB of XML, inside the guarded transport's 4 MiB response cap and its
/// 32 MiB parsed-allocation reservation; the inventory itself stays bounded by
/// MAX_GC_LIST_OBJECTS / MAX_GC_LIST_BYTES, not by the page size.
pub(crate) const GC_LIST_PAGE_KEYS: usize = 1_000;
/// Largest key page a guarded GC listing accepts (one checkpoint scan).
pub(crate) const GC_CHECKPOINT_PAGE_KEYS: usize = 256;
pub(crate) const MAX_GC_LIST_OBJECTS: usize = 262_144;
pub(crate) const MAX_GC_LIST_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn check_gc_inventory(objects: &[crate::lake_part_gc::ListedPartObject]) -> Result<()> {
    check_gc_inventory_capacity(objects, objects.len())
}

fn check_gc_inventory_capacity(objects: &[crate::lake_part_gc::ListedPartObject], capacity: usize) -> Result<()> {
    let bytes = objects.iter().fold(
        capacity.saturating_mul(std::mem::size_of::<crate::lake_part_gc::ListedPartObject>()),
        |total, object| {
        total.saturating_add(
            object.key.capacity() + object.strong_etag.capacity(),
        )
    });
    ensure!(
        objects.len() <= MAX_GC_LIST_OBJECTS && bytes <= MAX_GC_LIST_BYTES,
        "GC full listing exceeds inventory budget"
    );
    Ok(())
}

/// S3 list XML carries the ETag quoted; keep a bare one comparable.
fn quoted_etag(etag: &str) -> String {
    if etag.starts_with('"') || etag.starts_with("W/") {
        etag.to_string()
    } else {
        format!("\"{etag}\"")
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    async fn get_range(&self,key:&str,range:std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
        let bytes=range.end.checked_sub(range.start).context("invalid object range")?;
        ensure!(bytes>0 && bytes<=crate::parts::part_log::MAX_RANGE_GET_BYTES,"export object range exceeds budget");
        let op=self.op.load_full();
        match op.read_with(key).range(range).await {
            Ok(buffer)=>Ok(Some(buffer.to_vec())),
            Err(e) if e.kind()==ErrorKind::NotFound=>Ok(None),
            Err(e)=>Err(e.into()),
        }
    }
    async fn object_size(&self, key: &str) -> Result<Option<u64>> {
        match self.op.load().stat(key).await {
            Ok(meta) => Ok(Some(meta.content_length())),
            Err(e) if e.kind()==ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn modified_ms(&self, key: &str) -> Result<Option<i64>> {
        match self.op.load().stat(key).await {
            Ok(meta) => Ok(meta.last_modified().and_then(|modified| {
                std::time::SystemTime::from(modified)
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|at| at.as_millis() as i64)
            })),
            Err(e) if e.kind()==ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let guard = self.gc_guard.read().expect("GC guard lock").clone();
        let op = self.op.load_full();
        let read = async {
            match op.read(key).await {
                Ok(buffer) => Ok(Some(buffer.to_vec())),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            }
        };
        match guard {
            Some(guard) => guard.run(read).await,
            None => read.await,
        }
    }

    async fn get_to_file(&self, key: &str, path: &std::path::Path) -> Result<bool> {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;
        let op = self.op.load();
        let reader = match op.reader(key).await {
            Ok(reader) => reader,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let mut stream = reader.into_bytes_stream(..).await?;
        let mut file = tokio::fs::File::create(path).await?;
        while let Some(chunk) = stream.next().await {
            file.write_all(&chunk?).await?;
        }
        file.sync_all().await?;
        Ok(true)
    }

    /// Export copies use a single conditional streaming PUT, avoiding the
    /// default trait implementation's whole-file allocation. The staged file
    /// is private and its digest/length were checked by the export adapter.
    async fn put_export_file_if_absent(&self,key:&str,path:&std::path::Path,sha256_hex:&str,bytes:u64,_hints:&crate::parts::part_log::WriteHints) -> Result<bool> {
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut file=tokio::fs::File::open(path).await?;
        ensure!(file.metadata().await?.len()==bytes,"export staged size changed");
        let mut hash=Sha256::new();
        let mut buffer=vec![0u8;4*1024*1024];
        loop {
            let count=file.read(&mut buffer).await?;
            if count==0 { break; }
            hash.update(&buffer[..count]);
        }
        ensure!(hex::encode(hash.finalize())==sha256_hex,"export staged digest changed");
        file.rewind().await?;
        let op=self.op.load_full();
        let signed=op.presign_write_options(key,Duration::from_secs(600),opendal::options::WriteOptions { if_not_exists:true,..Default::default() }).await
            .map_err(|_|anyhow::anyhow!("export PUT signing failed"))?;
        ensure!(signed.header().get(reqwest::header::IF_NONE_MATCH).is_some_and(|v|v=="*"),"export PUT lacks conditional header");
        let client=reqwest::Client::builder().connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none()).build()?;
        let response=client.request(signed.method().clone(),signed.uri().to_string()).headers(signed.header().clone())
            .header(reqwest::header::CONTENT_LENGTH,bytes).body(reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file)))
            .send().await.map_err(|_|anyhow::anyhow!("export conditional PUT transport failed"))?;
        match response.status().as_u16() {
            200=>Ok(true),412|409=>Ok(false),_=>Err(anyhow::anyhow!("export conditional PUT refused")),
        }
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        match self.op.load().write_with(key, bytes.to_vec()).if_not_exists(true).await {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == ErrorKind::ConditionNotMatch => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.op.load().write(key, bytes.to_vec()).await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.op.load().delete(key).await?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let guarded = self.gc_guard.read().expect("GC guard lock").is_some();
        let listing = async {
        let mut op = self.op.load_full();
        let mut list = op.lister_with(prefix).recursive(true);
        if guarded { list = list.limit(256); }
        let mut entries = list.await?;
        let (mut cursor, mut restarts) = (None, 0);
        let (mut count, mut bytes) = (0_usize, 0_usize);
        let mut keys = Vec::new();
        while let Some(entry) = self
            .next_listing_entry(prefix, &mut op, &mut entries, &mut cursor, &mut restarts)
            .await?
        {
            count += 1;
            bytes = bytes.saturating_add(entry.path().len() + std::mem::size_of::<String>());
            ensure!(
                count <= MAX_GC_LIST_OBJECTS && bytes <= MAX_GC_LIST_BYTES,
                "S3 full listing exceeds key budget"
            );
            ensure!(!guarded || count <= GC_CHECKPOINT_PAGE_KEYS, "GC checkpoint scan key limit");
            if entry.metadata().is_file() {
                keys.push(entry.path().to_string());
            }
        }
        ensure!(
            op.scope == self.op.load().scope && op.scope_epoch == self.op.load().scope_epoch,
            "S3 listing storage scope replaced"
        );
        keys.sort();
        Ok(keys)
        };
        if guarded { crate::r2_ops::bounded_gc_list(listing).await } else { listing.await }
    }

    /// One page per call. Under the GC guard a page is at most
    /// [`GC_CHECKPOINT_PAGE_KEYS`] keys and its own bounded LIST budget, the
    /// same per-call bounds a guarded [`Self::list`] enforces on a whole prefix.
    async fn list_page(&self, prefix: &str, start_after: Option<&str>, limit: usize) -> Result<Vec<String>> {
        let guarded = self.gc_guard.read().expect("GC guard lock").is_some();
        let limit = limit.clamp(1, if guarded { GC_CHECKPOINT_PAGE_KEYS } else { GC_LIST_PAGE_KEYS });
        let page = async {
            Ok(self.list_page_after(prefix, start_after, limit).await?.into_iter().map(|listed| listed.key).collect())
        };
        if guarded { crate::r2_ops::bounded_gc_list(page).await } else { page.await }
    }
}

#[cfg(test)]
mod gc_inventory_tests {
    use super::*;

    use crate::lake_part_gc::planner::{InventorySelection, GcPolicy, plan};
    use crate::lake_part_gc::planner::tests::{Chain, key, T0};
    use crate::lake_part_gc::request::tests::TENANT_UUID;
    use crate::parts::levels::Level;
    use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};

    struct Pages {
        keys: Vec<String>,
        filler: usize,
        calls: AtomicUsize,
        accepted_end: AtomicUsize,
        rotation: Mutex<Option<(Arc<S3ObjectStore>, S3Location)>>,
        // A late page failure must not leak an apparently complete candidate set.
        fail_at: Option<usize>,
    }

    impl Pages {
        fn key(&self, n: usize) -> String {
            if n < self.filler {
                crate::parts::format::PartKeys::new(TENANT_UUID, Level::Hour,
                    (T0 / 3_600_000) as i32 - 1,
                    &crate::lake_part_gc::planner::tests::id(n as u64 + 1_000)).unwrap()
                    .file("data-00000.parquet")
            } else { self.keys[n - self.filler].clone() }
        }
    }

    struct Transport(Arc<Pages>);

    fn install_transport(store: &S3ObjectStore, pages: Arc<Pages>) {
        let previous = store.op.load_full();
        store.op.store(Arc::new(ScopedOperator {
            operator: previous.operator.clone().layer(opendal::layers::HttpClientLayer::new(
                opendal::raw::HttpClient::with(Transport(pages)))),
            scope: previous.scope.clone(), scope_epoch: previous.scope_epoch,
        }));
    }

    impl opendal::raw::HttpFetch for Transport {
        async fn fetch(&self, request: axum::http::Request<opendal::Buffer>)
            -> opendal::Result<axum::http::Response<opendal::raw::HttpBody>> {
            let pages = &self.0;
            pages.calls.fetch_add(1, Ordering::SeqCst);
            let url = reqwest::Url::parse(&request.uri().to_string()).unwrap();
            let query: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
            assert_eq!(query.get("max-keys").map(String::as_str), Some("1000"));
            let total = pages.filler + pages.keys.len();
            let start = if let Some(cursor) = query.get("start-after") {
                (0..total).find(|n| pages.key(*n) > *cursor).unwrap_or(total)
            } else {
                query.get("continuation-token").map_or(0, |n| n.parse().unwrap())
            };
            let (status, body) = if pages.fail_at.is_some_and(|at| start >= at) {
                (403, "<Error><Code>AccessDenied</Code></Error>".into())
            } else {
                if start >= 256 {
                    if let Some((store, location)) = pages.rotation.lock().unwrap().take() {
                        store.replace(&location).unwrap();
                        install_transport(&store, pages.clone());
                    }
                }
                // The fixture serves short 256-key pages (S3 may return fewer
                // than max-keys), so rotation and late failures still land
                // mid-scan and the client must follow continuation tokens.
                let end = (start + 256).min(total);
                pages.accepted_end.fetch_max(end, Ordering::SeqCst);
                let mut body = format!("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>test</Name><IsTruncated>{}</IsTruncated>", end < total);
                if end < total { body.push_str(&format!("<NextContinuationToken>{end}</NextContinuationToken>")); }
                for n in start..end {
                    body.push_str(&format!("<Contents><Key>{}</Key><Size>9</Size>", pages.key(n)));
                    // Missing identity metadata stays protected.
                    if n != pages.filler && n != pages.filler + 1 { body.push_str("<ETag>&quot;e&quot;</ETag>"); }
                    if n < pages.filler {
                        body.push_str("<LastModified>2026-09-29T10:00:00Z</LastModified>");
                    } else {
                        body.push_str("<LastModified>2026-09-25T10:00:00Z</LastModified>");
                    }
                    body.push_str("</Contents>");
                }
                body.push_str("</ListBucketResult>");
                assert!(body.len() < 256 * 1024, "one bounded wire page");
                (200, body)
            };
            let length = body.len() as u64;
            Ok(axum::http::Response::builder().status(status).body(opendal::raw::HttpBody::new(
                futures::stream::iter([Ok(opendal::Buffer::from(body))]), Some(length))).unwrap())
        }
    }

    fn provider(filler: usize, keys: Vec<String>, fail_at: Option<usize>)
        -> (Arc<S3ObjectStore>, S3Location, Arc<Pages>) {
        let pages = Arc::new(Pages { keys, filler, calls: AtomicUsize::new(0),
            accepted_end: AtomicUsize::new(0), rotation: Mutex::new(None), fail_at });
        let location = S3Location { endpoint: "http://fixture.invalid".into(),
            region: "auto".into(), bucket: "test".into(), prefix: String::new(),
            access_key_id: "fixture".into(), secret_access_key: "fixture".into(), session_token: None };
        let store = Arc::new(S3ObjectStore::new(&location).unwrap());
        install_transport(&store, pages.clone());
        (store, location, pages)
    }

    fn candidate_keys() -> Vec<String> {
        // Cross real hour and level boundaries, with more eligible objects than
        // one owned task can delete. Every name is a valid planner key.
        let mut keys: Vec<_> = (1..=600).map(|n| key(n, Level::L0, "data-00000.parquet")).collect();
        for n in 601..=604 {
            let other = crate::parts::format::PartKeys::new(TENANT_UUID, Level::Hour,
                (T0 / 3_600_000) as i32 + 1, &crate::lake_part_gc::planner::tests::id(n)).unwrap();
            keys.push(other.file("data-00000.parquet"));
        }
        keys.sort();
        keys
    }

    #[tokio::test]
    async fn complete_scan_above_inventory_cap_retains_exact_bounded_eligible_set() {
        let keys = candidate_keys();
        let (store, _, pages) = provider(MAX_GC_LIST_OBJECTS + 257, keys.clone(), None);
        let view = Chain::new().view();
        let mut live_keys = std::collections::BTreeSet::new();
        live_keys.insert(keys[2].clone()); // Includes adopted/original-key protection.
        let now = T0 + 4 * 86_400_000;
        let policy = GcPolicy::default();
        let selection = InventorySelection::new("tenant1", TENANT_UUID, &view, &live_keys, now, policy).unwrap();
        let prefix = format!("lake/parts/v1/tenant={TENANT_UUID}/parts/");
        let selected = store.list_selected_with_metadata(&prefix, &selection).await.unwrap();
        assert_eq!(pages.accepted_end.load(Ordering::SeqCst), pages.filler + keys.len());
        assert!(pages.calls.load(Ordering::SeqCst) > 1024);
        assert_eq!(selected.len(), 512);
        assert_eq!(selected.capacity(), 512);
        let all_candidates: Vec<_> = keys.iter().skip(2).map(|key| crate::lake_part_gc::ListedPartObject {
            key: key.clone(), strong_etag: "\"e\"".into(), content_length: 9, uploaded_at_ms: T0,
        }).collect();
        let expected = plan("tenant1", TENANT_UUID, &view, &live_keys, &all_candidates, now, &policy).unwrap();
        assert_eq!(selected.iter().map(|object| &object.key).collect::<Vec<_>>(),
            expected.requests.iter().map(|request| &request.key).collect::<Vec<_>>());
        check_gc_inventory(&selected).unwrap();
        let hours: std::collections::BTreeSet<_> = selected.iter().map(|object|
            crate::lake_part_gc::parse_part_file_key(&object.key).unwrap().path_hour).collect();
        assert_eq!(hours.len(), 2, "selected keys span actual hour/level partitions");
        let heap: usize = selected.capacity() * std::mem::size_of::<crate::lake_part_gc::ListedPartObject>()
            + selected.iter().map(|object| object.key.capacity() + object.strong_etag.capacity()).sum::<usize>();
        assert!(heap < 256 * 1024, "retained candidate heap {heap}");
        // Exact metadata identity survives selection; no synthetic receipt or key.
        assert!(selected.iter().all(|object| object.strong_etag == "\"e\"" && object.content_length == 9 && object.uploaded_at_ms == T0));
    }

    #[tokio::test]
    async fn selected_scan_resumes_rotation_but_rejects_scope_change_and_late_failure() {
        for (scope_change, fail_at) in [(false, None), (true, None), (false, Some(768))] {
            let (store, mut location, pages) = provider(257, candidate_keys(), fail_at);
            location.access_key_id = "rotated".into();
            if scope_change { location.bucket = "replacement".into(); }
            *pages.rotation.lock().unwrap() = Some((store.clone(), location));
            let view = Chain::new().view();
            let live_keys = Default::default();
            let selection = InventorySelection::new("tenant1", TENANT_UUID, &view, &live_keys,
                T0 + 4 * 86_400_000, GcPolicy::default()).unwrap();
            let result = store.list_selected_with_metadata(
                &format!("lake/parts/v1/tenant={TENANT_UUID}/parts/"), &selection).await;
            if scope_change || fail_at.is_some() { assert!(result.is_err()); }
            else {
                let objects = result.unwrap();
                assert_eq!(objects.len(), 512);
                assert!(objects.windows(2).all(|pair| pair[0].key < pair[1].key));
                assert_eq!(objects.iter().map(|object| &object.key).collect::<Vec<_>>(),
                    pages.keys.iter().skip(2).take(512).collect::<Vec<_>>(),
                    "obsolete response discarded and resume loses no accepted-range candidate");
                assert_eq!(pages.accepted_end.load(Ordering::SeqCst), pages.filler + pages.keys.len());
            }
            }
    }

    #[tokio::test]
    async fn credential_rotation_preserves_storage_identity_but_scope_aba_changes_epoch() {
        let mut location = S3Location {
            endpoint: "http://127.0.0.1:1".into(), region: "auto".into(), bucket: "first".into(), prefix: "tenant".into(),
            access_key_id: "old".into(), secret_access_key: "test".into(), session_token: None,
        };
        let store = S3ObjectStore::new(&location).unwrap();
        let original = store.inventory_scope();
        location.access_key_id = "new".into();
        store.replace(&location).unwrap();
        assert_eq!(store.inventory_scope(), original);
        location.bucket = "second".into();
        store.replace(&location).unwrap();
        assert_ne!(store.inventory_scope(), original);
        location.bucket = "first".into();
        store.replace(&location).unwrap();
        assert_ne!(store.inventory_scope(), original, "returning to A must never revive an A inventory");
    }

    #[test]
    fn incomplete_metadata_and_reserved_string_heap_stay_protected() {
        let meta = opendal::Metadata::new(opendal::EntryMode::FILE);
        assert!(listed_object("key", &meta).is_none());
        let mut with_etag = meta.clone();
        with_etag.set_etag("\"e\"");
        assert!(listed_object("key", &with_etag).is_none());
        let mut with_time = meta;
        with_time.set_last_modified("2026-09-25T10:00:00Z".parse::<opendal::raw::Timestamp>().unwrap());
        assert!(listed_object("key", &with_time).is_none());
        let mut key = String::with_capacity(MAX_GC_LIST_BYTES);
        key.push('k');
        let object = crate::lake_part_gc::ListedPartObject {
            key, strong_etag: "\"e\"".into(), content_length: 1, uploaded_at_ms: 0,
        };
        assert!(check_gc_inventory(&[object]).is_err(), "charge retained capacity, not short string length");
    }

    #[test]
    fn oversized_inventory_is_refused_instead_of_truncated() {
        let object = crate::lake_part_gc::ListedPartObject {
            key: "k".repeat(MAX_GC_LIST_BYTES),
            strong_etag: "\"e\"".into(),
            content_length: 1,
            uploaded_at_ms: 0,
        };
        assert!(check_gc_inventory(&[object]).is_err());
        check_gc_inventory(&[]).unwrap();
    }
}

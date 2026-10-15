// SPDX-License-Identifier: AGPL-3.0-or-later

//! Immutable Parquet-backed custom CIDR enrichment.
//!
//! Source configuration and sync status remain in PostgreSQL. The potentially
//! large CIDR payload is owned by the lake enrichment coordinator and published
//! as content-addressed snapshots. Readers verify the manifest digest and use
//! deterministic longest-prefix matching in process.

use anyhow::{bail, Context, Result};
use arrow_array::{Array, BooleanArray, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use fs2::FileExt;
use nanosiem_core::enrichment::IpEnrichmentResult;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_ROWS;

const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const MAX_ROWS: usize = 10_000_000;
const MAX_BATCH_ROWS: usize = 100_000;
/// Per-tenant lean ingest budget. A cell can host multiple tenants within 512 MiB.
/// Rows and bytes come from the one lean snapshot contract shared with IOC.
pub const LEAN_SNAPSHOT_MAX_BYTES: u64 =
    crate::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_BYTES as u64;
const LEAN_SNAPSHOT_MAX_FOOTER_BYTES: u64 = 1024 * 1024;
// Allow room for the old and candidate snapshots, Arrow's transient batch,
// and the ingest process when a cell rotates several tenants at once.
pub const LEAN_SNAPSHOT_MAX_DECODED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IpContextInput {
    pub network: String,
    pub source_id: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub continent: String,
    #[serde(default)]
    pub continent_code: String,
    #[serde(default)]
    pub asn: String,
    #[serde(default)]
    pub as_name: String,
    #[serde(default)]
    pub as_domain: String,
    #[serde(deserialize_with = "deserialize_datetime")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, deserialize_with = "deserialize_boolish")]
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotManifest {
    schema_version: u32,
    tenant_id: String,
    sha256: String,
    file_name: String,
    rows: usize,
    published_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpContextPublicationResult {
    pub status: &'static str,
    pub tenant_id: String,
    pub snapshot_sha256: String,
    pub rows: usize,
    pub changed: usize,
}

#[derive(Debug, Clone)]
pub struct IpContextDurableSnapshot {
    pub path: PathBuf,
    pub sha256: String,
    pub manifest: serde_json::Value,
}

pub struct PreparedIpContextPublication {
    result: IpContextPublicationResult,
    manifest: Option<SnapshotManifest>,
    snapshot: Option<IpContextDurableSnapshot>,
    rows: Option<BTreeMap<(String, String), StoredRow>>,
}

impl PreparedIpContextPublication {
    pub fn result(&self) -> &IpContextPublicationResult {
        &self.result
    }

    pub fn durable_snapshot(&self) -> Option<&IpContextDurableSnapshot> {
        self.snapshot.as_ref()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IpContextCounts {
    pub total_networks: usize,
    pub source_counts: BTreeMap<String, usize>,
    pub snapshot_sha256: Option<String>,
}

#[derive(Debug, Clone)]
struct StoredRow {
    input: IpContextInput,
    network: Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Network {
    V4 { base: u32, prefix: u8 },
    V6 { base: u128, prefix: u8 },
}

impl Network {
    fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value
            .trim()
            .split_once('/')
            .context("IP context network must be CIDR notation")?;
        let address: IpAddr = address
            .parse()
            .context("IP context network address is invalid")?;
        let prefix: u8 = prefix.parse().context("IP context prefix is invalid")?;
        match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let address = u32::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Ok(Self::V4 {
                    base: address & mask,
                    prefix,
                })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let address = u128::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Ok(Self::V6 {
                    base: address & mask,
                    prefix,
                })
            }
            _ => bail!("IP context prefix is outside the address-family range"),
        }
    }

    fn canonical(self) -> String {
        match self {
            Self::V4 { base, prefix } => format!("{}/{prefix}", Ipv4Addr::from(base)),
            Self::V6 { base, prefix } => format!("{}/{prefix}", Ipv6Addr::from(base)),
        }
    }

    fn prefix(self) -> u8 {
        match self {
            Self::V4 { prefix, .. } | Self::V6 { prefix, .. } => prefix,
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { base, prefix }, IpAddr::V4(address)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(address) & mask == base
            }
            (Self::V6 { base, prefix }, IpAddr::V6(address)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(address) & mask == base
            }
            _ => false,
        }
    }
}

impl StoredRow {
    fn new(mut input: IpContextInput) -> Result<Self> {
        validate_identity("source", &input.source_id)?;
        for value in [
            &input.country,
            &input.country_code,
            &input.continent,
            &input.continent_code,
            &input.asn,
            &input.as_name,
            &input.as_domain,
        ] {
            if value.len() > 2_048 || value.chars().any(char::is_control) {
                bail!("IP context row contains an invalid bounded text field");
            }
        }
        let network = Network::parse(&input.network)?;
        input.network = network.canonical();
        Ok(Self { input, network })
    }

    fn result(&self) -> IpEnrichmentResult {
        let optional = |value: &str| (!value.is_empty()).then(|| value.to_string());
        IpEnrichmentResult {
            source_id: Some(self.input.source_id.clone()),
            network: Some(self.input.network.clone()),
            country: optional(&self.input.country),
            country_code: optional(&self.input.country_code),
            continent: optional(&self.input.continent),
            continent_code: optional(&self.input.continent_code),
            asn: optional(&self.input.asn),
            as_name: optional(&self.input.as_name),
            as_domain: optional(&self.input.as_domain),
        }
    }
}

#[derive(Debug)]
pub struct IpContextSnapshot {
    path: PathBuf,
    sha256: String,
    rows: Vec<StoredRow>,
}

impl IpContextSnapshot {
    pub fn open(path: impl AsRef<Path>, expected_sha256: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        validate_digest(expected_sha256)?;
        if crate::native::file_sha256(&path)? != expected_sha256 {
            bail!("IP context snapshot digest differs from its assignment");
        }
        let rows = read_snapshot(&path)?;
        Ok(Self::from_rows(path, expected_sha256, rows))
    }

    /// Open an untrusted tenant artifact for lean ingest with limits applied
    /// before hashing and before Parquet builds Arrow batches.
    pub fn open_lean(path: impl AsRef<Path>, expected_sha256: &str) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let path = path.as_ref().to_path_buf();
        validate_digest(expected_sha256)?;
        let mut file = File::open(&path)?;
        let size = file.metadata()?.len();
        if size > LEAN_SNAPSHOT_MAX_BYTES {
            bail!("lean IP context snapshot exceeds 64 MiB");
        }
        let mut hasher = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied += count as u64;
            if copied > LEAN_SNAPSHOT_MAX_BYTES {
                bail!("lean IP context snapshot exceeds 64 MiB");
            }
            hasher.update(&buffer[..count]);
        }
        if copied != size {
            bail!("lean IP context snapshot changed size or exceeds 64 MiB");
        }
        if hex::encode(hasher.finalize()) != expected_sha256 {
            bail!("IP context snapshot digest differs from its assignment");
        }
        if size < 8 {
            bail!("lean IP context snapshot has no Parquet trailer");
        }
        file.seek(SeekFrom::End(-8))?;
        let mut trailer = [0u8; 8];
        file.read_exact(&mut trailer)?;
        let footer_size = u32::from_le_bytes(trailer[..4].try_into().expect("four bytes")) as u64;
        if &trailer[4..] != b"PAR1"
            || footer_size > LEAN_SNAPSHOT_MAX_FOOTER_BYTES
            || footer_size > size - 8
        {
            bail!("lean IP context snapshot has an invalid or oversized Parquet trailer");
        }
        file.seek(SeekFrom::Start(0))?;
        let rows = read_snapshot_lean(file)?;
        Ok(Self::from_rows(path, expected_sha256, rows))
    }

    fn from_rows(path: PathBuf, expected_sha256: &str, mut rows: Vec<StoredRow>) -> Self {
        rows.retain(|row| !row.input.deleted);
        rows.sort_by(|left, right| {
            right
                .network
                .prefix()
                .cmp(&left.network.prefix())
                .then_with(|| right.input.updated_at.cmp(&left.input.updated_at))
                .then_with(|| left.input.source_id.cmp(&right.input.source_id))
        });
        Self {
            path,
            sha256: expected_sha256.to_string(),
            rows,
        }
    }

    pub fn lookup(&self, ip: &str) -> Result<Option<IpEnrichmentResult>> {
        let address: IpAddr = ip
            .trim()
            .parse()
            .context("IP context lookup address is invalid")?;
        Ok(self
            .rows
            .iter()
            .find(|row| row.network.contains(address))
            .map(StoredRow::result))
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
}

/// A lean custom IP-context publication that would break the per-tenant lean
/// snapshot contract (rows, bytes, or decoded size). Raised before the
/// candidate becomes current, so the prior assignment stays active.
#[derive(Debug, thiserror::Error)]
#[error("lean IP context publication exceeds its snapshot cap: {0}")]
pub struct LeanSnapshotCapExceeded(pub String);

pub struct IpContextStore {
    root: PathBuf,
    tenant_id: String,
    /// Apply the lean cell reader limits at publication (see `new_lean`).
    lean: bool,
    cache: std::sync::RwLock<SnapshotCache>,
}

#[derive(Default)]
struct SnapshotCache {
    sha256: Option<String>,
    rows: Arc<BTreeMap<(String, String), StoredRow>>,
}

impl IpContextStore {
    /// gen1 publisher: keeps the historical 10 million row ceiling.
    pub fn new(root: PathBuf, tenant_id: String) -> Result<Self> {
        Self::open(root, tenant_id, false)
    }

    /// Publisher for a lean cell tenant. Every candidate must pass the same
    /// checks as `IpContextSnapshot::open_lean` before it can become current,
    /// so an over-cap upload is refused instead of failing later at ingest.
    pub fn new_lean(root: PathBuf, tenant_id: String) -> Result<Self> {
        Self::open(root, tenant_id, true)
    }

    pub fn is_lean(&self) -> bool {
        self.lean
    }

    fn open(root: PathBuf, tenant_id: String, lean: bool) -> Result<Self> {
        if !root.is_absolute() {
            bail!("IP context directory must be absolute");
        }
        validate_identity("tenant", &tenant_id)?;
        std::fs::create_dir_all(&root)?;
        let store = Self {
            root,
            tenant_id,
            lean,
            cache: std::sync::RwLock::new(SnapshotCache::default()),
        };
        store.load_rows()?;
        Ok(store)
    }

    pub fn upsert(&self, inputs: Vec<IpContextInput>) -> Result<IpContextPublicationResult> {
        self.activate(self.prepare_upsert(inputs)?)
    }

    pub fn prepare_upsert(
        &self,
        inputs: Vec<IpContextInput>,
    ) -> Result<PreparedIpContextPublication> {
        if inputs.is_empty() || inputs.len() > MAX_BATCH_ROWS {
            bail!("IP context batch must contain 1..={MAX_BATCH_ROWS} rows");
        }
        let rows = inputs
            .into_iter()
            .map(StoredRow::new)
            .collect::<Result<Vec<_>>>()?;
        self.prepare_mutation(|current| {
            let mut changed = 0;
            for row in rows {
                let key = (row.input.source_id.clone(), row.input.network.clone());
                if current
                    .get(&key)
                    .is_none_or(|value| row.input.updated_at > value.input.updated_at)
                {
                    if row.input.deleted {
                        current.remove(&key);
                    } else {
                        current.insert(key, row);
                    }
                    changed += 1;
                }
            }
            Ok(changed)
        })
    }

    pub fn delete_source(&self, source_id: &str) -> Result<IpContextPublicationResult> {
        self.activate(self.prepare_delete_source(source_id)?)
    }

    pub fn prepare_delete_source(&self, source_id: &str) -> Result<PreparedIpContextPublication> {
        validate_identity("source", source_id)?;
        self.prepare_mutation(|rows| {
            let before = rows.len();
            rows.retain(|(source, _), _| source != source_id);
            Ok(before.saturating_sub(rows.len()))
        })
    }

    pub fn lookup(&self, ip: &str) -> Result<Option<IpEnrichmentResult>> {
        let address: IpAddr = ip
            .trim()
            .parse()
            .context("IP context lookup address is invalid")?;
        let rows = self.load_rows()?;
        Ok(rows
            .values()
            .filter(|row| row.network.contains(address))
            .max_by(|left, right| {
                left.network
                    .prefix()
                    .cmp(&right.network.prefix())
                    .then_with(|| left.input.updated_at.cmp(&right.input.updated_at))
                    .then_with(|| right.input.source_id.cmp(&left.input.source_id))
            })
            .map(StoredRow::result))
    }

    pub fn counts(&self) -> Result<IpContextCounts> {
        let rows = self.load_rows()?;
        let mut source_counts = BTreeMap::new();
        for row in rows.values() {
            *source_counts
                .entry(row.input.source_id.clone())
                .or_default() += 1;
        }
        Ok(IpContextCounts {
            total_networks: rows.len(),
            source_counts,
            snapshot_sha256: self.read_manifest()?.map(|value| value.sha256),
        })
    }

    pub fn assignment(&self) -> Result<Option<(PathBuf, String)>> {
        let Some(manifest) = self.read_manifest()? else {
            return Ok(None);
        };
        let path = self.root.join(&manifest.file_name);
        if crate::native::file_sha256(&path)? != manifest.sha256 {
            bail!("IP context snapshot digest differs from its manifest");
        }
        Ok(Some((path, manifest.sha256)))
    }

    pub fn durable_snapshot(&self) -> Result<Option<IpContextDurableSnapshot>> {
        let Some(manifest) = self.read_manifest()? else {
            return Ok(None);
        };
        let path = self.root.join(&manifest.file_name);
        if crate::native::file_sha256(&path)? != manifest.sha256 {
            bail!("IP context snapshot digest differs from its manifest");
        }
        Ok(Some(IpContextDurableSnapshot {
            path,
            sha256: manifest.sha256.clone(),
            manifest: serde_json::to_value(manifest)?,
        }))
    }

    /// Make this lean working copy mirror the tenant's published revision
    /// (`None` = nothing published). The source file must already be the
    /// verified revision bytes; it is re-checked with the lean reader before
    /// the local manifest moves. Used by the lean coordinator, whose durable
    /// state is the R2 pointer, not this directory.
    pub fn adopt_lean_snapshot(&self, snapshot: Option<(&Path, &str)>) -> Result<()> {
        if !self.lean {
            bail!("only a lean IP context store adopts a published revision");
        }
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(self.root.join("publication.lock"))?;
        lock.lock_exclusive()?;
        let Some((source, sha256)) = snapshot else {
            match std::fs::remove_file(self.root.join("current.json")) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            *self.cache.write().unwrap_or_else(|error| error.into_inner()) =
                SnapshotCache::default();
            return Ok(());
        };
        if self.read_manifest()?.is_some_and(|manifest| manifest.sha256 == sha256) {
            return Ok(());
        }
        let verified = IpContextSnapshot::open_lean(source, sha256)?;
        let file_name = format!("{sha256}.parquet");
        let immutable = self.root.join(&file_name);
        if !immutable.exists() {
            let temporary = self
                .root
                .join(format!(".ip-context-adopt-{}.parquet", uuid::Uuid::now_v7()));
            std::fs::copy(source, &temporary)?;
            std::fs::rename(&temporary, &immutable)?;
        }
        if crate::native::file_sha256(&immutable)? != sha256 {
            bail!("adopted IP context snapshot digest differs");
        }
        // `from_rows` drops tombstones; the stored file never contains them.
        let rows = read_snapshot(&immutable)?;
        drop(verified);
        let manifest = SnapshotManifest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            tenant_id: self.tenant_id.clone(),
            sha256: sha256.to_string(),
            file_name,
            rows: rows.len(),
            published_at: chrono::Utc::now(),
            rollback_sha256: None,
        };
        self.write_manifest(&manifest)?;
        *self.cache.write().unwrap_or_else(|error| error.into_inner()) =
            SnapshotCache::default();
        self.prune_snapshots(&manifest)?;
        Ok(())
    }

    fn prepare_mutation(
        &self,
        mutation: impl FnOnce(&mut BTreeMap<(String, String), StoredRow>) -> Result<usize>,
    ) -> Result<PreparedIpContextPublication> {
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(self.root.join("publication.lock"))?;
        lock.lock_exclusive()?;
        let mut rows = (*self.load_rows()?).clone();
        let changed = mutation(&mut rows)?;
        if rows.len() > MAX_ROWS {
            bail!("IP context snapshot exceeds {MAX_ROWS} rows");
        }
        if self.lean && rows.len() > TENANT_SNAPSHOT_LIMIT_ROWS {
            return Err(LeanSnapshotCapExceeded(format!(
                "snapshot would hold {} rows; the cap is {TENANT_SNAPSHOT_LIMIT_ROWS}",
                rows.len()
            ))
            .into());
        }
        if changed == 0 {
            return Ok(PreparedIpContextPublication {
                result: IpContextPublicationResult {
                    status: "unchanged",
                    tenant_id: self.tenant_id.clone(),
                    snapshot_sha256: self
                        .read_manifest()?
                        .map(|value| value.sha256)
                        .unwrap_or_else(|| "0".repeat(64)),
                    rows: rows.len(),
                    changed,
                },
                manifest: None,
                snapshot: self.durable_snapshot()?,
                rows: None,
            });
        }
        let previous = self.read_manifest()?;
        let temporary = self
            .root
            .join(format!(".ip-context-{}.parquet", uuid::Uuid::now_v7()));
        write_snapshot(&temporary, rows.values())?;
        let digest = crate::native::file_sha256(&temporary)?;
        if self.lean {
            if let Err(error) = IpContextSnapshot::open_lean(&temporary, &digest) {
                let _ = std::fs::remove_file(&temporary);
                return Err(LeanSnapshotCapExceeded(format!("{error:#}")).into());
            }
        }
        let file_name = format!("{digest}.parquet");
        let immutable = self.root.join(&file_name);
        match std::fs::hard_link(&temporary, &immutable) {
            Ok(()) => std::fs::remove_file(&temporary)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&temporary)?;
                if crate::native::file_sha256(&immutable)? != digest {
                    bail!("IP context content-addressed snapshot has conflicting bytes");
                }
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
        let manifest = SnapshotManifest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            tenant_id: self.tenant_id.clone(),
            sha256: digest.clone(),
            file_name,
            rows: rows.len(),
            published_at: chrono::Utc::now(),
            rollback_sha256: previous.as_ref().map(|value| value.sha256.clone()),
        };
        let snapshot = IpContextDurableSnapshot {
            path: immutable,
            sha256: digest.clone(),
            manifest: serde_json::to_value(&manifest)?,
        };
        Ok(PreparedIpContextPublication {
            result: IpContextPublicationResult {
                status: "published",
                tenant_id: self.tenant_id.clone(),
                snapshot_sha256: digest,
                rows: rows.len(),
                changed,
            },
            manifest: Some(manifest),
            snapshot: Some(snapshot),
            rows: Some(rows),
        })
    }

    pub fn activate(
        &self,
        prepared: PreparedIpContextPublication,
    ) -> Result<IpContextPublicationResult> {
        let PreparedIpContextPublication {
            result,
            manifest,
            rows,
            ..
        } = prepared;
        let Some(manifest) = manifest else {
            return Ok(result);
        };
        let rows = rows.context("prepared IP context publication omitted its rows")?;
        self.write_manifest(&manifest)?;
        {
            let mut cache = self
                .cache
                .write()
                .unwrap_or_else(|error| error.into_inner());
            cache.sha256 = Some(manifest.sha256.clone());
            cache.rows = Arc::new(rows);
        }
        self.prune_snapshots(&manifest)?;
        Ok(result)
    }

    fn load_rows(&self) -> Result<Arc<BTreeMap<(String, String), StoredRow>>> {
        let Some(manifest) = self.read_manifest()? else {
            return Ok(Arc::new(BTreeMap::new()));
        };
        {
            let cache = self.cache.read().unwrap_or_else(|error| error.into_inner());
            if cache.sha256.as_deref() == Some(manifest.sha256.as_str()) {
                return Ok(cache.rows.clone());
            }
        }
        let path = self.root.join(&manifest.file_name);
        if crate::native::file_sha256(&path)? != manifest.sha256 {
            bail!("IP context snapshot digest differs from its manifest");
        }
        let loaded = read_snapshot(&path)?;
        if loaded.len() != manifest.rows {
            bail!("IP context snapshot row count differs from its manifest");
        }
        let rows: Arc<BTreeMap<(String, String), StoredRow>> = Arc::new(
            loaded
                .into_iter()
                .map(|row| {
                    (
                        (row.input.source_id.clone(), row.input.network.clone()),
                        row,
                    )
                })
                .collect(),
        );
        let mut cache = self
            .cache
            .write()
            .unwrap_or_else(|error| error.into_inner());
        cache.sha256 = Some(manifest.sha256);
        cache.rows = rows.clone();
        Ok(rows)
    }

    fn read_manifest(&self) -> Result<Option<SnapshotManifest>> {
        read_snapshot_manifest(&self.root, &self.tenant_id)
    }

    fn write_manifest(&self, manifest: &SnapshotManifest) -> Result<()> {
        let mut candidate = tempfile::Builder::new()
            .prefix(".ip-context-current-")
            .suffix(".json")
            .tempfile_in(&self.root)?;
        serde_json::to_writer_pretty(candidate.as_file_mut(), manifest)?;
        candidate.as_file_mut().write_all(b"\n")?;
        candidate.as_file().sync_all()?;
        candidate.persist(self.root.join("current.json"))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn prune_snapshots(&self, manifest: &SnapshotManifest) -> Result<()> {
        for entry in std::fs::read_dir(&self.root)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if !name.ends_with(".parquet") {
                continue;
            }
            let digest = name.trim_end_matches(".parquet");
            if digest != manifest.sha256 && manifest.rollback_sha256.as_deref() != Some(digest) {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}

fn read_snapshot_manifest(root: &Path, tenant_id: &str) -> Result<Option<SnapshotManifest>> {
    let file = match File::open(root.join("current.json")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(16_385).read_to_end(&mut bytes)?;
    if bytes.len() > 16_384 {
        bail!("IP context manifest exceeds 16 KiB");
    }
    let manifest: SnapshotManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != SNAPSHOT_SCHEMA_VERSION
        || manifest.tenant_id != tenant_id
        || manifest.file_name != format!("{}.parquet", manifest.sha256)
    {
        bail!("IP context manifest failed its immutable contract");
    }
    validate_digest(&manifest.sha256)?;
    Ok(Some(manifest))
}

/// Read the tenant-bound pointer without loading or hashing the potentially
/// large snapshot on every 30-second ingest refresh. `IpContextSnapshot::open_lean`
/// verifies the digest when the pointer changes.
pub fn current_assignment_pointer(
    root: &Path,
    tenant_id: &str,
) -> Result<Option<(PathBuf, String)>> {
    if !root.is_absolute() {
        bail!("IP context directory must be absolute");
    }
    validate_identity("tenant", tenant_id)?;
    Ok(read_snapshot_manifest(root, tenant_id)?
        .map(|manifest| (root.join(manifest.file_name), manifest.sha256)))
}

pub fn current_assignment(root: &Path, tenant_id: &str) -> Result<Option<(PathBuf, String)>> {
    IpContextStore::new(root.to_path_buf(), tenant_id.to_string())?.assignment()
}

fn snapshot_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("network", DataType::Utf8, false),
        Field::new("source_id", DataType::Utf8, false),
        Field::new("country", DataType::Utf8, false),
        Field::new("country_code", DataType::Utf8, false),
        Field::new("continent", DataType::Utf8, false),
        Field::new("continent_code", DataType::Utf8, false),
        Field::new("asn", DataType::Utf8, false),
        Field::new("as_name", DataType::Utf8, false),
        Field::new("as_domain", DataType::Utf8, false),
        Field::new("updated_at_ms", DataType::Int64, false),
        Field::new("deleted", DataType::Boolean, false),
    ]))
}

fn write_snapshot<'a>(path: &Path, rows: impl Iterator<Item = &'a StoredRow>) -> Result<()> {
    let rows = rows.collect::<Vec<_>>();
    let strings = |values: Vec<&str>| Arc::new(StringArray::from(values)) as _;
    let batch = RecordBatch::try_new(
        snapshot_schema(),
        vec![
            strings(rows.iter().map(|row| row.input.network.as_str()).collect()),
            strings(
                rows.iter()
                    .map(|row| row.input.source_id.as_str())
                    .collect(),
            ),
            strings(rows.iter().map(|row| row.input.country.as_str()).collect()),
            strings(
                rows.iter()
                    .map(|row| row.input.country_code.as_str())
                    .collect(),
            ),
            strings(
                rows.iter()
                    .map(|row| row.input.continent.as_str())
                    .collect(),
            ),
            strings(
                rows.iter()
                    .map(|row| row.input.continent_code.as_str())
                    .collect(),
            ),
            strings(rows.iter().map(|row| row.input.asn.as_str()).collect()),
            strings(rows.iter().map(|row| row.input.as_name.as_str()).collect()),
            strings(
                rows.iter()
                    .map(|row| row.input.as_domain.as_str())
                    .collect(),
            ),
            Arc::new(Int64Array::from_iter_values(
                rows.iter()
                    .map(|row| row.input.updated_at.timestamp_millis()),
            )),
            Arc::new(BooleanArray::from(
                rows.iter().map(|row| row.input.deleted).collect::<Vec<_>>(),
            )),
        ],
    )?;
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
        .build();
    let mut writer = ArrowWriter::try_new(File::create(path)?, batch.schema(), Some(properties))?;
    writer.write(&batch)?;
    writer.close()?;
    File::open(path)?.sync_all()?;
    Ok(())
}

fn read_snapshot(path: &Path) -> Result<Vec<StoredRow>> {
    read_snapshot_file(File::open(path)?, false)
}

fn read_snapshot_lean(file: File) -> Result<Vec<StoredRow>> {
    read_snapshot_file(file, true)
}

fn read_snapshot_file(file: File, lean: bool) -> Result<Vec<StoredRow>> {
    let page_file = lean.then(|| file.try_clone()).transpose()?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    if lean {
        let metadata = builder.metadata();
        let row_count = usize::try_from(metadata.file_metadata().num_rows())
            .context("lean IP context row count is invalid")?;
        if row_count > TENANT_SNAPSHOT_LIMIT_ROWS {
            bail!("lean IP context snapshot exceeds {TENANT_SNAPSHOT_LIMIT_ROWS} rows");
        }
        let mut decoded = 0usize;
        for group in metadata.row_groups() {
            for column in group.columns() {
                let size = usize::try_from(column.uncompressed_size())
                    .context("lean IP context decoded column size is invalid")?;
                decoded = decoded
                    .checked_add(size)
                    .context("lean IP context decoded size overflow")?;
                if decoded > LEAN_SNAPSHOT_MAX_DECODED_BYTES {
                    bail!("lean IP context snapshot exceeds 32 MiB decoded budget");
                }
            }
        }
        preflight_snapshot_pages(page_file.as_ref().expect("lean file clone"), metadata)?;
    }
    let reader = builder
        .with_batch_size(if lean { 256 } else { 16_384 })
        .build()?;
    let mut rows = Vec::new();
    let mut decoded_rows = 0usize;
    let mut retained_bytes = 0usize;
    for batch in reader {
        let batch = batch?;
        if lean {
            if batch.get_array_memory_size() > LEAN_SNAPSHOT_MAX_DECODED_BYTES {
                bail!("lean IP context batch exceeds decoded budget");
            }
            decoded_rows = decoded_rows
                .checked_add(batch.num_rows())
                .context("lean IP context row count overflow")?;
            if decoded_rows > TENANT_SNAPSHOT_LIMIT_ROWS {
                bail!("lean IP context snapshot exceeds {TENANT_SNAPSHOT_LIMIT_ROWS} rows");
            }
        }
        let string = |index: usize| -> Result<&StringArray> {
            batch
                .column(index)
                .as_any()
                .downcast_ref::<StringArray>()
                .context("IP context Parquet string column has the wrong type")
        };
        let updated = batch
            .column(9)
            .as_any()
            .downcast_ref::<Int64Array>()
            .context("IP context updated_at column has the wrong type")?;
        let deleted = batch
            .column(10)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .context("IP context deleted column has the wrong type")?;
        for index in 0..batch.num_rows() {
            if lean {
                let mut row_bytes = std::mem::size_of::<StoredRow>();
                for column in 0..9 {
                    let value = string(column)?.value(index);
                    if value.len() > 2_048 {
                        bail!("lean IP context row contains an oversized text field");
                    }
                    row_bytes = row_bytes
                        .checked_add(value.len())
                        .context("lean IP context row size overflow")?;
                }
                retained_bytes = retained_bytes
                    .checked_add(row_bytes)
                    .context("lean IP context decoded size overflow")?;
                if retained_bytes > LEAN_SNAPSHOT_MAX_DECODED_BYTES {
                    bail!("lean IP context snapshot exceeds 32 MiB retained budget");
                }
            }
            rows.push(StoredRow::new(IpContextInput {
                network: string(0)?.value(index).to_string(),
                source_id: string(1)?.value(index).to_string(),
                country: string(2)?.value(index).to_string(),
                country_code: string(3)?.value(index).to_string(),
                continent: string(4)?.value(index).to_string(),
                continent_code: string(5)?.value(index).to_string(),
                asn: string(6)?.value(index).to_string(),
                as_name: string(7)?.value(index).to_string(),
                as_domain: string(8)?.value(index).to_string(),
                updated_at: chrono::DateTime::from_timestamp_millis(updated.value(index))
                    .context("IP context updated_at is outside the supported range")?,
                deleted: deleted.value(index),
            })?);
        }
    }
    Ok(rows)
}

// Parquet footer totals can understate page sizes. Scan the actual compact
// Thrift page headers with fixed storage before Arrow allocates page buffers.
fn preflight_snapshot_pages(file: &File, metadata: &parquet::file::metadata::ParquetMetaData) -> Result<()> {
    let file_size = file.metadata()?.len();
    let mut decoded = 0usize;
    let mut pages = 0usize;
    for group in metadata.row_groups() {
        for column in group.columns() {
            let start = column.dictionary_page_offset().unwrap_or_else(|| column.data_page_offset());
            let start = u64::try_from(start).context("lean IP context column offset is invalid")?;
            let length = u64::try_from(column.compressed_size())
                .context("lean IP context column length is invalid")?;
            let end = start.checked_add(length).context("lean IP context column range overflow")?;
            if end > file_size {
                bail!("lean IP context column extends past artifact");
            }
            let mut offset = start;
            while offset < end {
                pages += 1;
                if pages > 10_000 {
                    bail!("lean IP context snapshot has too many pages");
                }
                let mut page_file = file.try_clone()?;
                page_file.seek(SeekFrom::Start(offset))?;
                let mut header = [0u8; 64 * 1024];
                let available = usize::try_from((end - offset).min(header.len() as u64))?;
                page_file.read_exact(&mut header[..available])?;
                let (header_bytes, uncompressed, compressed) = compact_page_sizes(&header[..available])?;
                decoded = decoded.checked_add(uncompressed)
                    .context("lean IP context decoded page size overflow")?;
                if decoded > LEAN_SNAPSHOT_MAX_DECODED_BYTES {
                    bail!("lean IP context snapshot exceeds 32 MiB decoded page budget");
                }
                offset = offset.checked_add(header_bytes as u64)
                    .and_then(|value| value.checked_add(compressed as u64))
                    .context("lean IP context page range overflow")?;
                if offset > end {
                    bail!("lean IP context page extends past column");
                }
            }
        }
    }
    Ok(())
}

struct CompactHeader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl CompactHeader<'_> {
    fn byte(&mut self) -> Result<u8> {
        let value = *self.bytes.get(self.position).context("lean IP context page header is truncated")?;
        self.position += 1;
        Ok(value)
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = self.byte()?;
            let low = (byte & 0x7f) as u64;
            if shift == 63 && low > 1 {
                bail!("lean IP context page header integer overflows");
            }
            value |= low << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("lean IP context page header integer is too long")
    }

    fn skip_bytes(&mut self, length: usize) -> Result<()> {
        self.position = self.position.checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .context("lean IP context page header is truncated")?;
        Ok(())
    }

    fn fields(&mut self, depth: usize, root: bool) -> Result<(Option<i32>, Option<i32>)> {
        if depth > 8 {
            bail!("lean IP context page header is too deep");
        }
        let (mut field_id, mut uncompressed, mut compressed) = (0i32, None, None);
        loop {
            let field = self.byte()?;
            let kind = field & 0x0f;
            if kind == 0 {
                return Ok((uncompressed, compressed));
            }
            let delta = (field >> 4) as i32;
            field_id = if delta == 0 {
                let encoded = u32::try_from(self.varint()?)
                    .context("lean IP context page field id is invalid")?;
                ((encoded >> 1) as i32) ^ (-((encoded & 1) as i32))
            } else {
                field_id.checked_add(delta).context("lean IP context page field id overflows")?
            };
            if root && (field_id == 2 || field_id == 3) {
                if kind != 5 {
                    bail!("lean IP context page size has the wrong type");
                }
                let encoded = u32::try_from(self.varint()?)
                    .context("lean IP context page size is invalid")?;
                let size = ((encoded >> 1) as i32) ^ (-((encoded & 1) as i32));
                if field_id == 2 { uncompressed = Some(size); } else { compressed = Some(size); }
            } else {
                self.skip(kind, depth)?;
            }
        }
    }

    fn skip(&mut self, kind: u8, depth: usize) -> Result<()> {
        if depth > 8 {
            bail!("lean IP context page header is too deep");
        }
        match kind {
            1 | 2 => Ok(()), // Boolean is encoded in the field type.
            3 => { self.byte()?; Ok(()) },
            4..=6 => { self.varint()?; Ok(()) },
            7 => self.skip_bytes(8),
            8 => {
                let length = usize::try_from(self.varint()?)?;
                self.skip_bytes(length)
            }
            9 | 10 => {
                let item = self.byte()?;
                let count = if item >> 4 == 15 { self.varint()? } else { (item >> 4) as u64 };
                if count > 64 * 1024 { bail!("lean IP context page header collection is too large"); }
                for _ in 0..count { self.skip(item & 0x0f, depth + 1)?; }
                Ok(())
            }
            11 => {
                let count = self.varint()?;
                if count > 64 * 1024 { bail!("lean IP context page header map is too large"); }
                if count != 0 {
                    let types = self.byte()?;
                    for _ in 0..count {
                        self.skip(types >> 4, depth + 1)?;
                        self.skip(types & 0x0f, depth + 1)?;
                    }
                }
                Ok(())
            }
            12 => { self.fields(depth + 1, false)?; Ok(()) },
            _ => bail!("lean IP context page header type is invalid"),
        }
    }
}

fn compact_page_sizes(bytes: &[u8]) -> Result<(usize, usize, usize)> {
    let mut header = CompactHeader { bytes, position: 0 };
    let (uncompressed, compressed) = header.fields(0, true)?;
    let uncompressed = usize::try_from(uncompressed.context("lean IP context page lacks decoded size")?)
        .context("lean IP context decoded page size is negative")?;
    let compressed = usize::try_from(compressed.context("lean IP context page lacks compressed size")?)
        .context("lean IP context compressed page size is negative")?;
    Ok((header.position, uncompressed, compressed))
}

fn deserialize_boolish<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Bool(value) => Ok(value),
        serde_json::Value::Number(value) => Ok(value.as_i64().unwrap_or_default() != 0),
        serde_json::Value::String(value) => match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" | "" => Ok(false),
            _ => Err(serde::de::Error::custom("expected a boolean or 0/1")),
        },
        serde_json::Value::Null => Ok(false),
        _ => Err(serde::de::Error::custom("expected a boolean or 0/1")),
    }
}

fn deserialize_datetime<'de, D>(
    deserializer: D,
) -> std::result::Result<chrono::DateTime<chrono::Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if let Some(milliseconds) = value.as_i64() {
        return chrono::DateTime::from_timestamp_millis(milliseconds)
            .ok_or_else(|| serde::de::Error::custom("invalid millisecond timestamp"));
    }
    let value = value
        .as_str()
        .ok_or_else(|| serde::de::Error::custom("expected timestamp string or milliseconds"))?;
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .map(|value| value.and_utc())
        })
        .map_err(|_| serde::de::Error::custom("invalid timestamp"))
}

fn validate_identity(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        bail!("{name} identity is invalid");
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("IP context snapshot digest is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(source: &str, network: &str, country: &str, timestamp: i64) -> IpContextInput {
        IpContextInput {
            network: network.to_string(),
            source_id: source.to_string(),
            country: country.to_string(),
            country_code: country.to_ascii_uppercase(),
            continent: String::new(),
            continent_code: String::new(),
            asn: String::new(),
            as_name: String::new(),
            as_domain: String::new(),
            updated_at: chrono::DateTime::from_timestamp_millis(timestamp).unwrap(),
            deleted: false,
        }
    }

    #[test]
    fn publishes_longest_prefix_dedupes_and_recovers() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("ip-context");
        let store = IpContextStore::new(directory.clone(), "tenant-a".to_string()).unwrap();
        store
            .upsert(vec![
                input("base", "10.0.0.9/8", "broad", 1_700_000_000_000),
                input("specific", "10.2.3.0/24", "specific", 1_700_000_000_001),
            ])
            .unwrap();
        assert_eq!(
            store
                .lookup("10.2.3.4")
                .unwrap()
                .unwrap()
                .country
                .as_deref(),
            Some("specific")
        );
        assert_eq!(
            store
                .lookup("10.9.0.1")
                .unwrap()
                .unwrap()
                .network
                .as_deref(),
            Some("10.0.0.0/8")
        );

        let stale = input("specific", "10.2.3.0/24", "stale", 1_699_000_000_000);
        assert_eq!(store.upsert(vec![stale]).unwrap().status, "unchanged");

        let assignment = store.assignment().unwrap().unwrap();
        let snapshot = IpContextSnapshot::open(&assignment.0, &assignment.1).unwrap();
        assert_eq!(snapshot.row_count(), 2);
        assert_eq!(
            snapshot
                .lookup("10.2.3.9")
                .unwrap()
                .unwrap()
                .source_id
                .as_deref(),
            Some("specific")
        );

        drop(store);
        let recovered = IpContextStore::new(directory.clone(), "tenant-a".to_string()).unwrap();
        assert_eq!(recovered.counts().unwrap().total_networks, 2);
        recovered.delete_source("specific").unwrap();
        assert_eq!(
            recovered
                .lookup("10.2.3.4")
                .unwrap()
                .unwrap()
                .source_id
                .as_deref(),
            Some("base")
        );
        let retained = std::fs::read_dir(directory)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("parquet")
            })
            .count();
        assert_eq!(retained, 2, "active and rollback snapshots are retained");
    }

    #[test]
    fn lean_open_refuses_valid_digest_oversize_and_malformed_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("oversize.parquet");
        File::create(&path)
            .unwrap()
            .set_len(LEAN_SNAPSHOT_MAX_BYTES + 1)
            .unwrap();
        let digest = crate::native::file_sha256(&path).unwrap();
        assert!(format!(
            "{:#}",
            IpContextSnapshot::open_lean(&path, &digest).unwrap_err()
        )
        .contains("64 MiB"));

        let path = root.path().join("malformed.parquet");
        std::fs::write(&path, b"not parquet").unwrap();
        let digest = crate::native::file_sha256(&path).unwrap();
        assert!(IpContextSnapshot::open_lean(&path, &digest).is_err());
        std::fs::write(&path, b"changed after digest").unwrap();
        assert!(format!(
            "{:#}",
            IpContextSnapshot::open_lean(&path, &digest).unwrap_err()
        )
        .contains("digest"));

        let row = StoredRow::new(input("source", "10.0.0.0/8", "US", 1_700_000_000_000)).unwrap();
        write_snapshot(&path, std::iter::once(&row)).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let trailer = bytes.len() - 8;
        bytes[trailer..trailer + 4]
            .copy_from_slice(&((LEAN_SNAPSHOT_MAX_FOOTER_BYTES + 1) as u32).to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let digest = crate::native::file_sha256(&path).unwrap();
        assert!(format!("{:#}", IpContextSnapshot::open_lean(&path, &digest).unwrap_err())
            .contains("oversized Parquet trailer"));
        bytes.truncate(bytes.len() - 4); // valid payload, missing Parquet trailer
        std::fs::write(&path, bytes).unwrap();
        let digest = crate::native::file_sha256(&path).unwrap();
        assert!(IpContextSnapshot::open_lean(&path, &digest).is_err());
    }

    #[test]
    fn lean_open_refuses_oversized_field_before_retaining_row() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("large-field.parquet");
        // Write a schema-valid artifact outside the validated publisher path.
        let batch = RecordBatch::try_new(
            snapshot_schema(),
            vec![
                Arc::new(StringArray::from(vec!["10.0.0.0/8"])) as _,
                Arc::new(StringArray::from(vec!["source"])) as _,
                Arc::new(StringArray::from(vec!["A".repeat(2_049)])) as _,
                Arc::new(StringArray::from(vec!["US"])) as _,
                Arc::new(StringArray::from(vec![""])) as _,
                Arc::new(StringArray::from(vec![""])) as _,
                Arc::new(StringArray::from(vec![""])) as _,
                Arc::new(StringArray::from(vec![""])) as _,
                Arc::new(StringArray::from(vec![""])) as _,
                Arc::new(Int64Array::from(vec![1_700_000_000_000])) as _,
                Arc::new(BooleanArray::from(vec![false])) as _,
            ],
        )
        .unwrap();
        let mut writer =
            ArrowWriter::try_new(File::create(&path).unwrap(), batch.schema(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let digest = crate::native::file_sha256(&path).unwrap();
        let error = format!("{:#}", IpContextSnapshot::open_lean(&path, &digest).unwrap_err());
        assert!(error.contains("oversized text field"), "{error}");
    }

    #[test]
    fn lean_open_refuses_over_row_artifact_before_decode() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("many.parquet");
        let row = StoredRow::new(input("source", "10.0.0.0/8", "US", 1_700_000_000_000)).unwrap();
        write_snapshot(&path, std::iter::repeat_n(&row, TENANT_SNAPSHOT_LIMIT_ROWS + 1)).unwrap();
        let digest = crate::native::file_sha256(&path).unwrap();
        assert_eq!(
            IpContextSnapshot::open(&path, &digest).unwrap().row_count(),
            TENANT_SNAPSHOT_LIMIT_ROWS + 1,
            "the pre-fix reader accepted this valid-digest artifact"
        );
        assert!(format!(
            "{:#}",
            IpContextSnapshot::open_lean(&path, &digest).unwrap_err()
        )
        .contains("rows"));
    }

    #[test]
    fn lean_open_refuses_high_ratio_decoded_artifact() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("compressed.parquet");
        let mut value = input(
            "source",
            "10.0.0.0/8",
            &"A".repeat(1_024),
            1_700_000_000_000,
        );
        value.country_code = "B".repeat(1_024);
        let row = StoredRow::new(value).unwrap();
        write_snapshot(&path, std::iter::repeat_n(&row, 49_000)).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() < LEAN_SNAPSHOT_MAX_BYTES);
        let digest = crate::native::file_sha256(&path).unwrap();
        let error = format!(
            "{:#}",
            IpContextSnapshot::open_lean(&path, &digest).unwrap_err()
        );
        assert!(error.contains("budget"), "{error}");
    }

    #[test]
    fn lean_page_header_scan_bounds_forged_decode_length() {
        let mut bytes = vec![0x15, 0, 0x15]; // page type 0, then decoded size
        let mut encoded = ((LEAN_SNAPSHOT_MAX_DECODED_BYTES + 1) as u64) << 1;
        while encoded >= 0x80 {
            bytes.push((encoded as u8) | 0x80);
            encoded >>= 7;
        }
        bytes.push(encoded as u8);
        bytes.extend([0x15, 2, 0, 0]); // one compressed byte, STOP, payload
        let (header, decoded, compressed) = compact_page_sizes(&bytes).unwrap();
        assert_eq!(header + compressed, bytes.len());
        assert!(decoded > LEAN_SNAPSHOT_MAX_DECODED_BYTES);
        assert!(compact_page_sizes(&bytes[..2]).is_err());
    }

    #[test]
    fn lean_open_retains_prior_revision_on_refused_rotation() {
        let root = tempfile::tempdir().unwrap();
        let store = IpContextStore::new(root.path().to_path_buf(), "tenant-a".into()).unwrap();
        store
            .upsert(vec![input("source", "10.0.0.0/8", "US", 1_700_000_000_000)])
            .unwrap();
        let assignment = store.assignment().unwrap().unwrap();
        let active = IpContextSnapshot::open_lean(&assignment.0, &assignment.1).unwrap();
        let other = root.path().join("other.parquet");
        File::create(&other)
            .unwrap()
            .set_len(LEAN_SNAPSHOT_MAX_BYTES + 1)
            .unwrap();
        let digest = crate::native::file_sha256(&other).unwrap();
        assert!(IpContextSnapshot::open_lean(&other, &digest).is_err());
        assert_eq!(active.sha256(), assignment.1);
        assert_eq!(
            active
                .lookup("10.2.3.4")
                .unwrap()
                .unwrap()
                .source_id
                .as_deref(),
            Some("source")
        );

        let other_store =
            IpContextStore::new(root.path().join("tenant-b"), "tenant-b".into()).unwrap();
        other_store
            .upsert(vec![input(
                "other-source",
                "192.0.2.0/24",
                "GB",
                1_700_000_000_000,
            )])
            .unwrap();
        let other_assignment = other_store.assignment().unwrap().unwrap();
        let other_active =
            IpContextSnapshot::open_lean(&other_assignment.0, &other_assignment.1).unwrap();
        assert!(active.lookup("192.0.2.1").unwrap().is_none());
        assert!(other_active.lookup("10.2.3.4").unwrap().is_none());
    }

    fn one_host(index: usize) -> String {
        format!("10.{}.{}.{}/32", (index >> 16) & 255, (index >> 8) & 255, index & 255)
    }

    #[test]
    fn lean_and_ioc_snapshots_share_one_row_cap() {
        // The lean IOC publisher and the lean custom IP-context reader must
        // agree; 50,000 is the original lookup/feed IOC expansion bound.
        assert_eq!(crate::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_ROWS, 50_000);
    }

    #[test]
    fn lean_store_refuses_over_row_upload_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("ip-context");
        let store = IpContextStore::new_lean(directory.clone(), "tenant-a".to_string()).unwrap();
        let cap = crate::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_ROWS;
        store
            .upsert(vec![input("seed", "192.0.2.0/24", "seed", 1_700_000_000_000)])
            .unwrap();
        let before = store.assignment().unwrap().unwrap();
        let rows = (0..cap)
            .map(|index| input("bulk", &one_host(index), "US", 1_700_000_000_001))
            .collect();
        let error = store.upsert(rows).unwrap_err();
        assert!(
            error.downcast_ref::<LeanSnapshotCapExceeded>().is_some(),
            "{error:#}"
        );
        assert_eq!(store.assignment().unwrap().unwrap(), before);
        let parquet = std::fs::read_dir(&directory)
            .unwrap()
            .filter(|entry| {
                entry.as_ref().unwrap().path().extension().is_some_and(|ext| ext == "parquet")
            })
            .count();
        assert_eq!(parquet, 1, "refused candidate must not leave a snapshot object");

        // gen1 stores keep their existing 10 million row ceiling.
        let gen1 = IpContextStore::new(root.path().join("gen1"), "tenant-a".to_string()).unwrap();
        let rows = (0..=cap)
            .map(|index| input("bulk", &one_host(index), "US", 1_700_000_000_001))
            .collect();
        assert_eq!(gen1.upsert(rows).unwrap().status, "published");
    }
}

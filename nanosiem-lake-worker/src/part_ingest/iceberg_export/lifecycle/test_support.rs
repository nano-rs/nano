// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory catalog/SQL service; all part verification and Iceberg manifest
//! construction still run through the production exporter.
use super::*;
use crate::part_ingest::iceberg_export::{
    self as export, hosted::HostedExportTarget, schema::SchemaContract, ExportTarget,
};
use crate::parts::{part_log::LocalObjectStore, provenance::TenantKeySet};
use iceberg::spec::{DataFileBuilder, Datum, SnapshotReference, SnapshotRetention, MAIN_BRANCH};
use iceberg::{
    memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE},
    CatalogBuilder, TableCreation, TableUpdate,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
};

pub(crate) struct Basin {
    tenant: String,
    bucket: String,
    root: PathBuf,
    target: HostedExportTarget,
    table: tokio::sync::Mutex<iceberg::table::Table>,
    metadata: Arc<metadata::MetadataGc>,
    pub metadata_authority: Arc<LocalMetadataAuthority>,
    pub blocked: AtomicBool,
    pub maintenance_on: AtomicBool,
    pub fail_expiry: AtomicBool,
    pub fail_cache: AtomicBool,
    pub ambiguous_commit: AtomicBool,
    /// NAN-4662: the catalog's commit-state read fails (catalog unreachable).
    pub fail_commit_state: AtomicBool,
    pub commit_state_reads: AtomicUsize,
    pub commits: AtomicUsize,
    pub checks: AtomicUsize,
    pub trace: Mutex<Vec<&'static str>>,
    cache: Mutex<Option<Vec<String>>>,
    /// NAN-4783: a long sync. While set, `expire_and_inspect` (custody held)
    /// signals `held` and waits for `release`.
    pub hold_inspection: AtomicBool,
    pub held: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}

impl Basin {
    pub async fn new(
        tenant: &str,
        root: PathBuf,
        source: Arc<LocalObjectStore>,
        trusted: TenantKeySet,
    ) -> Arc<Self> {
        let live = crate::parts::part_log::load_log(source.as_ref(), tenant)
            .await
            .unwrap();
        let arrow = live.schema().unwrap().to_arrow().unwrap();
        let contract = SchemaContract {
            version: 1,
            ocsf_version: "1.9.0".into(),
            schema: iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&arrow).unwrap(),
        };
        let catalog = MemoryCatalogBuilder::default()
            .with_storage_factory(Arc::new(iceberg::io::LocalFsStorageFactory))
            .load(
                "basin-fake",
                HashMap::from([(
                    MEMORY_CATALOG_WAREHOUSE.into(),
                    root.join(format!("metadata/{tenant}"))
                        .display()
                        .to_string(),
                )]),
            )
            .await
            .unwrap();
        let id = contract.table_ident("nano", "events").unwrap();
        catalog
            .create_namespace(&id.namespace, HashMap::new())
            .await
            .unwrap();
        let table = catalog
            .create_table(
                &id.namespace,
                TableCreation::builder()
                    .name(id.name.clone())
                    .schema(contract.schema)
                    .location(
                        root.join(format!("metadata/{tenant}/table"))
                            .display()
                            .to_string(),
                    )
                    .build(),
            )
            .await
            .unwrap();
        let bucket = crate::lake_part_gc::request::tenant_bucket(tenant);
        let target =
            HostedExportTarget::new(tenant.into(), source, trusted, bucket.clone()).unwrap();
        let table = Self::apply(&table, vec![]).unwrap();
        let location = format!(
            "s3://{bucket}/{}/nano/events_v1",
            crate::parts::format::iceberg_export_prefix(tenant).unwrap()
        );
        let metadata_authority = Arc::new(LocalMetadataAuthority {
            tenant: tenant.into(),
            prefix: format!("{location}/metadata/"),
            directory: PathBuf::from(table.metadata_location().unwrap())
                .parent()
                .unwrap()
                .into(),
            fail_delete: AtomicBool::new(false),
        });
        let metadata = Arc::new(
            metadata::MetadataGc::new(tenant, &location, metadata_authority.clone()).unwrap(),
        );
        Arc::new(Self {
            tenant: tenant.into(),
            bucket,
            root,
            target,
            table: tokio::sync::Mutex::new(table),
            metadata,
            metadata_authority,
            blocked: AtomicBool::new(false),
            maintenance_on: AtomicBool::new(false),
            fail_expiry: AtomicBool::new(false),
            fail_cache: AtomicBool::new(false),
            ambiguous_commit: AtomicBool::new(false),
            fail_commit_state: AtomicBool::new(false),
            commit_state_reads: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            checks: AtomicUsize::new(0),
            trace: Mutex::new(vec![]),
            cache: Mutex::new(None),
            hold_inspection: AtomicBool::new(false),
            held: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }

    fn apply(
        table: &iceberg::table::Table,
        updates: Vec<TableUpdate>,
    ) -> Result<iceberg::table::Table> {
        let mut builder = table.metadata().clone().into_builder(None);
        for update in updates {
            builder = update.apply(builder)?;
        }
        let metadata = builder.build()?.metadata;
        let location = format!(
            "{}/metadata/{}.metadata.json",
            metadata.location(),
            uuid::Uuid::new_v4()
        );
        std::fs::create_dir_all(PathBuf::from(&location).parent().unwrap())?;
        std::fs::write(&location, serde_json::to_vec(&metadata)?)?;
        Ok(iceberg::table::Table::builder()
            .metadata(metadata)
            .identifier(table.identifier().clone())
            .file_io(table.file_io().clone())
            .runtime(iceberg::Runtime::current())
            .metadata_location(location)
            .build()?)
    }

    fn file_names(&self, path: &str) -> Result<Vec<String>> {
        use arrow_array::{Array, StringArray};
        let key = path
            .strip_prefix(&format!("s3://{}/", self.bucket))
            .context("foreign SQL file")?;
        let file = std::fs::File::open(self.root.join("parts").join(key))?;
        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)?
            .build()?;
        let mut result = vec![];
        for batch in reader {
            let batch = batch?;
            let names = crate::erasure::resolve_string_leaf(&batch, "user.name")
                .context("fixture names absent")?;
            let names = arrow_cast::cast(&names, &arrow_schema::DataType::Utf8)?;
            let names = names.as_any().downcast_ref::<StringArray>().unwrap();
            result.extend(
                (0..names.len())
                    .filter(|i| !names.is_null(*i))
                    .map(|i| names.value(i).to_string()),
            );
        }
        Ok(result)
    }

    pub async fn query(&self, key_tenant: &str, snapshot: Option<i64>) -> Result<Vec<String>> {
        ensure!(key_tenant == self.tenant, "foreign tenant key refused");
        ensure!(
            !self.blocked.load(Ordering::SeqCst),
            "catalog privacy barrier"
        );
        let table = self.table.lock().await;
        let selected = snapshot
            .or(table.metadata().current_snapshot_id())
            .context("no snapshot")?;
        let snap = table
            .metadata()
            .snapshot_by_id(selected)
            .context("snapshot expired")?;
        if snapshot.is_none() {
            if let Some(rows) = self.cache.lock().unwrap().clone() {
                return Ok(rows);
            }
        }
        let list = table.manifest_list_reader(snap).load().await?;
        let mut rows = vec![];
        for descriptor in list.entries() {
            let manifest = descriptor.load_manifest(table.file_io()).await?;
            for entry in manifest.entries().iter().filter(|e| e.is_alive()) {
                rows.extend(self.file_names(entry.file_path())?);
            }
        }
        rows.sort();
        if snapshot.is_none() {
            *self.cache.lock().unwrap() = Some(rows.clone());
        }
        Ok(rows)
    }

    pub async fn snapshot_id(&self) -> i64 {
        self.table
            .lock()
            .await
            .metadata()
            .current_snapshot_id()
            .unwrap()
    }
    pub async fn checkpoint(&self) -> Option<i64> {
        self.table
            .lock()
            .await
            .metadata()
            .properties()
            .get(export::CHECKPOINT)
            .map(|v| v.parse().unwrap())
    }
    /// NAN-4614: every live data file of the current snapshot, duplicates kept.
    pub async fn live_files(&self) -> Vec<String> {
        let table = self.table.lock().await;
        let Some(snapshot) = table.metadata().current_snapshot() else { return vec![] };
        let mut files = vec![];
        for descriptor in table.manifest_list_reader(snapshot).load().await.unwrap().entries() {
            let manifest = descriptor.load_manifest(table.file_io()).await.unwrap();
            files.extend(manifest.entries().iter().filter(|e| e.is_alive()).map(|e| e.file_path().to_string()));
        }
        files
    }
    pub async fn snapshot_count(&self) -> usize {
        self.table.lock().await.metadata().snapshots().len()
    }
    pub fn cached_names(&self) -> Vec<String> {
        self.cache.lock().unwrap().clone().unwrap_or_default()
    }

    pub async fn bound_values(&self) -> Result<Vec<String>> {
        let table = self.table.lock().await;
        let mut values = vec![];
        for snapshot in table.metadata().snapshots() {
            for descriptor in table.manifest_list_reader(snapshot).load().await?.entries() {
                for entry in descriptor.load_manifest(table.file_io()).await?.entries() {
                    values.extend(
                        entry
                            .data_file()
                            .lower_bounds()
                            .values()
                            .chain(entry.data_file().upper_bounds().values())
                            .map(ToString::to_string),
                    );
                }
            }
        }
        Ok(values)
    }
}

#[async_trait::async_trait]
impl IcebergCommitter for Basin {
    async fn commit(&self, manifest: &ExportManifest) -> Result<()> {
        let mut table = self.table.lock().await;
        if export::checkpoint(&table, manifest)? {
            return Ok(());
        }
        let schema = table.metadata().current_schema();
        let mut added = self.target.prepare(manifest, schema).await?;
        // Include real per-column bounds, to detect leaking values through
        // deleted entries in the current manifest after snapshot expiry.
        // Resolved per added file: an empty delta needs no fixture column.
        for file in added.values_mut().flatten() {
            let field = schema.field_by_name("user.name").unwrap().id;
            let mut names = self.file_names(file.file_path())?;
            names.sort();
            *file = DataFileBuilder::default()
                .content(file.content_type())
                .file_format(file.file_format())
                .file_path(file.file_path().to_string())
                .partition(file.partition().clone())
                .partition_spec_id(0)
                .record_count(file.record_count())
                .file_size_in_bytes(file.file_size_in_bytes())
                .lower_bounds(
                    names
                        .first()
                        .map(|name| HashMap::from([(field, Datum::string(name))]))
                        .unwrap_or_default(),
                )
                .upper_bounds(
                    names
                        .last()
                        .map(|name| HashMap::from([(field, Datum::string(name))]))
                        .unwrap_or_default(),
                )
                .build()?;
        }
        let (snapshot, requirements) = export::prepare_lifecycle_snapshot(
            &table,
            manifest,
            added,
            schema,
            &self.target.data_prefix(),
            100_000,
        )
        .await?;
        for requirement in requirements {
            requirement.check(Some(table.metadata()))?;
        }
        let id = snapshot.snapshot_id();
        *table = Self::apply(
            &table,
            vec![
                TableUpdate::AddSnapshot { snapshot },
                TableUpdate::SetSnapshotRef {
                    ref_name: MAIN_BRANCH.into(),
                    reference: SnapshotReference::new(
                        id,
                        SnapshotRetention::branch(None, None, None),
                    ),
                },
                TableUpdate::SetProperties {
                    updates: HashMap::from([
                        (
                            export::CHECKPOINT.into(),
                            manifest.planned_at_ms.to_string(),
                        ),
                        (export::DIGEST.into(), manifest_digest(manifest)?),
                    ]),
                },
            ],
        )?;
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.trace.lock().unwrap().push("commit");
        ensure!(
            !self.ambiguous_commit.swap(false, Ordering::SeqCst),
            "lost commit response"
        );
        Ok(())
    }
}

#[async_trait::async_trait]
impl CatalogLifecycleBackend for Basin {
    fn tenant_id(&self) -> &str {
        &self.tenant
    }
    fn bucket(&self) -> &str {
        &self.bucket
    }
    async fn verify_maintenance(&self) -> Result<()> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        ensure!(
            !self.maintenance_on.load(Ordering::SeqCst),
            "automatic maintenance enabled"
        );
        Ok(())
    }
    async fn export_head(&self, with_parts: bool) -> Result<export::ExportHead> {
        let table = self.table.lock().await;
        export::export_head_of(&table, &self.target.data_prefix(), 100_000, with_parts).await
    }
    async fn no_committed_snapshot(&self) -> Result<bool> {
        self.commit_state_reads.fetch_add(1, Ordering::SeqCst);
        ensure!(
            !self.fail_commit_state.load(Ordering::SeqCst),
            "catalog commit-state lookup unavailable"
        );
        Ok(never_committed(&*self.table.lock().await))
    }
    async fn close_and_drain(&self) -> Result<()> {
        self.blocked.store(true, Ordering::SeqCst);
        self.trace.lock().unwrap().push("close");
        Ok(())
    }
    async fn expire_and_inspect(&self) -> Result<BTreeSet<String>> {
        if self.hold_inspection.load(Ordering::SeqCst) {
            self.held.notify_one();
            self.release.notified().await;
        }
        ensure!(
            !self.fail_expiry.load(Ordering::SeqCst),
            "expiry unavailable"
        );
        let mut table = self.table.lock().await;
        let (_, updates) = privacy_expiry_updates(&table)?;
        *table = Self::apply(&table, updates)?;
        self.trace.lock().unwrap().push("expire");
        let retained = metadata::retained_metadata(&table, 100_000)
            .await?
            .iter()
            .map(|p| self.metadata_authority.canonical(p))
            .collect::<Result<BTreeSet<_>>>()?;
        self.metadata
            .purge(
                table.metadata().uuid(),
                &self
                    .metadata_authority
                    .canonical(table.metadata_location().unwrap())?,
                &retained,
            )
            .await?;
        self.trace.lock().unwrap().push("purge");
        metadata_parts(&table, &self.target.data_prefix(), 100_000).await
    }
    async fn invalidate_results(&self) -> Result<()> {
        ensure!(
            !self.fail_cache.load(Ordering::SeqCst),
            "cache still reachable"
        );
        *self.cache.lock().unwrap() = None;
        self.trace.lock().unwrap().push("cache");
        Ok(())
    }
    async fn reopen(&self) -> Result<()> {
        self.trace.lock().unwrap().push("reopen");
        self.blocked.store(false, Ordering::SeqCst);
        Ok(())
    }
}

/// Local filesystem transport for the SAME guarded metadata authority contract.
/// It exposes canonical tenant URIs to production MetadataGc, never raw paths.
pub(crate) struct LocalMetadataAuthority {
    pub tenant: String,
    pub prefix: String,
    pub directory: PathBuf,
    pub fail_delete: AtomicBool,
}
impl LocalMetadataAuthority {
    fn canonical(&self, path: &str) -> Result<String> {
        let path = PathBuf::from(path);
        ensure!(
            path.parent() == Some(self.directory.as_path()),
            "foreign fixture metadata path"
        );
        Ok(format!(
            "{}{}",
            self.prefix,
            path.file_name()
                .context("metadata leaf missing")?
                .to_str()
                .context("invalid metadata leaf")?
        ))
    }
    pub fn subject_hits(&self, subject: &str) -> usize {
        std::fs::read_dir(&self.directory)
            .unwrap()
            .map(|e| {
                let bytes = std::fs::read(e.unwrap().path()).unwrap();
                usize::from(
                    bytes
                        .windows(subject.len())
                        .any(|w| w.eq_ignore_ascii_case(subject.as_bytes())),
                )
            })
            .sum()
    }
}
#[async_trait::async_trait]
impl metadata::MetadataDeleteAuthority for LocalMetadataAuthority {
    fn tenant_id(&self) -> &str {
        &self.tenant
    }
    fn metadata_prefix(&self) -> &str {
        &self.prefix
    }
    async fn inventory(&self) -> Result<Vec<String>> {
        std::fs::read_dir(&self.directory)?
            .map(|e| self.canonical(e?.path().to_str().context("invalid fixture path")?))
            .collect()
    }
    async fn retire(
        &self,
        request: &metadata::MetadataDeleteRequest,
    ) -> Result<metadata::MetadataDeleteRequest> {
        ensure!(
            !self.fail_delete.load(Ordering::SeqCst),
            "metadata delete unavailable"
        );
        ensure!(
            request.tenant_id == self.tenant
                && request.metadata_prefix == self.prefix
                && request.key != request.current_metadata,
            "foreign metadata delete"
        );
        let leaf = request
            .key
            .strip_prefix(&self.prefix)
            .context("foreign metadata key")?;
        ensure!(!leaf.contains('/'), "nested metadata key");
        std::fs::remove_file(self.directory.join(leaf))?;
        Ok(request.clone())
    }
}

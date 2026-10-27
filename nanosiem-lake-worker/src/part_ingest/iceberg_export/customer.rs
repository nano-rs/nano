// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verified immutable copies into a tenant's customer bucket. One bounded file
//! is staged on disk at a time; ingest/search never call this adapter.
use super::super::export::ExportManifest;
use super::{validate_manifest, ExportTarget};
use crate::parts::{
    format::{PartId, PartKeys},
    part_log::{ObjectStore, WriteHints, WriterClass},
    provenance::{SignedProvenance, TenantKeySet, MAX_PROVENANCE_BYTES},
};
use anyhow::{ensure, Result};
use iceberg::spec::{DataContentType, DataFile, DataFileBuilder, DataFileFormat, Schema, Struct};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const CHUNK: u64 = 4 * 1024 * 1024;

pub struct CustomerExportTarget {
    tenant: String,
    source: Arc<dyn ObjectStore>,
    destination: Arc<dyn ObjectStore>,
    keys: TenantKeySet,
    uri_prefix: String,
    pub bytes_copied: AtomicU64,
    pub files_copied: AtomicU64,
}
impl CustomerExportTarget {
    pub fn new(
        tenant: String,
        source: Arc<dyn ObjectStore>,
        destination: Arc<dyn ObjectStore>,
        keys: TenantKeySet,
        uri_prefix: String,
    ) -> Result<Self> {
        crate::parts::format::validate_tenant_uuid(&tenant)?;
        super::validate_object_uri(&uri_prefix)?;
        ensure!(
            uri_prefix.ends_with('/') && uri_prefix.contains(&format!("/tenant={tenant}/")),
            "customer export prefix must be tenant-bound"
        );
        Ok(Self {
            tenant,
            source,
            destination,
            keys,
            uri_prefix,
            bytes_copied: AtomicU64::new(0),
            files_copied: AtomicU64::new(0),
        })
    }
}

/// Download only signed byte ranges, incrementally hashing them. A short,
/// missing, enlarged, or changed object fails before any destination mutation.
async fn stage(
    store: &dyn ObjectStore,
    key: &str,
    path: &Path,
    size: u64,
    expected: &str,
) -> Result<()> {
    stage_bounded(store, key, path, size, expected, MAX_FILE_BYTES).await
}

pub(super) async fn stage_bounded(
    store: &dyn ObjectStore,
    key: &str,
    path: &Path,
    size: u64,
    expected: &str,
    limit: u64,
) -> Result<()> {
    ensure!(
        size > 0 && size <= limit,
        "export file exceeds copy bound"
    );
    ensure!(
        store.object_size(key).await? == Some(size),
        "export object size differs"
    );
    let mut file = std::fs::File::create(path)?;
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < size {
        let end = (offset + CHUNK).min(size);
        let bytes = store
            .get_range(key, offset..end)
            .await?
            .ok_or_else(|| anyhow::anyhow!("export source missing"))?;
        ensure!(
            bytes.len() as u64 == end - offset,
            "export source range differs"
        );
        hash.update(&bytes);
        file.write_all(&bytes)?;
        offset = end;
    }
    ensure!(
        hex::encode(hash.finalize()) == expected,
        "export source checksum differs"
    );
    Ok(())
}

fn compatible(expected: &iceberg::spec::Type, actual: &iceberg::spec::Type) -> bool {
    use iceberg::spec::Type;
    match (expected, actual) {
        (Type::Struct(e), Type::Struct(a)) => {
            e.fields()
                .iter()
                .filter(|f| f.required)
                .all(|f| a.fields().iter().any(|a| a.name == f.name))
                && a.fields().iter().all(|f| {
                    e.fields()
                        .iter()
                        .find(|x| x.name == f.name)
                        .is_some_and(|x| compatible(&x.field_type, &f.field_type))
                })
        }
        (Type::List(e), Type::List(a)) => {
            compatible(&e.element_field.field_type, &a.element_field.field_type)
        }
        (Type::Map(e), Type::Map(a)) => {
            e.key_field.field_type == a.key_field.field_type
                && compatible(&e.value_field.field_type, &a.value_field.field_type)
        }
        (Type::Primitive(e), Type::Primitive(a)) => e == a,
        _ => false,
    }
}

pub(super) fn footer(path: &Path, schema: &Schema, rows: u64) -> Result<()> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?;
    ensure!(
        reader.metadata().file_metadata().num_rows() as u64 == rows,
        "export footer row count differs"
    );
    let actual = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(reader.schema().as_ref())?;
    ensure!(
        schema
            .as_struct()
            .fields()
            .iter()
            .filter(|f| f.required)
            .all(|f| actual.as_struct().fields().iter().any(|a| a.name == f.name)),
        "export required footer field missing"
    );
    for field in actual.as_struct().fields() {
        // NAN-4664: the derived IOC indicator columns are a lake index, not
        // table data. They carry no field ID, so Iceberg's name mapping never
        // projects them.
        if nanosiem_core::search::lake_indicators::is_indicator_column(&field.name) {
            continue;
        }
        let expected = schema
            .as_struct()
            .fields()
            .iter()
            .find(|e| e.name == field.name)
            .ok_or_else(|| anyhow::anyhow!("export footer field is outside contract"))?;
        ensure!(
            compatible(&expected.field_type, &field.field_type),
            "export footer field type differs"
        );
    }
    for column in reader.metadata().file_metadata().schema_descr().columns() {
        let basic = column.self_type().get_basic_info();
        if basic.has_id() {
            let name = column.path().parts().join(".");
            let expected = schema
                .field_by_name(&name)
                .ok_or_else(|| anyhow::anyhow!("export embedded ID path unknown"))?;
            ensure!(
                expected.id == basic.id(),
                "export embedded field ID differs"
            );
        }
    }
    Ok(())
}

#[async_trait::async_trait]
impl ExportTarget for CustomerExportTarget {
    async fn prepare(
        &self,
        manifest: &ExportManifest,
        schema: &Schema,
    ) -> Result<BTreeMap<String, Vec<DataFile>>> {
        validate_manifest(manifest, &self.tenant, 100_000)?;
        let spool = tempfile::tempdir()?;
        let mut prepared = BTreeMap::new();
        for part in &manifest.add {
            let first = part
                .keys
                .first()
                .ok_or_else(|| anyhow::anyhow!("export part has no data"))?;
            let directory = first
                .rsplit_once('/')
                .ok_or_else(|| anyhow::anyhow!("export part key invalid"))?
                .0;
            let copied_provenance = format!("{}/provenance.json", part.part_id);
            let source_provenance = format!("{directory}/provenance.json");
            let (provenance_store, provenance_key) = if self
                .destination
                .object_size(&copied_provenance)
                .await?
                .is_some()
            {
                (self.destination.as_ref(), copied_provenance.as_str())
            } else {
                (self.source.as_ref(), source_provenance.as_str())
            };
            let size = provenance_store
                .object_size(provenance_key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("export provenance missing"))?;
            ensure!(
                size > 0 && size <= MAX_PROVENANCE_BYTES as u64,
                "export provenance exceeds bound"
            );
            let provenance = provenance_store
                .get_range(provenance_key, 0..size)
                .await?
                .ok_or_else(|| anyhow::anyhow!("export provenance missing"))?;
            let signed = SignedProvenance::verify_bytes(&provenance, &self.tenant, &self.keys)?;
            let record = &signed.record;
            let keys = PartKeys::new(
                &self.tenant,
                record.level,
                record.event_hour,
                &PartId::parse(&part.part_id)?,
            )?;
            ensure!(
                keys.provenance() == format!("{directory}/provenance.json")
                    && record.part_id.to_string() == part.part_id
                    && record.rows == part.rows
                    && record.files.data_bytes() == part.bytes
                    && record.min_time_us == part.min_time_us
                    && record.max_time_us == part.max_time_us
                    && record.files.data.len() == part.keys.len(),
                "export manifest differs from signed record"
            );
            let mut files = Vec::new();
            for (index, digest) in record.files.data.iter().enumerate() {
                ensure!(
                    part.keys[index] == keys.data(index),
                    "export data path differs from signed record"
                );
                let path = spool.path().join("data.parquet");
                let key = format!("{}/{}", part.part_id, digest.name);
                let present = self.destination.object_size(&key).await?.is_some();
                if present {
                    stage(
                        self.destination.as_ref(),
                        &key,
                        &path,
                        digest.bytes,
                        &digest.sha256,
                    )
                    .await?;
                } else {
                    stage(
                        self.source.as_ref(),
                        &part.keys[index],
                        &path,
                        digest.bytes,
                        &digest.sha256,
                    )
                    .await?;
                }
                footer(&path, schema, digest.rows)?;
                let created = !present
                    && self
                        .destination
                        .put_export_file_if_absent(
                            &key,
                            &path,
                            &digest.sha256,
                            digest.bytes,
                            &WriteHints {
                                class: WriterClass::LakePart,
                                event_hour: record.event_hour,
                                min_time_ms: digest.min_time_us / 1000,
                                max_time_ms: digest.max_time_us / 1000,
                            },
                        )
                        .await?;
                if !created && !present {
                    // Conditional collision is acceptable ONLY for exactly the signed bytes.
                    let existing = spool.path().join("existing.parquet");
                    stage(
                        self.destination.as_ref(),
                        &key,
                        &existing,
                        digest.bytes,
                        &digest.sha256,
                    )
                    .await?;
                    ensure!(
                        std::fs::metadata(&existing)?.len() == digest.bytes,
                        "export destination differs"
                    );
                } else if created {
                    self.bytes_copied.fetch_add(digest.bytes, Ordering::Relaxed);
                    self.files_copied.fetch_add(1, Ordering::Relaxed);
                }
                files.push(
                    DataFileBuilder::default()
                        .content(DataContentType::Data)
                        .file_format(DataFileFormat::Parquet)
                        .file_path(format!("{}{key}", self.uri_prefix))
                        .partition(Struct::empty())
                        .partition_spec_id(0)
                        .record_count(digest.rows)
                        .file_size_in_bytes(digest.bytes)
                        .build()?,
                );
            }
            if !self
                .destination
                .put_if_absent(&copied_provenance, &provenance)
                .await?
            {
                let existing = self
                    .destination
                    .get_range(&copied_provenance, 0..size)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("export proof missing"))?;
                ensure!(
                    existing == provenance
                        && self.destination.object_size(&copied_provenance).await? == Some(size),
                    "export proof collision"
                );
            }
            prepared.insert(part.part_id.clone(), files);
        }
        Ok(prepared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part_ingest::export::{ExportFile, ExportHour};
    use crate::parts::{
        levels::Level,
        part_log::LocalObjectStore,
        provenance::{
            tests::{sample_record, signer, TENANT},
            PartSigner, SignedProvenance,
        },
    };
    use arrow_array::{Int64Array, RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema as ArrowSchema};
    use parquet::arrow::ArrowWriter;
    async fn fixture() -> (
        tempfile::TempDir,
        Arc<LocalObjectStore>,
        Arc<LocalObjectStore>,
        CustomerExportTarget,
        ExportManifest,
        Schema,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let source = Arc::new(LocalObjectStore::new(directory.path().join("source")).unwrap());
        let destination =
            Arc::new(LocalObjectStore::new(directory.path().join("customer")).unwrap());
        let arrow = Arc::new(ArrowSchema::new(vec![
            Field::new("time", DataType::Int64, true),
            Field::new("uid", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            arrow.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1, 2])),
                Arc::new(StringArray::from(vec!["a", "b"])),
            ],
        )
        .unwrap();
        let mut bytes = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut bytes, arrow.clone(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let mut record = sample_record();
        record.level = Level::Hour;
        record.admission = None;
        record.inputs = crate::parts::provenance::PartInputs::Parts {
            parts: vec![crate::parts::provenance::InputPart {
                part_id: PartId::new(1).unwrap(),
                level: Level::L0,
                provenance_sha256: "0".repeat(64),
                rows: 2,
                merkle_root: "0".repeat(64),
            }],
        };
        record.files.data[0].bytes = bytes.len() as u64;
        record.files.data[0].sha256 = crate::parts::sha256_hex(&bytes);
        let keys = PartKeys::new(TENANT, record.level, record.event_hour, &record.part_id).unwrap();
        let owner = signer(7);
        let signature = owner
            .sign(TENANT, std::slice::from_ref(&record))
            .await
            .unwrap()
            .remove(0);
        let signed =
            SignedProvenance::assemble(record.clone(), signature, &owner.trusted()).unwrap();
        source
            .put(&keys.provenance(), &signed.to_bytes().unwrap())
            .await
            .unwrap();
        source.put(&keys.data(0), &bytes).await.unwrap();
        let id = record.part_id.to_string();
        let manifest = ExportManifest {
            tenant_id: TENANT.into(),
            planned_at_ms: 100,
            previous_plan_ms: None,
            add: vec![ExportFile {
                part_id: id.clone(),
                keys: vec![keys.data(0)],
                rows: 2,
                bytes: bytes.len() as u64,
                min_time_us: 1,
                max_time_us: 2,
            }],
            remove_parts: vec![],
            hours: vec![ExportHour {
                event_hour: record.event_hour,
                parts: vec![id],
            }],
        };
        let target = CustomerExportTarget::new(
            TENANT.into(),
            source.clone(),
            destination.clone(),
            owner.trusted(),
            format!("s3://customer/export/tenant={TENANT}/data/"),
        )
        .unwrap();
        (
            directory,
            source,
            destination,
            target,
            manifest,
            iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&arrow).unwrap(),
        )
    }
    /// NAN-4664: a signed data file carrying the derived IOC indicator
    /// columns still exports (they sit outside the table contract, without
    /// field IDs); any other extra column is still refused.
    #[test]
    fn export_footer_admits_only_the_indicator_columns_beyond_the_contract() {
        let contract = ArrowSchema::new(vec![Field::new("time", DataType::Int64, true), Field::new("uid", DataType::Utf8, true)]);
        let schema = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&contract).unwrap();
        let list = DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)));
        let write = |extra: &str| {
            let file = tempfile::NamedTempFile::new().unwrap();
            let arrow = Arc::new(ArrowSchema::new(vec![
                Field::new("time", DataType::Int64, true), Field::new("uid", DataType::Utf8, true), Field::new(extra, list.clone(), true),
            ]));
            let mut values = arrow_array::builder::ListBuilder::new(arrow_array::builder::StringBuilder::new());
            values.values().append_value("203.0.113.77");
            values.append(true);
            let batch = RecordBatch::try_new(arrow.clone(), vec![
                Arc::new(Int64Array::from(vec![1])), Arc::new(StringArray::from(vec!["a"])), Arc::new(values.finish()),
            ]).unwrap();
            let mut writer = ArrowWriter::try_new(file.reopen().unwrap(), arrow, None).unwrap();
            writer.write(&batch).unwrap();
            writer.close().unwrap();
            file
        };
        footer(write("nano_ioc_ips").path(), &schema, 1).unwrap();
        assert!(footer(write("other_ips").path(), &schema, 1).is_err());
    }

    #[tokio::test]
    async fn signed_copy_replays_without_rewriting_or_source_mutation() {
        let (_directory, source, destination, target, manifest, schema) = fixture().await;
        let source_before = source.get(&manifest.add[0].keys[0]).await.unwrap().unwrap();
        let first = target.prepare(&manifest, &schema).await.unwrap();
        let bytes = target.bytes_copied.load(Ordering::Relaxed);
        assert_eq!(bytes, source_before.len() as u64);
        // A copied pending plan must replay even after our supersession GC.
        source.delete(&manifest.add[0].keys[0]).await.unwrap();
        let dir = manifest.add[0].keys[0].rsplit_once('/').unwrap().0;
        source
            .delete(&format!("{dir}/provenance.json"))
            .await
            .unwrap();
        assert_eq!(first, target.prepare(&manifest, &schema).await.unwrap());
        assert_eq!(target.bytes_copied.load(Ordering::Relaxed), bytes);
        assert_eq!(target.files_copied.load(Ordering::Relaxed), 1);
        assert!(source
            .get(&manifest.add[0].keys[0])
            .await
            .unwrap()
            .is_none());
        assert_eq!(destination.list("").await.unwrap().len(), 2);
    }
    #[tokio::test]
    async fn corrupt_source_and_destination_collisions_fail_closed() {
        let (_directory, source, destination, target, manifest, schema) = fixture().await;
        let key = &manifest.add[0].keys[0];
        let mut body = source.get(key).await.unwrap().unwrap();
        body[0] ^= 1;
        source.put(key, &body).await.unwrap();
        assert!(target.prepare(&manifest, &schema).await.is_err());
        assert!(destination.list("").await.unwrap().is_empty());
        let (_directory, _, destination, target, manifest, schema) = fixture().await;
        destination
            .put(
                &format!("{}/data-00000.parquet", manifest.add[0].part_id),
                b"wrong",
            )
            .await
            .unwrap();
        assert!(target.prepare(&manifest, &schema).await.is_err());
    }
    #[tokio::test]
    async fn older_files_allow_optional_additions_but_require_required_fields() {
        for optional in [false, true] {
            let (_directory, _, destination, target, manifest, _) = fixture().await;
            let arrow = ArrowSchema::new(vec![
                Field::new("time", DataType::Int64, true),
                Field::new("uid", DataType::Utf8, true),
                Field::new("new_field", DataType::Utf8, optional),
            ]);
            let schema = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&arrow).unwrap();
            assert_eq!(target.prepare(&manifest, &schema).await.is_ok(), optional);
            if !optional {
                assert!(destination.list("").await.unwrap().is_empty());
            }
        }
    }
    #[tokio::test]
    async fn tenant_mismatch_is_rejected_before_any_copy() {
        let (_directory, _, destination, target, mut manifest, schema) = fixture().await;
        manifest.tenant_id = uuid::Uuid::new_v4().to_string();
        assert!(target.prepare(&manifest, &schema).await.is_err());
        assert!(destination.list("").await.unwrap().is_empty());
    }
}

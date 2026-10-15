// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded, immutable compact finding ledgers derived from authenticated parts.
use super::{
    engine::PartQueryEngine,
    risk::{CompactFinding, COMPACT_FINDING_PATH, TRUSTED_FINDING_PATH},
};
use crate::{
    generation::CompiledStringPath,
    parts::{parquet_ranges::ParquetRangeDigest, part_log::PartRef},
};
use anyhow::{ensure, Context, Result};
use arrow_array::RecordBatch;
use arrow_schema::{DataType, Field, Schema};
use parquet::arrow::{arrow_reader::ParquetRecordBatchReaderBuilder, ArrowWriter, ProjectionMask};
use parquet::file::reader::ChunkReader;
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

const LEAVES: [&str; 5] = [
    COMPACT_FINDING_PATH,
    TRUSTED_FINDING_PATH,
    "class_uid",
    "metadata.uid",
    "time",
];

fn selected_ranges(ranges: &[ParquetRangeDigest]) -> Vec<usize> {
    ranges
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            (r.column.is_none() || r.column.as_deref().is_some_and(|c| LEAVES.contains(&c)))
                .then_some(i)
        })
        .collect()
}

fn ledger_schema() -> Arc<Schema> {
    let strings = [
        "id",
        "entity",
        "stamped_entity_type",
        "rule_id",
        "rule_name",
        "severity",
    ];
    let mut fields = strings
        .into_iter()
        .map(|name| Field::new(name, DataType::Utf8, false))
        .collect::<Vec<_>>();
    fields.extend([
        Field::new("timestamp_us", DataType::Int64, false),
        Field::new("risk_score", DataType::Int64, false),
    ]);
    for name in ["origin_source_types", "mitre_tactics"] {
        fields.push(Field::new(
            name,
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ));
    }
    Arc::new(Schema::new(fields))
}

/// Empty finding inventories need no native query or admission slot.
pub(super) fn write_empty(path: &Path) -> Result<()> {
    ArrowWriter::try_new(File::create(path)?, ledger_schema(), None)?.close()?;
    Ok(())
}

fn append<R: ChunkReader + 'static>(reader: R, writer: &mut ArrowWriter<File>) -> Result<()> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(reader)?;
    let schema = builder.parquet_schema();
    let leaves = (0..schema.num_columns())
        .filter(|&i| LEAVES.contains(&schema.column(i).path().string().as_str()))
        .collect::<Vec<_>>();
    let mask = ProjectionMask::leaves(schema, leaves);
    for batch in builder
        .with_projection(mask)
        .with_batch_size(1024)
        .build()?
    {
        let batch = batch?;
        // Compaction may mix finding and ordinary source files. Preserve
        // the former reader's class/marker filter, including missing leaves.
        let Some(compact) = CompiledStringPath::new(&batch, COMPACT_FINDING_PATH) else {
            continue;
        };
        let Some(trusted) = CompiledStringPath::new(&batch, TRUSTED_FINDING_PATH) else {
            continue;
        };
        let uid = CompiledStringPath::new(&batch, "metadata.uid").context("finding has no uid")?;
        let class = arrow_cast::cast(
            batch
                .column_by_name("class_uid")
                .context("finding has no class")?
                .as_ref(),
            &DataType::Int64,
        )?;
        let class = class
            .as_any()
            .downcast_ref::<arrow_array::Int64Array>()
            .context("invalid finding class")?;
        let mut json = Vec::new();
        for row in 0..batch.num_rows() {
            use arrow_array::Array;
            if class.is_null(row) || class.value(row) != 2004 || trusted.strings(row) != ["v1"] {
                continue;
            }
            let values = compact.strings(row);
            if values.is_empty() {
                continue;
            }
            ensure!(values.len() == 1, "finding compact leaf is not singular");
            let finding: CompactFinding = serde_json::from_str(&values[0])?;
            ensure!(
                !finding.id.is_empty() && uid.strings(row) == [finding.id.clone()],
                "finding uid mismatch"
            );
            ensure!(
                crate::generation::event_time_us_from_array(
                    batch
                        .column_by_name("time")
                        .context("finding has no time")?
                        .as_ref(),
                    row
                ) == Some(finding.timestamp_us),
                "finding timestamp mismatch"
            );
            serde_json::to_writer(&mut json, &finding)?;
            json.push(b'\n');
        }
        let decoded = arrow_json::ReaderBuilder::new(ledger_schema())
            .with_batch_size(1024)
            .build(std::io::Cursor::new(json))?;
        for output in decoded {
            let output: RecordBatch = output?;
            writer.write(&output)?;
        }
    }
    Ok(())
}

pub(super) async fn part_ledger(
    engine: &PartQueryEngine,
    state: &Path,
    part: &PartRef,
) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let key = hex::encode(Sha256::digest(serde_json::to_vec(part)?));
    let path = state.join(format!("risk-part-v1-{key}.parquet"));
    if path.is_file() {
        File::open(&path)?.set_modified(std::time::SystemTime::now())?;
        return Ok(path);
    }
    let temporary = state.join(format!(
        ".risk-part-{}.parquet",
        uuid::Uuid::new_v4().simple()
    ));
    let result = async {
        let record = engine.fetcher().record(part).await?;
        let properties = parquet::file::properties::WriterProperties::builder()
            .set_max_row_group_row_count(Some(8192))
            .build();
        let mut writer =
            ArrowWriter::try_new(File::create(&temporary)?, ledger_schema(), Some(properties))?;
        for index in 0..record.files.data.len() {
            let _slot = super::product_state::idle(engine).await;
            if let Some(ranges) = engine.fetcher().data_ranges(part, index).await? {
                let selected = selected_ranges(&ranges);
                let reader = engine
                    .fetcher()
                    .range_reader(part, index, &selected)
                    .await?
                    .context("signed ranges disappeared")?;
                writer = tokio::task::spawn_blocking(move || {
                    append(reader, &mut writer)?;
                    Ok::<_, anyhow::Error>(writer)
                })
                .await??;
            } else {
                // Older signed parts lack range digests. Derive one file at
                // a time under the unchanged cold budget, never all payload
                // files of a merged part or the entire week's inventory.
                let local = engine
                    .fetcher()
                    .ensure_files(&[(part.clone(), super::fetch::PartFile::Data(index))])
                    .await?;
                let file = local
                    .path(&part.part_id, super::fetch::PartFile::Data(index))
                    .context("finding file missing")?;
                let reader = File::open(&file.path)?;
                writer = tokio::task::spawn_blocking(move || {
                    append(reader, &mut writer)?;
                    Ok::<_, anyhow::Error>(writer)
                })
                .await??;
            }
        }
        writer.close()?;
        std::fs::rename(&temporary, &path)?;
        Ok::<_, anyhow::Error>(path.clone())
    }
    .await;
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::fetch::FileSet;
    use super::*;
    #[test]
    fn mixed_compacted_rows_preserve_the_finding_class_and_trust_filter() {
        let root = tempfile::tempdir().unwrap();
        let at = 1_790_444_800_000_000_i64;
        let finding = CompactFinding {
            id: "trusted".into(),
            timestamp_us: at,
            entity: "alice".into(),
            stamped_entity_type: "user".into(),
            risk_score: 10,
            rule_id: "r1".into(),
            rule_name: "Rule".into(),
            severity: "low".into(),
            origin_source_types: vec![],
            mitre_tactics: vec![],
        };
        let trusted = super::super::risk::finding_event(&serde_json::json!({"class_uid":2004,
            "time":chrono::DateTime::from_timestamp_micros(at).unwrap().to_rfc3339(),"metadata":{"uid":"trusted"}}),&finding).unwrap();
        let mut source = trusted.clone();
        source["class_uid"] = serde_json::json!(6003);
        source["metadata"]["uid"] = serde_json::json!("source");
        let mut untrusted = trusted.clone();
        untrusted["unmapped"]["nano_finding_outbox_trusted"] = serde_json::Value::Null;
        let rows = [&trusted, &source, &untrusted];
        let schema = Arc::new(crate::part_ingest::schema::infer_schema(&rows).unwrap());
        let input = root.path().join("mixed.parquet");
        let mut writer =
            ArrowWriter::try_new(File::create(&input).unwrap(), schema.clone(), None).unwrap();
        writer
            .write(&crate::part_ingest::schema::decode(schema, &rows).unwrap())
            .unwrap();
        writer.close().unwrap();
        let output = root.path().join("ledger.parquet");
        let mut writer =
            ArrowWriter::try_new(File::create(&output).unwrap(), ledger_schema(), None).unwrap();
        append(File::open(input).unwrap(), &mut writer).unwrap();
        writer.close().unwrap();
        let rows = ParquetRecordBatchReaderBuilder::try_new(File::open(output).unwrap())
            .unwrap()
            .build()
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            rows.num_rows(),
            1,
            "ordinary events and untrusted findings must not contribute risk"
        );
    }

    #[tokio::test]
    async fn signed_multi_day_inventory_refuses_full_fetch_and_projects_real_findings() {
        use super::super::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
        use crate::{
            part_ingest::{
                schema,
                writer::{PartDraft, PartWriter, PartialSource},
            },
            parts::{
                format::PartKeys,
                levels::Level,
                part_log::{LocalObjectStore, ObjectStore},
                provenance::{
                    Admission, FileDigest, LocalPartSigner, PartInputs, PartSigner,
                    SignedProvenance, SourceObject,
                },
                DedupWindow,
            },
            reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings},
        };
        use std::io::{Read, Seek, SeekFrom, Write};
        let tenant = "00000000-0000-4000-8000-000000000001";
        let root = tempfile::tempdir().unwrap();
        let source_root = root.path().join("source");
        let store = Arc::new(LocalObjectStore::new(&source_root).unwrap());
        let signer = LocalPartSigner::new(
            "lab-risk-projection",
            ed25519_dalek::SigningKey::from_bytes(&[71; 32]),
        )
        .unwrap();
        let mut inventory = Vec::new();
        let mut manifests = Vec::new();
        for day in 0..7 {
            let timestamp = 1_790_444_800_000_000_i64 - day * 86_400_000_000;
            let compact = CompactFinding {
                id: format!("finding-{day}"),
                timestamp_us: timestamp,
                entity: "alice@example.com".into(),
                stamped_entity_type: "email".into(),
                risk_score: 75,
                rule_id: "r1".into(),
                rule_name: "Regression".into(),
                severity: "high".into(),
                origin_source_types: vec!["auth".into()],
                mitre_tactics: vec!["execution".into()],
            };
            let event = super::super::risk::finding_event(
                &serde_json::json!({"class_uid":2004,
                "time":chrono::DateTime::from_timestamp_micros(timestamp).unwrap().to_rfc3339(),
                "metadata":{"uid":compact.id,"tenant_uid":tenant}}),
                &compact,
            )
            .unwrap();
            let schema = Arc::new(schema::infer_schema(&[&event]).unwrap());
            let draft = PartDraft {
                tenant_id: tenant.into(),
                signer_key_id: signer.key_id().into(),
                level: Level::L0,
                event_hour: crate::parts::event_hour_of(timestamp),
                schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
                schema: schema.clone(),
                inputs: PartInputs::Sources {
                    sources: vec![SourceObject {
                        key: format!("fixture-{day}"),
                        version: "1".into(),
                        sha256: "a".repeat(64),
                        bytes: 1,
                        rows: 1,
                        edge_sha256: None,
                    }],
                    edge_log: None,
                },
                admission: Some(Admission {
                    ocsf_version: crate::iceberg::OCSF_VERSION.into(),
                    admission_contract: "finding-outbox-v1".into(),
                    feed_pins: std::collections::BTreeMap::new(),
                }),
                rows_in: 1,
                duplicates_dropped: 0,
                window: DedupWindow::Exact,
                build: "regression".into(),
            };
            let mut writer = PartWriter::create(
                root.path(),
                draft,
                PartialSource::FromFindings,
                timestamp / 1000,
                1,
            )
            .unwrap();
            writer
                .write(&schema::decode(schema, &[&event]).unwrap())
                .unwrap();
            let mut finished = writer.finish().unwrap();
            let data = &mut finished.record.files.data[0];
            let input = finished.dir.join(&data.name);
            // Each object remains below the signed 2 GiB object ceiling.
            // Sparse padding models physical payload size without allocating
            // it in RAM. Footer/chunks and whole-object digests are all real.
            let mut file = File::options().read(true).write(true).open(&input).unwrap();
            file.seek(SeekFrom::End(-8)).unwrap();
            let mut trailer = [0; 8];
            file.read_exact(&mut trailer).unwrap();
            let footer_size = u32::from_le_bytes(trailer[..4].try_into().unwrap()) as u64 + 8;
            let footer_start = file.metadata().unwrap().len() - footer_size;
            file.seek(SeekFrom::Start(footer_start)).unwrap();
            let mut footer = Vec::new();
            file.read_to_end(&mut footer).unwrap();
            file.set_len(footer_start).unwrap();
            file.seek(SeekFrom::Start(512 * 1024 * 1024)).unwrap();
            file.write_all(&footer).unwrap();
            drop(file);
            let (bytes, sha) = crate::part_ingest::writer::file_digest(&input).unwrap();
            data.bytes = bytes;
            data.sha256 = sha;
            let ranges = crate::parts::parquet_ranges::build(&input).unwrap();
            let manifest = serde_json::to_vec(&ranges).unwrap();
            data.parquet_ranges = Some(FileDigest {
                name: "ranges-00000.json".into(),
                bytes: manifest.len() as u64,
                sha256: crate::parts::sha256_hex(&manifest),
            });
            let keys = PartKeys::new(
                tenant,
                finished.record.level,
                finished.record.event_hour,
                &finished.record.part_id,
            )
            .unwrap();
            let destination = source_root.join(keys.file(&data.name));
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::rename(input, destination).unwrap();
            store
                .put(&keys.file("ranges-00000.json"), &manifest)
                .await
                .unwrap();
            let signature = signer
                .sign(tenant, &[finished.record.clone()])
                .await
                .unwrap()
                .remove(0);
            let signed =
                SignedProvenance::assemble(finished.record.clone(), signature, &signer.trusted())
                    .unwrap()
                    .to_bytes()
                    .unwrap();
            store.put(&keys.provenance(), &signed).await.unwrap();
            inventory.push(PartRef::from_record(
                &finished.record,
                &crate::parts::sha256_hex(&signed),
                true,
            ));
            manifests.push(ranges);
        }
        let cache = ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: root.path().join("cache"),
                // NAN-3644: over-threshold reads queue rather than refuse, so
                // a 4 GiB cache puts the ceiling at 2 GiB, under the ~3.5 GiB
                // full-data week. The full lease still trips the ceiling.
                max_bytes: 4 << 30,
                query_max_bytes: 2 << 30,
                fetch_concurrency: 4,
                fetch_deadline: std::time::Duration::from_secs(30),
            },
            tenant,
            "bucket",
            &parts_key_prefix(tenant).unwrap(),
            Arc::new(StoreObjectSource::local(
                "bucket",
                store.clone(),
                source_root,
            )),
        )
        .unwrap();
        let fetcher = PartFetcher::new(tenant, "bucket", store, signer.trusted(), cache).unwrap();
        let failure = fetcher
            .ensure(&inventory, &[FileSet::AllData])
            .await
            .err()
            .expect("old week's full-data lease must trip the cold ceiling");
        assert!(
            failure.to_string().contains("uncached bytes in one pass"),
            "{failure:#}"
        );
        let output = root.path().join("ledger.parquet");
        let mut writer =
            ArrowWriter::try_new(File::create(&output).unwrap(), ledger_schema(), None).unwrap();
        for (part, ranges) in inventory.iter().zip(manifests) {
            let reader = fetcher
                .range_reader(part, 0, &selected_ranges(&ranges))
                .await
                .unwrap()
                .unwrap();
            append(reader, &mut writer).unwrap();
        }
        writer.close().unwrap();
        let batch = ParquetRecordBatchReaderBuilder::try_new(File::open(output).unwrap())
            .unwrap()
            .build()
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(batch.num_rows(), 7);
        let scores = batch
            .column_by_name("risk_score")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow_array::Int64Array>()
            .unwrap();
        assert!(scores.iter().all(|score| score == Some(75)));
        assert!(fetcher.cache().stats().fetched_bytes < 1024 * 1024);
    }

    #[test]
    fn projected_columns_exclude_the_wide_event_payload() {
        let mut ranges = Vec::new();
        for column in LEAVES.into_iter().chain(["unmapped.raw_payload"]) {
            ranges.push(ParquetRangeDigest {
                offset: 4,
                bytes: if column == "unmapped.raw_payload" {
                    5 * 1024 * 1024 * 1024
                } else {
                    1024 * 1024
                },
                sha256: "a".repeat(64),
                row_group: Some(0),
                column: Some(column.into()),
            });
        }
        ranges.push(ParquetRangeDigest {
            offset: 0,
            bytes: 8192,
            sha256: "b".repeat(64),
            row_group: None,
            column: None,
        });
        assert!(ranges.iter().map(|r| r.bytes).sum::<u64>() > 2 * 1024 * 1024 * 1024);
        let selected = selected_ranges(&ranges);
        assert!(selected.iter().map(|&i| ranges[i].bytes).sum::<u64>() < 6 * 1024 * 1024);
        assert!(selected
            .iter()
            .all(|&i| ranges[i].column.as_deref() != Some("unmapped.raw_payload")));
    }
}

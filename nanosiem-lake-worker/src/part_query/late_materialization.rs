// SPDX-License-Identifier: AGPL-3.0-or-later

//! Predicate-first cold reads: the native identity pass reads narrow chunks;
//! this pass authenticates and decodes only payload pages holding those rows.
//! Derived files are query-owned scratch, never whole-object cache entries.
use super::*;
use crate::part_query::{engine::Selection, range_fetch::ColumnScope, two_pass::RowId};
use crate::parts::parquet_ranges::ParquetRangeDigest;
use crate::reader_object_cache::{ColdBudget, ScratchReservation};
use anyhow::ensure;
use arrow_array::RecordBatchReader;
use parquet::arrow::arrow_reader::{
    ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder, RowSelection,
};
use parquet::arrow::{ArrowWriter, ProjectionMask};
use parquet::file::metadata::ParquetMetaDataReader;
use parquet::file::page_index::offset_index::{OffsetIndexMetaData, PageLocation};
use parquet::file::reader::Length;

pub(crate) struct Payload {
    pub selection: Selection,
    pub ids: Vec<RowId>,
    pub fetched_bytes: u64,
    pub materialize_seconds: f64,
    pub whole_fetched_bytes: u64,
    _files: Vec<Materialized>,
    _scratch: Arc<crate::part_query::range_fetch::SparseStore>,
}

struct Materialized {
    path: PathBuf,
    _file: Option<tempfile::TempPath>,
    _reservation: Option<ScratchReservation>,
    _lease: Option<ReaderCacheLease>,
    compact: bool,
    fetched_bytes: u64,
}

struct RowsReader {
    input: LeasedRangeReader,
    metadata: ArrowReaderMetadata,
    groups: Vec<usize>,
    selection: RowSelection,
    projection: ProjectionMask,
    // Conservative source-derived scratch and decode bounds, never fixed caps.
    decoded_bytes: u64,
    peak_group_bytes: u64,
    selected_rows: usize,
    passthrough: bool,
}

impl PartFetcher {
    /// `ids` are native row identities from this exact leased selection.
    /// No caller-supplied offset, digest or path becomes fetch authority.
    pub(crate) async fn materialize_payload(
        &self,
        selection: &Selection,
        ids: &[RowId],
        scope: &ColumnScope,
        role_memory: u64,
        threads: usize,
    ) -> Result<Payload> {
        use futures::{StreamExt, TryStreamExt};
        ensure!(!ids.is_empty(), "empty payload identity set");
        let mut by_path = BTreeMap::<String, Vec<u64>>::new();
        for id in ids {
            by_path
                .entry(id.path.clone())
                .or_default()
                .push(u64::try_from(id.row).context("negative native row identity")?);
        }
        for rows in by_path.values_mut() {
            rows.sort_unstable();
            ensure!(
                rows.windows(2).all(|pair| pair[0] < pair[1]),
                "duplicate payload row"
            );
        }
        let mut payload = selection.only_paths(&by_path.keys().cloned().collect())?;
        ensure!(
            payload.manifest.objects.len() == by_path.len(),
            "payload path is outside the pinned selection"
        );
        let cache = payload
            .tenant
            .snapshot_cache
            .as_ref()
            .context("payload source is not local")?;
        let mut work = Vec::new();
        let parts = selection
            .parts
            .iter()
            .map(|part| (part.part_id.as_str(), part))
            .collect::<BTreeMap<_, _>>();
        // Resolve only the payload files. Walking every selected part here can
        // re-fetch evicted provenance on a large window just to return two rows.
        for (key, object) in &cache.objects {
            let (prefix, name) = key.rsplit_once('/').context("invalid payload object key")?;
            let part_id = prefix
                .rsplit('/')
                .next()
                .context("payload part id missing")?;
            let part = *parts
                .get(part_id)
                .context("payload object is outside selected parts")?;
            let index = name
                .strip_prefix("data-")
                .and_then(|name| name.strip_suffix(".parquet"))
                .context("invalid payload data name")?
                .parse::<usize>()?;
            let record = self.record(part).await?;
            ensure!(
                self.file_uri(part, &record, PartFile::Data(index))? == *key,
                "payload key differs from signed source"
            );
            let path = object
                .path
                .to_str()
                .context("payload path is not UTF-8")?
                .to_string();
            let rows = by_path
                .remove(&path)
                .context("payload source has no native identities")?;
            work.push((part.clone(), index, key.clone(), path, rows));
        }
        ensure!(by_path.is_empty(), "payload identity has no signed source");
        let parent = crate::part_query::range_fetch::current();
        let budget = ColdBudget::new(parent.as_ref().map_or(
            self.cache.query_cold_budget(),
            |scope| {
                scope
                    .budget(self.cache.query_cold_budget())
                    .saturating_sub(scope.cold_spent())
            },
        ));
        let concurrency = threads.max(1);
        // Reuse the process-locked sparse store: an abrupt exit otherwise
        // leaves query payloads forever outside object-cache accounting.
        // A live process's directory is never swept by another reader.
        let scratch = self.sparse_store().await?;
        scratch.maybe_sweep();
        let root = scratch.dir().to_path_buf();
        let results =
            futures::stream::iter(work.into_iter().map(|(part, index, key, old_path, rows)| {
                let (root, cache, scratch) = (root.clone(), self.cache.clone(), scratch.clone());
                let budget = &budget;
                async move {
                    let reader = self
                        .payload_reader(&part, index, &rows, scope, budget)
                        .await?;
                    // A part written by a larger role can have dictionaries
                    // too wide for this reader. Native execution already owns
                    // the memory-retry path; do not decode those in Rust.
                    let reader = if !reader.passthrough
                        && reader.peak_group_bytes > role_memory / concurrency as u64 / 2
                    {
                        drop(reader);
                        self.whole_rows_reader(&part, index, &rows, scope, budget)
                            .await?
                    } else {
                        reader
                    };
                    let (file, seconds) = tokio::task::spawn_blocking(move || {
                        // Cancellation cannot release the directory's lock
                        // while a blocking materializer is still writing.
                        let _scratch = scratch;
                        let started = std::time::Instant::now();
                        let file = if reader.passthrough {
                            reader.whole_file()?
                        } else {
                            reader.materialize(&root, &cache, role_memory / concurrency as u64)?
                        };
                        Ok::<_, anyhow::Error>((file, started.elapsed().as_secs_f64()))
                    })
                    .await??;
                    Ok::<_, anyhow::Error>((key, old_path, rows, file, seconds))
                }
            }))
            .buffered(concurrency)
            .try_collect::<Vec<_>>()
            .await;
        if let Some(parent) = parent {
            parent.add_cold_spent(budget.spent());
        }
        let results = results?;
        let mut remap = BTreeMap::new();
        let mut files = Vec::new();
        let cache = payload
            .tenant
            .snapshot_cache
            .as_mut()
            .context("payload cache missing")?;
        let mut materialize_seconds = 0.;
        let mut whole_fetched_bytes = 0;
        for (key, old_path, rows, file, seconds) in results {
            materialize_seconds += seconds;
            whole_fetched_bytes += file.fetched_bytes;
            let new_path = file
                .path
                .to_str()
                .context("materialized path is not UTF-8")?
                .to_string();
            for (position, row) in rows.into_iter().enumerate() {
                remap.insert(
                    RowId {
                        path: old_path.clone(),
                        row: i64::try_from(row)?,
                    },
                    RowId {
                        path: new_path.clone(),
                        row: if file.compact {
                            i64::try_from(position)?
                        } else {
                            i64::try_from(row)?
                        },
                    },
                );
            }
            cache
                .objects
                .get_mut(&key)
                .context("payload object missing")?
                .path = file.path.to_path_buf();
            files.push(file);
        }
        let mut paths = cache
            .objects
            .values()
            .map(|object| object.path.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        cache.source_spec = crate::planner::local_path_spec(&mut paths)?;
        // Compact files contain only proven rows; passthrough files retain
        // original offsets. Exact native identity parameters fence both forms.
        payload.candidates = None;
        let ids = ids
            .iter()
            .map(|id| {
                remap
                    .get(id)
                    .cloned()
                    .context("unmaterialized row identity")
            })
            .collect::<Result<Vec<_>>>()?;
        let mut evidence = crate::part_query::range_fetch::FetchEvidence::default();
        evidence.fetched(0, budget.spent() - whole_fetched_bytes, whole_fetched_bytes);
        Ok(Payload {
            selection: payload,
            ids,
            fetched_bytes: budget.spent(),
            materialize_seconds,
            whole_fetched_bytes,
            _files: files,
            _scratch: scratch,
        })
    }

    async fn whole_rows_reader(
        &self,
        part: &PartRef,
        index: usize,
        rows: &[u64],
        scope: &ColumnScope,
        budget: &ColdBudget,
    ) -> Result<RowsReader> {
        let local = self
            .ensure_files_within(&[(part.clone(), PartFile::Data(index))], Some(budget))
            .await?;
        let file = local
            .path(&part.part_id, PartFile::Data(index))
            .context("whole payload missing")?;
        let path = file.path.clone();
        let bytes = file.bytes;
        let input = LeasedRangeReader {
            bytes,
            chunks: BTreeMap::from([(0, (bytes, path))]),
            _lease: local.lease.context("whole payload lease missing")?,
        };
        let metadata = ArrowReaderMetadata::load(&input, ArrowReaderOptions::new())?;
        let mut reader = RowsReader::new(input, metadata, rows, scope)?;
        reader.passthrough = true;
        Ok(reader)
    }

    async fn payload_reader(
        &self,
        part: &PartRef,
        index: usize,
        rows: &[u64],
        scope: &ColumnScope,
        budget: &ColdBudget,
    ) -> Result<RowsReader> {
        let record = self.record(part).await?;
        let data = record
            .files
            .data
            .get(index)
            .context("payload index outside signed inventory")?;
        ensure!(
            rows.last().is_some_and(|last| *last < data.rows),
            "payload row outside signed file"
        );
        // Residency wins, including a legacy part or a failed narrow range read.
        if data.parquet_ranges.is_none() || self.whole_is_local(part, &record, index).await? {
            return self
                .whole_rows_reader(part, index, rows, scope, budget)
                .await;
        }
        let local = self
            .ensure_files_within(&[(part.clone(), PartFile::Ranges(index))], Some(budget))
            .await?;
        let manifest = local
            .path(&part.part_id, PartFile::Ranges(index))
            .context("payload manifest missing")?;
        let ranges = self.parse_ranges(manifest, data)?;
        let footer = ranges.last().context("payload footer missing")?;
        ensure!(
            footer.column.is_none(),
            "payload footer identity is invalid"
        );
        let refs = self.range_refs(part, &record, index, std::iter::once(footer))?;
        let footer_lease = self.cache.ensure_local_within(&refs, budget).await?;
        let bytes = tokio::fs::read(footer_lease.pinned_path(&footer.sha256)).await?;
        ensure!(bytes.len() >= 8, "short payload footer");
        let metadata = ParquetMetaDataReader::decode_metadata(&bytes[..bytes.len() - 8])?;
        ensure!(
            metadata.file_metadata().num_rows() == i64::try_from(data.rows)?
                && metadata.num_row_groups() == data.row_groups as usize,
            "payload footer differs from signed inventory"
        );
        let by_column = ranges
            .iter()
            .filter_map(|range| Some(((range.row_group?, range.column.as_deref()?), range)))
            .collect::<BTreeMap<_, _>>();
        let mut selected = vec![footer.clone()];
        let mut offsets = Vec::new();
        let mut group_start = 0_u64;
        let mut complete_index = true;
        for (group_index, group) in metadata.row_groups().iter().enumerate() {
            let group_end = group_start
                .checked_add(u64::try_from(group.num_rows())?)
                .context("payload row overflow")?;
            let keep = rows.partition_point(|row| *row < group_end)
                > rows.partition_point(|row| *row < group_start);
            let mut group_offsets = Vec::new();
            for column in group.columns() {
                let path = column.column_path().string();
                let range = by_column.get(&(group_index as u32, path.as_str())).copied();
                let pages = range
                    .map(|range| range.pages.as_slice())
                    .unwrap_or_default();
                let data_pages = pages
                    .iter()
                    .filter(|page| page.first_row.is_some())
                    .collect::<Vec<_>>();
                for page in &data_pages {
                    ensure!(
                        page.first_row.unwrap() < group_end - group_start,
                        "page row outside its signed group"
                    );
                }
                group_offsets.push(OffsetIndexMetaData {
                    page_locations: data_pages
                        .iter()
                        .map(|page| {
                            Ok(PageLocation {
                                offset: i64::try_from(page.offset)?,
                                compressed_page_size: i32::try_from(page.bytes)?,
                                first_row_index: i64::try_from(page.first_row.unwrap())?,
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                    unencoded_byte_array_data_bytes: None,
                });
                if !keep || !scope.covers(&path) {
                    continue;
                }
                let range = range.context("payload column absent from signed manifest")?;
                ensure!(
                    range.offset == column.byte_range().0 && range.bytes == column.byte_range().1,
                    "payload chunk differs from signed footer"
                );
                // Repeated leaves can split a row across pages. Keep their
                // whole authenticated chunk; flat leaves use exact page rows.
                if data_pages.is_empty() || column.column_descr().max_rep_level() > 0 {
                    complete_index &= !data_pages.is_empty();
                    selected.push(range.clone());
                } else {
                    ensure!(
                        data_pages
                            .windows(2)
                            .all(|pair| pair[0].first_row < pair[1].first_row),
                        "flat page rows must increase"
                    );
                    for (page_index, page) in pages.iter().enumerate() {
                        let keep_page = match page.first_row {
                            None => true,
                            Some(first) => {
                                let next = pages
                                    .get(page_index + 1)
                                    .and_then(|next| next.first_row)
                                    .unwrap_or(group_end - group_start);
                                let start = group_start + first;
                                let end = group_start + next;
                                rows.partition_point(|row| *row < end)
                                    > rows.partition_point(|row| *row < start)
                            }
                        };
                        if keep_page {
                            selected.push(ParquetRangeDigest {
                                offset: page.offset,
                                bytes: page.bytes,
                                sha256: page.sha256.clone(),
                                row_group: range.row_group,
                                column: range.column.clone(),
                                pages: Vec::new(),
                            });
                        }
                    }
                }
            }
            offsets.push(group_offsets);
            group_start = group_end;
        }
        // Without a complete offset index, use the legacy authenticated chunks.
        // RowSelection still avoids materializing rejected rows.
        if !complete_index
            || !crate::part_query::range_fetch::is_narrow(
                selected.iter().map(|range| range.bytes).sum(),
                data.bytes,
            )
        {
            return self
                .whole_rows_reader(part, index, rows, scope, budget)
                .await;
        }
        let metadata = Arc::new(
            metadata
                .into_builder()
                .set_offset_index(Some(offsets))
                .build(),
        );
        let refs = self.range_refs(part, &record, index, selected.iter())?;
        self.import_ranges(part, &record, index, &refs).await?;
        let lease = self.cache.ensure_local_within(&refs, budget).await?;
        let chunks = selected
            .iter()
            .map(|range| {
                (
                    range.offset,
                    (range.bytes, lease.pinned_path(&range.sha256)),
                )
            })
            .collect();
        let input = LeasedRangeReader {
            bytes: data.bytes,
            chunks,
            _lease: lease,
        };
        let metadata = ArrowReaderMetadata::try_new(metadata, ArrowReaderOptions::new())?;
        RowsReader::new(input, metadata, rows, scope)
    }
}

impl RowsReader {
    fn new(
        input: LeasedRangeReader,
        metadata: ArrowReaderMetadata,
        rows: &[u64],
        scope: &ColumnScope,
    ) -> Result<Self> {
        ensure!(
            !rows.is_empty() && rows.windows(2).all(|pair| pair[0] < pair[1]),
            "payload rows must be sorted and unique"
        );
        let parquet = metadata.metadata();
        ensure!(
            rows.last().copied().unwrap() < u64::try_from(parquet.file_metadata().num_rows())?,
            "payload row outside footer"
        );
        let columns = parquet
            .file_metadata()
            .schema_descr()
            .columns()
            .iter()
            .enumerate()
            .filter_map(|(index, column)| scope.covers(&column.path().string()).then_some(index))
            .collect::<Vec<_>>();
        ensure!(!columns.is_empty(), "empty payload projection");
        let projection = ProjectionMask::leaves(
            parquet.file_metadata().schema_descr(),
            columns.iter().copied(),
        );
        let (mut start, mut kept_rows, mut decoded_bytes) = (0_u64, 0_usize, 0_u64);
        let mut groups = Vec::new();
        let mut selected = Vec::new();
        let mut peak_group_bytes = 0;
        for (index, group) in parquet.row_groups().iter().enumerate() {
            let end = start
                .checked_add(u64::try_from(group.num_rows())?)
                .context("payload group overflow")?;
            let matches = &rows
                [rows.partition_point(|row| *row < start)..rows.partition_point(|row| *row < end)];
            if !matches.is_empty() {
                groups.push(index);
                for row in matches {
                    let at = kept_rows
                        .checked_add(usize::try_from(row - start)?)
                        .context("payload selection overflow")?;
                    selected.push(at..at + 1);
                }
                kept_rows = kept_rows
                    .checked_add(usize::try_from(end - start)?)
                    .context("payload row count overflow")?;
                let before = decoded_bytes;
                for column in &columns {
                    decoded_bytes = decoded_bytes
                        .checked_add(u64::try_from(group.column(*column).uncompressed_size())?)
                        .context("payload decode size overflow")?;
                }
                peak_group_bytes = peak_group_bytes.max(decoded_bytes - before);
            }
            start = end;
        }
        let selection = RowSelection::from_consecutive_ranges(selected.into_iter(), kept_rows);
        Ok(Self {
            input,
            metadata,
            groups,
            selection,
            projection,
            decoded_bytes,
            peak_group_bytes,
            selected_rows: rows.len(),
            passthrough: false,
        })
    }

    fn whole_file(self) -> Result<Materialized> {
        let (_, path) = self
            .input
            .chunks
            .get(&0)
            .context("whole-file payload is not fully leased")?;
        Ok(Materialized {
            path: path.clone(),
            fetched_bytes: self.input._lease.fetched_bytes(),
            _file: None,
            _reservation: None,
            _lease: Some(self.input._lease),
            compact: false,
        })
    }

    fn materialize(
        self,
        root: &std::path::Path,
        cache: &ReaderObjectCache,
        memory_per_thread: u64,
    ) -> Result<Materialized> {
        // Budget from the actual source footprint and the executing role. No
        // extra cache, environment setting, row cap or machine-size constant.
        let source_rows = self
            .groups
            .iter()
            .map(|g| self.metadata.metadata().row_group(*g).num_rows() as u64)
            .sum::<u64>()
            .max(1);
        let mean_row = self.decoded_bytes.div_ceil(source_rows).max(1);
        let batch_rows =
            usize::try_from((memory_per_thread / 16 / mean_row).max(1))?.min(self.selected_rows);
        let scratch_bytes = self
            .decoded_bytes
            .saturating_mul(2)
            .saturating_add(self.input.len().min(memory_per_thread));
        let ((path, count), reservation) = cache.scratch_write(scratch_bytes, || {
            (|| -> Result<_> {
                let reader =
                    ParquetRecordBatchReaderBuilder::new_with_metadata(self.input, self.metadata)
                        .with_projection(self.projection)
                        .with_row_groups(self.groups)
                        .with_row_selection(self.selection)
                        .with_batch_size(batch_rows)
                        .build()?;
                let file = tempfile::Builder::new()
                    .prefix("payload-")
                    .suffix(".parquet")
                    .tempfile_in(root)?;
                let properties = parquet::file::properties::WriterProperties::builder()
                    .set_compression(parquet::basic::Compression::ZSTD(Default::default()))
                    .set_max_row_group_row_count(Some(batch_rows))
                    .build();
                let mut writer =
                    ArrowWriter::try_new(file.reopen()?, reader.schema(), Some(properties))?;
                let mut count = 0;
                for batch in reader {
                    let batch = batch?;
                    count += batch.num_rows();
                    writer.write(&batch)?;
                }
                writer.close()?;
                ensure!(
                    file.as_file().metadata()?.len() <= scratch_bytes,
                    "materialized payload exceeds scratch reservation"
                );
                Ok((file.into_temp_path(), count))
            })()
            .map_err(|error| std::io::Error::other(format!("{error:#}")))
        })?;
        ensure!(
            count == self.selected_rows,
            "materialization lost native row identities"
        );
        Ok(Materialized {
            path: path.to_path_buf(),
            _file: Some(path),
            _reservation: Some(reservation),
            _lease: None,
            compact: true,
            fetched_bytes: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::provenance::tests::{sample_record, signer, TENANT};
    use crate::parts::provenance::{FileDigest, PartSigner, SignedProvenance};
    use crate::reader_object_cache::ReaderObjectCacheSettings;
    use arrow_array::{
        types::Int64Type, ArrayRef, Int64Array, ListArray, RecordBatch, StringArray, StructArray,
    };
    use arrow_schema::{DataType, Field, Fields, Schema};

    struct Fixture {
        root: tempfile::TempDir,
        fetcher: PartFetcher,
        part: PartRef,
        path: PathBuf,
    }
    async fn fixture(dictionary: bool, mutate: &str) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("fixture.parquet");
        let nested = Fields::from(vec![Field::new("uid", DataType::Utf8, true)]);
        let item = Arc::new(Field::new("item", DataType::Int64, true));
        let schema = Arc::new(Schema::new(vec![
            Field::new("key", DataType::Int64, false),
            Field::new("raw_data", DataType::Utf8, true),
            Field::new("metadata", DataType::Struct(nested.clone()), true),
            Field::new("tags", DataType::List(item), true),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from_iter_values(0..4096)) as ArrayRef,
                Arc::new(StringArray::from_iter((0..4096).map(|i| {
                    (i % 11 != 0).then(|| format!("{i} {}", "x".repeat(512)))
                }))),
                Arc::new(StructArray::new(
                    nested,
                    vec![Arc::new(StringArray::from_iter_values(
                        (0..4096).map(|i| format!("uid-{i}")),
                    ))],
                    None,
                )),
                Arc::new(ListArray::from_iter_primitive::<Int64Type, _, _>(
                    (0..4096).map(|i| {
                        if i % 9 == 0 {
                            None
                        } else {
                            Some(vec![Some(i), None, Some(i + 1)])
                        }
                    }),
                )),
            ],
        )
        .unwrap();
        let props = parquet::file::properties::WriterProperties::builder()
            .set_max_row_group_row_count(Some(2048))
            .set_data_page_row_count_limit(128)
            .set_write_batch_size(128)
            .set_dictionary_enabled(dictionary)
            .set_statistics_enabled(parquet::file::properties::EnabledStatistics::Page)
            .build();
        let mut writer =
            ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), schema, Some(props))
                .unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let body = std::fs::read(&path).unwrap();
        let mut ranges = crate::parts::parquet_ranges::build(&path).unwrap();
        let raw = ranges
            .iter_mut()
            .find(|r| r.column.as_deref() == Some("raw_data"))
            .unwrap();
        if mutate == "hash" {
            raw.pages[0].sha256 = "f".repeat(64);
        }
        if mutate == "rows" {
            raw.pages
                .iter_mut()
                .rev()
                .find(|p| p.first_row.is_some())
                .unwrap()
                .first_row = Some(2048);
        }
        if mutate == "offset" {
            raw.pages[0].offset += 1;
        }
        if mutate == "legacy" {
            for range in &mut ranges {
                range.pages.clear();
            }
        }
        let manifest = serde_json::to_vec(&ranges).unwrap();
        let source_root = root.path().join("source");
        let store = Arc::new(LocalObjectStore::new(&source_root).unwrap());
        let signer = signer(7);
        let mut record = sample_record();
        record.rows = 4096;
        record.hours[0].rows = 4096;
        record.dedup.rows_in = 4096;
        record.files.data[0].rows = 4096;
        record.files.data[0].row_groups = 2;
        record.files.data[0].bytes = body.len() as u64;
        record.files.data[0].sha256 = sha256_hex(&body);
        record.files.data[0].parquet_ranges = Some(FileDigest {
            name: "ranges-00000.json".into(),
            bytes: manifest.len() as u64,
            sha256: sha256_hex(&manifest),
        });
        let keys = crate::parts::format::PartKeys::new(
            TENANT,
            record.level,
            record.event_hour,
            &record.part_id,
        )
        .unwrap();
        store
            .put(&keys.file("data-00000.parquet"), &body)
            .await
            .unwrap();
        store
            .put(&keys.file("ranges-00000.json"), &manifest)
            .await
            .unwrap();
        let signature = signer
            .sign(TENANT, std::slice::from_ref(&record))
            .await
            .unwrap()
            .remove(0);
        let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted())
            .unwrap()
            .to_bytes()
            .unwrap();
        store.put(&keys.provenance(), &signed).await.unwrap();
        let part = PartRef::from_record(&record, &sha256_hex(&signed), true);
        let cache = ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: root.path().join("cache"),
                max_bytes: 64 << 20,
                query_max_bytes: 64 << 20,
                fetch_concurrency: 2,
                fetch_deadline: std::time::Duration::from_secs(10),
            },
            TENANT,
            "bucket",
            &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::local(
                "bucket",
                store.clone(),
                source_root,
            )),
        )
        .unwrap();
        let fetcher = PartFetcher::new(TENANT, "bucket", store, signer.trusted(), cache).unwrap();
        Fixture {
            root,
            fetcher,
            part,
            path,
        }
    }
    fn scope() -> ColumnScope {
        ColumnScope::new(
            ["key", "raw_data", "metadata", "tags"]
                .map(str::to_string)
                .into(),
            Default::default(),
        )
    }

    #[tokio::test]
    async fn signed_pages_match_whole_rows_with_nulls_nested_lists_and_dictionary() {
        for dictionary in [false, true] {
            let f = fixture(dictionary, "").await;
            let rows = [0, 127, 128, 2047, 2048, 4095];
            let reader = f
                .fetcher
                .payload_reader(&f.part, 0, &rows, &scope(), &ColdBudget::new(64 << 20))
                .await
                .unwrap();
            let output = reader
                .materialize(f.root.path(), f.fetcher.cache(), 64 << 20)
                .unwrap();
            let read = |path: &std::path::Path| {
                ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap())
                    .unwrap()
                    .build()
                    .unwrap()
                    .map(std::result::Result::unwrap)
                    .collect::<Vec<_>>()
            };
            let actual = read(&output.path);
            let builder =
                ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&f.path).unwrap())
                    .unwrap();
            let schema = builder.schema().clone();
            let expected = builder
                .with_row_selection(RowSelection::from_consecutive_ranges(
                    rows.iter().map(|r| *r as usize..*r as usize + 1),
                    4096,
                ))
                .build()
                .unwrap()
                .map(std::result::Result::unwrap)
                .collect::<Vec<_>>();
            assert_eq!(
                arrow_select::concat::concat_batches(&schema, &actual).unwrap(),
                arrow_select::concat::concat_batches(&schema, &expected).unwrap()
            );
            if !dictionary {
                assert!(
                    f.fetcher.cache().stats().fetched_bytes * 2
                        < std::fs::metadata(&f.path).unwrap().len()
                );
            }
            let path = output.path.to_path_buf();
            drop(output);
            assert!(!path.exists());
        }
    }

    #[tokio::test]
    async fn legacy_chunks_keep_exact_rows() {
        let f = fixture(false, "legacy").await;
        let reader = f
            .fetcher
            .payload_reader(
                &f.part,
                0,
                &[128, 2048],
                &scope(),
                &ColdBudget::new(64 << 20),
            )
            .await
            .unwrap();
        let output = reader
            .materialize(f.root.path(), f.fetcher.cache(), 64 << 20)
            .unwrap();
        let rows =
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&output.path).unwrap())
                .unwrap()
                .build()
                .unwrap()
                .map(|b| b.unwrap().num_rows())
                .sum::<usize>();
        assert_eq!(rows, 2);
    }

    #[tokio::test]
    async fn corrupt_pages_bad_offsets_and_out_of_bounds_rows_fail_closed() {
        for mutate in ["hash", "rows", "offset"] {
            let f = fixture(false, mutate).await;
            assert!(
                f.fetcher
                    .payload_reader(&f.part, 0, &[0], &scope(), &ColdBudget::new(64 << 20))
                    .await
                    .is_err(),
                "{mutate}"
            );
        }
        let f = fixture(false, "").await;
        for rows in [&[4096][..], &[u64::MAX][..], &[128, 0][..], &[0, 0][..]] {
            assert!(f
                .fetcher
                .payload_reader(&f.part, 0, rows, &scope(), &ColdBudget::new(64 << 20))
                .await
                .is_err());
        }
    }
    #[tokio::test]
    async fn payload_scratch_is_swept_only_after_its_process_lock_is_released() {
        let f = fixture(false, "").await;
        let scratch = f.fetcher.sparse_store().await.unwrap();
        let reader = f
            .fetcher
            .payload_reader(&f.part, 0, &[128], &scope(), &ColdBudget::new(64 << 20))
            .await
            .unwrap();
        let payload = reader
            .materialize(scratch.dir(), f.fetcher.cache(), 64 << 20)
            .unwrap();
        let path = payload.path.clone();
        let peer = crate::part_query::range_fetch::SparseStore::open(
            &f.fetcher.cache.scratch_dir("ranged"),
            f.fetcher.cache.max_bytes(),
        )
        .unwrap();
        assert!(
            path.exists(),
            "peer startup must preserve active native payloads"
        );
        drop(payload);
        assert!(
            !path.exists(),
            "normal query completion removes payload scratch"
        );
        let orphan = scratch.dir().join("payload-crashed.parquet");
        std::fs::write(&orphan, b"abandoned by a killed process").unwrap();
        peer.sweep();
        assert!(
            orphan.exists(),
            "the process lock must protect its whole directory"
        );
        drop(scratch);
        f.fetcher.reset_sparse_memo().await;
        peer.sweep();
        assert!(
            !orphan.exists(),
            "dead-process payloads must not accumulate outside cache accounting"
        );
    }

    #[tokio::test]
    async fn tampered_source_page_is_never_served_or_admitted() {
        for dictionary in [false, true] {
            let f = fixture(dictionary, "").await;
            let ranges = f.fetcher.data_ranges(&f.part, 0).await.unwrap().unwrap();
            let raw = ranges
                .iter()
                .find(|range| range.column.as_deref() == Some("raw_data"))
                .unwrap();
            let page = if dictionary {
                raw.pages
                    .iter()
                    .find(|page| page.first_row.is_none())
                    .unwrap()
            } else {
                raw.pages
                    .iter()
                    .find(|page| page.first_row == Some(128))
                    .unwrap()
            };
            let record = f.fetcher.record(&f.part).await.unwrap();
            let uri = f
                .fetcher
                .file_uri(&f.part, &record, PartFile::Data(0))
                .unwrap();
            let (_, key) = crate::hot_tail_cache::parse_s3_uri(&uri).unwrap();
            let mut bytes = f.fetcher.store.get(key).await.unwrap().unwrap();
            bytes[(page.offset + page.bytes - 1) as usize] ^= 1;
            // The signed record and manifest remain unchanged; only the remote
            // object is corrupt. Both page and whole-file paths must reject it.
            f.fetcher.store.put(key, &bytes).await.unwrap();
            let scope = ColumnScope::new(["raw_data".into()].into(), Default::default());
            let error = f
                .fetcher
                .payload_reader(&f.part, 0, &[128], &scope, &ColdBudget::new(64 << 20))
                .await
                .err()
                .expect("tampered page must fail");
            assert!(
                error
                    .downcast_ref::<crate::reader_object_cache::ReaderCacheError>()
                    .is_some_and(|error| matches!(
                        error,
                        crate::reader_object_cache::ReaderCacheError::Integrity(_)
                    )),
                "{error:#}"
            );
            assert!(
                !f.fetcher.cache.object_path(&page.sha256).exists(),
                "corrupt bytes must never enter the page cache"
            );
            assert!(
                f.fetcher
                    .ensure_files(&[(f.part.clone(), PartFile::Data(0))])
                    .await
                    .is_err(),
                "whole-file fallback cannot serve the corrupt object"
            );
        }
    }

    #[tokio::test]
    async fn dictionary_pages_are_independently_authenticated() {
        let narrow = ColumnScope::new(["raw_data".to_string()].into(), Default::default());
        let f = fixture(true, "").await;
        let reader = f
            .fetcher
            .payload_reader(&f.part, 0, &[128], &narrow, &ColdBudget::new(64 << 20))
            .await
            .unwrap();
        assert!(
            !reader.passthrough,
            "a dictionary-backed point read stays sparse"
        );
        let file = reader
            .materialize(f.root.path(), f.fetcher.cache(), 64 << 20)
            .unwrap();
        let batch =
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&file.path).unwrap())
                .unwrap()
                .build()
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
        assert_eq!(
            batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .value(0),
            format!("128 {}", "x".repeat(512))
        );
        let f = fixture(true, "hash").await;
        assert!(f
            .fetcher
            .payload_reader(&f.part, 0, &[128], &narrow, &ColdBudget::new(64 << 20))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_signed_foreign_tenant_record_cannot_supply_payload_pages() {
        let f = fixture(false, "").await;
        let other = "11111111-2222-4333-8444-555555555555";
        let own_keys = crate::parts::format::PartKeys::new(
            TENANT,
            f.part.level,
            f.part.event_hour,
            &f.part.part_id,
        )
        .unwrap();
        let foreign_keys = crate::parts::format::PartKeys::new(
            other,
            f.part.level,
            f.part.event_hour,
            &f.part.part_id,
        )
        .unwrap();
        let signed = f
            .fetcher
            .store
            .get(&own_keys.provenance())
            .await
            .unwrap()
            .unwrap();
        f.fetcher
            .store
            .put(&foreign_keys.provenance(), &signed)
            .await
            .unwrap();
        let cache = ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: f.root.path().join("foreign-cache"),
                max_bytes: 64 << 20,
                query_max_bytes: 64 << 20,
                fetch_concurrency: 2,
                fetch_deadline: std::time::Duration::from_secs(10),
            },
            other,
            "bucket",
            &parts_key_prefix(other).unwrap(),
            Arc::new(StoreObjectSource::local(
                "bucket",
                f.fetcher.store.clone(),
                f.root.path().join("source"),
            )),
        )
        .unwrap();
        let foreign = PartFetcher::new(
            other,
            "bucket",
            f.fetcher.store.clone(),
            signer(7).trusted(),
            cache,
        )
        .unwrap();
        let error = foreign
            .payload_reader(&f.part, 0, &[0], &scope(), &ColdBudget::new(64 << 20))
            .await
            .err()
            .expect("foreign provenance must fail");
        assert!(format!("{error:#}").contains("tenant"), "{error:#}");
    }
}

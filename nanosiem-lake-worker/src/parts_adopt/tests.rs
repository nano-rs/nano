// SPDX-License-Identifier: AGPL-3.0-or-later

//! Phase-4 acceptance tests: fixture adoption of synthetic compacted objects,
//! a double run that is a no-op, crash and real `kill -9` resume, the
//! count-parity checker, and mergeability of adopted with ingest partials.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use arrow_array::{ArrayRef, RecordBatch, StringArray, StructArray, TimestampMicrosecondArray};
use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use parquet::schema::types::ColumnPath;

use super::build::{build_adopted_sidecars, BuildBudgets};
use super::job::{adopted_parts, run_adoption, AdoptHooks, AdoptOptions, AdoptSigner, AdoptStage};
use super::parity::{check_parity, GenerationCounts, ObjectCount};
use super::partials::{merge_partial_dirs, read_all, EntityRangeRow, PartialCaps, PrevalenceRow, RollupRow, RowPartials};
use super::plan::AdoptionPlan;
use super::source::{file_sha256, BucketMirrorSource};
use crate::generation_bundle::GenerationBundleSourceObject;
use crate::parts::format::{
    tokens_file_name, PartKeys, PARTIAL_ENTITY_RANGES_FILE, PARTIAL_PREVALENCE_FILE, PARTIAL_ROLLUP_FILE,
};
use crate::parts::format::LogKeys;
use crate::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use crate::parts::provenance::tests::TENANT;
use crate::parts::provenance::{row_digests, AdoptionAnchor, LocalPartSigner, MerkleBuilder, TenantKeySet};
use crate::parts::sidecar::decode_token_index;
use crate::parts::{Level, DAY_US, HOUR_US};

const BUCKET: &str = "nano-shared-r2-6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
/// 2026-09-21T00:00Z, a day boundary.
const DAY0_US: i64 = 1_790_380_800_000_000 - 5 * DAY_US;

fn ts() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into()))
}

fn strukt(fields: &[&str]) -> DataType {
    DataType::Struct(fields.iter().map(|f| Field::new(*f, DataType::Utf8, true)).collect::<Vec<_>>().into())
}

fn event_schema(extra: bool) -> Arc<Schema> {
    let mut fields = vec![
        Field::new("time", ts(), false),
        Field::new("metadata", strukt(&["uid", "log_source"]), true),
        Field::new("message", DataType::Utf8, true),
        Field::new("src_endpoint", strukt(&["ip", "hostname"]), true),
        Field::new("dst_endpoint", strukt(&["ip"]), true),
        Field::new("user", strukt(&["name"]), true),
        Field::new("device", strukt(&["hostname"]), true),
        Field::new("process", strukt(&["name", "cmd_line"]), true),
    ];
    if extra {
        fields.push(Field::new("severity", DataType::Utf8, true));
    }
    Arc::new(Schema::new(fields))
}

fn struct_array(data_type: &DataType, columns: Vec<Vec<Option<String>>>) -> ArrayRef {
    let DataType::Struct(fields) = data_type else { unreachable!() };
    let arrays = columns.into_iter().map(|c| Arc::new(StringArray::from(c)) as ArrayRef).collect::<Vec<_>>();
    Arc::new(StructArray::new(Fields::from(fields.iter().cloned().collect::<Vec<_>>()), arrays, None))
}

/// `n` synthetic events with times `start_us + i * step_us`, emitted in a
/// scrambled order (compacted objects are not guaranteed sorted).
fn events(schema: &Arc<Schema>, seed: &str, start_us: i64, step_us: i64, n: usize) -> RecordBatch {
    let order = (0..n).map(|i| (i * 7 + 3) % n).collect::<Vec<_>>();
    let s = |f: &dyn Fn(usize) -> Option<String>| order.iter().map(|i| f(*i)).collect::<Vec<_>>();
    let schema_field = |name: &str| schema.field_with_name(name).unwrap().data_type().clone();
    let mut columns: Vec<ArrayRef> = vec![
        Arc::new(
            TimestampMicrosecondArray::from(order.iter().map(|i| start_us + *i as i64 * step_us).collect::<Vec<_>>())
                .with_timezone("+00:00"),
        ),
        struct_array(
            &schema_field("metadata"),
            vec![s(&|i| Some(format!("{seed}-uid-{i:05}"))), s(&|i| Some(if i % 3 == 0 { "Okta" } else { "Sysmon" }.into()))],
        ),
        Arc::new(StringArray::from(s(&|i| {
            Some(if i == 5 { "mimikatz sekurlsa::logonpasswords by ADMIN".into() } else { format!("Failed login {i} from host-{}", i % 4) })
        }))),
        struct_array(
            &schema_field("src_endpoint"),
            vec![s(&|i| Some(format!("10.0.{}.{}", i % 3, i % 7))), s(&|i| Some(format!("WS-{}.corp.local", i % 5)))],
        ),
        struct_array(&schema_field("dst_endpoint"), vec![s(&|i| (i % 2 == 0).then(|| format!("8.8.{}.8", i % 4)))]),
        struct_array(&schema_field("user"), vec![s(&|i| Some(format!("user{}", i % 6)))]),
        struct_array(&schema_field("device"), vec![s(&|i| Some(format!("dev-{}", i % 3)))]),
        struct_array(
            &schema_field("process"),
            vec![s(&|i| Some(format!("proc{}.exe", i % 4))), s(&|i| Some(format!("C:\\bin\\proc{}.exe --flag {i}", i % 4)))],
        ),
    ];
    if schema.field_with_name("severity").is_ok() {
        columns.push(Arc::new(StringArray::from(s(&|i| Some(format!("sev{}", i % 2))))));
    }
    RecordBatch::try_new(Arc::clone(schema), columns).unwrap()
}

struct FixtureObject {
    key: String,
    batch: RecordBatch,
    blooms: bool,
    row_group_rows: usize,
}

fn write_object(root: &Path, object: &FixtureObject) -> GenerationBundleSourceObject {
    let path = root.join(&object.key);
    if !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut props = WriterProperties::builder().set_max_row_group_row_count(Some(object.row_group_rows));
        if object.blooms {
            for column in crate::parts::format::BLOOM_PATHS {
                props = props.set_column_bloom_filter_enabled(ColumnPath::new(column.split('.').map(str::to_owned).collect()), true);
            }
        }
        let mut writer = ArrowWriter::try_new(File::create(&path).unwrap(), object.batch.schema(), Some(props.build())).unwrap();
        writer.write(&object.batch).unwrap();
        writer.close().unwrap();
    }
    let (sha256, size_bytes) = file_sha256(&path).unwrap();
    GenerationBundleSourceObject {
        relative_path: object.key.trim_start_matches("warehouse/nano/events/").to_string(),
        source_uri: format!("s3://{BUCKET}/{}", object.key),
        version_id: "v1".into(),
        size_bytes,
        sha256,
    }
}

fn key(hour: i64, name: &str) -> String {
    format!("warehouse/nano/events/data/event_hour={hour}/{name}.parquet")
}

/// Four hour-partitioned objects over hours H0, H0+1, H0+3 (two objects in
/// H0+3), with and without Parquet blooms, one of them with an extra column.
fn hourly_objects() -> Vec<FixtureObject> {
    let h0 = DAY0_US / HOUR_US;
    let s = event_schema(false);
    let x = event_schema(true);
    vec![
        FixtureObject { key: key(h0, "a"), batch: events(&s, "a", DAY0_US, 9_000_000, 300), blooms: true, row_group_rows: 128 },
        FixtureObject { key: key(h0 + 1, "b"), batch: events(&s, "b", DAY0_US + HOUR_US, 11_000_000, 250), blooms: false, row_group_rows: 100 },
        FixtureObject { key: key(h0 + 3, "c"), batch: events(&x, "c", DAY0_US + 3 * HOUR_US, 7_000_000, 200), blooms: false, row_group_rows: 1_000 },
        FixtureObject { key: key(h0 + 3, "d"), batch: events(&s, "d", DAY0_US + 3 * HOUR_US + 1, 13_000_000, 120), blooms: true, row_group_rows: 64 },
    ]
}

/// tenant1's real generation snapshot id: above 2^53, so every fixture run
/// exercises the decimal-string encoding end to end (plan, record,
/// canonical bytes, owner signature, verification, parity).
const REAL_SNAPSHOT_ID: u64 = 8_632_004_097_115_334_317;

fn anchor() -> AdoptionAnchor {
    AdoptionAnchor {
        generation_id: "lake-8632004097115334317-aaaaaaaaaaaaaaaaaaaaaaaa".into(),
        snapshot_id: REAL_SNAPSHOT_ID,
        bundle_identity_sha256: "1".repeat(64),
        object_stamp_manifest_sha256: "2".repeat(64),
        bundle_manifest_key: "retained-generation/v1/bundles/x/manifest.json".into(),
        bundle_manifest_sha256: "3".repeat(64),
        signer_key_id: "platform-bundle-2026-01".into(),
    }
}

struct Lab {
    _dir: tempfile::TempDir,
    root: PathBuf,
    mirror: PathBuf,
    store: LocalObjectStore,
    plan: AdoptionPlan,
    objects: Vec<FixtureObject>,
}

fn lab_at(root: &Path, objects: Vec<FixtureObject>, t0_us: i64) -> (PathBuf, LocalObjectStore, AdoptionPlan, Vec<FixtureObject>) {
    let mirror = root.join("mirror");
    let stamps = objects.iter().map(|o| write_object(&mirror, o)).collect::<Vec<_>>();
    let store = LocalObjectStore::new(root.join("store")).unwrap();
    let plan = AdoptionPlan::new(TENANT, t0_us, anchor(), stamps, 0, i32::MAX).unwrap();
    (mirror, store, plan, objects)
}

fn new_lab(objects: Vec<FixtureObject>, t0_us: i64) -> Lab {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let (mirror, store, plan, objects) = lab_at(&root, objects, t0_us);
    Lab { _dir: dir, root, mirror, store, plan, objects }
}

/// Plays the platform's `lake-parts:sign` (the job holds no signing key).
struct Owner {
    signer: LocalPartSigner,
    trusted: TenantKeySet,
}

impl Owner {
    fn adopt(&self) -> AdoptSigner<'_> {
        AdoptSigner { signer: &self.signer, trusted: &self.trusted, writer_epoch: 1 }
    }
}

fn owner() -> Owner {
    let signer = crate::parts::provenance::tests::signer(3);
    let trusted = signer.trusted();
    Owner { signer, trusted }
}

fn tiny_options(work: &Path) -> AdoptOptions {
    let mut options = AdoptOptions::new(work, "test");
    options.batch_parts = 2;
    // Tiny bounds force every spill path.
    options.budgets = BuildBudgets {
        batch_rows: 50,
        leaf_run_leaves: 40,
        partial_caps: PartialCaps { rollup_keys: 25, prevalence_keys: 25, entity_keys: 25 },
        ..BuildBudgets::default()
    };
    options
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

const T0_DEFAULT: i64 = DAY0_US + 6 * HOUR_US;

/// The contract root of a batch's rows, by an independent in-memory sort.
fn reference_root(batch: &RecordBatch) -> (String, BTreeMap<i32, (u64, String)>) {
    let digests = row_digests(batch).unwrap();
    let times = batch.column_by_name("time").unwrap().as_any().downcast_ref::<TimestampMicrosecondArray>().unwrap();
    let uids = batch.column_by_name("metadata").unwrap().as_any().downcast_ref::<StructArray>().unwrap().column(0).clone();
    let uids = uids.as_any().downcast_ref::<StringArray>().unwrap();
    let mut leaves = (0..batch.num_rows()).map(|i| (times.value(i), uids.value(i).to_string(), digests[i])).collect::<Vec<_>>();
    leaves.sort();
    let mut total = MerkleBuilder::new();
    let mut hours: BTreeMap<i32, MerkleBuilder> = BTreeMap::new();
    for (time, uid, digest) in &leaves {
        total.push_row(uid, digest);
        hours.entry(crate::parts::event_hour_of(*time)).or_default().push_row(uid, digest);
    }
    (total.root_hex().unwrap(), hours.into_iter().map(|(h, m)| (h, (m.leaves(), m.root_hex().unwrap()))).collect())
}

fn tree_digest(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.insert(path.strip_prefix(root).unwrap().display().to_string(), file_sha256(&path).unwrap().0);
            }
        }
    }
    out
}

#[tokio::test]
async fn adopts_fixture_history_in_place_with_verified_sidecars() {
    let lab = new_lab(hourly_objects(), T0_DEFAULT);
    let mirror_before = tree_digest(&lab.mirror);
    let owner = owner();
    let report = run_adoption(&lab.store, &BucketMirrorSource::new(&lab.mirror), &lab.plan, &owner.adopt(), &tiny_options(&lab.root.join("work")), &now_ms)
        .await
        .unwrap();
    assert_eq!(report.adopted_now, 4);
    assert_eq!(report.adopt_entries, 2);
    assert_eq!(report.rows_adopted, 300 + 250 + 200 + 120);
    // Object c adds `severity`: the log's read schema grew additively.
    assert!(report.schema_entries >= 1);
    assert!(report.objects.iter().all(|o| o.leaf_runs > 1 && o.partial_runs > 0), "tiny budgets must spill");
    // The source is read-only: byte-identical before and after.
    assert_eq!(tree_digest(&lab.mirror), mirror_before);

    let live = load_log(&lab.store, TENANT).await.unwrap();
    assert!(live.schema().unwrap().to_arrow().unwrap().field_with_name("severity").is_ok());
    let adopted = adopted_parts(&lab.store, TENANT, &owner.trusted).await.unwrap();
    assert_eq!(adopted.len(), 4);
    for object in &lab.objects {
        let part = &adopted[&object.key];
        assert_eq!(part.part.level, Level::Hour);
        assert!(!part.part.sorted);
        let record = &part.record;
        let keys = PartKeys::new(TENANT, record.level, record.event_hour, &record.part_id).unwrap();
        // Served in place: the data key is the original object.
        assert_eq!(record.data_key(&keys, 0).unwrap(), object.key);
        assert_eq!(record.files.data.len(), 1);
        assert!(lab.store.get(&keys.data(0)).await.unwrap().is_none(), "no data-00000.parquet copy");
        // Every pinned sidecar exists with its digest.
        for (name, sha, bytes) in record.files.all().into_iter().skip(1) {
            let body = lab.store.get(&keys.file(name)).await.unwrap().unwrap();
            assert_eq!((crate::parts::sha256_hex(&body).as_str(), body.len() as u64), (sha, bytes), "{name}");
        }
        // Token index: one filter per original row group; prunes by token.
        let path = lab.mirror.join(&object.key);
        let row_groups = ParquetRecordBatchReaderBuilder::try_new(File::open(&path).unwrap()).unwrap().metadata().num_row_groups();
        let tokens = decode_token_index(&lab.store.get(&keys.tokens(0)).await.unwrap().unwrap()).unwrap();
        assert_eq!(tokens.len(), row_groups);
        assert_eq!(record.files.data[0].row_groups as usize, row_groups);
        assert_eq!(record.files.data[0].tokens.name, tokens_file_name(0));
        let hunt = vec!["mimikatz".to_string(), "sekurlsa".to_string()];
        assert_eq!(tokens.iter().filter(|g| g.may_contain_all(&hunt)).count(), 1, "exactly the row group holding event 5");
        // Missing Parquet blooms are reported, never papered over.
        let report_row = report.objects.iter().find(|o| o.key == object.key).unwrap();
        assert_eq!(report_row.blooms_missing > 0, !object.blooms);
        // Merkle roots equal an independent sorted computation.
        let (root, hours) = reference_root(&object.batch);
        assert_eq!(record.merkle_root, root);
        assert_eq!(record.hours.len(), 1);
        assert_eq!(hours[&record.event_hour], (record.rows, record.hours[0].merkle_root.clone()));
        // Rollup invariant.
        let local = lab.root.join("check").join(record.part_id.as_str());
        std::fs::create_dir_all(local.join("partials")).unwrap();
        std::fs::write(local.join(PARTIAL_ROLLUP_FILE), lab.store.get(&keys.file(PARTIAL_ROLLUP_FILE)).await.unwrap().unwrap()).unwrap();
        assert_eq!(super::partials::rollup_field0_events(&local.join(PARTIAL_ROLLUP_FILE)).unwrap(), record.rows);
    }
    // Every write is under the tenant's parts root.
    let root_prefix = format!("lake/parts/v1/tenant={TENANT}/");
    assert!(lab.store.list("").await.unwrap().iter().all(|k| k.starts_with(&root_prefix)));
}

#[tokio::test]
async fn a_second_run_is_a_noop() {
    let lab = new_lab(hourly_objects(), T0_DEFAULT);
    let owner = owner();
    let source = BucketMirrorSource::new(&lab.mirror);
    let options = tiny_options(&lab.root.join("work"));
    let first = run_adoption(&lab.store, &source, &lab.plan, &owner.adopt(), &options, &now_ms).await.unwrap();
    let keys_after_first = lab.store.list("").await.unwrap();
    let second = run_adoption(&lab.store, &source, &lab.plan, &owner.adopt(), &options, &now_ms).await.unwrap();
    assert_eq!(second.adopted_now, 0);
    assert_eq!(second.already_adopted, 4);
    assert_eq!(second.adopt_entries + second.schema_entries, 0);
    assert_eq!(second.head_seq, first.head_seq);
    // HEAD is rewritten only on append; nothing else may change.
    assert_eq!(lab.store.list("").await.unwrap(), keys_after_first);
}

struct FailAt(&'static str, usize);

impl AdoptHooks for FailAt {
    fn at(&self, stage: &AdoptStage<'_>) -> Result<()> {
        match (self.0, stage) {
            ("before_append", AdoptStage::BeforeAppend { batch, .. }) if *batch == self.1 => anyhow::bail!("injected crash"),
            _ => Ok(()),
        }
    }
}

#[tokio::test]
async fn a_crash_before_commit_resumes_exactly_once() {
    let lab = new_lab(hourly_objects(), T0_DEFAULT);
    let owner = owner();
    let source = BucketMirrorSource::new(&lab.mirror);
    let mut options = tiny_options(&lab.root.join("work"));
    options.hooks = Some(Arc::new(FailAt("before_append", 1)));
    assert!(run_adoption(&lab.store, &source, &lab.plan, &owner.adopt(), &options, &now_ms).await.is_err());
    assert_eq!(adopted_parts(&lab.store, TENANT, &owner.trusted).await.unwrap().len(), 2);
    options.hooks = None;
    let resumed = run_adoption(&lab.store, &source, &lab.plan, &owner.adopt(), &options, &now_ms).await.unwrap();
    assert_eq!((resumed.already_adopted, resumed.adopted_now), (2, 2));
    assert_parity_ok(&lab, &owner).await;
    // The crashed batch left orphan records that no log entry names.
    let records = lab.store.list("").await.unwrap().into_iter().filter(|k| k.ends_with("provenance.json")).count();
    assert_eq!(records, 6);
}

fn expected_counts(objects: &[FixtureObject]) -> GenerationCounts {
    GenerationCounts {
        snapshot_id: 42,
        objects: objects
            .iter()
            .map(|o| {
                let hour = o.key.split("event_hour=").nth(1).unwrap().split('/').next().unwrap().parse().unwrap();
                (o.key.clone(), ObjectCount { event_hour: hour, rows: o.batch.num_rows() as u64 })
            })
            .collect(),
    }
}

async fn assert_parity_ok(lab: &Lab, owner: &Owner) {
    let counts = expected_counts(&lab.objects);
    let max_hour = counts.objects.values().map(|c| c.event_hour).max().unwrap();
    // T0 is 2 h after the newest object: hours between have no data but the
    // generation's signed max event time reaches T0.
    let report = check_parity(&lab.store, TENANT, &owner.trusted, &counts, lab.plan.t0_us, lab.plan.t0_hour() - 1).await.unwrap();
    assert!(report.ok, "{report:#?}");
    assert_eq!(report.hours_matched, 3);
    assert_eq!(report.hours_in_range, (lab.plan.t0_hour() - (DAY0_US / HOUR_US) as i32) as usize);
    assert_eq!(report.empty_hours, report.hours_in_range - 3);
    assert!(max_hour < lab.plan.t0_hour());
}

#[tokio::test]
async fn parity_checker_passes_and_catches_every_gap() {
    let lab = new_lab(hourly_objects(), T0_DEFAULT);
    let owner = owner();
    run_adoption(&lab.store, &BucketMirrorSource::new(&lab.mirror), &lab.plan, &owner.adopt(), &tiny_options(&lab.root.join("work")), &now_ms)
        .await
        .unwrap();
    assert_parity_ok(&lab, &owner).await;
    let t0 = lab.plan.t0_us;
    let gen_max = lab.plan.t0_hour() - 1;
    let check = |counts: GenerationCounts, t0: i64, gen_max: i32| {
        let store = &lab.store;
        let trusted = owner.trusted.clone();
        async move { check_parity(store, TENANT, &trusted, &counts, t0, gen_max).await.unwrap() }
    };

    // A count differing by one row.
    let mut counts = expected_counts(&lab.objects);
    counts.objects.get_mut(&lab.objects[1].key).unwrap().rows += 1;
    let report = check(counts, t0, gen_max).await;
    assert!(!report.ok);
    assert_eq!(report.mismatches.len(), 1);
    assert_eq!(report.object_row_mismatches, vec![lab.objects[1].key.clone()]);

    // An object the generation holds but nobody adopted.
    let mut counts = expected_counts(&lab.objects);
    counts.objects.insert(key(DAY0_US / HOUR_US + 2, "z"), ObjectCount { event_hour: (DAY0_US / HOUR_US + 2) as i32, rows: 5 });
    let report = check(counts, t0, gen_max).await;
    assert!(!report.ok);
    assert_eq!(report.missing_objects.len(), 1);

    // An adopted object the generation does not hold.
    let mut counts = expected_counts(&lab.objects);
    counts.objects.remove(&lab.objects[0].key);
    let report = check(counts, t0, gen_max).await;
    assert_eq!(report.unexpected_objects, vec![lab.objects[0].key.clone()]);

    // The generation stops 3 h before T0: those hours are a horizon gap.
    let report = check(expected_counts(&lab.objects), t0, gen_max - 3).await;
    assert_eq!(report.horizon_gap_hours.len(), 3);
    assert!(!report.ok);

    // T0 moved earlier than adopted history.
    let report = check(expected_counts(&lab.objects), DAY0_US + 2 * HOUR_US, 0).await;
    assert!(!report.adopted_hours_at_or_after_t0.is_empty());
    assert!(!report.ok);
}

#[tokio::test]
async fn generation_counts_come_from_iceberg_manifests() {
    use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
    use iceberg::spec::{
        DataContentType, DataFileBuilder, DataFileFormat, Literal, NestedField, PrimitiveType, Schema as IcebergSchema,
        Struct, Transform, Type, UnboundPartitionField, UnboundPartitionSpec,
    };
    use iceberg::transaction::{ApplyTransactionAction, Transaction};
    use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation};
    let dir = tempfile::tempdir().unwrap();
    let catalog = MemoryCatalogBuilder::default()
        .load("adopt-test", std::collections::HashMap::from([(MEMORY_CATALOG_WAREHOUSE.to_string(), dir.path().display().to_string())]))
        .await
        .unwrap();
    let namespace = NamespaceIdent::new("nano".into());
    catalog.create_namespace(&namespace, Default::default()).await.unwrap();
    let schema = IcebergSchema::builder()
        .with_fields(vec![Arc::new(NestedField::required(1, "time", Type::Primitive(PrimitiveType::Timestamptz)))])
        .build()
        .unwrap();
    let spec = UnboundPartitionSpec::builder()
        .with_spec_id(0)
        .add_partition_fields([UnboundPartitionField::builder()
            .source_id(1)
            .field_id(1_000)
            .name("event_hour".into())
            .transform(Transform::Hour)
            .build()])
        .unwrap()
        .build();
    let table = catalog
        .create_table(
            &namespace,
            TableCreation::builder()
                .name("events".into())
                .location(format!("{}/events", dir.path().display()))
                .schema(schema)
                .partition_spec(spec)
                .build(),
        )
        .await
        .unwrap();
    let files = [(10, 7_u64, "a"), (10, 3, "b"), (12, 5, "c")]
        .into_iter()
        .map(|(hour, rows, name)| {
            DataFileBuilder::default()
                .content(DataContentType::Data)
                .file_path(format!("s3://{BUCKET}/{}", key(hour, name)))
                .file_format(DataFileFormat::Parquet)
                .partition(Struct::from_iter([Some(Literal::int(hour as i32))]))
                .record_count(rows)
                .file_size_in_bytes(100)
                .partition_spec_id(0)
                .build()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let tx = Transaction::new(&table);
    let table = tx.fast_append().add_data_files(files).apply(tx).unwrap().commit(&catalog).await.unwrap();
    let snapshot = table.metadata().current_snapshot().unwrap().snapshot_id();
    let counts = GenerationCounts::from_iceberg_snapshot(&table, snapshot).await.unwrap();
    assert_eq!(counts.objects.len(), 3);
    assert_eq!(counts.objects[&key(10, "a")], ObjectCount { event_hour: 10, rows: 7 });
    assert_eq!(counts.hours_before(12), BTreeMap::from([(10, 10)]));
    assert_eq!(counts.hours_before(13), BTreeMap::from([(10, 10), (12, 5)]));
}

#[tokio::test]
async fn multi_hour_objects_are_refused_not_adopted_as_day_parts() {
    let s = event_schema(false);
    let day = FixtureObject {
        key: "warehouse/nano/events/data/day/x.parquet".into(),
        batch: events(&s, "x", DAY0_US + 2 * HOUR_US, 20 * 60_000_000, 12),
        blooms: false,
        row_group_rows: 5,
    };
    let lab = new_lab(vec![day], DAY0_US + 2 * DAY_US);
    let owner = owner();
    let error = run_adoption(&lab.store, &BucketMirrorSource::new(&lab.mirror), &lab.plan, &owner.adopt(), &tiny_options(&lab.root.join("work")), &now_ms)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("spans 4 event hours"), "{error}");
    assert!(adopted_parts(&lab.store, TENANT, &owner.trusted).await.unwrap().is_empty());
    // The builder itself still computes exact per-hour roots for such an object.
    let built = build_adopted_sidecars(&lab.mirror.join(&lab.objects[0].key), &lab.root.join("stage"), &BuildBudgets::default()).unwrap();
    assert_eq!(built.level, Level::Day);
    let (root, hours) = reference_root(&lab.objects[0].batch);
    assert_eq!(built.merkle_root, root);
    for hour in &built.hours {
        assert_eq!(hours[&hour.event_hour], (hour.rows, hour.merkle_root.clone()));
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("span.parquet");
    let batch = events(&s, "y", DAY0_US + 23 * HOUR_US, 30 * 60_000_000, 6);
    let mut writer = ArrowWriter::try_new(File::create(&path).unwrap(), batch.schema(), None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    let error = build_adopted_sidecars(&path, &dir.path().join("stage"), &BuildBudgets::default()).unwrap_err();
    assert!(error.to_string().contains("spans event days"), "{error}");
}

#[tokio::test]
async fn t0_is_respected_and_tampered_sources_are_refused() {
    let h0 = DAY0_US / HOUR_US;
    // T0 at H0+2: objects in H0+3 are shadow ingest's; they are skipped
    // WITHOUT being read (their mirror files are deleted to prove it).
    let lab = new_lab(hourly_objects(), (h0 + 2) * HOUR_US);
    let owner = owner();
    for object in &lab.objects[2..] {
        std::fs::remove_file(lab.mirror.join(&object.key)).unwrap();
    }
    let source = BucketMirrorSource::new(&lab.mirror);
    let report = run_adoption(&lab.store, &source, &lab.plan, &owner.adopt(), &tiny_options(&lab.root.join("work")), &now_ms).await.unwrap();
    assert_eq!(report.adopted_now, 2);
    assert_eq!(report.skipped_at_or_after_t0.len(), 2);
    assert_eq!(report.objects.len(), 2, "only pre-T0 objects were built");

    // An object straddling T0 fails closed.
    let s = event_schema(false);
    let straddle = FixtureObject { key: key(h0, "s"), batch: events(&s, "s", DAY0_US + HOUR_US - 60_000_000, 30_000_000, 4), blooms: false, row_group_rows: 10 };
    let lab2 = new_lab(vec![straddle], DAY0_US + HOUR_US);
    assert!(run_adoption(&lab2.store, &BucketMirrorSource::new(&lab2.mirror), &lab2.plan, &owner.adopt(), &tiny_options(&lab2.root.join("work")), &now_ms)
        .await
        .unwrap_err()
        .to_string()
        .contains("straddles T0"));

    // A mirrored object that differs from its signed stamp is refused.
    let lab3 = new_lab(hourly_objects(), T0_DEFAULT);
    let path = lab3.mirror.join(&lab3.objects[0].key);
    let mut bytes = std::fs::read(&path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    std::fs::write(&path, bytes).unwrap();
    let error = run_adoption(&lab3.store, &BucketMirrorSource::new(&lab3.mirror), &lab3.plan, &owner.adopt(), &tiny_options(&lab3.root.join("work")), &now_ms)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("differs from its signed stamp"), "{error}");
}

/// Adopted partials and ingest partials are the same contract rows: merging
/// an adopted part's partials with an ingest part's (keyed merge, 3.2–3.4)
/// equals building them from the union of the rows in one pass.
#[test]
fn adopted_partials_merge_with_ingest_shape() {
    let dir = tempfile::tempdir().unwrap();
    let s = event_schema(false);
    // Overlapping hours, hosts and entities so keys collide across parts.
    let adopted_rows = events(&s, "adopted", DAY0_US, 4_000_000, 400);
    let ingest_rows = events(&s, "ingest", DAY0_US + 600_000_000, 3_000_000, 300);
    let adopted_path = dir.path().join("adopted.parquet");
    let mut writer = ArrowWriter::try_new(File::create(&adopted_path).unwrap(), adopted_rows.schema(), None).unwrap();
    writer.write(&adopted_rows).unwrap();
    writer.close().unwrap();
    let tiny = BuildBudgets {
        batch_rows: 64,
        leaf_run_leaves: 50,
        partial_caps: PartialCaps { rollup_keys: 20, prevalence_keys: 20, entity_keys: 20 },
        ..BuildBudgets::default()
    };
    let built = build_adopted_sidecars(&adopted_path, &dir.path().join("adopted"), &tiny).unwrap();
    assert!(built.partial_runs > 0);

    // The ingest side: an L0 part's partials, built in memory (no spill).
    let ingest_dir = dir.path().join("ingest");
    let mut ingest = RowPartials::new(&ingest_dir, PartialCaps { rollup_keys: usize::MAX, prevalence_keys: usize::MAX, entity_keys: usize::MAX });
    ingest.add_batch(&ingest_rows).unwrap();
    std::fs::create_dir_all(&ingest_dir).unwrap();
    ingest.write(&ingest_dir).unwrap();

    let merged = dir.path().join("merged");
    merge_partial_dirs(&[&built.dir, &ingest_dir], &merged).unwrap();

    let union_dir = dir.path().join("union");
    std::fs::create_dir_all(&union_dir).unwrap();
    let mut union = RowPartials::new(&union_dir, PartialCaps::default());
    union.add_batch(&adopted_rows).unwrap();
    union.add_batch(&ingest_rows).unwrap();
    union.write(&union_dir).unwrap();

    assert_eq!(read_all::<RollupRow>(&merged.join(PARTIAL_ROLLUP_FILE)).unwrap(), read_all::<RollupRow>(&union_dir.join(PARTIAL_ROLLUP_FILE)).unwrap());
    let merged_prevalence = read_all::<PrevalenceRow>(&merged.join(PARTIAL_PREVALENCE_FILE)).unwrap();
    assert!(!merged_prevalence.is_empty());
    assert_eq!(merged_prevalence, read_all::<PrevalenceRow>(&union_dir.join(PARTIAL_PREVALENCE_FILE)).unwrap());
    assert_eq!(
        read_all::<EntityRangeRow>(&merged.join(PARTIAL_ENTITY_RANGES_FILE)).unwrap(),
        read_all::<EntityRangeRow>(&union_dir.join(PARTIAL_ENTITY_RANGES_FILE)).unwrap()
    );
    // The files carry the contract schemas exactly.
    for (name, schema) in [
        (PARTIAL_ROLLUP_FILE, crate::parts::sidecar::rollup_schema()),
        (PARTIAL_PREVALENCE_FILE, crate::parts::sidecar::prevalence_schema()),
        (PARTIAL_ENTITY_RANGES_FILE, crate::parts::sidecar::entity_ranges_schema()),
    ] {
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(built.dir.join(name)).unwrap()).unwrap();
        let fields = reader.schema().fields().iter().map(|f| (f.name().clone(), f.data_type().clone())).collect::<Vec<_>>();
        let want = schema.fields().iter().map(|f| (f.name().clone(), f.data_type().clone())).collect::<Vec<_>>();
        assert_eq!(fields, want, "{name}");
    }
}

// ---------------------------------------------------------------------------
// Real kill -9: a child test process adopts until a chosen stage, parks, and
// is SIGKILLed; the parent resumes and proves exactly-once adoption.
// ---------------------------------------------------------------------------

const KILL9_DIR: &str = "NANO_ADOPT_KILL9_DIR";
const KILL9_STAGE: &str = "NANO_ADOPT_KILL9_STAGE";

struct ParkAt {
    stage: String,
    marker: PathBuf,
}

impl AdoptHooks for ParkAt {
    fn at(&self, stage: &AdoptStage<'_>) -> Result<()> {
        let hit = match (self.stage.as_str(), stage) {
            // Batch 0 committed; batch 1 fully uploaded, not committed.
            ("before_append", AdoptStage::BeforeAppend { batch: 1, .. }) => true,
            // Batch 0 committed; one object of batch 1 uploaded.
            ("part_uploaded", AdoptStage::PartUploaded { .. }) => self.marker.with_extension("seen").exists(),
            ("part_uploaded", AdoptStage::AfterAppend { batch: 0, .. }) => {
                std::fs::write(self.marker.with_extension("seen"), b"").unwrap();
                false
            }
            _ => false,
        };
        if hit {
            std::fs::write(&self.marker, b"parked").unwrap();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "child process of the kill_minus_9_* tests"]
async fn kill9_child() {
    let Ok(root) = std::env::var(KILL9_DIR) else { return };
    let root = PathBuf::from(root);
    let (mirror, store, plan, _) = lab_at(&root, hourly_objects(), T0_DEFAULT);
    let mut options = tiny_options(&root.join("work"));
    options.hooks = Some(Arc::new(ParkAt { stage: std::env::var(KILL9_STAGE).unwrap(), marker: root.join("parked") }));
    run_adoption(&store, &BucketMirrorSource::new(&mirror), &plan, &owner().adopt(), &options, &now_ms).await.unwrap();
    panic!("the child must be killed before it finishes");
}

async fn kill9_at(stage: &str) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    // Parent writes the fixture; the child reuses the same bytes.
    let (mirror, store, plan, objects) = lab_at(&root, hourly_objects(), T0_DEFAULT);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["parts_adopt::tests::kill9_child", "--exact", "--ignored", "--nocapture", "--test-threads=1"])
        .env(KILL9_DIR, &root)
        .env(KILL9_STAGE, stage)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let marker = root.join("parked");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child exited before parking: {status}");
        }
        assert!(std::time::Instant::now() < deadline, "child never parked");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    child.kill().unwrap(); // SIGKILL
    let status = child.wait().unwrap();
    assert!(!status.success());

    let owner = owner();
    let before = adopted_parts(&store, TENANT, &owner.trusted).await.unwrap();
    assert_eq!(before.len(), 2, "batch 0 committed, batch 1 not");
    let report = run_adoption(&store, &BucketMirrorSource::new(&mirror), &plan, &owner.adopt(), &tiny_options(&root.join("work2")), &now_ms)
        .await
        .unwrap();
    assert_eq!((report.already_adopted, report.adopted_now), (2, 2));
    let after = adopted_parts(&store, TENANT, &owner.trusted).await.unwrap();
    assert_eq!(after.len(), 4);
    for (key, part) in &before {
        assert_eq!(after[key].part.part_id, part.part.part_id, "committed parts are never redone");
    }
    // Chain intact, each object exactly once, counts at parity.
    let lab = Lab { _dir: dir, root: root.clone(), mirror, store, plan, objects };
    assert_parity_ok(&lab, &owner).await;
    let log = LogKeys::new(TENANT).unwrap();
    assert!(lab.store.get(&log.entry(0)).await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_minus_9_before_commit_resumes_exactly_once() {
    kill9_at("before_append").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_minus_9_mid_batch_resumes_exactly_once() {
    kill9_at("part_uploaded").await;
}

/// Budget measurement over real tenant1 objects copied read-only (phase 0
/// lab). Run explicitly:
/// `NANO_ADOPT_BENCH_DIR=~/.cache/nan2865-p0/data/r2/... cargo test --release
///  -p nanosiem-lake-worker parts_adopt::tests::bench_real_objects -- --ignored --nocapture`
#[test]
#[ignore = "measurement over local real data"]
fn bench_real_objects() {
    let Ok(dir) = std::env::var("NANO_ADOPT_BENCH_DIR") else { return };
    let limit = std::env::var("NANO_ADOPT_BENCH_LIMIT").ok().and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    let mut files = Vec::new();
    let mut stack = vec![PathBuf::from(dir)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "parquet") {
                files.push(path);
            }
        }
    }
    files.sort();
    files.truncate(limit);
    // Optional: concatenate the inputs into ONE object shaped like a
    // compacted hour (262,144-row groups, identity blooms, zstd 9) to measure
    // the worst single object. Only inputs with the dominant schema are used.
    if let Ok(out) = std::env::var("NANO_ADOPT_BENCH_CONCAT_OUT") {
        let out = PathBuf::from(out);
        if !out.exists() {
            let mut by_schema: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
            for file in &files {
                let schema = ParquetRecordBatchReaderBuilder::try_new(File::open(file).unwrap()).unwrap().schema().clone();
                by_schema.entry(crate::parts::format::schema_fingerprint(&schema).unwrap()).or_default().push(file.clone());
            }
            let inputs = by_schema.into_values().max_by_key(Vec::len).unwrap();
            let schema = ParquetRecordBatchReaderBuilder::try_new(File::open(&inputs[0]).unwrap()).unwrap().schema().clone();
            let mut props = WriterProperties::builder()
                .set_compression(parquet::basic::Compression::ZSTD(parquet::basic::ZstdLevel::try_new(9).unwrap()))
                .set_max_row_group_row_count(Some(262_144));
            for column in crate::parts::format::BLOOM_PATHS {
                let path = ColumnPath::new(column.split('.').map(str::to_owned).collect());
                props = props
                    .set_column_bloom_filter_enabled(path.clone(), true)
                    .set_column_bloom_filter_fpp(path.clone(), 0.0001)
                    .set_column_bloom_filter_ndv(path, 262_144);
            }
            let mut writer = ArrowWriter::try_new(File::create(&out).unwrap(), schema, Some(props.build())).unwrap();
            for input in &inputs {
                for batch in ParquetRecordBatchReaderBuilder::try_new(File::open(input).unwrap()).unwrap().with_batch_size(8_192).build().unwrap() {
                    writer.write(&batch.unwrap()).unwrap();
                }
            }
            writer.close().unwrap();
            eprintln!("concatenated {} of {} inputs into {}", inputs.len(), files.len(), out.display());
            // Measure the build alone in a fresh process.
            return;
        }
        files = vec![out];
    }
    let work = tempfile::Builder::new().prefix("adopt-bench-").tempdir_in(std::env::var("NANO_ADOPT_BENCH_WORK").unwrap_or_else(|_| "/tmp".into())).unwrap();
    let (mut rows, mut bytes) = (0_u64, 0_u64);
    let started = std::time::Instant::now();
    for (index, file) in files.iter().enumerate() {
        let built = build_adopted_sidecars(file, &work.path().join(format!("s{index}")), &BuildBudgets::default()).unwrap();
        rows += built.rows;
        bytes += std::fs::metadata(file).unwrap().len();
        let sidecar_bytes: u64 = built.files().iter().map(|(_, p)| std::fs::metadata(p).unwrap().len()).sum();
        eprintln!(
            "{} rows={} groups={} level={} hours={} blooms_missing={} dups={} leaf_runs={} partial_runs={} sidecar_bytes={}",
            file.file_name().unwrap().to_string_lossy(),
            built.rows,
            built.row_groups,
            built.level.code(),
            built.hours.len(),
            built.blooms_missing.len(),
            built.duplicate_uids,
            built.leaf_runs,
            built.partial_runs,
            sidecar_bytes
        );
        std::fs::remove_dir_all(&built.dir).unwrap();
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let hwm = status.lines().find(|l| l.starts_with("VmHWM")).unwrap();
    eprintln!("objects={} rows={rows} bytes={bytes} wall={:.1}s {hwm}", files.len(), started.elapsed().as_secs_f64());
}

/// A source that, on its first read, lets a SECOND adopter run the whole plan
/// to completion: the outer run's snapshot is then stale when its writer
/// opens. It must re-derive the adopted set and append nothing.
struct RacingSource<'a> {
    inner: BucketMirrorSource,
    store: &'a LocalObjectStore,
    plan: &'a AdoptionPlan,
    owner: &'a Owner,
    work: PathBuf,
    fired: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl super::source::AdoptSource for RacingSource<'_> {
    async fn materialize(&self, object: &super::plan::PlannedObject, work: &Path) -> Result<super::source::Materialized> {
        if !self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let report = Box::pin(run_adoption(self.store, &self.inner, self.plan, &self.owner.adopt(), &tiny_options(&self.work), &now_ms)).await?;
            assert_eq!(report.adopted_now, 4);
        }
        self.inner.materialize(object, work).await
    }
}

#[tokio::test]
async fn a_stale_snapshot_never_adopts_a_key_twice() {
    let lab = new_lab(hourly_objects(), T0_DEFAULT);
    let owner = owner();
    let racing = RacingSource {
        inner: BucketMirrorSource::new(&lab.mirror),
        store: &lab.store,
        plan: &lab.plan,
        owner: &owner,
        work: lab.root.join("work-racer"),
        fired: std::sync::atomic::AtomicBool::new(false),
    };
    let head_before = {
        let report = run_adoption(&lab.store, &racing, &lab.plan, &owner.adopt(), &tiny_options(&lab.root.join("work")), &now_ms)
            .await
            .unwrap();
        assert_eq!(report.adopted_now, 0, "the outer run must see the racer's parts");
        assert_eq!(report.adopt_entries, 0);
        report.head_seq
    };
    assert_eq!(adopted_parts(&lab.store, TENANT, &owner.trusted).await.unwrap().len(), 4);
    assert_eq!(load_log(&lab.store, TENANT).await.unwrap().head().map(|h| h.0), head_before);
    assert_parity_ok(&lab, &owner).await;
}

#[tokio::test]
async fn a_second_generation_is_refused() {
    let lab = new_lab(hourly_objects(), T0_DEFAULT);
    let owner = owner();
    let source = BucketMirrorSource::new(&lab.mirror);
    let mut options = tiny_options(&lab.root.join("work"));
    options.max_objects = Some(2);
    run_adoption(&lab.store, &source, &lab.plan, &owner.adopt(), &options, &now_ms).await.unwrap();
    let mut other = lab.plan.clone();
    other.anchor.generation_id = "lake-43-bbbbbbbbbbbbbbbbbbbbbbbb".into();
    let error = run_adoption(&lab.store, &source, &other, &owner.adopt(), &tiny_options(&lab.root.join("work2")), &now_ms)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("refusing to mix generations"), "{error}");
    assert_eq!(adopted_parts(&lab.store, TENANT, &owner.trusted).await.unwrap().len(), 2);
}

#[test]
fn oversized_row_groups_are_refused_before_decoding() {
    let dir = tempfile::tempdir().unwrap();
    let s = event_schema(false);
    let object = FixtureObject { key: key(1, "big"), batch: events(&s, "big", DAY0_US, 1_000_000, 300), blooms: false, row_group_rows: 300 };
    write_object(dir.path(), &object);
    let path = dir.path().join(&object.key);
    let profile = super::build::object_profile(&path).unwrap();
    assert_eq!((profile.rows, profile.row_groups, profile.max_row_group_rows), (300, 1, 300));
    let budgets = BuildBudgets { max_row_group_rows: 299, ..BuildBudgets::default() };
    let error = build_adopted_sidecars(&path, &dir.path().join("stage"), &budgets).unwrap_err();
    assert!(error.to_string().contains("300-row row group"), "{error}");
}

#[tokio::test]
async fn adoption_round_trips_63_bit_and_max_snapshot_ids() {
    for snapshot in [REAL_SNAPSHOT_ID, u64::MAX] {
        let dir = tempfile::tempdir().unwrap();
        let mirror = dir.path().join("mirror");
        let objects = hourly_objects();
        let stamps = objects.iter().map(|o| write_object(&mirror, o)).collect::<Vec<_>>();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let plan = AdoptionPlan::new(TENANT, T0_DEFAULT, AdoptionAnchor { snapshot_id: snapshot, ..anchor() }, stamps, 0, i32::MAX).unwrap();
        let owner = owner();
        run_adoption(&store, &BucketMirrorSource::new(&mirror), &plan, &owner.adopt(), &tiny_options(&dir.path().join("work")), &now_ms)
            .await
            .unwrap();
        let adopted = adopted_parts(&store, TENANT, &owner.trusted).await.unwrap();
        assert_eq!(adopted.len(), 4);
        for part in adopted.values() {
            let crate::parts::provenance::PartInputs::Adopted { anchor, .. } = &part.record.inputs else { panic!() };
            assert_eq!(anchor.snapshot_id, snapshot);
            let keys = PartKeys::new(TENANT, part.record.level, part.record.event_hour, &part.record.part_id).unwrap();
            let stored = String::from_utf8(store.get(&keys.provenance()).await.unwrap().unwrap()).unwrap();
            assert!(stored.contains(&format!("\"snapshot_id\":\"{snapshot}\"")));
        }
    }
}

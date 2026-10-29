// SPDX-License-Identifier: AGPL-3.0-or-later

use super::super::export::{plan_export_reconciled, ExportFile, ExportHour, ExportState};
use super::*;
use crate::parts::levels::MergePolicy;
use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
use iceberg::spec::{
    DataFileBuilder, NestedField, PrimitiveType, Schema, Struct, StructType, Type,
};
use iceberg::CatalogBuilder;
use tempfile::TempDir;

const TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";
const HOUR_ID: &str = "0000000000001-aaaaaaaaaaaaaaaa";
const DAY_ID: &str = "0000000000002-bbbbbbbbbbbbbbbb";

fn contract(extra: bool) -> SchemaContract {
    let mut nested = vec![Arc::new(NestedField::optional(
        8,
        "uid",
        Type::Primitive(PrimitiveType::String),
    ))];
    if extra {
        nested.push(Arc::new(NestedField::optional(
            9,
            "product",
            Type::Primitive(PrimitiveType::String),
        )));
    }
    SchemaContract {
        version: 1,
        ocsf_version: "1.9.0".to_string(),
        schema: Schema::builder()
            .with_fields([Arc::new(NestedField::optional(
                7,
                "metadata",
                Type::Struct(StructType::new(nested)),
            ))])
            .build()
            .unwrap(),
    }
}

async fn fixture() -> (TempDir, impl Catalog, Table) {
    let dir = TempDir::new().unwrap();
    let catalog = MemoryCatalogBuilder::default()
        .load(
            "export-tests",
            HashMap::from([(
                MEMORY_CATALOG_WAREHOUSE.to_string(),
                dir.path().display().to_string(),
            )]),
        )
        .await
        .unwrap();
    let contract = contract(false);
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
                .location(format!("{}/table", dir.path().display()))
                .schema(contract.schema.clone())
                .properties(contract.properties(TENANT_ID))
                .build(),
        )
        .await
        .unwrap();
    (dir, catalog, table)
}

fn manifest(at: i64, previous: Option<i64>, id: Option<&str>, removed: &[&str]) -> ExportManifest {
    ExportManifest {
        tenant_id: TENANT_ID.to_string(),
        planned_at_ms: at,
        previous_plan_ms: previous,
        add: id
            .map(|id| ExportFile {
                part_id: id.to_string(),
                keys: vec![format!(
                    "{PARTS_ROOT}/tenant={TENANT_ID}/parts/H/2026/01/01/00/{id}/data-00000.parquet"
                )],
                rows: 10,
                bytes: 100,
                min_time_us: 0,
                max_time_us: 1,
            })
            .into_iter()
            .collect(),
        remove_parts: removed.iter().map(|s| s.to_string()).collect(),
        hours: vec![ExportHour {
            event_hour: 0,
            parts: id.map(str::to_string).into_iter().collect(),
        }],
    }
}

fn files(id: &str, prefix: &str) -> BTreeMap<String, Vec<DataFile>> {
    BTreeMap::from([(
        id.to_string(),
        vec![DataFileBuilder::default()
            .content(DataContentType::Data)
            .file_format(DataFileFormat::Parquet)
            .file_path(format!("{prefix}{id}/data-00000.parquet"))
            .partition(Struct::empty())
            .partition_spec_id(0)
            .record_count(10)
            .file_size_in_bytes(100)
            .build()
            .unwrap()],
    )])
}

async fn apply(
    _catalog: &impl Catalog,
    table: &Table,
    manifest: &ExportManifest,
    added: BTreeMap<String, Vec<DataFile>>,
) -> Table {
    let contract = contract(false);
    let (schema, mut requirements, mut updates) = contract.evolution(table).unwrap();
    let (snapshot, reqs) = prepare_snapshot(table, manifest, added, &schema, "s3://fixture/", 100)
        .await
        .unwrap();
    let snapshot_id = snapshot.snapshot_id();
    requirements.extend(reqs);
    updates.extend([
        TableUpdate::AddSnapshot { snapshot },
        TableUpdate::SetSnapshotRef {
            ref_name: MAIN_BRANCH.to_string(),
            reference: SnapshotReference::new(
                snapshot_id,
                SnapshotRetention::branch(None, None, None),
            ),
        },
        TableUpdate::SetProperties {
            updates: HashMap::from([
                (CHECKPOINT.to_string(), manifest.planned_at_ms.to_string()),
                (DIGEST.to_string(), manifest_digest(manifest).unwrap()),
            ]),
        },
    ]);
    for requirement in requirements {
        requirement.check(Some(table.metadata())).unwrap();
    }
    let mut builder = table.metadata().clone().into_builder(None);
    for update in updates {
        builder = update.apply(builder).unwrap();
    }
    Table::builder()
        .metadata(builder.build().unwrap().metadata)
        .identifier(table.identifier().clone())
        .file_io(table.file_io().clone())
        .runtime(iceberg::Runtime::current())
        .metadata_location(table.metadata_location().unwrap())
        .build()
        .unwrap()
}

async fn live_paths(table: &Table) -> Vec<String> {
    let list = table
        .manifest_list_reader(table.metadata().current_snapshot().unwrap())
        .load()
        .await
        .unwrap();
    let mut paths = vec![];
    for descriptor in list.entries().to_vec() {
        let manifest = descriptor.load_manifest(table.file_io()).await.unwrap();
        paths.extend(
            manifest
                .entries()
                .iter()
                .filter(|e| e.is_alive())
                .map(|e| e.file_path().to_string()),
        );
    }
    paths
}

#[tokio::test]
async fn frozen_erasure_cannot_append_or_resurrect_missing_parents() {
    let (_dir, catalog, table) = fixture().await;
    let table = apply(
        &catalog,
        &table,
        &manifest(1, None, Some(HOUR_ID), &[]),
        files(HOUR_ID, "s3://fixture/"),
    )
    .await;
    let mut too_many = files(DAY_ID, "s3://fixture/");
    too_many.get_mut(DAY_ID).unwrap()[0] = DataFileBuilder::default()
        .content(DataContentType::Data)
        .file_format(DataFileFormat::Parquet)
        .file_path(format!("s3://fixture/{DAY_ID}/data-00000.parquet"))
        .partition(Struct::empty())
        .partition_spec_id(0)
        .record_count(11)
        .file_size_in_bytes(100)
        .build()
        .unwrap();
    assert!(prepare_snapshot_inner(
        &table,
        &manifest(2, Some(1), Some(DAY_ID), &[HOUR_ID]),
        too_many,
        &contract(false).schema,
        "s3://fixture/",
        100,
        true
    )
    .await
    .is_err());
    assert!(prepare_snapshot_inner(
        &table,
        &manifest(2, Some(1), None, &[DAY_ID]),
        BTreeMap::new(),
        &contract(false).schema,
        "s3://fixture/",
        100,
        true
    )
    .await
    .is_err());
    assert!(prepare_snapshot_inner(
        &table,
        &manifest(2, Some(1), Some(DAY_ID), &[HOUR_ID]),
        files(DAY_ID, "s3://fixture/"),
        &contract(false).schema,
        "s3://fixture/",
        100,
        true
    )
    .await
    .is_ok());
}
#[tokio::test]
async fn append_retry_day_overwrite_and_full_erasure() {
    let (_dir, catalog, table) = fixture().await;
    let hour = manifest(1, None, Some(HOUR_ID), &[]);
    let table = apply(&catalog, &table, &hour, files(HOUR_ID, "s3://fixture/")).await;
    assert!(checkpoint(&table, &hour).unwrap());
    assert_eq!(live_paths(&table).await.len(), 1);
    let day = manifest(2, Some(1), Some(DAY_ID), &[HOUR_ID]);
    let table = apply(&catalog, &table, &day, files(DAY_ID, "s3://fixture/")).await;
    assert_eq!(
        table
            .metadata()
            .current_snapshot()
            .unwrap()
            .summary()
            .operation,
        Operation::Overwrite
    );
    assert_eq!(
        live_paths(&table).await,
        vec![format!("s3://fixture/{DAY_ID}/data-00000.parquet")]
    );
    assert!(checkpoint(&table, &hour).unwrap());
    let erased = manifest(3, Some(2), None, &[DAY_ID]);
    let table = apply(&catalog, &table, &erased, BTreeMap::new()).await;
    assert!(live_paths(&table).await.is_empty());
    assert_eq!(
        table
            .metadata()
            .current_snapshot()
            .unwrap()
            .summary()
            .operation,
        Operation::Delete
    );
    assert!(checkpoint(&table, &erased).unwrap());
}

#[tokio::test]
async fn shared_day_file_is_not_appended_twice() {
    let (_dir, catalog, table) = fixture().await;
    let first = manifest(1, None, Some(DAY_ID), &[]);
    let table = apply(&catalog, &table, &first, files(DAY_ID, "s3://fixture/")).await;
    let next = manifest(2, Some(1), Some(DAY_ID), &[]);
    let table = apply(&catalog, &table, &next, files(DAY_ID, "s3://fixture/")).await;
    assert_eq!(live_paths(&table).await.len(), 1);
}

#[tokio::test]
async fn additive_nested_schema_keeps_ids_and_breaking_change_is_refused() {
    let (_dir, _catalog, table) = fixture().await;
    let current = table.metadata().current_schema();
    let evolved = contract(true);
    let (schema, _, updates) = evolved.evolution(&table).unwrap();
    assert_eq!(
        schema.field_by_name("metadata.uid").unwrap().id,
        current.field_by_name("metadata.uid").unwrap().id
    );
    assert!(
        schema.field_by_name("metadata.product").unwrap().id > table.metadata().last_column_id()
    );
    assert!(matches!(updates[0], TableUpdate::AddSchema { .. }));
    let mut broken = contract(false);
    broken.schema = Schema::builder()
        .with_fields([Arc::new(NestedField::optional(
            1,
            "metadata",
            Type::Primitive(PrimitiveType::String),
        ))])
        .build()
        .unwrap();
    assert!(broken.evolution(&table).is_err());
    broken.version = 2;
    assert_ne!(
        broken.table_ident("nano", "events").unwrap(),
        table.identifier().clone()
    );
    assert!(schema::name_mapping(&schema).fields()[0].fields().len() == 2);
}

#[tokio::test]
async fn missing_predecessor_and_checkpoint_collision_fail_closed() {
    let (_dir, catalog, table) = fixture().await;
    assert!(checkpoint(&table, &manifest(2, Some(1), Some(DAY_ID), &[])).is_err());
    let hour = manifest(1, None, Some(HOUR_ID), &[]);
    let table = apply(&catalog, &table, &hour, files(HOUR_ID, "s3://fixture/")).await;
    assert!(checkpoint(&table, &manifest(1, None, Some(DAY_ID), &[])).is_err());
    assert!(checkpoint(&table, &manifest(2, None, Some(DAY_ID), &[])).is_err());
}

#[test]
fn tenant_paths_and_prepared_aggregate_are_checked() {
    let input = manifest(1, None, Some(HOUR_ID), &[]);
    assert!(validate_manifest(&input, "other-tenant", 10).is_err());
    validate_manifest(&input, TENANT_ID, 10).unwrap();
    validate_prepared(
        &input,
        &files(HOUR_ID, "s3://fixture/"),
        "s3://fixture/",
        10,
    )
    .unwrap();
    assert!(
        validate_prepared(&input, &files(HOUR_ID, "s3://fixture/"), "s3://other/", 10).is_err()
    );
    assert!(part_id_from_path(
        &format!("s3://fixture/../{HOUR_ID}/data-00000.parquet"),
        "s3://fixture/"
    )
    .is_err());
    let mut wrong = input.clone();
    wrong.add[0].rows += 1;
    assert!(validate_prepared(
        &wrong,
        &files(HOUR_ID, "s3://fixture/"),
        "s3://fixture/",
        10
    )
    .is_err());
}

#[test]
fn erasure_planner_emits_empty_hour_and_pending_survives_pruning() {
    let dir = TempDir::new().unwrap();
    let mut state = ExportState {
        exported: BTreeMap::from([(0, vec![HOUR_ID.to_string()])]),
        last_plan_ms: 1,
    };
    let pending = plan_export_reconciled(&[], &state, 10_000_000, &MergePolicy::default());
    assert_eq!(pending.len(), 1);
    assert!(pending[0].0.parts.is_empty());
    let path = state
        .record_durable_plan(dir.path(), TENANT_ID, &pending, 10_000_000)
        .unwrap();
    let input: ExportManifest = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(input.remove_parts, vec![HOUR_ID]);
    assert_eq!(input.previous_plan_ms, Some(1));
    state
        .prune_acknowledged(dir.path(), 1_000_000_000, 1, 1)
        .unwrap();
    assert!(path.exists());
    assert!(state.exported.is_empty());
    let reloaded = ExportState::load_durable(dir.path()).unwrap();
    assert_eq!(reloaded.last_plan_ms, 10_000_000);
}

#[test]
fn durable_load_recovers_published_manifest_before_state_and_legacy_is_unchanged() {
    let dir = TempDir::new().unwrap();
    let pending_dir = dir.path().join("export/pending");
    std::fs::create_dir_all(&pending_dir).unwrap();
    let hour = manifest(1, None, Some(HOUR_ID), &[]);
    std::fs::write(
        pending_dir.join("0000000000001.json"),
        serde_json::to_vec(&hour).unwrap(),
    )
    .unwrap();
    let state = ExportState::load_durable(dir.path()).unwrap();
    assert_eq!(state.last_plan_ms, 1);
    assert_eq!(state.exported[&0], vec![HOUR_ID]);
    let legacy = ExportState::load(dir.path()).unwrap();
    assert_eq!(legacy.last_plan_ms, 0);
    assert!(
        super::super::export::plan_export(&[], &state, 10_000_000, &MergePolicy::default())
            .is_empty()
    );
    let day = manifest(2, Some(1), Some(DAY_ID), &[HOUR_ID]);
    std::fs::write(
        pending_dir.join("0000000000002.json"),
        serde_json::to_vec(&day).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ExportState::load_durable(dir.path()).unwrap().exported[&0],
        vec![DAY_ID]
    );
    let invalid = manifest(3, Some(1), None, &[DAY_ID]);
    std::fs::write(
        pending_dir.join("0000000000003.json"),
        serde_json::to_vec(&invalid).unwrap(),
    )
    .unwrap();
    assert!(ExportState::load_durable(dir.path()).is_err());
}

#[tokio::test]
async fn snapshot_fences_reject_a_stale_parallel_writer_and_cursor_survives_expiry() {
    let (_dir, catalog, original) = fixture().await;
    let hour = manifest(1, None, Some(HOUR_ID), &[]);
    let (_, stale_requirements) = prepare_snapshot(
        &original,
        &hour,
        files(HOUR_ID, "s3://fixture/"),
        &contract(false).schema,
        "s3://fixture/",
        100,
    )
    .await
    .unwrap();
    let table = apply(&catalog, &original, &hour, files(HOUR_ID, "s3://fixture/")).await;
    assert!(stale_requirements
        .iter()
        .any(|r| r.check(Some(table.metadata())).is_err()));
    let day = manifest(2, Some(1), Some(DAY_ID), &[HOUR_ID]);
    let old_snapshot = table.metadata().current_snapshot_id().unwrap();
    let table = apply(&catalog, &table, &day, files(DAY_ID, "s3://fixture/")).await;
    let metadata = table
        .metadata()
        .clone()
        .into_builder(None)
        .remove_snapshots(&[old_snapshot])
        .build()
        .unwrap()
        .metadata;
    let table = Table::builder()
        .metadata(metadata)
        .identifier(table.identifier().clone())
        .file_io(table.file_io().clone())
        .runtime(iceberg::Runtime::current())
        .metadata_location(table.metadata_location().unwrap())
        .build()
        .unwrap();
    assert!(table.metadata().snapshot_by_id(old_snapshot).is_none());
    assert!(checkpoint(&table, &hour).unwrap());
    assert!(checkpoint(&table, &day).unwrap());
}

#[tokio::test]
async fn additive_fields_never_reuse_retired_ids() {
    let (_dir, _catalog, table) = fixture().await;
    let mut historic_fields = table
        .metadata()
        .current_schema()
        .as_struct()
        .fields()
        .to_vec();
    historic_fields.push(Arc::new(NestedField::optional(
        100,
        "retired",
        Type::Primitive(PrimitiveType::String),
    )));
    let historic = Schema::builder()
        .with_schema_id(1)
        .with_fields(historic_fields)
        .build()
        .unwrap();
    let metadata = table
        .metadata()
        .clone()
        .into_builder(None)
        .add_schema(historic)
        .unwrap()
        .set_current_schema(0)
        .unwrap()
        .build()
        .unwrap()
        .metadata;
    let table = Table::builder()
        .metadata(metadata)
        .identifier(table.identifier().clone())
        .file_io(table.file_io().clone())
        .runtime(iceberg::Runtime::current())
        .metadata_location(table.metadata_location().unwrap())
        .build()
        .unwrap();
    assert_eq!(table.metadata().last_column_id(), 100);
    let (schema, _, _) = contract(true).evolution(&table).unwrap();
    assert!(schema.field_by_name("metadata.product").unwrap().id > 100);
}

#[test]
fn legacy_manifest_wire_format_omits_optional_predecessor() {
    let dir = TempDir::new().unwrap();
    let mut state = ExportState::default();
    let pending = vec![(
        ExportHour {
            event_hour: 0,
            parts: vec![],
        },
        vec![],
    )];
    let path = state
        .record_plan(dir.path(), TENANT_ID, &pending, 1)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(json.get("previous_plan_ms").is_none());
    assert_eq!(ExportState::load(dir.path()).unwrap().last_plan_ms, 1);
}

#[cfg(feature = "enterprise")]
mod hosted_tests;

#[tokio::test]
async fn customer_export_keeps_removal_tombstones_while_lifecycle_omits_them() {
    let (_dir, catalog, table) = fixture().await;
    let table = apply(&catalog, &table, &manifest(1, None, Some(HOUR_ID), &[]), files(HOUR_ID, "s3://fixture/")).await;
    let removal = manifest(2, Some(1), None, &[HOUR_ID]);
    let customer = prepare_snapshot_inner(&table, &removal, BTreeMap::new(), &contract(false).schema, "s3://fixture/", 100, false).await.unwrap().0;
    let lifecycle = prepare_lifecycle_snapshot(&table, &removal, BTreeMap::new(), &contract(false).schema, "s3://fixture/", 100).await.unwrap().0;
    for (snapshot, expected) in [(customer, 1), (lifecycle, 0)] {
        let snapshot = Arc::new(snapshot);
        let mut tombstones = 0;
        for descriptor in table.manifest_list_reader(&snapshot).load().await.unwrap().entries() {
            tombstones += descriptor.load_manifest(table.file_io()).await.unwrap().entries().iter().filter(|e| !e.is_alive()).count();
        }
        assert_eq!(tombstones, expected);
    }
}

#[path = "lifecycle/rest_tests.rs"]
mod lifecycle_rest;

/// NAN-4614: the batch splitter registers each part once (a day part in the
/// batch of its first hour), keeps every removal in the last batch, chains
/// the batches, and is exactly the legacy manifest when one batch fits.
#[test]
fn export_plan_batches_chain_each_part_once_and_removals_last() {
    use super::super::export::{split_manifest, ExportBatchBounds};
    use crate::parts::{format::PartId, levels::Level, part_log::PartRef};
    let part = |i: usize, level: Level, hour: i32| PartRef {
        part_id: PartId::parse(&format!("{:013}-cccccccccccccccc", i)).unwrap(),
        level,
        event_hour: hour,
        event_day: None,
        rows: 1,
        min_time_us: i64::from(hour) * 3_600_000_000,
        max_time_us: i64::from(hour) * 3_600_000_000 + if level == Level::Day { 23 * 3_600_000_000 } else { 0 },
        schema_fingerprint: "0".repeat(64),
        provenance_sha256: "0".repeat(64),
        merkle_root: "0".repeat(64),
        sorted: true,
        data_bytes: 10,
        row_groups: 1,
        data_files: 2,
    };
    // A day part over hours 0..24, then ten hour parts; hour 40 was
    // exported with a part that is now gone (a removal).
    let mut live = vec![part(1, Level::Day, 0)];
    live.extend((0..10).map(|i| part(i + 2, Level::Hour, 24 + i as i32)));
    let gone = "0000000000099-cccccccccccccccc".to_string();
    let state = ExportState { exported: BTreeMap::from([(40, vec![gone.clone()])]), last_plan_ms: 5 };
    let now = 200 * 3_600_000;
    let pending = plan_export_reconciled(&live, &state, now, &MergePolicy::default());
    let whole = {
        let dir = TempDir::new().unwrap();
        let path = state.clone().record_durable_plan(dir.path(), TENANT_ID, &pending, now).unwrap();
        let mut m: ExportManifest = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        (m.planned_at_ms, m.previous_plan_ms) = (0, None);
        m
    };
    let one = state.split_plan(TENANT_ID, &pending, ExportBatchBounds::DEFAULT).unwrap();
    assert_eq!(one, vec![whole.clone()], "one batch is the legacy manifest");
    let batches = state
        .split_plan(TENANT_ID, &pending, ExportBatchBounds { max_files: 4, max_bytes: u64::MAX })
        .unwrap();
    assert!(batches.len() > 1);
    let mut added = batches.iter().flat_map(|b| b.add.iter().map(|p| p.part_id.clone())).collect::<Vec<_>>();
    let total = added.len();
    added.sort();
    added.dedup();
    assert_eq!((total, added.len()), (whole.add.len(), whole.add.len()), "each part exactly once");
    assert!(batches[0].add.iter().any(|p| p.part_id == live[0].part_id.to_string()), "the day part in its first hour's batch");
    let (last, rest) = batches.split_last().unwrap();
    assert!(rest.iter().all(|b| b.remove_parts.is_empty()), "earlier batches are add-only");
    assert_eq!(last.remove_parts, vec![gone]);
    assert_eq!(
        batches.iter().flat_map(|b| b.hours.clone()).collect::<Vec<_>>(),
        whole.hours,
        "every hour once, in order"
    );
    assert_eq!(split_manifest(whole, ExportBatchBounds { max_files: 4, max_bytes: u64::MAX }).unwrap(), batches);
    // Recorded as one chain; a crash after any prefix of it is recoverable.
    let dir = TempDir::new().unwrap();
    let mut recorded = state.clone();
    let paths = recorded.record_durable_batches(dir.path(), batches.clone(), now).unwrap();
    assert_eq!(recorded.last_plan_ms, now + batches.len() as i64 - 1);
    let chain = paths
        .iter()
        .map(|p| serde_json::from_slice::<ExportManifest>(&std::fs::read(p).unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(chain[0].previous_plan_ms, Some(5));
    assert!(chain.windows(2).all(|w| w[1].previous_plan_ms == Some(w[0].planned_at_ms)));
    std::fs::write(dir.path().join("export/state.json"), serde_json::to_vec(&state).unwrap()).unwrap();
    for path in &paths[1..] {
        std::fs::remove_file(path).unwrap();
    }
    let prefix = ExportState::load_durable(dir.path()).unwrap();
    assert_eq!(prefix.last_plan_ms, now, "the durable prefix is recovered");
    let rest = plan_export_reconciled(&live, &prefix, now + 10, &MergePolicy::default());
    assert!(!rest.is_empty() && rest.len() < pending.len(), "only the lost batches replan");
}

/// Apply a lifecycle (agent master) snapshot: removals leave no tombstone.
async fn apply_lifecycle(table: &Table, manifest: &ExportManifest, added: BTreeMap<String, Vec<DataFile>>) -> Table {
    apply_lifecycle_contract(table, manifest, added, &contract(false)).await
}

async fn apply_lifecycle_contract(table: &Table, manifest: &ExportManifest, added: BTreeMap<String, Vec<DataFile>>, contract: &SchemaContract) -> Table {
    let (schema, mut requirements, mut updates) = contract.evolution(table).unwrap();
    let (snapshot, reqs) = prepare_lifecycle_snapshot(table, manifest, added, &schema, "s3://fixture/", 100_000)
        .await
        .unwrap();
    let snapshot_id = snapshot.snapshot_id();
    requirements.extend(reqs);
    updates.extend([
        TableUpdate::AddSnapshot { snapshot },
        TableUpdate::SetSnapshotRef {
            ref_name: MAIN_BRANCH.to_string(),
            reference: SnapshotReference::new(snapshot_id, SnapshotRetention::branch(None, None, None)),
        },
        TableUpdate::SetProperties {
            updates: HashMap::from([
                (CHECKPOINT.to_string(), manifest.planned_at_ms.to_string()),
                (DIGEST.to_string(), manifest_digest(manifest).unwrap()),
            ]),
        },
    ]);
    commit_updates(table, requirements, updates)
}

fn commit_updates(table: &Table, requirements: Vec<TableRequirement>, updates: Vec<TableUpdate>) -> Table {
    for requirement in requirements {
        requirement.check(Some(table.metadata())).unwrap();
    }
    let mut builder = table.metadata().clone().into_builder(None);
    for update in updates {
        builder = update.apply(builder).unwrap();
    }
    Table::builder()
        .metadata(builder.build().unwrap().metadata)
        .identifier(table.identifier().clone())
        .file_io(table.file_io().clone())
        .runtime(iceberg::Runtime::current())
        .metadata_location(table.metadata_location().unwrap())
        .build()
        .unwrap()
}

async fn serving_table(catalog: &impl Catalog, dir: &TempDir, name: &str) -> Table {
    let contract = contract(false);
    let id = contract.table_ident("nano", name).unwrap();
    catalog
        .create_table(
            &id.namespace,
            TableCreation::builder()
                .name(id.name.clone())
                .location(format!("{}/{name}", dir.path().display()))
                .schema(contract.schema.clone())
                .properties(contract.properties(TENANT_ID))
                .build(),
        )
        .await
        .unwrap()
}

fn part_files(ids: &[String], prefix: &str) -> BTreeMap<String, Vec<DataFile>> {
    ids.iter().flat_map(|id| files(id, prefix)).collect()
}

fn add_manifest(at: i64, previous: Option<i64>, ids: &[String], removed: &[String]) -> ExportManifest {
    let mut m = manifest(at, previous, None, &[]);
    m.add = ids
        .iter()
        .map(|id| super::super::export::ExportFile {
            part_id: id.clone(),
            keys: vec![format!("{PARTS_ROOT}/tenant={TENANT_ID}/parts/H/2026/01/01/00/{id}/data-00000.parquet")],
            rows: 10,
            bytes: 100,
            min_time_us: 0,
            max_time_us: 1,
        })
        .collect();
    m.remove_parts = removed.to_vec();
    m.hours = vec![];
    m
}

fn part_ids(range: std::ops::Range<usize>) -> Vec<String> {
    range.map(|i| format!("{:013}-aaaaaaaaaaaaaaaa", i + 1)).collect()
}

/// NAN-4782: a fresh serving epoch is ONE metadata-only commit copying the
/// master's live catalog entries. Proven on real Iceberg metadata:
/// - no part file is opened (the fixture's data files do not exist at all);
/// - the epoch holds exactly the master's live files, with its checkpoint
///   and digest, so the master's next delta continues the epoch's chain;
/// - removals/erasures already reflected in the master never reach it: no
///   entry (live or tombstone, so no bounds) names a removed part;
/// - a retried seed (lost response) is a no-op, and a stale unpublished
///   attempt is replaced, not merged.
#[tokio::test]
async fn a_seeded_epoch_copies_the_masters_live_entries_and_never_a_removed_part() {
    let (dir, catalog, master) = fixture().await;
    let all = part_ids(0..6);
    let master = apply_lifecycle(&master, &add_manifest(1, None, &all[..4], &[]), part_files(&all[..4], "s3://fixture/")).await;
    // Hour of parts 0/1 erased (rewritten as part 4); part 5 newly sealed.
    let stale = live_entries_of(&master, "s3://fixture/", 100_000).await.unwrap();
    let master = apply_lifecycle(
        &master,
        &add_manifest(2, Some(1), &all[4..6], &all[..2]),
        part_files(&all[4..6], "s3://fixture/"),
    )
    .await;
    let entries = live_entries_of(&master, "s3://fixture/", 100_000).await.unwrap();
    let expected = all[2..6].iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(entries.parts, expected);
    assert_eq!(entries.all_parts, expected, "a lifecycle master keeps no tombstone");
    assert_eq!(entries.checkpoint, Some(2));
    let epoch = serving_table(&catalog, &dir, "events_0123456789abcdef0123456789abcdef").await;
    // An interrupted earlier attempt seeded the stale master (parts 0..4).
    let (_, _, requirements, updates) = prepare_seed(&epoch, &stale, &contract(false), "s3://fixture/", 100_000)
        .await
        .unwrap()
        .unwrap();
    let epoch = commit_updates(&epoch, requirements, updates);
    let (snapshot_id, _, requirements, updates) = prepare_seed(&epoch, &entries, &contract(false), "s3://fixture/", 100_000)
        .await
        .unwrap()
        .expect("a stale seed is replaced");
    let epoch = commit_updates(&epoch, requirements, updates);
    assert_eq!(epoch.metadata().current_snapshot_id(), Some(snapshot_id));
    let mut epoch_paths = live_paths(&epoch).await;
    let mut master_paths = live_paths(&master).await;
    epoch_paths.sort();
    master_paths.sort();
    assert_eq!(epoch_paths, master_paths);
    assert_eq!(epoch.metadata().properties().get(CHECKPOINT), master.metadata().properties().get(CHECKPOINT));
    assert_eq!(epoch.metadata().properties().get(DIGEST), master.metadata().properties().get(DIGEST));
    // The current snapshot names nothing removed (no entry, so no bounds).
    let current = live_entries_of(&epoch, "s3://fixture/", 100_000).await.unwrap();
    assert_eq!(current.all_parts, expected);
    // After the privacy expiry the publish path runs, no retained snapshot does.
    let (requirements, updates) = super::hosted::privacy_expiry_updates(&epoch).unwrap();
    let epoch = commit_updates(&epoch, requirements, updates);
    assert_eq!(super::lifecycle::metadata_parts(&epoch, "s3://fixture/", 100_000).await.unwrap(), expected);
    // A lost response: the retry commits nothing.
    assert!(prepare_seed(&epoch, &entries, &contract(false), "s3://fixture/", 100_000).await.unwrap().is_none());
    // The master's next delta continues the epoch's chain.
    let next = add_manifest(3, Some(2), &part_ids(6..7), &[]);
    let previous = epoch.metadata().properties().get(CHECKPOINT).map(|v| v.parse::<i64>().unwrap());
    assert!(!checkpoint_decision(previous, epoch.metadata().properties().get(DIGEST).map(String::as_str), &next).unwrap());
    let epoch = apply_lifecycle(&epoch, &next, part_files(&part_ids(6..7), "s3://fixture/")).await;
    assert_eq!(live_paths(&epoch).await.len(), expected.len() + 1);
    // An epoch ahead of the master is refused.
    assert!(prepare_seed(&epoch, &entries, &contract(false), "s3://fixture/", 100_000).await.is_err());
}

/// NAN-4782 bench: seeding a large epoch (50,000 data files) is a few
/// metadata objects and well under a minute, and reads zero part files
/// (none exist). Before: every live part file was read in full through the
/// export target (3.5-9 h for a hosted tenant). Run with
/// `--ignored --nocapture` for the timing line; the default run uses 5,000 files.
#[tokio::test]
async fn seeding_a_large_epoch_is_metadata_only() {
    seed_bench(5_000).await;
}
#[tokio::test]
#[ignore]
async fn seeding_a_b12_size_epoch_is_metadata_only_bench() {
    seed_bench(50_000).await;
}
async fn seed_bench(n: usize) {
    let (dir, catalog, master) = fixture().await;
    let ids = part_ids(0..n);
    let started = std::time::Instant::now();
    let master = apply_lifecycle(&master, &add_manifest(1, None, &ids, &[]), part_files(&ids, "s3://fixture/")).await;
    let master_ms = started.elapsed().as_millis();
    let started = std::time::Instant::now();
    let entries = live_entries_of(&master, "s3://fixture/", 1_000_000).await.unwrap();
    let epoch = serving_table(&catalog, &dir, "events_0123456789abcdef0123456789abcdef").await;
    let (_, _, requirements, updates) = prepare_seed(&epoch, &entries, &contract(false), "s3://fixture/", 1_000_000)
        .await
        .unwrap()
        .unwrap();
    let epoch = commit_updates(&epoch, requirements, updates);
    let seed_ms = started.elapsed().as_millis();
    let list = epoch.manifest_list_reader(epoch.metadata().current_snapshot().unwrap()).load().await.unwrap();
    let manifests = list.entries().len();
    assert_eq!(manifests, n.div_ceil(SEED_MANIFEST_ENTRIES));
    assert_eq!(live_paths(&epoch).await.len(), n);
    // Metadata objects the seed wrote: its manifests plus one manifest list,
    // each under the only names the platform's metadata PUT accepts.
    let leaf = |path: &str| path.rsplit('/').next().unwrap().to_string();
    let uuid_leaf = |name: &str, suffix: &str| {
        name.strip_prefix("export-")
            .and_then(|rest| rest.strip_suffix(suffix))
            .is_some_and(|id| id.len() == 36 && uuid::Uuid::parse_str(id).is_ok())
    };
    let mut names = list.entries().iter().map(|d| leaf(&d.manifest_path)).collect::<BTreeSet<_>>();
    assert!(names.iter().all(|n| uuid_leaf(n, ".avro")), "{names:?}");
    let list_name = leaf(epoch.metadata().current_snapshot().unwrap().manifest_list());
    assert!(uuid_leaf(&list_name, "-list.avro"), "{list_name}");
    names.insert(list_name);
    let written = names.len();
    assert_eq!(written, manifests + 1);
    eprintln!("NAN-4782 seed bench: files={n} master_commit_ms={master_ms} seed_ms={seed_ms} manifests={manifests} metadata_objects_written={written} part_file_reads=0");
    assert!(seed_ms < 60_000, "seed took {seed_ms} ms");
}

/// A later top-level field is assigned after the master's old nested IDs.
/// Catalog creation instead reassigns breadth-first. ID-bearing Parquet that
/// the master verified must never be published under that different schema.
#[tokio::test]
async fn a_seed_refuses_independently_reassigned_field_ids() {
    let (dir, catalog, master) = fixture().await;
    let arrow = Arc::new(iceberg::arrow::schema_to_arrow_schema(master.metadata().current_schema()).unwrap());
    let arrow_schema::DataType::Struct(children) = arrow.field(0).data_type() else { panic!("metadata struct"); };
    let metadata = arrow_array::StructArray::new(children.clone(),
        vec![Arc::new(arrow_array::StringArray::from(vec!["retained-person"])) as arrow_array::ArrayRef], None);
    let batch = arrow_array::RecordBatch::try_new(arrow.clone(), vec![Arc::new(metadata)]).unwrap();
    let path = dir.path().join("embedded-ids.parquet");
    let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), arrow, None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    let size = std::fs::metadata(&path).unwrap().len();
    let ids = vec![HOUR_ID.to_string(), DAY_ID.to_string()];
    let mut added = part_files(&ids, "s3://fixture/");
    let data_path = added[HOUR_ID][0].file_path().to_string();
    added.insert(HOUR_ID.into(), vec![DataFileBuilder::default()
        .content(DataContentType::Data).file_format(DataFileFormat::Parquet).file_path(data_path)
        .partition(Struct::empty()).partition_spec_id(0).record_count(1).file_size_in_bytes(size).build().unwrap()]);
    let mut first = add_manifest(1, None, &ids, &[]);
    first.add[0].rows = 1;
    first.add[0].bytes = size;
    let master = apply_lifecycle(&master, &first, added).await;
    let mut desired = contract(false);
    let mut fields = desired.schema.as_struct().fields().to_vec();
    fields.push(Arc::new(NestedField::optional(99, "message", Type::Primitive(PrimitiveType::String))));
    desired.schema = Schema::builder().with_fields(fields).build().unwrap();
    let master = apply_lifecycle_contract(&master, &add_manifest(2, Some(1), &[], &ids[1..]), BTreeMap::new(), &desired).await;
    let (reqs, updates) = super::hosted::privacy_expiry_updates(&master).unwrap();
    let master = commit_updates(&master, reqs, updates);
    super::customer::footer(&path, master.metadata().current_schema(), 1).unwrap();
    let entries = live_entries_of(&master, "s3://fixture/", 100_000).await.unwrap();
    // This is the old fresh-table creation: its IDs are silently reassigned.
    let legacy_id = desired.table_ident("nano", "legacy_ids").unwrap();
    let legacy = catalog.create_table(&legacy_id.namespace, TableCreation::builder()
        .name(legacy_id.name).location(format!("{}/legacy-ids", dir.path().display()))
        .schema(desired.schema.clone()).properties(desired.properties(TENANT_ID)).build()).await.unwrap();
    assert_ne!(legacy.metadata().current_schema().field_id_by_name("metadata.uid"),
        master.metadata().current_schema().field_id_by_name("metadata.uid"));
    match prepare_seed(&legacy, &entries, &desired, "s3://fixture/", 100_000).await {
        Err(error) => assert!(format!("{error:#}").contains("field IDs differ from the master"), "{error:#}"),
        Ok(Some((_, _, reqs, updates))) => {
            let seeded = commit_updates(&legacy, reqs, updates);
            assert_eq!(seeded.metadata().current_schema().field_id_by_name("metadata.uid"),
                master.metadata().current_schema().field_id_by_name("metadata.uid"),
                "a metadata seed must refuse incompatible IDs before publication");
            super::customer::footer(&path, seeded.metadata().current_schema(), 1).unwrap();
        }
        Ok(None) => panic!("an empty epoch cannot already hold the master"),
    }
    // The new creation path uses an additive prefix, then installs the exact
    // source IDs with the snapshot. No part is opened by the seed itself.
    let prefix = seed_creation_schema(&entries, &desired).unwrap();
    let id = desired.table_ident("nano", "preserved_ids").unwrap();
    let fresh = catalog.create_table(&id.namespace, TableCreation::builder()
        .name(id.name).location(format!("{}/preserved-ids", dir.path().display()))
        .schema(prefix).properties(desired.properties(TENANT_ID)).build()).await.unwrap();
    let (_, _, reqs, updates) = prepare_seed(&fresh, &entries, &desired, "s3://fixture/", 100_000).await.unwrap().unwrap();
    let fresh = commit_updates(&fresh, reqs, updates);
    assert_eq!(fresh.metadata().current_schema().as_struct(), master.metadata().current_schema().as_struct());
    super::customer::footer(&path, fresh.metadata().current_schema(), 1).unwrap();
    assert_eq!(live_entries_of(&fresh, "s3://fixture/", 100_000).await.unwrap().parts, BTreeSet::from([HOUR_ID.into()]));
    assert!(prepare_seed(&fresh, &entries, &desired, "s3://fixture/", 100_000).await.unwrap().is_none());
}

/// Required columns, list elements and map values keep their IDs even when
/// fields were added in a different order from a fresh breadth-first schema.
#[tokio::test]
async fn a_seed_preserves_field_ids_inside_lists_and_maps() {
    use iceberg::spec::{ListType, MapType};
    let initial = canonical_seed_schema(&Schema::builder().with_fields([
        Arc::new(NestedField::required(1, "time", Type::Primitive(PrimitiveType::Timestamp))),
        Arc::new(NestedField::optional(2, "nested", Type::Struct(StructType::new(vec![
            Arc::new(NestedField::optional(3, "old", Type::Primitive(PrimitiveType::String))),
        ])))),
        Arc::new(NestedField::optional(4, "values", Type::List(ListType::new(Arc::new(NestedField::list_element(
            5, Type::Struct(StructType::new(vec![Arc::new(NestedField::optional(6, "old", Type::Primitive(PrimitiveType::String)))])), false,
        )))))),
        Arc::new(NestedField::optional(7, "labels", Type::Map(MapType::new(
            Arc::new(NestedField::map_key_element(8, Type::Primitive(PrimitiveType::String))),
            Arc::new(NestedField::map_value_element(9, Type::Struct(StructType::new(vec![
                Arc::new(NestedField::optional(10, "old", Type::Primitive(PrimitiveType::String))),
            ])), false)),
        )))),
    ]).build().unwrap()).unwrap();
    let next = initial.highest_field_id() + 1;
    let mut fields = initial.as_struct().fields().to_vec();
    for (name, id) in [("nested", next + 1), ("values", next + 2), ("labels", next + 3)] {
        let position = fields.iter().position(|field| field.name == name).unwrap();
        let mut field = fields[position].as_ref().clone();
        let append = |ty: &Type| {
            let Type::Struct(value) = ty else { panic!("struct"); };
            let mut children = value.fields().to_vec();
            children.push(Arc::new(NestedField::optional(id, "new", Type::Primitive(PrimitiveType::String))));
            Type::Struct(StructType::new(children))
        };
        field.field_type = Box::new(match field.field_type.as_ref() {
            Type::Struct(_) => append(&field.field_type),
            Type::List(list) => {
                let mut element = list.element_field.as_ref().clone();
                element.field_type = Box::new(append(&element.field_type));
                Type::List(ListType::new(Arc::new(element)))
            }
            Type::Map(map) => {
                let mut value = map.value_field.as_ref().clone();
                value.field_type = Box::new(append(&value.field_type));
                Type::Map(MapType::new(map.key_field.clone(), Arc::new(value)))
            }
            _ => unreachable!(),
        });
        fields[position] = Arc::new(field);
    }
    fields.push(Arc::new(NestedField::optional(next, "new_top", Type::Primitive(PrimitiveType::String))));
    let source = Schema::builder().with_fields(fields).build().unwrap();
    let mut contract = contract(false);
    contract.schema = source.clone();
    let entries = LiveEntries { schema: Some(Arc::new(source.clone())), checkpoint: Some(1), digest: Some("a".repeat(64)), ..Default::default() };
    let prefix = seed_creation_schema(&entries, &contract).unwrap();
    assert_eq!(prefix.as_struct(), initial.as_struct());
    assert!(prefix.field_by_name("time").unwrap().required);
    let (dir, catalog, _) = fixture().await;
    let id = contract.table_ident("nano", "container_ids").unwrap();
    let epoch = catalog.create_table(&id.namespace, TableCreation::builder().name(id.name)
        .location(format!("{}/container-ids", dir.path().display())).schema(prefix.clone())
        .properties(contract.properties(TENANT_ID)).build()).await.unwrap();
    let (_, _, reqs, updates) = prepare_seed(&epoch, &entries, &contract, "s3://fixture/", 100_000).await.unwrap().unwrap();
    let epoch = commit_updates(&epoch, reqs, updates);
    assert_eq!(epoch.metadata().current_schema().as_struct(), source.as_struct());
    assert_eq!(epoch.metadata().snapshots().len(), 1, "schema and snapshot land together");

    // Matching checkpoint/digest/files is not a no-op when the current
    // snapshot still has an older, compatible schema.
    let id = contract.table_ident("nano", "older_schema").unwrap();
    let older = catalog.create_table(&id.namespace, TableCreation::builder().name(id.name)
        .location(format!("{}/older-schema", dir.path().display())).schema(prefix.clone())
        .properties(contract.properties(TENANT_ID)).build()).await.unwrap();
    let old_entries = LiveEntries { schema: Some(Arc::new(prefix)), ..entries.clone() };
    let (_, _, reqs, updates) = prepare_seed(&older, &old_entries, &contract, "s3://fixture/", 100_000).await.unwrap().unwrap();
    let older = commit_updates(&older, reqs, updates);
    let (_, _, reqs, updates) = prepare_seed(&older, &entries, &contract, "s3://fixture/", 100_000).await.unwrap()
        .expect("a matching checkpoint must still install the master's schema");
    let repaired = commit_updates(&older, reqs, updates);
    assert_eq!(repaired.metadata().current_schema().as_struct(), source.as_struct());
    assert!(prepare_seed(&repaired, &entries, &contract, "s3://fixture/", 100_000).await.unwrap().is_none());
}

/// A later top-level addition can temporarily cancel an earlier nested
/// reassignment. Removing that top-level field must reveal another cutoff.
#[tokio::test]
async fn a_seed_finds_the_canonical_prefix_after_multiple_schema_changes() {
    let initial = Schema::builder().with_fields([
        Arc::new(NestedField::optional(1, "a", Type::Struct(StructType::new(vec![
            Arc::new(NestedField::optional(3, "old", Type::Primitive(PrimitiveType::String))),
        ])))),
        Arc::new(NestedField::optional(2, "b", Type::Struct(StructType::new(vec![
            Arc::new(NestedField::optional(4, "old", Type::Primitive(PrimitiveType::String))),
        ])))),
    ]).build().unwrap();
    let (dir, catalog, _) = fixture().await;
    let mut desired = contract(false);
    desired.schema = initial.clone();
    let id = desired.table_ident("nano", "history_master").unwrap();
    let master = catalog.create_table(&id.namespace, TableCreation::builder().name(id.name)
        .location(format!("{}/history-master", dir.path().display())).schema(initial.clone())
        .properties(desired.properties(TENANT_ID)).build()).await.unwrap();
    let original = master.clone();
    let mut fields = initial.as_struct().fields().to_vec();
    let mut a = fields[0].as_ref().clone();
    let Type::Struct(children) = a.field_type.as_ref() else { panic!("struct"); };
    let mut children = children.fields().to_vec();
    children.push(Arc::new(NestedField::optional(99, "new", Type::Primitive(PrimitiveType::String))));
    a.field_type = Box::new(Type::Struct(StructType::new(children)));
    fields[0] = Arc::new(a);
    desired.schema = Schema::builder().with_fields(fields.clone()).build().unwrap();
    let (_, reqs, updates) = desired.evolution(&master).unwrap();
    let master = commit_updates(&master, reqs, updates);
    fields.push(Arc::new(NestedField::optional(100, "c", Type::Primitive(PrimitiveType::String))));
    desired.schema = Schema::builder().with_fields(fields).build().unwrap();
    let (_, reqs, updates) = desired.evolution(&master).unwrap();
    let master = commit_updates(&master, reqs, updates);
    let source = master.metadata().current_schema().clone();
    assert_eq!(source.field_id_by_name("a.new"), Some(5));
    assert_eq!(source.field_id_by_name("c"), Some(6));
    let entries = LiveEntries { schema: Some(source.clone()), checkpoint: Some(1), digest: Some("a".repeat(64)), ..Default::default() };
    let prefix = seed_creation_schema(&entries, &desired).unwrap();
    assert_eq!(prefix.as_struct(), initial.as_struct());
    let id = desired.table_ident("nano", "history_epoch").unwrap();
    let epoch = catalog.create_table(&id.namespace, TableCreation::builder().name(id.name)
        .location(format!("{}/history-epoch", dir.path().display())).schema(prefix)
        .properties(desired.properties(TENANT_ID)).build()).await.unwrap();
    let (_, _, reqs, updates) = prepare_seed(&epoch, &entries, &desired, "s3://fixture/", 100_000).await.unwrap().unwrap();
    let epoch = commit_updates(&epoch, reqs, updates);
    assert_eq!(epoch.metadata().current_schema().as_struct(), source.as_struct());

    // An optional addition can contain required descendants. A cutoff may
    // split that group even after its retained IDs become canonical.
    let mut fields = initial.as_struct().fields().to_vec();
    let mut b = fields[1].as_ref().clone();
    let Type::Struct(children) = b.field_type.as_ref() else { panic!("struct"); };
    let mut children = children.fields().to_vec();
    children.push(Arc::new(NestedField::optional(99, "new", Type::Struct(StructType::new(vec![
        Arc::new(NestedField::required(100, "child", Type::Struct(StructType::new(vec![
            Arc::new(NestedField::required(101, "leaf", Type::Primitive(PrimitiveType::String))),
        ])))),
        Arc::new(NestedField::required(102, "sibling", Type::Primitive(PrimitiveType::String))),
    ])))));
    b.field_type = Box::new(Type::Struct(StructType::new(children)));
    fields[1] = Arc::new(b);
    desired.schema = Schema::builder().with_fields(fields).build().unwrap();
    let (_, reqs, updates) = desired.evolution(&original).unwrap();
    let master = commit_updates(&original, reqs, updates);
    let source = master.metadata().current_schema().clone();
    assert_eq!(source.field_id_by_name("b.new.child.leaf"), Some(7));
    assert_eq!(source.field_id_by_name("b.new.sibling"), Some(8));
    let entries = LiveEntries { schema: Some(source.clone()), ..entries };
    let prefix = seed_creation_schema(&entries, &desired).unwrap();
    assert_eq!(prefix.as_struct(), initial.as_struct());
    let id = desired.table_ident("nano", "required_epoch").unwrap();
    let epoch = catalog.create_table(&id.namespace, TableCreation::builder().name(id.name)
        .location(format!("{}/required-epoch", dir.path().display())).schema(prefix)
        .properties(desired.properties(TENANT_ID)).build()).await.unwrap();
    let (_, _, reqs, updates) = prepare_seed(&epoch, &entries, &desired, "s3://fixture/", 100_000).await.unwrap().unwrap();
    let epoch = commit_updates(&epoch, reqs, updates);
    assert_eq!(epoch.metadata().current_schema().as_struct(), source.as_struct());

    // Map keys are immutable and must remain complete. A cutoff inside a
    // newly added complex key excludes its whole optional map instead.
    let mut fields = initial.as_struct().fields().to_vec();
    let mut b = fields[1].as_ref().clone();
    let Type::Struct(children) = b.field_type.as_ref() else { panic!("struct"); };
    let mut children = children.fields().to_vec();
    children.push(Arc::new(NestedField::optional(99, "map", Type::Map(iceberg::spec::MapType::new(
        Arc::new(NestedField::map_key_element(100, Type::Struct(StructType::new(vec![
            Arc::new(NestedField::required(101, "child", Type::Struct(StructType::new(vec![
                Arc::new(NestedField::required(102, "leaf", Type::Primitive(PrimitiveType::String))),
            ])))),
            Arc::new(NestedField::required(103, "sibling", Type::Primitive(PrimitiveType::String))),
        ])))),
        Arc::new(NestedField::map_value_element(104, Type::Primitive(PrimitiveType::String), false)),
    )))));
    b.field_type = Box::new(Type::Struct(StructType::new(children)));
    fields[1] = Arc::new(b);
    desired.schema = Schema::builder().with_fields(fields).build().unwrap();
    let (_, reqs, updates) = desired.evolution(&original).unwrap();
    let master = commit_updates(&original, reqs, updates);
    let source = master.metadata().current_schema().clone();
    assert_eq!(source.field_id_by_name("b.map.key.sibling"), Some(9));
    assert_eq!(source.field_id_by_name("b.map.value"), Some(10));
    let entries = LiveEntries { schema: Some(source.clone()), ..entries };
    let prefix = seed_creation_schema(&entries, &desired).unwrap();
    assert_eq!(prefix.as_struct(), initial.as_struct());
    let id = desired.table_ident("nano", "map_key_epoch").unwrap();
    let epoch = catalog.create_table(&id.namespace, TableCreation::builder().name(id.name)
        .location(format!("{}/map-key-epoch", dir.path().display())).schema(prefix)
        .properties(desired.properties(TENANT_ID)).build()).await.unwrap();
    let (_, _, reqs, updates) = prepare_seed(&epoch, &entries, &desired, "s3://fixture/", 100_000).await.unwrap().unwrap();
    let epoch = commit_updates(&epoch, reqs, updates);
    assert_eq!(epoch.metadata().current_schema().as_struct(), source.as_struct());
}

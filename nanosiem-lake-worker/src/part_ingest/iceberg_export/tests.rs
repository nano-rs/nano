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

// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4612: the A/B data-volume roll (FP-T91) wipes `/var/lib/nano-cell`,
//! including the tenant's catalog custody dir (`state/<t>/agent-catalog/custody`).
//! The large tenant's first GC pass afterwards failed every Worker `prepare` with a bare
//! `No such file or directory (os error 2)`: the guard read the absent
//! `planned-index-ready` marker, and the executor reported it as
//! `worker_unavailable`. Production constructors only: `new_guarded` via
//! `fixture`, `TenantCatalog::new`, and the `Seams` prepare/retire path.
use super::*;
use crate::lake_part_gc::{CatalogCustodyHeld, LakePartDeletePermit};
use crate::part_ingest::iceberg_export::lifecycle::{test_support::Basin, TenantCatalog};
use crate::parts::part_log::{LocalObjectStore, PartLogWriter};

fn permit() -> LakePartDeletePermit {
    let request = crate::lake_part_gc::request::tests::superseded();
    let now = chrono::Utc::now();
    LakePartDeletePermit {
        permit_id: request.permit_id().unwrap(),
        owner_authorization: crate::lake_part_gc::delete_control::DeleteOwnerAuthorization {
            schema_version: 1,
            signer_key_id: "fixture-owner".into(),
            issued_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
            identity_sha256: request.digest().unwrap(),
            signature_base64: "fixture-signature".into(),
        },
        request,
    }
}

fn seams(f: &Fixture) -> Seams {
    Seams {
        shared: f.gc.shared.clone(),
        fence: InventoryFence::capture(&f.gc.shared).unwrap(),
        receipted: std::sync::Mutex::new(vec![]),
        catalog_pass: Default::default(),
    }
}

#[tokio::test]
async fn wiped_custody_volume_fails_closed_with_a_custody_reason_until_a_reconciled_sync() {
    let f = fixture(1, Duration::ZERO, 200).await;
    let local = tempfile::tempdir().unwrap();
    let source = Arc::new(LocalObjectStore::new(local.path().join("parts")).unwrap());
    let writer = PartLogWriter::open(source.as_ref(), TENANT_UUID, 1,
        &crate::part_ingest::ingest::seed_schema(), chrono::Utc::now().timestamp_millis()).await.unwrap();
    drop(writer);
    let backend = Basin::new(TENANT_UUID, local.path().into(), source, fixture_keys()).await;
    let custody = local.path().join("state/agent-catalog/custody");
    let policy = crate::parts::levels::MergePolicy::default();
    let part = crate::lake_part_gc::request::tests::PART;

    // Before the roll: the agent table has committed exports (NAN-4662: a
    // table that never committed would reference nothing and need no fence)
    // and custody on the old volume is reconciled.
    commit_history(&backend).await;
    let catalog = TenantCatalog::new(TENANT_UUID, custody.clone(), backend.clone()).unwrap();
    catalog.sync_parts(TENANT_UUID, vec![], chrono::Utc::now().timestamp_millis(), &policy).await.unwrap();
    drop(catalog);
    // The roll: the data-wipe init container empties the volume.
    std::fs::remove_dir_all(local.path().join("state")).unwrap();

    // After the roll: the cell attaches custody on the empty volume.
    let catalog = Arc::new(TenantCatalog::new(TENANT_UUID, custody.clone(), backend.clone()).unwrap());
    f.gc.attach_catalog(catalog.clone()).unwrap();
    let checks = backend.checks.load(Ordering::SeqCst);
    let permit = permit();
    for retire in [false, true] {
        let seams = seams(&f);
        let error = if retire { seams.retire(&permit).await.unwrap_err() } else { seams.prepare(&permit).await.unwrap_err() };
        let text = format!("{error:#}");
        assert!(error.downcast_ref::<CatalogCustodyHeld>().is_some(), "typed custody refusal: {text}");
        assert!(text.contains("planned index not initialized"), "{text}");
        assert!(!text.contains("os error"), "no bare local IO error: {text}");
        assert!(!text.contains("retention authority"), "the Worker must not be called: {text}");
    }
    assert!(catalog.require_removed(TENANT_UUID, part).is_err(), "no receipt minted from a wiped index");
    assert_eq!(backend.checks.load(Ordering::SeqCst), checks, "an empty local index is never trusted");

    // The writer's next reconciled sync rebuilds the index from the catalog;
    // only then does the guard pass and the request reach the Worker.
    catalog.sync_parts(TENANT_UUID, vec![], chrono::Utc::now().timestamp_millis(), &policy).await.unwrap();
    let error = seams(&f).prepare(&permit).await.unwrap_err();
    assert!(error.downcast_ref::<CatalogCustodyHeld>().is_none(), "{error:#}");
    assert!(error.to_string().contains("retention authority"), "{error:#}");
    catalog.require_removed(TENANT_UUID, part).unwrap();
}

/// A committed export (an empty delta: the fixture source has no sealed
/// part) through the production lifecycle snapshot builder.
async fn commit_history(backend: &Basin) {
    use crate::part_ingest::export::IcebergCommitter;
    let manifest = crate::part_ingest::export::ExportManifest {
        tenant_id: TENANT_UUID.into(), planned_at_ms: 1, previous_plan_ms: None,
        add: vec![], remove_parts: vec![], hours: vec![],
    };
    backend.commit(&manifest).await.unwrap();
    assert_eq!(backend.snapshot_count().await, 1);
}

async fn basin(local: &std::path::Path) -> Arc<Basin> {
    let source = Arc::new(LocalObjectStore::new(local.join("parts")).unwrap());
    let writer = PartLogWriter::open(source.as_ref(), TENANT_UUID, 1,
        &crate::part_ingest::ingest::seed_schema(), chrono::Utc::now().timestamp_millis()).await.unwrap();
    drop(writer);
    Basin::new(TENANT_UUID, local.into(), source, fixture_keys()).await
}

/// NAN-4662 (the large tenant): the agent catalog's table never committed (create was
/// refused all day), so no marker was ever written. Nothing can reference
/// the part: the Worker is reached on the first pass, with one commit-state
/// read and no reader drain or catalog inspection.
#[tokio::test]
async fn a_catalog_that_never_committed_never_blocks_gc() {
    let f = fixture(1, Duration::ZERO, 200).await;
    let local = tempfile::tempdir().unwrap();
    let backend = basin(local.path()).await;
    let custody = local.path().join("state/agent-catalog/custody");
    let catalog = Arc::new(TenantCatalog::new(TENANT_UUID, custody.clone(), backend.clone()).unwrap());
    f.gc.attach_catalog(catalog.clone()).unwrap();
    assert!(!custody.join("planned-index-ready").exists());
    let permit = permit();
    let pass = seams(&f);
    for retire in [false, true] {
        let error = if retire { pass.retire(&permit).await.unwrap_err() } else { pass.prepare(&permit).await.unwrap_err() };
        assert!(error.downcast_ref::<CatalogCustodyHeld>().is_none(), "{error:#}");
        assert!(error.to_string().contains("retention authority"), "the Worker is reached: {error:#}");
    }
    catalog.require_removed(TENANT_UUID, crate::lake_part_gc::request::tests::PART).unwrap();
    assert_eq!(backend.commit_state_reads.load(Ordering::SeqCst), 1);
    assert_eq!(backend.commits.load(Ordering::SeqCst), 0);
    assert!(backend.trace.lock().unwrap().is_empty(), "{:?}", backend.trace.lock().unwrap());

    // Unreachable catalog, nothing proven: the NAN-4612 fence holds.
    let local = tempfile::tempdir().unwrap();
    let f = fixture(1, Duration::ZERO, 200).await;
    let backend = basin(local.path()).await;
    backend.fail_commit_state.store(true, Ordering::SeqCst);
    let catalog = Arc::new(TenantCatalog::new(TENANT_UUID, local.path().join("custody"), backend.clone()).unwrap());
    f.gc.attach_catalog(catalog.clone()).unwrap();
    let error = seams(&f).prepare(&permit).await.unwrap_err();
    assert!(error.downcast_ref::<CatalogCustodyHeld>().is_some_and(|held| !held.part_pinned), "{error:#}");
    assert!(format!("{error:#}").contains("planned index not initialized"), "{error:#}");
    assert!(catalog.require_removed(TENANT_UUID, crate::lake_part_gc::request::tests::PART).is_err());
}

/// A corrupt / foreign marker is not "not initialized": it stays a refusal.
#[tokio::test]
async fn foreign_planned_index_marker_is_refused() {
    let f = fixture(1, Duration::ZERO, 200).await;
    let local = tempfile::tempdir().unwrap();
    let source = Arc::new(LocalObjectStore::new(local.path().join("parts")).unwrap());
    let writer = PartLogWriter::open(source.as_ref(), TENANT_UUID, 1,
        &crate::part_ingest::ingest::seed_schema(), chrono::Utc::now().timestamp_millis()).await.unwrap();
    drop(writer);
    let backend = Basin::new(TENANT_UUID, local.path().into(), source, fixture_keys()).await;
    let custody = local.path().join("custody");
    std::fs::create_dir_all(&custody).unwrap();
    std::fs::write(custody.join("planned-index-ready"), b"3867bbbb-0000-4000-8000-000000000002").unwrap();
    let catalog = Arc::new(TenantCatalog::new(TENANT_UUID, custody, backend).unwrap());
    f.gc.attach_catalog(catalog.clone()).unwrap();
    let error = seams(&f).prepare(&permit()).await.unwrap_err();
    assert!(error.downcast_ref::<CatalogCustodyHeld>().is_some(), "{error:#}");
    assert!(format!("{error:#}").contains("another tenant"), "{error:#}");
    assert!(catalog.require_removed(TENANT_UUID, crate::lake_part_gc::request::tests::PART).is_err());
}

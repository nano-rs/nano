// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4612: the A/B data-volume roll (FP-T91) wipes `/var/lib/nano-cell`,
//! including the tenant's catalog custody dir (`state/<t>/agent-catalog/custody`).
//! The large tenant's first GC pass afterwards failed every Worker `prepare` with a bare
//! `No such file or directory (os error 2)`: the guard read the absent
//! `planned-index-ready` marker, and the executor reported it as
//! `worker_unavailable`. Since the 10-26 decision part GC is never gated on
//! the agent catalog: the same wipe degrades the agent lane (reads closed)
//! and GC proceeds. Production constructors only: `new_guarded` via
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
async fn wiped_custody_volume_never_holds_gc_and_degrades_the_agent_lane_until_a_reconciled_sync() {
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
    let permit = permit();
    // Decision 10-26: part GC is never gated on the agent catalog. On the
    // wiped volume (no planned index) the agent lane degrades instead: reads
    // close, durably, and the request reaches the Worker on both seams.
    for retire in [false, true] {
        let seams = seams(&f);
        let error = if retire { seams.retire(&permit).await.unwrap_err() } else { seams.prepare(&permit).await.unwrap_err() };
        let text = format!("{error:#}");
        assert!(error.downcast_ref::<CatalogCustodyHeld>().is_none(), "no custody hold: {text}");
        assert!(text.contains("retention authority"), "the Worker is reached: {text}");
    }
    let receipt = catalog.require_removed(TENANT_UUID, part).unwrap();
    assert_eq!(receipt.manifest_sha256,
        crate::part_ingest::iceberg_export::lifecycle::degraded_receipt_sha256(TENANT_UUID, part));
    assert!(backend.blocked.load(Ordering::SeqCst), "agent reads closed before the receipt");
    assert!(custody.join("gc-degraded").exists() && custody.join("reads-closed").exists());

    // The writer's next reconciled sync rebuilds the index from the catalog
    // (tolerating the vanished part) and only then reopens the lane.
    catalog.sync_parts(TENANT_UUID, vec![], chrono::Utc::now().timestamp_millis(), &policy).await.unwrap();
    assert!(!backend.blocked.load(Ordering::SeqCst));
    assert!(!custody.join("gc-degraded").exists());
    let error = seams(&f).prepare(&permit).await.unwrap_err();
    assert!(error.to_string().contains("retention authority"), "{error:#}");
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

    // Unreachable catalog, nothing proven: GC still proceeds; the agent
    // lane degrades (reads closed) instead of holding the delete.
    let local = tempfile::tempdir().unwrap();
    let f = fixture(1, Duration::ZERO, 200).await;
    let backend = basin(local.path()).await;
    backend.fail_commit_state.store(true, Ordering::SeqCst);
    let catalog = Arc::new(TenantCatalog::new(TENANT_UUID, local.path().join("custody"), backend.clone()).unwrap());
    f.gc.attach_catalog(catalog.clone()).unwrap();
    let error = seams(&f).prepare(&permit).await.unwrap_err();
    assert!(error.downcast_ref::<CatalogCustodyHeld>().is_none(), "{error:#}");
    assert!(error.to_string().contains("retention authority"), "the Worker is reached: {error:#}");
    let part = crate::lake_part_gc::request::tests::PART;
    assert_eq!(catalog.require_removed(TENANT_UUID, part).unwrap().manifest_sha256,
        crate::part_ingest::iceberg_export::lifecycle::degraded_receipt_sha256(TENANT_UUID, part));
    assert!(backend.blocked.load(Ordering::SeqCst));
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

/// NAN-4783: a hosted tenant's agent-catalog sync held custody for its
/// whole run (up to 30 min); every GC prepare that met it waited 120 s, then
/// read as a pass-wide custody hold and backed off to 6 h. Through the
/// production seams (`new_guarded`, `TenantCatalog::new`, `Seams::prepare`/
/// `retire`) a delete now reaches the Worker while a long sync is still in
/// flight, without degrading the agent lane, and the sync then converges.
#[tokio::test]
async fn gc_reaches_the_worker_while_a_long_catalog_sync_is_in_flight() {
    let f = fixture(1, Duration::ZERO, 200).await;
    let local = tempfile::tempdir().unwrap();
    let backend = basin(local.path()).await;
    let custody = local.path().join("state/agent-catalog/custody");
    // The part was planned (exported, then removed) long ago.
    let history = custody.join("export/committed");
    std::fs::create_dir_all(&history).unwrap();
    let part = crate::lake_part_gc::request::tests::PART;
    let manifest = crate::part_ingest::export::ExportManifest {
        tenant_id: TENANT_UUID.into(), planned_at_ms: 1, previous_plan_ms: None,
        add: vec![], remove_parts: vec![part.into()], hours: vec![],
    };
    std::fs::write(history.join("0000000000001.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
    commit_history(&backend).await;
    let catalog = Arc::new(TenantCatalog::new(TENANT_UUID, custody.clone(), backend.clone()).unwrap());
    f.gc.attach_catalog(catalog.clone()).unwrap();
    let policy = crate::parts::levels::MergePolicy::default();
    let now = chrono::Utc::now().timestamp_millis();
    catalog.sync_parts(TENANT_UUID, vec![], now, &policy).await.unwrap();

    // The next (hourly) sync stalls in its catalog inspection, custody held.
    backend.hold_inspection.store(true, Ordering::SeqCst);
    let held = backend.held.notified();
    let running = {
        let catalog = catalog.clone();
        tokio::spawn(async move { catalog.sync_parts(TENANT_UUID, vec![], now + 3_600_001, &policy).await })
    };
    held.await;
    let permit = permit();
    let started = std::time::Instant::now();
    for retire in [false, true] {
        let seams = seams(&f);
        let call = async { if retire { seams.retire(&permit).await.map(|_| ()) } else { seams.prepare(&permit).await.map(|_| ()) } };
        let error = tokio::time::timeout(Duration::from_secs(10), call).await
            .expect("GC never waits behind a catalog sync").unwrap_err();
        assert!(error.downcast_ref::<CatalogCustodyHeld>().is_none(), "no custody hold: {error:#}");
        assert!(error.to_string().contains("retention authority"), "the Worker is reached: {error:#}");
    }
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    let receipt = catalog.require_removed(TENANT_UUID, part).unwrap();
    assert_ne!(receipt.manifest_sha256,
        crate::part_ingest::iceberg_export::lifecycle::degraded_receipt_sha256(TENANT_UUID, part),
        "proved from the inspected catalog, not by degrading the lane");
    assert!(!backend.blocked.load(Ordering::SeqCst), "agent reads stay open");
    assert!(!custody.join("gc-degraded").exists());

    backend.hold_inspection.store(false, Ordering::SeqCst);
    backend.release.notify_one();
    running.await.unwrap().unwrap();
}

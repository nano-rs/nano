// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real ingestor, signed parts, production erasure/merge/log/planner and
//! catalog custody constructors; only the remote catalog and SQL API are fake.
use super::*;
use crate::part_ingest::iceberg_export::lifecycle::{test_support::Basin, TenantCatalog};
use std::sync::atomic::Ordering;

impl Lake {
    async fn seal_for_catalog(&mut self, tenant: &str) {
        let parts = self.parts();
        let sources = LocalObjectStore::new(self.root.join(format!("sources-{tenant}"))).unwrap();
        let spool = SpoolQueue::new(self.root.join(format!("spool-{tenant}")), tenant).unwrap();
        let signer = signer();
        let mut ingestor = self
            .ingestor(tenant, &parts, &sources, &spool, &signer)
            .await;
        for _ in 0..80 {
            self.clock += 61_000;
            ingestor.tick(self.clock).await.unwrap();
            if ingestor
                .live_parts()
                .iter()
                .all(|p| matches!(p.level, Level::Hour | Level::Day))
            {
                return;
            }
        }
        panic!("hour seals did not converge");
    }

    async fn catalog_tick_run(
        &mut self,
        tenant: &str,
        catalog: Arc<TenantCatalog>,
        ledger: Option<Arc<MemoryLedger>>,
        max: usize,
    ) {
        let parts = self.parts();
        let sources = LocalObjectStore::new(self.root.join(format!("sources-{tenant}"))).unwrap();
        let spool = SpoolQueue::new(self.root.join(format!("spool-{tenant}")), tenant).unwrap();
        let signer = signer();
        let mut config = IngestConfig::new(tenant, self.root.join(format!("work-{tenant}")));
        config.catalog = Some(catalog);
        config.prevalence_enabled = false;
        let mut ingestor = Ingestor::open(
            config,
            &parts,
            &sources,
            &spool,
            &signer,
            signer.trusted(),
            BronzeIngestEnricher::disabled(),
            &seed_schema(),
            self.clock,
        )
        .await
        .unwrap();
        if let Some(ledger) = &ledger {
            ingestor.set_erasure_ledger_fixed(ledger.clone(), "lean-cell:catalog-test".into());
        }
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            for _ in 0..if ledger.is_none() { usize::MAX } else { max } {
                self.clock += 61_000;
                ingestor.tick(self.clock).await.unwrap();
                if ledger.is_none() && ingestor.catalog_synced() {
                    break;
                }
                if ledger.as_ref().is_some_and(|l| {
                    l.state(order(tenant, LeanPhase::Scan).order_id).as_deref() == Some("completed")
                }) {
                    break;
                }
                // Await background progress independently of simulated lake
                // time, including when the full unit suite shares this CPU.
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("catalog tick run timed out");
        let synced = ingestor.catalog_synced();
        drop(ingestor);
        tokio::task::yield_now().await;
        if ledger.is_none() {
            assert!(synced, "initial catalog sync did not finish");
        }
    }

    async fn catalog(&self, tenant: &str) -> (Arc<Basin>, Arc<TenantCatalog>) {
        let backend = Basin::new(
            tenant,
            self.root.clone(),
            Arc::new(self.parts()),
            signer().trusted(),
        )
        .await;
        let catalog = Arc::new(
            TenantCatalog::new(
                tenant,
                self.root.join(format!("catalog-{tenant}")),
                backend.clone(),
            )
            .unwrap(),
        );
        (backend, catalog)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_e2e_revokes_catalog_history_bounds_and_cached_rows_before_gc() {
    let dir = tempfile::tempdir().unwrap();
    let mut lake = Lake {
        root: dir.path().into(),
        clock: i64::from(BASE_HOUR + HOURS + 1) * HOUR_MS,
    };
    lake.ingest(TENANT).await;
    lake.ingest(OTHER).await;
    lake.seal_for_catalog(TENANT).await;
    lake.seal_for_catalog(OTHER).await;
    let other_before = live_rows(&lake, OTHER).await;
    let (basin, catalog) = lake.catalog(TENANT).await;
    let (other_basin, other_catalog) = lake.catalog(OTHER).await;
    lake.catalog_tick_run(TENANT, catalog.clone(), None, 1)
        .await;
    lake.catalog_tick_run(OTHER, other_catalog, None, 1).await;
    let old_snapshot = basin.snapshot_id().await;
    let old_parts = load_log(&lake.parts(), TENANT)
        .await
        .unwrap()
        .parts()
        .cloned()
        .collect::<Vec<_>>();
    let initial = basin.query(TENANT, None).await.unwrap();
    assert!(initial.iter().any(|v| v.eq_ignore_ascii_case(SUBJECT)));
    assert!(basin
        .cached_names()
        .iter()
        .any(|v| v.eq_ignore_ascii_case(SUBJECT)));
    assert!(basin
        .bound_values()
        .await
        .unwrap()
        .iter()
        .any(|v| v.to_lowercase().contains(SUBJECT)));
    assert!(
        basin.metadata_authority.subject_hits(SUBJECT) > 0,
        "fixture must expose subject bytes on disk before erasure"
    );
    // Tenant A's key cannot read tenant B's catalog, even when B is populated.
    assert!(other_basin.query(TENANT, None).await.is_err());
    assert!(basin.query(OTHER, Some(old_snapshot)).await.is_err());
    assert!(TenantCatalog::new(OTHER, lake.root.join("foreign"), basin.clone()).is_err());
    assert!(
        TenantCatalog::new(
            TENANT,
            lake.root.join(format!("catalog-{TENANT}")),
            basin.clone()
        )
        .is_err(),
        "one catalog writer"
    );
    for part in &old_parts {
        assert!(catalog
            .require_removed(TENANT, part.part_id.as_str())
            .is_err());
        assert!(
            catalog
                .fence_retirement(TENANT, part.part_id.as_str())
                .await
                .is_err(),
            "live catalog files pin GC"
        );
    }
    // Since NAN-4612 (#7996) the shared GC proof invalidates reader results
    // before the per-part pin check, so the refused fences above already
    // dropped the cache and left reads closed. Reopen through the production
    // sync and re-cache the subject, so the erasure below must revoke a real
    // cached result.
    let live = load_log(&lake.parts(), TENANT).await.unwrap();
    catalog
        .sync(TENANT, &live, lake.clock, &Default::default())
        .await
        .unwrap();
    assert_eq!(basin.query(TENANT, None).await.unwrap(), initial);

    assert!(
        basin
            .cached_names()
            .iter()
            .any(|v| v.eq_ignore_ascii_case(SUBJECT)),
        "the erasure must invalidate an actual cached subject result"
    );
    let ledger = MemoryLedger::with(vec![order(TENANT, LeanPhase::Scan)]);
    lake.catalog_tick_run(TENANT, catalog.clone(), Some(ledger.clone()), 180)
        .await;
    assert_eq!(
        ledger
            .state(order(TENANT, LeanPhase::Scan).order_id)
            .as_deref(),
        Some("completed")
    );
    let result = basin.query(TENANT, None).await.unwrap();
    assert_eq!(
        result.len(),
        initial
            .iter()
            .filter(|v| !v.eq_ignore_ascii_case(SUBJECT))
            .count()
    );
    assert!(result.iter().all(|v| !v.eq_ignore_ascii_case(SUBJECT)));
    assert!(
        basin.query(TENANT, Some(old_snapshot)).await.is_err(),
        "old snapshot is expired"
    );
    assert_eq!(basin.snapshot_count().await, 1);
    assert!(
        basin
            .bound_values()
            .await
            .unwrap()
            .iter()
            .all(|v| !v.to_lowercase().contains(SUBJECT)),
        "no tombstone bounds survive"
    );
    assert_eq!(
        basin.metadata_authority.subject_hits(SUBJECT),
        0,
        "scan ALL metadata files, including orphan JSON, manifest lists and manifests"
    );
    for part in &old_parts {
        let receipt = catalog
            .require_removed(TENANT, part.part_id.as_str())
            .unwrap();
        assert_eq!(receipt.bucket, format!("nano-shared-r2-{TENANT}"));
        assert!(catalog
            .require_removed(OTHER, part.part_id.as_str())
            .is_err());
        // The fake retention Worker removes bytes only AFTER the production
        // per-part receipt check; catalog queries still work afterwards.
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        for file in 0..part.data_files as usize {
            lake.parts().delete(&keys.data(file)).await.unwrap();
        }
    }
    assert_eq!(basin.query(TENANT, None).await.unwrap(), result);
    assert_eq!(live_rows(&lake, OTHER).await, other_before);
    assert!(other_basin
        .query(OTHER, None)
        .await
        .unwrap()
        .iter()
        .any(|v| v.eq_ignore_ascii_case(SUBJECT)));
    let trace = basin.trace.lock().unwrap();
    let last_commit = trace.iter().rposition(|v| *v == "commit").unwrap();
    assert!(trace[..last_commit].contains(&"close"));
    assert!(
        trace[last_commit + 1..]
            .iter()
            .position(|v| *v == "expire")
            .unwrap()
            < trace[last_commit + 1..]
                .iter()
                .position(|v| *v == "cache")
                .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_e2e_keeps_receipts_and_completion_blocked_until_expiry_and_cache_acknowledge() {
    let dir = tempfile::tempdir().unwrap();
    let mut lake = Lake {
        root: dir.path().into(),
        clock: i64::from(BASE_HOUR + HOURS + 1) * HOUR_MS,
    };
    lake.ingest(TENANT).await;
    lake.seal_for_catalog(TENANT).await;
    let (basin, catalog) = lake.catalog(TENANT).await;
    lake.catalog_tick_run(TENANT, catalog.clone(), None, 1)
        .await;
    let initial = basin.query(TENANT, None).await.unwrap();
    let before = load_log(&lake.parts(), TENANT)
        .await
        .unwrap()
        .parts()
        .cloned()
        .collect::<Vec<_>>();
    let ledger = MemoryLedger::with(vec![order(TENANT, LeanPhase::Scan)]);
    basin.ambiguous_commit.store(true, Ordering::SeqCst);
    basin.fail_expiry.store(true, Ordering::SeqCst);
    lake.catalog_tick_run(TENANT, catalog.clone(), Some(ledger.clone()), 55)
        .await;
    assert_ne!(
        ledger
            .state(order(TENANT, LeanPhase::Scan).order_id)
            .as_deref(),
        Some("completed")
    );
    assert!(basin.blocked.load(Ordering::SeqCst));
    assert!(basin.query(TENANT, None).await.is_err());
    for part in &before {
        assert!(catalog
            .require_removed(TENANT, part.part_id.as_str())
            .is_err());
    }

    basin.fail_expiry.store(false, Ordering::SeqCst);
    basin
        .metadata_authority
        .fail_delete
        .store(true, Ordering::SeqCst);
    lake.catalog_tick_run(TENANT, catalog.clone(), Some(ledger.clone()), 3)
        .await;
    assert_ne!(
        ledger
            .state(order(TENANT, LeanPhase::Scan).order_id)
            .as_deref(),
        Some("completed")
    );
    for part in &before {
        assert!(catalog
            .require_removed(TENANT, part.part_id.as_str())
            .is_err());
    }
    assert!(basin.metadata_authority.subject_hits(SUBJECT) > 0);
    basin
        .metadata_authority
        .fail_delete
        .store(false, Ordering::SeqCst);
    basin.fail_cache.store(true, Ordering::SeqCst);
    lake.catalog_tick_run(TENANT, catalog.clone(), Some(ledger.clone()), 3)
        .await;
    assert_ne!(
        ledger
            .state(order(TENANT, LeanPhase::Scan).order_id)
            .as_deref(),
        Some("completed")
    );
    assert_eq!(
        basin.cached_names(),
        initial,
        "a stale result exists but cannot be served"
    );
    for part in &before {
        assert!(catalog
            .require_removed(TENANT, part.part_id.as_str())
            .is_err());
        // Decoupled GC: receipted with the lane degraded; erasure
        // completion (the ledger) still waits for expiry and the cache.
        let receipt = catalog.fence_retirement(TENANT, part.part_id.as_str()).await.unwrap();
        assert_eq!(receipt.manifest_sha256,
            crate::part_ingest::iceberg_export::lifecycle::degraded_receipt_sha256(TENANT, part.part_id.as_str()));
        assert!(basin.blocked.load(Ordering::SeqCst), "erased rows are never served");
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        assert!(
            lake.parts().get(&keys.data(0)).await.unwrap().is_some(),
            "GC has kept the source bytes"
        );
    }
    // Pod/process restart: reopen the same production constructor and replay
    // the durable pending manifest; never append an ambiguous success twice.
    let commits_before_retry = basin.commits.load(Ordering::SeqCst);
    drop(catalog);
    let catalog = Arc::new(
        TenantCatalog::new(
            TENANT,
            lake.root.join(format!("catalog-{TENANT}")),
            basin.clone(),
        )
        .unwrap(),
    );
    basin.fail_cache.store(false, Ordering::SeqCst);
    lake.catalog_tick_run(TENANT, catalog.clone(), Some(ledger.clone()), 100)
        .await;
    assert_eq!(
        ledger
            .state(order(TENANT, LeanPhase::Scan).order_id)
            .as_deref(),
        Some("completed")
    );
    assert!(
        basin.commits.load(Ordering::SeqCst) <= commits_before_retry + 1,
        "pending commit replay is idempotent"
    );
    assert!(basin
        .query(TENANT, None)
        .await
        .unwrap()
        .iter()
        .all(|v| !v.eq_ignore_ascii_case(SUBJECT)));
    for part in &before {
        catalog
            .require_removed(TENANT, part.part_id.as_str())
            .unwrap();
    }
    let checks = basin.checks.load(Ordering::SeqCst);
    basin.maintenance_on.store(true, Ordering::SeqCst);
    let live = load_log(&lake.parts(), TENANT).await.unwrap();
    assert!(catalog
        .sync(TENANT, &live, lake.clock + 3_600_001, &Default::default())
        .await
        .is_err());
    assert!(
        basin.checks.load(Ordering::SeqCst) > checks,
        "quiet sync rechecks maintenance"
    );
}

/// NAN-4627 (supersedes the pre-fix expectation that a lost planner wedges):
/// a writer whose export state is gone rebuilds it from the catalog and
/// removes the stale files through a real commit chained on the catalog
/// checkpoint. No receipt exists before that commit and expiry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_e2e_lost_planner_state_rebuilds_from_the_catalog_before_any_receipt()
{
    let dir = tempfile::tempdir().unwrap();
    let mut lake = Lake {
        root: dir.path().into(),
        clock: i64::from(BASE_HOUR + HOURS + 1) * HOUR_MS,
    };
    lake.ingest(TENANT).await;
    lake.seal_for_catalog(TENANT).await;
    let (basin, catalog) = lake.catalog(TENANT).await;
    lake.catalog_tick_run(TENANT, catalog.clone(), None, 1)
        .await;
    basin.query(TENANT, None).await.unwrap();
    let parts = lake.parts();
    let mut writer =
        crate::parts::part_log::PartLogWriter::open(&parts, TENANT, 2, &seed_schema(), lake.clock)
            .await
            .unwrap();
    let removed = writer
        .live()
        .parts()
        .map(|p| p.part_id.clone())
        .collect::<Vec<_>>();
    writer
        .append(
            LogOp::Retire {
                parts: removed.clone(),
                reason: RetireReason::Erasure,
                deletion_unit: "erasure:full-test".into(),
            },
            lake.clock + 1,
        )
        .await
        .unwrap();
    assert!(writer.live().parts().next().is_none());
    let before = basin.checkpoint().await.unwrap();
    let lost =
        TenantCatalog::new(TENANT, lake.root.join("lost-planner-state"), basin.clone()).unwrap();
    // Part GC never waits on the agent catalog: each erased part is
    // receipted with the lane degraded (reads closed) before the rebuild.
    for part in &removed {
        assert!(lost.require_removed(TENANT, part.as_str()).is_err());
        let receipt = lost.fence_retirement(TENANT, part.as_str()).await.unwrap();
        assert_eq!(receipt.manifest_sha256,
            crate::part_ingest::iceberg_export::lifecycle::degraded_receipt_sha256(TENANT, part.as_str()));
        assert!(basin.blocked.load(Ordering::SeqCst), "erased rows are never served");
        assert!(basin.query(TENANT, None).await.is_err());
    }
    lost.sync(TENANT, writer.live(), lake.clock + 2, &Default::default())
        .await
        .unwrap();
    assert!(basin.checkpoint().await.unwrap() > before);
    assert!(basin.query(TENANT, None).await.unwrap().is_empty());
    assert!(basin.cached_names().is_empty());
    for part in &removed {
        lost.require_removed(TENANT, part.as_str()).unwrap();
    }
    drop(lost);
    // The original custody is now behind the catalog: it rebuilds too, needs
    // no commit, and GC proves each removal against the catalog itself.
    let commits = basin.commits.load(Ordering::SeqCst);
    catalog
        .sync(TENANT, writer.live(), lake.clock + 3, &Default::default())
        .await
        .unwrap();
    assert_eq!(basin.commits.load(Ordering::SeqCst), commits);
    assert!(basin.query(TENANT, None).await.unwrap().is_empty());
    for part in &removed {
        catalog.fence_retirement(TENANT, part.as_str()).await.unwrap();
    }
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to.join(entry.file_name()));
        } else {
            std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

fn last_committed(custody: &std::path::Path) -> crate::part_ingest::export::ExportManifest {
    let mut paths = std::fs::read_dir(custody.join("export/committed"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    serde_json::from_slice(&std::fs::read(paths.last().unwrap()).unwrap()).unwrap()
}

/// Sealed hour parts committed through the production exporter (c1).
async fn committed_lake() -> (tempfile::TempDir, Lake, Arc<Basin>, Arc<TenantCatalog>, Vec<PartRef>, i64) {
    let dir = tempfile::tempdir().unwrap();
    let mut lake = Lake {
        root: dir.path().into(),
        clock: i64::from(BASE_HOUR + HOURS + 1) * HOUR_MS,
    };
    lake.ingest(TENANT).await;
    lake.seal_for_catalog(TENANT).await;
    let (basin, catalog) = lake.catalog(TENANT).await;
    let mut parts = load_log(&lake.parts(), TENANT).await.unwrap().parts().cloned().collect::<Vec<_>>();
    parts.sort_by_key(|p| p.event_hour);
    assert_eq!(parts.len(), HOURS as usize);
    assert!(parts.iter().all(|p| p.level == Level::Hour));
    catalog
        .sync_parts(TENANT, parts.clone(), lake.clock, &Default::default())
        .await
        .unwrap();
    let c1 = basin.checkpoint().await.unwrap();
    (dir, lake, basin, catalog, parts, c1)
}

/// NAN-4627: the A/B data-volume roll wipes `export/state.json` after the
/// catalog holds a checkpoint. Production constructors throughout: the
/// rebuilt writer continues the chain from the catalog checkpoint, GC stays
/// blocked until that reconciled sync, and a restart mid-recovery (the
/// rebuild persisted, the attempt died before any plan) resumes cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wiped_export_state_rebuilds_from_the_catalog_and_the_next_commit_continues_the_chain() {
    let (_dir, lake, basin, catalog, parts, c1) = committed_lake().await;
    drop(catalog);
    let custody = lake.root.join(format!("catalog-{TENANT}"));
    std::fs::remove_dir_all(&custody).unwrap();

    let catalog = TenantCatalog::new(TENANT, custody.clone(), basin.clone()).unwrap();
    let retired = parts[0].part_id.as_str();
    // GC never waits for the rebuild: the lane degrades (reads closed).
    let receipt = catalog.fence_retirement(TENANT, retired).await.unwrap();
    assert_eq!(receipt.manifest_sha256,
        crate::part_ingest::iceberg_export::lifecycle::degraded_receipt_sha256(TENANT, retired));
    assert!(basin.blocked.load(Ordering::SeqCst));
    // Retention drops the oldest hour; the attempt dies after the rebuild.
    let kept = parts[1..].to_vec();
    basin.maintenance_on.store(true, Ordering::SeqCst);
    assert!(catalog.sync_parts(TENANT, kept.clone(), lake.clock + 1, &Default::default()).await.is_err());
    basin.maintenance_on.store(false, Ordering::SeqCst);
    assert_eq!(basin.checkpoint().await, Some(c1), "nothing was committed");
    let rebuilt = crate::part_ingest::export::ExportState::load(&custody).unwrap();
    assert_eq!(rebuilt.last_plan_ms, c1, "the predecessor is the catalog checkpoint");
    assert_eq!(rebuilt.exported.values().flatten().count(), parts.len());
    assert!(basin.blocked.load(Ordering::SeqCst), "the degraded lane stays closed");
    drop(catalog);

    // Restart mid-recovery.
    let catalog = TenantCatalog::new(TENANT, custody.clone(), basin.clone()).unwrap();
    catalog.sync_parts(TENANT, kept, lake.clock + 2, &Default::default()).await.unwrap();
    let c2 = basin.checkpoint().await.unwrap();
    let delta = last_committed(&custody);
    assert_eq!((delta.planned_at_ms, delta.previous_plan_ms), (c2, Some(c1)));
    assert_eq!(delta.remove_parts, vec![retired.to_string()]);
    assert!(delta.add.is_empty(), "already-exported hours are not re-added");
    catalog.require_removed(TENANT, retired).unwrap();
    assert!(catalog.fence_retirement(TENANT, parts[1].part_id.as_str()).await.is_err(), "live parts stay pinned");
}

/// NAN-4627: a volume restored from an older copy is behind the catalog and
/// still holds a plan chained on the old checkpoint. That plan can never
/// commit; it is set aside (its parts stay in the planned index) and the
/// writer replans from the catalog's current snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custody_behind_the_catalog_rebuilds_and_supersedes_its_stale_plan() {
    let (_dir, lake, basin, catalog, parts, c1) = committed_lake().await;
    let custody = lake.root.join(format!("catalog-{TENANT}"));
    let backup = lake.root.join("custody-backup");
    copy_tree(&custody, &backup);
    catalog.sync_parts(TENANT, parts[1..].to_vec(), lake.clock + 1, &Default::default()).await.unwrap();
    let c2 = basin.checkpoint().await.unwrap();
    assert!(c2 > c1);
    drop(catalog);
    std::fs::remove_dir_all(&custody).unwrap();
    copy_tree(&backup, &custody);
    // The old writer's never-committed plan, chained on c1 and newer than c2.
    let mut old = crate::part_ingest::export::ExportState::load_durable(&custody).unwrap();
    let stale = crate::part_ingest::export::plan_export_reconciled(&parts[2..], &old, lake.clock + 5, &Default::default());
    let stale = old.record_durable_plan(&custody, TENANT, &stale, c2 + 1).unwrap();

    let catalog = TenantCatalog::new(TENANT, custody.clone(), basin.clone()).unwrap();
    catalog.sync_parts(TENANT, parts[2..].to_vec(), lake.clock + 10, &Default::default()).await.unwrap();
    let c3 = basin.checkpoint().await.unwrap();
    let delta = last_committed(&custody);
    assert_eq!((delta.planned_at_ms, delta.previous_plan_ms), (c3, Some(c2)));
    assert_eq!(delta.remove_parts, vec![parts[1].part_id.to_string()]);
    assert!(custody.join("export/superseded").join(stale.file_name().unwrap()).exists());
    assert!(!stale.exists());
    catalog.require_removed(TENANT, parts[1].part_id.as_str()).unwrap();
    catalog.fence_retirement(TENANT, parts[0].part_id.as_str()).await.unwrap();
}

/// NAN-4627: a catalog whose checkpoint is behind (here: absent, a recreated
/// table) is ambiguous. The writer fails closed with a typed reason and never
/// commits or mints a receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_behind_local_export_state_fails_closed_with_a_typed_reason() {
    let (_dir, lake, _basin, catalog, parts, _c1) = committed_lake().await;
    drop(catalog);
    let custody = lake.root.join(format!("catalog-{TENANT}"));
    let recreated = Basin::new(TENANT, lake.root.join("recreated"), Arc::new(lake.parts()), signer().trusted()).await;
    let catalog = TenantCatalog::new(TENANT, custody, recreated.clone()).unwrap();
    let error = catalog
        .sync_parts(TENANT, parts[1..].to_vec(), lake.clock + 1, &Default::default())
        .await
        .unwrap_err();
    let typed = error
        .downcast_ref::<crate::part_ingest::iceberg_export::ExportStateUnrecoverable>()
        .unwrap_or_else(|| panic!("typed refusal: {error:#}"));
    assert!(typed.reason.contains("behind"), "{error:#}");
    assert_eq!(recreated.checkpoint().await, None);
    assert_eq!(recreated.commits.load(Ordering::SeqCst), 0);
    assert!(catalog.require_removed(TENANT, parts[0].part_id.as_str()).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_ingestor_recovers_gc_read_barrier_without_waiting_for_hourly_sync() {
    let dir = tempfile::tempdir().unwrap();
    let mut lake = Lake {
        root: dir.path().into(),
        clock: i64::from(BASE_HOUR + HOURS + 1) * HOUR_MS,
    };
    lake.ingest(TENANT).await;
    lake.seal_for_catalog(TENANT).await;
    let (basin, catalog) = lake.catalog(TENANT).await;
    let parts = lake.parts();
    let sources = LocalObjectStore::new(lake.root.join("recovery-sources")).unwrap();
    let spool = SpoolQueue::new(lake.root.join("recovery-spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, lake.root.join("recovery-work"));
    config.catalog = Some(catalog.clone());
    config.prevalence_enabled = false;
    let mut ingestor = Ingestor::open(
        config,
        &parts,
        &sources,
        &spool,
        &signer,
        signer.trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        lake.clock,
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while !ingestor.catalog_synced() {
            ingestor.tick(lake.clock).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let before = ingestor.live_parts();
    basin.fail_expiry.store(true, Ordering::SeqCst);
    // A live part is held per key (pinned) whatever the catalog state; the
    // failed strict inspection still closed the read barrier.
    assert!(catalog
        .fence_retirement(TENANT, before[0].part_id.as_str())
        .await
        .unwrap_err()
        .to_string()
        .contains("still pins part"));
    assert!(basin.blocked.load(Ordering::SeqCst));
    basin.fail_expiry.store(false, Ordering::SeqCst);
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while basin.blocked.load(Ordering::SeqCst) {
            // Same persistent writer and part-log head, one millisecond later.
            ingestor.tick(lake.clock + 1).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("closed GC barrier was hidden by the writer hourly debounce");
    assert_eq!(ingestor.live_parts(), before);
    assert!(!catalog.recovery_required());
}

/// NAN-4627: a restart after the stale plan moved to `superseded/` but before
/// the rebuilt state.json landed resumes the rebuild (restored-volume variant).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_between_supersede_and_state_persist_resumes_the_rebuild_restored_volume() {
    let (_dir, lake, basin, catalog, parts, c1) = committed_lake().await;
    let custody = lake.root.join(format!("catalog-{TENANT}"));
    let backup = lake.root.join("custody-backup");
    copy_tree(&custody, &backup);
    catalog.sync_parts(TENANT, parts[1..].to_vec(), lake.clock + 1, &Default::default()).await.unwrap();
    let c2 = basin.checkpoint().await.unwrap();
    assert!(c2 > c1);
    drop(catalog);
    std::fs::remove_dir_all(&custody).unwrap();
    copy_tree(&backup, &custody);
    let mut old = crate::part_ingest::export::ExportState::load_durable(&custody).unwrap();
    let stale = crate::part_ingest::export::plan_export_reconciled(&parts[2..], &old, lake.clock + 5, &Default::default());
    let stale = old.record_durable_plan(&custody, TENANT, &stale, c2 + 1).unwrap();
    // Restart point: the rename landed, persist_durable did not.
    std::fs::create_dir_all(custody.join("export/superseded")).unwrap();
    std::fs::rename(&stale, custody.join("export/superseded").join(stale.file_name().unwrap())).unwrap();
    let catalog = TenantCatalog::new(TENANT, custody.clone(), basin.clone()).unwrap();
    let result = catalog.sync_parts(TENANT, parts[2..].to_vec(), lake.clock + 10, &Default::default()).await;
    assert!(result.is_ok(), "restart mid-rebuild must recover: {:#}", result.unwrap_err());
    let delta = last_committed(&custody);
    assert_eq!(delta.previous_plan_ms, Some(c2));
    assert_eq!(delta.remove_parts, vec![parts[1].part_id.to_string()]);
}

/// NAN-4627: the same restart window for the large-tenant wedge (wiped volume, then a
/// pre-fix plan with previous_plan_ms = None).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_between_supersede_and_state_persist_resumes_the_rebuild_wiped_wedge() {
    let (_dir, lake, basin, catalog, parts, c1) = committed_lake().await;
    drop(catalog);
    let custody = lake.root.join(format!("catalog-{TENANT}"));
    std::fs::remove_dir_all(&custody).unwrap();
    std::fs::create_dir_all(&custody).unwrap();
    let mut wiped = crate::part_ingest::export::ExportState::default();
    let plan = crate::part_ingest::export::plan_export_reconciled(&parts, &wiped, lake.clock + 5, &Default::default());
    let wedged = wiped.record_durable_plan(&custody, TENANT, &plan, lake.clock + 5).unwrap();
    std::fs::create_dir_all(custody.join("export/superseded")).unwrap();
    std::fs::rename(&wedged, custody.join("export/superseded").join(wedged.file_name().unwrap())).unwrap();
    let catalog = TenantCatalog::new(TENANT, custody.clone(), basin.clone()).unwrap();
    let result = catalog.sync_parts(TENANT, parts[1..].to_vec(), lake.clock + 10, &Default::default()).await;
    assert!(result.is_ok(), "restart mid-rebuild must recover: {:#}", result.unwrap_err());
    let delta = last_committed(&custody);
    assert_eq!(delta.previous_plan_ms, Some(c1));
    assert_eq!(delta.remove_parts, vec![parts[0].part_id.to_string()]);
    assert!(delta.add.is_empty());
}

/// NAN-4627: the large-tenant wedge (a pending plan with no predecessor against a
/// checkpointed catalog) heals on the next sync.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedged_plan_without_predecessor_is_superseded_and_the_chain_continues() {
    let (_dir, lake, basin, catalog, parts, c1) = committed_lake().await;
    drop(catalog);
    let custody = lake.root.join(format!("catalog-{TENANT}"));
    std::fs::remove_dir_all(&custody).unwrap();
    std::fs::create_dir_all(&custody).unwrap();
    let mut wiped = crate::part_ingest::export::ExportState::default();
    let plan = crate::part_ingest::export::plan_export_reconciled(&parts, &wiped, lake.clock + 5, &Default::default());
    wiped.record_durable_plan(&custody, TENANT, &plan, lake.clock + 5).unwrap();
    let catalog = TenantCatalog::new(TENANT, custody.clone(), basin.clone()).unwrap();
    catalog.sync_parts(TENANT, parts[1..].to_vec(), lake.clock + 10, &Default::default()).await.unwrap();
    let delta = last_committed(&custody);
    assert_eq!(delta.previous_plan_ms, Some(c1));
    assert_eq!(delta.remove_parts, vec![parts[0].part_id.to_string()]);
    assert!(delta.add.is_empty());
}

/// NAN-4614: one part per batch, one batch per sync.
const ONE_PART_BATCHES: crate::part_ingest::iceberg_export::lifecycle::SyncLimits =
    crate::part_ingest::iceberg_export::lifecycle::SyncLimits {
        batch_budget: std::time::Duration::ZERO,
        hard_bound: std::time::Duration::from_secs(60),
        batch: crate::part_ingest::export::ExportBatchBounds { max_files: 1, max_bytes: u64::MAX },
    };

/// Sealed hour parts, nothing exported yet.
async fn sealed_lake() -> (tempfile::TempDir, Lake, Arc<Basin>, Vec<PartRef>) {
    let dir = tempfile::tempdir().unwrap();
    let mut lake = Lake {
        root: dir.path().into(),
        clock: i64::from(BASE_HOUR + HOURS + 1) * HOUR_MS,
    };
    lake.ingest(TENANT).await;
    lake.seal_for_catalog(TENANT).await;
    let basin = Basin::new(TENANT, lake.root.clone(), Arc::new(lake.parts()), signer().trusted()).await;
    let mut parts = load_log(&lake.parts(), TENANT).await.unwrap().parts().cloned().collect::<Vec<_>>();
    parts.sort_by_key(|p| p.event_hour);
    assert_eq!(parts.len(), HOURS as usize);
    (dir, lake, basin, parts)
}

/// Sync until converged; every unconverged sync must be a budget stop.
async fn converge_batches(catalog: &TenantCatalog, parts: &[PartRef], now: i64) -> usize {
    for pass in 0..16 {
        match catalog.sync_parts(TENANT, parts.to_vec(), now + pass, &Default::default()).await {
            Ok(()) => return pass as usize,
            Err(error) => assert!(
                error
                    .downcast_ref::<crate::part_ingest::iceberg_export::lifecycle::CatalogSyncIncomplete>()
                    .is_some(),
                "only budget stops: {error:#}"
            ),
        }
    }
    panic!("catalog sync did not converge");
}

async fn assert_each_file_registered_once(basin: &Basin, parts: &[PartRef]) {
    let files = basin.live_files().await;
    let unique = files.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), files.len(), "no data file registered twice");
    assert_eq!(files.len(), parts.iter().map(|p| p.data_files as usize).sum::<usize>());
}

/// NAN-4614 (the large tenant): the first export of a live set larger than one sync
/// budget, through the production exporter (signed-part verification,
/// Iceberg manifests): each sync commits one durable batch, the next resumes
/// after it, and the table ends with every data file exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_export_lands_in_durable_batches_across_syncs_through_the_production_exporter() {
    let (_dir, lake, basin, parts) = sealed_lake().await;
    let custody = lake.root.join(format!("catalog-{TENANT}"));
    let catalog = TenantCatalog::new(TENANT, custody.clone(), basin.clone()).unwrap().with_limits(ONE_PART_BATCHES);
    let stops = converge_batches(&catalog, &parts, lake.clock).await;
    assert_eq!(stops, HOURS as usize - 1, "one batch per sync");
    assert_eq!(basin.commits.load(Ordering::SeqCst), HOURS as usize, "one commit per batch, none repeated");
    assert_each_file_registered_once(&basin, &parts).await;
    assert_eq!(std::fs::read_dir(custody.join("export/committed")).unwrap().count(), HOURS as usize);
    assert_eq!(std::fs::read_dir(custody.join("export/pending")).unwrap().count(), 0);
    // Settled once, at the end: one snapshot retained.
    assert_eq!(basin.snapshot_count().await, 1);
    assert!(catalog.fence_retirement(TENANT, parts[0].part_id.as_str()).await.is_err(), "live parts stay pinned");
    // A lost commit response mid-chain is replayed as a checkpoint skip.
    drop(catalog);
    let (_dir2, lake2, basin2, parts2) = sealed_lake().await;
    let catalog = TenantCatalog::new(TENANT, lake2.root.join(format!("catalog-{TENANT}")), basin2.clone())
        .unwrap()
        .with_limits(ONE_PART_BATCHES);
    assert!(catalog.sync_parts(TENANT, parts2.clone(), lake2.clock, &Default::default()).await.is_err());
    basin2.ambiguous_commit.store(true, Ordering::SeqCst);
    assert!(catalog.sync_parts(TENANT, parts2.clone(), lake2.clock + 1, &Default::default()).await.is_err());
    converge_batches(&catalog, &parts2, lake2.clock + 2).await;
    assert_eq!(basin2.commits.load(Ordering::SeqCst), HOURS as usize);
    assert_each_file_registered_once(&basin2, &parts2).await;
}

/// NAN-4614: the large tenant already holds ONE pending manifest naming its whole live
/// set (recorded by a pre-batching writer that never got it committed). The
/// writer replaces it by bounded batches chained to end at its own time,
/// after removing the strays of an interrupted earlier replacement, and
/// converges without a predecessor error or a duplicate file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_whole_live_set_manifest_is_rebatched_and_converges() {
    use crate::part_ingest::export::{plan_export_reconciled, split_manifest, ExportState};
    let (_dir, lake, basin, parts) = sealed_lake().await;
    let custody = lake.root.join(format!("catalog-{TENANT}"));
    std::fs::create_dir_all(&custody).unwrap();
    let mut state = ExportState::load_durable(&custody).unwrap();
    let pending = plan_export_reconciled(&parts, &state, lake.clock, &Default::default());
    let giant = state.record_durable_plan(&custody, TENANT, &pending, lake.clock).unwrap();
    let whole: crate::part_ingest::export::ExportManifest = serde_json::from_slice(&std::fs::read(&giant).unwrap()).unwrap();
    assert_eq!(whole.add.len(), HOURS as usize);
    // An earlier replacement died after writing its first batch.
    let mut stray = split_manifest(whole.clone(), ONE_PART_BATCHES.batch).unwrap().remove(0);
    stray.planned_at_ms = lake.clock - (HOURS as i64 - 1);
    std::fs::write(
        custody.join(format!("export/pending/{:013}.json", stray.planned_at_ms)),
        serde_json::to_vec(&stray).unwrap(),
    )
    .unwrap();
    let catalog = TenantCatalog::new(TENANT, custody.clone(), basin.clone()).unwrap().with_limits(ONE_PART_BATCHES);
    let stops = converge_batches(&catalog, &parts, lake.clock + 1).await;
    assert_eq!(stops, HOURS as usize - 1);
    assert_eq!(basin.commits.load(Ordering::SeqCst), HOURS as usize);
    assert_each_file_registered_once(&basin, &parts).await;
    assert_eq!(basin.checkpoint().await, Some(lake.clock), "the chain ends at the original plan time");
    assert_eq!(ExportState::load(&custody).unwrap().last_plan_ms, lake.clock);
    // The next delta continues the chain.
    catalog.sync_parts(TENANT, parts[1..].to_vec(), lake.clock + 3_600_000, &Default::default()).await.unwrap();
    assert!(basin.checkpoint().await.unwrap() > lake.clock);
    catalog.require_removed(TENANT, parts[0].part_id.as_str()).unwrap();
}

/// Counts full-object reads of part data files.
struct CountingStore {
    inner: LocalObjectStore,
    data_reads: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl ObjectStore for CountingStore {
    async fn get_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
        if key.contains("/data-") {
            self.data_reads.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get_range(key, range).await
    }
    async fn object_size(&self, key: &str) -> Result<Option<u64>> {
        self.inner.object_size(key).await
    }
    async fn object_identity(&self, key: &str) -> Result<Option<(String, u64)>> {
        self.inner.object_identity(key).await
    }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

/// NAN-4614: a data file verified once (signed digest + footer) is not read
/// again by the next preparation (a retried batch, the fresh serving epoch);
/// a record that does not match the signed digest exactly is a full read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_files_skip_the_full_read_only_on_an_exact_signed_match() {
    use crate::part_ingest::export::{plan_export_reconciled, ExportState};
    use crate::part_ingest::iceberg_export::{hosted::HostedExportTarget, ExportTarget};
    let (_dir, lake, _basin, parts) = sealed_lake().await;
    let store = Arc::new(CountingStore { inner: lake.parts(), data_reads: Default::default() });
    let memo = lake.root.join("verified-files");
    let target = HostedExportTarget::new(
        TENANT.into(),
        store.clone(),
        signer().trusted(),
        crate::lake_part_gc::request::tenant_bucket(TENANT),
    )
    .unwrap()
    .with_verified_files(memo.clone());
    let live = load_log(&lake.parts(), TENANT).await.unwrap();
    let schema = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&live.schema().unwrap().to_arrow().unwrap()).unwrap();
    let mut state = ExportState::default();
    let pending = plan_export_reconciled(&parts, &state, lake.clock, &Default::default());
    let path = state.record_durable_plan(&lake.root, TENANT, &pending, lake.clock).unwrap();
    let manifest: crate::part_ingest::export::ExportManifest = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let first = target.prepare(&manifest, &schema).await.unwrap();
    let reads = store.data_reads.swap(0, Ordering::SeqCst);
    assert!(reads > 0);
    assert_eq!(target.prepare(&manifest, &schema).await.unwrap(), first);
    assert_eq!(store.data_reads.load(Ordering::SeqCst), 0, "verified files are not read again");
    // A record that differs from the signed digest proves nothing.
    let record = std::fs::read_dir(&memo).unwrap().next().unwrap().unwrap().path();
    let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
    value["sha256"] = "0".repeat(64).into();
    std::fs::write(&record, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(target.prepare(&manifest, &schema).await.unwrap(), first);
    assert!(store.data_reads.load(Ordering::SeqCst) > 0, "a mismatched record is a full read");
    // NAN-4614 review: every record is valid again here. An object replaced
    // under the same key at the same size (a bucket writer swapping bytes)
    // must not ride the memo: the record names the old object's identity,
    // so the new bytes are read in full and refused.
    assert_eq!(target.prepare(&manifest, &schema).await.unwrap(), first);
    store.data_reads.store(0, Ordering::SeqCst);
    assert_eq!(target.prepare(&manifest, &schema).await.unwrap(), first);
    assert_eq!(store.data_reads.load(Ordering::SeqCst), 0, "all records valid again");
    // Records follow the live set: a file that left it is forgotten.
    let records = || std::fs::read_dir(&memo).unwrap().count();
    let total = parts.iter().map(|p| p.data_files as usize).sum::<usize>();
    assert_eq!(records(), total);
    target.retain_verified(&parts).unwrap();
    assert_eq!(records(), total, "live records stay");
    target.retain_verified(&parts[1..]).unwrap();
    assert_eq!(records(), total - parts[0].data_files as usize);
    assert_eq!(target.prepare(&manifest, &schema).await.unwrap(), first);
    assert_eq!(records(), total);
    let key = &manifest.add[0].keys[0];
    let local = lake.parts().path(key).unwrap();
    let mut bytes = std::fs::read(&local).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    std::fs::remove_file(&local).unwrap();
    std::fs::write(&local, &bytes).unwrap();
    let error = target.prepare(&manifest, &schema).await.unwrap_err();
    assert!(format!("{error:#}").contains("checksum differs"), "{error:#}");
}

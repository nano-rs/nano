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
        assert!(catalog
            .fence_retirement(TENANT, part.part_id.as_str())
            .await
            .is_err());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_e2e_lost_planner_state_cannot_acknowledge_an_empty_lake_with_stale_catalog_files()
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
    let lost =
        TenantCatalog::new(TENANT, lake.root.join("lost-planner-state"), basin.clone()).unwrap();
    let error = lost
        .sync(TENANT, writer.live(), lake.clock + 2, &Default::default())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("recover durable custody"));
    assert!(basin.query(TENANT, None).await.is_err());
    for part in &removed {
        assert!(lost.require_removed(TENANT, part.as_str()).is_err());
    }
    drop(lost);
    // Restoring the original custody chain permits the production full-delete
    // snapshot and expiry path to finish without recreating a fresh table.
    catalog
        .sync(TENANT, writer.live(), lake.clock + 3, &Default::default())
        .await
        .unwrap();
    assert!(basin.query(TENANT, None).await.unwrap().is_empty());
    assert!(basin.cached_names().is_empty());
    for part in &removed {
        catalog.require_removed(TENANT, part.as_str()).unwrap();
    }
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
    assert!(catalog
        .fence_retirement(TENANT, before[0].part_id.as_str())
        .await
        .unwrap_err()
        .to_string()
        .contains("expiry unavailable"));
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

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Small-role admission and merge headroom on the production ingestor.
use super::*;
use super::nan4749_ingest_tests::{Lab, CLOCK, TENANT};
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;
use std::time::Duration;

fn event(i: usize) -> Value {
    json!({"time": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(CLOCK - 5_000).unwrap().to_rfc3339(),
        "class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "severity_id": 1,
        "metadata": {"uid": format!("nan4806-{i:08}"), "tenant_uid": TENANT, "version": "1.9.0",
            "log_source": "WINDOWS_EVENT", "product": {"name": "fixture"}},
        "raw_data": format!("{i:08}").repeat(200), "raw_data_size": 1_600, "message": "authentication",
        "user": {"name": "fixture-user"}, "dst_endpoint": {"ip": "192.0.2.1"}})
}

struct HeldPublication {
    inner: LocalObjectStore,
    release: tokio::sync::Semaphore,
}
#[async_trait::async_trait]
impl ObjectStore for HeldPublication {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        if key.contains("/data-") {
            self.release.acquire().await.unwrap().forget();
        }
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
    async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.inner.list(prefix).await }
}

/// A real sealed buffer with a held provider PUT, not a fabricated flight.
/// At Mythos's role limit, the next two objects share one decode group while
/// that flight still owns all its build/writer reservation.
#[tokio::test]
async fn nan4806_two_objects_decode_together_beside_a_real_flight() {
    let lab = Lab::new(2_090_000_000);
    lab.land("warmup", &(0..512).map(event).collect::<Vec<_>>(), CLOCK - 5_000);
    let mut ingestor = lab.open().await;
    ingestor.tick(CLOCK).await.unwrap();
    ingestor.flush_now(CLOCK + 1).await.unwrap();
    lab.land("flight", &(512..30_512).map(event).collect::<Vec<_>>(), CLOCK - 4_000);
    let pending = lab.spool.pending(10).await.unwrap();
    assert_eq!(ingestor.admit(&pending, CLOCK + 2).await.unwrap().0, 30_000);
    let held = Box::leak(Box::new(HeldPublication { inner: LocalObjectStore::new(lab.root.join("parts")).unwrap(),
        release: tokio::sync::Semaphore::new(0) }));
    let signer = Box::leak(Box::new(LocalPartSigner::new("lab-signer-nan4749",
        ed25519_dalek::SigningKey::from_bytes(&[47; 32])).unwrap()));
    ingestor.set_background_store(held);
    ingestor.set_background_signer(signer);
    ingestor.flush(CLOCK + 3, true).await.unwrap();
    assert_eq!(ingestor.flush_in_flight.len(), 1);
    let flight_bytes = ingestor.flush_in_flight[0].reserved_bytes;
    assert!(ingestor.cfg.merge_headroom_bytes > 0, "merge headroom must be reserved before a merge starts");
    for object in 0..2 {
        lab.land(&format!("next-{object}"), &(30_512 + object * 3_000..33_512 + object * 3_000).map(event).collect::<Vec<_>>(), CLOCK - 3_000);
    }
    let pending = lab.spool.pending(10).await.unwrap().into_iter().filter(|(_, notice)| notice.key.contains("next-")).collect::<Vec<_>>();
    let groups_before = ingestor.health().admission_groups_total;
    assert_eq!(ingestor.admit(&pending, CLOCK + 4).await.unwrap().0, 6_000);
    assert_eq!(ingestor.health().admission_groups_total, groups_before + 1, "both objects share a parallel Arrow decode group");
    assert!(ingestor.health().admission_group_objects_peak >= 2);
    assert_eq!(ingestor.flush_in_flight[0].reserved_bytes, flight_bytes, "the flight keeps its full reservation");
    assert!(ingestor.committed_bytes() <= ingestor.cfg.buffer_budget_bytes);
    eprintln!("NAN-4806: {} flight bytes + {} merge headroom; two 3k-row objects share one decode group; working reservation {} / {} bytes",
        flight_bytes, ingestor.cfg.merge_headroom_bytes, ingestor.committed_bytes(), ingestor.cfg.buffer_budget_bytes);
    held.release.add_permits(1_024);
    tokio::time::timeout(Duration::from_secs(60), ingestor.flush_now(CLOCK + 5)).await.unwrap().unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 36_512);
    assert!(lab.spool.pending(10).await.unwrap().is_empty());
    assert_eq!((ingestor.health().objects_quarantined_total, ingestor.merge_quarantine.len()), (0, 0));
}

#[test]
fn nan4806_mythos_room_takes_a_slice_below_the_old_4096_row_floor() {
    use super::super::memory::*;
    let budget = buffer_budget_for(2_090_000_000);
    // Retain the reported 60 MB of admission headroom while the role's
    // total working envelope scales with its measured reservations.
    let committed = budget - 60_000_000;
    let (heap, arrow) = decoded_admission_cost(16_700_000);
    let rows = pipelined_slice_rows(budget, committed, heap, arrow, 10_000).unwrap();
    assert!((MIN_ADMISSION_SLICE_ROWS..4_096).contains(&rows));
    assert!(admission_fits(budget, committed, heap * rows as f64 / 10_000.0, arrow));
}

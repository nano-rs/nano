// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4567: the sanctioned GC deletes expired bronze quarantine keys.
//!
//! NAN-4554 mirrors the bronze quarantine into the tenant's
//! `log/checkpoints/bronze-quarantine-v1/` (`objects/{id}.parquet` and
//! immutable `records/{written_ms:013}-{sha16}.json`). Ingest holds no delete
//! authority there, and the R2 convergence adapter refuses a destructive
//! lifecycle rule on the tenant bucket, so without this every quarantined
//! object and record stayed forever. This planner hands the expired ones to
//! the same owner permit -> control attest -> Worker fence/delete/receipt
//! route every part delete takes (reason `quarantine_expired`).
//!
//! What is deletable, at `now`, with `H` = [`QUARANTINE_MIN_AGE_SECONDS`]
//! (the TTL plus the restore's day of slack, `RESTORE_HORIZON_MS`):
//!
//! - **A record** whose key time AND upload time are both at least `H` old.
//!   Restore lists only records younger than `H`, and an entry expires `TTL`
//!   after it was kept, so such a record can only describe an expired entry:
//!   no restore reads it again. Deleting it in any order is safe.
//! - **An object** uploaded at least `H` ago that no surviving (younger than
//!   `H`) record names. Objects are content-addressed, so a later keep of the
//!   same bytes reuses the object; its young record keeps it. The young
//!   records are read (one small GET each, at most
//!   [`MAX_YOUNG_RECORD_READS`]); if any read fails, or there are more, no
//!   object is planned that pass (records still are).
//!
//! Objects are planned before records. At most
//! [`MAX_QUARANTINE_DELETES_PER_PASS`] requests per pass, at most one pass
//! per [`QUARANTINE_EXPIRY_INTERVAL_MS`]. Only the tenant's own prefix is
//! listed, a listed key outside it fails the pass, and every request is
//! validated against its tenant ([`LakePartDeleteRequest::validate`]). The
//! audit line carries counts only.
//!
//! Residual race: a keep of identical bytes between this listing and the
//! Worker's delete loses the object from the bucket. That entry is then
//! pod-local only (restore skips a record whose object is missing), which is
//! exactly the pre-NAN-4554 durability, for that one entry.
//!
//! CF cost (R2): per pass, 1 LIST per 1,000 quarantine keys (class A), 1 GET
//! per young record (class B), and per deleted key the existing delete route
//! (Worker HEAD + DELETE + receipt PUT). Quarantined objects are rare (0 on
//! most tenants), so a pass is normally one LIST every 6 h.

use anyhow::{ensure, Context, Result};
use std::collections::BTreeSet;

use super::executor::{LakePartDeleteAuthority, LakePartGcState, PassReport};
use super::planner::ListedPartObject;
use super::request::{
    parse_quarantine_key, LakePartDeleteReason, LakePartDeleteRequest, QuarantineKeyKind, QUARANTINE_DIR,
    QUARANTINE_MIN_AGE_SECONDS,
};
use crate::part_ingest::part_gc_gate::PartObjectLister;

/// Requests one pass plans at most.
pub const MAX_QUARANTINE_DELETES_PER_PASS: usize = 64;
/// Young records one pass reads at most to learn which objects they keep.
pub const MAX_YOUNG_RECORD_READS: usize = 256;
/// Quarantine keys one listing may return (the cap holds at most 1 GiB of
/// objects; a record is written a few times per object).
pub const MAX_QUARANTINE_LISTED: usize = 100_000;
/// A record is a few hundred bytes; anything far larger is not one.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// The least time between two passes.
pub const QUARANTINE_EXPIRY_INTERVAL_MS: i64 = 6 * 3_600_000;
/// The Worker capability that admits `quarantine_expired` permits. Until the
/// Worker lists it, no quarantine request is ever planned.
pub const QUARANTINE_OPERATION: &str = "lake_part_delete.quarantine_expired";

const MIN_AGE_MS: i64 = QUARANTINE_MIN_AGE_SECONDS as i64 * 1_000;

/// `lake/parts/v1/tenant={uuid}/log/checkpoints/bronze-quarantine-v1/`.
pub fn quarantine_prefix(tenant_uuid: &str) -> String {
    format!("{}/tenant={tenant_uuid}/{QUARANTINE_DIR}", crate::parts::format::PARTS_ROOT)
}

/// One pass's plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuarantinePlan {
    /// Objects first, then records; at most the pass bound.
    pub requests: Vec<LakePartDeleteRequest>,
    pub objects: usize,
    pub records: usize,
    /// Old objects a young record still names.
    pub kept_by_young_record: usize,
    /// Old objects not planned because the young records were not all read.
    pub objects_blocked: usize,
}

fn is_young(object: &ListedPartObject, written_ms: Option<i64>, now_ms: i64) -> bool {
    let old = |at: i64| at.saturating_add(MIN_AGE_MS) <= now_ms;
    !old(object.uploaded_at_ms) || written_ms.is_some_and(|at| !old(at))
}

/// The record keys a pass must read: every record not yet deletable.
pub fn young_record_keys(tenant_uuid: &str, listed: &[ListedPartObject], now_ms: i64) -> Vec<String> {
    listed
        .iter()
        .filter(|object| match parse_quarantine_key(&object.key) {
            Some(key) if key.tenant_uuid == tenant_uuid => match key.kind {
                QuarantineKeyKind::Record { written_ms } => is_young(object, Some(written_ms), now_ms),
                QuarantineKeyKind::Object { .. } => false,
            },
            _ => false,
        })
        .map(|object| object.key.clone())
        .collect()
}

/// Plan one pass. `young_ids` is the set of ids the young records name, or
/// `None` when they could not all be read (then no object is planned).
pub fn plan(
    tenant_slug: &str,
    tenant_uuid: &str,
    listed: &[ListedPartObject],
    young_ids: Option<&BTreeSet<String>>,
    now_ms: i64,
    max_requests: usize,
) -> QuarantinePlan {
    let mut plan = QuarantinePlan::default();
    let mut objects = Vec::new();
    let mut records = Vec::new();
    for object in listed {
        let Some(key) = parse_quarantine_key(&object.key).filter(|key| key.tenant_uuid == tenant_uuid) else {
            continue;
        };
        let request = || {
            let mut request = LakePartDeleteRequest::base(
                tenant_slug, tenant_uuid, &object.key, &object.strong_etag, object.content_length,
                LakePartDeleteReason::QuarantineExpired,
            );
            request.quarantine_min_age_seconds = Some(QUARANTINE_MIN_AGE_SECONDS);
            request
        };
        match key.kind {
            QuarantineKeyKind::Object { id } => {
                if is_young(object, None, now_ms) {
                    continue;
                }
                match young_ids {
                    None => plan.objects_blocked += 1,
                    Some(ids) if ids.contains(&id) => plan.kept_by_young_record += 1,
                    Some(_) => objects.push(request()),
                }
            }
            QuarantineKeyKind::Record { written_ms } => {
                if !is_young(object, Some(written_ms), now_ms) {
                    records.push(request());
                }
            }
        }
    }
    objects.sort_by(|a, b| a.key.cmp(&b.key));
    records.sort_by(|a, b| a.key.cmp(&b.key));
    for (request, is_object) in objects.into_iter().map(|r| (r, true)).chain(records.into_iter().map(|r| (r, false))) {
        if plan.requests.len() >= max_requests {
            break;
        }
        // Never plan what the owner would refuse as malformed.
        if request.validate().is_err() {
            continue;
        }
        if is_object { plan.objects += 1 } else { plan.records += 1 }
        plan.requests.push(request);
    }
    plan
}

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuarantineExpiryReport {
    /// Why the pass did nothing, if it did nothing.
    pub skipped: Option<&'static str>,
    pub listed: usize,
    pub young_records: usize,
    pub plan: QuarantinePlan,
    pub executed: PassReport,
}

/// The ids the young records name, or `None` if they cannot all be read.
async fn young_ids(
    lister: &dyn PartObjectLister, tenant_uuid: &str, listed: &[ListedPartObject], keys: &[String],
) -> Option<BTreeSet<String>> {
    if keys.len() > MAX_YOUNG_RECORD_READS {
        return None;
    }
    let mut ids = BTreeSet::new();
    for key in keys {
        if listed.iter().any(|object| &object.key == key && object.content_length as usize > MAX_RECORD_BYTES) {
            return None;
        }
        match lister.get_small_object(key, MAX_RECORD_BYTES).await {
            Ok(Some(body)) => {
                // A foreign, corrupt or mis-keyed record is skipped by
                // restore too, so it keeps nothing.
                if let Some(id) = crate::part_ingest::quarantine_store::record_id(tenant_uuid, key, &body) {
                    ids.insert(id);
                }
            }
            // Gone since the listing: it keeps nothing.
            Ok(None) => {}
            Err(_) => return None,
        }
    }
    Some(ids)
}

/// One bounded pass: list the tenant's quarantine prefix, plan, and delete
/// through `authority`. Uses the state's refused-key memory and authorize
/// pacer; never touches its pending deleted-key report (a quarantine key has
/// no part writer rows to release in control).
pub async fn run(
    authority: &dyn LakePartDeleteAuthority,
    lister: &dyn PartObjectLister,
    state: &mut LakePartGcState,
    tenant_slug: &str,
    tenant_uuid: &str,
    now_ms: i64,
) -> Result<QuarantineExpiryReport> {
    let mut report = QuarantineExpiryReport::default();
    if !authority.worker_supports_quarantine_expiry().await.context("quarantine expiry capability probe")? {
        report.skipped = Some("worker_capability_missing");
        return Ok(report);
    }
    let prefix = quarantine_prefix(tenant_uuid);
    let mut listed = lister.list_part_objects(&prefix).await.context("list the bronze quarantine")?;
    ensure!(listed.len() <= MAX_QUARANTINE_LISTED, "bronze quarantine listing is over its bound");
    ensure!(listed.iter().all(|object| object.key.starts_with(&prefix)), "bronze quarantine listing escaped its prefix");
    listed.sort_by(|a, b| a.key.cmp(&b.key));
    ensure!(listed.windows(2).all(|pair| pair[0].key != pair[1].key), "bronze quarantine listing repeats a key");
    report.listed = listed.len();
    let young = young_record_keys(tenant_uuid, &listed, now_ms);
    report.young_records = young.len();
    let ids = young_ids(lister, tenant_uuid, &listed, &young).await;
    report.plan = plan(tenant_slug, tenant_uuid, &listed, ids.as_ref(), now_ms, MAX_QUARANTINE_DELETES_PER_PASS);
    if report.plan.requests.is_empty() {
        report.skipped = Some("nothing_expired");
    } else {
        report.executed = super::executor::execute_quarantine(
            authority, &report.plan.requests, &mut state.refused_keys, &mut state.authorize_pacer, now_ms,
        ).await;
    }
    // Audit: counts only, never keys or ids.
    tracing::info!(
        listed = report.listed,
        young_records = report.young_records,
        planned_objects = report.plan.objects,
        planned_records = report.plan.records,
        kept_by_young_record = report.plan.kept_by_young_record,
        objects_blocked = report.plan.objects_blocked,
        deleted = report.executed.deleted,
        skipped = report.executed.skipped.values().sum::<u64>(),
        paused = report.executed.paused_reason.is_some(),
        "bronze quarantine expiry pass"
    );
    Ok(report)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::lake_part_gc::request::tests::TENANT_UUID;

    pub const NOW: i64 = 1_790_000_000_000;
    pub const DAY: i64 = 86_400_000;

    pub fn listed(key: String, uploaded_at_ms: i64) -> ListedPartObject {
        ListedPartObject { key, strong_etag: "\"e\"".into(), content_length: 10, uploaded_at_ms }
    }

    pub fn object_key(tenant: &str, id: &str) -> String {
        format!("{}objects/{id}.parquet", quarantine_prefix(tenant))
    }

    pub fn record_key(tenant: &str, written_ms: i64, tag: &str) -> String {
        format!("{}records/{written_ms:013}-{tag}.json", quarantine_prefix(tenant))
    }

    #[test]
    fn plans_old_records_and_unreferenced_old_objects_objects_first() {
        let old = NOW - 9 * DAY;
        let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let keys = vec![
            listed(object_key(TENANT_UUID, &a), old),
            // Old bytes a young keep reused: kept.
            listed(object_key(TENANT_UUID, &b), old),
            // Young object: kept.
            listed(object_key(TENANT_UUID, &c), NOW - DAY),
            listed(record_key(TENANT_UUID, old, "0000000000000001"), old),
            // Young by key time though uploaded long ago: kept.
            listed(record_key(TENANT_UUID, NOW - DAY, "0000000000000002"), old),
            // Exactly at the horizon: deletable.
            listed(record_key(TENANT_UUID, NOW - 8 * DAY, "0000000000000003"), NOW - 8 * DAY),
        ];
        assert_eq!(young_record_keys(TENANT_UUID, &keys, NOW), vec![keys[4].key.clone()]);
        let ids = BTreeSet::from([b.clone()]);
        let plan = plan("tenant1", TENANT_UUID, &keys, Some(&ids), NOW, 64);
        let planned: Vec<_> = plan.requests.iter().map(|r| r.key.clone()).collect();
        assert_eq!(planned, vec![keys[0].key.clone(), keys[3].key.clone(), keys[5].key.clone()]);
        assert_eq!((plan.objects, plan.records, plan.kept_by_young_record, plan.objects_blocked), (1, 2, 1, 0));
        for request in &plan.requests {
            request.validate().unwrap();
            assert_eq!(request.reason, LakePartDeleteReason::QuarantineExpired);
        }
        // Unread young records block every object, never a record.
        let blocked = super::plan("tenant1", TENANT_UUID, &keys, None, NOW, 64);
        assert_eq!((blocked.objects, blocked.records, blocked.objects_blocked), (0, 2, 2));
        // Bounded; objects go first.
        let bounded = super::plan("tenant1", TENANT_UUID, &keys, Some(&ids), NOW, 2);
        assert_eq!(bounded.requests.iter().map(|r| r.key.clone()).collect::<Vec<_>>(), planned[..2].to_vec());
    }

    #[test]
    fn another_tenants_keys_are_never_planned() {
        let other = "7f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let old = NOW - 30 * DAY;
        let keys = vec![
            listed(object_key(other, &"a".repeat(64)), old),
            listed(record_key(other, old, "0000000000000001"), old),
            listed(format!("lake/parts/v1/tenant={TENANT_UUID}/log/checkpoints/00000000000000000001.json"), old),
        ];
        let plan = plan("tenant1", TENANT_UUID, &keys, Some(&BTreeSet::new()), NOW, 64);
        assert!(plan.requests.is_empty(), "{plan:?}");
        assert!(young_record_keys(TENANT_UUID, &keys, NOW).is_empty());
    }
}

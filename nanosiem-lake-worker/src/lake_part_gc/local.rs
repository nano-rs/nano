// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trusted-local GC. Used only by the local single-writer ingest process,
//! while its ingestor mutex and lifetime appender flock are held. Hosted
//! stores keep the owner/control/Worker authority. A local permit never
//! authorizes a hosted delete.

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{io::Read, sync::Arc};

use super::executor::{execute_local, LOG_CATCHING_UP, MAX_LOG_ENTRIES_PER_PASS};
use super::planner::plan_local;
use super::{
    catch_up_view_bounded, live_part_keys, parse_part_file_key, GcPolicy, LakePartDeleteAuthority,
    LakePartDeletePermit, LakePartDeleteReceipt, LakePartDeleteRequest, LakePartLogView,
    ListedPartObject, PartLogReader, PassReport, StorePartLogReader,
};
use crate::lake_part_gc::delete_control::DeleteOwnerAuthorization;
use crate::part_ingest::part_gc_gate::{PartGcAuthority, PartGcDecision, SanctionedPartGc};
use crate::parts::{
    part_log::{LocalObjectStore, ObjectStore},
    provenance::TenantKeySet,
    sha256_hex,
};

/// Directory store only: this type cannot accept a hosted R2 operator.
pub struct LocalDeleteAuthority {
    store: Arc<LocalObjectStore>,
    reader: StorePartLogReader,
    tenant: String,
    policy: std::sync::Mutex<(GcPolicy, Option<std::time::Instant>)>,
    settings: Option<sqlx::PgPool>,
    view: tokio::sync::Mutex<LakePartLogView>,
    signer: SigningKey,
    bronze: std::sync::Mutex<Option<super::local_bronze::LocalBronzeRetention>>,
    /// NAN-4766: which removed parts are already reclaimed and when the
    /// parts prefix was last listed in full.
    reclaim: std::sync::Mutex<Reclaim>,
    /// Test clock (ms); `None` reads the wall clock.
    clock: Option<Arc<std::sync::atomic::AtomicI64>>,
}

/// NAN-4766: least time between full listings of the tenant's parts prefix.
/// Between them a pass lists only the directories of parts the log removed
/// past the grace window and not yet reclaimed, so its cost follows the
/// supersede rate instead of the store's history (every superseded part
/// keeps its provenance file, so a full listing grows by ~1.7k files an hour
/// at 12k eps, forever without a retention policy). The full listing finds
/// what the removal memory cannot: orphans (eligible only after 49 h),
/// retention deletes of parts retired more than 48 h earlier, and removals
/// that aged out of the log's 48 h id memory before they were reclaimed.
/// The first pass of every process is a full listing.
pub const FULL_SWEEP_INTERVAL_MS: i64 = 6 * 3_600_000;

#[derive(Default)]
struct Reclaim {
    /// Removed parts whose directory held no deletable file at the last look
    /// (only kept provenance, or nothing). Pruned to the log's removal memory.
    drained: std::collections::BTreeSet<crate::parts::format::PartId>,
    full_listed_at_ms: Option<i64>,
    /// Keys the last pass listed (tests assert the pass cost).
    last_listed: usize,
}

impl LocalDeleteAuthority {
    pub fn new(
        store: Arc<LocalObjectStore>,
        tenant: &str,
        trusted: TenantKeySet,
        policy: GcPolicy,
        settings: Option<sqlx::PgPool>,
    ) -> Result<Arc<Self>> {
        policy.validate_with_local(true)?;
        // Use the same tenant/key parser as the delete planner.
        crate::parts::format::validate_tenant_uuid(tenant)?;
        let mut seed = [0_u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
        Ok(Arc::new(Self {
            reader: StorePartLogReader::new(store.clone(), tenant, trusted)?,
            store,
            tenant: tenant.to_string(),
            policy: std::sync::Mutex::new((policy, None)),
            settings,
            view: tokio::sync::Mutex::new(LakePartLogView::genesis()),
            signer: SigningKey::from_bytes(&seed),
            bronze: std::sync::Mutex::new(None),
            reclaim: std::sync::Mutex::new(Reclaim::default()),
            clock: None,
        }))
    }

    /// [`Self::new`] on a test clock (ms since the epoch).
    #[cfg(test)]
    pub(crate) fn new_with_clock(
        store: Arc<LocalObjectStore>,
        tenant: &str,
        trusted: TenantKeySet,
        policy: GcPolicy,
        clock: Arc<std::sync::atomic::AtomicI64>,
    ) -> Result<Arc<Self>> {
        let mut authority = Arc::into_inner(Self::new(store, tenant, trusted, policy, None)?)
            .expect("a fresh authority has one owner");
        authority.clock = Some(clock);
        Ok(Arc::new(authority))
    }

    fn now_ms(&self) -> i64 {
        self.clock.as_ref().map_or_else(
            || chrono::Utc::now().timestamp_millis(),
            |clock| clock.load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    fn reclaim(&self) -> Result<std::sync::MutexGuard<'_, Reclaim>> {
        self.reclaim.lock().map_err(|_| anyhow::anyhow!("local GC reclaim lock poisoned"))
    }

    /// Keys the last [`Self::collect`] listed under the parts prefix.
    #[cfg(test)]
    pub(crate) fn last_listed(&self) -> usize {
        self.reclaim().map_or(0, |reclaim| reclaim.last_listed)
    }

    pub fn attach_bronze(&self, bronze: super::local_bronze::LocalBronzeRetention) {
        *self.bronze.lock().expect("bronze retention lock") = Some(bronze);
    }

    /// Read the same open-core settings used by the retention UI. Never
    /// retire using a cached policy after a failed refresh.
    pub async fn refresh_policy(&self) -> Result<GcPolicy> {
        let (cached, refreshed) = *self
            .policy
            .lock()
            .map_err(|_| anyhow::anyhow!("local retention lock poisoned"))?;
        let Some(pool) = &self.settings else {
            return Ok(cached);
        };
        if refreshed.is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(60)) {
            return Ok(cached);
        }
        let row = sqlx::query_as::<_, (bool, i32)>(
            "SELECT retention_enabled, retention_days FROM system_settings WHERE id = 'default'",
        )
        .fetch_one(pool)
        .await
        .context("read trusted-local retention settings")?;
        ensure!(
            (1..=3650).contains(&row.1),
            "local retention days outside 1..=3650"
        );
        let policy = GcPolicy {
            retention_days: row.0.then_some(row.1 as u64),
            ..cached
        };
        *self
            .policy
            .lock()
            .map_err(|_| anyhow::anyhow!("local retention lock poisoned"))? =
            (policy, Some(std::time::Instant::now()));
        Ok(policy)
    }

    /// Reject symlinks at every path component, including the root. The
    /// single writer owns these paths and does not replace them during GC.
    fn safe_path(&self, key: &str) -> Result<std::path::PathBuf> {
        let path = self.store.path(key)?;
        let mut current = std::path::PathBuf::new();
        for component in path.components() {
            current.push(component);
            let meta = std::fs::symlink_metadata(&current)?;
            ensure!(!meta.file_type().is_symlink(), "local GC refuses symlinks");
        }
        Ok(path)
    }

    fn object(&self, key: &str) -> Result<ListedPartObject> {
        self.listed(key, true)
    }

    /// The listing record of one part file. `hashed == false` reads metadata
    /// only and carries a placeholder etag: a cheap eligibility pre-check
    /// (planning never reads the etag) that is never authorized or deleted.
    fn listed(&self, key: &str, hashed: bool) -> Result<ListedPartObject> {
        ensure!(
            parse_part_file_key(key).is_some_and(|parsed| parsed.tenant_uuid == self.tenant),
            "local GC key is not this tenant's part file"
        );
        let path = self.safe_path(key)?;
        let mut file = std::fs::File::open(&path)?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "local GC object is not a regular file");
        let digest = if hashed {
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hash.update(&buffer[..read]);
            }
            hex::encode(hash.finalize())
        } else {
            "unhashed".to_string()
        };
        Ok(ListedPartObject {
            key: key.to_string(),
            strong_etag: format!("\"{digest}\""),
            content_length: metadata.len(),
            uploaded_at_ms: i64::try_from(
                metadata
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis(),
            )?,
        })
    }

    /// Fold at most [`MAX_LOG_ENTRIES_PER_PASS`] new verified entries into
    /// the view (one bounded step: the caller holds the ingestor mutex).
    /// True when the view reached the log head. The view lives in memory, so
    /// a restart folds from genesis again; NAN-3818: the ingest scheduler
    /// continues an incomplete fold every few seconds instead of once per
    /// 10-min pass.
    async fn catch_up(&self, view: &mut LakePartLogView) -> Result<bool> {
        let applied = catch_up_view_bounded(view, &self.reader, MAX_LOG_ENTRIES_PER_PASS).await?;
        let complete = applied < MAX_LOG_ENTRIES_PER_PASS || {
            // A full step may have ended exactly at the head: probe the next
            // entry so a log of N x the bound folds in N steps, not N + 1.
            let next = view.head_seq().map_or(0, |seq| seq + 1);
            self.reader.verified_entry(next).await?.is_none()
        };
        ensure!(
            view.head_seq().is_some(),
            "local GC requires a genesis entry"
        );
        Ok(complete)
    }

    /// Every permit/prepare/retire check plans against the complete log.
    async fn require_caught_up(&self, view: &mut LakePartLogView) -> Result<()> {
        ensure!(
            self.catch_up(view).await?,
            "local GC log catch-up incomplete; retry next pass"
        );
        Ok(())
    }

    async fn check_request(&self, request: &LakePartDeleteRequest) -> Result<()> {
        request.validate_with_local(true)?;
        ensure!(
            request.tenant_uuid == self.tenant && request.tenant_id == self.tenant,
            "local GC request names another tenant"
        );
        let path = self.store.path(&request.key)?;
        let present = path.try_exists()?;
        let object = if present {
            Some(self.object(&request.key)?)
        } else {
            let prepared = format!(
                "lake/parts/v1/tenant={}/gc/prepared/{}.json",
                self.tenant,
                request.digest_with_local(true)?
            );
            ensure!(
                self.store.get(&prepared).await?.as_deref()
                    == Some(serde_json::to_vec(request)?.as_slice()),
                "absent object has no matching GC tombstone"
            );
            // Absence permits receipt recovery only; it never authorizes an unlink.
            None
        };
        let mut view = self.view.lock().await;
        self.require_caught_up(&mut view).await?;
        let live_keys = live_part_keys(&self.tenant, &mut view, &self.reader).await?;
        if object.is_none() {
            let parsed = parse_part_file_key(&request.key).context("invalid recovery key")?;
            ensure!(
                !view.is_live(&parsed.part_id) && !live_keys.contains(&request.key),
                "recovered GC key became live"
            );
            return Ok(());
        }
        let policy = self.refresh_policy().await?;
        let report = plan_local(
            &self.tenant,
            &view,
            &live_keys,
            &[object.expect("present object")],
            self.now_ms(),
            &policy,
        )?;
        ensure!(
            report.requests.first() == Some(request),
            "local GC request is no longer eligible"
        );
        Ok(())
    }

    fn permit_message(permit: &LakePartDeletePermit) -> String {
        let auth = &permit.owner_authorization;
        format!(
            "{}:{}:{}",
            auth.identity_sha256, auth.issued_at, auth.expires_at
        )
    }

    fn check_permit(&self, permit: &LakePartDeletePermit) -> Result<()> {
        permit.verify_with_local(&permit.request, chrono::Utc::now(), true)?;
        ensure!(
            permit.owner_authorization.signer_key_id == "trusted-local-gc",
            "foreign GC signer"
        );
        let signature =
            Signature::from_slice(&STANDARD.decode(&permit.owner_authorization.signature_base64)?)?;
        self.signer
            .verifying_key()
            .verify_strict(Self::permit_message(permit).as_bytes(), &signature)?;
        Ok(())
    }

    fn marker_key(&self, permit: &LakePartDeletePermit, kind: &str) -> String {
        format!(
            "lake/parts/v1/tenant={}/gc/{kind}/{}.json",
            self.tenant,
            permit
                .request
                .digest_with_local(true)
                .expect("validated request")
        )
    }

    pub async fn collect(&self) -> Result<PassReport> {
        let policy = self.refresh_policy().await?;
        let prefix = format!("lake/parts/v1/tenant={}/parts/", self.tenant);
        let mut view = self.view.lock().await;
        if !self.catch_up(&mut view).await? {
            // NAN-3818: one bounded step folded; nothing is planned, prepared
            // or deleted on a partial view. A routine pause (not a failure):
            // ingest runs the next step within seconds.
            return Ok(PassReport {
                paused_reason: Some(LOG_CATCHING_UP.into()),
                ..PassReport::default()
            });
        }
        let live_keys = live_part_keys(&self.tenant, &mut view, &self.reader).await?;
        let now_ms = self.now_ms();
        // NAN-4766: list in full on the first pass and every
        // FULL_SWEEP_INTERVAL_MS; otherwise only the directories of removed
        // parts past the grace window that are not yet reclaimed. Selection
        // only: every listed file still goes through the same planner, and
        // every permit and delete re-checks the complete log.
        let full = self.reclaim()?.full_listed_at_ms
            .is_none_or(|at| now_ms.saturating_sub(at) >= FULL_SWEEP_INTERVAL_MS);
        let (keys, candidates) = if full {
            (self.store.list(&prefix).await?, None)
        } else {
            let cutoff = now_ms.saturating_sub((policy.grace_seconds as i64).saturating_mul(1_000));
            let candidates: Vec<(crate::parts::format::PartId, String)> = {
                let reclaim = self.reclaim()?;
                let live = view.live();
                live.removed_before(cutoff)
                    .filter(|id| !reclaim.drained.contains(*id))
                    .filter_map(|id| {
                        let part = live.removed_ref(id)?;
                        let keys = crate::parts::format::PartKeys::new(&self.tenant, part.level, part.event_hour, id).ok()?;
                        Some((id.clone(), format!("{}/", keys.dir)))
                    })
                    .collect()
            };
            let mut keys = Vec::new();
            for (_, dir) in &candidates {
                keys.extend(self.store.list(dir).await?);
            }
            (keys, Some(candidates))
        };
        let listed = keys.len();
        // Parts are immutable, and GC runs under the ingestor mutex. A
        // fresh log check is still performed for every permit and delete.
        let mut objects = Vec::new();
        let mut more_eligible = false;
        // Parts with a deletable file at this listing (not reclaimed yet).
        let mut unreclaimed = std::collections::BTreeSet::new();
        let eligible = |object: &ListedPartObject| -> Result<bool> {
            Ok(!plan_local(
                &self.tenant,
                &view,
                &live_keys,
                std::slice::from_ref(object),
                now_ms,
                &policy,
            )?
            .requests
            .is_empty())
        };
        for key in keys {
            let Some(parsed) = parse_part_file_key(&key) else {
                continue;
            };
            if view.is_live(&parsed.part_id) || live_keys.contains(&key) {
                continue;
            }
            // NAN-4728: plan on metadata first; hash only eligible files (kept
            // provenance and in-grace files are no longer read every pass).
            if !eligible(&self.listed(&key, false)?)? {
                continue;
            }
            unreclaimed.insert(parsed.part_id.clone());
            if objects.len() >= policy.max_requests {
                more_eligible = true;
                break;
            }
            let object = self.object(&key)?;
            if eligible(&object)? {
                objects.push(object);
            }
        }
        let mut planned = plan_local(
            &self.tenant,
            &view,
            &live_keys,
            &objects,
            now_ms,
            &policy,
        )?;
        {
            let mut reclaim = self.reclaim()?;
            reclaim.last_listed = listed;
            // An incomplete full sweep must stay full on the catch-up
            // cadence: incremental listing cannot recover old removals,
            // orphans, or provenance that only retention now makes eligible.
            if full && !more_eligible {
                reclaim.full_listed_at_ms = Some(now_ms);
            }
            // A part is reclaimed once a complete look at its directory found
            // nothing deletable; a batch cut short proves nothing.
            if let (Some(candidates), false) = (&candidates, more_eligible) {
                reclaim.drained.extend(candidates.iter()
                    .filter(|(id, _)| !unreclaimed.contains(id))
                    .map(|(id, _)| id.clone()));
            }
            let live = view.live();
            reclaim.drained.retain(|id| live.removed_ref(id).is_some());
        }
        drop(view);
        // Recover unlink-before-receipt crashes using durable prepare records.
        let prepared_prefix = format!("lake/parts/v1/tenant={}/gc/prepared/", self.tenant);
        for key in self.store.list(&prepared_prefix).await? {
            if planned.requests.len() >= policy.max_requests {
                break;
            }
            let bytes = self
                .store
                .get(&key)
                .await?
                .context("GC prepare record disappeared")?;
            ensure!(bytes.len() <= 16 * 1024, "GC prepare record too large");
            let request: LakePartDeleteRequest = serde_json::from_slice(&bytes)?;
            request.validate_with_local(true)?;
            ensure!(
                request.tenant_uuid == self.tenant && request.tenant_id == self.tenant,
                "foreign GC prepare record"
            );
            if !self.store.path(&request.key)?.try_exists()? {
                planned.requests.push(request);
            }
        }
        let mut report = execute_local(self, &planned.requests).await;
        report.plan_skipped = planned.skipped;
        // NAN-4728: a full batch with progress continues soon (ingest's
        // catch-up cadence); a batch that deleted nothing, or stopped early
        // (a pause is not progress), waits the interval.
        report.more_eligible = more_eligible && report.deleted > 0 && report.paused_reason.is_none();
        let bronze = self.bronze.lock().expect("bronze retention lock").take();
        if let Some(bronze) = bronze {
            let result = bronze
                .collect(policy.retention_days, chrono::Utc::now().timestamp_millis())
                .await;
            *self.bronze.lock().expect("bronze retention lock") = Some(bronze);
            tracing::info!(
                deleted = result?,
                "trusted-local bronze retention completed"
            );
        }
        Ok(report)
    }
}

#[async_trait]
impl LakePartDeleteAuthority for LocalDeleteAuthority {
    async fn worker_supports_lake_part_delete(&self) -> Result<bool> {
        Ok(true)
    }

    async fn authorize(&self, request: &LakePartDeleteRequest) -> Result<LakePartDeletePermit> {
        self.check_request(request).await?;
        let now = chrono::Utc::now();
        let digest = request.digest_with_local(true)?;
        let mut permit = LakePartDeletePermit {
            request: request.clone(),
            permit_id: format!("lpd_{digest}"),
            owner_authorization: DeleteOwnerAuthorization {
                schema_version: 1,
                signer_key_id: "trusted-local-gc".into(),
                issued_at: now.to_rfc3339(),
                expires_at: (now + chrono::Duration::minutes(2)).to_rfc3339(),
                identity_sha256: digest,
                signature_base64: String::new(),
            },
        };
        permit.owner_authorization.signature_base64 = STANDARD.encode(
            self.signer
                .sign(Self::permit_message(&permit).as_bytes())
                .to_bytes(),
        );
        Ok(permit)
    }

    async fn prepare(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeletePermit> {
        self.check_permit(permit)?;
        self.check_request(&permit.request).await?;
        // Tombstone binds the immutable object identity, rather than the
        // expiring permit, so retries after a restart remain idempotent.
        let bytes = serde_json::to_vec(&permit.request)?;
        let key = self.marker_key(permit, "prepared");
        if !self.store.put_if_absent(&key, &bytes).await? {
            ensure!(
                self.store.get(&key).await?.as_deref() == Some(bytes.as_slice()),
                "local GC tombstone differs"
            );
        }
        Ok(permit.clone())
    }

    async fn retire(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeleteReceipt> {
        self.check_permit(permit)?;
        let prepared = self
            .store
            .get(&self.marker_key(permit, "prepared"))
            .await?
            .context("local GC has no durable tombstone")?;
        ensure!(
            prepared == serde_json::to_vec(&permit.request)?,
            "local GC tombstone differs"
        );
        self.check_request(&permit.request).await?;
        let path = self.store.path(&permit.request.key)?;
        if path.try_exists()? {
            self.safe_path(&permit.request.key)?;
            self.store.delete(&permit.request.key).await?;
        }
        let parent_key = permit
            .request
            .key
            .rsplit_once('/')
            .context("part file has no parent")?
            .0;
        let parent = self.safe_path(parent_key)?;
        std::fs::File::open(parent)?.sync_all()?;
        ensure!(!path.try_exists()?, "local GC final HEAD is not absent");
        let identity = permit.request.digest_with_local(true)?;
        let receipt = LakePartDeleteReceipt {
            schema_version:
                crate::lake_part_gc::delete_control::DELETE_CONTROL_SCHEMA_VERSION,
            permit_id: permit.permit_id.clone(),
            identity_sha256: identity.clone(),
            receipt_sha256: sha256_hex(format!("trusted-local-gc:{identity}:absent").as_bytes()),
            state: "receipt_appended".into(),
            final_head_absent: true,
        };
        self.store
            .put_if_absent(
                &self.marker_key(permit, "receipts"),
                &serde_json::to_vec(&receipt)?,
            )
            .await?;
        self.store
            .delete(&self.marker_key(permit, "prepared"))
            .await?;
        std::fs::File::open(
            self.store
                .path(&self.marker_key(permit, "prepared"))?
                .parent()
                .unwrap(),
        )?
        .sync_all()?;
        Ok(receipt)
    }
}

#[async_trait]
impl SanctionedPartGc for LocalDeleteAuthority {
    async fn run_pass(&self, _now_ms: i64) -> Result<PassReport> {
        self.collect().await
    }
}

pub struct LocalPartGcAuthority(pub Arc<LocalDeleteAuthority>);

#[async_trait]
impl PartGcAuthority for LocalPartGcAuthority {
    async fn decision(&self, _now_ms: i64) -> Result<PartGcDecision> {
        Ok(PartGcDecision::Sanctioned(self.0.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lake_part_gc::{
        planner::tests::{id, key, Chain, T0},
        request::tests::TENANT_UUID,
    };
    use crate::parts::{
        format::LogKeys,
        levels::Level,
        part_log::{LogOp, RetireReason},
    };

    async fn persist(store: &LocalObjectStore, chain: &Chain) {
        let keys = LogKeys::new(TENANT_UUID).unwrap();
        for (entry, _) in &chain.entries {
            store
                .put_if_absent(&keys.entry(entry.seq), &entry.to_bytes().unwrap())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn live_parts_are_protected_and_retired_bytes_are_freed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path()).unwrap());
        let mut chain = Chain::new();
        chain.add(1, T0 + 1);
        persist(&store, &chain).await;
        let key = key(1, Level::L0, "data-00000.parquet");
        store.put(&key, b"retained part bytes").await.unwrap();
        let authority = LocalDeleteAuthority::new(
            store.clone(),
            TENANT_UUID,
            TenantKeySet::new(vec![]),
            GcPolicy {
                retention_days: Some(7),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(authority.collect().await.unwrap().deleted, 0);
        assert!(store.get(&key).await.unwrap().is_some());
        chain.push(
            LogOp::Retire {
                parts: vec![id(1)],
                reason: RetireReason::Retention,
                deletion_unit: "local".into(),
            },
            T0 + 2,
        );
        persist(&store, &chain).await;
        let report = authority.collect().await.unwrap();
        assert_eq!(report.deleted, 1, "{report:?}");
        assert!(store.get(&key).await.unwrap().is_none());
        let log = LogKeys::new(TENANT_UUID).unwrap();
        assert!(store.get(&log.entry(0)).await.unwrap().is_some());
        assert!(store.get(&log.entry(2)).await.unwrap().is_some());
        assert_eq!(authority.collect().await.unwrap().deleted, 0);
    }

    /// NAN-3818: after a restart the view folds from genesis one bounded step
    /// per pass. A log of N x [`MAX_LOG_ENTRIES_PER_PASS`] entries must catch
    /// up in N steps a few seconds apart (ingest's catch-up cadence), not N
    /// 10-min pass intervals, and nothing may be deleted before the last step.
    #[tokio::test]
    async fn a_long_log_catches_up_in_short_bounded_steps_before_any_delete() {
        use crate::part_ingest::ingest::{
            pass_is_catching_up, sanctioned_pass_due, SANCTIONED_GC_CATCH_UP_INTERVAL_MS,
            SANCTIONED_GC_INTERVAL_MS,
        };
        const STEPS: u64 = 3;
        let total = STEPS * MAX_LOG_ENTRIES_PER_PASS;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path()).unwrap());
        let mut chain = Chain::new();
        chain.add(1, T0 + 1);
        // Live filler parts (no files), then the retire as the very last
        // entry: only a complete view knows part 1 is gone.
        let mut n = 2;
        while (chain.entries.len() as u64) < total - 1 {
            chain.add(n, T0 + n as i64);
            n += 1;
        }
        chain.push(
            LogOp::Retire {
                parts: vec![id(1)],
                reason: RetireReason::Retention,
                deletion_unit: "local".into(),
            },
            T0 + n as i64,
        );
        assert_eq!(chain.entries.len() as u64, total);
        persist(&store, &chain).await;
        let key = key(1, Level::L0, "data-00000.parquet");
        store.put(&key, b"retired part bytes").await.unwrap();
        let authority = LocalDeleteAuthority::new(
            store.clone(),
            TENANT_UUID,
            TenantKeySet::new(vec![]),
            GcPolicy {
                retention_days: Some(7),
                ..Default::default()
            },
            None,
        )
        .unwrap();

        // Ingest's scheduler on a 1 s tick: the restart's first pass runs at
        // once, later ones when `sanctioned_pass_due` allows.
        let started = 1_800_000_000_000_i64;
        let (mut last, mut catching_up, mut steps) = (None, false, 0_u64);
        let mut now = started;
        let finished = loop {
            assert!(
                now - started < SANCTIONED_GC_INTERVAL_MS,
                "catch-up waited a full pass interval ({steps} steps)"
            );
            if sanctioned_pass_due(last, catching_up, now) {
                last = Some(now);
                let report = authority.collect().await.unwrap();
                steps += 1;
                catching_up = pass_is_catching_up(&report);
                if catching_up {
                    assert_eq!(report.deleted, 0, "step {steps}: {report:?}");
                    assert_eq!(report.planned, 0, "step {steps}: {report:?}");
                    assert!(store.get(&key).await.unwrap().is_some(), "deleted on a partial view");
                    assert_eq!(
                        authority.view.lock().await.head_seq(),
                        Some(steps * MAX_LOG_ENTRIES_PER_PASS - 1),
                        "each step folds exactly one bounded chunk"
                    );
                } else {
                    assert!(report.paused_reason.is_none(), "{report:?}");
                    break (now, report);
                }
            }
            now += 1_000;
        };
        let (finished_at, report) = finished;
        assert_eq!(steps, STEPS, "N x bound entries fold in N steps");
        assert_eq!(
            finished_at - started,
            (STEPS as i64 - 1) * SANCTIONED_GC_CATCH_UP_INTERVAL_MS
        );
        assert_eq!(report.deleted, 1, "{report:?}");
        assert!(store.get(&key).await.unwrap().is_none());
        // Caught up: back on the ordinary pass interval.
        assert!(!sanctioned_pass_due(last, catching_up, finished_at + SANCTIONED_GC_CATCH_UP_INTERVAL_MS));
        assert!(sanctioned_pass_due(last, catching_up, finished_at + SANCTIONED_GC_INTERVAL_MS));
    }

    /// NAN-4728 (NAN-4689 open-core soak, ~12k eps): one bounded pass
    /// (`max_requests` = 512 files) per 10-min interval reclaimed ~3k files
    /// an hour while L0 -> minute merges superseded ~10k+ (6 files a part):
    /// the local store grew without bound. With the production policy, a
    /// backlog above one batch now drains in bounded passes on the catch-up
    /// cadence, well inside one pass interval; provenance (kept without a
    /// retention policy) and the live merge output stay, and once drained
    /// the scheduler is back on the ordinary interval.
    #[tokio::test]
    async fn a_merge_backlog_above_one_batch_drains_within_one_pass_interval() {
        use crate::part_ingest::ingest::{
            pass_is_catching_up, sanctioned_pass_due, SANCTIONED_GC_CATCH_UP_INTERVAL_MS,
            SANCTIONED_GC_INTERVAL_MS,
        };
        const FILES: [&str; 5] = [
            "data-00000.parquet",
            "tokens-00000.nti",
            "partials/rollup.parquet",
            "partials/prevalence.parquet",
            "partials/entity_ranges.parquet",
        ];
        let policy = GcPolicy::default();
        // Two full batches and one more file: three passes.
        let parts = (2 * policy.max_requests as u64) / FILES.len() as u64 + 1;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path()).unwrap());
        let mut chain = Chain::new();
        let mut superseded = Vec::new();
        for n in 1..=parts {
            chain.add(n, T0 + n as i64);
            for file in FILES {
                let key = key(n, Level::L0, file);
                store.put(&key, b"superseded part bytes").await.unwrap();
                superseded.push(key);
            }
            store.put(&key(n, Level::L0, "provenance.json"), b"{}").await.unwrap();
        }
        let output = parts + 1;
        chain.push(
            LogOp::Merge {
                output: crate::lake_part_gc::planner::tests::part_ref(output, Level::Minute),
                supersedes: (1..=parts).map(id).collect(),
            },
            T0 + 10_000,
        );
        persist(&store, &chain).await;
        let live = key(output, Level::Minute, "data-00000.parquet");
        store.put(&live, b"merged output").await.unwrap();
        assert!(superseded.len() > 2 * policy.max_requests);
        let authority =
            LocalDeleteAuthority::new(store.clone(), TENANT_UUID, TenantKeySet::new(vec![]), policy, None)
                .unwrap();

        // Ingest's scheduler on a 1 s tick, as in production.
        let started = 1_800_000_000_000_i64;
        let (mut last, mut catching_up, mut passes, mut deleted) = (None, false, 0_u64, 0_u64);
        let mut now = started;
        let drained_at = loop {
            assert!(
                now - started < SANCTIONED_GC_INTERVAL_MS,
                "the backlog waited a full pass interval ({passes} passes, {deleted} deleted)"
            );
            if sanctioned_pass_due(last, catching_up, now) {
                last = Some(now);
                let report = authority.collect().await.unwrap();
                passes += 1;
                deleted += report.deleted;
                assert!(report.deleted <= policy.max_requests as u64, "{report:?}");
                assert!(report.paused_reason.is_none(), "{report:?}");
                catching_up = pass_is_catching_up(&report);
                assert_eq!(catching_up, report.more_eligible, "{report:?}");
                if !catching_up {
                    break now;
                }
            }
            now += 1_000;
        };
        assert_eq!(passes, 3, "two full batches, then the remainder");
        assert_eq!(drained_at - started, 2 * SANCTIONED_GC_CATCH_UP_INTERVAL_MS);
        assert_eq!(deleted, superseded.len() as u64);
        for key in &superseded {
            assert!(store.get(key).await.unwrap().is_none(), "{key} survived");
        }
        assert!(store.get(&live).await.unwrap().is_some(), "the live merge output is kept");
        assert!(
            store.get(&key(1, Level::L0, "provenance.json")).await.unwrap().is_some(),
            "provenance stays without a retention policy"
        );
        // Drained: back on the ordinary pass interval.
        assert!(!sanctioned_pass_due(last, catching_up, drained_at + SANCTIONED_GC_CATCH_UP_INTERVAL_MS));
        assert!(sanctioned_pass_due(last, catching_up, drained_at + SANCTIONED_GC_INTERVAL_MS));
    }

    /// NAN-4728: `more_eligible` means another deletable file exists, not
    /// another listed one. Exactly one full batch followed only by kept
    /// files (provenance without a retention policy) ends the drain: no
    /// extra pass on the catch-up cadence.
    #[tokio::test]
    async fn an_exactly_full_batch_followed_by_kept_files_is_not_more_eligible() {
        const FILES: [&str; 5] = [
            "data-00000.parquet",
            "tokens-00000.nti",
            "partials/rollup.parquet",
            "partials/prevalence.parquet",
            "partials/entity_ranges.parquet",
        ];
        let policy = GcPolicy { max_requests: 2 * FILES.len(), ..GcPolicy::default() };
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path()).unwrap());
        let mut chain = Chain::new();
        for n in 1..=3_u64 {
            chain.add(n, T0 + n as i64);
            // Parts 1 and 2 fill the batch; part 3 keeps only provenance,
            // listed after every eligible file.
            if n < 3 {
                for file in FILES {
                    store.put(&key(n, Level::L0, file), b"superseded").await.unwrap();
                }
            }
            store.put(&key(n, Level::L0, "provenance.json"), b"{}").await.unwrap();
        }
        chain.push(
            LogOp::Merge {
                output: crate::lake_part_gc::planner::tests::part_ref(4, Level::Minute),
                supersedes: (1..=3).map(id).collect(),
            },
            T0 + 10_000,
        );
        persist(&store, &chain).await;
        store.put(&key(4, Level::Minute, "data-00000.parquet"), b"merged").await.unwrap();
        let authority =
            LocalDeleteAuthority::new(store.clone(), TENANT_UUID, TenantKeySet::new(vec![]), policy, None)
                .unwrap();
        let report = authority.collect().await.unwrap();
        assert_eq!(report.deleted, policy.max_requests as u64, "{report:?}");
        assert!(!report.more_eligible, "only kept files remain: {report:?}");
        assert!(store.get(&key(3, Level::L0, "provenance.json")).await.unwrap().is_some());
    }

    #[test]
    fn only_a_progressing_fold_shortens_the_pass_interval() {
        use crate::part_ingest::ingest::pass_is_catching_up;
        let paused = |reason: &str, backoff| PassReport {
            paused_reason: Some(reason.into()),
            backoff,
            ..PassReport::default()
        };
        assert!(pass_is_catching_up(&paused(LOG_CATCHING_UP, false)));
        assert!(!pass_is_catching_up(&paused(LOG_CATCHING_UP, true)));
        assert!(!pass_is_catching_up(&paused("log_unverifiable", true)));
        assert!(!pass_is_catching_up(&paused("index_route_not_served", false)));
        assert!(!pass_is_catching_up(&PassReport::default()));
        // NAN-4728: a full trusted-local batch with progress continues soon,
        // unless the pass asked for a back-off.
        let more = |backoff| PassReport { more_eligible: true, backoff, ..PassReport::default() };
        assert!(pass_is_catching_up(&more(false)));
        assert!(!pass_is_catching_up(&more(true)));
    }

    /// NAN-4728: back-to-back catch-up passes must not starve ingest. A pass
    /// that held the ingestor for 10 s waits 4 x that from its start (GC at
    /// most a quarter of wall time); a cheap one keeps the 5 s catch-up
    /// cadence, a very slow one never waits past the ordinary interval, and
    /// outside catch-up the busy time changes nothing.
    #[test]
    fn catch_up_passes_are_paced_by_their_busy_time() {
        use crate::part_ingest::ingest::{
            sanctioned_pass_due_paced as due, SANCTIONED_GC_CATCH_UP_INTERVAL_MS as CATCH_UP,
            SANCTIONED_GC_CATCH_UP_PACE as PACE, SANCTIONED_GC_INTERVAL_MS as INTERVAL,
        };
        let last = Some(1_000_000_i64);
        let at = |gap| 1_000_000 + gap;
        // Cheap step (log fold, small batch): the 5 s cadence.
        assert!(!due(last, true, 200, at(CATCH_UP - 1)));
        assert!(due(last, true, 200, at(CATCH_UP)));
        // A 10 s pass: next start 40 s after it started, not 5 s.
        assert_eq!(PACE, 4);
        assert!(!due(last, true, 10_000, at(CATCH_UP)));
        assert!(!due(last, true, 10_000, at(40_000 - 1)));
        assert!(due(last, true, 10_000, at(40_000)));
        // Never slower than the ordinary interval.
        assert!(due(last, true, INTERVAL, at(INTERVAL)));
        assert!(due(last, true, i64::MAX, at(INTERVAL)));
        // Not catching up: the ordinary interval regardless of busy time.
        assert!(!due(last, false, 0, at(INTERVAL - 1)));
        assert!(due(last, false, 10_000, at(INTERVAL)));
        assert!(due(None, true, i64::MAX, 0));
    }

    #[tokio::test]
    async fn unlink_before_receipt_is_recovered_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path()).unwrap());
        let mut chain = Chain::new();
        chain.add(1, T0 + 1).push(
            LogOp::Retire {
                parts: vec![id(1)],
                reason: RetireReason::Retention,
                deletion_unit: "local".into(),
            },
            T0 + 2,
        );
        persist(&store, &chain).await;
        let key = key(1, Level::L0, "data-00000.parquet");
        store.put(&key, b"expired bytes").await.unwrap();
        let create = || {
            LocalDeleteAuthority::new(
                store.clone(),
                TENANT_UUID,
                TenantKeySet::new(vec![]),
                GcPolicy {
                    retention_days: Some(7),
                    ..Default::default()
                },
                None,
            )
            .unwrap()
        };
        let authority = create();
        let request = plan_local(
            TENANT_UUID,
            &chain.view(),
            &Default::default(),
            &[authority.object(&key).unwrap()],
            chrono::Utc::now().timestamp_millis(),
            &authority.refresh_policy().await.unwrap(),
        )
        .unwrap()
        .requests
        .remove(0);
        let permit = authority.authorize(&request).await.unwrap();
        authority.prepare(&permit).await.unwrap();
        store.delete(&key).await.unwrap();
        drop(authority);
        let restarted = create();
        assert_eq!(restarted.collect().await.unwrap().deleted, 1);
        assert_eq!(restarted.collect().await.unwrap().deleted, 0);
        assert!(store.get(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn changed_identity_foreign_tenants_and_symlinks_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path()).unwrap());
        let mut chain = Chain::new();
        chain.add(1, T0 + 1).push(
            LogOp::Retire {
                parts: vec![id(1)],
                reason: RetireReason::Retention,
                deletion_unit: "local".into(),
            },
            T0 + 2,
        );
        persist(&store, &chain).await;
        let key = key(1, Level::L0, "data-00000.parquet");
        store.put(&key, b"old bytes").await.unwrap();
        let authority = LocalDeleteAuthority::new(
            store.clone(),
            TENANT_UUID,
            TenantKeySet::new(vec![]),
            GcPolicy {
                retention_days: Some(7),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let object = authority.object(&key).unwrap();
        let mut view = chain.view();
        let live_keys = live_part_keys(TENANT_UUID, &mut view, &authority.reader)
            .await
            .unwrap();
        let request = plan_local(
            TENANT_UUID,
            &view,
            &live_keys,
            &[object],
            chrono::Utc::now().timestamp_millis(),
            &authority.refresh_policy().await.unwrap(),
        )
        .unwrap()
        .requests
        .remove(0);
        let permit = authority.authorize(&request).await.unwrap();
        authority.prepare(&permit).await.unwrap();
        store.put(&key, b"changed bytes").await.unwrap();
        assert!(authority.retire(&permit).await.is_err());
        assert_eq!(store.get(&key).await.unwrap().unwrap(), b"changed bytes");
        let mut foreign = request;
        foreign.tenant_uuid = uuid::Uuid::new_v4().to_string();
        assert!(authority.authorize(&foreign).await.is_err());
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::remove_file(store.path(&key).unwrap()).unwrap();
        std::os::unix::fs::symlink(outside.path(), store.path(&key).unwrap()).unwrap();
        assert!(authority.object(&key).is_err());
        assert!(outside.path().exists());
    }

    /// A full sweep must drain beyond one batch even when incremental
    /// listing cannot find its remaining files: forgotten removals, orphans,
    /// and provenance that becomes eligible for retention later.
    #[tokio::test]
    async fn full_sweeps_drain_old_removals_orphans_and_late_retention() {
        use crate::lake_part_gc::planner::tests::part_ref;
        use crate::part_ingest::ingest::{pass_is_catching_up, SANCTIONED_GC_CATCH_UP_INTERVAL_MS};
        use crate::part_ingest::part_gc_gate::SanctionedPartGc;
        use crate::parts::part_log::ID_MEMORY_MS;
        use std::sync::atomic::{AtomicI64, Ordering};

        const HOUR: i64 = 3_600_000;
        // Both the process's initial sweep and a later six-hour sweep.
        for initial_sweep in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let store = Arc::new(LocalObjectStore::new(dir.path()).unwrap());
            let mut chain = Chain::new();
            for n in 1..=3 {
                chain.add(n, T0 + n as i64);
                for file in ["data-00000.parquet", "tokens-00000.nti", "provenance.json"] {
                    store.put(&key(n, Level::L0, file), b"old input").await.unwrap();
                }
            }
            persist(&store, &chain).await;
            let clock = Arc::new(AtomicI64::new(T0 + HOUR));
            let authority = LocalDeleteAuthority::new_with_clock(
                store.clone(), TENANT_UUID, TenantKeySet::new(vec![]),
                GcPolicy { max_requests: 2, ..GcPolicy::default() }, clock.clone(),
            ).unwrap();
            if !initial_sweep {
                assert_eq!(authority.run_pass(T0 + HOUR).await.unwrap().deleted, 0);
            }
            chain.push(LogOp::Merge {
                output: part_ref(4, Level::Minute),
                supersedes: (1..=3).map(id).collect(),
            }, T0 + 2 * HOUR);
            // Advance the verified log beyond its removal-memory horizon.
            let mut now = T0 + ID_MEMORY_MS + 3 * HOUR;
            let mut recent = part_ref(5, Level::L0);
            recent.part_id = crate::parts::format::PartId::parse(
                &format!("{now:013}-{:016x}", 5),
            ).unwrap();
            chain.push(LogOp::Add {
                parts: vec![recent], consumed: vec![crate::parts::part_log::SourceRef {
                    key: "bronze/recent".into(), version: "1".into(), sha256: "d".repeat(64),
                }], edge_log: None,
            }, now);
            let view = chain.view();
            assert!(view.live().removed_ref(&id(1)).is_none());
            assert!(view.removal(&id(1)).unwrap().is_some());
            persist(&store, &chain).await;
            let live = key(4, Level::Minute, "data-00000.parquet");
            store.put(&live, b"live output").await.unwrap();
            let orphan = key(90, Level::L0, "data-00000.parquet");
            store.put(&orphan, b"orphan").await.unwrap();
            std::fs::File::open(store.path(&orphan).unwrap()).unwrap().set_times(
                std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_millis(T0 as u64),
                ),
            ).unwrap();

            // Six superseded files and an orphan drain on the production
            // catch-up cadence, without waiting another six hours.
            for expected in [2, 2, 2, 1] {
                clock.store(now, Ordering::SeqCst);
                let report = authority.run_pass(now).await.unwrap();
                assert_eq!(report.deleted, expected, "initial={initial_sweep}: {report:?}");
                assert_eq!(pass_is_catching_up(&report), expected == 2, "{report:?}");
                now += SANCTIONED_GC_CATCH_UP_INTERVAL_MS;
            }
            assert!(store.get(&orphan).await.unwrap().is_none());
            for n in 1..=3 {
                for file in ["data-00000.parquet", "tokens-00000.nti"] {
                    assert!(store.get(&key(n, Level::L0, file)).await.unwrap().is_none());
                }
                assert!(store.get(&key(n, Level::L0, "provenance.json")).await.unwrap().is_some());
            }
            assert!(store.get(&live).await.unwrap().is_some());

            // Retention later makes the kept provenance eligible. It must
            // wait for the next full sweep, then drain all of its batches.
            authority.policy.lock().unwrap().0.retention_days = Some(1);
            let next_full = now - SANCTIONED_GC_CATCH_UP_INTERVAL_MS + FULL_SWEEP_INTERVAL_MS;
            clock.store(next_full - 1, Ordering::SeqCst);
            assert_eq!(authority.run_pass(next_full - 1).await.unwrap().deleted, 0);
            now = next_full;
            for expected in [2, 1] {
                clock.store(now, Ordering::SeqCst);
                let report = authority.run_pass(now).await.unwrap();
                assert_eq!(report.deleted, expected, "initial={initial_sweep}: {report:?}");
                assert_eq!(pass_is_catching_up(&report), expected == 2, "{report:?}");
                now += SANCTIONED_GC_CATCH_UP_INTERVAL_MS;
            }
            for n in 1..=3 {
                assert!(store.get(&key(n, Level::L0, "provenance.json")).await.unwrap().is_none());
            }
            assert!(store.get(&live).await.unwrap().is_some());
        }
    }

    /// NAN-4766: GC keeps pace with a steady merge rate. A four-hour run on
    /// a fake clock with ingest's production scheduler
    /// (`sanctioned_pass_due_paced` + `pass_is_catching_up`) driving the
    /// production pass (`SanctionedPartGc::run_pass`) over a real directory
    /// store: 6 L0 parts a minute, each minute's L0s superseded by an M
    /// merge, each hour's Ms by an H merge (~21 superseded files a minute).
    /// Every superseded file is gone within grace + one pass interval (so
    /// the superseded-pending set is bounded by that window), its bytes
    /// plateau, no live file is ever deleted, and a pass between full
    /// listings lists only the newly reclaimable parts, not the store's
    /// history (the kept provenance of every part ever superseded).
    #[tokio::test]
    async fn gc_keeps_pace_with_a_steady_merge_rate_and_superseded_disk_plateaus() {
        use crate::lake_part_gc::planner::tests::part_ref;
        use crate::part_ingest::ingest::{pass_is_catching_up, sanctioned_pass_due_paced, SANCTIONED_GC_INTERVAL_MS};
        use crate::part_ingest::part_gc_gate::SanctionedPartGc;
        use crate::parts::part_log::{PartRef, SourceRef};
        use crate::parts::format::PartId;
        use std::collections::BTreeMap;
        use std::sync::atomic::{AtomicI64, Ordering};
        const MINUTE: i64 = 60_000;
        const HOUR: i64 = 3_600_000;
        const HOURS: i64 = 4;
        const L0_PER_MINUTE: u64 = 6;
        const TICK: i64 = 5_000;
        const FILES: [&str; 3] = ["data-00000.parquet", "tokens-00000.nti", "partials/rollup.parquet"];
        // Superseded files a minute: the L0s, plus the Ms at each hour.
        const RATE: usize = (L0_PER_MINUTE as usize + 1) * FILES.len();
        let body = vec![7_u8; 1024];

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path()).unwrap());
        // A past, hour-aligned timeline: permits still expire on the wall clock.
        let start = (chrono::Utc::now().timestamp_millis() - (HOURS + 2) * HOUR).div_euclid(HOUR) * HOUR;
        let clock = Arc::new(AtomicI64::new(start));
        let policy = GcPolicy::default();
        let grace = policy.grace_seconds as i64 * 1_000;
        let authority = LocalDeleteAuthority::new_with_clock(
            store.clone(), TENANT_UUID, TenantKeySet::new(vec![]), policy, clock.clone()).unwrap();

        let mut chain = Chain::new();
        let mut persisted = 0;
        let mut n = 0_u64;
        let mut part = |level: Level, at: i64| -> PartRef {
            n += 1;
            let mut part = part_ref(n, level);
            part.part_id = PartId::parse(&format!("{:013}-{:016x}", at, n)).unwrap();
            part.event_hour = at.div_euclid(HOUR) as i32;
            // Written parts (L0/M/H merges) are sorted; adopted ones are not.
            part.sorted = true;
            part
        };
        let keys_of = |part: &PartRef| -> Vec<String> {
            let keys = crate::parts::format::PartKeys::new(TENANT_UUID, part.level, part.event_hour, &part.part_id).unwrap();
            FILES.iter().map(|file| keys.file(file)).collect()
        };
        async fn write(store: &LocalObjectStore, part: &PartRef, keys: &[String], body: &[u8]) {
            for key in keys {
                store.put(key, body).await.unwrap();
            }
            let keys = crate::parts::format::PartKeys::new(TENANT_UUID, part.level, part.event_hour, &part.part_id).unwrap();
            store.put(&keys.provenance(), b"{}").await.unwrap();
        }
        let present = |key: &str| store.path(key).unwrap().exists();

        // (removed at, deletable keys) of every superseded part; live keys.
        let mut removed: Vec<(i64, Vec<String>)> = Vec::new();
        let mut live: BTreeMap<PartId, Vec<String>> = BTreeMap::new();
        let (mut minute_l0, mut hour_m): (Vec<PartRef>, Vec<PartRef>) = (Vec::new(), Vec::new());
        let (mut last, mut catching_up, mut busy) = (None, false, 0_i64);
        let (mut deleted, mut targeted_listed_max_late) = (0_u64, 0_usize);
        let mut samples: Vec<(i64, u64)> = Vec::new();
        let mut source = 0_u64;

        let mut now = start;
        while now < start + HOURS * HOUR {
            clock.store(now, Ordering::SeqCst);
            if now % MINUTE == 0 {
                // The previous minute's L0s merge into one M part.
                if !minute_l0.is_empty() {
                    let output = part(Level::Minute, now);
                    let keys = keys_of(&output);
                    write(&store, &output, &keys, &body).await;
                    chain.push(LogOp::Merge { output: output.clone(),
                        supersedes: minute_l0.iter().map(|p| p.part_id.clone()).collect() }, now);
                    for input in minute_l0.drain(..) {
                        removed.push((now, live.remove(&input.part_id).unwrap()));
                    }
                    live.insert(output.part_id.clone(), keys);
                    hour_m.push(output);
                }
                // At the hour, the last hour's Ms merge into one H part.
                if now % HOUR == 0 && hour_m.len() > 1 {
                    let output = part(Level::Hour, now);
                    let keys = keys_of(&output);
                    write(&store, &output, &keys, &body).await;
                    chain.push(LogOp::Merge { output: output.clone(),
                        supersedes: hour_m.iter().map(|p| p.part_id.clone()).collect() }, now);
                    for input in hour_m.drain(..) {
                        removed.push((now, live.remove(&input.part_id).unwrap()));
                    }
                    live.insert(output.part_id.clone(), keys);
                }
                // This minute's ingest: one Add of the minute's L0 parts.
                let parts: Vec<_> = (0..L0_PER_MINUTE).map(|_| part(Level::L0, now)).collect();
                let consumed = parts.iter().map(|_| {
                    source += 1;
                    SourceRef { key: format!("bronze/{source}"), version: "1".into(), sha256: "d".repeat(64) }
                }).collect();
                for p in &parts {
                    let keys = keys_of(p);
                    write(&store, p, &keys, &body).await;
                    live.insert(p.part_id.clone(), keys);
                }
                chain.push(LogOp::Add { parts: parts.clone(), consumed, edge_log: None }, now);
                minute_l0 = parts;
                let keys = LogKeys::new(TENANT_UUID).unwrap();
                for (entry, _) in &chain.entries[persisted..] {
                    store.put_if_absent(&keys.entry(entry.seq), &entry.to_bytes().unwrap()).await.unwrap();
                }
                persisted = chain.entries.len();
            }
            if sanctioned_pass_due_paced(last, catching_up, busy, now) {
                last = Some(now);
                let started = std::time::Instant::now();
                let report = authority.run_pass(now).await.unwrap();
                busy = started.elapsed().as_millis() as i64;
                assert!(report.paused_reason.is_none(), "{report:?}");
                deleted += report.deleted;
                catching_up = pass_is_catching_up(&report);
                let full = authority.reclaim().unwrap().full_listed_at_ms == Some(now);
                if !full && now >= start + (HOURS - 1) * HOUR {
                    targeted_listed_max_late = targeted_listed_max_late.max(authority.last_listed());
                }
            }
            if now % (10 * MINUTE) == 0 {
                // Every superseded file is gone within grace + one interval
                // (+ one minute: a pass runs at most a tick after it is due).
                let overdue = now - grace - SANCTIONED_GC_INTERVAL_MS - MINUTE;
                for (at, keys) in removed.iter().filter(|(at, _)| *at <= overdue) {
                    for key in keys {
                        assert!(!present(key), "{key} superseded at {} still present at {}", at - start, now - start);
                    }
                }
                for keys in live.values() {
                    for key in keys {
                        assert!(present(key), "live {key} was deleted");
                    }
                }
                let pending = removed.iter().flat_map(|(_, keys)| keys).filter(|key| present(key)).count() as u64;
                samples.push((now, pending * body.len() as u64));
            }
            now += TICK;
        }

        // All but the last ~72 min of supersedes reclaimed.
        let total: usize = removed.iter().map(|(_, keys)| keys.len()).sum();
        assert!(deleted as usize >= total - RATE * 72, "deleted {deleted} of {total}");
        // Bounded: never above ~72 min of the supersede rate (grace + an
        // interval + slack), and flat over the last 90 min.
        let bound = (RATE * 72 * body.len()) as u64;
        for (at, bytes) in &samples {
            assert!(*bytes <= bound, "superseded-pending {bytes} B at +{} min exceeds {bound}", (at - start) / MINUTE);
        }
        let late: Vec<u64> = samples.iter().filter(|(at, _)| *at >= start + HOURS * HOUR - 90 * MINUTE)
            .map(|(_, bytes)| *bytes).collect();
        let (low, high) = (*late.iter().min().unwrap(), *late.iter().max().unwrap());
        assert!(low > 0 && high as f64 <= low as f64 * 1.25, "superseded-pending did not plateau: {late:?}");
        // A targeted pass lists the newly reclaimable parts, not history.
        let stored = store.list(&format!("lake/parts/v1/tenant={TENANT_UUID}/parts/")).await.unwrap().len();
        assert!(targeted_listed_max_late > 0 && targeted_listed_max_late * 4 < stored,
            "a targeted pass listed {targeted_listed_max_late} of {stored} stored keys");
    }

    #[test]
    fn local_retention_range_does_not_expand_hosted_validation() {
        for days in [1, 7, 3650] {
            let policy = GcPolicy {
                retention_days: Some(days),
                ..Default::default()
            };
            assert!(policy.validate().is_err());
            assert!(policy.validate_with_local(true).is_ok());
        }
        for days in [0, 3651, u64::MAX] {
            assert!(GcPolicy {
                retention_days: Some(days),
                ..Default::default()
            }
            .validate_with_local(true)
            .is_err());
        }
    }
}

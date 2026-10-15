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
        }))
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
        ensure!(
            parse_part_file_key(key).is_some_and(|parsed| parsed.tenant_uuid == self.tenant),
            "local GC key is not this tenant's part file"
        );
        let path = self.safe_path(key)?;
        let mut file = std::fs::File::open(&path)?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "local GC object is not a regular file");
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
        Ok(ListedPartObject {
            key: key.to_string(),
            strong_etag: format!("\"{}\"", hex::encode(hash.finalize())),
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
            chrono::Utc::now().timestamp_millis(),
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
        // Parts are immutable, and GC runs under the ingestor mutex. A
        // fresh log check is still performed for every permit and delete.
        let mut objects = Vec::new();
        for key in self.store.list(&prefix).await? {
            let Some(parsed) = parse_part_file_key(&key) else {
                continue;
            };
            if view.is_live(&parsed.part_id) || live_keys.contains(&key) {
                continue;
            }
            let object = self.object(&key)?;
            if !plan_local(
                &self.tenant,
                &view,
                &live_keys,
                std::slice::from_ref(&object),
                chrono::Utc::now().timestamp_millis(),
                &policy,
            )?
            .requests
            .is_empty()
            {
                objects.push(object);
                if objects.len() >= policy.max_requests {
                    break;
                }
            }
        }
        let mut planned = plan_local(
            &self.tenant,
            &view,
            &live_keys,
            &objects,
            chrono::Utc::now().timestamp_millis(),
            &policy,
        )?;
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

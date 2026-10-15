// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed gate on lake-part deletes from ingest (contract 6.4,
//! `lean_part_gc_gate_v1`).
//!
//! Ingest holds a read-write `lake_part` R2 credential (it must, to write
//! parts), but it never deletes a remote part file on that credential's
//! authority. Superseded and orphan part files are deleted only through the
//! sanctioned lake-part GC path ([`crate::lake_part_gc`]: owner
//! `lake-part-deletes:authorize` -> control `lake-part-deletes:attest`, which
//! checks the tenant's `lake_part_delete_grants` row, holds and retention ->
//! Worker prepare / retire behind `NANO_LAKE_PART_DELETE_ENABLED`), and only
//! while the tenant's lake_part delete grant, as delivered to the cell in the
//! credential exchange, is enabled.
//!
//! Every other state keeps every part and reports
//! `lake_part_gc_blocked{reason}` with the parts and bytes pending:
//!
//! | reason | meaning |
//! |---|---|
//! | `authority_missing` | no gate wired (lab, tests, older wiring) |
//! | `grant_not_delivered` | the exchange carried no `lake_part_delete_grant` |
//! | `grant_unreadable` | the grant did not parse or names another tenant |
//! | `grant_disabled` | the grant is recorded disabled (the default at lean birth) |
//! | `grant_expired` | the grant's `expires_at` passed without a refresh |
//! | `sanctioned_path_unavailable` | grant enabled, but this cell has no owner/Worker delete route |
//! | `authority_unreadable` | reading any of the above failed |
//! | `sanctioned_pass_paused` | the sanctioned pass ran and stopped (hold, grant refused, back-off) |
//!
//! Superseded parts are unreferenced by the live set, so keeping them never
//! changes a query answer; it only costs storage.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::{Arc, Mutex};

use crate::lake_part_gc::{
    run_pass, GcPolicy, LakePartDeleteAuthority, LakePartGcState, LakePartIndexClient, ListedPartObject,
    PartLogReader, PassInput, PassReport,
};

pub const REASON_AUTHORITY_MISSING: &str = "authority_missing";
pub const REASON_GRANT_NOT_DELIVERED: &str = "grant_not_delivered";
pub const REASON_GRANT_UNREADABLE: &str = "grant_unreadable";
pub const REASON_GRANT_DISABLED: &str = "grant_disabled";
pub const REASON_GRANT_EXPIRED: &str = "grant_expired";
pub const REASON_SANCTIONED_PATH_UNAVAILABLE: &str = "sanctioned_path_unavailable";
pub const REASON_AUTHORITY_UNREADABLE: &str = "authority_unreadable";
pub const REASON_SANCTIONED_PASS_PAUSED: &str = "sanctioned_pass_paused";

/// The tenant's lake_part delete grant as the platform delivers it in the
/// credential-exchange response (`lake_part_delete_grant`). See
/// LEAN-CELL-FEATURES-NANO-MAIN.md section 7.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LakePartDeleteGrant {
    pub schema_version: u8,
    /// The tenant UUID; must equal the process tenant.
    pub tenant_id: String,
    /// The tenant slug the sanctioned delete requests carry.
    pub tenant_slug: String,
    /// The control `lake_part_delete_grants` row state.
    pub enabled: bool,
    /// Opaque grant revision (logged only).
    #[serde(default)]
    pub revision: Option<String>,
    /// RFC 3339; past it the grant counts as disabled until refreshed.
    pub expires_at: String,
}

impl LakePartDeleteGrant {
    /// Parse and bind to `tenant`. Any failure is a closed gate.
    pub fn parse(value: &serde_json::Value, tenant: &str) -> Result<Self> {
        let grant: Self = serde_json::from_value(value.clone()).context("lake_part_delete_grant")?;
        anyhow::ensure!(grant.schema_version == 1, "lake_part_delete_grant schema_version {}", grant.schema_version);
        anyhow::ensure!(grant.tenant_id == tenant, "lake_part_delete_grant names another tenant");
        anyhow::ensure!(!grant.tenant_slug.is_empty(), "lake_part_delete_grant has no tenant slug");
        chrono::DateTime::parse_from_rfc3339(&grant.expires_at).context("lake_part_delete_grant expires_at")?;
        Ok(grant)
    }

    fn expired(&self, now_ms: i64) -> bool {
        chrono::DateTime::parse_from_rfc3339(&self.expires_at).map_or(true, |at| at.timestamp_millis() <= now_ms)
    }
}

/// The sanctioned lake-part GC pass (owner permit, control attestation,
/// Worker delete with an absence receipt). Ingest never plans or deletes
/// itself; the pass plans from the verified log and control re-attests.
#[async_trait]
pub trait SanctionedPartGc: Send + Sync {
    async fn run_pass(&self, now_ms: i64) -> Result<PassReport>;

    /// Schedule work; background starts/busy acknowledgements carry no report.
    /// Foreground implementations still return their completed report.
    async fn schedule_pass(&self, now_ms: i64) -> Option<Result<PassReport>> {
        Some(self.run_pass(now_ms).await)
    }

    /// Collect a completed background report without starting a destructive pass.
    async fn poll_report(&self, _now_ms: i64) -> Option<Result<PassReport>> { None }

    /// NAN-3852: receipted deletes so far in this process, including those of
    /// a pass still in flight. `None` when only completed reports count.
    fn deleted_total(&self) -> Option<u64> { None }

    /// Safe, bounded diagnostic; never includes a credential or endpoint.
    fn unavailable_detail(&self) -> &'static str {
        "sanctioned_route_unavailable"
    }

    /// The delete route (owner bearer, Worker endpoint, tenant slug) is in
    /// hand right now. A wired pass whose route the latest exchange did not
    /// deliver reports `sanctioned_path_unavailable`, like no pass at all.
    fn available(&self) -> bool {
        true
    }
}

/// What the gate allows right now.
pub enum PartGcDecision {
    /// Keep every part; the reason is a stable metric label.
    Blocked(&'static str),
    /// Delete only through this pass.
    Sanctioned(Arc<dyn SanctionedPartGc>),
}

/// Consulted before any lake-part delete. `Err` is a closed gate.
#[async_trait]
pub trait PartGcAuthority: Send + Sync {
    async fn decision(&self, now_ms: i64) -> Result<PartGcDecision>;

    /// Completion is observable even after the route or grant is withdrawn.
    async fn poll_report(&self, _now_ms: i64) -> Option<Result<PassReport>> { None }

    /// NAN-3852: live receipted-delete count of the wired pass (see
    /// [`SanctionedPartGc::deleted_total`]).
    fn deleted_total(&self) -> Option<u64> { None }

    fn blocked_detail(&self) -> &'static str {
        ""
    }
}

enum GrantSlot {
    NotDelivered,
    Unreadable,
    Grant(LakePartDeleteGrant),
}

/// Production gate: the grant from the latest credential exchange plus the
/// sanctioned pass, if this cell has one wired.
pub struct ExchangedGrantAuthority {
    tenant: String,
    grant: Mutex<GrantSlot>,
    sanctioned: Option<Arc<dyn SanctionedPartGc>>,
}

impl ExchangedGrantAuthority {
    pub fn new(tenant: &str, sanctioned: Option<Arc<dyn SanctionedPartGc>>) -> Self {
        Self { tenant: tenant.to_string(), grant: Mutex::new(GrantSlot::NotDelivered), sanctioned }
    }

    /// Replace the grant with what the latest exchange delivered. An absent
    /// or unreadable grant closes the gate (never keeps an older enabled one).
    pub fn update(&self, raw: Option<&serde_json::Value>) {
        let slot = match raw {
            None => GrantSlot::NotDelivered,
            Some(value) => match LakePartDeleteGrant::parse(value, &self.tenant) {
                Ok(grant) => {
                    tracing::info!(enabled = grant.enabled, revision = ?grant.revision, expires_at = %grant.expires_at,
                        "lake_part delete grant received");
                    GrantSlot::Grant(grant)
                }
                Err(error) => {
                    tracing::error!(error = %format!("{error:#}"), "lake_part delete grant unreadable; part deletes stay blocked");
                    GrantSlot::Unreadable
                }
            },
        };
        match self.grant.lock() {
            Ok(mut guard) => *guard = slot,
            // A poisoned slot reads as an error: fail closed.
            Err(poisoned) => *poisoned.into_inner() = GrantSlot::Unreadable,
        }
    }
}

#[async_trait]
impl PartGcAuthority for ExchangedGrantAuthority {
    async fn poll_report(&self, now_ms: i64) -> Option<Result<PassReport>> {
        match &self.sanctioned {
            Some(pass) => pass.poll_report(now_ms).await,
            None => None,
        }
    }

    fn blocked_detail(&self) -> &'static str {
        self.sanctioned.as_ref().map_or("sanctioned_route_not_wired", |pass| pass.unavailable_detail())
    }

    fn deleted_total(&self) -> Option<u64> {
        self.sanctioned.as_ref().and_then(|pass| pass.deleted_total())
    }
    async fn decision(&self, now_ms: i64) -> Result<PartGcDecision> {
        let guard = self.grant.lock().map_err(|_| anyhow::anyhow!("lake_part delete grant lock poisoned"))?;
        let reason = match &*guard {
            GrantSlot::NotDelivered => REASON_GRANT_NOT_DELIVERED,
            GrantSlot::Unreadable => REASON_GRANT_UNREADABLE,
            GrantSlot::Grant(grant) if !grant.enabled => REASON_GRANT_DISABLED,
            GrantSlot::Grant(grant) if grant.expired(now_ms) => REASON_GRANT_EXPIRED,
            GrantSlot::Grant(_) => match &self.sanctioned {
                Some(pass) if pass.available() => return Ok(PartGcDecision::Sanctioned(pass.clone())),
                _ => REASON_SANCTIONED_PATH_UNAVAILABLE,
            },
        };
        Ok(PartGcDecision::Blocked(reason))
    }
}

/// Lists the tenant's `parts/` objects with their etag, size and upload
/// time (the planner's input).
#[async_trait]
pub trait PartObjectLister: Send + Sync {
    /// Stable endpoint/bucket/prefix identity, excluding rotating secrets.
    /// None conservatively fences inventories to the exact exchange route.
    fn inventory_scope(&self) -> Option<String> {
        None
    }

    async fn list_part_objects(&self, prefix: &str) -> Result<Vec<ListedPartObject>>;

    /// Complete scan with bounded candidate retention. The production adapter
    /// streams; the default preserves compatibility for in-memory test listers.
    async fn list_selected_part_objects(
        &self, prefix: &str,
        selection: &crate::lake_part_gc::planner::InventorySelection<'_>,
    ) -> Result<Vec<ListedPartObject>> {
        let mut objects = self.list_part_objects(prefix).await?;
        super::s3_store::check_gc_inventory(&objects)?;
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        anyhow::ensure!(objects.windows(2).all(|pair| pair[0].key != pair[1].key),
            "GC listing repeats an object key");
        anyhow::ensure!(objects.iter().all(|object| object.key.starts_with(prefix)),
            "GC listing escaped tenant prefix");
        Ok(objects.into_iter().filter(|object| selection.eligible(object))
            .take(selection.limit()).collect())
    }

}

/// [`SanctionedPartGc`] over [`crate::lake_part_gc::run_pass`].
pub struct LakePartGcRunner {
    pub authority: Arc<dyn LakePartDeleteAuthority>,
    pub index: Arc<dyn LakePartIndexClient>,
    pub reader: Arc<dyn PartLogReader>,
    pub lister: Arc<dyn PartObjectLister>,
    pub tenant_slug: String,
    pub tenant_uuid: String,
    pub policy: GcPolicy,
    pub state: tokio::sync::Mutex<LakePartGcState>,
}

#[async_trait]
impl SanctionedPartGc for LakePartGcRunner {
    async fn run_pass(&self, now_ms: i64) -> Result<PassReport> {
        let prefix = format!("{}/tenant={}/parts/", crate::parts::format::PARTS_ROOT, self.tenant_uuid);
        let objects = self.lister.list_part_objects(&prefix).await?;
        let mut state = self.state.lock().await;
        Ok(run_pass(
            self.authority.as_ref(),
            self.index.as_ref(),
            self.reader.as_ref(),
            PassInput {
                tenant_id: &self.tenant_slug,
                tenant_uuid: &self.tenant_uuid,
                state: &mut state,
                objects: &objects,
                now_ms,
                receipted: None,
                policy: self.policy,
            },
        )
        .await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
    const NOW: i64 = 1_790_294_400_000;

    struct NoPass;

    #[async_trait]
    impl SanctionedPartGc for NoPass {
        async fn run_pass(&self, _now_ms: i64) -> Result<PassReport> {
            Ok(PassReport::default())
        }
    }

    struct CountingPass(u64);

    #[async_trait]
    impl SanctionedPartGc for CountingPass {
        async fn run_pass(&self, _now_ms: i64) -> Result<PassReport> {
            Ok(PassReport::default())
        }
        fn deleted_total(&self) -> Option<u64> {
            Some(self.0)
        }
    }

    /// NAN-3852: the gate forwards the wired pass's live delete count, whatever
    /// the grant state (the count is history, not permission).
    #[test]
    fn the_gate_forwards_the_live_deleted_count() {
        let counting = ExchangedGrantAuthority::new(T, Some(Arc::new(CountingPass(410))));
        assert_eq!(counting.deleted_total(), Some(410));
        assert_eq!(ExchangedGrantAuthority::new(T, Some(Arc::new(NoPass))).deleted_total(), None);
        assert_eq!(ExchangedGrantAuthority::new(T, None).deleted_total(), None);
    }

    fn grant(enabled: bool, expires_at: &str) -> serde_json::Value {
        serde_json::json!({"schema_version": 1, "tenant_id": T, "tenant_slug": "acme", "enabled": enabled,
            "revision": "r1", "expires_at": expires_at})
    }

    async fn reason(authority: &ExchangedGrantAuthority) -> &'static str {
        match authority.decision(NOW).await.unwrap() {
            PartGcDecision::Blocked(reason) => reason,
            PartGcDecision::Sanctioned(_) => "sanctioned",
        }
    }

    #[tokio::test]
    async fn every_state_but_an_enabled_current_grant_with_a_pass_is_blocked() {
        let pass: Arc<dyn SanctionedPartGc> = Arc::new(NoPass);
        let authority = ExchangedGrantAuthority::new(T, Some(pass));
        assert_eq!(reason(&authority).await, REASON_GRANT_NOT_DELIVERED);
        authority.update(Some(&grant(false, "2030-01-01T00:00:00Z")));
        assert_eq!(reason(&authority).await, REASON_GRANT_DISABLED);
        authority.update(Some(&grant(true, "2020-01-01T00:00:00Z")));
        assert_eq!(reason(&authority).await, REASON_GRANT_EXPIRED);
        authority.update(Some(&serde_json::json!({"enabled": true})));
        assert_eq!(reason(&authority).await, REASON_GRANT_UNREADABLE);
        let mut other = grant(true, "2030-01-01T00:00:00Z");
        other["tenant_id"] = serde_json::json!("6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f01");
        authority.update(Some(&other));
        assert_eq!(reason(&authority).await, REASON_GRANT_UNREADABLE);
        authority.update(Some(&grant(true, "2030-01-01T00:00:00Z")));
        assert_eq!(reason(&authority).await, "sanctioned");
        // A later exchange without the grant closes the gate again.
        authority.update(None);
        assert_eq!(reason(&authority).await, REASON_GRANT_NOT_DELIVERED);
    }

    #[tokio::test]
    async fn an_enabled_grant_without_a_sanctioned_path_never_deletes() {
        let authority = ExchangedGrantAuthority::new(T, None);
        authority.update(Some(&grant(true, "2030-01-01T00:00:00Z")));
        assert_eq!(reason(&authority).await, REASON_SANCTIONED_PATH_UNAVAILABLE);
    }

    /// The cell image advertises `lean_part_gc_gate_v1` exactly when this
    /// gate is in the ingest binary.
    #[test]
    fn cell_feature_lean_part_gc_gate_v1_is_backed() {
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"lean_part_gc_gate_v1"));
    }
}

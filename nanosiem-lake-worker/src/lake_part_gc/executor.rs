// SPDX-License-Identifier: AGPL-3.0-or-later

//! The GC pass: capability probe, log catch-up, index sync, plan, and the
//! per-key owner authorize -> local permit check -> Worker prepare -> Worker
//! retire -> exact receipt loop (the hosted Bronze reclaim pattern).

use anyhow::{bail, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::index::{
    catch_up_view_bounded, report_deleted, sync_index, DeletedKey, IndexSyncOutcome, LakePartIndexClient, PartLogReader,
};
use super::planner::{live_part_keys, GcPolicy, LakePartLogView, ListedPartObject};
use super::request::LakePartDeleteRequest;
use crate::lake_part_gc::delete_control::{
    DeleteOwnerAuthorization, DELETE_AUTHORIZATION_MAX_TTL, DELETE_CONTROL_SCHEMA_VERSION,
};
use crate::parts::is_sha256_hex;

/// Clock skew tolerated on the owner's `issued_at` / TTL.
const PERMIT_SKEW: chrono::Duration = chrono::Duration::seconds(2);
/// Consecutive Worker failures that end a pass with a back-off.
const MAX_CONSECUTIVE_WORKER_FAILURES: u32 = 3;
/// Most deleted-key records held for reporting. Past it the oldest are
/// dropped: each costs one leaked writer receipt row in control, never an
/// object, and control ignores records whose permit it already pruned.
pub const MAX_PENDING_DELETED: usize = 65_536;
/// Maximum new log entries folded per pass. A partial view never plans deletes.
pub const MAX_LOG_ENTRIES_PER_PASS: u64 = 2_048;
/// Pause reason of a pass that stopped after one bounded fold step with the
/// log still ahead of its view. Not a failure: the scheduler continues the
/// catch-up on a short cadence (NAN-3818), never planning before it is done.
pub const LOG_CATCHING_UP: &str = "log_catching_up";
/// Cap on the exponential back-off between passes.
pub const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(6 * 3_600);
/// NAN-3495: how long a key the owner refused per key (identity mismatch,
/// grace, orphan age, ...) is not authorized again. Before this every pass
/// re-asked the owner for every such key: the load-test tenant's passes spent ~150-560
/// authorize calls each on the same `lake_part_object_not_found` keys until
/// the owner's per-tenant limiter answered 429. Remembering a refusal only
/// ever keeps an object longer (fail-safe).
pub const REFUSED_KEY_TTL_MS: i64 = 3_600_000;
/// NAN-3495: a key control has no completed writer receipt for
/// (`lake_part_object_not_found`) is unauthorizable until control's receipt
/// state is reconciled; it is re-checked once a day, not every pass.
pub const UNAUTHORIZABLE_KEY_TTL_MS: i64 = 24 * 3_600_000;
/// The refusal code that marks a key unauthorizable.
pub const OBJECT_NOT_FOUND: &str = "lake_part_object_not_found";
/// Most remembered per-key refusals; past it the soonest-expiring are dropped.
pub const MAX_REFUSED_KEYS: usize = 65_536;
/// NAN-3495: most owner authorize calls one cell makes per minute, across
/// passes. Well below the owner's per-tenant budget (600/min), so GC never
/// spends all of it; a pass that reaches it waits for the next window.
pub const MAX_AUTHORIZES_PER_MINUTE: u32 = 240;

/// The owner rejected the cell's delete bearer (HTTP 401). Never a per-key
/// refusal and never retried within a pass: stop it at once.
#[derive(Debug, thiserror::Error)]
#[error("owner refused the lake-part delete bearer (401)")]
pub struct BearerRefused;

/// NAN-4612: the tenant's catalog custody guard refused a prepare / retire
/// before any Worker call: the catalog may still reference the part, or the
/// writer has not yet rebuilt its planned index from the remote catalog (a
/// fresh or wiped data volume). Nothing was deleted. This is a pass pause, not
/// a Worker failure: it must never read as `worker_unavailable`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("catalog custody holds the part: {reason}")]
pub struct CatalogCustodyHeld {
    pub reason: String,
    /// Only this part is still referenced by the catalog: skip the key, keep
    /// the pass. Otherwise the refusal is pass-wide (index not rebuilt, plan
    /// pending, inspection failed, ...) and the pass stops.
    pub part_pinned: bool,
}

/// Pause reason of a pass the catalog custody guard stopped (NAN-4612).
pub const CATALOG_CUSTODY_HELD: &str = "catalog_custody_held";
/// Per-key skip code: the catalog still references the part (NAN-4612).
pub const CATALOG_PINNED: &str = "catalog_pinned";

/// An owner / control refusal: `{"error": code}` with its HTTP status
/// (`None` for a transport fault).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("lake part delete refused: {code} (HTTP {status:?})")]
pub struct LakePartRefusal {
    pub status: Option<u16>,
    pub code: String,
    /// The answer's `Retry-After` (delta seconds), when it carried one.
    pub retry_after: Option<std::time::Duration>,
}

impl LakePartRefusal {
    pub fn new(status: Option<u16>, code: &str) -> Self {
        Self { status, code: code.to_string(), retry_after: None }
    }

    pub fn with_retry_after(mut self, retry_after: Option<std::time::Duration>) -> Self {
        self.retry_after = retry_after;
        self
    }

    /// Rate limit, unavailable, 5xx or transport.
    pub fn is_backoff(&self) -> bool {
        matches!(
            self.code.as_str(),
            "lake_part_tenant_rate_limit"
                | "lake_part_attestation_unavailable"
                | "lake_part_index_unavailable"
                | "lake_part_service_assertion_replay"
                | "lake_part_clock_skew"
        ) || self.status.is_none_or(|status| status == 429 || status >= 500)
    }

    pub fn action(&self) -> RefusalAction {
        match self.code.as_str() {
            "lake_part_held"
            | "lake_part_protected"
            | "lake_part_grant_required"
            | "lake_part_inactive_assignment"
            | "lake_part_control_forbidden"
            | "lake_part_binding_mismatch" => RefusalAction::Pause,
            "lake_part_index_incomplete" => RefusalAction::IndexIncomplete,
            _ if self.is_backoff() => RefusalAction::BackOff,
            // within_grace / orphan_too_young / within_retention / referenced /
            // removal_uncommitted, and any other per-key 4xx (identity
            // mismatch, object not found, policy mismatch, ...).
            _ => RefusalAction::Skip,
        }
    }
}

/// What a refusal does to the pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalAction {
    /// Stop the whole pass (hold, protection, grant, assignment).
    Pause,
    /// Stop; the next pass pushes the index first.
    IndexIncomplete,
    /// Skip this key this pass.
    Skip,
    /// Stop and back off.
    BackOff,
}

/// The owner's permit (`lake-part-deletes:authorize` response).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakePartDeletePermit {
    pub request: LakePartDeleteRequest,
    pub permit_id: String,
    pub owner_authorization: DeleteOwnerAuthorization,
}

impl LakePartDeletePermit {
    /// The permit is for exactly `request`, and its owner authorization is
    /// well-formed and current. The signature itself is verified by the
    /// Worker (it holds the owner key set).
    pub fn verify(&self, request: &LakePartDeleteRequest, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
        self.verify_with_local(request, now, false)
    }

    pub(crate) fn verify_with_local(&self, request: &LakePartDeleteRequest, now: chrono::DateTime<chrono::Utc>, trusted_local: bool) -> Result<()> {
        let digest = request.digest_with_local(trusted_local)?;
        let auth = &self.owner_authorization;
        let issued = chrono::DateTime::parse_from_rfc3339(&auth.issued_at)?;
        let expires = chrono::DateTime::parse_from_rfc3339(&auth.expires_at)?;
        if self.request != *request
            || self.permit_id != format!("lpd_{digest}")
            || auth.identity_sha256 != digest
            || auth.schema_version != 1
            || auth.signer_key_id.is_empty()
            || auth.signature_base64.is_empty()
            || expires <= now
            || expires <= issued
            || issued > now + PERMIT_SKEW
            || expires - issued > DELETE_AUTHORIZATION_MAX_TTL + PERMIT_SKEW
        {
            bail!("lake part permit identity or owner authorization differs");
        }
        Ok(())
    }
}

/// The Worker's absence receipt (same shape as the bronze receipt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakePartDeleteReceipt {
    pub schema_version: u8,
    pub permit_id: String,
    pub identity_sha256: String,
    pub receipt_sha256: String,
    pub state: String,
    pub final_head_absent: bool,
}

impl LakePartDeleteReceipt {
    pub fn verify(&self, permit: &LakePartDeletePermit) -> Result<()> {
        self.verify_with_local(permit, false)
    }

    pub(crate) fn verify_with_local(&self, permit: &LakePartDeletePermit, trusted_local: bool) -> Result<()> {
        if self.schema_version != DELETE_CONTROL_SCHEMA_VERSION
            || self.permit_id != permit.permit_id
            || self.identity_sha256 != permit.owner_authorization.identity_sha256
            || self.identity_sha256 != permit.request.digest_with_local(trusted_local)?
            || self.state != "receipt_appended"
            || !self.final_head_absent
            || !is_sha256_hex(&self.receipt_sha256)
            || self.receipt_sha256 == "0".repeat(64)
        {
            bail!("lake part authority omitted an exact durable absence receipt");
        }
        Ok(())
    }
}

/// The owner + Worker retention authority. No implementation holds an R2
/// delete credential.
#[async_trait]
pub trait LakePartDeleteAuthority: Send + Sync {
    /// The Worker lists `lake_part_delete` in its retention capabilities.
    async fn worker_supports_lake_part_delete(&self) -> Result<bool>;
    /// NAN-4567: the Worker also admits `quarantine_expired` permits
    /// ([`super::quarantine_expiry::QUARANTINE_OPERATION`]). Default: no.
    async fn worker_supports_quarantine_expiry(&self) -> Result<bool> {
        Ok(false)
    }
    /// Owner `lake-part-deletes:authorize`. Refusals are [`LakePartRefusal`].
    async fn authorize(&self, request: &LakePartDeleteRequest) -> Result<LakePartDeletePermit>;
    /// Worker `lake-part/prepare`: durable tombstone; echoes the permit.
    async fn prepare(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeletePermit>;
    /// Worker `lake-part/retire`: HEAD, delete, final HEAD, receipt.
    async fn retire(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeleteReceipt>;
}

/// Counters for one pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    pub planned: u64,
    /// Exact receipts only.
    pub deleted: u64,
    /// Per-key skips by refusal / failure code.
    pub skipped: BTreeMap<String, u64>,
    /// Planner pass-overs by reason.
    pub plan_skipped: BTreeMap<&'static str, u64>,
    /// Why the pass stopped early, if it did.
    pub paused_reason: Option<String>,
    /// The caller should wait longer than usual before the next pass.
    pub backoff: bool,
    /// Entries pushed to control's index this pass.
    pub indexed: u64,
    /// Deleted-key records control accepted this pass.
    pub deleted_reported: u64,
    /// Why reporting deleted keys failed (they stay queued), if it did.
    pub deleted_report_failed: Option<String>,
    /// Records dropped because the queue exceeded [`MAX_PENDING_DELETED`].
    pub deleted_dropped: u64,
    /// Control's `indexed_through_seq` after this pass's index sync, if it ran.
    pub index_head_seq: Option<u64>,
    /// `appended_at_ms` of the newest entry this pass pushed, if any.
    pub index_head_appended_ms: Option<i64>,
    /// NAN-4728: a trusted-local pass filled its request bound, deleted at
    /// least one file, and stopped with more eligible files listed. The
    /// ingest scheduler runs the next bounded pass after the short catch-up
    /// interval instead of the 10-min pass interval. Hosted passes never set it.
    pub more_eligible: bool,
}

/// What a caller keeps for one tenant across passes.
#[derive(Debug, Default)]
pub struct LakePartGcState {
    /// The verified log view; extended with new entries each pass.
    pub view: LakePartLogView,
    /// Deletes with an exact receipt not yet reported to control (in memory
    /// only: a restart forgets them, leaking only their receipt rows).
    pub pending_deleted: Vec<DeletedKey>,
    /// Consecutive passes that ended in a back-off.
    pub backoff_passes: u32,
    /// NAN-3495: keys the owner refused per key, until (unix ms) they may be
    /// authorized again, with the reason. The cell persists it next to its
    /// view.
    pub refused_keys: RefusedKeys,
    /// NAN-3495: paces owner authorize calls across passes.
    pub authorize_pacer: AuthorizePacer,
}

/// NAN-3495: at most `per_minute` authorize calls per rolling one-minute
/// window; a caller past it waits for the window to end.
#[derive(Debug, Clone)]
pub struct AuthorizePacer {
    per_minute: u32,
    window_started: Option<tokio::time::Instant>,
    used: u32,
}

impl Default for AuthorizePacer {
    fn default() -> Self {
        Self::new(MAX_AUTHORIZES_PER_MINUTE)
    }
}

impl AuthorizePacer {
    pub fn new(per_minute: u32) -> Self {
        Self { per_minute: per_minute.max(1), window_started: None, used: 0 }
    }

    /// Take one authorize slot, sleeping until the window ends if it is spent.
    pub async fn acquire(&mut self) {
        const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
        loop {
            let now = tokio::time::Instant::now();
            match self.window_started {
                Some(started) if now < started + WINDOW => {
                    if self.used < self.per_minute {
                        self.used += 1;
                        return;
                    }
                    tokio::time::sleep_until(started + WINDOW).await;
                }
                _ => {
                    self.window_started = Some(now);
                    self.used = 1;
                    return;
                }
            }
        }
    }
}

/// NAN-3495: per-key owner refusals remembered across passes, so a pass never
/// re-authorizes a key the owner refused (see [`REFUSED_KEY_TTL_MS`] and
/// [`UNAUTHORIZABLE_KEY_TTL_MS`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedKeys {
    keys: std::collections::HashMap<String, RefusedKey>,
    /// Changed since the last [`Self::take_dirty`].
    #[serde(skip)]
    dirty: bool,
}

/// One remembered refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedKey {
    /// Unix ms after which the key may be authorized again.
    pub until_ms: i64,
    /// The owner's refusal code.
    pub reason: String,
}

impl RefusedKeys {
    /// The key was refused and its memory has not expired.
    pub fn is_refused(&self, key: &str, now_ms: i64) -> bool {
        self.keys.get(key).is_some_and(|refused| refused.until_ms > now_ms)
    }

    /// Remember `key` refused for `reason` (unauthorizable keys for
    /// [`UNAUTHORIZABLE_KEY_TTL_MS`], others for [`REFUSED_KEY_TTL_MS`]).
    pub fn remember(&mut self, key: &str, reason: &str, now_ms: i64) {
        if self.keys.len() >= MAX_REFUSED_KEYS && !self.keys.contains_key(key) {
            self.prune(now_ms);
            if self.keys.len() >= MAX_REFUSED_KEYS {
                let soonest = self.keys.iter().min_by_key(|(_, refused)| refused.until_ms).map(|(key, _)| key.clone());
                if let Some(soonest) = soonest {
                    self.keys.remove(&soonest);
                }
            }
        }
        let ttl = if reason == OBJECT_NOT_FOUND { UNAUTHORIZABLE_KEY_TTL_MS } else { REFUSED_KEY_TTL_MS };
        self.keys.insert(key.to_string(), RefusedKey { until_ms: now_ms.saturating_add(ttl), reason: reason.to_string() });
        self.dirty = true;
    }

    /// Drop expired entries.
    pub fn prune(&mut self, now_ms: i64) {
        let before = self.keys.len();
        self.keys.retain(|_, refused| refused.until_ms > now_ms);
        self.dirty |= self.keys.len() != before;
    }

    /// Unexpired keys refused for `reason`.
    pub fn count(&self, reason: &str, now_ms: i64) -> usize {
        self.keys.values().filter(|refused| refused.reason == reason && refused.until_ms > now_ms).count()
    }

    /// Whether anything changed since the last call (for persistence).
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl LakePartGcState {
    /// A state whose view folds the log from seq 0 (orphans plannable).
    pub fn genesis() -> Self {
        Self { view: LakePartLogView::genesis(), ..Self::default() }
    }

    /// Wait before the next pass: `base` normally; `base * 2^n` (capped at
    /// [`MAX_BACKOFF`]) after `n` consecutive back-off passes.
    pub fn next_pass_delay(&self, base: std::time::Duration) -> std::time::Duration {
        if self.backoff_passes == 0 {
            return base;
        }
        base.saturating_mul(1_u32 << self.backoff_passes.min(16)).min(MAX_BACKOFF.max(base))
    }
}

impl PassReport {
    fn skip(&mut self, code: &str) {
        *self.skipped.entry(code.to_string()).or_default() += 1;
    }

    fn pause(&mut self, reason: impl Into<String>, backoff: bool) {
        self.paused_reason = Some(reason.into());
        self.backoff = backoff;
    }
}

/// NAN-3852: the next part-log entry is younger than the index settle gate
/// and not yet under the writer's receipted watermark. Under continuous
/// ingest this is the normal state for a moment after every append (the
/// entry is visible before the writer's completion returns). It clears with
/// time; it is not a stalled index and must not end the GC task.
pub const INDEX_SETTLING: &str = "index_settling";

/// The pause reason for a sync that did not reach the reader's head.
fn index_not_caught_up(settling: bool) -> &'static str {
    if settling { INDEX_SETTLING } else { "index_catching_up" }
}

enum Step {
    Deleted(DeletedKey),
    Skip(String),
    Stop { reason: String, backoff: bool },
    WorkerFailure(&'static str),
}

/// Longest Worker error text logged for one failed prepare / retire.
const WORKER_ERROR_LOG_CHARS: usize = 512;

/// NAN-3131: a Worker refusal (`HTTP {status} {reason}` from `worker_post`)
/// used to vanish into a bare `worker_*_failed` count. Log it, bounded and
/// stripped of control characters and any bearer material.
fn log_worker_failure(request: &LakePartDeleteRequest, phase: &'static str, error: &anyhow::Error) {
    let error = sanitize_worker_error(&format!("{error:#}"));
    tracing::warn!(key = %request.key, phase, %error, "lake part GC Worker call failed");
}

fn sanitize_worker_error(text: &str) -> String {
    let mut words = Vec::new();
    let mut redact_next = false;
    for word in text.split_whitespace() {
        if redact_next {
            words.push("[redacted]".to_string());
            redact_next = false;
            continue;
        }
        let lower = word.to_ascii_lowercase();
        if lower == "bearer" || lower.starts_with("bearer:") {
            redact_next = lower == "bearer";
            words.push("[redacted authorization]".to_string());
            continue;
        }
        if lower.contains("token=") || lower.contains("x-amz-signature=") || lower.contains("x-amz-credential=") {
            words.push("[redacted]".to_string());
            continue;
        }
        words.push(word.chars().filter(|c| !c.is_control()).collect());
    }
    words.join(" ").chars().take(WORKER_ERROR_LOG_CHARS).collect()
}

/// A pass-wide custody refusal stops the pass with a back-off: every later
/// key would meet the same guard. A part the catalog still pins is skipped
/// (remembered under the refusal TTL) so it never starves the rest (NAN-4612).
fn custody_held(request: &LakePartDeleteRequest, phase: &'static str, error: &anyhow::Error) -> Option<Step> {
    let held = error.downcast_ref::<CatalogCustodyHeld>()?;
    if held.part_pinned {
        tracing::debug!(key = %request.key, phase, "lake part GC skipped a part the catalog still references");
        return Some(Step::Skip(CATALOG_PINNED.into()));
    }
    let reason = sanitize_worker_error(&held.reason);
    tracing::warn!(key = %request.key, phase, %reason, "lake part GC held by catalog custody; nothing deleted");
    Some(Step::Stop { reason: CATALOG_CUSTODY_HELD.into(), backoff: true })
}

async fn delete_one(authority: &dyn LakePartDeleteAuthority, request: &LakePartDeleteRequest, trusted_local: bool) -> Step {
    if request.validate_with_local(trusted_local).is_err() {
        return Step::Skip("invalid_request".into());
    }
    let permit = match authority.authorize(request).await {
        Ok(permit) => permit,
        Err(error) => {
            let Some(refusal) = error.downcast_ref::<LakePartRefusal>() else {
                return Step::Stop { reason: format!("owner_unavailable: {error:#}"), backoff: true };
            };
            return match refusal.action() {
                RefusalAction::Pause => Step::Stop { reason: refusal.code.clone(), backoff: false },
                RefusalAction::IndexIncomplete => Step::Stop { reason: refusal.code.clone(), backoff: false },
                RefusalAction::BackOff => Step::Stop { reason: refusal.code.clone(), backoff: true },
                RefusalAction::Skip => Step::Skip(refusal.code.clone()),
            };
        }
    };
    if permit.verify_with_local(request, chrono::Utc::now(), trusted_local).is_err() {
        // The owner signed something other than what we asked for.
        return Step::Stop { reason: "permit_mismatch".into(), backoff: false };
    }
    let prepared = match authority.prepare(&permit).await {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Some(step) = custody_held(request, "prepare", &error) {
                return step;
            }
            log_worker_failure(request, "prepare", &error);
            return Step::WorkerFailure("worker_prepare_failed");
        }
    };
    if prepared != permit {
        return Step::Stop { reason: "worker_prepare_mismatch".into(), backoff: false };
    }
    let receipt = match authority.retire(&permit).await {
        Ok(receipt) => receipt,
        Err(error) => {
            if let Some(step) = custody_held(request, "retire", &error) {
                return step;
            }
            log_worker_failure(request, "retire", &error);
            return Step::WorkerFailure("worker_retire_failed");
        }
    };
    if receipt.verify_with_local(&permit, trusted_local).is_err() {
        return Step::Stop { reason: "receipt_mismatch".into(), backoff: false };
    }
    Step::Deleted(DeletedKey {
        key: request.key.clone(),
        permit_id: permit.permit_id.clone(),
        receipt_sha256: receipt.receipt_sha256.clone(),
    })
}

/// Execute planned requests in order. Stops at the first pause / back-off.
/// Every delete with an exact receipt is appended to `deleted` for the
/// control report. A per-key refusal (policy / identity mismatch, object
/// not found, invalid request, ...) is counted and skipped for this pass;
/// no key is ever retried within a pass.
pub async fn execute(
    authority: &dyn LakePartDeleteAuthority,
    requests: &[LakePartDeleteRequest],
    deleted: &mut Vec<DeletedKey>,
) -> PassReport {
    let mut refused = RefusedKeys::default();
    let mut pacer = AuthorizePacer::default();
    let mut report = execute_requests(
        authority, requests, deleted, &mut refused, &mut pacer, chrono::Utc::now().timestamp_millis(), false, None,
    ).await;
    // Public eager execution reports the full input plan, as before.
    report.planned = requests.len() as u64;
    report
}

/// NAN-4162: one sanctioned task's retained inventory across its bounded
/// passes. A listing retains up to `budget` eligible keys (refused keys are
/// never selected); each pass plans at most `max_requests` of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InventoryBudget {
    pub deleted: usize,
    pub budget: usize,
}

impl InventoryBudget {
    /// Requests the next pass may plan, or `None` once the budget is spent.
    /// An empty candidate set still runs (the pass also publishes the index).
    pub(crate) fn next_pass(&self, max_requests: usize) -> Option<usize> {
        (self.deleted < self.budget).then(|| max_requests.min(self.budget - self.deleted))
    }

    /// Fold one pass in: receipted keys and keys refused (within their TTL)
    /// leave `objects`. Whether the task should run another pass at once:
    /// only when the candidate set shrank, so the loop cannot spin.
    pub(crate) fn after_pass(
        &mut self, objects: &mut Vec<ListedPartObject>, receipted: &[String],
        refused: &RefusedKeys, now_ms: i64, report: &PassReport,
    ) -> bool {
        let before = objects.len();
        self.deleted += receipted.len();
        objects.retain(|object| !receipted.iter().any(|key| key == &object.key) && !refused.is_refused(&object.key, now_ms));
        report.paused_reason.is_none() && objects.len() < before && !objects.is_empty() && self.next_pass(1).is_some()
    }
}

pub(crate) async fn execute_local(
    authority: &dyn LakePartDeleteAuthority, requests: &[LakePartDeleteRequest],
) -> PassReport {
    execute_requests(
        authority, requests, &mut Vec::new(), &mut RefusedKeys::default(), &mut AuthorizePacer::default(),
        chrono::Utc::now().timestamp_millis(), true, None,
    ).await
}

/// NAN-4567: execute a bronze quarantine expiry plan. Shares the pass's
/// refused-key memory and authorize pacer; deleted keys are not queued for
/// the control report (a quarantine key has no part writer rows).
pub(crate) async fn execute_quarantine(
    authority: &dyn LakePartDeleteAuthority, requests: &[LakePartDeleteRequest],
    refused: &mut RefusedKeys, pacer: &mut AuthorizePacer, now_ms: i64,
) -> PassReport {
    execute_requests(authority, requests, &mut Vec::new(), refused, pacer, now_ms, false, None).await
}

async fn execute_requests<I, R>(
    authority: &dyn LakePartDeleteAuthority, requests: I, deleted: &mut Vec<DeletedKey>,
    refused: &mut RefusedKeys, pacer: &mut AuthorizePacer, now_ms: i64, trusted_local: bool,
    resync: Option<(&dyn LakePartIndexClient, &dyn PartLogReader, &str, Option<&super::index::ReceiptedAppends>)>,
) -> PassReport
where I: IntoIterator<Item = R>, R: std::borrow::Borrow<LakePartDeleteRequest> {
    let mut report = PassReport::default();
    let mut worker_failures = 0;
    let mut resynced = false;
    for request in requests {
        let request = request.borrow();
        report.planned += 1;
        if refused.is_refused(&request.key, now_ms) {
            // NAN-3495: refused within the TTL; never re-asked this pass.
            report.skip("recently_refused");
            continue;
        }
        // NAN-3495 paces the hosted authorize endpoint; a trusted-local
        // authority is in-process, so local reclaim is not paced.
        if !trusted_local && request.validate().is_ok() {
            pacer.acquire().await;
        }
        let mut step = delete_one(authority, request, trusted_local).await;
        if matches!(&step, Step::Stop { reason, .. } if reason == "lake_part_index_incomplete") && !resynced {
            if let Some((index, reader, tenant_uuid, receipted)) = resync {
                resynced = true;
                let receipted_through = receipted.and_then(|receipted| receipted.receipted_through(now_ms));
                match sync_index(index, reader, tenant_uuid, now_ms, receipted_through).await {
                    Ok(IndexSyncOutcome::Synced { caught_up: true, pushed, status, head_appended_ms, .. }) => {
                        report.indexed += pushed;
                        report.index_head_seq = status.indexed_through_seq;
                        report.index_head_appended_ms = head_appended_ms;
                        pacer.acquire().await;
                        step = delete_one(authority, request, trusted_local).await;
                    }
                    Ok(IndexSyncOutcome::BackOff(reason)) => step = Step::Stop { reason, backoff: true },
                    Ok(IndexSyncOutcome::Refused(reason)) => {
                        tracing::error!(%reason, "control refused the part-log index during re-sync");
                        step = Step::Stop { reason, backoff: false };
                    }
                    Ok(IndexSyncOutcome::Synced { settling, .. }) => step = Step::Stop { reason: index_not_caught_up(settling).into(), backoff: false },
                    Ok(IndexSyncOutcome::RouteNotServed) => step = Step::Stop { reason: "index_route_not_served".into(), backoff: false },
                    Err(error) => {
                        if let Some(progress) = error.downcast_ref::<super::index::IndexReadProgress>() {
                            report.indexed += progress.pushed;
                        }
                        let reason = crate::part_ingest::part_gc_cell::routine_fence(&error);
                        step = Step::Stop {
                            reason: reason.unwrap_or("log_unverifiable").into(),
                            backoff: reason.is_none_or(|reason| reason == crate::part_ingest::part_gc_cell::CREDENTIAL_REFRESH),
                        };
                    }
                }
            }
        }
        match step {
            Step::Deleted(record) => {
                worker_failures = 0;
                report.deleted += 1;
                deleted.push(record);
            }
            Step::Skip(code) => {
                // Skipped for this pass and remembered; never retried here.
                refused.remember(&request.key, &code, now_ms);
                report.skip(&code);
            }
            Step::WorkerFailure(code) => {
                report.skip(code);
                worker_failures += 1;
                if worker_failures >= MAX_CONSECUTIVE_WORKER_FAILURES {
                    report.pause("worker_unavailable", true);
                    break;
                }
            }
            Step::Stop { reason, backoff } => {
                if reason == "receipt_mismatch" || reason == "permit_mismatch" {
                    report.skip(&reason);
                }
                if reason == "log_catching_up" || reason == INDEX_SETTLING {
                    // NAN-3852: routine under live ingest (a flush landed
                    // mid-pass); the task folds / waits and continues.
                    tracing::debug!(key = %request.key, %reason, "lake part GC pass stopped");
                } else {
                    tracing::warn!(key = %request.key, %reason, "lake part GC pass stopped");
                }
                report.pause(reason, backoff);
                break;
            }
        }
    }
    report
}

/// One tenant's inputs to a pass.
pub struct PassInput<'a> {
    /// Tenant slug (`tenant_id` in requests).
    pub tenant_id: &'a str,
    pub tenant_uuid: &'a str,
    /// Held across passes: the log view, unreported deletes, back-off.
    pub state: &'a mut LakePartGcState,
    /// A listing of the tenant's `parts/` prefix.
    pub objects: &'a [ListedPartObject],
    pub now_ms: i64,
    /// NAN-3810: the tenant log writer's receipted appends, when this process
    /// owns that writer. Young entries it covers are indexed without waiting
    /// out [`super::index::INDEX_SETTLE_MS`]; `None` keeps the age gate alone.
    pub receipted: Option<&'a super::index::ReceiptedAppends>,
    pub policy: GcPolicy,
}

/// One GC pass for one tenant:
///
/// 1. the Worker must advertise `lake_part_delete`, else nothing happens;
/// 2. fold new verified entries into the view;
/// 3. bring control's index up to the log head (404 = older owner: stop);
/// 4. resolve every key a live part references (adopted objects included);
/// 5. plan; 6. [`execute`];
/// 7. report every receipted delete (this pass's and any still queued) to
///    control, and update the back-off (see
///    [`LakePartGcState::next_pass_delay`]).
pub async fn run_pass(
    authority: &dyn LakePartDeleteAuthority,
    index: &dyn LakePartIndexClient,
    reader: &dyn PartLogReader,
    input: PassInput<'_>,
) -> PassReport {
    run_pass_inner(authority, index, reader, input, false).await
}

/// Cell-only path after advance_view has completed its bounded, persisted fold.
/// Publish that exact immutable view, with no duplicate paced absent-tail
/// probes during publication. The exact index head/digest must match the view
/// before planning; control freshly refuses committed/committing arrivals at
/// EVERY authorization, forcing another bounded fold. No absence is cached. The public executor retains
/// its ordinary fold for callers that do not own that bounded cell path.
pub(crate) async fn run_pass_after_bounded_fold(
    authority: &dyn LakePartDeleteAuthority,
    index: &dyn LakePartIndexClient,
    reader: &dyn PartLogReader,
    input: PassInput<'_>,
) -> PassReport {
    run_pass_inner(authority, index, reader, input, true).await
}

async fn run_pass_inner(
    authority: &dyn LakePartDeleteAuthority,
    index: &dyn LakePartIndexClient,
    reader: &dyn PartLogReader,
    input: PassInput<'_>,
    bounded_fold_complete: bool,
) -> PassReport {
    let tenant_uuid = input.tenant_uuid;
    let state = &mut *input.state;
    let mut report = pass(authority, index, reader, input.tenant_id, tenant_uuid, state, input.objects, input.now_ms, &input.policy, input.receipted, bounded_fold_complete).await;
    if state.pending_deleted.len() > MAX_PENDING_DELETED {
        let excess = state.pending_deleted.len() - MAX_PENDING_DELETED;
        state.pending_deleted.drain(..excess);
        report.deleted_dropped = excess as u64;
        tracing::warn!(excess, "lake part GC dropped unreported deleted keys; their receipt rows leak in control");
    }
    if !state.pending_deleted.is_empty() {
        match report_deleted(index, tenant_uuid, &mut state.pending_deleted).await {
            Ok(reported) => report.deleted_reported = reported,
            Err(code) => {
                tracing::warn!(%code, pending = state.pending_deleted.len(), "lake part GC could not report deleted keys");
                report.deleted_report_failed = Some(code);
            }
        }
    }
    state.backoff_passes = if report.backoff { state.backoff_passes.saturating_add(1) } else { 0 };
    report
}

#[allow(clippy::too_many_arguments)]
async fn pass(
    authority: &dyn LakePartDeleteAuthority,
    index: &dyn LakePartIndexClient,
    reader: &dyn PartLogReader,
    tenant_id: &str,
    tenant_uuid: &str,
    state: &mut LakePartGcState,
    objects: &[ListedPartObject],
    now_ms: i64,
    policy: &GcPolicy,
    receipted: Option<&super::index::ReceiptedAppends>,
    bounded_fold_complete: bool,
) -> PassReport {
    let mut report = PassReport::default();
    static OBSERVATIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let observe = OBSERVATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 24;
    let phase_started = std::time::Instant::now();
    match authority.worker_supports_lake_part_delete().await {
        Ok(true) => {}
        Ok(false) => {
            report.pause("worker_capability_missing", false);
            return report;
        }
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "lake part GC capability probe failed");
            report.pause("worker_unavailable", true);
            return report;
        }
    }
    let capability_us = phase_started.elapsed().as_micros() as u64;
    let planning_started = std::time::Instant::now();
    if !bounded_fold_complete {
        match catch_up_view_bounded(&mut state.view, reader, MAX_LOG_ENTRIES_PER_PASS).await {
            Ok(applied) if applied == MAX_LOG_ENTRIES_PER_PASS => {
                report.pause("log_catching_up", false);
                return report;
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "lake part GC could not verify the part log");
                report.pause("log_unverifiable", true);
                return report;
            }
        }
    }
    let live_keys = match live_part_keys(tenant_uuid, &mut state.view, reader).await {
        Ok(keys) => keys,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "lake part GC could not resolve live part keys");
            report.pause("live_keys_unresolved", true);
            return report;
        }
    };
    let mut cursor = match super::planner::PlanCursor::new(
        tenant_id, tenant_uuid, &state.view, &live_keys, objects, now_ms, policy,
    ) {
        Ok(cursor) => cursor,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "lake part GC policy is invalid");
            report.pause("policy_invalid", false);
            return report;
        }
    };
    let planning_us = planning_started.elapsed().as_micros() as u64;
    let index_started = std::time::Instant::now();
    // NAN-3810: under continuous ingest the head entry is always younger than
    // the settle gate, and control refuses every attest while a receipted
    // entry is unindexed. The writer's receipted watermark admits it.
    let receipted_through = receipted.and_then(|receipted| receipted.receipted_through(now_ms));
    let sync = if bounded_fold_complete {
        super::index::sync_index_through_view(index, reader, tenant_uuid, state.view.head_seq(), now_ms, receipted_through).await
    } else {
        sync_index(index, reader, tenant_uuid, now_ms, receipted_through).await
    };
    match sync {
        Ok(IndexSyncOutcome::Synced { status, caught_up, pushed, head_appended_ms, settling, .. }) => {
            report.indexed = pushed;
            report.index_head_seq = status.indexed_through_seq;
            report.index_head_appended_ms = head_appended_ms;
            if !caught_up {
                report.pause(index_not_caught_up(settling), false);
                return report;
            }
            if bounded_fold_complete {
                let head = state.view.live().head();
                if status.indexed_through_seq.is_some_and(|indexed| head.is_none_or(|(seq, _, _)| indexed > seq)) {
                    // NAN-3495: another publisher (the cell's index-only
                    // task) indexed past this view: fold further, then plan.
                    report.pause("log_catching_up", false);
                    return report;
                }
                if status.indexed_through_seq != head.map(|(seq, _, _)| seq)
                    || status.head_entry_sha256.as_deref() != head.map(|(_, sha, _)| sha)
                {
                    report.pause("index_complete_view_mismatch", false);
                    return report;
                }
            }
        }
        Ok(IndexSyncOutcome::RouteNotServed) => {
            report.pause("index_route_not_served", false);
            return report;
        }
        Ok(IndexSyncOutcome::BackOff(code)) => {
            report.pause(code, true);
            return report;
        }
        Ok(IndexSyncOutcome::Refused(code)) => {
            tracing::error!(%code, "control refused the part-log index");
            report.pause(code, false);
            return report;
        }
        Err(error) => {
            if let Some(progress) = error.downcast_ref::<super::index::IndexReadProgress>() {
                report.indexed = progress.pushed;
            }
            // NAN-3459: a cell fence that closed mid-publication is routine
            // (every credential refresh, or a retained inventory reaching its
            // lifetime). The verified prefix is published; resume quietly.
            // Anything else is still a log-integrity error.
            if let Some(reason) = crate::part_ingest::part_gc_cell::routine_fence(&error) {
                tracing::debug!(error = %format!("{error:#}"), reason, "lake part GC index publication fenced; resuming");
                report.pause(reason, reason == crate::part_ingest::part_gc_cell::CREDENTIAL_REFRESH);
                return report;
            }
            tracing::error!(error = %format!("{error:#}"), "lake part GC could not read the part log");
            report.pause("log_unverifiable", true);
            return report;
        }
    }
    if observe {
        tracing::info!(capability_us, planning_us,
            index_us = index_started.elapsed().as_micros() as u64,
            head_seq = ?state.view.head_seq(), request_limit = policy.max_requests,
            "GC_PHASE bounded sanitized preparation timings");
    }
    if bounded_fold_complete {
        let executed = execute_requests(
            authority, &mut cursor, &mut state.pending_deleted, &mut state.refused_keys, &mut state.authorize_pacer, now_ms, false, Some((index, reader, tenant_uuid, receipted)),
        ).await;
        PassReport {
            plan_skipped: cursor.skipped, indexed: report.indexed + executed.indexed, index_head_seq: executed.index_head_seq.or(report.index_head_seq),
            index_head_appended_ms: executed.index_head_appended_ms.or(report.index_head_appended_ms), ..executed
        }
    } else {
        // Preserve eager public executor reporting and error behavior.
        let requests = cursor.by_ref().collect::<Vec<_>>();
        let mut executed =
            execute_requests(authority, &requests, &mut state.pending_deleted, &mut state.refused_keys, &mut state.authorize_pacer, now_ms, false, Some((index, reader, tenant_uuid, receipted))).await;
        executed.planned = requests.len() as u64;
        PassReport {
            plan_skipped: cursor.skipped, indexed: report.indexed + executed.indexed, index_head_seq: executed.index_head_seq.or(report.index_head_seq),
            index_head_appended_ms: executed.index_head_appended_ms.or(report.index_head_appended_ms), ..executed
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lake_part_gc::index::tests::{served_shas, ChainReader, FakeIndex};
    use crate::lake_part_gc::planner::tests::{id, key, Chain, T0};
    use crate::lake_part_gc::request::tests::{superseded, TENANT_UUID};
    use crate::parts::levels::Level;
    use crate::parts::part_log::LogOp;
    use std::sync::Mutex;

    #[test]
    fn worker_error_log_keeps_the_refusal_and_drops_secrets() {
        let refusal = sanitize_worker_error(
            "retention authority /admin/retention/lake-part/prepare refused: HTTP 403 tenant_authority_mismatch",
        );
        assert_eq!(
            refusal,
            "retention authority /admin/retention/lake-part/prepare refused: HTTP 403 tenant_authority_mismatch"
        );
        let leaked = sanitize_worker_error("send failed: Authorization: Bearer s3cr3t\nnext https://x/?token=abc&x=1");
        assert!(!leaked.contains("s3cr3t") && !leaked.contains("abc"), "{leaked}");
        assert!(!leaked.chars().any(char::is_control));
        assert!(sanitize_worker_error(&"x".repeat(4096)).len() <= WORKER_ERROR_LOG_CHARS);
    }

    #[derive(Default)]
    struct FakeAuthority {
        capable: bool,
        /// key -> refusal code the owner answers.
        refusals: BTreeMap<String, (u16, &'static str)>,
        bad_receipt: bool,
        incomplete_remaining: Mutex<usize>,
        reveal_on_incomplete: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeAuthority {
        fn capable() -> Self {
            Self { capable: true, ..Self::default() }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl LakePartDeleteAuthority for FakeAuthority {
        async fn worker_supports_lake_part_delete(&self) -> Result<bool> {
            Ok(self.capable)
        }

        async fn authorize(&self, request: &LakePartDeleteRequest) -> Result<LakePartDeletePermit> {
            self.calls.lock().unwrap().push(format!("authorize {}", request.key));
            {
                let mut remaining = self.incomplete_remaining.lock().unwrap();
                if *remaining > 0 {
                    *remaining -= 1;
                    if let Some(reveal) = &self.reveal_on_incomplete {
                        reveal.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    return Err(LakePartRefusal::new(Some(409), "lake_part_index_incomplete").into());
                }
            }
            if let Some((status, code)) = self.refusals.get(&request.key) {
                return Err(LakePartRefusal::new(Some(*status), code).into());
            }
            let now = chrono::Utc::now();
            Ok(LakePartDeletePermit {
                request: request.clone(),
                permit_id: request.permit_id()?,
                owner_authorization: DeleteOwnerAuthorization {
                    schema_version: 1,
                    signer_key_id: "owner-test".into(),
                    issued_at: now.to_rfc3339(),
                    expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
                    identity_sha256: request.digest()?,
                    signature_base64: "sig".into(),
                },
            })
        }

        async fn prepare(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeletePermit> {
            self.calls.lock().unwrap().push(format!("prepare {}", permit.request.key));
            Ok(permit.clone())
        }

        async fn retire(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeleteReceipt> {
            self.calls.lock().unwrap().push(format!("retire {}", permit.request.key));
            Ok(LakePartDeleteReceipt {
                schema_version: DELETE_CONTROL_SCHEMA_VERSION,
                permit_id: permit.permit_id.clone(),
                identity_sha256: permit.owner_authorization.identity_sha256.clone(),
                receipt_sha256: "a".repeat(64),
                state: "receipt_appended".into(),
                final_head_absent: !self.bad_receipt,
            })
        }
    }

    fn requests(n: usize) -> Vec<LakePartDeleteRequest> {
        ["data-00000.parquet", "tokens-00000.nti", "partials/rollup.parquet", "partials/risk.parquet"][..n]
            .iter()
            .map(|file| LakePartDeleteRequest { key: crate::lake_part_gc::request::tests::key(file), ..superseded() })
            .collect()
    }

    #[tokio::test]
    async fn exact_receipts_count_as_deleted() {
        let authority = FakeAuthority::capable();
        let report = execute(&authority, &requests(2), &mut Vec::new()).await;
        assert_eq!((report.planned, report.deleted, report.paused_reason.clone()), (2, 2, None));
        assert!(authority.calls()[..3].iter().zip(["authorize", "prepare", "retire"]).all(|(c, s)| c.starts_with(s)));
    }

    /// NAN-4612: the catalog guard in front of the Worker refuses (the large tenant after
    /// the T91 wipe: `os error 2` on the missing planned index). The pass
    /// stops at once with a custody reason: no Worker call, no retire, and
    /// never `worker_unavailable` / `worker_prepare_failed`.
    #[tokio::test]
    async fn catalog_custody_refusal_pauses_the_pass_without_reaching_the_worker() {
        struct Held(FakeAuthority);
        #[async_trait]
        impl LakePartDeleteAuthority for Held {
            async fn worker_supports_lake_part_delete(&self) -> Result<bool> {
                self.0.worker_supports_lake_part_delete().await
            }
            async fn authorize(&self, request: &LakePartDeleteRequest) -> Result<LakePartDeletePermit> {
                self.0.authorize(request).await
            }
            async fn prepare(&self, _: &LakePartDeletePermit) -> Result<LakePartDeletePermit> {
                // Context layers (as Seams / Hosted wrappers may add) keep the type.
                Err(anyhow::Error::new(CatalogCustodyHeld {
                    reason: "catalog planned index not initialized".into(),
                    part_pinned: false,
                })
                .context("catalog GC guard"))
            }
            async fn retire(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeleteReceipt> {
                self.0.retire(permit).await
            }
        }
        let authority = Held(FakeAuthority::capable());
        let report = execute(&authority, &requests(3), &mut Vec::new()).await;
        assert_eq!(report.deleted, 0);
        assert_eq!(report.paused_reason.as_deref(), Some(CATALOG_CUSTODY_HELD));
        assert!(report.backoff);
        assert!(report.skipped.is_empty(), "{report:?}");
        let calls = authority.0.calls();
        assert_eq!(calls.len(), 1, "one authorize, then stop: {calls:?}");
        assert!(calls[0].starts_with("authorize"));
    }

    /// NAN-4612: a part the catalog still references is a per-key skip; the
    /// next deletable key of the same pass is still deleted.
    #[tokio::test]
    async fn a_catalog_pinned_part_is_skipped_without_starving_the_pass() {
        struct Pinned(FakeAuthority, String);
        #[async_trait]
        impl LakePartDeleteAuthority for Pinned {
            async fn worker_supports_lake_part_delete(&self) -> Result<bool> {
                self.0.worker_supports_lake_part_delete().await
            }
            async fn authorize(&self, request: &LakePartDeleteRequest) -> Result<LakePartDeletePermit> {
                self.0.authorize(request).await
            }
            async fn prepare(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeletePermit> {
                if permit.request.key == self.1 {
                    return Err(CatalogCustodyHeld { reason: "catalog metadata still pins part".into(), part_pinned: true }.into());
                }
                self.0.prepare(permit).await
            }
            async fn retire(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeleteReceipt> {
                self.0.retire(permit).await
            }
        }
        let reqs = requests(3);
        let authority = Pinned(FakeAuthority::capable(), reqs[0].key.clone());
        let report = execute(&authority, &reqs, &mut Vec::new()).await;
        assert_eq!(report.deleted, 2, "{report:?}");
        assert_eq!(report.paused_reason, None);
        assert_eq!(report.skipped.get(CATALOG_PINNED), Some(&1));
        assert!(!authority.0.calls().iter().any(|c| *c == format!("retire {}", reqs[0].key)));
    }

    /// NAN-3495: a key the owner refused per key (404 object not found) is
    /// not authorized again until its memory expires; other keys still are.
    #[tokio::test]
    async fn per_key_refusals_are_not_reauthorized_across_passes() {
        let reqs = requests(3);
        let mut authority = FakeAuthority::capable();
        authority.refusals.insert(reqs[0].key.clone(), (404, "lake_part_object_not_found"));
        authority.refusals.insert(reqs[1].key.clone(), (409, "lake_part_identity_mismatch"));
        let mut refused = RefusedKeys::default();
        let first = execute_requests(&authority, &reqs, &mut Vec::new(), &mut refused, &mut AuthorizePacer::default(), T0, false, None).await;
        assert_eq!((first.deleted, first.skipped.get("lake_part_object_not_found")), (1, Some(&1)));
        assert_eq!(refused.len(), 2);
        let authorized = |authority: &FakeAuthority, key: &str| {
            authority.calls().iter().filter(|c| **c == format!("authorize {key}")).count()
        };
        // The next pass, a minute later: neither refused key reaches the owner.
        let second = execute_requests(&authority, &reqs[..2], &mut Vec::new(), &mut refused, &mut AuthorizePacer::default(), T0 + 60_000, false, None).await;
        assert_eq!(second.skipped.get("recently_refused"), Some(&2));
        assert_eq!((authorized(&authority, &reqs[0].key), authorized(&authority, &reqs[1].key)), (1, 1));
        // The unauthorizable key is re-checked after a day, the other after an hour.
        assert_eq!(refused.count(OBJECT_NOT_FOUND, T0), 1);
        execute_requests(&authority, &reqs[..2], &mut Vec::new(), &mut refused, &mut AuthorizePacer::default(), T0 + REFUSED_KEY_TTL_MS, false, None).await;
        assert_eq!((authorized(&authority, &reqs[0].key), authorized(&authority, &reqs[1].key)), (1, 2));
        execute_requests(&authority, &reqs[..1], &mut Vec::new(), &mut refused, &mut AuthorizePacer::default(), T0 + UNAUTHORIZABLE_KEY_TTL_MS, false, None).await;
        assert_eq!(authorized(&authority, &reqs[0].key), 2, "re-checked once its marker expires (control may have reconciled)");
        assert!(refused.take_dirty() && !refused.take_dirty());
    }

    /// NAN-3495: the memory is bounded; expired entries go first, then the
    /// soonest-expiring one.
    #[test]
    fn refused_key_memory_is_bounded() {
        let mut refused = RefusedKeys::default();
        for i in 0..MAX_REFUSED_KEYS {
            refused.remember(&format!("k{i}"), "lake_part_identity_mismatch", i as i64);
        }
        assert_eq!(refused.len(), MAX_REFUSED_KEYS);
        refused.remember("new", "lake_part_identity_mismatch", MAX_REFUSED_KEYS as i64);
        assert_eq!(refused.len(), MAX_REFUSED_KEYS);
        assert!(!refused.is_refused("k0", MAX_REFUSED_KEYS as i64), "the soonest-expiring entry was dropped");
        assert!(refused.is_refused("k1", MAX_REFUSED_KEYS as i64) && refused.is_refused("new", MAX_REFUSED_KEYS as i64));
        // Everything expired: one sweep frees the whole map.
        refused.remember("later", OBJECT_NOT_FOUND, REFUSED_KEY_TTL_MS * 4);
        assert_eq!(refused.len(), 1);
    }

    /// NAN-3495: one cell never spends the owner's per-tenant budget: past
    /// the per-minute cap the pass waits for the next window.
    #[tokio::test(start_paused = true)]
    async fn authorizes_are_paced_per_minute() {
        let reqs = requests(4);
        let authority = FakeAuthority::capable();
        let mut pacer = AuthorizePacer::new(2);
        let started = tokio::time::Instant::now();
        let report = execute_requests(&authority, &reqs, &mut Vec::new(), &mut RefusedKeys::default(), &mut pacer, T0, false, None).await;
        assert_eq!(report.deleted, 4);
        let waited = started.elapsed();
        assert!(waited >= std::time::Duration::from_secs(60) && waited < std::time::Duration::from_secs(61), "{waited:?}");
        assert!(MAX_AUTHORIZES_PER_MINUTE * 2 < 600, "well below the owner's per-tenant budget");
    }

    #[tokio::test]
    async fn held_pauses_the_whole_pass() {
        let reqs = requests(3);
        let mut authority = FakeAuthority::capable();
        authority.refusals.insert(reqs[1].key.clone(), (409, "lake_part_held"));
        let report = execute(&authority, &reqs, &mut Vec::new()).await;
        assert_eq!(report.deleted, 1);
        assert_eq!(report.paused_reason.as_deref(), Some("lake_part_held"));
        assert!(!report.backoff);
        assert!(!authority.calls().iter().any(|c| c.contains(&reqs[2].key)), "nothing after the hold");
    }

    #[tokio::test]
    async fn skip_codes_skip_one_key_and_rate_limit_backs_off() {
        let reqs = requests(4);
        let mut authority = FakeAuthority::capable();
        authority.refusals.insert(reqs[0].key.clone(), (409, "lake_part_within_grace"));
        authority.refusals.insert(reqs[1].key.clone(), (409, "lake_part_referenced"));
        authority.refusals.insert(reqs[3].key.clone(), (429, "lake_part_tenant_rate_limit"));
        let report = execute(&authority, &reqs, &mut Vec::new()).await;
        assert_eq!(report.deleted, 1);
        assert_eq!(report.skipped["lake_part_within_grace"], 1);
        assert_eq!(report.skipped["lake_part_referenced"], 1);
        assert_eq!(report.paused_reason.as_deref(), Some("lake_part_tenant_rate_limit"));
        assert!(report.backoff);
        assert_eq!(LakePartRefusal::new(Some(409), "lake_part_index_incomplete").action(), RefusalAction::IndexIncomplete);
        assert_eq!(LakePartRefusal::new(None, "transport").action(), RefusalAction::BackOff);
        assert_eq!(LakePartRefusal::new(Some(403), "lake_part_grant_required").action(), RefusalAction::Pause);
    }

    #[tokio::test]
    async fn receipt_mismatch_is_never_counted_as_deleted() {
        let mut authority = FakeAuthority::capable();
        authority.bad_receipt = true;
        let report = execute(&authority, &requests(2), &mut Vec::new()).await;
        assert_eq!(report.deleted, 0);
        assert_eq!(report.skipped["receipt_mismatch"], 1);
        assert_eq!(report.paused_reason.as_deref(), Some("receipt_mismatch"));
        // Every other receipt field is exact too.
        let permit = FakeAuthority::capable().authorize(&superseded()).await.unwrap();
        let good = FakeAuthority::capable().retire(&permit).await.unwrap();
        good.verify(&permit).unwrap();
        for bad in [
            LakePartDeleteReceipt { schema_version: 1, ..good.clone() },
            LakePartDeleteReceipt { permit_id: "lpd_x".into(), ..good.clone() },
            LakePartDeleteReceipt { identity_sha256: "b".repeat(64), ..good.clone() },
            LakePartDeleteReceipt { receipt_sha256: "0".repeat(64), ..good.clone() },
            LakePartDeleteReceipt { state: "prepared".into(), ..good.clone() },
        ] {
            assert!(bad.verify(&permit).is_err());
        }
        // A permit for a different request is refused locally.
        let mut other = permit.clone();
        other.request.content_length += 1;
        assert!(other.verify(&superseded(), chrono::Utc::now()).is_err());
    }

    fn pass_fixture() -> (ChainReader, Vec<ListedPartObject>) {
        let mut chain = Chain::new();
        chain.add(1, T0 + 1_000).add(2, T0 + 2_000);
        chain.push(
            LogOp::Merge {
                output: crate::lake_part_gc::planner::tests::part_ref(3, Level::Minute),
                supersedes: vec![id(1), id(2)],
            },
            T0 + 10_000,
        );
        let objects = ["data-00000.parquet", "provenance.json"]
            .into_iter()
            .map(|file| ListedPartObject {
                key: key(1, Level::L0, file),
                strong_etag: "\"e\"".into(),
                content_length: 3,
                uploaded_at_ms: T0,
            })
            .collect();
        (ChainReader { chain, checkpoint: None }, objects)
    }

    #[tokio::test]
    async fn bounded_cell_index_must_match_complete_view_head_and_digest() {
        let (reader, objects) = pass_fixture();
        for mismatch in ["ahead", "digest"] {
            let mut state = LakePartGcState::genesis();
            catch_up_view_bounded(&mut state.view, &reader, MAX_LOG_ENTRIES_PER_PASS).await.unwrap();
            let mut shas = served_shas(&reader.chain);
            if mismatch == "ahead" { shas.push("c".repeat(64)); }
            else { *shas.last_mut().unwrap() = "d".repeat(64); }
            let index = FakeIndex::new(shas);
            let authority = FakeAuthority::capable();
            let report = run_pass_after_bounded_fold(&authority, &index, &reader,
                pass_input(&mut state, &objects)).await;
            // NAN-3495: control indexed past the view (the cell's index-only
            // task published arrivals the fold had not reached): fold
            // further, never plan. A different digest is a disagreement.
            let expected = if mismatch == "ahead" { "log_catching_up" } else { "index_complete_view_mismatch" };
            assert_eq!(report.paused_reason.as_deref(), Some(expected));
            assert!(!report.backoff);
            assert_eq!(report.deleted, 0);
            assert!(authority.calls().is_empty());
        }
    }

    #[tokio::test]
    async fn a_partial_log_view_never_plans_or_deletes() {
        let mut chain = Chain::new();
        for n in 1..MAX_LOG_ENTRIES_PER_PASS + 10 {
            chain.add(n, T0 + n as i64);
        }
        let reader = ChainReader { chain, checkpoint: None };
        let index = FakeIndex::new(Vec::new());
        let authority = FakeAuthority::capable();
        let mut state = LakePartGcState::genesis();
        let first = run_pass(&authority, &index, &reader, pass_input(&mut state, &[])).await;
        assert_eq!(first.paused_reason.as_deref(), Some("log_catching_up"));
        assert!(!first.backoff);
        assert_eq!(state.view.head_seq(), Some(MAX_LOG_ENTRIES_PER_PASS - 1));
        assert!(index.calls.lock().unwrap().is_empty());
        assert!(authority.calls().is_empty());
        let second = run_pass(&authority, &index, &reader, pass_input(&mut state, &[])).await;
        assert_eq!(second.paused_reason.as_deref(), Some("index_catching_up"));
        assert_eq!(state.view.head_seq(), Some(MAX_LOG_ENTRIES_PER_PASS + 9));
        assert!(authority.calls().is_empty());
        let third = run_pass(&authority, &index, &reader, pass_input(&mut state, &[])).await;
        assert!(third.paused_reason.is_none(), "{third:?}");
    }

    #[tokio::test]
    async fn a_195_part_backlog_drains_in_four_bounded_passes() {
        let mut chain = Chain::new();
        let mut objects = Vec::new();
        for n in 1..=195 {
            chain.add(n, T0 + n as i64);
            objects.push(ListedPartObject {
                key: key(n, Level::L0, "data-00000.parquet"),
                strong_etag: "\"e\"".into(),
                content_length: 1_800_000,
                uploaded_at_ms: T0,
            });
        }
        chain.push(LogOp::Merge {
            output: crate::lake_part_gc::planner::tests::part_ref(196, Level::Minute),
            supersedes: (1..=195).map(id).collect(),
        }, T0 + 10_000);
        let reader = ChainReader { chain, checkpoint: None };
        let index = FakeIndex::new(Vec::new());
        let authority = FakeAuthority::capable();
        let mut state = LakePartGcState::genesis();
        let mut deleted = 0;
        for expected in [64, 64, 64, 3] {
            let input = PassInput {
                policy: GcPolicy { max_requests: 64, ..GcPolicy::default() },
                ..pass_input(&mut state, &objects)
            };
            let report = run_pass(&authority, &index, &reader, input).await;
            assert!(report.paused_reason.is_none(), "{report:?}");
            assert_eq!(report.deleted, expected);
            assert_eq!(report.deleted_reported, expected);
            deleted += report.deleted;
            // Simulate the exact absence receipts being reflected in the next listing.
            let retired: Vec<_> = authority.calls().into_iter()
                .filter_map(|call| call.strip_prefix("retire ").map(str::to_owned)).collect();
            objects.retain(|object| !retired.contains(&object.key));
        }
        assert_eq!(deleted, 195);
        assert!(objects.is_empty());
        assert!(state.pending_deleted.is_empty());
    }

    #[tokio::test]
    async fn index_incomplete_resyncs_once_then_retries_attest() {
        struct ArrivingReader {
            inner: ChainReader,
            reveal: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }
        #[async_trait]
        impl PartLogReader for ArrivingReader {
            async fn verified_entry(&self, seq: u64) -> Result<Option<super::super::index::VerifiedEntryBytes>> {
                if seq == 4 && !self.reveal.load(std::sync::atomic::Ordering::SeqCst) {
                    return Ok(None);
                }
                self.inner.verified_entry(seq).await
            }
            async fn newest_checkpoint(&self) -> Result<Option<super::super::index::CheckpointClaim>> {
                self.inner.newest_checkpoint().await
            }
            async fn verified_provenance(&self, part: &crate::parts::part_log::PartRef) -> Result<crate::parts::provenance::ProvenanceRecord> {
                self.inner.verified_provenance(part).await
            }
        }
        for failures in [1, 2] {
            let (mut reader, objects) = pass_fixture();
            reader.chain.add(99, T0 + 20_000);
            let reveal = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader = ArrivingReader { inner: reader, reveal: reveal.clone() };
            let index = FakeIndex::new(Vec::new());
            let mut authority = FakeAuthority::capable();
            authority.reveal_on_incomplete = Some(reveal);
            *authority.incomplete_remaining.lock().unwrap() = failures;
            let mut state = LakePartGcState::genesis();
            let report = run_pass(&authority, &index, &reader, pass_input(&mut state, &objects)).await;
            assert_eq!(authority.calls().iter().filter(|call| call.starts_with("authorize ")).count(), 2);
            // Initial status + append, then one re-sync status + newly arrived entry.
            assert_eq!(index.calls.lock().unwrap().len(), 4);
            assert_eq!(report.indexed, 5);
            assert_eq!(report.index_head_seq, Some(4));
            if failures == 1 {
                assert_eq!(report.deleted, 1);
                assert!(report.paused_reason.is_none());
            } else {
                assert_eq!(report.deleted, 0);
                assert_eq!(report.paused_reason.as_deref(), Some("lake_part_index_incomplete"));
            }
        }
    }

    /// Control's attest completeness rule (NL009): refuse while the index
    /// lags a receipted entry. Every entry of these chains is receipted.
    struct AttestingAuthority<'a> {
        inner: &'a FakeAuthority,
        index: &'a FakeIndex,
        receipted_head: u64,
    }

    #[async_trait]
    impl LakePartDeleteAuthority for AttestingAuthority<'_> {
        async fn worker_supports_lake_part_delete(&self) -> Result<bool> {
            self.inner.worker_supports_lake_part_delete().await
        }
        async fn authorize(&self, request: &LakePartDeleteRequest) -> Result<LakePartDeletePermit> {
            if (self.index.shas.lock().unwrap().len() as u64) <= self.receipted_head {
                self.inner.calls.lock().unwrap().push(format!("refused {}", request.key));
                return Err(LakePartRefusal::new(Some(409), "lake_part_index_incomplete").into());
            }
            self.inner.authorize(request).await
        }
        async fn prepare(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeletePermit> {
            self.inner.prepare(permit).await
        }
        async fn retire(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeleteReceipt> {
            self.inner.retire(permit).await
        }
    }

    /// NAN-3810 (the load-test tenant, 10-14): ingest appends an entry every ~20 s, so
    /// the log head is always younger than the 60 s settle gate. Without the
    /// writer's receipted watermark every pass stops at `index_settling`
    /// with the young tail unindexed and nothing is ever deleted; with it, GC indexes the
    /// receipted tail and deletes, on both the eager and the cell path.
    #[tokio::test]
    async fn continuously_flushing_log_still_lets_gc_delete() {
        for (bounded, receipted) in [(false, false), (false, true), (true, false), (true, true)] {
            let (mut reader, mut objects) = pass_fixture();
            for n in 10..30 {
                objects.push(ListedPartObject {
                    key: key(n, Level::L0, "data-00000.parquet"),
                    strong_etag: "\"e\"".into(),
                    content_length: 7,
                    uploaded_at_ms: T0,
                });
                reader.chain.add(n, T0 + 10_000 + n as i64);
            }
            reader.chain.push(LogOp::Merge {
                output: crate::lake_part_gc::planner::tests::part_ref(30, Level::Minute),
                supersedes: (10..30).map(id).collect(),
            }, T0 + 20_000);
            // The ingest writer receipted the merge and every append after it.
            let ledger = crate::lake_part_gc::index::ReceiptedAppends::default();
            ledger.record(reader.chain.entries.len() as u64 - 1, T0 + 20_000);
            let start = T0 + 20_000 + 3_600_000;
            let index = FakeIndex::new(Vec::new());
            let inner = FakeAuthority::capable();
            let mut state = LakePartGcState::genesis();
            let mut deleted = 0;
            for flush in 0..6_u64 {
                let now = start + flush as i64 * 20_000;
                reader.chain.add(100 + flush, now);
                ledger.record(reader.chain.entries.len() as u64 - 1, now);
                let authority = AttestingAuthority {
                    inner: &inner, index: &index, receipted_head: reader.chain.entries.len() as u64 - 1,
                };
                if bounded {
                    catch_up_view_bounded(&mut state.view, &reader, MAX_LOG_ENTRIES_PER_PASS).await.unwrap();
                }
                let input = PassInput {
                    now_ms: now,
                    receipted: receipted.then_some(&ledger),
                    ..pass_input(&mut state, &objects)
                };
                let report = if bounded {
                    run_pass_after_bounded_fold(&authority, &index, &reader, input).await
                } else {
                    run_pass(&authority, &index, &reader, input).await
                };
                if !receipted {
                    // NAN-3852: a young unreceipted tail is settling, not stalled.
                    assert_eq!(report.paused_reason.as_deref(), Some(INDEX_SETTLING), "flush {flush}: {report:?}");
                    assert!(index.shas.lock().unwrap().len() < reader.chain.entries.len(), "the young tail is never indexed");
                }
                deleted += report.deleted;
                let retired: Vec<_> = inner.calls().into_iter()
                    .filter_map(|call| call.strip_prefix("retire ").map(str::to_owned)).collect();
                objects.retain(|object| !retired.contains(&object.key));
            }
            if receipted {
                assert_eq!(index.shas.lock().unwrap().len(), reader.chain.entries.len(), "bounded={bounded}");
                assert_eq!(deleted, 21, "bounded={bounded}: superseded parts 1 and 10..30");
            } else {
                assert_eq!(deleted, 0, "bounded={bounded}");
            }
        }
    }

    /// NAN-3810: parts the young tail references are never deleted. A young
    /// receipted merge's inputs stay within grace, its output and a young add
    /// are live; a young entry above the watermark is never indexed, so the
    /// pass stops before planning any delete.
    #[tokio::test]
    async fn parts_referenced_by_the_young_tail_are_never_deleted() {
        for unreceipted_tail in [false, true] {
            let (mut reader, mut objects) = pass_fixture();
            let now = T0 + 10_000 + 3_600_000;
            reader.chain.add(5, T0 + 5_000).add(6, T0 + 6_000);
            let ledger = crate::lake_part_gc::index::ReceiptedAppends::default();
            ledger.record(reader.chain.entries.len() as u64 - 1, T0 + 6_000);
            // Young, receipted: merge 5 and 6 into 7; add 8.
            reader.chain.push(LogOp::Merge {
                output: crate::lake_part_gc::planner::tests::part_ref(7, Level::Minute),
                supersedes: vec![id(5), id(6)],
            }, now - 30_000);
            ledger.record(reader.chain.entries.len() as u64 - 1, now - 30_000);
            reader.chain.add(8, now - 10_000);
            ledger.record(reader.chain.entries.len() as u64 - 1, now - 10_000);
            if unreceipted_tail {
                // Young, no recorded receipt (receipt still in flight).
                reader.chain.add(9, now - 1_000);
            }
            for (n, level) in [(5, Level::L0), (6, Level::L0), (7, Level::Minute), (8, Level::L0), (9, Level::L0)] {
                objects.push(ListedPartObject {
                    key: key(n, level, "data-00000.parquet"),
                    strong_etag: "\"e\"".into(),
                    content_length: 7,
                    uploaded_at_ms: T0,
                });
            }
            let index = FakeIndex::new(Vec::new());
            let inner = FakeAuthority::capable();
            let authority = AttestingAuthority {
                inner: &inner, index: &index, receipted_head: reader.chain.entries.len() as u64 - 1,
            };
            let mut state = LakePartGcState::genesis();
            let report = run_pass(&authority, &index, &reader, PassInput {
                receipted: Some(&ledger),
                ..pass_input(&mut state, &objects)
            }).await;
            let retired: Vec<_> = inner.calls().into_iter()
                .filter_map(|call| call.strip_prefix("retire ").map(str::to_owned)).collect();
            let young: Vec<_> = (5..=9).map(|n| key(n, if n == 7 { Level::Minute } else { Level::L0 }, "data-00000.parquet")).collect();
            assert!(retired.iter().all(|key| !young.contains(key)), "{retired:?}");
            if unreceipted_tail {
                assert_eq!(index.shas.lock().unwrap().len(), reader.chain.entries.len() - 1, "seq above the watermark waits");
                assert_eq!(report.paused_reason.as_deref(), Some(INDEX_SETTLING));
                assert!(retired.is_empty());
            } else {
                assert_eq!(index.shas.lock().unwrap().len(), reader.chain.entries.len());
                assert_eq!(report.plan_skipped["within_grace"], 2, "{report:?}");
                assert_eq!(report.plan_skipped["live"], 2, "{report:?}");
                assert_eq!(retired, vec![objects[0].key.clone()], "only the long-superseded part 1");
            }
        }
    }

    #[tokio::test]
    async fn run_pass_syncs_the_index_then_deletes() {
        let (reader, objects) = pass_fixture();
        let index = FakeIndex::new(Vec::new());
        let authority = FakeAuthority::capable();
        let mut state = LakePartGcState::genesis();
        let input = PassInput {
            tenant_id: "tenant1",
            tenant_uuid: TENANT_UUID,
            state: &mut state,
            objects: &objects,
            now_ms: T0 + 10_000 + 3_600_000,
            receipted: None,
            policy: GcPolicy::default(),
        };
        let report = run_pass(&authority, &index, &reader, input).await;
        assert_eq!(report.indexed, 4);
        assert_eq!(*index.shas.lock().unwrap(), served_shas(&reader.chain));
        assert_eq!((report.planned, report.deleted), (1, 1), "{report:?}");
        assert_eq!(report.plan_skipped["provenance_kept"], 1);
        assert_eq!(state.view.head_seq(), Some(3));
        // The receipted delete was reported to control in the same pass.
        assert_eq!(report.deleted_reported, 1);
        assert!(state.pending_deleted.is_empty());
        let reported = index.deleted.lock().unwrap().clone();
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0][0].key, objects[0].key);
        assert!(reported[0][0].permit_id.starts_with("lpd_"));
        assert_eq!(reported[0][0].receipt_sha256, "a".repeat(64));
    }

    #[tokio::test]
    async fn run_pass_does_nothing_without_capability_or_index_route() {
        let (reader, objects) = pass_fixture();
        let index = FakeIndex::new(Vec::new());
        let mut state = LakePartGcState::genesis();
        let incapable = FakeAuthority::default();
        fn input<'a>(state: &'a mut LakePartGcState, objects: &'a [ListedPartObject]) -> PassInput<'a> {
            PassInput {
                tenant_id: "tenant1",
                tenant_uuid: TENANT_UUID,
                state,
                objects,
                now_ms: T0 + 100 * 3_600_000,
                receipted: None,
                policy: GcPolicy::default(),
            }
        }
        let report = run_pass(&incapable, &index, &reader, input(&mut state, &objects)).await;
        assert_eq!(report.paused_reason.as_deref(), Some("worker_capability_missing"));
        assert!(index.calls.lock().unwrap().is_empty());

        let mut old = FakeIndex::new(Vec::new());
        old.not_served = true;
        let authority = FakeAuthority::capable();
        let report = run_pass(&authority, &old, &reader, input(&mut state, &objects)).await;
        assert_eq!(report.paused_reason.as_deref(), Some("index_route_not_served"));
        assert!(authority.calls().is_empty(), "no deletes without the index");
    }

    fn pass_input<'a>(state: &'a mut LakePartGcState, objects: &'a [ListedPartObject]) -> PassInput<'a> {
        PassInput {
            tenant_id: "tenant1",
            tenant_uuid: TENANT_UUID,
            state,
            objects,
            now_ms: T0 + 10_000 + 3_600_000,
            receipted: None,
            policy: GcPolicy::default(),
        }
    }

    #[tokio::test]
    async fn unreported_deletes_stay_queued_for_the_next_pass() {
        let (reader, objects) = pass_fixture();
        let index = FakeIndex::new(Vec::new());
        *index.refuse_deleted.lock().unwrap() = true;
        let authority = FakeAuthority::capable();
        let mut state = LakePartGcState::genesis();
        let report = run_pass(&authority, &index, &reader, pass_input(&mut state, &objects)).await;
        assert_eq!(report.deleted, 1);
        assert_eq!(report.deleted_reported, 0);
        assert_eq!(report.deleted_report_failed.as_deref(), Some("lake_part_index_unavailable"));
        assert_eq!(state.pending_deleted.len(), 1);
        let queued = state.pending_deleted[0].clone();
        assert_eq!(queued.key, objects[0].key);

        // Next pass: nothing new to delete, the queued record goes out first.
        *index.refuse_deleted.lock().unwrap() = false;
        let report = run_pass(&authority, &index, &reader, pass_input(&mut state, &[])).await;
        assert_eq!((report.deleted, report.deleted_reported), (0, 1));
        assert!(state.pending_deleted.is_empty());
        assert_eq!(*index.deleted.lock().unwrap(), vec![vec![queued]]);
    }

    #[tokio::test]
    async fn permanent_owner_refusals_skip_the_key_once_without_retry() {
        for (status, code) in [
            (409, "lake_part_policy_mismatch"),
            (400, "lake_part_invalid_request"),
            (400, "lake_part_permit_mismatch"),
            (409, "lake_part_identity_mismatch"),
            (404, "lake_part_object_not_found"),
        ] {
            let reqs = requests(2);
            let mut authority = FakeAuthority::capable();
            authority.refusals.insert(reqs[0].key.clone(), (status, code));
            let mut deleted = Vec::new();
            let report = execute(&authority, &reqs, &mut deleted).await;
            assert_eq!(report.skipped[code], 1, "{code}");
            assert_eq!(report.deleted, 1, "{code}: the next key still runs");
            assert_eq!((report.paused_reason.clone(), report.backoff), (None, false), "{code}");
            let authorizations = authority.calls().iter().filter(|c| c.as_str() == format!("authorize {}", reqs[0].key)).count();
            assert_eq!(authorizations, 1, "{code}: never retried within the pass");
            assert_eq!(deleted.len(), 1);
            assert_eq!(deleted[0].key, reqs[1].key);
        }
    }

    #[tokio::test]
    async fn transient_refusals_back_off_exponentially_between_passes() {
        let (reader, objects) = pass_fixture();
        let index = FakeIndex::new(Vec::new());
        let mut authority = FakeAuthority::capable();
        authority.refusals.insert(objects[0].key.clone(), (429, "lake_part_tenant_rate_limit"));
        let mut state = LakePartGcState::genesis();
        let base = std::time::Duration::from_secs(900);
        assert_eq!(state.next_pass_delay(base), base);
        for expected in [1_800, 3_600, 7_200] {
            let report = run_pass(&authority, &index, &reader, pass_input(&mut state, &objects)).await;
            assert!(report.backoff);
            assert_eq!(state.next_pass_delay(base).as_secs(), expected);
        }
        state.backoff_passes = 40;
        assert_eq!(state.next_pass_delay(base), MAX_BACKOFF);
        authority.refusals.clear();
        let report = run_pass(&authority, &index, &reader, pass_input(&mut state, &objects)).await;
        assert!(!report.backoff && report.deleted == 1);
        assert_eq!(state.next_pass_delay(base), base, "a clean pass resets the back-off");
    }

    /// NAN-4162 (a large tenant, 10-13..10-18): 332 unauthorizable keys sorted first
    /// and filled most of every 512-key selection, so each task deleted 180
    /// while ingest superseded more. Refused keys never take a selection slot
    /// once known, one listing feeds several bounded passes, and the backlog
    /// drains within backlog / per-task budget tasks.
    #[tokio::test(start_paused = true)]
    async fn refused_keys_never_hold_the_selection_and_the_backlog_drains_in_bounded_tasks() {
        use crate::lake_part_gc::planner::{GcPolicy, InventorySelection};
        const PARTS: u64 = 240;
        const REFUSED: usize = 60;
        const MAX: usize = 8;
        let mut chain = Chain::new();
        for n in 1..=PARTS {
            chain.add(n, T0 + n as i64);
        }
        for group in 0..PARTS / 10 {
            chain.push(LogOp::Merge {
                output: crate::lake_part_gc::planner::tests::part_ref(10_000 + group, Level::Minute),
                supersedes: (1..=10).map(|k| id(group * 10 + k)).collect(),
            }, T0 + 10_000 + group as i64);
        }
        let reader = ChainReader { chain, checkpoint: None };
        let mut listing: Vec<ListedPartObject> = (1..=PARTS).map(|n| ListedPartObject {
            key: key(n, Level::L0, "data-00000.parquet"), strong_etag: "\"e\"".into(), content_length: 3, uploaded_at_ms: T0,
        }).collect();
        listing.sort_by(|a, b| a.key.cmp(&b.key));
        let mut authority = FakeAuthority::capable();
        for object in &listing[..REFUSED] {
            authority.refusals.insert(object.key.clone(), (404, OBJECT_NOT_FOUND));
        }
        let index = FakeIndex::new(Vec::new());
        let mut state = LakePartGcState::genesis();
        let now = T0 + 20_000 + 2 * 3_600_000;
        let policy = GcPolicy { max_requests: MAX, ..GcPolicy::default() };
        let per_task = MAX * crate::part_ingest::part_gc_cell::PASSES_PER_INVENTORY;
        // Fold the view (a pass over no objects) before the first selection.
        run_pass(&authority, &index, &reader, PassInput {
            tenant_id: "tenant1", tenant_uuid: TENANT_UUID, state: &mut state, objects: &[], now_ms: now, receipted: None, policy,
        }).await;
        // Backlog x per-task cost: every key (deletable or not yet known
        // refused) costs one slot, at most `per_task` per task.
        let bound = PARTS as usize / per_task + 1;
        let mut tasks = 0;
        loop {
            let live = crate::lake_part_gc::live_part_keys(TENANT_UUID, &mut state.view, &reader).await.unwrap();
            let mut objects: Vec<_> = {
                let selection = InventorySelection::new("tenant1", TENANT_UUID, &state.view, &live, now, policy).unwrap()
                    .excluding(&state.refused_keys)
                    .retaining(per_task);
                assert_eq!(selection.limit(), per_task);
                listing.iter().filter(|object| selection.eligible(object)).take(selection.limit()).cloned().collect()
            };
            if objects.is_empty() {
                break;
            }
            tasks += 1;
            assert!(tasks <= bound, "backlog did not drain within {bound} tasks");
            let mut budget = InventoryBudget { deleted: 0, budget: per_task };
            while let Some(requests) = budget.next_pass(MAX) {
                let reported = index.deleted.lock().unwrap().iter().flatten().count();
                let report = run_pass(&authority, &index, &reader, PassInput {
                    tenant_id: "tenant1", tenant_uuid: TENANT_UUID, state: &mut state, objects: &objects, now_ms: now,
                    receipted: None, policy: GcPolicy { max_requests: requests, ..policy },
                }).await;
                assert!(report.planned as usize <= MAX, "{report:?}");
                let receipted: Vec<String> = index.deleted.lock().unwrap().iter().flatten().skip(reported)
                    .map(|deleted| deleted.key.clone()).collect();
                listing.retain(|object| !receipted.contains(&object.key));
                if !budget.after_pass(&mut objects, &receipted, &state.refused_keys, now, &report) {
                    break;
                }
            }
        }
        // Everything deletable is gone; only the unauthorizable keys remain,
        // and each reached the owner exactly once.
        assert_eq!(listing.len(), REFUSED);
        for object in &listing {
            let asked = authority.calls().iter().filter(|call| **call == format!("authorize {}", object.key)).count();
            assert_eq!(asked, 1, "{}", object.key);
        }
        // Before NAN-4162 a selection of `MAX` kept refused keys at its head:
        // with every refused key known, the old selection still offered
        // them first, and a pass planned nothing deletable.
        let live = crate::lake_part_gc::live_part_keys(TENANT_UUID, &mut state.view, &reader).await.unwrap();
        let old = InventorySelection::new("tenant1", TENANT_UUID, &state.view, &live, now, policy).unwrap();
        assert!(listing.iter().take(MAX).all(|object| old.eligible(object)));
    }

}

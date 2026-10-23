// SPDX-License-Identifier: AGPL-3.0-or-later

//! The verified log view and the pure GC planner (contract 6.4).
//!
//! The planner only proposes. Control re-attests every request against its
//! own complete index before the owner signs anything, so a planner bug can
//! at worst cost a refused permit; the planner is still written to never
//! propose a live part, a log key or a superseded part's provenance.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::index::PartLogReader;

use super::request::{
    is_log_key, parse_part_file_key, LakePartDeleteReason, LakePartDeleteRequest, MAX_GRACE_SECONDS,
    MAX_ORPHAN_AGE_SECONDS, MIN_GRACE_SECONDS, MIN_ORPHAN_AGE_SECONDS, ORPHAN_ID_MEMORY_MARGIN_MS, RETENTION_DAYS,
};
use crate::parts::format::{
    data_file_name, tokens_file_name, PartKeys, PARTIAL_ENTITY_RANGES_FILE, PARTIAL_PREVALENCE_FILE,
    PARTIAL_RISK_FILE, PARTIAL_ROLLUP_FILE, PARTS_ROOT, PROVENANCE_FILE,
};
use crate::parts::part_log::{Checkpoint, LiveSet, LogEntry, LogOp, ID_MEMORY_MS};
use crate::parts::PartId;

const DAY_MS: i64 = 86_400_000;

/// Which op removed a part from the live set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalKind {
    Merge,
    Rewrite,
    Retire,
}

/// The committed entry that removed a part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Removal {
    pub seq: u64,
    /// SHA-256 of the entry's exact stored bytes.
    pub entry_sha256: String,
    pub kind: RemovalKind,
    /// The entry's `appended_at_ms`. Control checks grace against the entry's
    /// writer-receipt completion instead, which is never earlier in practice;
    /// a later receipt only turns into a `lake_part_within_grace` skip.
    pub committed_at_ms: i64,
}

/// The live set plus the history the planner needs, folded only from
/// verified entries (signature / canonical form and chain already checked by
/// the caller's reader; [`LiveSet::apply`] re-checks the chain and live-set
/// rules here).
///
/// Unlike [`LiveSet`], the view never forgets an added id or a removal, so a
/// caller keeps one view per tenant and extends it with [`Self::apply`]
/// (O(new entries) per pass). Memory is one id per part ever added.
///
/// Serializable: the lean cell persists it (with its head) so a restart
/// resumes from the last verified entry instead of re-reading from seq 0.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakePartLogView {
    live: LiveSet,
    known: BTreeSet<PartId>,
    removals: BTreeMap<PartId, Removal>,
    from_genesis: bool,
    /// Adopted part id -> its original object key (contract 8.1), from the
    /// part's verified provenance. Cached; pruned to live parts.
    adopted_keys: BTreeMap<PartId, String>,
}

impl LakePartLogView {
    /// An empty view that will be folded from seq 0. Only such a view may
    /// plan orphans: "no entry adds this id" needs every entry.
    pub fn genesis() -> Self {
        Self { from_genesis: true, ..Self::default() }
    }

    /// A view starting at a verified checkpoint. It never plans orphans
    /// (parts added and removed before the checkpoint are unknown to it) and
    /// only sees removals committed after the checkpoint.
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Result<Self> {
        let live = LiveSet::from_checkpoint(checkpoint)?;
        let known = live.parts().map(|part| part.part_id.clone()).collect();
        Ok(Self { live, known, removals: BTreeMap::new(), from_genesis: false, adopted_keys: BTreeMap::new() })
    }

    /// Apply one verified entry; `entry_sha256` is SHA-256 of its bytes.
    pub fn apply(&mut self, entry: &LogEntry, entry_sha256: &str) -> Result<()> {
        self.live.apply(entry, entry_sha256)?;
        let (seq, at) = (entry.seq, entry.appended_at_ms);
        let mut remove = |ids: &[PartId], kind: RemovalKind| {
            for id in ids {
                self.removals.insert(
                    id.clone(),
                    Removal { seq, entry_sha256: entry_sha256.to_string(), kind, committed_at_ms: at },
                );
            }
        };
        match &entry.op {
            LogOp::Merge { supersedes, .. } => remove(supersedes, RemovalKind::Merge),
            LogOp::Rewrite { supersedes, .. } => remove(supersedes, RemovalKind::Rewrite),
            LogOp::Retire { parts, .. } => remove(parts, RemovalKind::Retire),
            _ => {}
        }
        match &entry.op {
            LogOp::Add { parts, .. } | LogOp::Adopt { parts } => {
                self.known.extend(parts.iter().map(|part| part.part_id.clone()));
            }
            LogOp::Merge { output, .. } | LogOp::Rewrite { output, .. } => {
                self.known.insert(output.part_id.clone());
            }
            _ => {}
        }
        Ok(())
    }

    /// Historical identities retained by the GC view (for cell memory budgets).
    pub fn part_count(&self) -> usize { self.known.len().saturating_add(self.removals.len()) }

    pub fn head_seq(&self) -> Option<u64> {
        self.live.head().map(|(seq, _, _)| seq)
    }

    pub fn live(&self) -> &LiveSet {
        &self.live
    }

    pub fn is_live(&self, id: &PartId) -> bool {
        self.live.get(id).is_some()
    }

    pub fn is_known(&self, id: &PartId) -> bool {
        self.known.contains(id)
    }

    pub fn removal(&self, id: &PartId) -> Option<&Removal> {
        self.removals.get(id)
    }

    pub fn from_genesis(&self) -> bool {
        self.from_genesis
    }
}

/// Every key a LIVE part references: its part-directory files, and for an
/// adopted part (contract 8.1) the original object it serves from outside
/// `lake/parts/` (`ProvenanceRecord::data_key(keys, 0)`, read from the
/// part's verified provenance). The planner never emits one of these.
pub async fn live_part_keys(
    tenant_uuid: &str,
    view: &mut LakePartLogView,
    reader: &dyn PartLogReader,
) -> Result<BTreeSet<String>> {
    let mut keys = BTreeSet::new();
    let live: Vec<_> = view.live.parts().cloned().collect();
    // `live` is keyed by id: O(adopted log live), never adopted x live.
    let live_set = &view.live;
    view.adopted_keys.retain(|id, _| live_set.get(id).is_some());
    for part in &live {
        let part_keys = PartKeys::new(tenant_uuid, part.level, part.event_hour, &part.part_id)
            .with_context(|| format!("live part {} has no key layout", part.part_id))?;
        for index in 0..part.data_files as usize {
            keys.insert(part_keys.file(&data_file_name(index)));
            keys.insert(part_keys.file(&tokens_file_name(index)));
            keys.insert(part_keys.file(&format!("uids-{index:05}.json")));
            keys.insert(part_keys.file(&format!("entities-{index:05}.json")));
            keys.insert(part_keys.file(&format!("locators-{index:05}.json")));
            keys.insert(part_keys.file(&format!("ranges-{index:05}.json")));
        }
        for name in [
            PROVENANCE_FILE,
            PARTIAL_ROLLUP_FILE,
            PARTIAL_PREVALENCE_FILE,
            PARTIAL_ENTITY_RANGES_FILE,
            PARTIAL_RISK_FILE,
        ] {
            keys.insert(part_keys.file(name));
        }
        if part.sorted {
            continue;
        }
        // Unsorted = adopted: its data file is an object outside the part dir.
        if !view.adopted_keys.contains_key(&part.part_id) {
            let record = reader.verified_provenance(part).await?;
            let data_key = record
                .data_key(&part_keys, 0)
                .with_context(|| format!("adopted part {} has no data file", part.part_id))?;
            view.adopted_keys.insert(part.part_id.clone(), data_key);
        }
        keys.insert(view.adopted_keys[&part.part_id].clone());
    }
    Ok(keys)
}

/// One listed object under the tenant's `parts/` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedPartObject {
    pub key: String,
    /// Quoted strong etag, as R2 reports it.
    pub strong_etag: String,
    pub content_length: u64,
    pub uploaded_at_ms: i64,
}

/// GC policy (coordinator decisions in the spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcPolicy {
    pub grace_seconds: u64,
    pub orphan_min_age_seconds: u64,
    /// The tenant's retention; `None` plans no retention deletes.
    pub retention_days: Option<u64>,
    /// Most requests one plan returns.
    pub max_requests: usize,
}

impl Default for GcPolicy {
    fn default() -> Self {
        Self {
            grace_seconds: MIN_GRACE_SECONDS,
            orphan_min_age_seconds: MIN_ORPHAN_AGE_SECONDS,
            retention_days: None,
            max_requests: 512,
        }
    }
}

impl GcPolicy {
    pub fn validate(&self) -> Result<()> { self.validate_with_local(false) }

    pub(crate) fn validate_with_local(&self, trusted_local: bool) -> Result<()> {
        if !(MIN_GRACE_SECONDS..=MAX_GRACE_SECONDS).contains(&self.grace_seconds)
            || !(MIN_ORPHAN_AGE_SECONDS..=MAX_ORPHAN_AGE_SECONDS).contains(&self.orphan_min_age_seconds)
            || self.retention_days.is_some_and(|days| !(RETENTION_DAYS.contains(&days) || (trusted_local && (1..=3650).contains(&days))))
            || self.max_requests == 0
        {
            bail!("lake part GC policy is outside the spec bounds");
        }
        Ok(())
    }
}

/// What [`plan`] proposes and what it passed over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanReport {
    /// Ordered by key; at most `policy.max_requests`.
    pub requests: Vec<LakePartDeleteRequest>,
    /// Objects not planned, by reason.
    pub skipped: BTreeMap<&'static str, u64>,
    /// More deletable objects remained after `max_requests`.
    pub truncated: bool,
}

/// Plan deletes for one tenant. Pure and deterministic: the same inputs give
/// the same requests in key order.
///
/// `live_keys` is [`live_part_keys`]: as a final assertion no emitted key is
/// one of them, and every emitted key is under the tenant's `parts/` prefix.
pub fn plan(
    tenant_id: &str,
    tenant_uuid: &str,
    view: &LakePartLogView,
    live_keys: &BTreeSet<String>,
    objects: &[ListedPartObject],
    now_ms: i64,
    policy: &GcPolicy,
) -> Result<PlanReport> {
    let mut cursor = PlanCursor::new(tenant_id, tenant_uuid, view, live_keys, objects, now_ms, policy)?;
    let requests = cursor.by_ref().collect();
    Ok(PlanReport { requests, skipped: cursor.skipped, truncated: cursor.truncated })
}

/// Local-only planner, preserving the open settings range without widening
/// any hosted permit or policy validation.
pub(crate) fn plan_local(
    tenant: &str, view: &LakePartLogView, live_keys: &BTreeSet<String>,
    objects: &[ListedPartObject], now_ms: i64, policy: &GcPolicy,
) -> Result<PlanReport> {
    policy.validate_with_local(true)?;
    let mut objects: Vec<_> = objects.iter().collect();
    objects.sort_by(|a, b| a.key.cmp(&b.key));
    objects.dedup_by(|a, b| a.key == b.key);
    let mut report = PlanReport::default();
    for object in objects {
        match eligible_request_with_local(tenant, tenant, view, live_keys, object, now_ms, policy, true) {
            Ok(request) if report.requests.len() < policy.max_requests => report.requests.push(request),
            Ok(_) => { report.truncated = true; break; },
            Err(reason) => *report.skipped.entry(reason).or_default() += 1,
        }
    }
    Ok(report)
}

/// Selection from a complete ordered object scan, evaluated against a complete
/// verified log view. Object inventory is NOT an absence oracle: orphan absence
/// comes only from `view.from_genesis()` and its historical known-ID set.
///
/// Eligibility is object-local (including protection by every live key). Thus
/// retaining the first bounded eligible set is equivalent to the prefix of
/// `plan` for this view, regardless of inventory size or partition boundaries.
/// Discarded objects are deferred to a later task, never declared absent. The
/// executor MUST fold arrivals and re-plan retained objects before authorizing.
pub struct InventorySelection<'a> {
    tenant_id: &'a str,
    tenant_uuid: &'a str,
    view: &'a LakePartLogView,
    live_keys: &'a BTreeSet<String>,
    now_ms: i64,
    policy: GcPolicy,
    refused: Option<&'a super::executor::RefusedKeys>,
    retain: Option<usize>,
}

/// Most eligible objects one task retains ([`InventorySelection::retaining`]).
pub const MAX_SELECTION_RETAINED: usize = 4 * 512;

impl<'a> InventorySelection<'a> {
    pub(crate) fn new(
        tenant_id: &'a str, tenant_uuid: &'a str, view: &'a LakePartLogView,
        live_keys: &'a BTreeSet<String>, now_ms: i64, policy: GcPolicy,
    ) -> Result<Self> {
        policy.validate()?;
        Ok(Self { tenant_id, tenant_uuid, view, live_keys, now_ms, policy, refused: None, retain: None })
    }

    /// NAN-4162: keys the executor would skip as refused (within their TTL)
    /// are not candidates. Unauthorizable keys (no writer receipt, 24 h) sort
    /// first and used to fill most of every bounded selection, capping a large tenant's
    /// GC at 180 deletes per task while ingest superseded far more.
    pub(crate) fn excluding(mut self, refused: &'a super::executor::RefusedKeys) -> Self {
        self.refused = Some(refused);
        self
    }

    /// NAN-4162: retain up to `count` eligible objects (at most
    /// [`MAX_SELECTION_RETAINED`]) so one listing feeds several bounded passes.
    pub(crate) fn retaining(mut self, count: usize) -> Self {
        self.retain = Some(count.clamp(1, MAX_SELECTION_RETAINED));
        self
    }

    pub(crate) fn limit(&self) -> usize { self.retain.unwrap_or_else(|| self.policy.max_requests.min(512)) }

    pub(crate) fn eligible(&self, object: &ListedPartObject) -> bool {
        if self.refused.is_some_and(|refused| refused.is_refused(&object.key, self.now_ms)) {
            return false;
        }
        eligible_request(self.tenant_id, self.tenant_uuid, self.view, self.live_keys,
            object, self.now_ms, &self.policy).is_ok()
    }
}

fn eligible_request(
    tenant_id: &str, tenant_uuid: &str, view: &LakePartLogView,
    live_keys: &BTreeSet<String>, object: &ListedPartObject, now_ms: i64, policy: &GcPolicy,
) -> Result<LakePartDeleteRequest, &'static str> {
    eligible_request_with_local(tenant_id, tenant_uuid, view, live_keys, object, now_ms, policy, false)
}

#[allow(clippy::too_many_arguments)]
fn eligible_request_with_local(
    tenant_id: &str, tenant_uuid: &str, view: &LakePartLogView,
    live_keys: &BTreeSet<String>, object: &ListedPartObject, now_ms: i64, policy: &GcPolicy, trusted_local: bool,
) -> Result<LakePartDeleteRequest, &'static str> {
    let request = plan_one(tenant_id, tenant_uuid, view, object, now_ms, policy,
        policy.grace_seconds as i64 * 1_000, policy.orphan_min_age_seconds as i64 * 1_000)?;
    if !request.key.starts_with(&format!("{PARTS_ROOT}/tenant={tenant_uuid}/parts/")) {
        return Err("outside_parts_prefix");
    }
    if live_keys.contains(&request.key) { return Err("live_key"); }
    request.validate_with_local(trusted_local).map_err(|_| "invalid_request")?;
    Ok(request)
}

/// Evaluate one candidate at a time against the same complete view. This
/// retains no absence decisions: each next() performs every live/removal,
/// identity, grace/retention and exact request validation afresh. The caller
/// still needs current authoritative index completeness for EACH permit.
/// The sorted listing and attempt limit are the same bounds as plan().
pub(crate) struct PlanCursor<'a> {
    tenant_id: &'a str,
    tenant_uuid: &'a str,
    view: &'a LakePartLogView,
    live_keys: &'a BTreeSet<String>,
    objects: std::vec::IntoIter<&'a ListedPartObject>,
    now_ms: i64,
    policy: GcPolicy,
    emitted: usize,
    pub(crate) skipped: BTreeMap<&'static str, u64>,
    truncated: bool,
}

impl<'a> PlanCursor<'a> {
    pub(crate) fn new(
        tenant_id: &'a str, tenant_uuid: &'a str, view: &'a LakePartLogView,
        live_keys: &'a BTreeSet<String>, objects: &'a [ListedPartObject],
        now_ms: i64, policy: &GcPolicy,
    ) -> Result<Self> {
        policy.validate()?;
        let mut sorted: Vec<_> = objects.iter().collect();
        sorted.sort_by(|a, b| a.key.cmp(&b.key));
        sorted.dedup_by(|a, b| a.key == b.key);
        Ok(Self {
            tenant_id, tenant_uuid, view, live_keys, objects: sorted.into_iter(), now_ms,
            policy: *policy,
            emitted: 0, skipped: BTreeMap::new(), truncated: false,
        })
    }
}

impl Iterator for PlanCursor<'_> {
    type Item = LakePartDeleteRequest;
    fn next(&mut self) -> Option<Self::Item> {
        if self.truncated { return None; }
        for object in self.objects.by_ref() {
            let reason = match eligible_request(self.tenant_id, self.tenant_uuid, self.view,
                self.live_keys, object, self.now_ms, &self.policy) {
                Ok(request) if self.emitted < self.policy.max_requests => {
                    self.emitted += 1;
                    return Some(request);
                }
                Ok(_) => { self.truncated = true; return None; }
                Err(reason) => reason,
            };
            *self.skipped.entry(reason).or_default() += 1;
        }
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn plan_one(
    tenant_id: &str,
    tenant_uuid: &str,
    view: &LakePartLogView,
    object: &ListedPartObject,
    now_ms: i64,
    policy: &GcPolicy,
    grace_ms: i64,
    orphan_ms: i64,
) -> Result<LakePartDeleteRequest, &'static str> {
    if is_log_key(&object.key) {
        return Err("log_key");
    }
    let key = parse_part_file_key(&object.key).ok_or("unparseable_key")?;
    if key.tenant_uuid != tenant_uuid {
        return Err("foreign_tenant");
    }
    if view.is_live(&key.part_id) {
        return Err("live");
    }
    let base = |reason| {
        LakePartDeleteRequest::base(
            tenant_id,
            tenant_uuid,
            &object.key,
            &object.strong_etag,
            object.content_length,
            reason,
        )
    };
    if let Some(removal) = view.removal(&key.part_id) {
        if now_ms.saturating_sub(removal.committed_at_ms) < grace_ms {
            return Err("within_grace");
        }
        let with_removal = |mut request: LakePartDeleteRequest| {
            request.removal_seq = Some(removal.seq);
            request.removal_entry_sha256 = Some(removal.entry_sha256.clone());
            request.grace_seconds = Some(policy.grace_seconds);
            request
        };
        if matches!(removal.kind, RemovalKind::Merge | RemovalKind::Rewrite) && !key.is_provenance() {
            return Ok(with_removal(base(LakePartDeleteReason::Superseded)));
        }
        let Some(days) = policy.retention_days else {
            return Err(if key.is_provenance() { "provenance_kept" } else { "retired_no_retention_policy" });
        };
        let day_end_ms = key.path_hour.timestamp_millis().div_euclid(DAY_MS) * DAY_MS + DAY_MS;
        if day_end_ms.saturating_add(days as i64 * DAY_MS) > now_ms {
            return Err(if key.is_provenance() { "provenance_kept" } else { "within_retention" });
        }
        let mut request = with_removal(base(LakePartDeleteReason::Retention));
        request.retention_day = Some(key.day());
        request.retention_days = Some(days);
        return Ok(request);
    }
    if view.is_known(&key.part_id) {
        return Err("known_not_removed");
    }
    if !view.from_genesis() {
        return Err("orphan_needs_full_log");
    }
    if object.uploaded_at_ms.saturating_add(orphan_ms) > now_ms
        || key.part_id.created_unix_ms() + ID_MEMORY_MS + ORPHAN_ID_MEMORY_MARGIN_MS > now_ms
    {
        return Err("orphan_too_young");
    }
    let mut request = base(LakePartDeleteReason::Orphan);
    request.orphan_min_age_seconds = Some(policy.orphan_min_age_seconds);
    Ok(request)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::lake_part_gc::request::tests::TENANT_UUID;
    use crate::parts::levels::Level;
    use crate::parts::part_log::{LogSchema, PartRef, RetireReason, SourceRef, GENESIS_PREV, LOG_FORMAT};
    use crate::parts::provenance::{PartInputs, ProvenanceRecord};
    use crate::parts::sha256_hex;

    /// 2026-09-25T10:00:00Z.
    pub const T0: i64 = 1_790_330_400_000;
    const HOUR: i64 = 3_600_000;

    pub fn id(n: u64) -> PartId {
        PartId::parse(&format!("{:013}-{:016x}", T0 as u64 + n, n)).unwrap()
    }

    pub fn part_ref(n: u64, level: Level) -> PartRef {
        PartRef {
            part_id: id(n),
            level,
            event_hour: (T0 / HOUR) as i32,
            event_day: None,
            rows: 5,
            min_time_us: 1,
            max_time_us: 2,
            schema_fingerprint: "a".repeat(64),
            provenance_sha256: "b".repeat(64),
            merkle_root: "c".repeat(64),
            sorted: level == Level::L0 || level == Level::Minute,
            data_bytes: 10,
            row_groups: 1,
            data_files: 1,
        }
    }

    /// The verified record of adopted part `n` serving `object_key`.
    pub fn adopted_record(n: u64, object_key: &str, sha256: &str) -> ProvenanceRecord {
        let mut record = crate::parts::provenance::tests::adopted_record();
        record.tenant_id = TENANT_UUID.into();
        record.part_id = id(n);
        record.created_at_ms = id(n).created_unix_ms();
        record.files.data[0].name = object_key.into();
        record.files.data[0].sha256 = sha256.into();
        if let PartInputs::Adopted { objects, .. } = &mut record.inputs {
            objects[0].key = object_key.into();
            objects[0].sha256 = sha256.into();
        }
        record
    }

    pub fn key(n: u64, level: Level, file: &str) -> String {
        PartKeys::new(TENANT_UUID, level, (T0 / HOUR) as i32, &id(n)).unwrap().file(file)
    }

    /// A chain of entries `(entry, sha)`; the sha stands in for the stored bytes.
    pub struct Chain {
        pub entries: Vec<(LogEntry, String)>,
        /// Verified provenance of adopted parts, by id.
        pub records: BTreeMap<PartId, ProvenanceRecord>,
    }

    impl Chain {
        pub fn new() -> Self {
            use arrow_schema::{DataType, Field, Schema, TimeUnit};
            let schema = Schema::new(vec![
                Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())), false),
                Field::new("message", DataType::Utf8, true),
            ]);
            let mut chain = Self { entries: Vec::new(), records: BTreeMap::new() };
            chain.push(LogOp::Genesis { schema: LogSchema::from_arrow(&schema).unwrap() }, T0);
            chain
        }

        pub fn push(&mut self, op: LogOp, at_ms: i64) -> &mut Self {
            let seq = self.entries.len() as u64;
            let prev = self.entries.last().map_or(GENESIS_PREV.to_string(), |(_, sha)| sha.clone());
            let entry = LogEntry {
                format: LOG_FORMAT.into(),
                tenant_id: TENANT_UUID.into(),
                seq,
                prev_sha256: prev,
                writer_epoch: 1,
                appended_at_ms: at_ms,
                op,
            };
            let sha = sha256_hex(&entry.to_bytes().unwrap());
            self.entries.push((entry, sha));
            self
        }

        pub fn add(&mut self, n: u64, at_ms: i64) -> &mut Self {
            let consumed = vec![SourceRef { key: format!("bronze/{n}"), version: "1".into(), sha256: "d".repeat(64) }];
            self.push(LogOp::Add { parts: vec![part_ref(n, Level::L0)], consumed, edge_log: None }, at_ms)
        }

        /// Adopt the object `object_key` as H part `n`.
        pub fn adopt(&mut self, n: u64, object_key: &str, at_ms: i64) -> &mut Self {
            self.records.insert(id(n), adopted_record(n, object_key, &"e".repeat(64)));
            self.push(LogOp::Adopt { parts: vec![part_ref(n, Level::Hour)] }, at_ms)
        }

        pub fn view(&self) -> LakePartLogView {
            let mut view = LakePartLogView::genesis();
            for (entry, sha) in &self.entries {
                view.apply(entry, sha).unwrap();
            }
            view
        }
    }

    fn none() -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn object(key: String, uploaded_at_ms: i64) -> ListedPartObject {
        ListedPartObject { key, strong_etag: "\"e\"".into(), content_length: 9, uploaded_at_ms }
    }

    #[test]
    fn bounded_selection_equals_planner_and_arrivals_reprotect_candidates() {
        let mut chain = fixture();
        let view = chain.view();
        let mut objects = files(1, Level::L0); // Superseded; provenance protected.
        objects.extend(files(3, Level::Minute)); // Live output.
        objects.extend(files(4, Level::L0)); // Live input.
        objects.extend(files(50, Level::L0)); // Old orphan.
        objects.push(object(key(51, Level::L0, "data-00000.parquet"), T0 + 4 * DAY_MS));
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        let protected = BTreeSet::from([key(50, Level::L0, "tokens-00000.nti")]);
        let policy = GcPolicy { max_requests: 512, ..GcPolicy::default() };
        let now = T0 + 4 * DAY_MS;
        let selection = InventorySelection::new("tenant1", TENANT_UUID, &view, &protected, now, policy).unwrap();
        let selected: Vec<_> = objects.iter().filter(|object| selection.eligible(object))
            .take(selection.limit()).cloned().collect();
        let expected = plan("tenant1", TENANT_UUID, &view, &protected, &objects, now, &policy).unwrap();
        let actual = plan("tenant1", TENANT_UUID, &view, &protected, &selected, now, &policy).unwrap();
        assert_eq!(actual.requests, expected.requests);
        assert!(actual.requests.iter().any(|request| request.reason == LakePartDeleteReason::Orphan));
        assert!(actual.requests.iter().any(|request| request.reason == LakePartDeleteReason::Superseded));
        // An immutable first add arrives DURING listing. The post-list fold and
        // real planner must protect every retained key of that now-live part.
        // A delayed commit carries its original within-window append timestamp.
        chain.add(50, T0 + 700_000);
        let newer = chain.view();
        let replanned = plan("tenant1", TENANT_UUID, &newer, &protected, &selected, now, &policy).unwrap();
        assert!(replanned.requests.iter().all(|request| parse_part_file_key(&request.key).unwrap().part_id != id(50)));
        // A checkpoint/partial LOG view cannot manufacture orphan absence,
        // even when the object scan itself is complete.
        let partial = LakePartLogView::default();
        let selection = InventorySelection::new("tenant1", TENANT_UUID, &partial, &protected, now, policy).unwrap();
        assert!(files(70, Level::L0).iter().all(|object| !selection.eligible(object)));
    }

    fn reasons(report: &PlanReport) -> Vec<(String, LakePartDeleteReason)> {
        report.requests.iter().map(|r| (r.key.clone(), r.reason)).collect()
    }

    /// Parts 1, 2 merged into 3 at T0 + 10 min; part 4 live; part 5 retired.
    fn fixture() -> Chain {
        let mut chain = Chain::new();
        chain.add(1, T0 + 1_000).add(2, T0 + 2_000).add(4, T0 + 3_000).add(5, T0 + 4_000);
        chain.push(
            LogOp::Merge { output: part_ref(3, Level::Minute), supersedes: vec![id(1), id(2)] },
            T0 + 600_000,
        );
        chain.push(
            LogOp::Retire { parts: vec![id(5)], reason: RetireReason::Retention, deletion_unit: "u".into() },
            T0 + 600_000,
        );
        chain
    }

    fn files(n: u64, level: Level) -> Vec<ListedPartObject> {
        ["data-00000.parquet", "tokens-00000.nti", "partials/rollup.parquet", "provenance.json"]
            .into_iter()
            .map(|file| object(key(n, level, file), T0))
            .collect()
    }

    /// A refused entry leaves the live set and the view exactly as they
    /// were (the journaled rollback that replaced the per-entry clone),
    /// whatever it had mutated before the refusal.
    #[test]
    fn a_refused_entry_rolls_back_every_mutation() {
        let mut chain = fixture();
        let seq = chain.entries.len() as u64;
        let prev = chain.entries.last().unwrap().1.clone();
        let mut view = chain.view();
        let before = format!("{view:?}");
        let entry = |op: LogOp| LogEntry {
            format: crate::parts::part_log::LOG_FORMAT.into(),
            tenant_id: TENANT_UUID.into(),
            seq,
            prev_sha256: prev.clone(),
            writer_epoch: 1,
            appended_at_ms: T0 + 700_000,
            op,
        };
        for bad in [
            // Removes 3 and 4, then refuses 1 (already superseded).
            LogOp::Merge { output: part_ref(9, Level::Hour), supersedes: vec![id(3), id(4), id(1)] },
            // Adds 10, then refuses the repeated 4 (before any consume).
            LogOp::Add {
                parts: vec![part_ref(10, Level::L0), part_ref(4, Level::L0)],
                consumed: vec![SourceRef { key: "bronze/x".into(), version: "1".into(), sha256: "d".repeat(64) }],
                edge_log: None,
            },
            // Retires 4, then refuses 5 (already retired).
            LogOp::Retire { parts: vec![id(4), id(5)], reason: RetireReason::Retention, deletion_unit: "u".into() },
        ] {
            assert!(view.apply(&entry(bad.clone()), &"f".repeat(64)).is_err(), "{bad:?}");
            assert_eq!(format!("{view:?}"), before, "{bad:?} left a mutation behind");
        }
        // The same view still accepts the next good entry.
        chain.add(11, T0 + 700_000);
        let (good, sha) = chain.entries.last().unwrap().clone();
        view.apply(&good, &sha).unwrap();
        assert!(view.is_live(&id(11)));
    }

    /// The persisted form round-trips exactly (the lean cell resumes its
    /// GC view from it).
    #[test]
    fn the_view_round_trips_through_json() {
        let mut chain = fixture();
        chain.adopt(20, "warehouse/nano/events/data/a.parquet", T0 + 700_000);
        let mut view = chain.view();
        view.adopted_keys.insert(id(20), "warehouse/nano/events/data/a.parquet".into());
        let json = serde_json::to_vec(&view).unwrap();
        let back: LakePartLogView = serde_json::from_slice(&json).unwrap();
        assert_eq!(format!("{back:?}"), format!("{view:?}"));
        assert!(back.from_genesis());
        assert_eq!(back.live().head(), view.live().head());
    }

    #[test]
    fn superseded_grace_boundary_keeps_provenance_and_never_touches_live() {
        let chain = fixture();
        let view = chain.view();
        let mut objects = files(1, Level::L0);
        objects.extend(files(3, Level::Minute));
        objects.extend(files(4, Level::L0));
        let policy = GcPolicy::default();
        let removed_at = T0 + 600_000;

        let early = plan("tenant1", TENANT_UUID, &view, &none(), &objects, removed_at + 3_600_000 - 1, &policy).unwrap();
        assert!(early.requests.is_empty());
        assert_eq!(early.skipped["within_grace"], 4);
        assert_eq!(early.skipped["live"], 8);

        let due = plan("tenant1", TENANT_UUID, &view, &none(), &objects, removed_at + 3_600_000, &policy).unwrap();
        let mut expected: Vec<_> = ["data-00000.parquet", "partials/rollup.parquet", "tokens-00000.nti"]
            .into_iter()
            .map(|file| (key(1, Level::L0, file), LakePartDeleteReason::Superseded))
            .collect();
        expected.sort();
        assert_eq!(reasons(&due), expected);
        assert_eq!(due.skipped["provenance_kept"], 1);
        let request = &due.requests[0];
        assert_eq!(request.removal_seq, Some(5));
        assert_eq!(request.removal_entry_sha256.as_deref(), Some(chain.entries[5].1.as_str()));
        assert_eq!(request.grace_seconds, Some(3_600));
        // Deterministic.
        let mut shuffled = objects.clone();
        shuffled.reverse();
        assert_eq!(plan("tenant1", TENANT_UUID, &view, &none(), &shuffled, removed_at + 3_600_000, &policy).unwrap(), due);
    }

    #[test]
    fn sidecars_share_part_retention_and_live_protection() {
        let view = fixture().view();
        let objects: Vec<_> = [1, 5, 4].into_iter().flat_map(|n| {
            ["uids-00000.json", "entities-00000.json", "locators-00000.json", "ranges-00000.json"].into_iter()
                .map(move |file| object(key(n, Level::L0, file), T0))
        }).collect();
        let policy = GcPolicy { retention_days: Some(30), ..GcPolicy::default() };
        let due = T0 + 14 * HOUR + 30 * DAY_MS;
        let early = plan("tenant1", TENANT_UUID, &view, &none(), &objects, due - 1, &policy).unwrap();
        assert_eq!(early.requests.len(), 4);
        assert!(early.requests.iter().all(|r| r.reason == LakePartDeleteReason::Superseded));
        let retired = plan("tenant1", TENANT_UUID, &view, &none(), &objects, due, &policy).unwrap();
        assert_eq!(retired.requests.len(), 8);
        assert_eq!(retired.requests.iter().filter(|r| r.reason == LakePartDeleteReason::Retention).count(), 4);
        assert_eq!(retired.skipped["live"], 4);
        assert!(retired.requests.iter().all(|r| !r.key.contains(&id(4).to_string())));
    }

    #[test]
    fn retention_boundary_covers_provenance_and_retired_parts() {
        let view = fixture().view();
        let mut objects = files(1, Level::L0);
        objects.extend(files(5, Level::L0));
        objects.extend(files(4, Level::L0));
        let policy = GcPolicy { retention_days: Some(30), ..GcPolicy::default() };
        // Day 2026-09-25 ends at T0 + 14 h.
        let retention_due = T0 + 14 * HOUR + 30 * DAY_MS;

        let early = plan("tenant1", TENANT_UUID, &view, &none(), &objects, retention_due - 1, &policy).unwrap();
        assert!(early.requests.iter().all(|r| r.reason == LakePartDeleteReason::Superseded));
        assert_eq!(early.requests.len(), 3);
        assert_eq!(early.skipped["provenance_kept"], 2);
        assert_eq!(early.skipped["within_retention"], 3);

        let due = plan("tenant1", TENANT_UUID, &view, &none(), &objects, retention_due, &policy).unwrap();
        let retention: Vec<_> =
            due.requests.iter().filter(|r| r.reason == LakePartDeleteReason::Retention).collect();
        assert_eq!(retention.len(), 5, "part 1 provenance + all 4 files of retired part 5");
        assert!(retention.iter().all(|r| r.retention_day.as_deref() == Some("2026-09-25")
            && r.retention_days == Some(30)
            && r.removal_seq.is_some()));
        assert!(due.requests.iter().all(|r| !r.key.contains(&id(4).to_string())), "live part never planned");
        assert_eq!(due.skipped["live"], 4);
    }

    #[test]
    fn orphan_boundaries_include_the_id_age_rule() {
        let view = fixture().view();
        // Id 9 is never added. Its id was created at T0 + 9 ms.
        let orphan_key = key(9, Level::L0, "data-00000.parquet");
        let policy = GcPolicy::default();
        let id_ok = T0 + 9 + ID_MEMORY_MS + ORPHAN_ID_MEMORY_MARGIN_MS;

        // Uploaded long ago but the id is 1 ms too young.
        let plan_at = |uploaded: i64, now: i64| {
            plan("tenant1", TENANT_UUID, &view, &none(), &[object(orphan_key.clone(), uploaded)], now, &policy).unwrap()
        };
        assert_eq!(plan_at(T0 - 100 * HOUR, id_ok - 1).skipped["orphan_too_young"], 1);
        // Upload age 1 ms under 49 h.
        let now = id_ok + 10 * HOUR;
        assert_eq!(plan_at(now - 176_400_000 + 1, now).skipped["orphan_too_young"], 1);
        // Both boundaries met exactly.
        let due = plan_at(id_ok - 176_400_000, id_ok);
        assert_eq!(reasons(&due), vec![(orphan_key.clone(), LakePartDeleteReason::Orphan)]);
        assert_eq!(due.requests[0].orphan_min_age_seconds, Some(176_400));

        // An added part never reaches the orphan rule, even long after.
        let added = plan("tenant1", TENANT_UUID, &view, &none(), &[object(key(3, Level::Minute, "data-00000.parquet"), T0)], now, &policy)
            .unwrap();
        assert!(added.requests.is_empty());

        // A checkpoint-based view never plans orphans.
        let partial = LakePartLogView::from_checkpoint(&view.live().checkpoint(TENANT_UUID).unwrap()).unwrap();
        let refused =
            plan("tenant1", TENANT_UUID, &partial, &none(), &[object(orphan_key, T0 - 100 * HOUR)], id_ok, &policy).unwrap();
        assert_eq!(refused.skipped["orphan_needs_full_log"], 1);
    }

    #[test]
    fn log_keys_foreign_and_unparseable_keys_are_never_planned() {
        let view = fixture().view();
        let log = format!("lake/parts/v1/tenant={TENANT_UUID}/log/entries/00000000000000000001.json");
        let checkpoint = format!("lake/parts/v1/tenant={TENANT_UUID}/log/checkpoints/00000000000000001024.json");
        let other = "7f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let foreign = key(9, Level::L0, "data-00000.parquet").replace(TENANT_UUID, other);
        let objects = vec![
            object(log, T0),
            object(checkpoint, T0),
            object(format!("lake/parts/v1/tenant={TENANT_UUID}/log/HEAD"), T0),
            object(foreign, T0),
            object(key(9, Level::L0, "data-00000.parquet.tmp"), T0),
        ];
        let report = plan("tenant1", TENANT_UUID, &view, &none(), &objects, T0 + 400 * DAY_MS, &GcPolicy::default()).unwrap();
        assert!(report.requests.is_empty());
        assert_eq!(report.skipped["log_key"], 3);
        assert_eq!(report.skipped["foreign_tenant"], 1);
        assert_eq!(report.skipped["unparseable_key"], 1);
    }

    #[test]
    fn batch_is_bounded() {
        let view = fixture().view();
        let objects = files(1, Level::L0);
        let policy = GcPolicy { max_requests: 2, ..GcPolicy::default() };
        let report = plan("tenant1", TENANT_UUID, &view, &none(), &objects, T0 + DAY_MS, &policy).unwrap();
        assert_eq!(report.requests.len(), 2);
        assert!(report.truncated);
        assert!(GcPolicy { grace_seconds: 3_599, ..GcPolicy::default() }.validate().is_err());
        assert!(GcPolicy { orphan_min_age_seconds: 86_400, ..GcPolicy::default() }.validate().is_err());
        assert!(GcPolicy { retention_days: Some(7), ..GcPolicy::default() }.validate().is_err());
    }

    const OBJECT: &str = "warehouse/nano/events/data/a.parquet";

    #[tokio::test]
    async fn retired_then_readopted_object_is_never_planned() {
        use crate::lake_part_gc::index::tests::ChainReader;
        let mut chain = Chain::new();
        chain.adopt(10, OBJECT, T0 + 1_000);
        chain.push(
            LogOp::Retire { parts: vec![id(10)], reason: RetireReason::Retention, deletion_unit: "u".into() },
            T0 + 2_000,
        );
        chain.adopt(11, OBJECT, T0 + 3_000);
        let mut view = chain.view();
        let reader = ChainReader { chain, checkpoint: None };
        let live = live_part_keys(TENANT_UUID, &mut view, &reader).await.unwrap();
        assert!(live.contains(OBJECT), "the re-adopted object is a live key");
        assert!(live.contains(&key(11, Level::Hour, "provenance.json")));

        let mut objects = vec![object(OBJECT.into(), T0), object("warehouse/nano/events/data/b.parquet".into(), T0)];
        for part in [10, 11] {
            for file in ["tokens-00000.nti", "partials/rollup.parquet", "provenance.json", "data-00000.parquet"] {
                objects.push(object(key(part, Level::Hour, file), T0));
            }
        }
        let policy = GcPolicy { retention_days: Some(30), ..GcPolicy::default() };
        let now = T0 + 400 * DAY_MS;
        let report = plan("tenant1", TENANT_UUID, &view, &live, &objects, now, &policy).unwrap();
        let prefix = format!("lake/parts/v1/tenant={TENANT_UUID}/parts/");
        assert_eq!(report.requests.len(), 4, "only the retired part's own directory: {report:?}");
        for request in &report.requests {
            assert!(request.key.starts_with(&prefix));
            assert!(request.key.contains(&id(10).to_string()));
            assert!(!live.contains(&request.key));
            assert_eq!(request.reason, LakePartDeleteReason::Retention);
        }
        assert_eq!(report.skipped["unparseable_key"], 2, "both objects outside lake/parts/");
        assert_eq!(report.skipped["live"], 4);
        // Cached adopted keys survive a re-resolve without the provenance.
        let empty = ChainReader { chain: Chain::new(), checkpoint: None };
        assert!(live_part_keys(TENANT_UUID, &mut view, &empty).await.unwrap().contains(OBJECT));
    }

    #[tokio::test]
    async fn live_keys_are_a_final_assertion() {
        use crate::lake_part_gc::index::tests::ChainReader;
        let chain = fixture();
        let mut view = chain.view();
        let reader = ChainReader { chain, checkpoint: None };
        let mut live = live_part_keys(TENANT_UUID, &mut view, &reader).await.unwrap();
        for part in [(3, Level::Minute), (4, Level::L0)] {
            for file in ["data-00000.parquet", "tokens-00000.nti", "uids-00000.json", "entities-00000.json", "locators-00000.json", "ranges-00000.json", "provenance.json", "partials/risk.parquet"] {
                assert!(live.contains(&key(part.0, part.1, file)));
            }
        }
        assert!(!live.contains(&key(1, Level::L0, "data-00000.parquet")));
        let mut objects = files(1, Level::L0);
        objects.extend(files(4, Level::L0));
        let now = T0 + DAY_MS;
        let policy = GcPolicy::default();
        let before = plan("tenant1", TENANT_UUID, &view, &live, &objects, now, &policy).unwrap();
        assert_eq!(before.requests.len(), 3);
        assert!(before.requests.iter().all(|r| !live.contains(&r.key)));
        // Even a key the log view would delete is refused once a live part names it.
        live.insert(key(1, Level::L0, "data-00000.parquet"));
        let after = plan("tenant1", TENANT_UUID, &view, &live, &objects, now, &policy).unwrap();
        assert_eq!(after.requests.len(), 2);
        assert_eq!(after.skipped["live_key"], 1);
        assert_eq!(after.skipped["live"], 4);
    }
}

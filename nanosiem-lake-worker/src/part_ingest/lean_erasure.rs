// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data-subject erasure for a lean-lake tenant (NAN-3867).
//!
//! The platform erasure runner (the enterprise crate's `erasure_shared_runtime`)
//! files a work order in `public.lake_erasure_work_orders` (9000561/9000821),
//! exactly as for a gen1 tenant. On a lean cell the executor is `ingest[T]`
//! itself, the tenant's single part-log writer: it reaches the order through
//! the tenant's own `publish` data-path login (the credential exchange's
//! `erasure_ledger`, which RLS confines to this tenant's rows) and turns it
//! into signed part rewrites:
//!
//! 1. **scan**: hour by hour over the live parts that overlap
//!    `[event_time_floor, cutoff_time]`, probe each part from its signed
//!    sidecars alone ([`probe_part`]); rewrite every part that may hold the
//!    subject through the compaction merge with an [`ErasureRowFilter`]
//!    (subject rows dropped, free-text mentions replaced by the request's
//!    `identifier_hash`, every partial rebuilt from the kept rows), publish
//!    the output like a compaction, and commit one
//!    `rewrite{output, supersedes, deletion_unit: "erasure:<order>"}`
//!    (`retire{reason: erasure}` when no row of the hour survives).
//! 2. **tail**: sweep the parts created since the previous sweep started
//!    (compaction outputs, late adds, our own outputs) until a sweep
//!    changes nothing.
//! 3. **prevalence**: an IP subject's SlateDB window is deleted once the
//!    prevalence replay has applied every entry through the last rewrite.
//! 4. the order completes; the runner completes the request with the
//!    part-log receipt ([`WorkOrderPass`]-compatible pass records).
//!
//! Superseded part files are deleted by the sanctioned part GC
//! (`superseded`, after its grace), under the tenant's delete grant and
//! legal hold. Everything is idempotent: an uncommitted output is an orphan
//! (GC'd after 49 h); a replayed step finds the hour clean and commits
//! nothing; progress is persisted only after the log commit.
//!
//! [`WorkOrderPass`]: https://docs.rs/ (nanosiem-core `shared_erasure_runtime::WorkOrderPass`)

use anyhow::{bail, ensure, Context, Result};
use arrow_array::{Array, RecordBatch, StringArray};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;

use super::merge::RowFilter;
use crate::erasure::{
    subject_keep_mask_on, ErasureIdentifierType, ErasureSubject, FreeTextRedaction, LEAN_FREE_TEXT_COLUMNS,
};
use crate::parts::format::{PartKeys, ENTITY_RANGE_PATHS, PARTIAL_ENTITY_RANGES_FILE};
use crate::parts::levels::Level;
use crate::parts::part_log::{ObjectStore, PartRef};
use crate::parts::provenance::{SignedProvenance, TenantKeySet};
use crate::parts::sha256_hex;
use crate::parts::sidecar::{decode_token_index, tokenize, TOKEN_FIELDS, TOKEN_MAX_BYTES};

/// `progress.executor` of an order a lean executor owns.
pub const LEAN_EXECUTOR_KIND: &str = "lean_part_log_v1";
/// The data-path capability the exchange's `erasure_ledger` must carry.
pub const ERASURE_LEDGER_CAPABILITY: &str = "publish";
/// Executor lease on a claimed order (renewed by every recorded step).
pub const LEASE_SECS: i64 = 600;
/// Consecutive failed steps before the order is failed.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 8;
/// Pass records appended to `passes` (CHECK <= 256); counters always add.
pub const MAX_PASS_RECORDS: i32 = 250;
/// How often an idle executor looks for a new order.
pub const POLL_INTERVAL_MS: i64 = 60_000;
/// Parts one step probes from their sidecars; a larger hour is worked in
/// slices ([`HourResume`]).
pub const MAX_PROBES_PER_STEP: usize = 64;
/// Bound on every work-order ledger call: ingest[T] holds its own lock
/// while it waits.
pub const LEDGER_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long an IP order waits for the prevalence grant before it fails
/// (`lean_prevalence_unavailable`): the address must leave the SlateDB
/// window, which only a held state can do.
pub const PREVALENCE_GRANT_WAIT_MS: i64 = 6 * 3_600_000;
/// `failure_code` of an IP order whose prevalence state never came back.
pub const PREVALENCE_UNAVAILABLE: &str = "lean_prevalence_unavailable";

/// The exchange's `erasure_ledger`: the tenant's own `publish` data-path
/// login, used only for `lake_erasure_work_orders`.
#[derive(Clone, Deserialize)]
pub struct ErasureLedgerCredential {
    pub tenant_id: String,
    pub capability: String,
    pub database_url: String,
    pub expires_at: String,
}

impl std::fmt::Debug for ErasureLedgerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasureLedgerCredential")
            .field("tenant_id", &self.tenant_id)
            .field("capability", &self.capability)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl ErasureLedgerCredential {
    /// Bound to this tenant, the `publish` capability, a Postgres URL, and
    /// not expired. A credential naming another tenant is refused outright.
    pub fn validate(&self, tenant_id: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>> {
        ensure!(self.tenant_id == tenant_id, "erasure ledger credential is bound to another tenant");
        ensure!(self.capability == ERASURE_LEDGER_CAPABILITY, "erasure ledger credential is not the publish capability");
        ensure!(self.database_url.starts_with("postgres://") || self.database_url.starts_with("postgresql://"),
            "erasure ledger credential is not a Postgres URL");
        let expires = DateTime::parse_from_rfc3339(&self.expires_at)
            .context("erasure ledger credential expiry")?
            .with_timezone(&Utc);
        ensure!(expires > now, "erasure ledger credential is expired");
        Ok(expires)
    }
}

/// Where an order is in its life on this executor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeanPhase {
    #[default]
    Scan,
    Tail,
    Prevalence,
    Done,
}

/// Resume state in `lake_erasure_work_orders.progress` (opaque to the
/// runner). Written only after the step it describes is committed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeanProgress {
    #[serde(default)]
    pub executor: String,
    #[serde(default)]
    pub phase: LeanPhase,
    /// Last event hour finished in the current scan or sweep.
    #[serde(default)]
    pub cursor_hour: Option<i32>,
    /// The hour after the cursor is being worked in slices: its parts up
    /// to `after` are done.
    #[serde(default)]
    pub resume: Option<HourResume>,
    /// Parts created at or after this instant are (re)visited by the
    /// current tail sweep. Set when the scan starts.
    #[serde(default)]
    pub sweep_started_ms: Option<i64>,
    /// When the current scan or sweep began: the next sweep revisits every
    /// part created since then (a late add into an hour this pass had
    /// already passed).
    #[serde(default)]
    pub pass_began_ms: Option<i64>,
    /// An IP order has waited for the prevalence grant since then.
    #[serde(default)]
    pub prevalence_wait_since_ms: Option<i64>,
    /// The current sweep committed a change (another sweep follows).
    #[serde(default)]
    pub sweep_changed: bool,
    #[serde(default)]
    pub sweeps: u32,
    #[serde(default)]
    pub consecutive_failures: u32,
    /// Highest part-log seq this order committed (prevalence waits for it).
    #[serde(default)]
    pub last_commit_seq: Option<u64>,
}

/// The hour being worked in slices and the last part (in part-id order)
/// of it already handled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HourResume {
    pub hour: i32,
    pub after: String,
}

/// A claimed order, parsed and validated for this tenant.
#[derive(Debug, Clone)]
pub struct LeanErasureOrder {
    pub tenant_id: String,
    pub order_id: Uuid,
    pub request_id: Uuid,
    pub subject: ErasureSubject,
    pub identifier_hash: Option<String>,
    pub redact_free_text: bool,
    pub floor_us: i64,
    pub cutoff_us: i64,
    pub progress: LeanProgress,
}

impl LeanErasureOrder {
    /// The `deletion_unit` every log entry of this order carries: a verifier
    /// finds all of the order's entries in the tenant's hash-chained log.
    pub fn deletion_unit(&self) -> String {
        format!("erasure:{}", self.order_id)
    }

    /// Does the part hold any row in the order window?
    pub fn overlaps(&self, part: &PartRef) -> bool {
        part.min_time_us < self.cutoff_us && part.max_time_us >= self.floor_us
    }

    /// The selector paths of this subject on lean parts.
    pub fn paths(&self) -> &'static [&'static str] {
        self.subject.identifier_type.lean_column_paths()
    }

    /// Free-text redaction applies (request option + a hash to replace with).
    pub fn redaction(&self) -> Result<Option<FreeTextRedaction>> {
        match (&self.identifier_hash, self.redact_free_text) {
            (Some(hash), true) => Ok(Some(FreeTextRedaction::new_word_bounded(&self.subject, hash)?)),
            _ => Ok(None),
        }
    }

    pub fn filter(&self) -> Result<Arc<ErasureRowFilter>> {
        Ok(Arc::new(ErasureRowFilter { subject: self.subject.clone(), paths: self.paths(), redaction: self.redaction()? }))
    }
}

/// Drops the subject's rows and redacts free-text mentions in the kept ones.
/// Row order (and so the merge's `(time, uid)` order) is preserved.
pub struct ErasureRowFilter {
    subject: ErasureSubject,
    paths: &'static [&'static str],
    redaction: Option<FreeTextRedaction>,
}

impl RowFilter for ErasureRowFilter {
    fn apply(&self, batch: RecordBatch) -> Result<(RecordBatch, u64, u64)> {
        let (keep, removed) = subject_keep_mask_on(&batch, &self.subject, self.paths);
        let kept = if removed > 0 { arrow_select::filter::filter_record_batch(&batch, &keep)? } else { batch };
        let (kept, rewritten) = match &self.redaction {
            Some(redaction) if kept.num_rows() > 0 => redaction.redact_columns(&kept, &LEAN_FREE_TEXT_COLUMNS)?,
            _ => (kept, 0),
        };
        Ok((kept, removed, rewritten))
    }
}

/// The next event hour to work and its candidate parts (live, in the
/// window, and in a tail sweep created since the sweep started), strictly
/// after the cursor. `None`: the scan or sweep is through.
///
/// An hour being worked in slices ([`LeanProgress::resume`]) offers only
/// its parts after the resume point; with none left it counts as done.
/// At most [`MAX_PROBES_PER_STEP`] parts are returned (in part-id order);
/// the step that works them records where it stopped.
pub fn plan_hour<'p>(live: impl IntoIterator<Item = &'p PartRef>, order: &LeanErasureOrder) -> Option<(i32, Vec<PartRef>)> {
    let progress = &order.progress;
    let resume = progress.resume.as_ref()
        .filter(|resume| progress.cursor_hour.is_none_or(|cursor| resume.hour > cursor));
    let after = resume.and_then(|resume| crate::parts::format::PartId::parse(&resume.after).ok().map(|id| (resume.hour, id)));
    let mut parts = live
        .into_iter()
        .filter(|part| order.overlaps(part))
        .filter(|part| progress.cursor_hour.is_none_or(|cursor| part.event_hour > cursor))
        .filter(|part| match &after {
            // The sliced hour: only what is after the resume point; an
            // earlier hour cannot exist (the cursor is just before it).
            Some((hour, id)) if part.event_hour == *hour => part.part_id > *id,
            Some((hour, _)) => part.event_hour > *hour,
            None => true,
        })
        .filter(|part| match progress.phase {
            LeanPhase::Tail => progress.sweep_started_ms.is_none_or(|since| part.part_id.created_unix_ms() >= since),
            _ => true,
        })
        .collect::<Vec<_>>();
    let hour = parts.iter().map(|part| part.event_hour).min()?;
    parts.retain(|part| part.event_hour == hour);
    let mut parts = parts.into_iter().cloned().collect::<Vec<_>>();
    parts.sort_by(|a, b| a.part_id.cmp(&b.part_id));
    parts.truncate(MAX_PROBES_PER_STEP);
    Some((hour, parts))
}

/// The step over `hour` found nothing (left) to change: move the cursor
/// past it. A step that committed a change leaves the cursor where it is
/// ([`changed`]): the next step re-plans the same hour, finds the outputs
/// clean (or the rest of a large hour), and only then moves on.
///
/// `through`: the step handled only a slice of the hour, clean up to that
/// part; the next step continues after it.
pub fn clean(progress: &mut LeanProgress, hour: i32, through: Option<String>) {
    match through {
        None => {
            progress.cursor_hour = Some(hour);
            progress.resume = None;
        }
        Some(after) => progress.resume = Some(HourResume { hour, after }),
    }
    progress.consecutive_failures = 0;
}

/// A step over `hour` committed part-log entry `seq`. `resume_after`: every
/// part of the hour up to it was proven clean before the rewritten ones
/// (the next step starts after it; the outputs have newer ids).
pub fn changed(progress: &mut LeanProgress, seq: u64, hour: i32, resume_after: Option<String>) {
    progress.sweep_changed = true;
    progress.consecutive_failures = 0;
    progress.last_commit_seq = Some(progress.last_commit_seq.map_or(seq, |last| last.max(seq)));
    if let Some(after) = resume_after {
        progress.resume = Some(HourResume { hour, after });
    }
}

/// The scan or sweep found no hour after its cursor: start the next sweep
/// (`now_ms` is its start) or, after a sweep that changed nothing, move to
/// the prevalence phase.
pub fn end_of_pass(progress: &mut LeanProgress, now_ms: i64) {
    match progress.phase {
        // The first sweep revisits everything created since the scan
        // started (`sweep_started_ms`, set when the order was first taken).
        LeanPhase::Scan => {
            progress.phase = LeanPhase::Tail;
            progress.sweeps = 1;
            progress.sweep_changed = false;
            progress.pass_began_ms = Some(now_ms);
        }
        // The next sweep revisits everything created since THIS sweep
        // began, so a part added behind its cursor is not skipped.
        LeanPhase::Tail if progress.sweep_changed => {
            progress.sweeps = progress.sweeps.saturating_add(1);
            progress.sweep_started_ms = Some(progress.pass_began_ms.unwrap_or(now_ms));
            progress.pass_began_ms = Some(now_ms);
            progress.sweep_changed = false;
        }
        LeanPhase::Tail => progress.phase = LeanPhase::Prevalence,
        LeanPhase::Prevalence | LeanPhase::Done => {}
    }
    progress.cursor_hour = None;
    progress.resume = None;
}

/// Most parts one rewrite merges (the merge decode window bounds memory;
/// this bounds one step's download and publish).
pub const MAX_REWRITE_INPUTS: usize = 32;

/// What to rewrite among the parts of an hour that may hold the subject: a
/// day part alone (its output stays a day part), else up to
/// [`MAX_REWRITE_INPUTS`] parts into the highest input level (an L0 input
/// alone becomes a minute part, as any L0 merge does). `Err(code)`: an
/// adopted (unsorted) part may hold the subject and cannot be rewritten.
pub fn choose_rewrite(may_contain: &[PartRef]) -> std::result::Result<Option<(Level, Vec<PartRef>)>, &'static str> {
    Ok(rewrite_batches(may_contain)?.into_iter().next())
}

/// Every rewrite a step may need, in order: each day part alone, then the
/// rest in part-id order, at most [`MAX_REWRITE_INPUTS`] per batch. A batch
/// that turns out clean (the sidecars over-approximate) hands over to the
/// next one, so no candidate is skipped.
pub fn rewrite_batches(may_contain: &[PartRef]) -> std::result::Result<Vec<(Level, Vec<PartRef>)>, &'static str> {
    if may_contain.iter().any(|part| !part.sorted) {
        return Err(ADOPTED_PART_UNSUPPORTED);
    }
    let mut batches = may_contain.iter().filter(|part| part.level == Level::Day)
        .map(|day| (Level::Day, vec![day.clone()])).collect::<Vec<_>>();
    let mut rest = may_contain.iter().filter(|part| part.level != Level::Day).cloned().collect::<Vec<_>>();
    rest.sort_by(|a, b| a.part_id.cmp(&b.part_id));
    for chunk in rest.chunks(MAX_REWRITE_INPUTS) {
        let level = chunk.iter().map(|part| part.level).max().unwrap_or(Level::Minute);
        batches.push((level.max(Level::Minute), chunk.to_vec()));
    }
    Ok(batches)
}

/// What a step's I/O does to one part or batch (production:
/// `ingest_erasure::run_step`; tests: an in-memory lake).
#[async_trait::async_trait]
pub trait StepIo: Send + Sync {
    async fn probe(&self, part: &PartRef) -> Result<Probe>;
    /// The filtered merge of `inputs` (`Clean` when no row changed: nothing
    /// is published).
    async fn rewrite(&self, level: Level, event_hour: i32, inputs: &[PartRef]) -> Result<StepKind>;
}

/// One step over `candidates` (a slice of `hour`, in part-id order, from
/// [`plan_hour`]): probe each, then rewrite the batches that may hold the
/// subject until one changes something. `truncated`: the hour has more
/// parts after this slice.
pub async fn execute_step(io: &dyn StepIo, hour: i32, candidates: Vec<PartRef>, truncated: bool) -> Result<StepOutcome> {
    let mut may_contain = Vec::new();
    let mut pruned = 0_u64;
    for part in &candidates {
        match io.probe(part).await? {
            Probe::Absent => pruned += 1,
            Probe::MayContain(_) => may_contain.push(part.clone()),
        }
    }
    let probed = candidates.len() as u64;
    let through = || truncated.then(|| candidates.last().map(|part| part.part_id.to_string())).flatten();
    let outcome = |inputs: Vec<PartRef>, resume_after: Option<String>, kind| {
        Ok(StepOutcome { hour, probed, pruned, inputs, resume_after, kind })
    };
    let batches = match rewrite_batches(&may_contain) {
        Err(code) => return outcome(Vec::new(), None, StepKind::Unsupported(code)),
        Ok(batches) => batches,
    };
    for (index, (level, inputs)) in batches.iter().enumerate() {
        let event_hour = if *level == Level::Day { inputs[0].event_hour } else { hour };
        match io.rewrite(*level, event_hour, inputs).await? {
            StepKind::Clean => continue,
            kind => {
                // Proven clean: every candidate before the first part of THIS
                // or any later batch (a day batch goes first, so lower-id
                // parts may still be unprobed by a rewrite): start after it.
                let first = batches[index..].iter().flat_map(|(_, batch)| batch.iter().map(|part| &part.part_id)).min().cloned();
                let resume_after = first.and_then(|first| candidates.iter().map(|part| &part.part_id)
                    .filter(|id| **id < first).max().map(ToString::to_string));
                return outcome(inputs.clone(), resume_after, kind);
            }
        }
    }
    outcome(Vec::new(), through(), StepKind::Clean)
}

/// `failure_code` of an order that met an adopted part holding the subject.
pub const ADOPTED_PART_UNSUPPORTED: &str = "lean_adopted_part_unsupported";

/// What one step's background work produced.
pub enum StepKind {
    /// Every candidate was proven absent, or the rewrite changed no row:
    /// nothing is committed and the cursor moves on.
    Clean,
    /// The filtered merge of `inputs`, already published.
    Rewrite { result: super::merge::MergeResult, output: PartRef },
    /// The filter removed every row of `inputs`.
    Retire { rows_removed: u64 },
    /// A permanent failure (`failure_code`).
    Unsupported(&'static str),
}

pub struct StepOutcome {
    pub hour: i32,
    pub probed: u64,
    pub pruned: u64,
    pub inputs: Vec<PartRef>,
    /// Clean: the slice was clean through this part, more of the hour
    /// remains (`None`: the hour is done). Changed: the hour's parts up to
    /// this one are proven clean.
    pub resume_after: Option<String>,
    pub kind: StepKind,
}

/// The exchange's current `erasure_ledger`, shared between the credential
/// refresher (which replaces it) and ingest (which reads it each tick).
#[derive(Clone, Default)]
pub struct ErasureLedgerSlot(Arc<std::sync::Mutex<Option<ErasureLedgerCredential>>>);

impl ErasureLedgerSlot {
    pub fn set(&self, credential: Option<ErasureLedgerCredential>) {
        *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = credential;
    }

    pub fn get(&self) -> Option<ErasureLedgerCredential> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

/// Parse the exchange's raw `erasure_ledger`: absent or unreadable is
/// `None` (the executor stays idle; the exchange never fails over it).
pub fn ledger_from_exchange(value: Option<&serde_json::Value>, tenant_id: &str) -> Option<ErasureLedgerCredential> {
    let value = value?;
    match serde_json::from_value::<ErasureLedgerCredential>(value.clone())
        .map_err(anyhow::Error::from)
        .and_then(|credential| credential.validate(tenant_id, Utc::now()).map(|_| credential))
    {
        Ok(credential) => Some(credential),
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "erasure_ledger unreadable; lean erasure stays idle");
            None
        }
    }
}

/// Why a part may (or may not) hold the subject, from its signed sidecars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Proven absent: the entity ranges and the token index exclude it.
    Absent,
    /// May be present (or undecidable): the part is rewritten.
    MayContain(&'static str),
}

/// Lowercased tokens of the subject as ingest indexes them; `None` when the
/// token index cannot decide (no token, or one too long to be indexed).
pub fn subject_tokens(value: &str) -> Option<Vec<String>> {
    let mut tokens = BTreeSet::new();
    let mut too_long = false;
    tokenize(value, |token| {
        if token.len() > TOKEN_MAX_BYTES {
            too_long = true;
        }
        tokens.insert(token.to_string());
    });
    // `tokenize` skips over-long pieces itself; recheck on the raw pieces.
    for piece in value.split(|c: char| !c.is_alphanumeric()) {
        if piece.to_lowercase().len() > TOKEN_MAX_BYTES {
            too_long = true;
        }
    }
    (!too_long && !tokens.is_empty()).then(|| tokens.into_iter().collect())
}

/// Decide from the part's signed sidecars whether it may hold the subject.
/// Sound (never `Absent` for a part that holds it): every selector path must
/// be covered by the entity-range partial (exact values) or by the token
/// index (fields in [`TOKEN_FIELDS`]), and free-text redaction by the token
/// index; anything else, a missing sidecar or an undecodable one keeps the
/// part. Reads the provenance, `partials/entity_ranges.parquet` and the
/// `tokens-*.nti` files only, each verified against the signed record.
pub async fn probe_part(
    store: &dyn ObjectStore,
    tenant_id: &str,
    trusted: &TenantKeySet,
    part: &PartRef,
    order: &LeanErasureOrder,
) -> Result<Probe> {
    let keys = PartKeys::new(tenant_id, part.level, part.event_hour, &part.part_id)?;
    let provenance = store.get(&keys.provenance()).await?.context("live part has no provenance")?;
    ensure!(sha256_hex(&provenance) == part.provenance_sha256, "part provenance does not match the log");
    let signed = SignedProvenance::verify_bytes(&provenance, tenant_id, trusted)?;
    part.check_record(&signed.record, &part.provenance_sha256)?;
    let record = &signed.record;
    let paths = order.paths();
    let (ranged, rest): (Vec<&str>, Vec<&str>) = paths.iter().copied().partition(|path| ENTITY_RANGE_PATHS.contains(path));
    if rest.iter().any(|path| !TOKEN_FIELDS.contains(path)) {
        return Ok(Probe::MayContain("selector_path_unindexed"));
    }
    let redacting = order.redaction()?.is_some();
    let needs_tokens = !rest.is_empty() || redacting;
    if !ranged.is_empty() {
        let Some(digest) = record.files.partials.iter().find(|partial| partial.name == PARTIAL_ENTITY_RANGES_FILE) else {
            return Ok(Probe::MayContain("no_entity_ranges"));
        };
        let bytes = store.get(&keys.file(&digest.name)).await?.context("entity ranges partial missing")?;
        ensure!(bytes.len() as u64 == digest.bytes && sha256_hex(&bytes) == digest.sha256,
            "entity ranges partial does not match its record");
        match entity_ranges_hold(&bytes, &ranged, order.subject.value()) {
            Ok(true) => return Ok(Probe::MayContain("entity_range")),
            Ok(false) => {}
            Err(_) => return Ok(Probe::MayContain("entity_ranges_unreadable")),
        }
    }
    if needs_tokens {
        let Some(tokens) = subject_tokens(order.subject.value()) else {
            return Ok(Probe::MayContain("subject_not_tokenizable"));
        };
        for data in &record.files.data {
            let bytes = store.get(&keys.file(&data.tokens.name)).await?.context("token index missing")?;
            ensure!(bytes.len() as u64 == data.tokens.bytes && sha256_hex(&bytes) == data.tokens.sha256,
                "token index does not match its record");
            match decode_token_index(&bytes) {
                Ok(groups) if groups.len() == data.row_groups as usize => {
                    if groups.iter().any(|group| group.may_contain_all(&tokens)) {
                        return Ok(Probe::MayContain("token_index"));
                    }
                }
                _ => return Ok(Probe::MayContain("token_index_unreadable")),
            }
        }
    }
    // The token index covers `message`/`raw_data`, not `unmapped`, which the
    // redaction also rewrites: a part whose `unmapped` holds any value may
    // mention the subject there.
    if redacting {
        if let Some(reason) = unmapped_may_hold(store, &keys, record).await? {
            return Ok(Probe::MayContain(reason));
        }
    }
    Ok(Probe::Absent)
}

/// `None` when every `unmapped` leaf of every data file is all-null, proven
/// from the file's signed Parquet footer (its `parquet_ranges` manifest);
/// otherwise why the part must be rewritten to be sure.
async fn unmapped_may_hold(store: &dyn ObjectStore, keys: &PartKeys, record: &crate::parts::provenance::ProvenanceRecord)
    -> Result<Option<&'static str>> {
    use crate::parts::parquet_ranges::ParquetRangeDigest;
    for (index, data) in record.files.data.iter().enumerate() {
        let Some(manifest) = &data.parquet_ranges else { return Ok(Some("unmapped_unindexed")) };
        let body = store.get(&keys.file(&manifest.name)).await?.context("range manifest missing")?;
        ensure!(body.len() as u64 == manifest.bytes && sha256_hex(&body) == manifest.sha256,
            "range manifest does not match its record");
        let ranges: Vec<ParquetRangeDigest> = serde_json::from_slice(&body)?;
        crate::parts::parquet_ranges::validate(&ranges, data.bytes, data.row_groups)?;
        let Some(footer) = ranges.iter().find(|range| range.row_group.is_none() && range.column.is_none()) else {
            return Ok(Some("unmapped_unindexed"));
        };
        let remote = record.data_key(keys, index).context("data file index")?;
        let bytes = store.get_range(&remote, footer.offset..footer.offset + footer.bytes).await?
            .context("data file footer missing")?;
        ensure!(bytes.len() as u64 == footer.bytes && sha256_hex(&bytes) == footer.sha256,
            "data file footer does not match its signed digest");
        if !unmapped_all_null(&bytes)? {
            return Ok(Some("unmapped_present"));
        }
    }
    Ok(None)
}

/// Whether a verified footer (metadata + length + `PAR1`) shows every
/// `unmapped` leaf null in every row group. Missing statistics: not proven.
pub fn unmapped_all_null(footer: &[u8]) -> Result<bool> {
    ensure!(footer.len() >= 8 && &footer[footer.len() - 4..] == b"PAR1", "invalid Parquet footer");
    let length = u32::from_le_bytes(footer[footer.len() - 8..footer.len() - 4].try_into()?) as usize;
    ensure!(length + 8 == footer.len(), "footer range is not exactly the metadata");
    let metadata = parquet::file::metadata::ParquetMetaDataReader::decode_metadata(&footer[..length])?;
    for group in metadata.row_groups() {
        for column in group.columns() {
            let path = column.column_path().string();
            if path != "unmapped" && !path.starts_with("unmapped.") {
                continue;
            }
            let all_null = column.statistics()
                .and_then(|stats| stats.null_count_opt())
                .is_some_and(|nulls| nulls as i64 == column.num_values());
            if !all_null {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Does the entity-range partial list the subject on any of `paths`?
pub fn entity_ranges_hold(bytes: &[u8], paths: &[&str], subject: &str) -> Result<bool> {
    let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::copy_from_slice(bytes))?
        .with_batch_size(8_192)
        .build()?;
    for batch in reader {
        let batch = batch?;
        let column = |name: &str| batch.column_by_name(name).and_then(|c| c.as_any().downcast_ref::<StringArray>().cloned());
        let (Some(path), Some(value)) = (column("path"), column("value")) else {
            bail!("entity ranges partial has no path/value columns");
        };
        for row in 0..batch.num_rows() {
            if path.is_null(row) || value.is_null(row) {
                continue;
            }
            if paths.contains(&path.value(row)) && subject_matches(value.value(row), subject) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn subject_matches(candidate: &str, subject: &str) -> bool {
    let candidate = candidate.trim();
    candidate.eq_ignore_ascii_case(subject) || (!candidate.is_ascii() && candidate.to_lowercase() == subject)
}

// ---------------------------------------------------------------------------
// The work-order ledger, as the tenant's `publish` data-path login.
// ---------------------------------------------------------------------------

/// The work-order ledger as the executor sees it: production is
/// [`PgErasureLedger`] (the tenant's `publish` login, RLS-scoped to its own
/// rows); tests substitute an in-memory one.
#[async_trait::async_trait]
pub trait ErasureLedger: Send + Sync {
    /// Claim this tenant's oldest open order (or re-take the one this
    /// executor already holds), renewing the lease.
    async fn claim(&self, tenant_id: &str, executor_node: &str) -> Result<Option<LeanErasureOrder>>;
    /// Persist a step: progress always, counters, and (for a committed
    /// change, while under the bound) one pass record. Fenced on the lease.
    async fn record_step(&self, tenant_id: &str, executor_node: &str, order: &LeanErasureOrder, step: &StepRecord) -> Result<()>;
    /// Complete the order (the purge phase closes with it: superseded files
    /// are the sanctioned part GC's).
    async fn complete(&self, tenant_id: &str, executor_node: &str, order: &LeanErasureOrder) -> Result<()>;
    /// Record a failed step; `code` fails the order.
    async fn fail(&self, tenant_id: &str, executor_node: &str, order: &LeanErasureOrder, code: Option<&str>, message: &str) -> Result<()>;
}

/// Count a failed step on the order's progress: the failure code that
/// fails the order (a permanent one, or `executor_exhausted` past
/// [`MAX_CONSECUTIVE_FAILURES`]), or `None` to retry.
pub fn count_failure(progress: &mut LeanProgress, permanent: Option<&'static str>) -> Option<&'static str> {
    progress.consecutive_failures = progress.consecutive_failures.saturating_add(1);
    permanent.or((progress.consecutive_failures >= MAX_CONSECUTIVE_FAILURES).then_some("executor_exhausted"))
}

/// [`ErasureLedger`] over `public.lake_erasure_work_orders`.
pub struct PgErasureLedger(pub sqlx::PgPool);

/// Every ledger call is bounded ([`LEDGER_CALL_TIMEOUT`]): ingest[T] waits
/// on it under its own lock, so a slow database must never stall ingest.
async fn bounded<T>(what: &'static str, call: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(LEDGER_CALL_TIMEOUT, call).await
        .map_err(|_| anyhow::anyhow!("{what} timed out after {} s", LEDGER_CALL_TIMEOUT.as_secs()))?
}

#[async_trait::async_trait]
impl ErasureLedger for PgErasureLedger {
    async fn claim(&self, tenant_id: &str, executor_node: &str) -> Result<Option<LeanErasureOrder>> {
        bounded("erasure claim", claim(&self.0, tenant_id, executor_node)).await
    }
    async fn record_step(&self, tenant_id: &str, executor_node: &str, order: &LeanErasureOrder, step: &StepRecord) -> Result<()> {
        bounded("erasure step record", record_step(&self.0, tenant_id, executor_node, order, step)).await
    }
    async fn complete(&self, tenant_id: &str, executor_node: &str, order: &LeanErasureOrder) -> Result<()> {
        bounded("erasure completion", complete(&self.0, tenant_id, executor_node, order)).await
    }
    async fn fail(&self, tenant_id: &str, executor_node: &str, order: &LeanErasureOrder, code: Option<&str>, message: &str) -> Result<()> {
        bounded("erasure failure record", fail(&self.0, tenant_id, executor_node, order, code, message)).await
    }
}

async fn claim(pool: &sqlx::PgPool, tenant_id: &str, executor_node: &str) -> Result<Option<LeanErasureOrder>> {
    let row = sqlx::query(
        "WITH candidate AS ( \
             SELECT order_id FROM lake_erasure_work_orders \
              WHERE tenant_id = $1 AND expires_at > NOW() \
                AND COALESCE(progress->>'executor', $4) = $4 \
                AND (state = 'pending' \
                     OR (state IN ('running', 'awaiting_compaction', 'purging') \
                         AND (lease_expires_at IS NULL OR lease_expires_at < NOW() OR executor_node = $2))) \
              ORDER BY submitted_at, order_id LIMIT 1 FOR UPDATE SKIP LOCKED) \
         UPDATE lake_erasure_work_orders o \
            SET state = 'running', \
                attempts = o.attempts + CASE WHEN o.state = 'running' AND o.executor_node = $2 THEN 0 ELSE 1 END, \
                executor_node = $2, \
                lease_expires_at = NOW() + make_interval(secs => $3), started_at = COALESCE(o.started_at, NOW()) \
           FROM candidate WHERE o.order_id = candidate.order_id AND o.tenant_id = $1 \
         RETURNING o.order_id, o.tenant_id, o.request_id, o.identifier_type, o.identifier_value, o.identifier_hash, \
                   o.redact_free_text, o.cutoff_time, o.event_time_floor, o.progress",
    )
    .bind(tenant_id)
    .bind(executor_node)
    .bind(LEASE_SECS as f64)
    .bind(LEAN_EXECUTOR_KIND)
    .fetch_optional(pool)
    .await
    .context("claim erasure work order")?;
    let Some(row) = row else { return Ok(None) };
    // RLS already confines the login to its tenant; refuse anything else.
    let row_tenant: String = row.try_get("tenant_id")?;
    ensure!(row_tenant == tenant_id, "erasure work order belongs to another tenant");
    let progress: serde_json::Value = row.try_get("progress")?;
    let mut progress: LeanProgress = serde_json::from_value(progress).unwrap_or_default();
    if progress.executor.is_empty() {
        progress.executor = LEAN_EXECUTOR_KIND.to_string();
    }
    ensure!(progress.executor == LEAN_EXECUTOR_KIND, "erasure work order belongs to another executor kind");
    let subject = ErasureSubject::new(
        ErasureIdentifierType::parse(&row.try_get::<String, _>("identifier_type")?)?,
        &row.try_get::<String, _>("identifier_value")?,
    )?;
    let cutoff: DateTime<Utc> = row.try_get("cutoff_time")?;
    let floor: DateTime<Utc> = row.try_get("event_time_floor")?;
    Ok(Some(LeanErasureOrder {
        tenant_id: row_tenant,
        order_id: row.try_get("order_id")?,
        request_id: row.try_get("request_id")?,
        subject,
        identifier_hash: row.try_get("identifier_hash")?,
        redact_free_text: row.try_get("redact_free_text")?,
        floor_us: floor.timestamp_micros(),
        cutoff_us: cutoff.timestamp_micros(),
        progress,
    }))
}

/// What one committed (or clean) step did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StepRecord {
    pub objects_scanned: u64,
    pub objects_pruned: u64,
    pub objects_rewritten: u64,
    pub rows_removed: u64,
    pub rows_redacted: u64,
    pub bytes_rewritten: u64,
    pub part_log_first_seq: Option<u64>,
    pub part_log_last_seq: Option<u64>,
    pub parts_superseded: u64,
    pub parts_retired: u64,
}

impl StepRecord {
    pub fn changed(&self) -> bool {
        self.part_log_last_seq.is_some()
    }

    /// Fold a step whose record could not be written into the next one.
    pub fn absorb(&mut self, other: &StepRecord) {
        self.objects_scanned += other.objects_scanned;
        self.objects_pruned += other.objects_pruned;
        self.objects_rewritten += other.objects_rewritten;
        self.rows_removed += other.rows_removed;
        self.rows_redacted += other.rows_redacted;
        self.bytes_rewritten += other.bytes_rewritten;
        self.parts_superseded += other.parts_superseded;
        self.parts_retired += other.parts_retired;
        self.part_log_first_seq = match (self.part_log_first_seq, other.part_log_first_seq) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.part_log_last_seq = self.part_log_last_seq.max(other.part_log_last_seq);
    }
}

async fn record_step(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    executor_node: &str,
    order: &LeanErasureOrder,
    step: &StepRecord,
) -> Result<()> {
    let pass = step.changed().then(|| serde_json::json!([{
        "objects_scanned": step.objects_scanned,
        "objects_pruned": step.objects_pruned,
        "objects_rewritten": step.objects_rewritten,
        "rows_removed": step.rows_removed,
        "rows_redacted": step.rows_redacted,
        "bytes_rewritten": step.bytes_rewritten,
        "objects_enrolled_for_purge": step.parts_superseded,
        "part_log_first_seq": step.part_log_first_seq,
        "part_log_last_seq": step.part_log_last_seq,
        "parts_superseded": step.parts_superseded,
        "parts_retired": step.parts_retired,
        "committed_at": Utc::now(),
    }]));
    let updated = sqlx::query(
        "UPDATE lake_erasure_work_orders \
            SET progress = $3, \
                passes = CASE WHEN $4::jsonb IS NULL OR jsonb_array_length(passes) >= $5 THEN passes ELSE passes || $4::jsonb END, \
                objects_scanned = objects_scanned + $6, \
                objects_rewritten = objects_rewritten + $7, \
                rows_removed = rows_removed + $8, \
                rows_redacted = rows_redacted + $9, \
                bytes_rewritten = bytes_rewritten + $10, \
                lease_expires_at = NOW() + make_interval(secs => $11), \
                failure_message = NULL \
          WHERE order_id = $1 AND tenant_id = $2 AND state = 'running' AND executor_node = $12",
    )
    .bind(order.order_id)
    .bind(tenant_id)
    .bind(serde_json::to_value(&order.progress)?)
    .bind(pass)
    .bind(MAX_PASS_RECORDS)
    .bind(i64::try_from(step.objects_scanned)?)
    .bind(i64::try_from(step.objects_rewritten)?)
    .bind(i64::try_from(step.rows_removed)?)
    .bind(i64::try_from(step.rows_redacted)?)
    .bind(i64::try_from(step.bytes_rewritten)?)
    .bind(LEASE_SECS as f64)
    .bind(executor_node)
    .execute(pool)
    .await
    .context("record erasure step")?;
    ensure!(updated.rows_affected() == 1, "erasure work order lease was lost before the step could be recorded");
    Ok(())
}

/// The superseded files are the sanctioned part GC's (`superseded` after
/// its grace): nothing is enrolled in the gen1 purge ledger, so the purge
/// phase closes with the completion.
async fn complete(pool: &sqlx::PgPool, tenant_id: &str, executor_node: &str, order: &LeanErasureOrder) -> Result<()> {
    let updated = sqlx::query(
        "UPDATE lake_erasure_work_orders \
            SET state = 'completed', progress = $3, lease_expires_at = NULL, completed_at = NOW(), \
                objects_pending_purge = 0, purge_started_at = COALESCE(purge_started_at, NOW()), \
                purge_completed_at = NOW(), failure_message = NULL \
          WHERE order_id = $1 AND tenant_id = $2 AND state = 'running' AND executor_node = $4",
    )
    .bind(order.order_id)
    .bind(tenant_id)
    .bind(serde_json::to_value(&order.progress)?)
    .bind(executor_node)
    .execute(pool)
    .await
    .context("complete erasure work order")?;
    if updated.rows_affected() == 1 {
        return Ok(());
    }
    // Idempotent: a completion that committed but whose reply was lost (a
    // timeout) is retried; the order this executor already completed is done.
    let row = sqlx::query("SELECT state, executor_node FROM lake_erasure_work_orders WHERE order_id = $1 AND tenant_id = $2")
        .bind(order.order_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .context("read erasure work order after completion")?;
    let done = row.is_some_and(|row| row.try_get::<String, _>("state").is_ok_and(|state| state == "completed")
        && row.try_get::<Option<String>, _>("executor_node").is_ok_and(|node| node.as_deref() == Some(executor_node)));
    ensure!(done, "erasure work order lease was lost before completion");
    Ok(())
}

async fn fail(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    executor_node: &str,
    order: &LeanErasureOrder,
    code: Option<&str>,
    message: &str,
) -> Result<()> {
    let message: String = message.chars().take(2_000).collect();
    let query = match code {
        Some(_) => "UPDATE lake_erasure_work_orders SET state = 'failed', completed_at = NOW(), lease_expires_at = NULL, \
                    progress = $3, failure_code = $5, failure_message = $4 \
                    WHERE order_id = $1 AND tenant_id = $2 AND state = 'running' AND executor_node = $6",
        None => "UPDATE lake_erasure_work_orders SET progress = $3, failure_message = $4 \
                 WHERE order_id = $1 AND tenant_id = $2 AND state = 'running' AND executor_node = $6 AND $5::text IS NULL",
    };
    sqlx::query(query)
        .bind(order.order_id)
        .bind(tenant_id)
        .bind(serde_json::to_value(&order.progress)?)
        .bind(&message)
        .bind(code)
        .bind(executor_node)
        .execute(pool)
        .await
        .context("record failed erasure step")?;
    Ok(())
}

#[cfg(test)]
#[path = "lean_erasure_tests.rs"]
mod tests;

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fresh SQL names are the privacy fence for provider result caches. The
//! stable writer table is never registered with the public gateway.
use super::super::lifecycle::CatalogLifecycleBackend;
use super::*;
use crate::{
    part_ingest::export::{plan_export_reconciled, ExportManifest, ExportState, IcebergCommitter},
    parts::{levels::MergePolicy, part_log::PartRef},
};
use serde::{Deserialize, Serialize};
use crate::part_ingest::agent_lane::IngestPressure;
use std::{collections::BTreeSet, sync::Mutex};

#[async_trait::async_trait]
pub(super) trait ServingTable: CatalogLifecycleBackend {
    async fn retire(&self) -> Result<()>;
}
#[async_trait::async_trait]
impl ServingTable for RestLifecycleBackend {
    async fn retire(&self) -> Result<()> {
        self.retire_serving_table().await
    }
}
#[async_trait::async_trait]
pub(super) trait ServingFactory: Send + Sync {
    fn tenant_id(&self) -> &str;
    fn bucket(&self) -> &str;
    fn build(&self, dataset: &str) -> Result<Arc<dyn ServingTable>>;
    async fn close(&self) -> Result<()>;
    async fn publish(&self, details: Value) -> Result<()>;
    async fn retire_registry(&self) -> Result<()>;
    async fn invalidate(&self) -> Result<()>;
    async fn reopen(&self) -> Result<()>;
    /// NAN-4615: serving epochs (dataset names, `events_<32 hex>`) the remote
    /// catalog still holds. Survives the cell roll that wipes local state.
    async fn list_epochs(&self) -> Result<BTreeSet<String>>;
    /// NAN-4774: ask the platform to confirm `table` (`agent.events_<hex>_v1`)
    /// as this installation's registered serving name with no open privacy
    /// fence and custody attached, and to mark custody converged on it. An
    /// error (any refusal, or a platform without the op) means "not adopted".
    async fn adopt(&self, table: &str) -> Result<()>;
    /// NAN-4614: a fresh epoch holding exactly `live` was published; target
    /// bookkeeping about files outside it may go.
    fn retain_verified(&self, _live: &[PartRef]) -> Result<()> {
        Ok(())
    }
    /// NAN-4721: the tenant's ingest-lag signal, for the export target's
    /// cold file reads.
    fn set_ingest_pressure(&self, _pressure: Arc<IngestPressure>) {}
}
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    active: Option<String>,
    pending: Option<String>,
    retired: Vec<String>,
    last_plan_ms: i64,
    #[serde(default)]
    probe_hour: Option<i64>,
}
pub(super) struct FreshServingBackend {
    factory: Arc<dyn ServingFactory>,
    master: Arc<dyn ServingTable>,
    work: PathBuf,
    state: Mutex<State>,
    live: Mutex<(Vec<PartRef>, i64, MergePolicy)>,
    batch: crate::part_ingest::export::ExportBatchBounds,
    /// FP-T101: recorded batches past which a resumed epoch stops planning
    /// deltas and is retired instead (see [`EPOCH_RESUME_LIMIT`]).
    resume_limit: usize,
    vanished: Mutex<Option<super::super::lifecycle::Vanished>>,
    /// NAN-4721: an epoch build yields to ingest pressure (one bounded budget).
    pressure: Mutex<Arc<IngestPressure>>,
}
/// FP-T101: every resume after the master moved records one more delta, and
/// [`epoch_plans`] refuses more than 1024 batches (every batch is a retained
/// snapshot until the epoch's expiry). An epoch that keeps failing would grow
/// until that bound made every pass error. Past this count the epoch takes the
/// retire-and-rebuild fallback, leaving room for one maximal delta below it.
const EPOCH_RESUME_LIMIT: usize = 512;
impl FreshServingBackend {
    pub fn new(factory: Arc<dyn ServingFactory>, work: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&work)?;
        let path = work.join("state.json");
        let state = if path.try_exists()? {
            serde_json::from_slice(&std::fs::read(path)?)?
        } else {
            State::default()
        };
        let master = factory.build("events")?;
        Ok(Self {
            factory,
            master,
            work,
            state: Mutex::new(state),
            live: Mutex::new((vec![], 0, MergePolicy::default())),
            batch: crate::part_ingest::export::ExportBatchBounds::DEFAULT,
            resume_limit: EPOCH_RESUME_LIMIT,
            vanished: Mutex::new(None),
            pressure: Mutex::default(),
        })
    }
    #[cfg(test)]
    pub(super) fn with_batch(mut self, batch: crate::part_ingest::export::ExportBatchBounds) -> Self {
        self.batch = batch;
        self
    }
    #[cfg(test)]
    pub(super) fn with_resume_limit(mut self, limit: usize) -> Self {
        self.resume_limit = limit;
        self
    }
    fn state(&self) -> State {
        self.state.lock().expect("serving state").clone()
    }
    pub async fn uninstall(&self) -> Result<()> {
        self.factory.close().await?;
        self.factory.retire_registry().await?;
        let state = self.state();
        // NAN-4615: also every epoch a wiped writer no longer remembers.
        let names: BTreeSet<_> = state
            .active
            .iter()
            .chain(state.pending.iter())
            .chain(state.retired.iter())
            .cloned()
            .chain(self.factory.list_epochs().await?)
            .collect();
        for name in names {
            self.factory.build(&name)?.retire().await?;
        }
        // drop_table never purges part data. Each retirement verifies absence
        // and purges only catalog metadata through the scoped production GC.
        self.master.retire().await?;
        self.save(State::default())?;
        Ok(())
    }
    fn save(&self, state: State) -> Result<()> {
        use std::io::Write;
        let mut temp = tempfile::NamedTempFile::new_in(&self.work)?;
        temp.write_all(&serde_json::to_vec(&state)?)?;
        temp.as_file().sync_all()?;
        temp.persist(self.work.join("state.json"))?;
        std::fs::File::open(&self.work)?.sync_all()?;
        *self.state.lock().expect("serving state") = state;
        Ok(())
    }
    /// NAN-4615: a cell roll wipes `serving/state.json`, so the writer can
    /// forget an epoch the catalog still holds (the previously active one, or
    /// a pending one that never published). Every such epoch joins `retired`:
    /// it is named in the next publish and dropped through the verified
    /// retirement path before any GC proof is returned. Without a pending
    /// fresh epoch (no read barrier) the proof fails closed instead.
    fn adopt_unknown_epochs(&self, mut state: State, listed: BTreeSet<String>) -> Result<State> {
        let unknown: Vec<String> = listed
            .into_iter()
            .filter(|name| {
                state.active.as_ref() != Some(name)
                    && state.pending.as_ref() != Some(name)
                    && !state.retired.contains(name)
            })
            .collect();
        if unknown.is_empty() {
            return Ok(state);
        }
        ensure!(
            state.pending.is_some(),
            "catalog holds a serving epoch unknown to this writer; a fresh epoch must retire it first"
        );
        tracing::warn!(epochs = unknown.len(), "adopting serving epochs unknown to this writer for retirement");
        state.retired.extend(unknown);
        self.save(state.clone())?;
        Ok(state)
    }
    /// NAN-4774: the roll's A/B claim swap leaves this writer with no serving
    /// state while the catalog and the platform still hold the epoch it
    /// published. Adopt it as the active epoch only with proof that it is
    /// exactly what a fresh epoch would be:
    /// - the same export checkpoint (watermark) as the master, under the
    ///   current schema contract (`export_head` validates the table);
    /// - the same referenced parts as the master in every retained snapshot
    ///   (the predicate every publish and every sync already enforces). An
    ///   active epoch only ever receives add-only deltas (every removal takes
    ///   the privacy fence and a fresh name), so equality also proves that no
    ///   part it ever served has since been erased or merged away;
    /// - the platform confirms it as the sole registered serving name of this
    ///   installation (active custody, no open privacy fence).
    /// Any other listed epoch requires a privacy pass too: the platform
    /// broker refuses epoch retirement without an open privacy fence. Without
    /// full proof the writer falls back to today's privacy pass and fresh build.
    async fn adopt_serving_epoch(&self) -> Result<bool> {
        let state = self.state();
        if state.active.is_some() || state.pending.is_some() || !state.retired.is_empty() {
            return Ok(false);
        }
        let listed = self.factory.list_epochs().await?;
        if listed.len() != 1 {
            return Ok(false);
        }
        let Some(checkpoint) = self.master.export_head(false).await?.checkpoint else {
            return Ok(false);
        };
        let master = self.master.expire_and_inspect().await?;
        for name in &listed {
            let serving = self.factory.build(name)?;
            let head = match serving.export_head(false).await {
                Ok(head) => head,
                Err(error) => {
                    tracing::info!(epoch = %name, error = %format!("{error:#}"), "serving epoch not adoptable (contract)");
                    continue;
                }
            };
            if head.checkpoint != Some(checkpoint) {
                tracing::info!(epoch = %name, epoch_checkpoint = ?head.checkpoint, checkpoint,
                    "serving epoch not adoptable (watermark differs from the master)");
                continue;
            }
            if serving.expire_and_inspect().await? != master {
                tracing::info!(epoch = %name, "serving epoch not adoptable (parts differ from the master)");
                continue;
            }
            if let Err(error) = self.factory.adopt(&format!("agent.{name}_v1")).await {
                tracing::info!(epoch = %name, error = %format!("{error:#}"), "serving epoch not adoptable (platform refused)");
                continue;
            }
            tracing::warn!(epoch = %name, checkpoint, parts = master.len(),
                "adopted the published serving epoch after a wiped writer volume");
            self.save(State {
                active: Some(name.clone()),
                pending: None,
                retired: listed.iter().filter(|n| *n != name).cloned().collect(),
                last_plan_ms: checkpoint,
                probe_hour: None,
            })?;
            return Ok(true);
        }
        Ok(false)
    }
    /// NAN-4627: a roll wipes `probe_hour` too. With no sealed live part the
    /// lake has nothing to probe, and the master has already committed that
    /// (empty) state, so the hour before its checkpoint is a sealed, past,
    /// catalog-attested window. A master that never exported has no probe.
    async fn recovered_probe_hour(&self) -> Result<i64> {
        let checkpoint = self
            .master
            .export_head(false)
            .await?
            .checkpoint
            .context("serving activation has no sealed hour")?;
        Ok(checkpoint.div_euclid(3_600_000) * 3_600_000 - 3_600_000)
    }
    async fn retire(&self) -> Result<()> {
        for name in self.state().retired {
            self.factory.build(&name)?.retire().await?;
            let mut state = self.state();
            state.retired.retain(|n| n != &name);
            self.save(state)?;
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl IcebergCommitter for FreshServingBackend {
    async fn commit(&self, manifest: &ExportManifest) -> Result<()> {
        self.master.commit(manifest).await?;
        let mut state = self.state();
        if state.pending.is_none() {
            let name = state
                .active
                .as_ref()
                .context("serving table is not initialized")?;
            self.factory.build(name)?.commit(manifest).await?;
        }
        state.last_plan_ms = state.last_plan_ms.max(manifest.planned_at_ms);
        self.save(state)?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl CatalogLifecycleBackend for FreshServingBackend {
    fn tenant_id(&self) -> &str {
        self.factory.tenant_id()
    }
    fn bucket(&self) -> &str {
        self.factory.bucket()
    }
    fn set_vanished(&self, vanished: super::super::lifecycle::Vanished) {
        *self.vanished.lock().expect("serving vanished") = Some(vanished);
    }
    fn set_ingest_pressure(&self, pressure: Arc<IngestPressure>) {
        self.factory.set_ingest_pressure(pressure.clone());
        *self.pressure.lock().expect("serving pressure") = pressure;
    }
    async fn prepare_sync(&self, parts: &[PartRef], now: i64, policy: &MergePolicy) -> Result<()> {
        *self.live.lock().expect("serving live set") = (parts.to_vec(), now, *policy);
        Ok(())
    }
    async fn verify_maintenance(&self) -> Result<()> {
        self.master.verify_maintenance().await
    }
    /// NAN-4627: the master is the export chain. A wiped `serving/state.json`
    /// also forgot the master checkpoint, so a fresh epoch would be planned at
    /// 1 and every later delta (predecessor = the master checkpoint) would be
    /// refused by that epoch. Learn the checkpoint from the catalog itself.
    async fn export_head(&self, with_parts: bool) -> Result<super::super::ExportHead> {
        let head = self.master.export_head(with_parts).await?;
        if let Some(at) = head.checkpoint {
            let mut state = self.state();
            if state.last_plan_ms < at {
                state.last_plan_ms = at;
                self.save(state)?;
            }
        }
        Ok(head)
    }
    /// NAN-4662: serving epochs reference the same parts as the master, so
    /// none may exist (listed remotely, or still known locally) and the
    /// master must never have committed.
    async fn no_committed_snapshot(&self) -> Result<bool> {
        let state = self.state();
        if state.active.is_some() || !state.retired.is_empty() {
            return Ok(false);
        }
        if !self.factory.list_epochs().await?.is_empty() {
            return Ok(false);
        }
        self.master.no_committed_snapshot().await
    }
    async fn close_and_drain(&self) -> Result<()> {
        self.factory.close().await?;
        let mut state = self.state();
        if state.pending.is_none() {
            state.pending = Some(format!("events_{}", uuid::Uuid::new_v4().simple()));
            self.save(state)?;
        }
        Ok(())
    }
    async fn expire_and_inspect(&self) -> Result<BTreeSet<String>> {
        let master = self.master.expire_and_inspect().await?;
        let listed = self.factory.list_epochs().await?;
        let mut state = self.adopt_unknown_epochs(self.state(), listed)?;
        if let Some(next) = state.pending.clone() {
            let serving = self.factory.build(&next)?;
            let (parts, now, policy) = self.live.lock().expect("serving live set").clone();
            let directory = self.work.join(&next);
            std::fs::create_dir_all(&directory)?;
            let mut plans = ExportState::load_durable(&directory)?;
            let started = std::time::Instant::now();
            // Part GC never waits on this catalog. An uncommitted recorded
            // batch that adds a part GC may have deleted can never commit
            // (its data is gone) and the master never holds that part again:
            // this unpublished epoch cannot converge. Retire it unexposed;
            // the next attempt builds a fresh one from the live set.
            if plans.last_plan_ms > 0 {
                let vanished = self.vanished.lock().expect("serving vanished").clone();
                if let Some(vanished) = vanished {
                    // The newest batch adding such a part; only an
                    // uncommitted one (past the epoch checkpoint) is fatal.
                    let mut newest = None;
                    for path in epoch_plans(&directory)? {
                        let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
                        if manifest.add.iter().any(|p| vanished(&p.part_id)) {
                            newest = Some(manifest.planned_at_ms);
                        }
                    }
                    // The local watermark lags a commit at most (a landed
                    // commit without it): conservative, never a missed one.
                    let committed = epoch_committed(&directory)?;
                    if newest.is_some_and(|at| at > committed) {
                        serving.retire().await?;
                        state.pending = Some(format!("events_{}", uuid::Uuid::new_v4().simple()));
                        self.save(state)?;
                        anyhow::bail!("serving epoch names a part removed by part GC; rebuilding");
                    }
                }
            }
            // NAN-4614: the fresh epoch registers the whole live set, in
            // bounded batches like the master. The chain ENDS at the master
            // checkpoint, so the master's next delta continues it. Batches
            // stay in this epoch's directory: a retry replays them all, each
            // already-committed one is a checkpoint skip (no target IO).
            let mut paths = if plans.last_plan_ms > 0 {
                epoch_plans(&directory)?
            } else {
                vec![]
            };
            // FP-T101: a build cut off by the sync's hard bound (or an error)
            // resumes on a later pass, after the master has committed newer
            // plans (hourly seals). Replaying only the batches recorded
            // against the old live set can never match the master, so the
            // epoch was retired and rebuilt from zero forever. Instead the
            // epoch plans the delta from its OWN durable state to the current
            // live set, chained after its recorded batches and again ENDING
            // at the master checkpoint (an empty batch when only the
            // checkpoint moved). A delta may remove parts (erasure, merges):
            // the epoch is unpublished, so nothing reads it, and its expiry
            // below drops every older snapshot before the reference check;
            // any remaining difference still retires it unexposed. Planned
            // only against a prepared live set (`now > 0`).
            let end = state.last_plan_ms.max(1);
            let resumable = paths.len() < self.resume_limit;
            if !resumable && end > plans.last_plan_ms {
                tracing::warn!(recorded = paths.len(), "serving epoch resumed too often; retiring it for a rebuild");
            }
            if plans.last_plan_ms == 0 || (now > 0 && resumable && end > plans.last_plan_ms) {
                let pending = plan_export_reconciled(&parts, &plans, now, &policy);
                let mut batches = plans.split_plan(self.tenant_id(), &pending, self.batch)?;
                if end - (batches.len() as i64 - 1) <= plans.last_plan_ms {
                    batches = plans.split_plan(
                        self.tenant_id(),
                        &pending,
                        crate::part_ingest::export::ExportBatchBounds::UNBOUNDED,
                    )?;
                }
                let first = end - (batches.len() as i64 - 1);
                if !paths.is_empty() {
                    tracing::info!(recorded = paths.len(), delta = batches.len(), hours = pending.len(),
                        "serving epoch resumes with the live-set delta");
                }
                paths.extend(plans.record_durable_batches(&directory, batches, first)?);
            }
            // FP-T101: a resumed build skips batches this writer saw commit
            // (a local watermark, written only after the commit returned)
            // instead of one catalog load per already-committed batch. A
            // commit that landed without the watermark is still a checkpoint
            // skip; the reference check below verifies the result.
            let mut committed = epoch_committed(&directory)?;
            let pressure = self.pressure.lock().expect("serving pressure").clone();
            // One yield budget per epoch build, not per batch: this runs
            // under custody and the sync's hard bound, and a batch whose
            // files are already verified reads nothing. Cold reads inside a
            // batch are paced by the export target while pressure holds.
            let mut yield_left = crate::part_ingest::agent_lane::MAX_YIELD;
            for (index, path) in paths.iter().enumerate() {
                let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
                if manifest.planned_at_ms <= committed {
                    continue;
                }
                // NAN-4721: agents never compete with analysts. A cold epoch
                // batch reads GBs of part files; none starts while ingest
                // is under pressure (bounded, see agent_lane).
                yield_left = yield_left.saturating_sub(
                    pressure.yield_while_lagging_up_to("serving epoch batch", yield_left).await,
                );
                serving.commit(&manifest).await?;
                committed = manifest.planned_at_ms;
                crate::part_ingest::export::atomic_write(&directory.join(COMMITTED), committed.to_string().as_bytes(), false)?;
                tracing::info!(batch = index + 1, batches = paths.len(), parts = manifest.add.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64, "serving epoch batch committed");
            }
            let references = serving.expire_and_inspect().await?;
            if references != master {
                // Even after the delta the epoch differs from the master (a
                // stale or unprepared live set, a master rebuilt from the
                // catalog). Never expose it, even briefly. Retire and build
                // a new epoch on the next bounded writer attempt.
                serving.retire().await?;
                state.pending = Some(format!("events_{}", uuid::Uuid::new_v4().simple()));
                self.save(state)?;
                anyhow::bail!("serving epoch live set changed; replay required");
            }
            let new_name = format!("agent.{next}_v1");
            let hour = match parts
                .iter()
                .map(|p| p.max_time_us)
                .max()
                .map(|t| t.div_euclid(3_600_000_000) * 3_600_000)
                .or(state.probe_hour)
            {
                Some(hour) => hour,
                None => self.recovered_probe_hour().await?,
            };
            state.probe_hour = Some(hour);
            self.factory.publish(json!({"table":new_name,
                "probe_window":{"start":chrono::DateTime::from_timestamp_millis(hour).context("invalid probe hour")?.to_rfc3339(),
                    "end":chrono::DateTime::from_timestamp_millis(hour+3_600_000).context("invalid probe hour")?.to_rfc3339()},
                "retired":state.active.iter().chain(state.retired.iter()).map(|n|format!("agent.{n}_v1")).collect::<Vec<_>>() })).await?;
            if let Some(old) = state.active.replace(next) {
                state.retired.push(old);
            }
            state.pending = None;
            self.save(state)?;
            if let Err(error) = self.factory.retain_verified(&parts) {
                tracing::warn!(error = %format!("{error:#}"), "export verified-file records not pruned");
            }
        }
        // The gateway has durably retired every old name BEFORE drop/purge and
        // before this backend can acknowledge a per-part GC receipt.
        self.retire().await?;
        let state = self.state();
        if let Some(active) = state.active {
            let serving = self.factory.build(&active)?;
            ensure!(
                serving.expire_and_inspect().await? == master,
                "serving table and writer table differ"
            );
        }
        Ok(master)
    }
    async fn invalidate_results(&self) -> Result<()> {
        ensure!(
            self.state().pending.is_none() && self.state().retired.is_empty(),
            "serving retirement is incomplete"
        );
        self.factory.invalidate().await?;
        Ok(())
    }
    async fn reopen(&self) -> Result<()> {
        self.factory.reopen().await
    }
    async fn adopt_serving(&self) -> Result<bool> {
        self.adopt_serving_epoch().await
    }
}

/// The last batch this writer saw commit to one fresh epoch.
const COMMITTED: &str = "committed";
fn epoch_committed(directory: &std::path::Path) -> Result<i64> {
    match std::fs::read_to_string(directory.join(COMMITTED)) {
        Ok(text) => Ok(text.trim().parse()?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

/// Every batch planned for one fresh epoch, in chain order.
fn epoch_plans(directory: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut paths = std::fs::read_dir(directory.join("export/pending"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| path.extension().is_some_and(|e| e == "json"));
    paths.sort();
    ensure!(!paths.is_empty() && paths.len() <= 1024, "serving epoch plan set out of bounds");
    Ok(paths)
}

#[cfg(test)]
mod tests;

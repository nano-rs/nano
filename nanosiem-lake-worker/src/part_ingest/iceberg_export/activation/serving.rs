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
    /// NAN-4614: a fresh epoch holding exactly `live` was published; target
    /// bookkeeping about files outside it may go.
    fn retain_verified(&self, _live: &[PartRef]) -> Result<()> {
        Ok(())
    }
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
}
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
        })
    }
    #[cfg(test)]
    pub(super) fn with_batch(mut self, batch: crate::part_ingest::export::ExportBatchBounds) -> Self {
        self.batch = batch;
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
            // NAN-4614: the fresh epoch registers the whole live set, in
            // bounded batches like the master. The chain ENDS at the master
            // checkpoint, so the master's next delta continues it. Batches
            // stay in this epoch's directory: a retry replays them all, each
            // already-committed one is a checkpoint skip (no target IO).
            let paths = if plans.last_plan_ms > 0 {
                epoch_plans(&directory)?
            } else {
                let pending = plan_export_reconciled(&parts, &plans, now, &policy);
                let end = state.last_plan_ms.max(1);
                let mut batches = plans.split_plan(self.tenant_id(), &pending, self.batch)?;
                if end - (batches.len() as i64 - 1) <= plans.last_plan_ms {
                    batches = plans.split_plan(
                        self.tenant_id(),
                        &pending,
                        crate::part_ingest::export::ExportBatchBounds::UNBOUNDED,
                    )?;
                }
                let first = end - (batches.len() as i64 - 1);
                plans.record_durable_batches(&directory, batches, first)?
            };
            for (index, path) in paths.iter().enumerate() {
                let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
                serving.commit(&manifest).await?;
                tracing::info!(batch = index + 1, batches = paths.len(), parts = manifest.add.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64, "serving epoch batch committed");
            }
            let references = serving.expire_and_inspect().await?;
            if references != master {
                // A pending epoch survived a crash and the live set advanced.
                // Never expose it, even briefly. Retire and build a new epoch
                // on the next bounded writer attempt.
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

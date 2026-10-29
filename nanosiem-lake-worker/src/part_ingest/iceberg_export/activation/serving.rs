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
use super::super::LiveEntries;
use std::{collections::BTreeSet, sync::Mutex};
use super::super::control_retry::{is_transient, retry, RetryPolicy};

#[async_trait::async_trait]
pub(super) trait ServingTable: CatalogLifecycleBackend {
    async fn retire(&self) -> Result<()>;
    /// NAN-4782: the current snapshot as reusable catalog entries (the
    /// master's live data files, checkpoint and digest). Metadata reads only.
    async fn live_entries(&self) -> Result<LiveEntries>;
    /// NAN-4782: hold exactly `entries` in one metadata-only commit; no part
    /// file is read. Idempotent.
    async fn seed(&self, entries: &LiveEntries) -> Result<()>;
}
#[async_trait::async_trait]
impl ServingTable for RestLifecycleBackend {
    async fn retire(&self) -> Result<()> {
        self.retire_serving_table().await
    }
    async fn live_entries(&self) -> Result<LiveEntries> {
        self.committed_entries().await
    }
    async fn seed(&self, entries: &LiveEntries) -> Result<()> {
        self.seed_from(entries).await
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
    /// NAN-4798: `active` was published as a fresh epoch under the read
    /// fence that is still closed (reads never reopened since), holding the
    /// master exactly at this export checkpoint (`i64::MIN`: an empty
    /// master). A later sync that finds the fence closed only because the
    /// previous one failed after that publish (retire, purge, invalidate or
    /// reopen) finishes it instead of minting another epoch. Cleared by a
    /// successful reopen and by every mint.
    #[serde(default)]
    finishing: Option<i64>,
}
pub(super) struct FreshServingBackend {
    factory: Arc<dyn ServingFactory>,
    master: Arc<dyn ServingTable>,
    work: PathBuf,
    state: Mutex<State>,
    live: Mutex<(Vec<PartRef>, i64, MergePolicy)>,
    vanished: Mutex<Option<super::super::lifecycle::Vanished>>,
    retry: RetryPolicy,
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
            vanished: Mutex::new(None),
            retry: RetryPolicy::CONTROL,
        })
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
        let listed = self.control("list_epochs", || self.factory.list_epochs()).await?;
        if listed.len() != 1 {
            return Ok(false);
        }
        let Some(checkpoint) = self.control("export_head", || self.master.export_head(false)).await?.checkpoint else {
            return Ok(false);
        };
        let master = self.control("expire_and_inspect", || self.master.expire_and_inspect()).await?;
        for name in &listed {
            let serving = self.factory.build(name)?;
            let head = match self.control("export_head", || serving.export_head(false)).await {
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
            if self.control("expire_and_inspect", || serving.expire_and_inspect()).await? != master {
                tracing::info!(epoch = %name, "serving epoch not adoptable (parts differ from the master)");
                continue;
            }
            let table = format!("agent.{name}_v1");
            if let Err(error) = self.control("writer_adopt", || self.factory.adopt(&table)).await {
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
                finishing: None,
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
            .control("export_head", || self.master.export_head(false))
            .await?
            .checkpoint
            .context("serving activation has no sealed hour")?;
        Ok(checkpoint.div_euclid(3_600_000) * 3_600_000 - 3_600_000)
    }
    /// NAN-4798: every agent-catalog control call made by the writer rides
    /// out network loss (see [`super::super::control_retry`]).
    async fn control<T, F, Fut>(&self, op: &'static str, call: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        retry(op, self.retry, call).await
    }
    /// NAN-4798: a non-transient refusal of the fence's last steps means the
    /// platform no longer holds this epoch's fresh-serving proof (e.g. a
    /// `writer_reopen` that landed but whose response was lost). Finishing
    /// can then never succeed: forget it, so the next sync mints.
    fn abandon_finishing(&self, error: &anyhow::Error) {
        if is_transient(error) {
            return;
        }
        let mut state = self.state();
        if state.finishing.take().is_some() {
            tracing::warn!(error = %format!("{error:#}"),
                "published serving epoch can no longer finish its privacy pass; the next sync mints a fresh epoch");
            if let Err(error) = self.save(state) {
                tracing::warn!(error = %format!("{error:#}"), "serving state not saved");
            }
        }
    }
    async fn retire(&self) -> Result<()> {
        for name in self.state().retired {
            let table = self.factory.build(&name)?;
            self.control("retire_epoch", || table.retire()).await?;
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
        // An ambiguous commit is idempotent: its replay is a checkpoint skip.
        self.control("commit", || self.master.commit(manifest)).await?;
        let mut state = self.state();
        if state.pending.is_none() {
            let name = state
                .active
                .as_ref()
                .context("serving table is not initialized")?;
            let serving = self.factory.build(name)?;
            self.control("commit", || serving.commit(manifest)).await?;
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
        self.factory.set_ingest_pressure(pressure);
    }
    async fn prepare_sync(&self, parts: &[PartRef], now: i64, policy: &MergePolicy) -> Result<()> {
        *self.live.lock().expect("serving live set") = (parts.to_vec(), now, *policy);
        Ok(())
    }
    async fn verify_maintenance(&self) -> Result<()> {
        self.control("verify_maintenance", || self.master.verify_maintenance()).await
    }
    /// NAN-4627: the master is the export chain. A wiped `serving/state.json`
    /// also forgot the master checkpoint, so a fresh epoch would be planned at
    /// 1 and every later delta (predecessor = the master checkpoint) would be
    /// refused by that epoch. Learn the checkpoint from the catalog itself.
    async fn export_head(&self, with_parts: bool) -> Result<super::super::ExportHead> {
        let head = self.control("export_head", || self.master.export_head(with_parts)).await?;
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
        if !self.control("list_epochs", || self.factory.list_epochs()).await?.is_empty() {
            return Ok(false);
        }
        self.control("no_committed_snapshot", || self.master.no_committed_snapshot()).await
    }
    async fn close_and_drain(&self) -> Result<()> {
        // NAN-4798: the mint is durable BEFORE the gateway call. Every caller
        // closes for a reason the next sync may not see again (installation
        // rotation, part GC degrade, a foreign part): a failed close must
        // never leave a `finishing` epoch to be resumed in its place.
        let mut state = self.state();
        if state.pending.is_none() || state.finishing.is_some() {
            if state.pending.is_none() {
                state.pending = Some(format!("events_{}", uuid::Uuid::new_v4().simple()));
            }
            state.finishing = None;
            self.save(state)?;
        }
        self.control("close_and_drain", || self.factory.close()).await
    }
    fn published_under_fence(&self) -> Option<i64> {
        let state = self.state();
        state.finishing.filter(|_| state.pending.is_none() && state.active.is_some())
    }
    async fn resume_fence(&self) -> Result<()> {
        let Some(checkpoint) = self.published_under_fence() else {
            return self.close_and_drain().await;
        };
        tracing::info!(epoch = ?self.state().active, checkpoint,
            "finishing the serving epoch published under the still-closed read fence; no new epoch");
        // Re-assert the closed gateway. The platform keeps the open privacy
        // fence (and its fresh-serving proof) when it is already closed.
        self.control("close_and_drain", || self.factory.close()).await
    }
    async fn expire_and_inspect(&self) -> Result<BTreeSet<String>> {
        let master = self.control("expire_and_inspect", || self.master.expire_and_inspect()).await?;
        let listed = self.control("list_epochs", || self.factory.list_epochs()).await?;
        let mut state = self.adopt_unknown_epochs(self.state(), listed)?;
        if let Some(next) = state.pending.clone() {
            let serving = self.factory.build(&next)?;
            let (parts, now, policy) = self.live.lock().expect("serving live set").clone();
            // NAN-4782: the fresh epoch is a COPY of the master's catalog
            // entries, never a replay of the live set through the export
            // target (which read every live part file: 3.5-9 h on a large
            // tenant, all over again after every roll or privacy pass).
            // The new NAME is the privacy fence; its contents only need to
            // equal the live set the master reached. So: publish only when
            // the master's references are exactly what a fresh build of the
            // prepared live set would hold (the planner's hours; an
            // unprepared or stale live set, or a master holding a part the
            // live set cannot reproduce, e.g. one part GC receipted, fails
            // closed and the next writer sync repeats this cheaply).
            let expected = plan_export_reconciled(&parts, &ExportState::default(), now, &policy)
                .into_iter()
                .flat_map(|(hour, _)| hour.parts)
                .collect::<BTreeSet<_>>();
            if let Some(vanished) = self.vanished.lock().expect("serving vanished").clone() {
                ensure!(
                    !master.iter().any(|part| vanished(part)),
                    "serving epoch names a part removed by part GC; rebuilding"
                );
            }
            if expected != master {
                anyhow::bail!("serving epoch live set changed; replay required");
            }
            // Removals and erasures are already reflected: `master` (every
            // part its retained metadata names, after expiry) equals the
            // live entries copied below, so no erased or merged-away part
            // and none of its bounds can reach the fresh name.
            let entries = self.control("live_entries", || self.master.live_entries()).await?;
            ensure!(
                entries.parts == master && entries.all_parts == master,
                "master metadata names parts outside its live files"
            );
            let started = std::time::Instant::now();
            if let Err(error) = self.control("seed", || serving.seed(&entries)).await {
                if error.downcast_ref::<super::super::SeedSchemaMismatch>().is_some() {
                    // A pre-upgrade pending epoch may use independently assigned
                    // field IDs. Replace its name, then retire it through the
                    // ordinary publish-before-retire path (also safe if an
                    // earlier publish landed but its response was lost).
                    state.retired.push(next);
                    state.pending = Some(format!("events_{}", uuid::Uuid::new_v4().simple()));
                    self.save(state)?;
                }
                return Err(error);
            }
            let references = self.control("expire_and_inspect", || serving.expire_and_inspect()).await?;
            if references != master {
                // Never expose it, even briefly. Retire and seed a new epoch
                // on the next bounded writer attempt.
                self.control("retire_epoch", || serving.retire()).await?;
                state.pending = Some(format!("events_{}", uuid::Uuid::new_v4().simple()));
                self.save(state)?;
                anyhow::bail!("serving epoch live set changed; replay required");
            }
            tracing::info!(files = entries.files.len(), parts = master.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "serving epoch seeded from the master (metadata only)");
            let new_name = format!("agent.{next}_v1");
            let legacy = self.work.join(&next);
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
            let details = json!({"table":new_name,
                "probe_window":{"start":chrono::DateTime::from_timestamp_millis(hour).context("invalid probe hour")?.to_rfc3339(),
                    "end":chrono::DateTime::from_timestamp_millis(hour+3_600_000).context("invalid probe hour")?.to_rfc3339()},
                "retired":state.active.iter().chain(state.retired.iter()).map(|n|format!("agent.{n}_v1")).collect::<Vec<_>>() });
            // Re-publishing the same fresh name and retired set is idempotent.
            self.control("publish_serving", || self.factory.publish(details.clone())).await?;
            if let Some(old) = state.active.replace(next) {
                state.retired.push(old);
            }
            state.pending = None;
            // NAN-4798: durable together with the publish. Whatever fails
            // from here to reopen, the next sync finishes THIS epoch.
            state.finishing = Some(entries.checkpoint.unwrap_or(i64::MIN));
            self.save(state)?;
            if let Err(error) = self.factory.retain_verified(&parts) {
                tracing::warn!(error = %format!("{error:#}"), "export verified-file records not pruned");
            }
            // A pre-NAN-4782 writer staged batch plans per epoch here.
            if legacy.try_exists().unwrap_or(false) {
                if let Err(error) = std::fs::remove_dir_all(&legacy) {
                    tracing::warn!(error = %error, "legacy serving epoch staging not removed");
                }
            }
        }
        // The gateway has durably retired every old name BEFORE drop/purge and
        // before this backend can acknowledge a per-part GC receipt.
        self.retire().await?;
        let state = self.state();
        if let Some(active) = state.active {
            let serving = self.factory.build(&active)?;
            ensure!(
                self.control("expire_and_inspect", || serving.expire_and_inspect()).await? == master,
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
        let invalidated = self.control("invalidate_results", || self.factory.invalidate()).await;
        if let Err(error) = &invalidated {
            self.abandon_finishing(error);
        }
        invalidated
    }
    async fn reopen(&self) -> Result<()> {
        if let Err(error) = self.control("writer_reopen", || self.factory.reopen()).await {
            self.abandon_finishing(&error);
            return Err(error);
        }
        let mut state = self.state();
        if state.finishing.take().is_some() {
            self.save(state)?;
        }
        Ok(())
    }
    async fn adopt_serving(&self) -> Result<bool> {
        self.adopt_serving_epoch().await
    }
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-tenant local-disk ceiling (NAN-3523, `tenant_disk_ceiling_v1`).
//!
//! The cell's data volume is one node-local emptyDir (its `sizeLimit` is a
//! kubelet eviction fence) or an ephemeral PVC, shared by every tenant on a
//! pooled cell. Only the part cache (the worker's `cache_max_bytes`, from
//! [`TenantBudget::cache_disk_bytes`](crate::budget::TenantBudget)) and the
//! cell-wide hot window are capped; spill, part drafts and staging, tmp and
//! role state were not. One flooding tenant could get the pod evicted or
//! ENOSPC every tenant.
//!
//! A dedicated thread walks each placed tenant's local tree
//! (`<data_dir>/tenants/<t>`, without `query/cache`, which the hot-window
//! accountant and the reader cache already bound) every `walk_secs`, as each
//! directory's owner and bounded to `max_entries` entries. The watchdog tick
//! ([`crate::supervisor::Supervisor::resources_once`]) then applies:
//!
//! - **soft** = `cache_disk_bytes + max(allowance_bytes, cache_disk_bytes)`:
//!   the `tenant_disk_pressure` signal warns and the supervisor stops
//!   admitting ingest work for that tenant (wake and spawn answer a
//!   retryable 503 with `Retry-After`). Ingest is pull-based: the raw-handoff
//!   DO keeps every unacked notice, so the backlog queues upstream.
//! - **hard** = `hard_factor × soft`: the signal pages and the tenant's
//!   ingest process is SIGKILLed (`watchdog_tenant_disk_ceiling`). No
//!   acknowledged data is lost: ingest acks DO notices (and detect's finding
//!   appends) only after the part-log commit, so everything uncommitted is
//!   redelivered after the restart. It stays refused until the tree is back
//!   under soft.
//!
//! Every tenant's hard ceiling is scaled down by one factor when the hard
//! ceilings would sum past `volume_fraction` of the volume; soft then
//! becomes up to [`FITTED_SOFT_SHARE`] of the fitted hard, never above its
//! unfitted figure ([`fit_to_volume`], NAN-3817). An accounting
//! failure (walk error, stale figure, entry bound hit below soft) fails
//! OPEN: ingest is admitted and `tenant_disk_accounting_failed` warns.
//! Other tenants are never touched. `mode` unset: enforce on pooled cells,
//! observe (signals and metrics only) on dedicated cells; an explicit
//! `mode` wins.

use crate::contract::TenantId;
use crate::resources::{EventKind, LimitEvent};
use crate::signals::Signal;
use crate::volume_usage::TreeUsage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const GIB: u64 = 1024 * 1024 * 1024;
/// Excluded from the measurement: capped by the hot-window accountant
/// (cell-wide) and the reader cache's own budget, and never ingest's.
pub const SKIPPED_SUBTREE: &str = "query/cache";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskCeilingMode {
    /// No walk, no signal, no refusal.
    Off,
    /// Measure and signal only (rollback switch).
    Observe,
    /// Measure, signal, refuse ingest admission over soft, kill over hard.
    Enforce,
}

impl DiskCeilingMode {
    /// Unset `mode`: enforce on pooled cells (the noisy-neighbour case),
    /// observe on dedicated cells (one tenant: nobody to protect, and a
    /// live tenant already over its soft figure must never have ingest
    /// refused by a roll).
    pub fn for_cell(configured: Option<Self>, cell: crate::config::CellMode) -> Self {
        configured.unwrap_or(match cell {
            crate::config::CellMode::Pooled => Self::Enforce,
            crate::config::CellMode::Dedicated => Self::Observe,
        })
    }
}

/// `resources.tenant_disk` in cell.json.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TenantDiskConfig {
    /// Unset: enforce on pooled cells, observe on dedicated cells
    /// ([`DiskCeilingMode::for_cell`]). An explicit value always wins.
    pub mode: Option<DiskCeilingMode>,
    /// Spill/staging/tmp/state room above the part cache budget; the soft
    /// ceiling adds the larger of this and the cache budget itself.
    pub allowance_bytes: u64,
    /// hard = factor × soft.
    pub hard_factor: f64,
    /// The data volume's size. Unset: `statvfs` of `data_dir`. Render the
    /// emptyDir `sizeLimit` here (statvfs shows the node disk instead).
    pub volume_bytes: Option<u64>,
    /// The hard ceilings of all placed tenants sum to at most this share
    /// of the volume (the rest is the hot window and cell state).
    pub volume_fraction: f64,
    /// Seconds between walks of every tenant tree; also the `Retry-After`.
    pub walk_secs: u64,
    /// Directory entries one tenant walk may visit.
    pub max_entries: u64,
}

impl Default for TenantDiskConfig {
    fn default() -> Self {
        Self {
            mode: None,
            allowance_bytes: 8 * GIB,
            hard_factor: 2.0,
            volume_bytes: None,
            volume_fraction: 0.9,
            walk_secs: 30,
            max_entries: 250_000,
        }
    }
}

impl TenantDiskConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.hard_factor.is_finite() && self.hard_factor > 1.0, "resources.tenant_disk.hard_factor must be > 1");
        anyhow::ensure!(self.volume_fraction.is_finite() && self.volume_fraction > 0.0 && self.volume_fraction <= 1.0,
            "resources.tenant_disk.volume_fraction must be in (0, 1]");
        anyhow::ensure!((5..=3600).contains(&self.walk_secs), "resources.tenant_disk.walk_secs must be 5..=3600");
        anyhow::ensure!(self.max_entries >= 1000, "resources.tenant_disk.max_entries must be ≥ 1000");
        anyhow::ensure!(self.volume_bytes != Some(0), "resources.tenant_disk.volume_bytes must be positive");
        Ok(())
    }

    /// One tenant's ceilings before the volume fit.
    pub fn ceiling(&self, cache_disk_bytes: u64) -> Ceiling {
        let soft = cache_disk_bytes.saturating_add(self.allowance_bytes.max(cache_disk_bytes));
        Ceiling { soft_bytes: soft, hard_bytes: (soft as f64 * self.hard_factor) as u64 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Ceiling {
    pub soft_bytes: u64,
    pub hard_bytes: u64,
}

/// Share of a volume-fitted hard ceiling the fitted soft ceiling may reach
/// (NAN-3817). Scaling soft by the same factor as hard kept it at
/// `1 / hard_factor` (half) of hard, which on a dedicated 128Gi cell put it
/// ~7 GB above the part-cache budget (45% of the disk) and a normal merge or
/// spill spike tripped it.
pub const FITTED_SOFT_SHARE: f64 = 0.8;

/// Scale every hard ceiling by one factor so they sum to at most `fraction`
/// of the volume. Soft is then the smallest of its unfitted figure (never
/// raised) and the larger of its proportionally scaled figure and
/// [`FITTED_SOFT_SHARE`] of the fitted hard, so it stays below hard and
/// keeps the cache budget's working-set room instead of collapsing toward
/// the cache budget. Unknown volume: unchanged.
pub fn fit_to_volume(ceilings: &mut [(TenantId, Ceiling)], volume_bytes: Option<u64>, fraction: f64) {
    let Some(volume) = volume_bytes else { return };
    let budget = volume as f64 * fraction;
    let sum: f64 = ceilings.iter().map(|(_, c)| c.hard_bytes as f64).sum();
    if sum <= budget || sum <= 0.0 {
        return;
    }
    let f = budget / sum;
    for (_, c) in ceilings.iter_mut() {
        let hard = c.hard_bytes as f64 * f;
        let soft = (c.soft_bytes as f64 * f).max(hard * FITTED_SOFT_SHARE).min(c.soft_bytes as f64);
        c.soft_bytes = soft as u64;
        c.hard_bytes = hard as u64;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskLevel {
    Ok,
    /// Over soft: ingest admission refused (enforce).
    Pressure,
    /// Over hard: ingest killed (enforce).
    Ceiling,
    /// No trustworthy figure: fail open.
    Unknown,
}

/// One walk result.
#[derive(Debug, Clone)]
pub struct Sample {
    pub at: Instant,
    pub usage: Result<TreeUsage, String>,
}

/// The level for `sample` against `ceiling`. A lower bound (entry bound
/// hit) still counts once it is over soft.
pub fn level(sample: Option<&Sample>, ceiling: Ceiling, now: Instant, max_age: Duration) -> DiskLevel {
    let Some(s) = sample.filter(|s| now.saturating_duration_since(s.at) <= max_age) else {
        return DiskLevel::Unknown;
    };
    match &s.usage {
        Err(_) => DiskLevel::Unknown,
        Ok(u) if u.bytes >= ceiling.hard_bytes => DiskLevel::Ceiling,
        Ok(u) if u.bytes >= ceiling.soft_bytes => DiskLevel::Pressure,
        Ok(u) if !u.complete => DiskLevel::Unknown,
        Ok(_) => DiskLevel::Ok,
    }
}

/// A tenant's disk state, as `/v1/status` shows it (`tenants[].disk`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TenantDiskView {
    pub level: DiskLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    pub soft_bytes: u64,
    pub hard_bytes: u64,
    /// The last walk stopped at its entry bound (`bytes` is a lower bound).
    pub partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampled_secs_ago: Option<u64>,
    /// Ingest wake/spawn answers 503 now.
    pub ingest_refused: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Over the soft ceiling with enforcement on: why ingest is not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskRefusal {
    pub bytes: u64,
    pub soft_bytes: u64,
    pub retry_after_secs: u64,
}

/// What one watchdog tick must do.
#[derive(Debug, Default)]
pub struct DiskTick {
    /// Tenants over their hard ceiling: kill their ingest (enforce only).
    pub kills: Vec<(TenantId, u64, Ceiling)>,
    /// Transitions into pressure, for the tenant's limit events.
    pub events: Vec<LimitEvent>,
}

/// Measurements and verdicts, shared by the walker thread, the watchdog
/// tick, admission, status and signals.
pub struct DiskCeilings {
    cfg: TenantDiskConfig,
    mode: DiskCeilingMode,
    samples: Mutex<HashMap<TenantId, Sample>>,
    volume_bytes: Mutex<Option<u64>>,
    views: Mutex<HashMap<TenantId, TenantDiskView>>,
}

impl DiskCeilings {
    pub fn new(cfg: TenantDiskConfig, cell: crate::config::CellMode) -> Self {
        let volume = cfg.volume_bytes;
        let mode = DiskCeilingMode::for_cell(cfg.mode, cell);
        Self { cfg, mode, samples: Mutex::default(), volume_bytes: Mutex::new(volume), views: Mutex::default() }
    }

    pub fn mode(&self) -> DiskCeilingMode {
        self.mode
    }

    fn max_age(&self) -> Duration {
        Duration::from_secs(self.cfg.walk_secs.saturating_mul(3))
    }

    pub fn record(&self, tenant: TenantId, sample: Sample) {
        self.samples.lock().unwrap().insert(tenant, sample);
    }

    /// One tick: ceilings for the placed tenants (`(tenant, cache_disk_bytes)`),
    /// their levels, and what to do. Logs every level change.
    pub fn evaluate(&self, placed: &[(TenantId, u64)], now: Instant) -> DiskTick {
        let mut tick = DiskTick::default();
        if self.mode == DiskCeilingMode::Off {
            return tick;
        }
        let mut ceilings: Vec<(TenantId, Ceiling)> = placed.iter().map(|(t, cache)| (t.clone(), self.cfg.ceiling(*cache))).collect();
        fit_to_volume(&mut ceilings, *self.volume_bytes.lock().unwrap(), self.cfg.volume_fraction);
        let enforce = self.mode == DiskCeilingMode::Enforce;
        let mut samples = self.samples.lock().unwrap();
        samples.retain(|t, _| placed.iter().any(|(p, _)| p == t));
        let mut views = self.views.lock().unwrap();
        let before = std::mem::take(&mut *views);
        for (tenant, ceiling) in ceilings {
            let sample = samples.get(&tenant);
            let lvl = level(sample, ceiling, now, self.max_age());
            let (bytes, partial, error) = match sample.map(|s| &s.usage) {
                Some(Ok(u)) => (Some(u.bytes), !u.complete, None),
                Some(Err(e)) => (None, false, Some(e.clone())),
                None => (None, false, None),
            };
            let error = error.or_else(|| match (lvl, sample) {
                (DiskLevel::Unknown, None) => None,
                (DiskLevel::Unknown, Some(_)) if partial => Some(format!("walk stopped at {} entries", self.cfg.max_entries)),
                (DiskLevel::Unknown, Some(_)) => Some("disk figure is stale (walker stuck or failing)".into()),
                _ => None,
            });
            let view = TenantDiskView {
                level: lvl,
                bytes,
                soft_bytes: ceiling.soft_bytes,
                hard_bytes: ceiling.hard_bytes,
                partial,
                sampled_secs_ago: sample.map(|s| now.saturating_duration_since(s.at).as_secs()),
                ingest_refused: enforce && matches!(lvl, DiskLevel::Pressure | DiskLevel::Ceiling),
                error,
            };
            let prev = before.get(&tenant).map(|v| v.level);
            if prev != Some(lvl) && !(prev.is_none() && (lvl == DiskLevel::Ok || sample.is_none())) {
                let observed = bytes.unwrap_or(0);
                match lvl {
                    DiskLevel::Ok => tracing::info!(tenant = %tenant, bytes = observed, soft = ceiling.soft_bytes,
                        "tenant disk back under its soft ceiling; ingest admitted"),
                    DiskLevel::Pressure => tracing::warn!(tenant = %tenant, bytes = observed, soft = ceiling.soft_bytes,
                        hard = ceiling.hard_bytes, enforce, "tenant disk over its soft ceiling; ingest admission refused"),
                    DiskLevel::Ceiling => tracing::error!(tenant = %tenant, bytes = observed, hard = ceiling.hard_bytes, enforce,
                        "tenant disk over its hard ceiling; killing its ingest"),
                    DiskLevel::Unknown => tracing::warn!(tenant = %tenant, error = view.error.as_deref().unwrap_or("not measured yet"),
                        "tenant disk accounting unavailable; failing open (ingest admitted)"),
                }
                if lvl == DiskLevel::Pressure {
                    tick.events.push(LimitEvent::new(Some(&tenant), EventKind::SoftLimitExceeded, "tenant_disk_pressure",
                        observed as f64, ceiling.soft_bytes as f64, "bytes"));
                }
            }
            if enforce && lvl == DiskLevel::Ceiling {
                tick.kills.push((tenant.clone(), bytes.unwrap_or(0), ceiling));
            }
            views.insert(tenant, view);
        }
        tick
    }

    /// Ingest admission for `tenant`: refused only with enforcement on and
    /// the last evaluation over soft. Unknown (accounting failure) admits.
    pub fn admit_ingest(&self, tenant: &TenantId) -> Result<(), DiskRefusal> {
        match self.views.lock().unwrap().get(tenant) {
            Some(v) if v.ingest_refused => Err(DiskRefusal {
                bytes: v.bytes.unwrap_or(0),
                soft_bytes: v.soft_bytes,
                retry_after_secs: self.cfg.walk_secs,
            }),
            _ => Ok(()),
        }
    }

    pub fn view(&self, tenant: &TenantId) -> Option<TenantDiskView> {
        self.views.lock().unwrap().get(tenant).cloned()
    }

    /// `tenant_disk_pressure` (warns at soft, pages at hard) and
    /// `tenant_disk_accounting_failed` (warns) for one tenant.
    pub fn signals(&self, tenant: &TenantId) -> Vec<Signal> {
        let Some(v) = self.view(tenant) else { return vec![] };
        let t = Some(tenant.clone());
        let detail = matches!(v.level, DiskLevel::Pressure | DiskLevel::Ceiling).then(|| {
            format!("{} of {} soft / {} hard bytes{}", v.bytes.unwrap_or(0), v.soft_bytes, v.hard_bytes,
                if v.ingest_refused { "; ingest admission refused (503)" } else { " (observe only)" })
        });
        vec![
            Signal::evaluate(t.clone(), "cell", "tenant", "tenant_disk_pressure", "bytes", v.bytes.unwrap_or(0) as f64,
                v.soft_bytes as f64, v.hard_bytes as f64, detail),
            Signal::evaluate(t, "cell", "tenant", "tenant_disk_accounting_failed", "flag",
                (v.level == DiskLevel::Unknown && v.error.is_some()) as u8 as f64, 1.0, f64::INFINITY, v.error.clone()),
        ]
    }

    /// Walk every tenant `placed()` returns under `tenants_dir`, every
    /// `walk_secs`, on one dedicated thread (the walk switches fsuid per
    /// directory). Stops when `placed()` returns `None`.
    pub fn spawn_walker(
        self: &Arc<Self>,
        tenants_dir: PathBuf,
        placed: impl Fn() -> Option<Vec<TenantId>> + Send + 'static,
    ) -> std::io::Result<()> {
        if self.mode == DiskCeilingMode::Off {
            return Ok(());
        }
        let me = Arc::downgrade(self);
        std::thread::Builder::new().name("tenant-disk-walk".into()).spawn(move || loop {
            let Some(tenants) = placed() else { return };
            let Some(me) = me.upgrade() else { return };
            if me.cfg.volume_bytes.is_none() {
                *me.volume_bytes.lock().unwrap() = statvfs_bytes(&tenants_dir);
            }
            for tenant in tenants {
                let usage = walk_tenant(&tenants_dir, &tenant, me.cfg.max_entries);
                if let Err(error) = &usage {
                    tracing::debug!(tenant = %tenant, %error, "tenant disk walk failed");
                }
                me.record(tenant, Sample { at: Instant::now(), usage });
            }
            let every = Duration::from_secs(me.cfg.walk_secs);
            drop(me);
            std::thread::sleep(every);
        })?;
        Ok(())
    }
}

/// One tenant's tree; a tree not created yet is empty.
pub fn walk_tenant(tenants_dir: &Path, tenant: &TenantId, max_entries: u64) -> Result<TreeUsage, String> {
    let root = tenants_dir.join(tenant.as_str());
    match crate::volume_usage::owned_tree_usage(&root, &[Path::new(SKIPPED_SUBTREE)], max_entries) {
        Ok(u) => Ok(u),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TreeUsage { bytes: 0, entries: 0, complete: true }),
        Err(e) => Err(e.to_string()),
    }
}

fn statvfs_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs on a valid C string into an owned, zeroed struct.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    Some((s.f_blocks as u64).saturating_mul(s.f_frsize as u64)).filter(|b| *b > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> TenantId {
        TenantId::new(s).unwrap()
    }

    fn ok(bytes: u64, at: Instant) -> Sample {
        Sample { at, usage: Ok(TreeUsage { bytes, entries: 10, complete: true }) }
    }

    fn cells(cfg: TenantDiskConfig) -> DiskCeilings {
        DiskCeilings::new(TenantDiskConfig { volume_bytes: Some(1 << 50), ..cfg }, crate::config::CellMode::Pooled)
    }

    /// Unset mode: enforce on pooled cells, observe on dedicated cells; an
    /// explicit mode wins either way.
    #[test]
    fn default_mode_follows_the_cell_mode() {
        use crate::config::CellMode::{Dedicated, Pooled};
        let now = Instant::now();
        let dedicated = DiskCeilings::new(TenantDiskConfig::default(), Dedicated);
        assert_eq!(dedicated.mode(), DiskCeilingMode::Observe);
        dedicated.record(t("a"), ok(100 * GIB, now));
        assert!(dedicated.evaluate(&[(t("a"), GIB)], now).kills.is_empty(), "a dedicated cell never kills by default");
        assert_eq!(dedicated.admit_ingest(&t("a")), Ok(()), "nor refuses");
        let page = dedicated.signals(&t("a")).into_iter().find(|s| s.signal == "tenant_disk_pressure").unwrap();
        assert_eq!(page.severity, crate::signals::Severity::Page, "but still signals");
        assert_eq!(DiskCeilings::new(TenantDiskConfig::default(), Pooled).mode(), DiskCeilingMode::Enforce);
        let forced = TenantDiskConfig { mode: Some(DiskCeilingMode::Enforce), ..Default::default() };
        assert_eq!(DiskCeilings::new(forced, Dedicated).mode(), DiskCeilingMode::Enforce);
        let observe = TenantDiskConfig { mode: Some(DiskCeilingMode::Observe), ..Default::default() };
        assert_eq!(DiskCeilings::new(observe, Pooled).mode(), DiskCeilingMode::Observe);
    }

    #[test]
    fn defaults_validate_and_scale_with_the_budget() {
        let cfg = TenantDiskConfig::default();
        cfg.validate().unwrap();
        // 20 eps (1 GiB cache): 9 GiB soft, 18 GiB hard.
        assert_eq!(cfg.ceiling(GIB), Ceiling { soft_bytes: 9 * GIB, hard_bytes: 18 * GIB });
        // 1,200 eps (30 GiB cache): the allowance follows the cache.
        assert_eq!(cfg.ceiling(30 * GIB), Ceiling { soft_bytes: 60 * GIB, hard_bytes: 120 * GIB });
        assert!(TenantDiskConfig { hard_factor: 1.0, ..cfg.clone() }.validate().is_err());
        assert!(TenantDiskConfig { volume_fraction: 1.5, ..cfg.clone() }.validate().is_err());
        assert!(TenantDiskConfig { volume_bytes: Some(0), ..cfg }.validate().is_err());
    }

    #[test]
    fn ceilings_never_sum_past_the_volume() {
        let cfg = TenantDiskConfig::default();
        let mut c: Vec<_> = ["a", "b", "c"].iter().map(|n| (t(n), cfg.ceiling(8 * GIB))).collect();
        fit_to_volume(&mut c, Some(100 * GIB), 0.9);
        let sum: u64 = c.iter().map(|(_, c)| c.hard_bytes).sum();
        assert!(sum <= 90 * GIB, "{sum}");
        assert!(c.iter().all(|(_, c)| c.soft_bytes < c.hard_bytes));
        let mut roomy = vec![(t("a"), cfg.ceiling(GIB))];
        fit_to_volume(&mut roomy, Some(1000 * GIB), 0.9);
        assert_eq!(roomy[0].1, cfg.ceiling(GIB), "a roomy volume changes nothing");
    }

    const GB: u64 = 1_000_000_000;

    /// NAN-3817, tenant-a (dedicated, 2,000 eps): a 53.21 GB cache budget on a
    /// 128Gi PVC (134.15 GB statvfs). Proportional fitting put soft at
    /// 60.37 GB (45% of the disk, ~7 GB over the cache); it must sit near
    /// 0.72 of the volume with hard at 0.9.
    #[test]
    fn dedicated_fit_keeps_working_set_room_above_the_cache() {
        let cfg = TenantDiskConfig::default();
        let volume = 134_145_380_351;
        let mut c = vec![(t("tenant-a"), cfg.ceiling(53_210_000_000))];
        assert_eq!(c[0].1.soft_bytes, 106_420_000_000);
        fit_to_volume(&mut c, Some(volume), cfg.volume_fraction);
        let Ceiling { soft_bytes: soft, hard_bytes: hard } = c[0].1;
        assert!(hard.abs_diff(120_730_842_316) <= 1, "hard {hard}");
        assert!((96 * GB..=107 * GB).contains(&soft), "soft {soft}");
        assert!(soft > 53_210_000_000 + 40 * GB, "soft {soft} leaves working-set room over the cache");
        assert!(soft < hard);
        // The flapping figure (60.4–60.8 GB) is now well under soft.
        let d = DiskCeilings::new(TenantDiskConfig { volume_bytes: Some(volume), ..cfg }, crate::config::CellMode::Dedicated);
        let now = Instant::now();
        d.record(t("tenant-a"), ok(60_787_412_992, now));
        assert!(d.evaluate(&[(t("tenant-a"), 53_210_000_000)], now).events.is_empty());
        assert_eq!(d.view(&t("tenant-a")).unwrap().level, DiskLevel::Ok);
    }

    /// A pooled cell over-subscribed by its hard ceilings: every hard still
    /// fits the volume, soft rises to 0.8 × fitted hard but never above its
    /// unfitted figure, and refusal still happens before the kill.
    #[test]
    fn pooled_fit_raises_soft_within_its_unfitted_figure() {
        let cfg = TenantDiskConfig::default();
        // 160 GiB data volume; 4 × 16 GiB-cache tenants (32 GiB soft, 64 GiB
        // hard each) + 2 small ones (9 / 18 GiB): 292 GiB of hard on a
        // 144 GiB budget.
        let volume = 160 * GIB;
        let budget = (volume as f64 * cfg.volume_fraction) as u64;
        let mut c: Vec<_> = ["a", "b", "c", "d"].iter().map(|n| (t(n), cfg.ceiling(16 * GIB))).collect();
        c.extend(["s1", "s2"].iter().map(|n| (t(n), cfg.ceiling(GIB))));
        let unfitted: Vec<Ceiling> = c.iter().map(|(_, c)| *c).collect();
        fit_to_volume(&mut c, Some(volume), cfg.volume_fraction);
        let sum: u64 = c.iter().map(|(_, c)| c.hard_bytes).sum();
        assert!(sum <= budget, "{sum} > {budget}");
        for ((name, fitted), before) in c.iter().zip(&unfitted) {
            assert!(fitted.soft_bytes < fitted.hard_bytes, "{name}");
            assert!(fitted.soft_bytes <= before.soft_bytes, "{name}: soft never rises past its unfitted figure");
            let share = fitted.soft_bytes as f64 / fitted.hard_bytes as f64;
            assert!((share - FITTED_SOFT_SHARE).abs() < 1e-6, "{name}: {share}");
        }
        // f = 144/292: a big tenant's hard ≈ 31.6 GiB, soft ≈ 25.2 GiB (was 15.8).
        assert!(c[0].1.soft_bytes > 25 * GIB && c[0].1.soft_bytes < 26 * GIB, "{:?}", c[0].1);
        assert!(c[0].1.hard_bytes > 31 * GIB && c[0].1.hard_bytes < 32 * GIB, "{:?}", c[0].1);
        // Mildly over-subscribed (f close to 1): soft is capped at its unfitted figure.
        let mut mild = vec![(t("a"), cfg.ceiling(16 * GIB))];
        fit_to_volume(&mut mild, Some(70 * GIB), cfg.volume_fraction);
        assert_eq!(mild[0].1.soft_bytes, 32 * GIB);
        assert!(mild[0].1.hard_bytes <= 63 * GIB && mild[0].1.hard_bytes > 32 * GIB);
        // Enforce: between soft and hard is refused, over hard is killed.
        let d = DiskCeilings::new(TenantDiskConfig { volume_bytes: Some(volume), ..cfg }, crate::config::CellMode::Pooled);
        let now = Instant::now();
        let placed: Vec<_> = c.iter().map(|(n, _)| (n.clone(), if n.as_str().starts_with('s') { GIB } else { 16 * GIB })).collect();
        d.record(t("a"), ok(28 * GIB, now));
        d.record(t("b"), ok(40 * GIB, now));
        d.record(t("c"), ok(20 * GIB, now));
        let tick = d.evaluate(&placed, now);
        assert_eq!(tick.kills.iter().map(|(t, _, _)| t.as_str()).collect::<Vec<_>>(), vec!["b"]);
        assert!(d.admit_ingest(&t("a")).is_err(), "over soft, under hard: refused");
        assert_eq!(d.admit_ingest(&t("c")), Ok(()));
    }

    #[test]
    fn under_soft_admits() {
        let d = cells(TenantDiskConfig::default());
        let now = Instant::now();
        d.record(t("a"), ok(GIB, now));
        let tick = d.evaluate(&[(t("a"), GIB)], now);
        assert!(tick.kills.is_empty() && tick.events.is_empty());
        assert_eq!(d.admit_ingest(&t("a")), Ok(()));
        assert_eq!(d.view(&t("a")).unwrap().level, DiskLevel::Ok);
        assert!(d.signals(&t("a")).iter().all(|s| s.severity == crate::signals::Severity::Ok));
    }

    #[test]
    fn over_soft_refuses_ingest_with_retry_after_and_warns() {
        let d = cells(TenantDiskConfig::default());
        let now = Instant::now();
        d.record(t("a"), ok(10 * GIB, now));
        d.record(t("b"), ok(GIB, now));
        let tick = d.evaluate(&[(t("a"), GIB), (t("b"), GIB)], now);
        assert!(tick.kills.is_empty());
        assert_eq!(tick.events.len(), 1);
        assert_eq!(tick.events[0].reason, "tenant_disk_pressure");
        let refusal = d.admit_ingest(&t("a")).unwrap_err();
        assert_eq!(refusal, DiskRefusal { bytes: 10 * GIB, soft_bytes: 9 * GIB, retry_after_secs: 30 });
        assert_eq!(d.admit_ingest(&t("b")), Ok(()), "a neighbour is untouched");
        let sig = d.signals(&t("a"));
        let pressure = sig.iter().find(|s| s.signal == "tenant_disk_pressure").unwrap();
        assert_eq!(pressure.severity, crate::signals::Severity::Warn);
        assert!(pressure.detail.as_deref().unwrap().contains("503"));
        // A repeat tick logs nothing new.
        assert!(d.evaluate(&[(t("a"), GIB), (t("b"), GIB)], now).events.is_empty());
    }

    #[test]
    fn over_hard_kills_only_that_tenant_and_pages() {
        let d = cells(TenantDiskConfig::default());
        let now = Instant::now();
        d.record(t("flood"), ok(20 * GIB, now));
        d.record(t("calm"), ok(8 * GIB, now));
        let tick = d.evaluate(&[(t("flood"), GIB), (t("calm"), GIB)], now);
        assert_eq!(tick.kills.iter().map(|(t, _, _)| t.as_str()).collect::<Vec<_>>(), vec!["flood"]);
        assert_eq!(tick.kills[0].1, 20 * GIB);
        assert!(d.admit_ingest(&t("flood")).is_err());
        assert_eq!(d.admit_ingest(&t("calm")), Ok(()));
        let page = d.signals(&t("flood")).into_iter().find(|s| s.signal == "tenant_disk_pressure").unwrap();
        assert_eq!(page.severity, crate::signals::Severity::Page);
    }

    #[test]
    fn observe_mode_signals_but_never_refuses_or_kills() {
        let d = cells(TenantDiskConfig { mode: Some(DiskCeilingMode::Observe), ..Default::default() });
        let now = Instant::now();
        d.record(t("a"), ok(100 * GIB, now));
        let tick = d.evaluate(&[(t("a"), GIB)], now);
        assert!(tick.kills.is_empty());
        assert_eq!(d.admit_ingest(&t("a")), Ok(()));
        assert_eq!(d.view(&t("a")).unwrap().level, DiskLevel::Ceiling);
        let off = cells(TenantDiskConfig { mode: Some(DiskCeilingMode::Off), ..Default::default() });
        off.record(t("a"), ok(100 * GIB, now));
        assert!(off.evaluate(&[(t("a"), GIB)], now).kills.is_empty());
        assert!(off.view(&t("a")).is_none() && off.signals(&t("a")).is_empty());
    }

    #[test]
    fn accounting_failure_fails_open_with_a_warning() {
        let d = cells(TenantDiskConfig::default());
        let now = Instant::now();
        d.record(t("err"), Sample { at: now, usage: Err("Permission denied".into()) });
        d.record(t("stale"), ok(100 * GIB, now));
        d.record(t("partial"), Sample { at: now, usage: Ok(TreeUsage { bytes: GIB, entries: 250_000, complete: false }) });
        let later = now + Duration::from_secs(91);
        d.record(t("err"), Sample { at: later, usage: Err("Permission denied".into()) });
        d.record(t("partial"), Sample { at: later, usage: Ok(TreeUsage { bytes: GIB, entries: 250_000, complete: false }) });
        let placed = [(t("err"), GIB), (t("stale"), GIB), (t("partial"), GIB), (t("unmeasured"), GIB)];
        let tick = d.evaluate(&placed, later);
        assert!(tick.kills.is_empty(), "a stale figure over hard never kills");
        for (tenant, _) in &placed {
            assert_eq!(d.admit_ingest(tenant), Ok(()), "{tenant} fails open");
            assert_eq!(d.view(tenant).unwrap().level, DiskLevel::Unknown);
        }
        for name in ["err", "stale", "partial"] {
            let s = d.signals(&t(name)).into_iter().find(|s| s.signal == "tenant_disk_accounting_failed").unwrap();
            assert_eq!(s.severity, crate::signals::Severity::Warn, "{name}");
        }
        let quiet = d.signals(&t("unmeasured")).into_iter().find(|s| s.signal == "tenant_disk_accounting_failed").unwrap();
        assert_eq!(quiet.severity, crate::signals::Severity::Ok, "not measured yet is not a failure");
        // A lower bound already over hard still acts.
        d.record(t("partial"), Sample { at: later, usage: Ok(TreeUsage { bytes: 40 * GIB, entries: 250_000, complete: false }) });
        assert_eq!(d.evaluate(&placed, later).kills.len(), 1);
    }

    #[test]
    fn walker_measures_tenant_trees_without_the_query_cache() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a");
        std::fs::create_dir_all(root.join("query/cache")).unwrap();
        std::fs::create_dir_all(root.join("ingest/tmp")).unwrap();
        std::fs::write(root.join("query/cache/part"), vec![1; 4 << 20]).unwrap();
        std::fs::write(root.join("ingest/tmp/spill"), vec![1; 1 << 20]).unwrap();
        let u = walk_tenant(dir.path(), &t("a"), 1000).unwrap();
        assert!(u.complete && u.bytes >= 1 << 20 && u.bytes < 4 << 20, "{u:?}");
        assert_eq!(walk_tenant(dir.path(), &t("missing"), 1000).unwrap().bytes, 0);
        assert!(statvfs_bytes(dir.path()).is_some());
    }
}

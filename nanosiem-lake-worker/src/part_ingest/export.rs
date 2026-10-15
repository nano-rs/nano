// SPDX-License-Identifier: AGPL-3.0-or-later

//! The hourly Iceberg export (design decision 3): off the hot path, for BYO
//! readers only; never the serving source.
//!
//! Once an hour, every sealed hour whose final part set changed since its
//! last export gets an export manifest: the exact hour/day part data files
//! (keys, rows, bytes) to copy or register by reference, and the files they
//! replace. An [`IcebergCommitter`] turns a manifest into one catalog
//! commit (append, or overwrite when a day part replaces hour parts). The
//! optional REST committer is in `iceberg_export`; production target adapters
//! and scheduling are gated separately. Durable APIs below are opt-in, leaving
//! legacy ingest planner callers unchanged.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::io::Write;

use crate::parts::format::PartKeys;
use crate::parts::levels::{Level, MergePolicy};
use crate::parts::part_log::PartRef;
use crate::parts::HOUR_US;

pub const EXPORT_INTERVAL_MS: i64 = 3_600_000;

/// One hour's desired Iceberg content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportHour {
    pub event_hour: i32,
    /// Part ids whose data files represent this hour (an H part, or the D
    /// part covering it).
    pub parts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportFile {
    /// Data file keys of the part, in order.
    pub keys: Vec<String>,
    pub part_id: String,
    pub rows: u64,
    pub bytes: u64,
    pub min_time_us: i64,
    pub max_time_us: i64,
}

/// What one export commit must do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportManifest {
    pub tenant_id: String,
    pub planned_at_ms: i64,
    /// Required predecessor for ordered catalog replay. Legacy manifests have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_plan_ms: Option<i64>,
    pub add: Vec<ExportFile>,
    /// Part ids previously exported and now superseded (overwrite).
    pub remove_parts: Vec<String>,
    pub hours: Vec<ExportHour>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportState {
    /// event hour → part ids last exported for it.
    pub exported: BTreeMap<i32, Vec<String>>,
    pub last_plan_ms: i64,
}

fn state_path(work_dir: &Path) -> PathBuf {
    work_dir.join("export").join("state.json")
}

impl ExportState {
    pub fn load(work_dir: &Path) -> Result<Self> {
        match std::fs::read(state_path(work_dir)) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }

    /// Forget export state for hours past retention and delete pending
    /// manifests older than `keep_ms` (committed or superseded by then).
    pub fn prune(&mut self, work_dir: &Path, now_ms: i64, retention_hours: i64, keep_ms: i64) -> Result<()> {
        let floor = (now_ms / (HOUR_US / 1_000) - retention_hours) as i32;
        self.exported.retain(|hour, _| *hour >= floor);
        let dir = work_dir.join("export").join("pending");
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let planned = name.split('.').next().and_then(|n| n.parse::<i64>().ok());
            if planned.is_some_and(|at| now_ms - at > keep_ms) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(())
    }

    pub fn due(&self, now_ms: i64) -> bool {
        now_ms - self.last_plan_ms >= EXPORT_INTERVAL_MS
    }

    /// Write the manifest for `pending` and advance the state.
    pub fn record_plan(&mut self, work_dir: &Path, tenant_id: &str, pending: &[(ExportHour, Vec<PartRef>)], now_ms: i64) -> Result<PathBuf> {
        let manifest = make_manifest(self, tenant_id, pending, now_ms, None)?;
        let dir = work_dir.join("export").join("pending");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{now_ms:013}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&manifest)?)?;
        for (hour, _) in pending {
            self.exported.insert(hour.event_hour, hour.parts.clone());
        }
        self.last_plan_ms = now_ms;
        std::fs::write(state_path(work_dir), serde_json::to_vec(self)?)?;
        Ok(path)
    }
}

impl ExportState {
    /// Load only dedicated opt-in target state, recovering published plans.
    pub fn load_durable(work_dir: &Path) -> Result<Self> {
        let mut state = Self::load(work_dir)?;
        // A crash after publishing a manifest but before publishing state must
        // recover that plan, rather than create another delta with its predecessor.
        let directory = work_dir.join("export").join("pending");
        let mut paths = match std::fs::read_dir(directory) {
            Ok(entries) => entries.map(|entry| entry.map(|entry| entry.path())).collect::<std::io::Result<Vec<_>>>()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(error) => return Err(error.into()),
        };
        paths.retain(|path| path.extension().is_some_and(|extension| extension == "json"));
        paths.sort();
        for path in paths {
            let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
            if manifest.planned_at_ms <= state.last_plan_ms { continue; }
            ensure!(manifest.previous_plan_ms == (state.last_plan_ms > 0).then_some(state.last_plan_ms), "pending export predecessor mismatch");
            for hour in manifest.hours { state.exported.insert(hour.event_hour, hour.parts); }
            state.last_plan_ms = manifest.planned_at_ms;
        }
        Ok(state)
    }

    /// Forget old empty hours and prune acknowledged manifests only. Pending
    /// manifests must survive outages regardless of age; nonempty hours must
    /// first be exported as deletions before their state can be forgotten.
    pub fn prune_acknowledged(&mut self, work_dir: &Path, now_ms: i64, retention_hours: i64, keep_ms: i64) -> Result<()> {
        let floor = (now_ms / (HOUR_US / 1_000) - retention_hours) as i32;
        self.exported.retain(|hour, parts| *hour >= floor || !parts.is_empty());
        let dir = work_dir.join("export").join("committed");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let planned = name.split('.').next().and_then(|n| n.parse::<i64>().ok());
            if planned.is_some_and(|at| now_ms - at > keep_ms) {
                std::fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    /// Under an exclusive target planner lease, publish a complete immutable
    /// manifest before atomically advancing state. Reload/replan after an error.
    pub fn record_durable_plan(&mut self, work_dir: &Path, tenant_id: &str, pending: &[(ExportHour, Vec<PartRef>)], now_ms: i64) -> Result<PathBuf> {
        ensure!(now_ms > self.last_plan_ms, "export plan time must advance");
        let manifest = make_manifest(self, tenant_id, pending, now_ms, (self.last_plan_ms > 0).then_some(self.last_plan_ms))?;
        let dir = work_dir.join("export").join("pending");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{now_ms:013}.json"));
        atomic_write(&path, &serde_json::to_vec_pretty(&manifest)?, true)?;
        let mut next = self.clone();
        for (hour, _) in pending {
            next.exported.insert(hour.event_hour, hour.parts.clone());
        }
        next.last_plan_ms = now_ms;
        atomic_write(&state_path(work_dir), &serde_json::to_vec(&next)?, false)?;
        *self = next;
        Ok(path)
    }
}

fn make_manifest(state: &ExportState, tenant_id: &str, pending: &[(ExportHour, Vec<PartRef>)], now_ms: i64, previous_plan_ms: Option<i64>) -> Result<ExportManifest> {
    let mut add = BTreeMap::new();
    let mut remove = BTreeSet::new();
    for (hour, parts) in pending {
        for part in parts {
            let keys = PartKeys::new(tenant_id, part.level, part.event_hour, &part.part_id)?;
            add.insert(
                part.part_id.to_string(),
                ExportFile {
                    keys: (0..part.data_files as usize).map(|i| keys.data(i)).collect(),
                    part_id: part.part_id.to_string(),
                    rows: part.rows,
                    bytes: part.data_bytes,
                    min_time_us: part.min_time_us,
                    max_time_us: part.max_time_us,
                },
            );
        }
        if let Some(previous) = state.exported.get(&hour.event_hour) {
            remove.extend(previous.iter().filter(|id| !hour.parts.contains(id)).cloned());
        }
    }
    // A day part added for one hour is not "removed" for another hour.
    remove.retain(|id| !add.contains_key(id));
    Ok(ExportManifest {
        tenant_id: tenant_id.to_string(),
        planned_at_ms: now_ms,
        previous_plan_ms,
        add: add.into_values().collect(),
        remove_parts: remove.into_iter().collect(),
        hours: pending.iter().map(|(h, _)| h.clone()).collect(),
    })
}

// Publish complete files, fsync contents and directory before advancing state.
fn atomic_write(path: &Path, bytes: &[u8], immutable: bool) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("export path has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if immutable { temporary.persist_noclobber(path)?; } else { temporary.persist(path)?; }
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Commits one manifest to the tenant's Iceberg table.
#[async_trait::async_trait]
pub trait IcebergCommitter: Send + Sync {
    async fn commit(&self, manifest: &ExportManifest) -> Result<()>;
}

/// Sealed hours whose final part set differs from the last export.
pub fn plan_export(live: &[PartRef], state: &ExportState, now_ms: i64, policy: &MergePolicy) -> Vec<(ExportHour, Vec<PartRef>)> {
    plan_export_impl(live, state, now_ms, policy, false)
}

/// Export reconciliation includes sealed hours emptied by erasure/retention.
/// Optional runner callers use a separate target work directory and durable APIs.
pub fn plan_export_reconciled(live: &[PartRef], state: &ExportState, now_ms: i64, policy: &MergePolicy) -> Vec<(ExportHour, Vec<PartRef>)> {
    plan_export_impl(live, state, now_ms, policy, true)
}

fn plan_export_impl(live: &[PartRef], state: &ExportState, now_ms: i64, policy: &MergePolicy, include_erased: bool) -> Vec<(ExportHour, Vec<PartRef>)> {
    let mut by_hour: BTreeMap<i32, Vec<&PartRef>> = BTreeMap::new();
    for part in live {
        match part.level {
            Level::Day => {
                for hour in part.event_hour..part.event_hour + 24 {
                    by_hour.entry(hour).or_default().push(part);
                }
            }
            _ => by_hour.entry(part.event_hour).or_default().push(part),
        }
    }
    // Empty hours still need an overwrite after erasure or retention.
    if include_erased {
        for hour in state.exported.keys() {
            by_hour.entry(*hour).or_default();
        }
    }
    let mut out = Vec::new();
    for (hour, parts) in by_hour {
        let sealed = now_ms >= (i64::from(hour) + 1) * (HOUR_US / 1_000) + policy.hour_seal_ms;
        // Final = only H/D parts (L0/M means a merge is still due).
        if !sealed || parts.iter().any(|p| matches!(p.level, Level::L0 | Level::Minute)) {
            continue;
        }
        // A day part only exports hours it actually covers.
        let parts = parts
            .into_iter()
            .filter(|p| p.level != Level::Day || (p.min_time_us / HOUR_US <= i64::from(hour) && i64::from(hour) <= p.max_time_us / HOUR_US))
            .collect::<Vec<_>>();
        if parts.is_empty() && !include_erased { continue; }
        let mut ids = parts.iter().map(|p| p.part_id.to_string()).collect::<Vec<_>>();
        ids.sort();
        if state.exported.get(&hour) == Some(&ids) {
            continue;
        }
        out.push((ExportHour { event_hour: hour, parts: ids }, parts.into_iter().cloned().collect()));
    }
    out
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5450: disk usage for the volumes nano writes to.
//!
//! One report, three sources, warn at 80 % and critical at 90 %:
//!
//! * **ClickHouse**: every Local disk in `system.disks`. On a cluster the read
//!   fans out with `clusterAllReplicas` so each node's disk is reported, not
//!   only the node the load balancer picked. On single-host Compose this disk
//!   is the Docker filesystem, so it also covers PostgreSQL, the Vector
//!   buffers, images and backups that live on it.
//! * **PostgreSQL**: database size plus WAL size over SQL. PostgreSQL has no
//!   SQL function for filesystem free space, so a usage fraction needs one of:
//!   `NANO_POSTGRES_SHARES_CLICKHOUSE_DISK=true` (single-host Compose: both
//!   are named volumes on the Docker filesystem, so the ClickHouse disk's usage
//!   is PostgreSQL's too) or `NANO_POSTGRES_VOLUME_SIZE` (Helm bundled
//!   PostgreSQL: the PVC size, so usage is database + WAL over the volume).
//!   Without either (external or multi-host PostgreSQL) the sizes are reported
//!   with level `unknown`; node-exporter or the provider's own alerts cover it.
//! * **Vector disk buffers**: `buffer_size_bytes` against
//!   `buffer_max_size_bytes` from Vector's Prometheus exporter, per Vector
//!   instance (every pod on Helm, through the metrics peers Service). A full
//!   buffer stops its pipeline from accepting events. The nano Vector build
//!   has no `host_metrics` source, so the free space of the Vector data volume
//!   itself is not visible here: on single-host Compose it is the ClickHouse
//!   disk above; dedicated ingest hosts rely on node-exporter.
//!
//! [`DiskHealthReport`] backs the `disk` section of `/health/detailed`, the
//! SIEM Health findings and the health scheduler's admin notifications.

use std::time::Duration;

use chrono::{DateTime, Utc};
use clickhouse::Client as ClickHouseClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// Usage at or above this fraction is a warning.
pub const DISK_WARN_FRACTION: f64 = 0.80;
/// Usage at or above this fraction is critical.
pub const DISK_CRITICAL_FRACTION: f64 = 0.90;
/// Usage at or above this fraction (under 5 % free) is imminent: the banner
/// turns red and cannot be dismissed, and notifications repeat hourly.
pub const DISK_IMMINENT_FRACTION: f64 = 0.95;
/// A forecast of fewer hours than this until full escalates a volume to
/// critical even below [`DISK_CRITICAL_FRACTION`].
pub const FORECAST_CRITICAL_HOURS: f64 = 24.0;
/// Growth is fitted over the samples of this window.
pub const FORECAST_WINDOW: chrono::Duration = chrono::Duration::hours(6);
/// Samples older than this are pruned.
pub const SAMPLE_RETENTION: chrono::Duration = chrono::Duration::hours(24);
/// A forecast needs at least this many samples spanning at least
/// [`FORECAST_MIN_SPAN`]; fewer gives no forecast rather than a noisy one.
pub const FORECAST_MIN_SAMPLES: usize = 3;
pub const FORECAST_MIN_SPAN: chrono::Duration = chrono::Duration::minutes(30);
/// NAN-5450 review: slack above the evictor's high watermark before the
/// ClickHouse disk warns. The evictor checks every minute and drops down to
/// its low watermark, so a healthy capped install reads anywhere in
/// [low, high + a little]; only a reading clearly above the high watermark
/// means the evictor is not keeping up.
pub const EVICTOR_SLACK: f64 = 0.03;

/// The disk-pressure evictor's band on the ClickHouse disk (its high
/// watermark and the ingest-pause threshold), from the same environment the
/// evictor reads (`DISK_PRESSURE_HIGH_WATERMARK`, `DISK_PRESSURE_PAUSE_THRESHOLD`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EvictorBand {
    pub high: f64,
    pub pause: f64,
}

impl EvictorBand {
    pub const DEFAULT: Self = Self { high: 0.80, pause: 0.92 };

    pub fn from_env() -> Self {
        let c = crate::settings::disk_pressure::DiskPressureConfig::default();
        Self { high: c.high_watermark, pause: c.pause_threshold }
    }

    /// The ClickHouse disk warns only above the evictor's high watermark
    /// (plus [`EVICTOR_SLACK`]): below it, eviction is doing its job and a
    /// capped install cycling between the low and high watermarks must not
    /// raise the same warning every cycle. Never above the critical level.
    pub fn clickhouse_warn_fraction(&self) -> f64 {
        (self.high.max(DISK_WARN_FRACTION) + EVICTOR_SLACK).min(DISK_CRITICAL_FRACTION)
    }
}

/// The used fraction at which `component`'s volume warns.
pub fn warn_fraction_for(component: DiskComponent, band: &EvictorBand) -> f64 {
    match component {
        DiskComponent::Clickhouse => band.clickhouse_warn_fraction(),
        _ => DISK_WARN_FRACTION,
    }
}

/// The disk-full recovery runbook (docs site path).
pub const DISK_FULL_RUNBOOK: &str = "docs/administration/disk-full-recovery.md";

/// Per-source bound. `/health/detailed` waits for all three in parallel.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Per Vector instance. One exporter page is about 2 MB.
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(4);
/// Never scrape more Vector pods than this in one report.
const MAX_VECTOR_PEERS: usize = 32;

const DEFAULT_VECTOR_METRICS_URL: &str = "http://vector:9598/metrics";
/// Same variable generation delivery reads (Helm: a headless Service with
/// every Vector pod).
const METRICS_PEERS_ENV: &str = "NANO_VECTOR_ACK_METRICS_PEERS";

/// Disk usage level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiskLevel {
    /// Below the warning threshold.
    Ok,
    /// Not measurable (probe failed or no capacity known).
    Unknown,
    /// At or above 80 %.
    Warning,
    /// At or above 90 %, or forecast to fill within 24 hours.
    Critical,
    /// At or above 95 % (under 5 % free): about to fill.
    Imminent,
}

impl DiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            DiskLevel::Ok => "ok",
            DiskLevel::Unknown => "unknown",
            DiskLevel::Warning => "warning",
            DiskLevel::Critical => "critical",
            DiskLevel::Imminent => "imminent",
        }
    }
}

/// Classify a used fraction (0.0 to 1.0).
pub fn classify_usage(fraction: f64) -> DiskLevel {
    classify_usage_from(fraction, DISK_WARN_FRACTION)
}

/// [`classify_usage`] with the warning threshold `warn` (the ClickHouse disk
/// uses [`EvictorBand::clickhouse_warn_fraction`]).
pub fn classify_usage_from(fraction: f64, warn: f64) -> DiskLevel {
    if !fraction.is_finite() {
        DiskLevel::Unknown
    } else if fraction >= DISK_IMMINENT_FRACTION {
        DiskLevel::Imminent
    } else if fraction >= DISK_CRITICAL_FRACTION {
        DiskLevel::Critical
    } else if fraction >= warn {
        DiskLevel::Warning
    } else {
        DiskLevel::Ok
    }
}

/// Which nano component a volume belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiskComponent {
    Clickhouse,
    Postgres,
    VectorBuffer,
}

impl DiskComponent {
    pub fn as_str(self) -> &'static str {
        match self {
            DiskComponent::Clickhouse => "clickhouse",
            DiskComponent::Postgres => "postgres",
            DiskComponent::VectorBuffer => "vector_buffer",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            DiskComponent::Clickhouse => "ClickHouse disk",
            DiskComponent::Postgres => "PostgreSQL volume",
            DiskComponent::VectorBuffer => "Vector disk buffers",
        }
    }
}

/// One measured volume.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DiskVolumeHealth {
    pub component: DiskComponent,
    /// ClickHouse node, Vector instance (`host` label), or `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// ClickHouse disk name, `database`, or `disk_buffers`.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_bytes: Option<u64>,
    /// Used fraction the level is based on. For Vector, the fullest buffer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_fraction: Option<f64>,
    pub level: DiskLevel,
    pub detail: String,
    /// NAN-5450: linear growth over the recent samples, and when it fills.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forecast: Option<DiskForecast>,
    /// The key of the volume whose filesystem this one shares (single-host
    /// PostgreSQL on the ClickHouse disk). Alerts list the disk once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<String>,
}

/// NAN-5450: the growth forecast of one volume.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DiskForecast {
    /// Least-squares growth of used bytes per hour over the samples of the
    /// last 6 hours. Negative when the volume is shrinking.
    pub growth_bytes_per_hour: f64,
    /// Hours until the volume is "full" at that rate. `None` when it is not
    /// growing. For the ClickHouse disk (and a volume on its filesystem)
    /// "full" is the ingest-pause threshold ([`Self::full_fraction`]), not
    /// 100 %.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hours_to_full: Option<f64>,
    /// The used fraction `hours_to_full` counts to: the evictor's pause
    /// threshold (0.92 by default) on the ClickHouse disk, 1.0 elsewhere.
    #[serde(default = "full_fraction_default")]
    pub full_fraction: f64,
    /// Samples the fit used, and the hours they span.
    pub samples: usize,
    pub span_hours: f64,
    /// The forecast (fewer than 24 hours to full) raised the level to
    /// critical below 90 %. Only a volume above its high watermark (the
    /// evictor's on ClickHouse, 80 % elsewhere) is escalated.
    pub escalated: bool,
}

impl DiskVolumeHealth {
    /// Free fraction (0.0 to 1.0) when the usage is known.
    pub fn free_fraction(&self) -> Option<f64> {
        self.usage_fraction.map(|u| (1.0 - u).clamp(0.0, 1.0))
    }

    /// Stable identity for notifications and system health events.
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.component.as_str(),
            self.host.as_deref().unwrap_or("-"),
            self.name
        )
    }

    /// `ClickHouse disk default on ch-0`.
    pub fn display_name(&self) -> String {
        let mut s = format!("{} {}", self.component.label(), self.name);
        if let Some(host) = &self.host {
            s.push_str(" on ");
            s.push_str(host);
        }
        s
    }
}

/// The `disk` section of `/health/detailed` and SIEM Health.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DiskHealthReport {
    /// Worst level over the measured volumes; `unknown` only when none could
    /// be measured.
    pub status: DiskLevel,
    pub warn_fraction: f64,
    pub critical_fraction: f64,
    /// NAN-5450: 95 %: the banner turns red, notifications repeat hourly.
    #[serde(default = "default_imminent_fraction")]
    pub imminent_fraction: f64,
    /// NAN-5450: fewer forecast hours than this escalate to critical.
    #[serde(default = "default_forecast_critical_hours")]
    pub forecast_critical_hours: f64,
    pub volumes: Vec<DiskVolumeHealth>,
    /// What could not be measured, and why.
    pub notes: Vec<String>,
    pub checked_at: DateTime<Utc>,
    /// NAN-5567: Vector sinks holding batches ClickHouse permanently rejected
    /// in their dead-letter store (Vector `0.61.0-nano.13` and later).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vector_dead_letters: Vec<VectorDeadLetter>,
}

impl DiskHealthReport {
    pub fn new(volumes: Vec<DiskVolumeHealth>, notes: Vec<String>) -> Self {
        Self {
            status: overall_level(&volumes),
            warn_fraction: DISK_WARN_FRACTION,
            critical_fraction: DISK_CRITICAL_FRACTION,
            imminent_fraction: DISK_IMMINENT_FRACTION,
            forecast_critical_hours: FORECAST_CRITICAL_HOURS,
            volumes,
            notes,
            checked_at: Utc::now(),
            vector_dead_letters: Vec::new(),
        }
    }

    /// Volumes at warning or worse.
    pub fn alarming(&self) -> impl Iterator<Item = &DiskVolumeHealth> {
        self.volumes.iter().filter(|v| v.level >= DiskLevel::Warning)
    }

    /// Alarming volumes, each underlying disk once (a volume that shares
    /// another's filesystem is left out). Worst first.
    pub fn alarming_disks(&self) -> Vec<&DiskVolumeHealth> {
        let mut v: Vec<&DiskVolumeHealth> = self.alarming().filter(|v| v.shared_with.is_none()).collect();
        v.sort_by(|a, b| {
            b.level.cmp(&a.level).then_with(|| {
                let h = |x: &DiskVolumeHealth| x.forecast.as_ref().and_then(|f| f.hours_to_full).unwrap_or(f64::INFINITY);
                h(a).partial_cmp(&h(b)).unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        v
    }
}

fn full_fraction_default() -> f64 {
    1.0
}

fn default_imminent_fraction() -> f64 {
    DISK_IMMINENT_FRACTION
}

fn default_forecast_critical_hours() -> f64 {
    FORECAST_CRITICAL_HOURS
}

// ---------------------------------------------------------------------------
// Forecast (NAN-5450)
// ---------------------------------------------------------------------------

/// Least-squares slope of `used` bytes over time, in bytes per hour, from
/// `(when, used)` samples. `None` with fewer than [`FORECAST_MIN_SAMPLES`]
/// samples, a span under [`FORECAST_MIN_SPAN`], or a degenerate fit.
pub fn growth_bytes_per_hour(samples: &[(DateTime<Utc>, u64)]) -> Option<(f64, f64)> {
    if samples.len() < FORECAST_MIN_SAMPLES {
        return None;
    }
    let t0 = samples.iter().map(|(t, _)| *t).min()?;
    let t1 = samples.iter().map(|(t, _)| *t).max()?;
    if t1 - t0 < FORECAST_MIN_SPAN {
        return None;
    }
    let pts: Vec<(f64, f64)> = samples
        .iter()
        .map(|(t, u)| ((*t - t0).num_milliseconds() as f64 / 3_600_000.0, *u as f64))
        .collect();
    let n = pts.len() as f64;
    let mx = pts.iter().map(|p| p.0).sum::<f64>() / n;
    let my = pts.iter().map(|p| p.1).sum::<f64>() / n;
    let sxx: f64 = pts.iter().map(|p| (p.0 - mx).powi(2)).sum();
    if sxx <= 0.0 {
        return None;
    }
    let sxy: f64 = pts.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
    let slope = sxy / sxx;
    slope.is_finite().then(|| (slope, (t1 - t0).num_milliseconds() as f64 / 3_600_000.0))
}

/// Hours until `free` bytes are used at `growth` bytes per hour; `None` when
/// the volume is not growing (under 1 MiB per hour counts as flat).
pub fn hours_to_full(free: u64, growth_per_hour: f64) -> Option<f64> {
    (growth_per_hour >= 1_048_576.0).then(|| free as f64 / growth_per_hour)
}

/// Attach a forecast to `volume` from its samples (oldest first, the current
/// reading included by the caller) and escalate a growing volume that fills
/// within [`FORECAST_CRITICAL_HOURS`] to critical.
///
/// NAN-5450 review: on the ClickHouse disk "full" is the evictor's pause
/// threshold (ingest stops there, well before 100 %). A forecast escalates
/// only a volume already above its warning level's floor (the evictor's high
/// watermark on ClickHouse, 80 % elsewhere): a replay burst on a disk at 60 %
/// is what eviction handles, and must not page anyone.
pub fn apply_forecast(volume: &mut DiskVolumeHealth, samples: &[(DateTime<Utc>, u64)], band: &EvictorBand) {
    let Some((growth, span_hours)) = growth_bytes_per_hour(samples) else {
        return;
    };
    let full_fraction = match volume.component {
        DiskComponent::Clickhouse => band.pause.clamp(0.0, 1.0),
        _ => 1.0,
    };
    // Bytes left until "full". To 100 %: the reported free bytes, as before
    // (a PostgreSQL volume on the ClickHouse filesystem reports only its own
    // used bytes, so total - used would be wrong). To the pause threshold:
    // from the disk's total and used bytes.
    let free = match (full_fraction >= 1.0, volume.free_bytes, volume.total_bytes, volume.used_bytes) {
        (true, Some(f), _, _) => f,
        (_, _, Some(t), Some(u)) => ((t as f64 * full_fraction) - u as f64).max(0.0) as u64,
        _ => return,
    };
    let hours = hours_to_full(free, growth);
    let escalate_floor = match volume.component {
        DiskComponent::Clickhouse => band.high,
        _ => DISK_WARN_FRACTION,
    };
    let escalate = matches!(volume.level, DiskLevel::Ok | DiskLevel::Warning)
        && volume.usage_fraction.is_some_and(|u| u >= escalate_floor)
        && hours.is_some_and(|h| h < FORECAST_CRITICAL_HOURS);
    if escalate {
        volume.level = DiskLevel::Critical;
    }
    if let Some(h) = hours {
        if full_fraction < 1.0 {
            volume.detail.push_str(&format!(
                "; ingestion pauses at {:.0}% in about {}",
                full_fraction * 100.0,
                human_hours(h)
            ));
        } else {
            volume.detail.push_str(&format!("; full in about {}", human_hours(h)));
        }
    }
    volume.forecast = Some(DiskForecast {
        growth_bytes_per_hour: growth,
        hours_to_full: hours,
        full_fraction,
        samples: samples.len(),
        span_hours,
        escalated: escalate,
    });
}

/// `45 minutes`, `7 hours`, `3 days`.
pub fn human_hours(h: f64) -> String {
    if h < 1.0 {
        format!("{} minutes", (h * 60.0).round().max(1.0) as u64)
    } else if h < 48.0 {
        let n = h.round() as u64;
        format!("{n} hour{}", if n == 1 { "" } else { "s" })
    } else {
        format!("{} days", (h / 24.0).round() as u64)
    }
}

/// Usage samples (`disk_usage_samples`, migration 389) of the last
/// [`FORECAST_WINDOW`], per volume key, oldest first. Empty on error: no
/// forecast is better than a failed health report.
pub async fn load_samples(pool: &PgPool) -> std::collections::HashMap<String, Vec<(DateTime<Utc>, u64)>> {
    let since = Utc::now() - FORECAST_WINDOW;
    let rows = sqlx::query_as::<_, (String, DateTime<Utc>, i64)>(
        "SELECT volume_key, sampled_at, used_bytes FROM disk_usage_samples \
         WHERE sampled_at >= $1 ORDER BY volume_key, sampled_at",
    )
    .bind(since)
    .fetch_all(pool)
    .await;
    let mut out: std::collections::HashMap<String, Vec<(DateTime<Utc>, u64)>> = std::collections::HashMap::new();
    match rows {
        Ok(rows) => {
            for (key, at, used) in rows {
                out.entry(key).or_default().push((at, used.max(0) as u64));
            }
        }
        Err(e) => tracing::debug!(error = %e, "disk usage samples unavailable; no forecast"),
    }
    out
}

/// Record one sample per measured volume (health scheduler, jobs leader) and
/// prune samples older than [`SAMPLE_RETENTION`].
pub async fn record_samples(pool: &PgPool, report: &DiskHealthReport) -> Result<(), sqlx::Error> {
    let now = report.checked_at;
    for v in report.volumes.iter().filter(|v| v.shared_with.is_none()) {
        let (Some(used), Some(total)) = (v.used_bytes, v.total_bytes) else {
            continue;
        };
        sqlx::query(
            "INSERT INTO disk_usage_samples (volume_key, sampled_at, used_bytes, total_bytes) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (volume_key, sampled_at) DO NOTHING",
        )
        .bind(v.key())
        .bind(now)
        .bind(i64::try_from(used).unwrap_or(i64::MAX))
        .bind(i64::try_from(total).unwrap_or(i64::MAX))
        .execute(pool)
        .await?;
    }
    sqlx::query("DELETE FROM disk_usage_samples WHERE sampled_at < $1")
        .bind(now - SAMPLE_RETENTION)
        .execute(pool)
        .await?;
    Ok(())
}

/// Forecast every volume from the stored samples plus the current reading.
pub fn apply_forecasts(
    report: &mut DiskHealthReport,
    samples: &std::collections::HashMap<String, Vec<(DateTime<Utc>, u64)>>,
    band: &EvictorBand,
) {
    let now = report.checked_at;
    for v in report.volumes.iter_mut() {
        let Some(used) = v.used_bytes else { continue };
        let mut series = samples.get(&v.key()).cloned().unwrap_or_default();
        series.retain(|(t, _)| *t < now);
        series.push((now, used));
        apply_forecast(v, &series, band);
    }
    // A volume sharing another's filesystem takes that one's level and forecast.
    let by_key: std::collections::HashMap<String, (DiskLevel, Option<DiskForecast>)> = report
        .volumes
        .iter()
        .map(|v| (v.key(), (v.level, v.forecast.clone())))
        .collect();
    for v in report.volumes.iter_mut() {
        if let Some((level, forecast)) = v.shared_with.as_ref().and_then(|k| by_key.get(k)) {
            v.level = *level;
            v.forecast = forecast.clone();
        }
    }
    report.status = overall_level(&report.volumes);
}

/// Worst measured level. Unknown volumes don't raise it; all unknown (or none)
/// is unknown.
pub fn overall_level(volumes: &[DiskVolumeHealth]) -> DiskLevel {
    volumes
        .iter()
        .map(|v| v.level)
        .filter(|l| *l != DiskLevel::Unknown)
        .max()
        .unwrap_or(DiskLevel::Unknown)
}

fn fraction(used: u64, total: u64) -> Option<f64> {
    (total > 0).then(|| used as f64 / total as f64)
}

fn pct(f: f64) -> String {
    format!("{:.1}%", f * 100.0)
}

// ---------------------------------------------------------------------------
// ClickHouse
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, clickhouse::Row, Deserialize)]
pub struct ClickHouseDiskRow {
    pub host: String,
    pub name: String,
    pub path: String,
    pub total_space: u64,
    pub free_space: u64,
}

/// `system.disks`, or every node's on a cluster.
pub fn clickhouse_disks_sql(cluster: Option<&str>) -> String {
    let src = match cluster {
        Some(c) => format!(
            "clusterAllReplicas('{}', system.disks)",
            crate::sql_hygiene::escape_sql_string(c)
        ),
        None => "system.disks".to_string(),
    };
    // Object-storage disks report u64::MAX capacity; only Local disks fill.
    format!(
        "SELECT hostName() AS host, name, path, total_space, free_space FROM {src} \
         WHERE type = 'Local' AND total_space > 0 ORDER BY host, name"
    )
}

/// One volume per ClickHouse Local disk. `total_space` already excludes
/// `keep_free_space_bytes`, matching the disk-pressure service.
///
/// NAN-5450 review: the warning level sits above the evictor's high
/// watermark ([`EvictorBand::clickhouse_warn_fraction`]).
pub fn clickhouse_volumes_from_rows(
    rows: &[ClickHouseDiskRow],
    clustered: bool,
    band: &EvictorBand,
) -> Vec<DiskVolumeHealth> {
    let warn = band.clickhouse_warn_fraction();
    rows.iter()
        .map(|r| {
            let used = r.total_space.saturating_sub(r.free_space);
            let usage = fraction(used, r.total_space);
            let level = usage.map(|u| classify_usage_from(u, warn)).unwrap_or(DiskLevel::Unknown);
            DiskVolumeHealth {
                component: DiskComponent::Clickhouse,
                host: clustered.then(|| r.host.clone()),
                name: r.name.clone(),
                path: Some(r.path.clone()),
                total_bytes: Some(r.total_space),
                used_bytes: Some(used),
                free_bytes: Some(r.free_space),
                usage_fraction: usage,
                level,
                detail: match usage {
                    Some(u) => format!("{} used", pct(u)),
                    None => "no capacity reported".to_string(),
                },
                forecast: None,
                shared_with: None,
            }
        })
        .collect()
}

async fn read_clickhouse_disks(
    client: &ClickHouseClient,
    cluster: Option<&str>,
    notes: &mut Vec<String>,
) -> Vec<DiskVolumeHealth> {
    if let Some(c) = cluster {
        // A hard-down replica must not hide every other node's disk (the
        // disk-pressure service reads with the same setting, NAN-5215).
        let fanout = client.clone().with_setting("skip_unavailable_shards", "1");
        match tokio::time::timeout(
            PROBE_TIMEOUT,
            fanout.query(&clickhouse_disks_sql(Some(c))).fetch_all::<ClickHouseDiskRow>(),
        )
        .await
        {
            Ok(Ok(rows)) if !rows.is_empty() => return clickhouse_volumes_from_rows(&rows, true, &EvictorBand::from_env()),
            Ok(Ok(_)) => notes.push("No ClickHouse node reported a Local disk across the cluster.".into()),
            Ok(Err(e)) => notes.push(format!(
                "Could not read every ClickHouse node's disks ({e}); showing the connected node only."
            )),
            Err(_) => notes.push(
                "Reading every ClickHouse node's disks timed out; showing the connected node only.".into(),
            ),
        }
    }
    match tokio::time::timeout(
        PROBE_TIMEOUT,
        client.query(&clickhouse_disks_sql(None)).fetch_all::<ClickHouseDiskRow>(),
    )
    .await
    {
        Ok(Ok(rows)) => clickhouse_volumes_from_rows(&rows, cluster.is_some(), &EvictorBand::from_env()),
        Ok(Err(e)) => {
            notes.push(format!("Could not read ClickHouse disks: {e}"));
            Vec::new()
        }
        Err(_) => {
            notes.push("Reading ClickHouse disks timed out.".into());
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL
// ---------------------------------------------------------------------------

/// How the PostgreSQL volume's capacity is known.
#[derive(Debug, Clone, PartialEq)]
pub enum PostgresCapacity {
    /// Same filesystem as the (single-host) ClickHouse data disk.
    SharesClickHouseDisk,
    /// The volume size in bytes (Helm bundled PostgreSQL PVC).
    VolumeBytes(u64),
    /// Not known (external or multi-host PostgreSQL).
    Unknown,
}

impl PostgresCapacity {
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Self {
        if get("NANO_POSTGRES_SHARES_CLICKHOUSE_DISK")
            .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        {
            return Self::SharesClickHouseDisk;
        }
        match get("NANO_POSTGRES_VOLUME_SIZE").as_deref().and_then(parse_quantity) {
            Some(bytes) if bytes > 0 => Self::VolumeBytes(bytes),
            _ => Self::Unknown,
        }
    }
}

/// Parse a byte count or a Kubernetes quantity (`20Gi`, `500G`, `1.5Ti`).
pub fn parse_quantity(s: &str) -> Option<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let value: f64 = num.parse().ok()?;
    let mult: f64 = match unit.trim() {
        "" => 1.0,
        "k" | "K" => 1e3,
        "M" => 1e6,
        "G" => 1e9,
        "T" => 1e12,
        "P" => 1e15,
        "Ki" => 1024.0,
        "Mi" => 1024f64.powi(2),
        "Gi" => 1024f64.powi(3),
        "Ti" => 1024f64.powi(4),
        "Pi" => 1024f64.powi(5),
        _ => return None,
    };
    let bytes = value * mult;
    (bytes.is_finite() && bytes >= 0.0).then_some(bytes as u64)
}

/// The PostgreSQL volume from its measured sizes and the capacity source.
/// `clickhouse_local` is the ClickHouse data disk on this host (single-host),
/// used when PostgreSQL shares it.
pub fn postgres_volume(
    database_bytes: u64,
    wal_bytes: Option<u64>,
    capacity: &PostgresCapacity,
    clickhouse_local: Option<&DiskVolumeHealth>,
) -> DiskVolumeHealth {
    let own = database_bytes + wal_bytes.unwrap_or(0);
    let sizes = match wal_bytes {
        Some(w) => format!("database {} + WAL {}", human_bytes(database_bytes), human_bytes(w)),
        None => format!("database {} (WAL size not readable)", human_bytes(database_bytes)),
    };
    let mut v = DiskVolumeHealth {
        component: DiskComponent::Postgres,
        host: None,
        name: "database".into(),
        path: None,
        total_bytes: None,
        used_bytes: Some(own),
        free_bytes: None,
        usage_fraction: None,
        level: DiskLevel::Unknown,
        detail: String::new(),
        forecast: None,
        shared_with: None,
    };
    match (capacity, clickhouse_local) {
        (PostgresCapacity::SharesClickHouseDisk, Some(ch)) => {
            v.shared_with = Some(ch.key());
            v.total_bytes = ch.total_bytes;
            v.free_bytes = ch.free_bytes;
            v.usage_fraction = ch.usage_fraction;
            v.level = ch.level;
            v.detail = format!(
                "{sizes}; shares the ClickHouse filesystem, usage is that filesystem's ({})",
                ch.usage_fraction.map(pct).unwrap_or_else(|| "unknown".into())
            );
        }
        (PostgresCapacity::SharesClickHouseDisk, None) => {
            v.detail = format!("{sizes}; the shared ClickHouse filesystem could not be read");
        }
        (PostgresCapacity::VolumeBytes(total), _) => {
            let usage = fraction(own, *total);
            v.total_bytes = Some(*total);
            v.free_bytes = Some(total.saturating_sub(own));
            v.usage_fraction = usage;
            v.level = usage.map(classify_usage).unwrap_or(DiskLevel::Unknown);
            v.detail = format!(
                "{sizes} of a {} volume (estimate: filesystem overhead and other files are not counted)",
                human_bytes(*total)
            );
        }
        (PostgresCapacity::Unknown, _) => {
            v.detail = format!(
                "{sizes}; free space is not visible over SQL. Set NANO_POSTGRES_VOLUME_SIZE, or monitor the \
                 PostgreSQL host's disk (node-exporter, provider alerts)"
            );
        }
    }
    v
}

async fn read_postgres_sizes(pool: &PgPool, notes: &mut Vec<String>) -> Option<(u64, Option<u64>)> {
    let db = match tokio::time::timeout(
        PROBE_TIMEOUT,
        sqlx::query_scalar::<_, i64>("SELECT pg_database_size(current_database())").fetch_one(pool),
    )
    .await
    {
        Ok(Ok(n)) => n.max(0) as u64,
        Ok(Err(e)) => {
            notes.push(format!("Could not read the PostgreSQL database size: {e}"));
            return None;
        }
        Err(_) => {
            notes.push("Reading the PostgreSQL database size timed out.".into());
            return None;
        }
    };
    // pg_ls_waldir needs superuser or pg_monitor; a managed database often
    // refuses it. The database size alone is still reported.
    let wal = match tokio::time::timeout(
        PROBE_TIMEOUT,
        sqlx::query_scalar::<_, i64>("SELECT COALESCE(sum(size), 0)::bigint FROM pg_ls_waldir()")
            .fetch_one(pool),
    )
    .await
    {
        Ok(Ok(n)) => Some(n.max(0) as u64),
        _ => None,
    };
    Some((db, wal))
}

// ---------------------------------------------------------------------------
// Vector
// ---------------------------------------------------------------------------

/// One disk buffer read from a Vector exporter page.
#[derive(Debug, Clone, PartialEq)]
pub struct VectorBufferSample {
    pub host: Option<String>,
    pub buffer_id: String,
    pub size_bytes: u64,
    pub max_bytes: Option<u64>,
}

/// Label value from a Prometheus label set body (`a="x",b="y"`).
fn label<'a>(labels: &'a str, name: &str) -> Option<&'a str> {
    let mut rest = labels;
    while !rest.is_empty() {
        let eq = rest.find('=')?;
        let key = rest[..eq].trim().trim_start_matches(',').trim();
        let after = rest[eq + 1..].strip_prefix('"')?;
        // Values are escaped with backslashes; find the closing quote.
        let mut end = None;
        let mut escaped = false;
        for (i, c) in after.char_indices() {
            match c {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => {
                    end = Some(i);
                    break;
                }
                _ => escaped = false,
            }
        }
        let end = end?;
        if key == name {
            return Some(&after[..end]);
        }
        rest = &after[end + 1..];
    }
    None
}

/// Disk buffers on one Vector exporter page. Accepts the exporter's
/// `nanosiem_vector_` namespace and Vector's older `buffer_byte_size` /
/// `buffer_max_byte_size` names.
pub fn parse_vector_buffers(metrics: &str) -> Vec<VectorBufferSample> {
    use std::collections::BTreeMap;
    let mut size: BTreeMap<(Option<String>, String), u64> = BTreeMap::new();
    let mut max: BTreeMap<(Option<String>, String), u64> = BTreeMap::new();
    for line in metrics.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some(brace) = line.find('{') else { continue };
        let name = &line[..brace];
        let is_size = matches!(
            name,
            "nanosiem_vector_buffer_size_bytes" | "nanosiem_vector_buffer_byte_size"
        );
        let is_max = matches!(
            name,
            "nanosiem_vector_buffer_max_size_bytes" | "nanosiem_vector_buffer_max_byte_size"
        );
        if !is_size && !is_max {
            continue;
        }
        let Some(close) = line.rfind('}') else { continue };
        let labels = &line[brace + 1..close];
        if label(labels, "buffer_type") != Some("disk") {
            continue;
        }
        let Some(id) = label(labels, "buffer_id").or_else(|| label(labels, "component_id")) else {
            continue;
        };
        let Some(value) = line[close + 1..]
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
        else {
            continue;
        };
        let key = (label(labels, "host").map(str::to_string), id.to_string());
        // Both metric spellings may be present; keep the larger reading.
        let map = if is_size { &mut size } else { &mut max };
        let slot = map.entry(key).or_insert(0);
        *slot = (*slot).max(value as u64);
    }
    size.into_iter()
        .map(|(key, size_bytes)| VectorBufferSample {
            max_bytes: max.get(&key).copied().filter(|m| *m > 0),
            host: key.0,
            buffer_id: key.1,
            size_bytes,
        })
        .collect()
}

/// NAN-5567: one Vector sink's dead-letter store, from its exporter page.
/// Vector (`0.61.0-nano.13`+) writes a batch ClickHouse permanently rejects
/// (a 4xx, or a non-retryable code such as 117/53) to
/// `<data_dir>/dead_letter/<sink>/` instead of dropping it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VectorDeadLetter {
    pub host: Option<String>,
    pub component_id: String,
    /// Events written to the store since that Vector started.
    pub dead_lettered_events: u64,
    /// Bytes the store holds now (includes batches from earlier runs).
    pub held_bytes: u64,
    /// Dead-letter events discarded since that Vector started: evicted
    /// because the store was full, too large for it, or a failed write.
    pub discarded_events: u64,
}

impl VectorDeadLetter {
    /// Anything to act on: batches held now, or dead-letter events lost
    /// since Vector started. Events stored and since replayed and deleted
    /// (held bytes back to 0) are resolved, even though the counter only
    /// resets when Vector restarts.
    pub fn is_active(&self) -> bool {
        self.held_bytes > 0 || self.discarded_events > 0
    }
}

/// Dead-letter stores on one Vector exporter page (NAN-5567). Only sinks
/// with something to report are returned.
pub fn parse_vector_dead_letters(metrics: &str) -> Vec<VectorDeadLetter> {
    use std::collections::BTreeMap;
    let mut by_sink: BTreeMap<(Option<String>, String), VectorDeadLetter> = BTreeMap::new();
    for line in metrics.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some(brace) = line.find('{') else { continue };
        let name = &line[..brace];
        let field = match name {
            "nanosiem_vector_component_dead_lettered_events_total" => 0,
            "nanosiem_vector_component_dead_letter_bytes" => 1,
            "nanosiem_vector_component_dead_letter_discarded_events_total" => 2,
            _ => continue,
        };
        let Some(close) = line.rfind('}') else { continue };
        let labels = &line[brace + 1..close];
        let Some(id) = label(labels, "component_id") else { continue };
        let Some(value) = line[close + 1..]
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
        else {
            continue;
        };
        let host = label(labels, "host").map(str::to_string);
        let entry = by_sink.entry((host.clone(), id.to_string())).or_insert_with(|| VectorDeadLetter {
            host,
            component_id: id.to_string(),
            dead_lettered_events: 0,
            held_bytes: 0,
            discarded_events: 0,
        });
        let value = value as u64;
        match field {
            0 => entry.dead_lettered_events += value,
            1 => entry.held_bytes = entry.held_bytes.max(value),
            // One series per discard reason.
            _ => entry.discarded_events += value,
        }
    }
    by_sink.into_values().filter(VectorDeadLetter::is_active).collect()
}

/// One volume per Vector instance: totals over its disk buffers, level from
/// the fullest buffer (a full buffer blocks that pipeline even when the
/// others are empty).
pub fn vector_volumes(samples: &[VectorBufferSample], instance: &str) -> Vec<DiskVolumeHealth> {
    use std::collections::BTreeMap;
    let mut by_host: BTreeMap<Option<String>, Vec<&VectorBufferSample>> = BTreeMap::new();
    for s in samples {
        by_host.entry(s.host.clone()).or_default().push(s);
    }
    by_host
        .into_iter()
        .map(|(host, bufs)| {
            let used: u64 = bufs.iter().map(|b| b.size_bytes).sum();
            let total: u64 = bufs.iter().filter_map(|b| b.max_bytes).sum();
            let worst = bufs
                .iter()
                .filter_map(|b| b.max_bytes.map(|m| (b, b.size_bytes as f64 / m as f64)))
                .max_by(|a, b| a.1.total_cmp(&b.1));
            let (usage, level, detail) = match worst {
                Some((b, f)) => (
                    Some(f),
                    classify_usage(f),
                    format!(
                        "{} disk buffers hold {} of {}; fullest is {} at {}",
                        bufs.len(),
                        human_bytes(used),
                        human_bytes(total),
                        b.buffer_id,
                        pct(f)
                    ),
                ),
                None => (
                    None,
                    DiskLevel::Unknown,
                    format!("{} disk buffers hold {}; no max size reported", bufs.len(), human_bytes(used)),
                ),
            };
            DiskVolumeHealth {
                component: DiskComponent::VectorBuffer,
                host: Some(host.unwrap_or_else(|| instance.to_string())),
                name: "disk_buffers".into(),
                path: None,
                total_bytes: (total > 0).then_some(total),
                used_bytes: Some(used),
                free_bytes: (total > 0).then(|| total.saturating_sub(used)),
                usage_fraction: usage,
                level,
                detail,
                forecast: None,
                shared_with: None,
            }
        })
        .collect()
}

/// Where to scrape Vector: every pod behind the metrics peers Service (Helm),
/// else `VECTOR_METRICS_URL`, else the Compose default. `None` on a
/// role-split app host (`NANO_VECTOR_ON_INGEST_HOSTS`, or `INGEST_SERVICE_URL`
/// on the api), where Vector runs on the ingest hosts.
pub fn vector_scrape_plan(get: impl Fn(&str) -> Option<String>) -> Option<VectorScrape> {
    let nonempty = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    if let Some(peers) = nonempty(METRICS_PEERS_ENV) {
        return Some(VectorScrape::Peers(peers));
    }
    if let Some(url) = nonempty("VECTOR_METRICS_URL") {
        return Some(VectorScrape::Url(url));
    }
    // Role-split app hosts: Vector is on the ingest hosts.
    let on_ingest_hosts = nonempty("NANO_VECTOR_ON_INGEST_HOSTS")
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    if on_ingest_hosts || nonempty("INGEST_SERVICE_URL").is_some() {
        return None;
    }
    Some(VectorScrape::Url(DEFAULT_VECTOR_METRICS_URL.to_string()))
}

#[derive(Debug, Clone, PartialEq)]
pub enum VectorScrape {
    /// `host:port` resolving to every Vector pod.
    Peers(String),
    Url(String),
}

async fn scrape(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.text().await.map_err(|e| e.to_string())
}

async fn read_vector_buffers(notes: &mut Vec<String>) -> (Vec<DiskVolumeHealth>, Vec<VectorDeadLetter>) {
    let Some(plan) = vector_scrape_plan(|k| std::env::var(k).ok()) else {
        notes.push(
            "Vector runs on the ingest hosts; their disks are covered by the monitoring role's node-exporter \
             alerts, not by this check, and their dead-letter stores (/var/lib/vector/dead_letter) are not \
             read either."
                .into(),
        );
        return (Vec::new(), Vec::new());
    };
    let client = match reqwest::Client::builder().timeout(SCRAPE_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            notes.push(format!("Could not build the Vector metrics client: {e}"));
            return (Vec::new(), Vec::new());
        }
    };
    let urls: Vec<(String, String)> = match plan {
        VectorScrape::Url(url) => vec![(url.clone(), url)],
        VectorScrape::Peers(target) => {
            match tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(target.clone())).await {
                Ok(Ok(addrs)) => {
                    let mut seen: Vec<String> = addrs.map(|a| a.to_string()).collect();
                    seen.sort();
                    seen.dedup();
                    seen.truncate(MAX_VECTOR_PEERS);
                    seen.into_iter()
                        .map(|a| (a.clone(), format!("http://{a}/metrics")))
                        .collect()
                }
                Ok(Err(e)) => {
                    notes.push(format!("Could not resolve the Vector pods ({target}): {e}"));
                    Vec::new()
                }
                Err(_) => {
                    notes.push(format!("Resolving the Vector pods ({target}) timed out."));
                    Vec::new()
                }
            }
        }
    };
    let pages = futures::future::join_all(urls.iter().map(|(instance, url)| {
        let client = client.clone();
        async move { (instance.clone(), scrape(&client, url).await) }
    }))
    .await;
    let mut volumes = Vec::new();
    let mut dead_letters = Vec::new();
    for (instance, page) in pages {
        match page {
            Ok(text) => {
                // NAN-5567: a sink without a host label is named by the
                // instance it was scraped from.
                dead_letters.extend(parse_vector_dead_letters(&text).into_iter().map(|mut d| {
                    d.host.get_or_insert_with(|| instance.clone());
                    d
                }));
                let samples = parse_vector_buffers(&text);
                if samples.is_empty() {
                    notes.push(format!("Vector at {instance} reports no disk buffers."));
                }
                volumes.extend(vector_volumes(&samples, &instance));
            }
            Err(e) => notes.push(format!("Could not read Vector metrics at {instance}: {e}")),
        }
    }
    (volumes, dead_letters)
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/// Read every source. `cluster` is the ClickHouse cluster when clustered (the
/// client must then hold REMOTE, i.e. be the admin identity); a failed
/// fan-out falls back to the connected node with a note.
pub async fn collect_disk_health(
    pg: &PgPool,
    ch: &ClickHouseClient,
    cluster: Option<&str>,
) -> DiskHealthReport {
    let mut ch_notes = Vec::new();
    let mut pg_notes = Vec::new();
    let mut vec_notes = Vec::new();
    let (ch_volumes, pg_sizes, (vector, vector_dead_letters)) = tokio::join!(
        read_clickhouse_disks(ch, cluster, &mut ch_notes),
        read_postgres_sizes(pg, &mut pg_notes),
        read_vector_buffers(&mut vec_notes),
    );
    let capacity = PostgresCapacity::from_env(|k| std::env::var(k).ok());
    // Shared disk only applies to single-host, where there is one ClickHouse
    // node: the data disk is its largest Local disk (as disk pressure picks).
    let ch_local = (cluster.is_none())
        .then(|| ch_volumes.iter().max_by_key(|v| v.total_bytes.unwrap_or(0)))
        .flatten();
    let mut volumes = ch_volumes.clone();
    if let Some((db, wal)) = pg_sizes {
        volumes.push(postgres_volume(db, wal, &capacity, ch_local));
    }
    volumes.extend(vector);
    let mut notes = ch_notes;
    notes.extend(pg_notes);
    notes.extend(vec_notes);
    let mut report = DiskHealthReport::new(volumes, notes);
    report.vector_dead_letters = vector_dead_letters;
    // NAN-5450: growth forecast from the samples the health scheduler records.
    let samples = load_samples(pg).await;
    apply_forecasts(&mut report, &samples, &EvictorBand::from_env());
    report
}

/// [`collect_disk_health`] for a [`crate::db::DualPool`]: the admin client
/// when present (it reads every node on a cluster), else the runtime client
/// on the connected node only.
pub async fn collect_from_dual_pool(dual: &crate::db::DualPool) -> DiskHealthReport {
    let cluster = if dual.is_clustered() && dual.has_clickhouse_admin() {
        std::env::var("CLICKHOUSE_CLUSTER")
            .ok()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
    } else {
        None
    };
    let mut report = collect_disk_health(dual.postgres(), dual.clickhouse_admin(), cluster.as_deref()).await;
    if dual.is_clustered() && cluster.is_none() {
        report
            .notes
            .push("No ClickHouse admin identity: only the connected ClickHouse node's disks are shown.".into());
    }
    report
}

/// How long `/health/detailed` reuses a report. Disks don't fill in seconds,
/// and the Vector scrape is about 2 MB per pod.
const CACHE_TTL: Duration = Duration::from_secs(30);

static CACHE: std::sync::OnceLock<tokio::sync::Mutex<Option<(std::time::Instant, DiskHealthReport)>>> =
    std::sync::OnceLock::new();

/// [`collect_from_dual_pool`], cached for 30 seconds per process. One caller
/// collects at a time; the others wait for its result.
pub async fn cached_disk_health(dual: &crate::db::DualPool) -> DiskHealthReport {
    let lock = CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
    let mut guard = lock.lock().await;
    if let Some((at, report)) = guard.as_ref() {
        if at.elapsed() < CACHE_TTL {
            return report.clone();
        }
    }
    let report = collect_from_dual_pool(dual).await;
    *guard = Some((std::time::Instant::now(), report.clone()));
    report
}

/// `12.3 GiB`.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
#[path = "disk_monitor_tests.rs"]
mod tests;

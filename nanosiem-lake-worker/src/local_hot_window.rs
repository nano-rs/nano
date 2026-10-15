// SPDX-License-Identifier: AGPL-3.0-or-later
//! Runtime-only local residency policy for lean parts. No provenance changes.
use anyhow::{ensure, Context, Result};
use std::path::{Path, PathBuf};

pub const FLAG: &str = "NANO_LAKE_LOCAL_HOT_WINDOW";
pub const HOURS: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_HOURS";
pub const DIR: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_DIR";
pub const RATE: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_BYTES_PER_SECOND";
pub const MAX_BYTES: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_MAX_BYTES";
pub const DEFAULT_MAX_BYTES: u64 = 12 * 1024 * 1024 * 1024;

pub const RESERVE: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_RESERVE_BYTES";
/// NAN-3164: concurrent background object downloads sharing the rate cap.
pub const CONCURRENCY: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_CONCURRENCY";
/// NAN-3164: divide the cap by this while queries are in flight, once the
/// warm window is resident (never before: those queries want this data).
pub const QUERY_BACKOFF: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_QUERY_BACKOFF";
/// NAN-3164: newest hours that must be resident before the cell reports warm.
pub const WARM_HOURS: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_HOURS";
/// NAN-3164: bound on the warm wait, so a slow or failing R2 cannot hold a roll.
pub const WARM_TIMEOUT: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_TIMEOUT_SECONDS";
/// NAN-3164: delay before the first hydration pass (was a fixed 60 s).
pub const START_DELAY: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_START_DELAY_SECONDS";
/// NAN-3647: opt-in warm readiness gate (exact "1"; default off = NAN-3164
/// behavior, unchanged). On: the startup warm waits for the newest
/// `WARM_HOURS` up to `WARM_GATE_TIMEOUT` instead of `WARM_TIMEOUT`, and the
/// pass that fills them runs at the warm-up rate and fan-out below (the pod
/// serves no search before it is Ready, so nothing competes for the link).
/// NAN-3690: the gate also covers the older hours that summary searches
/// read. Before the pod reports warm, (1) the pass hydrates the resident
/// partials (rollup, entity ranges) of EVERY selected part in `HOURS` before
/// any data file, so a 7d `stats count` reads only local rollups at Ready;
/// (2) once the warm hours are resident the pass rediscovers once and
/// refills the newest hours (what the old writer committed meanwhile) before
/// latching warm. Both stay inside `WARM_GATE_TIMEOUT`.
pub const WARM_GATE: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_GATE";
/// NAN-3647: bound on the gated warm wait, seconds; unset = 900. Past it the
/// pod goes Ready cold and the query process logs an error.
pub const WARM_GATE_TIMEOUT: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_GATE_TIMEOUT_SECONDS";
/// NAN-3647: hydrate cap until the warm hours are resident (gate on only);
/// unset = 4x the steady-state cap. Never below the steady-state cap.
pub const WARMUP_RATE: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_WARMUP_BYTES_PER_SECOND";
/// NAN-3647: objects in flight until the warm hours are resident (gate on
/// only), 1..64; unset = 8. Never below `CONCURRENCY`.
pub const WARMUP_CONCURRENCY: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_WARMUP_CONCURRENCY";
/// NAN-3647: `DIR` is a persistent volume reused across pods (the A/B hot
/// volumes). Exact "1"; default off. On: a cache the query process cannot
/// open (foreign marker, unreadable tree) is set aside and rebuilt cold
/// instead of failing the process, a corrupt membership ledger restarts
/// empty, and the first hydration pass evicts every inherited object the
/// current catalog no longer references.
pub const PERSISTENT: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_PERSISTENT";

/// Every knob, for the supervisor's env allowlist and the docs.
pub const ENV: &[&str] = &[
    FLAG, HOURS, DIR, RATE, RESERVE, MAX_BYTES, CONCURRENCY, QUERY_BACKOFF, WARM_HOURS, WARM_TIMEOUT,
    START_DELAY, WARM_GATE, WARM_GATE_TIMEOUT, WARMUP_RATE, WARMUP_CONCURRENCY, PERSISTENT,
];

/// NAN-3647: [`PERSISTENT`].
pub fn persistent() -> bool {
    std::env::var(PERSISTENT).is_ok_and(|v| matches!(v.as_str(), "1" | "true"))
}

/// NAN-3164 scheduling knobs. Defaults are what production gets unrendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub concurrency: usize,
    pub query_backoff: u64,
    pub warm_hours: u64,
    pub warm_timeout: std::time::Duration,
    pub start_delay: std::time::Duration,
    /// NAN-3647 [`WARM_GATE`]: off = every field below is ignored.
    pub warm_gate: bool,
    /// [`WARMUP_RATE`]; zero = 4x the steady-state cap.
    pub warmup_bytes_per_second: u64,
    /// [`WARMUP_CONCURRENCY`].
    pub warmup_concurrency: usize,
}
impl Default for Schedule {
    fn default() -> Self {
        Self {
            concurrency: 4,
            query_backoff: 4,
            warm_hours: 24,
            warm_timeout: std::time::Duration::from_secs(300),
            start_delay: std::time::Duration::from_secs(5),
            warm_gate: false,
            warmup_bytes_per_second: 0,
            warmup_concurrency: 8,
        }
    }
}
/// NAN-3647: [`WARM_GATE_TIMEOUT`] default.
pub const DEFAULT_WARM_GATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);
impl Schedule {
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let d = Self::default();
        let get = |name: &str, default: u64, zero_ok: bool| -> Result<u64> {
            let Some(raw) = lookup(name).filter(|v| !v.trim().is_empty()) else {
                return Ok(default);
            };
            let value: u64 = raw.trim().parse().with_context(|| format!("{name} must be an integer"))?;
            ensure!(zero_ok || value > 0, "{name} must be positive");
            Ok(value)
        };
        let concurrency = get(CONCURRENCY, d.concurrency as u64, false)?;
        ensure!(concurrency <= 64, "{CONCURRENCY} must be at most 64");
        let warm_gate = lookup(WARM_GATE).is_some_and(|v| matches!(v.trim(), "1" | "true"));
        // Off: the NAN-3164 timeout, and the gate's own knobs are not even parsed.
        let warm_timeout = if warm_gate {
            get(WARM_GATE_TIMEOUT, DEFAULT_WARM_GATE_TIMEOUT.as_secs(), true)?
        } else {
            get(WARM_TIMEOUT, d.warm_timeout.as_secs(), true)?
        };
        let (warmup_bytes_per_second, warmup_concurrency) = if warm_gate {
            let fan_out = get(WARMUP_CONCURRENCY, d.warmup_concurrency as u64, false)?;
            ensure!(fan_out <= 64, "{WARMUP_CONCURRENCY} must be at most 64");
            (get(WARMUP_RATE, 0, true)?, fan_out as usize)
        } else {
            (d.warmup_bytes_per_second, d.warmup_concurrency)
        };
        Ok(Self {
            concurrency: concurrency as usize,
            query_backoff: get(QUERY_BACKOFF, d.query_backoff, false)?,
            // Zero disables the warm gate (report warm as soon as ready).
            warm_hours: get(WARM_HOURS, d.warm_hours, true)?,
            warm_timeout: std::time::Duration::from_secs(warm_timeout),
            start_delay: std::time::Duration::from_secs(get(START_DELAY, d.start_delay.as_secs(), true)?),
            warm_gate,
            warmup_bytes_per_second,
            warmup_concurrency,
        })
    }

    /// NAN-3690: does a pass that starts with the warm hours `resident` or
    /// not hydrate every selected part's resident partials before any data
    /// file? Gate off: never (unchanged).
    pub fn partials_first(&self, resident: bool) -> bool {
        self.warm_gate && !resident
    }

    /// NAN-3690: when a pass first finds the warm hours resident, does it
    /// rediscover once (refilling what the old writer committed meanwhile)
    /// instead of latching warm? `caught_up`: a rediscovery already ran.
    pub fn rediscover_before_latch(&self, caught_up: bool) -> bool {
        self.warm_gate && !caught_up
    }

    /// NAN-3647: the aggregate cap while the warm hours are not yet resident.
    /// Gate off: the steady-state cap (NAN-3164, unchanged).
    pub fn cap_before_warm(&self, steady: u64) -> u64 {
        if !self.warm_gate {
            steady
        } else if self.warmup_bytes_per_second > 0 {
            self.warmup_bytes_per_second.max(steady)
        } else {
            steady.saturating_mul(4)
        }
    }

    /// NAN-3647: objects in flight for a pass that starts with the warm hours
    /// `resident` or not. Gate off: [`Self::concurrency`] (unchanged).
    pub fn pass_concurrency(&self, resident: bool) -> usize {
        if self.warm_gate && !resident {
            self.warmup_concurrency.max(self.concurrency).max(1)
        } else {
            self.concurrency.max(1)
        }
    }
}

/// Aggregate hydration rate for the next object. Before the warm window is
/// resident the cell is not serving from this pod yet (or its queries miss
/// exactly what we are fetching), so run at the cap. Afterwards yield to
/// foreground cold fetches while any query is in flight.
pub fn effective_rate(cap: u64, queries_active: bool, warm_resident: bool, backoff: u64) -> u64 {
    if queries_active && warm_resident {
        (cap / backoff.max(1)).max(1)
    } else {
        cap.max(1)
    }
}

/// Selected parts are newest first and hydrated in that order. The warm
/// window is resident once every selected part ending at or after
/// `warm_cutoff` lies in the completed prefix.
pub fn warm_window_resident(selected_ends: &[i64], completed_prefix: usize, warm_cutoff: i64) -> bool {
    selected_ends
        .iter()
        .skip(completed_prefix)
        .all(|end| *end < warm_cutoff)
}

/// Startup warm gate reported to the cell supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmGate {
    /// The recent window is resident.
    Resident,
    /// Still hydrating the recent window.
    Hydrating,
    /// Gave up waiting: report warm anyway; hydration continues.
    TimedOut,
    /// `WARM_HOURS=0`: no gate.
    Disabled,
}
impl WarmGate {
    pub fn warm(self) -> bool {
        !matches!(self, Self::Hydrating)
    }
}
pub fn warm_gate(schedule: &Schedule, resident: bool, elapsed: std::time::Duration) -> WarmGate {
    if schedule.warm_hours == 0 {
        WarmGate::Disabled
    } else if resident {
        WarmGate::Resident
    } else if elapsed >= schedule.warm_timeout {
        WarmGate::TimedOut
    } else {
        WarmGate::Hydrating
    }
}

pub fn enabled() -> bool {
    std::env::var(FLAG).is_ok_and(|v| matches!(v.as_str(), "1" | "true"))
}
#[derive(Clone, Debug)]
pub struct Settings {
    pub root: PathBuf,
    pub hours: u64,
    /// Zero derives a cap from the selected window; positive values are explicit.
    pub bytes_per_second: u64,
    pub reserve_bytes: Option<u64>,
    /// Total volume usage target, including all non-cache data.
    pub max_bytes: u64,
    pub schedule: Schedule,
    /// NAN-3647 [`PERSISTENT`]: the root outlives the pod (A/B hot volumes).
    pub persistent: bool,
}
impl Settings {
    pub fn from_env(default: &Path, tenant: &str, _cpu_millis: u32) -> Result<Option<Self>> {
        if !enabled() {
            return Ok(None);
        }
        let positive = |name, default| -> Result<u64> {
            let value = std::env::var(name)
                .ok()
                .map(|v| v.parse())
                .transpose()?
                .unwrap_or(default);
            ensure!(value > 0, "{name} must be positive");
            Ok(value)
        };
        let root = std::env::var_os(DIR)
            .map(|base| {
                PathBuf::from(base)
                    .join("tenants")
                    .join(tenant)
                    .join("query/cache")
            })
            .unwrap_or_else(|| default.to_path_buf());
        ensure!(root.is_absolute(), "hot-window directory must be absolute");
        Ok(Some(Self {
            root,
            hours: positive(HOURS, 168)?,
            // Zero means derive the rate from the selected window and warm deadline.
            bytes_per_second: match std::env::var(RATE).ok() {
                Some(_) => positive(RATE, 1)?,
                None => 0,
            },
            reserve_bytes: std::env::var(RESERVE).ok().map(|v| v.parse()).transpose()?,
            max_bytes: configured_max_bytes(std::env::var(MAX_BYTES).ok().as_deref())?,
            schedule: Schedule::from_lookup(|name| std::env::var(name).ok())?,
            persistent: persistent(),
        }))
    }
    pub fn capacity(&self, resident_bytes: u64) -> Result<u64> {
        let headroom = capacity(&self.root, self.reserve_bytes, resident_bytes)?;
        match nanosiem_lake_cell::volume_usage::usage(
            &nanosiem_lake_cell::volume_usage::volume_root(&self.root),
        ) {
            Ok(usage) => Ok(headroom.min(
                self.max_bytes
                    .saturating_sub(usage.saturating_sub(resident_bytes)),
            )),
            // NAN-3139: an unreachable accountant must not fail admission;
            // fall back to free-space headroom under the volume target.
            Err(error) => {
                warn_accounting_unavailable(&error);
                Ok(headroom.min(self.max_bytes))
            }
        }
    }
}
/// Rate-limited (once per 5 min): accounting is degraded, not search.
pub fn warn_accounting_unavailable(error: &dyn std::fmt::Display) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let last = LAST.load(Ordering::Relaxed);
    if (last == 0 || now.saturating_sub(last) >= 300)
        && LAST.compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed).is_ok()
    {
        tracing::warn!(%error,
            "hot-window volume accounting unavailable; using free-space headroom under the volume target");
    }
}

/// A missing volume limit is unsafe even when statvfs reports ample node space.
pub fn configured_max_bytes(value: Option<&str>) -> Result<u64> {
    if let Some(value) = value {
        let bytes = value.parse::<u64>()?;
        ensure!(bytes > 0, "{MAX_BYTES} must be positive");
        return Ok(bytes);
    }
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(max_bytes = DEFAULT_MAX_BYTES,
            "hot-window volume limit unknown; using conservative 12 GiB total data cap; render NANO_LAKE_LOCAL_HOT_WINDOW_MAX_BYTES from emptyDir sizeLimit");
    }
    Ok(DEFAULT_MAX_BYTES)
}

/// Leave a eighth of this filesystem for ingest/merge scratch by default.
/// Only currently available blocks plus our existing residency are claimable.
pub fn capacity(root: &Path, reserve: Option<u64>, resident: u64) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(root.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is NUL-terminated and stat points to writable storage.
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs hot-window directory: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: successful statvfs initialized stat.
    let stat = unsafe { stat.assume_init() };
    let total = stat.f_blocks.saturating_mul(stat.f_frsize);
    let available = stat.f_bavail.saturating_mul(stat.f_frsize);
    Ok(available
        .saturating_add(resident)
        .saturating_sub(reserve.unwrap_or(total / 8)))
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Coverage {
    pub capacity_bytes: u64,
    pub configured_hours: u64,
    pub selected_bytes: u64,
    pub local_bytes: u64,
    pub selected_parts: usize,
    pub local_parts: usize,
    pub effective_hours: f64,
    pub buckets: [Bucket; 3],
    pub hydrate_bytes: u64,
    pub hydrate_seconds: f64,
    pub rate_bytes_per_second: f64,
    pub rate_cap_bytes_per_second: u64,
    pub eta_seconds: f64,
    pub warm: bool,
    pub discovery_seconds: f64,
    pub lookup_seconds: f64,
    pub fetch_seconds: f64,
    pub cache_hit_objects: u64,
    pub cache_miss_objects: u64,
    pub deferred_objects: u64,
    /// NAN-3164: newest hours gating the startup warm signal.
    pub warm_hours: u64,
    /// Latched once the newest `warm_hours` were resident in some pass.
    pub warm_resident: bool,
    pub concurrency: usize,
}
impl Coverage {
    pub fn update_progress(&mut self, elapsed: f64) {
        self.hydrate_seconds = elapsed;
        self.rate_bytes_per_second = self.hydrate_bytes as f64 / elapsed.max(0.001);
        self.eta_seconds = (self.selected_bytes.saturating_sub(self.local_bytes)) as f64
            / if self.hydrate_bytes > 0 {
                self.rate_bytes_per_second.max(1.0)
            } else {
                self.rate_cap_bytes_per_second.max(1) as f64
            };
        self.warm = self.selected_parts > 0 && self.local_parts == self.selected_parts;
    }
    pub fn log_progress(&self) {
        tracing::info!(
            covered_hours = self.effective_hours,
            bytes_resident = self.local_bytes,
            bytes_target = self.selected_bytes,
            parts_resident = self.local_parts,
            parts_target = self.selected_parts,
            rate = self.rate_bytes_per_second,
            eta = self.eta_seconds,
            rate_cap = self.rate_cap_bytes_per_second,
            discovery_seconds = self.discovery_seconds,
            lookup_seconds = self.lookup_seconds,
            fetch_seconds = self.fetch_seconds,
            cache_hits = self.cache_hit_objects,
            cache_misses = self.cache_miss_objects,
            deferred_objects = self.deferred_objects,
            warm_hours = self.warm_hours,
            warm_resident = self.warm_resident,
            concurrency = self.concurrency,
            "local hot-window hydration progress"
        );
    }
}

/// Reserve three of the fifteen minutes for startup and object/verification overhead.
/// Explicit caps win; the default follows the selected bytes, not CPU shares.
pub fn hydrate_rate(configured: u64, target: u64) -> u64 {
    if configured > 0 {
        configured
    } else {
        target.div_ceil(12 * 60).max(1)
    }
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Bucket {
    pub hours: u64,
    pub total_bytes: u64,
    pub local_bytes: u64,
    pub total_parts: usize,
    pub local_parts: usize,
}

/// Newest first; a part is admitted whole. Stop at the first part that cannot
/// fit so the selected window is contiguous rather than scattered old files.
pub fn select<T>(mut parts: Vec<(i64, u64, T)>, cutoff: i64, capacity: u64) -> Vec<(i64, u64, T)> {
    parts.sort_by_key(|p| std::cmp::Reverse(p.0));
    let mut remaining = capacity;
    parts
        .into_iter()
        .take_while(|(end, bytes, _)| {
            if *end < cutoff || *bytes > remaining {
                return false;
            }
            remaining -= bytes;
            true
        })
        .collect()
}

pub fn create_root(settings: &Settings) -> Result<()> {
    std::fs::create_dir_all(&settings.root).context("create local hot-window directory")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn newest_first_capacity_and_overlap() {
        let result = select(
            vec![(10, 4, "old"), (30, 4, "new"), (20, 4, "middle")],
            10,
            8,
        );
        assert_eq!(
            result.iter().map(|p| p.2).collect::<Vec<_>>(),
            ["new", "middle"]
        );
        assert_eq!(select(vec![(20, 1, ())], 21, 8).len(), 0);
        assert_eq!(select(vec![(20, 1, ())], 20, 8).len(), 1);
    }
    #[test]
    fn derived_rate_and_progress() {
        assert!(hydrate_rate(0, 16 * 1024 * 1024 * 1024) * 720 >= 16 * 1024 * 1024 * 1024);
        assert_eq!(hydrate_rate(123, u64::MAX), 123);
        let mut coverage = Coverage {
            selected_bytes: 200,
            local_bytes: 100,
            selected_parts: 2,
            local_parts: 1,
            hydrate_bytes: 100,
            ..Default::default()
        };
        coverage.update_progress(2.0);
        assert_eq!(coverage.rate_bytes_per_second, 50.0);
        assert_eq!(coverage.eta_seconds, 2.0);
        assert!(!coverage.warm);
        coverage.local_parts = 2;
        coverage.local_bytes = 200;
        coverage.update_progress(4.0);
        assert!(coverage.warm);
        assert_eq!(coverage.eta_seconds, 0.0);
    }
    #[test]
    fn progress_log_contains_operational_fields() {
        #[derive(Clone)]
        struct Writer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = Writer(output.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || Coverage::default().log_progress());
        let text = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        for field in [
            "INFO",
            "covered_hours",
            "bytes_resident",
            "bytes_target",
            "parts_resident",
            "parts_target",
            "rate",
            "eta",
            "hydration progress",
        ] {
            assert!(text.contains(field), "missing {field}: {text}");
        }
    }
    #[test]
    fn schedule_knobs_parse_with_defaults() {
        let none = Schedule::from_lookup(|_| None).unwrap();
        assert_eq!(none, Schedule::default());
        assert_eq!((none.concurrency, none.query_backoff, none.warm_hours), (4, 4, 24));
        assert_eq!(none.warm_timeout, std::time::Duration::from_secs(300));
        assert_eq!(none.start_delay, std::time::Duration::from_secs(5));
        let env = std::collections::HashMap::from([
            (CONCURRENCY, "8"), (QUERY_BACKOFF, "2"), (WARM_HOURS, "0"), (WARM_TIMEOUT, "0"), (START_DELAY, "60"),
        ]);
        let set = Schedule::from_lookup(|name| env.get(name).map(|v| v.to_string())).unwrap();
        assert_eq!((set.concurrency, set.query_backoff, set.warm_hours), (8, 2, 0));
        assert_eq!(set.warm_timeout, std::time::Duration::ZERO);
        assert_eq!(set.start_delay, std::time::Duration::from_secs(60));
        for (name, bad) in [(CONCURRENCY, "0"), (CONCURRENCY, "65"), (QUERY_BACKOFF, "0"), (WARM_HOURS, "x")] {
            assert!(Schedule::from_lookup(|n| (n == name).then(|| bad.to_string())).is_err(), "{name}={bad}");
        }
        for name in [CONCURRENCY, QUERY_BACKOFF, WARM_HOURS, WARM_TIMEOUT, START_DELAY] {
            assert!(ENV.contains(&name));
        }
    }

    /// NAN-3647: the gate is opt-in. Off, its knobs are ignored (NAN-3164
    /// timeout, steady cap and fan-out before warm); on, the gated timeout
    /// and the warm-up cap and fan-out apply until the warm hours are resident.
    #[test]
    fn warm_gate_is_opt_in_and_boosts_only_before_warm() {
        use std::time::Duration;
        let env = |pairs: &[(&'static str, &'static str)]| {
            let map = std::collections::HashMap::<&str, &str>::from_iter(pairs.iter().copied());
            Schedule::from_lookup(move |name| map.get(name).map(|v| v.to_string()))
        };
        // Off: gate knobs (even invalid ones) change nothing.
        let off = env(&[(WARM_GATE_TIMEOUT, "x"), (WARMUP_RATE, "1"), (WARMUP_CONCURRENCY, "99"), (WARM_TIMEOUT, "120")]).unwrap();
        assert_eq!(off, Schedule { warm_timeout: Duration::from_secs(120), ..Schedule::default() });
        assert_eq!(off.cap_before_warm(32 << 20), 32 << 20);
        assert_eq!((off.pass_concurrency(false), off.pass_concurrency(true)), (4, 4));
        assert_eq!(env(&[(WARM_GATE, "0")]).unwrap(), Schedule::default());

        let on = env(&[(WARM_GATE, "1"), (WARM_TIMEOUT, "120")]).unwrap();
        assert!(on.warm_gate);
        assert_eq!(on.warm_timeout, DEFAULT_WARM_GATE_TIMEOUT, "the gate's own bound replaces WARM_TIMEOUT");
        assert_eq!(on.cap_before_warm(32 << 20), 128 << 20, "unset warm-up rate = 4x the steady cap");
        assert_eq!((on.pass_concurrency(false), on.pass_concurrency(true)), (8, 4));
        assert_eq!(effective_rate(on.cap_before_warm(32 << 20), true, false, 4), 128 << 20,
            "queries in flight never throttle the warm-up");

        let set = env(&[(WARM_GATE, "1"), (WARM_GATE_TIMEOUT, "600"), (WARMUP_RATE, "1000"), (WARMUP_CONCURRENCY, "2"),
            (CONCURRENCY, "3")]).unwrap();
        assert_eq!(set.warm_timeout, Duration::from_secs(600));
        assert_eq!(set.cap_before_warm(32 << 20), 32 << 20, "never below the steady cap");
        assert_eq!(set.cap_before_warm(500), 1000);
        assert_eq!(set.pass_concurrency(false), 3, "never below the steady fan-out");
        for (name, bad) in [(WARMUP_CONCURRENCY, "0"), (WARMUP_CONCURRENCY, "65"), (WARM_GATE_TIMEOUT, "x")] {
            assert!(env(&[(WARM_GATE, "1"), (name, bad)]).is_err(), "{name}={bad}");
        }
        for name in [WARM_GATE, WARM_GATE_TIMEOUT, WARMUP_RATE, WARMUP_CONCURRENCY, PERSISTENT] {
            assert!(ENV.contains(&name));
        }
    }

    /// NAN-3690: partials first and one rediscovery come with the warm gate
    /// (no separate switch), only before warm; gate off: never.
    #[test]
    fn warm_partials_come_with_the_gate() {
        let off = Schedule::default();
        assert!(!off.partials_first(false) && !off.rediscover_before_latch(false), "gate off: unchanged");
        let on = Schedule::from_lookup(|name| (name == WARM_GATE).then(|| "1".to_string())).unwrap();
        assert!(on.partials_first(false) && !on.partials_first(true), "only passes that start before warm");
        assert!(on.rediscover_before_latch(false) && !on.rediscover_before_latch(true), "one rediscovery");
        assert!(!ENV.iter().any(|name| name.ends_with("WARM_PARTIALS")), "no separate knob");
    }

    #[test]
    fn rate_runs_at_cap_until_warm_then_backs_off_for_queries() {
        let cap = 32 << 20;
        // Cold start: queries in flight miss exactly what we fetch; full cap.
        assert_eq!(effective_rate(cap, true, false, 4), cap);
        assert_eq!(effective_rate(cap, false, false, 4), cap);
        assert_eq!(effective_rate(cap, false, true, 4), cap);
        assert_eq!(effective_rate(cap, true, true, 4), cap / 4);
        assert_eq!(effective_rate(1, true, true, 4), 1, "never zero (zero means unpaced)");
    }

    #[test]
    fn warm_window_is_the_newest_completed_prefix() {
        // Newest first; the warm cutoff is 70.
        let ends = [100, 90, 80, 70, 60, 50];
        assert!(!warm_window_resident(&ends, 0, 70));
        assert!(!warm_window_resident(&ends, 3, 70), "70 is inside the window");
        assert!(warm_window_resident(&ends, 4, 70));
        assert!(warm_window_resident(&ends, 6, 70));
        assert!(warm_window_resident(&[], 0, 70), "nothing selected: nothing to wait for");
        assert!(warm_window_resident(&[60, 50], 0, 70), "no recent data: nothing to wait for");
    }

    #[test]
    fn warm_gate_is_bounded_by_its_timeout() {
        use std::time::Duration;
        let schedule = Schedule { warm_timeout: Duration::from_secs(300), ..Default::default() };
        assert_eq!(warm_gate(&schedule, false, Duration::from_secs(10)), WarmGate::Hydrating);
        assert!(!WarmGate::Hydrating.warm());
        assert_eq!(warm_gate(&schedule, true, Duration::from_secs(10)), WarmGate::Resident);
        assert_eq!(warm_gate(&schedule, false, Duration::from_secs(300)), WarmGate::TimedOut);
        assert!(WarmGate::TimedOut.warm(), "a slow R2 must not hold the roll");
        let off = Schedule { warm_hours: 0, ..schedule };
        assert_eq!(warm_gate(&off, false, Duration::ZERO), WarmGate::Disabled);
        assert!(WarmGate::Disabled.warm());
        assert_eq!(serde_json::to_value(WarmGate::TimedOut).unwrap(), "timed_out");
    }

    #[test]
    fn unknown_volume_limit_defaults_conservatively() {
        assert_eq!(configured_max_bytes(None).unwrap(), 12 * 1024 * 1024 * 1024);
        assert_eq!(configured_max_bytes(Some("12345")).unwrap(), 12345);
        assert!(configured_max_bytes(Some("0")).is_err());
        assert!(configured_max_bytes(Some("32Gi")).is_err());
    }

    #[test]
    fn cap_accounts_for_all_volume_data_growing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tenants/t/query/cache");
        std::fs::create_dir_all(&root).unwrap();
        let settings = Settings {
            root,
            hours: 72,
            bytes_per_second: 0,
            reserve_bytes: Some(0),
            max_bytes: 64 * 1024,
            schedule: Schedule::default(),
            persistent: false,
        };
        let before = settings.capacity(0).unwrap();
        let ingest = dir.path().join("ingest-scratch");
        std::fs::write(&ingest, vec![0; 8192]).unwrap();
        assert_eq!(settings.capacity(0).unwrap(), before - 8192);
        std::fs::write(ingest, vec![0; 64 * 1024]).unwrap();
        assert_eq!(settings.capacity(0).unwrap(), 0);
    }

    #[test]
    fn filesystem_reserve_is_derived() {
        let dir = tempfile::tempdir().unwrap();
        let without = capacity(dir.path(), Some(0), 0).unwrap();
        assert!(capacity(dir.path(), Some(without + 1), 0).unwrap() == 0);
        assert!(capacity(dir.path(), None, 0).unwrap() < without);
    }
}

pub type Membership = std::collections::BTreeMap<String, Vec<String>>;
/// Reconcile a restart ledger only against verified live membership. Merely
/// falling outside the configured window does not mean a part was retired.
pub fn retired(
    previous: &Membership,
    live: &std::collections::BTreeSet<String>,
    live_digests: &std::collections::HashSet<String>,
) -> Vec<String> {
    previous
        .iter()
        .filter(|(id, _)| !live.contains(*id))
        .flat_map(|(_, digests)| digests)
        .filter(|digest| !live_digests.contains(*digest))
        .cloned()
        .collect()
}
pub fn load_membership(root: &Path, tenant: &str) -> Result<Membership> {
    let path = root
        .join(format!("tenant-{tenant}"))
        .join("hot-membership.json");
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Membership::new()),
        Err(e) => Err(e.into()),
    }
}
/// NAN-3647: [`load_membership`] on a persistent root, where a ledger torn by
/// a pod killed mid-write (or written by an older image) must not stop every
/// hydration pass: set it aside and start empty. Objects it listed are then
/// reconciled by the first pass's unreferenced sweep.
pub fn load_membership_or_reset(root: &Path, tenant: &str) -> Result<Membership> {
    match load_membership(root, tenant) {
        Ok(membership) => Ok(membership),
        Err(error) if error.downcast_ref::<serde_json::Error>().is_some() => {
            let path = root.join(format!("tenant-{tenant}")).join("hot-membership.json");
            tracing::error!(%error, path = %path.display(),
                "hot-window membership ledger unreadable on the persistent volume; discarding it and starting empty");
            std::fs::remove_file(&path).with_context(|| format!("discard {}", path.display()))?;
            Ok(Membership::new())
        }
        Err(error) => Err(error),
    }
}
pub fn save_membership(root: &Path, tenant: &str, membership: &Membership) -> Result<()> {
    let dir = root.join(format!("tenant-{tenant}"));
    let temp = tempfile::NamedTempFile::new_in(&dir)?;
    serde_json::to_writer(temp.as_file(), membership)?;
    temp.as_file().sync_all()?;
    temp.persist(dir.join("hot-membership.json"))
        .map_err(|e| e.error)?;
    Ok(())
}
#[cfg(test)]
mod membership_tests {
    use super::*;
    #[test]
    fn restart_ledger_purges_only_retired_unshared_digests() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("tenant-t")).unwrap();
        let membership = Membership::from([
            ("old".into(), vec!["retired".into(), "shared".into()]),
            ("live".into(), vec!["keep".into()]),
        ]);
        save_membership(dir.path(), "t", &membership).unwrap();
        let restored = load_membership(dir.path(), "t").unwrap();
        assert_eq!(restored, membership);
        assert_eq!(
            retired(
                &restored,
                &std::collections::BTreeSet::from(["live".into()]),
                &std::collections::HashSet::from(["shared".into(), "keep".into()])
            ),
            ["retired"]
        );
    }

    /// NAN-3647: a torn ledger on a persistent volume restarts empty (and is
    /// removed); any other failure still surfaces.
    #[test]
    fn corrupt_ledger_on_a_persistent_volume_restarts_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("tenant-t")).unwrap();
        let path = dir.path().join("tenant-t/hot-membership.json");
        std::fs::write(&path, b"{\"part\": [\"abc").unwrap();
        assert!(load_membership(dir.path(), "t").is_err(), "the strict loader still refuses it");
        assert_eq!(load_membership_or_reset(dir.path(), "t").unwrap(), Membership::new());
        assert!(!path.exists());
        assert_eq!(load_membership_or_reset(dir.path(), "t").unwrap(), Membership::new(), "absent = empty");
        std::fs::create_dir(&path).unwrap();
        assert!(load_membership_or_reset(dir.path(), "t").is_err(), "an I/O error is not a torn ledger");
    }
}

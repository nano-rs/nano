// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in realistic variance for generated telemetry (NAN-3174).
//!
//! The default generators draw entities uniformly, sample from a few hundred
//! profile hashes / process chains, stamp a whole batch with one timestamp and
//! run at a flat rate. That makes an unrealistically uniform search test bed:
//! every host lands in every part and the hash column has almost no
//! cardinality. This module holds the building blocks to break that up:
//!
//! - [`ZipfSampler`] — O(1) alias-table sampler over Zipf(s) ranks, built once.
//! - [`HashPool`] — N deterministic synthetic SHA-256 files unioned (as the
//!   long tail) with the profile file hashes.
//! - [`vary_cmdline`] — appends random arguments/paths to a command line.
//! - [`batch_timestamps`] — per-event timestamps spread over a batch period.
//! - [`RateShape`] — diurnal sine × deterministic per-minute bursts.
//!
//! Everything is OFF unless installed: [`install`] is only called when a
//! variance flag is set, and every hook here returns `None` without touching
//! the caller's RNG when nothing is installed, so default output is unchanged.

use chrono::{DateTime, Duration, Timelike, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

// =============================================================================
// Deterministic seeding helpers
// =============================================================================

/// SplitMix64 step: a cheap, well-mixed deterministic hash of a u64.
pub fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Uniform f64 in [0, 1) derived deterministically from (seed, key).
fn unit_from(seed: u64, key: u64) -> f64 {
    (splitmix64(seed ^ splitmix64(key)) >> 11) as f64 / (1u64 << 53) as f64
}

// =============================================================================
// Zipf sampler (Vose alias method)
// =============================================================================

/// Samples ranks `0..n` with P(k) ∝ 1 / (k + 1)^s in O(1) per draw.
#[derive(Debug, Clone)]
pub struct ZipfSampler {
    prob: Vec<f64>,
    alias: Vec<usize>,
}

impl ZipfSampler {
    /// Build the alias table once. `n` must be > 0; `s` ≥ 0 (0 = uniform).
    pub fn new(n: usize, s: f64) -> Self {
        assert!(n > 0, "ZipfSampler needs at least one rank");
        let s = s.max(0.0);
        let weights: Vec<f64> = (0..n).map(|k| 1.0 / ((k + 1) as f64).powf(s)).collect();
        Self::from_weights(&weights)
    }

    fn from_weights(weights: &[f64]) -> Self {
        let n = weights.len();
        let total: f64 = weights.iter().sum();
        let mut scaled: Vec<f64> = weights.iter().map(|w| w * n as f64 / total).collect();
        let mut prob = vec![1.0; n];
        let mut alias: Vec<usize> = (0..n).collect();
        let (mut small, mut large): (Vec<usize>, Vec<usize>) =
            (0..n).partition(|&i| scaled[i] < 1.0);
        while let (Some(s), Some(l)) = (small.pop(), large.last().copied()) {
            prob[s] = scaled[s];
            alias[s] = l;
            scaled[l] = (scaled[l] + scaled[s]) - 1.0;
            if scaled[l] < 1.0 {
                large.pop();
                small.push(l);
            }
        }
        // Leftovers (numerical residue) keep prob 1.0 / alias self.
        Self { prob, alias }
    }

    pub fn len(&self) -> usize {
        self.prob.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prob.is_empty()
    }

    /// Draw a rank in `0..len()`; rank 0 is the most popular.
    pub fn sample(&self, rng: &mut (impl Rng + ?Sized)) -> usize {
        let i = rng.random_range(0..self.prob.len());
        if rng.random::<f64>() < self.prob[i] {
            i
        } else {
            self.alias[i]
        }
    }
}

/// Zipf popularity over a fixed population (e.g. the fleet's entities). The
/// rank→index mapping is a seeded shuffle so the "hot" hosts are spread over
/// the fleet instead of being the first N created.
#[derive(Debug, Clone)]
pub struct SkewedIndex {
    sampler: ZipfSampler,
    rank_to_index: Vec<usize>,
}

impl SkewedIndex {
    pub fn new(n: usize, skew: f64, seed: u64) -> Self {
        let mut rank_to_index: Vec<usize> = (0..n).collect();
        // Seeded Fisher–Yates with SplitMix64 (no RNG crate state involved).
        for i in (1..n).rev() {
            let j = (splitmix64(seed ^ (i as u64).wrapping_mul(0xA24B_AED4_963E_E407))
                % (i as u64 + 1)) as usize;
            rank_to_index.swap(i, j);
        }
        Self {
            sampler: ZipfSampler::new(n, skew),
            rank_to_index,
        }
    }

    pub fn sample(&self, rng: &mut (impl Rng + ?Sized)) -> usize {
        self.rank_to_index[self.sampler.sample(rng)]
    }
}

// =============================================================================
// Long-tail hash pool
// =============================================================================

/// A synthetic file: deterministic SHA-256 plus a plausible path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticFile {
    /// 64-char uppercase hex, matching the profile hash format.
    pub hash: String,
    pub path: String,
    pub name: String,
}

const SYNTH_DIRS: &[&str] = &[
    r"C:\Program Files\Common Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\WinSxS",
    r"C:\Users\Public\Downloads",
    r"C:\Windows\Temp",
];
const SYNTH_VENDORS: &[&str] = &[
    "Adobe",
    "Google",
    "Mozilla",
    "Zoom",
    "Citrix",
    "Microsoft",
    "Dell",
    "Intel",
    "Nvidia",
    "Slack",
    "Atlassian",
    "Oracle",
    "VMware",
    "Cisco",
    "Logitech",
    "CrowdStrike",
];
const SYNTH_EXTS: &[&str] = &["dll", "dll", "dll", "exe", "sys", "tmp", "ps1", "msi"];

impl SyntheticFile {
    fn generate(seed: u64, i: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"log-blaster-hash-pool");
        hasher.update(seed.to_le_bytes());
        hasher.update(i.to_le_bytes());
        let digest = hasher.finalize();
        let hash: String = digest.iter().map(|b| format!("{b:02X}")).collect();
        let dir = SYNTH_DIRS[digest[0] as usize % SYNTH_DIRS.len()];
        let vendor = SYNTH_VENDORS[digest[1] as usize % SYNTH_VENDORS.len()];
        let ext = SYNTH_EXTS[digest[2] as usize % SYNTH_EXTS.len()];
        let name = format!(
            "{}_{}.{}",
            vendor.to_lowercase(),
            hash[..8].to_lowercase(),
            ext
        );
        let path = format!(r"{dir}\{vendor}\{name}");
        Self { hash, path, name }
    }
}

/// Profile hashes (the popular head) unioned with N synthetic hashes (the
/// long tail), drawn by Zipf rank. A head draw returns `None` so the caller
/// keeps its normal weighted profile sample (path/hash stay consistent).
#[derive(Debug, Clone)]
pub struct HashPool {
    profile_len: usize,
    synthetic: Vec<SyntheticFile>,
    sampler: ZipfSampler,
}

impl HashPool {
    pub fn new(profile_len: usize, extra: usize, skew: f64, seed: u64) -> Self {
        let synthetic = (0..extra as u64)
            .map(|i| SyntheticFile::generate(seed, i))
            .collect();
        Self {
            profile_len,
            synthetic,
            sampler: ZipfSampler::new((profile_len + extra).max(1), skew),
        }
    }

    pub fn synthetic(&self) -> &[SyntheticFile] {
        &self.synthetic
    }

    pub fn sample(&self, rng: &mut (impl Rng + ?Sized)) -> Option<&SyntheticFile> {
        let rank = self.sampler.sample(rng);
        rank.checked_sub(self.profile_len)
            .and_then(|i| self.synthetic.get(i))
    }
}

// =============================================================================
// Command-line variance
// =============================================================================

/// Append realistic random arguments / paths to a profile command line so the
/// command_line column has real cardinality. Leaves ~40% unchanged.
pub fn vary_cmdline(base: &str, rng: &mut (impl Rng + ?Sized)) -> String {
    const USERS: &[&str] = &["jsmith", "adavis", "mlee", "svc_backup", "kchen", "rpatel"];
    const SVCS: &[&str] = &[
        "netsvcs",
        "LocalService",
        "NetworkService",
        "DcomLaunch",
        "appmodel",
    ];
    const EXTS: &[&str] = &["txt", "log", "ps1", "json", "xml", "docx", "xlsx", "zip"];
    let roll: u32 = rng.random_range(0..10);
    match roll {
        0..=3 => base.to_string(),
        4 | 5 => format!(
            r#"{base} "C:\Users\{}\AppData\Local\Temp\{:08x}.{}""#,
            USERS[rng.random_range(0..USERS.len())],
            rng.random::<u32>(),
            EXTS[rng.random_range(0..EXTS.len())]
        ),
        6 => format!(
            "{base} -k {} -p -s Svc{}",
            SVCS[rng.random_range(0..SVCS.len())],
            rng.random_range(1u32..400)
        ),
        7 => format!(
            "{base} --profile-directory=\"Profile {}\" --type=renderer --field-trial-handle={}",
            rng.random_range(1u32..9),
            rng.random::<u32>()
        ),
        8 => format!(
            r#"{base} /c "C:\ProgramData\{:06x}\run.cmd" /q"#,
            rng.random_range(0u32..0xFFFFFF)
        ),
        _ => format!(
            "{base} -ExecutionPolicy Bypass -Session {}",
            rng.random::<u16>()
        ),
    }
}

// =============================================================================
// Global install (generator-side hooks)
// =============================================================================

/// Generator-side variance, installed once at startup when any flag is set.
#[derive(Debug, Clone, Default)]
pub struct GeneratorVariance {
    pub hash_pool: Option<HashPool>,
    pub cmdline_variance: bool,
}

static GENERATOR_VARIANCE: OnceLock<GeneratorVariance> = OnceLock::new();

/// Install generator-side variance. Only call when a variance flag is set;
/// the first install wins.
pub fn install(v: GeneratorVariance) {
    let _ = GENERATOR_VARIANCE.set(v);
}

/// True once [`install`] has run.
pub fn installed() -> bool {
    GENERATOR_VARIANCE.get().is_some()
}

/// Long-tail file override. `None` (without touching `rng`) when no hash pool
/// is installed or when the draw lands in the profile head.
pub fn sample_synthetic_file(rng: &mut (impl Rng + ?Sized)) -> Option<&'static SyntheticFile> {
    GENERATOR_VARIANCE.get()?.hash_pool.as_ref()?.sample(rng)
}

/// Varied command line, or `None` (without drawing randomness) when
/// `--cmdline-variance` is off. Uses the thread RNG so callers without an RNG
/// parameter can opt in.
pub fn varied_cmdline(base: &str) -> Option<String> {
    GENERATOR_VARIANCE
        .get()
        .filter(|v| v.cmdline_variance)
        .map(|_| vary_cmdline(base, &mut rand::rng()))
}

// =============================================================================
// Per-event time jitter
// =============================================================================

/// Timestamps for one batch. With `jitter == false` this is exactly
/// `vec![sim_time; n]` and does not touch `rng` (the historical behavior).
///
/// With jitter each event gets a time in `[sim_time - period, sim_time]`,
/// sorted ascending, then ~5% of adjacent pairs are swapped to mimic the mild
/// reordering real collectors produce.
pub fn batch_timestamps(
    sim_time: DateTime<Utc>,
    n: usize,
    period: std::time::Duration,
    jitter: bool,
    rng: &mut (impl Rng + ?Sized),
) -> Vec<DateTime<Utc>> {
    if !jitter {
        return vec![sim_time; n];
    }
    let period_us = period.as_micros().min(i64::MAX as u128) as i64;
    let mut offsets: Vec<i64> = (0..n)
        .map(|_| {
            if period_us > 0 {
                rng.random_range(0..=period_us)
            } else {
                0
            }
        })
        .collect();
    offsets.sort_unstable_by(|a, b| b.cmp(a)); // largest offset = oldest first
    let mut ts: Vec<DateTime<Utc>> = offsets
        .into_iter()
        .map(|o| sim_time - Duration::microseconds(o))
        .collect();
    let mut i = 0;
    while i + 1 < ts.len() {
        if rng.random_bool(0.05) {
            ts.swap(i, i + 1);
            i += 2;
        } else {
            i += 1;
        }
    }
    ts
}

// =============================================================================
// Rate shape: diurnal × bursts
// =============================================================================

/// Burst spec: each wall-clock minute, with probability `prob`, run at
/// `mult`× for the first `secs` seconds of that minute.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BurstSpec {
    pub prob: f64,
    pub mult: f64,
    pub secs: u32,
}

impl std::str::FromStr for BurstSpec {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').map(str::trim).collect();
        if parts.len() != 3 {
            return Err("expected prob,mult,secs (e.g. 0.1,4,15)".into());
        }
        let prob: f64 = parts[0].parse().map_err(|e| format!("prob: {e}"))?;
        let mult: f64 = parts[1].parse().map_err(|e| format!("mult: {e}"))?;
        let secs: u32 = parts[2].parse().map_err(|e| format!("secs: {e}"))?;
        if !(0.0..=1.0).contains(&prob) {
            return Err("prob must be in 0..=1".into());
        }
        if !(mult >= 1.0 && mult.is_finite()) {
            return Err("mult must be >= 1".into());
        }
        if !(1..=60).contains(&secs) {
            return Err("secs must be in 1..=60".into());
        }
        Ok(Self { prob, mult, secs })
    }
}

/// Rate multiplier over time. The long-run average multiplier is ~1.0, so the
/// average EPS stays at `--eps`: the diurnal sine averages to 1 over 24 h, and
/// the burst factor is divided by its expected value.
#[derive(Debug, Clone, Copy)]
pub struct RateShape {
    /// Sine amplitude in [0, 1); peak at 14:00 UTC, trough at 02:00 UTC.
    pub diurnal: f64,
    pub burst: Option<BurstSpec>,
    pub seed: u64,
}

impl RateShape {
    pub fn is_flat(&self) -> bool {
        self.diurnal == 0.0 && self.burst.is_none()
    }

    fn burst_mean(b: &BurstSpec) -> f64 {
        1.0 + b.prob * (b.mult - 1.0) * b.secs as f64 / 60.0
    }

    /// Is this wall-clock minute a burst minute? Deterministic in (seed,
    /// minute) so every sender thread agrees.
    pub fn burst_minute(&self, minute: i64) -> bool {
        self.burst
            .is_some_and(|b| unit_from(self.seed, minute as u64) < b.prob)
    }

    /// Multiplier on the base EPS at `t`.
    pub fn multiplier(&self, t: DateTime<Utc>) -> f64 {
        let mut m = 1.0;
        if self.diurnal > 0.0 {
            let hour = t.num_seconds_from_midnight() as f64 / 3600.0;
            // sin peaks at hour 14 ((14 - 8) / 24 * 2π = π/2).
            let phase = (hour - 8.0) / 24.0 * std::f64::consts::TAU;
            m *= 1.0 + self.diurnal * phase.sin();
        }
        if let Some(b) = self.burst {
            let secs = t.timestamp();
            let minute = secs.div_euclid(60);
            let in_window = secs.rem_euclid(60) < b.secs as i64;
            let factor = if in_window && self.burst_minute(minute) {
                b.mult
            } else {
                1.0
            };
            m *= factor / Self::burst_mean(&b);
        }
        m.max(0.01)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn zipf_shape_matches_theory() {
        let z = ZipfSampler::new(1000, 1.0);
        let mut rng = StdRng::seed_from_u64(7);
        let draws = 400_000;
        let mut counts = vec![0u32; 1000];
        for _ in 0..draws {
            counts[z.sample(&mut rng)] += 1;
        }
        let h: f64 = (1..=1000).map(|k| 1.0 / k as f64).sum();
        for k in [0usize, 1, 9, 99] {
            let expected = draws as f64 / ((k + 1) as f64 * h);
            let got = counts[k] as f64;
            assert!(
                (got - expected).abs() / expected < 0.08,
                "rank {k}: got {got}, expected {expected}"
            );
        }
        // Monotone-ish head and a long tail: top 10 ranks ≈ H(10)/H(1000).
        let top10: u32 = counts[..10].iter().sum();
        let share = top10 as f64 / draws as f64;
        let theory = (1..=10).map(|k| 1.0 / k as f64).sum::<f64>() / h;
        assert!(
            (share - theory).abs() < 0.01,
            "top10 share {share} vs {theory}"
        );
    }

    #[test]
    fn zipf_zero_skew_is_uniform() {
        let z = ZipfSampler::new(10, 0.0);
        let mut rng = StdRng::seed_from_u64(1);
        let mut counts = [0u32; 10];
        for _ in 0..100_000 {
            counts[z.sample(&mut rng)] += 1;
        }
        for c in counts {
            assert!((c as f64 - 10_000.0).abs() < 600.0, "{counts:?}");
        }
    }

    #[test]
    fn skewed_index_is_seeded_permutation() {
        let a = SkewedIndex::new(500, 1.2, 42);
        let b = SkewedIndex::new(500, 1.2, 42);
        let c = SkewedIndex::new(500, 1.2, 43);
        assert_eq!(a.rank_to_index, b.rank_to_index);
        assert_ne!(a.rank_to_index, c.rank_to_index);
        let mut sorted = a.rank_to_index.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..500).collect::<Vec<_>>());
    }

    #[test]
    fn hash_pool_is_deterministic_and_long_tailed() {
        let a = HashPool::new(500, 20_000, 1.1, 99);
        let b = HashPool::new(500, 20_000, 1.1, 99);
        let c = HashPool::new(500, 20_000, 1.1, 100);
        assert_eq!(a.synthetic(), b.synthetic());
        assert_ne!(a.synthetic()[0], c.synthetic()[0]);
        for f in &a.synthetic()[..50] {
            assert_eq!(f.hash.len(), 64);
            assert!(f
                .hash
                .bytes()
                .all(|x| x.is_ascii_digit() || (b'A'..=b'F').contains(&x)));
            assert!(f.path.ends_with(&f.name));
        }
        let distinct: std::collections::HashSet<_> =
            a.synthetic().iter().map(|f| &f.hash).collect();
        assert_eq!(distinct.len(), 20_000);

        let mut rng = StdRng::seed_from_u64(3);
        let mut seen = std::collections::HashMap::<&str, u32>::new();
        let mut head = 0u32;
        for _ in 0..100_000 {
            match a.sample(&mut rng) {
                Some(f) => *seen.entry(&f.hash).or_default() += 1,
                None => head += 1,
            }
        }
        // Head (profile) gets the majority, tail is wide and mostly rare.
        assert!(head > 50_000, "head draws {head}");
        assert!(seen.len() > 5_000, "distinct tail hashes {}", seen.len());
        let singletons = seen.values().filter(|&&c| c <= 2).count();
        assert!(
            singletons * 2 > seen.len(),
            "most tail hashes should be rare"
        );
    }

    #[test]
    fn hooks_are_noops_without_install_and_do_not_touch_rng() {
        // Nothing in this test binary calls install().
        assert!(!installed());
        let mut a = StdRng::seed_from_u64(5);
        let mut b = StdRng::seed_from_u64(5);
        assert!(sample_synthetic_file(&mut a).is_none());
        assert!(varied_cmdline("cmd.exe").is_none());
        let t = Utc::now();
        let ts = batch_timestamps(t, 37, std::time::Duration::from_millis(986), false, &mut a);
        assert_eq!(ts, vec![t; 37]);
        assert_eq!(a.next_u64(), b.next_u64(), "RNG must be untouched");
    }

    #[test]
    fn jitter_bounds_and_ordering() {
        let mut rng = StdRng::seed_from_u64(11);
        let t = Utc::now();
        let period = std::time::Duration::from_millis(986);
        for _ in 0..200 {
            let ts = batch_timestamps(t, 37, period, true, &mut rng);
            assert_eq!(ts.len(), 37);
            let lo = t - Duration::milliseconds(986);
            assert!(ts.iter().all(|x| *x >= lo && *x <= t));
            // Mostly ascending: at most a few adjacent inversions.
            let inversions = ts.windows(2).filter(|w| w[0] > w[1]).count();
            assert!(inversions <= 8, "{inversions} inversions");
        }
        // Spread, not one shared value.
        let ts = batch_timestamps(t, 37, period, true, &mut rng);
        let distinct: std::collections::HashSet<_> = ts.iter().collect();
        assert!(distinct.len() > 30);
    }

    fn average_over_day(shape: &RateShape) -> f64 {
        let start = DateTime::parse_from_rfc3339("2026-10-06T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let n = 7 * 86_400; // a week of seconds
        (0..n)
            .map(|s| shape.multiplier(start + Duration::seconds(s)))
            .sum::<f64>()
            / n as f64
    }

    #[test]
    fn diurnal_averages_to_target_and_peaks_mid_afternoon() {
        let shape = RateShape {
            diurnal: 0.6,
            burst: None,
            seed: 0,
        };
        assert!((average_over_day(&shape) - 1.0).abs() < 1e-3);
        let at = |h: u32| {
            shape.multiplier(
                DateTime::parse_from_rfc3339(&format!("2026-10-06T{h:02}:00:00Z"))
                    .unwrap()
                    .with_timezone(&Utc),
            )
        };
        assert!((at(14) - 1.6).abs() < 1e-9);
        assert!((at(2) - 0.4).abs() < 1e-9);
    }

    #[test]
    fn burst_averages_to_target_and_is_deterministic() {
        let burst: BurstSpec = "0.2,5,15".parse().unwrap();
        let shape = RateShape {
            diurnal: 0.5,
            burst: Some(burst),
            seed: 1234,
        };
        let avg = average_over_day(&shape);
        assert!((avg - 1.0).abs() < 0.05, "avg multiplier {avg}");
        let minutes = 7 * 1440;
        let bursts = (0..minutes).filter(|m| shape.burst_minute(*m)).count();
        let frac = bursts as f64 / minutes as f64;
        assert!((frac - 0.2).abs() < 0.02, "burst fraction {frac}");
        let same = RateShape {
            diurnal: 0.5,
            burst: Some(burst),
            seed: 1234,
        };
        assert!((0..500).all(|m| shape.burst_minute(m) == same.burst_minute(m)));
        assert!("0.2,0.5,15".parse::<BurstSpec>().is_err());
        assert!("1.2,2,15".parse::<BurstSpec>().is_err());
        assert!("0.2,2".parse::<BurstSpec>().is_err());
    }

    #[test]
    fn flat_shape_is_exactly_one() {
        let shape = RateShape {
            diurnal: 0.0,
            burst: None,
            seed: 9,
        };
        assert!(shape.is_flat());
        assert_eq!(shape.multiplier(Utc::now()), 1.0);
    }

    #[test]
    fn vary_cmdline_keeps_base_prefix() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut changed = 0;
        for _ in 0..1000 {
            let v = vary_cmdline("svchost.exe", &mut rng);
            assert!(v.starts_with("svchost.exe"));
            if v != "svchost.exe" {
                changed += 1;
            }
        }
        assert!((500..700).contains(&changed), "{changed}");
    }
}

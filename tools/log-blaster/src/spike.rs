//! Multi-rhythm spike scheduler.
//!
//! A `SpikeProfile` is a baseline EPS plus a list of overlapping rhythms.
//! Each rhythm has a schedule (periodic / daily / poisson), an envelope
//! (ramp-up → plateau → ramp-down) and a peak EPS. At any moment the
//! effective EPS is `baseline + Σ active rhythm contributions`, and the
//! source-type mix is a weighted blend of each contribution's preferred
//! mix.
//!
//! Rhythms can have negative peak EPS to model traffic *dips* (lunch lull)
//! without removing the variety of the baseline mix. Effective EPS is
//! clamped to zero in the worker loop.

use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Default source-type mix used when neither baseline nor any active rhythm
/// overrides it. Mirrors the historical fixed distribution in `generate_event`.
pub const DEFAULT_MIX: SourceMix = SourceMix {
    sysmon: 0.60,
    winevt: 0.10,
    proxy: 0.12,
    apache: 0.10,
    cloudtrail: 0.08,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct SourceMix {
    #[serde(default)]
    pub sysmon: f64,
    #[serde(default)]
    pub winevt: f64,
    #[serde(default)]
    pub proxy: f64,
    #[serde(default)]
    pub apache: f64,
    #[serde(default)]
    pub cloudtrail: f64,
}

impl SourceMix {
    fn total(&self) -> f64 {
        self.sysmon + self.winevt + self.proxy + self.apache + self.cloudtrail
    }

    /// Renormalize to sum to 1.0. Returns `DEFAULT_MIX` if the input has no
    /// positive weight (degenerate profile).
    pub fn normalized(self) -> Self {
        let t = self.total();
        if t <= 0.0 {
            return DEFAULT_MIX;
        }
        SourceMix {
            sysmon: self.sysmon / t,
            winevt: self.winevt / t,
            proxy: self.proxy / t,
            apache: self.apache / t,
            cloudtrail: self.cloudtrail / t,
        }
    }

    /// Add `other * scale` into self (used to combine per-rhythm mixes
    /// weighted by their EPS contribution).
    fn add_scaled(&mut self, other: &SourceMix, scale: f64) {
        self.sysmon += other.sysmon * scale;
        self.winevt += other.winevt * scale;
        self.proxy += other.proxy * scale;
        self.apache += other.apache * scale;
        self.cloudtrail += other.cloudtrail * scale;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Schedule {
    /// Fires every `interval_secs` seconds with optional ±jitter (0.0–1.0).
    Periodic { interval_secs: u64, #[serde(default)] jitter: f64 },
    /// Fires once per local day at `hh:mm`.
    Daily { hh: u32, mm: u32 },
    /// Inter-arrival times are exponential with mean `mean_interval_secs`.
    Poisson { mean_interval_secs: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(default)]
    pub ramp_up_secs: u64,
    pub plateau_secs: u64,
    #[serde(default)]
    pub ramp_down_secs: u64,
}

impl Envelope {
    pub fn total_secs(&self) -> u64 {
        self.ramp_up_secs + self.plateau_secs + self.ramp_down_secs
    }

    /// Returns a 0.0–1.0 multiplier on `peak_eps` for time `elapsed` since
    /// the spike instance started. Outside the window returns 0.
    fn shape(&self, elapsed_secs: f64) -> f64 {
        let ru = self.ramp_up_secs as f64;
        let pl = self.plateau_secs as f64;
        let rd = self.ramp_down_secs as f64;
        if elapsed_secs < 0.0 {
            0.0
        } else if elapsed_secs < ru {
            if ru == 0.0 { 1.0 } else { elapsed_secs / ru }
        } else if elapsed_secs < ru + pl {
            1.0
        } else if elapsed_secs < ru + pl + rd {
            if rd == 0.0 { 0.0 } else { 1.0 - (elapsed_secs - ru - pl) / rd }
        } else {
            0.0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rhythm {
    pub name: String,
    pub schedule: Schedule,
    pub envelope: Envelope,
    /// Peak contribution. Negative values model dips (e.g. lunch lull).
    pub peak_eps: f64,
    /// Optional per-rhythm source-type mix. Falls back to baseline /
    /// DEFAULT_MIX when omitted. Negative-peak rhythms ignore this and
    /// inherit baseline composition (a dip shouldn't reshape the mix).
    #[serde(default)]
    pub mix: Option<SourceMix>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpikeProfile {
    pub baseline_eps: f64,
    /// Source mix for the baseline EPS. Falls back to `DEFAULT_MIX`.
    #[serde(default)]
    pub baseline_mix: Option<SourceMix>,
    pub rhythms: Vec<Rhythm>,
}

impl SpikeProfile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading spike profile {}", path.display()))?;
        let profile: SpikeProfile = serde_json::from_str(&raw)
            .with_context(|| format!("parsing spike profile {}", path.display()))?;
        profile
            .validate()
            .with_context(|| format!("validating spike profile {}", path.display()))?;
        Ok(profile)
    }

    /// Reject obvious profile bugs at load time: invalid hh/mm in Daily
    /// schedules and zero-length envelopes (no plateau, no ramps) that
    /// would silently never contribute.
    fn validate(&self) -> Result<()> {
        for r in &self.rhythms {
            if let Schedule::Daily { hh, mm } = r.schedule {
                if hh >= 24 {
                    anyhow::bail!("rhythm '{}': daily.hh must be 0..=23, got {}", r.name, hh);
                }
                if mm >= 60 {
                    anyhow::bail!("rhythm '{}': daily.mm must be 0..=59, got {}", r.name, mm);
                }
            }
            if r.envelope.total_secs() == 0 {
                anyhow::bail!(
                    "rhythm '{}': envelope has zero total duration — set plateau_secs or ramps",
                    r.name
                );
            }
        }
        Ok(())
    }

    fn baseline_mix(&self) -> SourceMix {
        self.baseline_mix.unwrap_or(DEFAULT_MIX)
    }
}

/// Snapshot of what the scheduler wants right now: total EPS, the source
/// mix to draw from, and the names of currently active rhythms (for stats).
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub effective_eps: f64,
    pub mix: SourceMix,
    pub active: Vec<ActiveRhythm>,
}

#[derive(Debug, Clone)]
pub struct ActiveRhythm {
    pub name: String,
    pub contribution_eps: f64,
}

/// One in-flight instance of a rhythm. The scheduler holds a Vec of these
/// and prunes them as they age out of their envelope.
#[derive(Debug, Clone)]
struct Instance {
    rhythm_idx: usize,
    started_at: DateTime<Utc>,
    total_secs: u64,
}

/// Mutable per-rhythm scheduler state (next-fire pointer for periodic /
/// poisson, last-fired marker for daily).
#[derive(Debug, Clone)]
enum SchedState {
    Periodic { next_fire_at: DateTime<Utc> },
    Daily { last_fired_date: Option<chrono::NaiveDate> },
    Poisson { next_fire_at: DateTime<Utc> },
}

pub struct Scheduler {
    profile: SpikeProfile,
    state: Vec<SchedState>,
    instances: Vec<Instance>,
}

impl Scheduler {
    pub fn new(profile: SpikeProfile, now: DateTime<Utc>, rng: &mut impl Rng) -> Self {
        let state = profile
            .rhythms
            .iter()
            .map(|r| match &r.schedule {
                Schedule::Periodic { interval_secs, jitter } => SchedState::Periodic {
                    next_fire_at: now + jittered(*interval_secs, *jitter, rng),
                },
                Schedule::Daily { .. } => SchedState::Daily { last_fired_date: None },
                Schedule::Poisson { mean_interval_secs } => SchedState::Poisson {
                    next_fire_at: now + exponential_delay(*mean_interval_secs, rng),
                },
            })
            .collect();
        Self { profile, state, instances: Vec::new() }
    }

    /// Advance scheduler to `now`, firing any newly-due rhythms and pruning
    /// expired instances. Returns the current snapshot.
    pub fn tick(&mut self, now: DateTime<Utc>, rng: &mut impl Rng) -> Snapshot {
        for (idx, rhythm) in self.profile.rhythms.iter().enumerate() {
            match &mut self.state[idx] {
                SchedState::Periodic { next_fire_at } => {
                    if now >= *next_fire_at {
                        self.instances.push(Instance {
                            rhythm_idx: idx,
                            started_at: *next_fire_at,
                            total_secs: rhythm.envelope.total_secs(),
                        });
                        let (interval_secs, jitter) = match &rhythm.schedule {
                            Schedule::Periodic { interval_secs, jitter } => (*interval_secs, *jitter),
                            _ => unreachable!(),
                        };
                        // Anchor on the prior scheduled fire, not `now`, so
                        // phase is preserved across many cycles. If the host
                        // slept and we're now multiple periods behind, advance
                        // the anchor forward without re-firing — single fire
                        // per tick is enough; older instances would prune
                        // immediately anyway. Cap iterations to keep a
                        // multi-day suspend from spinning.
                        *next_fire_at += jittered(interval_secs, jitter, rng);
                        for _ in 0..1000 {
                            if now < *next_fire_at {
                                break;
                            }
                            *next_fire_at += jittered(interval_secs, jitter, rng);
                        }
                    }
                }
                SchedState::Daily { last_fired_date } => {
                    let (hh, mm) = match &rhythm.schedule {
                        Schedule::Daily { hh, mm } => (*hh, *mm),
                        _ => unreachable!(),
                    };
                    let local = now.with_timezone(&Local);
                    let today = local.date_naive();
                    // hh/mm validated at profile load — bounds-check is for
                    // safety against direct in-memory construction in tests.
                    let target = match NaiveTime::from_hms_opt(hh, mm, 0) {
                        Some(t) => t,
                        None => continue,
                    };
                    if local.time() >= target && Some(today) != *last_fired_date {
                        // `with_time(target).single()` returns None for DST
                        // spring-forward ambiguity (skipped hour). Fall back
                        // to the current local time so we still emit *some*
                        // event near the right wall-clock minute.
                        let started_local = local.with_time(target).single().unwrap_or(local);
                        self.instances.push(Instance {
                            rhythm_idx: idx,
                            started_at: started_local.with_timezone(&Utc),
                            total_secs: rhythm.envelope.total_secs(),
                        });
                        *last_fired_date = Some(today);
                    }
                }
                SchedState::Poisson { next_fire_at } => {
                    if now >= *next_fire_at {
                        self.instances.push(Instance {
                            rhythm_idx: idx,
                            started_at: *next_fire_at,
                            total_secs: rhythm.envelope.total_secs(),
                        });
                        let mean = match &rhythm.schedule {
                            Schedule::Poisson { mean_interval_secs } => *mean_interval_secs,
                            _ => unreachable!(),
                        };
                        *next_fire_at = now + exponential_delay(mean, rng);
                    }
                }
            }
        }

        self.instances.retain(|inst| {
            let elapsed = (now - inst.started_at).num_seconds();
            elapsed >= 0 && (elapsed as u64) < inst.total_secs
        });

        let baseline_eps = self.profile.baseline_eps.max(0.0);
        let baseline_mix = self.profile.baseline_mix().normalized();

        let mut effective_eps = self.profile.baseline_eps;
        let mut mix_acc = SourceMix::default();
        mix_acc.add_scaled(&baseline_mix, baseline_eps);
        let mut active = Vec::new();

        for inst in &self.instances {
            let rhythm = &self.profile.rhythms[inst.rhythm_idx];
            let elapsed = (now - inst.started_at).num_seconds() as f64;
            let shape = rhythm.envelope.shape(elapsed);
            let contribution = rhythm.peak_eps * shape;
            if contribution.abs() < f64::EPSILON {
                continue;
            }
            effective_eps += contribution;
            // Negative contributions inherit baseline mix (a dip shouldn't
            // bend the source-type distribution). Positive contributions
            // use the rhythm's mix if it specifies one.
            let mix = if contribution > 0.0 {
                rhythm.mix.map(|m| m.normalized()).unwrap_or(baseline_mix)
            } else {
                baseline_mix
            };
            mix_acc.add_scaled(&mix, contribution);
            active.push(ActiveRhythm {
                name: rhythm.name.clone(),
                contribution_eps: contribution,
            });
        }

        let mix = if mix_acc.total() > 0.0 { mix_acc.normalized() } else { baseline_mix };
        Snapshot {
            effective_eps: effective_eps.max(0.0),
            mix,
            active,
        }
    }
}

fn jittered(interval_secs: u64, jitter: f64, rng: &mut impl Rng) -> chrono::Duration {
    let j = jitter.clamp(0.0, 1.0);
    let factor = if j == 0.0 { 1.0 } else { 1.0 + rng.random_range(-j..j) };
    let secs = ((interval_secs as f64) * factor).max(1.0) as i64;
    chrono::Duration::seconds(secs)
}

fn exponential_delay(mean_interval_secs: u64, rng: &mut impl Rng) -> chrono::Duration {
    // Inverse-CDF sampling. Clamp u away from 0 to avoid -ln(0) = ∞.
    let u: f64 = rng.random_range(f64::EPSILON..1.0);
    let secs = -(mean_interval_secs as f64) * u.ln();
    chrono::Duration::seconds(secs.max(1.0) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn envelope_shape_phases() {
        let env = Envelope { ramp_up_secs: 10, plateau_secs: 20, ramp_down_secs: 10 };
        assert!((env.shape(0.0) - 0.0).abs() < 1e-9);
        assert!((env.shape(5.0) - 0.5).abs() < 1e-9);
        assert!((env.shape(15.0) - 1.0).abs() < 1e-9);
        assert!((env.shape(35.0) - 0.5).abs() < 1e-9);
        assert!((env.shape(41.0) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn negative_rhythm_does_not_reshape_mix() {
        let profile = SpikeProfile {
            baseline_eps: 1000.0,
            baseline_mix: None,
            rhythms: vec![Rhythm {
                name: "lunch_dip".into(),
                schedule: Schedule::Periodic { interval_secs: 1, jitter: 0.0 },
                envelope: Envelope { ramp_up_secs: 0, plateau_secs: 60, ramp_down_secs: 0 },
                peak_eps: -400.0,
                mix: Some(SourceMix {
                    // Even if someone fills this in, negative contribution
                    // should ignore it.
                    sysmon: 0.0,
                    winevt: 1.0,
                    proxy: 0.0,
                    apache: 0.0,
                    cloudtrail: 0.0,
                }),
            }],
        };
        let mut rng = rand::rng();
        let t0 = now();
        let mut sched = Scheduler::new(profile, t0, &mut rng);
        // Periodic schedule first fires at t0 + interval_secs, so tick past it.
        let snap = sched.tick(t0 + chrono::Duration::seconds(2), &mut rng);
        assert!(
            snap.effective_eps < 1000.0,
            "dip should drop baseline; got {}",
            snap.effective_eps
        );
        // Mix should still be the default (sysmon-dominant), not winevt-dominant.
        assert!(snap.mix.sysmon > snap.mix.winevt);
    }

    #[test]
    fn invalid_daily_hh_is_rejected() {
        let profile = SpikeProfile {
            baseline_eps: 0.0,
            baseline_mix: None,
            rhythms: vec![Rhythm {
                name: "bad".into(),
                schedule: Schedule::Daily { hh: 25, mm: 0 },
                envelope: Envelope { ramp_up_secs: 0, plateau_secs: 60, ramp_down_secs: 0 },
                peak_eps: 1.0,
                mix: None,
            }],
        };
        let err = profile.validate().unwrap_err().to_string();
        assert!(err.contains("daily.hh"), "got: {}", err);
    }

    #[test]
    fn zero_duration_envelope_is_rejected() {
        let profile = SpikeProfile {
            baseline_eps: 0.0,
            baseline_mix: None,
            rhythms: vec![Rhythm {
                name: "ghost".into(),
                schedule: Schedule::Periodic { interval_secs: 1, jitter: 0.0 },
                envelope: Envelope { ramp_up_secs: 0, plateau_secs: 0, ramp_down_secs: 0 },
                peak_eps: 1.0,
                mix: None,
            }],
        };
        let err = profile.validate().unwrap_err().to_string();
        assert!(err.contains("zero total duration"), "got: {}", err);
    }

    #[test]
    fn periodic_does_not_drift_across_cycles() {
        // Anchor stays on the prior scheduled time, so after N firings the
        // cumulative drift is bounded by jitter (0 here) regardless of how
        // late `tick` is called relative to the schedule.
        let interval = 10_i64;
        let profile = SpikeProfile {
            baseline_eps: 0.0,
            baseline_mix: None,
            rhythms: vec![Rhythm {
                name: "metronome".into(),
                schedule: Schedule::Periodic { interval_secs: interval as u64, jitter: 0.0 },
                envelope: Envelope { ramp_up_secs: 0, plateau_secs: 1, ramp_down_secs: 0 },
                peak_eps: 1.0,
                mix: None,
            }],
        };
        let mut rng = rand::rng();
        let t0 = now();
        let mut sched = Scheduler::new(profile, t0, &mut rng);
        // Tick at +11, +25, +39 — each is several seconds *after* the scheduled
        // fire (10, 20/30, 30/40). The anchor must still land on multiples of
        // the original interval, not on the observation times.
        let _ = sched.tick(t0 + chrono::Duration::seconds(11), &mut rng);
        // Internal anchor should now be t0+20 (interval after t0+10).
        let _ = sched.tick(t0 + chrono::Duration::seconds(25), &mut rng);
        let _ = sched.tick(t0 + chrono::Duration::seconds(39), &mut rng);
        // After many cycles, the next scheduled fire must be close to
        // t0 + k * interval for some integer k, not t0 + 39 + interval = 49.
        if let SchedState::Periodic { next_fire_at } = &sched.state[0] {
            let offset = (*next_fire_at - t0).num_seconds();
            assert_eq!(offset % interval, 0, "anchor drifted: offset={}", offset);
        } else {
            panic!("expected Periodic state");
        }
    }

    #[test]
    fn periodic_fires_repeatedly() {
        let profile = SpikeProfile {
            baseline_eps: 0.0,
            baseline_mix: None,
            rhythms: vec![Rhythm {
                name: "tick".into(),
                schedule: Schedule::Periodic { interval_secs: 10, jitter: 0.0 },
                envelope: Envelope { ramp_up_secs: 0, plateau_secs: 2, ramp_down_secs: 0 },
                peak_eps: 1000.0,
                mix: None,
            }],
        };
        let mut rng = rand::rng();
        let t0 = now();
        let mut sched = Scheduler::new(profile, t0, &mut rng);
        // First fire at t0 + 10s
        let s1 = sched.tick(t0 + chrono::Duration::seconds(11), &mut rng);
        assert_eq!(s1.active.len(), 1, "should be active in plateau");
        // After plateau (2s), should be idle by t0 + 13s
        let s2 = sched.tick(t0 + chrono::Duration::seconds(15), &mut rng);
        assert!(s2.active.is_empty(), "should have aged out");
        // Second fire at t0 + 20s
        let s3 = sched.tick(t0 + chrono::Duration::seconds(21), &mut rng);
        assert_eq!(s3.active.len(), 1, "should fire again");
    }
}

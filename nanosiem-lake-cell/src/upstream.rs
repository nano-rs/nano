// SPDX-License-Identifier: AGPL-3.0-or-later

//! Upstream readiness: the cell's own egress watchdog (NAN-3440, cell
//! feature `upstream_readiness_v1`).
//!
//! On 2026-10-09 two lake-cells nodes lost external egress while in-cluster
//! traffic, DNS and kubelet `Ready` stayed fine. The cells on them could
//! reach neither R2 nor the control plane, yet nothing said so, nothing moved
//! them and nothing alerted. This module makes that gray failure visible from
//! inside the pod, as a SIGNAL (never readiness, see below):
//!
//! - `upstream_readiness` in `cell.json` lists 1–4 HTTPS targets (e.g. the
//!   R2 account endpoint and the control-plane health route). Absent = the
//!   module is off and the cell behaves exactly as before.
//! - A background task GETs every target each `interval_secs` with a
//!   `timeout_secs` budget, no redirects and no pooled connections (every
//!   probe is a fresh TCP + TLS handshake). **Any** HTTP response, whatever
//!   its status, counts as reachable: the path out worked. A transport, TLS
//!   or timeout error counts as unreachable and is recorded as a short error
//!   class (never the URL, which may carry an account id).
//! - [`verdict`] (pure) turns the per-target state into the upstream
//!   verdict: upstream is not ready while at least two targets (every target when only one is
//!   configured) have each been failing for at least `not_ready_after_secs`
//!   since their last success. One destination failing alone is never
//!   enough: on 2026-10-09 22:01Z a cell's credential refresh timed out
//!   against api.nano.rs during a control-plane deploy, the retry succeeded
//!   80 s later and ingest never stopped. Only object storage AND the
//!   control plane both unreachable means the cell cannot commit ingest.
//!   The supervisor's start
//!   counts as a success, so a fresh pod is never instantly not-ready, and
//!   one success makes the target healthy again.
//! - The verdict NEVER gates `/readyz` (unchanged): if R2 and the control
//!   plane are unreachable cluster-wide (an R2 or control outage), every
//!   cell would drop out of its Service and a partial degradation would
//!   become a total search outage, while the cells can still serve hydrated
//!   data (stale-but-serving beats an outage). Instead `/healthz` (always
//!   200) adds the public boolean `upstream_ready`, which the platform's node
//!   egress controller reads as its ingest-stall corroboration (combined
//!   with node-level evidence and a cluster-wide hold). The cell signal
//!   `upstream_unreachable` (seconds) warns at half the threshold and pages
//!   at the threshold; `/metrics` has `nano_cell_upstream_ready` and
//!   `nano_cell_upstream_unreachable_seconds{target}`.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn default_interval() -> u64 {
    15
}
fn default_timeout() -> u64 {
    5
}
fn default_not_ready_after() -> u64 {
    300
}

/// `upstream_readiness` in `cell.json`. Present = the watchdog is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamReadinessConfig {
    /// 1–4 targets, probed every interval.
    pub targets: Vec<UpstreamTarget>,
    /// Probe period (5..=300 s).
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Per-probe budget for connect + TLS + response headers (1..=30 s,
    /// below `interval_secs`).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Two targets (R2 AND control; every target when only one is configured)
    /// each failing this long since their last success make the upstream
    /// verdict not ready, i.e. `/healthz` `upstream_ready: false` (30..=3600 s,
    /// at least two intervals). One target alone never does.
    #[serde(default = "default_not_ready_after")]
    pub not_ready_after_secs: u64,
}

/// One probed endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTarget {
    /// `^[a-z][a-z0-9_]{0,31}$`, unique; the only identifier ever shown.
    pub name: String,
    /// `https://` URL without userinfo. Never logged or reported.
    pub url: String,
}

fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

impl UpstreamReadinessConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!((1..=4).contains(&self.targets.len()), "upstream_readiness.targets: 1..=4 entries");
        let mut seen = std::collections::HashSet::new();
        for t in &self.targets {
            anyhow::ensure!(valid_name(&t.name), "upstream_readiness target name {:?} must match ^[a-z][a-z0-9_]{{0,31}}$", t.name);
            anyhow::ensure!(seen.insert(t.name.as_str()), "upstream_readiness target {:?} listed twice", t.name);
            // The URL itself is never echoed: it may name an account.
            let url = reqwest::Url::parse(&t.url)
                .map_err(|_| anyhow::anyhow!("upstream_readiness target {:?}: url does not parse", t.name))?;
            anyhow::ensure!(url.scheme() == "https", "upstream_readiness target {:?}: url must be https", t.name);
            anyhow::ensure!(url.host_str().is_some_and(|h| !h.is_empty()), "upstream_readiness target {:?}: url needs a host", t.name);
            anyhow::ensure!(
                url.username().is_empty() && url.password().is_none(),
                "upstream_readiness target {:?}: url must not carry credentials",
                t.name
            );
        }
        anyhow::ensure!((5..=300).contains(&self.interval_secs), "upstream_readiness.interval_secs must be 5..=300");
        anyhow::ensure!(
            (1..=30).contains(&self.timeout_secs) && self.timeout_secs < self.interval_secs,
            "upstream_readiness.timeout_secs must be 1..=30 and below interval_secs"
        );
        anyhow::ensure!(
            (30..=3600).contains(&self.not_ready_after_secs) && self.not_ready_after_secs >= 2 * self.interval_secs,
            "upstream_readiness.not_ready_after_secs must be 30..=3600 and at least two intervals"
        );
        Ok(())
    }

    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
    pub fn not_ready_after(&self) -> Duration {
        Duration::from_secs(self.not_ready_after_secs)
    }
}

/// What the probe loop knows about one target.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetState {
    pub name: String,
    /// Last probe that got any HTTP response (the supervisor start before
    /// the first one: the start grace).
    pub last_ok: Instant,
    /// Error class of the latest failed probe.
    pub last_error: Option<String>,
    /// Failed probes since the last success (0 = healthy).
    pub consecutive_failures: u32,
}

impl TargetState {
    pub fn new(name: impl Into<String>, started: Instant) -> Self {
        Self { name: name.into(), last_ok: started, last_error: None, consecutive_failures: 0 }
    }

    /// Fold one probe result in.
    pub fn record(&mut self, result: Result<(), String>, now: Instant) {
        match result {
            Ok(()) => {
                self.last_ok = now;
                self.last_error = None;
                self.consecutive_failures = 0;
            }
            Err(class) => {
                self.last_error = Some(class);
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            }
        }
    }

    /// Seconds this target has been failing since its last success (0 when
    /// its latest probe succeeded).
    fn unreachable_secs(&self, now: Instant) -> f64 {
        if self.consecutive_failures == 0 {
            0.0
        } else {
            now.saturating_duration_since(self.last_ok).as_secs_f64()
        }
    }
}

/// One target in the verdict (name, never the URL).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TargetView {
    pub name: String,
    /// The latest probe succeeded (or none has run yet).
    pub ok: bool,
    /// Seconds since the last success (since start before the first).
    pub last_ok_age_s: f64,
    /// Seconds failing since the last success (0 when ok).
    pub unreachable_s: f64,
    pub consecutive_failures: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// The readiness decision.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub ready: bool,
    /// Set when not ready, e.g. `upstream_unreachable: r2 unreachable for
    /// 212s (last error: connect timeout); control ok`.
    pub reason: Option<String>,
    /// Largest [`TargetView::unreachable_s`] (0 when every target is ok).
    pub worst_unreachable_secs: f64,
    /// How long [`corroborating_targets`] distinct targets have ALL been
    /// failing: the k-th largest `unreachable_s`. Readiness and the
    /// `upstream_unreachable` signal use this, never one target alone.
    pub stalled_secs: f64,
    pub targets: Vec<TargetView>,
}

impl Verdict {
    /// Per-target summary: `r2 unreachable for 212s (last error: …); control ok`.
    fn summary(&self) -> String {
        self.targets
            .iter()
            .map(|t| {
                if t.ok {
                    format!("{} ok", t.name)
                } else {
                    format!("{} unreachable for {:.0}s (last error: {})", t.name, t.unreachable_s,
                        t.last_error.as_deref().unwrap_or("unknown"))
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Signal detail: the reason when not ready, the summary while a target
    /// is failing but under the threshold, nothing when all are ok.
    pub fn detail(&self) -> Option<String> {
        self.reason.clone().or_else(|| (self.worst_unreachable_secs > 0.0).then(|| format!("upstream_degraded: {}", self.summary())))
    }
}

/// Distinct targets that must all be failing before the upstream verdict is not ready:
/// two, or every target when fewer are configured.
pub fn corroborating_targets(n: usize) -> usize {
    n.min(2)
}

/// Pure upstream verdict (a signal, never `/readyz`): not ready while [`corroborating_targets`]
/// targets have each been failing for at least `not_ready_after` since their
/// last success.
pub fn verdict(targets: &[TargetState], not_ready_after: Duration, now: Instant) -> Verdict {
    let views: Vec<TargetView> = targets
        .iter()
        .map(|t| TargetView {
            name: t.name.clone(),
            ok: t.consecutive_failures == 0,
            last_ok_age_s: round1(now.saturating_duration_since(t.last_ok).as_secs_f64()),
            unreachable_s: round1(t.unreachable_secs(now)),
            consecutive_failures: t.consecutive_failures,
            last_error: t.last_error.clone(),
        })
        .collect();
    let threshold = not_ready_after.as_secs_f64();
    let mut ages: Vec<f64> = targets.iter().map(|t| t.unreachable_secs(now)).collect();
    ages.sort_by(|a, b| b.total_cmp(a));
    let worst = ages.first().copied().unwrap_or(0.0);
    let k = corroborating_targets(targets.len());
    let stalled = if k == 0 { 0.0 } else { ages[k - 1] };
    let ready = stalled < threshold;
    let mut v = Verdict { ready, reason: None, worst_unreachable_secs: round1(worst), stalled_secs: round1(stalled), targets: views };
    if !ready {
        v.reason = Some(format!("upstream_unreachable: {}", v.summary()));
    }
    v
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// A short, URL-free class for a failed probe.
fn error_class(e: &reqwest::Error) -> String {
    let mut chain: Vec<String> = Vec::new();
    let mut io_kind = None;
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            io_kind.get_or_insert(io.kind());
        }
        chain.push(s.to_string().to_ascii_lowercase());
        src = s.source();
    }
    let has = |needle: &str| chain.iter().any(|m| m.contains(needle));
    let class = if e.is_timeout() || io_kind == Some(std::io::ErrorKind::TimedOut) {
        if e.is_connect() { "connect timeout" } else { "timeout" }
    } else if has("dns error") || has("failed to lookup") {
        "dns error"
    } else if io_kind == Some(std::io::ErrorKind::ConnectionRefused) {
        "connection refused"
    } else if io_kind == Some(std::io::ErrorKind::ConnectionReset) {
        "connection reset"
    } else if has("certificate") || has("tls") || has("handshake") {
        "tls error"
    } else if io_kind == Some(std::io::ErrorKind::NetworkUnreachable) || io_kind == Some(std::io::ErrorKind::HostUnreachable) {
        "network unreachable"
    } else if e.is_connect() {
        "connect error"
    } else {
        "transport error"
    };
    class.to_owned()
}

/// The probe client: rustls, no redirects, no pooled connections.
pub fn client(timeout: Duration) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout)
        .pool_max_idle_per_host(0)
        .build()?)
}

/// One probe: any HTTP response is reachable; the body is never read.
pub async fn probe(client: &reqwest::Client, url: &str) -> Result<(), String> {
    match client.get(url).send().await {
        Ok(_resp) => Ok(()),
        Err(e) => Err(error_class(&e)),
    }
}

/// The running watchdog: config, per-target state, the probe loop.
pub struct UpstreamMonitor {
    cfg: UpstreamReadinessConfig,
    state: Mutex<Vec<TargetState>>,
}

impl UpstreamMonitor {
    pub fn new(cfg: UpstreamReadinessConfig, started: Instant) -> Self {
        let state = cfg.targets.iter().map(|t| TargetState::new(t.name.clone(), started)).collect();
        Self { cfg, state: Mutex::new(state) }
    }

    pub fn config(&self) -> &UpstreamReadinessConfig {
        &self.cfg
    }

    pub fn verdict(&self, now: Instant) -> Verdict {
        verdict(&self.state.lock().unwrap(), self.cfg.not_ready_after(), now)
    }

    /// Fold a probe result for target `idx` in, logging transitions.
    pub fn record(&self, idx: usize, result: Result<(), String>, now: Instant) {
        let threshold = self.cfg.not_ready_after();
        let mut state = self.state.lock().unwrap();
        let Some(t) = state.get_mut(idx) else { return };
        let was_failing = t.consecutive_failures > 0;
        let was_down = now.saturating_duration_since(t.last_ok) >= threshold && was_failing;
        t.record(result, now);
        match (was_failing, t.consecutive_failures > 0) {
            (false, true) => tracing::warn!(target_name = %t.name, error = t.last_error.as_deref().unwrap_or(""),
                "upstream probe failed"),
            (true, false) => tracing::info!(target_name = %t.name, was_down, "upstream reachable again"),
            _ => {}
        }
        if !was_down && t.unreachable_secs(now) >= threshold.as_secs_f64() {
            tracing::error!(target_name = %t.name, error = t.last_error.as_deref().unwrap_or(""),
                not_ready_after_secs = self.cfg.not_ready_after_secs,
                "upstream target unreachable past the threshold (upstream_ready goes false once two targets are)");
        }
    }

    /// Probe every target each interval until `halted()`.
    pub async fn run(self: std::sync::Arc<Self>, halted: impl Fn() -> bool + Send + 'static) {
        let client = match client(self.cfg.timeout()) {
            Ok(c) => c,
            Err(e) => {
                // Without a client every target stays unprobed, ages past
                // the threshold and upstream_ready goes false: loud, not silent.
                tracing::error!(error = %e, "upstream readiness: probe client unavailable");
                return self.fail_forever(halted).await;
            }
        };
        let mut tick = tokio::time::interval(self.cfg.interval());
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if halted() {
                return;
            }
            let mut set = tokio::task::JoinSet::new();
            for (idx, t) in self.cfg.targets.iter().enumerate() {
                let (client, url) = (client.clone(), t.url.clone());
                set.spawn(async move { (idx, probe(&client, &url).await) });
            }
            while let Some(done) = set.join_next().await {
                if let Ok((idx, result)) = done {
                    self.record(idx, result, Instant::now());
                }
            }
        }
    }

    async fn fail_forever(&self, halted: impl Fn() -> bool) {
        let mut tick = tokio::time::interval(self.cfg.interval());
        while !halted() {
            tick.tick().await;
            for idx in 0..self.cfg.targets.len() {
                self.record(idx, Err("probe client unavailable".into()), Instant::now());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(v: serde_json::Value) -> serde_json::Result<UpstreamReadinessConfig> {
        serde_json::from_value(v)
    }

    fn two() -> serde_json::Value {
        serde_json::json!({"targets": [
            {"name": "r2", "url": "https://acct.r2.cloudflarestorage.com/"},
            {"name": "control", "url": "https://api.nano.rs/api/health"}]})
    }

    #[test]
    fn config_defaults_and_validation() {
        let c = cfg(two()).unwrap();
        c.validate().unwrap();
        assert_eq!((c.interval_secs, c.timeout_secs, c.not_ready_after_secs), (15, 5, 300));
        let bad = |patch: serde_json::Value| {
            let mut v = two();
            v.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
            cfg(v).unwrap().validate().is_err()
        };
        // Scheme, credentials, host.
        assert!(bad(serde_json::json!({"targets": [{"name": "r2", "url": "http://acct.r2.cloudflarestorage.com/"}]})));
        assert!(bad(serde_json::json!({"targets": [{"name": "r2", "url": "https://user:pw@example.com/"}]})));
        assert!(bad(serde_json::json!({"targets": [{"name": "r2", "url": "not a url"}]})));
        // Names: duplicates, shape.
        assert!(bad(serde_json::json!({"targets": [{"name": "r2", "url": "https://a.example/"}, {"name": "r2", "url": "https://b.example/"}]})));
        for name in ["", "R2", "2r", "r-2", "a".repeat(33).as_str()] {
            assert!(bad(serde_json::json!({"targets": [{"name": name, "url": "https://a.example/"}]})), "{name}");
        }
        assert!(!bad(serde_json::json!({"targets": [{"name": "a".repeat(32), "url": "https://a.example/"}]})));
        // Count.
        assert!(bad(serde_json::json!({"targets": []})));
        let five: Vec<_> = (0..5).map(|i| serde_json::json!({"name": format!("t{i}"), "url": "https://a.example/"})).collect();
        assert!(bad(serde_json::json!({"targets": five})));
        // Timings.
        assert!(bad(serde_json::json!({"timeout_secs": 15})), "timeout >= interval");
        assert!(bad(serde_json::json!({"interval_secs": 10, "timeout_secs": 10})));
        assert!(bad(serde_json::json!({"interval_secs": 4})));
        assert!(bad(serde_json::json!({"interval_secs": 301})));
        assert!(bad(serde_json::json!({"timeout_secs": 0})));
        assert!(bad(serde_json::json!({"not_ready_after_secs": 29})));
        assert!(bad(serde_json::json!({"not_ready_after_secs": 3601})));
        assert!(bad(serde_json::json!({"interval_secs": 60, "not_ready_after_secs": 90})), "under two intervals");
        assert!(!bad(serde_json::json!({"interval_secs": 60, "not_ready_after_secs": 120})));
        // Unknown keys refused.
        assert!(cfg(serde_json::json!({"targets": [{"name": "r2", "url": "https://a.example/", "x": 1}]})).is_err());
        let mut v = two();
        v["nope"] = 1.into();
        assert!(cfg(v).is_err());
    }

    #[test]
    fn verdict_start_grace() {
        let t0 = Instant::now();
        let after = Duration::from_secs(180);
        let mut s = vec![TargetState::new("r2", t0), TargetState::new("control", t0)];
        // No probe yet, well past the threshold: still ready (nothing failed).
        assert!(verdict(&s, after, t0 + Duration::from_secs(600)).ready);
        // Failing from the first probe: the start counts as the last success.
        s[0].record(Err("connect timeout".into()), t0 + Duration::from_secs(15));
        let v = verdict(&s, after, t0 + Duration::from_secs(100));
        assert!(v.ready && v.reason.is_none());
        assert_eq!(v.worst_unreachable_secs, 100.0);
        assert_eq!(v.stalled_secs, 0.0);
        assert!(v.detail().unwrap().starts_with("upstream_degraded: r2 unreachable for 100s"));
    }

    /// 2026-10-09 22:01Z: api.nano.rs timed out during a control-plane
    /// deploy while R2 answered. However long one target fails alone, the
    /// cell stays ready (and the signal stays at 0): it only degrades.
    #[test]
    fn verdict_one_target_alone_never_makes_the_cell_not_ready() {
        let t0 = Instant::now();
        let after = Duration::from_secs(300);
        let mut s = vec![TargetState::new("r2", t0), TargetState::new("control", t0)];
        for i in 1..=60u64 {
            s[0].record(Ok(()), t0 + Duration::from_secs(15 * i));
            s[1].record(Err("timeout".into()), t0 + Duration::from_secs(15 * i));
        }
        let v = verdict(&s, after, t0 + Duration::from_secs(900));
        assert!(v.ready && v.reason.is_none());
        assert_eq!((v.worst_unreachable_secs, v.stalled_secs), (900.0, 0.0));
        assert_eq!(v.detail().as_deref(), Some("upstream_degraded: r2 ok; control unreachable for 900s (last error: timeout)"));
    }

    #[test]
    fn verdict_both_targets_down_then_one_recovers() {
        let t0 = Instant::now();
        let after = Duration::from_secs(180);
        let mut s = vec![TargetState::new("r2", t0), TargetState::new("control", t0)];
        s[0].record(Ok(()), t0 + Duration::from_secs(10));
        s[1].record(Ok(()), t0 + Duration::from_secs(40));
        for i in 1..=15u64 {
            s[0].record(Err("connect timeout".into()), t0 + Duration::from_secs(10 + 15 * i));
            s[1].record(Err("connect timeout".into()), t0 + Duration::from_secs(40 + 15 * i));
        }
        // r2 failing 212 s, control 182 s: both past 180 s.
        let now = t0 + Duration::from_secs(222);
        let v = verdict(&s, after, now);
        assert!(!v.ready);
        assert_eq!(v.reason.as_deref(), Some(
            "upstream_unreachable: r2 unreachable for 212s (last error: connect timeout); control unreachable for 182s (last error: connect timeout)"));
        assert_eq!((v.worst_unreachable_secs, v.stalled_secs), (212.0, 182.0));
        assert_eq!(v.detail(), v.reason);
        assert_eq!(v.targets[0].consecutive_failures, 15);
        // The second-longest failure (control, 182 s) sets the clock, not the longest.
        assert!(verdict(&s, Duration::from_secs(183), now).ready);
        assert!(!verdict(&s, Duration::from_secs(182), now).ready);
        // One success on either target: ready again at once.
        s[1].record(Ok(()), now);
        let v = verdict(&s, after, now + Duration::from_secs(1));
        assert!(v.ready && v.reason.is_none());
        assert_eq!(v.stalled_secs, 0.0);
        assert!(v.detail().unwrap().starts_with("upstream_degraded: r2 unreachable"));
    }

    #[test]
    fn verdict_single_configured_target_is_its_own_corroboration() {
        assert_eq!((corroborating_targets(1), corroborating_targets(2), corroborating_targets(4)), (1, 2, 2));
        let t0 = Instant::now();
        let mut s = vec![TargetState::new("r2", t0)];
        s[0].record(Err("timeout".into()), t0 + Duration::from_secs(5));
        assert!(!verdict(&s, Duration::from_secs(60), t0 + Duration::from_secs(61)).ready);
    }

    #[test]
    fn verdict_all_ok_is_ready() {
        let t0 = Instant::now();
        let mut s = vec![TargetState::new("r2", t0), TargetState::new("control", t0)];
        for t in &mut s {
            t.record(Ok(()), t0 + Duration::from_secs(5));
        }
        let v = verdict(&s, Duration::from_secs(30), t0 + Duration::from_secs(20));
        assert!(v.ready && v.reason.is_none());
        assert_eq!(v.worst_unreachable_secs, 0.0);
        assert_eq!(v.targets[0].last_ok_age_s, 15.0);
    }

    #[test]
    fn both_down_names_both() {
        let t0 = Instant::now();
        let mut s = vec![TargetState::new("r2", t0), TargetState::new("control", t0)];
        s[0].record(Err("dns error".into()), t0 + Duration::from_secs(1));
        s[1].record(Err("tls error".into()), t0 + Duration::from_secs(1));
        let v = verdict(&s, Duration::from_secs(60), t0 + Duration::from_secs(61));
        assert_eq!(v.reason.as_deref(), Some(
            "upstream_unreachable: r2 unreachable for 61s (last error: dns error); control unreachable for 61s (last error: tls error)"));
    }

    /// A real probe against a closed loopback port: a transport failure
    /// recorded as a URL-free class.
    #[tokio::test]
    async fn probe_classifies_refused_without_the_url() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let c = client(Duration::from_secs(2)).unwrap();
        let err = probe(&c, &format!("https://127.0.0.1:{port}/secret-path")).await.unwrap_err();
        assert!(!err.contains("127.0.0.1") && !err.contains("secret"), "{err}");
        assert!(["connection refused", "connect error"].contains(&err.as_str()), "{err}");
    }

    /// A listener that never answers TLS: the probe times out.
    #[tokio::test]
    async fn probe_times_out_on_a_silent_peer() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                if let Ok((s, _)) = l.accept().await {
                    held.push(s);
                }
            }
        });
        let c = client(Duration::from_millis(300)).unwrap();
        let err = probe(&c, &format!("https://127.0.0.1:{port}/")).await.unwrap_err();
        hold.abort();
        assert!(err.contains("timeout"), "{err}");
    }
}

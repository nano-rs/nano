//! Public-benchmark plumbing (`benchmarks/public/`).
//!
//! * [`Router`]: nano v2 binds every ingest token to ONE log source, so a
//!   mixed-source blast needs one token per `source_type`. `--tokens-file`
//!   maps each source type to its token; events are grouped by source type
//!   and each group is posted with its own bearer token.
//! * Markers: with `--run-id` and a `bench_marker` entry in the tokens file,
//!   every batch also carries one sequenced marker record. The collector
//!   counts them in ClickHouse; `count() == uniqExact(seq) == markers_sent`
//!   proves every accepted batch landed exactly once.
//! * [`RunSummary`]: what the sender saw, written as JSON at exit so the
//!   results step never scrapes logs.
//! * [`run_output_mode`]: offline, single-threaded generation to an NDJSON
//!   file on a simulated clock. With `--seed` the file is byte-for-byte
//!   reproducible; this is how the published sample day is made.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::Client;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::path::Path;

use event_core::entity::WorldState;
use event_core::event::Event;
use event_core::generators::{
    ApacheGenerator, CloudTrailGenerator, LateralChainGenerator, ProxyGenerator, SysmonGenerator,
    WindowsEventGenerator,
};
use event_core::http::{send_batch_with_retry, Transport};

/// `--tokens-file` key (and record `source_type`) for marker records. Bind it
/// to a JSON log source (e.g. the first-party `json_generic` parser).
pub const MARKER_SOURCE: &str = "bench_marker";

/// Per-source-type transports. Falls back to the default transport for any
/// source type the tokens file does not name.
pub struct Router {
    default: Transport,
    by_source: HashMap<String, Transport>,
}

/// Outcome of one routed send, split by what the counters care about.
#[derive(Default, Debug, Clone, Copy)]
pub struct SendOutcome {
    pub events_ok: u64,
    pub events_failed: u64,
    pub markers_ok: u64,
    pub markers_failed: u64,
}

impl Router {
    /// `url` is the resolved ingest URL; `tokens_file` is a JSON object
    /// `{ "<source_type>": "<ingest token>", ... }`. Token values are never
    /// logged.
    pub fn new(url: &str, default: Transport, tokens_file: Option<&Path>) -> Result<Self> {
        let mut by_source = HashMap::new();
        if let Some(path) = tokens_file {
            if !matches!(default, Transport::Vector { .. }) {
                bail!("--tokens-file only applies to the Vector HTTP lane (not --hec/--tenzir)");
            }
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("read --tokens-file {}", path.display()))?;
            let map: HashMap<String, String> =
                serde_json::from_str(&raw).context("--tokens-file must be a JSON object of strings")?;
            for (source_type, token) in map {
                if token.trim().is_empty() {
                    bail!("--tokens-file: empty token for {source_type}");
                }
                by_source.insert(
                    source_type,
                    Transport::Vector {
                        url: url.to_string(),
                        token: Some(token),
                    },
                );
            }
            let mut names: Vec<&String> = by_source.keys().collect();
            names.sort();
            tracing::info!("Per-source ingest tokens loaded for: {:?}", names);
        }
        Ok(Self { default, by_source })
    }

    pub fn has_marker_lane(&self) -> bool {
        self.by_source.contains_key(MARKER_SOURCE)
    }

    fn transport_for(&self, source_type: &str) -> &Transport {
        self.by_source.get(source_type).unwrap_or(&self.default)
    }

    /// Group `events` by source type (stable order) and post each group with
    /// its own token. A failed group never aborts the others. Takes the batch
    /// by value so grouping moves events instead of cloning them (blast mode
    /// pushes 100k+ events/s through here).
    pub async fn send(&self, client: &Client, events: Vec<Event>, retries: u32) -> SendOutcome {
        let mut order: Vec<String> = Vec::new();
        let mut groups: HashMap<String, Vec<Event>> = HashMap::new();
        for e in events {
            match groups.get_mut(&e.source_type) {
                Some(g) => g.push(e),
                None => {
                    order.push(e.source_type.clone());
                    groups.insert(e.source_type.clone(), vec![e]);
                }
            }
        }
        let mut out = SendOutcome::default();
        for key in &order {
            let key = key.as_str();
            let group = &groups[key];
            let n = group.len() as u64;
            let marker = key == MARKER_SOURCE;
            match send_batch_with_retry(client, self.transport_for(key), group, retries).await {
                Ok(()) if marker => out.markers_ok += n,
                Ok(()) => out.events_ok += n,
                Err(e) => {
                    tracing::error!("send {} x{} failed after retries: {}", key, n, e);
                    if marker {
                        out.markers_failed += n
                    } else {
                        out.events_failed += n
                    }
                }
            }
        }
        out
    }
}

/// One marker record. The raw line is a JSON object so a JSON parser keeps
/// it whole as `message`; the collector extracts `nanobench_seq` from it.
pub fn marker_event(run_id: &str, worker: usize, seq: u64, ts: DateTime<Utc>) -> Event {
    let message = serde_json::json!({
        "nanobench_run": run_id,
        "nanobench_worker": worker,
        "nanobench_seq": seq,
        "message": format!("nanobench marker run={run_id} seq={seq}"),
        "timestamp": ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
    .to_string();
    Event {
        message,
        timestamp: ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        source_type: MARKER_SOURCE.to_string(),
        display_label: format!("marker {seq}"),
    }
}

/// Sender-side view of a run, written by `--summary-json`.
#[derive(Debug, Serialize, Default)]
pub struct RunSummary {
    pub tool: &'static str,
    pub version: &'static str,
    pub run_id: Option<String>,
    pub seed: Option<u64>,
    pub mode: &'static str,
    pub target_eps: u32,
    pub threads: usize,
    pub batch_size: usize,
    pub assets: usize,
    pub started_at: String,
    pub ended_at: String,
    pub elapsed_secs: f64,
    pub events_sent: u64,
    pub events_failed: u64,
    pub markers_sent: u64,
    pub markers_failed: u64,
    pub achieved_eps: f64,
}

impl RunSummary {
    pub fn write(&self, path: Option<&Path>) -> Result<()> {
        let json = serde_json::to_string(self)?;
        // One greppable line on stdout as well, for the run log.
        println!("BENCH_SUMMARY {json}");
        if let Some(p) = path {
            std::fs::write(p, format!("{}\n", serde_json::to_string_pretty(self)?))
                .with_context(|| format!("write --summary-json {}", p.display()))?;
        }
        Ok(())
    }
}

/// Offline generation: `events` records on a simulated clock starting at
/// `start`, spaced `1/eps` seconds apart, with a lateral-movement chain every
/// `chain_interval_secs` of simulated time. Single-threaded on purpose: with a
/// seed set, the output is byte-for-byte reproducible.
#[allow(clippy::too_many_arguments)]
pub fn run_output_mode(
    world: &WorldState,
    path: &Path,
    events: u64,
    eps: u32,
    start: DateTime<Utc>,
    chain_interval_secs: u64,
    chain_max_hops: usize,
) -> Result<u64> {
    if event_core::rng::seed().is_none() {
        tracing::warn!("--output without --seed: the file will not be reproducible");
    }
    let eps = eps.max(1) as i64;
    let file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut out = BufWriter::with_capacity(1 << 20, file);

    let sysmon_gen = SysmonGenerator::new();
    let winevt_gen = WindowsEventGenerator::new();
    let proxy_gen = ProxyGenerator::new();
    let apache_gen = ApacheGenerator::new();
    let cloudtrail_gen = CloudTrailGenerator::new();
    let chain_gen = LateralChainGenerator::new();
    let mut rng = event_core::rng::stream_rng(1);
    let mut chain_rng = event_core::rng::stream_rng(1_000);

    let ws_count = world.workstation_count.max(1).min(world.entities().len().max(1));
    let chain_every = (chain_interval_secs as i64).saturating_mul(eps).max(0) as u64;
    let mut chain_cursor = 0usize;
    let mut written = 0u64;

    for i in 0..events {
        let ts = start + ChronoDuration::nanoseconds((i as i64).saturating_mul(1_000_000_000) / eps);
        let entity = world.random_entity();
        let ev = crate::generate_event(
            ts,
            entity,
            world.entities(),
            &sysmon_gen,
            &winevt_gen,
            &proxy_gen,
            &apache_gen,
            &cloudtrail_gen,
            &crate::spike::DEFAULT_MIX,
            &mut rng,
        );
        serde_json::to_writer(&mut out, &ev)?;
        out.write_all(b"\n")?;
        written += 1;

        if chain_every > 0 && i > 0 && i % chain_every == 0 {
            let seed_idx = chain_cursor % ws_count;
            chain_cursor = chain_cursor.wrapping_add(1);
            for ev in chain_gen.emit_chain(world, seed_idx, chain_max_hops, ts, &mut chain_rng) {
                serde_json::to_writer(&mut out, &ev)?;
                out.write_all(b"\n")?;
                written += 1;
            }
        }
    }
    out.flush()?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dump(dir: &Path, name: &str) -> Vec<u8> {
        // One generation per process in real use; here, restart the thread's
        // stream so both dumps start from the same RNG state.
        event_core::rng::reseed_thread(0);
        let world = WorldState::new(60);
        let path = dir.join(name);
        let start = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let n = run_output_mode(&world, &path, 3_000, 500, start, 2, 3).unwrap();
        assert!(n >= 3_000);
        std::fs::read(path).unwrap()
    }

    #[test]
    fn seeded_output_is_byte_reproducible() {
        event_core::rng::set_seed(20261114);
        let dir = std::env::temp_dir().join(format!("lb-seed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dump(&dir, "a.ndjson");
        let b = dump(&dir, "b.ndjson");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(a, b, "same seed must produce identical bytes");
        // Lateral chains (every 2 simulated seconds) are interleaved.
        assert!(a.len() > 1_000_000);
    }

    #[test]
    fn marker_is_a_json_record_with_its_sequence() {
        let ts = Utc::now();
        let m = marker_event("r1", 3, 42, ts);
        assert_eq!(m.source_type, MARKER_SOURCE);
        let v: serde_json::Value = serde_json::from_str(&m.message).unwrap();
        assert_eq!(v["nanobench_seq"], 42);
        assert_eq!(v["nanobench_run"], "r1");
    }
}

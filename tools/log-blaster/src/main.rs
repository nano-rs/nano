//! Log Blaster - Profile-driven SIEM log generator
//!
//! Generates realistic Sysmon, Windows Event, and proxy logs using real
//! telemetry data exported from the Ludus lab. Supports three modes:
//! - **Normal** — steady rate (events per minute).
//! - **Blast** — flat high-throughput stress testing.
//! - **Spike** — multi-rhythm corporate traffic shape driven by a profile
//!   JSON (login surges, AV scans, alert storms, lunch dips).
//!
//! Usage:
//!   log-blaster --vector http://localhost:8080 --rate 30                       # Normal mode
//!   log-blaster --vector http://localhost:8080 --blast --eps 50000             # Blast mode
//!   log-blaster --vector http://localhost:8080 --spike \
//!     --spike-profile tools/log-blaster/profiles/spike_corporate.json          # Spike mode
//!   log-blaster --hec --rate 30                                                # Splunk HEC (default :8088)
//!   log-blaster --hec --vector http://hec.example:8088 --blast --eps 50000    # HEC at custom URL
//!   log-blaster --tenzir --rate 30                                             # Tenzir raw-log lane (default :9095)
//!   log-blaster --tenzir http://tenzir.example:9095 --blast --eps 5000        # Tenzir at custom URL

mod spike;

use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use rand::{Rng, SeedableRng};
use reqwest::Client;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{error, info, warn};

use event_core::entity::WorldState;
use event_core::event::Event;
use event_core::generators::{
    ApacheGenerator, CloudTrailGenerator, LateralChainGenerator, ProxyGenerator, SysmonGenerator,
    WindowsEventGenerator,
};
use event_core::http::{send_batch_with_retry, send_event, Transport};
use event_core::profiles;

#[derive(Parser, Debug)]
#[command(name = "log-blaster")]
#[command(about = "Profile-driven SIEM log generator using real telemetry data")]
struct Args {
    /// Vector HTTP endpoint (or HEC base URL when `--hec` is set).
    /// HEC default: `http://localhost:8088`. Path suffix is auto-appended:
    /// `/ingest` (Vector dev mode) or `/services/collector/event` (HEC).
    #[arg(long, default_value = "http://localhost:8080")]
    vector: String,

    /// Auth token. Vector uses Bearer; HEC uses `Authorization: Splunk <token>`.
    /// Falls back to `VECTOR_AUTH_TOKEN` env var, then a dev default.
    #[arg(long)]
    token: Option<String>,

    /// Send events via Splunk HEC instead of Vector HTTP. Targets the OOTB
    /// `splunk_hec_ingest` listener on :8088 with line-delimited JSON
    /// envelopes and the Splunk auth scheme. Use to validate the HEC
    /// routing-rule UI and the hec_normalize transform end-to-end.
    #[arg(long)]
    hec: bool,

    /// Ship RAW events to a Tenzir `accept_http` listener instead of
    /// Vector/HEC (NAN-1402). Tenzir parses the raw payloads to OCSF 1.8.0
    /// and writes directly into ClickHouse `nanosiem.ocsf_logs` — see
    /// `tools/log-blaster/tenzir/` for the pipeline + runner. Takes the
    /// listener URL; bare `--tenzir` targets the default local rig
    /// (`http://localhost:9095`). Mutually exclusive with `--hec`/`--dev`;
    /// `--vector` and `--token` are ignored (the listener has no auth).
    #[arg(
        long,
        conflicts_with_all = ["hec", "dev"],
        num_args = 0..=1,
        default_missing_value = "http://localhost:9095"
    )]
    tenzir: Option<String>,

    /// Events per minute (normal mode)
    #[arg(long, default_value = "30")]
    rate: u32,

    /// Enable blast mode for stress testing
    #[arg(long)]
    blast: bool,

    /// Enable spike mode (multi-rhythm corporate traffic shape).
    /// Requires --spike-profile.
    #[arg(long, requires = "spike_profile")]
    spike: bool,

    /// Path to a SpikeProfile JSON (required when --spike is set)
    #[arg(long)]
    spike_profile: Option<std::path::PathBuf>,

    /// Events per second target (blast mode)
    #[arg(long, default_value = "50000")]
    eps: u32,

    /// Number of sender threads (blast mode)
    #[arg(long, default_value = "8")]
    threads: usize,

    /// Batch size for HTTP requests (blast mode)
    #[arg(long, default_value = "1000")]
    batch_size: usize,

    /// Run duration in minutes (0 = unlimited)
    #[arg(long, default_value = "0")]
    duration: u64,

    /// Number of simulated assets (hosts) to generate
    #[arg(long, default_value = "2000")]
    assets: usize,

    /// Seconds between lateral-movement chains (0 = disabled)
    #[arg(long, default_value = "45")]
    chain_interval_secs: u64,

    /// Max hops per lateral chain
    #[arg(long, default_value = "4")]
    chain_max_hops: usize,

    /// Dev mode — auto-appends `/ingest` to the Vector URL. Convenient for
    /// local docker-compose setups where Vector's HTTP source listens on
    /// `/ingest`. In prod the endpoint is usually passed directly, so leave
    /// this off unless you're hitting a dev stack.
    #[arg(long)]
    dev: bool,

    /// Quiet mode (suppress per-event logs)
    #[arg(short, long)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("log_blaster=info".parse()?),
        )
        .init();

    let mut args = Args::parse();

    // HEC and Vector use different default ports / path suffixes. When
    // `--hec` is set and `--vector` was left at its default, switch the
    // base URL to the HEC standard `:8088`. Users who explicitly pass
    // `--vector http://hec.example:8088` keep their override.
    const VECTOR_DEFAULT: &str = "http://localhost:8080";
    const HEC_DEFAULT_BASE: &str = "http://localhost:8088";
    if args.hec && args.vector == VECTOR_DEFAULT {
        args.vector = HEC_DEFAULT_BASE.to_string();
    }

    // Resolve the wire-format-specific path suffix. Idempotent — bails if
    // the user already passed a fully-qualified URL. Tenzir replaces the
    // Vector/HEC target wholesale: the raw NDJSON goes straight to the
    // `accept_http` listener URL, no path suffix.
    if let Some(t) = &args.tenzir {
        args.vector = t.trim_end_matches('/').to_string();
    } else {
        let trimmed = args.vector.trim_end_matches('/').to_string();
        args.vector = if args.hec {
            if trimmed.ends_with("/services/collector/event")
                || trimmed.ends_with("/services/collector/raw")
            {
                trimmed
            } else {
                format!("{trimmed}/services/collector/event")
            }
        } else if args.dev && !trimmed.ends_with("/ingest") {
            format!("{trimmed}/ingest")
        } else {
            trimmed
        };
    }
    info!(
        "Transport: {} → {}",
        if args.tenzir.is_some() {
            "Tenzir"
        } else if args.hec {
            "HEC"
        } else {
            "Vector"
        },
        args.vector
    );

    // Auth token resolution (matches scripts/generate-*.py convention):
    //   --token flag  >  VECTOR_AUTH_TOKEN env  >  "nanosiem-default-token"
    // The token field is shared across the Vector and HEC transports — the
    // OOTB HEC listener also reads `VECTOR_AUTH_TOKEN` (one token to
    // rotate). The Tenzir listener has no auth, so skip resolution there.
    if args.token.is_none() && args.tenzir.is_none() {
        let resolved = std::env::var("VECTOR_AUTH_TOKEN")
            .unwrap_or_else(|_| "nanosiem-default-token".to_string());
        info!(
            "Using {} auth token: ***{}",
            if args.hec { "HEC" } else { "Vector" },
            tail4(&resolved)
        );
        args.token = Some(resolved);
    }

    // Force profile loading at startup so errors surface early
    let p = profiles::profiles();
    info!(
        "Profiles loaded: {} process chains, {} file hashes, {} proxy patterns",
        p.process_chains.len(),
        p.file_hashes.len(),
        p.proxy_patterns.len()
    );

    // Build the wire-format-specific transport once. Cheap-to-clone
    // (`Clone`) so each spawned worker carries its own copy without
    // sharing locks.
    let transport = if args.tenzir.is_some() {
        Transport::Tenzir {
            url: args.vector.clone(),
        }
    } else if args.hec {
        // NAN-919: HEC requires the X-Splunk-Request-Channel header when
        // the receiving source has ACK enabled (nano's OOTB config does).
        // `new_hec` generates a fresh per-process UUID for it.
        Transport::new_hec(args.vector.clone(), args.token.clone())
    } else {
        Transport::Vector {
            url: args.vector.clone(),
            token: args.token.clone(),
        }
    };

    info!("Initializing World State ({} assets)...", args.assets);
    let world = Arc::new(parking_lot::RwLock::new(WorldState::new(args.assets)));

    {
        let w = world.read();
        println!(
            "\n--- Network Population ({} assets) ---",
            w.entities().len()
        );
        println!("  Workstations: {}", w.workstation_count);
        println!("  Laptops:      {}", w.laptop_count);
        println!("  Servers:      {}", w.server_count);
        println!("  Users:        {}", w.user_count);
        println!("  IP range:     10.1.x.x (endpoints), 10.2.x.x (servers)");
        println!(
            "  Source types:  windows_sysmon, windows_event, conduit_proxy, aws_cloudtrail"
        );
        println!("--------------------------------------\n");
    }

    // Spawn a background lateral-movement chain emitter. One task shared
    // across both normal and blast modes — it fires a full chain (3 events
    // per hop × N hops) every `chain_interval_secs` so the `| lateral`
    // aggregate always has something to render.
    let chain_handle = if args.chain_interval_secs > 0 {
        let chain_world = world.clone();
        let chain_transport = transport.clone();
        let interval_secs = args.chain_interval_secs;
        let max_hops = args.chain_max_hops;
        Some(tokio::spawn(async move {
            run_chain_emitter(chain_world, chain_transport, interval_secs, max_hops).await;
        }))
    } else {
        None
    };

    let result = if args.spike {
        run_spike_mode(args, transport, world).await
    } else if args.blast {
        run_blast_mode(args, transport, world).await
    } else {
        run_normal_mode(args, transport, world).await
    };

    if let Some(h) = chain_handle {
        h.abort();
    }
    result
}

/// Tail characters of a secret for log display (masks most of it).
fn tail4(s: &str) -> String {
    if s.len() <= 4 {
        "***".to_string()
    } else {
        s[s.len() - 4..].to_string()
    }
}

/// Periodically emits a full lateral-movement chain (network + auth + remote
/// exec per hop). Picks a rotating seed across the workstation population so
/// the graph doesn't always center on the same host.
async fn run_chain_emitter(
    world: Arc<parking_lot::RwLock<WorldState>>,
    transport: Transport,
    interval_secs: u64,
    max_hops: usize,
) {
    let client = match Client::builder()
        .connect_timeout(TokioDuration::from_secs(10))
        .timeout(TokioDuration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("chain emitter: failed to build HTTP client: {}", e);
            return;
        }
    };
    let gen = LateralChainGenerator::new();
    let mut rng = rand::rngs::StdRng::from_os_rng();
    let mut seed_cursor: usize = 0;

    info!(
        "Lateral chain emitter active: every {}s, max {} hops",
        interval_secs, max_hops
    );

    // Prime delay so the first chain fires shortly after startup.
    tokio::time::sleep(TokioDuration::from_secs(5)).await;

    loop {
        let batch = {
            let w = world.read();
            let entities = w.entities();
            if entities.is_empty() {
                break;
            }
            // Rotate across the first N workstations so chains spread. Skip
            // servers (they make poor seeds in a "patient zero" scenario).
            let ws_count = w.workstation_count.max(1);
            let seed_idx = seed_cursor % ws_count.min(entities.len());
            seed_cursor = seed_cursor.wrapping_add(1);
            gen.emit_chain(&w, seed_idx, max_hops, Utc::now(), &mut rng)
        };

        if batch.is_empty() {
            tokio::time::sleep(TokioDuration::from_secs(interval_secs)).await;
            continue;
        }

        let seed_label = batch
            .first()
            .map(|e| e.display_label.clone())
            .unwrap_or_default();
        match send_batch_with_retry(&client, &transport, &batch, 3).await {
            Ok(()) => {
                info!(
                    "[CHAIN] {} events across {} hops (seed: {})",
                    batch.len(),
                    batch.len() / 3,
                    seed_label
                );
            }
            Err(e) => {
                warn!("chain emitter: failed to send batch ({} events): {}", batch.len(), e);
            }
        }

        tokio::time::sleep(TokioDuration::from_secs(interval_secs)).await;
    }
}

/// Generate a single event, sampling source type from `mix` (assumed
/// normalized — caller is responsible). The historical fixed distribution
/// (60/10/12/10/8) lives in [`spike::DEFAULT_MIX`].
#[allow(clippy::too_many_arguments)]
fn generate_event(
    timestamp: chrono::DateTime<Utc>,
    entity: &event_core::entity::Entity,
    all_entities: &[event_core::entity::Entity],
    sysmon_gen: &SysmonGenerator,
    winevt_gen: &WindowsEventGenerator,
    proxy_gen: &ProxyGenerator,
    apache_gen: &ApacheGenerator,
    cloudtrail_gen: &CloudTrailGenerator,
    mix: &spike::SourceMix,
    rng: &mut impl Rng,
) -> Event {
    let r: f64 = rng.random();
    let mut cum = mix.sysmon;
    if r < cum {
        return sysmon_gen.generate(timestamp, entity, rng);
    }
    cum += mix.winevt;
    if r < cum {
        return winevt_gen.generate(timestamp, entity, all_entities, rng);
    }
    cum += mix.proxy;
    if r < cum {
        return proxy_gen.generate(timestamp, entity, rng);
    }
    cum += mix.apache;
    if r < cum {
        return apache_gen.generate(timestamp, entity, rng);
    }
    cloudtrail_gen.generate(timestamp, entity, rng)
}

async fn run_normal_mode(
    args: Args,
    transport: Transport,
    world: Arc<parking_lot::RwLock<WorldState>>,
) -> Result<()> {
    let client = Client::builder()
        .pool_max_idle_per_host(4)
        .connect_timeout(TokioDuration::from_secs(10))
        .timeout(TokioDuration::from_secs(30))
        .build()?;

    let use_batching = args.rate > 120;
    let batch_interval_ms: u64 = if use_batching { 1000 } else { 0 };
    if use_batching {
        info!("High rate detected ({}epm), using batched sends", args.rate);
    }

    let sysmon_gen = SysmonGenerator::new();
    let winevt_gen = WindowsEventGenerator::new();
    let proxy_gen = ProxyGenerator::new();
    let apache_gen = ApacheGenerator::new();
    let cloudtrail_gen = CloudTrailGenerator::new();

    let sleep_ms = (60_000.0 / args.rate as f64) as u64;
    info!(
        "Starting simulation. Rate: ~{} events/min. {}: {}",
        args.rate,
        transport.kind(),
        args.vector
    );

    let mut sim_time = Utc::now();
    let start_time = Instant::now();
    let mut rng = rand::rng();
    let mut pending_batch: Vec<Event> = Vec::new();
    let mut last_flush = Instant::now();
    let mut consecutive_errors = 0u32;

    loop {
        // Generate event
        let event = {
            let w = world.read();
            let entity = w.random_entity();
            generate_event(
                sim_time,
                entity,
                w.entities(),
                &sysmon_gen,
                &winevt_gen,
                &proxy_gen,
                &apache_gen,
                &cloudtrail_gen,
                &spike::DEFAULT_MIX,
                &mut rng,
            )
        };

        if !args.quiet {
            println!(
                "[BASE] {} {}",
                sim_time.format("%H:%M:%S"),
                event.display_label
            );
        }

        if use_batching {
            pending_batch.push(event);
            let since_flush = last_flush.elapsed().as_millis() as u64;
            if since_flush >= batch_interval_ms || pending_batch.len() >= 500 {
                let batch = std::mem::take(&mut pending_batch);
                match send_batch_with_retry(&client, &transport, &batch, 3).await {
                    Ok(()) => {
                        consecutive_errors = 0;
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        warn!(
                            "Error sending batch ({} events): {} (consecutive errors: {})",
                            batch.len(),
                            e,
                            consecutive_errors
                        );
                        if consecutive_errors >= 10 {
                            error!("10 consecutive send failures, backing off 10s");
                            tokio::time::sleep(TokioDuration::from_secs(10)).await;
                            consecutive_errors = 0;
                        }
                    }
                }
                last_flush = Instant::now();
            }
        } else {
            match send_event(&client, &transport, &event).await {
                Ok(()) => {
                    consecutive_errors = 0;
                }
                Err(e) => {
                    consecutive_errors += 1;
                    warn!(
                        "Error sending event: {} (consecutive errors: {})",
                        e, consecutive_errors
                    );
                    if consecutive_errors >= 10 {
                        error!("10 consecutive send failures, backing off 10s");
                        tokio::time::sleep(TokioDuration::from_secs(10)).await;
                        consecutive_errors = 0;
                    }
                }
            }
        }

        // Rate limiting
        let loop_elapsed = sim_time
            .signed_duration_since(Utc::now())
            .num_milliseconds();
        let remaining = (sleep_ms as i64 + loop_elapsed).max(0) as u64;
        if remaining > 0 {
            tokio::time::sleep(TokioDuration::from_millis(remaining)).await;
        }
        sim_time = Utc::now();

        if args.duration > 0 {
            let elapsed = start_time.elapsed().as_secs() / 60;
            if elapsed >= args.duration {
                break;
            }
        }
    }

    if !pending_batch.is_empty() {
        if let Err(e) = send_batch_with_retry(&client, &transport, &pending_batch, 3).await {
            warn!("Error flushing final batch: {}", e);
        }
    }

    Ok(())
}

async fn run_blast_mode(
    args: Args,
    transport: Transport,
    world: Arc<parking_lot::RwLock<WorldState>>,
) -> Result<()> {
    let eps_per_thread_raw = args.eps / args.threads as u32;
    let max_sleep_ms: u64 = 1000;
    let effective_batch_size = if eps_per_thread_raw > 0 {
        let ideal = args.batch_size;
        let max_batch_for_sleep = (eps_per_thread_raw as u64 * max_sleep_ms / 1000) as usize;
        ideal.min(max_batch_for_sleep).max(1)
    } else {
        args.batch_size
    };

    info!(
        "BLAST MODE: Target {} EPS with {} threads, batch size {} (requested {})",
        args.eps, args.threads, effective_batch_size, args.batch_size
    );

    let events_sent = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    let inflight_per_thread: usize = 4;
    let mut handles = Vec::new();
    for thread_id in 0..args.threads {
        let transport = transport.clone();
        let events_sent = events_sent.clone();
        let running = running.clone();
        let worker_world = world.clone();
        let batch_size = effective_batch_size;
        let max_inflight = inflight_per_thread;

        let handle = tokio::spawn(async move {
            let client = Client::builder()
                .pool_max_idle_per_host(max_inflight + 2)
                .connect_timeout(TokioDuration::from_secs(10))
                .timeout(TokioDuration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client");

            let sysmon_gen = SysmonGenerator::new();
            let winevt_gen = WindowsEventGenerator::new();
            let proxy_gen = ProxyGenerator::new();
            let apache_gen = ApacheGenerator::new();
            let cloudtrail_gen = CloudTrailGenerator::new();
            let mut rng = rand::rngs::StdRng::from_os_rng();

            let sem = Arc::new(tokio::sync::Semaphore::new(max_inflight));

            while running.load(Ordering::Relaxed) {
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                let sim_time = Utc::now();
                let mut batch = Vec::with_capacity(batch_size);
                {
                    let w = worker_world.read();
                    for _ in 0..batch_size {
                        let entity = w.random_entity();
                        let event = generate_event(
                            sim_time,
                            entity,
                            w.entities(),
                            &sysmon_gen,
                            &winevt_gen,
                            &proxy_gen,
                            &apache_gen,
                            &cloudtrail_gen,
                            &spike::DEFAULT_MIX,
                            &mut rng,
                        );
                        batch.push(event);
                    }
                }

                let batch_len = batch.len() as u64;
                let client = client.clone();
                let transport = transport.clone();
                let events_sent = events_sent.clone();
                tokio::spawn(async move {
                    match send_batch_with_retry(&client, &transport, &batch, 3).await {
                        Ok(()) => {
                            events_sent.fetch_add(batch_len, Ordering::Relaxed);
                        }
                        Err(e) => {
                            error!(
                                "Thread {}: Error sending batch after retries: {}",
                                thread_id, e
                            );
                        }
                    }
                    drop(permit);
                });

                if eps_per_thread_raw > 0 {
                    let sleep_ms = (batch_size as f64 / eps_per_thread_raw as f64) * 1000.0;
                    tokio::time::sleep(TokioDuration::from_millis(sleep_ms as u64)).await;
                }
            }
        });
        handles.push(handle);
    }

    // Stats reporter
    let stats_events = events_sent.clone();
    let stats_running = running.clone();
    let stats_handle = tokio::spawn(async move {
        let mut interval = interval(TokioDuration::from_secs(1));
        let mut last_count = 0u64;
        let start = Instant::now();

        while stats_running.load(Ordering::Relaxed) {
            interval.tick().await;
            let current = stats_events.load(Ordering::Relaxed);
            let delta = current - last_count;
            let elapsed = start.elapsed().as_secs_f64();
            let avg_eps = current as f64 / elapsed;

            info!(
                "EPS: {} (avg: {:.0}) | Total: {} | Elapsed: {:.1}s",
                delta, avg_eps, current, elapsed
            );
            last_count = current;
        }
    });

    if args.duration > 0 {
        tokio::time::sleep(TokioDuration::from_secs(args.duration * 60)).await;
        running.store(false, Ordering::Relaxed);
    } else {
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");
        running.store(false, Ordering::Relaxed);
    }

    for handle in handles {
        handle.await?;
    }
    stats_handle.abort();

    let total = events_sent.load(Ordering::Relaxed);
    info!("Total events sent: {}", total);

    Ok(())
}

/// Spike mode: profile-driven multi-rhythm traffic.
///
/// Architecture is similar to blast mode (N worker threads, semaphore-bounded
/// inflight sends, async batch dispatch), but a single scheduler task ticks
/// at 1Hz, advances rhythm state, and publishes the current target EPS and
/// source-type mix to all workers via `Arc<parking_lot::RwLock<...>>`.
///
/// Each worker recomputes its per-thread EPS from the shared target on every
/// batch, so a ramp-up from 500 → 15000 EPS over 30s is reflected in worker
/// sleep intervals within ~250ms of each tick.
async fn run_spike_mode(
    args: Args,
    transport: Transport,
    world: Arc<parking_lot::RwLock<WorldState>>,
) -> Result<()> {
    // Clap's `requires = "spike_profile"` on the --spike flag guarantees this
    // is set before we reach this function.
    let profile_path = args
        .spike_profile
        .as_ref()
        .expect("clap requires guarantees --spike-profile is present");
    let profile = spike::SpikeProfile::load(profile_path)?;

    info!(
        "SPIKE MODE: baseline {:.0} EPS, {} rhythms (profile: {})",
        profile.baseline_eps,
        profile.rhythms.len(),
        profile_path.display()
    );
    for r in &profile.rhythms {
        info!(
            "  rhythm '{}' peak={:.0} eps shape={}+{}+{}s",
            r.name,
            r.peak_eps,
            r.envelope.ramp_up_secs,
            r.envelope.plateau_secs,
            r.envelope.ramp_down_secs
        );
    }

    // Shared spike state — scheduler writes, workers + stats read.
    let target_state = Arc::new(parking_lot::RwLock::new(spike::Snapshot {
        effective_eps: profile.baseline_eps.max(0.0),
        mix: profile
            .baseline_mix
            .unwrap_or(spike::DEFAULT_MIX)
            .normalized(),
        active: Vec::new(),
    }));

    let events_sent = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    // Scheduler tick — 1Hz is fine; envelope curves resolve at sub-1s
    // granularity through worker EPS recomputation.
    let sched_state = target_state.clone();
    let sched_running = running.clone();
    let sched_handle = tokio::spawn(async move {
        let mut rng = rand::rngs::StdRng::from_os_rng();
        let mut scheduler = spike::Scheduler::new(profile, Utc::now(), &mut rng);
        let mut tick = interval(TokioDuration::from_secs(1));
        while sched_running.load(Ordering::Relaxed) {
            tick.tick().await;
            let snap = scheduler.tick(Utc::now(), &mut rng);
            *sched_state.write() = snap;
        }
    });

    let inflight_per_thread: usize = 4;
    // Workers refresh target EPS every ~250ms.
    let worker_period_ms: u64 = 250;
    // Cap each HTTP POST at args.batch_size; split a tick's events across
    // multiple sends if needed. Mirrors blast-mode's batch sizing so a
    // profile with extreme peak_eps doesn't produce oversized payloads.
    let batch_size_cap = args.batch_size.max(1);
    let mut handles = Vec::new();
    for thread_id in 0..args.threads {
        let transport = transport.clone();
        let events_sent = events_sent.clone();
        let running = running.clone();
        let worker_world = world.clone();
        let target_state = target_state.clone();
        let max_inflight = inflight_per_thread;
        let thread_count = args.threads.max(1);

        let handle = tokio::spawn(async move {
            let client = Client::builder()
                .pool_max_idle_per_host(max_inflight + 2)
                .connect_timeout(TokioDuration::from_secs(10))
                .timeout(TokioDuration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client");

            let sysmon_gen = SysmonGenerator::new();
            let winevt_gen = WindowsEventGenerator::new();
            let proxy_gen = ProxyGenerator::new();
            let apache_gen = ApacheGenerator::new();
            let cloudtrail_gen = CloudTrailGenerator::new();
            let mut rng = rand::rngs::StdRng::from_os_rng();

            let sem = Arc::new(tokio::sync::Semaphore::new(max_inflight));

            while running.load(Ordering::Relaxed) {
                let (target_eps, mix) = {
                    let s = target_state.read();
                    (s.effective_eps, s.mix)
                };
                // Target events for this thread for one worker_period_ms slice.
                let per_thread_eps = target_eps / thread_count as f64;
                let events_this_tick =
                    ((per_thread_eps * worker_period_ms as f64) / 1000.0).round() as usize;

                if events_this_tick == 0 {
                    tokio::time::sleep(TokioDuration::from_millis(worker_period_ms)).await;
                    continue;
                }

                let mut remaining = events_this_tick;
                while remaining > 0 && running.load(Ordering::Relaxed) {
                    let chunk = remaining.min(batch_size_cap);
                    remaining -= chunk;

                    let permit = match sem.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    let sim_time = Utc::now();
                    let mut batch = Vec::with_capacity(chunk);
                    {
                        let w = worker_world.read();
                        for _ in 0..chunk {
                            let entity = w.random_entity();
                            let event = generate_event(
                                sim_time,
                                entity,
                                w.entities(),
                                &sysmon_gen,
                                &winevt_gen,
                                &proxy_gen,
                                &apache_gen,
                                &cloudtrail_gen,
                                &mix,
                                &mut rng,
                            );
                            batch.push(event);
                        }
                    }

                    let batch_len = batch.len() as u64;
                    let client = client.clone();
                    let transport = transport.clone();
                    let events_sent = events_sent.clone();
                    tokio::spawn(async move {
                        match send_batch_with_retry(&client, &transport, &batch, 3).await {
                            Ok(()) => {
                                events_sent.fetch_add(batch_len, Ordering::Relaxed);
                            }
                            Err(e) => {
                                error!(
                                    "Thread {}: Error sending spike batch after retries: {}",
                                    thread_id, e
                                );
                            }
                        }
                        drop(permit);
                    });
                }

                tokio::time::sleep(TokioDuration::from_millis(worker_period_ms)).await;
            }
        });
        handles.push(handle);
    }

    // Stats reporter — shows baseline, active rhythms, target vs actual EPS.
    let stats_events = events_sent.clone();
    let stats_running = running.clone();
    let stats_target = target_state.clone();
    let stats_handle = tokio::spawn(async move {
        let mut tick = interval(TokioDuration::from_secs(1));
        let mut last_count = 0u64;
        let start = Instant::now();
        while stats_running.load(Ordering::Relaxed) {
            tick.tick().await;
            let current = stats_events.load(Ordering::Relaxed);
            let delta = current - last_count;
            let elapsed = start.elapsed().as_secs_f64();
            // `interval` fires immediately on the first tick, so elapsed
            // can be ~0 — `current / elapsed` would render as `inf`. Show
            // the instantaneous delta until we have at least one full second.
            let avg_eps = if elapsed >= 1.0 {
                current as f64 / elapsed
            } else {
                delta as f64
            };
            let snap = stats_target.read().clone();
            let active = if snap.active.is_empty() {
                "idle".to_string()
            } else {
                snap.active
                    .iter()
                    .map(|a| format!("{}:{:+.0}", a.name, a.contribution_eps))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            info!(
                "target={:.0} eps | actual={} eps (avg {:.0}) | rhythms=[{}] | total={}",
                snap.effective_eps, delta, avg_eps, active, current
            );
            last_count = current;
        }
    });

    if args.duration > 0 {
        tokio::time::sleep(TokioDuration::from_secs(args.duration * 60)).await;
        running.store(false, Ordering::Relaxed);
    } else {
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");
        running.store(false, Ordering::Relaxed);
    }

    for handle in handles {
        handle.await?;
    }
    sched_handle.abort();
    stats_handle.abort();

    let total = events_sent.load(Ordering::Relaxed);
    info!("Total events sent: {}", total);

    Ok(())
}

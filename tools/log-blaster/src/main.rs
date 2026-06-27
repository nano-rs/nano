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
//!   log-blaster --otlp --otlp-direct --blast --eps 5000 --threads 8 --otlp-batch 50  # OTLP firehose → ClickHouse (10k+ spans/s)
//!   log-blaster --otlp --blast --eps 2000 --threads 4 --otlp-batch 20         # OTLP firehose → Vector :4318
//!   log-blaster --combo-join --combo-join-fraction 0.3 --rate 600 --duration 1 \
//!     --clickhouse-url http://localhost:8123                                   # Spans→otel_spans + correlated auth-failure logs→nanosiem.logs (validate spans↔logs join)

mod spike;

use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use rand::{Rng, SeedableRng};
use reqwest::Client;
use serde_json::Value;
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
use event_core::http::{
    send_batch_with_retry, send_event, send_otlp_with_retry, OtlpSignal, Transport,
};
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

    /// Seed user_registry with identities matching the fleet's users (push
    /// nano_enrich kind=identity source=ad records through the lane), then exit.
    /// Run once before a blast so generated logs enrich via user_registry_dict.
    /// Requires the enrichments/identity/ad parser imported + deployed.
    #[arg(long)]
    seed_identities: bool,

    /// Quiet mode (suppress per-event logs)
    #[arg(short, long)]
    quiet: bool,

    // --- OTLP (OpenTelemetry) mode — NAN-1533 -------------------------------
    /// Generate and ship OTLP signals (traces / metrics / logs) instead of the
    /// raw-log generators. Targets Vector's `opentelemetry` receiver by default
    /// (OTLP/HTTP JSON to :4318); add `--otlp-direct` for the Vector-independent
    /// direct-to-ClickHouse path. Honors --epm/--rate, --blast, --duration.
    #[arg(long, conflicts_with_all = ["hec", "tenzir", "spike", "seed_identities"])]
    otlp: bool,

    /// Which OTLP signals to emit (CSV). Recognised tokens:
    ///   `traces`, `metrics`, `logs` — the app/RED + correlated-log set;
    ///   `infra` — host-fleet system metrics (cpu/mem/load/net) for the Infra tab;
    ///   `rum`   — web-vital metrics + page-view / JS-error spans for the RUM tab.
    /// Default emits the full set so a single run lights up every tab.
    #[arg(
        long,
        default_value = "traces,metrics,logs,infra,rum",
        value_delimiter = ','
    )]
    otlp_signals: Vec<String>,

    /// Use the direct OTLP->ClickHouse path (mirrors Tenzir/Cribl direct
    /// producers) instead of OTLP/HTTP to Vector. Writes raw rows straight into
    /// the otel_spans_raw / otel_metrics_raw Null tables (and the UDM logs lane
    /// for logs) so the derivation MVs run regardless of Vector's OTLP decode.
    #[arg(long)]
    otlp_direct: bool,

    /// ClickHouse HTTP endpoint for `--otlp-direct` (default dev docker-compose).
    #[arg(long, default_value = "http://localhost:8123")]
    clickhouse_url: String,

    /// ClickHouse user for `--otlp-direct`.
    #[arg(long, default_value = "nanosiem")]
    clickhouse_user: String,

    /// ClickHouse password for `--otlp-direct`.
    #[arg(long, default_value = "nanosiem")]
    clickhouse_password: String,

    // --- Combo-join (spans <-> logs correlation) — NAN-1566 -----------------
    /// Emit OTEL spans AND correlated UDM security-signal logs in ONE run so
    /// the cross-dataset spans<->logs correlation can be validated. Spans land
    /// in `otel_spans` (existing OTLP path); a `--combo-join-fraction` slice of
    /// the UDM logs carry a REAL `trace_id` minted by the span side and are
    /// shaped as an auth FAILURE (auth_result=failure + user + src_ip). The
    /// correlated log rows are written DIRECTLY into `nanosiem.logs` via the
    /// ClickHouse HTTP interface (the demo parsers don't carry trace_id through
    /// Vector, so direct-CH is the deterministic delivery path). Implies the
    /// direct-to-ClickHouse path; honors --rate/--blast/--eps/--threads/--duration.
    #[arg(long, conflicts_with_all = ["hec", "tenzir", "spike", "seed_identities"])]
    combo_join: bool,

    /// Fraction (0.0..=1.0) of combo-join UDM logs that carry a real span
    /// `trace_id` (the rest are normal, uncorrelated logs). Default 0.3.
    #[arg(long, default_value = "0.3")]
    combo_join_fraction: f64,

    /// OTLP records generated per tick (NAN-1545 firehose). Each tick sources
    /// ONE fleet entity and generates K full signal sets (K traces, K metric
    /// scrapes, K correlated logs, …), then ships each signal lane as a SINGLE
    /// bulk OTLP POST / ClickHouse insert — the cheapest throughput multiplier
    /// (amortizes one request over K records). Default 1 preserves the original
    /// one-entity-per-tick behavior. Combine with `--blast --eps --threads` to
    /// scale: spans/s ≈ eps × threads × otlp-batch × spans-per-trace.
    #[arg(long, default_value = "1")]
    otlp_batch: usize,
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

    // OTLP mode is wholly separate from the raw-log transports: it builds its
    // own transport (OtlpHttp -> Vector :4318, or OtlpClickHouse -> :8123) and
    // runs `run_otlp_mode`. Short-circuit the Vector/HEC/Tenzir path-suffix and
    // token resolution below and dispatch directly.
    if args.otlp {
        return run_otlp_entry(args).await;
    }

    // Combo-join (NAN-1566): emit OTEL spans AND correlated UDM security logs in
    // one run, sharing a bounded trace_id pool, so spans<->logs correlation is
    // validatable. Like --otlp it builds its own ClickHouse transport and
    // bypasses the Vector/HEC/Tenzir path-suffix + token plumbing below.
    if args.combo_join {
        return run_combo_join_entry(args).await;
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

    // NAN-1154: seed user_registry with identities matching the fleet's users,
    // then exit. Push nano_enrich kind=identity source=ad records through the
    // lane so a subsequent blast produces logs whose `.user` matches the
    // user_registry_dict key (lower(gen_user(i))) and enriches.
    if args.seed_identities {
        let roster = world.read().identity_roster();
        let client = Client::builder()
            .timeout(TokioDuration::from_secs(30))
            .build()?;
        info!(
            "Seeding {} identities to user_registry via the nano_enrich lane (source=ad)...",
            roster.len()
        );
        let mut sent = 0usize;
        for chunk in roster.chunks(500) {
            event_core::http::send_json_records(&client, &transport, "nano_enrich", chunk).await?;
            sent += chunk.len();
        }
        println!(
            "✓ Seeded {sent} identities (source=ad). Deploy the enrichments/identity/ad parser, \
             then run a blast — logs for those users will enrich via user_registry_dict."
        );
        return Ok(());
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

// =============================================================================
// OTLP (OpenTelemetry) mode — NAN-1533
// =============================================================================

/// Content selectors parsed from `--otlp-signals`. These describe WHAT to
/// generate; each maps onto a wire-level [`OtlpSignal`] (Metrics/Traces/Logs)
/// when shipped. `Infra` and `Rum` are new content kinds (NAN-1537) that ride
/// the existing metrics/traces lanes — host-fleet system metrics and RUM
/// web-vitals + page-view/JS-error spans respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OtlpContent {
    Traces,
    Metrics,
    Logs,
    Infra,
    Rum,
}

/// Parse `--otlp-signals` into the set of [`OtlpContent`] selectors to emit.
/// Unknown tokens are warned-and-skipped; an empty/all-unknown set defaults to
/// traces so a typo doesn't silently send nothing.
fn parse_otlp_signals(raw: &[String]) -> Vec<OtlpContent> {
    let mut signals = Vec::new();
    for s in raw {
        match s.trim().to_lowercase().as_str() {
            "traces" | "trace" | "spans" => signals.push(OtlpContent::Traces),
            "metrics" | "metric" => signals.push(OtlpContent::Metrics),
            "logs" | "log" => signals.push(OtlpContent::Logs),
            "infra" | "hosts" | "host" => signals.push(OtlpContent::Infra),
            "rum" => signals.push(OtlpContent::Rum),
            "" => {}
            other => warn!("unknown --otlp-signals token '{}' (skipped)", other),
        }
    }
    signals.dedup();
    if signals.is_empty() {
        warn!("no valid --otlp-signals; defaulting to traces");
        signals.push(OtlpContent::Traces);
    }
    signals
}

/// Build the OTLP transport and run the generator loop. Separated from `main`
/// so the OTLP path doesn't share the raw-log transports' URL/token plumbing.
async fn run_otlp_entry(args: Args) -> Result<()> {
    let signals = parse_otlp_signals(&args.otlp_signals);

    // Default the OtlpHttp base to :4318 unless the user explicitly pointed
    // `--vector` somewhere; we treat a non-default `--vector` as the receiver
    // base so `--otlp --vector http://collector:4318` works.
    const VECTOR_DEFAULT: &str = "http://localhost:8080";
    let otlp_http_base = if args.vector == VECTOR_DEFAULT {
        "http://localhost:4318".to_string()
    } else {
        args.vector.clone()
    };

    let transport = if args.otlp_direct {
        Transport::OtlpClickHouse {
            url: args.clickhouse_url.clone(),
            user: args.clickhouse_user.clone(),
            password: args.clickhouse_password.clone(),
        }
    } else {
        Transport::OtlpHttp {
            base_url: otlp_http_base,
            token: args.token.clone(),
        }
    };

    info!(
        "OTLP MODE [{}] signals={:?} → {}",
        transport.kind(),
        signals
            .iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(","),
        transport_target(&transport),
    );

    info!("Initializing World State ({} assets)...", args.assets);
    let world = Arc::new(parking_lot::RwLock::new(WorldState::new(args.assets)));

    if args.blast {
        run_otlp_blast_mode(args, transport, world, signals).await
    } else {
        run_otlp_mode(args, transport, world, signals).await
    }
}

/// Which OTLP content kinds this run emits, precomputed from the parsed
/// `--otlp-signals` selectors so the hot generate loop avoids re-scanning the
/// `Vec<OtlpContent>` on every tick. Shared by the normal and blast loops.
#[derive(Clone, Copy)]
struct OtlpWants {
    traces: bool,
    metrics: bool,
    logs: bool,
    infra: bool,
    rum: bool,
}

impl OtlpWants {
    fn from(signals: &[OtlpContent]) -> Self {
        Self {
            traces: signals.contains(&OtlpContent::Traces),
            metrics: signals.contains(&OtlpContent::Metrics),
            logs: signals.contains(&OtlpContent::Logs),
            infra: signals.contains(&OtlpContent::Infra),
            rum: signals.contains(&OtlpContent::Rum),
        }
    }
}

/// Generate ONE tick's worth of OTLP content and accumulate it into the three
/// wire lanes. A tick produces `batch` independent signal sets (each set =
/// one trace + one metric scrape + one correlated log + optional infra/rum),
/// all appended into the SAME `spans` / `metrics` / `logs` buffers so the caller
/// ships each lane as a single bulk request. `tick_seed` drives the
/// deterministic ~1-in-4 convergence-entity selection (NAN-1542); each of the
/// `batch` sets uses `tick_seed + i` so a batched tick spreads across the seed
/// pool rather than hammering one entity.
///
/// Returns `(spans, metrics, logs)`. Holds the world read-lock only for the
/// generation (no awaits inside) — callers ship outside the lock.
fn generate_otlp_tick(
    world: &parking_lot::RwLock<WorldState>,
    wants: OtlpWants,
    batch: usize,
    tick_seed: u64,
    rng: &mut impl Rng,
) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    let mut spans = Vec::new();
    let mut metrics = Vec::new();
    let mut logs = Vec::new();

    let w = world.read();
    for i in 0..batch.max(1) {
        let seed = tick_seed.wrapping_add(i as u64);
        // NAN-1542 convergence: ~1-in-4 sets source the entity from the
        // lateral-chain seed pool (where security detections concentrate) so
        // the trace's host.name / client.address overlaps a host with security
        // signals — the join the service-detail security cross-link uses. The
        // rest stay uniform-random so the service fleet still looks broad.
        let entity = if seed % 4 == 0 {
            w.convergence_entity(seed as usize)
                .unwrap_or_else(|| w.random_entity())
        } else {
            w.random_entity()
        };

        let set_spans_start = spans.len();
        if wants.traces {
            spans.extend(event_core::otlp::gen_trace(entity, rng));
        }
        if wants.rum {
            spans.extend(event_core::otlp::gen_rum_spans(rng));
        }
        if wants.metrics {
            metrics.extend(event_core::otlp::gen_metrics(rng));
        }
        if wants.infra {
            metrics.extend(event_core::otlp::gen_host_metrics(rng));
        }
        if wants.rum {
            metrics.extend(event_core::otlp::gen_rum_metrics(rng));
        }
        if wants.logs {
            // Correlate the log to THIS set's app-trace root span (the first
            // span emitted for this iteration; RUM spans are appended after).
            let corr = spans.get(set_spans_start).map(|s| {
                (
                    s["traceId"].as_str().unwrap_or("").to_string(),
                    s["spanId"].as_str().unwrap_or("").to_string(),
                )
            });
            let corr_ref = corr.as_ref().map(|(t, s)| (t.as_str(), s.as_str()));
            logs.push(event_core::otlp::gen_log(entity, corr_ref, rng));
        }
    }

    (spans, metrics, logs)
}

/// Ship the three accumulated OTLP lanes (each as ONE bulk request). Returns
/// the first error encountered (lanes after a failure are skipped so a retry
/// at the call site re-sends the whole tick). Empty lanes no-op.
async fn ship_otlp_lanes(
    client: &Client,
    transport: &Transport,
    spans: &[Value],
    metrics: &[Value],
    logs: &[Value],
) -> Result<()> {
    if !spans.is_empty() {
        send_otlp_with_retry(client, transport, OtlpSignal::Traces, spans, 3).await?;
    }
    if !metrics.is_empty() {
        send_otlp_with_retry(client, transport, OtlpSignal::Metrics, metrics, 3).await?;
    }
    if !logs.is_empty() {
        send_otlp_with_retry(client, transport, OtlpSignal::Logs, logs, 3).await?;
    }
    Ok(())
}

/// Human-readable target for OTLP log lines.
fn transport_target(t: &Transport) -> String {
    match t {
        Transport::OtlpHttp { base_url, .. } => base_url.clone(),
        Transport::OtlpClickHouse { url, .. } => url.clone(),
        _ => "?".to_string(),
    }
}

/// OTLP generator loop (normal / non-blast). One "tick" generates the selected
/// signals for `--otlp-batch` fleet entities (each a full trace, a per-service
/// metric scrape, a correlated log) and ships each signal lane as ONE bulk
/// OTLP request. Rate is driven by `--rate` (epm); `--duration` bounds the run
/// (0 = until ctrl-c). Single-threaded and readable — for high throughput use
/// `--blast` (see [`run_otlp_blast_mode`]).
async fn run_otlp_mode(
    args: Args,
    transport: Transport,
    world: Arc<parking_lot::RwLock<WorldState>>,
    signals: Vec<OtlpContent>,
) -> Result<()> {
    let client = Client::builder()
        .pool_max_idle_per_host(4)
        .connect_timeout(TokioDuration::from_secs(10))
        .timeout(TokioDuration::from_secs(30))
        .build()?;

    let sleep_ms: u64 = (60_000.0 / (args.rate.max(1) as f64)) as u64;
    let batch = args.otlp_batch.max(1);
    info!(
        "Starting OTLP simulation (normal). {} record-set(s)/tick every ~{}ms.",
        batch,
        sleep_ms.max(1),
    );

    let wants = OtlpWants::from(&signals);
    let mut rng = rand::rngs::StdRng::from_os_rng();
    let start_time = Instant::now();
    let mut ticks: u64 = 0;
    let mut consecutive_errors = 0u32;

    loop {
        // Generate one tick of signals for `batch` entities (lock held only for
        // generation), then ship each lane as a single bulk request.
        let (spans, metrics, logs) =
            generate_otlp_tick(&world, wants, batch, ticks.wrapping_mul(batch as u64), &mut rng);

        match ship_otlp_lanes(&client, &transport, &spans, &metrics, &logs).await {
            Ok(()) => {
                consecutive_errors = 0;
                if !args.quiet {
                    println!(
                        "[OTLP] tick {} — {} spans, {} metric points, {} logs",
                        ticks,
                        spans.len(),
                        metrics.len(),
                        logs.len(),
                    );
                }
            }
            Err(e) => {
                consecutive_errors += 1;
                warn!(
                    "Error shipping OTLP tick {}: {} (consecutive: {})",
                    ticks, e, consecutive_errors
                );
                if consecutive_errors >= 10 {
                    error!("10 consecutive OTLP send failures, backing off 10s");
                    tokio::time::sleep(TokioDuration::from_secs(10)).await;
                    consecutive_errors = 0;
                }
            }
        }

        ticks += 1;

        // --duration 0 loops until ctrl-c; bound by --duration (minutes) when set.
        if args.duration > 0 {
            let elapsed_min = start_time.elapsed().as_secs() / 60;
            if elapsed_min >= args.duration {
                break;
            }
        }

        if sleep_ms > 0 {
            tokio::time::sleep(TokioDuration::from_millis(sleep_ms)).await;
        }
    }

    info!("OTLP simulation complete: {} ticks shipped.", ticks);
    Ok(())
}

/// OTLP firehose (`--otlp --blast`) — NAN-1545. Mirrors [`run_blast_mode`]'s
/// worker model for the OTLP lanes: spawns `--threads` worker tasks, each
/// running its own generate→ship loop with a semaphore-bounded inflight window
/// so requests overlap. Each tick a worker generates `--otlp-batch` signal sets
/// and ships each lane as ONE bulk OTLP POST / ClickHouse insert. Throughput
/// scales as `threads × otlp-batch × spans-per-set` per tick, paced so each
/// worker targets `eps / threads` ticks/sec.
///
/// Stats report SPANS/sec (the firehose unit), not ticks — a single set yields
/// several spans (root + downstream + RUM), so spans/s is the meaningful rate.
async fn run_otlp_blast_mode(
    args: Args,
    transport: Transport,
    world: Arc<parking_lot::RwLock<WorldState>>,
    signals: Vec<OtlpContent>,
) -> Result<()> {
    let wants = OtlpWants::from(&signals);
    let batch = args.otlp_batch.max(1);
    let threads = args.threads.max(1);
    // --eps is interpreted as TICKS/sec (each tick = `batch` signal sets), so
    // the per-thread tick rate is eps / threads.
    let ticks_per_sec_per_thread = (args.eps.max(1) as f64) / threads as f64;

    info!(
        "OTLP BLAST: {} threads × {} record-set(s)/tick, target {} ticks/s ({:.0}/thread). \
         Each lane ships as ONE bulk request.",
        threads, batch, args.eps, ticks_per_sec_per_thread,
    );

    // GLOBAL inflight cap across ALL workers. ClickHouse limits concurrent
    // inserts (max_concurrent_insert_queries, ~20 → Code 202
    // TOO_MANY_SIMULTANEOUS_QUERIES); per-thread semaphores let threads×inflight
    // blow past it. One shared semaphore keeps total in-flight inserts under the
    // cap regardless of --threads, so the firehose self-throttles instead of
    // tripping the limit. ship_otlp_lanes sends each lane sequentially, so one
    // permit ≈ one concurrent insert.
    const GLOBAL_MAX_INFLIGHT_INSERTS: usize = 16;
    let global_inflight = Arc::new(tokio::sync::Semaphore::new(GLOBAL_MAX_INFLIGHT_INSERTS));

    let spans_sent = Arc::new(AtomicU64::new(0));
    let records_sent = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    let inflight_per_thread: usize = 4;
    let mut handles = Vec::new();
    for thread_id in 0..threads {
        let transport = transport.clone();
        let spans_sent = spans_sent.clone();
        let records_sent = records_sent.clone();
        let running = running.clone();
        let worker_world = world.clone();
        let max_inflight = inflight_per_thread;
        let global_inflight = global_inflight.clone();

        let handle = tokio::spawn(async move {
            let client = match Client::builder()
                .pool_max_idle_per_host(max_inflight + 2)
                .connect_timeout(TokioDuration::from_secs(10))
                .timeout(TokioDuration::from_secs(30))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    error!("OTLP worker {}: failed to build HTTP client: {}", thread_id, e);
                    return;
                }
            };

            let mut rng = rand::rngs::StdRng::from_os_rng();
            // Per-worker tick seed namespace so convergence selection spreads
            // across threads instead of every worker hitting the same entities.
            let mut tick: u64 = thread_id as u64;

            // Per-tick sleep to pace the worker toward its target tick rate.
            let sleep_ms: u64 = if ticks_per_sec_per_thread > 0.0 {
                (1000.0 / ticks_per_sec_per_thread) as u64
            } else {
                0
            };

            while running.load(Ordering::Relaxed) {
                let permit = match global_inflight.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                let (spans, metrics, logs) = generate_otlp_tick(
                    &worker_world,
                    wants,
                    batch,
                    tick.wrapping_mul(threads as u64).wrapping_add(thread_id as u64),
                    &mut rng,
                );
                tick = tick.wrapping_add(1);

                let n_spans = spans.len() as u64;
                let n_records = (spans.len() + metrics.len() + logs.len()) as u64;
                let client = client.clone();
                let transport = transport.clone();
                let spans_sent = spans_sent.clone();
                let records_sent = records_sent.clone();
                tokio::spawn(async move {
                    match ship_otlp_lanes(&client, &transport, &spans, &metrics, &logs).await {
                        Ok(()) => {
                            spans_sent.fetch_add(n_spans, Ordering::Relaxed);
                            records_sent.fetch_add(n_records, Ordering::Relaxed);
                        }
                        Err(e) => {
                            error!(
                                "OTLP worker {}: error shipping tick after retries: {}",
                                thread_id, e
                            );
                        }
                    }
                    drop(permit);
                });

                if sleep_ms > 0 {
                    tokio::time::sleep(TokioDuration::from_millis(sleep_ms)).await;
                }
            }
        });
        handles.push(handle);
    }

    // Stats reporter — spans/s is the firehose headline; total records covers
    // metric points + logs too.
    let stats_spans = spans_sent.clone();
    let stats_records = records_sent.clone();
    let stats_running = running.clone();
    let stats_handle = tokio::spawn(async move {
        let mut interval = interval(TokioDuration::from_secs(1));
        let mut last_spans = 0u64;
        let start = Instant::now();
        while stats_running.load(Ordering::Relaxed) {
            interval.tick().await;
            let spans = stats_spans.load(Ordering::Relaxed);
            let records = stats_records.load(Ordering::Relaxed);
            let delta = spans - last_spans;
            let elapsed = start.elapsed().as_secs_f64().max(0.001);
            info!(
                "spans/s: {} (avg: {:.0}) | total spans: {} | total records: {} | elapsed: {:.1}s",
                delta,
                spans as f64 / elapsed,
                spans,
                records,
                elapsed,
            );
            last_spans = spans;
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

    info!(
        "OTLP firehose complete: {} spans, {} total records shipped.",
        spans_sent.load(Ordering::Relaxed),
        records_sent.load(Ordering::Relaxed),
    );
    Ok(())
}

// =============================================================================
// Combo-join (spans <-> logs correlation) — NAN-1566
// =============================================================================

use event_core::http::{insert_combo_log_rows, ComboLogRow};
use std::collections::VecDeque;

/// Cap on the shared trace_id pool. Bounded so a long run doesn't grow the
/// VecDeque unboundedly — the log side pulls recent ids, the span side pushes,
/// and the oldest ids age out. ~5000 keeps a healthy window of correlatable
/// traces without retaining the whole run.
const COMBO_POOL_CAP: usize = 5000;

/// Shared bounded pool of recently-minted span trace_ids. The span generator
/// pushes the trace_ids it emits; the UDM-log generator pops a real one for the
/// `combo-join-fraction` of logs that should correlate. parking_lot::Mutex (no
/// awaits held across the lock) keeps contention cheap.
type TraceIdPool = Arc<parking_lot::Mutex<VecDeque<String>>>;

/// Push a trace_id into the bounded pool, evicting the oldest if at capacity.
fn pool_push(pool: &TraceIdPool, trace_id: String) {
    let mut p = pool.lock();
    if p.len() >= COMBO_POOL_CAP {
        p.pop_front();
    }
    p.push_back(trace_id);
}

/// Pop a recent trace_id from the pool (back = most recently minted, so the log
/// correlates to a fresh span). `None` if the pool hasn't been primed yet.
fn pool_pop_recent(pool: &TraceIdPool) -> Option<String> {
    pool.lock().pop_back()
}

/// Build the combo-join ClickHouse transport and run the span + log lanes
/// together. combo-join ALWAYS uses the direct-to-ClickHouse path: spans ride
/// the OTLP-direct lane into `otel_spans`, and the correlated security logs are
/// inserted directly into `nanosiem.logs` (the demo source-type parsers don't
/// carry trace_id through Vector, so direct-CH is the only deterministic
/// delivery for a validatable spans<->logs overlap).
async fn run_combo_join_entry(args: Args) -> Result<()> {
    let fraction = args.combo_join_fraction.clamp(0.0, 1.0);
    let transport = Transport::OtlpClickHouse {
        url: args.clickhouse_url.clone(),
        user: args.clickhouse_user.clone(),
        password: args.clickhouse_password.clone(),
    };

    info!(
        "COMBO-JOIN MODE → {} (spans→otel_spans, {:.0}% of logs carry a span trace_id → nanosiem.logs)",
        args.clickhouse_url,
        fraction * 100.0,
    );
    info!("Initializing World State ({} assets)...", args.assets);
    let world = Arc::new(parking_lot::RwLock::new(WorldState::new(args.assets)));

    let pool: TraceIdPool = Arc::new(parking_lot::Mutex::new(VecDeque::with_capacity(
        COMBO_POOL_CAP,
    )));

    run_combo_join_mode(args, transport, world, pool, fraction).await
}

/// Run the span side and the UDM-log side concurrently, sharing the trace_id
/// pool. Two tasks: the span task generates OTLP traces (shipping each tick's
/// spans to `otel_spans` via the OTLP-direct lane) and pushes the trace_ids it
/// minted into the pool; the log task generates UDM security logs where
/// `fraction` of them pop a real trace_id from the pool. `--rate` paces the log
/// lane (epm); the span lane runs at the same tick cadence. `--duration`
/// (minutes) bounds the run (0 = until ctrl-c).
async fn run_combo_join_mode(
    args: Args,
    transport: Transport,
    world: Arc<parking_lot::RwLock<WorldState>>,
    pool: TraceIdPool,
    fraction: f64,
) -> Result<()> {
    let sleep_ms: u64 = (60_000.0 / (args.rate.max(1) as f64)) as u64;
    let batch = args.otlp_batch.max(1);
    // In --blast scale the per-tick batch up so the firehose isn't paced by the
    // epm sleep alone; otherwise honor --otlp-batch.
    let log_batch = if args.blast { args.batch_size.max(1) } else { batch };
    let duration = args.duration;
    let quiet = args.quiet;

    let spans_sent = Arc::new(AtomicU64::new(0));
    let logs_sent = Arc::new(AtomicU64::new(0));
    let correlated_sent = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    // --- Span lane: generate traces, ship to otel_spans, push trace_ids -------
    let span_task = {
        let transport = transport.clone();
        let world = world.clone();
        let pool = pool.clone();
        let running = running.clone();
        let spans_sent = spans_sent.clone();
        let span_batch = batch;
        tokio::spawn(async move {
            let client = match Client::builder()
                .pool_max_idle_per_host(4)
                .connect_timeout(TokioDuration::from_secs(10))
                .timeout(TokioDuration::from_secs(30))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    error!("combo-join span lane: failed to build HTTP client: {}", e);
                    return;
                }
            };
            let mut rng = rand::rngs::StdRng::from_os_rng();
            let mut consecutive_errors = 0u32;

            while running.load(Ordering::Relaxed) {
                // Generate `span_batch` traces (lock held only for generation).
                let spans: Vec<Value> = {
                    let w = world.read();
                    let mut acc = Vec::new();
                    for _ in 0..span_batch {
                        let entity = w.random_entity();
                        acc.extend(event_core::otlp::gen_trace(entity, &mut rng));
                    }
                    acc
                };

                // Mint the pool entries: one trace_id per ROOT span (the first of
                // each trace). gen_trace returns spans in DAG order (root first),
                // and every span in a trace shares the trace_id, so de-dup.
                let mut seen = std::collections::HashSet::new();
                for s in &spans {
                    if let Some(tid) = s["traceId"].as_str() {
                        if seen.insert(tid.to_string()) {
                            pool_push(&pool, tid.to_string());
                        }
                    }
                }

                match send_otlp_with_retry(&client, &transport, OtlpSignal::Traces, &spans, 3).await
                {
                    Ok(()) => {
                        consecutive_errors = 0;
                        spans_sent.fetch_add(spans.len() as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        warn!(
                            "combo-join span lane: ship error: {} (consecutive: {})",
                            e, consecutive_errors
                        );
                        if consecutive_errors >= 10 {
                            error!("combo-join span lane: 10 consecutive failures, backing off 10s");
                            tokio::time::sleep(TokioDuration::from_secs(10)).await;
                            consecutive_errors = 0;
                        }
                    }
                }

                if sleep_ms > 0 {
                    tokio::time::sleep(TokioDuration::from_millis(sleep_ms)).await;
                }
            }
        })
    };

    // --- Log lane: generate UDM security logs, pull pool trace_ids ------------
    let log_task = {
        let transport = transport.clone();
        let world = world.clone();
        let pool = pool.clone();
        let running = running.clone();
        let logs_sent = logs_sent.clone();
        let correlated_sent = correlated_sent.clone();
        tokio::spawn(async move {
            let client = match Client::builder()
                .pool_max_idle_per_host(4)
                .connect_timeout(TokioDuration::from_secs(10))
                .timeout(TokioDuration::from_secs(30))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    error!("combo-join log lane: failed to build HTTP client: {}", e);
                    return;
                }
            };
            let mut rng = rand::rngs::StdRng::from_os_rng();
            let mut consecutive_errors = 0u32;
            // Small head-start so the span lane primes the pool before the log
            // lane starts pulling correlated ids.
            tokio::time::sleep(TokioDuration::from_millis(250)).await;

            while running.load(Ordering::Relaxed) {
                let rows: Vec<ComboLogRow> = {
                    let w = world.read();
                    let mut acc = Vec::with_capacity(log_batch);
                    for _ in 0..log_batch {
                        let entity = w.random_entity();
                        // `fraction` of rows correlate: pull a real span trace_id
                        // from the pool. If the pool is empty (not yet primed) or
                        // this row isn't selected, emit a normal uncorrelated log.
                        let want_corr = rng.random_bool(fraction);
                        let trace_id = if want_corr {
                            pool_pop_recent(&pool).unwrap_or_default()
                        } else {
                            String::new()
                        };
                        acc.push(ComboLogRow {
                            trace_id,
                            user: entity.user.clone(),
                            src_ip: entity.ip.clone(),
                            // Correlated rows are auth FAILURES (the meaningful
                            // security pivot); uncorrelated rows mix success too.
                            failure: want_corr || rng.random_bool(0.4),
                        });
                    }
                    acc
                };

                let n_corr = rows.iter().filter(|r| !r.trace_id.is_empty()).count() as u64;

                match insert_combo_log_rows(&client, &transport, &rows).await {
                    Ok(()) => {
                        consecutive_errors = 0;
                        logs_sent.fetch_add(rows.len() as u64, Ordering::Relaxed);
                        correlated_sent.fetch_add(n_corr, Ordering::Relaxed);
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        warn!(
                            "combo-join log lane: insert error: {} (consecutive: {})",
                            e, consecutive_errors
                        );
                        if consecutive_errors >= 10 {
                            error!("combo-join log lane: 10 consecutive failures, backing off 10s");
                            tokio::time::sleep(TokioDuration::from_secs(10)).await;
                            consecutive_errors = 0;
                        }
                    }
                }

                if sleep_ms > 0 {
                    tokio::time::sleep(TokioDuration::from_millis(sleep_ms)).await;
                }
            }
        })
    };

    // --- Stats reporter -------------------------------------------------------
    let stats_handle = {
        let spans_sent = spans_sent.clone();
        let logs_sent = logs_sent.clone();
        let correlated_sent = correlated_sent.clone();
        let running = running.clone();
        tokio::spawn(async move {
            let mut tick = interval(TokioDuration::from_secs(1));
            let start = Instant::now();
            while running.load(Ordering::Relaxed) {
                tick.tick().await;
                if quiet {
                    continue;
                }
                info!(
                    "[COMBO] spans: {} | logs: {} ({} correlated) | elapsed: {:.1}s",
                    spans_sent.load(Ordering::Relaxed),
                    logs_sent.load(Ordering::Relaxed),
                    correlated_sent.load(Ordering::Relaxed),
                    start.elapsed().as_secs_f64(),
                );
            }
        })
    };

    if duration > 0 {
        tokio::time::sleep(TokioDuration::from_secs(duration * 60)).await;
        running.store(false, Ordering::Relaxed);
    } else {
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");
        running.store(false, Ordering::Relaxed);
    }

    let _ = span_task.await;
    let _ = log_task.await;
    stats_handle.abort();

    info!(
        "Combo-join complete: {} spans, {} logs ({} correlated to a span trace_id).",
        spans_sent.load(Ordering::Relaxed),
        logs_sent.load(Ordering::Relaxed),
        correlated_sent.load(Ordering::Relaxed),
    );
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

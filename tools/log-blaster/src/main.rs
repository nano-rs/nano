// SPDX-License-Identifier: AGPL-3.0-or-later

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
//!   log-blaster --otlp --blast --eps 2000 --threads 4 --otlp-batch 20         # OTLP firehose → Vector :4318

mod source_tokens;
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
use tokio::time::{interval, sleep_until, Duration as TokioDuration, Instant as TokioInstant};
use tracing::{error, info, warn};

use event_core::entity::WorldState;
use event_core::event::Event;
use event_core::generators::{
    ApacheGenerator, CloudTrailGenerator, LateralChainGenerator, ProxyGenerator, SysmonGenerator,
    WindowsEventGenerator,
};
use event_core::http::{
    send_batch_with_retry, send_event, send_otlp_with_retry, OtlpSignal, RetryPolicy, Transport,
};
use event_core::profiles;

/// Retries for blast paths that predate forwarder-style delivery.
const LEGACY_SEND_RETRIES: u32 = 3;

/// NAN-2988: the source-credential blast retries like a forwarder unless
/// --send-retries bounds it; the deadline applies either way (0 = none).
fn source_retry_policy(send_retries: Option<u32>, deadline_secs: u64) -> RetryPolicy {
    let deadline = (deadline_secs > 0).then(|| TokioDuration::from_secs(deadline_secs));
    RetryPolicy {
        max_retries: send_retries,
        deadline,
    }
}

#[derive(Parser, Debug)]
#[command(name = "log-blaster")]
#[command(about = "Profile-driven SIEM log generator using real telemetry data")]
#[command(
    after_help = "Hosted source mode example:\n  log-blaster --vector https://tenant1.ingest.nano.rs --blast --eps 2000 --duration 5 \\\n    --source-token windows_sysmon=$SYSMON_TOKEN --source-token windows_event=$WINDOWS_TOKEN \\\n    --source-token conduit_proxy=$PROXY_TOKEN --source-token aws_cloudtrail=$CLOUDTRAIL_TOKEN \\\n    --source-token apache_http_server=$APACHE_TOKEN\nSee tools/log-blaster/README.md for accounting and credential precedence."
)]
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

    /// Per-source Vector or HEC blast credential (repeatable). Also reads SOURCE_TOKENS
    /// as source_type=token,source_type=token; CLI entries override matching env entries.
    /// Implies source-homogeneous batches; missing credentials use --token or
    /// VECTOR_AUTH_TOKEN, otherwise that source is skipped (no dev default).
    #[arg(long, value_name = "SOURCE_TYPE=TOKEN", requires = "blast")]
    source_token: Vec<String>,

    /// Restrict the Vector or HEC blast mix to these comma-separated source types.
    #[arg(long, value_delimiter = ',', requires = "blast")]
    sources: Vec<String>,

    /// Stable-key namespace for durable Vector/HEC source requests. Every
    /// logical request gets a unique UUID suffix; retries retain the same key.
    /// Unset by default for both transports; retries without a key may duplicate events.
    #[arg(long)]
    idempotency_key_prefix: Option<String>,

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

    /// Maximum time to accumulate a paced blast batch before sending it.
    #[arg(long, default_value = "2000", value_parser = clap::value_parser!(u64).range(1..))]
    max_batch_latency_ms: u64,

    /// Keep each Vector blast request source-homogeneous while preserving the
    /// default aggregate source mix. Vector carries `X-Source-Type` at the
    /// request level, so a mixed batch is otherwise split into five smaller
    /// requests by the transport. Hosted durable-ingest capacity gates use
    /// this to model customer Vector aggregators without changing the default
    /// open-core load-generator behavior.
    #[arg(long, requires = "blast")]
    vector_source_homogeneous_batches: bool,

    /// Maximum acknowledged HTTP batches in flight per sender thread.
    ///
    /// Vector object-sink acknowledgements can take tens of seconds. Keep this
    /// bounded, but make it explicit so a durable-ACK capacity run can size the
    /// window from measured request latency instead of silently rate-limiting
    /// the generator.
    #[arg(long, default_value = "16")]
    inflight_per_thread: usize,

    /// Send exactly this many blast batches per sender thread, then drain all
    /// acknowledged sends and exit. Intended for short, repeatable throughput
    /// sweeps where a wall-clock duration would hide the in-flight tail.
    #[arg(long)]
    blast_batches_per_thread: Option<usize>,

    /// Retries for each raw-event HTTP group in blast mode. With source
    /// credentials (--source-token/SOURCE_TOKENS/--sources) the default is to
    /// retry like a real forwarder: every 429/503/5xx/timeout is retried with
    /// the identical body (and key when explicitly configured), honouring
    /// Retry-After, until accepted or --send-deadline-secs runs out (NAN-2988).
    /// Setting this bounds the retries instead. Other blast paths default to 3.
    #[arg(long, value_parser = clap::value_parser!(u32).range(0..))]
    send_retries: Option<u32>,

    /// How long one source-credential batch keeps retrying a retryable failure
    /// before it is counted lost (0 = never give up). Only a permanent 4xx
    /// refusal is dropped earlier.
    #[arg(long, default_value = "900")]
    send_deadline_secs: u64,

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
    /// (OTLP/HTTP protobuf to :4318). Honors --epm/--rate, --blast, --duration.
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

    /// OTLP records generated per tick (NAN-1545 firehose). Each tick sources
    /// ONE fleet entity and generates K full signal sets (K traces, K metric
    /// scrapes, K correlated logs, …), then ships each signal lane as a SINGLE
    /// bulk OTLP POST — the cheapest throughput multiplier
    /// (amortizes one request over K records). Default 1 preserves the original
    /// one-entity-per-tick behavior. Combine with `--blast --eps --threads` to
    /// scale: spans/s ≈ eps × threads × otlp-batch × spans-per-trace.
    #[arg(long, default_value = "1")]
    otlp_batch: usize,

    // --- Realistic variance (NAN-3174) — all opt-in --------------------------
    /// Variance preset. `realistic` turns on every knob below with sensible
    /// values (--entity-skew 1.0, --hash-pool 50000, --cmdline-variance,
    /// --time-jitter, --diurnal 0.5, --burst 0.05,3,15); any knob passed
    /// explicitly with a non-default value wins over the preset. `off`
    /// (default) leaves output identical to previous releases.
    #[arg(long, value_enum, default_value = "off")]
    variance: VariancePreset,

    /// Zipf skew for host/user popularity (`random_entity`). 0 = uniform
    /// (default). ~1.0 gives a realistic long tail: a few busy servers and
    /// workstations, many quiet ones.
    #[arg(long, default_value = "0")]
    entity_skew: f64,

    /// Synthesize this many extra deterministic SHA-256 file hashes (seeded by
    /// --variance-seed) as a long tail behind the profile hashes. 0 = off.
    #[arg(long, default_value = "0")]
    hash_pool: usize,

    /// Zipf skew over [profile hashes ∪ synthetic pool]; higher = rarer tail.
    #[arg(long, default_value = "1.1")]
    hash_skew: f64,

    /// Append random arguments/paths to profile command lines.
    #[arg(long)]
    cmdline_variance: bool,

    /// Blast mode: give each event its own timestamp spread over the batch
    /// period (sorted, mildly reordered) instead of one shared `now`.
    #[arg(long)]
    time_jitter: bool,

    /// Blast mode: 24 h sine amplitude on the target EPS (0..1, peak ~14:00
    /// UTC). The daily average stays ~--eps. 0 = flat (default).
    #[arg(long, default_value = "0")]
    diurnal: f64,

    /// Blast mode: `prob,mult,secs` — each minute, with probability `prob`, run
    /// at `mult`× EPS for the first `secs` seconds. Normalized so the long-run
    /// average stays ~--eps.
    #[arg(long)]
    burst: Option<event_core::variance::BurstSpec>,

    /// Seed for the variance structure (popular-host ranking, synthetic hash
    /// set, burst schedule). Default: random.
    #[arg(long)]
    variance_seed: Option<u64>,
}

/// NAN-3174: `--variance` presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum VariancePreset {
    /// No variance (historical uniform behavior).
    Off,
    /// Skewed entities, long-tail hashes, varied command lines, per-event
    /// timestamps, diurnal rate and occasional bursts.
    Realistic,
}

/// Values `--variance realistic` fills in for knobs left at their defaults.
const REALISTIC_ENTITY_SKEW: f64 = 1.0;
const REALISTIC_HASH_POOL: usize = 50_000;
const REALISTIC_DIURNAL: f64 = 0.5;
const REALISTIC_BURST: event_core::variance::BurstSpec = event_core::variance::BurstSpec {
    prob: 0.05,
    mult: 3.0,
    secs: 15,
};

/// NAN-3174: resolved variance settings. `None` from [`VarianceSettings::from_args`]
/// means every flag is at its default and no variance code runs.
#[derive(Debug, Clone, Copy)]
struct VarianceSettings {
    seed: u64,
    entity_skew: f64,
    hash_pool: usize,
    hash_skew: f64,
    cmdline_variance: bool,
    time_jitter: bool,
    rate: event_core::variance::RateShape,
}

impl VarianceSettings {
    fn from_args(args: &Args) -> Result<Option<Self>> {
        anyhow::ensure!(
            args.entity_skew >= 0.0 && args.entity_skew.is_finite(),
            "--entity-skew must be >= 0"
        );
        anyhow::ensure!(
            args.hash_skew >= 0.0 && args.hash_skew.is_finite(),
            "--hash-skew must be >= 0"
        );
        anyhow::ensure!(
            (0.0..1.0).contains(&args.diurnal),
            "--diurnal must be in [0, 1)"
        );
        let realistic = args.variance == VariancePreset::Realistic;
        // Explicit non-default knobs win; defaults take the preset value.
        let entity_skew = if realistic && args.entity_skew == 0.0 {
            REALISTIC_ENTITY_SKEW
        } else {
            args.entity_skew
        };
        let hash_pool = if realistic && args.hash_pool == 0 {
            REALISTIC_HASH_POOL
        } else {
            args.hash_pool
        };
        let diurnal = if realistic && args.diurnal == 0.0 {
            REALISTIC_DIURNAL
        } else {
            args.diurnal
        };
        let burst = args.burst.or(realistic.then_some(REALISTIC_BURST));
        let cmdline_variance = args.cmdline_variance || realistic;
        let time_jitter = args.time_jitter || realistic;

        let active = entity_skew > 0.0
            || hash_pool > 0
            || cmdline_variance
            || time_jitter
            || diurnal > 0.0
            || burst.is_some();
        if !active {
            return Ok(None);
        }
        let seed = args.variance_seed.unwrap_or_else(rand::random);
        Ok(Some(Self {
            seed,
            entity_skew,
            hash_pool,
            hash_skew: args.hash_skew,
            cmdline_variance,
            time_jitter,
            rate: event_core::variance::RateShape {
                diurnal,
                burst,
                seed,
            },
        }))
    }

    /// Install generator hooks and skew the world. Called once at startup.
    fn apply(&self, world: &mut WorldState) {
        use event_core::variance;
        world.set_entity_skew(self.entity_skew, self.seed);
        let hash_pool = (self.hash_pool > 0).then(|| {
            variance::HashPool::new(
                profiles::profiles().file_hashes.len(),
                self.hash_pool,
                self.hash_skew,
                self.seed,
            )
        });
        variance::install(variance::GeneratorVariance {
            hash_pool,
            cmdline_variance: self.cmdline_variance,
        });
        info!(
            "VARIANCE: seed={} entity_skew={} hash_pool={} hash_skew={} \
             cmdline_variance={} time_jitter={} diurnal={} burst={}",
            self.seed,
            self.entity_skew,
            self.hash_pool,
            self.hash_skew,
            self.cmdline_variance,
            self.time_jitter,
            self.rate.diurnal,
            self.rate
                .burst
                .map(|b| format!("{}x for {}s @ p={}/min", b.mult, b.secs, b.prob))
                .unwrap_or_else(|| "off".into()),
        );
    }
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
    let source_env = std::env::var("SOURCE_TOKENS")
        .ok()
        .filter(|s| !s.is_empty());
    let fallback = args
        .token
        .clone()
        .or_else(|| std::env::var("VECTOR_AUTH_TOKEN").ok());
    let source_config =
        if !args.source_token.is_empty() || !args.sources.is_empty() || source_env.is_some() {
            source_tokens::SourceConfig::resolve(&mut args, source_env.as_deref(), fallback)?
        } else {
            source_tokens::SourceConfig::default()
        };

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
    // own transport (OtlpHttp -> Vector :4318) and
    // runs `run_otlp_mode`. Short-circuit the Vector/HEC/Tenzir path-suffix and
    // token resolution below and dispatch directly.
    if args.otlp {
        return run_otlp_entry(args).await;
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
    if args.token.is_none() && args.tenzir.is_none() && !source_config.configured {
        let resolved = std::env::var("VECTOR_AUTH_TOKEN")
            .unwrap_or_else(|_| "nanosiem-default-token".to_string());
        info!(
            "Using {} auth token: ***{}",
            if args.hec { "HEC" } else { "Vector" },
            tail4(&resolved)
        );
        args.token = Some(resolved);
    }

    if let Some(prefix) = args.idempotency_key_prefix.as_deref() {
        let valid = (1..=90).contains(&prefix.len())
            && prefix.is_ascii()
            && prefix.bytes().enumerate().all(|(index, byte)| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => true,
                b'.' | b'_' | b':' | b'~' | b'-' => index > 0,
                _ => false,
            });
        if !valid {
            anyhow::bail!(
                "--idempotency-key-prefix must be 1-90 ASCII characters and match [A-Za-z0-9][A-Za-z0-9._:~-]*"
            );
        }
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
            idempotency_key_prefix: args.idempotency_key_prefix.clone(),
        }
    };

    info!("Initializing World State ({} assets)...", args.assets);
    let variance = VarianceSettings::from_args(&args)?;
    let mut initial_world = WorldState::new(args.assets);
    match &variance {
        Some(v) => v.apply(&mut initial_world),
        None => info!("Variance: off (uniform entities, profile hashes, flat rate)"),
    }
    let world = Arc::new(parking_lot::RwLock::new(initial_world));

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
        println!("  Source types:  windows_sysmon, windows_event, conduit_proxy, aws_cloudtrail");
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
    if source_config.configured && args.chain_interval_secs > 0 {
        warn!("Lateral chain emitter disabled for a restricted source mix; blast accounting covers the selected sources");
    }
    let chain_handle = if args.chain_interval_secs > 0 && !source_config.configured {
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
        run_blast_mode(args, transport, world, source_config, variance).await
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
                warn!(
                    "chain emitter: failed to send batch ({} events): {}",
                    batch.len(),
                    e
                );
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HomogeneousBlastSource {
    Sysmon,
    WindowsEvent,
    Proxy,
    Apache,
    CloudTrail,
}

/// A smooth 50-request schedule with the exact historical source mix:
/// 60% Sysmon, 10% Windows Event, 12% proxy, 10% Apache, 8% CloudTrail.
/// Keeping this deterministic makes fixed-batch capacity gates repeatable.
const HOMOGENEOUS_BLAST_SOURCE_CYCLE: [HomogeneousBlastSource; 50] = [
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Proxy,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::WindowsEvent,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Proxy,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Apache,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::WindowsEvent,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::CloudTrail,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Proxy,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Apache,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::WindowsEvent,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::CloudTrail,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Proxy,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Apache,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::WindowsEvent,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::CloudTrail,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Proxy,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Apache,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::WindowsEvent,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::CloudTrail,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Proxy,
    HomogeneousBlastSource::Sysmon,
    HomogeneousBlastSource::Apache,
    HomogeneousBlastSource::Sysmon,
];

/// NAN-3174: batch period at a rate multiplier. Clamped so a deep diurnal
/// trough never sleeps a sender for more than 10 s per batch.
fn shaped_eps(base: f64, multiplier: f64) -> f64 {
    base * multiplier.max(0.01)
}

fn homogeneous_blast_mix(batch_index: usize) -> spike::SourceMix {
    match HOMOGENEOUS_BLAST_SOURCE_CYCLE[batch_index % HOMOGENEOUS_BLAST_SOURCE_CYCLE.len()] {
        HomogeneousBlastSource::Sysmon => spike::SourceMix {
            sysmon: 1.0,
            ..Default::default()
        },
        HomogeneousBlastSource::WindowsEvent => spike::SourceMix {
            winevt: 1.0,
            ..Default::default()
        },
        HomogeneousBlastSource::Proxy => spike::SourceMix {
            proxy: 1.0,
            ..Default::default()
        },
        HomogeneousBlastSource::Apache => spike::SourceMix {
            apache: 1.0,
            ..Default::default()
        },
        HomogeneousBlastSource::CloudTrail => spike::SourceMix {
            cloudtrail: 1.0,
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod homogeneous_blast_tests {
    use super::{homogeneous_blast_mix, HomogeneousBlastSource, HOMOGENEOUS_BLAST_SOURCE_CYCLE};

    #[test]
    fn source_cycle_preserves_the_default_mix_exactly() {
        let count = |source| {
            HOMOGENEOUS_BLAST_SOURCE_CYCLE
                .iter()
                .filter(|candidate| **candidate == source)
                .count()
        };

        assert_eq!(count(HomogeneousBlastSource::Sysmon), 30);
        assert_eq!(count(HomogeneousBlastSource::WindowsEvent), 5);
        assert_eq!(count(HomogeneousBlastSource::Proxy), 6);
        assert_eq!(count(HomogeneousBlastSource::Apache), 5);
        assert_eq!(count(HomogeneousBlastSource::CloudTrail), 4);
    }

    #[test]
    fn every_scheduled_mix_is_source_homogeneous() {
        for batch_index in 0..HOMOGENEOUS_BLAST_SOURCE_CYCLE.len() * 2 {
            let mix = homogeneous_blast_mix(batch_index);
            let weights = [
                mix.sysmon,
                mix.winevt,
                mix.proxy,
                mix.apache,
                mix.cloudtrail,
            ];
            assert_eq!(weights.iter().filter(|weight| **weight == 1.0).count(), 1);
            assert_eq!(weights.iter().filter(|weight| **weight == 0.0).count(), 4);
        }
    }
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

/// Number of paced events that fit before the maximum batch age.
fn paced_batch_size(requested: usize, eps: f64, latency: TokioDuration) -> usize {
    if eps == 0.0 {
        return requested;
    }
    requested.min((eps * latency.as_secs_f64()).floor().max(1.0) as usize)
}

async fn run_blast_mode(
    args: Args,
    transport: Transport,
    world: Arc<parking_lot::RwLock<WorldState>>,
    source_config: source_tokens::SourceConfig,
    variance: Option<VarianceSettings>,
) -> Result<()> {
    if !(1..=64).contains(&args.inflight_per_thread) {
        anyhow::bail!("--inflight-per-thread must be between 1 and 64");
    }
    if args.vector_source_homogeneous_batches && !matches!(transport, Transport::Vector { .. }) {
        anyhow::bail!("--vector-source-homogeneous-batches requires the Vector transport");
    }
    anyhow::ensure!(
        args.threads > 0 && args.batch_size > 0,
        "--threads and --batch-size must be positive"
    );
    let eps_per_thread_raw = args.eps as f64 / args.threads as f64;
    let effective_batch_size = paced_batch_size(
        args.batch_size,
        eps_per_thread_raw,
        TokioDuration::from_millis(args.max_batch_latency_ms),
    );

    info!(
        "BLAST MODE: Target {} EPS with {} threads, batch size {} (requested {}), Vector source-homogeneous batches: {}",
        args.eps,
        args.threads,
        effective_batch_size,
        args.batch_size,
        args.vector_source_homogeneous_batches
    );

    let accounting = source_tokens::Accounting::default();
    let events_sent = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    // Durable Vector acknowledgements include the object sink's flush window.
    // The caller sizes this bounded window from observed ACK latency and actual
    // events per request; the default preserves the established behavior.
    let inflight_per_thread = args.inflight_per_thread;
    let batches_per_thread = args.blast_batches_per_thread;
    let vector_source_homogeneous_batches = args.vector_source_homogeneous_batches;
    let thread_count = args.threads;
    let max_batch_latency = TokioDuration::from_millis(args.max_batch_latency_ms);
    let mut handles = Vec::new();
    for thread_id in 0..args.threads {
        let transport = transport.clone();
        let source_config = source_config.clone();
        let accounting = accounting.clone();
        let events_sent = events_sent.clone();
        let running = running.clone();
        let worker_world = world.clone();
        let requested_batch_size = args.batch_size;
        let max_inflight = inflight_per_thread;
        let send_retries = args.send_retries.unwrap_or(LEGACY_SEND_RETRIES);
        let source_policy = source_retry_policy(args.send_retries, args.send_deadline_secs);
        let batch_limit = batches_per_thread;
        let source_homogeneous = vector_source_homogeneous_batches
            || (matches!(transport, Transport::Hec { .. }) && source_config.configured);
        // NAN-3174: per-event jitter + shaped rate; both None/false by default.
        let time_jitter = variance.is_some_and(|v| v.time_jitter);
        let rate_shape = variance.map(|v| v.rate).filter(|r| !r.is_flat());

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
            let mut send_tasks = tokio::task::JoinSet::new();
            let mut scheduled_batches = 0usize;
            let mut next_batch_at = TokioInstant::now();

            while running.load(Ordering::Relaxed) {
                while let Some(result) = send_tasks.try_join_next() {
                    result.expect("blast send task panicked");
                }
                if batch_limit.is_some_and(|limit| scheduled_batches >= limit) {
                    break;
                }
                let eps = rate_shape.map_or(eps_per_thread_raw, |shape| {
                    shaped_eps(eps_per_thread_raw, shape.multiplier(Utc::now()))
                });
                let batch_size = paced_batch_size(requested_batch_size, eps, max_batch_latency);
                let this_period =
                    (eps > 0.0).then(|| TokioDuration::from_secs_f64(batch_size as f64 / eps));
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                if !running.load(Ordering::Relaxed) && batch_limit.is_none() {
                    break;
                }

                let sim_time = Utc::now();
                let mut batch = Vec::with_capacity(batch_size);
                let mut flush_at = None;
                let batch_mix = if source_homogeneous {
                    homogeneous_blast_mix(if source_config.configured {
                        source_config.cycle[(scheduled_batches * thread_count + thread_id)
                            % source_config.cycle.len()]
                    } else {
                        scheduled_batches * thread_count + thread_id
                    })
                } else if source_config.configured {
                    source_config.mix()
                } else {
                    spike::DEFAULT_MIX
                };
                let timestamps = time_jitter.then(|| {
                    event_core::variance::batch_timestamps(
                        sim_time,
                        batch_size,
                        this_period.unwrap_or(TokioDuration::from_secs(1)),
                        true,
                        &mut rng,
                    )
                });
                {
                    // Accumulate events at the exact fractional per-worker rate. Sleeping
                    // between events keeps batches bounded by latency without an initial burst.
                    for i in 0..batch_size {
                        if let Some(period) = this_period {
                            let wake_at = flush_at
                                .map_or(next_batch_at, |deadline| next_batch_at.min(deadline));
                            sleep_until(wake_at).await;
                            if flush_at.is_some_and(|deadline| TokioInstant::now() >= deadline) {
                                break;
                            }
                            next_batch_at += period.div_f64(batch_size as f64);
                        }
                        flush_at.get_or_insert_with(|| TokioInstant::now() + max_batch_latency);
                        if !running.load(Ordering::Relaxed) && batch_limit.is_none() {
                            break;
                        }
                        let w = worker_world.read();
                        let entity = w.random_entity();
                        let event = generate_event(
                            timestamps.as_ref().map_or(sim_time, |ts| ts[i]),
                            entity,
                            w.entities(),
                            &sysmon_gen,
                            &winevt_gen,
                            &proxy_gen,
                            &apache_gen,
                            &cloudtrail_gen,
                            &batch_mix,
                            &mut rng,
                        );
                        batch.push(event);
                    }
                }

                if batch.is_empty() {
                    break;
                }
                let batch_len = batch.len() as u64;
                let client = client.clone();
                let transport = transport.clone();
                let events_sent = events_sent.clone();
                let source_config = source_config.clone();
                let accounting = accounting.clone();
                send_tasks.spawn(async move {
                    if matches!(transport, Transport::Vector { .. })
                        || source_config.configured
                        || (matches!(transport, Transport::Hec { .. })
                            && source_config.has_idempotency_prefix())
                    {
                        let accepted = source_tokens::send_batch(
                            &client,
                            &transport,
                            batch,
                            source_policy,
                            &source_config,
                            &accounting,
                        )
                        .await;
                        events_sent.fetch_add(accepted, Ordering::Relaxed);
                    } else {
                        match send_batch_with_retry(&client, &transport, &batch, send_retries).await
                        {
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
                    }
                    drop(permit);
                });
                scheduled_batches += 1;
            }
            while let Some(result) = send_tasks.join_next().await {
                result.expect("blast send task panicked");
            }
        });
        handles.push(handle);
    }

    // Stats reporter
    let stats_events = events_sent.clone();
    let stats_running = running.clone();
    let stats_accounting = accounting.clone();
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
                "EPS: {} (avg: {:.0}) | Total: {} | Elapsed: {:.1}s | {}",
                delta,
                avg_eps,
                current,
                elapsed,
                source_tokens::summary(&stats_accounting)
            );
            last_count = current;
        }
    });

    if batches_per_thread.is_some() {
        // Sender tasks self-terminate at the exact batch bound and drain their
        // acknowledged request tasks before their handles resolve.
    } else if args.duration > 0 {
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
    running.store(false, Ordering::Relaxed);
    stats_handle.abort();

    let total = events_sent.load(Ordering::Relaxed);
    info!(
        "Total events accepted: {} | {}",
        total,
        source_tokens::summary(&accounting)
    );

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

    let transport = Transport::OtlpHttp {
        base_url: otlp_http_base,
        token: args.token.clone(),
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
        let (spans, metrics, logs) = generate_otlp_tick(
            &world,
            wants,
            batch,
            ticks.wrapping_mul(batch as u64),
            &mut rng,
        );

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
/// and ships each lane as ONE bulk OTLP POST. Throughput
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

    // GLOBAL inflight cap across ALL workers: per-thread semaphores let
    // threads×inflight grow without bound. One shared semaphore keeps total
    // in-flight requests bounded regardless of --threads, so the firehose
    // self-throttles instead of overrunning the receiver. ship_otlp_lanes sends
    // each lane sequentially, so one permit ≈ one concurrent request.
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
                    error!(
                        "OTLP worker {}: failed to build HTTP client: {}",
                        thread_id, e
                    );
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
                    tick.wrapping_mul(threads as u64)
                        .wrapping_add(thread_id as u64),
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

#[cfg(test)]
mod variance_tests {
    use super::{shaped_eps, Args, VarianceSettings};
    use clap::Parser;
    use event_core::entity::WorldState;

    #[test]
    fn defaults_run_no_variance_code() {
        let args = Args::parse_from(["log-blaster", "--blast", "--eps", "300"]);
        assert!(VarianceSettings::from_args(&args).unwrap().is_none());
        // Nothing in this test binary installs generator variance, and a fresh
        // world keeps the historical uniform `choose` draw.
        assert!(!event_core::variance::installed());
        assert!(!WorldState::new(50).entity_skew_active());
    }

    #[test]
    fn flags_resolve_with_seed() {
        let args = Args::parse_from([
            "log-blaster",
            "--blast",
            "--entity-skew",
            "1.0",
            "--hash-pool",
            "50000",
            "--hash-skew",
            "1.2",
            "--cmdline-variance",
            "--time-jitter",
            "--diurnal",
            "0.5",
            "--burst",
            "0.1,4,15",
            "--variance-seed",
            "42",
        ]);
        let v = VarianceSettings::from_args(&args).unwrap().unwrap();
        assert_eq!(v.seed, 42);
        assert_eq!(v.rate.seed, 42);
        assert_eq!(v.hash_pool, 50_000);
        assert!(v.time_jitter && v.cmdline_variance);
        let b = v.rate.burst.unwrap();
        assert_eq!((b.prob, b.mult, b.secs), (0.1, 4.0, 15));

        let mut world = WorldState::new(100);
        world.set_entity_skew(v.entity_skew, v.seed);
        assert!(world.entity_skew_active());
    }

    #[test]
    fn realistic_preset_fills_defaults_and_explicit_flags_win() {
        let args = Args::parse_from([
            "log-blaster",
            "--blast",
            "--variance",
            "realistic",
            "--variance-seed",
            "7",
        ]);
        let v = VarianceSettings::from_args(&args).unwrap().unwrap();
        assert_eq!(v.seed, 7);
        assert_eq!(v.entity_skew, super::REALISTIC_ENTITY_SKEW);
        assert_eq!(v.hash_pool, super::REALISTIC_HASH_POOL);
        assert!(v.cmdline_variance && v.time_jitter);
        assert_eq!(v.rate.diurnal, super::REALISTIC_DIURNAL);
        assert_eq!(v.rate.burst, Some(super::REALISTIC_BURST));
        assert!(!v.rate.is_flat());

        let args = Args::parse_from([
            "log-blaster",
            "--variance",
            "realistic",
            "--entity-skew",
            "1.5",
            "--burst",
            "0.5,2,30",
        ]);
        let v = VarianceSettings::from_args(&args).unwrap().unwrap();
        assert_eq!(v.entity_skew, 1.5);
        assert_eq!(v.rate.burst.unwrap().secs, 30);

        let args = Args::parse_from(["log-blaster", "--variance", "off"]);
        assert!(VarianceSettings::from_args(&args).unwrap().is_none());
    }

    #[test]
    fn invalid_variance_flags_are_rejected() {
        for bad in [
            &["log-blaster", "--diurnal", "1.0"][..],
            &["log-blaster", "--entity-skew=-1"][..],
        ] {
            let args = Args::parse_from(bad);
            assert!(VarianceSettings::from_args(&args).is_err(), "{bad:?}");
        }
        assert!(Args::try_parse_from(["log-blaster", "--burst", "0.1,0.5,15"]).is_err());
    }

    #[test]
    fn entity_skew_concentrates_popularity() {
        let mut world = WorldState::new(200);
        let n = world.entities().len();
        let top_share = |w: &WorldState| {
            let mut counts = std::collections::HashMap::<String, u32>::new();
            for _ in 0..40_000 {
                *counts
                    .entry(w.random_entity().hostname.clone())
                    .or_default() += 1;
            }
            let mut c: Vec<u32> = counts.into_values().collect();
            c.sort_unstable_by(|a, b| b.cmp(a));
            c.iter().take(n / 10).sum::<u32>() as f64 / 40_000.0
        };
        let uniform = top_share(&world);
        world.set_entity_skew(1.0, 42);
        let skewed = top_share(&world);
        // Uniform: top 10% of hosts ≈ 10-13% of events. Zipf(1): > 50%.
        assert!(uniform < 0.2, "uniform top-10% share {uniform}");
        assert!(skewed > 0.5, "skewed top-10% share {skewed}");
        world.set_entity_skew(0.0, 42);
        assert!(!world.entity_skew_active());
    }

    #[test]
    fn shaped_eps_scales_and_clamps() {
        assert_eq!(shaped_eps(100.0, 1.0), 100.0);
        assert_eq!(shaped_eps(100.0, 2.0), 200.0);
        assert_eq!(shaped_eps(100.0, 0.001), 1.0);
    }
}

#[cfg(test)]
mod paced_batch_tests {
    use super::*;

    #[test]
    fn size_and_latency_bounds_preserve_fractional_eps() {
        let latency = TokioDuration::from_secs(2);
        assert_eq!(paced_batch_size(500, 300.0 / 2.0, latency), 300);
        assert_eq!(paced_batch_size(100, 300.0 / 8.0, latency), 75);
        assert_eq!(paced_batch_size(500, 1000.0, latency), 500);
        for threads in [2, 8, 400] {
            let eps = 300.0 / threads as f64;
            let size = paced_batch_size(500, eps, latency);
            let period = size as f64 / eps;
            assert!((size as f64 / period * threads as f64 - 300.0).abs() < 1e-9);
            assert!((size - 1) as f64 / eps <= latency.as_secs_f64());
        }
    }
}

#[cfg(test)]
mod blast_accumulation_tests {
    use super::*;
    use clap::Parser;

    #[tokio::test]
    async fn accumulates_to_size_or_latency_with_exact_eps_and_one_source() {
        for (requested, expected) in [(3, 3), (100, 5)] {
            let (url, receiver) =
                source_tokens::tests::scripted_receiver(vec![("200 OK", None); 4]).await;
            // 105 / 2 = 52.5 EPS, not the old truncated 52 EPS.
            let mut args = Args::parse_from([
                "log-blaster",
                "--blast",
                "--hec",
                "--eps",
                "105",
                "--threads",
                "2",
                "--batch-size",
                &requested.to_string(),
                "--max-batch-latency-ms",
                "100",
                "--blast-batches-per-thread",
                "2",
                "--sources",
                "windows_sysmon,windows_event",
                "--chain-interval-secs",
                "0",
            ]);
            let config =
                source_tokens::SourceConfig::resolve(&mut args, None, Some("test-token".into()))
                    .unwrap();
            let started = TokioInstant::now();
            tokio::time::timeout(
                TokioDuration::from_secs(5),
                run_blast_mode(
                    args,
                    Transport::new_hec(url, None),
                    Arc::new(parking_lot::RwLock::new(WorldState::new(10))),
                    config,
                    None,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            let mut seen = receiver.await.unwrap();
            seen.sort_by_key(|(arrival, _)| *arrival);
            for (_, request) in &seen {
                assert!(!request.contains("idempotency-key:"));
                let body = request.split_once("\r\n\r\n").unwrap().1;
                let events: Vec<serde_json::Value> = body
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(events.len(), expected);
                assert!(events
                    .iter()
                    .all(|event| event["sourcetype"] == events[0]["sourcetype"]));
            }
            // First dispatch waits for accumulation, and subsequent requests
            // retain the exact per-worker period rather than burst immediately.
            let first_age = seen[0].0.duration_since(started).as_secs_f64();
            assert!(first_age >= (expected - 1) as f64 / 52.5 - 0.01);
            assert!(first_age < 0.25);
            let spacing = seen[2].0.duration_since(seen[0].0).as_secs_f64();
            assert!((spacing - expected as f64 / 52.5).abs() < 0.025);
        }
    }
}

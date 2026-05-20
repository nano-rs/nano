//! Injector - Attack scenario injection tool for SIEM testing
//!
//! Injects realistic attack chains into a running nano SIEM instance
//! via the Vector HTTP endpoint. Each scenario is a timed sequence of
//! events that simulate a real attack chain using real process hashes
//! and command lines from lab telemetry.
//!
//! Usage:
//!   injector --vector http://localhost:8080 --quick
//!   injector --vector http://localhost:8080 --lateral --target WS-ENG-001
//!   injector --vector http://localhost:8080 --staggered --duration 60
//!   injector --vector http://localhost:8080 --exfil
//!   injector --vector http://localhost:8080 --persistence

mod scenarios;

use anyhow::Result;
use clap::Parser;
use reqwest::Client;
use std::sync::Arc;
use tokio::time::Duration as TokioDuration;
use tracing::info;

use event_core::entity::WorldState;
use event_core::http::{send_batch_with_retry, Transport};
use event_core::profiles;

use scenarios::{exfil, lateral, persistence, quick, staggered, AttackScenario};

#[derive(Parser, Debug)]
#[command(name = "injector")]
#[command(about = "Attack scenario injector for SIEM testing")]
struct Args {
    /// Vector HTTP endpoint
    #[arg(long, default_value = "http://localhost:8080")]
    vector: String,

    /// Vector auth token (Bearer)
    #[arg(long)]
    token: Option<String>,

    /// Target hostname for the attack (random if not specified)
    #[arg(long)]
    target: Option<String>,

    /// Number of simulated assets (hosts) — must match the blaster's --assets value
    #[arg(long, default_value = "2000")]
    assets: usize,

    /// Quiet mode (suppress per-step logs)
    #[arg(short, long)]
    quiet: bool,

    // --- Scenario flags (exactly one required) ---
    /// Quick smash-and-grab attack (<5 minutes)
    #[arg(long)]
    quick: bool,

    /// Lateral movement — pivot across hosts via RDP/SMB
    #[arg(long)]
    lateral: bool,

    /// Low-and-slow APT — C2 beacons spread over hours
    #[arg(long)]
    staggered: bool,

    /// Data exfiltration — staging, compression, upload
    #[arg(long)]
    exfil: bool,

    /// Persistence — scheduled tasks, registry, WMI, startup folder
    #[arg(long)]
    persistence: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("injector=info".parse()?),
        )
        .init();

    let args = Args::parse();

    // Load profiles
    let p = profiles::profiles();
    info!("Profiles loaded: {} process chains", p.process_chains.len());

    // Build world
    let world = Arc::new(parking_lot::RwLock::new(WorldState::new(args.assets)));

    // Pick target
    let target_hostname = args.target.clone().unwrap_or_else(|| {
        let w = world.read();
        w.random_entity().hostname.clone()
    });

    // Select scenario
    let scenario: Box<dyn AttackScenario> = if args.quick {
        Box::new(quick::QuickScenario)
    } else if args.lateral {
        Box::new(lateral::LateralScenario)
    } else if args.staggered {
        Box::new(staggered::StaggeredScenario)
    } else if args.exfil {
        Box::new(exfil::ExfilScenario)
    } else if args.persistence {
        Box::new(persistence::PersistenceScenario)
    } else {
        eprintln!("Error: specify a scenario flag: --quick, --lateral, --staggered, --exfil, or --persistence");
        std::process::exit(1);
    };

    info!(
        "Scenario: {} | Target: {}",
        scenario.name(),
        target_hostname
    );

    // Generate attack steps
    let w = world.read();
    let target = w.get_entity(&target_hostname).unwrap_or_else(|| {
        eprintln!(
            "Target '{}' not found in world state. Available hosts:",
            target_hostname
        );
        for e in w.entities().iter().take(10) {
            eprintln!("  {}", e.hostname);
        }
        std::process::exit(1);
    });

    let steps = scenario.generate(target, w.entities());
    drop(w);

    info!("{} attack steps generated", steps.len());

    // Execute steps with timing. Injector currently only targets Vector
    // HTTP; if HEC injection is needed, add a `--hec` flag and build the
    // matching Transport variant (mirrors log-blaster's NAN-909 wiring).
    let client = Client::builder()
        .connect_timeout(TokioDuration::from_secs(10))
        .timeout(TokioDuration::from_secs(30))
        .build()?;
    let transport = Transport::Vector {
        url: args.vector.clone(),
        token: args.token.clone(),
    };

    let start = std::time::Instant::now();

    for step in &steps {
        // Wait until the step's delay
        let target_elapsed = step.delay;
        let actual_elapsed = start.elapsed();
        if target_elapsed > actual_elapsed {
            tokio::time::sleep(target_elapsed - actual_elapsed).await;
        }

        if !args.quiet {
            println!(
                "[{:>6.1}s] [{}] {} — {} event(s)",
                step.delay.as_secs_f64(),
                step.stage,
                step.description,
                step.events.len()
            );
        }

        if let Err(e) = send_batch_with_retry(&client, &transport, &step.events, 3).await {
            tracing::warn!("Failed to send step '{}': {}", step.description, e);
        }
    }

    let total_events: usize = steps.iter().map(|s| s.events.len()).sum();
    info!(
        "Scenario '{}' complete: {} steps, {} events in {:.1}s",
        scenario.name(),
        steps.len(),
        total_events,
        start.elapsed().as_secs_f64()
    );

    Ok(())
}

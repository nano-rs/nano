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
//!   injector --vector http://localhost:8080 --drive-by --target WS-FIN-042 --user CORP\\alice
//!   injector --hec --vector http://localhost:8088 --token <ingest token> --hunts --hunt-tag r1

mod scenarios;

use anyhow::Result;
use clap::Parser;
use reqwest::Client;
use std::sync::Arc;
use tokio::time::Duration as TokioDuration;
use tracing::info;

use event_core::entity::{Entity, WorldState};
use event_core::http::{send_batch_with_retry, Transport};
use event_core::profiles;

use scenarios::{drive_by, exfil, hunts, lateral, persistence, quick, staggered, AttackScenario};

#[derive(Parser, Debug)]
#[command(name = "injector")]
#[command(about = "Attack scenario injector for SIEM testing")]
struct Args {
    /// Vector HTTP endpoint
    #[arg(long, default_value = "http://localhost:8080")]
    vector: String,

    /// Vector auth token (Bearer). Falls back to `VECTOR_AUTH_TOKEN` (keeps the
    /// token out of argv, visible in `ps` on shared runners).
    #[arg(long, env = "VECTOR_AUTH_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Target hostname for the attack (random if not specified)
    #[arg(long)]
    target: Option<String>,

    /// Override the target user for --drive-by (for example CORP\\alice)
    #[arg(long, requires = "drive_by")]
    user: Option<String>,

    /// SHA-256 of the delivered file in --drive-by (inert telemetry only)
    #[arg(long, requires = "drive_by", value_parser = parse_sha256)]
    sha256: Option<String>,

    /// Leaf filename of the delivered sample in --drive-by
    #[arg(long, requires = "drive_by", value_parser = parse_leaf_filename)]
    malware_filename: Option<String>,

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

    /// Drive-by download — search ad redirect, ZIP delivery, JS execution, and follow-on activity
    #[arg(long)]
    drive_by: bool,

    /// Hunts v2 ground truth (NAN-5561): Office -> encoded PowerShell -> Tor C2 -> dropper,
    /// a password spray ending in a success, SMB lateral movement, DNS tunneling, a benign
    /// SCCM lookalike with 14 days of history, and a prompt-injection string. OCSF JSON events.
    #[arg(long, requires = "hunt_tag")]
    hunts: bool,

    /// Suffix for every host / user / domain the --hunts scenario uses.
    #[arg(long, value_parser = parse_hunt_tag)]
    hunt_tag: Option<String>,

    /// Send through Splunk HEC (`--vector` is then the HEC base URL, `--token` an ingest
    /// token) instead of Vector HTTP.
    #[arg(long)]
    hec: bool,
}

fn parse_hunt_tag(value: &str) -> std::result::Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 24 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("hunt tag must be 1-24 letters, digits or dashes".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_sha256(value: &str) -> std::result::Result<String, String> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("SHA-256 must be exactly 64 hexadecimal characters".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_leaf_filename(value: &str) -> std::result::Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 255
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
    {
        return Err("malware filename must be a non-empty leaf filename".into());
    }
    Ok(value.to_string())
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
    } else if args.hunts {
        Box::new(hunts::HuntsScenario { tag: args.hunt_tag.clone().unwrap_or_default() })
    } else if args.drive_by {
        Box::new(drive_by::DriveByScenario::new(
            args.sha256
                .as_deref()
                .unwrap_or(drive_by::DEFAULT_SAMPLE_SHA256),
            args.malware_filename
                .as_deref()
                .unwrap_or(drive_by::DEFAULT_SAMPLE_NAME),
        ))
    } else {
        eprintln!("Error: specify a scenario flag: --quick, --lateral, --staggered, --exfil, --persistence, --drive-by, or --hunts");
        std::process::exit(1);
    };

    // Generate attack steps
    let steps = {
        let w = world.read();
        let requested_hostname = args.target.as_deref();
        let existing_target = requested_hostname
            .and_then(|hostname| w.get_entity(hostname))
            .or_else(|| requested_hostname.is_none().then(|| w.random_entity()));

        let base_target = existing_target.unwrap_or_else(|| {
            eprintln!(
                "Target '{}' not found in world state. Available hosts:",
                requested_hostname.unwrap_or_default()
            );
            for entity in w.entities().iter().take(10) {
                eprintln!("  {}", entity.hostname);
            }
            std::process::exit(1);
        });

        let custom_target = if args.drive_by && args.user.is_some() {
            Some(Entity::new(
                &base_target.hostname,
                args.user.as_deref().unwrap_or(&base_target.user),
                &base_target.ip,
                &base_target.mac,
                &base_target.domain,
            ))
        } else {
            None
        };
        let target = custom_target.as_ref().unwrap_or(base_target);

        info!(
            "Scenario: {} | Target: {} | User: {}",
            scenario.name(),
            target.hostname,
            target.user
        );

        scenario.generate(target, w.entities())
    };

    info!("{} attack steps generated", steps.len());

    // Execute steps with timing. Injector currently only targets Vector
    // HTTP; if HEC injection is needed, add a `--hec` flag and build the
    // matching Transport variant (mirrors log-blaster's NAN-909 wiring).
    let client = Client::builder()
        .connect_timeout(TokioDuration::from_secs(10))
        .timeout(TokioDuration::from_secs(30))
        .build()?;
    let transport = if args.hec {
        let base = args.vector.trim_end_matches('/');
        let url = if base.ends_with("/services/collector/event") {
            base.to_string()
        } else {
            format!("{base}/services/collector/event")
        };
        Transport::new_hec(url, args.token.clone())
    } else {
        Transport::Vector {
            url: args.vector.clone(),
            token: args.token.clone(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Review N7: the ingest token can come from the environment (never argv,
    /// visible in `ps`), and its value is never printed in `--help`.
    #[test]
    fn the_token_reads_vector_auth_token_from_the_env() {
        use clap::CommandFactory;
        let cmd = Args::command();
        let token = cmd.get_arguments().find(|a| a.get_id() == "token").expect("--token");
        assert_eq!(token.get_env(), Some(std::ffi::OsStr::new("VECTOR_AUTH_TOKEN")));
        assert!(token.is_hide_env_values_set());
        // The flag still wins when given.
        let args = Args::try_parse_from(["injector", "--token", "t1"]).unwrap();
        assert_eq!(args.token.as_deref(), Some("t1"));
    }

    #[test]
    fn sha256_parser_normalizes_valid_input() {
        let uppercase = drive_by::DEFAULT_SAMPLE_SHA256.to_ascii_uppercase();
        assert_eq!(
            parse_sha256(&format!(" {uppercase} ")).expect("valid SHA-256"),
            drive_by::DEFAULT_SAMPLE_SHA256
        );
        assert!(parse_sha256("abc").is_err());
        assert!(parse_sha256(&"z".repeat(64)).is_err());
    }

    #[test]
    fn hunt_tags_are_safe_suffixes() {
        assert_eq!(parse_hunt_tag(" R1-ab ").unwrap(), "r1-ab");
        for bad in ["", "a b", "a.b", "x;rm", &"a".repeat(25)] {
            assert!(parse_hunt_tag(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sample_filename_must_be_a_leaf_name() {
        assert_eq!(
            parse_leaf_filename(" EhDSjenZsx.js ").expect("valid leaf filename"),
            "EhDSjenZsx.js"
        );
        for invalid in ["", ".", "..", "../sample.js", r"folder\sample.js"] {
            assert!(
                parse_leaf_filename(invalid).is_err(),
                "`{invalid}` must be rejected"
            );
        }
    }
}

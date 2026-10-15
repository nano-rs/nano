// SPDX-License-Identifier: AGPL-3.0-or-later

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
//!
//! Ingest-edge targets (NAN-2705): send to a tenant's HEC / HTTPS edge instead of raw Vector.
//! Ingest credentials are per source, so the token file maps each source:
//!   injector --hec-url https://t1.ingest.example/services/collector/event \
//!            --token-file tokens.txt --marker nanoe2eabc123 --host-name E2E-ABC-Q --quick
//!   injector --https-url https://t1.ingest.example/ingest --token-file tokens.txt --persistence
//!   injector --quick --plan          # print the generated steps as JSON, send nothing

mod edge;
mod scenarios;

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::Client;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::Duration as TokioDuration;
use tracing::info;

use event_core::entity::{Entity, WorldState};
use event_core::http::send_batch_with_retry;
use event_core::profiles;

use edge::{SinkKind, SinkRouter};
use scenarios::{drive_by, exfil, lateral, persistence, quick, staggered, AttackScenario, AttackStep};

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

    /// HEC endpoint (…/services/collector/event). Needs --token-file.
    #[arg(long, conflicts_with = "https_url")]
    hec_url: Option<String>,

    /// HTTPS JSON endpoint (…/ingest): NDJSON, Bearer, Idempotency-Key. Needs --token-file.
    #[arg(long)]
    https_url: Option<String>,

    /// Ingest token file: one bare token, and/or `source_type=token` lines
    /// (ingest credentials are per source). Tokens are never printed.
    #[arg(long, conflicts_with = "token")]
    token_file: Option<PathBuf>,

    /// Run marker stamped on every event (`nano_e2e_marker`), 8-64 letters/digits
    #[arg(long, value_parser = edge::parse_marker)]
    marker: Option<String>,

    /// Replace the target (and the lateral pivots, as <name>-p1/-p2) with
    /// synthetic hosts, so detections and risk are attributable to this run
    #[arg(long, value_parser = edge::parse_host_name)]
    host_name: Option<String>,

    /// Print the generated steps as JSON and exit without sending anything
    #[arg(long)]
    plan: bool,

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
        // Logs go to stderr: stdout carries only the step lines, the
        // `--plan` JSON and the final `INJECTOR_RESULT` line.
        .with_writer(std::io::stderr)
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
        eprintln!("Error: specify a scenario flag: --quick, --lateral, --staggered, --exfil, --persistence, or --drive-by");
        std::process::exit(1);
    };

    // Resolve the sink before generating anything: a missing or malformed
    // token file must fail before a single event is sent.
    let (sink, url) = match (&args.hec_url, &args.https_url) {
        (Some(url), None) => (SinkKind::Hec, url.clone()),
        (None, Some(url)) => (SinkKind::Https, url.clone()),
        _ => (SinkKind::Vector, args.vector.clone()),
    };
    let tokens = match &args.token_file {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read --token-file {}", path.display()))?;
            Some(edge::parse_token_file(&text).map_err(anyhow::Error::msg)?)
        }
        None => args.token.clone().map(|token| edge::TokenMap {
            default: Some(token),
            ..Default::default()
        }),
    };
    if sink != SinkKind::Vector && tokens.is_none() && !args.plan {
        anyhow::bail!("--hec-url/--https-url need --token-file");
    }
    let run_tag = args.marker.clone().unwrap_or_else(|| {
        uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).simple().to_string()
    });
    let router = SinkRouter::build(sink, &url, tokens.as_ref(), &format!("injector-{run_tag}"));

    // Generate attack steps
    let (mut steps, target_host, hosts) = {
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

        // --host-name: a private three-host world (target + two pivots) built
        // from the base target's addressing, so no event names a host that
        // background traffic also uses.
        let synthetic: Option<Vec<Entity>> = args.host_name.as_deref().map(|name| {
            let user = args.user.as_deref().unwrap_or(&base_target.user);
            // Two pivots, always: the neighbors first, then any other host.
            let neighbors: Vec<&Entity> = base_target
                .neighbor_indices
                .iter()
                .filter_map(|&idx| w.entities().get(idx))
                .chain(w.entities().iter())
                .filter(|e| e.hostname != base_target.hostname)
                .take(2)
                .collect();
            let mut hosts = vec![Entity::new(
                name,
                user,
                &base_target.ip,
                &base_target.mac,
                &base_target.domain,
            )];
            for (i, pivot) in neighbors.iter().enumerate() {
                hosts.push(Entity::new(
                    &format!("{name}-p{}", i + 1),
                    &pivot.user,
                    &pivot.ip,
                    &pivot.mac,
                    &pivot.domain,
                ));
            }
            hosts[0].neighbor_indices = (1..hosts.len()).collect();
            hosts
        });

        let custom_target = if synthetic.is_none() && args.drive_by && args.user.is_some() {
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
        let (target, all_entities): (&Entity, &[Entity]) = match &synthetic {
            Some(hosts) => (&hosts[0], hosts.as_slice()),
            None => (custom_target.as_ref().unwrap_or(base_target), w.entities()),
        };

        info!(
            "Scenario: {} | Target: {} | User: {}",
            scenario.name(),
            target.hostname,
            target.user
        );

        let named: Vec<&Entity> = synthetic
            .as_ref()
            .map(|hosts| hosts.iter().collect())
            .unwrap_or_else(|| vec![target]);
        let hosts: Vec<HostIdentity> = named
            .iter()
            .map(|h| HostIdentity { fqdn: h.fqdn(), ip: h.ip.clone(), user: h.user.clone() })
            .collect();
        (scenario.generate(target, all_entities), target.fqdn(), hosts)
    };

    if let Some(marker) = &args.marker {
        for event in steps.iter_mut().flat_map(|s| s.events.iter_mut()) {
            edge::tag_event(event, marker);
        }
    }

    info!("{} attack steps generated", steps.len());

    let sources: Vec<&str> = steps
        .iter()
        .flat_map(|s| s.events.iter().map(|e| e.source_type.as_str()))
        .collect();
    if args.plan {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan_json(scenario.name(), &target_host, &hosts, &steps, sink, &args.marker))?
        );
        return Ok(());
    }
    let missing = router.missing(sources.iter().copied());
    if !missing.is_empty() {
        anyhow::bail!(
            "no ingest token for source(s) {} in --token-file (ingest credentials are per source)",
            missing.join(", ")
        );
    }

    let client = Client::builder()
        .connect_timeout(TokioDuration::from_secs(10))
        .timeout(TokioDuration::from_secs(30))
        .build()?;

    let start = std::time::Instant::now();
    let started_at = chrono::Utc::now();
    let mut sent: BTreeMap<String, usize> = BTreeMap::new();
    let mut failed: BTreeMap<String, usize> = BTreeMap::new();
    let mut last_error: Option<String> = None;

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

        // Ingest credentials are per source, so a mixed step is one request
        // per source (the Vector transport groups the same way internally).
        for (source_type, events) in edge::group_by_source(&step.events) {
            let transport = router
                .for_source(&source_type)
                .expect("every source was checked for a token before sending");
            match send_batch_with_retry(&client, transport, &events, 3).await {
                Ok(()) => *sent.entry(source_type).or_default() += events.len(),
                Err(e) => {
                    // reqwest errors carry the URL and status, never the auth header.
                    tracing::warn!("Failed to send step '{}' ({source_type}): {}", step.description, e);
                    last_error = Some(format!("{source_type}: {e}"));
                    *failed.entry(source_type).or_default() += events.len();
                }
            }
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

    // One machine-readable line for drivers (scripts/e2e-detections-live.mjs).
    println!(
        "INJECTOR_RESULT {}",
        serde_json::json!({
            "scenario": scenario.name(),
            "sink": sink.label(),
            "marker": args.marker,
            "target_host": target_host,
            "hosts": hosts,
            "steps": steps.len(),
            "events": total_events,
            "sent": sent,
            "failed": failed,
            "last_error": last_error,
            "started_at": started_at.to_rfc3339(),
            "finished_at": chrono::Utc::now().to_rfc3339(),
        })
    );

    // An edge run is a test: a dropped step must not pass silently.
    if sink != SinkKind::Vector && !failed.is_empty() {
        std::process::exit(3);
    }
    Ok(())
}

/// A host a run's events name: detections group by hostname, IP or user.
#[derive(serde::Serialize)]
struct HostIdentity {
    fqdn: String,
    ip: String,
    user: String,
}

/// `--plan` output: what would be sent, without tokens or sending.
fn plan_json(
    scenario: &str,
    target_host: &str,
    hosts: &[HostIdentity],
    steps: &[AttackStep],
    sink: SinkKind,
    marker: &Option<String>,
) -> serde_json::Value {
    let mut per_source: BTreeMap<&str, usize> = BTreeMap::new();
    for event in steps.iter().flat_map(|s| s.events.iter()) {
        *per_source.entry(event.source_type.as_str()).or_default() += 1;
    }
    serde_json::json!({
        "scenario": scenario,
        "sink": sink.label(),
        "marker": marker,
        "target_host": target_host,
        "hosts": hosts,
        "duration_s": steps.last().map(|s| s.delay.as_secs()).unwrap_or(0),
        "events_per_source": per_source,
        "steps": steps.iter().map(|s| serde_json::json!({
            "delay_s": s.delay.as_secs(),
            "stage": s.stage,
            "description": s.description,
            "sources": s.events.iter().map(|e| e.source_type.as_str()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

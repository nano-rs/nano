// SPDX-License-Identifier: AGPL-3.0-or-later

//! `ingest[T]` for the lean-lake part model (NAN-2868).
//!
//! `run`: the per-tenant ingest loop over local stores (the lab/shadow form;
//! production object transport is the DO writer authority, phase 5).
//! `bench`: replays one hour of real bronze objects in simulated time and
//! reports CPU and peak RSS against the design §4 budget.
//!
//! No live writes: every store here is a local directory.

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::{BronzeIngestEnricher, IocSnapshot};
use nanosiem_lake_worker::ip_context::IpContextSnapshot;
use nanosiem_lake_worker::lean_platform_bundle::{PlatformBundle, TenantPlatformPolicy};
use nanosiem_lake_worker::part_ingest::ingest::{cpu_now, seed_schema};
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::parts::part_log::LocalObjectStore;
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

struct Flags(BTreeMap<String, String>);

#[derive(PartialEq, Eq)]
struct LabEnrichmentIdentity {
    platform_digest: Option<String>,
    policy_revision: Option<u64>,
    ioc_digest: Option<String>,
    custom_digest: Option<String>,
    ioc_revision: Option<String>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self> {
        let mut map = BTreeMap::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            let name = flag.strip_prefix("--").with_context(|| format!("unexpected argument {flag}"))?;
            if name == "exit-when-idle" {
                map.insert(name.to_string(), "true".to_string());
                continue;
            }
            let value = iter.next().with_context(|| format!("--{name} needs a value"))?;
            map.insert(name.to_string(), value.clone());
        }
        Ok(Self(map))
    }
    fn get(&self, name: &str) -> Result<&str> {
        self.0.get(name).map(String::as_str).with_context(|| format!("--{name} is required"))
    }
    fn opt(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

fn read_key(path: &str) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path).context("read signing key")?;
    let bytes = hex::decode(text.trim()).context("signing key is not hex")?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn main() -> Result<()> {
    // Cell child: the handshake and the jail come FIRST, before any runtime
    // or thread (NAN-2871 contract).
    if std::env::args().any(|a| a == nanosiem_lake_cell::contract::CONTROL_FD_FLAG) {
        let boot = nanosiem_lake_cell::child::bootstrap()?;
        nanosiem_lake_worker::process_limits::initialize()?;
        // INFO + JSON without RUST_LOG (production cells render none): the
        // old from_default_env() kept ERROR only (NAN-2964).
        nanosiem_lake_worker::cell_logging::init_child_tracing();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .on_thread_start(|| {
                if let Err(error) = nanosiem_lake_cell::crash_capture::register_thread() {
                    eprintln!("lake_native_crash alternate stack registration failed: {error}");
                }
            })
            .worker_threads(2).enable_all().build()?;
        let role = std::sync::Arc::new(std::sync::Mutex::new("ingest"));
        let role_seen = role.clone();
        let result = runtime.block_on(async move {
            let (assignment, secret, control) = boot.into_async()?;
            *role_seen.lock().expect("role lock") = assignment.role.as_str();
            if assignment.role == nanosiem_lake_cell::contract::Role::Maintenance {
                return run_maintenance(assignment, secret, control).await;
            }
            if assignment.role == nanosiem_lake_cell::contract::Role::Landing {
                return run_landing(assignment, secret, control).await;
            }
            // A 503 from the credential exchange at start is retried with a
            // FRESH bootstrap (tokens are single-use) on the refresh backoff;
            // 401/403 are final.
            use nanosiem_lake_worker::part_ingest::cell::{ExchangeRefused, IngestService, REFRESH_BACKOFF_S};
            let mut secret = secret;
            let mut attempt = 0;
            let progress = nanosiem_lake_worker::part_ingest::startup::StartupProgress::new();
            let mut startup_heartbeat = nanosiem_lake_worker::part_ingest::startup::StartupHeartbeat::start(
                progress.clone(), control.clone());
            let service = loop {
                let result = tokio::select! {
                    result = nanosiem_lake_worker::part_ingest::startup::PROGRESS.scope(
                        progress.clone(), IngestService::start(&assignment, secret)) => result,
                    result = startup_heartbeat.wait() => { result?; unreachable!() },
                };
                match result {
                    Ok(service) => break service,
                    Err(error) => {
                        // NAN-4052: the cell writer lease is held by another
                        // pod generation (or unreachable): standby, no fatal.
                        if nanosiem_lake_worker::part_ingest::writer_lease::is_standby(&error) {
                            return Err(error);
                        }
                        let retryable = error.downcast_ref::<ExchangeRefused>().is_some_and(|r| !r.is_final());
                        if !retryable || attempt >= REFRESH_BACKOFF_S.len() {
                            let _ = control.fatal(&format!("{error:#}")).await;
                            return Err(error);
                        }
                        tracing::warn!(error = %format!("{error:#}"), attempt, "credential exchange unavailable at start; retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(REFRESH_BACKOFF_S[attempt])).await;
                        attempt += 1;
                        control.request_secrets().await?;
                        secret = loop {
                            match control.next_event().await? {
                                nanosiem_lake_cell::child::Event::Secrets(fresh) => break fresh,
                                nanosiem_lake_cell::child::Event::Shutdown { .. } | nanosiem_lake_cell::child::Event::Closed => return Ok(()),
                                _ => continue,
                            }
                        };
                    }
                }
            };
            startup_heartbeat.stop().await;
            tokio::select! {
                result = nanosiem_lake_cell::child::run_service(service.clone(), control.clone()) => result.context("ingest control channel"),
                result = service.run(control.clone()) => result.context("ingest processing loop"),
            }
        });
        if let Err(error) = &result {
            // NAN-4052: another pod generation holds (or took) the cell writer
            // lease. Exit as standby: the supervisor neither counts a crash
            // nor restarts ingest here until its standby window passed.
            if nanosiem_lake_worker::part_ingest::writer_lease::is_standby(error) {
                tracing::warn!(error = %format!("{error:#}"), "ingest standing by: the cell writer lease belongs to another pod generation");
                std::process::exit(nanosiem_lake_cell::contract::WRITER_STANDBY_EXIT_CODE);
            }
            // Exit non-zero NOW so the supervisor respawns ingest with a fresh
            // bootstrap: dropping the runtime would first wait for blocking
            // tasks (a merge can run for minutes).
            let role = *role.lock().expect("role lock");
            tracing::error!(error = %format!("{error:#}"), role, "{role} exiting non-zero for a respawn");
            eprintln!("Error: {error:?}");
            std::process::exit(1);
        }
        return result;
    }
    nanosiem_lake_worker::process_limits::initialize()?;
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(lab_main())
}

/// `maintenance[T]` (cell feature `lean_prevalence_maintenance_v1`): the
/// tenant prevalence SlateDB compactor. Start-up exchange retries like
/// ingest's (a 503 with a fresh bootstrap; 401/403 final).
async fn run_maintenance(
    assignment: nanosiem_lake_cell::contract::Assignment,
    secret: zeroize::Zeroizing<Vec<u8>>,
    control: nanosiem_lake_cell::child::ControlChannel,
) -> Result<()> {
    use nanosiem_lake_worker::part_ingest::cell::{ExchangeRefused, REFRESH_BACKOFF_S};
    use nanosiem_lake_worker::part_ingest::maintenance::MaintenanceService;
    let mut secret = secret;
    let mut attempt = 0;
    let service = loop {
        match MaintenanceService::start(&assignment, secret).await {
            Ok(service) => break service,
            Err(error) => {
                let retryable = error.downcast_ref::<ExchangeRefused>().is_some_and(|r| !r.is_final());
                if !retryable || attempt >= REFRESH_BACKOFF_S.len() {
                    let _ = control.fatal(&format!("{error:#}")).await;
                    return Err(error);
                }
                tracing::warn!(error = %format!("{error:#}"), attempt, "maintenance credential exchange unavailable at start; retrying");
                tokio::time::sleep(std::time::Duration::from_secs(REFRESH_BACKOFF_S[attempt])).await;
                attempt += 1;
                control.request_secrets().await?;
                secret = loop {
                    match control.next_event().await? {
                        nanosiem_lake_cell::child::Event::Secrets(fresh) => break fresh,
                        nanosiem_lake_cell::child::Event::Shutdown { .. } | nanosiem_lake_cell::child::Event::Closed => return Ok(()),
                        _ => continue,
                    }
                };
            }
        }
    };
    service.serve(control).await
}

/// `landing[T]` (cell feature `lean_tenzir_landing_v1`, NAN-4137): the
/// hosted OCSF bucket-drop converter. Start-up exchange retries like
/// ingest's (a 503 with a fresh bootstrap; 401/403 final).
async fn run_landing(
    assignment: nanosiem_lake_cell::contract::Assignment,
    secret: zeroize::Zeroizing<Vec<u8>>,
    control: nanosiem_lake_cell::child::ControlChannel,
) -> Result<()> {
    use nanosiem_lake_worker::landing_cell::LandingService;
    use nanosiem_lake_worker::part_ingest::cell::{ExchangeRefused, REFRESH_BACKOFF_S};
    let mut secret = secret;
    let mut attempt = 0;
    let service = loop {
        match LandingService::start(&assignment, secret).await {
            Ok(service) => break service,
            Err(error) => {
                let retryable = error.downcast_ref::<ExchangeRefused>().is_some_and(|r| !r.is_final());
                if !retryable || attempt >= REFRESH_BACKOFF_S.len() {
                    let _ = control.fatal(&format!("{error:#}")).await;
                    return Err(error);
                }
                tracing::warn!(error = %format!("{error:#}"), attempt, "landing credential exchange unavailable at start; retrying");
                tokio::time::sleep(std::time::Duration::from_secs(REFRESH_BACKOFF_S[attempt])).await;
                attempt += 1;
                control.request_secrets().await?;
                secret = loop {
                    match control.next_event().await? {
                        nanosiem_lake_cell::child::Event::Secrets(fresh) => break fresh,
                        nanosiem_lake_cell::child::Event::Shutdown { .. } | nanosiem_lake_cell::child::Event::Closed => return Ok(()),
                        _ => continue,
                    }
                };
            }
        }
    };
    tokio::select! {
        result = nanosiem_lake_cell::child::run_service(service.clone(), control.clone()) => result.context("landing control channel"),
        result = service.run(control.clone()) => result.context("landing conversion loop"),
    }
}

async fn lab_main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (command, rest) = args.split_first().context("usage: lake_part_ingest run|bench --flags")?;
    let flags = Flags::parse(rest)?;
    match command.as_str() {
        "run" => run(&flags).await,
        "bench" => bench(&flags).await,
        "merge-probe" => merge_probe(&flags),
        other => bail!("unknown command {other}"),
    }
}

async fn run(flags: &Flags) -> Result<()> {
    let tenant = flags.get("tenant-id")?;
    // Lab only: an in-process stand-in for the owner signer.
    let signer = LocalPartSigner::new(flags.opt("signer-key-id").unwrap_or("lab-signer-0001"), read_key(flags.get("signing-key-file")?)?)?;
    let trusted = signer.trusted();
    let parts = LocalObjectStore::new(flags.get("parts-dir")?)?;
    let sources = LocalObjectStore::new(flags.get("sources-dir")?)?;
    let queue = SpoolQueue::new(flags.get("spool-dir")?, tenant)?;
    let mut cfg = IngestConfig::new(tenant, flags.get("work-dir")?);
    if let Some(epoch) = flags.opt("writer-epoch") {
        cfg.writer_epoch = epoch.parse()?;
    }
    if let Some(flush) = flags.opt("flush-ms") {
        cfg.flush_interval_override_ms = Some(flush.parse()?);
    }
    let tick = Duration::from_millis(flags.opt("tick-ms").unwrap_or("250").parse()?);
    let exit_when_idle = flags.opt("exit-when-idle").is_some();
    let (enricher, mut enrichment_identity) = lab_enricher(flags, tenant)?;
    let mut ingestor = Ingestor::open(
        cfg,
        &parts,
        &sources,
        &queue,
        &signer,
        trusted,
        enricher,
        &seed_schema(),
        now_ms(),
    )
    .await?;
    ingestor.set_initial_enrichment_revision(enrichment_identity.ioc_revision.clone())?;
    let mut last_enrichment_check = Instant::now();
    loop {
        // Match the production cell's 30-second source check. Every source
        // change cuts a part boundary before the next object is admitted.
        if last_enrichment_check.elapsed() >= Duration::from_secs(30) {
            let (next, identity) = lab_enricher(flags, tenant)?;
            if identity != enrichment_identity {
                ingestor.replace_enricher(next, identity.ioc_revision.clone(), now_ms()).await?;
                enrichment_identity = identity;
            }
            last_enrichment_check = Instant::now();
        }
        let report = ingestor.tick(now_ms()).await?;
        if exit_when_idle && queue.pending(1).await?.is_empty() && ingestor.health().buffered_rows == 0 {
            ingestor.flush_now(now_ms()).await?;
            tracing::info!(?report, "spool drained; exiting");
            return Ok(());
        }
        tokio::time::sleep(tick).await;
    }
}

/// Local fixture wiring for the production Bronze enricher. All files are
/// immutable inputs or atomically replaced pointers; no external service is
/// contacted by this lab entry point.
fn lab_enricher(flags: &Flags, tenant: &str) -> Result<(BronzeIngestEnricher, LabEnrichmentIdentity)> {
    let ioc = match (flags.opt("ioc-snapshot-file"), flags.opt("ioc-digest-file")) {
        (None, None) => None,
        (Some(path), Some(digest_file)) => {
            let digest = std::fs::read_to_string(digest_file)?.trim().to_string();
            Some(IocSnapshot::open(path, &digest)?)
        }
        _ => bail!("IOC snapshot and digest file must be configured together"),
    };
    let custom = match (flags.opt("custom-snapshot-file"), flags.opt("custom-digest-file")) {
        (None, None) => None,
        (Some(path), Some(digest_file)) => {
            let digest = std::fs::read_to_string(digest_file)?.trim().to_string();
            Some(IpContextSnapshot::open(path, &digest)?)
        }
        _ => bail!("custom snapshot and digest file must be configured together"),
    };
    let mut enricher = BronzeIngestEnricher::new(None, ioc, custom);
    let (platform_digest, policy_revision) = match (flags.opt("platform-bundle-file"), flags.opt("platform-policy-file")) {
        (None, None) => (None, None),
        (Some(bundle_file), Some(policy_file)) => {
            let tenant_id = tenant.parse()?;
            let policy = TenantPlatformPolicy::read_for_query(std::path::Path::new(policy_file), tenant_id)?;
            let bundle = Arc::new(PlatformBundle::open(std::path::Path::new(bundle_file), &policy.bundle_sha256)?);
            let identity = (Some(bundle.digest().to_string()), Some(policy.revision));
            enricher = enricher.with_lean_platform(bundle, policy);
            identity
        }
        _ => bail!("platform bundle and tenant policy file must be configured together"),
    };
    let ioc_digest = enricher.initial_metrics().ioc_snapshot_sha256;
    let custom_digest = enricher.initial_metrics().ip_context_snapshot_sha256;
    let ioc_revision = flags.opt("ioc-revision-file")
        .map(|path| std::fs::read_to_string(path).map(|text| text.trim().to_string()))
        .transpose()?;
    if ioc_revision.is_some() && ioc_digest.is_none() {
        bail!("IOC revision requires a tenant IOC snapshot");
    }
    Ok((enricher, LabEnrichmentIdentity {
        platform_digest, policy_revision, ioc_digest, custom_digest, ioc_revision,
    }))
}

fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage writes into the provided struct only.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    usage.ru_maxrss as u64 * 1024
}

fn current_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()))
        .map_or(0, |pages| pages * 4096)
}

/// Replay `--hours` hours of real bronze objects from `--bronze-dir`
/// (`shard=*/tenant_id=T/{unix_s}-{uuid}.parquet`, read-only) in simulated
/// time, one tick per simulated second, then seal and merge.
async fn bench(flags: &Flags) -> Result<()> {
    let bronze = PathBuf::from(flags.get("bronze-dir")?);
    let tenant = flags.get("tenant-id")?;
    let start: i64 = flags.get("start-unix")?.parse()?;
    let hours: i64 = flags.opt("hours").unwrap_or("1").parse()?;
    let work = PathBuf::from(flags.get("work-dir")?);
    if work.exists() {
        bail!("--work-dir {} exists; pass a fresh directory", work.display());
    }
    let end = start + hours * 3_600;
    // Index objects by their Vector timestamp (keys are relative to bronze-dir).
    let mut by_second: BTreeMap<i64, Vec<(String, u64)>> = BTreeMap::new();
    for shard in std::fs::read_dir(&bronze)? {
        let dir = shard?.path().join(format!("tenant_id={tenant}"));
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().into_string().unwrap_or_default();
            if !name.ends_with(".parquet") {
                continue;
            }
            let Some(ts) = name.split('-').next().and_then(|t| t.parse::<i64>().ok()) else { continue };
            if (start..end).contains(&ts) {
                let key = entry.path().strip_prefix(&bronze)?.to_string_lossy().into_owned();
                by_second.entry(ts).or_default().push((key, entry.metadata()?.len()));
            }
        }
    }
    let objects: usize = by_second.values().map(Vec::len).sum();
    eprintln!("bench: {objects} objects over {hours} h");
    let signer = LocalPartSigner::new("lab-signer-bench", SigningKey::from_bytes(&[7; 32]))?;
    let trusted = signer.trusted();
    let parts = LocalObjectStore::new(work.join("store"))?;
    let sources = LocalObjectStore::new(&bronze)?;
    let queue = SpoolQueue::new(work.join("spool"), tenant)?;
    let mut cfg = IngestConfig::new(tenant, work.join("ingest"));
    cfg.max_objects_per_admission = 256;
    let base_rss = current_rss_bytes();
    let mut ingestor = Ingestor::open(
        cfg,
        &parts,
        &sources,
        &queue,
        &signer,
        trusted,
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        start * 1_000,
    )
    .await?;
    let cpu_start = cpu_now();
    let mut max_rss = 0_u64;
    let mut rows = 0_u64;
    for second in start..end {
        if let Some(objs) = by_second.get(&second) {
            for (key, bytes) in objs {
                queue.deliver(&SourceNotice {
                    tenant_id: tenant.to_string(),
                    key: key.clone(),
                    version: "1".into(),
                    bytes: *bytes,
                    sha256: None,
                    edge_sha256: None,
                    notified_at_ms: second * 1_000,
                })?;
            }
        }
        let report = ingestor.tick(second * 1_000 + 999).await?;
        rows += report.admitted_rows;
        if second % 60 == 0 {
            max_rss = max_rss.max(current_rss_bytes());
        }
        if (second - start) % 600 == 599 {
            let h = ingestor.health();
            eprintln!(
                "bench: t+{}s rows={} live={} window_uids={} rss={} MiB cpu={} ms",
                second - start + 1,
                rows,
                h.live_parts,
                h.window_uids,
                current_rss_bytes() >> 20,
                cpu_now() - cpu_start
            );
        }
    }
    ingestor.flush_now(end * 1_000).await?;
    let ingest_cpu_ms = cpu_now() - cpu_start;
    let ingest_rss = max_rss.max(current_rss_bytes());
    // Seal every hour: run merges until none are due.
    let merge_start = cpu_now();
    let mut clock = end * 1_000 + 11 * 60_000;
    for _ in 0..200 {
        let report = ingestor.tick(clock).await?;
        max_rss = max_rss.max(current_rss_bytes());
        if report.merges == 0 && ingestor.health().merge_backlog == 0 {
            break;
        }
        clock += 1_000;
    }
    let merge_cpu_ms = cpu_now() - merge_start;
    let h = ingestor.health().clone();
    let simulated_s = (hours * 3_600) as f64;
    let summary = serde_json::json!({
        "objects": objects,
        "rows_admitted": rows,
        "rows_committed": h.rows_committed_total,
        "duplicates_dropped": h.duplicates_dropped_total,
        "same_uid_payload_diff": h.same_uid_payload_diff_total,
        "eps": rows as f64 / simulated_s,
        "ingest_cpu_s": ingest_cpu_ms as f64 / 1e3,
        "ingest_core_avg": ingest_cpu_ms as f64 / 1e3 / simulated_s,
        "cpu_admission_s": h.cpu_ms_admission as f64 / 1e3,
        "cpu_parts_s": h.cpu_ms_parts as f64 / 1e3,
        "cpu_merges_s": h.cpu_ms_merges as f64 / 1e3,
        "seal_merge_cpu_s": merge_cpu_ms as f64 / 1e3,
        "total_core_avg_incl_merges": (ingest_cpu_ms + merge_cpu_ms) as f64 / 1e3 / simulated_s,
        "rss_base_mib": base_rss >> 20,
        "rss_ingest_peak_sampled_mib": ingest_rss >> 20,
        "rss_peak_sampled_mib": max_rss >> 20,
        "vm_hwm_mib": peak_rss_bytes() >> 20,
        "live_parts": h.live_parts,
        "live_parts_by_level": h.live_parts_by_level,
        "window_uids": h.window_uids,
    });
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

/// Re-run the largest hour merge of a finished bench work dir in a fresh
/// process and report its peak RSS (VmHWM), to attribute merge memory.
fn merge_probe(flags: &Flags) -> Result<()> {
    use nanosiem_lake_worker::part_ingest::merge::{merge_parts, MergeInput};
    use nanosiem_lake_worker::parts::levels::Level;
    use nanosiem_lake_worker::parts::part_log::{LogEntry, LogOp, PartRef};
    let work = PathBuf::from(flags.get("work-dir")?);
    let tenant = flags.get("tenant-id")?;
    let entries = work.join(format!("store/lake/parts/v1/tenant={tenant}/log/entries"));
    let mut names = std::fs::read_dir(&entries)?.filter_map(|e| e.ok()).map(|e| e.path()).collect::<Vec<_>>();
    names.sort();
    let mut refs: BTreeMap<String, PartRef> = BTreeMap::new();
    let mut best: Option<(Vec<String>, i32)> = None;
    let mut schema = None;
    for path in names {
        let entry = LogEntry::parse_bytes(&std::fs::read(&path)?, tenant)?;
        match entry.op {
            LogOp::Genesis { schema: s } | LogOp::Schema { schema: s } => schema = Some(s),
            LogOp::Add { parts, .. } => parts.into_iter().for_each(|p| {
                refs.insert(p.part_id.to_string(), p);
            }),
            LogOp::Merge { output, supersedes } => {
                if output.level == Level::Hour && best.as_ref().is_none_or(|(b, _)| supersedes.len() > b.len()) {
                    best = Some((supersedes.iter().map(|p| p.to_string()).collect(), output.event_hour));
                }
                refs.insert(output.part_id.to_string(), output);
            }
            _ => {}
        }
    }
    let (inputs, hour) = best.context("no hour merge in the log")?;
    let schema = schema.context("no schema")?;
    let inputs = inputs
        .iter()
        .map(|id| MergeInput { part: refs[id].clone(), dir: work.join("ingest/parts").join(id) })
        .collect::<Vec<_>>();
    let out = work.join("probe-out");
    std::fs::create_dir_all(&out)?;
    let hwm_before = std::fs::read_to_string("/proc/self/status")?;
    let started = std::time::Instant::now();
    let cpu = cpu_now();
    let result = merge_parts(&out, tenant, Level::Hour, hour, &inputs, std::sync::Arc::new(schema.to_arrow()?), &schema.fingerprint, "lab-signer-bench", "probe", 1)?;
    let hwm = |s: &str| s.lines().find(|l| l.starts_with("VmHWM")).unwrap_or("").to_string();
    println!(
        "{}",
        serde_json::json!({
            "inputs": inputs.len(),
            "input_rows": inputs.iter().map(|i| i.part.rows).sum::<u64>(),
            "output_rows": result.finished.record.rows,
            "data_files": result.finished.record.files.data.len(),
            "row_groups": result.finished.record.files.row_groups(),
            "wall_s": started.elapsed().as_secs_f64(),
            "cpu_s": (cpu_now() - cpu) as f64 / 1e3,
            "vm_hwm_before": hwm(&hwm_before),
            "vm_hwm_after": hwm(&std::fs::read_to_string("/proc/self/status")?),
        })
    );
    Ok(())
}

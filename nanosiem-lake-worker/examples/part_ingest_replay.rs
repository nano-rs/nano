// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline admission/buffer/flush replay. All writes stay in a new local directory.
//! Usage: part_ingest_replay TENANT INPUT_DIR OUTPUT_DIR [FIRST LAST [LATENCY_MS [FAIL_EVERY_N_CALLS]]]
//! Input files must be named SEQUENCE.bin, SEQUENCE.parquet or SEQUENCE.parquet.gz.
//! Range arguments select an inclusive subset for poison-input bisection.
//! No source values or underlying error messages are printed.

use anyhow::{ensure, Context, Result};
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::{
    discovery::{NoticeQueue, SourceNotice, SpoolQueue},
    ingest::{seed_schema, IngestConfig, Ingestor},
};
use nanosiem_lake_worker::parts::{
    part_log::{LocalObjectStore, ObjectStore},
    provenance::LocalPartSigner,
};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const STEP_LIMIT: Duration = Duration::from_secs(1200);

// Model reserve, verify, PUT, provider HEAD, complete and registration.
// The four control calls share 40 RPC/s (2400/min); PUT/HEAD use provider IO.
// Native authorize/complete each wrap two of these control calls.
struct SlowOwner {
    inner: LocalObjectStore,
    delay: Duration,
    calls: std::sync::atomic::AtomicU64,
    fail_every: u64,
    next_owner_call: tokio::sync::Mutex<tokio::time::Instant>,
}

#[async_trait::async_trait]
impl ObjectStore for SlowOwner {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        for stage in 0..6 {
            if matches!(stage, 0 | 1 | 4 | 5) {
                let mut next = self.next_owner_call.lock().await;
                tokio::time::sleep_until(*next).await;
                *next = tokio::time::Instant::now() + Duration::from_millis(25);
            }
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            tokio::time::sleep(self.delay).await;
            if self.fail_every != 0 && call % self.fail_every == 0 {
                return Err(nanosiem_lake_worker::part_ingest::native_writer::OwnerRefused { status: 503 }.into());
            }
        }
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
    async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.inner.list(prefix).await }
}

struct Stages(Arc<Mutex<(&'static str, Instant)>>);

impl Stages {
    fn new() -> Self {
        let state = Arc::new(Mutex::new(("arguments", Instant::now())));
        let monitor = Arc::clone(&state);
        // Tokio deadlines cannot interrupt synchronous Arrow/Parquet work.
        // The independent watchdog also bounds that portion of a replay.
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            let (stage, since) = *monitor.lock().expect("replay stage");
            if since.elapsed() > STEP_LIMIT {
                eprintln!("replay timeout stage={stage}");
                std::process::exit(124);
            }
        });
        Self(state)
    }

    fn enter(&self, stage: &'static str) {
        *self.0.lock().expect("replay stage") = (stage, Instant::now());
        eprintln!("replay stage={stage}");
    }
}

async fn replay(stages: &Stages) -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(args.len() == 3 || (5..=7).contains(&args.len()), "usage");
    let tenant = &args[0];
    let input = PathBuf::from(&args[1]).canonicalize()?;
    let output = PathBuf::from(&args[2]);
    let range = if args.len() >= 5 {
        let first = args[3].parse::<u64>()?;
        let last = args[4].parse::<u64>()?;
        ensure!(first <= last, "reversed range");
        first..=last
    } else {
        0..=u64::MAX
    };
    // Refuse reuse: earlier parts/UID state would change bisection results.
    std::fs::create_dir(&output)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))?;
    }
    let source = LocalObjectStore::new(output.join("source"))?;
    let parts = Box::leak(Box::new(SlowOwner {
        inner: LocalObjectStore::new(output.join("parts"))?,
        delay: Duration::from_millis(args.get(5).map(|v| v.parse()).transpose()?.unwrap_or(0)),
        calls: std::sync::atomic::AtomicU64::new(0),
        next_owner_call: tokio::sync::Mutex::new(tokio::time::Instant::now()),
        fail_every: args.get(6).map(|v| v.parse()).transpose()?.unwrap_or(0),
    }));
    let replay_started = Instant::now();
    let signer = Box::leak(Box::new(LocalPartSigner::new(
        "offline-replay",
        ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
    )?));
    let queue = SpoolQueue::new(output.join("spool"), tenant)?;
    let now = chrono::Utc::now().timestamp_millis();
    stages.enter("stage-input");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(input)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_str().context("non-UTF8 input name")?;
        let Some(stem) = name
            .strip_suffix(".parquet.gz")
            .or_else(|| name.strip_suffix(".parquet"))
            .or_else(|| name.strip_suffix(".bin"))
        else {
            continue;
        };
        let sequence = stem.parse::<u64>()?;
        if range.contains(&sequence) {
            files.push((sequence, entry.path()));
        }
    }
    files.sort_by_key(|(sequence, _)| *sequence);
    ensure!(!files.is_empty(), "no selected input files");
    for (ordinal, (_, path)) in files.iter().enumerate() {
        stages.enter("stage-object");
        let bytes = std::fs::read(path)?;
        let bytes = if bytes.starts_with(&[0x1f, 0x8b]) {
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(bytes.as_slice())
                .take(256 * 1024 * 1024 + 1)
                .read_to_end(&mut decoded)?;
            ensure!(
                decoded.len() <= 256 * 1024 * 1024,
                "decompressed object exceeds cap"
            );
            decoded
        } else {
            bytes
        };
        ensure!(
            bytes.starts_with(b"PAR1") && bytes.ends_with(b"PAR1"),
            "input is not Parquet"
        );
        let key = format!("replay/{ordinal:06}.parquet");
        ensure!(source.put_if_absent(&key, &bytes).await?, "duplicate input");
        queue.deliver(&SourceNotice {
            tenant_id: tenant.clone(),
            key,
            version: "offline-v1".into(),
            bytes: bytes.len() as u64,
            sha256: None,
            edge_sha256: None,
            notified_at_ms: now + ordinal as i64,
        })?;
        eprintln!("replay staged ordinal={ordinal} bytes={}", bytes.len());
    }
    stages.enter("open");
    let mut config = IngestConfig::new(tenant, output.join("ingest"));
    config.prevalence_enabled = false;
    config.background_merges = true;
    config.flush_interval_override_ms = Some(30_000);
    let mut ingestor = Ingestor::open(
        config,
        &*parts,
        &source,
        &queue,
        &*signer,
        signer.trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        now,
    )
    .await?;
    ingestor.set_background_store(&*parts);
    ingestor.set_background_signer(&*signer);
    let diagnostics = ingestor.diagnostics();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(30));
        eprintln!("replay pipeline={}", diagnostics.snapshot());
    });
    // Exercise the production admission and flush phases without maintenance
    // merges, owner RPCs, remote prevalence state, or historical part downloads.
    for tick in 0..(files.len() * 4 + 16) {
        stages.enter("admit-buffer-seal");
        let started = Instant::now();
        let timestamp = now + tick as i64 * 1_000;
        let (report, _) = match tokio::time::timeout(STEP_LIMIT, ingestor.tick_ingest(timestamp)).await? {
            Ok(report) => report,
            Err(_) => { eprintln!("replay publication retry tick={tick}; error suppressed"); continue; }
        };
        let pending = queue.pending(files.len() + 1).await?.len();
        eprintln!(
            "replay tick={tick} admitted={} flushed={} pending={pending} elapsed_ms={}",
            report.admitted_rows,
            report.flushed_parts,
            started.elapsed().as_millis()
        );
        if report.admitted_rows == 0 || pending == 0 {
            stages.enter("flush");
            let count = match tokio::time::timeout(STEP_LIMIT, ingestor.flush_now(timestamp)).await? {
                Ok(count) => count,
                Err(_) => { eprintln!("replay flush retry tick={tick}; error suppressed"); continue; }
            };
            eprintln!("replay explicit_flush_parts={count}");
        }
        if queue.pending(1).await?.is_empty() {
            stages.enter("complete");
            let hours = ingestor.live_parts().iter().map(|part| part.event_hour).collect::<std::collections::BTreeSet<_>>().len();
            let part_files = parts.list("").await?.iter().filter(|key| key.contains("/parts/")).count();
            eprintln!("replay summary distinct_hours={hours} part_objects={part_files}");
            eprintln!(
                "replay complete inputs={} live_parts={} rows={} owner_calls={} elapsed_ms={}",
                files.len(),
                ingestor.live_parts().len(),
                ingestor
                    .live_parts()
                    .iter()
                    .map(|part| part.rows)
                    .sum::<u64>(),
                parts.calls.load(std::sync::atomic::Ordering::Relaxed),
                replay_started.elapsed().as_millis()
            );
            return Ok(());
        }
    }
    anyhow::bail!("replay did not drain within tick bound")
}

#[tokio::main]
async fn main() {
    let stages = Stages::new();
    if replay(&stages).await.is_err() {
        let stage = stages.0.lock().expect("replay stage").0;
        // Admission errors may contain producer values. Never display them.
        eprintln!("replay failed stage={stage}; underlying error suppressed");
        std::process::exit(1);
    }
}

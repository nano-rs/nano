// SPDX-License-Identifier: AGPL-3.0-or-later

//! One-shot CLI for the serialized immutable enrichment publisher.

use anyhow::{Context, Result, bail};
use nanosiem_lake_worker::enrichment::IocSnapshotInput;
use nanosiem_lake_worker::ioc_publish::{IocPublisher, IocSourceUpdate};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_INPUT_BYTES: u64 = 2 * 1_024 * 1_024 * 1_024;
const MAX_ROWS: usize = 5_000_000;

struct Arguments {
    input: Option<PathBuf>,
    output_directory: PathBuf,
    worker_config: PathBuf,
    tenant_id: String,
    snapshot_id: String,
    replace_source_id: Option<String>,
    delete_source_id: Option<String>,
    generation_config_root: Option<PathBuf>,
    snapshot_prune_grace: Duration,
    snapshot_prune_disabled: bool,
}

fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    // Publication results stay on stdout for callers; prune reports and
    // retention warnings go to stderr so silent GC never hides behind the
    // result JSON.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lake_ioc_publish=info,nanosiem_lake_worker=info".into()),
        )
        .with_writer(std::io::stderr)
        .json()
        .init();
    let args = Arguments::parse(std::env::args().skip(1))?;
    let rows = args.input.as_deref().map(read_rows).transpose()?;
    let update = match (args.replace_source_id, args.delete_source_id, rows) {
        (Some(source_id), None, Some(rows)) => IocSourceUpdate::Replace { source_id, rows },
        (None, Some(source_id), None) => IocSourceUpdate::Delete { source_id },
        (None, None, Some(rows)) => IocSourceUpdate::FullReplace(rows),
        _ => bail!("IOC source operation and input are inconsistent"),
    };
    let publisher = IocPublisher::new(
        args.output_directory,
        args.worker_config,
        args.tenant_id,
        args.snapshot_id,
    )?
    .with_snapshot_prune(
        args.snapshot_prune_grace,
        args.snapshot_prune_disabled,
        args.generation_config_root,
    );
    println!("{}", serde_json::to_string(&publisher.publish(update)?)?);
    Ok(())
}

fn read_rows(path: &Path) -> Result<Vec<IocSnapshotInput>> {
    let metadata = std::fs::metadata(path).context("inspect IOC publication input")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        bail!("IOC publication input must be one non-empty bounded NDJSON file");
    }
    let mut rows = Vec::new();
    for (line_number, line) in BufReader::new(File::open(path)?).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if rows.len() >= MAX_ROWS {
            bail!("IOC publication input exceeds {MAX_ROWS} rows");
        }
        rows.push(serde_json::from_str(&line).with_context(|| {
            format!("decode IOC publication input line {}", line_number + 1)
        })?);
    }
    if rows.is_empty() {
        bail!("IOC publication input contains no rows");
    }
    Ok(rows)
}

impl Arguments {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self> {
        let mut parsed = Self {
            input: None,
            output_directory: PathBuf::new(),
            worker_config: PathBuf::new(),
            tenant_id: String::new(),
            snapshot_id: String::new(),
            replace_source_id: None,
            delete_source_id: None,
            generation_config_root: None,
            snapshot_prune_grace: Duration::from_secs(86_400),
            snapshot_prune_disabled: false,
        };
        let mut output_directory = None;
        let mut worker_config = None;
        let mut tenant_id = None;
        let mut snapshot_id = None;
        // Mirrors --sidecar-prune-grace-seconds in lake_risk_publish:
        // superseded snapshots survive at least one day by default so a
        // draining worker generation or an operator rollback can still read
        // them.
        let mut snapshot_prune_grace_seconds = 86_400_u64;
        let mut arguments = arguments;
        while let Some(name) = arguments.next() {
            if name == "--snapshot-prune-disabled" {
                parsed.snapshot_prune_disabled = true;
                continue;
            }
            let value = arguments
                .next()
                .with_context(|| format!("{name} requires a value"))?;
            match name.as_str() {
                "--input" => parsed.input = Some(PathBuf::from(value)),
                "--output-directory" => output_directory = Some(PathBuf::from(value)),
                "--worker-config" => worker_config = Some(PathBuf::from(value)),
                "--tenant-id" => tenant_id = Some(value),
                "--snapshot-id" => snapshot_id = Some(value),
                "--replace-source-id" => parsed.replace_source_id = Some(value),
                "--delete-source-id" => parsed.delete_source_id = Some(value),
                "--generation-config-root" => {
                    parsed.generation_config_root = Some(PathBuf::from(value))
                }
                "--snapshot-prune-grace-seconds" => snapshot_prune_grace_seconds = value.parse()?,
                _ => bail!("unknown argument {name}"),
            }
        }
        if !(3_600..=90 * 24 * 60 * 60).contains(&snapshot_prune_grace_seconds) {
            bail!("snapshot prune grace must be between one hour and ninety days");
        }
        parsed.snapshot_prune_grace = Duration::from_secs(snapshot_prune_grace_seconds);
        parsed.output_directory = output_directory.context("--output-directory is required")?;
        parsed.worker_config = worker_config.context("--worker-config is required")?;
        parsed.tenant_id = tenant_id.context("--tenant-id is required")?;
        parsed.snapshot_id = snapshot_id.context("--snapshot-id is required")?;
        match (
            parsed.replace_source_id.is_some(),
            parsed.delete_source_id.is_some(),
            parsed.input.is_some(),
        ) {
            (true, false, true) | (false, true, false) | (false, false, true) => {}
            (true, true, _) => {
                bail!("--replace-source-id and --delete-source-id are mutually exclusive")
            }
            _ => bail!("--input is required unless deleting one source"),
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_arguments() -> Vec<String> {
        [
            "--input",
            "/tmp/rows.ndjson",
            "--output-directory",
            "/var/lib/nano-lake/ioc",
            "--worker-config",
            "/var/lib/nano-lake/worker.json",
            "--tenant-id",
            "tenant-a",
            "--snapshot-id",
            "ioc-current",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn publisher_arguments_enforce_prune_bounds() {
        let parsed = Arguments::parse(base_arguments().into_iter()).expect("valid arguments");
        assert!(!parsed.snapshot_prune_disabled);
        assert_eq!(parsed.snapshot_prune_grace, Duration::from_secs(86_400));

        let mut disabled = base_arguments();
        disabled.push("--snapshot-prune-disabled".to_string());
        assert!(
            Arguments::parse(disabled.into_iter())
                .expect("valid arguments")
                .snapshot_prune_disabled
        );

        let mut too_short = base_arguments();
        too_short.extend(["--snapshot-prune-grace-seconds".to_string(), "59".to_string()]);
        assert!(Arguments::parse(too_short.into_iter()).is_err());

        let mut too_long = base_arguments();
        too_long.extend([
            "--snapshot-prune-grace-seconds".to_string(),
            (91 * 24 * 60 * 60).to_string(),
        ]);
        assert!(Arguments::parse(too_long.into_iter()).is_err());
    }
}

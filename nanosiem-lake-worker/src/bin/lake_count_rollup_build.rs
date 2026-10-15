// SPDX-License-Identifier: AGPL-3.0-or-later

//! Build exact hourly count parts for one hydrated Iceberg snapshot.

use anyhow::{Context, Result, bail};
use nanosiem_lake_worker::generation::build_count_rollup_generation;
use std::path::PathBuf;

fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    let args = Arguments::parse(std::env::args().skip(1))?;
    let result = build_count_rollup_generation(
        &args.input,
        &args.output,
        &args.object_stamp_manifest,
        &args.tenant_id,
    )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

struct Arguments {
    input: PathBuf,
    output: PathBuf,
    object_stamp_manifest: PathBuf,
    tenant_id: String,
}

impl Arguments {
    fn parse(mut values: impl Iterator<Item = String>) -> Result<Self> {
        let mut input = None;
        let mut output = None;
        let mut object_stamp_manifest = None;
        let mut tenant_id = None;
        while let Some(argument) = values.next() {
            let value = values
                .next()
                .with_context(|| format!("{argument} requires a value"))?;
            match argument.as_str() {
                "--input" => input = Some(PathBuf::from(value)),
                "--output" => output = Some(PathBuf::from(value)),
                "--object-stamp-manifest" => {
                    object_stamp_manifest = Some(PathBuf::from(value));
                }
                "--tenant-id" => tenant_id = Some(value),
                _ => bail!("unknown argument: {argument}"),
            }
        }
        Ok(Self {
            input: input.context("--input is required")?,
            output: output.context("--output is required")?,
            object_stamp_manifest: object_stamp_manifest
                .context("--object-stamp-manifest is required")?,
            tenant_id: tenant_id.context("--tenant-id is required")?,
        })
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generate a finite, reproducible raw-event corpus without a network sink.
//!
//! This uses the same event-core generators as log-blaster's live sender. It is
//! intended for parser/schema regression gates where retaining every raw input
//! is more useful than measuring transport throughput.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use event_core::entity::WorldState;
use event_core::event::Event;
use event_core::generators::{
    ApacheGenerator, CloudTrailGenerator, ProxyGenerator, SysmonGenerator,
    WindowsEventGenerator,
};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

#[derive(Debug, Parser)]
#[command(about = "Write a finite log-blaster raw-event corpus as NDJSON")]
struct Args {
    #[arg(long)]
    output: PathBuf,

    #[arg(long, default_value_t = 2_416)]
    sysmon: usize,

    #[arg(long, default_value_t = 407)]
    windows_event: usize,

    #[arg(long, default_value_t = 482)]
    proxy: usize,

    #[arg(long, default_value_t = 431)]
    apache: usize,

    #[arg(long, default_value_t = 324)]
    cloudtrail: usize,

    #[arg(long, default_value_t = 2_000)]
    assets: usize,

    #[arg(long, default_value_t = 2_361)]
    seed: u64,

    #[arg(long, default_value = "2026-08-11T00:00:00Z")]
    start_time: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let start_time = DateTime::parse_from_rfc3339(&args.start_time)
        .context("--start-time must be RFC3339")?
        .with_timezone(&Utc);
    let world = WorldState::new(args.assets);
    let entities = world.entities();
    anyhow::ensure!(!entities.is_empty(), "--assets must produce at least one entity");

    let mut rng = rand::rngs::StdRng::seed_from_u64(args.seed);
    let sysmon = SysmonGenerator::new();
    let windows_event = WindowsEventGenerator::new();
    let proxy = ProxyGenerator::new();
    let apache = ApacheGenerator::new();
    let cloudtrail = CloudTrailGenerator::new();
    let total = args.sysmon + args.windows_event + args.proxy + args.apache + args.cloudtrail;
    let mut events = Vec::with_capacity(total);

    let mut event_index = 0_i64;
    let mut next_time = || {
        let timestamp = start_time + Duration::microseconds(event_index);
        event_index += 1;
        timestamp
    };

    for _ in 0..args.sysmon {
        let entity = &entities[rng.random_range(0..entities.len())];
        events.push(sysmon.generate(next_time(), entity, &mut rng));
    }
    for _ in 0..args.windows_event {
        let entity = &entities[rng.random_range(0..entities.len())];
        events.push(windows_event.generate(next_time(), entity, entities, &mut rng));
    }
    for _ in 0..args.proxy {
        let entity = &entities[rng.random_range(0..entities.len())];
        events.push(proxy.generate(next_time(), entity, &mut rng));
    }
    for _ in 0..args.apache {
        let entity = &entities[rng.random_range(0..entities.len())];
        events.push(apache.generate(next_time(), entity, &mut rng));
    }
    for _ in 0..args.cloudtrail {
        let entity = &entities[rng.random_range(0..entities.len())];
        events.push(cloudtrail.generate(next_time(), entity, &mut rng));
    }

    events.shuffle(&mut rng);
    write_events(&args.output, &events)?;
    println!(
        "wrote {} raw events to {} (sysmon={}, windows_event={}, proxy={}, apache={}, cloudtrail={}, seed={})",
        total,
        args.output.display(),
        args.sysmon,
        args.windows_event,
        args.proxy,
        args.apache,
        args.cloudtrail,
        args.seed,
    );
    Ok(())
}

fn write_events(path: &PathBuf, events: &[Event]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for event in events {
        serde_json::to_writer(&mut writer, event).context("serializing raw event")?;
        writer.write_all(b"\n").context("writing raw event")?;
    }
    writer.flush().context("flushing raw corpus")?;
    Ok(())
}

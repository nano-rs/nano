// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local, disposable benchmark for a node-shared platform bundle. Never loads
//! tenant feeds or contacts a service. Run separate processes to measure PSS.
use anyhow::{ensure, Context, Result};
use chrono::{Duration, Utc};
use nanosiem_lake_worker::lean_platform_bundle::{
    PlatformBundle, PlatformGrant, TenantPlatformPolicy,
};
use serde_json::json;
use std::{collections::BTreeMap, path::PathBuf, time::Instant};
use uuid::Uuid;

fn cpu_micros() -> i64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1_000_000
        + usage.ru_utime.tv_usec
        + usage.ru_stime.tv_usec
}

fn memory_kib() -> Result<(u64, u64)> {
    let rollup = std::fs::read_to_string("/proc/self/smaps_rollup")?;
    let field = |name: &str| -> Result<u64> {
        rollup
            .lines()
            .find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|value| value.parse().ok())
            })
            .with_context(|| format!("missing {name} in smaps_rollup"))
    };
    Ok((field("Rss:")?, field("Pss:")?))
}

fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        args.len() == 6,
        "usage: lake_platform_bench BUNDLE SHA256 EPS SECONDS enabled|baseline"
    );
    let path = PathBuf::from(&args[1]);
    let eps: u32 = args[3].parse()?;
    let seconds: u32 = args[4].parse()?;
    ensure!(
        eps > 0 && eps <= 300 && seconds > 0 && seconds <= 30,
        "invalid rate or duration"
    );
    let enabled = match args[5].as_str() {
        "enabled" => true,
        "baseline" => false,
        _ => anyhow::bail!("mode must be enabled or baseline"),
    };
    let bundle = PlatformBundle::open(&path, &args[2])?;
    let policy = TenantPlatformPolicy {
        tenant_id: Uuid::new_v4(),
        revision: 1,
        bundle_sha256: args[2].clone(),
        grants: BTreeMap::from([
            (
                "ipinfo_lite".into(),
                PlatformGrant {
                    feed_revision: 1,
                    valid_until: Utc::now() + Duration::hours(1),
                    premium: None,
                },
            ),
            (
                "threatfox".into(),
                PlatformGrant {
                    feed_revision: 1,
                    valid_until: Utc::now() + Duration::hours(1),
                    premium: None,
                },
            ),
        ]),
    };
    let (rss_before, pss_before) = memory_kib()?;
    let cpu_before = cpu_micros();
    let start = Instant::now();
    let mut lookup_ns = 0_u128;
    for i in 0..(eps * seconds) {
        let due = start + std::time::Duration::from_nanos(i as u64 * 1_000_000_000 / eps as u64);
        if let Some(wait) = due.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
        let mut event = json!({"src_endpoint":{"ip":"8.8.8.8"}});
        if enabled {
            let begin = Instant::now();
            bundle.stamp(
                event.as_object_mut().context("event is not an object")?,
                &policy,
                Utc::now(),
            )?;
            lookup_ns += begin.elapsed().as_nanos();
        }
        std::hint::black_box(event);
    }
    let elapsed = start.elapsed();
    let (rss_after, pss_after) = memory_kib()?;
    println!(
        "{}",
        json!({
            "eps": eps, "seconds": seconds, "enabled": enabled,
            "bundle_bytes": bundle.bytes(), "events": eps * seconds,
            "elapsed_ms": elapsed.as_millis(), "cpu_us": cpu_micros() - cpu_before,
            "rss_before_kib": rss_before, "rss_after_kib": rss_after,
            "pss_before_kib": pss_before, "pss_after_kib": pss_after,
            "lookup_us_per_event": lookup_ns / (eps * seconds) as u128 / 1000
        })
    );
    Ok(())
}

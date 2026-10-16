// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic RSS probe of the production Arrow/Parquet writer and BTreeMap
//! serving reader. Each case runs in a fresh process so VmHWM is case-local.
use nanosiem_lake_worker::enrichment::{write_ioc_snapshot_owned, IocSnapshot, IocSnapshotInput};
use std::process::Command;

fn memory_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
#[ignore = "capacity probe: run explicitly on the build farm with --ignored --nocapture"]
fn ioc_memory_matrix() {
    for kind in ["ip", "cidr", "domain", "hash", "url", "url_max_metadata"] {
        for count in [10_000, 50_000, 100_000, 500_000] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "ioc_memory_child", "--nocapture"])
                .env("IOC_MEMORY_KIND", kind)
                .env("IOC_MEMORY_COUNT", count.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }
}

#[test]
#[ignore = "maximum allowed value, list name, tags, note, expiry and publisher metadata"]
fn ioc_memory_worst_case() {
    for count in [5_000, 10_000, 25_000, 50_000] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "ioc_memory_child", "--nocapture"])
            .env("IOC_MEMORY_KIND", "url_escaped_metadata")
            .env("IOC_MEMORY_COUNT", count.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
}

#[test]
#[ignore = "child of ioc_memory_matrix"]
fn ioc_memory_child() {
    let Ok(kind) = std::env::var("IOC_MEMORY_KIND") else {
        return;
    };
    let count: usize = std::env::var("IOC_MEMORY_COUNT").unwrap().parse().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let baseline = memory_kib("VmRSS:");
    let rows: Vec<_> = (0..count).map(|n| indicator(&kind, n)).collect();
    let input_rss = memory_kib("VmRSS:");
    let path = directory.path().join("one.parquet");
    let (digest, written) = write_ioc_snapshot_owned(&path, rows).unwrap();
    assert_eq!(written, count);
    let old = IocSnapshot::open(&path, &digest).unwrap();
    let steady = memory_kib("VmRSS:");
    // A conservative two-generation bound includes the current serving map,
    // a full replacement input, Arrow encode, and a second serving reader.
    let replacement = old.publication_rows();
    let next_path = directory.path().join("two.parquet");
    let (next_digest, _) = write_ioc_snapshot_owned(&next_path, replacement).unwrap();
    let next = IocSnapshot::open(&next_path, &next_digest).unwrap();
    std::hint::black_box((&old, &next));
    println!("IOC_MEMORY kind={kind} count={count} baseline_kib={baseline} input_kib={input_rss} steady_kib={steady} two_generation_kib={} peak_kib={}",
        memory_kib("VmRSS:"), memory_kib("VmHWM:"));
}

fn indicator(kind: &str, n: usize) -> IocSnapshotInput {
    // CIDRs are expanded by the API, so coordinator rows contain exact IPs.
    let value = match kind {
        "ip" | "cidr" => std::net::Ipv4Addr::from(0x0a000000 + n as u32).to_string(),
        "domain" => format!("indicator-{n:08}.example.test"),
        "hash" => format!("{n:064x}"),
        "url" => format!("https://indicator.example.test/{n:08}"),
        _ => {
            let prefix = format!("https://indicator.example.test/{n:08}/");
            format!("{prefix}{}", "\\".repeat(2048 - prefix.len()))
        }
    };
    let worst = kind.contains("metadata");
    IocSnapshotInput {
        ioc_value: value,
        ioc_type: if kind == "cidr" {
            "ip"
        } else if worst {
            "url"
        } else {
            kind
        }
        .into(),
        source_id: "00000000-0000-0000-0000-000000000100".into(),
        enrichment_name: if worst {
            "l".repeat(100)
        } else {
            "capacity-probe".into()
        },
        confidence_level: 75,
        risk_score: Some(75),
        tags: if worst {
            (0..16)
                .map(|n| format!("{n:02}{}", "\"".repeat(62)))
                .collect()
        } else {
            vec![]
        },
        data: serde_json::json!({"note": if worst { "\"".repeat(512) } else { String::new() },
                "ioc_list": if worst { "l".repeat(100) } else { "capacity-probe".into() },
                "indicator_expires_at": "9999-12-31T23:59:59Z",
                "nano_marketplace": false,
                "nano_namespace": "00000000-0000-0000-0000-000000000100"}),
        ..Default::default()
    }
}

#[test]
fn maximum_ioc_list_fits_the_coordinator_wire_contract() {
    let row = indicator("url_escaped_metadata", 0);
    let record_bytes = serde_json::to_vec(&row).unwrap().len() + 1;
    // Include the tenant/records envelope, a maximum-length publication
    // timestamp, and optional timestamp variation without materializing a list.
    let bytes = (record_bytes + 64) * nanosiem_core::ioc_limits::MAX_INDICATORS_PER_LIST + 1024;
    assert!(bytes < nanosiem_lake_worker::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_BYTES);
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3159: what the per-query compiler process costs. Each search spawns
//! the pinned `lake_query_compile` binary once per step; this times 36
//! compiles (the Q6 hunt's steps, cycled) against the bare spawn floor (the
//! same binary refusing an empty request, and `/bin/true`).
//!
//! ```sh
//! NANO_LAKE_COMPILER=<target>/release/lake_query_compile \
//!   cargo test -p nanosiem-lake-worker --lib part_query::engine::compiler_spawn_bench -- --ignored --nocapture
//! ```

use super::*;
use std::time::Instant;

/// The k6 Q6 hunt's distinct step queries (36 steps cycle through them).
const Q6: &[&str] = &[
    "metadata.log_source=aws_cloudtrail | head 100",
    "metadata.log_source=windows_sysmon | head 100",
    "* | stats count by metadata.log_source",
    "metadata.log_source=conduit_proxy | stats count by src_endpoint.ip | sort -count | head 10",
    "* | timechart span=1h count by metadata.log_source",
    "user.name=\"MWRIGHT\" | head 100",
    "user.name=\"mwright\" OR actor.user.name=\"mwright\" | stats count by metadata.log_source",
    "device.hostname=\"srv-file06.corp.local\" | head 100",
    "device.hostname=\"srv-file06.corp.local\" | sort -time | head 50",
    "device.hostname=\"srv-file06.corp.local\" | stats count by metadata.log_source",
    "src_endpoint.ip=\"10.1.6.251\" | head 100",
    "src_endpoint.ip=\"10.1.6.251\" OR dst_endpoint.ip=\"10.1.6.251\" | stats count by metadata.log_source",
    "1361618d0d1f83ce599a4646da8655548f1aea219ffa4d93b88893ce35315c84 | head 100",
    "1361618d0d1f83ce599a4646da8655548f1aea219ffa4d93b88893ce35315c84 | stats count by metadata.log_source",
    "rundll32 | head 100",
    "process.name=*dll32* | head 100",
    "process.name=/rundll3[0-9]/i | head 100",
    "process.name=*shell* | head 100",
    "process.name=/^power.*\\.exe$/i | head 100",
    "user.name=/^svc_/ | head 100",
    "metadata.log_source=aws_cloudtrail OR metadata.log_source=apache_access | head 100",
    "metadata.log_source=windows_sysmon process.name=powershell.exe | head 100",
    "metadata.log_source=windows_sysmon 1361618d0d1f83ce599a4646da8655548f1aea219ffa4d93b88893ce35315c84 | head 100",
    "metadata.log_source=aws_cloudtrail OR 1361618d0d1f83ce599a4646da8655548f1aea219ffa4d93b88893ce35315c84 | head 100",
    "metadata.log_source=conduit_proxy | where cidr_match(\"10.0.0.0/8\", src_endpoint.ip) | head 100",
    "metadata.log_source=conduit_proxy | head 100",
    "metadata.log_source=apache_access NOT http_response.code=200 | head 100",
    "metadata.log_source=windows_sysmon | where isnull(device.hostname) | head 100",
    "device.hostname=\"srv-file06.corp.local\" | timechart span=10m count",
];

fn field_types() -> BTreeMap<String, String> {
    [
        ("time", "timestamp"),
        ("message", "string"),
        ("raw_data", "string"),
        ("status", "string"),
        ("class_uid", "long"),
        ("severity_id", "long"),
        ("metadata.uid", "string"),
        ("metadata.log_source", "string"),
        ("metadata.product.name", "string"),
        ("user.name", "string"),
        ("actor.user.name", "string"),
        ("device.hostname", "string"),
        ("src_endpoint.ip", "string"),
        ("src_endpoint.hostname", "string"),
        ("src_endpoint.port", "long"),
        ("dst_endpoint.ip", "string"),
        ("dst_endpoint.hostname", "string"),
        ("dst_endpoint.port", "long"),
        ("process.name", "string"),
        ("process.cmd_line", "string"),
        ("process.file.path", "string"),
        ("http_response.code", "long"),
        ("traffic.bytes_out", "long"),
    ]
    .into_iter()
    .map(|(path, kind)| (path.to_string(), kind.to_string()))
    .collect()
}

fn stats(label: &str, mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let at = |q: f64| samples[((samples.len() as f64 - 1.0) * q).round() as usize];
    eprintln!(
        "{label}: n={} mean={mean:.2} ms p50={:.2} p90={:.2} max={:.2} total={:.1} ms",
        samples.len(),
        at(0.5),
        at(0.9),
        at(1.0),
        samples.iter().sum::<f64>()
    );
    mean
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "bench: NANO_LAKE_COMPILER (a release lake_query_compile)"]
async fn compiler_spawn_cost_over_36_compiles() {
    let compiler =
        std::path::PathBuf::from(std::env::var("NANO_LAKE_COMPILER").expect("NANO_LAKE_COMPILER"));
    let types = field_types();
    let request = |query: &'static str| CompilerRequest {
        stats_page: false,
        stats_page_offset: 0,
        query,
        dataset: "logs",
        start: "2026-10-04T22:30:00Z",
        end: "2026-10-05T22:30:00Z",
        limit: 201,
        table_view: true,
        event_contract: "ocsf-1.9",
        snapshot_field_types: types.clone(),
        lowercased_fields: Vec::new(),
    };
    // Warm the page cache and the binary's first exec.
    for query in Q6.iter().take(3) {
        run_compiler(&compiler, &request(query), 30)
            .await
            .unwrap_or_else(|error| panic!("{query}: {error}"));
    }
    let mut compiles = Vec::new();
    for query in Q6.iter().cycle().take(36) {
        let started = Instant::now();
        run_compiler(&compiler, &request(query), 30)
            .await
            .unwrap_or_else(|error| panic!("{query}: {error}"));
        compiles.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let mut refusals = Vec::new();
    for _ in 0..36 {
        let started = Instant::now();
        let mut empty = request("");
        empty.start = "not-a-time";
        assert!(run_compiler(&compiler, &empty, 30).await.is_err());
        refusals.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let mut trues = Vec::new();
    for _ in 0..36 {
        let started = Instant::now();
        let status = tokio::process::Command::new("/bin/true")
            .status()
            .await
            .unwrap();
        assert!(status.success());
        trues.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let compile = stats("compile (spawn + compile)", compiles);
    let floor = stats("compiler spawn floor (refused request)", refusals);
    stats("/bin/true spawn", trues);
    eprintln!(
        "compile work over the floor: {:.2} ms/step; 36 steps spend {:.1} ms in spawn",
        compile - floor,
        floor * 36.0
    );
}

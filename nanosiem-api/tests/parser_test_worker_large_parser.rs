// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5396: the largest shipped parser runs in the real `nanosiem-api
//! --parser-test-worker` process, inside the worker's CPU bounds.
//!
//! The fixture is a pinned copy of `parsers-ocsf/crowdstrike_falcon/parser.yaml`
//! from nano-rs/parsers main at b956e608d34d21dd00984fbca7dcd8ab265758cc (the
//! largest parser.yaml, about 70 KiB of VRL). Its bundled samples are repeated
//! up to [`MAX_TEST_SAMPLES`], the largest batch one parser test accepts.
//!
//! Before NAN-5396 one 8 s `RLIMIT_CPU` covered compiling the program AND
//! running every sample. Compiling is nearly all of it (release build, Apple
//! silicon: 4.6 s compile, 17 ms for 100 samples), so a host about 1.7x
//! slower per core failed this parser. Compile now has its own allowance
//! ([`WORKER_COMPILE_CPU_SECONDS`]); execution gets
//! `WORKER_EXECUTION_CPU_SECONDS` on top of whatever compile used.
//!
//! Release only: an unoptimized VRL compiler takes about 17 s on this parser,
//! far beyond anything shipped, so a debug run measures nothing useful.
//!   cargo test --release -p nanosiem-api --test parser_test_worker_large_parser -- --nocapture

use nanosiem_core::parser_repository::parse_parser_yaml;
use nanosiem_core::parsers::{
    test_sandbox::{
        run_with_executable, Outcome, ParserTestJob, Work, WORKER_ARGUMENT,
        WORKER_COMPILE_CPU_SECONDS,
    },
    vrl_functions::VrlRegistry,
    worker_process, MAX_TEST_SAMPLES,
};
use serde_json::json;
use std::path::Path;
use std::time::Instant;

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_nanosiem-api"))
}

fn fixture() -> (String, Vec<String>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/parsers/crowdstrike_falcon.parser.yaml");
    let content = std::fs::read_to_string(&path).expect("crowdstrike_falcon fixture");
    let parsed = parse_parser_yaml(&content).expect("fixture parses");
    let vrl = parsed.parser_vrl.expect("fixture has parser_vrl");
    let samples: Vec<String> = parsed
        .samples
        .expect("fixture has samples")
        .into_iter()
        .map(|sample| sample.raw)
        .collect();
    assert!(vrl.len() > 64 * 1024, "the fixture is the large parser ({} bytes)", vrl.len());
    assert!(!samples.is_empty());
    (vrl, samples)
}

/// CPU seconds (user + system) of this test process's reaped children.
#[cfg(unix)]
fn children_cpu_seconds() -> f64 {
    worker_process::children_cpu_time()
        .expect("getrusage(RUSAGE_CHILDREN)")
        .as_secs_f64()
}

#[cfg_attr(
    debug_assertions,
    ignore = "run with --release: a debug build compiles this parser in ~17 s, far slower than any shipped worker"
)]
#[tokio::test]
async fn the_largest_shipped_parser_runs_a_full_batch_inside_the_worker_bounds() {
    let (vrl, samples) = fixture();
    let inputs: Vec<_> = samples
        .iter()
        .cycle()
        .take(MAX_TEST_SAMPLES)
        .map(|raw| json!({ "message": raw }))
        .collect();
    let job = ParserTestJob {
        registry: VrlRegistry::Parser,
        work: Work::Each { code: vrl, inputs },
    };

    #[cfg(unix)]
    let cpu_before = children_cpu_seconds();
    let started = Instant::now();
    let outcome = run_with_executable(&job, worker(), &[WORKER_ARGUMENT])
        .await
        .expect("the worker completes the large parser inside its CPU and wall bounds");
    let wall = started.elapsed();

    let Outcome::Each(Ok(rows)) = outcome else {
        panic!("the parser did not compile in the worker: {outcome:?}")
    };
    assert_eq!(rows.len(), MAX_TEST_SAMPLES);
    for (index, row) in rows.iter().enumerate() {
        let output = row
            .as_ref()
            .unwrap_or_else(|error| panic!("sample {}: {error}", index % samples.len() + 1));
        assert!(output.get("class_uid").is_some(), "sample {}: {output}", index + 1);
    }

    #[cfg(unix)]
    {
        let cpu = children_cpu_seconds() - cpu_before;
        eprintln!("crowdstrike_falcon x{MAX_TEST_SAMPLES}: worker cpu {cpu:.2}s, wall {wall:?}");
        // Headroom for a host 2x slower per core than this one: the whole
        // test (start-up, compile and every sample) fits twice into the
        // compile allowance alone.
        let allowance = WORKER_COMPILE_CPU_SECONDS as f64;
        assert!(cpu * 2.0 < allowance, "worker cpu {cpu:.2}s leaves no 2x headroom under the {allowance}s compile allowance");
    }
}

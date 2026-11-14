// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5406: the largest shipped OCSF parsers pass the publish/deploy OCSF
//! gate in the real `nanosiem-api --parser-test-worker --deploy-gate` process,
//! with headroom for a cloud core several times slower than this one.
//!
//! On a GCE e2-standard-8 (AMD EPYC Rome) the official Microsoft Sysmon (OCSF)
//! parser could not be deployed: the gate's worker ran out of its wall clock
//! compiling it. The gate now runs under [`Budget::DeployGate`].
//!
//! Fixtures are pinned copies of `parsers-ocsf/<name>/parser.yaml` from
//! nano-rs/parsers main at b956e60 (identical to d739819, the content the
//! failing lane deployed). The test runs each parser over all of its bundled
//! samples through [`run_ocsf_samples`], the function the deploy and publish
//! prechecks call, and checks every sample passes VRL and the OCSF contract.
//!
//! Release only: an unoptimized VRL compiler is several times slower than any
//! shipped worker, so a debug run measures nothing useful.
//!   cargo test --release -p nanosiem-api --test deploy_gate_largest_parsers -- --nocapture

use nanosiem_core::log_sources::run_ocsf_samples;
use nanosiem_core::parser_repository::parse_parser_yaml;
use nanosiem_core::parsers::{
    test_sandbox::{
        register_worker_executable, Budget, DEPLOY_GATE_COMPILE_CPU_SECONDS,
        DEPLOY_GATE_WALL_SECONDS,
    },
    worker_process, VrlValidator,
};
use std::path::Path;
use std::time::Instant;

/// How many times slower per core than the test host the gate must still
/// fit: the M5 Max development box against EPYC Rome is about 3–4x on this
/// compile; a slower test host leaves the real margin larger, not smaller.
const SLOW_HOST_FACTOR: f64 = 3.0;

const PARSERS: [&str; 3] = ["windows_sysmon", "cisco_asa", "crowdstrike_falcon"];

fn fixture(name: &str) -> (String, Vec<String>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/parsers/{name}.parser.yaml"));
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name} fixture: {e}"));
    let parsed = parse_parser_yaml(&content).unwrap_or_else(|e| panic!("{name} parses: {e}"));
    let vrl = parsed.parser_vrl.expect("fixture has parser_vrl");
    let samples: Vec<String> = parsed
        .samples
        .expect("fixture has samples")
        .into_iter()
        .map(|sample| sample.raw)
        .filter(|raw| !raw.trim().is_empty())
        .collect();
    assert!(vrl.len() > 40 * 1024, "{name} is one of the large parsers ({} bytes)", vrl.len());
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
    ignore = "run with --release: a debug VRL compiler is far slower than any shipped worker"
)]
#[tokio::test]
async fn the_largest_shipped_parsers_pass_the_deploy_gate_with_slow_host_headroom() {
    register_worker_executable(Path::new(env!("CARGO_BIN_EXE_nanosiem-api")).to_path_buf());
    let validator = VrlValidator::new();
    let limits = Budget::DeployGate.limits();
    assert_eq!(limits.cpu_seconds, DEPLOY_GATE_COMPILE_CPU_SECONDS);

    // One parser at a time, in one test: the CPU measurement reads every
    // reaped child of this process.
    for name in PARSERS {
        let (vrl, samples) = fixture(name);
        #[cfg(unix)]
        let cpu_before = children_cpu_seconds();
        let started = Instant::now();
        let results = run_ocsf_samples(&validator, &vrl, None, &samples)
            .await
            .unwrap_or_else(|e| panic!("{name}: the gate refused to run: {e}"));
        let wall = started.elapsed();

        assert_eq!(results.len(), samples.len());
        for (index, result) in results.iter().enumerate() {
            assert!(
                result.success,
                "{name} sample {}: {}",
                index + 1,
                result.error.as_deref().unwrap_or("failed")
            );
        }
        assert!(
            wall.as_secs() < DEPLOY_GATE_WALL_SECONDS,
            "{name}: {wall:?} is past the {DEPLOY_GATE_WALL_SECONDS}s wall clock"
        );

        #[cfg(unix)]
        {
            let cpu = children_cpu_seconds() - cpu_before;
            eprintln!(
                "{name}: {} samples, {} bytes of VRL: worker cpu {cpu:.2}s, wall {wall:?}",
                samples.len(),
                vrl.len()
            );
            // The whole gate (start-up, the one compile, every sample) fits
            // the compile allowance alone on a host SLOW_HOST_FACTOR slower.
            let allowance = DEPLOY_GATE_COMPILE_CPU_SECONDS as f64;
            assert!(
                cpu * SLOW_HOST_FACTOR < allowance,
                "{name}: worker cpu {cpu:.2}s leaves no {SLOW_HOST_FACTOR}x headroom under the {allowance}s deploy gate compile allowance"
            );
        }
    }
}

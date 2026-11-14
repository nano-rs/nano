// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5234: parser-test isolation — request/response bounds, admission and
//! the executor decision. The real worker process is exercised end to end by
//! `nanosiem-api/tests/parser_test_worker.rs`; fail-closed behaviour of an
//! unregistered process by `nanosiem-api/tests/parser_test_fail_closed.rs`.
use super::*;
use serde_json::json;

fn each(code: &str, inputs: Vec<Value>) -> ParserTestJob {
    ParserTestJob {
        registry: VrlRegistry::Parser,
        work: Work::Each {
            code: code.into(),
            inputs,
        },
    }
}

#[test]
fn a_registered_worker_always_wins_and_nothing_else_runs_in_process() {
    let exe = Path::new("/usr/local/bin/nanosiem-api");
    assert_eq!(choose_executor(Some(exe), false), Executor::Worker(exe.into()));
    assert_eq!(choose_executor(Some(exe), true), Executor::Worker(exe.into()));
    assert_eq!(choose_executor(None, true), Executor::InProcessTestHarness);
    // A service process that never registered fails closed.
    assert_eq!(choose_executor(None, false), Executor::Unavailable);
}

#[test]
fn limits_fit_the_largest_legitimate_request() {
    // The worker must hold the request, its parsed form and the reply with
    // room to spare; the address space must exceed the data bound.
    let request = MAX_REQUEST_BYTES as u64;
    let reply = MAX_RESPONSE_BYTES as u64;
    assert!(WORKER_PRIVATE_MEMORY_BYTES >= 4 * request + 4 * reply);
    assert!(WORKER_ADDRESS_SPACE_BYTES >= WORKER_PRIVATE_MEMORY_BYTES + 768 * 1024 * 1024);
    // The budget elapses before the CPU limit, and the CPU limit before the
    // wall clock, so a slow program gets the clear budget message.
    assert!(TEST_EXECUTION_BUDGET.as_secs() < WORKER_EXECUTION_CPU_SECONDS);
    assert!(WORKER_CPU_CEILING_SECONDS < WORKER_WALL_SECONDS);
    // NAN-5396: the hard limit holds both phases, and stays a DoS bound.
    assert_eq!(LIMITS.cpu_seconds, WORKER_COMPILE_CPU_SECONDS);
    assert_eq!(LIMITS.cpu_hard_seconds(), WORKER_CPU_CEILING_SECONDS);
    assert!(WORKER_COMPILE_CPU_SECONDS + WORKER_EXECUTION_CPU_SECONDS < WORKER_CPU_CEILING_SECONDS);
    assert!(WORKER_CPU_CEILING_SECONDS <= 30);
    // Every sample a parser test admits fits in one request.
    assert!(MAX_REQUEST_BYTES > MAX_TEST_TOTAL_SAMPLE_BYTES);
}

#[test]
fn job_shapes_are_bounded() {
    assert!(each(".x = 1", vec![]).validate().is_err());
    assert!(each(".x = 1", vec![json!({}); exec_bounds::MAX_TEST_SAMPLES + 1])
        .validate()
        .is_err());
    assert!(each(".x = 1", vec![json!({}); exec_bounds::MAX_TEST_SAMPLES])
        .validate()
        .is_ok());
    let chain = |stages: usize| ParserTestJob {
        registry: VrlRegistry::Parser,
        work: Work::Chain {
            stages: (0..stages).map(|i| (i, ".x = 1".to_string())).collect(),
            input: json!({}),
        },
    };
    assert!(chain(0).validate().is_err());
    assert!(chain(MAX_STAGES).validate().is_ok());
    assert!(chain(MAX_STAGES + 1).validate().is_err());
}

#[test]
fn an_oversized_request_is_refused_before_any_worker_starts() {
    let sample = json!({ "message": "x".repeat(4 * 1024 * 1024) });
    let job = each(".x = 1", vec![sample; 7]);
    match encode_request(&job) {
        Err(ParserTestSandboxError::Invalid(message)) => assert!(message.contains("MiB"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert!(encode_request(&each(".x = 1", vec![json!({"message": "a"})])).is_ok());
}

#[test]
fn replies_must_match_the_job() {
    let job = each(".x = 1", vec![json!({}), json!({})]);
    let reply = |reply: WorkerReply| serde_json::to_vec(&reply).unwrap();
    let ok = Outcome::Each(Ok(vec![Ok(json!({"x": 1})), Err("boom".into())]));
    assert_eq!(decode_reply(&job, &reply(WorkerReply::Done(ok.clone()))), Ok(ok));
    // One row short, or the wrong kind of outcome: a protocol error.
    let short = Outcome::Each(Ok(vec![Ok(json!({}))]));
    assert_eq!(
        decode_reply(&job, &reply(WorkerReply::Done(short))),
        Err(ParserTestSandboxError::Protocol)
    );
    assert_eq!(
        decode_reply(&job, &reply(WorkerReply::Done(Outcome::Chain(Ok(json!({})))))),
        Err(ParserTestSandboxError::Protocol)
    );
    assert_eq!(decode_reply(&job, b"not json"), Err(ParserTestSandboxError::Protocol));
    assert_eq!(
        decode_reply(&job, &reply(WorkerReply::OutputTooLarge)),
        Err(ParserTestSandboxError::OutputLimit)
    );
    assert!(matches!(
        decode_reply(&job, &reply(WorkerReply::Invalid("no".into()))),
        Err(ParserTestSandboxError::Invalid(_))
    ));
}

#[test]
fn bounds_the_program_hit_are_test_failures_and_refusals_are_errors() {
    for bound in [
        ParserTestSandboxError::Deadline(WORKER_WALL_SECONDS),
        ParserTestSandboxError::ResourceLimit,
        ParserTestSandboxError::OutputLimit,
    ] {
        assert!(bound.is_execution_bound());
    }
    assert!(matches!(
        VrlValidatorError::from(ParserTestSandboxError::Busy),
        VrlValidatorError::Busy(_)
    ));
    assert!(matches!(
        VrlValidatorError::from(ParserTestSandboxError::Unavailable),
        VrlValidatorError::ExecutionError(_)
    ));
    assert!(matches!(
        VrlValidatorError::from(ParserTestSandboxError::Invalid("x".into())),
        VrlValidatorError::InvalidInput(_)
    ));
}

#[test]
fn the_pure_engine_runs_each_chain_and_compile_errors() {
    let out = execute(&each(".parsed = upcase!(.message)", vec![json!({"message": "hi"})]));
    assert_eq!(out, Outcome::Each(Ok(vec![Ok(json!({"message": "hi", "parsed": "HI"}))])));
    assert!(matches!(execute(&each("((", vec![json!({})])), Outcome::Each(Err(_))));
    let chain = ParserTestJob {
        registry: VrlRegistry::Parser,
        work: Work::Chain {
            stages: vec![(0, ".a = 1".into()), (1, ".b = to_int(.a) ?? 0\n.b = .b + 1".into())],
            input: json!({}),
        },
    };
    assert_eq!(execute(&chain), Outcome::Chain(Ok(json!({"a": 1, "b": 2}))));
    // The worker answers a malformed request with a reason, not a crash.
    assert!(matches!(worker_reply(b"{}".to_vec(), &LIMITS), WorkerReply::Invalid(_)));
}

/// The admission gate is process-wide: tests that hold its slots run one at
/// a time.
static GATE_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn a_full_replica_is_busy_after_the_bounded_wait() {
    let _serial = GATE_SERIAL.lock().await;
    // Hold every slot of the process-wide parser-test gate.
    let held: Vec<_> = (0..MAX_WORKERS)
        .map_while(|i| gate().try_acquire(&format!("holder:{i}")).ok())
        .collect();
    assert!(!held.is_empty());
    let started = std::time::Instant::now();
    let refused = run_with_executable(
        &each(".x = 1", vec![json!({})]),
        Path::new("/bin/true"),
        &[],
    )
    .await;
    assert_eq!(refused, Err(ParserTestSandboxError::Busy));
    assert!(started.elapsed() >= ADMISSION_WAIT);
    drop(held);
    // A stand-in worker that answers nothing is a protocol error, not a hang.
    let result = run_with_executable(
        &each(".x = 1", vec![json!({})]),
        Path::new("/bin/sh"),
        &["-c", "cat > /dev/null"],
    )
    .await;
    assert_eq!(result, Err(ParserTestSandboxError::Protocol));
}

/// NAN-5396 (P2): one principal holds at most half the workers (one of the
/// default two), so it can never occupy all of them.
#[test]
fn one_principal_holds_less_than_every_worker() {
    assert_eq!(per_principal_workers(1), 1);
    assert_eq!(per_principal_workers(DEFAULT_WORKERS), 1);
    for workers in 2..=MAX_WORKERS {
        assert!(per_principal_workers(workers) < workers, "{workers}");
        assert!(per_principal_workers(workers) >= 1);
    }
    assert_eq!(per_principal_workers(MAX_WORKERS), MAX_WORKERS / 2);
}

/// NAN-5396 (P2): the HTTP admission and the worker admission are one gate.
/// A principal at its share is refused while another principal is admitted;
/// a request's own jobs run in its one slot even when the replica is full.
#[tokio::test]
async fn admission_is_per_principal_and_a_request_runs_its_jobs_in_its_slot() {
    let _serial = GATE_SERIAL.lock().await;
    assert_eq!(worker_count(), DEFAULT_WORKERS, "the test assumes the default sizing");
    let alice = admit(Some("user:alice")).await.unwrap();
    let refused = admit(Some("user:alice")).await.err().expect("alice is at her share");
    assert_eq!(refused.scope, crate::principal_gate::GateScope::Principal);
    let bob = admit(Some("user:bob")).await.unwrap();
    // Replica full: an internal job is refused after the bounded wait.
    let job = each(".x = 1", vec![json!({})]);
    let stand_in = || run_with_executable(&job, Path::new("/bin/sh"), &["-c", "cat > /dev/null"]);
    assert_eq!(stand_in().await, Err(ParserTestSandboxError::Busy));
    // Alice's request runs two jobs, one after the other, in her slot (the
    // stand-in answers nothing: a protocol error means it ran).
    let ran = admitted(async {
        let first = stand_in().await;
        let second = stand_in().await;
        (first, second)
    })
    .await;
    assert_eq!(ran, (Err(ParserTestSandboxError::Protocol), Err(ParserTestSandboxError::Protocol)));
    drop((alice, bob));
    assert_eq!(stand_in().await, Err(ParserTestSandboxError::Protocol));
}

/// NAN-5400: the validate endpoint's verdict is the same whether the compile
/// runs here (validate_vrl) or in the worker (validate_vrl_isolated; under
/// this test harness the worker engine runs in-process): valid with
/// warnings, compile errors, text-gate refusals, empty and oversized input.
#[tokio::test]
async fn isolated_validation_matches_validate_vrl() {
    let validator = crate::parsers::VrlValidator::new();
    let oversized = format!(".x = \"{}\"", "a".repeat(2 * 1024 * 1024));
    for source in [
        ".parsed = upcase!(.message)",
        ".timestamp = now()\n.message = .message",
        ".x = no_such_function_nan5400()",
        ".foo = { bar",
        ".foo = exec('ls')",
        "[sources.evil]\n.foo = .bar",
        "",
        oversized.as_str(),
    ] {
        assert_eq!(
            validator.validate_vrl_isolated(source).await.unwrap(),
            validator.validate_vrl(source).await.unwrap(),
            "{}",
            &source[..source.len().min(80)]
        );
    }
    // The worker engine itself answers a Validate job with that verdict.
    let job = ParserTestJob {
        registry: VrlRegistry::Parser,
        work: Work::Validate { code: ".x = no_such_function_nan5400()".into() },
    };
    let Outcome::Validate(result) = execute(&job) else { panic!("wrong outcome") };
    assert!(!result.valid);
    assert_eq!(result, validator.validate_vrl(".x = no_such_function_nan5400()").await.unwrap());
}

/// NAN-5406: the deploy gate gets more compile CPU and wall clock than an
/// interactive test, the same memory bounds and execution allowance, and is
/// still a bound: its CPU ceiling elapses before its wall clock.
#[test]
fn the_deploy_gate_budget_is_larger_but_still_bounded() {
    let interactive = Budget::Interactive.limits();
    let gate = Budget::DeployGate.limits();
    assert_eq!(interactive, &LIMITS);
    assert!(gate.cpu_seconds > interactive.cpu_seconds);
    assert!(gate.cpu_hard_seconds() > interactive.cpu_hard_seconds());
    assert!(gate.wall > interactive.wall);
    assert!(gate.cpu_hard_seconds() < gate.wall.as_secs());
    assert_eq!(gate.cpu_hard_seconds(), DEPLOY_GATE_CPU_CEILING_SECONDS);
    assert!(DEPLOY_GATE_COMPILE_CPU_SECONDS + WORKER_EXECUTION_CPU_SECONDS < DEPLOY_GATE_CPU_CEILING_SECONDS);
    assert_eq!(gate.private_memory_bytes, interactive.private_memory_bytes);
    assert_eq!(gate.address_space_bytes, interactive.address_space_bytes);
    assert_eq!(gate.max_output_bytes, interactive.max_output_bytes);
    // A runaway program is still killed within about a minute of CPU.
    assert!(DEPLOY_GATE_CPU_CEILING_SECONDS <= 60);
    assert!(Budget::DeployGate.admission_wait() > Budget::Interactive.admission_wait());
    // Interactive tests keep their NAN-5396 bounds (30 s upstream deadline).
    assert_eq!(interactive.wall.as_secs(), WORKER_WALL_SECONDS);
    assert!(WORKER_WALL_SECONDS < 30);
}

/// NAN-5406: the worker picks its bounds from its arguments; anything but the
/// exact deploy gate arguments is the smaller, interactive budget. The deadline
/// message names the wall clock that ran out.
#[test]
fn the_worker_reads_its_budget_from_its_arguments() {
    for budget in [Budget::Interactive, Budget::DeployGate] {
        assert_eq!(Budget::from_worker_args(budget.worker_args()), budget);
    }
    assert_eq!(Budget::from_worker_args::<&str>(&[]), Budget::Interactive);
    assert_eq!(Budget::from_worker_args(&[DEPLOY_GATE_ARGUMENT]), Budget::Interactive);
    assert_eq!(
        Budget::from_worker_args(&[WORKER_ARGUMENT, "--deploy-gate=1"]),
        Budget::Interactive
    );
    assert_eq!(
        ParserTestSandboxError::from_failure(WorkerFailure::Deadline, Budget::DeployGate.limits()),
        ParserTestSandboxError::Deadline(DEPLOY_GATE_WALL_SECONDS)
    );
    assert!(ParserTestSandboxError::Deadline(DEPLOY_GATE_WALL_SECONDS)
        .to_string()
        .contains(&format!("{DEPLOY_GATE_WALL_SECONDS}s deadline")));
}

/// NAN-5406: a deploy is never refused because the replica's workers are
/// briefly busy with parser tests: past the interactive 2 s wait it keeps
/// waiting, and runs as soon as a slot frees.
#[tokio::test]
async fn the_deploy_gate_waits_for_a_slot_instead_of_answering_busy() {
    let _serial = GATE_SERIAL.lock().await;
    let held: Vec<_> = (0..MAX_WORKERS)
        .map_while(|i| gate().try_acquire(&format!("holder:{i}")).ok())
        .collect();
    assert!(!held.is_empty());
    let release_after = ADMISSION_WAIT + Duration::from_secs(1);
    let releaser = tokio::spawn(async move {
        tokio::time::sleep(release_after).await;
        drop(held);
    });
    let started = std::time::Instant::now();
    let job = each(".x = 1", vec![json!({})]);
    // The stand-in worker answers nothing: a protocol error means it ran.
    let ran = run_with_executable_under(
        &job,
        Path::new("/bin/sh"),
        &["-c", "cat > /dev/null"],
        Budget::DeployGate,
    )
    .await;
    assert_eq!(ran, Err(ParserTestSandboxError::Protocol));
    assert!(started.elapsed() >= release_after, "it ran only once a slot freed");
    releaser.await.unwrap();
}

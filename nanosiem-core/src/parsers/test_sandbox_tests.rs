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
    assert!(TEST_EXECUTION_BUDGET.as_secs() < WORKER_CPU_SECONDS);
    assert!(WORKER_CPU_SECONDS < WORKER_WALL_SECONDS);
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
        ParserTestSandboxError::Deadline,
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
    assert!(matches!(worker_reply(b"{}".to_vec()), WorkerReply::Invalid(_)));
}

#[tokio::test]
async fn a_full_replica_is_busy_after_the_bounded_wait() {
    // Hold every slot of the process-wide parser-test gate.
    let held: Vec<_> = (0..MAX_WORKERS)
        .map_while(|_| gate().try_admit(None).ok())
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

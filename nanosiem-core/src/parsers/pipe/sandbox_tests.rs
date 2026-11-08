// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4919: preview isolation bounds. The worker is exercised end to end by
//! `nanosiem-api/tests/pipe_preview_worker.rs` (the real binary); these tests
//! drive the exchange with stand-in commands.
use super::*;
use serde_json::json;

fn request() -> PipePreviewRequest {
    PipePreviewRequest {
        parser_vrl: Some(".x = 1".into()),
        extension_vrl: None,
        events: vec![json!({"message":"a"})],
        inputs: None,
    }
}

#[test]
fn concurrency_is_clamped() {
    assert_eq!(configured_concurrency(None), DEFAULT_CONCURRENCY);
    assert_eq!(configured_concurrency(Some("0")), 1);
    assert_eq!(configured_concurrency(Some("99")), MAX_CONCURRENCY);
    assert_eq!(configured_concurrency(Some("x")), DEFAULT_CONCURRENCY);
}

#[test]
fn requests_are_bounded() {
    let mut r = request();
    r.events = vec![json!({}); 101];
    assert!(r.validate().is_err());
    r.events = vec![json!({"m": "x".repeat(70 * 1024)})];
    assert!(r.validate().is_err());
    r.events = vec![json!({})];
    r.inputs = Some(vec![None, None]);
    assert!(r.validate().is_err());
}

#[tokio::test]
async fn a_hung_worker_is_killed_at_the_deadline() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 30"]);
    let started = std::time::Instant::now();
    let result = exchange(command, b"{}", Duration::from_millis(300), 1024).await;
    assert!(matches!(result, Err(PreviewSandboxError::Deadline)));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn oversized_output_is_refused() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "head -c 4096 /dev/zero"]);
    let result = exchange(command, b"", Duration::from_secs(5), 1024).await;
    assert!(matches!(result, Err(PreviewSandboxError::OutputLimit)));
}

#[tokio::test]
async fn the_worker_sees_no_parent_environment() {
    std::env::set_var("NANO_PIPE_SANDBOX_SECRET_PROBE", "leak");
    let mut command = Command::new("/usr/bin/env");
    command.args(Vec::<String>::new());
    let output = exchange(command, b"", Duration::from_secs(5), 64 * 1024)
        .await
        .unwrap();
    let env = String::from_utf8(output).unwrap();
    assert!(!env.contains("NANO_PIPE_SANDBOX_SECRET_PROBE"), "{env}");
    assert!(env.contains("TZ=UTC"));
}

#[tokio::test]
async fn one_running_preview_per_user_then_429() {
    let user = Uuid::new_v4();
    let _held = UserSlot::acquire(user).unwrap();
    let refused = preview_with_executable(&request(), user, Path::new("/bin/true"), &[])
        .await
        .unwrap_err();
    assert!(matches!(refused, PreviewSandboxError::UserBusy));
    assert_eq!(refused.retry_after_seconds(), Some(RETRY_AFTER_SECONDS));
}

#[tokio::test]
async fn a_malformed_worker_reply_is_a_protocol_error() {
    let result =
        preview_with_executable(&request(), Uuid::new_v4(), Path::new("/bin/echo"), &["{}"]).await;
    assert!(matches!(result, Err(PreviewSandboxError::Protocol)));
}

#[tokio::test]
async fn the_engine_previews_plans_and_plain_vrl() {
    use crate::parsers::pipe::{Plan, Step};
    let plan = Plan {
        version: 2,
        revision: 1,
        steps: vec![
            Step {
                id: "mask".into(),
                name: "Mask".into(),
                kind: "mask".into(),
                enabled: true,
                condition: None,
                config: json!({"fields":["user"]}).as_object().unwrap().clone(),
            },
            Step {
                id: "drop".into(),
                name: "Drop".into(),
                kind: "filter".into(),
                enabled: true,
                condition: None,
                config: json!({"predicate":".noise == true","action":"drop"})
                    .as_object()
                    .unwrap()
                    .clone(),
            },
        ],
    };
    let mut r = request();
    r.parser_vrl = Some(plan.stored().unwrap());
    r.events = vec![json!({"user":"alice"}), json!({"user":"bob","noise":true})];
    let response = super::super::preview::run(&r).await.unwrap();
    assert_eq!(response.engine, "pipeline");
    assert_eq!(response.results[0].outputs[0]["user"], "[REDACTED]");
    assert_eq!(response.results[1].disposition, "filtered");
    assert_eq!(response.summary.dropped_events, 1);
    assert_eq!(response.results[0].traces.len(), 2);
    let plain = super::super::preview::run(&request()).await.unwrap();
    assert_eq!(plain.engine, "vrl");
    assert_eq!(plain.results[0].outputs[0]["x"], 1);
    // Plain VRL still compiles on the allowlist.
    let mut bad = request();
    bad.parser_vrl = Some("log(.message)".into());
    assert!(super::super::preview::run(&bad).await.is_err());
}

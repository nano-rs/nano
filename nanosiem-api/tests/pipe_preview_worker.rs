// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4919: the real `nanosiem-api --pipe-preview-worker` process runs a
//! draft pipeline end to end, and a runaway program is stopped by the bounds.

use nanosiem_core::parsers::pipe::{
    preview::PipePreviewRequest,
    sandbox::{preview_with_executable, PreviewSandboxError, WORKER_ARGUMENT},
    Plan, Step,
};
use serde_json::json;
use std::path::Path;
use uuid::Uuid;

fn step(id: &str, kind: &str, config: serde_json::Value) -> Step {
    Step {
        id: id.into(),
        name: id.into(),
        kind: kind.into(),
        enabled: true,
        condition: None,
        config: config.as_object().unwrap().clone(),
    }
}

/// The per-replica gate (default 2) is process-global: run these serially
/// so a test never sees another's admission as a 429.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_nanosiem-api"))
}

#[tokio::test]
async fn worker_previews_mask_filter_and_native_dedupe() {
    let _serial = SERIAL.lock().await;
    let plan = Plan {
        version: 2,
        revision: 1,
        steps: vec![
            step("parse", "parse", json!({"format":"json"})),
            step("mask", "mask", json!({"fields":["user"],"operation":"hash"})),
            step("noise", "filter", json!({"predicate":".action == \"heartbeat\"","action":"drop"})),
            step("dedupe", "dedupe", json!({"fields":["action","user"]})),
        ],
    };
    let request = PipePreviewRequest {
        parser_vrl: Some(plan.stored().unwrap()),
        extension_vrl: Some(".team = \"soc\"".into()),
        events: vec![
            json!({"message": "{\"user\":\"alice\",\"action\":\"deny\"}"}),
            json!({"message": "{\"user\":\"alice\",\"action\":\"deny\"}"}),
            json!({"message": "{\"user\":\"bob\",\"action\":\"heartbeat\"}"}),
        ],
        inputs: None,
    };
    let response = preview_with_executable(&request, Uuid::new_v4(), worker(), &[WORKER_ARGUMENT])
        .await
        .unwrap();
    assert_eq!(response.engine, "pipeline+native");
    let first = &response.results[0].outputs[0];
    assert_eq!(first["user"].as_str().unwrap().len(), 64);
    assert_eq!(first["team"], "soc");
    assert!(response.results[1].outputs.is_empty(), "duplicate dropped");
    assert_eq!(response.results[2].disposition, "filtered");
    assert_eq!(response.summary.output_events, 1);
    assert_eq!(response.degraded_isolation, !cfg!(target_os = "linux"));
}

#[tokio::test]
async fn invalid_drafts_come_back_as_reasons_not_worker_failures() {
    let _serial = SERIAL.lock().await;
    let request = PipePreviewRequest {
        parser_vrl: Some("get_env_var!(\"HOME\")".into()),
        extension_vrl: None,
        events: vec![json!({"message":"x"})],
        inputs: None,
    };
    let error = preview_with_executable(&request, Uuid::new_v4(), worker(), &[WORKER_ARGUMENT])
        .await
        .unwrap_err();
    assert!(matches!(error, PreviewSandboxError::Invalid(_)), "{error:?}");
}

#[tokio::test]
async fn a_cpu_bound_program_is_stopped() {
    let _serial = SERIAL.lock().await;
    // A split that fans out to the output bound, then a quadratic string
    // build per child: bounded by CPU time (Linux) or the wall clock.
    let code = "s = \"x\"\nfor_each(range(0, 40000) ?? []) -> |_i, _v| { s = s + s }";
    let request = PipePreviewRequest {
        parser_vrl: Some(code.into()),
        extension_vrl: None,
        events: vec![json!({"message":"x"})],
        inputs: None,
    };
    let started = std::time::Instant::now();
    let result =
        preview_with_executable(&request, Uuid::new_v4(), worker(), &[WORKER_ARGUMENT]).await;
    assert!(result.is_err(), "{result:?}");
    assert!(started.elapsed().as_secs() <= 12);
}

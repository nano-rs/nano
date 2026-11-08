// SPDX-License-Identifier: AGPL-3.0-or-later

use super::VectorConfigManager;
use crate::parsers::vector_config::parser_config::OCSF_PREPARE_VRL;

#[test]
fn udm_pipeline_clamps_future_timestamps_and_preserves_the_original() {
    let pipeline = VectorConfigManager::pipeline_config_content();

    assert!(pipeline.contains("NANO_FUTURE_TIMESTAMP_SKEW_SECONDS"));
    assert!(pipeline.contains("event_seconds > now_seconds + skew_seconds"));
    assert!(pipeline.contains(".original_timestamp = if original_ts !="));
    assert!(pipeline.contains("\"original_timestamp\", \"message\""));
}

#[test]
fn ocsf_prepare_clamps_the_storage_timestamp_but_keeps_event_time() {
    assert!(OCSF_PREPARE_VRL.contains("NANO_FUTURE_TIMESTAMP_SKEW_SECONDS"));
    assert!(OCSF_PREPARE_VRL.contains("time_ms <= max_future_ms"));
    assert!(!OCSF_PREPARE_VRL.contains("from_unix_timestamp!(time_ms"));
    assert!(OCSF_PREPARE_VRL.contains("\"event\": ocsf_event"));
    assert!(OCSF_PREPARE_VRL.contains("\"future_timestamp_skew_seconds\": skew_seconds"));
}

#[test]
fn ocsf_prepare_runtime_clamps_nanosecond_scale_without_aborting() {
    use serde_json::json;
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{compile, TargetValue, TimeZone};
    use vrl::value::{Secrets, Value};

    const ORIGINAL_NS: i64 = 1_762_300_000_000_000_000;
    let source = OCSF_PREPARE_VRL.replace(
        "skew_seconds = to_int(get_env_var(\"NANO_FUTURE_TIMESTAMP_SKEW_SECONDS\") ?? \"86400\") ?? 86400",
        "skew_seconds = 86400",
    );
    let program = compile(&source, &vrl::stdlib::all())
        .unwrap_or_else(|diagnostics| panic!("OCSF prepare failed to compile: {diagnostics:?}"))
        .program;
    let mut target = TargetValue {
        value: Value::from(json!({ "class_uid": 3002, "time": ORIGINAL_NS })),
        metadata: Value::from(json!({ "source_type": "future_scale" })),
        secrets: Secrets::new(),
    };

    Runtime::new(RuntimeState::default())
        .resolve(
            &mut target,
            &program,
            &TimeZone::parse("UTC").expect("UTC timezone"),
        )
        .expect("out-of-range OCSF time must not abort the remap");

    let row: serde_json::Value = target.value.try_into().expect("row JSON");
    assert_eq!(row["event"]["time"], ORIGINAL_NS);
    let stored = chrono::NaiveDateTime::parse_from_str(
        row["timestamp"].as_str().expect("timestamp string"),
        "%Y-%m-%d %H:%M:%S%.3f",
    )
    .expect("clamped timestamp");
    assert!(
        (chrono::Utc::now().naive_utc() - stored)
            .num_seconds()
            .abs()
            < 10
    );
}

fn timestamp_guard_program() -> String {
    let pipeline = VectorConfigManager::pipeline_config_content();
    let start = pipeline.find("ts_fell_back = false").unwrap();
    let tail = &pipeline[start..];
    let end = tail.find("# Marked, not silent.").unwrap();
    tail[..end].replace(
        "skew_seconds = to_int(get_env_var(\"NANO_FUTURE_TIMESTAMP_SKEW_SECONDS\") ?? \"86400\") ?? 86400",
        "skew_seconds = 86400",
    )
}

#[test]
fn udm_guard_runtime_clamps_year_9999_and_preserves_the_sender_value() {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{compile, TargetValue, TimeZone};
    use vrl::value::{ObjectMap, Secrets, Value};

    let source = timestamp_guard_program();
    let program = compile(&source, &vrl::stdlib::all())
        .unwrap_or_else(|diagnostics| panic!("timestamp guard failed to compile: {diagnostics:?}"))
        .program;
    let original = "9999-01-01T00:00:00Z";
    let mut event = ObjectMap::new();
    event.insert("timestamp".into(), Value::from(original));
    let mut target = TargetValue {
        value: Value::Object(event),
        metadata: Value::Object(ObjectMap::new()),
        secrets: Secrets::new(),
    };

    Runtime::new(RuntimeState::default())
        .resolve(
            &mut target,
            &program,
            &TimeZone::parse("UTC").expect("UTC timezone"),
        )
        .expect("timestamp guard executes");

    let event = target.value.as_object().unwrap();
    assert_eq!(
        event
            .get("original_timestamp")
            .and_then(|value| value.to_str_lossy().map(|value| value.into_owned()))
            .as_deref(),
        Some(original)
    );
    let stored = event
        .get("timestamp")
        .and_then(Value::to_str_lossy)
        .unwrap();
    let stored = chrono::NaiveDateTime::parse_from_str(&stored, "%Y-%m-%d %H:%M:%S").unwrap();
    let delta = chrono::Utc::now().naive_utc() - stored;
    assert!(
        delta.num_seconds().abs() < 10,
        "clamped timestamp was {stored}"
    );
}

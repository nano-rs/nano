// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4484: output of the pinned TQL through the production landing stage.
use base64::Engine;
use nanosiem_core::parsers::landing_ocsf::{LandingOcsfStage, StageContext};
use nanosiem_lake_worker::bronze::precheck_source_row;
use nanosiem_lake_worker::landing::{read_rows, FileFormat};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;

const FIXTURE: &str = include_str!("../../tools/log-blaster/tenzir/fixtures/mapped.ndjson");
const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const CREDENTIAL: &str = "96a0738d-542d-41b3-abae-e763907da310";

fn actual_pinned_parquet_rows() -> Vec<Value> {
    let mut archive = String::new();
    flate2::read::GzDecoder::new(
        &include_bytes!("../../tools/log-blaster/tenzir/fixtures/landing-parquet.json.gz")[..],
    )
    .read_to_string(&mut archive)
    .unwrap();
    let archive: Value = serde_json::from_str(&archive).unwrap();
    assert_eq!(
        archive["pipeline_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../tools/log-blaster/tenzir/blaster_to_ocsf.tql"
        )))
    );
    assert_eq!(
        archive["input_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../tools/log-blaster/tenzir/fixtures/raw.ndjson"
        )))
    );
    let mut rows = Vec::new();
    for encoded in archive["objects"].as_array().unwrap() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_str().unwrap())
            .unwrap();
        rows.extend(read_rows(&bytes, FileFormat::Parquet).unwrap());
    }
    rows
}

#[test]
fn actual_pinned_parquet_passes_the_production_decoder_and_admission() {
    let stage = LandingOcsfStage::new(1).unwrap();
    let mut failures = Vec::new();
    let rows = actual_pinned_parquet_rows();
    let count = rows.len();
    for input in rows {
        let class = input["class_uid"].clone();
        let standard = nanosiem_core::parsers::validate_ocsf_event(&input);
        let row = stage.prepare(input, &context()).unwrap();
        let mut event: Value = serde_json::from_str(&row.event_json).unwrap();
        event["time"] = json!(row.time_micros / 1000);
        if let Err(error) = precheck_source_row(event, TENANT) {
            let paths: Vec<_> = standard
                .errors
                .iter()
                .map(|e| (&e.code, &e.attribute_path, &e.message))
                .collect();
            failures.push(format!("class {class}: {error:?}; {paths:?}"));
        }
    }
    assert_eq!(count, FIXTURE.lines().count());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn coalesced_parquet_preserves_all_mapped_values_and_row_multiplicity() {
    fn meaningful(value: Value) -> Value {
        match value {
            Value::Object(values) => Value::Object(
                values
                    .into_iter()
                    .filter_map(|(key, value)| {
                        let value = meaningful(value);
                        (!value.is_null() && value.as_object().is_none_or(|v| !v.is_empty()))
                            .then_some((key, value))
                    })
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.into_iter().map(meaningful).collect()),
            value => value,
        }
    }
    let stage = LandingOcsfStage::new(1).unwrap();
    let canonical = |inputs: Vec<Value>| {
        let mut counts = std::collections::BTreeMap::new();
        for input in inputs {
            // Admission generates these two ingest clocks afresh per call.
            // Compare any source-supplied values instead, so generated clocks
            // cannot cause nondeterminism or conceal a changed mapped value.
            let source_clocks = ["logged_time", "processed_time"]
                .map(|name| (name, input["metadata"][name].clone()));
            let row = stage.prepare(input, &context()).unwrap();
            let mut event: Value = serde_json::from_str(&row.event_json).unwrap();
            event["time"] = json!(row.time_micros / 1000);
            for (name, source_value) in source_clocks {
                assert!(event["metadata"][name].as_i64().is_some_and(|ms| ms > 0));
                event["metadata"][name] = source_value;
            }
            *counts
                .entry(meaningful(event).to_string())
                .or_insert(0usize) += 1;
        }
        counts
    };
    let expected = FIXTURE
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let actual = canonical(actual_pinned_parquet_rows());
    let expected = canonical(expected);
    assert!(
        actual == expected,
        "mapped values/multiplicity changed: {} actual unique rows, {} expected",
        actual.len(),
        expected.len()
    );
}

fn context() -> StageContext<'static> {
    StageContext {
        tenant_id: TENANT,
        source_type: "tenzir_canary",
        credential_id: CREDENTIAL,
        event_key: None,
    }
}

#[test]
fn every_pinned_tql_fixture_passes_the_real_landing_and_ocsf19_admission() {
    let stage = LandingOcsfStage::new(1).unwrap();
    let mut failures = Vec::new();
    let mut classes = std::collections::BTreeSet::new();
    for (index, line) in FIXTURE.lines().enumerate() {
        let input: Value = serde_json::from_str(line).unwrap();
        classes.insert(input["class_uid"].as_i64().unwrap());
        let row = stage
            .prepare(input.clone(), &context())
            .unwrap_or_else(|e| panic!("fixture {index}: {e}"));
        let mut event: Value = serde_json::from_str(&row.event_json).unwrap();
        event["time"] = json!(row.time_micros / 1000);
        let checked = precheck_source_row(event.clone(), TENANT);
        if let Err(error) = checked {
            failures.push(format!(
                "fixture {index} class {}: {error:?}",
                event["class_uid"]
            ));
        }
        assert_eq!(event["metadata"]["version"], "1.9.0");
        assert_eq!(event["metadata"]["log_source"], "tenzir_canary");
        assert_eq!(event["metadata"]["tenant_uid"], TENANT);
        assert_eq!(event["metadata"]["nano_credential_id"], CREDENTIAL);
        assert_eq!(event["metadata"]["ingress_transport"], "landing_bucket");
        assert_eq!(event["raw_data"], input["raw_data"]);
        assert!(event["raw_data_size"].as_u64().unwrap() > 0);
        assert!(event["message"].as_str().unwrap().len() > 10);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(
        classes.into_iter().collect::<Vec<_>>(),
        vec![1001, 1005, 1007, 3002, 3003, 4001, 4002, 4003, 6003, 201001, 201002]
    );
}

#[test]
fn sender_metadata_cannot_change_tenant_source_or_credential() {
    let stage = LandingOcsfStage::new(1).unwrap();
    let mut input: Value = serde_json::from_str(FIXTURE.lines().next().unwrap()).unwrap();
    input["metadata"]["tenant_uid"] = json!("11111111-1111-4111-8111-111111111111");
    input["metadata"]["log_source"] = json!("another_tenant_source");
    input["metadata"]["nano_credential_id"] = json!("22222222-2222-4222-8222-222222222222");
    let row = stage.prepare(input, &context()).unwrap();
    let event: Value = serde_json::from_str(&row.event_json).unwrap();
    assert_eq!(event["metadata"]["tenant_uid"], TENANT);
    assert_eq!(event["metadata"]["log_source"], "tenzir_canary");
    assert_eq!(event["metadata"]["nano_credential_id"], CREDENTIAL);
}

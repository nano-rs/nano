// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3490: Google Workspace token activities delivered by the hosted
//! connector over HEC are admitted by the lake, end to end through the real
//! tenant lane.
//!
//! Each synthetic Reports API activity (`applicationName = token`) is POSTed
//! in the hosted runner's HEC envelope (`nano-connector` `hec_envelope`, with
//! the engine's `_nano_ingest_id` stamp), decoded as Vector's `splunk_hec`
//! source does, through the release base's `hec_normalize`, the source's
//! `_parse` (the published `google_workspace_ocsf` VRL), `_ocsf_split`,
//! `_ocsf_prepare` and `ocsf_lake_storage_prepare`, Vector's Parquet encode,
//! and the real salvaging admission.
//!
//! The live failure: the runner sent `event` as a JSON OBJECT. Vector spreads
//! an object over the log root and leaves `.message` unset, `hec_normalize`
//! sets `message = ""`, the parser (which reads `.message`) emits a Base Event
//! with an empty `raw_data`, and the lake refuses every row
//! (`raw_data_missing`). The runner now sends the event as JSON text.

use std::collections::BTreeSet;
use std::sync::Arc;

use arrow_json::reader::infer_json_schema_from_iterator;
use arrow_json::ReaderBuilder;
use arrow_schema::{ArrowError, DataType, Field, Schema, TimeUnit};
use base64::Engine as _;
use nanosiem_core::parsers::tenant_bundle::archive::{self, BundleTree};
use nanosiem_core::parsers::tenant_bundle::bronze_row_contract::{lake_rows, LakeRow, LaneInput};
use nanosiem_core::parsers::tenant_bundle::model::TenantSource;
use nanosiem_core::parsers::tenant_bundle::overlay;
use nanosiem_lake_worker::bronze::{admit_bronze_files_salvaging, NoCanonicalEvents, RowRefusal};
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};

const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f10";
const SLUG: &str = "gws_token";
/// The release base hosted tenants run (zero-nan3523).
const BASE: &str = "selected-parser-zero-nan3523.js";
const PARSER: &str = include_str!("fixtures/nan3490/google_workspace_ocsf.vrl");
const MODULES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../workers/hosted-ingest/src"
);

/// Same emulation as `nan3339_bronze_batch_isolation.rs`.
/// Vector 0.57 `ParquetSerializer::encode` with `schema_mode = "auto_infer"`
/// (lib/codecs/src/encoding/format/parquet.rs + arrow.rs `build_record_batch`),
/// after the sink's `encoding.except_fields`: infer one schema from the whole
/// batch, retype a top-level column whose every non-null value is a Vector
/// timestamp, decode the batch with that schema, write one Parquet file.
fn vector_parquet_encode(rows: &[LakeRow]) -> Result<Vec<u8>, String> {
    let values: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut value = row.json.clone();
            value
                .as_object_mut()
                .expect("a log event")
                .remove("_nano_bronze_partition");
            value
        })
        .collect();
    let schema = infer_json_schema_from_iterator(values.iter().map(Ok::<_, ArrowError>))
        .map_err(|e| format!("parquet_schema_generation_failed: {e}"))?;
    let mut timestamps = BTreeSet::new();
    let mut others = BTreeSet::new();
    for (row, value) in rows.iter().zip(&values) {
        for (key, member) in value.as_object().unwrap() {
            if row.timestamp_fields.contains(key) {
                timestamps.insert(key.clone());
            } else if !member.is_null() {
                others.insert(key.clone());
            }
        }
    }
    let fields: Vec<Field> = schema
        .fields()
        .iter()
        .map(|f| {
            if timestamps.contains(f.name()) && !others.contains(f.name()) {
                Field::new(
                    f.name(),
                    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                    f.is_nullable(),
                )
            } else {
                f.as_ref().clone()
            }
        })
        .collect();
    let schema = Arc::new(Schema::new_with_metadata(fields, schema.metadata().clone()));
    let mut decoder = ReaderBuilder::new(schema)
        .build_decoder()
        .map_err(|e| format!("arrow_record_batch_creation: {e}"))?;
    decoder
        .serialize(&values)
        .map_err(|e| format!("arrow_json_decode: {e}"))?;
    let batch = decoder
        .flush()
        .map_err(|e| format!("arrow_json_decode: {e}"))?
        .ok_or("no events")?;
    let mut bytes = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut bytes, batch.schema(), None)
        .map_err(|e| format!("parquet: {e}"))?;
    writer.write(&batch).map_err(|e| format!("parquet: {e}"))?;
    writer.close().map_err(|e| format!("parquet: {e}"))?;
    Ok(bytes)
}

fn module_base(name: &str) -> BundleTree {
    let text = std::fs::read_to_string(format!("{MODULES}/{name}")).unwrap();
    let json = text
        .trim_start_matches("// Generated by prepare-config.py; contains no credentials.\n")
        .strip_prefix("export const TENANT_VECTOR_CONFIGS = Object.freeze(")
        .and_then(|t| t.strip_suffix(");\n"))
        .unwrap_or_else(|| panic!("{name} is not a base module"));
    let value: Value = serde_json::from_str(json).unwrap();
    let chunks: String = value["output-bound"]["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    archive::unpack(
        &base64::engine::general_purpose::STANDARD
            .decode(chunks)
            .unwrap(),
    )
    .unwrap()
}

fn gws_token_source() -> TenantSource {
    TenantSource {
        slug: SLUG.into(),
        log_source_id: uuid::Uuid::from_u128(3490),
        version_id: 1,
        version_number: 1,
        name: SLUG.into(),
        parser_vrl: PARSER.into(),
        extension_vrl: None,
        extension_enabled: false,
        vendor: None,
        product: None,
        category: None,
        namespace: "default".into(),
        timezone: "UTC".into(),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        forked_from: None,
        samples: Vec::new(),
    }
}

/// Synthetic Reports API token activities: every token event kind and
/// parameter value type the API documents.
fn token_activities() -> Vec<Value> {
    let id = |time: &str, uniq: &str| json!({"time": time, "uniqueQualifier": uniq, "applicationName": "token", "customerId": "C01ab2cd3"});
    let user = json!({"email": "jane.doe@example.com", "profileId": "114511223344556677889", "callerType": "USER"});
    vec![
        json!({"kind": "admin#reports#activity", "id": id("2026-10-11T13:05:44.221Z", "-8234567890123456789"), "etag": "\"e1\"",
            "actor": user, "ipAddress": "203.0.113.55",
            "events": [{"type": "auth", "name": "authorize", "parameters": [
                {"name": "client_id", "value": "1234567890-abcdefg.apps.googleusercontent.com"},
                {"name": "app_name", "value": "Third Party Backup Tool"},
                {"name": "client_type", "value": "WEB"},
                {"name": "scope_data", "multiMessageValue": [
                    {"parameter": [{"name": "scope_name", "value": "https://www.googleapis.com/auth/drive"}, {"name": "product_bucket", "multiValue": ["DRIVE"]}]},
                    {"parameter": [{"name": "scope_name", "value": "openid"}, {"name": "product_bucket", "multiValue": ["IDENTITY"]}]}]},
                {"name": "scope", "multiValue": ["https://www.googleapis.com/auth/drive", "openid"]}]}]}),
        json!({"kind": "admin#reports#activity", "id": id("2026-10-11T13:06:00.123Z", "4567890123456789012"), "etag": "\"e2\"",
            "actor": user, "ipAddress": "2001:db8::1", "networkInfo": {"ipAsn": [64500], "regionCode": "US", "subdivisionCode": "US-CA"},
            "events": [{"type": "auth", "name": "activity", "parameters": [
                {"name": "api_name", "value": "gmail"},
                {"name": "method_name", "value": "gmail.users.messages.list"},
                {"name": "client_id", "value": "1234567890-abcdefg.apps.googleusercontent.com"},
                {"name": "num_response_bytes", "intValue": "1234"},
                {"name": "product_bucket", "value": "GMAIL"},
                {"name": "app_name", "value": "Example Mail Client"},
                {"name": "client_type", "value": "NATIVE_DESKTOP"}]}]}),
        json!({"kind": "admin#reports#activity", "id": id("2026-10-11T13:08:00.000Z", "2222222222222222222"), "etag": "\"e3\"",
            "actor": {"callerType": "KEY", "key": "SYSTEM"},
            "events": [{"type": "auth", "name": "revoke", "parameters": [
                {"name": "client_id", "value": "1234567890-abcdefg.apps.googleusercontent.com"},
                {"name": "app_name", "value": "Third Party Backup Tool"}]}]}),
        json!({"kind": "admin#reports#activity", "id": id("2026-10-11T13:09:00.000Z", "3333333333333333333"), "etag": "\"e4\"",
            "actor": {"email": "jane.doe@example.com", "profileId": "114511223344556677889",
                "applicationInfo": {"oauthClientId": "1234567890-abcdefg.apps.googleusercontent.com", "applicationName": "Example", "impersonation": true}},
            "ipAddress": "198.51.100.7",
            "events": [{"type": "auth", "name": "request", "parameters": [
                {"name": "client_id", "value": "1234567890-abcdefg.apps.googleusercontent.com"},
                {"name": "is_impersonation", "boolValue": true},
                {"name": "device", "messageValue": {"parameter": [{"name": "device_id", "value": "abc"}]}}]}]}),
    ]
}

/// One activity as the hosted runner POSTs it: the engine's ingest-id stamp
/// (`stamp_ingest_id` with the stream's `ingest_id` fields), then
/// `hec_envelope` (`event` as JSON text). `as_object` reproduces the envelope
/// the runner sent before NAN-3490 (`event` as a JSON object).
fn runner_envelope(activity: &Value, as_object: bool) -> Value {
    let mut event = activity.clone();
    let id = &activity["id"];
    event["_nano_ingest_id"] = json!(format!(
        "{}:{}:{}:{}",
        id["applicationName"].as_str().unwrap(),
        id["customerId"].as_str().unwrap(),
        id["uniqueQualifier"].as_str().unwrap(),
        id["time"].as_str().unwrap()
    ));
    let event = if as_object { event } else { Value::String(event.to_string()) };
    json!({"event": event, "sourcetype": SLUG, "source": "nano-connector:google_workspace"})
}

/// Admit one bronze object of `envelopes` for the gws_token source.
fn admit(envelopes: Vec<Value>) -> anyhow::Result<(nanosiem_lake_worker::bronze::BronzeAdmission, nanosiem_lake_worker::bronze::RefusedRows)> {
    let (candidate, _) = overlay::apply_overlay(&module_base(BASE), &[gws_token_source()]).unwrap();
    let inputs = envelopes
        .into_iter()
        .map(|envelope| LaneInput::HecEnvelope { slug: SLUG.into(), envelope })
        .collect::<Vec<_>>();
    let rows = lake_rows(&candidate, TENANT, &inputs).unwrap_or_else(|e| panic!("{e}"));
    let bytes = vector_parquet_encode(&rows).unwrap_or_else(|e| panic!("{e}"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bronze.parquet");
    std::fs::write(&path, &bytes).unwrap();
    admit_bronze_files_salvaging(&[path], TENANT, &BronzeIngestEnricher::disabled())
}

/// The live refusal, reproduced: the pre-NAN-3490 envelope loses `raw_data`
/// and the lake refuses every row of the object.
#[test]
fn object_event_envelopes_are_refused_raw_data_missing() {
    let envelopes = token_activities().iter().map(|a| runner_envelope(a, true)).collect();
    let Err(error) = admit(envelopes) else {
        panic!("the object-event envelope must not be admitted");
    };
    let refused = error.downcast_ref::<NoCanonicalEvents>().unwrap_or_else(|| panic!("{error:#}"));
    assert_eq!(refused.first_row, Some(RowRefusal::new("raw_data_missing", Some("raw_data"))));
}

#[test]
fn gws_token_hec_deliveries_are_admitted_by_the_lake() {
    let activities = token_activities();
    let envelopes = activities.iter().map(|a| runner_envelope(a, false)).collect();
    let (admission, refused) = admit(envelopes).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(refused.is_empty(), "{refused:?}");
    let admitted = admission.batch.rows();
    assert_eq!(admitted.len(), activities.len());
    let uids = admitted.iter().map(|row| row.event_uid.as_str()).collect::<BTreeSet<_>>();
    for activity in &activities {
        let id = &activity["id"];
        let uid = format!(
            "gws|token|C01ab2cd3|{}|{}",
            id["uniqueQualifier"].as_str().unwrap(),
            id["time"].as_str().unwrap()
        );
        assert!(uids.contains(uid.as_str()), "{uid} missing from {uids:?}");
    }
    for row in admitted {
        let event = &row.ocsf_event;
        assert_eq!(event["class_uid"], 6003, "{event}");
        assert_eq!(event["metadata"]["log_source"], SLUG);
        assert_eq!(event["metadata"]["tenant_uid"], TENANT);
        assert!(event["raw_data"].as_str().is_some_and(|raw| raw.contains("admin#reports#activity")));
    }
}

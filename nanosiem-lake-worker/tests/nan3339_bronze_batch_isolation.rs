// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3339 contract: one malformed row never takes the other rows of its
//! Vector batch with it.
//!
//! The tenant Vector's bronze sink encodes each batch as ONE Parquet file
//! whose Arrow schema it infers from that batch. [`vector_parquet_encode`] is
//! Vector 0.57's `ParquetSerializer::encode` (`schema_mode = "auto_infer"`,
//! the same arrow 58 calls in the same order), so "the encode fails" here is
//! `parquet_schema_generation_failed` / `arrow_json_decode` live, after which
//! Vector drops the whole batch.
//!
//! Every lane feeds one batch: the generic lane, the platform audit lane and
//! a tenant parser's `_ocsf_prepare`, through each base's own VRL and its own
//! `ocsf_lake_storage_prepare` (`bronze_row_contract::lake_rows`), plus
//! adversarial tenant rows (object / array / scalar drift in `unmapped`,
//! `message` and `enrichments`, a string where other rows carry a number, a
//! mixed-type array, an empty object). Without the contract the batch fails
//! to encode; with it the batch encodes, every row decodes back to its event
//! (`decode_bronze_row`), and the real admission lands every well-formed row.

use std::collections::BTreeSet;
use std::sync::Arc;

use arrow_json::reader::infer_json_schema_from_iterator;
use arrow_json::{LineDelimitedWriter, ReaderBuilder};
use arrow_schema::{ArrowError, DataType, Field, Schema, TimeUnit};
use base64::Engine as _;
use nanosiem_core::parsers::tenant_bundle::archive::{self, BundleTree};
use nanosiem_core::parsers::tenant_bundle::bronze_row_contract::{
    add_bronze_row_contract, lake_rows, LakeRow, LaneInput,
};
use nanosiem_core::parsers::tenant_bundle::model::TenantSource;
use nanosiem_core::parsers::tenant_bundle::{overlay, platform_audit_lane};
use nanosiem_lake_worker::bronze::{admit_bronze_files_salvaging, decode_bronze_row};
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};

const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f10";
const SLUG: &str = "acme_proxy";
const TESTDATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../nanosiem-core/src/parsers/tenant_bundle/testdata"
);
const MODULES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../workers/hosted-ingest/src"
);

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

/// The rows `ingest[T]` decodes from one bronze object (bronze.rs: Parquet ->
/// Arrow -> NDJSON -> `decode_bronze_row`).
fn decode_object(bytes: &[u8]) -> Vec<Value> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::copy_from_slice(bytes))
        .unwrap()
        .build()
        .unwrap();
    let mut rows = Vec::new();
    for batch in reader {
        let mut writer = LineDelimitedWriter::new(Vec::new());
        writer.write(&batch.unwrap()).unwrap();
        writer.finish().unwrap();
        for line in writer
            .into_inner()
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
        {
            rows.push(decode_bronze_row(serde_json::from_slice(line).unwrap()).unwrap());
        }
    }
    rows
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

/// Every platform base the contract applies to, each with the audit lane:
/// the current release base and the four builder test bases.
fn bases() -> Vec<(String, BundleTree)> {
    let mut out = vec![(
        "zero-nan3304".to_string(),
        module_base("selected-parser-zero-nan3304.js"),
    )];
    for name in [
        "platform-base",
        "platform-base-collector-v2",
        "platform-base-zero",
        "platform-base-zero-collector-v2",
    ] {
        let base =
            archive::unpack(&std::fs::read(format!("{TESTDATA}/{name}.tar.gz")).unwrap()).unwrap();
        out.push((
            name.to_string(),
            platform_audit_lane::add_platform_audit_lane(&base).unwrap(),
        ));
    }
    out
}

fn tenant_source() -> TenantSource {
    TenantSource {
        slug: SLUG.into(),
        log_source_id: uuid::Uuid::from_u128(3339),
        version_id: 1,
        version_number: 1,
        name: SLUG.into(),
        parser_vrl: ". = parse_json!(.message)".into(),
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

/// A well-formed OCSF 1.9 Base Event as a tenant parser emits it.
fn ocsf(message: &str, extra: Value) -> Value {
    let mut event = json!({
        "activity_id": 0, "activity_name": "Unknown", "category_name": "Uncategorized", "category_uid": 0,
        "class_name": "Base Event", "class_uid": 0, "message": message,
        "metadata": {"product": {"name": "Acme Proxy", "vendor_name": "Acme"}, "version": "1.9.0"},
        "severity": "Informational", "severity_id": 1, "time": 1_790_000_000_000_i64,
        "type_name": "Base Event: Unknown", "type_uid": 0,
    });
    for (key, value) in extra.as_object().unwrap() {
        event[key] = value.clone();
    }
    event
}

fn audit_line(details: Value) -> LaneInput {
    let line = json!({
        "activity_id": 1, "activity_name": "Create", "category_name": "Application Activity", "category_uid": 6,
        "class_name": "API Activity", "class_uid": 6003, "severity_id": 1, "type_uid": 600301,
        "time": 1_790_000_000_000_i64, "api": {"operation": "rule_created"}, "message": "rule_created",
        "actor": {"user": {"name": "dan"}}, "src_endpoint": {"ip": "10.1.2.3"},
        "metadata": {"tenant_uid": TENANT, "uid": uuid::Uuid::new_v4().to_string(), "log_name": "audit",
            "product": {"name": "nano", "vendor_name": "nano"}, "version": "1.9.0"},
        "unmapped": {"action": "rule_created", "details": details},
    });
    LaneInput::Audit {
        line: line.to_string(),
    }
}

fn tenant(event: Value) -> LaneInput {
    LaneInput::Tenant {
        slug: SLUG.into(),
        event,
    }
}

/// Well-formed rows of every lane: (inputs, how many).
fn every_lane() -> Vec<LaneInput> {
    vec![
        LaneInput::Generic {
            event: json!({"message": "generic hello"}),
            source_type: "unknown".into(),
        },
        LaneInput::Generic {
            event: json!({"message": "otlp line", "trace_id": "AB12"}),
            source_type: "otlp_log".into(),
        },
        audit_line(json!({"templates_suspended": 2})),
        audit_line(json!("free text")),
        tenant(ocsf("tenant plain", json!({}))),
        tenant(ocsf(
            "tenant with unmapped",
            json!({"unmapped": {"k": "v", "n": 1}}),
        )),
    ]
}

/// Rows whose shapes conflict with the well-formed rows: each group alone
/// fails an otherwise good batch.
fn adversarial_groups() -> Vec<Vec<LaneInput>> {
    vec![
        vec![tenant(ocsf(
            "unmapped array",
            json!({"unmapped": ["a", 1]}),
        ))],
        vec![tenant(ocsf("unmapped scalar", json!({"unmapped": 42})))],
        vec![tenant(ocsf(
            "message object",
            json!({"message": {"nested": true}}),
        ))],
        vec![
            tenant(ocsf(
                "enrichments object",
                json!({"enrichments": {"name": "x"}}),
            )),
            tenant(ocsf(
                "enrichments array",
                json!({"enrichments": [{"name": "ip", "value": "1.2.3.4", "data": {"k": 1}}]}),
            )),
        ],
        vec![tenant(ocsf(
            "severity_id string",
            json!({"severity_id": "3"}),
        ))],
        vec![tenant(ocsf(
            "mixed array",
            json!({"metadata": {"labels": [1, "two"], "product": {"name": "Acme"}, "version": "1.9.0"}}),
        ))],
        vec![tenant(ocsf("empty object", json!({"cloud": {}})))],
    ]
}

fn adversarial() -> Vec<LaneInput> {
    adversarial_groups().into_iter().flatten().collect()
}

fn uid(row: &LakeRow) -> String {
    row.json["metadata"]["uid"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| {
            let event: Value =
                serde_json::from_str(row.json["_nano_bronze_event"].as_str().unwrap()).unwrap();
            event["metadata"]["uid"].as_str().unwrap().to_string()
        })
}

/// The event `ingest[T]` must see for a pre-contract row: its JSON without
/// the stripped partition helper, null members dropped, `unmapped` decoded.
fn expected_event(row: &LakeRow) -> Value {
    let mut value = row.json.clone();
    value
        .as_object_mut()
        .unwrap()
        .remove("_nano_bronze_partition");
    fn strip(value: &mut Value) {
        match value {
            Value::Object(map) => {
                map.retain(|_, v| !v.is_null());
                map.values_mut().for_each(strip);
            }
            Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut value);
    nanosiem_lake_worker::bronze::decode_bronze_unmapped(&mut value);
    value
}

fn same_instant(a: &Value, b: &Value) -> bool {
    let parse = |v: &Value| chrono::DateTime::parse_from_rfc3339(v.as_str().unwrap()).unwrap();
    parse(a) == parse(b)
}

#[test]
fn one_drifting_row_never_takes_the_batch_with_it() {
    let inputs: Vec<LaneInput> = every_lane().into_iter().chain(adversarial()).collect();
    let well_formed = every_lane().len();
    for (name, base) in bases() {
        let (candidate, _) = overlay::apply_overlay(&base, &[tenant_source()]).unwrap();
        let columnar =
            lake_rows(&candidate, TENANT, &inputs).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(columnar.len(), inputs.len(), "{name}");

        // The bug: one batch, one inferred schema, and the drifting rows fail
        // it, so Vector drops every row, every lane's.
        let error = vector_parquet_encode(&columnar)
            .expect_err(&format!("{name}: the columnar batch must fail"));
        assert!(
            error.starts_with("parquet_schema_generation_failed")
                || error.starts_with("arrow_json_decode")
                || error.starts_with("parquet:"),
            "{name}: {error}"
        );
        // Each adversarial group alone poisons an otherwise good batch. (The
        // builder test bases predate NAN-3079: their generic lane's object
        // `unmapped` already conflicts with a tenant lane's string, so even
        // their well-formed rows fail columnar; the release base does not.)
        let good_alone = vector_parquet_encode(&columnar[..well_formed]);
        assert!(
            good_alone.is_ok() || name.starts_with("platform-base"),
            "{name}: the well-formed rows alone encode"
        );
        if good_alone.is_ok() {
            let mut next = well_formed;
            for (index, group) in adversarial_groups().iter().enumerate() {
                let mut batch = columnar[..well_formed].to_vec();
                batch.extend_from_slice(&columnar[next..next + group.len()]);
                next += group.len();
                assert!(
                    vector_parquet_encode(&batch).is_err(),
                    "{name}: adversarial group {index} alone fails the batch"
                );
            }
        }

        // The contract: the same rows, as a base carrying it writes them.
        let contracted: Vec<LakeRow> = columnar
            .iter()
            .map(|r| r.with_bronze_row_contract().unwrap())
            .collect();
        let bytes = vector_parquet_encode(&contracted)
            .unwrap_or_else(|e| panic!("{name}: the contract batch encodes: {e}"));
        let decoded = decode_object(&bytes);
        assert_eq!(
            decoded.len(),
            inputs.len(),
            "{name}: every row is in the object"
        );
        for (row, got) in columnar.iter().zip(&decoded) {
            let mut want = expected_event(row);
            let (want_time, got_time) = (
                want.as_object_mut().unwrap().remove("time").unwrap(),
                got["time"].clone(),
            );
            assert!(
                same_instant(&want_time, &got_time),
                "{name}: {want_time} vs {got_time}"
            );
            let mut got = got.clone();
            got.as_object_mut().unwrap().remove("time");
            assert_eq!(got, want, "{name}: the row decodes back to its event");
        }

        // And the base derived with the contract writes encodable batches itself.
        let with = add_bronze_row_contract(&base).unwrap();
        let (candidate, _) = overlay::apply_overlay(&with, &[tenant_source()]).unwrap();
        let rows = lake_rows(&candidate, TENANT, &inputs).unwrap_or_else(|e| panic!("{name}: {e}"));
        let bytes = vector_parquet_encode(&rows)
            .unwrap_or_else(|e| panic!("{name}: the derived base's batch encodes: {e}"));

        // ingest[T] admits every well-formed row of every lane; an adversarial
        // row is admitted or refused on its own, never with the others.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bronze.parquet");
        std::fs::write(&path, &bytes).unwrap();
        let (admission, refused) = admit_bronze_files_salvaging(
            &[path.clone()],
            TENANT,
            &BronzeIngestEnricher::disabled(),
        )
        .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        let admitted: BTreeSet<&str> = admission
            .batch
            .rows()
            .iter()
            .map(|r| r.event_uid.as_str())
            .collect();
        for row in &rows[..well_formed] {
            assert!(
                admitted.contains(uid(row).as_str()),
                "{name}: well-formed row {} lost ({refused:?})",
                uid(row)
            );
        }
        let refused_rows = refused.get(&path).map_or(0, |(n, _)| *n);
        assert_eq!(
            admitted.len() as u64 + refused_rows,
            inputs.len() as u64,
            "{name}: every row is accounted for"
        );
    }
}

/// Columnar/contract parity: on a batch the columnar form CAN encode, both
/// forms decode to byte-identical events (null members, nested arrays, the
/// `time` rendering, `unmapped`), so the source identity of a row replayed
/// across the base roll is unchanged and never reads as a conflicting replay.
#[test]
fn contract_rows_decode_exactly_as_the_columnar_rows_did() {
    // Two batches, so each also encodes columnar on the oldest bases (whose
    // generic lane still wrote `unmapped` as an object: the NAN-3079 drift).
    let generic = vec![
        LaneInput::Generic {
            event: json!({"message": "generic hello"}),
            source_type: "unknown".into(),
        },
        LaneInput::Generic {
            event: json!({"message": "otlp line", "trace_id": "AB12"}),
            source_type: "otlp_log".into(),
        },
    ];
    let mixed = vec![
        audit_line(json!({"templates_suspended": 2, "nothing": null})),
        tenant(ocsf(
            "a",
            json!({"observables": [{"name": "src", "type_id": 2, "value": "10.0.0.1"}],
            "unmapped": {"k": null, "deep": {"x": [1, 2]}}}),
        )),
        tenant(ocsf(
            "b",
            json!({"observables": [{"name": "dst", "type_id": 2, "value": null}], "status": null}),
        )),
        tenant(ocsf("c", json!({"time": 1_790_000_000_123_i64}))),
    ];
    for (name, base) in bases() {
        let (candidate, _) = overlay::apply_overlay(&base, &[tenant_source()]).unwrap();
        for inputs in [&generic, &mixed] {
            let columnar =
                lake_rows(&candidate, TENANT, inputs).unwrap_or_else(|e| panic!("{name}: {e}"));
            let contracted: Vec<LakeRow> = columnar
                .iter()
                .map(|r| r.with_bronze_row_contract().unwrap())
                .collect();
            let before = decode_object(
                &vector_parquet_encode(&columnar).unwrap_or_else(|e| panic!("{name}: {e}")),
            );
            let after = decode_object(
                &vector_parquet_encode(&contracted).unwrap_or_else(|e| panic!("{name}: {e}")),
            );
            assert_eq!(after, before, "{name}: identical decoded events");

            // Both forms admit to the same rows through the real admission.
            let dir = tempfile::tempdir().unwrap();
            let admit = |file: &str, rows: &[LakeRow]| {
                let path = dir.path().join(file);
                std::fs::write(&path, vector_parquet_encode(rows).unwrap()).unwrap();
                let (admission, refused) = admit_bronze_files_salvaging(
                    &[path],
                    TENANT,
                    &BronzeIngestEnricher::disabled(),
                )
                .unwrap_or_else(|e| panic!("{name}: {e:#}"));
                assert!(refused.is_empty(), "{name}: {refused:?}");
                serde_json::to_value(
                    admission
                        .batch
                        .rows()
                        .iter()
                        .map(|r| (&r.event_uid, &r.ocsf_event))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            };
            assert_eq!(
                admit("after.parquet", &contracted),
                admit("before.parquet", &columnar),
                "{name}"
            );
        }
    }
}

/// The release bases `selected-parser-zero-nan3339.js` (zero-nan3304 + the
/// contract) and `selected-parser-zero-nan3339-v2.js` (zero-nan3304-v2 + the
/// contract, which supersedes it), and `selected-parser-zero-nan3460.js`
/// (zero-nan3339-v2 with the NAN-3460 audit lane), and `selected-parser-zero-nan3523.js`
/// (zero-nan3460 with the NAN-3523 byte-bounded bronze buffer) write every lane's rows and the adversarial
/// rows as ONE encodable batch, and ingest[T] admits every well-formed row.
#[test]
fn the_nan3339_release_base_writes_one_encodable_batch_for_every_lane() {
    for name in ["selected-parser-zero-nan3339.js", "selected-parser-zero-nan3339-v2.js", "selected-parser-zero-nan3460.js",
        "selected-parser-zero-nan3523.js"] {
        one_encodable_batch_for_every_lane(name);
    }
}

fn one_encodable_batch_for_every_lane(name: &str) {
    let base = module_base(name);
    assert!(
        nanosiem_core::parsers::tenant_bundle::bronze_row_contract::has_bronze_row_contract(&base)
    );
    let inputs: Vec<LaneInput> = every_lane().into_iter().chain(adversarial()).collect();
    let (candidate, _) = overlay::apply_overlay(&base, &[tenant_source()]).unwrap();
    let rows = lake_rows(&candidate, TENANT, &inputs).unwrap();
    let bytes = vector_parquet_encode(&rows).expect("one batch, one schema");
    assert_eq!(decode_object(&bytes).len(), inputs.len());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bronze.parquet");
    std::fs::write(&path, &bytes).unwrap();
    let (admission, refused) =
        admit_bronze_files_salvaging(&[path.clone()], TENANT, &BronzeIngestEnricher::disabled())
            .unwrap();
    let admitted: BTreeSet<&str> = admission
        .batch
        .rows()
        .iter()
        .map(|r| r.event_uid.as_str())
        .collect();
    for row in &rows[..every_lane().len()] {
        assert!(
            admitted.contains(uid(row).as_str()),
            "{name}: well-formed row {} lost ({refused:?})",
            uid(row)
        );
    }
    assert_eq!(
        admitted.len() as u64 + refused.get(&path).map_or(0, |(n, _)| *n),
        inputs.len() as u64,
        "{name}"
    );
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! The fixed bronze row contract in a tenant parser base (NAN-3339).
//!
//! [`add_bronze_row_contract`] derives a base whose lake storage stage
//! (`ocsf_lake_storage_prepare`, the one transform every lane reaches the
//! bronze sink through) ends with
//! [`crate::parsers::lake_bronze_row::LAKE_BRONZE_ROW_VRL`]: every bronze
//! row then has the same two columns, so no row's shape can fail the sink's
//! per-batch Parquet schema and take the batch's other rows with it. The
//! edit is confined to that stage's VRL in the two `_ocsf_sink.toml` copies;
//! the guard/sink wiring the product contract pins
//! (`ocsf_lake_storage_prepare` -> `ocsf_output_guard` -> `ocsf_parquet_bronze`)
//! is unchanged, and so are the HEC config and the output guard (their pins).
//!
//! [`lake_rows`] runs a base's own lane VRL and storage stage with the
//! embedded VRL runtime: the exact rows a cell's Vector hands the bronze
//! sink, for the cross-lane contract tests in `nanosiem-lake-worker`.

use super::archive::BundleTree;
use super::overlay::{TenantName, LAKE_SINK_FILE};
use super::platform_audit_lane::{storage_prepare_vrl, AUDIT_LANE_FILE, AUDIT_PREPARE, AUDIT_SLUG};
use super::TenantBundleError;
use crate::parsers::lake_bronze_row::{
    append_to_storage_prepare, LAKE_BRONZE_ROW_MARKER, LAKE_BRONZE_ROW_VRL,
};

/// Every `_ocsf_sink.toml` copy a base carries (the product contract checks
/// both; `backup/` is the fallback config).
pub const BRONZE_SINK_FILES: [&str; 2] = [LAKE_SINK_FILE, "backup/_ocsf_sink.toml"];

const PIPELINE_FILE: &str = "sources/parsers/_pipeline.toml";
const GENERIC_PREPARE: &str = "generic_ocsf_prepare";

fn base_error(what: &str) -> TenantBundleError {
    TenantBundleError::Base(format!("bronze row contract: {what}"))
}

/// `text` with every `${VAR:-default}` resolved to its default, as Vector
/// renders it with the variable unset (typed knobs are unquoted).
fn resolve_interpolation(text: &str) -> String {
    let defaults = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}").expect("static regex");
    defaults.replace_all(text, "$1").into_owned()
}

/// Whether the base's lake storage stage already ends with the contract.
pub fn has_bronze_row_contract(base: &BundleTree) -> bool {
    base.text(LAKE_SINK_FILE)
        .is_ok_and(|text| text.contains(LAKE_BRONZE_ROW_MARKER))
}

/// Derive the base whose bronze rows follow the fixed row contract: append
/// the contract VRL to `ocsf_lake_storage_prepare` in every `_ocsf_sink.toml`
/// copy, and change nothing else. Refuses a base whose lake sink is not the
/// Parquet bronze sink fed by the output guard, or that already carries it.
pub fn add_bronze_row_contract(base: &BundleTree) -> Result<BundleTree, TenantBundleError> {
    if has_bronze_row_contract(base) {
        return Err(base_error("the base already carries the contract"));
    }
    let sink: toml::Table = resolve_interpolation(base.text(LAKE_SINK_FILE)?)
        .parse()
        .map_err(|_| base_error("the lake sink is not TOML"))?;
    let bronze = sink.get("sinks").and_then(|s| s.get("ocsf_parquet_bronze"));
    let codec = bronze
        .and_then(|b| b.get("batch_encoding"))
        .and_then(|e| e.get("codec"))
        .and_then(toml::Value::as_str);
    if codec != Some("parquet") {
        return Err(base_error("the lake sink is not the Parquet bronze sink"));
    }
    let mut tree = base.clone();
    for path in BRONZE_SINK_FILES {
        let Ok(text) = base.text(path) else {
            if path == LAKE_SINK_FILE {
                return Err(base_error("the base has no lake sink"));
            }
            continue;
        };
        let edited = append_to_storage_prepare(text)
            .ok_or_else(|| base_error(&format!("{path} has no single storage stage to extend")))?;
        tree.put(path, edited.into_bytes());
    }
    Ok(tree)
}

/// One input to a lane, as it reaches that lane's prepare transform.
#[derive(Debug, Clone)]
pub enum LaneInput {
    /// A parserless event on the generic lane (`generic_ocsf_prepare`), with
    /// the routing key it arrived under.
    Generic {
        event: serde_json::Value,
        source_type: String,
    },
    /// One delivered platform audit line (the `audit` lane).
    Audit { line: String },
    /// A tenant parser's OCSF output on that source's `_ocsf_prepare`.
    Tenant {
        slug: String,
        event: serde_json::Value,
    },
    /// One delivery on a tenant source as it reaches that source's parser
    /// (`_parse`, e.g. `{"message": "<raw line>"}`): the parser runs, and its
    /// output must take the OCSF split onto `_ocsf_prepare` (NAN-3490).
    TenantDelivery {
        slug: String,
        event: serde_json::Value,
    },
    /// One Splunk HEC envelope (`{"event": ..., "sourcetype": ...}`) POSTed
    /// for a tenant source: Vector's `splunk_hec` source decodes it
    /// ([`splunk_hec_log`]), the base's `hec_normalize` runs with the source's
    /// private delivery token, then the tenant lane as for
    /// [`LaneInput::TenantDelivery`] (NAN-3490).
    HecEnvelope {
        slug: String,
        envelope: serde_json::Value,
    },
}

/// The shipped HEC source uses `event.decoding.codec = "bytes"`:
/// string payloads stay text and object payloads are serialized to JSON in
/// `.message`. Envelope metadata remains separate from payload routing fields.
pub fn splunk_hec_log(envelope: &serde_json::Value) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    let mut log = serde_json::Map::new();
    let message = match envelope.get("event") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        Some(Value::Null) | None => return Err("splunk_hec refuses the envelope's event".into()),
        Some(Value::String(_)) => return Err("splunk_hec refuses the envelope's event".into()),
        Some(value) => value.to_string(),
    };
    log.insert("message".into(), Value::String(message));
    for (field, key) in [("sourcetype", "splunk_sourcetype"), ("source", "splunk_source")] {
        if let Some(value) = envelope.get(field).filter(|v| v.is_string()) {
            log.insert(key.into(), value.clone());
        }
    }
    log.insert("source_type".into(), Value::String("splunk_hec".into()));
    Ok(Value::Object(log))
}

/// The base's `hec_normalize` for one tenant source, with the cell's
/// environment (`VECTOR_AUTH_TOKEN`, `NANO_TENANT_ID`) and the delivery
/// token the Worker presents resolved in place (Vector's `get_secret` /
/// `remove_secret` are not VRL stdlib functions).
fn hec_normalize(
    tree: &BundleTree,
    tenant_id: &str,
    slug: &str,
    log: serde_json::Value,
) -> Result<vrl::value::Value, String> {
    const TOKEN: &str = "lake-rows-delivery-token";
    let mut source = transform_source(tree, super::overlay::HEC_FILE, "hec_normalize")?;
    for (call, value) in [
        ("get_env_var(\"VECTOR_AUTH_TOKEN\") ?? \"\"", TOKEN),
        ("get_env_var(\"NANO_TENANT_ID\") ?? \"\"", tenant_id),
        ("get_secret(\"splunk_hec_token\")", format!("{TOKEN}:nano-source-v1:{slug}").as_str()),
    ] {
        if !source.contains(call) {
            return Err(format!("hec_normalize no longer reads {call}"));
        }
        source = source.replace(call, &format!("{value:?}"));
    }
    let removal = "remove_secret(\"splunk_hec_token\")";
    if !source.contains(removal) {
        return Err(format!("hec_normalize no longer calls {removal}"));
    }
    let source = source.replace(removal, "null");
    run_vrl(&source, vrl::value::Value::from(log), &[])
}

/// One row as the bronze sink receives it.
#[derive(Debug, Clone)]
pub struct LakeRow {
    /// The row as Vector's Parquet encoder sees it (`serde_json::to_value`
    /// of the event: timestamps become RFC 3339 strings).
    pub json: serde_json::Value,
    /// Top-level fields that are Vector timestamps (Vector's encoder types
    /// such a column as a Timestamp when every row agrees).
    pub timestamp_fields: Vec<String>,
    value: vrl::value::Value,
}

impl LakeRow {
    fn new(value: vrl::value::Value) -> Result<Self, String> {
        let json = serde_json::to_value(&value).map_err(|e| e.to_string())?;
        let timestamp_fields = match &value {
            vrl::value::Value::Object(map) => map
                .iter()
                .filter(|(_, v)| matches!(v, vrl::value::Value::Timestamp(_)))
                .map(|(k, _)| k.to_string())
                .collect(),
            _ => Vec::new(),
        };
        Ok(Self {
            json,
            timestamp_fields,
            value,
        })
    }

    /// This exact row passed through the contract VRL, as a base carrying the
    /// contract would have ended its storage stage (for columnar/contract
    /// parity tests over identical rows).
    pub fn with_bronze_row_contract(&self) -> Result<Self, String> {
        Self::new(run_vrl(LAKE_BRONZE_ROW_VRL, self.value.clone(), &[])?)
    }
}

pub(super) fn run_vrl(
    source: &str,
    value: vrl::value::Value,
    metadata: &[(&str, &str)],
) -> Result<vrl::value::Value, String> {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{TargetValue, TimeZone};
    use vrl::value::{ObjectMap, Secrets, Value};
    let program = crate::parsers::vrl_guard::compile(source, &vrl::stdlib::all())
        .map_err(|e| e.render(source))?
        .program;
    let mut meta = ObjectMap::new();
    for (key, value) in metadata {
        meta.insert((*key).into(), Value::from(*value));
    }
    let mut target = TargetValue {
        value,
        metadata: Value::Object(meta),
        secrets: Secrets::new(),
    };
    Runtime::new(RuntimeState::default())
        .resolve(&mut target, &program, &TimeZone::Local)
        .map_err(|e| e.to_string())?;
    Ok(target.value)
}

fn transform_source(tree: &BundleTree, path: &str, transform: &str) -> Result<String, String> {
    let doc: toml::Table = tree
        .text(path)
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|e| format!("{path}: {e}"))?;
    doc.get("transforms")
        .and_then(|t| t.get(transform))
        .and_then(|t| t.get("source"))
        .and_then(toml::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{path} has no {transform} source"))
}

/// A tenant source's `_parse` (its parser) on one delivery, then the
/// generated `_ocsf_split` route: anything but OCSF output takes the UDM
/// recovery lane, never bronze. Returns the `_ocsf_prepare` lane input.
fn tenant_parse(
    tree: &BundleTree,
    tenant_id: &str,
    slug: &str,
    event: vrl::value::Value,
    index: usize,
) -> Result<(String, serde_json::Value, String), String> {
    let name = TenantName::new(slug, false);
    let parse = transform_source(tree, &name.file(), &format!("{}_parse", name.name))?;
    let meta = [("tenant_id", tenant_id), ("source_type", slug)];
    let parsed = run_vrl(&parse, event, &meta).map_err(|e| format!("input {index}: parser: {e}"))?;
    let json = serde_json::to_value(&parsed).map_err(|e| e.to_string())?;
    if json.get("class_uid").is_none()
        || json.get("parse_error").is_some()
        || json.pointer("/metadata/parse_error").is_some()
    {
        return Err(format!("input {index}: parser output misses the OCSF split"));
    }
    Ok((
        transform_source(tree, &name.file(), &format!("{}_ocsf_prepare", name.name))?,
        json,
        slug.to_string(),
    ))
}

/// The rows a cell's Vector hands the bronze sink for `inputs`, through the
/// base's own lane VRL and its own `ocsf_lake_storage_prepare` (shard knobs
/// at their defaults), for tenant `tenant_id`. A tenant input needs the
/// tenant's overlay applied to `tree`; an audit input needs the audit lane.
/// `Err` names the first input a lane or the storage stage refused.
pub fn lake_rows(
    tree: &BundleTree,
    tenant_id: &str,
    inputs: &[LaneInput],
) -> Result<Vec<LakeRow>, String> {
    let storage = storage_prepare_vrl(tree)?;
    let mut rows = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        let (source, event, source_type) = match input {
            LaneInput::Generic { event, source_type } => {
                let mut event = event.clone();
                event["source_type"] = source_type.clone().into();
                (
                    transform_source(tree, PIPELINE_FILE, GENERIC_PREPARE)?,
                    event,
                    source_type.clone(),
                )
            }
            LaneInput::Audit { line } => (
                transform_source(tree, AUDIT_LANE_FILE, AUDIT_PREPARE)?,
                serde_json::json!({"message": line, "source_type": AUDIT_SLUG}),
                AUDIT_SLUG.to_string(),
            ),
            LaneInput::Tenant { slug, event } => {
                let name = TenantName::new(slug, false);
                (
                    transform_source(tree, &name.file(), &format!("{}_ocsf_prepare", name.name))?,
                    event.clone(),
                    slug.clone(),
                )
            }
            LaneInput::TenantDelivery { slug, event } => {
                tenant_parse(tree, tenant_id, slug, vrl::value::Value::from(event.clone()), index)?
            }
            LaneInput::HecEnvelope { slug, envelope } => {
                let log = splunk_hec_log(envelope).map_err(|e| format!("input {index}: {e}"))?;
                let normalized = hec_normalize(tree, tenant_id, slug, log)
                    .map_err(|e| format!("input {index}: hec_normalize: {e}"))?;
                tenant_parse(tree, tenant_id, slug, normalized, index)?
            }
        };
        let meta = [
            ("tenant_id", tenant_id),
            ("source_type", source_type.as_str()),
        ];
        let laned = run_vrl(&source, vrl::value::Value::from(event), &meta)
            .map_err(|e| format!("input {index}: lane: {e}"))?;
        let row = run_vrl(&storage, laned, &meta)
            .map_err(|e| format!("input {index}: storage stage: {e}"))?;
        rows.push(LakeRow::new(row)?);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::super::{archive, overlay, platform_audit_lane};
    use super::*;

    #[test]
    fn splunk_hec_log_matches_vector_bytes_decode() {
        use serde_json::json;
        for payload in [json!({"a": 1, "message": "m"}), json!({"line": "l", "b": 2}), json!({}), json!(3)] {
            let log = splunk_hec_log(&json!({"event": payload, "sourcetype": "s"})).unwrap();
            assert_eq!(serde_json::from_str::<serde_json::Value>(log["message"].as_str().unwrap()).unwrap(), payload);
            assert_eq!(log["splunk_sourcetype"], "s");
            assert!(log.get("a").is_none());
        }
        let text = splunk_hec_log(&json!({"event": "raw text"})).unwrap();
        assert_eq!(text["message"], "raw text");
        for bad in [json!({}), json!({"event": ""}), json!({"event": null})] {
            assert!(splunk_hec_log(&bad).is_err(), "{bad}");
        }
    }

    const BASES: [(&str, &[u8]); 4] = [
        ("v1", include_bytes!("testdata/platform-base.tar.gz")),
        (
            "collector-v2",
            include_bytes!("testdata/platform-base-collector-v2.tar.gz"),
        ),
        ("zero", include_bytes!("testdata/platform-base-zero.tar.gz")),
        (
            "zero-collector-v2",
            include_bytes!("testdata/platform-base-zero-collector-v2.tar.gz"),
        ),
    ];

    /// The contract edits exactly the storage stage's VRL in both sink copies:
    /// every other file, and every other line of those files, is unchanged,
    /// and the stage's wiring (inputs, drop policy) is the base's.
    #[test]
    fn the_contract_extends_only_the_storage_stage() {
        for (name, packed) in BASES {
            let base = archive::unpack(packed).unwrap();
            assert!(!has_bronze_row_contract(&base), "{name}");
            let with = add_bronze_row_contract(&base).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(has_bronze_row_contract(&with), "{name}");
            let changed: Vec<&String> = with
                .files
                .keys()
                .filter(|p| base.files.get(*p) != with.files.get(*p))
                .collect();
            assert_eq!(
                changed,
                ["backup/_ocsf_sink.toml", LAKE_SINK_FILE],
                "{name}"
            );
            for path in BRONZE_SINK_FILES {
                let before: toml::Table = resolve_interpolation(base.text(path).unwrap())
                    .parse()
                    .unwrap();
                let after: toml::Table = resolve_interpolation(with.text(path).unwrap())
                    .parse()
                    .unwrap();
                let source = |t: &toml::Table| {
                    t["transforms"]["ocsf_lake_storage_prepare"]["source"]
                        .as_str()
                        .unwrap()
                        .to_string()
                };
                assert_eq!(
                    source(&after),
                    format!("{}{LAKE_BRONZE_ROW_VRL}", source(&before)),
                    "{name} {path}"
                );
                let strip = |mut t: toml::Table| {
                    t["transforms"]["ocsf_lake_storage_prepare"]
                        .as_table_mut()
                        .unwrap()
                        .remove("source");
                    t
                };
                assert_eq!(
                    strip(before),
                    strip(after),
                    "{name} {path}: only the VRL changes"
                );
            }
            assert!(
                add_bronze_row_contract(&with).is_err(),
                "{name}: already carries it"
            );
            // The contract survives a tenant overlay and the structural guard.
            let (candidate, _) = overlay::apply_overlay(&with, &[]).unwrap();
            overlay::verify_against_base(&with, &candidate)
                .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        }
    }

    /// Every lane's row leaves the storage stage as the same two columns,
    /// whatever its payload.
    #[test]
    fn every_lane_leaves_the_storage_stage_as_two_columns() {
        const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f10";
        for (name, packed) in BASES {
            let base =
                platform_audit_lane::add_platform_audit_lane(&archive::unpack(packed).unwrap())
                    .unwrap();
            let with = add_bronze_row_contract(&base).unwrap();
            let audit = |details: serde_json::Value| {
                let line = serde_json::json!({"class_uid": 6003, "time": 1_790_000_000_000_i64,
                    "metadata": {"tenant_uid": TENANT, "uid": "0b9f3c4e-1d2a-4b5c-8d6e-7f8091a2b3c4",
                        "log_name": "audit", "product": {"name": "nano"}},
                    "unmapped": {"action": "rule_created", "details": details}});
                LaneInput::Audit {
                    line: line.to_string(),
                }
            };
            let inputs = [
                LaneInput::Generic {
                    event: serde_json::json!({"message": "plain"}),
                    source_type: "unknown".into(),
                },
                audit(serde_json::json!({"n": 1})),
                audit(serde_json::json!("free text")),
            ];
            for row in lake_rows(&with, TENANT, &inputs).unwrap_or_else(|e| panic!("{name}: {e}")) {
                let keys: Vec<&String> = row.json.as_object().unwrap().keys().collect();
                assert!(
                    keys == ["_nano_bronze_event", "_nano_bronze_partition", "time"]
                        || keys == ["_nano_bronze_event", "time"],
                    "{name}: {keys:?}"
                );
                assert_eq!(row.timestamp_fields, ["time"], "{name}");
                let event: serde_json::Value =
                    serde_json::from_str(row.json["_nano_bronze_event"].as_str().unwrap()).unwrap();
                assert_eq!(event["metadata"]["tenant_uid"], TENANT, "{name}");
                assert!(
                    event.get("time").is_none() && event.get("_nano_bronze_partition").is_none(),
                    "{name}"
                );
            }
        }
    }
}

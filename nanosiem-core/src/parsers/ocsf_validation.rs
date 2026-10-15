// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline OCSF event validation for the Log Sources parser test path.
//!
//! VRL is compiled and executed first. The resulting JSON event is then checked
//! against a compact contract generated from the official OCSF server's
//! resolved schema. Keeping the contract embedded makes parser onboarding work
//! in self-hosted and air-gapped deployments without an OCSF server sidecar.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::sync::OnceLock;

use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::Value;

const CONTRACT_GZIP: &[u8] = include_bytes!("ocsf-1.9.0-contract.json.gz");
pub const OCSF_VALIDATION_VERSION: &str = "1.9.0";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct OcsfValidationDiagnostic {
    /// Stable machine-readable code aligned with the official validator where
    /// the same check exists.
    pub code: String,
    /// Exact JSON attribute path, including array indexes.
    pub attribute_path: String,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct OcsfValidationResult {
    pub valid: bool,
    pub schema_version: String,
    pub errors: Vec<OcsfValidationDiagnostic>,
    pub warnings: Vec<OcsfValidationDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct Contract {
    version: String,
    classes: BTreeMap<String, SchemaItem>,
    objects: BTreeMap<String, SchemaItem>,
    profiles: Vec<String>,
    types: BTreeMap<String, DataType>,
}

#[derive(Debug, Deserialize)]
struct SchemaItem {
    #[serde(default)]
    uid: Option<i64>,
    attributes: BTreeMap<String, Attribute>,
    #[serde(default)]
    constraints: Constraints,
}

#[derive(Debug, Default, Deserialize)]
struct Constraints {
    #[serde(default)]
    at_least_one: Vec<String>,
    #[serde(default)]
    just_one: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Attribute {
    #[serde(rename = "type")]
    type_name: String,
    #[serde(default)]
    object_type: Option<String>,
    #[serde(default)]
    is_array: bool,
    #[serde(default)]
    requirement: String,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    enum_values: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DataType {
    #[serde(rename = "type")]
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    regex: Option<String>,
    #[serde(default)]
    range: Vec<f64>,
    #[serde(default)]
    max_len: Option<usize>,
    #[serde(default)]
    values: Vec<Value>,
}

struct RuntimeContract {
    contract: Contract,
    class_by_uid: HashMap<i64, String>,
    profiles: HashSet<String>,
    /// OCSF data-type expressions are part of the immutable embedded
    /// contract. Compiling them for every scalar turns admission into a CPU
    /// spin at sustained ingest rates, so compile each expression once with
    /// the rest of the runtime contract.
    regexes: HashMap<String, regex::Regex>,
}

fn runtime_contract() -> Result<&'static RuntimeContract, String> {
    static CONTRACT: OnceLock<Result<RuntimeContract, String>> = OnceLock::new();
    CONTRACT
        .get_or_init(|| {
            let mut decoder = GzDecoder::new(CONTRACT_GZIP);
            let mut json = Vec::new();
            decoder
                .read_to_end(&mut json)
                .map_err(|error| format!("decompressing embedded OCSF contract: {error}"))?;
            let contract: Contract = serde_json::from_slice(&json)
                .map_err(|error| format!("parsing embedded OCSF contract: {error}"))?;
            let class_by_uid = contract
                .classes
                .iter()
                .filter_map(|(name, class)| class.uid.map(|uid| (uid, name.clone())))
                .collect();
            let profiles = contract.profiles.iter().cloned().collect();
            let regexes = contract
                .types
                .iter()
                .filter_map(|(name, data_type)| {
                    data_type
                        .regex
                        .as_deref()
                        .and_then(|pattern| regex::Regex::new(pattern).ok())
                        .map(|regex| (name.clone(), regex))
                })
                .collect();
            Ok(RuntimeContract {
                contract,
                class_by_uid,
                profiles,
                regexes,
            })
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Validate one transformed parser output against Nano's pinned OCSF schema.
pub fn validate_ocsf_event(event: &Value) -> OcsfValidationResult {
    let runtime = match runtime_contract() {
        Ok(runtime) => runtime,
        Err(error) => {
            return OcsfValidationResult {
                valid: false,
                schema_version: "unavailable".to_string(),
                errors: vec![diagnostic("schema_contract_unavailable", "", error)],
                warnings: Vec::new(),
            };
        }
    };

    let mut errors = Vec::new();
    let event = match event.as_object() {
        Some(event) => event,
        None => {
            errors.push(diagnostic(
                "event_wrong_type",
                "",
                "OCSF parser output must be a JSON object",
            ));
            return finish(runtime, errors);
        }
    };

    let profiles = event
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("profiles"))
        .and_then(Value::as_array)
        .map(|profiles| {
            profiles
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();

    for profile in &profiles {
        if !runtime.profiles.contains(profile) {
            errors.push(diagnostic(
                "profile_unknown",
                "metadata.profiles",
                format!("OCSF profile {profile:?} is not defined in schema 1.9.0"),
            ));
        }
    }

    let class_uid = match event.get("class_uid").and_then(Value::as_i64) {
        Some(class_uid) => class_uid,
        None => {
            errors.push(diagnostic(
                "class_uid_missing_or_invalid",
                "class_uid",
                "class_uid must be an integer identifying an OCSF event class",
            ));
            return finish(runtime, errors);
        }
    };
    let Some(class_name) = runtime.class_by_uid.get(&class_uid) else {
        errors.push(diagnostic(
            "class_uid_unknown",
            "class_uid",
            format!("no OCSF 1.9.0 event class has class_uid {class_uid}"),
        ));
        return finish(runtime, errors);
    };
    let class = &runtime.contract.classes[class_name];

    validate_item(runtime, event, class, "", &profiles, &mut errors);
    validate_version(runtime, event, &mut errors);
    validate_type_uid(event, &mut errors);

    finish(runtime, errors)
}

/// A scalar leaf of the pinned OCSF 1.9 schema, addressed by its dotted path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcsfAttributeLeaf {
    /// Primitive OCSF type after resolving derived types (`port_t` →
    /// `integer_t`, `timestamp_t` → `long_t`, `ip_t` → `string_t`, …).
    pub primitive_type: &'static str,
    /// The leaf itself, or any object on the way to it, is an array: the
    /// lake stores the leaf as `Array(...)`.
    pub repeated: bool,
    /// Defined only by the OCSF `datetime` profile (the `*_dt` RFC 3339
    /// string siblings of epoch timestamps such as `time_dt`).
    pub datetime_profile_only: bool,
}

/// Resolve a dotted attribute path (`metadata.event_code`, `action_id`,
/// `actor.process.parent_process.cmd_line`) against the embedded OCSF 1.9
/// contract (NAN-2994).
///
/// The first segment may be an attribute of ANY event class; each further
/// segment must be an attribute of the object the previous one references.
/// Only scalar leaves resolve: an object (`metadata`) or a free-form `json_t`
/// value (`enrichments.data`, whose keys are producer-defined) returns `None`,
/// as does anything that is not an OCSF 1.9 path. The walk is O(depth), so
/// OCSF's recursive objects (`process.parent_process.parent_process…`) need no
/// enumeration bound.
pub fn ocsf_attribute_leaf(path: &str) -> Option<OcsfAttributeLeaf> {
    let runtime = runtime_contract().ok()?;
    let mut segments = path.split('.');
    let first = segments.next().filter(|segment| !segment.is_empty())?;
    let rest: Vec<&str> = segments.collect();
    // Walk per class so two classes that bind one attribute name to different
    // object types can never be conflated.
    runtime.contract.classes.values().find_map(|class| {
        let mut attribute = class.attributes.get(first)?;
        let datetime_only = |attribute: &Attribute| attribute.profiles == ["datetime"];
        let mut repeated = attribute.is_array;
        let mut datetime_profile_only = datetime_only(attribute);
        for segment in &rest {
            if attribute.type_name != "object_t" {
                return None;
            }
            let object = runtime
                .contract
                .objects
                .get(attribute.object_type.as_deref()?)?;
            attribute = object.attributes.get(*segment)?;
            repeated |= attribute.is_array;
            datetime_profile_only |= datetime_only(attribute);
        }
        let primitive = primitive_type(runtime, &attribute.type_name);
        if matches!(primitive, "object_t" | "json_t") {
            return None;
        }
        let primitive_type: &'static str = match primitive {
            "string_t" => "string_t",
            "integer_t" => "integer_t",
            "long_t" => "long_t",
            "float_t" => "float_t",
            "boolean_t" => "boolean_t",
            _ => return None,
        };
        Some(OcsfAttributeLeaf {
            primitive_type,
            repeated,
            datetime_profile_only,
        })
    })
}

fn finish(
    runtime: &RuntimeContract,
    errors: Vec<OcsfValidationDiagnostic>,
) -> OcsfValidationResult {
    OcsfValidationResult {
        valid: errors.is_empty(),
        schema_version: runtime.contract.version.clone(),
        errors,
        warnings: Vec::new(),
    }
}

fn validate_version(
    runtime: &RuntimeContract,
    event: &serde_json::Map<String, Value>,
    errors: &mut Vec<OcsfValidationDiagnostic>,
) {
    let version = event
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("version"))
        .and_then(Value::as_str);
    if let Some(version) = version {
        if version != runtime.contract.version {
            errors.push(diagnostic(
                "version_incompatible",
                "metadata.version",
                format!(
                    "parser emits OCSF {version}, but this Nano release accepts {}",
                    runtime.contract.version
                ),
            ));
        }
    }
}

fn validate_type_uid(
    event: &serde_json::Map<String, Value>,
    errors: &mut Vec<OcsfValidationDiagnostic>,
) {
    let values = (
        event.get("class_uid").and_then(Value::as_i64),
        event.get("activity_id").and_then(Value::as_i64),
        event.get("type_uid").and_then(Value::as_i64),
    );
    if let (Some(class_uid), Some(activity_id), Some(type_uid)) = values {
        let expected = class_uid * 100 + activity_id;
        if type_uid != expected {
            errors.push(diagnostic(
                "type_uid_incorrect",
                "type_uid",
                format!(
                    "type_uid must equal class_uid * 100 + activity_id ({expected}), got {type_uid}"
                ),
            ));
        }
    }
}

fn validate_item(
    runtime: &RuntimeContract,
    value: &serde_json::Map<String, Value>,
    item: &SchemaItem,
    path: &str,
    profiles: &HashSet<String>,
    errors: &mut Vec<OcsfValidationDiagnostic>,
) {
    for (name, attribute) in &item.attributes {
        if !attribute_allowed(attribute, profiles) {
            continue;
        }
        let attribute_path = child_path(path, name);
        match value.get(name) {
            None | Some(Value::Null) if attribute.requirement == "required" => {
                errors.push(diagnostic(
                    "attribute_required_missing",
                    &attribute_path,
                    format!("required OCSF attribute {attribute_path:?} is missing"),
                ));
            }
            None | Some(Value::Null) => {}
            Some(value) => {
                validate_attribute(runtime, value, attribute, &attribute_path, profiles, errors)
            }
        }
    }

    for name in value.keys() {
        match item.attributes.get(name) {
            Some(attribute) if attribute_allowed(attribute, profiles) => {}
            _ => {
                let attribute_path = child_path(path, name);
                errors.push(diagnostic(
                    "attribute_unknown",
                    &attribute_path,
                    format!(
                        "attribute {attribute_path:?} is not defined for this OCSF class/profile"
                    ),
                ));
            }
        }
    }

    validate_constraints(value, item, path, errors);
}

fn attribute_allowed(attribute: &Attribute, profiles: &HashSet<String>) -> bool {
    attribute.profiles.is_empty()
        || attribute
            .profiles
            .iter()
            .any(|profile| profiles.contains(profile))
}

fn validate_constraints(
    value: &serde_json::Map<String, Value>,
    item: &SchemaItem,
    path: &str,
    errors: &mut Vec<OcsfValidationDiagnostic>,
) {
    if !item.constraints.at_least_one.is_empty()
        && !item
            .constraints
            .at_least_one
            .iter()
            .any(|name| value.contains_key(name))
    {
        errors.push(diagnostic(
            "constraint_failed",
            path,
            format!(
                "at least one of [{}] is required",
                item.constraints.at_least_one.join(", ")
            ),
        ));
    }
    if !item.constraints.just_one.is_empty() {
        let count = item
            .constraints
            .just_one
            .iter()
            .filter(|name| value.contains_key(*name))
            .count();
        if count != 1 {
            errors.push(diagnostic(
                "constraint_failed",
                path,
                format!(
                    "exactly one of [{}] is required; found {count}",
                    item.constraints.just_one.join(", ")
                ),
            ));
        }
    }
}

fn validate_attribute(
    runtime: &RuntimeContract,
    value: &Value,
    attribute: &Attribute,
    path: &str,
    profiles: &HashSet<String>,
    errors: &mut Vec<OcsfValidationDiagnostic>,
) {
    if attribute.is_array {
        let Some(values) = value.as_array() else {
            errors.push(wrong_type(path, "array", value));
            return;
        };
        for (index, value) in values.iter().enumerate() {
            validate_scalar(
                runtime,
                value,
                attribute,
                &format!("{path}[{index}]"),
                profiles,
                errors,
            );
        }
    } else {
        validate_scalar(runtime, value, attribute, path, profiles, errors);
    }
}

fn validate_scalar(
    runtime: &RuntimeContract,
    value: &Value,
    attribute: &Attribute,
    path: &str,
    profiles: &HashSet<String>,
    errors: &mut Vec<OcsfValidationDiagnostic>,
) {
    if attribute.type_name == "object_t" {
        let Some(object) = value.as_object() else {
            errors.push(wrong_type(path, "object", value));
            return;
        };
        let Some(object_type) = attribute.object_type.as_deref() else {
            errors.push(diagnostic(
                "schema_contract_invalid",
                path,
                "object attribute has no object_type in embedded contract",
            ));
            return;
        };
        // OCSF's base `object` type is intentionally open-ended. In
        // particular, the top-level `unmapped` attribute uses it so a parser
        // can retain source-native keys that have no canonical mapping.
        if object_type == "object" {
            return;
        }
        let Some(schema_object) = runtime.contract.objects.get(object_type) else {
            errors.push(diagnostic(
                "schema_contract_invalid",
                path,
                format!("embedded contract has no object definition for {object_type:?}"),
            ));
            return;
        };
        validate_item(runtime, object, schema_object, path, profiles, errors);
        return;
    }

    let primitive = primitive_type(runtime, &attribute.type_name);
    let type_matches = match primitive {
        "json_t" => true,
        "boolean_t" => value.is_boolean(),
        "integer_t" | "long_t" | "timestamp_t" => value.as_i64().is_some(),
        "float_t" => value.is_number(),
        _ => value.is_string(),
    };
    if !type_matches {
        errors.push(wrong_type(path, primitive, value));
        return;
    }

    if !attribute.enum_values.is_empty() {
        let normalized = match value {
            Value::String(value) => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            Value::Bool(value) => Some(value.to_string()),
            _ => None,
        };
        if normalized
            .as_ref()
            .is_some_and(|value| !attribute.enum_values.contains(value))
        {
            errors.push(diagnostic(
                "attribute_enum_value_unknown",
                path,
                format!("value {} is not defined by the OCSF enum", value),
            ));
        }
    }

    validate_data_type_constraints(runtime, value, &attribute.type_name, path, errors);
}

fn primitive_type<'a>(runtime: &'a RuntimeContract, type_name: &'a str) -> &'a str {
    let mut current = type_name;
    for _ in 0..8 {
        let Some(parent) = runtime
            .contract
            .types
            .get(current)
            .and_then(|definition| definition.parent.as_deref())
        else {
            break;
        };
        current = parent;
    }
    current
}

fn validate_data_type_constraints(
    runtime: &RuntimeContract,
    value: &Value,
    type_name: &str,
    path: &str,
    errors: &mut Vec<OcsfValidationDiagnostic>,
) {
    let mut current = Some(type_name);
    for _ in 0..8 {
        let Some(name) = current else { break };
        let Some(definition) = runtime.contract.types.get(name) else {
            break;
        };
        if let (Some(regex), Some(value)) = (runtime.regexes.get(name), value.as_str()) {
            if !regex.is_match(value) {
                errors.push(diagnostic(
                    "attribute_regex_failed",
                    path,
                    format!("value does not match OCSF data type {type_name}"),
                ));
            }
        }
        if let (Some(max_len), Some(value)) = (definition.max_len, value.as_str()) {
            if value.chars().count() > max_len {
                errors.push(diagnostic(
                    "attribute_max_len_exceeded",
                    path,
                    format!("value exceeds OCSF maximum length {max_len}"),
                ));
            }
        }
        if definition.range.len() == 2 {
            if let Some(number) = value.as_f64() {
                if number < definition.range[0] || number > definition.range[1] {
                    errors.push(diagnostic(
                        "attribute_range_failed",
                        path,
                        format!(
                            "value must be between {} and {}",
                            definition.range[0], definition.range[1]
                        ),
                    ));
                }
            }
        }
        if !definition.values.is_empty() && !definition.values.contains(value) {
            errors.push(diagnostic(
                "attribute_value_unknown",
                path,
                "value is not permitted by the OCSF data type",
            ));
        }
        current = definition.parent.as_deref();
    }
}

fn wrong_type(path: &str, expected: &str, value: &Value) -> OcsfValidationDiagnostic {
    diagnostic(
        "attribute_wrong_type",
        path,
        format!("expected {expected}, got {}", json_type(value)),
    )
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}.{child}")
    }
}

fn diagnostic(
    code: impl Into<String>,
    attribute_path: impl Into<String>,
    message: impl Into<String>,
) -> OcsfValidationDiagnostic {
    OcsfValidationDiagnostic {
        code: code.into(),
        attribute_path: attribute_path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_http() -> Value {
        serde_json::json!({
            "activity_id": 3,
            "category_uid": 4,
            "class_uid": 4002,
            "type_uid": 400203,
            "severity_id": 1,
            "time": 1786406400000_i64,
            "metadata": {
                "product": {"name": "Nano", "vendor_name": "Nanos"},
                "version": "1.9.0"
            },
            "http_request": {
                "http_method": "GET",
                "url": {"path": "/"}
            }
        })
    }

    #[test]
    fn accepts_valid_ocsf_1_9_event() {
        let result = validate_ocsf_event(&base_http());
        assert!(result.valid, "{:?}", result.errors);
    }

    #[test]
    fn dns_activity_requires_an_endpoint_and_accepts_the_observing_host() {
        let mut event = serde_json::json!({
            "activity_id": 1,
            "category_uid": 4,
            "class_uid": 4003,
            "type_uid": 400301,
            "severity_id": 1,
            "time": 1786406400000_i64,
            "metadata": {
                "product": {"name": "Sysmon", "vendor_name": "Microsoft"},
                "version": "1.9.0"
            },
            "query": {"hostname": "example.com"}
        });

        let missing_endpoint = validate_ocsf_event(&event);
        assert!(missing_endpoint.errors.iter().any(|error| {
            error.code == "constraint_failed"
                && error.message == "at least one of [dst_endpoint, src_endpoint] is required"
        }));

        event["src_endpoint"] = serde_json::json!({"hostname": "host.example"});
        let with_observer = validate_ocsf_event(&event);
        assert!(with_observer.valid, "{:?}", with_observer.errors);
    }

    #[test]
    fn rejects_unknown_field_and_wrong_type_with_paths() {
        let mut event = base_http();
        event["http_response"] = serde_json::json!({"code": "200"});
        event["made_up"] = Value::Bool(true);

        let result = validate_ocsf_event(&event);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|error| {
            error.code == "attribute_wrong_type" && error.attribute_path == "http_response.code"
        }));
        assert!(result.errors.iter().any(|error| {
            error.code == "attribute_unknown" && error.attribute_path == "made_up"
        }));
    }

    #[test]
    fn profile_fields_require_declared_profile() {
        let mut event = base_http();
        event["action_id"] = Value::from(2);

        let without_profile = validate_ocsf_event(&event);
        assert!(without_profile.errors.iter().any(|error| {
            error.code == "attribute_unknown" && error.attribute_path == "action_id"
        }));

        event["metadata"]["profiles"] = serde_json::json!(["security_control"]);
        event["action"] = Value::from("Denied");
        let with_profile = validate_ocsf_event(&event);
        assert!(with_profile.valid, "{:?}", with_profile.errors);
    }

    #[test]
    fn catches_required_nested_attributes_and_type_uid() {
        let mut event = base_http();
        event["type_uid"] = Value::from(400201);
        event["metadata"].as_object_mut().unwrap().remove("product");

        let result = validate_ocsf_event(&event);
        assert!(result.errors.iter().any(|error| {
            error.code == "attribute_required_missing" && error.attribute_path == "metadata.product"
        }));
        assert!(result.errors.iter().any(|error| {
            error.code == "type_uid_incorrect" && error.attribute_path == "type_uid"
        }));
    }

    #[test]
    fn generic_unmapped_object_accepts_source_native_keys() {
        let mut event = base_http();
        event["unmapped"] = serde_json::json!({
            "cache_status": "expired",
            "tls_intercepted": true,
            "vendor": {"nested": [1, "two", false]}
        });

        let result = validate_ocsf_event(&event);
        assert!(result.valid, "{:?}", result.errors);
    }
}

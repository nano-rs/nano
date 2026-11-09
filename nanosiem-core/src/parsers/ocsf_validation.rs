// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline OCSF event validation for the Log Sources parser test path.
//!
//! VRL is compiled and executed first. The resulting JSON event is then checked
//! against a compact contract generated from the official OCSF server's
//! resolved schema. Keeping the contract embedded makes parser onboarding work
//! in self-hosted and air-gapped deployments without an OCSF server sidecar.
//!
//! The contracts are the ones the version-agnostic schema registry
//! ([`crate::schema::ocsf_registry`]) embeds; there is no second copy. An
//! event is checked against the contract of its own `metadata.version` when
//! nano embeds it, else against the newest one (which then reports
//! `version_incompatible`). On ClickHouse the store accepts any JSON, so this
//! is an onboarding gate and an offline tool, not an ingest filter.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::sync::OnceLock;

use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::Value;

/// The newest embedded OCSF version: what a parser should emit, and what a
/// validation receipt is bound to.
pub fn ocsf_validation_version() -> &'static str {
    crate::schema::ocsf_registry::embedded_contracts()
        .last()
        .map(|(version, _)| *version)
        .unwrap_or("unavailable")
}

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

fn load_contract(gz: &[u8]) -> Result<RuntimeContract, String> {
    let mut decoder = GzDecoder::new(gz);
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
}

/// Every embedded contract, oldest first, decoded once.
fn runtime_contracts() -> &'static [(&'static str, Result<RuntimeContract, String>)] {
    static CONTRACTS: OnceLock<Vec<(&'static str, Result<RuntimeContract, String>)>> =
        OnceLock::new();
    CONTRACTS.get_or_init(|| {
        crate::schema::ocsf_registry::embedded_contracts()
            .iter()
            .map(|(version, gz)| (*version, load_contract(gz)))
            .collect()
    })
}

/// The contract for `version` when nano embeds it, else the newest one.
fn runtime_contract_for(version: Option<&str>) -> Result<&'static RuntimeContract, String> {
    let contracts = runtime_contracts();
    let chosen = version
        .and_then(|version| contracts.iter().find(|(label, _)| *label == version))
        .or_else(|| contracts.last())
        .ok_or_else(|| "no OCSF contract is embedded".to_string())?;
    chosen.1.as_ref().map_err(Clone::clone)
}

/// The newest embedded contract.
fn runtime_contract() -> Result<&'static RuntimeContract, String> {
    runtime_contract_for(None)
}

/// Validate one transformed parser output against nano's embedded OCSF schema.
pub fn validate_ocsf_event(event: &Value) -> OcsfValidationResult {
    let declared_version = event
        .get("metadata")
        .and_then(|metadata| metadata.get("version"))
        .and_then(Value::as_str);
    let runtime = match runtime_contract_for(declared_version) {
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
                format!(
                    "OCSF profile {profile:?} is not defined in schema {}",
                    runtime.contract.version
                ),
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
            format!(
                "no OCSF {} event class has class_uid {class_uid}",
                runtime.contract.version
            ),
        ));
        return finish(runtime, errors);
    };
    let class = &runtime.contract.classes[class_name];

    validate_item(runtime, event, class, "", &profiles, &mut errors);
    validate_version(runtime, event, &mut errors);
    validate_type_uid(event, &mut errors);

    finish(runtime, errors)
}

/// Human name of an OCSF event class (`3002` → `"Authentication"`).
pub fn ocsf_class_name(class_uid: i64) -> Option<String> {
    let runtime = runtime_contract().ok()?;
    runtime.class_by_uid.get(&class_uid).map(|name| title_case(name))
}

/// Compact contract card for one event class, rendered from the same
/// embedded contract [`validate_ocsf_event`] checks against (NAN-4885).
///
/// Parser drafts that compiled still failed this validator on every sample
/// because the prompt never said what the chosen class requires. The card
/// lists, in a few lines: the required attributes with their types and
/// enums, the class `at_least_one`/`just_one` constraints, its boolean
/// attributes, its object attributes, the attributes that only exist under
/// a profile (`device` needs `host`), where `user`/`session` live when the
/// class has no top-level slot for them, and the constraints of the objects
/// it references. `None` for an unknown class.
pub fn ocsf_class_grounding(class_uid: i64) -> Option<String> {
    let runtime = runtime_contract().ok()?;
    let name = runtime.class_by_uid.get(&class_uid)?;
    let class = runtime.contract.classes.get(name)?;
    let mut out = String::new();
    let category = class
        .attributes
        .get("category_uid")
        .and_then(|attribute| attribute.enum_values.first())
        .map(|value| format!(", category_uid {value}"))
        .unwrap_or_default();
    out.push_str(&format!(
        "{} (class_uid {class_uid}{category})\n",
        title_case(name)
    ));

    let required: Vec<String> = class
        .attributes
        .iter()
        .filter(|(_, attribute)| attribute.requirement == "required" && attribute.profiles.is_empty())
        .map(|(name, attribute)| describe_attribute(runtime, name, attribute))
        .collect();
    out.push_str(&format!("- required: {}\n", required.join("; ")));
    for line in constraint_lines(&class.constraints) {
        out.push_str(&format!("- {line}\n"));
    }

    let booleans: Vec<&str> = class
        .attributes
        .iter()
        .filter(|(_, attribute)| {
            attribute.profiles.is_empty() && primitive_type(runtime, &attribute.type_name) == "boolean_t"
        })
        .map(|(name, _)| name.as_str())
        .collect();
    if !booleans.is_empty() {
        out.push_str(&format!(
            "- booleans (JSON true/false, never 0/1 or strings): {}\n",
            booleans.join(", ")
        ));
    }

    let objects: Vec<String> = class
        .attributes
        .iter()
        .filter(|(name, attribute)| {
            attribute.type_name == "object_t"
                && attribute.profiles.is_empty()
                && attribute.requirement != "optional"
                && !SECONDARY_OBJECTS.contains(&name.as_str())
                && !matches!(attribute.object_type.as_deref(), Some("object") | None)
        })
        .map(|(name, attribute)| {
            let object = attribute.object_type.as_deref().unwrap_or_default();
            let array = if attribute.is_array { "[]" } else { "" };
            if object == name {
                format!("{name}{array}")
            } else {
                format!("{name}{array}<{object}>")
            }
        })
        .collect();
    if !objects.is_empty() {
        out.push_str(&format!("- objects: {}\n", objects.join(", ")));
    }

    let mut by_profile: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (name, attribute) in &class.attributes {
        if attribute.type_name != "object_t" {
            continue;
        }
        for profile in &attribute.profiles {
            by_profile.entry(profile.as_str()).or_default().push(name.as_str());
        }
    }
    if !by_profile.is_empty() {
        let groups: Vec<String> = by_profile
            .iter()
            .map(|(profile, names)| format!("{profile}: {}", names.join(", ")))
            .collect();
        out.push_str(&format!(
            "- only with that profile in metadata.profiles (else omit): {}\n",
            groups.join("; ")
        ));
    }

    // Where identity lives: Network Activity has no top-level user/session;
    // they belong under actor (itself gated by the host profile there).
    if let Some(actor) = class.attributes.get("actor") {
        let actor_object = actor
            .object_type
            .as_deref()
            .and_then(|object| runtime.contract.objects.get(object));
        let misplaced: Vec<&str> = ["user", "session"]
            .into_iter()
            .filter(|field| {
                !class.attributes.contains_key(*field)
                    && actor_object.is_some_and(|object| object.attributes.contains_key(*field))
            })
            .collect();
        if !misplaced.is_empty() {
            let profile = if actor.profiles.is_empty() {
                String::new()
            } else {
                format!(" (actor needs profile {})", actor.profiles.join("/"))
            };
            out.push_str(&format!(
                "- no top-level {}: use {}{profile}\n",
                misplaced.join("/"),
                misplaced
                    .iter()
                    .map(|field| format!("actor.{field}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    let object_rules = referenced_object_rules(runtime, class);
    if !object_rules.is_empty() {
        out.push_str(&format!("- object rules: {}\n", object_rules.join("; ")));
    }
    Some(out)
}

/// Enrichment-style attributes a parser rarely sets; left off class cards.
const SECONDARY_OBJECTS: [&str; 2] = ["observables", "enrichments"];

fn title_case(snake: &str) -> String {
    snake
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn type_label(runtime: &RuntimeContract, attribute: &Attribute) -> String {
    if attribute.type_name == "object_t" {
        let object = attribute.object_type.as_deref().unwrap_or("object");
        return format!("object<{object}>{}", if attribute.is_array { "[]" } else { "" });
    }
    let label = match (attribute.type_name.as_str(), primitive_type(runtime, &attribute.type_name)) {
        ("timestamp_t", _) => "epoch-ms int",
        (_, "integer_t" | "long_t") => "int",
        (_, "boolean_t") => "bool",
        (_, "float_t") => "float",
        (_, "json_t") => "json",
        _ => "string",
    };
    format!("{label}{}", if attribute.is_array { "[]" } else { "" })
}

fn describe_attribute(runtime: &RuntimeContract, name: &str, attribute: &Attribute) -> String {
    if name == "type_uid" {
        return "type_uid int = class_uid*100+activity_id".to_string();
    }
    let mut text = format!("{name} {}", type_label(runtime, attribute));
    if !attribute.enum_values.is_empty() {
        // Activity choices are required grounding even for classes such as
        // HTTP Activity, whose enum is larger than the compact-card cutoff.
        if name == "activity_id" || attribute.enum_values.len() <= 16 {
            text.push_str(&format!(" {{{}}}", attribute.enum_values.join(",")));
        } else {
            text.push_str(&format!(" (enum of {} values)", attribute.enum_values.len()));
        }
    }
    text
}

fn constraint_lines(constraints: &Constraints) -> Vec<String> {
    let mut lines = Vec::new();
    if !constraints.at_least_one.is_empty() {
        lines.push(format!("at least one of: {}", constraints.at_least_one.join(", ")));
    }
    if !constraints.just_one.is_empty() {
        lines.push(format!("exactly one of: {}", constraints.just_one.join(", ")));
    }
    lines
}

/// One-level rules (required attributes and constraints) of the objects a
/// class references in its required/recommended or profile-gated object
/// attributes, plus the objects those rules require (`metadata` →
/// `product`) and the identity objects under `actor`.
fn referenced_object_rules(runtime: &RuntimeContract, class: &SchemaItem) -> Vec<String> {
    // Profile-gated objects only for the host profile (device, actor): the
    // others (cloud, osint, ai_operation, …) rarely apply to a custom feed.
    let mut queue: Vec<String> = class
        .attributes
        .iter()
        .filter(|(name, attribute)| {
            attribute.type_name == "object_t"
                && attribute.requirement != "optional"
                && !SECONDARY_OBJECTS.contains(&name.as_str())
                && (attribute.profiles.is_empty() || attribute.profiles.iter().any(|p| p == "host"))
        })
        .filter_map(|(_, attribute)| attribute.object_type.clone())
        .collect();
    if let Some(actor) = class.attributes.get("actor").and_then(|a| a.object_type.as_deref()) {
        if let Some(object) = runtime.contract.objects.get(actor) {
            for field in ["user", "session"] {
                if let Some(object_type) = object.attributes.get(field).and_then(|a| a.object_type.clone()) {
                    queue.push(object_type);
                }
            }
        }
    }
    let mut seen = HashSet::new();
    let mut rules = Vec::new();
    while let Some(object_name) = queue.pop() {
        if object_name == "object" || !seen.insert(object_name.clone()) || rules.len() >= 14 {
            continue;
        }
        let Some(object) = runtime.contract.objects.get(&object_name) else {
            continue;
        };
        let mut parts = Vec::new();
        let required: Vec<String> = object
            .attributes
            .iter()
            .filter(|(_, attribute)| attribute.requirement == "required" && attribute.profiles.is_empty())
            .map(|(name, attribute)| {
                if attribute.type_name == "object_t" {
                    if let Some(next) = attribute.object_type.clone() {
                        queue.push(next);
                    }
                }
                describe_attribute(runtime, name, attribute)
            })
            .collect();
        if !required.is_empty() {
            parts.push(format!("requires {}", required.join(", ")));
        }
        parts.extend(constraint_lines(&object.constraints));
        if !parts.is_empty() {
            rules.push(format!("{object_name} {}", parts.join(", ")));
        }
    }
    rules.sort();
    rules
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
                    "parser emits OCSF {version}, but this nano release accepts {}",
                    crate::schema::ocsf_registry::versions().join(", ")
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

/// Object nesting the validator descends before giving up. OCSF objects are
/// recursive (`process.parent_process.parent_process…`) and a parser can build
/// arbitrarily deep output, so recursion must be bounded; real events stay far
/// below this.
const MAX_OBJECT_DEPTH: usize = 32;

fn validate_item(
    runtime: &RuntimeContract,
    value: &serde_json::Map<String, Value>,
    item: &SchemaItem,
    path: &str,
    profiles: &HashSet<String>,
    errors: &mut Vec<OcsfValidationDiagnostic>,
) {
    if path.matches('.').count() >= MAX_OBJECT_DEPTH {
        errors.push(diagnostic(
            "attribute_nesting_too_deep",
            path,
            format!("OCSF objects nest deeper than {MAX_OBJECT_DEPTH} levels"),
        ));
        return;
    }
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
            .any(|name| constraint_attribute_present(value, name))
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
            .filter(|name| constraint_attribute_present(value, name))
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

/// Whether a constraint member is present on `value`, the object the
/// constraint is declared on. OCSF constraint lists may name nested attributes
/// by dotted path (class 5004 Patch State: `at_least_one: [device.os.sp_name,
/// device.os.sp_ver, device.os.version]`), so each segment is walked from
/// `value` (NAN-4392). Present means the key exists at every segment, exactly
/// the `contains_key` rule constraints have always used: a null leaf counts as
/// present, so undotted names behave as before. An intermediate null or scalar
/// has nothing to descend into and counts as absent; an array on the way counts
/// when any element carries the rest of the path.
fn constraint_attribute_present(value: &serde_json::Map<String, Value>, name: &str) -> bool {
    match name.split_once('.') {
        None => value.contains_key(name),
        Some((first, rest)) => value
            .get(first)
            .is_some_and(|child| nested_attribute_present(child, rest)),
    }
}

fn nested_attribute_present(value: &Value, path: &str) -> bool {
    match value {
        Value::Object(object) => constraint_attribute_present(object, path),
        Value::Array(items) => items
            .iter()
            .any(|item| nested_attribute_present(item, path)),
        _ => false,
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
#[path = "ocsf_validation_tests.rs"]
mod tests;

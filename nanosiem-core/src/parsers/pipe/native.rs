// SPDX-License-Identifier: AGPL-3.0-or-later
//! Validated native Vector stages and source-owned immutable lookup data.
//!
//! ClickHouse-product port (NAN-4919) differences from main:
//! - **Lookup** is a compiler-owned remap carrying the snapshot inline as a
//!   VRL object literal, so it needs no enrichment-table file (nothing to stage,
//!   promote, publish or sync beside the parser TOML) and calls no
//!   `get_enrichment_table_record`. The guard refuses enrichment-table
//!   functions and `enrichment_tables` in every parser document.
//! - **Route first-match** renders as a chain of single-branch `route`s,
//!   each fed by the previous `_unmatched`: the pinned nano Vector image has
//!   no `exclusive_route`.
//! - **Combine** renders main's reduce + fixed Lua gate graph, but the pinned
//!   image ships neither transform, so [`deployable`] refuses it at publish and
//!   deploy until the image carries them ([`RUNTIME_TRANSFORMS_ENV`]).
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use sha2::Digest;
pub mod metadata;

pub const MAX_GROUPS: usize = 64;
pub const MAX_EXPIRE_SEC: u64 = 5;
pub const MAX_DEDUPE_EVENTS: usize = 5000;

pub const KINDS: &[&str] = &["dedupe", "combine", "route", "lookup"];
/// Total bytes of lookup cells one step may embed in its compiled remap.
pub const MAX_LOOKUP_BYTES: usize = 256 * 1024;

/// Transform types the pinned Vector image (`ghcr.io/nano-rs/vector:0.61.0-nano.2`)
/// ships, from `vector list`. The fork is built with a minimal feature set.
pub const PINNED_RUNTIME_TRANSFORMS: &[&str] = &[
    "dedupe",
    "filter",
    "metric_to_log",
    "remap",
    "route",
    "throttle",
    "trace_to_log",
];
/// Comma-separated extra transform types a deployment's Vector image provides
/// (e.g. `reduce,lua` once the fork enables them). Read by nano-api only.
pub const RUNTIME_TRANSFORMS_ENV: &str = "NANO_PIPE_VECTOR_TRANSFORMS";

/// Transform types the deployment's Vector can run.
pub fn runtime_transforms() -> BTreeSet<String> {
    let mut set: BTreeSet<String> = PINNED_RUNTIME_TRANSFORMS.iter().map(|s| s.to_string()).collect();
    if let Ok(extra) = std::env::var(RUNTIME_TRANSFORMS_ENV) {
        set.extend(
            extra
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
        );
    }
    set
}

/// Whether `plan` can be published to a Vector that runs `transforms`. Preview
/// simulates every kind; only publication needs the runtime components.
pub fn deployable_with(plan: &Plan, transforms: &BTreeSet<String>) -> Result<(), String> {
    let combines = plan.steps.iter().any(|s| s.enabled && s.kind == "combine");
    if combines && !(transforms.contains("reduce") && transforms.contains("lua")) {
        return Err("Combine needs Vector's reduce and lua transforms, which this deployment's \
                    Vector image does not include. Preview it here; disable the step to publish."
            .into());
    }
    Ok(())
}

/// [`deployable_with`] against this deployment's runtime.
pub fn deployable(plan: &Plan) -> Result<(), String> {
    deployable_with(plan, &runtime_transforms())
}

#[derive(Clone, Debug)]
pub struct Merge {
    pub field: String,
    pub strategy: String,
}
#[derive(Clone, Debug)]
pub struct Branch {
    pub label: String,
    /// The compiled condition: the author's predicate AND, when the branch
    /// routes by input (NAN-3625), the platform input check.
    pub predicate: String,
    /// Canonical `push:`/`pull:` inputs this branch matches; empty = any.
    pub inputs: Vec<String>,
    pub drop: bool,
}
#[derive(Clone, Debug)]
pub struct Lookup {
    pub table: String,
    pub version: String,
    pub rows: Vec<BTreeMap<String, String>>,
    pub matches: BTreeMap<String, String>,
    pub outputs: BTreeMap<String, String>,
    pub missing_error: bool,
}
#[derive(Clone, Debug)]
pub enum Native {
    Dedupe {
        fields: Vec<String>,
        capacity: usize,
    },
    Combine {
        keys: Vec<String>,
        count: String,
        max: usize,
        timeout: u64,
        merges: Vec<Merge>,
    },
    Route {
        fanout: bool,
        field: String,
        branches: Vec<Branch>,
        fallback_drop: bool,
    },
    Lookup(Lookup),
}

fn paths(step: &Step, key: &str) -> Result<Vec<String>, String> {
    let paths = step
        .config
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be field paths"))?;
    if paths.is_empty() || paths.len() > 16 {
        return Err(format!("{key} requires 1–16 field paths"));
    }
    paths
        .iter()
        .map(|v| {
            let path = v.as_str().ok_or("Field paths must be text")?;
            field(path)?;
            Ok(path.trim().trim_start_matches('.').to_string())
        })
        .collect()
}
fn label(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Use a lookup/branch name of 1–64 letters, digits, '_' or '-'".into());
    }
    Ok(value.to_string())
}
fn mapping(step: &Step, key: &str) -> Result<BTreeMap<String, String>, String> {
    let map = step
        .config
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must map table columns to event fields"))?;
    if map.is_empty() || map.len() > 16 {
        return Err(format!("{key} requires 1–16 mappings"));
    }
    map.iter()
        .map(|(column, path)| {
            if column.is_empty()
                || column.len() > 64
                || !column
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err("Table columns must be 1–64 letters, digits or '_'".into());
            }
            let path = path.as_str().ok_or("Mapped event fields must be text")?;
            field(path)?;
            Ok((column.clone(), path.to_string()))
        })
        .collect()
}

pub fn parse(step: &Step) -> Result<Native, String> {
    execution_condition(step)?;
    let allowed: &[&str] = match step.kind.as_str() {
        "dedupe" => &["fields", "cacheEvents"],
        "combine" => &["keys", "countField", "maxEvents", "timeoutSec", "merge"],
        "route" => &["mode", "field", "routes", "fallback"],
        "lookup" => &["table", "version", "rows", "match", "outputs", "missing"],
        _ => return Err("Not a native Vector step".into()),
    };
    if let Some(key) = step.config.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("Unknown {} setting {key}", step.kind));
    }
    match step.kind.as_str() {
        "dedupe" => Ok(Native::Dedupe {
            fields: paths(step, "fields")?,
            // Accept saved legacy values, but always enforce the effective cap.
            capacity: number(step, "cacheEvents", 1000, 1, 50_000)?.min(MAX_DEDUPE_EVENTS as u64)
                as usize,
        }),
        "combine" => {
            let keys = paths(step, "keys")?;
            let count = text(step, "countField", "unmapped.event_count")?.to_string();
            field(&count)?;
            let mut merges = Vec::new();
            if let Some(value) = step.config.get("merge") {
                let rules = value
                    .as_object()
                    .ok_or("Merge rules must map field paths to strategies")?;
                if rules.len() > 16 {
                    return Err("At most 16 merge rules".into());
                }
                for (path, strategy) in rules {
                    field(path)?;
                    let strategy = strategy.as_str().ok_or("Merge strategies must be text")?;
                    if ![
                        "retain",
                        "sum",
                        "min",
                        "max",
                        "concat",
                        "concat_newline",
                        "array",
                    ]
                    .contains(&strategy)
                    {
                        return Err(format!("Unsupported merge strategy {strategy}"));
                    }
                    if field(path)? == field(&count)? {
                        return Err("Count field cannot also have a merge rule".into());
                    }
                    merges.push(Merge {
                        field: path.clone(),
                        strategy: strategy.into(),
                    });
                }
            }
            Ok(Native::Combine {
                keys,
                count,
                max: number(step, "maxEvents", 100, 1, 1000)? as usize,
                timeout: number(step, "timeoutSec", MAX_EXPIRE_SEC, 1, 60)?.min(MAX_EXPIRE_SEC),
                merges,
            })
        }
        "route" => {
            let mode = text(step, "mode", "first")?;
            if !["first", "fanout"].contains(&mode) {
                return Err("Route mode must be first or fanout".into());
            }
            let field_name = text(step, "field", "unmapped.pipe_route")?.to_string();
            field(&field_name)?;
            let routes = step
                .config
                .get("routes")
                .and_then(Value::as_array)
                .ok_or("Routes must be an ordered array")?;
            if routes.is_empty() || routes.len() > 16 {
                return Err("Use 1–16 route branches".into());
            }
            let mut labels = BTreeSet::new();
            let mut branches = Vec::new();
            for route in routes {
                let row = route.as_object().ok_or("Each route must be an object")?;
                if row
                    .keys()
                    .any(|k| !["label", "predicate", "inputs", "drop"].contains(&k.as_str()))
                {
                    return Err(
                        "Route requires label, a predicate and/or inputs, and optional drop".into(),
                    );
                }
                let branch = label(
                    row.get("label")
                        .and_then(Value::as_str)
                        .ok_or("A branch label is required")?,
                )?;
                if !labels.insert(branch.clone()) {
                    return Err("Route labels must be unique".into());
                }
                // NAN-3625: "Input is" matches the platform input identity.
                let inputs = row
                    .get("inputs")
                    .map(super::input::parse_list)
                    .transpose()?
                    .unwrap_or_default();
                let written = match row.get("predicate") {
                    None if !inputs.is_empty() => None,
                    None => return Err("A branch predicate or input is required".into()),
                    Some(value) => {
                        let text = value.as_str().ok_or("A branch predicate must be text")?;
                        if text.trim().is_empty() && !inputs.is_empty() {
                            None
                        } else {
                            Some(condition(text)?)
                        }
                    }
                };
                let predicate = match (written, inputs.is_empty()) {
                    (Some(written), true) => written,
                    (None, _) => super::input::predicate(&inputs),
                    (Some(written), false) => {
                        format!("{} && ({written})", super::input::predicate(&inputs))
                    }
                };
                let drop = row.get("drop").map_or(Ok(false), |v| {
                    v.as_bool().ok_or("Route drop must be boolean")
                })?;
                branches.push(Branch {
                    label: branch,
                    predicate,
                    inputs,
                    drop,
                });
            }
            let fallback = text(step, "fallback", "keep")?;
            if !["keep", "drop", "output:nano-lake"].contains(&fallback) {
                return Err("Single-output route fallback must be keep or drop".into());
            }
            Ok(Native::Route {
                fanout: mode == "fanout",
                field: field_name,
                branches,
                fallback_drop: fallback == "drop",
            })
        }
        "lookup" => {
            let table = label(text(step, "table", "")?)?;
            let version = text(step, "version", "")?.to_string();
            if version.is_empty() || version.len() > 128 {
                return Err("Lookup version requires 1–128 bytes".into());
            }
            let matches = mapping(step, "match")?;
            let outputs = mapping(step, "outputs")?;
            let rows = step
                .config
                .get("rows")
                .and_then(Value::as_array)
                .ok_or("Lookup rows must be an array")?;
            if rows.is_empty() || rows.len() > 1000 {
                return Err("A lookup snapshot requires 1–1000 rows".into());
            }
            let mut data = Vec::new();
            let mut identities = BTreeSet::new();
            let mut total_bytes = 0usize;
            let columns: BTreeSet<String> = matches.keys().chain(outputs.keys()).cloned().collect();
            for row in rows {
                let row = row
                    .as_object()
                    .ok_or("Lookup rows must be objects with string values")?;
                if row.keys().cloned().collect::<BTreeSet<_>>() != columns {
                    return Err(
                        "Lookup rows must have exactly the mapped match/output columns".into(),
                    );
                }
                let row: BTreeMap<String, String> = row
                    .iter()
                    .map(|(key, value)| {
                        let value = value.as_str().ok_or("Lookup cell values must be strings")?;
                        if value.len() > 4096 {
                            return Err("Lookup cell exceeds 4096 bytes".into());
                        }
                        total_bytes += value.len() + key.len();
                        Ok((key.clone(), value.to_string()))
                    })
                    .collect::<Result<_, String>>()?;
                if total_bytes > MAX_LOOKUP_BYTES {
                    return Err(format!(
                        "A lookup snapshot holds at most {} KiB of cells",
                        MAX_LOOKUP_BYTES / 1024
                    ));
                }
                let identity: Vec<_> = matches.keys().map(|k| row[k].clone()).collect();
                if !identities.insert(identity) {
                    return Err("Lookup match keys must be unique".into());
                }
                data.push(row);
            }
            let missing = text(step, "missing", "leave")?;
            if !["leave", "error"].contains(&missing) {
                return Err("Lookup missing must be leave or error".into());
            }
            Ok(Native::Lookup(Lookup {
                table,
                version,
                rows: data,
                matches,
                outputs,
                missing_error: missing == "error",
            }))
        }
        _ => unreachable!(),
    }
}

impl Lookup {
    /// The compiler-owned lookup remap. The snapshot is a nested VRL object
    /// literal keyed by the match columns in column order; matching uses VRL's
    /// own `to_string` conversion (so `1.0` matches the cell `"1"`), exactly as
    /// the batch preview does. Only allowlisted functions are called.
    pub fn program(&self) -> Result<String, String> {
        let mut tree = serde_json::Map::new();
        for row in &self.rows {
            let mut node = &mut tree;
            let keys: Vec<&String> = self.matches.keys().collect();
            for (depth, column) in keys.iter().enumerate() {
                let cell = row[*column].clone();
                if depth + 1 == keys.len() {
                    let outputs: serde_json::Map<String, Value> = self
                        .outputs
                        .keys()
                        .map(|c| (c.clone(), Value::String(row[c].clone())))
                        .collect();
                    node.insert(cell, Value::Object(outputs));
                } else {
                    node = node
                        .entry(cell)
                        .or_insert_with(|| Value::Object(Default::default()))
                        .as_object_mut()
                        .ok_or("Lookup match keys must be unique")?;
                }
            }
        }
        let path = self
            .matches
            .values()
            .map(|path| Ok(format!("to_string({}) ?? \"\"", field(path)?)))
            .collect::<Result<Vec<_>, String>>()?;
        let mut code = format!(
            "# nano-pipe-lookup-name: {}\nnano_lookup = get({}, [{}]) ?? null\n",
            quote(&self.table),
            vrl_value(&Value::Object(tree)),
            path.join(", ")
        );
        if self.missing_error {
            code.push_str("if !is_object(nano_lookup) { abort }\n");
        }
        code.push_str("if is_object(nano_lookup) {\n");
        for (column, path) in &self.outputs {
            code.push_str(&format!(
                "  {} = get!(nano_lookup, [{}])\n",
                field(path)?,
                quote(column)
            ));
        }
        code.push('}');
        Ok(code)
    }
}

/// Whether `name` is a component the pipeline compiler generates for `prefix`.
pub fn owns_component(prefix: &str, name: &str) -> bool {
    let Some(tail) = name
        .strip_prefix(prefix)
        .and_then(|tail| tail.strip_prefix("_pipe_"))
    else {
        return false;
    };
    let Some((index, suffix)) = tail.split_once('_') else {
        return false;
    };
    if !index.parse::<usize>().is_ok_and(|i| i <= 50) {
        return false;
    }
    [
        "remap", "native", "gate", "prepare", "finish", "fallback", "join", "bypass", "bound",
        "control", "stash", "restore",
    ]
    .contains(&suffix)
        || ["branch_", "route_"].iter().any(|prefix| {
            suffix
                .strip_prefix(prefix)
                .is_some_and(|value| value.parse::<usize>().is_ok_and(|i| i < 16))
        })
}

pub fn guard_transform(kind: &str, body: &toml::Table) -> Result<(), String> {
    if kind == "lua" {
        let inputs: Vec<String> = body
            .get("inputs")
            .and_then(toml::Value::as_array)
            .ok_or("Bounded group gate inputs are missing")?
            .iter()
            .map(|input| {
                input
                    .as_str()
                    .map(str::to_owned)
                    .ok_or("Gate input must be text")
            })
            .collect::<Result<_, _>>()?;
        if !(1..=MAX_EXPIRE_SEC).any(|timeout| body == &bound_transform(timeout, inputs.clone())) {
            return Err("Only the fixed Nano bounded-group gate is permitted".into());
        }
    } else if kind == "dedupe" {
        if body
            .keys()
            .any(|key| !["type", "inputs", "fields", "cache"].contains(&key.as_str()))
        {
            return Err("Unknown native dedupe setting".into());
        }
        let fields = body
            .get("fields")
            .and_then(toml::Value::as_table)
            .ok_or("Dedupe match fields are missing")?;
        if fields.len() != 1
            || fields
                .get("match")
                .and_then(toml::Value::as_array)
                .is_none_or(|values| values != &[toml::Value::String("signature".into())])
        {
            return Err("Dedupe requires bounded explicit match fields".into());
        }
        let cache = body
            .get("cache")
            .and_then(toml::Value::as_table)
            .ok_or("Dedupe cache is missing")?;
        if cache.len() != 1
            || !cache
                .get("num_events")
                .and_then(toml::Value::as_integer)
                .is_some_and(|value| (1..=MAX_DEDUPE_EVENTS as i64).contains(&value))
        {
            return Err("Dedupe cache must be 1–5000 hashed signatures".into());
        }
    } else if kind == "reduce" {
        if body.keys().any(|key| {
            ![
                "type",
                "inputs",
                "group_by",
                "max_events",
                "expire_after_ms",
                "flush_period_ms",
                "merge_strategies",
                "ends_when",
            ]
            .contains(&key.as_str())
        }) {
            return Err("Unknown native reduce setting".into());
        }
        if !body
            .get("max_events")
            .and_then(toml::Value::as_integer)
            .is_some_and(|v| (1..=1000).contains(&v))
            || !body
                .get("expire_after_ms")
                .and_then(toml::Value::as_integer)
                .is_some_and(|v| (1000..=MAX_EXPIRE_SEC as i64 * 1000).contains(&v))
            || body
                .get("flush_period_ms")
                .and_then(toml::Value::as_integer)
                != Some(100)
        {
            return Err("Reduce event/time bounds differ from the managed contract".into());
        }
        let groups = body
            .get("group_by")
            .and_then(toml::Value::as_array)
            .ok_or("Reduce grouping is missing")?;
        if groups != &[toml::Value::String("group_hash".into())]
            || body.get("ends_when").and_then(toml::Value::as_str) != Some(".nano_flush == true")
        {
            return Err("Reduce grouping must be bounded".into());
        }
        let merges = body
            .get("merge_strategies")
            .and_then(toml::Value::as_table)
            .ok_or("Reduce merge strategies are missing")?;
        if merges.len() > 34
            || merges.iter().any(|(key, v)| {
                v.as_str().is_none_or(|v| {
                    if key == "_nano_pipe_metadata" && v == "discard" {
                        return false;
                    }
                    ![
                        "retain",
                        "sum",
                        "min",
                        "max",
                        "concat",
                        "concat_newline",
                        "array",
                    ]
                    .contains(&v)
                })
            })
        {
            return Err("Unsupported reduce merge strategy".into());
        }
    }
    Ok(())
}

pub struct Chain {
    pub transforms: toml::Table,
    pub output: String,
    pub failures: Vec<String>,
}
fn strings(values: &[String]) -> toml::Value {
    toml::Value::Array(values.iter().cloned().map(toml::Value::String).collect())
}
fn transform(kind: &str, inputs: Vec<String>) -> toml::Table {
    let mut value = toml::Table::new();
    value.insert("type".into(), kind.into());
    value.insert("inputs".into(), strings(&inputs));
    value
}
fn remap(code: String, inputs: Vec<String>) -> toml::Table {
    let mut value = transform("remap", inputs);
    value.insert("source".into(), code.into());
    for flag in ["drop_on_abort", "drop_on_error", "reroute_dropped"] {
        value.insert(flag.into(), true.into());
    }
    value
}

/// Hash a bounded signature, retaining missing/null and scalar type distinctions.
pub fn signature(fields: &[String], distinguish_missing: bool) -> Result<String, String> {
    let values = fields.iter().map(|path| {
        let path = field(path)?;
        let kind = type_tag(&path);
        Ok(if distinguish_missing {
            format!("{{ \"present\": exists({path}), \"type\": {kind}, \"value\": {path} }}")
        } else { format!("{{ \"type\": {kind}, \"value\": {path} }}") })
    }).collect::<Result<Vec<_>, String>>()?;
    Ok(format!(
        "sha2(encode_json([{}]), variant: \"SHA-256\")",
        values.join(", ")
    ))
}

fn type_tag(path: &str) -> String {
    let flags = ["timestamp", "integer", "float", "string", "boolean", "array", "object"].iter().map(|kind| format!("is_{kind}({path})")).collect::<Vec<_>>();
    format!("[{}]", flags.join(", "))
}

pub fn bound_source(timeout: u64) -> String {
    format!(
        "local NANO_PIPE_MAX_GROUPS = {MAX_GROUPS}\nlocal NANO_PIPE_EXPIRE_TICKS = {timeout}\n{}",
        include_str!("bounds.lua")
    )
}
fn bound_transform(timeout: u64, inputs: Vec<String>) -> toml::Table {
    let mut body = transform("lua", inputs);
    body.insert("version".into(), "2".into());
    body.insert("source".into(), bound_source(timeout).into());
    let mut hooks = toml::Table::new();
    for (name, handler) in [
        ("init", "nano_pipe_init"),
        ("process", "nano_pipe_process"),
        ("shutdown", "nano_pipe_shutdown"),
    ] {
        hooks.insert(name.into(), handler.into());
    }
    body.insert("hooks".into(), hooks.into());
    let mut timer = toml::Table::new();
    timer.insert("handler".into(), "nano_pipe_expire".into());
    timer.insert("interval_seconds".into(), 1.into());
    body.insert("timers".into(), toml::Value::Array(vec![timer.into()]));
    body
}

/// Native stages own their generated ids, inputs and table files. User config
/// never supplies TOML, component identifiers, filesystem paths or egress.
pub fn render(plan: &Plan, prefix: &str, input: &str) -> Result<Chain, String> {
    plan.validate()?;
    let mut chain = Chain {
        transforms: toml::Table::new(),
        output: input.into(),
        failures: vec![],
    };
    let mut group = Vec::new();
    let flush = |group: &mut Vec<Step>, chain: &mut Chain, index: usize| -> Result<(), String> {
        if group.is_empty() {
            return Ok(());
        }
        let name = format!("{prefix}_pipe_{index}_remap");
        let segment = Plan {
            version: 2,
            revision: plan.revision,
            steps: std::mem::take(group),
        };
        chain.transforms.insert(
            name.clone(),
            remap(segment.program()?, vec![chain.output.clone()]).into(),
        );
        chain.failures.push(format!("{name}.dropped"));
        chain.output = name;
        Ok(())
    };
    for (index, step) in plan.steps.iter().enumerate() {
        if !step.enabled {
            continue;
        }
        if !KINDS.contains(&step.kind.as_str()) {
            group.push(step.clone());
            continue;
        }
        flush(&mut group, &mut chain, index)?;
        let spec = parse(step)?;
        let name = format!("{prefix}_pipe_{index}_native");
        let mut input = chain.output.clone();
        let mut bypass = None;
        if let Some(gate) = execution_condition(step)? {
            let gate_id = format!("{prefix}_pipe_{index}_gate");
            let mut body = transform("route", vec![input]);
            let mut routes = toml::Table::new();
            routes.insert("apply".into(), gate.into());
            body.insert("route".into(), routes.into());
            chain.transforms.insert(gate_id.clone(), body.into());
            input = format!("{gate_id}.apply");
            bypass = Some(format!("{gate_id}._unmatched"));
        }
        let output = match spec {
            Native::Dedupe { fields, capacity } => {
                let prepare = format!("{prefix}_pipe_{index}_prepare");
                chain.transforms.insert(prepare.clone(), remap(format!("nano_signature = {}\n. = {{ \"context\": [.], \"signature\": nano_signature }}", signature(&fields, true)?), vec![input]).into());
                chain.failures.push(format!("{prepare}.dropped"));
                let mut body = transform("dedupe", vec![prepare]);
                let mut matched = toml::Table::new();
                matched.insert("match".into(), strings(&["signature".into()]));
                body.insert("fields".into(), matched.into());
                let mut cache = toml::Table::new();
                cache.insert("num_events".into(), (capacity as i64).into());
                body.insert("cache".into(), cache.into());
                chain.transforms.insert(name.clone(), body.into());
                let finish = format!("{prefix}_pipe_{index}_finish");
                chain.transforms.insert(
                    finish.clone(),
                    remap(". = object!(.context[0])".into(), vec![name]).into(),
                );
                chain.failures.push(format!("{finish}.dropped"));
                finish
            }
            Native::Combine {
                keys,
                count,
                max,
                timeout,
                merges,
            } => {
                let prepare = format!("{prefix}_pipe_{index}_prepare");
                let pairs: [String; 3] = [
                    "\"context\": [.]".into(),
                    "\"count\": 1".into(),
                    format!("\"group_hash\": {}", signature(&keys, false)?),
                ];
                let mut checks =
                    String::from("del(._nano_pipe_metadata)\ndel(._nano_pipe_scope)\n");
                for (i, merge) in merges.iter().enumerate() {
                    let value = format!("nano_value_{i}");
                    checks.push_str(&format!("{value} = {}\n", field(&merge.field)?));
                    let valid = match merge.strategy.as_str() {
                        "sum" | "min" | "max" => {
                            format!("is_integer({value}) || is_float({value})")
                        }
                        "concat" | "concat_newline" => format!("is_string({value})"),
                        _ => "true".into(),
                    };
                    if valid != "true" {
                        checks.push_str(&format!("if {value} != null && !({valid}) {{ abort }}\n"));
                    }
                }
                checks.push_str(&format!(". = {{ {} }}\n", pairs.join(", ")));
                // Scope group keys by the authored pipeline step, so two
                // combines never share a group.
                let scope = hex::encode(sha2::Sha256::digest(
                    serde_json::to_vec(&(prefix, index, plan)).map_err(|e| e.to_string())?,
                ));
                checks.push_str(&format!("._nano_pipe_scope = {}\n", quote(&scope)));
                for (i, merge) in merges.iter().enumerate() {
                    if merge.strategy == "array" {
                        checks.push_str(&format!(".value_{i} = nano_value_{i}\n"));
                    } else {
                        checks.push_str(&format!(
                            "if nano_value_{i} != null {{ .value_{i} = nano_value_{i} }}\n"
                        ));
                    }
                }
                chain
                    .transforms
                    .insert(prepare.clone(), remap(checks, vec![input]).into());
                chain.failures.push(format!("{prepare}.dropped"));
                let stash = format!("{prefix}_pipe_{index}_stash");
                chain.transforms.insert(
                    stash.clone(),
                    metadata::stash_transform(vec![prepare]).into(),
                );
                chain.failures.push(format!("{stash}.dropped"));
                // Events go straight to reduce, which keeps their finalizers and
                // value types. Only a {group_hash} copy passes through the Lua gate,
                // whose sole output is end-group markers: Vector's Lua conversion
                // drops event metadata and turns null into "" and [] into {}.
                let control = format!("{prefix}_pipe_{index}_control");
                chain.transforms.insert(
                    control.clone(),
                    remap(
                        ". = { \"group_hash\": .group_hash }".into(),
                        vec![stash.clone()],
                    )
                    .into(),
                );
                chain.failures.push(format!("{control}.dropped"));
                let bounded = format!("{prefix}_pipe_{index}_bound");
                chain.transforms.insert(
                    bounded.clone(),
                    bound_transform(timeout, vec![control]).into(),
                );
                let mut body = transform("reduce", vec![stash, bounded]);
                body.insert("ends_when".into(), ".nano_flush == true".into());
                body.insert("group_by".into(), strings(&["group_hash".into()]));
                body.insert("max_events".into(), (max as i64).into());
                body.insert("expire_after_ms".into(), ((timeout * 1000) as i64).into());
                body.insert("flush_period_ms".into(), 100.into());
                let mut strategies = toml::Table::new();
                strategies.insert("context".into(), "retain".into());
                strategies.insert("count".into(), "sum".into());
                strategies.insert("group_hash".into(), "retain".into());
                strategies.insert("_nano_pipe_metadata".into(), "discard".into());
                for (i, merge) in merges.iter().enumerate() {
                    strategies.insert(format!("value_{i}"), merge.strategy.clone().into());
                }
                body.insert("merge_strategies".into(), strategies.into());
                chain.transforms.insert(name.clone(), body.into());
                let restore = format!("{prefix}_pipe_{index}_restore");
                chain.transforms.insert(
                    restore.clone(),
                    metadata::restore_transform(vec![name]).into(),
                );
                chain.failures.push(format!("{restore}.dropped"));
                let finish = format!("{prefix}_pipe_{index}_finish");
                let mut code = String::from(
                    "nano_reduced = .\nif exists(nano_reduced.context) {\n. = object!(nano_reduced.context[0])\n",
                );
                code.push_str(&format!("{} = nano_reduced.count\n", field(&count)?));
                for (i, merge) in merges.iter().enumerate() {
                    code.push_str(&format!(
                        "if exists(nano_reduced.value_{i}) {{ {} = nano_reduced.value_{i} }}\n",
                        field(&merge.field)?
                    ));
                }
                code.push_str("} else { . = [] }\n");
                chain
                    .transforms
                    .insert(finish.clone(), remap(code, vec![restore]).into());
                chain.failures.push(format!("{finish}.dropped"));
                finish
            }
            Native::Lookup(lookup) => {
                chain.transforms.insert(
                    name.clone(),
                    remap(lookup.program()?, vec![input]).into(),
                );
                chain.failures.push(format!("{name}.dropped"));
                name
            }
            Native::Route {
                fanout,
                field: tag,
                branches,
                fallback_drop,
            } => {
                // Each branch's events come from `(route, output port)`.
                let mut branch_inputs = Vec::new();
                let unmatched = if fanout {
                    let mut body = transform("route", vec![input]);
                    let mut routes = toml::Table::new();
                    for (i, branch) in branches.iter().enumerate() {
                        routes.insert(format!("branch_{i}"), branch.predicate.clone().into());
                        branch_inputs.push(format!("{name}.branch_{i}"));
                    }
                    body.insert("route".into(), routes.into());
                    chain.transforms.insert(name.clone(), body.into());
                    format!("{name}._unmatched")
                } else {
                    // The pinned image has no `exclusive_route`. First-match is
                    // a CHAIN of single-branch routes, each consuming the
                    // previous one's `_unmatched`: a predicate's runtime error is
                    // a non-match there, so the event moves on to the next
                    // branch (negating an erroring predicate would error too
                    // and drop the event — Codex P1, NAN-4919).
                    let mut previous = input;
                    for (i, branch) in branches.iter().enumerate() {
                        let id = format!("{prefix}_pipe_{index}_route_{i}");
                        let mut body = transform("route", vec![previous]);
                        let mut routes = toml::Table::new();
                        routes.insert("branch".into(), branch.predicate.clone().into());
                        body.insert("route".into(), routes.into());
                        chain.transforms.insert(id.clone(), body.into());
                        branch_inputs.push(format!("{id}.branch"));
                        previous = format!("{id}._unmatched");
                    }
                    previous
                };
                let mut inputs = Vec::new();
                for (i, branch) in branches.iter().enumerate() {
                    let id = format!("{prefix}_pipe_{index}_branch_{i}");
                    let source = if branch.drop {
                        ". = []".into()
                    } else {
                        format!("{} = {}", field(&tag)?, quote(&branch.label))
                    };
                    chain.transforms.insert(
                        id.clone(),
                        remap(source, vec![branch_inputs[i].clone()]).into(),
                    );
                    chain.failures.push(format!("{id}.dropped"));
                    inputs.push(id);
                }
                let fallback = format!("{prefix}_pipe_{index}_fallback");
                let source = if fallback_drop {
                    ". = []".into()
                } else {
                    format!("{} = \"unmatched\"", field(&tag)?)
                };
                chain.transforms.insert(
                    fallback.clone(),
                    remap(source, vec![unmatched]).into(),
                );
                chain.failures.push(format!("{fallback}.dropped"));
                inputs.push(fallback);
                let join = format!("{prefix}_pipe_{index}_join");
                chain
                    .transforms
                    .insert(join.clone(), remap(".".into(), inputs).into());
                chain.failures.push(format!("{join}.dropped"));
                join
            }
        };
        chain.output = output;
        if let Some(bypass) = bypass {
            let join = format!("{prefix}_pipe_{index}_bypass");
            chain.transforms.insert(
                join.clone(),
                remap(".".into(), vec![chain.output.clone(), bypass]).into(),
            );
            chain.failures.push(format!("{join}.dropped"));
            chain.output = join;
        }
    }
    flush(&mut group, &mut chain, plan.steps.len())?;
    if chain.output == input {
        let name = format!("{prefix}_pipe_0_remap");
        chain
            .transforms
            .insert(name.clone(), remap(".".into(), vec![input.into()]).into());
        chain.failures.push(format!("{name}.dropped"));
        chain.output = name;
    }
    Ok(chain)
}

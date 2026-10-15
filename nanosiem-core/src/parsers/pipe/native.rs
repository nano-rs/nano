// SPDX-License-Identifier: AGPL-3.0-or-later
//! Validated native Vector stages and tenant-owned immutable lookup data.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use sha2::Digest;
pub mod metadata;

pub const MAX_GROUPS: usize = 64;
pub const MAX_EXPIRE_SEC: u64 = 5;
pub const MAX_DEDUPE_EVENTS: usize = 5000;

pub const KINDS: &[&str] = &["dedupe", "combine", "route", "lookup"];
pub const LOOKUP_ROOT: &str = "${NANO_PIPE_LOOKUP_ROOT:-/etc/vector/sources/parsers}";

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
                        Ok((key.clone(), value.to_string()))
                    })
                    .collect::<Result<_, String>>()?;
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
    pub fn csv(&self) -> Vec<u8> {
        let columns: Vec<&String> = self.rows[0].keys().collect();
        let row = |values: Vec<&str>| {
            values
                .into_iter()
                .map(|v| format!("\"{}\"", v.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(",")
                + "\n"
        };
        let mut csv = row(columns.iter().map(|v| v.as_str()).collect());
        for values in &self.rows {
            csv.push_str(&row(columns.iter().map(|k| values[*k].as_str()).collect()));
        }
        csv.into_bytes()
    }
    pub fn program(&self, table_id: &str) -> Result<String, String> {
        let pairs = self
            .matches
            .iter()
            .map(|(column, path)| {
                Ok(format!(
                    "{}: to_string({}) ?? \"\"",
                    quote(column),
                    field(path)?
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut code=format!("# nano-pipe-lookup-name: {}\nnano_lookup, nano_lookup_error = get_enrichment_table_record({}, {{ {} }}, case_sensitive: true)\n",quote(&self.table),quote(table_id),pairs.join(", "));
        if self.missing_error {
            code.push_str("if nano_lookup_error != null { abort }\n");
        }
        code.push_str("if nano_lookup_error == null {\n");
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

pub fn table_id(prefix: &str, index: usize) -> String {
    format!("{prefix}_pipe_{index}_lookup")
}
pub fn table_file(prefix: &str, index: usize) -> String {
    format!("{}_lookup_{index}.csv", prefix)
}

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
        || suffix
            .strip_prefix("branch_")
            .is_some_and(|value| value.parse::<usize>().is_ok_and(|i| i < 16))
}
fn lookup_index(prefix: &str, name: &str) -> Result<usize, String> {
    name.strip_prefix(&format!("{prefix}_pipe_"))
        .and_then(|s| s.strip_suffix("_lookup"))
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|i| *i < 50)
        .ok_or_else(|| "Lookup table is outside its source namespace".into())
}
pub fn lookup_files(prefix: &str, document: &toml::Table) -> Result<Vec<String>, String> {
    let Some(tables) = document.get("enrichment_tables") else {
        return Ok(vec![]);
    };
    let tables = tables
        .as_table()
        .ok_or("Enrichment tables must be a table")?;
    let mut paths = Vec::new();
    for (name, table) in tables {
        let index = lookup_index(prefix, name)?;
        let table = table
            .as_table()
            .ok_or("Lookup definition must be a table")?;
        if table
            .keys()
            .any(|key| !["type", "file"].contains(&key.as_str()))
            || table.get("type").and_then(toml::Value::as_str) != Some("file")
        {
            return Err("Only source-owned CSV lookup tables are allowed".into());
        }
        let file = table
            .get("file")
            .and_then(toml::Value::as_table)
            .ok_or("Lookup file definition is missing")?;
        if file
            .keys()
            .any(|key| !["path", "encoding"].contains(&key.as_str()))
        {
            return Err("Unknown lookup file setting".into());
        }
        let expected = format!("{LOOKUP_ROOT}/{}", table_file(prefix, index));
        if file.get("path").and_then(toml::Value::as_str) != Some(expected.as_str()) {
            return Err("Lookup path must be the managed source-owned snapshot".into());
        }
        let encoding = file
            .get("encoding")
            .and_then(toml::Value::as_table)
            .ok_or("CSV encoding is missing")?;
        if encoding
            .keys()
            .any(|key| !["type", "include_headers"].contains(&key.as_str()))
            || encoding.get("type").and_then(toml::Value::as_str) != Some("csv")
            || encoding.get("include_headers") != Some(&toml::Value::Boolean(true))
        {
            return Err("Lookup encoding must be CSV with headers".into());
        }
        paths.push(format!("sources/parsers/{}", table_file(prefix, index)));
    }
    Ok(paths)
}
pub fn restore_lookup_paths(prefix: &str, text: &str) -> Result<String, String> {
    let mut doc: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
    let Some(tables) = doc
        .get_mut("enrichment_tables")
        .and_then(toml::Value::as_table_mut)
    else {
        return Ok(text.into());
    };
    for (name, table) in tables {
        let index = lookup_index(prefix, name)?;
        let expected = format!("{LOOKUP_ROOT}/{}", table_file(prefix, index));
        let path = table
            .get_mut("file")
            .and_then(|file| file.get_mut("path"))
            .ok_or("Lookup file path is missing")?;
        if path.as_str() != Some(expected.replace('$', "$$").as_str()) {
            return Err("Lookup path was not generated by the managed compiler".into());
        }
        *path = expected.into();
    }
    lookup_files(prefix, &doc)?;
    toml::to_string(&doc).map_err(|e| e.to_string())
}
pub fn interpolation_scan(prefix: &str, text: &str) -> Result<String, String> {
    let mut doc: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
    lookup_files(prefix, &doc)?;
    if let Some(tables) = doc
        .get_mut("enrichment_tables")
        .and_then(toml::Value::as_table_mut)
    {
        for (_, table) in tables.iter_mut() {
            *table
                .get_mut("file")
                .and_then(|file| file.get_mut("path"))
                .ok_or("Lookup path missing")? = "managed-lookup.csv".into();
        }
    }
    toml::to_string(&doc).map_err(|e| e.to_string())
}
pub fn lookup_calls_owned(prefix: &str, source: &str) -> bool {
    let calls = regex::Regex::new(
        r"(?:get_enrichment_table_record|find_enrichment_table_records)\s*!?\s*\(",
    )
    .expect("static lookup regex");
    let literals=regex::Regex::new(r#"(?:get_enrichment_table_record|find_enrichment_table_records)\s*!?\s*\(\s*"([A-Za-z0-9_]+)"\s*,"#).expect("static lookup literal regex");
    let tables: Vec<_> = literals.captures_iter(source).collect();
    tables.len() == calls.find_iter(source).count()
        && tables.iter().all(|m| lookup_index(prefix, &m[1]).is_ok())
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
    pub tables: toml::Table,
    pub files: BTreeMap<String, Vec<u8>>,
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
        tables: toml::Table::new(),
        files: BTreeMap::new(),
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
                let mut checks = String::from(
                    "del(._nano_pipe_metadata)\ndel(._nano_pipe_keys)\ndel(._nano_pipe_scope)\n",
                );
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
                // Scope keys by the authored pipeline/revision as well as its
                // member identities; a different combine must not share a UID.
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
                strategies.insert("_nano_pipe_keys".into(), "array".into());
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
                let table = table_id(prefix, index);
                let file = table_file(prefix, index);
                let mut definition = toml::Table::new();
                definition.insert("type".into(), "file".into());
                let mut config = toml::Table::new();
                config.insert("path".into(), format!("{LOOKUP_ROOT}/{file}").into());
                let mut encoding = toml::Table::new();
                encoding.insert("type".into(), "csv".into());
                encoding.insert("include_headers".into(), true.into());
                config.insert("encoding".into(), encoding.into());
                definition.insert("file".into(), config.into());
                chain.tables.insert(table.clone(), definition.into());
                chain
                    .files
                    .insert(format!("sources/parsers/{file}"), lookup.csv());
                chain.transforms.insert(
                    name.clone(),
                    remap(lookup.program(&table)?, vec![input]).into(),
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
                let mut body = transform(
                    if fanout { "route" } else { "exclusive_route" },
                    vec![input],
                );
                if fanout {
                    let mut routes = toml::Table::new();
                    for (i, branch) in branches.iter().enumerate() {
                        routes.insert(format!("branch_{i}"), branch.predicate.clone().into());
                    }
                    body.insert("route".into(), routes.into());
                } else {
                    let routes = branches
                        .iter()
                        .enumerate()
                        .map(|(i, branch)| {
                            let mut route = toml::Table::new();
                            route.insert("name".into(), format!("branch_{i}").into());
                            route.insert("condition".into(), branch.predicate.clone().into());
                            toml::Value::Table(route)
                        })
                        .collect();
                    body.insert("routes".into(), toml::Value::Array(routes));
                }
                chain.transforms.insert(name.clone(), body.into());
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
                        remap(source, vec![format!("{name}.branch_{i}")]).into(),
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
                    remap(source, vec![format!("{name}._unmatched")]).into(),
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

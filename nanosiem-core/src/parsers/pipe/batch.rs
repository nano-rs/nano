// SPDX-License-Identifier: AGPL-3.0-or-later
//! Frozen-batch preview. Native state is local to this invocation; production
//! Vector state is instance-local and expires/flushes on its configured clock.
use super::{
    native::{self, Merge, Native},
    *,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use vrl::compiler::{runtime::Runtime, Program, TargetValue, TimeZone};
use vrl::value::{Secrets, Value as VrlValue};

#[derive(Clone)]
struct Frame {
    value: Value,
    origins: Vec<usize>,
    /// Trusted Vector `%` metadata (NAN-3625: the input identity). Tenant
    /// VRL cannot write it, so programs read it but never change it here.
    metadata: Value,
}
#[derive(Clone, Debug)]
pub struct Trace {
    pub id: String,
    pub outputs: Vec<Value>,
    pub error: Option<String>,
    pub bypassed: bool,
}
#[derive(Clone, Debug)]
pub struct ResultRow {
    pub outputs: Vec<Value>,
    pub disposition: String,
    pub error: Option<String>,
    pub traces: Vec<Trace>,
}
struct Vm {
    programs: HashMap<String, Program>,
}
impl Vm {
    fn compile(&mut self, code: &str) -> Result<(), String> {
        if !self.programs.contains_key(code) {
            let compiled = crate::parsers::vrl_guard::compile(
                code,
                &crate::parsers::validator::safe_vrl_functions(),
            )
            .map_err(|e| e.render(code))?;
            self.programs.insert(code.into(), compiled.program);
        }
        Ok(())
    }
    fn run(&mut self, code: &str, input: &Value, metadata: &Value) -> Result<Value, String> {
        self.compile(code)?;
        let mut target = TargetValue {
            value: VrlValue::from(input.clone()),
            metadata: if metadata.is_object() {
                VrlValue::from(metadata.clone())
            } else {
                VrlValue::Object(Default::default())
            },
            secrets: Secrets::new(),
        };
        Runtime::default()
            .resolve(
                &mut target,
                &self.programs[code],
                &TimeZone::parse("UTC").expect("UTC timezone"),
            )
            .map_err(|e| e.to_string())?;
        serde_json::to_value(target.value).map_err(|e| e.to_string())
    }
    fn matches(&mut self, expr: &str, input: &Value, metadata: &Value) -> Result<bool, String> {
        let code = format!("nano_condition = {expr}\n. = {{ \"result\": bool!(nano_condition) }}");
        self.compile(&code)?;
        // Vector treats a condition's runtime failure as a non-match. Compile
        // failures still reject the preview rather than becoming false.
        let Ok(value) = self.run(&code, input, metadata) else {
            return Ok(false);
        };
        value
            .get("result")
            .and_then(Value::as_bool)
            .ok_or_else(|| "Condition must return boolean".into())
    }
}
fn unpack(value: Value) -> Vec<Value> {
    match value {
        Value::Array(values) => values,
        value => vec![value],
    }
}
fn peek<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut value = value;
    for part in path.trim().trim_start_matches('.').split('.') {
        value = value.get(part)?;
    }
    Some(value)
}
fn assign(value: &mut Value, path: &str, new: Value) -> Result<(), String> {
    let parts: Vec<_> = path.trim().trim_start_matches('.').split('.').collect();
    let mut target = value;
    for part in &parts[..parts.len() - 1] {
        if !target.is_object() {
            *target = serde_json::json!({});
        }
        let map = target
            .as_object_mut()
            .ok_or("Output parent must be an object")?;
        target = map
            .entry(part.to_string())
            .or_insert_with(|| serde_json::json!({}));
    }
    if !target.is_object() {
        *target = serde_json::json!({});
    }
    target
        .as_object_mut()
        .ok_or("Output parent must be an object")?
        .insert(parts.last().unwrap().to_string(), new);
    Ok(())
}
fn canonical(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values
                .iter()
                .map(|(key, value)| (key.clone(), canonical(value)))
                .collect();
            serde_json::to_value(sorted).expect("canonical object")
        }
        value => value.clone(),
    }
}
fn key(frame: &Frame, fields: &[String]) -> String {
    let fields: Vec<_> = fields
        .iter()
        .map(|path| match peek(&frame.value, path) {
            None => serde_json::json!({"present":false}),
            Some(value) => serde_json::json!({"present":true,"value":canonical(value)}),
        })
        .collect();
    serde_json::to_string(&fields).expect("key serialization")
}
fn error(rows: &mut [ResultRow], origins: &[usize], message: String) {
    for &index in origins {
        rows[index].error = Some(message.clone());
        rows[index].disposition = "error".into();
    }
}
fn drop(rows: &mut [ResultRow], origins: &[usize], disposition: &str) {
    for &index in origins {
        if rows[index].error.is_none()
            && !(disposition == "filtered" && rows[index].disposition == "sampled_out")
            && !(disposition == "sampled_out" && rows[index].disposition == "filtered")
        {
            rows[index].disposition = disposition.into();
        }
    }
}
fn outputs(frames: &[Frame], rows: &mut [ResultRow]) {
    for row in rows.iter_mut() {
        row.outputs.clear();
    }
    for frame in frames {
        if let Some(&owner) = frame.origins.first() {
            rows[owner].outputs.push(frame.value.clone());
        }
    }
    for row in rows.iter_mut().filter(|row| row.error.is_none()) {
        if row.outputs.len() > 1 {
            row.disposition = "split".into();
        } else if !row.outputs.is_empty()
            && ["filtered", "sampled_out", "split"].contains(&row.disposition.as_str())
        {
            row.disposition = "retained".into();
        } else if row.outputs.is_empty()
            && ["retained", "split"].contains(&row.disposition.as_str())
        {
            row.disposition = "filtered".into();
        }
    }
}

fn aggregate(frames: Vec<Frame>, count: &str, merges: &[Merge]) -> Result<Frame, String> {
    let mut output = frames.last().unwrap().value.clone();
    if let Some(metadata) = output.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata.remove("uid");
    }
    let mut origins = Vec::new();
    for frame in &frames {
        for &origin in &frame.origins {
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
    }
    assign(&mut output, count, Value::from(frames.len()))?;
    for merge in merges {
        let values: Vec<Value> = frames
            .iter()
            .map(|frame| {
                peek(&frame.value, &merge.field)
                    .cloned()
                    .unwrap_or(Value::Null)
            })
            .filter(|value| merge.strategy == "array" || !value.is_null())
            .collect();
        if values.is_empty() {
            continue;
        }
        let merged = match merge.strategy.as_str() {
            "retain" => values.last().unwrap().clone(),
            "array" => Value::Array(values),
            "concat" | "concat_newline" => {
                if values.iter().any(|v| !v.is_string()) {
                    return Err("String merge requires string values".into());
                }
                Value::String(
                    values
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect::<Vec<_>>()
                        .join(if merge.strategy == "concat_newline" {
                            "\n"
                        } else {
                            " "
                        }),
                )
            }
            "sum" | "min" | "max" => {
                if values.iter().any(|v| !v.is_number()) {
                    return Err("Numeric merge requires numeric values".into());
                }
                if values.iter().all(|v| v.as_i64().is_some()) {
                    let mut result = values[0].as_i64().unwrap();
                    for value in &values[1..] {
                        let value = value.as_i64().unwrap();
                        result = match merge.strategy.as_str() {
                            "sum" => result.checked_add(value).ok_or("Numeric sum overflows")?,
                            "min" => result.min(value),
                            _ => result.max(value),
                        };
                    }
                    Value::from(result)
                } else {
                    let mut result = values[0].as_f64().unwrap();
                    for value in &values[1..] {
                        let value = value.as_f64().unwrap();
                        result = match merge.strategy.as_str() {
                            "sum" => result + value,
                            "min" => result.min(value),
                            _ => result.max(value),
                        };
                    }
                    Value::Number(
                        serde_json::Number::from_f64(result)
                            .ok_or("Numeric merge is not finite")?,
                    )
                }
            }
            _ => return Err("Unsupported merge strategy".into()),
        };
        assign(&mut output, &merge.field, merged)?;
    }
    // Vector reduce drops `%` metadata; the combine restore re-sets only the
    // tenant/source/transport envelope, never the input identity.
    Ok(Frame {
        value: output,
        origins,
        metadata: Value::Object(Default::default()),
    })
}

pub fn run(
    plan: &Plan,
    inputs: &[Value],
    extension: Option<&str>,
) -> Result<Vec<ResultRow>, String> {
    run_from(plan, inputs, extension, None)
}

/// NAN-3625: `sources[i]` is the canonical input (`push:<credential id>` /
/// `pull:<source id>`) event `i` arrived on, seeded as the platform's
/// `%nano_credential_id` exactly as ingress stamps it. `None` (or a `None`
/// entry) is an event with no input identity, like a saved release sample.
pub fn run_from(
    plan: &Plan,
    inputs: &[Value],
    extension: Option<&str>,
    sources: Option<&[Option<String>]>,
) -> Result<Vec<ResultRow>, String> {
    plan.validate()?;
    if inputs.is_empty() || inputs.len() > 100 {
        return Err("Batch preview requires 1–100 inputs".into());
    }
    if sources.is_some_and(|sources| sources.len() != inputs.len()) {
        return Err("Preview inputs must name one input per event".into());
    }
    let mut metadata = Vec::with_capacity(inputs.len());
    for index in 0..inputs.len() {
        let mut object = serde_json::Map::new();
        if let Some(source) = sources.and_then(|sources| sources[index].as_deref()) {
            let source = super::input::canonical(source)?;
            object.insert(
                super::input::METADATA.into(),
                Value::String(super::input::stamped(&source).into()),
            );
        }
        metadata.push(Value::Object(object));
    }
    let mut rows: Vec<_> = inputs
        .iter()
        .map(|input| ResultRow {
            outputs: vec![input.clone()],
            disposition: "retained".into(),
            error: None,
            traces: vec![],
        })
        .collect();
    let mut frames: Vec<_> = inputs
        .iter()
        .enumerate()
        .map(|(i, input)| Frame {
            value: input.clone(),
            origins: vec![i],
            metadata: metadata[i].clone(),
        })
        .collect();
    let mut vm = Vm {
        programs: HashMap::new(),
    };
    let mut group_inputs = frames.clone();
    let mut group = Vec::new();
    let mut trace_bytes = 0;
    for step in &plan.steps {
        let mut applied = vec![false; inputs.len()];
        if step.enabled && !native::KINDS.contains(&step.kind.as_str()) {
            group.push(step.clone());
            let prefix = Plan {
                version: 2,
                revision: plan.revision,
                steps: group.clone(),
            };
            let code = prefix.program()?;
            let mut next = Vec::new();
            for frame in &group_inputs {
                for &origin in &frame.origins {
                    applied[origin] = true;
                }
                match vm.run(&code, &frame.value, &frame.metadata) {
                    Err(message) => error(&mut rows, &frame.origins, message),
                    Ok(value) => {
                        let values = unpack(value);
                        if values.is_empty() {
                            drop(
                                &mut rows,
                                &frame.origins,
                                if step.kind == "sample" {
                                    "sampled_out"
                                } else {
                                    "filtered"
                                },
                            );
                        }
                        if values.len() > 1 {
                            drop(&mut rows, &frame.origins, "split");
                        }
                        for value in values {
                            next.push(Frame {
                                value,
                                origins: frame.origins.clone(),
                                metadata: frame.metadata.clone(),
                            });
                        }
                    }
                }
            }
            frames = next;
        } else if step.enabled {
            group.clear();
            let spec = native::parse(step)?;
            let mut eligible = Vec::new();
            let mut next = Vec::new();
            for frame in std::mem::take(&mut frames) {
                let matches = step
                    .condition
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| vm.matches(s, &frame.value, &frame.metadata))
                    .unwrap_or(Ok(true));
                match matches {
                    Ok(true) => {
                        for &i in &frame.origins {
                            applied[i] = true;
                        }
                        eligible.push(frame);
                    }
                    Ok(false) => next.push(frame),
                    Err(message) => error(&mut rows, &frame.origins, message),
                }
            }
            match spec {
                Native::Dedupe { fields, capacity } => {
                    let mut cache = VecDeque::new();
                    for frame in eligible {
                        let identity = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                            key(&frame, &fields).as_bytes(),
                        ));
                        if let Some(position) = cache.iter().position(|entry| entry == &identity) {
                            cache.remove(position);
                            cache.push_back(identity);
                            drop(&mut rows, &frame.origins, "filtered");
                        } else {
                            cache.push_back(identity);
                            if cache.len() > capacity {
                                cache.pop_front();
                            }
                            next.push(frame);
                        }
                    }
                }
                Native::Route {
                    fanout,
                    field,
                    branches,
                    fallback_drop,
                } => {
                    for frame in eligible {
                        let mut matched = false;
                        let mut retained = 0;
                        for branch in &branches {
                            match vm.matches(&branch.predicate, &frame.value, &frame.metadata) {
                                Ok(true) => {
                                    matched = true;
                                    if !branch.drop {
                                        let mut branch_frame = frame.clone();
                                        assign(
                                            &mut branch_frame.value,
                                            &field,
                                            Value::String(branch.label.clone()),
                                        )?;
                                        next.push(branch_frame);
                                        retained += 1;
                                    }
                                    if !fanout {
                                        break;
                                    }
                                }
                                Ok(false) => {}
                                Err(message) => {
                                    error(&mut rows, &frame.origins, message);
                                    break;
                                }
                            }
                        }
                        if !matched && !fallback_drop {
                            let mut frame = frame.clone();
                            assign(&mut frame.value, &field, Value::String("unmatched".into()))?;
                            next.push(frame);
                            retained += 1;
                        }
                        if retained == 0 {
                            drop(&mut rows, &frame.origins, "filtered");
                        } else if retained > 1 {
                            drop(&mut rows, &frame.origins, "split");
                        }
                    }
                }
                Native::Lookup(lookup) => {
                    // Use VRL's conversion rather than JSON formatting (for
                    // example, a floating 1.0 becomes "1" in to_string).
                    let match_code = format!(
                        ". = {{ {} }}",
                        lookup
                            .matches
                            .iter()
                            .map(|(column, path)| {
                                Ok(format!(
                                    "{}: to_string({}) ?? \"\"",
                                    quote(column),
                                    field(path)?
                                ))
                            })
                            .collect::<Result<Vec<_>, String>>()?
                            .join(", ")
                    );
                    for mut frame in eligible {
                        let values = vm.run(&match_code, &frame.value, &frame.metadata)?;
                        let matched = lookup.rows.iter().find(|row| {
                            lookup
                                .matches
                                .keys()
                                .all(|column| values[column].as_str() == Some(row[column].as_str()))
                        });
                        if let Some(row) = matched {
                            for (column, path) in &lookup.outputs {
                                assign(&mut frame.value, path, Value::String(row[column].clone()))?;
                            }
                            next.push(frame);
                        } else if lookup.missing_error {
                            error(&mut rows, &frame.origins, "Lookup record not found".into());
                        } else {
                            next.push(frame);
                        }
                    }
                }
                Native::Combine {
                    keys,
                    count,
                    max,
                    merges,
                    ..
                } => {
                    let mut groups: Vec<Vec<Frame>> = Vec::new();
                    let mut ids = HashMap::new();
                    let mut order = VecDeque::new();
                    for frame in eligible {
                        if merges.iter().any(|merge| {
                            let value = peek(&frame.value, &merge.field).unwrap_or(&Value::Null);
                            !value.is_null()
                                && match merge.strategy.as_str() {
                                    "sum" | "min" | "max" => !value.is_number(),
                                    "concat" | "concat_newline" => !value.is_string(),
                                    _ => false,
                                }
                        }) {
                            error(
                                &mut rows,
                                &frame.origins,
                                "Merge field has the wrong value type".into(),
                            );
                            continue;
                        }
                        // The prepare remap writes missing group keys as null.
                        let identity = serde_json::to_string(
                            &keys
                                .iter()
                                .map(|path| {
                                    canonical(peek(&frame.value, path).unwrap_or(&Value::Null))
                                })
                                .collect::<Vec<_>>(),
                        )
                        .expect("group key");
                        let index = if let Some(&index) = ids.get(&identity) {
                            index
                        } else {
                            let index = if ids.len() >= native::MAX_GROUPS {
                                let oldest = order.pop_front().expect("bounded group order");
                                let index = ids.remove(&oldest).expect("tracked oldest group");
                                let members: Vec<Frame> = std::mem::take(&mut groups[index]);
                                if !members.is_empty() {
                                    let origins: Vec<_> = members
                                        .iter()
                                        .flat_map(|frame| frame.origins.clone())
                                        .collect();
                                    match aggregate(members, &count, &merges) {
                                        Ok(frame) => {
                                            drop(&mut rows, &origins, "combined");
                                            next.push(frame);
                                        }
                                        Err(message) => error(&mut rows, &origins, message),
                                    }
                                }
                                index
                            } else {
                                groups.push(vec![]);
                                groups.len() - 1
                            };
                            order.push_back(identity.clone());
                            ids.insert(identity, index);
                            index
                        };
                        groups[index].push(frame);
                        if groups[index].len() >= max {
                            let members = std::mem::take(&mut groups[index]);
                            let origins: Vec<_> =
                                members.iter().flat_map(|f| f.origins.clone()).collect();
                            match aggregate(members, &count, &merges) {
                                Ok(frame) => {
                                    drop(&mut rows, &origins, "combined");
                                    next.push(frame);
                                }
                                Err(message) => error(&mut rows, &origins, message),
                            }
                        }
                    }
                    // Finite previews flush partial groups at EOF. This is not
                    // a claim about production wall-clock timeout behavior.
                    for members in groups.into_iter().filter(|g| !g.is_empty()) {
                        let origins: Vec<_> =
                            members.iter().flat_map(|f| f.origins.clone()).collect();
                        match aggregate(members, &count, &merges) {
                            Ok(frame) => {
                                drop(&mut rows, &origins, "combined");
                                next.push(frame);
                            }
                            Err(message) => error(&mut rows, &origins, message),
                        }
                    }
                }
            }
            frames = next;
            group_inputs = frames.clone();
        }
        if frames.len() > MAX_OUTPUTS {
            return Err("Preview expansion exceeds 1000 output events".into());
        }
        outputs(&frames, &mut rows);
        for (index, row) in rows.iter_mut().enumerate() {
            row.traces.push(Trace {
                id: step.id.clone(),
                outputs: row.outputs.clone(),
                error: row.error.clone(),
                bypassed: !step.enabled || !applied[index],
            });
        }
        trace_bytes += serde_json::to_vec(&rows.iter().map(|row| &row.outputs).collect::<Vec<_>>())
            .map_err(|e| e.to_string())?
            .len()
            + rows.len() * 256;
        if trace_bytes > 10 * 1024 * 1024 {
            return Err("Preview traces exceed 10 MiB; reduce the sample size".into());
        }
    }
    if let Some(extension) = extension.filter(|s| !s.trim().is_empty()) {
        let code = runtime_program(extension)?;
        let mut next = Vec::new();
        for frame in frames {
            match vm.run(&code, &frame.value, &frame.metadata) {
                Ok(value) => {
                    for value in unpack(value) {
                        next.push(Frame {
                            value,
                            origins: frame.origins.clone(),
                            metadata: frame.metadata.clone(),
                        });
                    }
                }
                Err(message) => error(&mut rows, &frame.origins, message),
            }
        }
        if next.len() > MAX_OUTPUTS {
            return Err("Source extension expands beyond 1000 preview outputs".into());
        }
        outputs(&next, &mut rows);
        if trace_bytes
            + serde_json::to_vec(&rows.iter().map(|row| &row.outputs).collect::<Vec<_>>())
                .map_err(|e| e.to_string())?
                .len()
            > 10 * 1024 * 1024
        {
            return Err("Source extension preview exceeds 10 MiB".into());
        }
        for row in &mut rows {
            row.traces.push(Trace {
                id: "existing-source-extension".into(),
                outputs: row.outputs.clone(),
                error: row.error.clone(),
                bypassed: row.error.is_some(),
            });
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests;

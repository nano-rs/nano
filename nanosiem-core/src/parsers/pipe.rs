// SPDX-License-Identifier: AGPL-3.0-or-later

//! Versioned processing plans stored with a source's existing parser revision.
//! The fixed body is a marker, never user-supplied executable configuration.
//! Publication and preview compile the same validated plan.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const HEADER: &str = "# nano-pipe-v2 ";
// Deliberately invalid raw VRL: an older API/builder must refuse the plan,
// rather than publish a marker as an apparently successful identity parser.
pub const BODY: &str = "# Processing plan compiled by Nano at publication.\nnano_pipe_plan_v2()";
pub const STATELESS_KINDS: &[&str] = &[
    "parse", "rename", "remove", "set", "redact", "fields", "mask", "filter", "sample", "split",
    "vrl",
];
pub const MAX_OUTPUTS: usize = 1000;
pub mod batch;
pub mod input;
pub mod native;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    pub config: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub version: u32,
    pub revision: u64,
    pub steps: Vec<Step>,
}

pub fn stored_plan(source: &str) -> Result<Option<Plan>, String> {
    let Some(rest) = source.strip_prefix(HEADER) else {
        return Ok(None);
    };
    if source.len() > 256 * 1024 {
        return Err("Processing plan exceeds 256 KiB".into());
    }
    let (document, body) = rest
        .split_once('\n')
        .ok_or("Processing plan body is missing")?;
    if body != BODY {
        return Err(
            "Processing plan body was edited; import the actual VRL as an advanced step".into(),
        );
    }
    let plan: Plan =
        serde_json::from_str(document).map_err(|e| format!("Invalid processing plan: {e}"))?;
    plan.validate()?;
    Ok(Some(plan))
}

impl Plan {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 2 || self.revision == 0 || self.steps.len() > 50 {
            return Err(
                "Processing plan requires version 2, a positive revision and at most 50 steps"
                    .into(),
            );
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut combined = false;
        for step in &self.steps {
            if step.id.is_empty()
                || step.id.len() > 128
                || !step
                    .id
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
                || ["__proto__", "constructor", "prototype"].contains(&step.id.as_str())
                || step.name.len() > 255
                || !ids.insert(&step.id)
            {
                return Err("Processing step identifiers must be unique and bounded".into());
            }
            if ![
                "parse", "rename", "remove", "set", "redact", "fields", "mask", "filter", "sample",
                "split", "vrl", "dedupe", "combine", "route", "lookup",
            ]
            .contains(&step.kind.as_str())
            {
                return Err(format!("Unknown processing step {}", step.kind));
            }
            if step.enabled {
                compile_step(step)?;
                // NAN-3625: Vector reduce does not carry `%` metadata, and the
                // combine restore re-sets only the tenant/source/transport
                // envelope, so an aggregate has no input identity.
                if combined && step.kind == "route" {
                    if let native::Native::Route { branches, .. } = native::parse(step)? {
                        if branches.iter().any(|branch| !branch.inputs.is_empty()) {
                            return Err(
                                "Route by input must come before a Combine step; combined events carry no input identity".into(),
                            );
                        }
                    }
                }
                combined |= step.kind == "combine";
            }
        }
        if self.has_native() {
            for segment in self.segments() {
                segment.program()?;
            }
            Ok(())
        } else {
            self.program().map(|_| ())
        }
    }

    pub fn has_native(&self) -> bool {
        self.steps
            .iter()
            .any(|step| step.enabled && native::KINDS.contains(&step.kind.as_str()))
    }

    pub fn segments(&self) -> Vec<Plan> {
        let mut groups = Vec::new();
        let mut steps = Vec::new();
        for step in &self.steps {
            if !step.enabled {
                continue;
            }
            if native::KINDS.contains(&step.kind.as_str()) {
                if !steps.is_empty() {
                    groups.push(Plan {
                        version: 2,
                        revision: self.revision,
                        steps: std::mem::take(&mut steps),
                    });
                }
            } else {
                steps.push(step.clone());
            }
        }
        if !steps.is_empty() {
            groups.push(Plan {
                version: 2,
                revision: self.revision,
                steps,
            });
        }
        groups
    }

    pub fn stored(&self) -> Result<String, String> {
        Ok(format!(
            "{HEADER}{}\n{BODY}",
            serde_json::to_string(self).map_err(|e| e.to_string())?
        ))
    }

    pub fn program(&self) -> Result<String, String> {
        if self.has_native() {
            return Err(
                "Native transform plans require pipeline batch preview, not a single remap".into(),
            );
        }
        let steps: Vec<&Step> = self.steps.iter().filter(|s| s.enabled).collect();
        let program = sequence(&steps, 0)?;
        if program.len() > 256 * 1024 {
            return Err("Compiled processing exceeds 256 KiB".into());
        }
        Ok(program)
    }
}

fn quote(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization")
}
fn indent(code: &str) -> String {
    code.lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn field(value: &str) -> Result<String, String> {
    let value = value.trim().strip_prefix('.').unwrap_or(value.trim());
    let parts: Vec<&str> = value.split('.').collect();
    if value.len() > 256
        || parts.len() > 16
        || parts
            .iter()
            .any(|p| p.is_empty() || p.chars().any(char::is_control))
    {
        return Err("Use a bounded, non-empty field path".into());
    }
    if [
        "tenant_id",
        "nano_tenant_id",
        "source_type",
        "_nano",
        "_nano_internal",
        "_nano_pipe_metadata",
        "_nano_pipe_keys",
        "_nano_pipe_scope",
    ]
    .contains(&parts[0])
        || parts[0] == "metadata"
            && parts
                .get(1)
                .is_some_and(|p| {
                    // NAN-3625: the stored input identity is platform-owned.
                    [
                        "tenant_id",
                        "tenant_uid",
                        "log_source",
                        "nano_credential_id",
                        "nano_input",
                    ]
                    .contains(p)
                })
    {
        return Err("Platform identity fields cannot be changed".into());
    }
    Ok(format!(
        ".{}",
        parts.iter().map(|p| quote(p)).collect::<Vec<_>>().join(".")
    ))
}

pub fn condition(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() > 4096 || value.contains(['\n', '\r', '\0']) {
        return Err("A condition must be one bounded single-line expression".into());
    }
    // NAN-3494: the parser recurses per nesting level too.
    super::vrl_guard::check(value).map_err(|e| e.to_string())?;
    let program = vrl::parser::parse(value)
        .map_err(|_| "A condition must contain a complete VRL expression")?;
    if program.len() != 1 || program[0].start() != 0 || program[0].end() != value.len() {
        return Err("A condition must be one expression, without statements or comments".into());
    }
    let Some(vrl::parser::ast::RootExpr::Expr(expr)) = program
        .into_iter()
        .next()
        .map(vrl::parser::ast::Node::into_inner)
    else {
        return Err("A condition must contain a complete VRL expression".into());
    };
    if !condition_expr(expr.into_inner(), 0) {
        return Err(
            "A condition must be one read-only expression, without assignments or blocks".into(),
        );
    }
    Ok(value.to_string())
}

/// Walks the parsed AST by value: cloning a subtree per level made a deeply
/// nested 4 KiB condition overflow the stack (process abort) before the depth
/// limit could reject it.
fn condition_expr(expr: vrl::parser::ast::Expr, depth: usize) -> bool {
    use vrl::parser::ast::{Container, Expr, FunctionCall, QueryTarget, Unary};
    if depth > 64 {
        return false;
    }
    let check = |expr: vrl::parser::ast::Node<Expr>| condition_expr(expr.into_inner(), depth + 1);
    let container = |value: Container| match value {
        Container::Group(group) => check(group.into_inner().into_inner()),
        Container::Array(array) => array.into_inner().into_iter().all(check),
        // Keep object/block syntax out of conditions, matching the established contract.
        _ => false,
    };
    let call = |call: FunctionCall| {
        call.closure.is_none()
            && call.ident.inner().as_ref() != "del"
            && call
                .arguments
                .into_iter()
                .all(|arg| check(arg.into_inner().expr))
    };
    match expr {
        Expr::Literal(_) | Expr::Variable(_) => true,
        Expr::Container(value) => container(value.into_inner()),
        Expr::FunctionCall(value) => call(value.into_inner()),
        Expr::Op(value) => {
            let op = value.into_inner();
            check(*op.0) && check(*op.2)
        }
        Expr::Unary(value) => match value.into_inner() {
            Unary::Not(expr) => check(*expr.into_inner().take().1),
        },
        Expr::Query(value) => match value.into_inner().target.into_inner() {
            QueryTarget::External(_) | QueryTarget::Internal(_) => true,
            QueryTarget::Container(value) => container(value),
            QueryTarget::FunctionCall(value) => call(value),
        },
        _ => false,
    }
}

fn text<'a>(step: &'a Step, key: &str, fallback: &'a str) -> Result<&'a str, String> {
    step.config.get(key).map_or(Ok(fallback), |v| {
        v.as_str().ok_or_else(|| format!("{key} must be text"))
    })
}
fn number(step: &Step, key: &str, fallback: u64, min: u64, max: u64) -> Result<u64, String> {
    let value = step
        .config
        .get(key)
        .map_or(Some(fallback), Value::as_u64)
        .ok_or_else(|| format!("{key} must be an integer"))?;
    if !(min..=max).contains(&value) {
        return Err(format!("{key} must be {min}–{max}"));
    }
    Ok(value)
}
fn fields(step: &Step, key: &str, allow_empty: bool) -> Result<Vec<String>, String> {
    if allow_empty && !step.config.contains_key(key) {
        return Ok(Vec::new());
    }
    let values = step
        .config
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be field paths"))?;
    if values.len() > 64 || !allow_empty && values.is_empty() {
        return Err(format!("{key} requires 1–64 field paths"));
    }
    values
        .iter()
        .map(|v| field(v.as_str().ok_or("Field paths must be text")?))
        .collect()
}
fn execution_condition(step: &Step) -> Result<Option<String>, String> {
    step.condition
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(condition)
        .transpose()
}

fn field_operation(
    config: &serde_json::Map<String, Value>,
    operation: &str,
) -> Result<String, String> {
    let path = field(
        config
            .get("field")
            .and_then(Value::as_str)
            .ok_or("A field is required")?,
    )?;
    match operation {
        "rename" => Ok(format!(
            "{} = del({path})",
            field(
                config
                    .get("target")
                    .and_then(Value::as_str)
                    .ok_or("A target is required")?
            )?
        )),
        "remove" => Ok(format!("del({path})")),
        "set" => Ok(format!(
            "{path} = {}",
            serde_json::to_string(config.get("value").ok_or("A JSON value is required")?)
                .map_err(|e| e.to_string())?
        )),
        _ => Err("Choose rename, remove or set".into()),
    }
}

fn discard_condition(step: &Step) -> Result<String, String> {
    let matched = match step.kind.as_str() {
        "filter" => {
            let predicate = condition(text(step, "predicate", "true")?)?;
            match text(step, "action", "keep")? {
                "keep" => format!("!({predicate})"),
                "drop" => format!("({predicate})"),
                _ => return Err("Filter action must be keep or drop".into()),
            }
        }
        "sample" => {
            let ratio = number(step, "ratio", 10, 1, 1_000_000)?;
            let key = text(step, "groupBy", "message")?;
            let path = field(if key.trim().is_empty() {
                "message"
            } else {
                key
            })?;
            let hash = format!("parse_int!(slice!(sha2(encode_json({path}), variant: \"SHA-256\"), 0, 7), base: 16)");
            let reject = format!("mod({hash}, {ratio}) != 0");
            let exempt = text(step, "exempt", "")?;
            if exempt.trim().is_empty() {
                reject
            } else {
                format!("!({}) && ({reject})", condition(exempt)?)
            }
        }
        _ => return Err("Not a discard step".into()),
    };
    Ok(if let Some(gate) = execution_condition(step)? {
        format!("({gate}) && ({matched})")
    } else {
        matched
    })
}

pub fn compile_step(step: &Step) -> Result<String, String> {
    if native::KINDS.contains(&step.kind.as_str()) {
        native::parse(step)?;
        return Ok(format!("# Native Vector {} transform", step.kind));
    }
    let allowed: &[&str] = match step.kind.as_str() {
        "parse" => &["format", "field"],
        "rename" => &["field", "target"],
        "remove" => &["field"],
        "set" => &["field", "value"],
        "fields" => &["operation", "field", "target", "value", "operations"],
        "redact" => &["fields", "replacement"],
        "mask" => &[
            "fields",
            "operation",
            "replacement",
            "algorithm",
            "keepStart",
            "keepEnd",
        ],
        "filter" => &["predicate", "action"],
        "sample" => &["ratio", "groupBy", "exempt"],
        "split" => &["field", "as", "keep", "max"],
        "vrl" => &["code", "onError"],
        _ => {
            return Err(format!(
                "{} requires native Vector pipeline support",
                step.kind
            ))
        }
    };
    if let Some(key) = step
        .config
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(format!("Unknown {} setting {key}", step.kind));
    }
    if step.kind == "vrl" && text(step, "onError", "pass")? != "pass" {
        return Err("This runtime preserves parser failures; onError must be pass".into());
    }
    let raw = match step.kind.as_str() {
        "vrl" => {
            let code = text(step, "code", "")?;
            if code.trim().is_empty() {
                return Err("Add VRL code".into());
            }
            code.to_string()
        }
        "parse" => {
            if text(step, "format", "json")? != "json" {
                return Err("Choose JSON parsing".into());
            }
            format!(
                "parsed = object!(parse_json!(string!({})))\n. = merge(., parsed)",
                field(text(step, "field", "message")?)?
            )
        }
        "rename" | "remove" | "set" => field_operation(&step.config, &step.kind)?,
        "fields" => {
            let operation = text(step, "operation", "rename")?;
            if operation == "batch" {
                let operations = step
                    .config
                    .get("operations")
                    .and_then(Value::as_array)
                    .ok_or("Field operations must be an array")?;
                if operations.is_empty() || operations.len() > 64 {
                    return Err("Use 1–64 field operations".into());
                }
                operations
                    .iter()
                    .map(|op| {
                        let op = op
                            .as_object()
                            .ok_or("Each field operation must be an object")?;
                        field_operation(
                            op,
                            op.get("operation")
                                .and_then(Value::as_str)
                                .ok_or("Choose a field operation")?,
                        )
                    })
                    .collect::<Result<Vec<_>, String>>()?
                    .join("\n")
            } else {
                field_operation(&step.config, operation)?
            }
        }
        "mask" | "redact" => {
            let paths = fields(step, "fields", false)?;
            if text(step, "replacement", "[REDACTED]")?.len() > 1024 {
                return Err("Mask replacement exceeds 1024 bytes".into());
            }
            let replacement = quote(text(step, "replacement", "[REDACTED]")?);
            let operation = text(step, "operation", "replace")?;
            paths.iter().map(|path| match operation {
                "replace" => Ok(format!("{path} = {replacement}")),
                "hash" => match text(step, "algorithm", "sha256")? {
                    "sha256" => Ok(format!("{path} = sha2(string!({path}), variant: \"SHA-256\")")),
                    "md5" => Ok(format!("{path} = md5(string!({path}))")),
                    _ => Err("Choose sha256 or md5".into()),
                },
                "partial" => {
                    let start = number(step, "keepStart", 1, 0, 64)?;
                    let end = number(step, "keepEnd", 0, 0, 64)?;
                    let replacement = quote(text(step, "replacement", "*")?);
                    Ok(format!("nano_mask, nano_mask_error = parse_regex(string!({path}), r'(?s)^(?P<head>.{{{start}}})(?P<middle>.*)(?P<tail>.{{{end}}})$')\n{path} = if nano_mask_error == null {{ string!(nano_mask.head) + replace(string!(nano_mask.middle), r'(?s).', {replacement}) + string!(nano_mask.tail) }} else {{ replace(string!({path}), r'(?s).', {replacement}) }}"))
                }
                _ => Err("Choose replace, hash or partial masking".into()),
            }).collect::<Result<Vec<_>, String>>()?.join("\n")
        }
        "filter" | "sample" => {
            return Ok(format!("if {} {{\n  . = []\n}}", discard_condition(step)?))
        }
        "split" => return sequence(&[step], 0),
        _ => {
            return Err(format!(
                "{} requires native Vector pipeline support",
                step.kind
            ))
        }
    };
    Ok(if let Some(gate) = execution_condition(step)? {
        format!("if {gate} {{\n{}\n}}", indent(&raw))
    } else {
        raw
    })
}

fn sequence(steps: &[&Step], depth: usize) -> Result<String, String> {
    let Some((step, rest)) = steps.split_first() else {
        return Ok(".".into());
    };
    if depth > 50 {
        return Err("Too many processing steps".into());
    }
    let tail = sequence(rest, depth + 1)?;
    let code = if step.kind == "split" {
        let path = field(text(step, "field", "items")?)?;
        let output = field(text(step, "as", "item")?)?;
        let max = number(step, "max", 50, 1, MAX_OUTPUTS as u64)?;
        let keep = fields(step, "keep", true)?;
        let gate = execution_condition(step)?.unwrap_or_else(|| "true".into());
        let prefix = format!("nano_pipe_{depth}");
        let context = if keep.is_empty() {
            format!(". = {prefix}_parent")
        } else {
            let mut lines = vec![". = {}".into()];
            lines.extend(
                keep.iter()
                    .map(|field| format!("{field} = {prefix}_parent{field}")),
            );
            lines.join("\n")
        };
        let child = format!("if {prefix}_run {{\n{}\n  {output} = {prefix}_item\n}} else {{\n  . = {prefix}_parent\n}}\n{tail}\n{prefix}_out = if is_array(.) {{ append({prefix}_out, array!(.)) }} else {{ push({prefix}_out, .) }}\nif length({prefix}_out) > {MAX_OUTPUTS} {{ abort }}", indent(&context));
        format!("{prefix}_run = {gate}\n{prefix}_parent = .\n{prefix}_items = if {prefix}_run {{ array!({path}) }} else {{ [null] }}\nif length({prefix}_items) > {max} {{ abort }}\n{prefix}_out = []\nfor_each({prefix}_items) -> |{prefix}_index, {prefix}_item| {{\n{}\n}}\n. = {prefix}_out", indent(&child))
    } else {
        let head = compile_step(step)?;
        if ["filter", "sample"].contains(&step.kind.as_str()) && !rest.is_empty() {
            format!("{head}\nif is_object(.) {{\n{}\n}}", indent(&tail))
        } else if rest.is_empty() {
            head
        } else {
            format!("{head}\n\n{tail}")
        }
    };
    if code.len() > 256 * 1024 {
        return Err("Compiled processing exceeds 256 KiB".into());
    }
    Ok(code)
}

pub fn runtime_program(source: &str) -> Result<String, String> {
    stored_plan(source)?.map_or_else(|| Ok(source.to_string()), |plan| plan.program())
}

/// Offline sample classification for release tests. Uses the same restricted
/// function registry as preview; a runtime error never predicts an intentional
/// drop. This runs inside the bounded parser-bundle build job.
pub fn evaluate(plan: &Plan, input: &Value) -> Result<Value, String> {
    use vrl::compiler::{runtime::Runtime, state::RuntimeState, TargetValue, TimeZone};
    use vrl::value::{Secrets, Value as VrlValue};
    let source = plan.program()?;
    let program = super::vrl_guard::compile(&source, &super::validator::safe_vrl_functions())
        .map_err(|e| e.render(&source))?
        .program;
    let mut target = TargetValue {
        value: VrlValue::from(input.clone()),
        metadata: VrlValue::Object(Default::default()),
        secrets: Secrets::new(),
    };
    Runtime::new(RuntimeState::default())
        .resolve(
            &mut target,
            &program,
            &TimeZone::parse("UTC").expect("UTC timezone"),
        )
        .map_err(|e| e.to_string())?;
    serde_json::to_value(target.value).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests;

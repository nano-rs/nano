// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5180: per-component VRL CPU of the HTTP ingest lane for one parser.
//!
//! ```text
//! cargo run --release -p nanosiem-core --example vector_stage_profile -- \
//!     <repo config/vector dir> <rendered sources dir> <samples.json> \
//!     <X-Source-Type> [iterations] [content-type]
//! ```
//!
//! `<rendered sources dir>` holds a deployed `parsers/` (and, if present,
//! `configs/`) tree; `parser_deploy_profile --emit <dir>` writes one.
//! `<samples.json>` is a JSON array of raw log lines. Each line becomes an event
//! shaped the way `http_ingest` builds it, and the profiler follows it through
//! the rendered Vector topology by walking every transform's `inputs`, the
//! way Vector would:
//!
//! * `remap`: runs the VRL. An array root fans out into one event per element.
//!   An abort or error follows `drop_on_abort` / `drop_on_error` /
//!   `reroute_dropped`, so a rerouted original (annotated under
//!   `.metadata.dropped`, as Vector does) reaches every `<name>.dropped`
//!   consumer (`_output`, then `db_parser_health`).
//! * `route` / `filter`: evaluate the VRL conditions; `_unmatched` gets misses.
//! * Anything else on the path (`dedupe`, `throttle`, `sample`, ...) cannot be
//!   simulated and is REFUSED with its name, never skipped.
//!
//! The report is microseconds of VRL per input event for every component that
//! ran, single-threaded, then the parser's own components that no sample
//! reached. Not measured: the topology itself (per-component hops, the event
//! deep copy a VRL route condition makes per route, sink encoding, disk
//! buffers). Measure those with Vector (cut the pipeline after a stage, feed
//! it, divide CPU time by events).

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value as Json};
use vrl::compiler::runtime::{Runtime, Terminate};
use vrl::compiler::state::RuntimeState;
use vrl::compiler::{compile, Program, TargetValue, TimeZone};
use vrl::value::{Secrets, Value};

/// The source every simulated event starts from.
pub const START: &str = "http_ingest";

enum Kind {
    Remap {
        program: Program,
        drop_on_abort: bool,
        drop_on_error: bool,
        reroute_dropped: bool,
    },
    Route(Vec<(String, Program)>),
    Filter(Program),
    /// A component type the profiler cannot run (it refuses when one is reached).
    Native(String),
}

struct Component {
    kind: Kind,
    time: Duration,
    runs: usize,
}

pub struct Profile {
    components: BTreeMap<String, Component>,
    /// `<component>[.<output>]` -> the transforms that read it.
    consumers: BTreeMap<String, Vec<String>>,
    order: Vec<String>,
    events: usize,
    runtime: Runtime,
}

/// One row of the report.
pub struct Row {
    pub component: String,
    pub us_per_event: f64,
    pub runs: usize,
}

/// `${NAME:-default}` / `${NAME}` interpolated the way Vector does with an
/// empty environment, and `$$` (the escape for a literal `$`) unescaped.
fn interpolate(text: &str) -> String {
    let text = text.replace("$$", "\u{0}");
    let re = regex::Regex::new(r"\$\{[A-Za-z0-9_]+(?::-([^}]*))?\}").unwrap();
    re.replace_all(&text, |c: &regex::Captures| c.get(1).map_or("", |m| m.as_str()).to_string())
        .replace('\u{0}', "$")
}

/// Unauthenticated ingest on: auth is not what is being measured.
fn vrl_source(src: &str) -> String {
    src.replace(
        r#"get_env_var("VECTOR_ALLOW_UNAUTHENTICATED_INGEST") ?? """#,
        r#""true""#,
    )
}

fn program(name: &str, src: &str) -> Result<Program, String> {
    let src = vrl_source(src);
    compile(&src, &vrl::stdlib::all())
        .map(|c| c.program)
        .map_err(|d| format!("{name}: {}", vrl::diagnostic::Formatter::new(&src, d)))
}

fn condition(name: &str, cond: &toml::Value) -> Result<Program, String> {
    match cond {
        toml::Value::String(src) => program(name, src),
        toml::Value::Table(t) if t.get("type").and_then(|v| v.as_str()) == Some("vrl") => {
            program(name, t.get("source").and_then(|v| v.as_str()).unwrap_or(""))
        }
        other => Err(format!("{name}: condition {other} is not VRL; cannot simulate")),
    }
}

impl Profile {
    /// Every `[transforms.*]` of the given Vector TOML documents.
    pub fn load(documents: &[(String, String)]) -> Result<Self, String> {
        let mut components = BTreeMap::new();
        let mut consumers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (file, text) in documents {
            let doc: toml::Table = interpolate(text).parse().map_err(|e| format!("{file}: {e}"))?;
            let Some(transforms) = doc.get("transforms").and_then(|t| t.as_table()) else {
                continue;
            };
            for (name, body) in transforms {
                let flag = |key: &str, default: bool| body.get(key).and_then(|v| v.as_bool()).unwrap_or(default);
                let kind = match body.get("type").and_then(|v| v.as_str()).unwrap_or("") {
                    "remap" => Kind::Remap {
                        program: program(name, body.get("source").and_then(|v| v.as_str()).unwrap_or(""))?,
                        drop_on_abort: flag("drop_on_abort", true),
                        drop_on_error: flag("drop_on_error", false),
                        reroute_dropped: flag("reroute_dropped", false),
                    },
                    "route" => {
                        let mut routes = Vec::new();
                        for (route, cond) in body.get("route").and_then(|r| r.as_table()).into_iter().flatten() {
                            routes.push((route.clone(), condition(&format!("{name}.{route}"), cond)?));
                        }
                        Kind::Route(routes)
                    }
                    "filter" => Kind::Filter(condition(name, body.get("condition").unwrap_or(&toml::Value::Boolean(true)))?),
                    other => Kind::Native(other.to_string()),
                };
                for input in body.get("inputs").and_then(|v| v.as_array()).into_iter().flatten() {
                    if let Some(input) = input.as_str() {
                        consumers.entry(input.to_string()).or_default().push(name.clone());
                    }
                }
                components.insert(name.clone(), Component { kind, time: Duration::ZERO, runs: 0 });
            }
        }
        Ok(Self {
            components,
            consumers,
            order: Vec::new(),
            events: 0,
            runtime: Runtime::new(RuntimeState::default()),
        })
    }

    /// Follow one event from [`START`] through every reachable transform.
    pub fn run(&mut self, event: Json) -> Result<(), String> {
        self.events += 1;
        let mut queue: VecDeque<(String, Value, Value)> = VecDeque::new();
        let start = (Value::from(event), Value::from(json!({})));
        self.emit(&mut queue, START, start);
        while let Some((name, value, metadata)) = queue.pop_front() {
            let component = self.components.get_mut(&name).expect("consumer is a transform");
            if component.runs == 0 && !self.order.contains(&name) {
                self.order.push(name.clone());
            }
            let began = Instant::now();
            let mut out: Vec<(String, (Value, Value))> = Vec::new();
            match &component.kind {
                Kind::Native(kind) => {
                    return Err(format!(
                        "cannot simulate `{name}` (type {kind}): refusing rather than skipping it"
                    ))
                }
                Kind::Filter(cond) => {
                    if truthy(&mut self.runtime, cond, &value, &metadata) {
                        out.push((name.clone(), (value, metadata)));
                    }
                }
                Kind::Route(routes) => {
                    let mut matched = false;
                    for (route, cond) in routes {
                        if truthy(&mut self.runtime, cond, &value, &metadata) {
                            matched = true;
                            out.push((format!("{name}.{route}"), (value.clone(), metadata.clone())));
                        }
                    }
                    if !matched {
                        out.push((format!("{name}._unmatched"), (value, metadata)));
                    }
                }
                Kind::Remap { program, drop_on_abort, drop_on_error, reroute_dropped } => {
                    let mut target = TargetValue { value: value.clone(), metadata: metadata.clone(), secrets: Secrets::new() };
                    let result = self.runtime.resolve(&mut target, program, &TimeZone::Local);
                    self.runtime.clear();
                    let failed = match result {
                        Ok(_) => None,
                        Err(Terminate::Abort(e)) => Some(("abort", e.to_string(), *drop_on_abort)),
                        Err(e) => Some(("error", e.to_string(), *drop_on_error)),
                    };
                    match failed {
                        None => match target.value {
                            Value::Array(items) => {
                                for item in items {
                                    out.push((name.clone(), (item, target.metadata.clone())));
                                }
                            }
                            v => out.push((name.clone(), (v, target.metadata))),
                        },
                        Some((reason, message, dropped)) if dropped => {
                            if *reroute_dropped {
                                let annotated = annotate_dropped(value, reason, &message, &name);
                                out.push((format!("{name}.dropped"), (annotated, metadata)));
                            }
                        }
                        // Not dropped: Vector forwards the event as it arrived.
                        Some(_) => out.push((name.clone(), (value, metadata))),
                    }
                }
            }
            let component = self.components.get_mut(&name).unwrap();
            component.time += began.elapsed();
            component.runs += 1;
            for (port, event) in out {
                self.emit(&mut queue, &port, event);
            }
        }
        Ok(())
    }

    fn emit(&self, queue: &mut VecDeque<(String, Value, Value)>, port: &str, event: (Value, Value)) {
        for consumer in self.consumers.get(port).into_iter().flatten() {
            queue.push_back((consumer.clone(), event.0.clone(), event.1.clone()));
        }
    }

    /// Every component that ran, in first-run order.
    pub fn rows(&self) -> Vec<Row> {
        let events = self.events.max(1) as f64;
        self.order
            .iter()
            .map(|name| {
                let c = &self.components[name];
                Row { component: name.clone(), us_per_event: c.time.as_secs_f64() * 1e6 / events, runs: c.runs }
            })
            .collect()
    }

    /// Components whose name starts with one of `prefixes` that no event reached.
    pub fn not_reached(&self, prefixes: &[&str]) -> Vec<String> {
        self.components
            .iter()
            .filter(|(name, c)| c.runs == 0 && prefixes.iter().any(|p| name.starts_with(p)))
            .map(|(name, _)| name.clone())
            .collect()
    }
}

fn truthy(runtime: &mut Runtime, cond: &Program, value: &Value, metadata: &Value) -> bool {
    let mut target = TargetValue { value: value.clone(), metadata: metadata.clone(), secrets: Secrets::new() };
    let result = runtime.resolve(&mut target, cond, &TimeZone::Local);
    runtime.clear();
    matches!(result, Ok(Value::Boolean(true)))
}

/// Vector's `reroute_dropped` annotation (legacy namespace: `.metadata.dropped`).
fn annotate_dropped(value: Value, reason: &str, message: &str, component: &str) -> Value {
    let mut event: Json = value.try_into().unwrap_or(Json::Null);
    if !event.is_object() {
        event = json!({ "message": event });
    }
    let root = event.as_object_mut().unwrap();
    let metadata = root.entry("metadata").or_insert_with(|| json!({}));
    if !metadata.is_object() {
        *metadata = json!({});
    }
    metadata["dropped"] = json!({
        "reason": reason, "message": message, "component_id": component,
        "component_type": "remap", "component_kind": "transform",
    });
    Value::from(event)
}

/// The event `http_ingest` builds for one newline-framed line.
pub fn http_event(line: &str, source_type: &str, content_type: &str) -> Json {
    json!({
        "message": line, "X-Source-Type": source_type, "Content-Type": content_type,
        "path": "/", "nano_ingest_peer": "192.0.2.1", "source_type": "http_server",
        "timestamp": "2026-01-01T00:00:00Z",
    })
}

fn toml_files(dir: &Path) -> Vec<(String, String)> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map(|d| d.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "toml")).collect())
        .unwrap_or_default();
    files.sort();
    files
        .into_iter()
        .map(|p| (p.display().to_string(), std::fs::read_to_string(&p).expect("read config")))
        .collect()
}

#[allow(dead_code)] // also compiled into the nanosiem-core unit tests
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = Path::new(args.get(1).expect("config/vector dir"));
    let rendered = Path::new(args.get(2).expect("rendered sources dir"));
    let samples: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(args.get(3).expect("samples.json")).expect("read samples"),
    )
    .expect("samples.json is an array of strings");
    let source_type = args.get(4).expect("X-Source-Type");
    let iterations: usize = args.get(5).map_or(200, |s| s.parse().expect("iterations"));
    let content_type = args.get(6).cloned().unwrap_or_else(|| "text/plain".into());

    let mut documents = toml_files(config);
    documents.extend(toml_files(&rendered.join("parsers")));
    documents.extend(toml_files(&rendered.join("configs")));
    let mut profile = Profile::load(&documents).unwrap_or_else(|e| panic!("{e}"));
    for _ in 0..iterations {
        for line in &samples {
            if let Err(e) = profile.run(http_event(line, source_type, &content_type)) {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    }
    let rows = profile.rows();
    let total: f64 = rows.iter().map(|r| r.us_per_event).sum();
    println!("{:<48} {:>10} {:>7} {:>8}", "component", "us/event", "share", "runs");
    for r in &rows {
        println!("{:<48} {:>10.2} {:>6.1}% {:>8}", r.component, r.us_per_event, 100.0 * r.us_per_event / total.max(f64::MIN_POSITIVE), r.runs);
    }
    println!("{:<48} {:>10.2}   (VRL only, per input event)", "total", total);
    let ran: Vec<&str> = rows.iter().map(|r| r.component.as_str()).collect();
    let lanes: Vec<String> = ran
        .iter()
        .filter_map(|c| c.strip_suffix("_parse"))
        .map(|p| format!("{p}_"))
        .collect();
    let mut prefixes: Vec<&str> = lanes.iter().map(String::as_str).collect();
    prefixes.push("db_parser");
    let skipped = profile.not_reached(&prefixes);
    if !skipped.is_empty() {
        println!("\nnot reached by these samples: {}", skipped.join(", "));
    }
}

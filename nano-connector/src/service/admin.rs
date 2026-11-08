// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feed administration: plan a feed from a bundled spec, check its operator
//! input, and resolve the parser lanes it will emit into.
//!
//! The functions never take the spec or the ingest destination from the
//! caller's free input: the spec is a reviewed bundled spec selected by name
//! ([`crate::first_party`]) and pinned on the feed by sha256; the ingest
//! destination is the runner's own configuration. Config must be exactly what
//! the spec reads.

use std::collections::{BTreeSet, HashMap};

use serde_json::{Map, Value};

use crate::spec::{ConnectorSpec, Discover, Kind};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdminError {
    #[error("connector `{0}` is not a bundled spec")]
    CatalogNotFound(String),
    #[error("connector spec is invalid: {0}")]
    InvalidSpec(String),
    #[error("feed input is invalid: {0}")]
    InvalidInput(String),
    #[error("feed {0} not found")]
    FeedNotFound(uuid::Uuid),
    #[error("a feed with this name already exists")]
    DuplicateName,
    #[error("{0}")]
    Backend(String),
}

/// What a bundled spec pins onto a new feed.
#[derive(Debug, Clone)]
pub struct FeedPlan {
    pub connector: String,
    pub spec_yaml: String,
    pub spec_sha256: String,
    /// The lane label: the spec's single stream `source_type`, literal or a
    /// template (`gws_{{item}}`) for a fan-out spec.
    pub source_type: String,
    pub spec: ConnectorSpec,
}

/// Operator input for a new feed (never the spec or the ingest destination).
#[derive(Debug, Clone, Default)]
pub struct NewFeed {
    pub name: String,
    pub config: Map<String, Value>,
    pub credential_id: Option<uuid::Uuid>,
    pub schedule: Option<String>,
    pub max_run_secs: Option<i32>,
    pub enabled: bool,
}

pub(crate) fn is_source_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 100
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
        && s != "unknown"
}

/// The lane label of an identity feed (`kind: identity`, G22): its rows go
/// to the user directory, not to a parser lane.
pub const IDENTITY_LANE_LABEL: &str = "identity";

/// Plan a feed from a spec. Collectors and identity directory syncs run as
/// feeds. Every collector stream must name a `source_type` (a feed's events
/// always land in a known lane); an identity feed has no lane.
pub fn plan_from_spec(connector: &str, spec_yaml: &str) -> Result<FeedPlan, AdminError> {
    let spec = ConnectorSpec::from_yaml(spec_yaml).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    crate::preview::validate_static(&spec).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    if spec.kind == Kind::Identity {
        crate::engine::compile(&spec, &crate::engine::default_ceilings()).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
        return Ok(FeedPlan {
            connector: connector.to_string(),
            spec_yaml: spec_yaml.to_string(),
            spec_sha256: super::feed::spec_sha256(spec_yaml),
            source_type: IDENTITY_LANE_LABEL.to_string(),
            spec,
        });
    }
    if spec.kind != Kind::Collector {
        return Err(AdminError::InvalidSpec("only collector and identity specs run as pull feeds".into()));
    }
    let labels: BTreeSet<&str> = spec.streams.iter().filter_map(|s| s.source_type.as_deref()).collect();
    if spec.streams.iter().any(|s| s.source_type.is_none()) || labels.len() != 1 {
        return Err(AdminError::InvalidSpec(format!(
            "a feed needs every stream on one source_type; this spec has {}",
            if labels.is_empty() { "none".to_string() } else { labels.into_iter().collect::<Vec<_>>().join(", ") }
        )));
    }
    let source_type = labels.into_iter().next().unwrap_or_default().to_string();
    if !source_type.contains("{{") && !is_source_slug(&source_type) {
        return Err(AdminError::InvalidSpec(format!("source_type `{source_type}` is not a source slug")));
    }
    Ok(FeedPlan {
        connector: connector.to_string(),
        spec_yaml: spec_yaml.to_string(),
        spec_sha256: super::feed::spec_sha256(spec_yaml),
        source_type,
        spec,
    })
}

/// The parser lanes a feed with `config` emits into: a literal stream
/// `source_type`, or a `{{item}}` template expanded over the stream's
/// config-driven fan-out (`discover: {from: config, key: K}`, a
/// comma-separated list, as the engine reads it). `Err` when a template
/// cannot be expanded from config (a request-discovered fan-out).
pub fn lanes(plan: &FeedPlan, config: &Map<String, Value>) -> Result<BTreeSet<String>, AdminError> {
    let mut out = BTreeSet::new();
    if plan.spec.kind == Kind::Identity {
        // Identity rows go to the user directory: no parser lane.
        return Ok(out);
    }
    for stream in &plan.spec.streams {
        let Some(label) = stream.source_type.as_deref() else { continue };
        if !label.contains("{{") {
            out.insert(label.to_string());
            continue;
        }
        let key = match stream.fanout.as_ref().map(|f| &f.discover) {
            Some(Discover::Config { key }) if label.matches("{{").count() == 1 && label.contains("{{item}}") => key,
            _ => {
                return Err(AdminError::InvalidSpec(format!(
                    "stream `{}` source_type `{label}` cannot be resolved from config",
                    stream.id
                )))
            }
        };
        let items = config.get(key).map(crate::template::value_to_string).unwrap_or_default();
        for item in items.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let lane = label.replace("{{item}}", item);
            if !is_source_slug(&lane) {
                return Err(AdminError::InvalidInput(format!("`{item}` in {key} makes `{lane}`, which is not a source slug")));
            }
            out.insert(lane);
        }
    }
    if out.is_empty() {
        return Err(AdminError::InvalidInput("the feed would emit into no parser lane".into()));
    }
    Ok(out)
}

/// The config keys a spec reads: `{{config.X}}` references in templates,
/// and each `.config.X` read inside a stream's VRL `program`.
pub fn config_keys(spec_yaml: &str) -> Result<BTreeSet<String>, AdminError> {
    let doc: Value = serde_yaml::from_str(spec_yaml).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    let mut out = template_keys(&doc)?;
    out.extend(program_config_keys(&doc));
    out.extend(fanout_config_keys(&doc));
    out.extend(engine_config_keys(&doc));
    Ok(out)
}

/// Config keys the engine itself reads (always optional): an identity feed's
/// `identity_allow_shrink` (G22, the shrink guard override).
fn engine_config_keys(doc: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if doc.get("kind").and_then(Value::as_str) == Some("identity") {
        out.insert(crate::identity::ALLOW_SHRINK_CONFIG.to_string());
    }
    out
}

fn template_keys(doc: &Value) -> Result<BTreeSet<String>, AdminError> {
    let mut out = BTreeSet::new();
    let mut stack = vec![doc];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) => {
                for r in crate::template::references(s).map_err(|e| AdminError::InvalidSpec(e.to_string()))? {
                    if let Some(k) = r.strip_prefix("config.") {
                        out.insert(k.to_string());
                    }
                }
            }
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(m) => stack.extend(m.values()),
            _ => {}
        }
    }
    Ok(out)
}

/// `discover: {from: config, key: K}` reads config key `K`.
fn fanout_config_keys(doc: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack = vec![doc];
    while let Some(v) = stack.pop() {
        match v {
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(m) => {
                if m.get("from").and_then(Value::as_str) == Some("config") {
                    if let Some(k) = m.get("key").and_then(Value::as_str) {
                        out.insert(k.to_string());
                    }
                }
                stack.extend(m.values());
            }
            _ => {}
        }
    }
    out
}

/// Config keys read by `.config.X` paths in VRL `program` strings. A program
/// reads its input fallibly (`string(.config.X) ?? ""`), so these keys are
/// optional unless a template also reads them.
fn program_config_keys(doc: &Value) -> BTreeSet<String> {
    fn scan(src: &str, out: &mut BTreeSet<String>) {
        const NEEDLE: &str = ".config.";
        let mut rest = src;
        while let Some(i) = rest.find(NEEDLE) {
            let after = &rest[i + NEEDLE.len()..];
            let key: String = after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
                out.insert(key);
            }
            rest = after;
        }
    }
    let mut out = BTreeSet::new();
    let mut stack = vec![doc];
    while let Some(v) = stack.pop() {
        match v {
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(m) => {
                for (k, x) in m {
                    match (k.as_str(), x) {
                        ("program", Value::String(src)) => scan(src, &mut out),
                        _ => stack.push(x),
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Config keys a feed may leave out: every reference to them is a whole
/// request query value (`param: "{{config.X}}"`, the engine omits an empty
/// query parameter) or a VRL program read.
pub fn optional_config_keys(spec_yaml: &str) -> Result<BTreeSet<String>, AdminError> {
    fn walk(v: &Value, under_query: bool, seen: &mut BTreeSet<String>, other: &mut BTreeSet<String>) -> Result<(), AdminError> {
        match v {
            Value::String(s) => {
                let refs = crate::template::references(s).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
                let whole = refs.len() == 1 && s.trim() == format!("{{{{{}}}}}", refs[0]);
                for r in refs {
                    if let Some(k) = r.strip_prefix("config.") {
                        if under_query && whole { seen.insert(k.to_string()) } else { other.insert(k.to_string()) };
                    }
                }
            }
            Value::Array(a) => {
                for x in a {
                    walk(x, false, seen, other)?;
                }
            }
            Value::Object(m) => {
                for (k, x) in m {
                    if k == "request" {
                        if let Value::Object(req) = x {
                            for (rk, rv) in req {
                                match (rk.as_str(), rv) {
                                    ("query", Value::Object(q)) => {
                                        for qv in q.values() {
                                            walk(qv, true, seen, other)?;
                                        }
                                    }
                                    _ => walk(rv, false, seen, other)?,
                                }
                            }
                            continue;
                        }
                    }
                    walk(x, false, seen, other)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let doc: Value = serde_yaml::from_str(spec_yaml).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    let (mut seen, mut other) = (BTreeSet::new(), BTreeSet::new());
    walk(&doc, false, &mut seen, &mut other)?;
    seen.extend(program_config_keys(&doc));
    seen.extend(engine_config_keys(&doc));
    other.extend(fanout_config_keys(&doc));
    Ok(seen.difference(&other).cloned().collect())
}

/// The vendor credential fields the spec's auth scheme reads.
pub fn credential_fields(spec: &ConnectorSpec) -> Result<BTreeSet<String>, AdminError> {
    let plugin = crate::auth::build(&spec.auth.kind, &spec.auth.params).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    Ok(plugin.credential_fields().into_iter().collect())
}

/// Fastest schedule a feed override may set: once a minute.
pub const MIN_SCHEDULE_SECS: i64 = 60;

/// Config, schedule and run limits must fit the spec: nothing missing (a
/// run would fail), nothing extra (a typo, or a secret in the wrong place),
/// a schedule no faster than the spec's own cadence (the vendor's floor) and
/// a run limit inside the spec's.
pub fn check_inputs(plan: &FeedPlan, feed: &NewFeed) -> Result<(), AdminError> {
    let name = feed.name.trim();
    if name.is_empty() || name.chars().count() > 100 || name != feed.name || name.chars().any(char::is_control) {
        return Err(AdminError::InvalidInput("name must be 1-100 characters, trimmed, no control characters".into()));
    }
    let wanted = config_keys(&plan.spec_yaml)?;
    let optional = optional_config_keys(&plan.spec_yaml)?;
    let given: BTreeSet<String> = feed.config.keys().cloned().collect();
    let missing: Vec<_> = wanted.difference(&given).filter(|k| !optional.contains(*k)).cloned().collect();
    let extra: Vec<_> = given.difference(&wanted).cloned().collect();
    if !missing.is_empty() {
        return Err(AdminError::InvalidInput(format!("config is missing {}", missing.join(", "))));
    }
    if !extra.is_empty() {
        return Err(AdminError::InvalidInput(format!("config has keys the spec never reads: {}", extra.join(", "))));
    }
    if let Some((k, _)) = feed
        .config
        .iter()
        .find(|(k, v)| v.is_null() || (!optional.contains(*k) && v.as_str().is_some_and(|s| s.trim().is_empty())))
    {
        return Err(AdminError::InvalidInput(format!("config `{k}` is empty")));
    }
    if let Some((k, _)) = feed.config.iter().find(|(_, v)| !(v.is_string() || v.is_number() || v.is_boolean())) {
        return Err(AdminError::InvalidInput(format!("config `{k}` must be a string, number or boolean")));
    }
    if feed.config.get(crate::identity::ALLOW_SHRINK_CONFIG).is_some_and(|v| !v.is_boolean()) {
        return Err(AdminError::InvalidInput(format!("config `{}` must be true or false", crate::identity::ALLOW_SHRINK_CONFIG)));
    }
    if !credential_fields(&plan.spec)?.is_empty() && feed.credential_id.is_none() {
        return Err(AdminError::InvalidInput("this connector needs a credential".into()));
    }
    if let Some(s) = feed.schedule.as_deref() {
        check_schedule(plan, s)?;
    }
    if let Some(m) = feed.max_run_secs {
        let ceiling = plan.spec.limits.max_run_secs.clamp(10, 3600) as i32;
        if !(10..=ceiling).contains(&m) {
            return Err(AdminError::InvalidInput(format!("max_run_secs must be 10..={ceiling} (the spec's own limit)")));
        }
    }
    Ok(())
}

/// NAN-4931: whether an operator can adopt the bundled `bundled` plan (a
/// newer build's spec) for a feed pinned to `pinned_yaml` without editing the
/// feed: the same kind, stream ids and credential fields, and the feed's
/// existing config still satisfies the new spec. A precondition for EXPLICIT
/// adoption only (which also resets checkpoints); nothing re-pins
/// automatically. `Err` names why the feed must be recreated instead.
pub fn repin_compatible(pinned_yaml: &str, bundled: &FeedPlan, feed: &NewFeed) -> Result<(), String> {
    let old = ConnectorSpec::from_yaml(pinned_yaml).map_err(|e| format!("pinned spec unreadable: {e}"))?;
    if old.kind != bundled.spec.kind {
        return Err("the spec kind changed".into());
    }
    let ids = |s: &ConnectorSpec| s.streams.iter().map(|x| x.id.clone()).collect::<BTreeSet<_>>();
    if ids(&old) != ids(&bundled.spec) {
        return Err("the stream ids changed (checkpoints would not carry over)".into());
    }
    let creds = |s: &ConnectorSpec| credential_fields(s).map_err(|e| e.to_string());
    if creds(&old)? != creds(&bundled.spec)? {
        return Err("the credential fields changed".into());
    }
    check_inputs(bundled, feed).map_err(|e| format!("the feed's settings do not fit the new spec: {e}"))
}

/// A feed's schedule override: valid cron, at most once a minute, and no
/// faster than the spec's schedule (the vendor's rate floor).
pub fn check_schedule(plan: &FeedPlan, schedule: &str) -> Result<(), AdminError> {
    let now = chrono::Utc::now();
    let gap = super::feed::min_interval(schedule, now)
        .map_err(|e| AdminError::InvalidInput(format!("schedule `{schedule}` is not a valid cron expression: {e}")))?;
    let mut floor = chrono::Duration::seconds(MIN_SCHEDULE_SECS);
    if let Some(spec_schedule) = plan.spec.schedule.as_deref().filter(|s| !s.trim().is_empty()) {
        if let Ok(spec_gap) = super::feed::min_interval(spec_schedule, now) {
            floor = floor.max(spec_gap);
        }
    }
    if gap < floor {
        return Err(AdminError::InvalidInput(format!(
            "schedule `{schedule}` runs every {} s; this connector allows at most one run every {} s",
            gap.num_seconds(),
            floor.num_seconds()
        )));
    }
    Ok(())
}

/// Credential fields of a stored credential payload that the spec reads,
/// as runner secrets. Extra fields (metadata the credentials store merges in,
/// such as `external_id`) are ignored; a missing or blank field is an error
/// so the run fails with a clear message instead of an auth failure.
pub fn vendor_secrets(spec: &ConnectorSpec, payload: &Value) -> Result<HashMap<String, super::feed::Secret>, String> {
    let wanted = credential_fields(spec).map_err(|e| e.to_string())?;
    let mut out = HashMap::new();
    for field in wanted {
        let value = payload
            .get(&field)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("the bound credential has no `{field}`"))?;
        out.insert(field, super::feed::Secret::new(value));
    }
    Ok(out)
}

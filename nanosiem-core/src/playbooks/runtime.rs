// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-462 — Playbook runtime templating engine.
//!
//! Playbook docs store `{{...}}` tokens that reference case / alert / rule /
//! entity / event context. When a playbook attaches to a case, a frozen
//! [`RunContext`] snapshot is captured on the `playbook_runs.run_context`
//! column; this module resolves those tokens against the snapshot at
//! read time.
//!
//! ## Grammar
//!
//! ```text
//! {{case.id}} {{case.title}} {{case.severity}}
//! {{alert.id}} {{alert.<udm>}}              → event top-field alias
//! {{rule.id}} {{rule.name}} {{rule.severity}}
//! {{source_type}}
//! {{event.<udm>}}                           → field on top_matched_event
//! {{entity.<type>}}                         → first entity of that type
//! {{entity.<type>[N]}}                      → explicit index
//! {{entities.<type>}}                       → the entire array
//! {{lower <path>}} {{upper <path>}}
//! {{default <path> "fallback"}}
//! {{join <path> ","}}
//! ```
//!
//! ## Resolution rules
//!
//! - Missing scalar → empty string.
//! - Missing array → `[]`; `{{join empty ","}}` → `""`.
//! - Unknown namespace → empty string + the path is added to
//!   [`Resolution::unresolved`] so the caller can surface a
//!   "missing context" indicator.
//! - No mutation of the stored `playbooks.doc` — the symbolic form stays
//!   put; resolution runs on read.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::entity_extraction::ExtractedEntity;
use super::models::PlaybookStep;

// ---------------------------------------------------------------------------
// RunContext
// ---------------------------------------------------------------------------

/// Frozen context a playbook run resolves tokens against. Serialised to JSONB
/// on `playbook_runs.run_context` at attach time, never re-computed for the
/// life of the run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<CaseCtx>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<AlertCtx>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleCtx>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    /// Raw top-scored matched event — a JSON object of UDM fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_matched_event: Option<JsonValue>,
    /// Map of `entity_type` → ordered list of values. Built from
    /// [`ExtractedEntity`] via [`RunContext::from_entities`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub entities: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseCtx {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCtx {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCtx {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

impl RunContext {
    /// Group `ExtractedEntity` rows by `entity_type` into the `entities` map.
    /// Preserves insertion order within each type; de-duplicates values
    /// (same user extracted from multiple events only shows up once).
    pub fn set_entities(&mut self, extracted: &[ExtractedEntity]) {
        self.entities.clear();
        for e in extracted {
            let bucket = self
                .entities
                .entry(e.entity_type.clone())
                .or_insert_with(Vec::new);
            if !bucket.iter().any(|v| v == &e.value) {
                bucket.push(e.value.clone());
            }
        }
    }

    /// Pull `source_type` off the top matched event, if that event has one.
    /// Called automatically by [`RunContext::set_top_matched_event`].
    fn sync_source_type_from_event(&mut self) {
        if self.source_type.is_some() {
            return;
        }
        if let Some(ev) = &self.top_matched_event {
            if let Some(s) = ev.get("source_type").and_then(|v| v.as_str()) {
                self.source_type = Some(s.to_string());
            }
        }
    }

    /// Set the top matched event and, as a convenience, backfill
    /// `source_type` from it.
    pub fn set_top_matched_event(&mut self, event: JsonValue) {
        self.top_matched_event = Some(event);
        self.sync_source_type_from_event();
    }

    /// Serialise to the JSONB shape stored on `playbook_runs.run_context`.
    pub fn to_json(&self) -> JsonValue {
        serde_json::to_value(self).unwrap_or(JsonValue::Null)
    }
}

/// NAN-462 — build a snapshot from the alert-driven auto-attach path.
///
/// Picks the first element of `alert.matched_events` as the top matched
/// event (the rule engine sorts matched_events by triggering order, so the
/// first is the one that caused the rule to fire). Missing pieces degrade
/// gracefully — the templating engine accepts a partial snapshot.
pub fn build_snapshot_from_alert(
    case_id: &str,
    case_title: Option<&str>,
    case_severity: Option<&str>,
    alert_id: &str,
    alert_severity: Option<&str>,
    rule_id: Option<&str>,
    rule_name: Option<&str>,
    rule_severity: Option<&str>,
    matched_events: &JsonValue,
    entities: &[ExtractedEntity],
) -> JsonValue {
    let mut ctx = RunContext {
        case: Some(CaseCtx {
            id: case_id.to_string(),
            title: case_title.map(|s| s.to_string()),
            severity: case_severity.map(|s| s.to_string()),
        }),
        alert: Some(AlertCtx {
            id: alert_id.to_string(),
            severity: alert_severity.map(|s| s.to_string()),
        }),
        rule: rule_id.map(|id| RuleCtx {
            id: id.to_string(),
            name: rule_name.map(|s| s.to_string()),
            severity: rule_severity.map(|s| s.to_string()),
        }),
        ..Default::default()
    };

    // First element of the matched_events array is the top (triggering) event.
    if let Some(arr) = matched_events.as_array() {
        if let Some(first) = arr.first() {
            ctx.set_top_matched_event(first.clone());
        }
    }

    ctx.set_entities(entities);
    ctx.to_json()
}

/// NAN-469 — build a snapshot from the manual-attach path (no rule fire).
///
/// Manual attaches don't have an alert/event seed, so `alert.*` / `event.*`
/// tokens stay unresolved (the runtime renders them as empty strings —
/// known-namespace, missing-data is intentionally silent). The case fields
/// + the case's already-extracted entities are still useful: they let
/// `{{case.id}}`, `{{case.title}}`, `{{entity.user}}`, `{{entity.host}}`,
/// etc. render correctly for hand-attached playbooks.
///
/// `entities` is the flat list of `(entity_type, value)` pulled from
/// `case_entities` (already de-duped by the case repo's `(case_id,
/// entity_type, entity_value)` constraint). Order is preserved per type —
/// the caller is expected to pass them sorted by `is_primary DESC,
/// occurrence_count DESC` so `{{entity.user}}` (== index 0) returns the
/// primary user for the case.
pub fn build_snapshot_from_case(
    case_id: &str,
    case_title: Option<&str>,
    case_severity: Option<&str>,
    entities: &[ExtractedEntity],
) -> JsonValue {
    let mut ctx = RunContext {
        case: Some(CaseCtx {
            id: case_id.to_string(),
            title: case_title.map(|s| s.to_string()),
            severity: case_severity.map(|s| s.to_string()),
        }),
        ..Default::default()
    };
    ctx.set_entities(entities);
    ctx.to_json()
}

// ---------------------------------------------------------------------------
// Tokenisation + expression parsing
// ---------------------------------------------------------------------------

/// `{{ ... }}` matcher. Non-greedy body; we assume tokens don't nest (they
/// don't in this grammar — no partials, no block helpers).
fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\{\s*(?P<body>[^{}]+?)\s*\}\}").unwrap())
}

#[derive(Debug, Clone)]
enum Segment {
    Key(String),
    Index(usize),
}

#[derive(Debug, Clone)]
struct Path {
    root: String,
    segments: Vec<Segment>,
}

#[derive(Debug, Clone)]
enum Arg {
    /// A quoted literal: "n/a"
    Literal(String),
    /// A second-position path: (rare — only `default` uses it today, but
    /// kept general so `{{default entity.user entity.src_user}}` composes)
    Path(Path),
}

#[derive(Debug, Clone)]
struct Expr {
    helper: Option<String>,
    path: Path,
    args: Vec<Arg>,
}

/// Parse a path like `entity.user[0]` or `case.title` into segments.
fn parse_path(raw: &str) -> Option<Path> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let bracket = Regex::new(r"\[(\d+)\]").unwrap();

    // Split into `root.rest...`, tolerate bare root.
    let mut parts = s.splitn(2, '.');
    let first = parts.next()?;
    // The root may itself carry an index: `entities[0]` isn't meaningful but
    // keep it general. Strip trailing [N] from the root into a segment.
    let (root, mut segs) = split_indices(first, &bracket);

    if let Some(rest) = parts.next() {
        for piece in rest.split('.') {
            let (key, extra) = split_indices(piece, &bracket);
            if !key.is_empty() {
                segs.push(Segment::Key(key));
            }
            segs.extend(extra);
        }
    }
    Some(Path { root, segments: segs })
}

/// Strip trailing `[N]` brackets off `piece`, returning the bare key + any
/// index segments.
fn split_indices(piece: &str, bracket: &Regex) -> (String, Vec<Segment>) {
    let mut key = piece.to_string();
    let mut out = Vec::new();
    // Iterate brackets from the end of the string.
    while let Some(m) = bracket.find(&key) {
        if m.end() != key.len() {
            // bracket in the middle — not a grammar we support; stop.
            break;
        }
        let idx: usize = bracket
            .captures(&key[m.start()..])
            .and_then(|c| c.get(1))
            .and_then(|g| g.as_str().parse().ok())
            .unwrap_or(0);
        out.insert(0, Segment::Index(idx));
        key.truncate(m.start());
    }
    (key, out)
}

/// Parse the interior of a `{{...}}` into an [`Expr`].
///
/// Grammar (informal):
/// ```text
/// expr    := [helper] path arg*
/// helper  := lower | upper | default | join
/// path    := ident (. ident)* ([N])*
/// arg     := "quoted" | path
/// ```
fn parse_expr(body: &str) -> Option<Expr> {
    let s = body.trim();
    if s.is_empty() {
        return None;
    }

    // Split on whitespace, respecting quoted strings.
    let tokens = shell_split(s);
    if tokens.is_empty() {
        return None;
    }

    let helpers = ["lower", "upper", "default", "join"];
    let (helper, rest): (Option<String>, &[String]) = if helpers.contains(&tokens[0].as_str()) {
        (Some(tokens[0].clone()), &tokens[1..])
    } else {
        (None, &tokens[..])
    };

    let first = rest.first()?;
    let path = parse_path(first)?;
    let args: Vec<Arg> = rest[1..]
        .iter()
        .map(|t| {
            if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
                Arg::Literal(t[1..t.len() - 1].to_string())
            } else {
                match parse_path(t) {
                    Some(p) => Arg::Path(p),
                    None => Arg::Literal(t.clone()),
                }
            }
        })
        .collect();

    Some(Expr { helper, path, args })
}

/// Minimal shell-style splitter — respects "…" quoting but doesn't do
/// backslash escapes (not needed for our grammar).
fn shell_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quote = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                buf.push(c);
            }
            _ if c.is_whitespace() && !in_quote => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
            }
            _ => buf.push(c),
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Intermediate resolved value type — mirrors what a path walk can return.
#[derive(Debug, Clone)]
enum RVal {
    Scalar(String),
    Array(Vec<String>),
    Missing,
}

impl RVal {
    fn into_string(self) -> String {
        match self {
            RVal::Scalar(s) => s,
            _ => String::new(),
        }
    }
    fn is_empty(&self) -> bool {
        matches!(self, RVal::Missing)
            || matches!(self, RVal::Scalar(s) if s.is_empty())
            || matches!(self, RVal::Array(a) if a.is_empty())
    }
}

fn udm_field(event: &JsonValue, key: &str) -> RVal {
    match event.get(key) {
        Some(v) => json_to_rval(v),
        None => RVal::Missing,
    }
}

fn json_to_rval(v: &JsonValue) -> RVal {
    match v {
        JsonValue::Null => RVal::Missing,
        JsonValue::String(s) => RVal::Scalar(s.clone()),
        JsonValue::Number(n) => RVal::Scalar(n.to_string()),
        JsonValue::Bool(b) => RVal::Scalar(b.to_string()),
        JsonValue::Array(arr) => {
            let strs: Vec<String> = arr
                .iter()
                .map(|item| match item {
                    JsonValue::String(s) => s.clone(),
                    _ => item.to_string(),
                })
                .collect();
            RVal::Array(strs)
        }
        JsonValue::Object(_) => RVal::Missing, // not scalar-shaped
    }
}

/// Resolve a path to an [`RVal`]. `unresolved` collects any path whose
/// namespace is outright unknown (so the caller can flag a "missing
/// context" indicator); empty-but-known scalars don't count as unresolved.
fn resolve_path(path: &Path, ctx: &RunContext, unresolved: &mut Vec<String>) -> RVal {
    let full = path_to_string(path);
    let segs = &path.segments;

    match path.root.as_str() {
        "case" => match ctx.case.as_ref() {
            Some(c) => match first_segment_key(segs) {
                Some("id") => RVal::Scalar(c.id.clone()),
                Some("title") => c
                    .title
                    .clone()
                    .map(RVal::Scalar)
                    .unwrap_or(RVal::Missing),
                Some("severity") => c
                    .severity
                    .clone()
                    .map(RVal::Scalar)
                    .unwrap_or(RVal::Missing),
                _ => {
                    unresolved.push(full);
                    RVal::Missing
                }
            },
            None => RVal::Missing,
        },
        "alert" => {
            // `alert.id | severity` resolve from AlertCtx;
            // `alert.<udm>` aliases to the top matched event.
            let key = first_segment_key(segs);
            match key {
                Some("id") => ctx
                    .alert
                    .as_ref()
                    .map(|a| RVal::Scalar(a.id.clone()))
                    .unwrap_or(RVal::Missing),
                Some("severity") => ctx
                    .alert
                    .as_ref()
                    .and_then(|a| a.severity.clone())
                    .map(RVal::Scalar)
                    .unwrap_or(RVal::Missing),
                Some(k) => ctx
                    .top_matched_event
                    .as_ref()
                    .map(|ev| udm_field(ev, k))
                    .unwrap_or(RVal::Missing),
                None => RVal::Missing,
            }
        }
        "rule" => match ctx.rule.as_ref() {
            Some(r) => match first_segment_key(segs) {
                Some("id") => RVal::Scalar(r.id.clone()),
                Some("name") => r.name.clone().map(RVal::Scalar).unwrap_or(RVal::Missing),
                Some("severity") => r
                    .severity
                    .clone()
                    .map(RVal::Scalar)
                    .unwrap_or(RVal::Missing),
                _ => {
                    unresolved.push(full);
                    RVal::Missing
                }
            },
            None => RVal::Missing,
        },
        "source_type" => ctx
            .source_type
            .clone()
            .map(RVal::Scalar)
            .unwrap_or(RVal::Missing),
        "event" => match (ctx.top_matched_event.as_ref(), first_segment_key(segs)) {
            (Some(ev), Some(k)) => udm_field(ev, k),
            _ => RVal::Missing,
        },
        "entity" => resolve_entity_path(ctx, segs, /*single=*/ true, unresolved, &full),
        "entities" => resolve_entity_path(ctx, segs, /*single=*/ false, unresolved, &full),
        _ => {
            unresolved.push(full);
            RVal::Missing
        }
    }
}

fn resolve_entity_path(
    ctx: &RunContext,
    segs: &[Segment],
    single: bool,
    unresolved: &mut Vec<String>,
    full: &str,
) -> RVal {
    let kind = match segs.first() {
        Some(Segment::Key(k)) => k.clone(),
        _ => {
            unresolved.push(full.to_string());
            return RVal::Missing;
        }
    };
    let bucket = ctx.entities.get(&kind).cloned().unwrap_or_default();

    // Second segment can be an index on `entity.<kind>[N]`.
    let idx = match segs.get(1) {
        Some(Segment::Index(n)) => Some(*n),
        _ => None,
    };

    if single {
        // {{entity.<kind>}} → index 0 unless [N] was given
        let i = idx.unwrap_or(0);
        bucket.get(i).cloned().map(RVal::Scalar).unwrap_or(RVal::Missing)
    } else {
        // {{entities.<kind>}} → array
        if let Some(i) = idx {
            bucket.get(i).cloned().map(RVal::Scalar).unwrap_or(RVal::Missing)
        } else if bucket.is_empty() {
            RVal::Array(Vec::new())
        } else {
            RVal::Array(bucket)
        }
    }
}

fn first_segment_key(segs: &[Segment]) -> Option<&str> {
    match segs.first() {
        Some(Segment::Key(k)) => Some(k.as_str()),
        _ => None,
    }
}

fn path_to_string(p: &Path) -> String {
    let mut s = p.root.clone();
    for seg in &p.segments {
        match seg {
            Segment::Key(k) => {
                s.push('.');
                s.push_str(k);
            }
            Segment::Index(n) => {
                s.push('[');
                s.push_str(&n.to_string());
                s.push(']');
            }
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn apply_helper(helper: &str, base: RVal, args: &[Arg], ctx: &RunContext, unresolved: &mut Vec<String>) -> String {
    match helper {
        "lower" => base.into_string().to_lowercase(),
        "upper" => base.into_string().to_uppercase(),
        "default" => {
            if base.is_empty() {
                resolve_arg(args.first(), ctx, unresolved)
            } else {
                base.into_string()
            }
        }
        "join" => {
            let sep = resolve_arg(args.first(), ctx, unresolved);
            match base {
                RVal::Array(arr) => arr.join(&sep),
                RVal::Scalar(s) => s,
                RVal::Missing => String::new(),
            }
        }
        _ => base.into_string(),
    }
}

fn resolve_arg(arg: Option<&Arg>, ctx: &RunContext, unresolved: &mut Vec<String>) -> String {
    match arg {
        Some(Arg::Literal(s)) => s.clone(),
        Some(Arg::Path(p)) => resolve_path(p, ctx, unresolved).into_string(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// The resolved form of a string — the output text plus the set of paths
/// whose namespace or shape didn't resolve (useful for UI "missing context"
/// indicators). Empty-but-known scalars (`entity.user` where no user entity
/// exists) do NOT count as unresolved.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    pub out: String,
    pub unresolved: Vec<String>,
}

/// Resolve `{{...}}` tokens in `input` against `ctx`.
pub fn resolve_string(input: &str, ctx: &RunContext) -> Resolution {
    let re = token_re();
    let mut unresolved: Vec<String> = Vec::new();
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for m in re.captures_iter(input) {
        let mat = m.get(0).unwrap();
        out.push_str(&input[last..mat.start()]);
        let body = m.name("body").map(|m| m.as_str()).unwrap_or("");
        if let Some(expr) = parse_expr(body) {
            let base = resolve_path(&expr.path, ctx, &mut unresolved);
            let rendered = match &expr.helper {
                Some(h) => apply_helper(h, base, &expr.args, ctx, &mut unresolved),
                None => match base {
                    RVal::Scalar(s) => s,
                    RVal::Array(_) => String::new(),
                    RVal::Missing => String::new(),
                },
            };
            out.push_str(&rendered);
        }
        last = mat.end();
    }
    out.push_str(&input[last..]);
    Resolution { out, unresolved }
}

/// Resolve a [`PlaybookStep`] — walks `label` + every string leaf in
/// `params` + each option. Returns a cloned step with the resolved values
/// substituted in. Non-string leaves (numbers, booleans, nested arrays) are
/// left alone.
pub fn resolve_step(step: &PlaybookStep, ctx: &RunContext) -> (PlaybookStep, Vec<String>) {
    let mut unresolved: Vec<String> = Vec::new();
    let mut out = step.clone();
    let lr = resolve_string(&step.label, ctx);
    out.label = lr.out;
    unresolved.extend(lr.unresolved);

    if let Some(params) = out.params.as_object_mut() {
        for (_, v) in params.iter_mut() {
            resolve_json_in_place(v, ctx, &mut unresolved);
        }
    }

    if let Some(opts) = out.options.as_mut() {
        let new_opts: Vec<JsonValue> = opts
            .iter()
            .map(|o| match o {
                JsonValue::String(s) => {
                    let r = resolve_string(s, ctx);
                    unresolved.extend(r.unresolved);
                    JsonValue::String(r.out)
                }
                _ => o.clone(),
            })
            .collect();
        *opts = new_opts;
    }

    (out, unresolved)
}

fn resolve_json_in_place(v: &mut JsonValue, ctx: &RunContext, unresolved: &mut Vec<String>) {
    match v {
        JsonValue::String(s) => {
            let r = resolve_string(s, ctx);
            unresolved.extend(r.unresolved);
            *s = r.out;
        }
        JsonValue::Array(arr) => {
            for item in arr.iter_mut() {
                resolve_json_in_place(item, ctx, unresolved);
            }
        }
        JsonValue::Object(obj) => {
            for (_, val) in obj.iter_mut() {
                resolve_json_in_place(val, ctx, unresolved);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn alice_ctx() -> RunContext {
        let mut ctx = RunContext {
            case: Some(CaseCtx {
                id: "case_01hz".into(),
                title: Some("AWS root key used outside bastion".into()),
                severity: Some("p1".into()),
            }),
            alert: Some(AlertCtx {
                id: "alert_01hz".into(),
                severity: Some("high".into()),
            }),
            rule: Some(RuleCtx {
                id: "rule_01hz".into(),
                name: Some("Root key use".into()),
                severity: Some("high".into()),
            }),
            ..Default::default()
        };
        ctx.set_top_matched_event(json!({
            "source_type": "cloudtrail",
            "user": "alice",
            "src_ip": "10.0.0.5",
            "process_name": "aws-cli",
        }));
        ctx.set_entities(&[
            ExtractedEntity { entity_type: "user".into(), value: "alice".into() },
            ExtractedEntity { entity_type: "user".into(), value: "bob".into() },
            ExtractedEntity { entity_type: "src_ip".into(), value: "10.0.0.5".into() },
        ]);
        ctx
    }

    #[test]
    fn resolves_entity_first() {
        let ctx = alice_ctx();
        let r = resolve_string("user = {{entity.user}}", &ctx);
        assert_eq!(r.out, "user = alice");
        assert!(r.unresolved.is_empty());
    }

    #[test]
    fn resolves_entity_indexed() {
        let ctx = alice_ctx();
        assert_eq!(resolve_string("{{entity.user[0]}}", &ctx).out, "alice");
        assert_eq!(resolve_string("{{entity.user[1]}}", &ctx).out, "bob");
        assert_eq!(resolve_string("{{entity.user[9]}}", &ctx).out, "");
    }

    #[test]
    fn array_without_helper_renders_empty() {
        let ctx = alice_ctx();
        // `entities.user` without a join helper produces nothing (plain
        // array interpolation isn't a grammar we want to expose).
        assert_eq!(resolve_string("{{entities.user}}", &ctx).out, "");
    }

    #[test]
    fn join_helper() {
        let ctx = alice_ctx();
        assert_eq!(
            resolve_string(r#"users={{join entities.user ","}}"#, &ctx).out,
            "users=alice,bob"
        );
    }

    #[test]
    fn join_on_empty_array_is_empty() {
        let ctx = alice_ctx();
        assert_eq!(
            resolve_string(r#"{{join entities.file_hash ","}}"#, &ctx).out,
            ""
        );
    }

    #[test]
    fn lower_upper_helpers() {
        let ctx = alice_ctx();
        assert_eq!(resolve_string("{{lower rule.name}}", &ctx).out, "root key use");
        assert_eq!(resolve_string("{{upper entity.user}}", &ctx).out, "ALICE");
    }

    #[test]
    fn default_helper_fallback_and_present() {
        let ctx = alice_ctx();
        assert_eq!(
            resolve_string(r#"{{default entity.file_hash "none"}}"#, &ctx).out,
            "none"
        );
        assert_eq!(
            resolve_string(r#"{{default entity.user "none"}}"#, &ctx).out,
            "alice"
        );
    }

    #[test]
    fn case_alert_rule_fields() {
        let ctx = alice_ctx();
        assert_eq!(resolve_string("{{case.id}}", &ctx).out, "case_01hz");
        assert_eq!(
            resolve_string("{{case.title}}", &ctx).out,
            "AWS root key used outside bastion"
        );
        assert_eq!(resolve_string("{{alert.id}}", &ctx).out, "alert_01hz");
        assert_eq!(resolve_string("{{rule.name}}", &ctx).out, "Root key use");
    }

    #[test]
    fn source_type_and_event_fields() {
        let ctx = alice_ctx();
        assert_eq!(resolve_string("{{source_type}}", &ctx).out, "cloudtrail");
        assert_eq!(resolve_string("{{event.src_ip}}", &ctx).out, "10.0.0.5");
        // alert.<udm> is the alias for event.<udm>:
        assert_eq!(resolve_string("{{alert.src_ip}}", &ctx).out, "10.0.0.5");
    }

    #[test]
    fn unknown_namespace_flags_unresolved() {
        let ctx = alice_ctx();
        let r = resolve_string("{{widget.foo}}", &ctx);
        assert_eq!(r.out, "");
        assert_eq!(r.unresolved, vec!["widget.foo".to_string()]);
    }

    #[test]
    fn missing_scalar_is_empty_not_unresolved() {
        // entity.file_hash is a known namespace, just no values → empty
        // and NOT flagged as unresolved (the grammar works, the data is
        // absent — an authoring decision, not a bug).
        let ctx = alice_ctx();
        let r = resolve_string("{{entity.file_hash}}", &ctx);
        assert_eq!(r.out, "");
        assert!(r.unresolved.is_empty());
    }

    #[test]
    fn literals_preserved_around_tokens() {
        let ctx = alice_ctx();
        let r = resolve_string(
            r#"user = "{{entity.user}}" AND source_type = "{{source_type}}""#,
            &ctx,
        );
        assert_eq!(r.out, r#"user = "alice" AND source_type = "cloudtrail""#);
    }

    #[test]
    fn resolves_step_label_and_params() {
        let ctx = alice_ctx();
        let step = PlaybookStep {
            id: "s1".into(),
            kind: "query".into(),
            label: "pull events for {{entity.user}}".into(),
            params: json!({
                "from": "auth-events",
                "where": "user = \"{{entity.user}}\"",
                "window": "30d"
            }),
            options: None,
            note_required_on: None,
            decision_id: None,
            suggested: None,
            suggested_conf: None,
            auto_result: None,
            when: None,
        };
        let (resolved, unresolved) = resolve_step(&step, &ctx);
        assert_eq!(resolved.label, "pull events for alice");
        assert_eq!(
            resolved.params.get("where").and_then(|v| v.as_str()),
            Some(r#"user = "alice""#)
        );
        assert!(unresolved.is_empty());
    }

    #[test]
    fn manual_attach_none_context_resolves_to_empty() {
        // Simulate a manual attach — no alert / entities / rule. Tokens
        // should resolve to empty strings, not abort or throw.
        let ctx = RunContext::default();
        let r = resolve_string("user = {{entity.user}}", &ctx);
        assert_eq!(r.out, "user = ");
        assert!(r.unresolved.is_empty());
    }

    #[test]
    fn set_entities_dedups_within_type() {
        let mut ctx = RunContext::default();
        ctx.set_entities(&[
            ExtractedEntity { entity_type: "user".into(), value: "alice".into() },
            ExtractedEntity { entity_type: "user".into(), value: "alice".into() }, // dup
            ExtractedEntity { entity_type: "user".into(), value: "bob".into() },
        ]);
        assert_eq!(ctx.entities.get("user").unwrap(), &vec!["alice", "bob"]);
    }

    // -----------------------------------------------------------------------
    // NAN-469 — manual-attach snapshot builder
    // -----------------------------------------------------------------------

    fn manual_entities() -> Vec<ExtractedEntity> {
        // Cover all 9 normalized entity types (the runtime is type-agnostic
        // for entity names; the case service is the layer that constrains
        // them to user / host / ip / domain / hash / url / file / process /
        // email).
        vec![
            ExtractedEntity { entity_type: "user".into(),    value: "alice".into() },
            ExtractedEntity { entity_type: "user".into(),    value: "bob".into() },
            ExtractedEntity { entity_type: "host".into(),    value: "web-01".into() },
            ExtractedEntity { entity_type: "ip".into(),      value: "10.0.0.5".into() },
            ExtractedEntity { entity_type: "domain".into(),  value: "evil.example".into() },
            ExtractedEntity { entity_type: "hash".into(),    value: "abc123".into() },
            ExtractedEntity { entity_type: "url".into(),     value: "https://evil/x".into() },
            ExtractedEntity { entity_type: "file".into(),    value: "/tmp/malware".into() },
            ExtractedEntity { entity_type: "process".into(), value: "powershell.exe".into() },
            ExtractedEntity { entity_type: "email".into(),   value: "alice@example.com".into() },
        ]
    }

    #[test]
    fn build_snapshot_from_case_populates_case_and_entities() {
        let snap = build_snapshot_from_case(
            "case_01hzcaseabc",
            Some("Suspicious PowerShell on web-01"),
            Some("p2"),
            &manual_entities(),
        );

        // Round-trips through the same struct the runtime consumes.
        let ctx: RunContext =
            serde_json::from_value(snap.clone()).expect("snapshot deserialises into RunContext");

        let case = ctx.case.expect("case present");
        assert_eq!(case.id, "case_01hzcaseabc");
        assert_eq!(case.title.as_deref(), Some("Suspicious PowerShell on web-01"));
        assert_eq!(case.severity.as_deref(), Some("p2"));

        // No alert / event / rule on the manual path — those keys must stay
        // absent so the resolver flags alert.* / event.* paths cleanly.
        assert!(ctx.alert.is_none());
        assert!(ctx.rule.is_none());
        assert!(ctx.top_matched_event.is_none());

        // All 9 normalized entity types round-trip into the entities map.
        for kind in [
            "user", "host", "ip", "domain", "hash", "url", "file", "process", "email",
        ] {
            assert!(
                ctx.entities.contains_key(kind),
                "missing entity bucket: {}",
                kind
            );
        }
        // user has two values, ordered as inserted
        assert_eq!(ctx.entities.get("user").unwrap(), &vec!["alice", "bob"]);
    }

    #[test]
    fn build_snapshot_from_case_resolves_via_runtime() {
        // Round-trip: build snapshot → deserialise → resolve tokens. This is
        // the end-to-end shape `GET /api/playbook-runs/{id}/resolved` will
        // see for a manually-attached run.
        let snap = build_snapshot_from_case(
            "case_01hzcaseabc",
            Some("Suspicious PowerShell on web-01"),
            Some("p2"),
            &manual_entities(),
        );
        let ctx: RunContext = serde_json::from_value(snap).unwrap();

        // case + entity tokens resolve cleanly, no `unresolved` entries.
        // Entity indexing is `entity.<kind>[N]` per runtime grammar; bare
        // `{{entity.user}}` is sugar for index 0 (the primary).
        let r = resolve_string(
            "case={{case.id}} title={{case.title}} sev={{case.severity}} \
             user={{entity.user}} u2={{entity.user[1]}} host={{entity.host}} \
             ip={{entity.ip}} email={{entity.email}}",
            &ctx,
        );
        assert_eq!(
            r.out,
            "case=case_01hzcaseabc title=Suspicious PowerShell on web-01 sev=p2 \
             user=alice u2=bob host=web-01 \
             ip=10.0.0.5 email=alice@example.com"
        );
        assert!(
            r.unresolved.is_empty(),
            "case + entity tokens should resolve; got unresolved={:?}",
            r.unresolved
        );

        // alert.id / event.<udm> / rule.id stay missing (rendered empty) but
        // are NOT flagged as unresolved — the namespaces are known, just
        // unpopulated. This matches the behaviour rule-fire alert seeds get
        // when an event lacks a particular UDM column.
        let r2 = resolve_string("a={{alert.id}} e={{event.src_ip}} r={{rule.name}}", &ctx);
        assert_eq!(r2.out, "a= e= r=");
        assert!(r2.unresolved.is_empty());
    }

    #[test]
    fn build_snapshot_from_case_with_no_entities_still_has_case() {
        // A freshly-created case with no entities yet should still produce a
        // useful snapshot — case.id / case.title resolve, entity buckets
        // render as empty.
        let snap = build_snapshot_from_case(
            "case_01hzempty",
            Some("Empty case"),
            Some("low"),
            &[],
        );
        let ctx: RunContext = serde_json::from_value(snap).unwrap();
        assert_eq!(
            resolve_string("{{case.id}} / {{entity.user}}", &ctx).out,
            "case_01hzempty / "
        );
    }
}

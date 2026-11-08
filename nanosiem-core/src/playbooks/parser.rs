// SPDX-License-Identifier: AGPL-3.0-or-later

//! Markdown + slash-command parser for playbook docs.
//!
//! Ported from `design-ref/shadcn/playbook-parser.jsx`. Output is a `ParsedStepTree`
//! that mirrors the JS parser's shape so the frontend can render the same data
//! whether it came from the mock or the real API.
//!
//! Grammar (informal):
//!
//! ```text
//! # Title                   → doc title
//! ## Phase heading          → starts a new phase
//! /kind: label              → starts a new step; kind ∈ {query,pivot,enrichment,
//!                             baseline,lead,decision,action,review,note}
//!   key: value              → YAML-ish indented block becomes step.params
//!   key:
//!     - item                → list value
//!     - item
//!   key:
//!     subkey: value         → nested map value
//! Plain prose               → goes into phase.body (or out.intro before any phase)
//! ```
//!
//! Special decision keys:
//! - `options`       → `step.options`
//! - `note_required_on` / `note-required-on` → `step.note_required_on`
//! - `_suggested` / `_suggested_confidence`  → `step.suggested` / `step.suggested_conf`
//! - `_auto_result`  → `step.auto_result`
//! - `id`            → overrides the auto-generated step id
//! - `when`          → parsed into `step.when`

use regex::Regex;
use serde_json::{json, Map, Value};

use super::models::{ParsedStepTree, PlaybookPhase, PlaybookStep, WhenClause, WhenOp};

/// Parse a `when:` clause like `d1 = yes` or `d1 in [yes, partial]`.
/// Returns `None` if the input doesn't match either form.
pub fn parse_when_clause(raw: &str) -> Option<WhenClause> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    // in [a, b, c]
    let in_re = Regex::new(r"^([\w-]+)\s+in\s+\[(.+)\]$").ok()?;
    if let Some(caps) = in_re.captures(s) {
        let ref_id = caps.get(1)?.as_str().to_string();
        let values: Vec<String> = caps
            .get(2)?
            .as_str()
            .split(',')
            .map(|v| strip_quotes(v.trim()).to_string())
            .collect();
        return Some(WhenClause {
            ref_id,
            op: WhenOp::In,
            values,
        });
    }

    // = value | == value
    let eq_re = Regex::new(r"^([\w-]+)\s*==?\s*(.+)$").ok()?;
    if let Some(caps) = eq_re.captures(s) {
        let ref_id = caps.get(1)?.as_str().to_string();
        let v = strip_quotes(caps.get(2)?.as_str().trim()).to_string();
        return Some(WhenClause {
            ref_id,
            op: WhenOp::Eq,
            values: vec![v],
        });
    }

    None
}

fn strip_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len >= 2
        && ((bytes[0] == b'"' && bytes[len - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[len - 1] == b'\''))
    {
        &s[1..len - 1]
    } else {
        s
    }
}

/// Normalize an option label to its answer-key (first word before `·`, em-dash, or `-`).
pub fn normalize_answer(s: &str) -> String {
    let trimmed = s.trim();
    // Match `·`, em-dash (—), or hyphen, with optional surrounding whitespace.
    let re = Regex::new(r"\s*[·—-]\s*").unwrap();
    let first: String = re
        .split(trimmed)
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_string();
    first.to_ascii_lowercase()
}

/// Evaluate a `when:` clause against a set of resolved decision answers.
/// Returns `pass` | `fail` | `pending`. Pending = the referenced decision
/// has not yet been answered.
pub fn eval_when(clause: &WhenClause, decision_answers: &serde_json::Map<String, Value>) -> WhenResult {
    let ans = match decision_answers.get(&clause.ref_id) {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::Null) | None => return WhenResult::Pending,
        Some(v) if !v.is_null() => v.to_string(),
        _ => return WhenResult::Pending,
    };

    let na = normalize_answer(&ans);
    let vals: Vec<String> = clause.values.iter().map(|v| normalize_answer(v)).collect();
    match clause.op {
        WhenOp::In => {
            if vals.contains(&na) {
                WhenResult::Pass
            } else {
                WhenResult::Fail
            }
        }
        WhenOp::Eq => {
            if vals.first().map(|v| v == &na).unwrap_or(false) {
                WhenResult::Pass
            } else {
                WhenResult::Fail
            }
        }
    }
}

/// Result of a `when:` evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhenResult {
    Pass,
    Fail,
    Pending,
}

impl WhenResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            WhenResult::Pass => "pass",
            WhenResult::Fail => "fail",
            WhenResult::Pending => "pending",
        }
    }
}

// =============================================================================
// Main parser
// =============================================================================

/// Parse a playbook markdown string into a step tree.
pub fn parse_playbook(src: &str) -> ParsedStepTree {
    let lines: Vec<&str> = src.split('\n').collect();
    let mut out = ParsedStepTree::default();
    let mut step_id_counter: u32 = 0;
    let mut decision_counter: u32 = 0;

    // Index of the current phase in out.phases; None while we're still in intro.
    let mut phase_idx: Option<usize> = None;
    let mut cur_step: Option<PendingStep> = None;
    let mut step_body: Vec<String> = Vec::new();

    // `baseline` and `lead` are the two step kinds hunts add (NAN-2238). They
    // are parsed by the shared parser rather than a second one: a hunt is the
    // same authoring language, and a separate parser would drift the moment
    // either side gained a feature.
    //
    // The narrowing runs the other way — hunts may not use `decision`,
    // `review` or `action` (nobody is present to decide or review, and an
    // unattended process on a cron must not change the world). That is enforced
    // at import by `crate::hunts::spec`, not here, because this parser is also
    // how the UI renders a doc and refusing to parse a step would hide the
    // very thing the reviewer needs to see.
    let slash_re = Regex::new(
        r"^/(query|pivot|enrichment|baseline|lead|decision|action|review|note):\s*(.*)$",
    )
    .unwrap();
    let h1_re = Regex::new(r"^#\s+(.*)$").unwrap();
    let h2_re = Regex::new(r"^##\s+(.*)$").unwrap();

    let mut i = 0usize;
    while i < lines.len() {
        let raw = lines[i];

        // Inside a step, indented body lines belong to it.
        if cur_step.is_some() && is_indented(raw, 2) {
            step_body.push(strip_one_indent(raw, 2));
            i += 1;
            continue;
        }
        if cur_step.is_some() && is_indented(raw, 4) {
            step_body.push(strip_one_indent(raw, 2));
            i += 1;
            continue;
        }
        // Blank line inside a step — only ends the step if the next non-blank
        // line is not indented.
        if cur_step.is_some() && raw.trim().is_empty() {
            let nxt = lines.get(i + 1).copied().unwrap_or("");
            if !is_indented(nxt, 2) {
                close_step(
                    &mut cur_step,
                    &mut step_body,
                    &mut out,
                    &mut phase_idx,
                    &mut decision_counter,
                );
            } else {
                step_body.push(String::new());
            }
            i += 1;
            continue;
        }

        // Not inside a step body — close any pending step and handle structure.
        close_step(
            &mut cur_step,
            &mut step_body,
            &mut out,
            &mut phase_idx,
            &mut decision_counter,
        );

        // H1 = title
        if let Some(caps) = h1_re.captures(raw) {
            out.title = caps.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
            i += 1;
            continue;
        }

        // H2 = phase
        if let Some(caps) = h2_re.captures(raw) {
            let heading = caps.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
            out.phases.push(PlaybookPhase {
                heading,
                body: Vec::new(),
                steps: Vec::new(),
            });
            phase_idx = Some(out.phases.len() - 1);
            i += 1;
            continue;
        }

        // Slash command
        if let Some(caps) = slash_re.captures(raw) {
            step_id_counter += 1;
            let kind = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            let label = caps
                .get(2)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            cur_step = Some(PendingStep {
                id: format!("s{}", step_id_counter),
                kind,
                label,
            });
            step_body = Vec::new();
            i += 1;
            continue;
        }

        // Plain prose
        if let Some(pi) = phase_idx {
            out.phases[pi].body.push(raw.to_string());
        } else {
            out.intro.push(raw.to_string());
        }
        i += 1;
    }

    // Close any trailing step
    close_step(
        &mut cur_step,
        &mut step_body,
        &mut out,
        &mut phase_idx,
        &mut decision_counter,
    );

    trim_trailing_empty(&mut out.intro);
    for phase in out.phases.iter_mut() {
        trim_trailing_empty(&mut phase.body);
    }

    // NAN-453: if the author wrote slash-command steps without any `## Phase`
    // headings (common for short playbooks like lateral_movement /
    // c2_beacon), the step collector parked them on the root-level
    // `out.steps` array. The UI only renders `out.phases`, so those steps
    // were orphaned. Synthesize a default phase to keep them visible.
    if !out.steps.is_empty() && out.phases.is_empty() {
        let orphaned = std::mem::take(&mut out.steps);
        out.phases.push(PlaybookPhase {
            heading: "Steps".to_string(),
            body: Vec::new(),
            steps: orphaned,
        });
    }

    out
}

fn trim_trailing_empty(v: &mut Vec<String>) {
    while matches!(v.last(), Some(s) if s.trim().is_empty()) {
        v.pop();
    }
}

fn is_indented(line: &str, n: usize) -> bool {
    let bytes = line.as_bytes();
    if bytes.len() < n + 1 {
        return false;
    }
    for b in bytes.iter().take(n) {
        if *b != b' ' {
            return false;
        }
    }
    // Must have non-whitespace after the indent
    bytes[n] != b' ' && bytes[n] != b'\t'
}

fn strip_one_indent(line: &str, n: usize) -> String {
    if line.len() >= n && line.as_bytes().iter().take(n).all(|b| *b == b' ') {
        line[n..].to_string()
    } else {
        line.to_string()
    }
}

// =============================================================================
// Step body YAML-ish parser
// =============================================================================

struct PendingStep {
    id: String,
    kind: String,
    label: String,
}

fn close_step(
    cur: &mut Option<PendingStep>,
    body: &mut Vec<String>,
    out: &mut ParsedStepTree,
    phase_idx: &mut Option<usize>,
    decision_counter: &mut u32,
) {
    let Some(pending) = cur.take() else {
        body.clear();
        return;
    };
    let parsed = parse_step_body(body);
    *body = Vec::new();

    let mut step = PlaybookStep {
        id: pending.id,
        kind: pending.kind.clone(),
        label: pending.label,
        params: Value::Object(Map::new()),
        auto_result: None,
        suggested: None,
        suggested_conf: None,
        note_required_on: None,
        options: None,
        decision_id: None,
        when: None,
    };

    // author-provided id overrides the auto id
    if let Some(id_val) = parsed.get("id") {
        if let Some(s) = value_to_plain_string(id_val) {
            step.id = s;
        }
    }

    // when:
    if let Some(when_val) = parsed.get("when") {
        if let Some(s) = value_to_plain_string(when_val) {
            step.when = parse_when_clause(&s);
        }
    }

    // Decisions
    if step.kind == "decision" {
        if let Some(Value::Array(arr)) = parsed.get("options") {
            step.options = Some(arr.clone());
        } else if let Some(v) = parsed.get("options") {
            // Accept inline list like `options: [yes, no]`
            step.options = parse_inline_array(v);
        }
        let nro = parsed
            .get("note_required_on")
            .or_else(|| parsed.get("note-required-on"));
        if let Some(v) = nro {
            step.note_required_on = value_to_plain_string(v);
        }
        step.suggested = parsed.get("_suggested").cloned();
        step.suggested_conf = parsed
            .get("_suggested_confidence")
            .and_then(|v| v.as_f64());

        *decision_counter += 1;
        let decision_id = if let Some(id_val) = parsed.get("id") {
            value_to_plain_string(id_val).unwrap_or_else(|| format!("d{}", decision_counter))
        } else {
            format!("d{}", decision_counter)
        };
        step.decision_id = Some(decision_id.clone());
        // If author didn't override top-level step.id, use decisionId
        if parsed.get("id").is_none() {
            step.id = decision_id;
        }
    }

    if let Some(auto) = parsed.get("_auto_result") {
        step.auto_result = Some(auto.clone());
    }

    // Clean internal keys out of visible params
    let mut rest = parsed.clone();
    for k in [
        "options",
        "note_required_on",
        "note-required-on",
        "_suggested",
        "_suggested_confidence",
        "_auto_result",
        "id",
        "when",
    ] {
        rest.remove(k);
    }
    step.params = Value::Object(rest);

    // Append to phase or top-level (rare)
    if let Some(pi) = *phase_idx {
        out.phases[pi].steps.push(step);
    } else {
        out.steps.push(step);
    }
}

/// Coerce a YAML-ish scalar to a JSON value.
fn coerce(v: &str) -> Value {
    let s = v.trim();
    if s == "true" {
        return Value::Bool(true);
    }
    if s == "false" {
        return Value::Bool(false);
    }
    if s == "null" {
        return Value::Null;
    }
    if let Ok(i) = s.parse::<i64>() {
        // keep as number
        return json!(i);
    }
    if let Ok(f) = s.parse::<f64>() {
        if s.contains('.') {
            return json!(f);
        }
    }
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        return Value::String(strip_quotes(s).to_string());
    }
    Value::String(s.to_string())
}

fn value_to_plain_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => None,
        _ => None,
    }
}

fn parse_inline_array(v: &Value) -> Option<Vec<Value>> {
    let s = match v {
        Value::String(s) => s.trim().to_string(),
        _ => return None,
    };
    if !s.starts_with('[') || !s.ends_with(']') {
        return None;
    }
    let inner = &s[1..s.len() - 1];
    Some(
        inner
            .split(',')
            .map(|item| coerce(item))
            .collect(),
    )
}

/// Parse the indented body of a slash-command block into a JSON object.
pub fn parse_step_body(lines: &[String]) -> Map<String, Value> {
    let mut iter_idx: usize = 0;
    let base_indent = first_non_empty_indent(lines).unwrap_or(0);
    parse_block(lines, &mut iter_idx, base_indent)
}

fn first_non_empty_indent(lines: &[String]) -> Option<usize> {
    for l in lines {
        if !l.trim().is_empty() {
            return Some(leading_spaces(l));
        }
    }
    None
}

fn leading_spaces(s: &str) -> usize {
    s.chars().take_while(|c| *c == ' ').count()
}

fn parse_block(lines: &[String], i: &mut usize, base_indent: usize) -> Map<String, Value> {
    let kv_re = Regex::new(r"^( *)([\w-]+):\s*(.*)$").unwrap();
    let list_marker_re = Regex::new(r"^ *-\s").unwrap();
    let list_item_re = Regex::new(r"^ *-\s+(.*)$").unwrap();

    let mut result: Map<String, Value> = Map::new();

    while *i < lines.len() {
        let raw = &lines[*i];
        if raw.trim().is_empty() {
            *i += 1;
            continue;
        }
        let indent = leading_spaces(raw);
        if indent < base_indent {
            return result;
        }
        if list_marker_re.is_match(raw) {
            // Parent block should have become an array — bail out to caller.
            return result;
        }

        let caps = match kv_re.captures(raw) {
            Some(c) => c,
            None => {
                *i += 1;
                continue;
            }
        };
        let pad = caps.get(1).map(|m| m.as_str()).unwrap_or("").len();
        let key = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
        let val = caps.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();

        if pad != base_indent {
            *i += 1;
            continue;
        }
        *i += 1;

        if val.is_empty() {
            // Either a list or a nested block — look at next non-empty line.
            let mut j = *i;
            while j < lines.len() && lines[j].trim().is_empty() {
                j += 1;
            }
            let peek = lines.get(j).cloned().unwrap_or_default();
            let peek_indent = leading_spaces(&peek);

            if list_marker_re.is_match(&peek) && peek_indent > base_indent {
                // list
                let mut arr: Vec<Value> = Vec::new();
                while *i < lines.len() {
                    let ln = &lines[*i];
                    if ln.trim().is_empty() {
                        *i += 1;
                        continue;
                    }
                    let li = leading_spaces(ln);
                    if li <= base_indent {
                        break;
                    }
                    if let Some(lcaps) = list_item_re.captures(ln) {
                        let item = lcaps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                        arr.push(coerce(item));
                        *i += 1;
                    } else {
                        break;
                    }
                }
                result.insert(key, Value::Array(arr));
            } else if peek_indent > base_indent {
                // nested map
                let nested = parse_block(lines, i, peek_indent);
                result.insert(key, Value::Object(nested));
            } else {
                result.insert(key, Value::String(String::new()));
            }
        } else {
            result.insert(key, coerce(val.trim()));
        }
    }

    result
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const CRED_REUSE: &str = r#"# Credential reuse · offboarded / dormant account

Agent-first identity investigation for the pattern **"account that shouldn't be active is active."**

## Phase 1 · establish state

/enrichment: HR system · is the user currently employed
  system: workday
  employee: {{entity.user}}
  fields: status, end_date, manager, team

/query: last 30d of auth events for this user
  window: 30d
  from:   auth-events
  where:  user = "{{entity.user}}"

## Phase 2 · decide what we're looking at

/decision: is this a live user account?
  options:
    - yes · user is employed and active
    - no · user is offboarded
    - partial · employed but on leave / role changed
  note_required_on: no, partial

/review: check the key-use timeline against the HR end_date
  hint: "any key use after end_date is the smoking gun"

## Phase 3 · containment

/action: rotate or disable the compromised credential
  kind:   iam.key_rotate
  target: {{entity.key_id}}
  danger: medium
  reversible: true
  when: d1 in [no, partial]
"#;

    #[test]
    fn parse_title_and_phases() {
        let tree = parse_playbook(CRED_REUSE);
        assert_eq!(
            tree.title, "Credential reuse · offboarded / dormant account",
            "title parsed from H1"
        );
        assert_eq!(tree.phases.len(), 3, "three phases");
        assert_eq!(tree.phases[0].heading, "Phase 1 · establish state");
        assert_eq!(tree.phases[1].heading, "Phase 2 · decide what we're looking at");
        assert_eq!(tree.phases[2].heading, "Phase 3 · containment");
    }

    #[test]
    fn parse_step_kinds_and_counts() {
        let tree = parse_playbook(CRED_REUSE);
        assert_eq!(tree.phases[0].steps.len(), 2);
        assert_eq!(tree.phases[0].steps[0].kind, "enrichment");
        assert_eq!(tree.phases[0].steps[1].kind, "query");
        assert_eq!(tree.phases[1].steps.len(), 2);
        assert_eq!(tree.phases[1].steps[0].kind, "decision");
        assert_eq!(tree.phases[1].steps[1].kind, "review");
        assert_eq!(tree.phases[2].steps.len(), 1);
        assert_eq!(tree.phases[2].steps[0].kind, "action");
    }

    /// NAN-453: playbooks that jump straight from H1 title into slash-command
    /// steps (no `## Phase` H2) — e.g. `network/lateral_movement.md` — used
    /// to park steps on `out.steps` where the UI couldn't render them.
    /// Parser now synthesizes a default "Steps" phase so they're visible.
    #[test]
    fn synthesizes_phase_for_phaseless_playbooks() {
        const NO_PHASES: &str = "\
# Lateral movement

/query: every authenticated session from this host in 8h
  window: 8h
  from:   edr-network

/action: isolate source + all touched destinations
  kind:   edr.isolate_many
  danger: high
";
        let tree = parse_playbook(NO_PHASES);
        // Synthetic phase picked up the orphaned steps.
        assert_eq!(tree.phases.len(), 1);
        assert_eq!(tree.phases[0].heading, "Steps");
        assert_eq!(tree.phases[0].steps.len(), 2);
        assert_eq!(tree.phases[0].steps[0].kind, "query");
        assert_eq!(tree.phases[0].steps[1].kind, "action");
        // No orphans left at the root.
        assert!(tree.steps.is_empty());
    }

    #[test]
    fn parse_decision_options_and_note_required() {
        let tree = parse_playbook(CRED_REUSE);
        let decision = &tree.phases[1].steps[0];
        assert_eq!(decision.kind, "decision");
        let options = decision.options.as_ref().expect("options present");
        assert_eq!(options.len(), 3);
        assert_eq!(
            decision.note_required_on.as_deref(),
            Some("no, partial")
        );
        assert_eq!(decision.decision_id.as_deref(), Some("d1"));
        // Since author didn't override id, step.id should equal decision_id.
        assert_eq!(decision.id, "d1");
    }

    #[test]
    fn parse_when_clause_on_action() {
        let tree = parse_playbook(CRED_REUSE);
        let action = &tree.phases[2].steps[0];
        let when = action.when.as_ref().expect("when clause present");
        assert_eq!(when.ref_id, "d1");
        assert_eq!(when.op, WhenOp::In);
        assert_eq!(when.values, vec!["no".to_string(), "partial".to_string()]);
    }

    #[test]
    fn parse_step_params_preserve_yaml_ish() {
        let tree = parse_playbook(CRED_REUSE);
        let enrichment = &tree.phases[0].steps[0];
        let params = &enrichment.params;
        assert_eq!(params.get("system").and_then(Value::as_str), Some("workday"));
        assert_eq!(
            params.get("fields").and_then(Value::as_str),
            Some("status, end_date, manager, team")
        );
    }

    #[test]
    fn parse_when_clause_eq() {
        let clause = parse_when_clause("d1 = yes").unwrap();
        assert_eq!(clause.ref_id, "d1");
        assert_eq!(clause.op, WhenOp::Eq);
        assert_eq!(clause.values, vec!["yes".to_string()]);
    }

    #[test]
    fn parse_when_clause_in() {
        let clause = parse_when_clause("d1 in [yes, partial]").unwrap();
        assert_eq!(clause.ref_id, "d1");
        assert_eq!(clause.op, WhenOp::In);
        assert_eq!(clause.values, vec!["yes".to_string(), "partial".to_string()]);
    }

    #[test]
    fn parse_when_clause_rejects_junk() {
        assert!(parse_when_clause("not a clause").is_none());
        assert!(parse_when_clause("").is_none());
    }

    #[test]
    fn normalize_answer_handles_separator_chars() {
        assert_eq!(normalize_answer("yes · user is active"), "yes");
        assert_eq!(normalize_answer("no - user is offboarded"), "no");
        assert_eq!(normalize_answer("Partial"), "partial");
    }

    #[test]
    fn eval_when_pass_fail_pending() {
        let clause = parse_when_clause("d1 in [yes, partial]").unwrap();
        let mut answers = Map::new();
        assert_eq!(
            eval_when(&clause, &answers),
            WhenResult::Pending,
            "no answer yet"
        );
        answers.insert("d1".into(), Value::String("yes".into()));
        assert_eq!(eval_when(&clause, &answers), WhenResult::Pass);
        answers.insert("d1".into(), Value::String("no".into()));
        assert_eq!(eval_when(&clause, &answers), WhenResult::Fail);
    }

    #[test]
    fn intro_captured_before_first_phase() {
        let tree = parse_playbook(CRED_REUSE);
        assert!(
            tree.intro.iter().any(|l| l.contains("Agent-first identity")),
            "intro should include prose before Phase 1"
        );
    }
}

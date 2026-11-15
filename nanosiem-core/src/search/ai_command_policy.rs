// SPDX-License-Identifier: AGPL-3.0-or-later
//! The nPL command policy for searches written by an AI (NAN-5437).
//!
//! An AI agent writes nPL from context that can carry attacker-controlled
//! text (log rows, case titles, notebook entries). A search it runs must not
//! be able to reach outside nano or change anything, whatever that text
//! steers it to write. So a search whose ORIGIN is AI may only use commands
//! that read and transform data; the server refuses the rest before anything
//! runs. Filtering the model's text in the AI layer is not relied on.
//!
//! # Origin
//!
//! The origin rides on the request's admission query class
//! ([`crate::search::admission::QueryClass`]): an `agent` search is AI-origin.
//! That class is already set, and can only ever be lowered to `agent`, by:
//!
//! - an API key nano Desktop mints for its agents (the nano MCP `search` tool,
//!   recon, hunt runner and hunt sweep), whatever headers the client sends;
//! - the `x-nano-query-class: agent` header (any MCP / agent API caller);
//! - [`with_ai_origin`], which every in-process meloD / pivt path that runs
//!   model-written nPL wraps its search in.
//!
//! The class follows spawned search work ([`crate::search::request_actor::inherit`]).
//! A durable background job is checked when it is submitted.
//!
//! # Policy
//!
//! [`check_ai_query`] walks the whole query, every subsearch included, and
//! classifies each command with an exhaustive match: a new command does not
//! compile until it is placed here. Refused by default:
//!
//! | Command | Why |
//! |---|---|
//! | `inputlookup url=…` | fetches an external URL (row values can be substituted into it). `inputlookup <table>` reads an internal lookup table and stays allowed. |
//! | `ai` | sends rows to the AI provider |
//! | `output` | writes results to a destination |
//!
//! An administrator can allow any of these for AI searches with the
//! `ai_search_allowed_commands` search setting
//! ([`crate::settings::SearchQueryLimitsConfig`]). Human searches are never
//! checked.
//!
//! A refusal is an ordinary search error the model can read and recover from,
//! and is audited ([`actions::SEARCH_AI_COMMAND_REFUSED`]).

use std::future::Future;
use std::sync::{Arc, OnceLock};

use serde_json::json;
use uuid::Uuid;

use crate::audit::{actions, AuditEvent, AuditSource};
use crate::query::{Command, Query, SearchExpr};
use crate::search::admission::{self, QueryClass};

/// Who wrote the search being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchOrigin {
    /// An analyst (or a human-authored artifact: a rule, a dashboard, a report).
    Human,
    /// An AI agent (pivt, meloD tool loops, the nano MCP, Desktop agents).
    Ai,
}

/// The current request's search origin.
pub fn current_search_origin() -> SearchOrigin {
    match admission::current_query_class() {
        QueryClass::Agent => SearchOrigin::Ai,
        QueryClass::Human => SearchOrigin::Human,
    }
}

/// Run `future` as an AI-origin search. Every in-process path that executes
/// model-written nPL wraps its search call in this. `actor` is the member the
/// AI acts for, recorded on a refusal's audit event.
pub async fn with_ai_origin<F: Future>(actor: Option<Uuid>, future: F) -> F::Output {
    let classed = admission::with_query_class(QueryClass::Agent, future);
    match actor.filter(|actor| !actor.is_nil()) {
        Some(actor) => crate::search::request_actor::with_request_actor(actor, classed).await,
        None => classed.await,
    }
}

/// The commands refused to AI searches by default, as written in nPL. These
/// are the only names the admin allowlist accepts.
pub const RESTRICTED_COMMANDS: [&str; 3] = ["inputlookup", "ai", "output"];

/// A command an AI search may not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiCommandRefusal {
    /// The command as written in nPL (one of [`RESTRICTED_COMMANDS`]).
    pub command: &'static str,
    /// Why, in a few words.
    pub reason: &'static str,
}

impl std::fmt::Display for AiCommandRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "command `{}` is not available to AI searches ({}). Rewrite the search \
             without it: searching, filtering, stats, table, eval and the other read-only \
             commands are available. An administrator can allow it for AI searches in the \
             search settings.",
            self.command, self.reason
        )
    }
}

/// What one command does, for the policy.
enum Effect {
    /// Reads and transforms data inside nano.
    ReadOnly,
    /// Reaches outside nano or writes.
    Restricted(AiCommandRefusal),
}

fn restricted(command: &'static str, reason: &'static str) -> Effect {
    Effect::Restricted(AiCommandRefusal { command, reason })
}

fn effect(command: &Command) -> Effect {
    // Exhaustive on purpose: a new command must be classified here.
    match command {
        Command::InputLookup { url, .. } => {
            // The same test execution routes on: anything it does not treat
            // as an internal table goes to the HTTP fetcher.
            if crate::inputlookup::internal_lookup_table(&url.template).is_some() {
                Effect::ReadOnly
            } else {
                restricted("inputlookup", "it fetches an external URL")
            }
        }
        Command::Ai { .. } => restricted("ai", "it sends rows to the AI provider"),
        Command::Output { .. } => restricted("output", "it writes results to a destination"),
        Command::Stats { .. }
        | Command::Chart { .. }
        | Command::StreamStats { .. }
        | Command::Where { .. }
        | Command::Sort { .. }
        | Command::Head { .. }
        | Command::Tail { .. }
        | Command::Timechart { .. }
        | Command::Table { .. }
        | Command::Rename { .. }
        | Command::Lookup { .. }
        | Command::Eval { .. }
        | Command::Dedup { .. }
        | Command::Bin { .. }
        | Command::Rex { .. }
        | Command::Fields { .. }
        | Command::Top { .. }
        | Command::Rare { .. }
        | Command::Transaction { .. }
        | Command::Fillnull { .. }
        | Command::Mvexpand { .. }
        | Command::Spath { .. }
        | Command::Append { .. }
        | Command::Join { .. }
        | Command::Format { .. }
        | Command::Return { .. }
        | Command::Risk { .. }
        | Command::Prevalence { .. }
        | Command::Sample { .. }
        | Command::Reverse
        | Command::EventStats { .. }
        | Command::Sequence { .. }
        | Command::Funnel { .. }
        | Command::Anomaly { .. }
        | Command::Tree { .. }
        | Command::ResolveIdentity { .. }
        | Command::Asset { .. }
        | Command::Cloud { .. }
        | Command::Lateral { .. }
        | Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. }
        | Command::Retro { .. }
        | Command::Baseline { .. } => Effect::ReadOnly,
    }
}

/// Check a parsed AI-origin query against the policy. `extra_allowed` is the
/// admin's allowlist of [`RESTRICTED_COMMANDS`] names (case-insensitive).
/// The first refused command found wins.
pub fn check_ai_query(query: &Query, extra_allowed: &[String]) -> Result<(), AiCommandRefusal> {
    walk_query(query, extra_allowed)
}

fn allowed_by_admin(command: &str, extra_allowed: &[String]) -> bool {
    extra_allowed
        .iter()
        .any(|name| name.trim().eq_ignore_ascii_case(command))
}

fn walk_query(query: &Query, extra_allowed: &[String]) -> Result<(), AiCommandRefusal> {
    match query {
        Query::Search(expr) => walk_expr(expr, extra_allowed),
        Query::Piped { source, command } => {
            walk_query(source, extra_allowed)?;
            walk_command(command, extra_allowed)
        }
    }
}

fn walk_command(command: &Command, extra_allowed: &[String]) -> Result<(), AiCommandRefusal> {
    if let Effect::Restricted(refusal) = effect(command) {
        if !allowed_by_admin(refusal.command, extra_allowed) {
            return Err(refusal);
        }
    }
    // Every place a command nests a query.
    match command {
        Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
            walk_query(subsearch, extra_allowed)
        }
        Command::Where { condition } => walk_expr(condition, extra_allowed),
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            for expr in [startswith, endswith].into_iter().flatten() {
                walk_expr(expr, extra_allowed)?;
            }
            Ok(())
        }
        Command::Sequence { conditions, .. } => {
            conditions
                .iter()
                .try_for_each(|expr| walk_expr(expr, extra_allowed))
        }
        Command::Funnel { steps, .. } => steps
            .iter()
            .try_for_each(|(_, expr)| walk_expr(expr, extra_allowed)),
        _ => Ok(()),
    }
}

fn walk_expr(expr: &SearchExpr, extra_allowed: &[String]) -> Result<(), AiCommandRefusal> {
    // Exhaustive on purpose: a new expression that can nest a query must be
    // walked here.
    match expr {
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            walk_expr(left, extra_allowed)?;
            walk_expr(right, extra_allowed)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => walk_expr(inner, extra_allowed),
        SearchExpr::InSubsearch { subsearch, .. } => walk_query(subsearch, extra_allowed),
        SearchExpr::Keyword(_)
        | SearchExpr::FieldFilter { .. }
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::EvalPredicate(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => Ok(()),
    }
}

/// Validate an admin allowlist: every entry must name one of
/// [`RESTRICTED_COMMANDS`]. Returns the normalized (lowercase, deduplicated,
/// sorted) list.
pub fn normalize_allowlist(names: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if !RESTRICTED_COMMANDS.contains(&name.as_str()) {
            return Err(format!(
                "ai_search_allowed_commands: `{name}` is not a restricted command. \
                 Allowed values: {}",
                RESTRICTED_COMMANDS.join(", ")
            ));
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Enforcement + audit
// ---------------------------------------------------------------------------

/// Query text on the audit event is truncated to this many bytes.
const MAX_AUDIT_QUERY_BYTES: usize = 1024;

/// Where refusal audit events go. Implementations must not block.
pub trait AiCommandAuditSink: Send + Sync {
    fn submit(&self, event: AuditEvent);
}

static AUDIT_SINK: OnceLock<Arc<dyn AiCommandAuditSink>> = OnceLock::new();

/// Install the process's audit sink (once, at boot). Later calls are ignored.
pub fn install_audit_sink(sink: Arc<dyn AiCommandAuditSink>) {
    let _ = AUDIT_SINK.set(sink);
}

/// Sink over the platform [`crate::audit::AuditEmitter`].
pub struct EmitterAiCommandAuditSink {
    emitter: Arc<crate::audit::AuditEmitter>,
}

impl EmitterAiCommandAuditSink {
    pub fn new(emitter: Arc<crate::audit::AuditEmitter>) -> Arc<dyn AiCommandAuditSink> {
        Arc::new(Self { emitter })
    }
}

impl AiCommandAuditSink for EmitterAiCommandAuditSink {
    fn submit(&self, event: AuditEvent) {
        let emitter = self.emitter.clone();
        tokio::spawn(async move {
            if let Err(error) = emitter.emit(&event).await {
                tracing::error!(%error, action = %event.action, "AI search refusal audit could not be emitted");
            }
        });
    }
}

/// The audit event for a refused AI search.
pub fn refusal_audit_event(
    actor: Option<Uuid>,
    refusal: &AiCommandRefusal,
    query: &str,
    entry_point: &str,
) -> AuditEvent {
    AuditEvent::builder(AuditSource::Search, actions::SEARCH_AI_COMMAND_REFUSED)
        .actor(actor, None)
        .resource("search", None, Some(refusal.command.to_string()))
        .success(false)
        .details(json!({
            "origin": "ai",
            "command": refusal.command,
            "reason": refusal.reason,
            "query": truncate_bytes(query, MAX_AUDIT_QUERY_BYTES),
            "entry_point": entry_point,
        }))
        .build()
}

fn truncate_bytes(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// The search engine's hook, called right after a query parses. A no-op for
/// a human search. For an AI search, refuses (and audits) a restricted
/// command the admin has not allowed.
pub fn enforce(
    query_text: &str,
    parsed: &Query,
    extra_allowed: &[String],
    entry_point: &str,
) -> Result<(), crate::search::SearchError> {
    if current_search_origin() != SearchOrigin::Ai {
        return Ok(());
    }
    let Err(refusal) = check_ai_query(parsed, extra_allowed) else {
        return Ok(());
    };
    let actor = crate::search::request_actor::current_request_actor();
    tracing::warn!(
        command = refusal.command,
        actor = ?actor,
        entry_point,
        "AI search refused: restricted nPL command"
    );
    if let Some(sink) = AUDIT_SINK.get() {
        sink.submit(refusal_audit_event(actor, &refusal, query_text, entry_point));
    }
    Err(crate::search::SearchError::SqlValidationError(refusal.to_string()))
}

/// [`enforce`] on query TEXT, for a handler that may answer a search from a
/// cache, a finished job or another caller's identical run before the engine
/// parses it: an AI search is refused consistently, whichever path answers.
/// Text that does not parse is left to the engine to report.
pub fn enforce_text(
    query_text: &str,
    extra_allowed: &[String],
    entry_point: &str,
) -> Result<(), crate::search::SearchError> {
    if current_search_origin() != SearchOrigin::Ai {
        return Ok(());
    }
    let Ok((cleaned, _, _)) = crate::search::service::extract_time_bounds_at(query_text, chrono::Utc::now()) else {
        return Ok(());
    };
    match crate::query::parse_query(&cleaned) {
        Ok(parsed) => enforce(query_text, &parsed, extra_allowed, entry_point),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
#[path = "ai_command_policy_tests.rs"]
mod tests;

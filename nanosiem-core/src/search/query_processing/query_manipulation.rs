// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query manipulation and transformation utilities
//!
//! This module provides functions to transform and filter parsed query ASTs,
//! particularly for handling prevalence commands and their interaction with other commands.

use std::collections::BTreeSet;

use super::command_extraction::extract_post_ai_commands;
use crate::query::{Command, Comparator, Query, SearchExpr, TableField, Value};
use crate::search::field_utils::{is_post_processing_field, normalize_field_alias};

/// Strip commands that come after prevalence enrichment from the query
/// Returns a new query with only the commands up to and including prevalence
pub fn strip_post_prevalence_commands(query: &Query) -> Query {
    strip_post_prevalence_recursive(query, false).0
}

/// Strip prevalence commands AND all commands after them from the query
/// This is used for JOIN-based prevalence filtering where we need the base query
/// without any prevalence-related processing
pub fn strip_prevalence_and_after(query: &Query) -> Query {
    strip_prevalence_and_after_recursive(query, false).0
}

/// Recursively strip prevalence and all commands after it
/// Returns (modified_query, found_prevalence)
fn strip_prevalence_and_after_recursive(query: &Query, parent_found: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            let (new_source, source_found) =
                strip_prevalence_and_after_recursive(source, parent_found);

            // Check if this is a prevalence command
            let is_prevalence = matches!(command, Command::Prevalence { .. });

            // If we found prevalence in the source or this is prevalence, skip this and all subsequent commands
            if source_found || is_prevalence {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    false,
                )
            }
        }
    }
}

/// Recursively strip commands after any prevalence command
/// Returns (modified_query, found_prevalence)
fn strip_post_prevalence_recursive(query: &Query, parent_found_prevalence: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            // First process the source
            let (new_source, source_found_prevalence) =
                strip_post_prevalence_recursive(source, parent_found_prevalence);

            // Check if this is any prevalence command (enrich or filter-only)
            let is_prevalence = matches!(command, Command::Prevalence { .. });
            let found_prevalence = source_found_prevalence || is_prevalence;

            // If we already found prevalence in the source and this is not the prevalence command itself,
            // skip this command (it will be applied as post-processing)
            if source_found_prevalence && !is_prevalence {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    found_prevalence,
                )
            }
        }
    }
}

/// Strip inputlookup commands AND all commands after them from the query
/// This is used because inputlookup enrichment happens in post-processing,
/// so commands that reference inputlookup_* fields must also be post-processed
pub fn strip_inputlookup_and_after(query: &Query) -> Query {
    strip_inputlookup_and_after_recursive(query, false).0
}

/// Recursively strip inputlookup and all commands after it
/// Returns (modified_query, found_inputlookup)
fn strip_inputlookup_and_after_recursive(query: &Query, parent_found: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            let (new_source, source_found) =
                strip_inputlookup_and_after_recursive(source, parent_found);

            // Check if this is an inputlookup command
            let is_inputlookup = matches!(command, Command::InputLookup { .. });

            // If we found inputlookup in the source or this is inputlookup, skip this and all subsequent commands
            if source_found || is_inputlookup {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    false,
                )
            }
        }
    }
}

/// Strip ai command and all commands after it from the query.
/// The AI and post-AI commands are handled in post-processing, so they need
/// to be removed before SQL generation.
///
/// If post-AI commands include `| table`, a filtered version (without ai_* fields)
/// is re-appended so the SQL generator selects the right database columns.
pub fn strip_ai_and_after(query: &Query) -> Query {
    let stripped = strip_ai_and_after_recursive(query, false).0;

    // Check if post-AI commands included a | table — if so, re-inject the
    // database-safe fields so the SQL generator selects them (e.g., url, timestamp).
    // Field names are normalized (e.g., _time → timestamp) so the SQL generator
    // can resolve them against actual column names.
    let post_ai = extract_post_ai_commands(query);
    if let Some(table_cmd) = post_ai.iter().find(|c| matches!(c, Command::Table { .. })) {
        if let Command::Table { fields } = table_cmd {
            let db_fields: Vec<_> = fields
                .iter()
                .filter(|f| !is_post_processing_field(&f.name))
                .map(|f| TableField {
                    name: normalize_field_alias(&f.name).to_string(),
                    alias: f.alias.clone(),
                })
                .collect();
            if !db_fields.is_empty() {
                return Query::Piped {
                    source: Box::new(stripped),
                    command: Command::Table { fields: db_fields },
                };
            }
        }
    }

    stripped
}

/// Strip lateral command and all commands after it from the query.
/// Lateral and post-lateral commands are handled in post-processing.
pub fn strip_lateral_and_after(query: &Query) -> Query {
    strip_lateral_and_after_recursive(query, false).0
}

/// Enforce a source_type exclusion at the AST level.
///
/// EVERY scan in the query tree — the main search AND every subsearch reachable
/// through any command (`join`, `append`, `field IN [ … ]`, plus any subsearch
/// nested inside `where` / `transaction` / `sequence` / `funnel` conditions) —
/// is rewritten as:
///
/// `(<the user's expression>) AND source_type != "<excluded_source_type>"`
///
/// (for `"audit"` — the only production input; any other single source takes
/// the `source_type NOT IN (…)` form, see [`mandatory_exclusion`])
///
/// NAN-1794 (security): this conjunct is UNCONDITIONAL and MANDATORY. It is
/// deliberately *not* skipped when the user's query already "mentions"
/// `source_type`. The previous presence-check was semantically unsound — it
/// reported "already excluded" whenever a `source_type != "audit"` node appeared
/// ANYWHERE in the tree, including in positions that invert or weaken it, and
/// two crafted forms defeated it:
///
///  * `NOT (source_type != "audit")` — the check walked into the `Not`, saw the
///    exclusion term and suppressed injection; the predicate actually means
///    `source_type == "audit"`.
///  * `source_type!="audit" OR source_type="audit"` — the check was satisfied by
///    the left `OR` arm while the right arm selected audit rows.
///
/// The sound model is structural, not textual: `X AND source_type != "audit"`
/// cannot match an audit row for ANY `X`, however the user wrote `X`. So we
/// always AND, and never detect-and-skip. Re-introducing a "the user already
/// wrote it" optimization is a security regression unless it can PROVE the
/// identical conjunct is already ANDed at the TOP level (a mention under a
/// `Not`, or in an `Or` arm, must never satisfy it). The cost it would save is
/// one column compare against a hot, bloom-indexed column — so the honest
/// answer is: don't.
///
/// NAN-1799: this gate is now generalized to a denied-SET (per-source RBAC
/// scoping). This function is kept as a thin single-source wrapper so every
/// existing caller (and every NAN-1794 test) is untouched; the deny-set entry
/// point is [`enforce_source_scope`].
pub fn enforce_source_type_exclusion(query: &Query, excluded_source_type: &str) -> Query {
    let deny_set = BTreeSet::from([excluded_source_type.to_string()]);
    inject_source_type_exclusion_recursive(query, &deny_set)
}

/// The mandatory conjunct ANDed onto every scan.
///
/// NAN-1799 — EXACT emitted AST shape (load-bearing for the OTLP strip matcher
/// in `clickhouse_sql_gen::strip_injected_audit_gate`, which must structurally
/// recognize the injected conjunct; see the wrap-shape note on
/// [`inject_source_type_exclusion_recursive`]):
///
///  * `deny_set == {"audit"}` exactly (the legacy audit gate) — byte-identical
///    to the pre-NAN-1799 output so every NAN-1794 test and the NAN-1733 OTLP
///    strip keep matching:
///
///    ```ignore
///    SearchExpr::FieldFilter {
///        field: "source_type".to_string(),
///        op: Comparator::Ne,
///        value: Value::String("audit".to_string()),
///    }
///    ```
///
///  * any other non-empty deny set — ONE negated IN-list, values in `BTreeSet`
///    iteration order (i.e. lexicographically sorted, deterministic):
///
///    ```ignore
///    SearchExpr::InList {
///        field: "source_type".to_string(),
///        values: deny_set.iter().map(|s| Value::String(s.clone())).collect(),
///        negated: true,
///    }
///    ```
///
/// Either conjunct is wrapped at each scan leaf as the RHS of
/// `SearchExpr::And(Box::new(SearchExpr::Group(<gated user expr>)), Box::new(<conjunct>))`
/// — only the conjunct builder changed for NAN-1799, never the wrap shape.
///
/// Callers guarantee `deny_set` is non-empty ([`enforce_source_scope`] returns
/// the query unchanged for an empty set before any injection runs); an empty
/// set here would emit an unparseable `source_type NOT IN ()`.
fn mandatory_exclusion(deny_set: &BTreeSet<String>) -> SearchExpr {
    debug_assert!(
        !deny_set.is_empty(),
        "mandatory_exclusion requires a non-empty deny set; empty sets must \
         short-circuit in enforce_source_scope"
    );
    if deny_set.len() == 1 && deny_set.contains("audit") {
        // Legacy audit-gate shape — kept byte-identical (NAN-704 / NAN-1794).
        SearchExpr::FieldFilter {
            field: "source_type".to_string(),
            op: Comparator::Ne,
            value: Value::String("audit".to_string()),
        }
    } else {
        SearchExpr::InList {
            field: "source_type".to_string(),
            values: deny_set.iter().map(|s| Value::String(s.clone())).collect(),
            negated: true,
        }
    }
}

/// Parse a piped-query string, inject `source_type != "audit"` at the AST
/// level, and serialize back to a string. Used by every authenticated
/// search surface to gate audit-log access for users without
/// `audit:view` permission.
///
/// NAN-704: extracted from duplicated private helpers in
/// `nanosiem-search/src/handlers/{search,streaming}.rs` so that
/// `nanosiem-api`'s dashboard panel handler (and any future caller)
/// shares one canonical implementation. Drift on one site now surfaces
/// as a compile error instead of a silent permission bypass.
pub fn enforce_non_audit_query(query: &str) -> Result<String, crate::SearchError> {
    let deny_set = BTreeSet::from(["audit".to_string()]);
    enforce_source_scope(query, &deny_set)
}

/// NAN-1799 (per-source RBAC scoping): parse a piped-query string, inject an
/// exclusion of EVERY source_type in `deny_set` at every base-table scan —
/// the main search and every subsearch at any depth (`join` / `append` /
/// `IN [ … ]`, including subsearches nested inside `where` / `transaction` /
/// `sequence` / `funnel` conditions) — and serialize back to a string.
///
/// Contract (shared across the NAN-1799 wave — do not deviate):
///
///  * `deny_set.is_empty()` → the query is returned UNCHANGED, byte-identical.
///    This is the zero-restricted-sources back-compat guarantee: unrestricted
///    callers pay nothing and their query text is not even reparsed.
///  * `deny_set == {"audit"}` exactly → output is byte-identical to
///    [`enforce_non_audit_query`] (the legacy `source_type != "audit"`
///    conjunct), preserving every NAN-1794 test and the NAN-1733 OTLP strip.
///  * otherwise → one `source_type NOT IN ("a", "b", …)` conjunct per scan,
///    values sorted (BTreeSet order), rendered from
///    `SearchExpr::InList { negated: true, .. }`. See [`mandatory_exclusion`]
///    for the exact AST shape.
///
/// The injection is UNCONDITIONAL and structural — see
/// [`enforce_source_type_exclusion`] for why detect-and-skip is a security
/// regression.
pub fn enforce_source_scope(
    query: &str,
    deny_set: &BTreeSet<String>,
) -> Result<String, crate::SearchError> {
    use crate::query::{extract_time_modifier_tokens, parse_query, PrettyPrint};

    // Zero restricted sources → nothing to enforce. Return the input verbatim
    // (no parse/pretty-print round-trip, so formatting and time modifiers are
    // untouched by construction).
    if deny_set.is_empty() {
        return Ok(query.to_string());
    }

    let parsed = parse_query(query).map_err(|e| {
        crate::SearchError::ParseError(format!(
            "Query parsing failed for access control enforcement: {}",
            e
        ))
    })?;
    let injected = inject_source_type_exclusion_recursive(&parsed, deny_set);
    let mut enforced = injected.pretty_print();

    // NAN-2006 (F1,F2,F4,F5,F6,F7,F9) — FAIL-CLOSED round-trip verification.
    //
    // The security guarantee is that EVERY scan in the query is ANDed at its
    // top level with the mandatory source-type exclusion. Every caller re-parses
    // this serialized string (core_search.rs:481, sql_execution.rs:162,
    // streaming.rs, field_queries.rs, prevalence, cloud, reports), and the nPL
    // grammar has NO working escape for `"` (NAN-1157) — so historically a
    // crafted keyword / rex pattern / filter value / quoted field name could
    // break out of the injected `Group(...)`, re-balance the parens, and
    // re-parse `source_type=<denied>` as an ungated top-level OR arm (or inject
    // an ungated `| append [...]` subsearch). The pretty-printer now strips the
    // breakout `"`, but we do NOT let serialization fidelity be the only thing
    // standing between an authenticated user and audit / denied-source rows:
    // re-parse our own output exactly as the callers will, and PROVE the gate
    // survived on every scan. If it did not, refuse to run the query.
    let reparsed = parse_query(&enforced).map_err(|e| {
        crate::SearchError::SqlValidationError(format!(
            "source-scope enforcement produced an unparseable query: {}",
            e
        ))
    })?;
    if !all_scans_gated(&reparsed, deny_set) {
        return Err(crate::SearchError::SqlValidationError(
            "source-scope enforcement could not be verified for this query; \
             refusing to run it (NAN-2006)"
                .to_string(),
        ));
    }

    // NAN-1453: `parse_query` strips `earliest=`/`latest=` (they are TimeRange
    // controls, not AST nodes), so the pretty-printed rewrite above drops them.
    // Re-append the analyst's original tokens so the downstream search layer's
    // `extract_time_modifiers` still applies them — otherwise a scoped user's
    // `earliest=` silently no-ops and their results/timeline come back
    // empty. Append position is safe: that consumer strips modifiers by regex
    // anywhere in the string, regardless of pipe placement.
    for token in extract_time_modifier_tokens(query) {
        enforced.push(' ');
        enforced.push_str(&token);
    }
    Ok(enforced)
}

/// Apply the mandatory exclusion to every scan in `query`, recursing through
/// piped sources AND into every subsearch-bearing command.
///
/// The wrap shape — `And(Group(<user expr>), <exclusion>)` — is load-bearing:
/// `clickhouse_sql_gen::strip_injected_audit_gate` is its exact structural
/// inverse (it unwraps this on the OTLP spans/metrics datasets, where
/// `source_type` is not a column — NAN-1733). Change the shape here and you
/// must change it there.
///
/// NAN-1799: `<exclusion>` is now one of TWO conjunct forms (see
/// [`mandatory_exclusion`] for the exact AST): the legacy
/// `FieldFilter { source_type, Ne, "audit" }` when the deny set is exactly
/// `{"audit"}`, or `InList { field: "source_type", values: <sorted>, negated: true }`
/// for any other deny set. The OTLP strip matcher must recognize both.
fn inject_source_type_exclusion_recursive(query: &Query, deny_set: &BTreeSet<String>) -> Query {
    match query {
        Query::Search(expr) => Query::Search(SearchExpr::And(
            Box::new(SearchExpr::Group(Box::new(gate_search_expr(
                expr, deny_set,
            )))),
            Box::new(mandatory_exclusion(deny_set)),
        )),
        Query::Piped { source, command } => Query::Piped {
            source: Box::new(inject_source_type_exclusion_recursive(source, deny_set)),
            command: gate_command(command, deny_set),
        },
    }
}

/// Rewrite a `SearchExpr`, gating every subsearch it carries.
///
/// The expression's own logical structure is preserved verbatim — the caller
/// ANDs the mandatory exclusion on the outside, so nothing in here can weaken
/// it. The only job is to reach nested `IN [ <subsearch> ]` scans.
///
/// FAIL-CLOSED: the match is exhaustive with NO wildcard arm. A new
/// `SearchExpr` variant that carries a `Query` is a compile error here rather
/// than a silent audit leak.
fn gate_search_expr(expr: &SearchExpr, deny_set: &BTreeSet<String>) -> SearchExpr {
    match expr {
        SearchExpr::InSubsearch {
            field,
            subsearch,
            negated,
            subsearch_dataset,
        } => SearchExpr::InSubsearch {
            field: field.clone(),
            subsearch: Box::new(inject_source_type_exclusion_recursive(subsearch, deny_set)),
            negated: *negated,
            subsearch_dataset: *subsearch_dataset,
        },
        SearchExpr::And(left, right) => SearchExpr::And(
            Box::new(gate_search_expr(left, deny_set)),
            Box::new(gate_search_expr(right, deny_set)),
        ),
        SearchExpr::Or(left, right) => SearchExpr::Or(
            Box::new(gate_search_expr(left, deny_set)),
            Box::new(gate_search_expr(right, deny_set)),
        ),
        SearchExpr::Not(inner) => SearchExpr::Not(Box::new(gate_search_expr(inner, deny_set))),
        SearchExpr::Group(inner) => SearchExpr::Group(Box::new(gate_search_expr(inner, deny_set))),
        // Leaves — carry no nested `Query`, nothing to walk. Listed explicitly
        // (no `_` arm) so the fail-closed property above holds.
        SearchExpr::Keyword(_)
        | SearchExpr::FieldFilter { .. }
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => expr.clone(),
    }
}

/// Rewrite a `Command`, gating every subsearch it carries.
///
/// Enumerated from the AST (`query::ast::commands::Command`), not assumed:
///  * `Join` / `Append` hold a `Box<Query>` subsearch that reads the log table
///    directly — these are the direct audit-exfiltration paths.
///  * `Where` / `Transaction` / `Sequence` / `Funnel` hold `SearchExpr`s that
///    can themselves contain an `IN [ <subsearch> ]`. These conditions run over
///    rows the (already-gated) main scan produced, so they cannot resurrect
///    audit rows on their own — but the subsearches inside them hit the table
///    directly and must be gated.
///
/// FAIL-CLOSED: the match is exhaustive with NO wildcard arm. Adding a new
/// subsearch-bearing `Command` variant is a compile error here rather than a
/// silent audit leak.
fn gate_command(command: &Command, deny_set: &BTreeSet<String>) -> Command {
    let mut gated = command.clone();
    match &mut gated {
        Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
            **subsearch = inject_source_type_exclusion_recursive(subsearch, deny_set);
        }
        Command::Where { condition } => {
            *condition = gate_search_expr(condition, deny_set);
        }
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            if let Some(expr) = startswith {
                *expr = gate_search_expr(expr, deny_set);
            }
            if let Some(expr) = endswith {
                *expr = gate_search_expr(expr, deny_set);
            }
        }
        Command::Sequence { conditions, .. } => {
            for condition in conditions.iter_mut() {
                *condition = gate_search_expr(condition, deny_set);
            }
        }
        Command::Funnel { steps, .. } => {
            for (_, condition) in steps.iter_mut() {
                *condition = gate_search_expr(condition, deny_set);
            }
        }
        // Commands carrying no nested `Query`/`SearchExpr` — pass through
        // untouched. Listed explicitly (no `_` arm) to keep the fail-closed
        // property above.
        Command::Stats { .. }
        | Command::Chart { .. }
        | Command::StreamStats { .. }
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
        | Command::Fillnull { .. }
        | Command::Mvexpand { .. }
        | Command::Spath { .. }
        | Command::Format { .. }
        | Command::Return { .. }
        | Command::Risk { .. }
        | Command::Prevalence { .. }
        | Command::Sample { .. }
        | Command::Reverse
        | Command::EventStats { .. }
        | Command::Anomaly { .. }
        | Command::InputLookup { .. }
        | Command::Tree { .. }
        | Command::ResolveIdentity { .. }
        | Command::Asset { .. }
        | Command::Cloud { .. }
        | Command::Lateral { .. }
        | Command::Ai { .. }
        | Command::Output { .. }
        | Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. }
        | Command::Retro { .. }
        | Command::Baseline { .. } => {}
    }
    gated
}

/// FAIL-CLOSED verification (NAN-2006): true iff EVERY base-table scan in
/// `query` — the top-level `Search` leaf AND the `Search` leaf of every
/// subsearch at any depth (join / append / IN-subsearch, including those nested
/// inside where / transaction / sequence / funnel conditions) — is ANDed at its
/// TOP LEVEL with the exact [`mandatory_exclusion`] conjunct for `deny_set`.
///
/// This is the structural inverse of the postcondition of
/// [`inject_source_type_exclusion_recursive`] ("every scan is
/// `And(Group(<gated user expr>), <mandatory exclusion>)`"), and the production
/// twin of the `assert_scope_gate_on_every_scan` test oracle.
/// [`enforce_source_scope`] runs it on the RE-PARSED pretty-printed output, so
/// if a crafted token broke out of a `Group` and dislodged the exclusion from
/// its ANDed position (or injected an ungated subsearch), this returns `false`
/// and the query is refused rather than run ungated.
///
/// It is a *proof*, not a heuristic: `X AND source_type NOT IN (D)` cannot match
/// a row of any source in `D` for ANY user expr `X`. A gate merely *mentioned*
/// inside `X` (under a `Not`, in an `Or` arm) does NOT satisfy it — exactly the
/// NAN-1794 bypass class.
fn all_scans_gated(query: &Query, deny_set: &BTreeSet<String>) -> bool {
    match query {
        Query::Search(expr) => match expr {
            SearchExpr::And(left, right) if is_mandatory_exclusion(right, deny_set) => {
                expr_subsearches_gated(left, deny_set)
            }
            _ => false,
        },
        Query::Piped { source, command } => {
            all_scans_gated(source, deny_set) && command_subsearches_gated(command, deny_set)
        }
    }
}

/// True iff `expr` is exactly the conjunct [`mandatory_exclusion`] emits for
/// `deny_set`: the legacy `source_type != "audit"` FieldFilter when the deny set
/// is exactly `{"audit"}`, else a negated `source_type NOT IN (…)` whose string
/// value set equals `deny_set` (a superset/subset is NOT the gate).
fn is_mandatory_exclusion(expr: &SearchExpr, deny_set: &BTreeSet<String>) -> bool {
    if deny_set.len() == 1 && deny_set.contains("audit") {
        return matches!(
            expr,
            SearchExpr::FieldFilter {
                field,
                op: Comparator::Ne,
                value: Value::String(s),
            } if field.eq_ignore_ascii_case("source_type") && s.eq_ignore_ascii_case("audit")
        );
    }
    match expr {
        SearchExpr::InList {
            field,
            values,
            negated: true,
        } if field.eq_ignore_ascii_case("source_type") => {
            let got: BTreeSet<String> = values
                .iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect();
            got.len() == values.len() && &got == deny_set
        }
        _ => false,
    }
}

/// Require every `InSubsearch` reachable in `expr` to be fully gated. Mirrors
/// the subsearch-reaching walk in [`gate_search_expr`]; exhaustive (no `_` arm)
/// so a new `Query`-carrying `SearchExpr` variant is a compile error here rather
/// than a silent gap in the fail-closed verification.
fn expr_subsearches_gated(expr: &SearchExpr, deny_set: &BTreeSet<String>) -> bool {
    match expr {
        SearchExpr::InSubsearch { subsearch, .. } => all_scans_gated(subsearch, deny_set),
        SearchExpr::And(l, r) | SearchExpr::Or(l, r) => {
            expr_subsearches_gated(l, deny_set) && expr_subsearches_gated(r, deny_set)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            expr_subsearches_gated(inner, deny_set)
        }
        SearchExpr::Keyword(_)
        | SearchExpr::FieldFilter { .. }
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => true,
    }
}

/// Require every subsearch reachable in `command` to be fully gated. Mirrors
/// [`gate_command`]; exhaustive (no `_` arm) so a new subsearch-bearing
/// `Command` variant is a compile error here rather than a silent gap.
fn command_subsearches_gated(command: &Command, deny_set: &BTreeSet<String>) -> bool {
    match command {
        Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
            all_scans_gated(subsearch, deny_set)
        }
        Command::Where { condition } => expr_subsearches_gated(condition, deny_set),
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            startswith
                .as_ref()
                .map_or(true, |e| expr_subsearches_gated(e, deny_set))
                && endswith
                    .as_ref()
                    .map_or(true, |e| expr_subsearches_gated(e, deny_set))
        }
        Command::Sequence { conditions, .. } => conditions
            .iter()
            .all(|c| expr_subsearches_gated(c, deny_set)),
        Command::Funnel { steps, .. } => steps
            .iter()
            .all(|(_, c)| expr_subsearches_gated(c, deny_set)),
        // Commands carrying no nested `Query`/`SearchExpr` — nothing to verify.
        // Enumerated (no `_` arm) to keep the fail-closed property above.
        Command::Stats { .. }
        | Command::Chart { .. }
        | Command::StreamStats { .. }
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
        | Command::Fillnull { .. }
        | Command::Mvexpand { .. }
        | Command::Spath { .. }
        | Command::Format { .. }
        | Command::Return { .. }
        | Command::Risk { .. }
        | Command::Prevalence { .. }
        | Command::Sample { .. }
        | Command::Reverse
        | Command::EventStats { .. }
        | Command::Anomaly { .. }
        | Command::InputLookup { .. }
        | Command::Tree { .. }
        | Command::ResolveIdentity { .. }
        | Command::Asset { .. }
        | Command::Cloud { .. }
        | Command::Lateral { .. }
        | Command::Ai { .. }
        | Command::Output { .. }
        | Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. }
        | Command::Retro { .. }
        | Command::Baseline { .. } => true,
    }
}

/// Recursively strip lateral and all commands after it
fn strip_lateral_and_after_recursive(query: &Query, parent_found: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            let (new_source, source_found) =
                strip_lateral_and_after_recursive(source, parent_found);
            let is_lateral = matches!(command, Command::Lateral { .. });
            if source_found || is_lateral {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    false,
                )
            }
        }
    }
}

/// Recursively strip ai and all commands after it
fn strip_ai_and_after_recursive(query: &Query, parent_found: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            let (new_source, source_found) = strip_ai_and_after_recursive(source, parent_found);

            let is_ai = matches!(command, Command::Ai { .. });

            if source_found || is_ai {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    false,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests;

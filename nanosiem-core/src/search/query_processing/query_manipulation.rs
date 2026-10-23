// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query manipulation and transformation utilities
//!
//! This module provides functions to transform and filter parsed query ASTs,
//! particularly for handling prevalence commands and their interaction with other commands.

use std::collections::BTreeSet;

use super::command_extraction::extract_post_ai_commands;
use crate::query::{
    Command, Comparator, Query, RhsSyntax, SearchExpr, TableField, TreePreset, Value,
};
use crate::search::field_utils::{is_post_processing_field, normalize_field_alias};

/// Resolve schema-dependent product semantics without creating field aliases.
/// Explicit field names remain untouched and must validate against the active
/// profile. Only named presets, omitted defaults and OCSF object roots in
/// `table` / `fields` (`http_request` → `http_request.*`) are translated.
pub fn apply_profile_product_semantics(
    query: &mut Query,
    profile: &dyn crate::schema::SchemaProfile,
) {
    let Query::Piped { source, command } = query else {
        return;
    };
    apply_profile_product_semantics(source, profile);

    if !profile.uses_strict_canonical_fields() {
        return;
    }

    // NAN-4279 (F13): an OCSF object root in `table` / `fields` names every
    // leaf beneath it. The lake view has only the dotted leaves, so the root
    // becomes the `<root>.*` wildcard the projection already expands. Only
    // over event rows: after stats/eval/rename a name like `device` may be a
    // pipeline column, never an OCSF object.
    let as_root_wildcard = |name: &mut String| {
        if !profile.object_root_leaves(name).is_empty() {
            name.push_str(".*");
        }
    };
    let over_event_rows = carries_event_fields_only(source);
    match command {
        _ if !over_event_rows => {}
        Command::Table { fields } => {
            for field in fields.iter_mut().filter(|field| field.alias.is_none()) {
                as_root_wildcard(&mut field.name);
            }
            return;
        }
        Command::Fields { fields, .. } => {
            fields.iter_mut().for_each(as_root_wildcard);
            return;
        }
        _ => {}
    }

    if let Command::ResolveIdentity {
        field,
        field_is_default: true,
        ..
    } = command
    {
        *field = "src_endpoint.ip".to_string();
        return;
    }

    let Command::Tree {
        preset,
        parent_field,
        child_field,
        label_field,
        detail_field,
        prevalence_field,
        ..
    } = command
    else {
        return;
    };

    match preset {
        Some(TreePreset::Process) => {
            *parent_field = "actor.process.uid".to_string();
            *child_field = "process.uid".to_string();
            *label_field = "process.name".to_string();
            *detail_field = Some("process.cmd_line".to_string());
            *prevalence_field = Some("process.file.hashes.value".to_string());
        }
        Some(TreePreset::Web) => {
            *parent_field = "http_request.referrer".to_string();
            *child_field = "http_request.url.url_string".to_string();
            *label_field = "http_request.url.hostname".to_string();
            *prevalence_field = Some("http_request.url.hostname".to_string());
        }
        None => {}
    }
}

/// Whether every column `query` outputs is a stored event field: the search
/// itself and commands that only filter, order, project or expand event rows.
fn carries_event_fields_only(query: &Query) -> bool {
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            (matches!(
                command,
                Command::Where { .. }
                    | Command::Sort { .. }
                    | Command::Head { .. }
                    | Command::Tail { .. }
                    | Command::Dedup { .. }
                    | Command::Fields { .. }
                    | Command::Mvexpand { .. }
            ) || matches!(command, Command::Table { fields } if fields.iter().all(|f| f.alias.is_none())))
                && carries_event_fields_only(source)
        }
    }
}

/// NAN-3257: OCSF fields that carry the same tree concept when a source fills a
/// sibling path instead of the preset's primary one. Field-based, never
/// source-based: a process tree's parent is `actor.process.uid` on sources that
/// report the acting process (Sysmon 1, Defender, CrowdStrike) and
/// `process.parent_process.uid` on sources that nest the parent under the
/// process (osquery, EDR exports). An HTTP tree's host is
/// `http_request.url.hostname`, `dst_endpoint.hostname` or `url.hostname`.
/// The first non-placeholder value in `[field, alternates…]` wins. UDM fields
/// have no alternates, so the established ClickHouse tree is unchanged.
pub fn tree_field_alternates(field: &str) -> &'static [&'static str] {
    match field {
        "actor.process.uid" => &["process.parent_process.uid"],
        "process.parent_process.uid" => &["actor.process.uid"],
        // NAN-3261: an access log that records only the request path (no
        // full URL, no host) still names its page: host+path when both are
        // set, else the bare path. The referrer is normalized to the same
        // key shape by the tree builder ([`tree_key_shape`]).
        "http_request.url.url_string" => &[
            "url.url_string",
            "http_request.url.hostname+http_request.url.path",
            "http_request.url.path",
        ],
        "http_request.url.hostname" => &[
            "dst_endpoint.hostname",
            "url.hostname",
            "http_request.url.path",
        ],
        _ => &[],
    }
}

/// `field` followed by its [`tree_field_alternates`]. A candidate may be a
/// composite `host+path` key (see [`tree_candidate_parts`]).
pub fn tree_field_candidates(field: &str) -> impl Iterator<Item = &str> {
    std::iter::once(field).chain(tree_field_alternates(field).iter().copied())
}

/// NAN-3261: the real columns a tree candidate reads. A plain field is its own
/// single part; a composite `a+b` key joins the values of `a` and `b` and is
/// only present when every part is.
pub fn tree_candidate_parts(candidate: &str) -> impl Iterator<Item = &str> {
    candidate.split('+')
}

/// NAN-3261: the shape of the key a tree candidate produces. A parent value
/// that is a full URL (a referrer) is normalized to the child's shape so a
/// path-only child and a full-URL referrer name the same page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TreeKeyShape {
    /// The value is the key as-is (process uids, full URLs, hostnames).
    #[default]
    Raw,
    /// `host/path`: a composite of a hostname and a URL path.
    HostPath,
    /// `/path`: a bare URL path.
    Path,
}

/// The [`TreeKeyShape`] a candidate field produces. Field-based: any composite
/// candidate is `host+path`, and any `*url.path` field is a bare path.
pub fn tree_key_shape(candidate: &str) -> TreeKeyShape {
    if candidate.contains('+') {
        TreeKeyShape::HostPath
    } else if candidate == "url.path" || candidate.ends_with(".url.path") {
        TreeKeyShape::Path
    } else {
        TreeKeyShape::Raw
    }
}

/// The internal row cap of a lean tree candidate fetch. Matches the product's
/// 10k-node tree bound; a fuller window returns a partial tree with a note.
pub const LAKE_TREE_CANDIDATE_CAP: usize = 10_000;

/// NAN-3257: the narrow candidate query for a terminal `| tree` over the strict
/// canonical (lean) lake.
///
/// The tree used to reach the worker as `SELECT *` over every matching event:
/// `tree` is not a newest-first projection, so the worker scanned the whole
/// window of full-width rows (one hour of an endpoint source is ~360k events,
/// ~55 s) to keep 10k rows that were mostly NOT edges (module loads, network
/// events). This projects only the columns the tree builder reads (time,
/// child, parent, label, detail and the parent-side label twin, each with its
/// [`tree_field_alternates`]) and keeps only rows that carry a real edge:
/// a non-empty child, a non-empty parent and child != parent. The result is a
/// `search | table …` timeline the worker pages newest-first and stops at the
/// row cap.
///
/// The edge predicate joins the base search (ahead of any `head`/`sort`/`where`
/// prefix) so a bounded preview (`| head 200 | tree`) also samples edges.
/// Returns `None` for anything but a terminal tree whose child and parent the
/// profile resolves; those keep the established pass-through.
pub fn lake_tree_candidate_query(
    query: &Query,
    profile: &dyn crate::schema::SchemaProfile,
) -> Option<Query> {
    let Query::Piped {
        source,
        command:
            Command::Tree {
                parent_field,
                child_field,
                label_field,
                detail_field,
                prevalence_field,
                preset,
                ..
            },
    } = query
    else {
        return None;
    };
    // NAN-3294: a web tree also renders sources that log no referrer (the
    // client → domain → URL layout), so its candidates are every request
    // with a URL, not only referrer edges.
    let web = *preset == Some(TreePreset::Web);
    let resolves = |field: &str| {
        !field.is_empty()
            && !matches!(
                profile.resolve(field),
                crate::schema::FieldResolution::Unknown
            )
    };
    // A composite candidate is known when every part it joins is.
    let known = |field: &&str| tree_candidate_parts(field).all(resolves);
    let children = tree_field_candidates(child_field)
        .filter(known)
        .collect::<Vec<_>>();
    let parents = tree_field_candidates(parent_field)
        .filter(known)
        .collect::<Vec<_>>();
    if children.first() != Some(&child_field.as_str())
        || parents.first() != Some(&parent_field.as_str())
    {
        return None;
    }

    let ne = |field: &str, value: Value, rhs: RhsSyntax| SearchExpr::FieldFilter {
        field: field.to_string(),
        op: Comparator::Ne,
        value,
        rhs,
    };
    let and = |left: SearchExpr, right: SearchExpr| SearchExpr::And(Box::new(left), Box::new(right));
    let mut edge: Option<SearchExpr> = None;
    // Every part of a composite candidate must be set.
    let set = |candidate: &str| {
        tree_candidate_parts(candidate)
            .map(|part| ne(part, Value::String(String::new()), RhsSyntax::Literal))
            .reduce(and)
            .expect("split yields at least one part")
    };
    if web {
        for child in &children {
            let term = SearchExpr::Group(Box::new(set(child)));
            edge = Some(match edge {
                None => term,
                Some(previous) => SearchExpr::Or(Box::new(previous), Box::new(term)),
            });
        }
    }
    for child in children.iter().filter(|_| !web) {
        for parent in &parents {
            let mut term = and(set(child), set(parent));
            // A bareword RHS naming a known field is a column comparison on a
            // strict canonical profile. Only emit it when both sides are real
            // columns with the same key shape (a path child never equals its
            // full-URL referrer column); otherwise the tree builder still
            // drops self-loops after normalizing the parent.
            if profile.uses_strict_canonical_fields()
                && tree_key_shape(child) == TreeKeyShape::Raw
                && tree_key_shape(parent) == TreeKeyShape::Raw
                && profile.is_known_field(child)
                && profile.is_known_field(parent)
            {
                term = and(term, ne(child, Value::String(parent.to_string()), RhsSyntax::Bareword));
            }
            let term = SearchExpr::Group(Box::new(term));
            edge = Some(match edge {
                None => term,
                Some(previous) => SearchExpr::Or(Box::new(previous), Box::new(term)),
            });
        }
    }
    let edge = SearchExpr::Group(Box::new(edge?));

    let mut fields: Vec<String> = Vec::new();
    let mut push = |field: &str| {
        if resolves(field) && !fields.iter().any(|existing| existing == field) {
            fields.push(field.to_string());
        }
    };
    push("time");
    children
        .iter()
        .flat_map(|field| tree_candidate_parts(field))
        .for_each(&mut push);
    parents
        .iter()
        .flat_map(|field| tree_candidate_parts(field))
        .for_each(&mut push);
    tree_field_candidates(label_field)
        .flat_map(tree_candidate_parts)
        .for_each(&mut push);
    if let Some(detail) = detail_field {
        tree_field_candidates(detail)
            .flat_map(tree_candidate_parts)
            .for_each(&mut push);
    }
    if web {
        // The client of the fallback layout.
        for field in ["src_endpoint.ip", "src_endpoint.hostname", "device.hostname"] {
            push(field);
        }
    }
    for parent in &parents {
        if let Some(twin) = crate::search::service::derived_parent_label_field(
            child_field,
            parent,
            label_field,
        ) {
            push(&twin);
        }
    }
    // NAN-3451: node prevalence. The builder reads the flat `prevalence_*`
    // scalars: physical columns on lean, `enrichments[]`-derived computed
    // columns on an open-core lake (unknown, so skipped, when the snapshot has
    // no stamp). A `prevalence=` field is read against the row's own stamp,
    // so it also needs its values and the aligned stamp arrays.
    for field in crate::search::service::TREE_PREVALENCE_FIELDS {
        push(field);
    }
    if let Some(field) = prevalence_field.as_deref() {
        push(field);
        for array in crate::schema::LAKE_PREVALENCE_STAMP_ARRAYS {
            push(array);
        }
    }

    // No `| sort`: an outer sort forces the full-width stage_0 again. An
    // unordered `LIMIT` over the narrow, edge-filtered scan stops reading as
    // soon as the cap is filled.
    Some(Query::Piped {
        source: Box::new(with_tree_edge_predicate(source, edge)),
        command: Command::Table {
            fields: fields
                .into_iter()
                .map(|name| TableField { name, alias: None })
                .collect(),
        },
    })
}

/// AND the edge predicate into the base search when only row-selection stages
/// sit between it and the tree; otherwise filter right before the tree.
fn with_tree_edge_predicate(query: &Query, edge: SearchExpr) -> Query {
    fn selection_only(query: &Query) -> bool {
        match query {
            Query::Search(_) => true,
            Query::Piped { source, command } => {
                matches!(
                    command,
                    Command::Head { .. } | Command::Where { .. } | Command::Sort { .. }
                ) && selection_only(source)
            }
        }
    }
    fn inject(query: &Query, edge: SearchExpr) -> Query {
        match query {
            Query::Search(expr) => Query::Search(SearchExpr::And(
                Box::new(SearchExpr::Group(Box::new(expr.clone()))),
                Box::new(edge),
            )),
            Query::Piped { source, command } => Query::Piped {
                source: Box::new(inject(source, edge)),
                command: command.clone(),
            },
        }
    }
    if selection_only(query) {
        inject(query, edge)
    } else {
        Query::Piped {
            source: Box::new(query.clone()),
            command: Command::Where { condition: edge },
        }
    }
}

/// Split a pipeline at its first stateful Nano-side command. The returned
/// prefix is safe to send to a storage/query worker; the suffix preserves the
/// original command order for bounded Rust post-processing.
pub fn split_lake_post_processing(query: &Query) -> (Query, Vec<Command>) {
    fn recurse(query: &Query) -> (Query, Vec<Command>, bool) {
        match query {
            Query::Search(expr) => (Query::Search(expr.clone()), Vec::new(), false),
            Query::Piped { source, command } => {
                let (prefix, mut suffix, found) = recurse(source);
                let boundary = matches!(
                    command,
                    Command::Prevalence { .. }
                        | Command::Lookup { .. }
                        | Command::InputLookup { .. }
                        | Command::ResolveIdentity { .. }
                        | Command::Ai { .. }
                );
                if found || boundary {
                    suffix.push(command.clone());
                    (prefix, suffix, true)
                } else {
                    (
                        Query::Piped {
                            source: Box::new(prefix),
                            command: command.clone(),
                        },
                        suffix,
                        false,
                    )
                }
            }
        }
    }

    let (prefix, suffix, _) = recurse(query);
    (prefix, suffix)
}

/// Whether any Nano-side stateful command occurs anywhere in `query`, including
/// inside a join/append or expression subsearch.
///
/// The durable lake runner executes one compiler-produced SQL statement and
/// cannot apply Nano-side state afterward. This visitor is deliberately
/// exhaustive over every AST node that can carry a nested query. A new
/// subsearch-bearing command or expression must therefore update this match or
/// fail compilation instead of silently bypassing the durable-lane guard.
pub fn contains_lake_post_processing_anywhere(query: &Query) -> bool {
    match query {
        Query::Search(expr) => lake_post_processing_in_search_expr(expr),
        Query::Piped { source, command } => {
            contains_lake_post_processing_anywhere(source)
                || is_lake_post_processing_command(command)
                || lake_post_processing_in_nested_command(command)
        }
    }
}

/// Whether Nano-side state occurs specifically below a nested-query boundary.
///
/// Top-level stateful commands remain supported by the bounded interactive
/// post-processing path. The same commands inside a subsearch cannot be split
/// into that outer suffix without changing query semantics, so the primary
/// lake path rejects them explicitly.
pub fn contains_nested_lake_post_processing(query: &Query) -> bool {
    match query {
        Query::Search(expr) => lake_post_processing_in_search_expr(expr),
        Query::Piped { source, command } => {
            contains_nested_lake_post_processing(source)
                || lake_post_processing_in_nested_command(command)
        }
    }
}

fn is_lake_post_processing_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Prevalence { .. }
            | Command::Lookup { .. }
            | Command::InputLookup { .. }
            | Command::ResolveIdentity { .. }
            | Command::Ai { .. }
    )
}

/// Inspect only queries/expressions nested *inside* `command`; the command
/// itself is intentionally not classified here. This distinction lets the
/// interactive outer pipeline retain its supported Nano-side suffix.
fn lake_post_processing_in_nested_command(command: &Command) -> bool {
    match command {
        Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
            contains_lake_post_processing_anywhere(subsearch)
        }
        Command::Where { condition } => lake_post_processing_in_search_expr(condition),
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            startswith
                .as_ref()
                .is_some_and(lake_post_processing_in_search_expr)
                || endswith
                    .as_ref()
                    .is_some_and(lake_post_processing_in_search_expr)
        }
        Command::Sequence { conditions, .. } => {
            conditions.iter().any(lake_post_processing_in_search_expr)
        }
        Command::Funnel { steps, .. } => steps
            .iter()
            .any(|(_, condition)| lake_post_processing_in_search_expr(condition)),
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
        | Command::Baseline { .. } => false,
    }
}

/// Inspect every expression node that can carry an `IN [subsearch]` query.
fn lake_post_processing_in_search_expr(expr: &SearchExpr) -> bool {
    match expr {
        SearchExpr::InSubsearch { subsearch, .. } => {
            contains_lake_post_processing_anywhere(subsearch)
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            lake_post_processing_in_search_expr(left) || lake_post_processing_in_search_expr(right)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            lake_post_processing_in_search_expr(inner)
        }
        SearchExpr::Keyword(_)
        | SearchExpr::FieldFilter { .. }
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::EvalPredicate(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => false,
    }
}

/// Whether the first Nano-side stage replaces its input instead of enriching
/// it. A data-source `inputlookup` explicitly ignores every input event, so a
/// primary-lake worker scan before that stage is both expensive and
/// semantically unobservable.
pub fn lake_post_processing_replaces_source(commands: &[Command]) -> bool {
    matches!(
        commands.first(),
        Some(Command::InputLookup {
            key_field: None,
            ..
        })
    )
}

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
    inject_source_exclusion_recursive(query, &SourceGate::plain(&deny_set, "source_type"))
}

/// Everything the gate builder / verifier needs to emit and recognize ONE
/// scan-level conjunct: the deny set, the provenance field it filters, and
/// (case-scoped reads only, NAN-2361 wave 8) the evidence allow-list that
/// re-admits exactly the rows a case's evidence ledger names.
#[derive(Clone, Copy)]
struct SourceGate<'a> {
    deny_set: &'a BTreeSet<String>,
    source_field: &'a str,
    /// `(evidence field, evidence ids)`; `None` or an empty set means the
    /// plain exclusion.
    evidence: Option<(&'a str, &'a BTreeSet<String>)>,
}

impl<'a> SourceGate<'a> {
    fn plain(deny_set: &'a BTreeSet<String>, source_field: &'a str) -> Self {
        Self { deny_set, source_field, evidence: None }
    }
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
fn mandatory_exclusion(gate: &SourceGate<'_>) -> SearchExpr {
    let deny_set = gate.deny_set;
    let source_field = gate.source_field;
    debug_assert!(
        !deny_set.is_empty(),
        "mandatory_exclusion requires a non-empty deny set; empty sets must \
         short-circuit in enforce_source_scope"
    );
    let exclusion = if deny_set.len() == 1 && deny_set.contains("audit") {
        // Legacy audit-gate shape — kept byte-identical (NAN-704 / NAN-1794).
        SearchExpr::FieldFilter {
            field: source_field.to_string(),
            op: Comparator::Ne,
            value: Value::String("audit".to_string()),
            rhs: RhsSyntax::Literal,
        }
    } else {
        SearchExpr::InList {
            field: source_field.to_string(),
            values: deny_set.iter().map(|s| Value::String(s.clone())).collect(),
            negated: true,
        }
    };
    match gate.evidence {
        // NAN-2361 wave 8 case-scoped bypass: `(<exclusion> OR <evidence
        // field> IN (<attached evidence ids>))`. Only rows the case's
        // evidence ledger names survive from a denied source; the OR is
        // wrapped in a Group so it stays one conjunct of the outer AND.
        Some((evidence_field, evidence)) if !evidence.is_empty() => {
            SearchExpr::Group(Box::new(SearchExpr::Or(
                Box::new(exclusion),
                Box::new(SearchExpr::InList {
                    field: evidence_field.to_string(),
                    values: evidence.iter().map(|s| Value::String(s.clone())).collect(),
                    negated: false,
                }),
            )))
        }
        _ => exclusion,
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
    enforce_source_scope_with_field(query, deny_set, "source_type")
}

/// Pin a private worker query to one exact log source. Unlike the product
/// viewer deny-set, this is an allow-one authority boundary: an empty or
/// unknown inventory must never become unrestricted. Nested scans are refused
/// until the exact positive predicate can be carried independently by every
/// subsearch/dataset boundary.
pub fn enforce_exact_source_scope(
    query: &str,
    allowed_source: &str,
) -> Result<String, crate::SearchError> {
    enforce_exact_source_scope_with_field(query, allowed_source, "source_type")
}

/// Enforce a source using a server-selected storage profile field.
/// Only the dedicated and canonical lake source fields are valid authorities.
pub fn enforce_exact_source_scope_with_field(
    query: &str,
    allowed_source: &str,
    source_field: &str,
) -> Result<String, crate::SearchError> {
    use crate::query::{extract_time_modifier_tokens, parse_query, PrettyPrint};
    if !matches!(source_field, "source_type" | "metadata.log_source") {
        return Err(crate::SearchError::SqlValidationError(
            "exact source authority has an invalid profile field".to_string(),
        ));
    }

    let allowed_source = allowed_source.trim().to_ascii_lowercase();
    if allowed_source.is_empty()
        || allowed_source.len() > 128
        || !allowed_source
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(crate::SearchError::SqlValidationError(
            "exact source authority has an invalid identity".to_string(),
        ));
    }
    let parsed = parse_query(query)
        .map_err(|error| crate::SearchError::ParseError(format!("Invalid query: {error}")))?;
    if contains_nested_scan(&parsed) {
        return Err(crate::SearchError::SqlValidationError(
            "exact source authority does not permit nested scans".to_string(),
        ));
    }
    let injected = inject_exact_source_top(&parsed, &allowed_source, source_field);
    let mut enforced = injected.pretty_print();
    let reparsed = parse_query(&enforced).map_err(|error| {
        crate::SearchError::SqlValidationError(format!(
            "exact source enforcement produced an unparseable query: {error}"
        ))
    })?;
    if contains_nested_scan(&reparsed)
        || !top_scan_has_exact_source(&reparsed, &allowed_source, source_field)
    {
        return Err(crate::SearchError::SqlValidationError(
            "exact source authority could not be verified".to_string(),
        ));
    }
    for token in extract_time_modifier_tokens(query) {
        enforced.push(' ');
        enforced.push_str(&token);
    }
    Ok(enforced)
}

fn inject_exact_source_top(query: &Query, allowed_source: &str, source_field: &str) -> Query {
    match query {
        Query::Search(expr) => Query::Search(SearchExpr::And(
            Box::new(SearchExpr::Group(Box::new(expr.clone()))),
            Box::new(SearchExpr::FieldFilter {
                field: source_field.to_string(),
                op: Comparator::Eq,
                value: Value::String(allowed_source.to_string()),
                rhs: RhsSyntax::Literal,
            }),
        )),
        Query::Piped { source, command } => Query::Piped {
            source: Box::new(inject_exact_source_top(
                source,
                allowed_source,
                source_field,
            )),
            command: command.clone(),
        },
    }
}

fn top_scan_has_exact_source(query: &Query, allowed_source: &str, source_field: &str) -> bool {
    match query {
        Query::Search(SearchExpr::And(_, right)) => matches!(
            &**right,
            SearchExpr::FieldFilter {
                field,
                op: Comparator::Eq,
                value: Value::String(value),
                ..
            } if field.eq_ignore_ascii_case(source_field)
                && value.eq_ignore_ascii_case(allowed_source)
        ),
        Query::Search(_) => false,
        Query::Piped { source, .. } => {
            top_scan_has_exact_source(source, allowed_source, source_field)
        }
    }
}

/// Whether `query` runs any scan besides its top-level one: an `IN [ … ]`
/// subsearch, a `join` / `append`, or a subsearch inside a `where` /
/// `transaction` / `sequence` / `funnel` condition (NAN-2961). Part pruning
/// derived from the outer search alone is unsound for such a query.
pub fn query_has_nested_scan(query: &Query) -> bool {
    contains_nested_scan(query)
}

fn contains_nested_scan(query: &Query) -> bool {
    fn expression(expr: &SearchExpr) -> bool {
        match expr {
            SearchExpr::InSubsearch { .. } => true,
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                expression(left) || expression(right)
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => expression(inner),
            SearchExpr::Keyword(_)
            | SearchExpr::FieldFilter { .. }
            | SearchExpr::FunctionFilter { .. }
            | SearchExpr::FieldFunctionFilter { .. }
            | SearchExpr::InList { .. }
            | SearchExpr::BooleanFunction(_)
            | SearchExpr::EvalPredicate(_)
            | SearchExpr::LiteralComparison { .. }
            | SearchExpr::IocMatch { .. } => false,
        }
    }

    match query {
        Query::Search(expr) => expression(expr),
        Query::Piped { source, command } => {
            if contains_nested_scan(source) {
                return true;
            }
            match command {
                Command::Join { .. } | Command::Append { .. } => true,
                Command::Where { condition } => expression(condition),
                Command::Transaction {
                    startswith,
                    endswith,
                    ..
                } => {
                    startswith.as_ref().is_some_and(expression)
                        || endswith.as_ref().is_some_and(expression)
                }
                Command::Sequence { conditions, .. } => conditions.iter().any(expression),
                Command::Funnel { steps, .. } => {
                    steps.iter().any(|(_, condition)| expression(condition))
                }
                _ => false,
            }
        }
    }
}

/// Enforce source RBAC through the canonical provenance field for the active
/// event contract. Legacy ClickHouse rows use `source_type`; the OCSF 1.9 lake
/// lane uses `metadata.log_source`. The field is selected by trusted product
/// code, never by a request.
pub fn enforce_source_scope_with_field(
    query: &str,
    deny_set: &BTreeSet<String>,
    source_field: &'static str,
) -> Result<String, crate::SearchError> {
    enforce_source_visibility_with_field(query, deny_set, None, source_field)
}

/// NAN-3163: `query` with the lake source-scope gate that
/// [`enforce_source_scope_with_field`] injected for `deny_set` removed from
/// its base scan, or `None` when that exact gate is not there.
///
/// Only the conjunct the injection emits for this deny set (after the
/// unattributed-alias expansion), in its exact wrap shape
/// `And(Group(<user expr>), <gate>)` on the base scan, is removed; a
/// user-written `metadata.log_source` filter, a gate for another deny set and
/// any subsearch gate stay. The result is for PLANNING routes that enforce the
/// same deny set themselves (the count rollups and their raw edges take it as
/// `deny_source_types`); it must never be executed as a query.
///
/// A deny set naming the Unattributed label (`default` / `unknown`) is never
/// stripped: rows without a declared source may carry an empty or NULL
/// source, which the scan gate excludes but a `!= 'unknown'` rollup filter
/// would count, so those callers keep the gated (scanning) plan.
pub fn strip_lake_source_scope_gate(query: &Query, deny_set: &BTreeSet<String>) -> Option<Query> {
    fn strip(query: &Query, gate: &SearchExpr) -> Option<Query> {
        match query {
            Query::Search(SearchExpr::And(left, right)) if right.as_ref() == gate => {
                match left.as_ref() {
                    SearchExpr::Group(inner) => Some(Query::Search(inner.as_ref().clone())),
                    _ => None,
                }
            }
            Query::Search(_) => None,
            Query::Piped { source, command } => Some(Query::Piped {
                source: Box::new(strip(source, gate)?),
                command: command.clone(),
            }),
        }
    }
    let normalized = crate::auth::source_visibility::expand_unattributed_sources(deny_set);
    if normalized.is_empty()
        || normalized
            .iter()
            .any(|source| crate::auth::source_visibility::is_unattributed_source(source))
    {
        return None;
    }
    strip(
        query,
        &mandatory_exclusion(&SourceGate::plain(&normalized, LAKE_SOURCE_FIELD)),
    )
}

/// The field a lake event's identity lives in; the case evidence ledger keys
/// attached events by it (NAN-2361 wave 8 case-scoped bypass).
pub const LAKE_EVENT_UID_FIELD: &str = "metadata.uid";

/// The lake's canonical provenance field: the ingest route slug every lake
/// event carries. The source-visibility row filter is on this field.
pub const LAKE_SOURCE_FIELD: &str = "metadata.log_source";

/// Native OTLP lake datasets and the ingest route slug EVERY row of them
/// arrived on (`source-payload.js` binds `/v1/traces` → `otlp_trace`,
/// `/v1/metrics` → `otlp_metric`; the lake writer refuses a row whose
/// `source_type` differs from its dataset). The native tables carry no
/// per-row source column, so a dataset is visible iff its slug is.
pub const OTLP_DATASET_SOURCES: &[(&str, &str)] = &[("spans", "otlp_trace"), ("metrics", "otlp_metric")];

/// Is a native OTLP dataset entirely hidden from a caller whose lake deny
/// set is `deny_set`? (NAN-2361 wave 8: the OTLP half of the one
/// `metadata.log_source` row filter.) `logs` / `risk` are never gated here.
pub fn otlp_dataset_denied(dataset: &str, deny_set: &BTreeSet<String>) -> bool {
    let dataset = dataset.trim().to_ascii_lowercase();
    OTLP_DATASET_SOURCES.iter().any(|(name, slug)| {
        *name == dataset && deny_set.iter().any(|denied| denied.trim().eq_ignore_ascii_case(slug))
    })
}

/// [`enforce_source_scope_with_field`] plus the case-scoped bypass: when
/// `evidence` is `Some((field, ids))` with a non-empty id set, every scan is
/// ANDed with `(<field> NOT IN (deny) OR <evidence field> IN (ids))` instead
/// of the plain exclusion, so a case participant sees exactly the attached
/// evidence rows of a denied source and nothing else from it. An empty deny
/// set still returns the query byte-identical (nothing to re-admit).
pub fn enforce_source_visibility_with_field(
    query: &str,
    deny_set: &BTreeSet<String>,
    evidence: Option<(&'static str, &BTreeSet<String>)>,
    source_field: &'static str,
) -> Result<String, crate::SearchError> {
    use crate::query::{extract_time_modifier_tokens, parse_query, PrettyPrint};

    // Stored source identities are canonical lowercase. Normalize the policy
    // input at this final structural boundary as well, so a mixed-case or
    // whitespace-padded registry value cannot weaken only the broad lake path
    // while typed fetch/risk routes still deny it.
    //
    // NAN-2602: on the lake field, `default` and `unknown` are ONE label
    // (Unattributed). Stored rows with no declared source carry `unknown`
    // while the model / UI restrict `default`; expand here so the gate fails
    // closed whichever spelling the policy named.
    let normalized_deny_set = if source_field == LAKE_SOURCE_FIELD {
        crate::auth::source_visibility::expand_unattributed_sources(deny_set)
    } else {
        deny_set
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>()
    };

    // Zero restricted sources → nothing to enforce. Return the input verbatim
    // (no parse/pretty-print round-trip, so formatting and time modifiers are
    // untouched by construction).
    if normalized_deny_set.is_empty() {
        return Ok(query.to_string());
    }
    let normalized_evidence: Option<(&'static str, BTreeSet<String>)> =
        evidence.and_then(|(field, ids)| {
            let ids: BTreeSet<String> = ids
                .iter()
                .map(|id| id.trim().to_string())
                .filter(|id| !id.is_empty())
                .collect();
            (!ids.is_empty()).then_some((field, ids))
        });
    let gate = SourceGate {
        deny_set: &normalized_deny_set,
        source_field,
        evidence: normalized_evidence.as_ref().map(|(field, ids)| (*field, ids)),
    };

    // NAN-2241: this is the FIRST parse a scoped caller's query hits, so an
    // ordinary syntax error surfaces from here. Lead with the syntax error
    // itself — the old "Query parsing failed for access control enforcement"
    // prefix read as a permissions problem and buried the actual diagnosis.
    let parsed = parse_query(query)
        .map_err(|e| crate::SearchError::ParseError(format!("Invalid query: {}", e)))?;
    // NAN-3222: record (never alter) an explicit reference to a denied
    // source. A no-op outside a request's audit scope; the rewrite below is
    // byte-identical either way.
    crate::search::denied_source_audit::observe_gated_query(query, &parsed, &normalized_deny_set);
    let injected = inject_source_exclusion_recursive(&parsed, &gate);
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
    if !all_scans_gated(&reparsed, &gate) {
        return Err(crate::SearchError::SqlValidationError(
            "source-scope enforcement could not be verified for this query; \
             refusing to run it"
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
fn inject_source_exclusion_recursive(
    query: &Query,
    gate: &SourceGate<'_>,
) -> Query {
    match query {
        Query::Search(expr) => Query::Search(SearchExpr::And(
            Box::new(SearchExpr::Group(Box::new(gate_search_expr(
                expr,
                gate,
            )))),
            Box::new(mandatory_exclusion(gate)),
        )),
        Query::Piped { source, command } => Query::Piped {
            source: Box::new(inject_source_exclusion_recursive(
                source,
                gate,
            )),
            command: gate_command(command, gate),
        },
    }
}

#[cfg(test)]
fn inject_source_type_exclusion_recursive(query: &Query, deny_set: &BTreeSet<String>) -> Query {
    inject_source_exclusion_recursive(query, &SourceGate::plain(deny_set, "source_type"))
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
fn gate_search_expr(
    expr: &SearchExpr,
    gate: &SourceGate<'_>,
) -> SearchExpr {
    match expr {
        SearchExpr::InSubsearch {
            field,
            subsearch,
            negated,
            subsearch_dataset,
        } => SearchExpr::InSubsearch {
            field: field.clone(),
            subsearch: Box::new(inject_source_exclusion_recursive(
                subsearch,
                gate,
            )),
            negated: *negated,
            subsearch_dataset: *subsearch_dataset,
        },
        SearchExpr::And(left, right) => SearchExpr::And(
            Box::new(gate_search_expr(left, gate)),
            Box::new(gate_search_expr(right, gate)),
        ),
        SearchExpr::Or(left, right) => SearchExpr::Or(
            Box::new(gate_search_expr(left, gate)),
            Box::new(gate_search_expr(right, gate)),
        ),
        SearchExpr::Not(inner) => {
            SearchExpr::Not(Box::new(gate_search_expr(inner, gate)))
        }
        SearchExpr::Group(inner) => {
            SearchExpr::Group(Box::new(gate_search_expr(inner, gate)))
        }
        // Leaves — carry no nested `Query`, nothing to walk. Listed explicitly
        // (no `_` arm) so the fail-closed property above holds.
        SearchExpr::Keyword(_)
        | SearchExpr::FieldFilter { .. }
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::EvalPredicate(_)
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
fn gate_command(command: &Command, gate: &SourceGate<'_>) -> Command {
    let mut gated = command.clone();
    match &mut gated {
        Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
            **subsearch = inject_source_exclusion_recursive(subsearch, gate);
        }
        Command::Where { condition } => {
            *condition = gate_search_expr(condition, gate);
        }
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            if let Some(expr) = startswith {
                *expr = gate_search_expr(expr, gate);
            }
            if let Some(expr) = endswith {
                *expr = gate_search_expr(expr, gate);
            }
        }
        Command::Sequence { conditions, .. } => {
            for condition in conditions.iter_mut() {
                *condition = gate_search_expr(condition, gate);
            }
        }
        Command::Funnel { steps, .. } => {
            for (_, condition) in steps.iter_mut() {
                *condition = gate_search_expr(condition, gate);
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
fn all_scans_gated(query: &Query, gate: &SourceGate<'_>) -> bool {
    match query {
        Query::Search(expr) => match expr {
            SearchExpr::And(left, right)
                if is_mandatory_exclusion(right, gate) =>
            {
                expr_subsearches_gated(left, gate)
            }
            _ => false,
        },
        Query::Piped { source, command } => {
            all_scans_gated(source, gate)
                && command_subsearches_gated(command, gate)
        }
    }
}

/// True iff `expr` is exactly the conjunct [`mandatory_exclusion`] emits for
/// `deny_set`: the legacy `source_type != "audit"` FieldFilter when the deny set
/// is exactly `{"audit"}`, else a negated `source_type NOT IN (…)` whose string
/// value set equals `deny_set` (a superset/subset is NOT the gate).
fn is_mandatory_exclusion(
    expr: &SearchExpr,
    gate: &SourceGate<'_>,
) -> bool {
    let deny_set = gate.deny_set;
    let source_field = gate.source_field;
    // Case-scoped form: `Group(Or(<exclusion>, <evidence field> IN (E)))`
    // with E exactly the evidence set. Anything else is not the gate.
    if let Some((evidence_field, evidence)) = gate.evidence {
        if !evidence.is_empty() {
            let plain = SourceGate { evidence: None, ..*gate };
            return match expr {
                SearchExpr::Group(inner) => match inner.as_ref() {
                    SearchExpr::Or(left, right) => {
                        is_mandatory_exclusion(left, &plain)
                            && matches!(
                                right.as_ref(),
                                SearchExpr::InList { field, values, negated: false }
                                    if field.eq_ignore_ascii_case(evidence_field) && {
                                        let got: BTreeSet<String> = values
                                            .iter()
                                            .filter_map(|v| match v {
                                                Value::String(s) => Some(s.clone()),
                                                _ => None,
                                            })
                                            .collect();
                                        got.len() == values.len() && &got == evidence
                                    }
                            )
                    }
                    _ => false,
                },
                _ => false,
            };
        }
    }
    if deny_set.len() == 1 && deny_set.contains("audit") {
        return matches!(
            expr,
            SearchExpr::FieldFilter {
                field,
                op: Comparator::Ne,
                value: Value::String(s),
                ..
            } if field.eq_ignore_ascii_case(source_field) && s.eq_ignore_ascii_case("audit")
        );
    }
    match expr {
        SearchExpr::InList {
            field,
            values,
            negated: true,
        } if field.eq_ignore_ascii_case(source_field) => {
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
fn expr_subsearches_gated(
    expr: &SearchExpr,
    gate: &SourceGate<'_>,
) -> bool {
    match expr {
        SearchExpr::InSubsearch { subsearch, .. } => {
            all_scans_gated(subsearch, gate)
        }
        SearchExpr::And(l, r) | SearchExpr::Or(l, r) => {
            expr_subsearches_gated(l, gate)
                && expr_subsearches_gated(r, gate)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            expr_subsearches_gated(inner, gate)
        }
        SearchExpr::Keyword(_)
        | SearchExpr::FieldFilter { .. }
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::EvalPredicate(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => true,
    }
}

/// Require every subsearch reachable in `command` to be fully gated. Mirrors
/// [`gate_command`]; exhaustive (no `_` arm) so a new subsearch-bearing
/// `Command` variant is a compile error here rather than a silent gap.
fn command_subsearches_gated(
    command: &Command,
    gate: &SourceGate<'_>,
) -> bool {
    match command {
        Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
            all_scans_gated(subsearch, gate)
        }
        Command::Where { condition } => expr_subsearches_gated(condition, gate),
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            startswith
                .as_ref()
                .map_or(true, |e| expr_subsearches_gated(e, gate))
                && endswith
                    .as_ref()
                    .map_or(true, |e| expr_subsearches_gated(e, gate))
        }
        Command::Sequence { conditions, .. } => conditions
            .iter()
            .all(|c| expr_subsearches_gated(c, gate)),
        Command::Funnel { steps, .. } => steps
            .iter()
            .all(|(_, c)| expr_subsearches_gated(c, gate)),
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

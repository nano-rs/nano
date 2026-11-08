// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query complexity budget and stack-safety helpers (NAN-4917).
//!
//! Independent defences keep a hostile nPL query from aborting the process
//! with a stack overflow (Rust cannot catch one — it kills every in-flight
//! search and job on the worker):
//!
//! 1. [`check_query_complexity`] — an explicit, NON-recursive budget enforced at
//!    the end of every successful [`parse_query`](super::parse_query), so the
//!    batch search path, the streaming path, `explain`, and the detection-rule
//!    compiler all reject the same queries with the same error. It bounds:
//!    * the raw AST depth of the whole query (the parser's 50-level nesting cap
//!      only counts parentheses/function calls; left-nested operator chains of
//!      up to 1024 terms, and parenthesised groups of such chains, stack on top
//!      of it), and
//!    * the ALIAS-INLINED size of every expression. ClickHouse's analyzer
//!      substitutes each `eval` alias into the expressions that reference it
//!      (CTE stages are inlined), so `eval h1=f(h0.h0…) | eval h2=f(h1.h1…)`
//!      grows multiplicatively in what ClickHouse — and any downstream consumer
//!      that expands the lineage — has to materialise, even though every
//!      individual expression is small and passes the parser.
//!
//! 2. [`ensure_sufficient_stack`] — called at the entry of each recursive walk
//!    over the AST (parser nesting points, SQL generation, the in-memory
//!    post-processing evaluator, the pretty-printer). When the remaining stack
//!    drops below [`STACK_RED_ZONE`] it continues on a freshly allocated
//!    segment, so the depth the budget admits never depends on the caller's
//!    stack size (tokio workers get 2 MiB) or on debug-build frame sizes
//!    (~40 KiB per expression level in SQL generation, measured).
//!
//! 3. [`with_query_stack`] around whole passes (`parse_query`,
//!    `generate_with_options`) and [`RUNTIME_THREAD_STACK_SIZE`] for the
//!    search/api/jobs runtimes cover the many small walks that are bounded by
//!    [`MAX_AST_DEPTH`] but not individually guarded.
//!
//! Measured before this fix (debug): a single 20-deep nested-function `eval`
//! needed ~900 KiB of stack through parse + SQL generation; a 1024-term `where`
//! chain needed ~16 MiB debug / ~2 MiB release — both past a tokio worker's
//! 2 MiB stack.

use std::collections::HashMap;

use super::ast::{
    Aggregation, Command, EvalExpression, Query, RiskScoreExpr, SearchExpr,
};

/// Remaining-stack threshold below which [`ensure_sufficient_stack`] switches
/// to a new segment. Must exceed the largest stack span between two guarded
/// recursion points; debug-build SQL generation uses ~40-50 KiB per expression
/// level, so 1 MiB leaves a wide margin.
pub(crate) const STACK_RED_ZONE: usize = 1024 * 1024;

/// Size of each additional stack segment (virtual; pages are committed lazily).
pub(crate) const STACK_SEGMENT_SIZE: usize = 8 * 1024 * 1024;

/// Maximum raw AST depth of a whole query (search + every command expression,
/// subsearches included). Admits a full `MAX_CHAIN_LEN` (1024-term) chain plus
/// generous nesting around it; rejects stacked/grouped chains whose depth would
/// otherwise reach tens of thousands of levels.
pub const MAX_AST_DEPTH: usize = 1280;

/// Maximum function-call nesting of any expression after `eval` aliases are
/// substituted. A single expression is already capped at 50 by the parser; a
/// chain of evals that nests past this (e.g. six stages of 20 nested hashes =
/// 120) is rejected.
pub const MAX_INLINED_FUNCTION_NESTING: usize = 64;

/// Maximum AST depth of any expression after `eval` aliases are substituted.
pub const MAX_INLINED_DEPTH: usize = 2048;

/// Maximum node count of any expression after `eval` aliases are substituted.
/// Bounds multiplicative alias fan-out (`h2=f(h1.h1…)`). Kept well under
/// ClickHouse's default `max_expanded_ast_elements` (500 000).
pub const MAX_INLINED_NODES: u64 = 100_000;

/// Maximum alias-inlined node count summed over the WHOLE query (every
/// expression and field reference, subsearches included). Per-expression
/// limits alone do not bound the sum (`eval o1=c, …, o31=c`); kept below
/// ClickHouse's default `max_expanded_ast_elements` (500 000).
pub const MAX_TOTAL_EXPANDED_NODES: u64 = 400_000;

/// Maximum number of pipe commands across the root pipeline AND every
/// subsearch. Each subsearch is individually capped at `MAX_PIPE_COMMANDS` by
/// the parser; this bounds breadth (many subsearch-bearing stages).
pub const MAX_TOTAL_COMMANDS: usize = 256;

/// Run `f`, first moving onto a fresh stack segment if fewer than
/// [`STACK_RED_ZONE`] bytes remain. Cheap (a stack-pointer comparison) when the
/// stack is healthy.
#[inline]
pub(crate) fn ensure_sufficient_stack<R>(f: impl FnOnce() -> R) -> R {
    stacker::maybe_grow(STACK_RED_ZONE, STACK_SEGMENT_SIZE, f)
}

/// Stack size for the tokio worker/blocking threads of every binary that
/// handles user queries (search, api, jobs). Covers the service-level AST
/// walks outside parse/SQL generation (command extraction, scope gating,
/// validation) that are bounded by [`MAX_AST_DEPTH`] but not individually
/// guarded. Virtual reservation; pages are committed on use.
pub const RUNTIME_THREAD_STACK_SIZE: usize = 8 * 1024 * 1024;

/// Minimum stack a whole query pass (parse, SQL generation) should start with;
/// below it [`with_query_stack`] moves to a fresh [`QUERY_STACK_SIZE`] segment.
pub(crate) const QUERY_STACK_MIN: usize = 4 * 1024 * 1024;

/// Size of the segment [`with_query_stack`] allocates (virtual, lazily committed).
pub(crate) const QUERY_STACK_SIZE: usize = 16 * 1024 * 1024;

/// Run a whole query pass with at least [`QUERY_STACK_MIN`] of stack. Covers
/// the many small recursive walks inside parse/SQL generation that are bounded
/// by [`MAX_AST_DEPTH`] but not individually guarded. One stack-pointer check
/// (plus one lazily committed mmap when called from a small stack) per call.
#[inline]
pub(crate) fn with_query_stack<R>(f: impl FnOnce() -> R) -> R {
    stacker::maybe_grow(QUERY_STACK_MIN, QUERY_STACK_SIZE, f)
}

/// Alias-inlined size of one expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InlinedMetrics {
    depth: usize,
    function_nesting: usize,
    nodes: u64,
}

impl InlinedMetrics {
    const LEAF: Self = Self {
        depth: 1,
        function_nesting: 0,
        nodes: 1,
    };
}

type AliasEnv = HashMap<String, InlinedMetrics>;

/// Enforce the query complexity budget. Returns a human-readable reason on
/// rejection. Never recurses on expression depth (explicit work stacks), so it
/// is itself safe on arbitrarily deep input.
pub fn check_query_complexity(query: &Query) -> Result<(), String> {
    let (depth, commands) = max_ast_depth(query);
    if commands > MAX_TOTAL_COMMANDS {
        return Err(format!(
            "Query too complex: {commands} pipe commands across the query and its \
             subsearches exceeds the limit of {MAX_TOTAL_COMMANDS}."
        ));
    }
    if depth > MAX_AST_DEPTH {
        return Err(format!(
            "Query too complex: expression nesting depth {depth} exceeds the limit of \
             {MAX_AST_DEPTH}. Split long boolean/arithmetic chains or deeply grouped \
             conditions into simpler clauses."
        ));
    }
    check_inlined(query)
}

// ---------------------------------------------------------------------------
// Raw AST depth (iterative)
// ---------------------------------------------------------------------------

enum Node<'a> {
    Query(&'a Query),
    Search(&'a SearchExpr),
    Eval(&'a EvalExpression),
}

/// Returns `(max depth, total pipe commands)`; stops early once either is over
/// budget.
fn max_ast_depth(query: &Query) -> (usize, usize) {
    let mut max = 0usize;
    let mut commands = 0usize;
    let mut work: Vec<(Node<'_>, usize)> = vec![(Node::Query(query), 1)];
    while let Some((node, depth)) = work.pop() {
        if depth > max {
            max = depth;
            if max > MAX_AST_DEPTH {
                // Already over budget — no need to walk the rest.
                return (max, commands);
            }
        }
        let child = depth + 1;
        match node {
            Node::Query(Query::Search(expr)) => work.push((Node::Search(expr), child)),
            Node::Query(Query::Piped { source, command }) => {
                commands += 1;
                if commands > MAX_TOTAL_COMMANDS {
                    return (max, commands);
                }
                // The pipe spine is bounded (MAX_PIPE_COMMANDS) — keep its
                // commands at the same depth rather than nesting them.
                work.push((Node::Query(source), depth));
                for_each_command_child(command, |n| work.push((n, child)));
            }
            Node::Search(expr) => for_each_search_child(expr, |n| work.push((n, child))),
            Node::Eval(expr) => match expr {
                EvalExpression::Field(_) | EvalExpression::Literal(_) => {}
                EvalExpression::BinaryOp { left, right, .. } => {
                    work.push((Node::Eval(left), child));
                    work.push((Node::Eval(right), child));
                }
                EvalExpression::FunctionCall { args, .. } => {
                    for a in args {
                        work.push((Node::Eval(a), child));
                    }
                }
            },
        }
    }
    (max, commands)
}

fn for_each_search_child<'a>(expr: &'a SearchExpr, mut push: impl FnMut(Node<'a>)) {
    match expr {
        SearchExpr::And(l, r) | SearchExpr::Or(l, r) => {
            push(Node::Search(l));
            push(Node::Search(r));
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => push(Node::Search(inner)),
        SearchExpr::FunctionFilter { function, .. }
        | SearchExpr::FieldFunctionFilter { function, .. }
        | SearchExpr::BooleanFunction(function)
        | SearchExpr::EvalPredicate(function) => push(Node::Eval(function)),
        SearchExpr::InSubsearch { subsearch, .. } => push(Node::Query(subsearch)),
        SearchExpr::Keyword(_)
        | SearchExpr::FieldFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => {}
    }
}

fn for_each_aggregation_child<'a>(aggs: &'a [Aggregation], push: &mut impl FnMut(Node<'a>)) {
    for agg in aggs {
        if let Some(c) = &agg.condition {
            push(Node::Eval(c));
        }
        if let Some(e) = &agg.field_expr {
            push(Node::Eval(e));
        }
    }
}

/// Every expression / subquery carried by a command. Commands not listed carry
/// none (field lists, literals, durations).
fn for_each_command_child<'a>(command: &'a Command, mut push: impl FnMut(Node<'a>)) {
    match command {
        Command::Where { condition } => push(Node::Search(condition)),
        Command::Eval { assignments } => {
            for a in assignments {
                push(Node::Eval(&a.expression));
            }
        }
        Command::Stats { aggregations, .. }
        | Command::Chart { aggregations, .. }
        | Command::StreamStats { aggregations, .. }
        | Command::Timechart { aggregations, .. }
        | Command::EventStats { aggregations, .. } => {
            for_each_aggregation_child(aggregations, &mut push)
        }
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            if let Some(s) = startswith {
                push(Node::Search(s));
            }
            if let Some(e) = endswith {
                push(Node::Search(e));
            }
        }
        Command::Append { subsearch, .. } | Command::Join { subsearch, .. } => {
            push(Node::Query(subsearch))
        }
        Command::Risk { score, factor, .. } => {
            if let RiskScoreExpr::Dynamic(e) = score {
                push(Node::Eval(e));
            }
            if let Some(f) = factor {
                push(Node::Eval(f));
            }
        }
        Command::Sequence { conditions, .. } => {
            for c in conditions {
                push(Node::Search(c));
            }
        }
        Command::Funnel { steps, .. } => {
            for (_, c) in steps {
                push(Node::Search(c));
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Alias-inlined size (iterative per expression)
// ---------------------------------------------------------------------------

/// Query-wide accumulator: every expression and every field reference, at its
/// alias-inlined size, across the root pipeline and all subsearches.
struct Budget {
    total: u64,
}

impl Budget {
    fn add(&mut self, nodes: u64) -> Result<(), String> {
        self.total = self.total.saturating_add(nodes);
        if self.total > MAX_TOTAL_EXPANDED_NODES {
            return Err(format!(
                "Query too complex: the query expands to more than \
                 {MAX_TOTAL_EXPANDED_NODES} expression nodes once eval fields are \
                 substituted into every place they are used. Reference large chained \
                 eval fields fewer times."
            ));
        }
        Ok(())
    }

    /// Account one expression (per-expression limits + query-wide total).
    fn expr(&mut self, m: &InlinedMetrics, what: &str) -> Result<(), String> {
        enforce(m, what)?;
        self.add(m.nodes)
    }

    /// Account a bare field reference (sort key, group-by, dedup key, …).
    fn field(&mut self, name: &str, env: &AliasEnv) -> Result<(), String> {
        self.add(field_metrics(name, env).nodes)
    }
}

fn check_inlined(query: &Query) -> Result<(), String> {
    let mut budget = Budget { total: 0 };
    check_inlined_scope(query, &mut budget)
}

fn is_wildcard(name: &str) -> bool {
    name.contains('*')
}

/// Walk one pipeline scope (root or subsearch) in order, maintaining the
/// alias-lineage environment with each stage's output semantics:
/// * `eval` / `rename` / `table … AS` / `bin … AS` carry lineage (ClickHouse
///   substitutes the expression), and a reassigned name shadows the old one;
/// * `table` / `fields` projections drop fields that are projected out;
/// * aggregations (`stats`, `chart`, `timechart`, `top`, `rare`) materialize
///   new outputs, so lineage resets to the group keys;
/// * every field-only consumer (sort/dedup/group-by/aggregate input/…) is
///   charged its inlined size against the query-wide budget.
fn check_inlined_scope(query: &Query, budget: &mut Budget) -> Result<(), String> {
    // Flatten the left-nested pipe spine (bounded by MAX_PIPE_COMMANDS).
    let mut commands: Vec<&Command> = Vec::new();
    let mut cur = query;
    let base = loop {
        match cur {
            Query::Search(expr) => break expr,
            Query::Piped { source, command } => {
                commands.push(command);
                cur = source;
            }
        }
    };
    commands.reverse();

    let mut env: AliasEnv = HashMap::new();
    check_search_inlined(base, &env, budget)?;

    for command in commands {
        match command {
            Command::Eval { assignments } => {
                // Assignments in one eval see their earlier siblings: ClickHouse
                // substitutes a SELECT-level alias into later sibling expressions.
                for a in assignments {
                    let m = eval_metrics(&a.expression, &env);
                    budget.expr(&m, &a.field)?;
                    env.insert(a.field.clone(), m);
                }
            }
            Command::Rename { mappings } => {
                for m in mappings {
                    let metrics = field_metrics(&m.from, &env);
                    budget.add(metrics.nodes)?;
                    env.remove(&m.from);
                    env.insert(m.to.clone(), metrics);
                }
            }
            Command::Table { fields } => {
                if fields.iter().any(|f| is_wildcard(&f.name)) {
                    // Wildcard projection: survivors unknown statically — keep
                    // the environment (conservative), but still apply aliases.
                    for f in fields.iter().filter(|f| !is_wildcard(&f.name)) {
                        budget.field(&f.name, &env)?;
                        if let Some(alias) = &f.alias {
                            let m = field_metrics(&f.name, &env);
                            env.insert(alias.clone(), m);
                        }
                    }
                } else {
                    let mut next: AliasEnv = HashMap::new();
                    for f in fields {
                        budget.field(&f.name, &env)?;
                        let out = f.alias.clone().unwrap_or_else(|| f.name.clone());
                        if let Some(m) = env.get(&f.name) {
                            next.insert(out, *m);
                        }
                    }
                    env = next;
                }
            }
            Command::Fields { fields, keep } => {
                if *keep {
                    if !fields.iter().any(|f| is_wildcard(f)) {
                        env.retain(|k, _| fields.iter().any(|f| f == k));
                    }
                } else {
                    for f in fields.iter().filter(|f| !is_wildcard(f)) {
                        env.remove(f);
                    }
                }
            }
            Command::Stats {
                aggregations,
                group_by,
            }
            | Command::Chart {
                aggregations,
                group_by,
            } => {
                let keys: Vec<&String> = group_by.iter().flatten().collect();
                aggregate_scope(&mut env, budget, aggregations, &keys)?;
            }
            Command::Timechart {
                aggregations,
                split_by,
                ..
            } => {
                let keys: Vec<&String> = split_by.iter().collect();
                aggregate_scope(&mut env, budget, aggregations, &keys)?;
            }
            Command::Top {
                field, by_fields, ..
            }
            | Command::Rare {
                field, by_fields, ..
            } => {
                let keys: Vec<&String> = std::iter::once(field).chain(by_fields).collect();
                aggregate_scope(&mut env, budget, &[], &keys)?;
            }
            Command::EventStats {
                aggregations,
                group_by,
            }
            | Command::StreamStats {
                aggregations,
                group_by,
                ..
            } => {
                // Rows preserved: lineage survives; aggregate outputs are new
                // materialized columns that shadow reused names.
                for k in group_by.iter().flatten() {
                    budget.field(k, &env)?;
                }
                for agg in aggregations {
                    aggregation_inputs(agg, &env, budget)?;
                }
                for agg in aggregations {
                    env.remove(&agg.output_alias());
                }
            }
            Command::Sort { fields, .. } => {
                for f in fields {
                    budget.field(&f.field, &env)?;
                }
            }
            Command::Dedup { fields, .. } => {
                for f in fields {
                    budget.field(f, &env)?;
                }
            }
            Command::Bin { field, alias, .. } => {
                let input = field.clone().unwrap_or_else(|| "timestamp".to_string());
                let m = field_metrics(&input, &env);
                budget.add(m.nodes)?;
                let out = alias.clone().unwrap_or_else(|| {
                    if field.is_some() {
                        input.clone()
                    } else {
                        "time_bucket".to_string()
                    }
                });
                // The bucket expression wraps the input: lineage carries.
                env.insert(out, combine(&[m], true));
            }
            other => {
                let mut result = Ok(());
                for_each_command_child(other, |node| {
                    if result.is_err() {
                        return;
                    }
                    result = match node {
                        Node::Eval(e) => budget.expr(&eval_metrics(e, &env), "expression"),
                        Node::Search(s) => check_search_inlined(s, &env, budget),
                        // Subqueries are independent CTE scopes sharing the
                        // query-wide budget.
                        Node::Query(q) => check_inlined_scope(q, budget),
                    };
                });
                result?;
            }
        }
    }
    Ok(())
}

fn aggregation_inputs(agg: &Aggregation, env: &AliasEnv, budget: &mut Budget) -> Result<(), String> {
    if let Some(f) = &agg.field {
        budget.field(f, env)?;
    }
    if let Some(c) = &agg.condition {
        budget.expr(&eval_metrics(c, env), "aggregation condition")?;
    }
    if let Some(e) = &agg.field_expr {
        budget.expr(&eval_metrics(e, env), "aggregation expression")?;
    }
    Ok(())
}

/// An aggregation materializes its outputs: afterwards only the group keys
/// keep (inlined) lineage; aggregate outputs and everything else are leaves or
/// gone.
fn aggregate_scope(
    env: &mut AliasEnv,
    budget: &mut Budget,
    aggregations: &[Aggregation],
    keys: &[&String],
) -> Result<(), String> {
    for k in keys {
        budget.field(k, env)?;
    }
    for agg in aggregations {
        aggregation_inputs(agg, env, budget)?;
    }
    let mut next: AliasEnv = HashMap::new();
    for k in keys {
        if let Some(m) = env.get(*k) {
            next.insert((*k).clone(), *m);
        }
    }
    *env = next;
    Ok(())
}

fn enforce(m: &InlinedMetrics, what: &str) -> Result<(), String> {
    if m.function_nesting > MAX_INLINED_FUNCTION_NESTING {
        return Err(format!(
            "Query too complex: `{what}` nests {} function calls once earlier eval fields \
             are substituted (limit {MAX_INLINED_FUNCTION_NESTING}). Chained evals that each \
             wrap the previous field multiply the final expression; simplify the chain.",
            m.function_nesting
        ));
    }
    if m.depth > MAX_INLINED_DEPTH {
        return Err(format!(
            "Query too complex: `{what}` reaches expression depth {} once earlier eval \
             fields are substituted (limit {MAX_INLINED_DEPTH}).",
            m.depth
        ));
    }
    if m.nodes > MAX_INLINED_NODES {
        return Err(format!(
            "Query too complex: `{what}` expands to more than {MAX_INLINED_NODES} expression \
             nodes once earlier eval fields are substituted (each reference to an eval field \
             copies its whole expression). Reduce how often chained eval fields are \
             referenced."
        ));
    }
    Ok(())
}

fn field_metrics(name: &str, env: &AliasEnv) -> InlinedMetrics {
    env.get(name).copied().unwrap_or(InlinedMetrics::LEAF)
}

fn combine(children: &[InlinedMetrics], is_function: bool) -> InlinedMetrics {
    let mut depth = 0usize;
    let mut nesting = 0usize;
    let mut nodes = 1u64;
    for c in children {
        depth = depth.max(c.depth);
        nesting = nesting.max(c.function_nesting);
        nodes = nodes.saturating_add(c.nodes);
    }
    InlinedMetrics {
        depth: depth.saturating_add(1),
        function_nesting: if is_function {
            nesting.saturating_add(1)
        } else {
            nesting
        },
        nodes,
    }
}

/// Post-order, explicit-stack metric computation for one eval expression.
fn eval_metrics(expr: &EvalExpression, env: &AliasEnv) -> InlinedMetrics {
    enum Step<'a> {
        Enter(&'a EvalExpression),
        Exit(&'a EvalExpression),
    }
    let mut work = vec![Step::Enter(expr)];
    let mut results: Vec<InlinedMetrics> = Vec::new();
    while let Some(step) = work.pop() {
        match step {
            Step::Enter(e) => match e {
                EvalExpression::Field(name) => results.push(field_metrics(name, env)),
                EvalExpression::Literal(_) => results.push(InlinedMetrics::LEAF),
                EvalExpression::BinaryOp { left, right, .. } => {
                    work.push(Step::Exit(e));
                    work.push(Step::Enter(right));
                    work.push(Step::Enter(left));
                }
                EvalExpression::FunctionCall { args, .. } => {
                    work.push(Step::Exit(e));
                    for a in args.iter().rev() {
                        work.push(Step::Enter(a));
                    }
                }
            },
            Step::Exit(e) => {
                let (arity, is_function) = match e {
                    EvalExpression::BinaryOp { .. } => (2, false),
                    EvalExpression::FunctionCall { args, .. } => (args.len(), true),
                    _ => unreachable!("leaves never push Exit"),
                };
                let split = results.len() - arity;
                let m = combine(&results[split..], is_function);
                results.truncate(split);
                results.push(m);
            }
        }
    }
    results.pop().unwrap_or(InlinedMetrics::LEAF)
}

/// Check every expression inside a search/where condition against the budget,
/// counting field references to eval aliases at their inlined size.
fn check_search_inlined(
    expr: &SearchExpr,
    env: &AliasEnv,
    budget: &mut Budget,
) -> Result<(), String> {
    // Total inlined nodes across the whole condition (each alias reference is a
    // full copy in ClickHouse), plus per-expression nesting/depth checks.
    let mut total: u64 = 0;
    let mut work: Vec<&SearchExpr> = vec![expr];
    while let Some(e) = work.pop() {
        total = total.saturating_add(1);
        match e {
            SearchExpr::And(l, r) | SearchExpr::Or(l, r) => {
                work.push(l);
                work.push(r);
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => work.push(inner),
            SearchExpr::FieldFilter { field, .. } | SearchExpr::InList { field, .. } => {
                total = total.saturating_add(field_metrics(field, env).nodes);
            }
            SearchExpr::FieldFunctionFilter {
                field, function, ..
            } => {
                let m = eval_metrics(function, env);
                enforce(&m, "where condition")?;
                total = total
                    .saturating_add(m.nodes)
                    .saturating_add(field_metrics(field, env).nodes);
            }
            SearchExpr::FunctionFilter { function, .. }
            | SearchExpr::BooleanFunction(function)
            | SearchExpr::EvalPredicate(function) => {
                let m = eval_metrics(function, env);
                enforce(&m, "where condition")?;
                total = total.saturating_add(m.nodes);
            }
            SearchExpr::InSubsearch { field, subsearch, .. } => {
                total = total.saturating_add(field_metrics(field, env).nodes);
                check_inlined_scope(subsearch, budget)?;
            }
            SearchExpr::Keyword(_)
            | SearchExpr::LiteralComparison { .. }
            | SearchExpr::IocMatch { .. } => {}
        }
        if total > MAX_INLINED_NODES {
            return enforce(
                &InlinedMetrics {
                    depth: 0,
                    function_nesting: 0,
                    nodes: total,
                },
                "where condition",
            );
        }
    }
    budget.add(total)
}

#[cfg(test)]
#[path = "complexity_tests.rs"]
mod tests;

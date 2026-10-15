// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3462 / NAN-3463: open-edition SQL must match the open schema.
//!
//! The open edition runs the open fresh-init schema
//! (`migrations/postgres-open/000_open_init.sql` plus `migrations/postgres/`
//! above the baseline). Enterprise builds add the overlay
//! (the enterprise migrations), which adds `tenant_id`, rebuilds unique
//! keys around it, and creates the enterprise-only tables. Code written and
//! tested against an enterprise database therefore compiled into the open
//! build and failed only at runtime there:
//!
//! * `ON CONFLICT (tenant_id, …)` on tables without `tenant_id` (42P10) broke
//!   every scheduled detection run, so detection never completed (NAN-3462).
//! * Queries against tables the splitter strips from the open snapshot (42P01)
//!   returned 500s on Rule Matches, Health, the Home detection-health card and
//!   the tuning pages, and a risk poller logged ~1,700 errors/h (NAN-3463).
//!
//! `sqlx::query*` calls with a string argument are runtime-checked, so the
//! compiler cannot see either class. This test closes that gap:
//!
//! 1. It walks the module tree of every crate the open build links, starting
//!    from each crate root and binary, and evaluates `#[cfg(...)]` the way an
//!    open build does (`feature = "…"` is off, `test` is off). Items, blocks
//!    and `if cfg!(feature = "enterprise")` branches that the open build
//!    compiles out are skipped, as is the rest of a block after an
//!    `if !cfg!(feature = "enterprise") { return …; }` guard.
//! 2. It takes the first argument of every `sqlx::query*` call that resolves
//!    to a string: a literal, a `concat!` (with `tenant_key!()` expanded to its
//!    open value `""`), or a `const` defined in the same file.
//! 3. It PREPAREs each statement against a database built by the open
//!    migration path, which resolves every table, column, function and
//!    `ON CONFLICT` target without executing anything.
//!
//! Every missing-object error must be listed in [`ALLOWED`] with the reason
//! the open build never reaches it at runtime (a hosted-only path, a route the
//! open build does not mount, a runtime capability check). An entry that no
//! longer matches anything fails the test too, so the list cannot rot.
//!
//! Not covered: SQL assembled with `format!` or `QueryBuilder` (it has no
//! complete static text), and ClickHouse SQL (it is never passed to
//! `sqlx::query*`).
//!
//! Prerequisites: Postgres at `TEST_DATABASE_URL`
//! (default `postgres://nanosiem:nanosiem@localhost:5432/postgres`) and the
//! NAN-2215 destructive opt-in; the test drops and recreates its own database,
//! `nanosiem_open_sql_scan`. `#[ignore]`d so a plain `cargo test` skips it;
//! the `pg-integration-tests` job runs it (`.config/nextest-pg-ignored.filter`).
//! The source walk itself is not DB-backed and always runs.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, Executor, PgConnection};
use syn::punctuated::Punctuated;
use syn::visit::Visit;
use syn::{Expr, Lit, Meta, Stmt, Token};

mod common;

const TEST_DB: &str = "nanosiem_open_sql_scan";

/// Crates linked into the open build whose SQL runs against the open schema.
const CRATES: &[&str] = &[
    "nanosiem-core",
    "nanosiem-api-lib",
    "nanosiem-api",
    "nanosiem-search",
    "nanosiem-lake-worker",
];

/// Postgres error codes that mean "this object is not in the schema".
/// 42P01 undefined_table, 42703 undefined_column, 42883 undefined_function,
/// 3F000 invalid_schema_name, 42P10 invalid_column_reference (an `ON CONFLICT`
/// target with no matching unique index).
const MISSING_OBJECT_CODES: &[&str] = &["42P01", "42703", "42883", "3F000", "42P10"];

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

const HOSTED: &str = "hosted (enterprise_shared) only: reached through a trusted tenant \
    context / shared-session authority, which the open build never establishes";
const HOSTED_LAKE: &str = "hosted lake schema; NAN-3472 decides per binary whether open-core \
    needs it (add to the open schema) or it is compiled out";
const CASES: &str = "cases / notebooks / hunts: the cases routes are mounted only under \
    #[cfg(feature = \"enterprise\")], and hunts:* permissions are seeded only by the enterprise \
    overlay (9000054), so every open hunts route answers 403";
const PLAYBOOKS: &str = "playbooks: playbooks:* permissions are seeded only by the enterprise \
    overlay (9000004), so every open playbooks route answers 403";
const SSO: &str = "SSO / OIDC handlers live in the enterprise crate; open callers check \
    capabilities::SSO_AVAILABLE first";
const DEMO: &str = "demo mode only (NANOSIEM_DEMO_MODE), never enabled on an open install";
const RBAC_GUARDED: &str = "runtime-guarded by to_regclass(...) before the query runs";
const CUSTOM_ENRICHMENT: &str = "custom enrichments (Deno feeds) are enterprise-only: \
    install_service refuses them in open (NAN-3463), so no custom_enrichment_id is ever set";
const COLLECTOR: &str = "pull collectors run from integration_instances, which only the \
    enterprise integrations routes create; install_service refuses them in open (NAN-3463)";
const AI_TUNING: &str = "AI tuning proposals / logs / breaches: routes mounted only when \
    ai_tuning_routes (enterprise), scheduler tasks gated in TuningScheduler::start (NAN-3463)";
const TUNING_MODE_WRITE: &str = "write_deployment_ai_tuning_mode has no open caller; the open \
    read goes through to_jsonb(row) and answers the default";
const CASE_GROUPS: &str = "case groups apply only to a non-public case_visibility, whose writes \
    are compiled out of open (crud.rs); the read swallows errors (unwrap_or_default)";
const CASE_RECONCILE: &str = "ungrouped-alert reconciliation is started only inside the \
    #[cfg(feature = \"enterprise\")] block of AppState lifecycle; open has no case grouping";
const LEGACY_PG_LOGS: &str = "pre-DualPool PostgreSQL fallback, taken only without a ClickHouse \
    client; every open caller is built from DualPool, which always has one (NAN-800)";

/// `(file relative to the repo root, missing object, reason)`. An object of
/// `"*"` covers every finding in a file that is wholly enterprise or hosted.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "nanosiem-api/src/handlers/marketplace.rs",
        "custom_enrichments",
        CUSTOM_ENRICHMENT,
    ),
    (
        "nanosiem-api/src/handlers/tuning/proposals.rs",
        "tuning_proposals",
        AI_TUNING,
    ),
    ("nanosiem-core/src/auth/repository/oidc.rs", "*", SSO),
    (
        "nanosiem-core/src/auth/repository/roles.rs",
        "playbook_permissions",
        RBAC_GUARDED,
    ),
    (
        "nanosiem-core/src/auth/repository/roles.rs",
        "playbooks",
        RBAC_GUARDED,
    ),
    (
        "nanosiem-core/src/auth/repository/users.rs",
        "playbook_approvals",
        RBAC_GUARDED,
    ),
    (
        "nanosiem-core/src/auth/repository/users.rs",
        "u.home_tenant_id",
        HOSTED,
    ),
    (
        "nanosiem-core/src/auth/search_admission.rs",
        "nano_shared.search_session_admission",
        HOSTED,
    ),
    (
        "nanosiem-core/src/auth/source_scope_resolver.rs",
        "enterprise_shared_tenant_plan_assignments",
        HOSTED,
    ),
    (
        "nanosiem-core/src/auth/tenant.rs",
        "nano_shared.session_grant_history_active",
        HOSTED,
    ),
    ("nanosiem-core/src/auth/tenant_auth_methods.rs", "*", HOSTED),
    ("nanosiem-core/src/auth/tenant_oidc.rs", "*", HOSTED),
    (
        "nanosiem-core/src/bin/activate_enterprise_shared_rls.rs",
        "*",
        HOSTED,
    ),
    (
        "nanosiem-core/src/db/repository/case_visibility.rs",
        "cases",
        CASES,
    ),
    (
        "nanosiem-core/src/db/repository/detection_rules/case_permissions.rs",
        "detection_rule_case_groups",
        CASE_GROUPS,
    ),
    (
        "nanosiem-core/src/db/repository/notebooks/bulk_sharing.rs",
        "*",
        CASES,
    ),
    (
        "nanosiem-core/src/db/repository/notebooks/cases.rs",
        "*",
        CASES,
    ),
    (
        "nanosiem-core/src/db/repository/notebooks/crud.rs",
        "*",
        CASES,
    ),
    (
        "nanosiem-core/src/db/repository/notebooks/entries.rs",
        "*",
        CASES,
    ),
    (
        "nanosiem-core/src/db/repository/notebooks/references.rs",
        "*",
        CASES,
    ),
    (
        "nanosiem-core/src/db/repository/notebooks/shares.rs",
        "*",
        CASES,
    ),
    (
        "nanosiem-core/src/db/repository/notebooks/tabs.rs",
        "*",
        CASES,
    ),
    ("nanosiem-core/src/demo/migrations.rs", "*", DEMO),
    ("nanosiem-core/src/demo/service.rs", "*", DEMO),
    (
        "nanosiem-core/src/detection/service/alerts.rs",
        "a.case_id",
        CASE_RECONCILE,
    ),
    (
        "nanosiem-core/src/feeds/repository.rs",
        "logs",
        LEGACY_PG_LOGS,
    ),
    (
        "nanosiem-core/src/health/feed_monitor.rs",
        "logs",
        LEGACY_PG_LOGS,
    ),
    ("nanosiem-core/src/hunts/knowledge.rs", "*", CASES),
    ("nanosiem-core/src/hunts/recon.rs", "*", CASES),
    ("nanosiem-core/src/hunts/repository.rs", "*", CASES),
    ("nanosiem-core/src/hunts/scheduler.rs", "*", CASES),
    (
        "nanosiem-core/src/ip_allowlist/tenant.rs",
        "nano_shared.check_tenant_ip_policy",
        HOSTED,
    ),
    (
        "nanosiem-core/src/marketplace/install_service.rs",
        "custom_enrichment_runs",
        CUSTOM_ENRICHMENT,
    ),
    (
        "nanosiem-core/src/marketplace/install_service.rs",
        "custom_enrichments",
        CUSTOM_ENRICHMENT,
    ),
    (
        "nanosiem-core/src/marketplace/install_service.rs",
        "integration_instances",
        COLLECTOR,
    ),
    (
        "nanosiem-core/src/marketplace/repository.rs",
        "custom_enrichment_runs",
        CUSTOM_ENRICHMENT,
    ),
    ("nanosiem-core/src/platform_enrichment.rs", "*", HOSTED),
    (
        "nanosiem-core/src/platform_enrichment/read.rs",
        "nano_shared.platform_enrichment_read_context",
        HOSTED,
    ),
    (
        "nanosiem-core/src/playbook_repository/repository.rs",
        "*",
        PLAYBOOKS,
    ),
    ("nanosiem-core/src/playbooks/repository.rs", "*", PLAYBOOKS),
    ("nanosiem-core/src/query_retention_authority.rs", "*", HOSTED),
    (
        "nanosiem-core/src/tenant_entitlements.rs",
        "enterprise_shared_tenant_plan_assignments",
        HOSTED,
    ),
    (
        "nanosiem-core/src/tuning/mode.rs",
        "ai_tuning_mode",
        TUNING_MODE_WRITE,
    ),
    (
        "nanosiem-core/src/tuning/repository/application.rs",
        "*",
        AI_TUNING,
    ),
    (
        "nanosiem-core/src/tuning/repository/logs.rs",
        "*",
        AI_TUNING,
    ),
    (
        "nanosiem-core/src/tuning/repository/proposals.rs",
        "*",
        AI_TUNING,
    ),
    (
        "nanosiem-core/src/tuning/repository/test_results.rs",
        "*",
        AI_TUNING,
    ),
    (
        "nanosiem-core/src/tuning/test_engine.rs",
        "tuning_tp_corpus_revisions",
        AI_TUNING,
    ),
    (
        "nanosiem-core/src/tuning/threshold.rs",
        "detection_threshold_breaches",
        AI_TUNING,
    ),
    (
        "nanosiem-core/src/tuning/versions.rs",
        "tuning_logs",
        AI_TUNING,
    ),
    (
        "nanosiem-lake-worker/src/admission_archive/postgres.rs",
        "*",
        HOSTED_LAKE,
    ),
    (
        "nanosiem-lake-worker/src/ingest_source_counters.rs",
        "*",
        HOSTED_LAKE,
    ),
    ("nanosiem-lake-worker/src/otel_handoff.rs", "*", HOSTED_LAKE),
    ("nanosiem-lake-worker/src/otel_lean.rs", "*", HOSTED_LAKE),
    (
        "nanosiem-lake-worker/src/part_ingest/finding_outbox.rs",
        "*",
        HOSTED_LAKE,
    ),
    ("nanosiem-lake-worker/src/tail_ledger.rs", "*", HOSTED_LAKE),
    (
        "nanosiem-search/src/auth_cache.rs",
        "enterprise_shared_tenant_plan_assignments",
        HOSTED,
    ),
];

// ---------------------------------------------------------------------------
// cfg evaluation: an open build with no optional features and no `test`.
// ---------------------------------------------------------------------------

fn eval_cfg_meta(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => {
            let name = path.get_ident().map(|i| i.to_string()).unwrap_or_default();
            match name.as_str() {
                "test" | "doc" | "miri" | "windows" => false,
                // debug_assertions, unix, … — the scanned build is a Linux build.
                _ => true,
            }
        }
        Meta::NameValue(nv) => {
            let key = nv
                .path
                .get_ident()
                .map(|i| i.to_string())
                .unwrap_or_default();
            let value = match &nv.value {
                Expr::Lit(lit) => match &lit.lit {
                    Lit::Str(s) => s.value(),
                    _ => String::new(),
                },
                _ => String::new(),
            };
            match key.as_str() {
                // Every optional feature of the scanned crates is off in the open
                // build: none of them declares a non-empty `default`.
                "feature" => false,
                "target_os" => value == "linux",
                "target_family" => value == "unix",
                _ => true,
            }
        }
        Meta::List(list) => {
            let name = list
                .path
                .get_ident()
                .map(|i| i.to_string())
                .unwrap_or_default();
            let inner: Vec<Meta> = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .map(|p| p.into_iter().collect())
                .unwrap_or_default();
            match name.as_str() {
                "not" => !inner.first().map(eval_cfg_meta).unwrap_or(true),
                "any" => inner.iter().any(eval_cfg_meta),
                "all" => inner.iter().all(eval_cfg_meta),
                _ => true,
            }
        }
    }
}

/// False when a `#[cfg(...)]` among `attrs` compiles the item out.
fn cfg_enabled(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().all(|attr| {
        if !attr.path().is_ident("cfg") {
            return true;
        }
        match attr.parse_args::<Meta>() {
            Ok(meta) => eval_cfg_meta(&meta),
            Err(_) => true,
        }
    })
}

/// The value of a condition the open build fixes at compile time, if any:
/// `cfg!(...)`, its negation, and `&&` / `||` / parentheses over them.
fn static_cond(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::Macro(m) if last_segment(&m.mac.path) == "cfg" => m
            .mac
            .parse_body::<Meta>()
            .ok()
            .map(|meta| eval_cfg_meta(&meta)),
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => static_cond(&u.expr).map(|v| !v),
        Expr::Paren(p) => static_cond(&p.expr),
        Expr::Group(g) => static_cond(&g.expr),
        Expr::Binary(b) => {
            let (l, r) = (static_cond(&b.left), static_cond(&b.right));
            match b.op {
                syn::BinOp::And(_) => match (l, r) {
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                },
                syn::BinOp::Or(_) => match (l, r) {
                    (Some(true), _) | (_, Some(true)) => Some(true),
                    (Some(false), Some(false)) => Some(false),
                    _ => None,
                },
                _ => None,
            }
        }
        _ => None,
    }
}

fn last_segment(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

fn expr_attrs(expr: &Expr) -> &[syn::Attribute] {
    match expr {
        Expr::Array(e) => &e.attrs,
        Expr::Assign(e) => &e.attrs,
        Expr::Async(e) => &e.attrs,
        Expr::Await(e) => &e.attrs,
        Expr::Binary(e) => &e.attrs,
        Expr::Block(e) => &e.attrs,
        Expr::Call(e) => &e.attrs,
        Expr::Closure(e) => &e.attrs,
        Expr::ForLoop(e) => &e.attrs,
        Expr::If(e) => &e.attrs,
        Expr::Loop(e) => &e.attrs,
        Expr::Macro(e) => &e.attrs,
        Expr::Match(e) => &e.attrs,
        Expr::MethodCall(e) => &e.attrs,
        Expr::Return(e) => &e.attrs,
        Expr::Struct(e) => &e.attrs,
        Expr::Tuple(e) => &e.attrs,
        Expr::Unsafe(e) => &e.attrs,
        Expr::While(e) => &e.attrs,
        Expr::Break(e) => &e.attrs,
        Expr::Cast(e) => &e.attrs,
        Expr::Const(e) => &e.attrs,
        Expr::Continue(e) => &e.attrs,
        Expr::Field(e) => &e.attrs,
        Expr::Group(e) => &e.attrs,
        Expr::Index(e) => &e.attrs,
        Expr::Let(e) => &e.attrs,
        Expr::Lit(e) => &e.attrs,
        Expr::Paren(e) => &e.attrs,
        Expr::Path(e) => &e.attrs,
        Expr::Range(e) => &e.attrs,
        Expr::Reference(e) => &e.attrs,
        Expr::Repeat(e) => &e.attrs,
        Expr::Try(e) => &e.attrs,
        Expr::TryBlock(e) => &e.attrs,
        Expr::Unary(e) => &e.attrs,
        Expr::Yield(e) => &e.attrs,
        _ => &[],
    }
}

/// True when a block cannot fall through: it ends in `return`, `bail!`, … .
fn block_diverges(block: &syn::Block) -> bool {
    let diverging_macro = |m: &syn::Macro| {
        matches!(
            last_segment(&m.path).as_str(),
            "bail" | "panic" | "unreachable" | "todo" | "unimplemented"
        )
    };
    match block.stmts.last() {
        Some(Stmt::Expr(Expr::Return(_), _)) => true,
        Some(Stmt::Expr(Expr::Macro(m), _)) => diverging_macro(&m.mac),
        Some(Stmt::Macro(m)) => diverging_macro(&m.mac),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Source walk
// ---------------------------------------------------------------------------

/// The open value of `tenant_key!()` (see `nanosiem_core::db::edition_sql`).
const OPEN_TENANT_KEY: &str = "";

/// Callees whose first argument is a complete Postgres statement.
const SQLX_QUERY_FNS: &[&str] = &[
    "query",
    "query_as",
    "query_scalar",
    "query_with",
    "query_as_with",
    "query_scalar_with",
];

/// Macros whose arguments are format strings or tokens, never sqlx calls.
const OPAQUE_MACROS: &[&str] = &[
    "format",
    "format_args",
    "write",
    "writeln",
    "print",
    "println",
    "eprint",
    "eprintln",
    "panic",
    "bail",
    "anyhow",
    "ensure",
    "info",
    "warn",
    "error",
    "debug",
    "trace",
    "event",
    "info_span",
    "debug_span",
    "warn_span",
    "error_span",
    "trace_span",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "unreachable",
    "todo",
    "unimplemented",
    "matches",
    "json",
    "concat",
    "stringify",
    "include_str",
    "include_bytes",
    "env",
    "option_env",
    "cfg",
    "tenant_key",
    "query",
    "query_as",
    "query_scalar",
];

#[derive(Debug, Clone)]
struct FoundQuery {
    file: String,
    line: usize,
    sql: String,
}

#[derive(Default)]
struct Scan {
    queries: Vec<FoundQuery>,
    files: BTreeSet<PathBuf>,
}

struct FileVisitor<'a> {
    rel: String,
    /// Directory that `mod foo;` resolves against.
    mod_dir: PathBuf,
    /// Directory of the source file (for `#[path]`).
    file_dir: PathBuf,
    consts: &'a HashMap<String, Vec<Expr>>,
    bare_query_is_sqlx: bool,
    collect_consts: Option<&'a mut HashMap<String, Vec<Expr>>>,
    queries: Vec<FoundQuery>,
    child_files: Vec<(PathBuf, PathBuf)>,
}

impl FileVisitor<'_> {
    fn resolve_str(&self, expr: &Expr, depth: usize) -> Option<String> {
        if depth > 8 {
            return None;
        }
        match expr {
            Expr::Lit(lit) => match &lit.lit {
                Lit::Str(s) => Some(s.value()),
                Lit::Int(i) => Some(i.base10_digits().to_string()),
                _ => None,
            },
            Expr::Reference(r) => self.resolve_str(&r.expr, depth + 1),
            Expr::Paren(p) => self.resolve_str(&p.expr, depth + 1),
            Expr::Group(g) => self.resolve_str(&g.expr, depth + 1),
            Expr::Macro(m) => {
                let name = last_segment(&m.mac.path);
                if name == "tenant_key" {
                    return Some(OPEN_TENANT_KEY.to_string());
                }
                if name != "concat" {
                    return None;
                }
                let parts = m
                    .mac
                    .parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                    .ok()?;
                let mut out = String::new();
                for part in &parts {
                    out.push_str(&self.resolve_str(part, depth + 1)?);
                }
                Some(out)
            }
            Expr::Path(p) => {
                let candidates = self.consts.get(&last_segment(&p.path))?;
                // A name defined more than once (in different impls) is only
                // resolved when every definition agrees.
                let values: BTreeSet<String> = candidates
                    .iter()
                    .filter_map(|e| self.resolve_str(e, depth + 1))
                    .collect();
                (values.len() == 1).then(|| values.into_iter().next().unwrap())
            }
            _ => None,
        }
    }

    fn record_call(&mut self, call: &syn::ExprCall) {
        let Expr::Path(func) = &*call.func else {
            return;
        };
        let segments: Vec<String> = func
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        let Some(last) = segments.last() else { return };
        if !SQLX_QUERY_FNS.contains(&last.as_str()) {
            return;
        }
        let is_sqlx = segments.iter().any(|s| s == "sqlx")
            || (segments.len() == 1 && (last != "query" || self.bare_query_is_sqlx));
        if !is_sqlx {
            return;
        }
        let Some(arg) = call.args.first() else { return };
        if let Some(sql) = self.resolve_str(arg, 0) {
            let line = proc_macro2::Span::start(&syn::spanned::Spanned::span(arg)).line;
            self.queries.push(FoundQuery {
                file: self.rel.clone(),
                line,
                sql,
            });
        }
    }

    fn push_mod_file(&mut self, file: PathBuf) {
        let child_dir = module_dir_of(&file, false);
        self.child_files.push((file, child_dir));
    }
}

/// The directory `mod foo;` inside `file` resolves against.
fn module_dir_of(file: &Path, is_root: bool) -> PathBuf {
    let parent = file.parent().unwrap().to_path_buf();
    let name = file.file_name().unwrap().to_string_lossy();
    if is_root || name == "mod.rs" {
        parent
    } else {
        parent.join(file.file_stem().unwrap())
    }
}

impl<'ast> Visit<'ast> for FileVisitor<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            _ => &[],
        };
        if !cfg_enabled(attrs) {
            return;
        }
        if let syn::Item::Const(c) = item {
            if let Some(map) = self.collect_consts.as_deref_mut() {
                map.entry(c.ident.to_string())
                    .or_default()
                    .push((*c.expr).clone());
            }
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        let path_attr = m.attrs.iter().find_map(|a| match &a.meta {
            Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
                Expr::Lit(syn::ExprLit {
                    lit: Lit::Str(s), ..
                }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        });
        match (&m.content, path_attr) {
            (None, Some(path)) => {
                let file = self.file_dir.join(path);
                self.push_mod_file(file);
            }
            (None, None) => {
                let name = m.ident.to_string();
                let flat = self.mod_dir.join(format!("{name}.rs"));
                let nested = self.mod_dir.join(&name).join("mod.rs");
                let file = if flat.exists() {
                    flat
                } else if nested.exists() {
                    nested
                } else {
                    panic!("{}: cannot resolve `mod {name};`", self.rel);
                };
                self.push_mod_file(file);
            }
            (Some((_, items)), _) => {
                let saved = self.mod_dir.clone();
                self.mod_dir = saved.join(m.ident.to_string());
                for item in items {
                    self.visit_item(item);
                }
                self.mod_dir = saved;
            }
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::ImplItem::Const(i) => &i.attrs,
            syn::ImplItem::Fn(i) => &i.attrs,
            syn::ImplItem::Type(i) => &i.attrs,
            syn::ImplItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        if !cfg_enabled(attrs) {
            return;
        }
        if let syn::ImplItem::Const(c) = item {
            if let Some(map) = self.collect_consts.as_deref_mut() {
                map.entry(c.ident.to_string())
                    .or_default()
                    .push(c.expr.clone());
            }
        }
        syn::visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::TraitItem::Const(i) => &i.attrs,
            syn::TraitItem::Fn(i) => &i.attrs,
            _ => &[],
        };
        if cfg_enabled(attrs) {
            syn::visit::visit_trait_item(self, item);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if cfg_enabled(&local.attrs) {
            syn::visit::visit_local(self, local);
        }
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if cfg_enabled(&arm.attrs) {
            syn::visit::visit_arm(self, arm);
        }
    }

    fn visit_field_value(&mut self, fv: &'ast syn::FieldValue) {
        if cfg_enabled(&fv.attrs) {
            syn::visit::visit_field_value(self, fv);
        }
    }

    fn visit_stmt_macro(&mut self, m: &'ast syn::StmtMacro) {
        if cfg_enabled(&m.attrs) {
            syn::visit::visit_stmt_macro(self, m);
        }
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        for stmt in &block.stmts {
            self.visit_stmt(stmt);
            // `if !cfg!(feature = "enterprise") { return …; }`: the rest of the
            // block is enterprise-only.
            if let Stmt::Expr(Expr::If(i), _) = stmt {
                if i.else_branch.is_none()
                    && static_cond(&i.cond) == Some(true)
                    && block_diverges(&i.then_branch)
                {
                    break;
                }
            }
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if !cfg_enabled(expr_attrs(expr)) {
            return;
        }
        match expr {
            Expr::If(i) => match static_cond(&i.cond) {
                Some(true) => {
                    self.visit_block(&i.then_branch);
                    return;
                }
                Some(false) => {
                    if let Some((_, else_branch)) = &i.else_branch {
                        self.visit_expr(else_branch);
                    }
                    return;
                }
                None => {}
            },
            Expr::Call(call) => self.record_call(call),
            _ => {}
        }
        syn::visit::visit_expr(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = last_segment(&mac.path);
        if OPAQUE_MACROS.contains(&name.as_str()) {
            return;
        }
        // `tokio::try_join!(…)`, `vec![…]`, … : arguments are expressions.
        if let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
            for arg in &args {
                self.visit_expr(arg);
            }
            return;
        }
        // `tokio::select! { … }` and other statement-shaped bodies.
        if let Ok(stmts) = mac.parse_body_with(syn::Block::parse_within) {
            for stmt in &stmts {
                self.visit_stmt(stmt);
            }
        }
    }
}

impl Scan {
    fn walk(&mut self, repo: &Path, file: &Path, mod_dir: &Path) {
        let file = file
            .canonicalize()
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        if !self.files.insert(file.clone()) {
            return;
        }
        let src = std::fs::read_to_string(&file).unwrap();
        let ast = syn::parse_file(&src).unwrap_or_else(|e| panic!("parse {}: {e}", file.display()));
        if !cfg_enabled(&ast.attrs) {
            return;
        }
        let rel = file
            .strip_prefix(repo)
            .unwrap_or(&file)
            .to_string_lossy()
            .into_owned();
        let (queries, children) = scan_ast(&ast, &src, rel, &file, mod_dir);
        self.queries.extend(queries);
        for (child, child_dir) in children {
            self.walk(repo, &child, &child_dir);
        }
    }
}

type ScanResult = (Vec<FoundQuery>, Vec<(PathBuf, PathBuf)>);

fn scan_ast(ast: &syn::File, src: &str, rel: String, file: &Path, mod_dir: &Path) -> ScanResult {
    let bare_query_is_sqlx = src.contains("use sqlx::query;")
        || src.split("use sqlx::{").skip(1).any(|rest| {
            rest.split('}')
                .next()
                .unwrap_or("")
                .split(',')
                .any(|s| s.trim() == "query")
        });
    let empty = HashMap::new();
    // Pass 1: collect the `const`s the open build compiles.
    let mut consts = HashMap::new();
    {
        let mut collector = FileVisitor {
            rel: rel.clone(),
            mod_dir: mod_dir.to_path_buf(),
            file_dir: file.parent().unwrap().to_path_buf(),
            consts: &empty,
            bare_query_is_sqlx,
            collect_consts: Some(&mut consts),
            queries: Vec::new(),
            child_files: Vec::new(),
        };
        collector.visit_file(ast);
    }
    // Pass 2: resolve queries and child modules.
    let mut visitor = FileVisitor {
        rel,
        mod_dir: mod_dir.to_path_buf(),
        file_dir: file.parent().unwrap().to_path_buf(),
        consts: &consts,
        bare_query_is_sqlx,
        collect_consts: None,
        queries: Vec::new(),
        child_files: Vec::new(),
    };
    visitor.visit_file(ast);
    (visitor.queries, visitor.child_files)
}

/// Binaries of `crate_dir` that an open build compiles (no `required-features`).
fn crate_roots(crate_dir: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = ["src/lib.rs", "src/main.rs"]
        .iter()
        .map(|p| crate_dir.join(p))
        .filter(|p| p.exists())
        .collect();
    let manifest = std::fs::read_to_string(crate_dir.join("Cargo.toml")).unwrap();
    let mut gated = BTreeSet::new();
    for block in manifest.split("[[bin]]").skip(1) {
        let block = block.split("\n[").next().unwrap_or("");
        if !block.contains("required-features") {
            continue;
        }
        for line in block.lines() {
            if let Some(path) = line.trim().strip_prefix("path = \"") {
                gated.insert(crate_dir.join(path.trim_end_matches('"')));
            }
        }
    }
    let bin_dir = crate_dir.join("src/bin");
    if let Ok(entries) = std::fs::read_dir(&bin_dir) {
        let mut bins: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter_map(|p| {
                if p.extension().is_some_and(|x| x == "rs") {
                    Some(p)
                } else if p.join("main.rs").exists() {
                    Some(p.join("main.rs"))
                } else {
                    None
                }
            })
            .filter(|p| !gated.contains(p))
            .collect();
        bins.sort();
        roots.extend(bins);
    }
    roots
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
}

fn scan_open_sources() -> Scan {
    let repo = repo_root();
    let mut scan = Scan::default();
    for krate in CRATES {
        for root in crate_roots(&repo.join(krate)) {
            let mod_dir = module_dir_of(&root, true);
            scan.walk(&repo, &root, &mod_dir);
        }
    }
    scan
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn scan_snippet(src: &str) -> Vec<String> {
    let ast = syn::parse_file(src).unwrap();
    let file = Path::new("/nonexistent/snippet.rs");
    let (queries, _) = scan_ast(
        &ast,
        src,
        "snippet.rs".into(),
        file,
        Path::new("/nonexistent"),
    );
    queries.into_iter().map(|q| q.sql).collect()
}

#[test]
fn extractor_follows_the_open_build() {
    let found = scan_snippet(
        r#"
        use sqlx::query;
        const OPEN_SQL: &str = "SELECT 1 FROM open_t";
        #[cfg(feature = "enterprise")]
        const GATED: &str = "SELECT 1 FROM enterprise_only_const";
        #[cfg(not(feature = "enterprise"))]
        const GATED: &str = "SELECT 1 FROM open_variant";

        async fn f() {
            sqlx::query(concat!("INSERT INTO t (a) VALUES ($1) ON CONFLICT (", crate::tenant_key!(), "a) DO NOTHING"));
            query("SELECT 1 FROM bare");
            sqlx::query_scalar::<_, i64>(OPEN_SQL);
            sqlx::query(GATED);
            #[cfg(feature = "enterprise")]
            sqlx::query("SELECT 1 FROM enterprise_only_stmt");
            if cfg!(feature = "enterprise") {
                sqlx::query("SELECT 1 FROM enterprise_only_branch");
            } else {
                sqlx::query("SELECT 1 FROM open_branch");
            }
            let _ = tokio::try_join!(sqlx::query("SELECT 1 FROM in_macro").fetch_one(p));
            client.query("SELECT count() FROM clickhouse_logs");
            if !cfg!(feature = "enterprise") {
                return;
            }
            sqlx::query("SELECT 1 FROM after_open_guard");
        }

        #[cfg(test)]
        mod tests { fn t() { sqlx::query("SELECT 1 FROM test_only"); } }
        "#,
    );
    assert_eq!(
        found,
        vec![
            "INSERT INTO t (a) VALUES ($1) ON CONFLICT (a) DO NOTHING",
            "SELECT 1 FROM bare",
            "SELECT 1 FROM open_t",
            "SELECT 1 FROM open_variant",
            "SELECT 1 FROM open_branch",
            "SELECT 1 FROM in_macro",
        ]
    );
}

/// Guards the walk itself, so the DB test below cannot pass vacuously.
#[test]
fn walk_reaches_the_open_detection_path() {
    let scan = scan_open_sources();
    assert!(
        scan.queries.len() > 1000,
        "only {} sqlx queries found in {} files; the module walk is broken",
        scan.queries.len(),
        scan.files.len()
    );
    // The NAN-3462 conflict target, expanded to its open form.
    assert!(
        scan.queries
            .iter()
            .any(|q| q.sql.contains("detection_daily_stats")
                && q.sql.contains("ON CONFLICT (rule_id, date)")),
        "detection_daily_stats upsert not found with its open conflict target"
    );
}

#[derive(Debug)]
struct Finding {
    file: String,
    line: usize,
    code: String,
    object: String,
    message: String,
    sql: String,
}

/// The missing object a Postgres error names.
fn missing_object(code: &str, message: &str) -> String {
    if code == "42P10" {
        return "ON CONFLICT".to_string();
    }
    let rest = message
        .strip_prefix("relation ")
        .or_else(|| message.strip_prefix("column "))
        .or_else(|| message.strip_prefix("function "))
        .or_else(|| message.strip_prefix("schema "))
        .unwrap_or(message);
    let token = if let Some(quoted) = rest.strip_prefix('"') {
        quoted.split('"').next().unwrap_or(quoted)
    } else {
        rest.split([' ', '(']).next().unwrap_or(rest)
    };
    token.to_string()
}

fn allows((file, object, _): &(&str, &str, &str), finding: &Finding) -> bool {
    *file == finding.file && (*object == "*" || *object == finding.object)
}

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/postgres".to_string())
}

fn url_for(db: &str) -> String {
    let admin = admin_url();
    let last_slash = admin.rfind('/').expect("admin url must contain '/'");
    format!("{}/{}", &admin[..last_slash], db)
}

#[tokio::test]
#[ignore = "DB-backed; run with --ignored in pg-integration-tests"]
async fn open_sql_matches_the_open_schema() {
    common::assert_destructive_opt_in(&admin_url());

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await
        .expect("connect admin db");
    let _ = admin
        .execute(
            format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = '{TEST_DB}' AND pid <> pg_backend_pid()"
            )
            .as_str(),
        )
        .await;
    admin
        .execute(format!("DROP DATABASE IF EXISTS {TEST_DB}").as_str())
        .await
        .expect("drop scan db");
    admin
        .execute(format!("CREATE DATABASE {TEST_DB}").as_str())
        .await
        .expect("create scan db");

    // The open fresh-init path: snapshot, backfill, post-baseline migrations.
    // `run_postgres_migrations` never applies the enterprise overlay.
    std::env::remove_var("NANOSIEM_MIGRATION_MODE");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url_for(TEST_DB))
        .await
        .expect("connect scan db");
    nanosiem_core::db::run_postgres_migrations(&pool)
        .await
        .expect("open fresh-init migrations");
    pool.close().await;

    let scan = scan_open_sources();
    let mut by_sql: BTreeMap<String, Vec<&FoundQuery>> = BTreeMap::new();
    for q in &scan.queries {
        by_sql.entry(q.sql.clone()).or_default().push(q);
    }

    let mut conn = PgConnection::connect(&url_for(TEST_DB))
        .await
        .expect("connect scan db");
    let mut findings = Vec::new();
    for (sql, sites) in &by_sql {
        let Err(sqlx::Error::Database(err)) = conn.prepare(sql.as_str()).await else {
            continue;
        };
        let code = err.code().map(|c| c.into_owned()).unwrap_or_default();
        if !MISSING_OBJECT_CODES.contains(&code.as_str()) {
            continue;
        }
        // 42883 also covers "operator does not exist", which PREPARE raises when
        // it infers an untyped `$n` from its neighbour (`$1 + INTERVAL …` makes
        // `$1` an interval) while the runtime binds a typed value. Only a
        // missing *function* is a schema finding.
        if code == "42883" && !err.message().starts_with("function ") {
            continue;
        }
        let object = missing_object(&code, err.message());
        for site in sites {
            findings.push(Finding {
                file: site.file.clone(),
                line: site.line,
                code: code.clone(),
                object: object.clone(),
                message: err.message().to_string(),
                sql: sql.clone(),
            });
        }
    }
    conn.close().await.ok();

    let unexplained: Vec<&Finding> = findings
        .iter()
        .filter(|f| !ALLOWED.iter().any(|entry| allows(entry, f)))
        .collect();
    let stale: Vec<&(&str, &str, &str)> = ALLOWED
        .iter()
        .filter(|entry| !findings.iter().any(|f| allows(entry, f)))
        .collect();

    let mut report = String::new();
    for f in &unexplained {
        let snippet: String = f.sql.split_whitespace().collect::<Vec<_>>().join(" ");
        let snippet: String = snippet.chars().take(160).collect();
        report.push_str(&format!(
            "  {}:{} [{}] {} -- {}\n      ({:?}, {:?}, REASON),\n",
            f.file, f.line, f.code, f.message, snippet, f.file, f.object
        ));
    }
    assert!(
        unexplained.is_empty(),
        "\n{} open-edition query site(s) reference objects the open schema does not have.\n\
         Fix the SQL (e.g. `tenant_key!()` for a tenant-led ON CONFLICT target), add the \
         object to the open schema, compile the code out of the open build, or allowlist it \
         in ALLOWED with the reason the open build never runs it:\n{report}",
        unexplained.len()
    );
    assert!(
        stale.is_empty(),
        "ALLOWED entries that no longer match any finding (remove them): {stale:#?}"
    );
    eprintln!(
        "prepared {} distinct statements from {} sites in {} files; {} allowlisted findings",
        by_sql.len(),
        scan.queries.len(),
        scan.files.len(),
        findings.len()
    );
}

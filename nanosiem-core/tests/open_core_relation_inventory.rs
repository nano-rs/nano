// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fresh open-core PostgreSQL relation inventory.
//!
//! It walks the Rust modules that an open build compiles (evaluating the
//! `cfg(test)` and `cfg(feature = "enterprise")` gates statically, so the
//! result is the same in the private tree and in the stripped mirror),
//! extracts PostgreSQL relation names from SQL string literals, migrates an
//! empty database through the real fresh-open path, and compares the two sets.
//!
//! The open-source stack gate runs it on the stripped mirror tree; the PG
//! integration workflow runs it on the private tree, where the enterprise
//! overlay's table names also count as candidates for SQL held outside a
//! direct `sqlx` call.
//!
//! `migrations/postgres-open/000_open_init.sql` is a snapshot whose migration
//! history is backfilled through version 175. A relation created by an older
//! shared migration can therefore be absent forever when the snapshot splitter
//! classifies it as enterprise-only. Compile checks cannot detect that drift;
//! only the code-to-fresh-schema comparison below can.

use proc_macro2::{TokenStream, TokenTree};
use regex::Regex;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool, Row};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::Visit;
use syn::{Attribute, Expr, Item, Lit, LitStr, Meta, Token};

const DB_PREFIX: &str = "nanosiem_open_relation_inventory_";

#[derive(Debug, Clone)]
struct LiteralSource {
    value: String,
    path: PathBuf,
}

#[derive(Default)]
struct LiteralCollector {
    path: PathBuf,
    literals: Vec<LiteralSource>,
}

#[derive(Default)]
struct SqlLiteralCollector {
    path: PathBuf,
    literals: Vec<LiteralSource>,
}

impl SqlLiteralCollector {
    fn collect_expr(&mut self, expr: &Expr) {
        let mut collector = LiteralCollector {
            path: self.path.clone(),
            literals: Vec::new(),
        };
        collector.visit_expr(expr);
        self.literals.extend(collector.literals);
    }

    fn collect_tokens(&mut self, tokens: TokenStream) {
        let mut collector = LiteralCollector {
            path: self.path.clone(),
            literals: Vec::new(),
        };
        collector.collect_tokens(tokens);
        self.literals.extend(collector.literals);
    }
}

impl LiteralCollector {
    fn push(&mut self, value: String) {
        self.literals.push(LiteralSource {
            value,
            path: self.path.clone(),
        });
    }

    fn collect_tokens(&mut self, tokens: TokenStream) {
        for token in tokens {
            match token {
                TokenTree::Group(group) => self.collect_tokens(group.stream()),
                TokenTree::Literal(literal) => {
                    if let Ok(value) = syn::parse_str::<LitStr>(&literal.to_string()) {
                        self.push(value.value());
                    }
                }
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for LiteralCollector {
    fn visit_attribute(&mut self, node: &'ast Attribute) {
        // Rust doc comments are represented as string-valued `#[doc = ...]`
        // attributes. Prose such as "group alerts into cases" is not SQL.
        if !node.path().is_ident("doc") {
            syn::visit::visit_attribute(self, node);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_expr_if(self, node);
        }
    }

    fn visit_expr_block(&mut self, node: &'ast syn::ExprBlock) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_expr_block(self, node);
        }
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_expr_match(self, node);
        }
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_arm(self, node);
        }
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_local(self, node);
        }
    }

    fn visit_lit_str(&mut self, node: &'ast LitStr) {
        self.push(node.value());
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // syn does not visit literals inside opaque macro token streams. SQL
        // commonly lives in format!/concat!/sqlx macro arguments, so recurse
        // through their tokens explicitly.
        self.collect_tokens(node.tokens.clone());
    }

    fn visit_item_mod(&mut self, _node: &'ast syn::ItemMod) {
        // Module bodies are handled by `collect_items`, which also resolves
        // external `mod foo;` files and evaluates the cfg on the declaration.
    }
}

impl<'ast> Visit<'ast> for SqlLiteralCollector {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_expr_if(self, node);
        }
    }

    fn visit_expr_block(&mut self, node: &'ast syn::ExprBlock) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_expr_block(self, node);
        }
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_expr_match(self, node);
        }
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_arm(self, node);
        }
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if attrs_enabled(&node.attrs) {
            syn::visit::visit_local(self, node);
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(function) = node.func.as_ref() {
            let name = function
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            let sqlx_call = function
                .path
                .segments
                .first()
                .is_some_and(|segment| segment.ident == "sqlx")
                && name.as_deref().is_some_and(|name| {
                    matches!(
                        name,
                        "query"
                            | "query_as"
                            | "query_as_with"
                            | "query_scalar"
                            | "query_scalar_with"
                            | "query_with"
                            | "raw_sql"
                    )
                });
            let query_builder = name.as_deref() == Some("new")
                && function
                    .path
                    .segments
                    .iter()
                    .any(|segment| segment.ident == "QueryBuilder");
            if query_builder || sqlx_call {
                for argument in &node.args {
                    self.collect_expr(argument);
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let sqlx_macro = node
            .path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == "sqlx");
        let name = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        if sqlx_macro
            && name.as_deref().is_some_and(|name| {
                matches!(name, "query" | "query_as" | "query_scalar" | "raw_sql")
            })
        {
            self.collect_tokens(node.tokens.clone());
        }
    }

    fn visit_item_mod(&mut self, _node: &'ast syn::ItemMod) {}
}

fn cfg_meta_enabled(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) if path.is_ident("test") => false,
        Meta::Path(path) if path.is_ident("unix") => cfg!(unix),
        Meta::Path(path) if path.is_ident("windows") => cfg!(windows),
        // Custom bare cfgs (for example `nano_content_acceptance`) are off in
        // the normal stripped build unless rustc was explicitly given them.
        Meta::Path(_) => false,
        Meta::NameValue(value) if value.path.is_ident("feature") => {
            // The stripped mirror declares no enterprise feature and all open
            // packages use empty default feature sets.
            false
        }
        Meta::NameValue(value) if value.path.is_ident("target_os") => {
            matches!(&value.value, Expr::Lit(expr) if matches!(&expr.lit, Lit::Str(os) if os.value() == std::env::consts::OS))
        }
        Meta::NameValue(value) if value.path.is_ident("target_arch") => {
            matches!(&value.value, Expr::Lit(expr) if matches!(&expr.lit, Lit::Str(arch) if arch.value() == std::env::consts::ARCH))
        }
        Meta::NameValue(_) => true,
        Meta::List(list) if list.path.is_ident("all") => {
            let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
            parser
                .parse2(list.tokens.clone())
                .is_ok_and(|items| items.iter().all(cfg_meta_enabled))
        }
        Meta::List(list) if list.path.is_ident("any") => {
            let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
            parser
                .parse2(list.tokens.clone())
                .is_ok_and(|items| items.iter().any(cfg_meta_enabled))
        }
        Meta::List(list) if list.path.is_ident("not") => {
            syn::parse2::<Meta>(list.tokens.clone()).is_ok_and(|inner| !cfg_meta_enabled(&inner))
        }
        Meta::List(_) => true,
    }
}

fn attrs_enabled(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .all(|attr| {
            attr.parse_args::<Meta>()
                .is_ok_and(|meta| cfg_meta_enabled(&meta))
        })
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        Item::Verbatim(_) | _ => &[],
    }
}

fn path_override(attrs: &[Attribute]) -> Option<PathBuf> {
    attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("path") {
            return None;
        }
        let Meta::NameValue(value) = &attr.meta else {
            return None;
        };
        let Expr::Lit(expr) = &value.value else {
            return None;
        };
        let Lit::Str(path) = &expr.lit else {
            return None;
        };
        Some(PathBuf::from(path.value()))
    })
}

fn external_module_path(module_dir: &Path, source_path: &Path, item: &syn::ItemMod) -> PathBuf {
    if let Some(path) = path_override(&item.attrs) {
        // Rust reference: a `#[path]` on a module declared at the top level of
        // a file is relative to that file's directory; inside an inline module
        // block it is relative to the inline module's directory.
        if module_dir == module_dir_for_file(source_path) {
            return source_path
                .parent()
                .expect("Rust module file has a parent")
                .join(path);
        }
        return module_dir.join(path);
    }
    let name = item.ident.to_string();
    let flat = module_dir.join(format!("{name}.rs"));
    if flat.is_file() {
        flat
    } else {
        module_dir.join(name).join("mod.rs")
    }
}

fn module_dir_for_file(path: &Path) -> PathBuf {
    let parent = path.parent().expect("Rust module file has a parent");
    if path.file_name().is_some_and(|name| name == "mod.rs") {
        parent.to_path_buf()
    } else {
        parent.join(path.file_stem().expect("Rust module file has a stem"))
    }
}

fn collect_module_file(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    literals: &mut Vec<LiteralSource>,
    sql_literals: &mut Vec<LiteralSource>,
) {
    let module_dir = module_dir_for_file(path);
    collect_module_file_from(path, &module_dir, visited, literals, sql_literals);
}

fn collect_module_file_from(
    path: &Path,
    module_dir: &Path,
    visited: &mut HashSet<PathBuf>,
    literals: &mut Vec<LiteralSource>,
    sql_literals: &mut Vec<LiteralSource>,
) {
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|error| panic!("cannot resolve Rust module {}: {error}", path.display()));
    if !visited.insert(canonical.clone()) {
        return;
    }
    let source = fs::read_to_string(&canonical)
        .unwrap_or_else(|error| panic!("cannot read Rust module {}: {error}", canonical.display()));
    let syntax = syn::parse_file(&source).unwrap_or_else(|error| {
        panic!("cannot parse Rust module {}: {error}", canonical.display())
    });
    collect_items(
        &syntax.items,
        module_dir,
        &canonical,
        visited,
        literals,
        sql_literals,
    );
}

fn collect_items(
    items: &[Item],
    module_dir: &Path,
    source_path: &Path,
    visited: &mut HashSet<PathBuf>,
    literals: &mut Vec<LiteralSource>,
    sql_literals: &mut Vec<LiteralSource>,
) {
    for item in items {
        if !attrs_enabled(item_attrs(item)) {
            continue;
        }
        if let Item::Mod(module) = item {
            if let Some((_, inline_items)) = &module.content {
                collect_items(
                    inline_items,
                    &module_dir.join(module.ident.to_string()),
                    source_path,
                    visited,
                    literals,
                    sql_literals,
                );
            } else {
                let child = external_module_path(module_dir, source_path, module);
                assert!(
                    child.is_file(),
                    "enabled module `{}` declared by {} has no source at {}",
                    module.ident,
                    source_path.display(),
                    child.display()
                );
                collect_module_file(&child, visited, literals, sql_literals);
            }
            continue;
        }

        let mut collector = LiteralCollector {
            path: source_path.to_path_buf(),
            literals: Vec::new(),
        };
        collector.visit_item(item);
        literals.extend(collector.literals);

        let mut sql_collector = SqlLiteralCollector {
            path: source_path.to_path_buf(),
            literals: Vec::new(),
        };
        sql_collector.visit_item(item);
        sql_literals.extend(sql_collector.literals);
    }
}

fn runtime_literals(workspace: &Path) -> (Vec<LiteralSource>, Vec<LiteralSource>) {
    let roots = [
        "nanosiem-core/src/lib.rs",
        "nanosiem-api-lib/src/lib.rs",
        "nanosiem-api/src/lib.rs",
        "nanosiem-api/src/main.rs",
        "nanosiem-api/src/bin/jobs.rs",
        "nanosiem-api/src/bin/clickhouse_migrator.rs",
        "nanosiem-search/src/lib.rs",
        "nanosiem-search/src/main.rs",
        "nano-connector/src/lib.rs",
    ];
    let mut visited = HashSet::new();
    let mut literals = Vec::new();
    let mut sql_literals = Vec::new();
    for root in roots {
        let root = workspace.join(root);
        let module_dir = root.parent().expect("crate root has a source directory");
        collect_module_file_from(
            &root,
            module_dir,
            &mut visited,
            &mut literals,
            &mut sql_literals,
        );
    }
    (literals, sql_literals)
}

fn relation_candidates(workspace: &Path) -> BTreeSet<String> {
    let create = Regex::new(
        r#"(?i)\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:UNLOGGED\s+|MATERIALIZED\s+)?(?:TABLE|VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"#,
    )
    .unwrap();
    let mut relations = BTreeSet::new();
    // The enterprise overlay is stripped from the mirror; in the private tree
    // its relations are candidates too, so a literal naming an enterprise-only
    // table is caught even when it is not passed straight to `sqlx`.
    let mut sources = vec![workspace.join("migrations/postgres")];
    let enterprise = workspace.join("migrations/postgres-enterprise");
    if enterprise.is_dir() {
        sources.push(enterprise);
    }
    for path in sources.iter().flat_map(|dir| {
        fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
            .map(|entry| entry.expect("migration directory entry").path())
    }) {
        if path.extension().is_some_and(|extension| extension == "sql") {
            let sql = fs::read_to_string(&path).expect("read PostgreSQL migration");
            relations.extend(
                create
                    .captures_iter(&sql)
                    .map(|capture| capture[1].to_lowercase()),
            );
        }
    }
    relations
}

fn sql_comments() -> Regex {
    Regex::new(r"(?ms)--[^\r\n]*|/\*.*?\*/").unwrap()
}

/// Session-local tables created at runtime, keyed by the source file whose SQL
/// creates them.
///
/// Only literals handed straight to `sqlx` count (with SQL comments removed):
/// prose such as an error message mentioning "CREATE TEMPORARY TABLE
/// permissions" must never hide a real table. The exemption is per file, so
/// a temp table in one module cannot mask a genuinely missing permanent table
/// of the same name referenced from another.
fn temporary_relations(direct_sql_literals: &[LiteralSource]) -> BTreeMap<PathBuf, BTreeSet<String>> {
    // `CREATE [LOCAL|GLOBAL] TEMP[ORARY] TABLE [IF NOT EXISTS] [pg_temp.]name`
    // and `CREATE TABLE [IF NOT EXISTS] pg_temp.name` both create a
    // session-local table.
    let temporary = Regex::new(
        r#"(?ix)
        \bCREATE\s+(?:
            (?:(?:LOCAL|GLOBAL)\s+)?(?:TEMP|TEMPORARY)\s+(?:UNLOGGED\s+)?TABLE\s+
            (?:IF\s+NOT\s+EXISTS\s+)?(?:"?pg_temp"?\s*\.\s*)?
          | (?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?pg_temp"?\s*\.\s*
        )
        "?([a-z_][a-z0-9_]*)
        "#,
    )
    .unwrap();
    let comments = sql_comments();
    let mut by_file: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    for literal in direct_sql_literals {
        let sql = comments.replace_all(&literal.value, " ");
        for capture in temporary.captures_iter(&sql) {
            by_file
                .entry(literal.path.clone())
                .or_default()
                .insert(capture[1].to_lowercase());
        }
    }
    by_file
}

/// Normalizes a matched schema qualifier the way PostgreSQL resolves it:
/// unquoted identifiers fold to lower case, quoted ones are exact.
fn schema_name(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        raw[1..raw.len() - 1].to_string()
    } else {
        raw.trim_matches('"').to_lowercase()
    }
}

fn previous_words(sql_before: &str, count: usize) -> Vec<String> {
    let mut words: Vec<String> = sql_before
        .split_whitespace()
        .rev()
        .take(count)
        .map(|word| word.to_ascii_uppercase())
        .collect();
    words.reverse();
    words
}

/// True when the UPDATE that follows `sql_before` is a clause keyword rather
/// than the start of an `UPDATE <relation>` statement.
fn update_is_control_syntax(sql_before: &str) -> bool {
    let words = previous_words(sql_before, 3);
    let last = words.last().map(String::as_str);
    matches!(last, Some("DO" | "FOR")) || words.ends_with(&["FOR".into(), "NO".into(), "KEY".into()])
}

/// True when the FROM that follows `sql_before` belongs to an expression:
/// `IS [NOT] DISTINCT FROM`, or the `FROM` argument separator of
/// `EXTRACT(field FROM src)`, `TRIM(... FROM src)`, `SUBSTRING(src FROM ...)`
/// and `OVERLAY(src PLACING x FROM n)`.
fn from_is_expression_syntax(sql_before: &str) -> bool {
    if previous_words(sql_before, 1).first().is_some_and(|word| word == "DISTINCT") {
        return true;
    }
    // Find the innermost unclosed `(` before this FROM, then the identifier
    // immediately before it.
    let mut depth = 0usize;
    for (index, ch) in sql_before.char_indices().rev() {
        match ch {
            ')' => depth += 1,
            '(' if depth > 0 => depth -= 1,
            '(' => {
                let function = sql_before[..index]
                    .trim_end()
                    .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or("");
                return ["extract", "trim", "substring", "overlay"]
                    .iter()
                    .any(|name| function.eq_ignore_ascii_case(name));
            }
            _ => {}
        }
    }
    false
}

fn relation_references(
    candidates: &BTreeSet<String>,
    runtime_literals: Vec<LiteralSource>,
    direct_sql_literals: Vec<LiteralSource>,
) -> BTreeMap<String, BTreeSet<PathBuf>> {
    let relation = Regex::new(
        r#"(?ix)
        \b(?P<operation>FROM|JOIN|UPDATE|INSERT\s+INTO|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?|LOCK\s+TABLE)
        \s+(?:ONLY\s+)?(?:LATERAL\s+)?
        (?:(?P<schema>"?[a-z_][a-z0-9_]*"?)\s*\.\s*)?
        "?(?P<name>[a-z_][a-z0-9_]*)"?
        "#,
    )
    .unwrap();
    let comments = sql_comments();
    // `WITH [RECURSIVE] name [(col, ...)] AS [[NOT] MATERIALIZED] (`, also
    // after a comma for the second and later CTEs.
    let cte = Regex::new(
        r#"(?i)(?:\bWITH(?:\s+RECURSIVE)?|,)\s*"?([a-z_][a-z0-9_]*)"?(?:\s*\([^()]*\))?\s+AS\s*(?:(?:NOT\s+)?MATERIALIZED\s*)?\("#,
    )
    .unwrap();
    // A `CREATE TEMP TABLE` is usually its own statement, so the INSERT /
    // SELECT / TRUNCATE that use it are separate literals in the same file
    // (for example the `ON COMMIT DROP` slice table in content_bundle/store.rs).
    let temporary = temporary_relations(&direct_sql_literals);
    let no_temporary = BTreeSet::new();
    let mut references: BTreeMap<String, BTreeSet<PathBuf>> = BTreeMap::new();

    for (literal, allow_unknown) in runtime_literals
        .into_iter()
        .map(|literal| (literal, false))
        .chain(
            direct_sql_literals
                .into_iter()
                .map(|literal| (literal, true)),
        )
    {
        let sql = comments.replace_all(&literal.value, " ");
        let ctes: BTreeSet<String> = cte
            .captures_iter(&sql)
            .map(|capture| capture[1].to_lowercase())
            .collect();
        let file_temporary = temporary.get(&literal.path).unwrap_or(&no_temporary);
        for capture in relation.captures_iter(&sql) {
            let matched = capture.get(0).expect("relation match has a span");
            if capture["operation"].eq_ignore_ascii_case("UPDATE")
                && update_is_control_syntax(&sql[..matched.start()])
            {
                // `ON CONFLICT DO UPDATE SET` and `SELECT ... FOR [NO KEY]
                // UPDATE SKIP LOCKED` contain UPDATE as control syntax, not a
                // relation.
                continue;
            }
            if capture["operation"].eq_ignore_ascii_case("FROM")
                && from_is_expression_syntax(&sql[..matched.start()])
            {
                // `IS [NOT] DISTINCT FROM col` and `EXTRACT(EPOCH FROM col)`
                // style calls use FROM inside an expression, not a FROM clause.
                continue;
            }
            let reads_rows = capture["operation"].eq_ignore_ascii_case("FROM")
                || capture["operation"].eq_ignore_ascii_case("JOIN");
            if reads_rows && sql[matched.end()..].trim_start().starts_with('(') {
                // `FROM jsonb_array_elements(...)` and similar table
                // functions do not name relations. Only FROM / JOIN take a
                // function there: `INSERT INTO t (a, b)` is a column list and
                // `t` must still be checked (NAN-5727).
                continue;
            }
            let schema = capture.name("schema").map(|schema| schema_name(schema.as_str()));
            if schema.as_deref().is_some_and(|schema| schema != "public") {
                // pg_catalog, information_schema and pg_temp are supplied by
                // PostgreSQL or the session, not the open migration set.
                continue;
            }
            let name = capture["name"].to_lowercase();
            // An explicit `public.` qualifier names a permanent relation; a
            // temp table never lives in `public`, so it is never exempt.
            let session_local = schema.is_none() && file_temporary.contains(&name);
            if ctes.contains(&name)
                || session_local
                || (!allow_unknown && !candidates.contains(&name))
            {
                continue;
            }
            references
                .entry(name)
                .or_default()
                .insert(literal.path.clone());
        }
    }
    references
}

fn referenced_relations(workspace: &Path) -> BTreeMap<String, BTreeSet<PathBuf>> {
    let candidates = relation_candidates(workspace);
    let (runtime_literals, direct_sql_literals) = runtime_literals(workspace);
    relation_references(&candidates, runtime_literals, direct_sql_literals)
}

fn admin_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL").ok()
}

fn database_url(admin: &str, database: &str) -> String {
    let slash = admin
        .rfind('/')
        .expect("TEST_DATABASE_URL must include a database path");
    format!("{}/{database}", &admin[..slash])
}

async fn recreate_database(admin_url: &str, database: &str) -> PgPool {
    assert_eq!(
        std::env::var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS").as_deref(),
        Ok("1"),
        "set NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 for the isolated relation inventory database"
    );
    assert!(
        database.starts_with(DB_PREFIX),
        "refusing to recreate a database outside the lane-owned prefix"
    );
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_url)
        .await
        .expect("connect to isolated PostgreSQL admin database");
    admin
        .execute(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)")))
        .await
        .expect("drop stale isolated inventory database");
    admin
        .execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .await
        .expect("create isolated inventory database");
    admin.close().await;
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url(admin_url, database))
        .await
        .expect("connect to isolated inventory database")
}

async fn available_relations(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query(
        "SELECT c.relname FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname IN ('public', 'pg_catalog', 'information_schema') \
           AND c.relkind IN ('r', 'p', 'v', 'm', 'f')",
    )
    .fetch_all(pool)
    .await
    .expect("list fresh open-core relations")
    .into_iter()
    .map(|row| row.get::<String, _>(0))
    .collect()
}

#[tokio::test]
async fn open_runtime_only_references_fresh_open_relations() {
    let Some(admin_url) = admin_url() else {
        // CI sets NANOSIEM_REQUIRE_RELATION_INVENTORY so a missing database
        // fails the gate instead of silently passing it.
        assert!(
            std::env::var("NANOSIEM_REQUIRE_RELATION_INVENTORY").as_deref() != Ok("1"),
            "NANOSIEM_REQUIRE_RELATION_INVENTORY=1 but TEST_DATABASE_URL is unset"
        );
        eprintln!("TEST_DATABASE_URL is unset; skipping the open-core relation inventory");
        return;
    };
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("nanosiem-core lives under the workspace root");

    let database = format!("{DB_PREFIX}{}", std::process::id());
    let pool = recreate_database(&admin_url, &database).await;
    std::env::set_var("NANOSIEM_MIGRATION_MODE", "fresh");
    nanosiem_core::db::run_postgres_migrations(&pool)
        .await
        .expect("migrate a fresh stripped open-core database");
    std::env::remove_var("NANOSIEM_MIGRATION_MODE");

    let schema = available_relations(&pool).await;
    let references = referenced_relations(workspace);
    let missing: Vec<_> = references
        .iter()
        .filter(|(relation, _)| !schema.contains(*relation))
        .collect();

    pool.close().await;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("reconnect for isolated database cleanup");
    admin
        .execute(sqlx::AssertSqlSafe(format!("DROP DATABASE {database} WITH (FORCE)")))
        .await
        .expect("drop isolated inventory database");

    assert!(
        missing.is_empty(),
        "stripped open-core runtime references PostgreSQL relations absent from a fresh open migration:\n{}",
        missing
            .iter()
            .map(|(relation, paths)| format!(
                "- {relation}: {}",
                paths
                    .iter()
                    .map(|path| path.strip_prefix(workspace).unwrap_or(path).display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// Self-tests for the reference scan (no database needed).

fn sql(path: &str, value: &str) -> LiteralSource {
    LiteralSource {
        value: value.to_string(),
        path: PathBuf::from(path),
    }
}

fn scan(
    candidates: &[&str],
    runtime: Vec<LiteralSource>,
    direct: Vec<LiteralSource>,
) -> BTreeMap<String, BTreeSet<PathBuf>> {
    let candidates = candidates.iter().map(|name| name.to_string()).collect();
    // `runtime_literals` is a superset of the direct sqlx literals, as in
    // `collect_items`.
    let runtime = runtime.into_iter().chain(direct.iter().cloned()).collect();
    relation_references(&candidates, runtime, direct)
}

#[test]
fn temp_table_used_from_separate_literals_in_same_file_is_exempt() {
    // The content_bundle/store.rs shape (NAN-5725).
    let references = scan(
        &["content_channel_files"],
        vec![],
        vec![
            sql("store.rs", "CREATE TEMP TABLE content_file_slices (n integer NOT NULL, part bytea NOT NULL) ON COMMIT DROP"),
            sql("store.rs", "INSERT INTO content_file_slices (n, part) VALUES ($1, $2)"),
            sql("store.rs", "INSERT INTO content_channel_files (channel) SELECT string_agg(part, ''::bytea ORDER BY n) FROM content_file_slices"),
            sql("store.rs", "TRUNCATE content_file_slices"),
            sql("store.rs", "SELECT octet_length(content) FROM content_channel_files WHERE channel = $1"),
        ],
    );
    assert!(!references.contains_key("content_file_slices"), "{references:?}");
    assert!(references.contains_key("content_channel_files"));
}

#[test]
fn temp_table_in_another_file_does_not_mask_a_missing_real_table() {
    let references = scan(
        &["staging"],
        vec![],
        vec![
            sql("a.rs", "CREATE TEMP TABLE staging (id bigint) ON COMMIT DROP"),
            sql("a.rs", "INSERT INTO staging (id) VALUES ($1)"),
            sql("b.rs", "SELECT id FROM staging"),
        ],
    );
    assert_eq!(
        references.get("staging"),
        Some(&BTreeSet::from([PathBuf::from("b.rs")])),
        "the reference from b.rs must still be checked against the schema"
    );
}

#[test]
fn public_qualified_reference_is_never_temp_exempt() {
    for reference in [
        "SELECT id FROM public.staging",
        "SELECT id FROM PUBLIC.staging",
        "SELECT id FROM \"public\".staging",
    ] {
        let references = scan(
            &["staging"],
            vec![],
            vec![
                sql("a.rs", "CREATE TEMP TABLE staging (id bigint)"),
                sql("a.rs", reference),
            ],
        );
        assert!(references.contains_key("staging"), "{reference}: {references:?}");
    }
}

#[test]
fn quoted_non_public_schema_is_skipped() {
    let references = scan(&["staging"], vec![], vec![sql("a.rs", "SELECT id FROM \"PUBLIC\".staging")]);
    assert!(references.is_empty(), "{references:?}");
}

#[test]
fn temp_table_syntax_variants_are_recognized() {
    for create in [
        "CREATE TEMPORARY TABLE staging (id bigint)",
        "CREATE LOCAL TEMP TABLE staging (id bigint)",
        "CREATE GLOBAL TEMPORARY TABLE staging (id bigint)",
        "create temp table if not exists \"Staging\" (id bigint)",
        "CREATE TEMP TABLE pg_temp.staging (id bigint)",
        "CREATE TEMP TABLE \"pg_temp\".\"staging\" (id bigint)",
        "CREATE TABLE pg_temp.staging (id bigint)",
    ] {
        let references = scan(
            &[],
            vec![],
            vec![sql("a.rs", create), sql("a.rs", "INSERT INTO staging (id) VALUES ($1)")],
        );
        assert!(references.is_empty(), "{create}: {references:?}");
    }
}

#[test]
fn pg_temp_qualified_reference_is_skipped() {
    let references = scan(&[], vec![], vec![sql("a.rs", "SELECT id FROM pg_temp.staging")]);
    assert!(references.is_empty(), "{references:?}");
}

#[test]
fn prose_and_sql_comments_do_not_create_temp_exemptions() {
    // A non-sqlx string (an error message) and a SQL comment both mention
    // CREATE TEMPORARY TABLE; neither may hide the real `permissions` table.
    let references = scan(
        &["permissions"],
        vec![
            sql("a.rs", "CREATE TEMPORARY TABLE permissions are denied for this role"),
            sql("a.rs", "SELECT id FROM permissions"),
        ],
        vec![sql("a.rs", "-- CREATE TEMP TABLE permissions (id int)\nSELECT id FROM permissions")],
    );
    assert!(references.contains_key("permissions"), "{references:?}");
}

#[test]
fn insert_with_column_list_is_checked() {
    // NAN-5727: `name (` after INSERT INTO is a column list, not a function.
    for statement in [
        "INSERT INTO missing_table (a) VALUES ($1)",
        "INSERT INTO missing_table(a, b) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        "INSERT INTO public.missing_table (a) SELECT 1",
    ] {
        let references = scan(&[], vec![], vec![sql("a.rs", statement)]);
        assert_eq!(
            references.get("missing_table"),
            Some(&BTreeSet::from([PathBuf::from("a.rs")])),
            "{statement}: {references:?}"
        );
    }
}

#[test]
fn table_functions_after_from_or_join_are_skipped() {
    for statement in [
        "SELECT value FROM jsonb_array_elements($1)",
        "SELECT * FROM t JOIN LATERAL unnest($1) (x) ON true",
        "SELECT g FROM generate_series (1, 10) g",
    ] {
        let references = scan(&[], vec![], vec![sql("a.rs", statement)]);
        assert!(
            !references.contains_key("jsonb_array_elements")
                && !references.contains_key("unnest")
                && !references.contains_key("generate_series"),
            "{statement}: {references:?}"
        );
    }
}

#[test]
fn valid_postgres_syntax_does_not_invent_relations() {
    // Each statement is valid PostgreSQL reading only `alerts`; the scan
    // must not report a CTE, a lock clause word or a column as a relation.
    for statement in [
        "WITH RECURSIVE tree AS (SELECT id FROM alerts UNION ALL SELECT a.id FROM alerts a JOIN tree t ON a.id = t.id) SELECT * FROM tree",
        "WITH sev_rank(name, weight) AS (VALUES ('high', 3)) SELECT * FROM alerts JOIN sev_rank ON true",
        "WITH recent AS MATERIALIZED (SELECT id FROM alerts) SELECT * FROM recent",
        "WITH recent AS NOT MATERIALIZED (SELECT id FROM alerts) SELECT * FROM recent",
        "WITH a AS (SELECT 1), pairs (k, v) AS (SELECT id, id FROM alerts) SELECT * FROM pairs",
        "SELECT 1 FROM alerts WHERE id = $1 FOR NO KEY UPDATE NOWAIT",
        "SELECT 1 FROM alerts WHERE id = $1 FOR NO KEY UPDATE SKIP LOCKED",
        "SELECT 1 FROM alerts WHERE id = $1 FOR UPDATE SKIP LOCKED",
        "INSERT INTO alerts (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id",
        "UPDATE alerts SET status = $1 WHERE status IS DISTINCT FROM status_before",
        "SELECT 1 FROM alerts WHERE status IS NOT DISTINCT FROM status_before",
        "SELECT EXTRACT(EPOCH FROM created_at) FROM alerts",
        "SELECT TRIM(BOTH '/' FROM path) FROM alerts",
        "SELECT SUBSTRING(title FROM 1 FOR 3) FROM alerts",
        "SELECT OVERLAY(title PLACING 'x' FROM 2) FROM alerts",
    ] {
        let references = scan(&["alerts"], vec![], vec![sql("a.rs", statement)]);
        assert!(
            references.keys().all(|name| name == "alerts"),
            "{statement}: {references:?}"
        );
    }
}

#[test]
fn expression_from_does_not_hide_a_real_from_clause() {
    // The FROM after the EXTRACT call closes is a real FROM clause.
    let references = scan(
        &[],
        vec![],
        vec![sql("a.rs", "SELECT EXTRACT(EPOCH FROM created_at) FROM missing_table")],
    );
    assert!(references.contains_key("missing_table"), "{references:?}");
}

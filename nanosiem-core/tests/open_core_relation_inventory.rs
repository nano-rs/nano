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

#[derive(Debug)]
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

fn referenced_relations(workspace: &Path) -> BTreeMap<String, BTreeSet<PathBuf>> {
    let candidates = relation_candidates(workspace);
    let relation = Regex::new(
        r#"(?ix)
        \b(?P<operation>FROM|JOIN|UPDATE|INSERT\s+INTO|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?|LOCK\s+TABLE)
        \s+(?:ONLY\s+)?(?:LATERAL\s+)?
        (?:(?P<schema>"?[a-z_][a-z0-9_]*"?)\s*\.\s*)?
        "?(?P<name>[a-z_][a-z0-9_]*)"?
        "#,
    )
    .unwrap();
    let comments = Regex::new(r"(?ms)--[^\r\n]*|/\*.*?\*/").unwrap();
    let cte = Regex::new(r"(?i)(?:\bWITH|,)\s*([a-z_][a-z0-9_]*)\s+AS\s*\(").unwrap();
    let temporary = Regex::new(
        r#"(?i)\bCREATE\s+(?:TEMP|TEMPORARY)\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z_][a-z0-9_]*)"#,
    )
    .unwrap();
    let mut references: BTreeMap<String, BTreeSet<PathBuf>> = BTreeMap::new();
    let (runtime_literals, direct_sql_literals) = runtime_literals(workspace);

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
        let temporary: BTreeSet<String> = temporary
            .captures_iter(&sql)
            .map(|capture| capture[1].to_lowercase())
            .collect();
        for capture in relation.captures_iter(&sql) {
            let matched = capture.get(0).expect("relation match has a span");
            if capture["operation"].eq_ignore_ascii_case("UPDATE")
                && sql[..matched.start()]
                    .split_whitespace()
                    .next_back()
                    .is_some_and(|word| {
                        word.eq_ignore_ascii_case("DO") || word.eq_ignore_ascii_case("FOR")
                    })
            {
                // `ON CONFLICT DO UPDATE SET` and `SELECT ... FOR UPDATE SKIP
                // LOCKED` contain UPDATE as control syntax, not a relation.
                continue;
            }
            if capture
                .get(0)
                .is_some_and(|matched| sql[matched.end()..].trim_start().starts_with('('))
            {
                // `FROM jsonb_array_elements(...)` and similar table
                // functions do not name relations.
                continue;
            }
            if capture
                .name("schema")
                .is_some_and(|schema| schema.as_str().trim_matches('"') != "public")
            {
                // pg_catalog and information_schema are supplied by PostgreSQL,
                // not the open migration set.
                continue;
            }
            let name = capture["name"].to_lowercase();
            if ctes.contains(&name)
                || temporary.contains(&name)
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
        .execute(format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)").as_str())
        .await
        .expect("drop stale isolated inventory database");
    admin
        .execute(format!("CREATE DATABASE {database}").as_str())
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
        .execute(format!("DROP DATABASE {database} WITH (FORCE)").as_str())
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

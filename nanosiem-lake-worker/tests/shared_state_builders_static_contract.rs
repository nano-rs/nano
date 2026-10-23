// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4195 (NAN-4194 regression guard): no production `Arc::get_mut` builder.
//!
//! T57 (10-19) panicked every ingest role at startup: `with_view_dir` called
//! `Arc::get_mut(&mut self.shared).expect("not shared yet")` after
//! `new_guarded` had already handed the R2 store a `Weak` to `Shared`, so
//! `get_mut` returned `None`. Its unit test used the unguarded constructor
//! and passed. A builder that mutates shared state after construction only
//! works while nothing else holds a reference, and a later constructor change
//! silently breaks it.
//!
//! This walks the module tree of nanosiem-lake-worker and nanosiem-lake-cell
//! from every crate root and binary (following `mod` / `#[path]`, skipping
//! anything compiled out by `cfg(test)`; feature cfgs count as reachable) and
//! refuses, outside test code:
//! - `Arc::get_mut(..)` / `Rc::get_mut(..)` unwrapped with `.expect` / `.unwrap`;
//! - any `Arc::get_mut` / `Rc::get_mut` in a `with_*` builder.
//!
//! Set options in the constructor before the `Arc` is created instead
//! (`CellPartGcWiring`, `new_guarded(.., view_dir)`), or make the builder
//! `#[cfg(test)]` on a constructor that never shares.

use std::path::{Path, PathBuf};
use syn::visit::Visit;
use syn::{Expr, Meta};

/// `Some(false)` = compiled out in every non-test build; `None` = depends on
/// features/target (reachable in some production build).
fn eval_cfg(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Some(false),
        Meta::List(list) => {
            let name = list.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
            let inner: Vec<Meta> = list
                .parse_args_with(syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated)
                .map(|p| p.into_iter().collect())
                .unwrap_or_default();
            let values: Vec<Option<bool>> = inner.iter().map(eval_cfg).collect();
            match name.as_str() {
                "not" => values.first().copied().flatten().map(|v| !v),
                "all" if values.contains(&Some(false)) => Some(false),
                "all" if values.iter().all(|v| *v == Some(true)) => Some(true),
                "any" if values.contains(&Some(true)) => Some(true),
                "any" if values.iter().all(|v| *v == Some(false)) => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

/// False when a `#[cfg(..)]` (or `#[test]`) makes the item test-only.
fn production(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().all(|attr| {
        let last = attr.path().segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        if last == "test" && attr.path().segments.len() <= 2 && matches!(attr.meta, Meta::Path(_)) {
            return false; // #[test], #[tokio::test]
        }
        if !attr.path().is_ident("cfg") {
            return true;
        }
        attr.parse_args::<Meta>().ok().and_then(|meta| eval_cfg(&meta)) != Some(false)
    })
}

fn is_get_mut_call(expr: &Expr) -> bool {
    let Expr::Call(call) = expr else { return false };
    let Expr::Path(path) = &*call.func else { return false };
    let segments: Vec<String> = path.path.segments.iter().map(|s| s.ident.to_string()).collect();
    segments.len() >= 2
        && segments[segments.len() - 1] == "get_mut"
        && matches!(segments[segments.len() - 2].as_str(), "Arc" | "Rc")
}

#[derive(Default)]
struct Scan {
    findings: Vec<String>,
    files: Vec<PathBuf>,
    pending: Vec<PathBuf>,
    file: PathBuf,
    /// Directory child `mod x;` declarations resolve against.
    mod_dir: PathBuf,
    /// Enclosing fn names (innermost last).
    fns: Vec<String>,
}

impl Scan {
    fn finding(&mut self, what: &str) {
        let at = self.fns.last().cloned().unwrap_or_else(|| "<item>".into());
        self.findings.push(format!("{}: fn {at}: {what}", self.file.display()));
    }

    fn in_with_builder(&self) -> bool {
        self.fns.last().is_some_and(|name| name.starts_with("with_"))
    }
}

impl<'ast> Visit<'ast> for Scan {
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
        if production(attrs) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::ImplItem::Fn(f) => &f.attrs,
            syn::ImplItem::Const(c) => &c.attrs,
            _ => &[],
        };
        if production(attrs) {
            syn::visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if let syn::TraitItem::Fn(f) = item {
            if !production(&f.attrs) {
                return;
            }
        }
        syn::visit::visit_trait_item(self, item);
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            syn::Stmt::Local(l) => &l.attrs,
            syn::Stmt::Macro(m) => &m.attrs,
            _ => &[],
        };
        if production(attrs) {
            syn::visit::visit_stmt(self, stmt);
        }
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.fns.push(f.sig.ident.to_string());
        syn::visit::visit_item_fn(self, f);
        self.fns.pop();
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.fns.push(f.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, f);
        self.fns.pop();
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if matches!(method.as_str(), "expect" | "unwrap") && is_get_mut_call(&call.receiver) {
            self.finding(&format!("Arc::get_mut(..).{method}(..) on shared state"));
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if self.in_with_builder() && is_get_mut_call(&Expr::Call(call.clone())) {
            self.finding("Arc::get_mut in a with_* builder");
        }
        syn::visit::visit_expr_call(self, call);
    }

    /// Macro bodies are not parsed: refuse the pattern in their tokens too.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let tokens = mac.tokens.to_string().replace(' ', "");
        if tokens.contains("Arc::get_mut(") || tokens.contains("Rc::get_mut(") {
            self.finding("Arc::get_mut inside a macro");
        }
        syn::visit::visit_macro(self, mac);
    }

    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        let path_attr = m.attrs.iter().find_map(|a| match &a.meta {
            Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
                Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        });
        let name = m.ident.to_string();
        match (&m.content, path_attr) {
            (None, Some(path)) => {
                let base = self.file.parent().unwrap().to_path_buf();
                self.pending.push(base.join(path));
            }
            (None, None) => {
                let flat = self.mod_dir.join(format!("{name}.rs"));
                let nested = self.mod_dir.join(&name).join("mod.rs");
                let file = if flat.exists() { flat } else { nested };
                assert!(file.exists(), "{}: mod {name} has no source file", self.file.display());
                self.pending.push(file);
            }
            (Some(_), _) => {
                let inner = self.mod_dir.join(&name);
                let outer = std::mem::replace(&mut self.mod_dir, inner);
                syn::visit::visit_item_mod(self, m);
                self.mod_dir = outer;
            }
        }
    }
}

fn module_dir(file: &Path, root: bool) -> PathBuf {
    let parent = file.parent().unwrap().to_path_buf();
    let stem = file.file_stem().unwrap().to_string_lossy();
    if root || stem == "mod" {
        parent
    } else {
        parent.join(stem.as_ref())
    }
}

fn scan_source(scan: &mut Scan, file: &Path, root: bool, source: &str) {
    let parsed = syn::parse_file(source).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    scan.file = file.to_path_buf();
    scan.mod_dir = module_dir(file, root);
    scan.visit_file(&parsed);
}

fn scan_crate(scan: &mut Scan, crate_dir: &Path) {
    let src = crate_dir.join("src");
    let mut roots = vec![src.join("lib.rs"), src.join("main.rs")];
    for dir in [src.join("bin")] {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "rs") {
                    roots.push(path);
                } else if path.join("main.rs").exists() {
                    roots.push(path.join("main.rs"));
                }
            }
        }
    }
    for root in roots.into_iter().filter(|r| r.exists()) {
        let source = std::fs::read_to_string(&root).unwrap();
        scan.files.push(root.clone());
        scan_source(scan, &root, true, &source);
        while let Some(file) = scan.pending.pop() {
            if scan.files.contains(&file) {
                continue;
            }
            let source = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
            scan.files.push(file.clone());
            scan_source(scan, &file, false, &source);
        }
    }
}

#[test]
fn no_production_builder_mutates_shared_state_through_arc_get_mut() {
    let worker = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cell = worker.parent().unwrap().join("nanosiem-lake-cell");
    let mut scan = Scan::default();
    scan_crate(&mut scan, &worker);
    scan_crate(&mut scan, &cell);
    // Not vacuous: the GC wiring and the ingest role were scanned.
    for required in ["src/part_ingest/part_gc_cell.rs", "src/part_ingest/cell.rs", "src/supervisor.rs"] {
        assert!(
            scan.files.iter().any(|f| f.ends_with(required)),
            "{required} was not reached from a crate root"
        );
    }
    assert!(
        !scan.files.iter().any(|f| f.ends_with("part_gc_transport_tests.rs")),
        "cfg(test) modules are not production code"
    );
    assert!(
        scan.findings.is_empty(),
        "production code mutates shared state after construction (NAN-4194: this panicked every \
         ingest role once a constructor shared the Arc). Set the option in the constructor \
         before the Arc exists, or make the builder #[cfg(test)]:\n{}",
        scan.findings.join("\n")
    );
}

/// The scanner itself: the T57 shape is caught, test-only builders are not.
#[test]
fn scanner_catches_the_nan4194_shape_and_skips_test_code() {
    let findings = |source: &str| {
        let mut scan = Scan::default();
        scan_source(&mut scan, Path::new("/fixture/lib.rs"), true, source);
        scan.findings
    };
    let t57 = r#"
        impl Gc {
            pub fn with_view_dir(mut self, dir: &Path) -> Self {
                let shared = Arc::get_mut(&mut self.shared).expect("not shared yet");
                shared.views = Some(ViewStore::new(dir));
                self
            }
        }"#;
    assert_eq!(findings(t57).len(), 2, "{:?}", findings(t57));
    let unwrapped = "fn f(a: &mut Arc<u8>) { *std::sync::Arc::get_mut(a).unwrap() = 1; }";
    assert_eq!(findings(unwrapped).len(), 1);
    let fallible = "fn f(a: &mut Arc<u8>) { if let Some(v) = Arc::get_mut(a) { *v = 1; } }";
    assert!(findings(fallible).is_empty());
    let in_macro = r#"fn f() { tokio::select! { _ = x => { Arc::get_mut(&mut a).unwrap(); } } }"#;
    assert_eq!(findings(in_macro).len(), 1);
    for test_only in [
        "#[cfg(test)] impl Gc { pub fn with_x(mut self) -> Self { Arc::get_mut(&mut self.s).expect(\"x\"); self } }",
        "impl Gc { #[cfg(test)] pub fn with_x(mut self) -> Self { Arc::get_mut(&mut self.s).expect(\"x\"); self } }",
        "#[cfg(test)] mod tests { fn t() { Arc::get_mut(&mut s).unwrap(); } }",
        "#[cfg(all(test, feature = \"x\"))] fn t() { Arc::get_mut(&mut s).unwrap(); }",
        "#[tokio::test] async fn t() { Arc::get_mut(&mut s).unwrap(); }",
    ] {
        assert!(findings(test_only).is_empty(), "{test_only}");
    }
    let feature_gated = "#[cfg(feature = \"enterprise\")] fn f() { Arc::get_mut(&mut s).unwrap(); }";
    assert_eq!(findings(feature_gated).len(), 1, "a feature build is production");
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5793 review round 2: no SQL generator is built for a request without
//! a source-scope decision.
//!
//! The unscoped constructors (`ClickHouseSqlGenerator::new` / `with_table` /
//! `Default`) exist only for tests (`cfg(test)` / the `test-support` feature),
//! so production code can only call `scoped` / `scoped_with_table` with a
//! `GeneratorScope`. The search service keeps its template private
//! (`ch_sql_generator_base`) and hands out generators only through
//! `sql_generator(scope)`. This guard pins the rest:
//! - no production dependency enables `nanosiem-core/test-support`;
//! - the template is read only by the accessor (and its constructors);
//! - every `GeneratorScope::unrestricted()` call site is listed, with why;
//! - nothing outside the generator re-scopes one (`with_source_scope_deny`).

use super::source_scope_inline_guard_tests::{skip_literal, strip_comments};
use std::path::{Path, PathBuf};

/// Every file allowed to build an UNRESTRICTED generator, how many times, and
/// why it has no viewer.
const UNRESTRICTED_ALLOWED: &[(&str, usize, &str)] = &[
    (
        "nanosiem-core/src/search/service/mod.rs",
        2,
        "the service's template; every use re-scopes it through `sql_generator`",
    ),
    ("nanosiem-core/src/detection/materialized_view.rs", 1, "real-time detection rules run as the system"),
    ("nanosiem-core/src/query/sql_to_npl/canon.rs", 1, "a conversion probe compiled for comparison"),
    ("nanosiem-core/src/bin/ocsf_rule_check.rs", 1, "an offline rule-compile check"),
    ("nanosiem-core/fuzz/fuzz_targets/fuzz_npl_to_sql.rs", 1, "the fuzzer"),
    (
        "nanosiem-enterprise/src/melod/query_response/mod.rs",
        1,
        "display SQL; the nPL runs through the search service under the viewer's scope",
    ),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Every workspace member (from the root manifest), so a new crate is
/// scanned without editing this file.
fn members() -> Vec<String> {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(root().join("Cargo.toml")).unwrap()).unwrap();
    let members: Vec<String> = manifest["workspace"]["members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|m| m.as_str().unwrap().to_string())
        .collect();
    for known in ["nanosiem-core", "nanosiem-api", "nanosiem-enterprise", "nano-connector"] {
        assert!(members.iter().any(|m| m == known), "workspace member {known} missing");
    }
    members
}

fn walk(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&path, ext, out);
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

/// `(relative path, comment-stripped source)` of every Rust file in the
/// crates (sources, tests, benches, bins, fuzz targets).
fn rust_sources() -> Vec<(String, String)> {
    let root = root();
    let mut files = Vec::new();
    for krate in members() {
        assert!(root.join(&krate).join("src").is_dir(), "missing crate {krate}");
        walk(&root.join(&krate), "rs", &mut files);
    }
    files
        .into_iter()
        .filter(|p| !p.ends_with("generator_scope_guard_tests.rs"))
        .map(|p| {
            let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            (rel, strip_comments(&std::fs::read_to_string(&p).unwrap_or_default()))
        })
        .collect()
}

/// `text` without its inline `#[cfg(test)] mod name { … }` blocks (a
/// `#[cfg(test)] mod name;` declaration is kept: its file is classified by
/// path).
fn without_test_modules(text: &str) -> String {
    let re = regex::Regex::new(
        r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{",
    )
    .unwrap();
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(m) = re.find(rest) {
        out.push_str(&rest[..m.start()]);
        let bytes = rest.as_bytes();
        let mut depth = 0i32;
        let mut end = rest.len();
        let mut i = m.end() - 1;
        while i < bytes.len() {
            // Braces inside string / char literals do not count.
            if let Some(after) = skip_literal(bytes, i) {
                i = after;
                continue;
            }
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn is_test_path(rel: &str) -> bool {
    rel.ends_with("_tests.rs")
        || rel.ends_with("/tests.rs")
        || rel.contains("/tests/")
        || rel.contains("/benches/")
}

/// Everything in `manifest` that turns on `nanosiem-core/test-support`
/// outside a dev-dependency: a dependency on nanosiem-core (by key or
/// `package = "nanosiem-core"`, inline or `[dependencies.x]` table, in
/// `[dependencies]`, `[build-dependencies]`, `[target.*.dependencies]` or
/// `[workspace.dependencies]`) whose features include it; a `[features]`
/// entry naming `<dep>/test-support` or `<dep>?/test-support`; and, in
/// nanosiem-core's own manifest, any feature (`default` included) that
/// enables `test-support`.
fn test_support_enablers(name: &str, manifest: &toml::Value) -> Vec<String> {
    let mut found = Vec::new();
    let is_core = |key: &str, spec: &toml::Value| {
        key == "nanosiem-core" || spec.get("package").and_then(|p| p.as_str()) == Some("nanosiem-core")
    };
    let enables = |spec: &toml::Value| {
        spec.get("features")
            .and_then(|f| f.as_array())
            .is_some_and(|f| f.iter().any(|x| x.as_str() == Some("test-support")))
    };
    let mut tables: Vec<(String, &toml::Value)> = Vec::new();
    for section in ["dependencies", "build-dependencies"] {
        if let Some(t) = manifest.get(section) {
            tables.push((section.to_string(), t));
        }
    }
    if let Some(t) = manifest.get("workspace").and_then(|w| w.get("dependencies")) {
        tables.push(("workspace.dependencies".to_string(), t));
    }
    if let Some(targets) = manifest.get("target").and_then(|t| t.as_table()) {
        for (cfg, target) in targets {
            for section in ["dependencies", "build-dependencies"] {
                if let Some(t) = target.get(section) {
                    tables.push((format!("target.{cfg}.{section}"), t));
                }
            }
        }
    }
    let mut core_aliases = vec!["nanosiem-core".to_string()];
    for (section, deps) in &tables {
        for (key, spec) in deps.as_table().into_iter().flatten() {
            if is_core(key, spec) {
                core_aliases.push(key.clone());
                if enables(spec) {
                    found.push(format!("{name}: [{section}] {key} enables test-support"));
                }
            }
        }
    }
    if let Some(features) = manifest.get("features").and_then(|f| f.as_table()) {
        for (feature, list) in features {
            for entry in list.as_array().into_iter().flatten().filter_map(|e| e.as_str()) {
                let via_dep = core_aliases.iter().any(|alias| {
                    entry == format!("{alias}/test-support") || entry == format!("{alias}?/test-support")
                });
                let own = name == "nanosiem-core" && entry == "test-support" && feature != "test-support";
                if via_dep || own {
                    found.push(format!("{name}: [features] {feature} = {entry}"));
                }
            }
        }
    }
    found
}

#[test]
fn no_production_dependency_enables_test_support() {
    let root = root();
    let mut manifests = vec![("workspace".to_string(), root.join("Cargo.toml"))];
    for member in members() {
        manifests.push((member.clone(), root.join(&member).join("Cargo.toml")));
    }
    let mut offenders = Vec::new();
    for (member, path) in manifests {
        let manifest: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let name = manifest
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or(&member)
            .to_string();
        offenders.extend(test_support_enablers(&name, &manifest));
    }
    assert!(
        offenders.is_empty(),
        "`test-support` exposes the UNSCOPED generator constructors; only dev-dependencies \
         may enable it (NAN-5793):\n{}",
        offenders.join("\n")
    );
}

/// The manifest check on every form Cargo accepts.
#[test]
fn the_manifest_check_catches_every_enabling_form() {
    let check = |name: &str, toml_text: &str| test_support_enablers(name, &toml::from_str(toml_text).unwrap());
    for (case, text) in [
        ("inline", "[dependencies]\nnanosiem-core = { path = \"x\", features = [\"test-support\"] }"),
        (
            "multi-line inline",
            "[dependencies]\nnanosiem-core = { path = \"x\",\n  features = [\"test-support\"],\n}",
        ),
        ("table header", "[dependencies.nanosiem-core]\npath = \"x\"\nfeatures = [\"test-support\"]"),
        (
            "renamed",
            "[dependencies]\ncore = { package = \"nanosiem-core\", features = [\"test-support\"] }",
        ),
        (
            "renamed via feature",
            "[dependencies]\ncore = { package = \"nanosiem-core\" }\n[features]\nx = [\"core/test-support\"]",
        ),
        ("weak feature", "[features]\nx = [\"nanosiem-core?/test-support\"]"),
        (
            "workspace dependency",
            "[workspace.dependencies]\nnanosiem-core = { path = \"x\", features = [\"test-support\"] }",
        ),
        (
            "target dependency",
            "[target.'cfg(unix)'.dependencies]\nnanosiem-core = { path = \"x\", features = [\"test-support\"] }",
        ),
        ("build dependency", "[build-dependencies]\nnanosiem-core = { path = \"x\", features = [\"test-support\"] }"),
    ] {
        assert!(!check("consumer", text).is_empty(), "{case} was not caught");
    }
    assert!(!check("nanosiem-core", "[features]\ndefault = [\"test-support\"]\ntest-support = []").is_empty());
    assert!(!check("nanosiem-core", "[features]\nextra = [\"test-support\"]\ntest-support = []").is_empty());
    // Allowed: dev-dependencies, and the feature's own definition.
    assert!(check(
        "nanosiem-core",
        "[features]\ntest-support = []\n[dev-dependencies]\nnanosiem-core = { path = \".\", features = [\"test-support\"] }",
    )
    .is_empty());
}

#[test]
fn production_code_never_names_an_unscoped_constructor() {
    let re = regex::Regex::new(
        r"ClickHouseSqlGenerator\s*::\s*(new|with_table|default)\s*\(|<ClickHouseSqlGenerator\s+as\s+Default>",
    )
    .unwrap();
    let offenders: Vec<String> = rust_sources()
        .into_iter()
        .filter(|(rel, _)| !is_test_path(rel))
        .filter_map(|(rel, text)| {
            // An inline `#[cfg(test)] mod` tail is test code.
            let prod = without_test_modules(&text);
            let prod = prod.as_str();
            re.find(prod).map(|m| format!("{rel}: {}", m.as_str()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "production code must build generators with `ClickHouseSqlGenerator::scoped` / \
         `scoped_with_table` and a `GeneratorScope` (NAN-5793):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_service_template_is_read_only_by_its_accessor() {
    let field = regex::Regex::new(r"\bch_sql_generator(_base)?\b").unwrap();
    let mut problems = Vec::new();
    for (rel, text) in rust_sources() {
        let n = field.find_iter(&text).count();
        let allowed = match rel.as_str() {
            // field, accessor, two constructors
            "nanosiem-core/src/search/service/mod.rs" => 4,
            // asserts the template stays untouched by a generation
            "nanosiem-core/src/search/service/prevalence_stage_alias_tests.rs" => 1,
            _ => 0,
        };
        if n != allowed {
            problems.push(format!("{rel}: {n} use(s), pinned at {allowed}"));
        }
    }
    assert!(
        problems.is_empty(),
        "read the search service's generator through `sql_generator(scope)` only (NAN-5793):\n{}",
        problems.join("\n")
    );
}

/// No alias of `GeneratorScope` (an `as` import or a type alias would hide
/// an unrestricted call from the pin), and no unrestricted scope spelled as
/// an empty viewer or deny-set.
#[test]
fn no_unrestricted_scope_hides_behind_another_spelling() {
    let alias = regex::Regex::new(r"GeneratorScope\s+as\s+\w|type\s+\w+\s*(<[^>]*>)?\s*=\s*[\w:]*GeneratorScope").unwrap();
    let empty = regex::Regex::new(
        r"GeneratorScope\s*::\s*(viewer|deny_set)\s*\(\s*&\s*(\w+::)*(unrestricted|new|default)\s*\(",
    )
    .unwrap();
    let mut offenders = Vec::new();
    for (rel, text) in rust_sources() {
        if is_test_path(&rel) {
            continue;
        }
        let prod = without_test_modules(&text);
        if let Some(m) = alias.find(&prod).or_else(|| empty.find(&prod)) {
            offenders.push(format!("{rel}: {}", m.as_str()));
        }
    }
    assert!(
        offenders.is_empty(),
        "spell an unrestricted generator `GeneratorScope::unrestricted()` so the pin sees it \
         (NAN-5793):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn every_unrestricted_generator_is_listed() {
    let re = regex::Regex::new(r"GeneratorScope\s*::\s*unrestricted\s*\(").unwrap();
    let mut problems = Vec::new();
    for (rel, text) in rust_sources() {
        if is_test_path(&rel) {
            continue;
        }
        let prod = without_test_modules(&text);
            let prod = prod.as_str();
        let n = re.find_iter(prod).count();
        let allowed = UNRESTRICTED_ALLOWED.iter().find(|(f, _, _)| *f == rel).map(|(_, c, _)| *c).unwrap_or(0);
        if n != allowed {
            problems.push(format!("{rel}: {n} unrestricted generator(s), pinned at {allowed}"));
        }
    }
    assert!(
        problems.is_empty(),
        "an unrestricted generator reads every source. A request path passes \
         `GeneratorScope::viewer(scope)`; list a system path in UNRESTRICTED_ALLOWED with \
         its reason (NAN-5793):\n{}",
        problems.join("\n")
    );
}

#[test]
fn nothing_outside_the_generator_rescopes_one() {
    // Any spelling (method or UFCS); the method is also module-private.
    let re = regex::Regex::new(r"\bwith_source_scope_deny\s*\(").unwrap();
    let offenders: Vec<String> = rust_sources()
        .into_iter()
        .filter(|(rel, _)| !is_test_path(rel))
        .filter(|(rel, _)| {
            rel != "nanosiem-core/src/query/clickhouse_sql_gen.rs"
                && rel != "nanosiem-core/src/query/clickhouse_sql_gen/identity.rs"
        })
        .filter_map(|(rel, text)| {
            let prod = without_test_modules(&text);
            let prod = prod.as_str();
            re.find(prod).map(|_| rel)
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "build the generator with the scope instead (`scoped` / `sql_generator`): an ad-hoc \
         `with_source_scope_deny` can drop a viewer's scope (NAN-5793):\n{}",
        offenders.join("\n")
    );
}

/// `apply_scope` (crate-visible so the search service can scope its
/// template) is called from exactly that accessor.
#[test]
fn only_the_service_accessor_applies_a_scope() {
    let re = regex::Regex::new(r"\bapply_scope\s*\(").unwrap();
    let mut problems = Vec::new();
    for (rel, text) in rust_sources() {
        let n = re.find_iter(&without_test_modules(&text)).count();
        let allowed = match rel.as_str() {
            // the definition and the two `scoped*` constructors
            "nanosiem-core/src/query/clickhouse_sql_gen.rs" => 3,
            // `sql_generator`
            "nanosiem-core/src/search/service/mod.rs" => 1,
            _ => 0,
        };
        if n != allowed {
            problems.push(format!("{rel}: {n} use(s), pinned at {allowed}"));
        }
    }
    assert!(problems.is_empty(), "re-scoping outside the accessor (NAN-5793):\n{}", problems.join("\n"));
}

/// The test-module stripper ignores braces in literals, so a `"{"` in an
/// inline test module cannot hide the production code after it.
#[test]
fn test_module_stripping_ignores_braces_in_literals() {
    let src = "fn a() {}\n#[cfg(test)]\nmod tests { fn t() { let _ = \"{\"; let _ = '{'; } }\nfn prod() { X::new() }";
    let out = without_test_modules(src);
    assert!(out.contains("fn prod() { X::new() }"), "{out}");
    assert!(!out.contains("fn t()"), "{out}");
}

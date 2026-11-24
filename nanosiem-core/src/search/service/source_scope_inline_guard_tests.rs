// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5793 guard: no hand-built ClickHouse read renders a viewer's denied
//! source names into its SQL text, and no read that carries the bound
//! predicate runs without binding the deny list.
//!
//! The `clickhouse` driver reads every `?` in a query template as a
//! client-side bind, string literals included, and rewrites `?fields`. A
//! denied source name in the SQL text therefore failed the query (or shifted
//! every later bind) for a restricted viewer. Source-scoped side-door SQL
//! renders [`source_scope_bound_predicate`] and binds the list as the
//! server-side `nano_source_deny` parameter instead.
//!
//! This scans the Rust sources of every crate that builds ClickHouse SQL,
//! with comments stripped:
//! - the removed inline builder must not come back under its old name;
//! - the literal builder is named only in the allowlisted files, exactly as
//!   many times as pinned there;
//! - per FUNCTION: a function that renders the bound predicate (or calls a
//!   function that does and returns SQL) and also executes a ClickHouse query
//!   must bind the deny list. "Calls a function that does" propagates through
//!   helper builders, across files for `pub` builders, to a fixed point.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Every file allowed to NAME `source_scope_literal_predicate`, with the
/// exact number of times it may, and the reason a `?` is inert there.
const LITERAL_ALLOWED: &[(&str, usize, &str)] = &[
    (
        "nanosiem-core/src/search/service/lateral.rs",
        3,
        "the definition and its two unit tests",
    ),
    (
        "nanosiem-core/src/search/service/mod.rs",
        1,
        "the crate re-export",
    ),
    (
        "nanosiem-core/src/search/service/source_scope_bound_ch_tests.rs",
        1,
        "the real-ClickHouse test proving the inline form breaks",
    ),
    (
        "nanosiem-core/src/query/clickhouse_sql_gen/identity.rs",
        1,
        "nPL-generated SQL: its executors double `?` inside literals",
    ),
];

/// Calls that render the bound predicate.
const RENDERERS: &[&str] = &[
    "source_scope_bound_predicate(",
    "source_scope_param_predicate(",
    "scope_and_clause(",
];

/// Calls that bind the deny list (or run a query that does).
const BINDERS: &[&str] = &[
    // Its signature takes the deny set it binds.
    ".execute_clickhouse_sql(",
    "bind_source_scope(",
    "SourceScopedClient::new(",
    "with_source_scope(",
    "scoped_query(",
    "SOURCE_SCOPE_DENY_PARAM",
];

/// Calls that execute a ClickHouse query.
/// (Plus `.query(<arg>` / `.query_raw(`: `scoped.query()` is not one.)
const EXECUTORS: &[&str] = &[
    ".fetch_bytes(",
    ".fetch_all",
    ".fetch_one",
    ".fetch_optional",
    ".execute_sql_to_json(",
    ".execute_dynamic_query(",
    ".execute_clickhouse_sql(",
];

/// Workspace crates whose sources build ClickHouse SQL.
const CRATES: &[&str] = &[
    "nanosiem-core",
    "nanosiem-api",
    "nanosiem-api-lib",
    "nanosiem-search",
    "nanosiem-enterprise",
];

/// This file talks about the patterns it hunts for.
const SELF: &str = "nanosiem-core/src/search/service/source_scope_inline_guard_tests.rs";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `(workspace-relative path, source with comments stripped)`.
fn sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut files = Vec::new();
    for krate in CRATES {
        let src = root.join(krate).join("src");
        assert!(src.is_dir(), "guard crate {krate} has no src/ at {}", src.display());
        rust_files(&src, &mut files);
    }
    assert!(files.len() > 100, "guard found too few sources under {}", root.display());
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            (rel, strip_comments(&text))
        })
        .filter(|(rel, _)| rel != SELF)
        .collect()
}

/// Rust source with `//` and `/* */` comments removed (string, raw string and
/// char literals are kept, so a `//` inside `"http://…"` is not a comment).
pub(super) fn strip_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 1;
            i += 2;
            while i < chars.len() && depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        // Raw string: r"…", r#"…"#, br#"…"#.
        if c == 'r' && (next == Some('"') || next == Some('#')) {
            let mut j = i + 1;
            let mut hashes = 0;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) == Some(&'"') {
                let close: String = std::iter::once('"').chain(std::iter::repeat('#').take(hashes)).collect();
                let rest: String = chars[j + 1..].iter().collect();
                let end = rest.find(&close).map(|e| j + 1 + rest[..e].chars().count() + close.len());
                let end = end.unwrap_or(chars.len()).min(chars.len());
                out.extend(&chars[i..end]);
                i = end;
                continue;
            }
        }
        if c == '"' {
            out.push(c);
            i += 1;
            while i < chars.len() {
                out.push(chars[i]);
                if chars[i] == '\\' && i + 1 < chars.len() {
                    out.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        // Char literal ('x', '\n', '"'); a lifetime ('a) is left alone.
        if c == '\'' {
            if next == Some('\\') {
                let end = chars[i + 2..].iter().position(|&ch| ch == '\'').map(|p| i + 3 + p);
                if let Some(end) = end {
                    out.extend(&chars[i..end]);
                    i = end;
                    continue;
                }
            } else if chars.get(i + 2) == Some(&'\'') {
                out.extend(&chars[i..i + 3]);
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Whitespace removed, so `client\n    .query(` matches `.query(`.
fn compact(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

struct Function {
    file: String,
    name: String,
    public: bool,
    /// The signature returns a `String` (an SQL builder can).
    returns_string: bool,
    /// Whitespace-free body.
    body: String,
    /// Free / associated / `self.` calls in the body (`x.name(` method calls
    /// on other values are excluded: `ch.query(` is not a call to a `query`
    /// helper).
    called: BTreeSet<String>,
    /// The subset of `called` that resolves to a function in scope: bare
    /// `name(`, `self.name(` and `Self::name(` (not `sqlx::query(`).
    local_calls: BTreeSet<String>,
    /// Bare `name(` calls only: what may resolve to a `pub` function in
    /// ANOTHER file (a `self.query(` there is that file's own method).
    bare_calls: BTreeSet<String>,
}

/// The byte just past a string / raw-string / char literal starting at `i`,
/// or `None` when `i` does not start one (a lifetime `'a` is not a literal).
pub(super) fn skip_literal(bytes: &[u8], i: usize) -> Option<usize> {
    match bytes[i] {
        b'"' => {
            let mut j = i + 1;
            while j < bytes.len() {
                match bytes[j] {
                    b'\\' => j += 2,
                    b'"' => return Some(j + 1),
                    _ => j += 1,
                }
            }
            Some(bytes.len())
        }
        b'r' if matches!(bytes.get(i + 1), Some(b'"') | Some(b'#'))
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_')) =>
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while bytes.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if bytes.get(j) != Some(&b'"') {
                return None;
            }
            j += 1;
            while j < bytes.len() {
                if bytes[j] == b'"' && bytes[j + 1..].iter().take(hashes).filter(|&&b| b == b'#').count() == hashes {
                    return Some(j + 1 + hashes);
                }
                j += 1;
            }
            Some(bytes.len())
        }
        b'\'' => {
            if bytes.get(i + 1) == Some(&b'\\') {
                bytes[i + 2..].iter().position(|&b| b == b'\'').map(|p| i + 3 + p)
            } else if bytes.get(i + 2) == Some(&b'\'') {
                Some(i + 3)
            } else {
                // A multi-byte char literal ('é') or a lifetime.
                let rest = std::str::from_utf8(&bytes[i + 1..]).ok()?;
                let ch = rest.chars().next()?;
                (bytes.get(i + 1 + ch.len_utf8()) == Some(&b'\'')).then(|| i + 2 + ch.len_utf8())
            }
        }
        _ => None,
    }
}

/// `(signature, body)` of the function whose `fn` keyword starts at `at`, or
/// `None` for a body-less declaration. Braces and parentheses inside string
/// and char literals do not count.
fn body_span(text: &str, at: usize) -> Option<(&str, &str)> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut i = at;
    while i < bytes.len() {
        if let Some(end) = skip_literal(bytes, i) {
            i = end;
            continue;
        }
        match bytes[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b';' if depth <= 0 => return None,
            b'{' if depth <= 0 => break,
            _ => {}
        }
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let open = i;
    let mut braces = 0i32;
    while i < bytes.len() {
        if let Some(end) = skip_literal(bytes, i) {
            i = end;
            continue;
        }
        match bytes[i] {
            b'{' => braces += 1,
            b'}' => {
                braces -= 1;
                if braces == 0 {
                    return Some((&text[at..open], &text[open..=i]));
                }
            }
            _ => {}
        }
        i += 1;
    }
    Some((&text[at..open], &text[open..]))
}

/// Every function (brace-matched body) in each source.
fn functions(files: &[(String, String)]) -> Vec<Function> {
    let fn_re = regex::Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let call_re = regex::Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\(").unwrap();
    let mut out = Vec::new();
    for (file, text) in files {
        for cap in fn_re.captures_iter(text) {
            let at = cap.get(0).unwrap().start();
            let name = cap[1].to_string();
            let Some((sig, body)) = body_span(text, at) else {
                continue;
            };
            let line_start = text[..at].rfind('\n').map(|p| p + 1).unwrap_or(0);
            let body = compact(body);
            let mut called = BTreeSet::new();
            let mut local_calls = BTreeSet::new();
            let mut bare_calls = BTreeSet::new();
            for c in call_re.captures_iter(&body) {
                let start = c.get(1).unwrap().start();
                let before = &body[..start];
                let prev = before.chars().last();
                if matches!(prev, Some(ch) if ch.is_ascii_alphanumeric() || ch == '_')
                    || (prev == Some('.') && !before.ends_with("self."))
                {
                    continue;
                }
                let callee = c[1].to_string();
                if callee == name {
                    continue;
                }
                if prev != Some(':') || before.ends_with("Self::") {
                    local_calls.insert(callee.clone());
                }
                if prev != Some(':') && prev != Some('.') {
                    bare_calls.insert(callee.clone());
                }
                called.insert(callee);
            }
            out.push(Function {
                file: file.clone(),
                name,
                public: text[line_start..at].contains("pub"),
                returns_string: sig.split_once("->").is_some_and(|(_, r)| r.contains("String")),
                body,
                called,
                local_calls,
                bare_calls,
            });
        }
    }
    out
}

/// The per-function binding analysis. Returns `file::fn` offenders.
///
/// - A **builder** renders the bound predicate (directly or by calling a
///   builder), returns a `String`, and executes nothing.
/// - A **binding executor** executes a query and binds: calling one binds.
/// - An **offender** renders (directly or via a builder) and executes, but
///   binds nothing.
///
/// A private builder reaches callers in its own file; a `pub` one reaches
/// other files unless the caller's file defines a function of that name.
fn unbound_scoped_reads(files: &[(String, String)]) -> Vec<String> {
    let fns = functions(files);
    let exec_re = regex::Regex::new(r"\.query\([^)]|\.query_raw\(").unwrap();
    let mut local: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for f in &fns {
        local.entry(f.file.as_str()).or_default().insert(f.name.as_str());
    }
    let mut builders: BTreeSet<(String, String, bool)> = BTreeSet::new();
    let mut binding_fns: BTreeSet<(String, String, bool)> = BTreeSet::new();
    let mut offenders = BTreeSet::new();
    loop {
        let before = (builders.len(), binding_fns.len());
        offenders.clear();
        for f in &fns {
            let renders = RENDERERS.iter().any(|r| {
                f.body.match_indices(r).any(|(at, _)| !f.body[..at].ends_with("pg_"))
            }) || builders.iter().any(|(file, name, public)| {
                f.called.contains(name)
                    && (*file == f.file || (*public && !local[f.file.as_str()].contains(name.as_str())))
            });
            let executes =
                exec_re.is_match(&f.body) || EXECUTORS.iter().any(|e| f.body.contains(e));
            let binds = BINDERS.iter().any(|b| f.body.contains(b))
                || binding_fns.iter().any(|(file, name, public)| {
                    (*file == f.file && f.local_calls.contains(name))
                        || (*public
                            && f.bare_calls.contains(name)
                            && !local[f.file.as_str()].contains(name.as_str()))
                });
            if executes && binds {
                binding_fns.insert((f.file.clone(), f.name.clone(), f.public));
            }
            if renders && !executes && f.returns_string {
                builders.insert((f.file.clone(), f.name.clone(), f.public));
            }
            if renders && executes && !binds {
                offenders.insert(format!("{}::{}", f.file, f.name));
            }
        }
        if (builders.len(), binding_fns.len()) == before {
            break;
        }
    }
    offenders.into_iter().collect()
}

#[test]
fn the_removed_inline_builder_does_not_come_back() {
    let old = ["source_scope", "sql_predicate"].join("_");
    let offenders: Vec<String> = sources()
        .into_iter()
        .filter(|(_, text)| text.contains(&old))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        offenders.is_empty(),
        "`{old}` rendered denied source names into ClickHouse SQL text (NAN-5793). \
         Use `source_scope_bound_predicate` + `bind_source_scope`:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_literal_builder_is_only_named_where_a_question_mark_is_inert() {
    let ident = regex::Regex::new(r"\bsource_scope_literal_predicate\b").unwrap();
    let mut problems = Vec::new();
    for (rel, text) in sources() {
        let n = ident.find_iter(&text).count();
        let allowed = LITERAL_ALLOWED.iter().find(|(f, _, _)| *f == rel).map(|(_, c, _)| *c);
        match allowed {
            None if n > 0 => problems.push(format!("{rel}: {n} use(s), not allowlisted")),
            Some(c) if c != n => problems.push(format!("{rel}: {n} use(s), pinned at {c}")),
            _ => {}
        }
    }
    assert!(
        problems.is_empty(),
        "the literal builder renders denied source names into SQL text. For ClickHouse use \
         `source_scope_bound_predicate` + `bind_source_scope` (NAN-5793); allowlist a use only \
         for nPL-generated SQL, with its count:\n{}",
        problems.join("\n")
    );
    let root = workspace_root();
    for (rel, _, _) in LITERAL_ALLOWED {
        assert!(root.join(rel).exists(), "LITERAL_ALLOWED names a missing file: {rel}");
    }
}

#[test]
fn every_function_running_a_scoped_read_binds_the_deny_list() {
    let offenders = unbound_scoped_reads(&sources());
    assert!(
        offenders.is_empty(),
        "these functions run a query carrying the bound source-scope predicate without \
         binding the deny list, so a restricted viewer's query fails (NAN-5793). Run it \
         through `bind_source_scope` / `SourceScopedClient` / \
         `ClickHouseExecutor::with_source_scope`:\n{}",
        offenders.join("\n")
    );
}

/// The analysis itself: it catches an unbound read directly, through a
/// file-local builder, through a `pub` builder in another file, and when
/// a comment mentions a binder; and it accepts the bound forms.
#[test]
fn the_function_analysis_catches_unbound_reads() {
    let file = |name: &str, src: &str| (name.to_string(), strip_comments(src));
    let flagged = unbound_scoped_reads(&[
        file(
            "a.rs",
            "fn direct(ch: &C, s: &S) { let p = source_scope_bound_predicate(\"x\", s); \
             ch.query(&p).fetch_all(); }
             fn local_builder(s: &S) -> String { source_scope_bound_predicate(\"x\", s).unwrap() }
             fn via_local(ch: &C, s: &S) { ch.query(&local_builder(s)).fetch_all(); }
             fn commented(ch: &C, s: &S) { // bind_source_scope(
                 /* SourceScopedClient::new( */
                 ch.query(&local_builder(s)).fetch_one(); }
             fn bound(ch: &C, s: &S) { bind_source_scope(ch.query(&local_builder(s)), s).fetch_all(); }
             pub fn shared_builder(s: &S) -> String { local_builder(s) }",
        ),
        file(
            "b.rs",
            "fn cross_file(ch: &C, s: &S) { ch\n    .query(&shared_builder(s))\n    .fetch_all(); }
             fn private_name_elsewhere(ch: &C) { ch.query(&local_builder()).fetch_all(); }
             fn pg_only(pool: &P, s: &S) { let c = pg_scope_and_clause(s, \"x\"); sqlx::query(&c).fetch_all(pool); }",
        ),
        file(
            "c.rs",
            "fn shared_builder() -> String { String::new() }
             fn uses_its_own(ch: &C) { ch.query(&shared_builder()).fetch_all(); }
             fn ast_query_is_not_a_read(s: &S, q: &Q) { \
                 let p = source_scope_bound_predicate(\"x\", s); let _ = q.query(); }",
        ),
        // Round 2: binding executors named like common calls.
        file(
            "d.rs",
            "fn query(ch: &C, s: &S) { bind_source_scope(ch.query(&x), s).fetch_all(); }
             pub fn read(ch: &C, s: &S) { bind_source_scope(ch.query(&x), s).fetch_one(); }",
        ),
        file(
            "e.rs",
            "fn path_call_is_not_a_bind(ch: &C, s: &S, pool: &P) { \
                 let p = source_scope_bound_predicate(\"x\", s); \
                 sqlx::query(\"SELECT 1\").fetch_one(pool); ch.query(&p).fetch_all(); }
             fn brace_in_a_literal(ch: &C, s: &S) { \
                 let p = source_scope_bound_predicate(\"x\", s); let _ = \"}\"; let _ = '{'; \
                 ch.query(&p).fetch_all(); }
             fn calls_the_pub_binder(ch: &C, s: &S) { \
                 let p = source_scope_bound_predicate(\"x\", s); read(ch, s); ch.query(&p).fetch_all(); }",
        ),
        // Round 3: a `self.read(` is the calling file's own method, never
        // another file's `pub fn read`.
        file(
            "f.rs",
            "fn self_call_elsewhere(ch: &C, s: &S) { \
                 let p = source_scope_bound_predicate(\"x\", s); self.read(); ch.query(&p).fetch_all(); }",
        ),
    ]);
    assert_eq!(
        flagged,
        vec![
            "a.rs::commented",
            "a.rs::direct",
            "a.rs::via_local",
            "b.rs::cross_file",
            "e.rs::brace_in_a_literal",
            "e.rs::path_call_is_not_a_bind",
            "f.rs::self_call_elsewhere",
        ],
    );
}

/// The bound predicate itself never carries a denied name, however hostile.
#[test]
fn the_bound_predicate_text_is_independent_of_the_deny_list() {
    use super::{source_scope_bound_predicate, source_scope_param_values};
    let hostile: BTreeSet<String> =
        ["we?ird", "o'brien?fields", "x') OR 1=1 --"].iter().map(|s| s.to_string()).collect();
    let pred = source_scope_bound_predicate("source_type", &hostile).unwrap();
    assert_eq!(pred, "lower(source_type) NOT IN {nano_source_deny:Array(String)}");
    assert!(!pred.contains('?') && !pred.contains('\''));
    assert_eq!(
        source_scope_param_values(&hostile).unwrap(),
        vec!["o'brien?fields".to_string(), "we?ird".to_string(), "x') or 1=1 --".to_string()]
    );
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3494: deeply nested tenant VRL must be refused with an error, never
//! overflow the stack (which aborts the whole API process).
//!
//! Without the guard every `refused_*` test below aborts the test binary with
//! "thread has overflowed its stack" — that is the reproduction.

use super::*;

/// A 2 MiB stack: tokio workers and `spawn_blocking` threads, where the API
/// compiles and runs tenant VRL.
const WORKER_STACK: usize = 2 * 1024 * 1024;

fn on_worker_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(WORKER_STACK)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("join")
}

/// Every construct whose depth the VRL parser/compiler/runtime recurse on.
const SHAPES: &[&str] = &[
    "paren",
    "array",
    "object",
    "block",
    "if_nest",
    "else_if",
    "plus",
    "concat",
    "not",
    "minus",
    "coalesce",
    "and",
    "or",
    "eq_chain",
    "path",
    "index",
    "call",
    "fallible_call",
    "assign",
    "multiline_plus",
    "multiline_else_if",
    "closure",
];

fn shape(kind: &str, n: usize) -> String {
    match kind {
        "paren" => format!(".x = {}1{}", "(".repeat(n), ")".repeat(n)),
        "array" => format!(".x = {}1{}", "[".repeat(n), "]".repeat(n)),
        "object" => format!(".x = {}1{}", "{\"a\": ".repeat(n), "}".repeat(n)),
        "block" => format!(".x = {}1{}", "{ ".repeat(n), " }".repeat(n)),
        "if_nest" => format!("{}.x = 1{}", "if .a == 1 { ".repeat(n), " }".repeat(n)),
        "else_if" => {
            let mut s = String::from("if .a == 0 { .x = 0 }");
            for i in 1..n {
                s.push_str(&format!(" else if .a == {i} {{ .x = {i} }}"));
            }
            s
        }
        "multiline_else_if" => {
            let mut s = String::from("if .a == 0 {\n  .x = 0\n}");
            for i in 1..n {
                s.push_str(&format!(" else if .a == {i} {{\n  .x = {i}\n}}"));
            }
            s
        }
        "plus" => format!(".x = 1{}", " + 1".repeat(n)),
        "multiline_plus" => format!(".x = 1{}", " +\n  1".repeat(n)),
        "concat" => format!(".x = \"a\"{}", " + \"a\"".repeat(n)),
        "not" => format!(".x = {}true", "!".repeat(n)),
        "minus" => format!(".x = 1{}", " - 1".repeat(n)),
        "coalesce" => format!(".x = .a{}", " ?? .a".repeat(n)),
        "and" => format!(".x = true{}", " && true".repeat(n)),
        "or" => format!(".x = false{}", " || false".repeat(n)),
        "eq_chain" => format!(".x = 1{}", " == 1".repeat(n)),
        "path" => format!(".x = .a{}", ".b".repeat(n)),
        "index" => format!(".x = .a{}", "[0]".repeat(n)),
        "call" => format!(".x = {}\"a\"{}", "upcase(".repeat(n), ")".repeat(n)),
        "fallible_call" => format!(".x = {}\"1\"{}", "to_string!(".repeat(n), ")".repeat(n)),
        "assign" => format!("{}1", ".a = ".repeat(n)),
        // The commas in `|k, v|` must not reset the `!` chain the closure
        // body nests under.
        "closure" => format!(
            ".x = {}true{}",
            "!!!!!!!! map_values(.a) -> |k, v| { ".repeat(n),
            " }".repeat(n)
        ),
        other => panic!("unknown shape {other}"),
    }
}

fn fns() -> Vec<Box<dyn Function>> {
    crate::parsers::validator::safe_vrl_functions()
}

fn assert_refused(kind: &str, n: usize) {
    let src = shape(kind, n);
    let len = src.len();
    let err = on_worker_stack(move || compile(&src, &fns()).err());
    match err {
        Some(VrlCompileError::Guard(
            VrlGuardError::TooDeep { .. }
            | VrlGuardError::TooLarge { .. }
            | VrlGuardError::TooCostly { .. },
        )) => {}
        other => panic!("{kind} x{n} ({len} bytes): expected a guard refusal, got {other:?}"),
    }
}

#[test]
fn refused_every_deep_shape() {
    for kind in SHAPES {
        for n in [700, 3_000] {
            assert_refused(kind, n);
        }
    }
}

/// The two inputs from the NAN-3490 / #5936 attack suite.
#[test]
fn refused_5936_attack_inputs() {
    assert_refused("not", 50_000);
    assert_refused("plus", 60_000);
}

/// Not a stack overflow but a CPU wedge: type-checking doubles per nested
/// call (22 nested `to_string!` took 26 s in release, 30 would take hours),
/// well inside the depth cap.
#[test]
fn refused_exponential_nested_calls() {
    for n in [24, 30, 63] {
        for src in [
            shape("fallible_call", n),
            format!(".x = {}.a{}", "to_string(".repeat(n), ")".repeat(n)),
            format!(".x = {}.a{}", "to_string(1 + ".repeat(n), ")".repeat(n)),
        ] {
            let started = std::time::Instant::now();
            let err = on_worker_stack(move || compile(&src, &fns()).err());
            assert!(
                matches!(
                    err,
                    Some(VrlCompileError::Guard(VrlGuardError::TooCostly { .. }))
                ),
                "x{n}: {err:?}"
            );
            assert!(started.elapsed() < std::time::Duration::from_secs(1));
        }
    }
}

#[test]
fn refused_oversized_source() {
    let src = format!(".x = \"{}\"", "a".repeat(MAX_VRL_SOURCE_BYTES));
    assert!(matches!(check(&src), Err(VrlGuardError::TooLarge { .. })));
}

/// The cap must sit well under what the compiler, the runtime and `Drop`
/// can handle on an ordinary worker stack, for every shape: compile with the
/// raw compiler (no large-stack thread), resolve, and drop the program on a
/// 2 MiB thread at the deepest size the guard accepts.
#[test]
fn deepest_accepted_program_of_every_shape_is_safe_on_a_worker_stack() {
    for kind in SHAPES {
        // Largest n the guard accepts (accepting is monotonic in n).
        let (mut lo, mut hi) = (1usize, 4096usize);
        assert!(
            check(&shape(kind, lo)).is_ok(),
            "{kind}: smallest program refused"
        );
        assert!(check(&shape(kind, hi)).is_err(), "{kind}: 4096 accepted");
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            if check(&shape(kind, mid)).is_ok() {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        // Realistic programs must keep room: a 40-arm else-if ladder, a
        // 40-term `??` / `+` chain, 40 levels of brackets.
        // (`closure` spends ~14 levels per repetition by construction.)
        // (`call` shapes are bounded by the type-work budget instead.)
        let floor = match *kind {
            "closure" => 5,
            "call" | "fallible_call" => 12,
            "assign" => 25,
            _ => 40,
        };
        assert!(lo >= floor, "{kind}: guard accepts only {lo} levels");
        let src = shape(kind, lo);
        eprintln!("{kind}: deepest accepted n = {lo} ({} bytes)", src.len());
        let started = std::time::Instant::now();
        on_worker_stack(move || {
            use vrl::compiler::{runtime::Runtime, TargetValue, TimeZone};
            use vrl::value::{Secrets, Value};
            let Ok(result) = vrl::compiler::compile(&src, &fns()) else {
                return; // a type error is fine; it did not crash
            };
            let mut target = TargetValue {
                value: Value::from(serde_json::json!({"a": 0})),
                metadata: Value::Object(Default::default()),
                secrets: Secrets::new(),
            };
            let _ = Runtime::default().resolve(&mut target, &result.program, &TimeZone::Local);
            drop(result);
        });
        eprintln!(
            "{kind}: compiled, ran and dropped in {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn strings_literals_and_comments_do_not_count() {
    let noise = "((([[[{{{!!!+++???&&||==".repeat(400);
    for src in [
        format!(".x = \"{noise}\""),
        format!(".x = \"\\\"{noise}\""),
        format!(".x = s'{noise}'"),
        format!(".x = s'\\'{noise}'"),
        format!(".x = match(.m, r'{noise}') ?? false"),
        format!("# {noise}\n.x = 1"),
    ] {
        let depth = nesting_depth(&src, usize::MAX);
        assert!(depth < 10, "depth {depth} for {}", &src[..40]);
        assert!(check(&src).is_ok());
    }
}

#[test]
fn statements_and_siblings_do_not_accumulate() {
    // 5,000 statements, each a short chain: siblings, not nesting.
    let many = ".a = .b ?? .c ?? \"x\"\n".repeat(5_000);
    assert!(nesting_depth(&many, usize::MAX) < 10);
    // A 2,000-element array / object literal / call argument list.
    let array = format!(".x = [{}]", "1, ".repeat(2_000));
    assert!(nesting_depth(&array, usize::MAX) < 10);
    let object = format!(".x = {{ {} }}", "\"k\": .a.b ?? 1, ".repeat(2_000));
    assert!(nesting_depth(&object, usize::MAX) < 10);
}

#[test]
fn a_realistic_parser_is_shallow() {
    let src = r#"
# Apache combined log
parsed, err = parse_regex(.message, r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)')
if err != null {
    .parse_error = err
} else {
    .src_ip = parsed.ip
    .user = if parsed.user == "-" { null } else { parsed.user }
    .timestamp = parse_timestamp(parsed.ts, "%d/%b/%Y:%H:%M:%S %z") ?? now()
    .status = to_int!(parsed.status ?? "0")
    .tags = map_values(compact([.a, .b, .c])) -> |v| { upcase(to_string(v) ?? "") }
}
"#;
    let depth = nesting_depth(src, usize::MAX);
    assert!(depth <= 16, "depth {depth}");
}

/// Entry points: every in-process path that compiles or parses tenant VRL
/// returns an error for each deep shape and the process survives.
#[tokio::test]
async fn entry_points_refuse_deep_vrl() {
    use crate::parsers::{pipe, CompiledNormalizer, VrlValidator};
    let validator = VrlValidator::new();
    for kind in SHAPES {
        let src = shape(kind, 3_000);

        // Parser validate / save / AI parser editor (validate_vrl_collect_errors).
        let result = validator.validate_vrl(&src).await.expect("validator ran");
        assert!(!result.valid, "{kind}: validate_vrl accepted it");
        let (result, errors) = validator
            .validate_vrl_collect_errors(&src)
            .await
            .expect("validator ran");
        assert!(
            !result.valid && !errors.is_empty(),
            "{kind}: collect_errors accepted it"
        );

        // Parser test / live test.
        let tested = validator.test_vrl(&src, "{}").await;
        assert!(
            tested.map(|r| !r.success).unwrap_or(true),
            "{kind}: test_vrl ran it"
        );

        // Enrichment normalize programs.
        assert!(
            CompiledNormalizer::compile(&src).is_err(),
            "{kind}: normalizer"
        );
    }
    // Pipe conditions are single-line and <= 4 KiB; the parser recurses too.
    for kind in ["not", "paren", "plus", "coalesce", "and"] {
        let src = shape(kind, 1_000);
        let expr = src.trim_start_matches(".x = ");
        assert!(pipe::condition(expr).is_err(), "{kind}: pipe condition");
    }
}

/// Every production compile in nanosiem-core goes through this module. A new
/// direct `vrl::compiler::compile` outside tests must route through
/// [`compile`] (or be added here with a reason it is not tenant-reachable).
#[test]
fn no_unguarded_compile_in_production_code() {
    // Fixed platform programs, not tenant input.
    const ALLOWED: &[&str] = &["parsers/vrl_guard.rs"];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if !rel.ends_with(".rs")
                || rel.ends_with("/tests.rs")
                || rel.ends_with("_tests.rs")
                || ALLOWED.contains(&rel.as_str())
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read");
            // Production part only: everything before the test module.
            let prod = text.split("\n#[cfg(test)]\nmod ").next().unwrap_or("");
            for (i, line) in prod.lines().enumerate() {
                let l = line.trim_start();
                if l.starts_with("//") {
                    continue;
                }
                if l.contains("vrl::compiler::compile(")
                    || l.contains("vrl::parser::parse(")
                    || (l.starts_with("use vrl::compiler::")
                        && ["compile,", "compile;", "compile}", "{compile"]
                            .iter()
                            .any(|p| l.contains(p)))
                {
                    offenders.push(format!("{rel}:{}: {l}", i + 1));
                }
            }
        }
    }
    // lake_bronze_row's own test module is past the split; the fixed contract
    // program is compiled only there. `pipe::condition` checks before parsing.
    offenders.retain(|o| !o.starts_with("parsers/pipe.rs") || !o.contains("vrl::parser::parse("));
    assert!(
        offenders.is_empty(),
        "unguarded VRL compile:\n{}",
        offenders.join("\n")
    );
}

/// Calibration aid: `NAN3494_VRL_CORPUS=<dir of .vrl files>` prints the
/// deepest real programs and fails if any is refused. A no-op otherwise.
#[test]
fn corpus_depths() {
    let Ok(dir) = std::env::var("NAN3494_VRL_CORPUS") else {
        return;
    };
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(dir).expect("corpus dir") {
        let path = entry.expect("entry").path();
        let src = std::fs::read_to_string(&path).expect("read");
        let shape = scan(&src, usize::MAX, u64::MAX);
        rows.push((shape.depth, shape.type_work, path.display().to_string()));
    }
    rows.sort();
    for (depth, work, path) in rows.iter().rev().take(10) {
        println!("depth {depth}\twork {work}\t{path}");
    }
    rows.sort_by_key(|r| r.1);
    for (depth, work, path) in rows.iter().rev().take(10) {
        println!("work {work}\tdepth {depth}\t{path}");
    }
    assert!(rows
        .iter()
        .all(|r| r.0 <= MAX_VRL_NESTING_DEPTH && r.1 <= MAX_VRL_TYPE_WORK));
}

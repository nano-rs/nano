// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one place tenant-controlled VRL is compiled (NAN-3494).
//!
//! The VRL parser, compiler and runtime all recurse once per nesting level of
//! the program. A stack overflow is not a panic: it aborts the whole process.
//! A tenant who saves a parser like `.x = !!!!…!!!!true`, a 2,000-term `+`
//! chain, a few hundred `else if` arms, or ~600 levels of brackets would take
//! down `nanosiem-api` (or the bundle build) for every tenant: on a 2 MiB
//! `spawn_blocking` / tokio worker stack the compiler overflows at roughly
//! 400–2,000 levels depending on the construct, and the old validator only
//! counted brackets, naively, so `else if` and operator chains walked past it.
//!
//! [`compile`] is the guard every tenant-reachable compile goes through:
//!
//! 1. a size cap ([`MAX_VRL_SOURCE_BYTES`]);
//! 2. a cheap, lexer-aware scan ([`nesting_depth`]) that bounds how deep the
//!    program's syntax tree can be, capped at [`MAX_VRL_NESTING_DEPTH`]. It
//!    skips strings, single-quoted literals and comments, and counts bracket
//!    levels plus every operator, `else`, path segment, call and index on the
//!    current expression chain — each of which adds one level to the tree;
//! 3. a type-check work budget ([`MAX_VRL_TYPE_WORK`]). The compiler
//!    re-derives an argument's type once per enclosing function call level,
//!    so its time doubles with every nested call: 22 nested `to_string!(…)`
//!    take 26 s, 30 take hours — a CPU wedge rather than a crash. The scan
//!    charges every token `2^calls - 1`, `calls` being the number of
//!    function calls it sits inside, which bounds that exponential excess
//!    while charging nothing to the linear cost of ordinary programs;
//! 4. compilation on a dedicated thread with a [`COMPILE_STACK_BYTES`] stack,
//!    so the compiler has far more headroom than the cap needs (defence in
//!    depth if the scan ever under-counts a construct).
//!
//! The cap is low enough that the accepted program also resolves and drops
//! safely on an ordinary 2 MiB worker stack (pinned by a test), so callers
//! can keep running the returned program where they are.

use vrl::compiler::{Function, Program};
use vrl::diagnostic::{DiagnosticList, Formatter};

/// Largest VRL program accepted, in bytes. Matches the validator's
/// long-standing `MAX_VRL_SIZE`.
pub const MAX_VRL_SOURCE_BYTES: usize = 1024 * 1024;

/// Deepest syntax tree accepted, as measured by [`nesting_depth`]. Real
/// parsers stay well below this; the compiler overflows a 2 MiB stack at
/// roughly 400 for the costliest construct (`else if` arms / nested blocks).
pub const MAX_VRL_NESTING_DEPTH: usize = 128;

/// Budget for the exponential part of type-checking, in [`scan`] work units
/// (`Σ tokens 2^enclosing_calls - 1`). One unit is roughly 2 µs of compile
/// time in a release build, so the budget bounds that excess to about half a
/// second. The deepest real parsers (cisco_asa, sysmon, …) use well under
/// a tenth of it.
pub const MAX_VRL_TYPE_WORK: u64 = 1 << 18;

/// Nesting levels charged per assignment operator (see [`scan`]).
const ASSIGN_WEIGHT: usize = 4;

/// Stack of the dedicated compile thread. Virtual memory only: pages are
/// touched as the compiler recurses.
pub const COMPILE_STACK_BYTES: usize = 64 * 1024 * 1024;

/// A compiled program and the compiler's warnings. (`CompilationResult`
/// itself is not `Send`: its config carries a type map.)
pub struct Compiled {
    pub program: Program,
    pub warnings: DiagnosticList,
}

/// A program refused before (or instead of) compilation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VrlGuardError {
    #[error("VRL program exceeds maximum size of {max} bytes (got {len} bytes)")]
    TooLarge { len: usize, max: usize },
    #[error(
        "VRL program is nested too deeply (depth {depth}, max {max}); \
         split long operator chains, else-if ladders or nested blocks into \
         intermediate variables"
    )]
    TooDeep { depth: usize, max: usize },
    #[error(
        "VRL program nests function calls too deeply to type-check \
         (cost {work}, max {max}); assign inner calls to intermediate variables"
    )]
    TooCostly { work: u64, max: u64 },
    #[error("VRL compile failed to run: {0}")]
    Internal(String),
}

/// Why [`compile`] produced no program.
#[derive(Debug)]
pub enum VrlCompileError {
    /// Refused by the size/nesting guard; never reached the compiler.
    Guard(VrlGuardError),
    /// The compiler's own diagnostics.
    Diagnostics(DiagnosticList),
}

impl VrlCompileError {
    /// One human-readable block per error (codespan-formatted diagnostics).
    pub fn messages(self, source: &str) -> Vec<String> {
        match self {
            Self::Guard(e) => vec![e.to_string()],
            Self::Diagnostics(list) => list
                .into_iter()
                .map(|d| Formatter::new(source, d).to_string())
                .collect(),
        }
    }

    /// All errors as one string.
    pub fn render(self, source: &str) -> String {
        match self {
            Self::Guard(e) => e.to_string(),
            Self::Diagnostics(list) => Formatter::new(source, list).to_string(),
        }
    }
}

impl From<VrlGuardError> for VrlCompileError {
    fn from(e: VrlGuardError) -> Self {
        Self::Guard(e)
    }
}

/// Size + nesting guard alone. Use before handing tenant VRL to anything that
/// parses it (e.g. `vrl::parser::parse`) without going through [`compile`].
pub fn check(source: &str) -> Result<(), VrlGuardError> {
    if source.len() > MAX_VRL_SOURCE_BYTES {
        return Err(VrlGuardError::TooLarge {
            len: source.len(),
            max: MAX_VRL_SOURCE_BYTES,
        });
    }
    let shape = scan(source, MAX_VRL_NESTING_DEPTH, MAX_VRL_TYPE_WORK);
    if shape.depth > MAX_VRL_NESTING_DEPTH {
        return Err(VrlGuardError::TooDeep {
            depth: shape.depth,
            max: MAX_VRL_NESTING_DEPTH,
        });
    }
    if shape.type_work > MAX_VRL_TYPE_WORK {
        return Err(VrlGuardError::TooCostly {
            work: shape.type_work,
            max: MAX_VRL_TYPE_WORK,
        });
    }
    Ok(())
}

/// Guarded `vrl::compiler::compile`: [`check`], then compile on a dedicated
/// large-stack thread. The only sanctioned way to compile VRL that a tenant
/// (or an AI acting for one) can influence.
pub fn compile(source: &str, fns: &[Box<dyn Function>]) -> Result<Compiled, VrlCompileError> {
    check(source)?;
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .name("vrl-compile".into())
            .stack_size(COMPILE_STACK_BYTES)
            .spawn_scoped(scope, || {
                vrl::compiler::compile(source, fns).map(|result| Compiled {
                    program: result.program,
                    warnings: result.warnings,
                })
            })
            .map_err(|e| VrlGuardError::Internal(format!("spawn compile thread: {e}")))?;
        handle
            .join()
            .map_err(|_| VrlGuardError::Internal("compile thread panicked".into()))?
            .map_err(VrlCompileError::Diagnostics)
    })
}

/// [`compile`] with errors formatted one block per diagnostic.
pub fn compile_formatted(source: &str, fns: &[Box<dyn Function>]) -> Result<Compiled, Vec<String>> {
    compile(source, fns).map_err(|e| e.messages(source))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Prev {
    /// Start of input, or after `,` `;` `:` / an opening bracket.
    Start,
    /// An operator, `.` segment or `if`/`else`: the expression continues.
    Operator,
    /// A literal, identifier or closing bracket.
    Value,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bracket,
    /// An `if` condition, open until its block's `{`.
    Cond,
}

struct Frame {
    kind: Kind,
    chain: usize,
    /// Opened by a function call's `(`.
    call: bool,
}

/// What [`scan`] measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// Upper bound on the syntax-tree depth.
    pub depth: usize,
    /// Type-check work beyond linear: `Σ tokens 2^enclosing_calls - 1`.
    pub type_work: u64,
}

/// [`scan`]'s depth alone.
pub fn nesting_depth(source: &str, stop_above: usize) -> usize {
    scan(source, stop_above, u64::MAX).depth
}

/// Upper bound on the syntax-tree depth of `source`, scanning tokens without
/// parsing. Returns as soon as the depth exceeds `stop_depth` (the exact
/// value past the cap is not useful and the scan stays O(n) either way).
///
/// Model: every open bracket (and every `if` condition) is a frame worth one
/// level. Inside a frame, each token that nests the expression one level
/// deeper — an operator (`!`, `+`, `??`, `=`, …), `else`, a `.field` / `[i]`
/// / `(args)` postfix — adds one to that frame's chain. `,` `;` `:` and a
/// newline that ends a statement start a new chain. The depth at any point is
/// the sum over open frames of `1 + chain`; the result is its maximum.
/// Over-counting is deliberate (it only ever makes the cap stricter).
///
/// Work: every token is charged `2^calls - 1`, `calls` being the function
/// calls (`name(` / `name!(`) it is inside. Stops early once the work
/// exceeds `stop_work`.
pub fn scan(source: &str, stop_depth: usize, stop_work: u64) -> Shape {
    let stop_above = stop_depth;
    let b = source.as_bytes();
    let mut frames = vec![Frame {
        kind: Kind::Bracket,
        chain: 0,
        call: false,
    }];
    let mut calls = 0u32;
    let mut work = 0u64;
    // frames.len() + sum of chains, maintained incrementally.
    let mut depth = 1usize;
    let mut max = 1usize;
    let mut prev = Prev::Start;
    // The previous byte ended a value with no whitespace in between, so a
    // following `.` / `[` / `(` is a postfix on it.
    let mut glued = false;
    let mut pending_newline = false;
    // Inside a closure's `|a, b|` parameter list (opened right after `->`):
    // its commas do not end the expression the closure is attached to.
    let mut arrow = false;
    let mut in_params = false;
    let mut i = 0;

    macro_rules! bump {
        () => {{
            if let Some(top) = frames.last_mut() {
                top.chain += 1;
            }
            depth += 1;
            max = max.max(depth);
            if max > stop_above {
                return Shape {
                    depth: max,
                    type_work: work,
                };
            }
        }};
    }
    // A token that cannot continue the previous line's expression ends the
    // statement there (VRL statements are newline-terminated).
    macro_rules! token {
        ($continues:expr) => {{
            if pending_newline && !$continues && prev != Prev::Operator {
                if let Some(top) = frames.last_mut() {
                    depth -= top.chain;
                    top.chain = 0;
                }
            }
            pending_newline = false;
            work = work.saturating_add((1u64 << calls.min(63)) - 1);
            if work > stop_work {
                return Shape {
                    depth: max,
                    type_work: work,
                };
            }
        }};
    }
    macro_rules! pop {
        () => {{
            if frames.len() > 1 {
                let f = frames.pop().expect("len > 1");
                depth -= 1 + f.chain;
                if f.call {
                    calls -= 1;
                }
            }
        }};
    }

    while i < b.len() {
        let c = b[i];
        let after_arrow = arrow;
        if !matches!(c, b' ' | b'\t' | b'\r' | b'\n' | b'#') {
            arrow = false;
        }
        match c {
            b'\n' => {
                pending_newline = true;
                glued = false;
                i += 1;
            }
            b' ' | b'\t' | b'\r' => {
                glued = false;
                i += 1;
            }
            b'#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                glued = false;
            }
            b'"' | b'\'' => {
                token!(false);
                i += 1;
                while i < b.len() && b[i] != c {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
                prev = Prev::Value;
                glued = true;
            }
            b'(' | b'[' | b'{' => {
                token!(false);
                if c == b'{' && frames.last().is_some_and(|f| f.kind == Kind::Cond) {
                    pop!();
                }
                if glued {
                    // call / index / fallible-call postfix on the chain
                    bump!();
                }
                let call = glued && c == b'(';
                if call {
                    calls += 1;
                }
                frames.push(Frame {
                    kind: Kind::Bracket,
                    chain: 0,
                    call,
                });
                depth += 1;
                max = max.max(depth);
                if max > stop_above {
                    return Shape {
                        depth: max,
                        type_work: work,
                    };
                }
                prev = Prev::Start;
                glued = false;
                i += 1;
            }
            b')' | b']' | b'}' => {
                token!(false);
                while frames.len() > 1 && frames.last().is_some_and(|f| f.kind == Kind::Cond) {
                    pop!();
                }
                pop!();
                prev = Prev::Value;
                glued = true;
                i += 1;
            }
            b',' | b';' | b':' => {
                token!(false);
                if !in_params {
                    if let Some(top) = frames.last_mut() {
                        depth -= top.chain;
                        top.chain = 0;
                    }
                }
                prev = Prev::Start;
                glued = false;
                i += 1;
            }
            b'.' => {
                // `.a.b` / `x.y` / `1.5`: a segment glued to a value nests the
                // chain; a leading `.` is a path root (a new operand).
                token!(glued);
                if glued {
                    bump!();
                }
                prev = Prev::Operator;
                glued = false;
                i += 1;
            }
            b'!' if glued && prev == Prev::Value && b.get(i + 1) == Some(&b'(') => {
                // `parse_json!(…)`: the fallible-call marker, part of the name.
                i += 1;
            }
            b'+' | b'-' | b'*' | b'/' | b'%' | b'<' | b'>' | b'=' | b'&' | b'|' | b'?' | b'!' => {
                token!(true);
                let two = b.get(i + 1).is_some_and(|&n| {
                    matches!(
                        (c, n),
                        (b'=', b'=')
                            | (b'!', b'=')
                            | (b'<', b'=')
                            | (b'>', b'=')
                            | (b'&', b'&')
                            | (b'|', b'|')
                            | (b'?', b'?')
                            | (b'|', b'=')
                            | (b'-', b'>')
                    )
                });
                if c == b'-' && two {
                    arrow = true;
                } else if c == b'|' && !two && (after_arrow || in_params) {
                    in_params = !in_params;
                }
                // An assignment (`=`, `|=`) costs the compiler and runtime
                // several times the stack of other levels (a debug build
                // overflows 2 MiB at ~127 chained `.a = .a = …`).
                let assign = (c == b'=' && !two) || (c == b'|' && b.get(i + 1) == Some(&b'='));
                for _ in 0..if assign { ASSIGN_WEIGHT } else { 1 } {
                    bump!();
                }
                prev = Prev::Operator;
                glued = false;
                i += if two { 2 } else { 1 };
            }
            _ if c == b'_' || c == b'@' || c == b'$' || c.is_ascii_alphanumeric() || c >= 0x80 => {
                let start = i;
                while i < b.len() {
                    let d = b[i];
                    if d == b'_' || d == b'@' || d == b'$' || d.is_ascii_alphanumeric() || d >= 0x80
                    {
                        i += 1;
                    } else {
                        break;
                    }
                }
                let word = &b[start..i];
                if word == b"else" {
                    token!(true);
                    bump!();
                    prev = Prev::Operator;
                    glued = false;
                } else if word == b"if" {
                    token!(false);
                    frames.push(Frame {
                        kind: Kind::Cond,
                        chain: 0,
                        call: false,
                    });
                    depth += 1;
                    max = max.max(depth);
                    if max > stop_above {
                        return Shape {
                            depth: max,
                            type_work: work,
                        };
                    }
                    prev = Prev::Operator;
                    glued = false;
                } else {
                    token!(false);
                    prev = Prev::Value;
                    glued = true;
                }
            }
            _ => {
                glued = false;
                i += 1;
            }
        }
    }
    Shape {
        depth: max,
        type_work: work,
    }
}

#[cfg(test)]
mod tests;

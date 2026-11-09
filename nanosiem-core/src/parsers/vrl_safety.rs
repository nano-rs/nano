// SPDX-License-Identifier: AGPL-3.0-or-later

//! The safety layer for tenant text that nano renders into Vector config.
//!
//! Vector runs every remap, filter and sample condition it loads with its FULL
//! VRL standard library and with `CLICKHOUSE_PASSWORD` / `VECTOR_AUTH_TOKEN` in
//! its environment. So everything a tenant (or a synced repository) can put
//! into generated VRL has to be one of two things:
//!
//! - **A scalar inside a string literal** (vendor, product, `source_type`,
//!   match values, …) — rendered with [`vrl_string_body`] / [`vrl_str`], which
//!   escape every character VRL or the surrounding TOML literal could read as
//!   syntax. Escaping is the identity on ordinary values, so this never
//!   changes what a legitimate value means.
//! - **A program or condition** (parser / extension VRL, the sampling exclude
//!   condition) — compiled against the parser function allowlist
//!   ([`super::vrl_functions::VrlRegistry::Parser`]), at write time for a clear
//!   error AND again at render time, because the render is the only path every
//!   stored value passes through (the 5 s publication reconciler ships rows a
//!   write path never saw: legacy rows, repository imports, never-published
//!   working copies).
//!
//! A value that fails at render time does not fail the whole render: one bad
//! source would otherwise freeze every tenant's Vector at its last generation.
//! [`quarantine`] degrades the one source instead, always toward keeping data:
//! a bad sampling condition turns sampling off (everything is kept), a bad
//! extension is skipped, and a bad parser becomes an `abort`, so its events
//! take the existing parse-failure path and are stored unparsed. NAN-5012,
//! NAN-5033, NAN-5057.



use super::types::Parser;
use super::vrl_functions::VrlRegistry;
use super::VrlValidator;

/// Largest accepted sampling exclude condition. A predicate does not need the
/// 1 MiB a parser may use.
pub const MAX_CONDITION_BYTES: usize = 4096;

/// Prefix of the note the render writes to `log_sources.validation_error`
/// when it quarantines part of a source. Only notes with this prefix are ever
/// overwritten or cleared by the render, so a real validation error stays.
pub const QUARANTINE_NOTE_PREFIX: &str = "Deploy safety check:";

/// The `_parse` program a quarantined parser renders as: every event aborts,
/// is rerouted to `.dropped`, and is stored unparsed as a parse failure.
pub const QUARANTINED_PARSER_VRL: &str =
    "abort # nano: parser quarantined by the deploy safety check";

/// Escape `s` for the body of a VRL double-quoted string literal.
///
/// Besides `\` and `"`, this escapes `'` (a run of three would close the
/// `'''` TOML literal the remap source sits in), `{` / `}` (VRL template
/// segments), and every control character as `\u{..}` (VRL's only unicode
/// escape form). `\'`, `\{` and `\}` all unescape to the same character, so
/// the runtime value is byte-identical to the input.
pub fn vrl_string_body(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\'' => out.push_str("\\'"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

/// `s` as a complete, quoted VRL string literal.
pub fn vrl_str(s: &str) -> String {
    format!("\"{}\"", vrl_string_body(s))
}

/// Render-time verdicts, memoized in the shared bounded LRU
/// ([`super::vrl_verdict_memo`]). The render runs on every publication; a
/// parser's verdict only changes when its text does.
fn memo(kind: &str, src: &str, check: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    super::vrl_verdict_memo::verdict(&format!("safety-{kind}"), src, check)
}

/// Check a tenant boolean condition (today: `sampling_exclude_condition`).
///
/// A condition must be a single-line, pure predicate over the event: it is
/// compiled on its own (so it cannot close the parentheses it is rendered
/// inside), against the parser allowlist (no `get_env_var`, `dns_lookup`,
/// `http_request`, `log`, …), with the event and its metadata read-only.
pub fn check_condition(field: &str, src: &str) -> Result<(), String> {
    crate::vector_env::reject_vrl_interpolation(field, src.trim())?;
    condition_verdict(src).map_err(|e| format!("{field}: {e}"))
}

fn condition_verdict(src: &str) -> Result<(), String> {
    let src = src.trim();
    if src.contains("SECRET[") {
        return Err("`SECRET[` is Vector secret-backend syntax and is not allowed".into());
    }
    if src.len() > MAX_CONDITION_BYTES {
        return Err(format!(
            "condition exceeds {MAX_CONDITION_BYTES} bytes (got {})",
            src.len()
        ));
    }
    if src.contains('\n') || src.contains('\r') {
        return Err("a condition must be a single line".into());
    }
    VrlValidator::new()
        .check_normalize_vrl_safety(src)
        .map_err(|e| e.to_string())?;
    let fns = VrlRegistry::Parser.functions();
    super::vrl_guard::compile_read_only(src, &fns)
        .map_err(|e| e.render(src).trim_end().to_string())?;
    // The rendered form must compile too (catches a trailing comment that
    // would swallow the closing parenthesis).
    let rendered = render_condition(src);
    super::vrl_guard::compile_read_only(&rendered, &fns)
        .map_err(|e| e.render(&rendered).trim_end().to_string())?;
    Ok(())
}

/// The condition as embedded in a generated `exclude`: compared to `true`, so
/// a non-boolean result means "not excluded" explicitly, and the comparison is
/// infallible whatever the expression's type.
pub fn render_condition(src: &str) -> String {
    format!("(({}) == true)", src.trim())
}

/// Check a tenant VRL program (parser or extension VRL, plain or a stored
/// processing plan) exactly as the parser editor's validate step does: the
/// security patterns, the guarded compile against the parser allowlist, and a
/// plan's native predicates.
pub fn check_program(field: &str, src: &str) -> Result<(), String> {
    program_verdict(src).map_err(|e| format!("{field}: {e}"))
}

/// The text a plain-VRL remap actually carries: the renderer rewrites `\r\n`
/// and a lone `\r` to `\n` (`parser_config::generate_transform_config`), but
/// VRL comments end only at `\n`, so `.a = 1 # x\r)` validates as one line
/// and renders as two. Validate what renders. A stored processing plan is a
/// TOML basic string and is not rewritten.
pub fn as_rendered(src: &str) -> std::borrow::Cow<'_, str> {
    if src.contains('\r') && !src.starts_with(super::pipe::HEADER) {
        std::borrow::Cow::Owned(src.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        std::borrow::Cow::Borrowed(src)
    }
}

fn program_verdict(src: &str) -> Result<(), String> {
    if src.contains("SECRET[") {
        return Err("`SECRET[` is Vector secret-backend syntax and is not allowed".into());
    }
    let src = as_rendered(src);
    let result = futures::executor::block_on(VrlValidator::new().validate_vrl(&src))
        .map_err(|e| e.to_string())?;
    if result.valid {
        Ok(())
    } else {
        Err(result.error.unwrap_or_else(|| "invalid VRL".into()))
    }
}

fn program_verdict_memo(src: &str) -> Result<(), String> {
    memo("program", src, || program_verdict(src))
}

fn condition_verdict_memo(src: &str) -> Result<(), String> {
    memo("condition", src, || condition_verdict(src))
}

pub(crate) fn shorten(message: &str) -> String {
    const MAX: usize = 400;
    let flat = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= MAX {
        flat
    } else {
        format!("{}…", flat.chars().take(MAX).collect::<String>())
    }
}

/// Whether sampling is configured in a way the renderer would emit.
fn sampling_active(parser: &Parser) -> bool {
    parser.sampling_ratio.is_some_and(|r| r > 0.0 && r < 1.0)
}

/// The render-time verdict for one log source: the source as it is safe to
/// render, plus one operator-facing note per part that was degraded.
/// Enrichment sources and disabled sources are returned unchanged (the
/// enrichment lane has its own render guard; a disabled source renders
/// nothing).
pub fn quarantine(parser: &Parser) -> (Parser, Vec<String>) {
    let mut safe = parser.clone();
    let mut notes = Vec::new();
    if parser.kind == "enrichment" || !parser.enabled {
        return (safe, notes);
    }

    let has_extension = parser.extension_enabled
        && parser
            .extension_vrl
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty());

    if has_extension {
        if let Err(reason) =
            program_verdict_memo(parser.extension_vrl.as_deref().unwrap_or_default())
        {
            safe.extension_enabled = false;
            notes.push(format!(
                "Parser extension disabled: {}. Events are parsed by the base parser only.",
                shorten(&reason)
            ));
        }
    }

    let parser_blank = parser.parser_vrl.trim().is_empty();
    let parser_verdict = if parser_blank {
        Ok(())
    } else {
        program_verdict_memo(&parser.parser_vrl)
    };
    // A stub source (no parser, logic in the extension) whose extension was
    // just disabled has nothing safe left to run: quarantine it whole.
    let stub_lost_extension = parser_blank && has_extension && !safe.extension_enabled;
    if parser_verdict.is_err() || stub_lost_extension {
        safe.parser_vrl = QUARANTINED_PARSER_VRL.to_string();
        safe.extension_enabled = false;
        let reason = match parser_verdict {
            Err(reason) => shorten(&reason),
            Ok(()) => "its extension did not pass the check".to_string(),
        };
        notes.push(format!(
            "Parser quarantined: {reason}. Events are stored unparsed as parse failures until the parser is fixed and published."
        ));
    }

    if sampling_active(parser) {
        if let Some(condition) = parser
            .sampling_exclude_condition
            .as_deref()
            .filter(|c| !c.trim().is_empty())
        {
            if let Err(reason) = condition_verdict_memo(condition) {
                safe.sampling_ratio = None;
                notes.push(format!(
                    "Sampling paused: the exclude condition is not allowed ({}). All events are kept until the condition is fixed or cleared.",
                    shorten(&reason)
                ));
            }
        }
    }

    (safe, notes)
}

/// `parser` with every tenant-authored part removed: the parser aborts (events
/// take the parse-failure path), no extension, no sampling. What a source
/// renders as when even its degraded document fails the deploy guard.
pub fn quarantined_whole(parser: &Parser) -> Parser {
    let mut safe = parser.clone();
    safe.parser_vrl = QUARANTINED_PARSER_VRL.to_string();
    safe.extension_enabled = false;
    safe.sampling_ratio = None;
    safe
}

/// The note to store in `log_sources.validation_error` for these notes, or
/// `None` when the source rendered unchanged.
pub fn quarantine_note(notes: &[String]) -> Option<String> {
    (!notes.is_empty()).then(|| format!("{QUARANTINE_NOTE_PREFIX} {}", notes.join(" ")))
}

#[cfg(test)]
#[path = "vrl_safety_tests.rs"]
mod tests;

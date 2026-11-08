// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4954 source guard: every handler that emits a SECURITY-CRITICAL audit
//! action must make it durable before responding — either
//! `state.emit_audit_durable(..).await` (PostgreSQL outbox write awaited) or a
//! `*_audited(..)` service call that records it in the handler's own
//! transaction. A bare `state.emit_audit(..)` spawns before the PostgreSQL
//! write, so a crash after the response would lose the event.

use std::path::{Path, PathBuf};

use nanosiem_core::audit::SECURITY_CRITICAL_ACTIONS;

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && !path.to_string_lossy().ends_with("_tests.rs")
        {
            out.push(path);
        }
    }
}

/// `LOGIN_SUCCESS` for `"login_success"` — the actions module names every
/// constant as the upper-cased value (checked below).
fn constant_names() -> Vec<String> {
    SECURITY_CRITICAL_ACTIONS.iter().map(|a| a.to_uppercase()).collect()
}

fn is_word_at(s: &str, idx: usize, word: &str) -> bool {
    let before = s[..idx].chars().next_back();
    let after = s[idx + word.len()..].chars().next();
    let ident = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    !ident(before) && !ident(after)
}

fn mentions_critical(args: &str, names: &[String]) -> Option<String> {
    names.iter().find_map(|n| {
        args.match_indices(n.as_str())
            .any(|(i, _)| is_word_at(args, i, n))
            .then(|| n.clone())
    })
}

#[test]
fn constant_names_match_security_critical_values() {
    let actions = include_str!("../../../nanosiem-core/src/audit/actions.rs");
    for (name, value) in constant_names().iter().zip(SECURITY_CRITICAL_ACTIONS) {
        assert!(
            actions.contains(&format!("pub const {name}: &str = \"{value}\"")),
            "{value} is not declared as `{name}`; update this guard's name mapping"
        );
    }
}

#[test]
fn security_critical_actions_are_emitted_durably() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src/handlers"), &mut files);
    // Enterprise handlers (absent from the stripped open-core tree).
    rust_files(&root.join("../nanosiem-enterprise/src/handlers"), &mut files);
    assert!(files.len() > 20, "handler sources not found under {}", root.display());

    let names = constant_names();
    let mut checked = 0;
    let mut offenders = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file).unwrap();
        for (i, _) in src.match_indices("AuditEvent::builder(") {
            let args_end = src[i..].find(')').map(|e| i + e).unwrap_or(src.len());
            let Some(action) = mentions_critical(&src[i..args_end], &names) else {
                continue;
            };
            checked += 1;
            let prefix = &src[..i];
            let last = |pat: &str| prefix.rfind(pat).map(|p| p as isize).unwrap_or(-1);
            let bare = last(".emit_audit(");
            let durable = last(".emit_audit_durable(").max(last("_audited("));
            if bare > durable {
                let line = prefix.matches('\n').count() + 1;
                offenders.push(format!("{}:{line} {action}", file.display()));
            }
        }
    }
    assert!(checked >= 20, "expected to find the security-critical call sites, saw {checked}");
    assert!(
        offenders.is_empty(),
        "security-critical audit actions emitted fire-and-forget (use emit_audit_durable(..).await):\n{}",
        offenders.join("\n")
    );
}

/// The ingest-token handlers pass the action through a helper, so the literal
/// scan cannot see it; every action there is security-critical.
#[test]
fn ingest_token_audit_helper_is_durable() {
    let src = include_str!("ingest_tokens.rs");
    assert!(!src.contains(".emit_audit("), "ingest_tokens.rs must use emit_audit_durable");
    assert!(src.contains("async fn audit("));
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-text safety scans for tenant-authored overlay files.
//!
//! These run on the *generated* overlay file, not on the tenant's VRL alone,
//! so everything the file carries (parser VRL, extension VRL, the sampling
//! exclusion, metadata strings) is covered by one pass. Vector compiles VRL
//! with no dynamic dispatch, so a function can only be reached by naming it:
//! an identifier scan cannot be obfuscated around. It can false-positive on a
//! string literal or comment that merely mentions a blocked name; that fails
//! closed, which is the right direction for untrusted tenant code.

use regex::Regex;
use std::sync::LazyLock;

use crate::parsers::validator::BLOCKED_VRL_FUNCTIONS;

/// Functions a tenant overlay may never call, beyond `BLOCKED_VRL_FUNCTIONS`.
///
/// The cell's HEC normalizer reads the private delivery token through
/// `get_secret("splunk_hec_token")` and removes it before buffering; a tenant
/// remap that could read, set or remove secrets could observe or forge that
/// binding. Event-metadata setters are blocked for the same reason `%` writes
/// are (see [`metadata_writes`]).
pub const OVERLAY_EXTRA_BLOCKED_FUNCTIONS: &[&str] = &[
    "get_secret",
    "set_secret",
    "remove_secret",
    "set_metadata_field",
    "remove_metadata_field",
];

static CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9_])([a-z_][a-z0-9_]*)\s*!?\s*\(").expect("static regex")
});

/// Every blocked function the text names as a call, in first-seen order.
pub fn blocked_function_calls(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for captures in CALL_RE.captures_iter(text) {
        let name = &captures[1];
        let blocked = BLOCKED_VRL_FUNCTIONS.contains(&name)
            || OVERLAY_EXTRA_BLOCKED_FUNCTIONS.contains(&name);
        if blocked && !found.iter().any(|seen| seen == name) {
            found.push(name.to_string());
        }
    }
    found
}

/// Offsets of writes to Vector event metadata (`%path = …`, `%path |= …`,
/// `del(%…)`).
///
/// The platform stamps `%tenant_id` and `%source_type` before any parser runs,
/// and the lake sink turns them into the Bronze key prefix and
/// `metadata.log_source` — the label source-visibility RBAC keys on. A tenant
/// remap that could rewrite them could file its rows under another source, or
/// try another tenant's prefix. Reads (`%source_type` on the right-hand side)
/// are fine; VRL's modulo operator (`a % b`) is not a path and is not matched.
pub fn metadata_writes(text: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut hits = Vec::new();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'%' {
            continue;
        }
        // Skip the metadata path itself.
        let mut cursor = index + 1;
        while cursor < bytes.len() {
            match bytes[cursor] {
                // A quoted path segment may hold anything but a quote.
                b'"' => {
                    cursor += 1;
                    while cursor < bytes.len() && bytes[cursor] != b'"' {
                        cursor += 1;
                    }
                    cursor += 1;
                }
                b if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'[' | b']' | b'-') => {
                    cursor += 1
                }
                _ => break,
            }
        }
        cursor = cursor.min(bytes.len());
        while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
            cursor += 1;
        }
        let rest = &bytes[cursor..];
        let is_assign = |rest: &[u8]| {
            (rest.first() == Some(&b'=') && rest.get(1) != Some(&b'=')) || rest.starts_with(b"|=")
        };
        // `%path, err = f()` — the ok target of a fallible assignment.
        let fallible_target = rest.first() == Some(&b',') && {
            let mut next = 1;
            while next < rest.len() && matches!(rest[next], b' ' | b'\t') {
                next += 1;
            }
            while next < rest.len() && (rest[next].is_ascii_alphanumeric() || rest[next] == b'_') {
                next += 1;
            }
            while next < rest.len() && matches!(rest[next], b' ' | b'\t') {
                next += 1;
            }
            is_assign(&rest[next..])
        };
        let assigns = is_assign(rest) || fallible_target;
        let deletes = text[..index]
            .trim_end_matches([' ', '\t'])
            .ends_with("del(");
        if assigns || deletes {
            hits.push(index);
        }
    }
    hits
}

/// Scan every decoded string, including VRL sources/conditions and nested
/// arrays. TOML string escaping must not conceal quoted metadata paths.
pub fn metadata_writes_in_toml(value: &toml::Value) -> bool {
    match value {
        toml::Value::String(text) => !metadata_writes(text).is_empty(),
        toml::Value::Array(values) => values.iter().any(metadata_writes_in_toml),
        toml::Value::Table(values) => values.values().any(metadata_writes_in_toml),
        _ => false,
    }
}

/// `true` when some `$` is not part of a `$$` escape pair.
///
/// The cell runs Vector with `--dangerously-allow-env-var-interpolation`, which
/// substitutes `${VAR}` / `$VAR` anywhere in the config text — VRL string
/// literals included — before the TOML is parsed. An unescaped `$` in tenant
/// text would let a parser copy `${NANO_LAKE_SECRET_ACCESS_KEY}` into its own
/// events. The generator escapes every `$` as `$$`; this re-checks it.
pub fn has_unescaped_dollar(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'$' {
            if bytes.get(index + 1) == Some(&b'$') {
                index += 2;
                continue;
            }
            return true;
        }
        index += 1;
    }
    false
}

/// Escape every `$` so Vector's interpolation yields the literal text back.
pub fn escape_interpolation(text: &str) -> String {
    text.replace('$', "$$")
}

// The same secret heuristics the tenant Worker renderer applies to every
// bundle member (`load_vector_bundle`). Running them here fails a build that
// the renderer would refuse later, with the reason attached.
pub(crate) static SECRET_PRIVATE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").expect("static regex")
});
pub(crate) static SECRET_AKIA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAKIA[A-Z0-9]{16}\b").expect("static regex"));
pub(crate) static SECRET_BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}\b").expect("static regex")
});
pub(crate) static SECRET_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:password|api[_-]?token|auth[_-]?token|secret[_-]?access[_-]?key)\s*=\s*["']([^"']{8,})["']"#,
    )
    .expect("static regex")
});

pub(crate) fn contains_secret_pattern(text: &str) -> bool {
    SECRET_PRIVATE_KEY_RE.is_match(text)
        || SECRET_AKIA_RE.is_match(text)
        || SECRET_BEARER_RE.is_match(text)
}

/// The renderer's refusal for a tenant file (no README exemption applies).
pub fn secret_material(text: &str) -> bool {
    contains_secret_pattern(text)
        || SECRET_ASSIGNMENT_RE.captures_iter(text).any(|captures| {
            let value = &captures[1];
            !value.starts_with("${")
                && !value.starts_with("unused-")
                && !value.starts_with("not-a-credential")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_calls_are_found_with_bang_and_space() {
        let text = ".a = get_env_var!(\"X\")\n.b = get_secret (\"y\")\n.c = my_get_env_var(1)";
        assert_eq!(
            blocked_function_calls(text),
            vec!["get_env_var", "get_secret"]
        );
        assert!(blocked_function_calls(".x = parse_json!(.message)").is_empty());
    }

    #[test]
    fn metadata_writes_flag_assignments_and_deletes_but_not_reads_or_modulo() {
        assert_eq!(metadata_writes("%tenant_id = \"other\"").len(), 1);
        assert_eq!(metadata_writes("%source_type |= {}").len(), 1);
        assert_eq!(metadata_writes("% = {}").len(), 1);
        assert_eq!(metadata_writes("del(%tenant_id)").len(), 1);
        assert_eq!(metadata_writes("%\"odd key\" = 1").len(), 1);
        assert_eq!(metadata_writes("%tenant_id, err = to_string(.x)").len(), 1);
        assert_eq!(metadata_writes(".ok, %tenant_id = parse_json(.x)").len(), 1);
        assert!(metadata_writes(".x = join!([%source_type, \"a\"], \",\")").is_empty());
        assert!(metadata_writes(".x = to_string(%source_type) ?? \"\"").is_empty());
        assert!(metadata_writes(".r = .a % 2\nif .a % 2 == 0 { .b = 1 }").is_empty());
        assert!(metadata_writes("if %source_type == \"x\" { .y = 1 }").is_empty());
        assert!(metadata_writes(".pct = \"50%\"").is_empty());
    }

    #[test]
    fn dollar_escaping_round_trips() {
        let raw = ".k = \"${NANO_LAKE_SECRET_ACCESS_KEY}\" + \"$HOME\" + \"$$\"";
        assert!(has_unescaped_dollar(raw));
        let escaped = escape_interpolation(raw);
        assert!(!has_unescaped_dollar(&escaped));
        assert_eq!(escaped.replace("$$", "$"), raw);
    }

    #[test]
    fn secret_material_matches_the_renderer_rule() {
        assert!(secret_material("password = \"hunter2hunter2\""));
        assert!(!secret_material("password = \"${VECTOR_PASSWORD}\""));
        assert!(!secret_material("password = \"unused-build\""));
        assert!(secret_material("x AKIAIOSFODNN7EXAMPLE y"));
    }
}

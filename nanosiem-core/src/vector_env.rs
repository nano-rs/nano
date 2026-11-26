// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vector environment-interpolation hygiene for every file nano renders into
//! the live Vector's config dirs (NAN-4936 source configs, NAN-4953 parsers).
//!
//! # Why
//!
//! The live Vector runs with `--dangerously-allow-env-var-interpolation`: the
//! install-owned static configs and the generated sinks (`_pipeline.toml`,
//! `_ocsf_sink.toml`, `_enrichment.toml`) read `${VECTOR_AUTH_TOKEN}` and
//! `${CLICKHOUSE_*}` from the container environment. Vector substitutes
//! `${NAME}`, `${NAME:-default}` and `$NAME` inside every string value of the
//! config, and a VRL program is one (`source = '''...'''`), so the
//! substitution reaches string literals inside VRL as well. A tenant who
//! writes `.leak = "${CLICKHOUSE_PASSWORD}"` in a parser would otherwise ship
//! the ClickHouse password inside every event.
//!
//! NAN-5810: Vector 0.62 (vectordotdev/vector#26475) PARSES the file first and
//! then substitutes only inside string values, coercing the result to the
//! field's type (0.61 and older substituted over the raw text before parsing).
//! So a placeholder must be a quoted TOML string even where the field is a
//! number: `max_bytes = "${VECTOR_BATCH_MAX_BYTES:-52428800}"`. The bare form
//! `max_bytes = ${...}` is a TOML parse error on 0.62 and Vector refuses the
//! whole config. [`quote_bare_placeholders`] rewrites files an older release
//! left behind; `config/vector/.nano/vector-entrypoint.sh` does the same to
//! the persisted dynamic tree before Vector starts. A `#` comment is no
//! longer interpolated at all.
//!
//! # The rule
//!
//! * A file whose content nano does not need interpolated (a per-parser TOML,
//!   `_router.toml`, a source-config file) is rendered with EVERY `$` doubled
//!   ([`escape_file`]). Vector reads `$$` back as a literal `$`, so the
//!   escaping is semantics-preserving under interpolation (a VRL regex
//!   `r'^a$'` still ends in `$`) and inert for everything else. Line 1 carries
//!   [`ENV_ESCAPED_HEADER`] so the Vector entrypoint can tell a pre-upgrade
//!   file from an escaped one and migrate the former before Vector starts.
//! * A file that mixes nano-owned interpolation with tenant text (only
//!   `_enrichment.toml`: tenant `normalize_vrl` next to the ClickHouse sinks)
//!   escapes the tenant fragment itself ([`escape_fragment`]) and carries
//!   [`ENV_ESCAPED_TENANT_HEADER`]. The entrypoint migrates such a file by
//!   escaping only the bodies of its `'''` VRL blocks, where the tenant text
//!   lives.
//! * Tenant input that is not a credential rejects interpolation syntax at
//!   save time ([`contains_env_interpolation`]); escaping is the backstop.
//!
//! Keep the header strings in sync with `config/vector/.nano/vector-entrypoint.sh`.
//!
//! # Why the live Vector keeps env interpolation (NAN-4953 evaluation)
//!
//! Turning `--dangerously-allow-env-var-interpolation` off would close this
//! class at the root, and was evaluated. It is not done here, because:
//!
//! * **Vector's secret backend is the same hazard, with no escape.** Moving
//!   `VECTOR_AUTH_TOKEN` / `CLICKHOUSE_*` to a `[secret.<name>]` backend makes
//!   Vector substitute `SECRET[<name>.<key>]` over the raw config text before
//!   parsing, exactly as it does `${NAME}`, and Vector has no `$$`-style
//!   escape for it. Tenant text containing `SECRET[nano.clickhouse_password]`
//!   would resolve and could not be neutralized by rendering, only refused.
//!   That is why [`reject_vrl_interpolation`] already refuses `SECRET[`.
//! * **The install owns the interpolating files, not nano-api.** The static
//!   configs (`config/vector/*.toml`: HEC `valid_tokens`, the OTLP and metrics
//!   ClickHouse sinks, numeric batch tunables quoted for Vector 0.62) are a
//!   read-only bind mount in compose and a ConfigMap in Kubernetes, and the
//!   managed deployer (nano-main) generates the same command line. Rendering
//!   them at deploy time means a new renderer in every deployer plus a new
//!   entrypoint contract, not a change this repository can make alone.
//! * **It is a flag day for every rendered file.** With interpolation off,
//!   Vector stops reading `$$` as `$`, so every escaped file (source configs
//!   since NAN-4936, parser files since NAN-4953) would have to be re-rendered
//!   unescaped in the same step, or a VRL regex `r'^a$'` silently becomes
//!   `r'^a$$'`.
//!
//! The escaping here makes the hazard inert without any of that, on every
//! topology, and stays correct if the flag is later removed together with a
//! one-shot unescaped re-render.

/// First line of every file rendered with [`escape_file`].
pub const ENV_ESCAPED_HEADER: &str = "# nano-env-escaped: v1";

/// First line of a file whose tenant fragments were escaped with
/// [`escape_fragment`] while the rest keeps nano's own `${...}` references.
pub const ENV_ESCAPED_TENANT_HEADER: &str = "# nano-env-escaped: v1 tenant-vrl";

/// Does `value` contain Vector environment-interpolation syntax
/// (`${NAME}` / `${NAME:-default}` or `$NAME`)?
///
/// `$$` is Vector's escape for a literal `$` and is not interpolation: the
/// scan consumes it as a pair, so `$$HOME` is a literal `$HOME`.
pub fn contains_env_interpolation(value: &str) -> bool {
    first_env_interpolation(value).is_some()
}

/// Byte offset of the first interpolation sequence in `value`, if any.
pub fn first_env_interpolation(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' {
            let next = bytes[i + 1];
            if next == b'$' {
                i += 2;
                continue;
            }
            if next == b'{' || next == b'_' || next.is_ascii_alphabetic() {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// NAN-4953: refuse Vector interpolation syntax in tenant-authored VRL (the
/// parser editor, Nano Pipe advanced VRL steps, extension and enrichment
/// normalize VRL, pivt drafts: they all save through the log-source API).
///
/// Rendering escapes every `$`, so such text can no longer expand; but an
/// author who writes `${CLICKHOUSE_PASSWORD}` means an expansion, and saving it
/// silently as a literal would hide that. `field` names the input in the error.
///
/// The explicit way to keep a literal is to split the `$` from what follows,
/// e.g. `"$" + "{NAME}"` or `"$" + "NAME"`. Numbered capture references in
/// `replace()` (`"$1"`) are not interpolation syntax and stay allowed.
pub fn reject_vrl_interpolation(field: &str, vrl: &str) -> Result<(), String> {
    // Vector's secret-backend syntax has no escape (see the module docs).
    if vrl.contains("SECRET[") {
        return Err(format!(
            "{field}: `SECRET[` is Vector secret-backend syntax, which Vector would resolve \
             against its own secrets, so nano refuses it. To keep the literal text, split it, \
             for example \"SECRET\" + \"[\"."
        ));
    }
    let Some(at) = first_env_interpolation(vrl) else {
        return Ok(());
    };
    let line = vrl[..at].matches('\n').count() + 1;
    let column = at - vrl[..at].rfind('\n').map_or(0, |nl| nl + 1) + 1;
    let snippet: String = vrl[at..]
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
        .take(40)
        .collect();
    Err(format!(
        "{field}: `{snippet}` at line {line}, column {column} is environment-variable syntax. \
         Vector would read `${{NAME}}` / `$NAME` as a reference to its own environment, so nano \
         refuses it. To keep a literal `$`, split it from what follows, for example \
         \"$\" + \"{{NAME}}\". Numbered capture references such as \"$1\" are fine."
    ))
}

/// Double every `$` in a tenant fragment embedded in an otherwise
/// interpolated file. See the module docs.
pub fn escape_fragment(fragment: &str) -> String {
    fragment.replace('$', "$$")
}

/// Make a whole rendered file inert to Vector's environment interpolation:
/// [`ENV_ESCAPED_HEADER`] on line 1 and every `$` doubled. Idempotent: a file
/// that already starts with the header is returned unchanged, so a caller can
/// never double-escape.
pub fn escape_file(rendered: &str) -> String {
    if is_escaped_file(rendered) {
        return rendered.to_string();
    }
    format!("{ENV_ESCAPED_HEADER}\n{}", escape_fragment(rendered))
}

/// Whether `content` was rendered by [`escape_file`].
pub fn is_escaped_file(content: &str) -> bool {
    content.lines().next() == Some(ENV_ESCAPED_HEADER)
}

/// The inverse of [`escape_file`] for readers that want nano's own view of a
/// rendered file (diffs, snapshots, in-process graph checks): drops the header
/// and turns `$$` back into `$`. A file without the header is returned as is.
pub fn unescape_file(content: &str) -> String {
    match content.strip_prefix(ENV_ESCAPED_HEADER) {
        Some(rest) => rest.strip_prefix('\n').unwrap_or(rest).replace("$$", "$"),
        None => content.to_string(),
    }
}

/// What Vector's interpolation does to `raw` with an EMPTY environment, for
/// in-process checks that must read the raw files the way Vector will.
/// Applied to the raw text, not per string value as Vector 0.62 does
/// (NAN-5810), which is equivalent for nano's files: every placeholder is a
/// whole quoted value and the defaults hold no TOML syntax. A quoted numeric
/// placeholder stays a TOML string after substitution (`max_bytes =
/// "52428800"`, which Vector coerces to the field's type). A file an older
/// release left with a bare placeholder (`max_bytes = ${...}`) substitutes to
/// a bare number, so these checks read either form. Mirrors Vector's
/// `ENVIRONMENT_VARIABLE_INTERPOLATION_REGEX`:
///
/// * `$$` becomes `$`;
/// * `$NAME` (NAME = word characters and `.`) becomes empty;
/// * `${NAME}` becomes empty, `${NAME:-default}` / `${NAME-default}` become
///   `default` (and the `?` error forms become empty);
/// * any other `$` stays literal.
pub fn substitute_like_vector(raw: &str) -> String {
    fn is_name(b: u8) -> bool {
        b == b'_' || b == b'.' || b.is_ascii_alphanumeric()
    }
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    let mut literal_start = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        if next == b'$' {
            out.push_str(&raw[literal_start..i]);
            out.push('$');
            i += 2;
            literal_start = i;
        } else if is_name(next) {
            out.push_str(&raw[literal_start..i]);
            let mut j = i + 1;
            while j < bytes.len() && is_name(bytes[j]) {
                j += 1;
            }
            i = j;
            literal_start = i;
        } else if next == b'{' {
            let name_start = i + 2;
            let mut j = name_start;
            while j < bytes.len() && is_name(bytes[j]) {
                j += 1;
            }
            let Some(close) = raw[j..].find('}').map(|c| j + c) else {
                i += 1;
                continue;
            };
            if j == name_start {
                i += 1;
                continue;
            }
            let rest = &raw[j..close];
            let default = if let Some(d) = rest.strip_prefix(":-").or_else(|| rest.strip_prefix('-')) {
                Some(d)
            } else if rest.is_empty() || rest.starts_with(":?") || rest.starts_with('?') {
                None
            } else {
                // `${NAME<junk>}`: not an interpolation in Vector's grammar.
                i += 1;
                continue;
            };
            out.push_str(&raw[literal_start..i]);
            out.push_str(default.unwrap_or(""));
            i = close + 1;
            literal_start = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&raw[literal_start..]);
    out
}

/// NAN-5810: a line whose whole TOML value is one bare placeholder,
/// `key = ${NAME}` / `key = ${NAME:-default}` (optionally followed by a `#`
/// comment). Vector 0.62 parses before it interpolates, so such a line is a
/// TOML parse error there. Captures: 1 = `key = ` (with its indentation),
/// 2 = the placeholder, 3 = the trailing whitespace and comment.
///
/// The default may not hold `"`, `\` or `}` (it is wrapped in a basic string
/// as is); `${NAME-default}` and the `?` error forms are accepted too.
static BARE_PLACEHOLDER_LINE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(
        r#"^(\s*[A-Za-z0-9_."-]+\s*=\s*)(\$\{[A-Za-z0-9_.]+(?:(?::?-|:?\?)[^}"\\\r\n]*)?\})(\s*(?:#.*)?)$"#,
    )
    .expect("static regex")
});

/// Visit every line of `content` that is outside a TOML multi-line string
/// (`'''` / `"""`, where VRL programs live) with its 0-based index and its
/// text without the line ending. Lines that open, sit inside, or close such a
/// string are never visited.
fn for_each_toml_value_line(content: &str, mut visit: impl FnMut(usize, &str)) {
    // The delimiter of the multi-line string the scan is inside, if any.
    let mut open: Option<&str> = None;
    for (index, line) in content.split_inclusive('\n').enumerate() {
        let body = line.trim_end_matches(['\n', '\r']);
        match open {
            Some(delim) => {
                if body.matches(delim).count() % 2 == 1 {
                    open = None;
                }
            }
            // A full-line comment outside a multi-line string opens nothing,
            // whatever quotes it mentions (NAN-5810 review: `# its ''' VRL
            // blocks` must not flip the scan for the rest of the file).
            None if body.trim_start().starts_with('#') => {}
            None => {
                // An odd count of a delimiter opens a multi-line string; a
                // line holding one at all is never a bare-value line.
                let opened = ["'''", "\"\"\""]
                    .into_iter()
                    .find(|delim| body.matches(delim).count() % 2 == 1);
                match opened {
                    Some(delim) => open = Some(delim),
                    None => visit(index, body),
                }
            }
        }
    }
}

/// NAN-5810: the 1-based line numbers (with the line) whose whole TOML value
/// is a bare `${...}` placeholder, which Vector 0.62 cannot parse. Empty for
/// a file whose placeholders 0.62 can load.
pub fn bare_placeholder_lines(content: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for_each_toml_value_line(content, |index, body| {
        if BARE_PLACEHOLDER_LINE.is_match(body) {
            out.push((index + 1, body.to_string()));
        }
    });
    out
}

/// NAN-5810: make a Vector TOML written by an older release (whose Vector
/// interpolated before parsing) loadable by Vector 0.62. Every line whose
/// whole value is one bare placeholder,
/// `max_bytes = ${VECTOR_BATCH_MAX_BYTES:-52428800}`, becomes the quoted form
/// `max_bytes = "${VECTOR_BATCH_MAX_BYTES:-52428800}"`, which 0.62
/// substitutes and coerces to the field's type.
///
/// Everything else stays byte-identical: other lines, line endings, the
/// bodies of `'''` / `"""` multi-line strings (VRL is never touched), and an
/// already-quoted value. Idempotent. Keep in sync with the quoting awk in
/// `config/vector/.nano/vector-entrypoint.sh` (`nano-quote-bare-placeholders`).
pub fn quote_bare_placeholders(content: &str) -> String {
    let mut targets = std::collections::HashSet::new();
    for_each_toml_value_line(content, |index, body| {
        if BARE_PLACEHOLDER_LINE.is_match(body) {
            targets.insert(index);
        }
    });
    if targets.is_empty() {
        return content.to_string();
    }
    let mut out = String::with_capacity(content.len() + 2 * targets.len());
    for (index, line) in content.split_inclusive('\n').enumerate() {
        if !targets.contains(&index) {
            out.push_str(line);
            continue;
        }
        let body = line.trim_end_matches(['\n', '\r']);
        let ending = &line[body.len()..];
        let caps = BARE_PLACEHOLDER_LINE.captures(body).expect("matched in the scan");
        out.push_str(&caps[1]);
        out.push('"');
        out.push_str(&caps[2]);
        out.push('"');
        out.push_str(&caps[3]);
        out.push_str(ending);
    }
    out
}

/// Test helper: an integer TOML field as Vector 0.62 reads it after
/// substitution: a TOML integer, or a string holding one (a quoted
/// placeholder substitutes to `"52428800"`, which Vector coerces).
#[cfg(test)]
pub(crate) fn toml_integer(value: &toml::Value) -> Option<i64> {
    value
        .as_integer()
        .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
}

#[cfg(test)]
#[path = "vector_env_tests.rs"]
mod tests;

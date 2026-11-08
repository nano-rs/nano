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
//! `${NAME}`, `${NAME:-default}` and `$NAME` over the RAW file text before it
//! parses the TOML, so the substitution reaches string literals inside VRL as
//! well. A tenant who writes `.leak = "${CLICKHOUSE_PASSWORD}"` in a parser
//! would otherwise ship the ClickHouse password inside every event.
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
//!   ClickHouse sinks, numeric batch tunables that must be unquoted TOML) are a
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
/// in-process checks that must parse the raw files the way Vector will (the
/// raw text is not valid TOML: `max_bytes = ${...}`). Mirrors Vector's
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

#[cfg(test)]
#[path = "vector_env_tests.rs"]
mod tests;

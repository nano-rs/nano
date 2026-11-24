// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vector Configuration Manager
//!
//! Generates and deploys Vector TOML configurations from database parsers.
//!
//! # Submodules
//!
//! - [`backup`] - Backup and restore for rollback support
//! - [`credentials`] - Cleanup for retired parser-owned credential files
//! - [`deploy`] - Parser deployment and Vector reload
//! - [`parser_config`] - Per-parser TOML config generation
//! - [`redaction`] - Snapshot redaction for persisted Vector configs
//! - [`router`] - Dynamic source type router generation
//! - [`sources`] - Source-specific config generators (Kafka, S3, GCP, HEC)
//! - [`staging`] - Staging directory for validation before deployment
//! - [`validation`] - Vector validate integration via Docker

/// NAN-4038: VRL that removes credential-named fields from the event at any
/// depth before it is stored.
///
/// Header names are case-insensitive, and a credential can arrive as a JSON
/// body key (`parse_content` merges body keys onto the event), inside a header
/// map (`.headers`, `.http.request.headers`), from a HEC `event` object, or
/// from an upstream Vector. Every path into storage passes one of the blocks
/// that splice this in (`prepare_output`, `clickhouse_mapping`, and the two
/// OCSF prepare blocks), so it is applied there rather than at each source.
///
/// A field is removed when ANY segment of its path names a credential, so an
/// object-valued `Authorization` goes too. Arrays are not descended into
/// (`flatten` keeps them whole). A macro, not a `const`, so it can be
/// `concat!`-ed into the static config literals.
///
/// NAN-5180: the path walk (`flatten` + a split and a downcase per segment)
/// cost 35-60 us per event on the OCSF lane, and almost no event carries a
/// credential key. It now runs only when [`credential_key_precheck_vrl!`]
/// finds one in the event's JSON text, which it always does when the walk
/// would remove something (see that macro), so the output is unchanged.
macro_rules! credential_field_redaction_vrl {
    () => {
        concat!(
            r#"# NAN-4038: credential-named fields never reach storage (any depth,
# case-insensitive). See credential_field_redaction_vrl! in vector_config/mod.rs.
nano_cred_names = ["authorization", "proxy-authorization", "x-api-key", "x-webhook-secret", "cookie", "set-cookie"]
nano_cred_paths = []
# NAN-5352: one gate for both forms. It also matches a credential name written
# INSIDE a string (`raw_data`, `message`, any other text), which is a superset
# of the key precheck below, so an event without either pays one scan.
nano_cred_text = encode_json(.)
if match(nano_cred_text, "#,
            credential_text_gate_vrl!(),
            r#") || match(nano_cred_text, "#,
            credential_escape_gate_vrl!(),
            r#") {
    if match(encode_json(.), "#,
            credential_key_precheck_vrl!(),
            r#") {
        for_each(keys(flatten(., "\u{1f}"))) -> |_idx, nano_flat_key| {
            nano_segments = split(nano_flat_key, "\u{1f}")
            nano_hit = -1
            for_each(nano_segments) -> |nano_i, nano_seg| {
                if nano_hit < 0 && includes(nano_cred_names, downcase(nano_seg)) {
                    nano_hit = nano_i
                }
            }
            if nano_hit >= 0 {
                nano_cred_paths = push(nano_cred_paths, slice!(nano_segments, 0, nano_hit + 1))
            }
        }
    }
    for_each(nano_cred_paths) -> |_idx, nano_path| {
        . = object!(remove!(., array!(nano_path)))
    }
"#,
            credential_text_redaction_vrl!(),
            r#"}
"#
        )
    };
}

/// NAN-5352: the text half of the storage boundary. Runs inside the
/// [`credential_text_gate_vrl!`] branch of [`credential_field_redaction_vrl!`],
/// after the key walk, over every value of the event:
///
/// * an object nested anywhere, including inside an array (which the key walk
///   does not descend into), loses its credential-named keys, and so does a
///   dotted attribute name ending in one (`http.request.header.authorization`);
/// * a string that names a credential has the VALUE replaced by `[REDACTED]`
///   in place, so `raw_data` / `message` keep the rest of the original text.
///   Forms: a JSON key (`"Cookie": "..."`, also a flat array/object or a
///   scalar), the same JSON escaped once inside a string (`\"Cookie\":\"...\"`),
///   a header line (`Authorization: Bearer ...` to the end of the line,
///   including folded continuation lines, real or escaped CR/LF), a cookie
///   header (each cookie VALUE, `Cookie: a=[REDACTED]; b=[REDACTED]`) and
///   `key=value` (`x-api-key=...`, quoted or not, with an auth scheme word,
///   ending at whitespace, `;`, `|`, `,` or `&`);
/// * letters written as JSON `\u00XX` escapes (and the Kelvin sign) are
///   decoded first in a string that names a credential that way, so an
///   escaped key is still a key;
/// * A name counts where it starts the text or follows a non-alphanumeric
///   character or an escaped `\n` / `\r` / `\t` (a header line inside a
///   JSON string).
/// * Fail closed: when a credential name followed by `:` / `=` is still left
///   with a value that is not `[REDACTED]` (deeper escaping, a nested object
///   value, a name glued to a preceding letter), the whole string becomes
///   `[REDACTED: credential-bearing text]`.
///
/// The replacements are `replace_with` closures, not `replace(.., "$1...")`:
/// the pipeline file this lands in is environment-interpolated unescaped, and
/// Vector reads `$1` there as a reference to an environment variable named
/// `1` and refuses the whole config. The text has no `$` (a test checks it).
macro_rules! credential_text_redaction_vrl {
    () => {
        concat!(
            r#"    # NAN-5352: credential values inside text, and credential keys inside
    # arrays and dotted attribute names; see credential_text_redaction_vrl! in
    # vector_config/mod.rs.
    . = map_values(., recursive: true) -> |nano_value| {
        if is_object(nano_value) {
            filter(object!(nano_value)) -> |nano_key, _nano_v| {
                nano_lk = downcase(nano_key)
                !includes(nano_cred_names, nano_lk) && !match(nano_lk, r'\.(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)\z')
            }
        } else if is_string(nano_value) && (match(string!(nano_value), "#,
            credential_text_gate_vrl!(),
            r#") || match(string!(nano_value), "#,
            credential_escape_gate_vrl!(),
            r#")) {
            nano_text = string!(nano_value)
            # JSON lets any letter be written as \u00XX; decode those (and the
            # Kelvin sign) so an escaped name is still a name.
            nano_norm = nano_text
            if match(nano_text, r'\\+u(?:00(?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|2[Dd])|212[Aa])') {
                nano_norm = replace(nano_norm, r'\\+u212[Aa]', "K")
                nano_norm = replace_with(nano_norm, r'\\+u00(?P<nano_h>4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|2[Dd])') -> |nano_e| { decode_base16(to_string(nano_e.nano_h)) ?? "" }
            }
            if match(nano_norm, r'(?i)(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)\\*"?\s*[:=]') {
                nano_text = nano_norm
                nano_text = replace_with(nano_text, r'(?i)(?P<nano_k>(?:\A|[^A-Za-z0-9]|\\[nrt])(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|\[(?:[^\[\]{}"]|"(?:[^"\\]|\\.)*")*\]|\{(?:[^\[\]{}"]|"(?:[^"\\]|\\.)*")*\}|-?[0-9][0-9.eE+-]*|true|false|null)') -> |nano_m| { to_string(nano_m.nano_k) + "\"[REDACTED]\"" }
                nano_text = replace_with(nano_text, r'(?i)(?P<nano_k>(?:\A|[^A-Za-z0-9]|\\[nrt])(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)\\"\s*:\s*)(?:\\"(?:[^"\\]|\\\\\\"|\\\\\\\\|\\\\[^"\\])*\\"|-?[0-9][0-9.eE+-]*|true|false|null)') -> |nano_m| { to_string(nano_m.nano_k) + "\\\"[REDACTED]\\\"" }
                nano_text = replace_with(nano_text, r'(?i)(?P<nano_k>(?:\A|[^A-Za-z0-9]|\\[nrt])(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)[ \t]*[:=][ \t]*)(?:"(?:[^"\\]|\\.)*"|\x27[^\x27]*\x27)') -> |nano_m| { to_string(nano_m.nano_k) + "\"[REDACTED]\"" }
                nano_text = replace_with(nano_text, r'(?i)(?P<nano_k>(?:\A|[^A-Za-z0-9]|\\[nrt])(?:set-cookie|cookie)[ \t]*:)(?P<nano_v>(?:[ \t]|(?:\r\n|\r|\n|\\r\\n|\\r|\\n)(?:[ \t]|\\t)+)*[^\s"\\\x27|](?:[^\r\n"\\|]|\\[^rn"\\])*(?:(?:\r\n|\r|\n|\\r\\n|\\r|\\n)(?:[ \t]|\\t)+(?:[^\r\n"\\|]|\\[^rn"\\])*)*)') -> |nano_m| {
                    nano_cv = to_string(nano_m.nano_v)
                    if contains(nano_cv, "=") { to_string(nano_m.nano_k) + replace(nano_cv, r'=[^;\r\n"\\|]*', "=[REDACTED]") } else { to_string(nano_m.nano_k) + " [REDACTED]" }
                }
                nano_text = replace_with(nano_text, r'(?i)(?P<nano_k>(?:\A|[^A-Za-z0-9]|\\[nrt])(?:proxy-authorization|authorization|x-webhook-secret|x-api-key)[ \t]*:)(?:[ \t]|(?:\r\n|\r|\n|\\r\\n|\\r|\\n)(?:[ \t]|\\t)+)*[^\s"\\\x27|](?:[^\r\n"\\|]|\\[^rn"\\])*(?:(?:\r\n|\r|\n|\\r\\n|\\r|\\n)(?:[ \t]|\\t)+(?:[^\r\n"\\|]|\\[^rn"\\])*)*') -> |nano_m| { to_string(nano_m.nano_k) + " [REDACTED]" }
                nano_text = replace_with(nano_text, r'(?i)(?P<nano_k>(?:\A|[^A-Za-z0-9]|\\[nrt])(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)[ \t]*=[ \t]*)(?:(?:bearer|basic|digest|negotiate|ntlm|token)[ \t]+)?[^\s"\\\x27&,;|][^\s"\\&,;|]*') -> |nano_m| { to_string(nano_m.nano_k) + "[REDACTED]" }
                nano_left = replace(nano_text, r'(?i)(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)\\*"?\s*[:=](?:\s*\\*"\[REDACTED\]\\*"|(?:[ \t]|(?:\r\n|\r|\n|\\r\\n|\\r|\\n)(?:[ \t]|\\t)+)*(?:\[REDACTED\]|[^=;\s"\\]+=\[REDACTED\]|[&,;|}\]]|(?:\r\n|\r|\n|\\r\\n|\\r|\\n)(?:[^ \t\\\r\n]|\\[^trn]|\z)|\z))', "")
                if match(nano_left, r'(?i)(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)\\*"?\s*[:=]') {
                    nano_text = "[REDACTED: credential-bearing text]"
                }
            }
            nano_text
        } else {
            nano_value
        }
    }
"#
        )
    };
}

/// NAN-5352: the outer gate of [`credential_field_redaction_vrl!`], matched
/// against `encode_json(.)`. A credential name followed (after an optional,
/// possibly escaped, closing quote and whitespace) by `:` or `=`. It matches
/// every `"<name>":` the key precheck matches, plus the same name written in
/// a string value at any escaping depth (`\"Cookie\":`, `Cookie: ...`,
/// `x-api-key=...`). Keep the alternation equal to `nano_cred_names`.
macro_rules! credential_text_gate_vrl {
    () => {
        r#"r'(?i)(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)\\*"?\s*[:=]'"#
    };
}

/// NAN-5352: any JSON `\u00XX` escape of a letter or `-` (or of the Kelvin
/// sign). No encoder needs one, so it only appears in a deliberately spelled
/// name such as `\u0041uthorization`; a string carrying one is decoded and
/// checked again. A separate match from [`credential_text_gate_vrl!`] so
/// each keeps its literal prefilter: one regex with both alternations made
/// the no-credential path twice as slow.
macro_rules! credential_escape_gate_vrl {
    () => {
        r#"r'\\u(?:00(?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|2[Dd])|212[Aa])'"#
    };
}

/// NAN-5180: a cheap gate in front of the credential path walk
/// ([`credential_field_redaction_vrl!`] and the three copies in
/// `config/vector/00-base.toml`). Matched against `encode_json(<value>)`.
///
/// It never misses a key the walk would remove. `encode_json` writes every
/// object key, at any depth, as `"<key>":` with no whitespace and escapes only
/// `"`, `\` and control characters, none of which a credential name contains.
/// The walk compares `downcase(segment)`, and `(?i)` covers every key that
/// downcases to a name: ASCII case, and U+212A KELVIN SIGN, which downcases to
/// `k` and which Unicode case folding also maps to `k`. Extra matches (a key
/// inside an array, `ſ` folding to `s`, ...) only run the walk, which then
/// decides exactly as before. Keep the alternation equal to
/// `nano_cred_names` (a test checks it).
macro_rules! credential_key_precheck_vrl {
    () => {
        r#"r'(?i)"(?:authorization|proxy-authorization|x-api-key|x-webhook-secret|cookie|set-cookie)":'"#
    };
}

/// NAN-4945: storage-boundary strip of the HTTP request's `Content-Type`.
///
/// `parse_content` (00-base.toml) leaves the header on the event so parsers can
/// pick a decoder from it, and records its value in `%nano_content_type`. At
/// every block that shapes a stored row the root field is dropped when it still
/// holds that header value. A body field of the same name with its own value
/// is sender data and stays.
macro_rules! ingest_transport_strip_vrl {
    () => {
        r#"# NAN-4945: the request Content-Type is transport metadata; see
# ingest_transport_strip_vrl! in vector_config/mod.rs.
nano_transport_ct = to_string(%nano_content_type) ?? ""
if nano_transport_ct != "" {
    if (to_string(."Content-Type") ?? "") == nano_transport_ct { del(."Content-Type") }
    if (to_string(."content-type") ?? "") == nano_transport_ct { del(."content-type") }
}
"#
    };
}

/// NAN-5839: storage-boundary strip of the injected source timezone.
///
/// The `<name>_source_tz` step sets `.nano.source_timezone` for the parser and
/// records the same value in `%nano_source_timezone`. A parsers#87 parser
/// reads and removes it first; a custom parser that keeps the root and never
/// reads it would otherwise store it as an OCSF root `nano` object. At every
/// block that shapes a stored row the field is dropped when it still holds the
/// injected value (and `.nano` with it when nothing else is left). A body field
/// of the same name with its own value is sender data and stays.
macro_rules! source_timezone_strip_vrl {
    () => {
        r#"# NAN-5839: the injected source timezone is ingest metadata; see
# source_timezone_strip_vrl! in vector_config/mod.rs.
nano_injected_tz = to_string(%nano_source_timezone) ?? ""
if nano_injected_tz != "" && is_object(.nano) {
    if (to_string(.nano.source_timezone) ?? "") == nano_injected_tz { del(.nano.source_timezone) }
    if is_empty(object!(.nano)) { del(.nano) }
}
"#
    };
}

/// NAN-5846: nano's ingest provenance on a stored OCSF event, under its own
/// namespace `unmapped.nano.ingest`.
///
/// - `client_ip`: the trusted client address (the TCP peer, or the trusted
///   proxy's `X-Real-IP`, or the role-split edge's assertion), from the
///   protected metadata `%nano_ingest_client_ip`.
/// - `peer`: the TCP peer (`%nano_ingest_peer`), written ONLY when it differs
///   from `client_ip` (a trusted proxy or edge resolved the client), since it
///   carries no information otherwise.
///
/// nano owns the `unmapped.nano` namespace. ClickHouse's `JSON` column reads
/// a `.` inside a key as a path separator, so a vendor key can spell nano's
/// path as the nested object (`{"nano": {"ingest": {...}}}`), a flat dotted
/// key (`"nano.ingest.client_ip"`, which every shipped OCSF parser's residual
/// spill emits for a nested source key), a mix of the two, or, for a custom
/// parser that keeps the event root, a dotted key at the event root
/// (`"unmapped.nano.ingest.client_ip"`). Left in place, such a key would
/// either forge provenance or meet nano's nested write as a second spelling
/// of one path, which ClickHouse refuses with Code 117 (duplicate path): a
/// non-retryable error that drops the whole sink batch.
///
/// Vendor data is never dropped or masked, so those keys are MOVED, whole and
/// unmodified, into ONE JSON string: every top-level `unmapped` key that is
/// `nano` or starts with `nano.`, and every event-root key `unmapped.nano` /
/// `unmapped.nano.*` (plus a sender's flat root `nano.source_timezone`, which
/// `source_timezone_vrl` stashes in `%nano_reserved_spill` as
/// `root:nano.source_timezone`), become one object, encoded once with
/// `encode_json` and stored as `unmapped.source_nano_json`. Its keys are the
/// original names and are distinct by construction (`unmapped` keys start
/// with `nano`, root keys with `unmapped.nano`, stashed ones with `root:`),
/// so no value overwrites another. A single string leaf is
/// lossless (duplicates, empty objects and every value survive in the text),
/// cannot collide with any path, and costs O(size). If that name is already
/// used (`unmapped.source_nano_json`, or the root key
/// `unmapped.source_nano_json` of a root-keeping parser), `_2` ... `_10` are
/// tried, then a UUID suffix.
///
/// Events without such a key are not touched. Every other key stays as it is
/// (the `nano_*` parser markers and `source_nano*` included): a vendor field
/// that spills as `unmapped.client_ip` (microsoft_365 `ClientIP`,
/// json_generic) is stored unchanged. Before NAN-5846 this step deleted
/// `unmapped.client_ip` and wrote the ingest IP there (plus
/// `ingest_client_ip` / `ingest_peer`). A non-object `unmapped` (malformed
/// OCSF) is kept as `unmapped.value` when provenance is written.
///
/// Cost: every VRL read of a path deep-clones its value, so the common path
/// reads no event field. It gates on one regex over `nano_cred_text`, the
/// event's JSON text that [`credential_field_redaction_vrl!`] already built
/// earlier in the same program (every block that splices this macro splices
/// that one first; an undefined variable would fail the VRL compile test).
/// The regex anchors on a KEY (`"nano":`, `"nano.<rest>":`, with an optional
/// `unmapped.` prefix); in compact JSON a string value is never followed by
/// `:`, so a value such as `"vendor_name":"nano"` does not match. The text
/// holds every key, so the gate cannot miss one. A normal event then does at
/// most one write (`unmapped.nano.ingest`). The moved path is strictly
/// linear: a fixed number of `filter` / `map_*` / `merge` passes (no `set!`
/// in a loop, no nested loops), one `encode_json`, and at most 10 lookups in
/// a map of at most 10 taken names. The event root is scanned only when the
/// text holds an `"unmapped.nano` / `"unmapped.source_nano_json` key.
macro_rules! ingest_provenance_vrl {
    () => {
        r#"# NAN-5846: nano owns unmapped.nano; vendor keys spelling it are moved,
# whole, into one JSON string (unmapped.source_nano_json), never dropped. See
# ingest_provenance_vrl! in vector_config/mod.rs.
nano_ingest_client = to_string(%nano_ingest_client_ip) ?? ""
nano_ingest_peer = to_string(%nano_ingest_peer) ?? ""
nano_ingest = {}
if nano_ingest_client != "" { nano_ingest.client_ip = nano_ingest_client }
if nano_ingest_peer != "" && nano_ingest_peer != nano_ingest_client { nano_ingest.peer = nano_ingest_peer }
# A root control key the timezone step moved aside (`root:nano.<field>`).
nano_stash = object(%nano_reserved_spill) ?? {}
if match(nano_cred_text, r'"(?:unmapped\.)?nano(?:\.(?:[^"\\]|\\.)*)?":') || !is_empty(nano_stash) {
    # Every step below is one linear pass. The collected object's keys are
    # distinct by construction: `unmapped` keys start with `nano`, root keys
    # with `unmapped.nano`, stashed ones with `root:`, so nothing overwrites.
    nano_names = ["source_nano_json", "source_nano_json_2", "source_nano_json_3", "source_nano_json_4", "source_nano_json_5", "source_nano_json_6", "source_nano_json_7", "source_nano_json_8", "source_nano_json_9", "source_nano_json_10"]
    nano_root_names = ["unmapped.source_nano_json", "unmapped.source_nano_json_2", "unmapped.source_nano_json_3", "unmapped.source_nano_json_4", "unmapped.source_nano_json_5", "unmapped.source_nano_json_6", "unmapped.source_nano_json_7", "unmapped.source_nano_json_8", "unmapped.source_nano_json_9", "unmapped.source_nano_json_10"]
    nano_unmapped = ocsf_event.unmapped
    nano_is_object = is_object(nano_unmapped)
    nano_spill = nano_stash
    nano_taken = {}
    if nano_is_object {
        nano_hits = filter(object!(nano_unmapped)) -> |nano_key, _nano_value| {
            nano_key == "nano" || starts_with(nano_key, "nano.") || includes(nano_names, nano_key)
        }
        if !is_empty(nano_hits) {
            nano_taken = map_values(filter(nano_hits) -> |nano_key, _nano_value| { includes(nano_names, nano_key) }) -> |_nano_value| { true }
            nano_spill = merge(nano_spill, filter(nano_hits) -> |nano_key, _nano_value| { !includes(nano_names, nano_key) })
        }
    }
    # The event root (a root-keeping parser), only when its text has such a key.
    if contains(nano_cred_text, "\"unmapped.nano") || contains(nano_cred_text, "\"unmapped.source_nano_json") {
        nano_root_hits = filter(ocsf_event) -> |nano_key, _nano_value| {
            nano_key == "unmapped.nano" || starts_with(nano_key, "unmapped.nano.") || includes(nano_root_names, nano_key)
        }
        if !is_empty(nano_root_hits) {
            nano_root_taken = map_values(filter(nano_root_hits) -> |nano_key, _nano_value| { includes(nano_root_names, nano_key) }) -> |_nano_value| { true }
            nano_taken = merge(nano_taken, map_keys(nano_root_taken) -> |nano_key| { slice!(nano_key, 9) })
            nano_root_spill = filter(nano_root_hits) -> |nano_key, _nano_value| { !includes(nano_root_names, nano_key) }
            if !is_empty(nano_root_spill) {
                ocsf_event = filter(ocsf_event) -> |nano_key, _nano_value| {
                    nano_key != "unmapped.nano" && !starts_with(nano_key, "unmapped.nano.")
                }
                nano_spill = merge(nano_spill, nano_root_spill)
            }
        }
    }
    if !is_empty(nano_spill) {
        nano_rest = {}
        if nano_is_object {
            nano_rest = filter(object!(nano_unmapped)) -> |nano_key, _nano_value| {
                nano_key != "nano" && !starts_with(nano_key, "nano.")
            }
        } else if nano_unmapped != null {
            # A non-object `unmapped` (malformed OCSF) is kept as `value`.
            nano_rest = { "value": nano_unmapped }
        }
        nano_target = ""
        for_each(nano_names) -> |_nano_i, nano_name| {
            if nano_target == "" && (get(nano_taken, [nano_name]) ?? null) == null { nano_target = nano_name }
        }
        if nano_target == "" { nano_target = "source_nano_json_" + uuid_v4() }
        ocsf_event.unmapped = set!(nano_rest, [nano_target], encode_json(nano_spill))
    }
}
if !is_empty(nano_ingest) {
    # A non-object `unmapped` (malformed OCSF) is kept, never overwritten.
    if match(nano_cred_text, r'"unmapped":[^{n]') {
        nano_unmapped = ocsf_event.unmapped
        if nano_unmapped != null && !is_object(nano_unmapped) { ocsf_event.unmapped = { "value": nano_unmapped } }
    }
    ocsf_event.unmapped.nano = { "ingest": nano_ingest }
}
"#
    };
}

/// The provenance step as text, for tests that time or run it alone.
#[cfg(test)]
pub(crate) const INGEST_PROVENANCE_VRL: &str = ingest_provenance_vrl!();

/// NAN-5431: the deepest container level kept in a stored object (the OCSF
/// `event`, the UDM `ext`). A container nested deeper is stored as its JSON
/// text instead.
///
/// Vector encodes every event as protobuf on its way into a disk buffer, and
/// that encoding refuses an event nested past a fixed cost (about 32 object
/// levels in the stored row, measured on nano-rs/vector 0.61.0-nano.12). Such
/// an event was accepted at ingest and then discarded at the ClickHouse sink's
/// buffer. 24 keeps a margin under that limit (the row adds a level or two
/// around the object) and far above real vendor payloads. Keep in step with
/// the level count in [`nesting_depth_limit_vrl!`] (a test checks it).
pub(crate) const MAX_STORED_NESTING_DEPTH: usize = 24;

/// One level of the [`nesting_depth_limit_vrl!`] walk: replace the frontier
/// (paths of the containers at this level) with the paths of their container
/// children. Sequential, not nested: VRL type-checks nested closures in time
/// exponential in the nesting (a 14-deep nested walk took ~30 s to compile).
macro_rules! nesting_depth_level_vrl {
    ($var:literal) => {
        concat!(
            "    nano_depth_next = []\n",
            "    for_each(nano_depth_frontier) -> |_nano_depth_i, nano_depth_path| {\n",
            "        nano_depth_value = get(", $var, ", nano_depth_path) ?? null\n",
            "        if is_object(nano_depth_value) {\n",
            "            for_each(object!(nano_depth_value)) -> |nano_depth_key, nano_depth_child| {\n",
            "                if is_object(nano_depth_child) || is_array(nano_depth_child) { nano_depth_next = push(nano_depth_next, push(nano_depth_path, nano_depth_key)) }\n",
            "            }\n",
            "        } else if is_array(nano_depth_value) {\n",
            "            for_each(array!(nano_depth_value)) -> |nano_depth_index, nano_depth_child| {\n",
            "                if is_object(nano_depth_child) || is_array(nano_depth_child) { nano_depth_next = push(nano_depth_next, push(nano_depth_path, nano_depth_index)) }\n",
            "            }\n",
            "        }\n",
            "    }\n",
            "    nano_depth_frontier = nano_depth_next\n",
        )
    };
}

/// NAN-5431: store any container nested deeper than
/// [`MAX_STORED_NESTING_DEPTH`] levels inside the object variable `$var` as
/// its JSON text, so the event fits Vector's disk-buffer encoding instead of
/// being discarded after ingest acknowledged it. Nothing is lost: the subtree
/// is kept verbatim as a string, the event is marked with `true` at
/// `$marker_path` (a VRL path array literal, e.g. `["nano_nesting_truncated"]`)
/// so affected events are searchable, and a rate-limited warning is logged.
///
/// Gate: a value can only be nested N levels deep when its JSON text has at
/// least N opening brackets, so events with fewer skip the walk after one
/// linear scan. The gate counts brackets, not depth: a wide event (many
/// small objects) also passes it and pays for the walk, which visits each
/// container once and stops early once a level has no containers left. The
/// walk is breadth first over container paths; the level block is repeated
/// [`MAX_STORED_NESTING_DEPTH`] times.
macro_rules! nesting_depth_limit_vrl {
    ($var:literal, $marker_path:literal) => {
        concat!(
            "# NAN-5431: containers nested deeper than 24 levels are stored as JSON text;\n",
            "# see nesting_depth_limit_vrl! in vector_config/mod.rs.\n",
            "nano_depth_json = encode_json(", $var, ")\n",
            "if match(nano_depth_json, r'^(?:[^\\[{]*[\\[{]){25}') {\n",
            "    nano_depth_frontier = [[]]\n",
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            nesting_depth_level_vrl!($var), nesting_depth_level_vrl!($var),
            "    if length(nano_depth_frontier) > 0 {\n",
            "        for_each(nano_depth_frontier) -> |_nano_depth_i, nano_depth_path| {\n",
            "            nano_depth_sub = get(", $var, ", nano_depth_path) ?? null\n",
            "            ", $var, " = set(", $var, ", nano_depth_path, encode_json(nano_depth_sub)) ?? ", $var, "\n",
            "        }\n",
            "        ", $var, " = set(", $var, ", ", $marker_path, ", true) ?? ", $var, "\n",
            "        log(\"Stored an event's deeply nested values as JSON text (nesting limit 24)\", level: \"warn\", rate_limit_secs: 60)\n",
            "    }\n",
            "}\n",
        )
    };
}

#[cfg(test)]
pub(crate) const NESTING_DEPTH_LIMIT_TEST_VRL: &str = nesting_depth_limit_vrl!("nano_test_value", r#"["nano_nesting_truncated"]"#);

/// NAN-5032: platform-owned `source_type` values are rewritten at the UDM
/// storage boundary, whatever lane an event arrived on.
///
/// Keep the literal lists identical to
/// `nanosiem_core::auth::reserved_source_types` (`ENFORCED`, `WARN_ONLY`,
/// `WARN_ONLY_PREFIXES`, `PLATFORM_LANES`, `SPOOF_MARKER`); a unit test checks
/// them. Spliced into `clickhouse_mapping`, which both the generic lane
/// (`prepare_output`) and every deployed parser (`db_parsers_combined`) feed,
/// so no lane — HTTP, HEC, OTLP, upstream Vector, or a parser's own VRL — can
/// store `audit` / `findings`. The declared value is kept as
/// `claimed_source_type` (stored in `ext`) so a forgery stays visible.
/// ClickHouse's `logs_ingest_mv` applies the same rewrite as a backstop.
macro_rules! reserved_source_type_guard_vrl {
    () => {
        r#"# NAN-5032: reserved source types; see reserved_source_type_guard_vrl! in
# vector_config/mod.rs and nanosiem_core::auth::reserved_source_types.
nano_reserved_st = downcase(to_string(.source_type) ?? "")
if includes(["audit", "findings"], nano_reserved_st) {
    if (to_string(.claimed_source_type) ?? "") == "" { .claimed_source_type = .source_type }
    .source_type = "reserved_spoof"
    log("Rewrote a reserved source_type declared at ingest to reserved_spoof", level: "warn", rate_limit_secs: 60)
} else if !starts_with(nano_reserved_st, "nano_enrich") && !starts_with(nano_reserved_st, "nano_operational") && (includes(["signal", "signals"], nano_reserved_st) || starts_with(nano_reserved_st, "nano_") || starts_with(nano_reserved_st, "__nano:")) {
    log("Ingested event declares a reserved source_type (accepted in this release; rejected in a future one)", level: "warn", rate_limit_secs: 300)
}
"#
    };
}

#[cfg(test)]
pub(crate) const RESERVED_SOURCE_TYPE_GUARD_VRL: &str = reserved_source_type_guard_vrl!();

/// NAN-5032 (review): the OCSF generic lane stamps the row's `source_type`
/// from `src_type` and never passes `clickhouse_mapping`, so it carries its own
/// copy of the rewrite. The record (including the declared value) stays under
/// `unmapped`. `ocsf_logs_raw_mv` (ocsf/193) applies the same rule as the
/// database backstop.
macro_rules! reserved_ocsf_source_type_guard_vrl {
    () => {
        r#"# NAN-5032: reserved source types on the OCSF generic lane; see
# reserved_ocsf_source_type_guard_vrl! in vector_config/mod.rs.
if includes(["audit", "findings"], src_type) {
    log("Rewrote a reserved source_type declared at OCSF ingest to reserved_spoof", level: "warn", rate_limit_secs: 60)
    src_type = "reserved_spoof"
}
"#
    };
}

#[cfg(test)]
pub(crate) const RESERVED_OCSF_SOURCE_TYPE_GUARD_VRL: &str = reserved_ocsf_source_type_guard_vrl!();

#[cfg(test)]
pub(crate) const INGEST_TRANSPORT_STRIP_VRL: &str = ingest_transport_strip_vrl!();

/// The credential-field redaction program (NAN-4038); the live tap's own
/// recursive redactor is checked against its name list (NAN-4919).
#[cfg(test)]
pub(crate) const CREDENTIAL_FIELD_REDACTION_VRL: &str = credential_field_redaction_vrl!();

/// NAN-5180: the gate regex literal (VRL raw string), for the sync tests.
#[cfg(test)]
pub(crate) const CREDENTIAL_KEY_PRECHECK_VRL: &str = credential_key_precheck_vrl!();

/// NAN-5352: the outer text gate literal (VRL raw string), for the tests.
#[cfg(test)]
pub(crate) const CREDENTIAL_TEXT_GATE_VRL: &str = credential_text_gate_vrl!();

/// NAN-5352: the escaped-letter gate literal (VRL raw string), for the tests.
#[cfg(test)]
pub(crate) const CREDENTIAL_ESCAPE_GATE_VRL: &str = credential_escape_gate_vrl!();

/// NAN-5352: the text pass spliced into the redaction macro, for the tests.
#[cfg(test)]
pub(crate) const CREDENTIAL_TEXT_REDACTION_VRL: &str = credential_text_redaction_vrl!();

mod backup;
pub(crate) mod config_lock;
#[cfg(test)]
#[path = "claim_metadata_tests.rs"]
mod claim_metadata_tests;
#[cfg(test)]
#[path = "nesting_depth_limit_tests.rs"]
mod nesting_depth_limit_tests;
#[cfg(test)]
#[path = "credential_precheck_tests.rs"]
mod credential_precheck_tests;
#[cfg(test)]
#[path = "raw_text_redaction_tests.rs"]
mod raw_text_redaction_tests;
#[cfg(test)]
#[path = "hec_payload_tests.rs"]
mod hec_payload_tests;
#[cfg(test)]
#[path = "hec_route_tests.rs"]
mod hec_route_tests;
#[cfg(test)]
#[path = "stage_profile_tests.rs"]
mod stage_profile_tests;
#[cfg(test)]
#[path = "reserved_source_type_guard_tests.rs"]
mod reserved_source_type_guard_tests;
#[cfg(test)]
#[path = "ocsf_lane_stamp_tests.rs"]
mod ocsf_lane_stamp_tests;
#[cfg(test)]
#[path = "source_timezone_tests.rs"]
mod source_timezone_tests;
#[cfg(test)]
#[path = "ocsf_parser_health_tests.rs"]
mod ocsf_parser_health_tests;
#[cfg(test)]
#[path = "ocsf_parse_failure_tests.rs"]
mod ocsf_parse_failure_tests;
#[cfg(test)]
#[path = "token_bound_route_tests.rs"]
mod token_bound_route_tests;
#[cfg(test)]
#[path = "two_phase_activation_tests.rs"]
mod two_phase_activation_tests;
#[cfg(test)]
#[path = "pipeline_gate_tests.rs"]
mod pipeline_gate_tests;
#[cfg(test)]
#[path = "reload_acked_loss_fixtures.rs"]
mod reload_acked_loss_fixtures;
#[cfg(test)]
#[path = "work_dir_tests.rs"]
mod work_dir_tests;
#[cfg(test)]
#[path = "json_path_collision_tests.rs"]
mod json_path_collision_tests;
// NAN-5849: `json_path_collision_vrl!`, used by `deploy` and `parser_config`.
#[macro_use]
mod json_path_collision;
mod credentials;
pub mod delivery;
mod deploy;
mod fanin_slots;
mod hec_payload;
pub mod hec_route;
mod parser_config;
mod pipeline_gate;
mod publication;
pub mod redaction;
pub mod remote_delivery;
mod router;
mod sources;
mod staging;
pub(crate) mod tree_write;
mod validation;

pub use publication::{
    publication_root, PublicationOutcome, SnapshotBundle, VectorConfigPublicationError, VectorConfigPublisher,
    PUBLICATION_DIR_ENV,
};
pub use redaction::redact_config_snapshot;
pub use backup::BackupGeneration;
pub use deploy::{
    current_reload_wait, ActivationOutcome, DeployReloadFailure, ReloadWaitStatus, ReloadWatch, VerifyFailure,
    DEFAULT_RELOAD_ACK_MAX_SECS,
};

/// NAN-4936: hooks for tests elsewhere in the crate (the entrypoint tests).
#[cfg(test)]
pub(crate) mod test_hooks {
    pub(crate) use super::deploy::request_reload_in;
}
pub use router::{base_router_inputs, hec_normalize_present};

/// NAN-5132 (two-phase activation): stable fan-in slots are on, so the parked
/// filter a held source reads exists.
pub fn fanin_slots_enabled() -> bool {
    fanin_slots::enabled()
}

/// NAN-5132: Vector pulls generations with no acknowledgement to wait for
/// (Kubernetes), so a staged phase cannot be verified.
pub fn local_reload_disabled() -> bool {
    deploy::local_reload_disabled()
}

/// NAN-5132: a parser of this source type reads `source_router` (HTTP, Vector
/// native, unknown labels), not the HEC, OTLP or a pull lane.
pub fn is_router_fed(source_type: &str) -> bool {
    matches!(router::transport_of(source_type), router::Transport::Routed)
}

impl VectorConfigManager {
    /// NAN-5132: this process grades reloads by ingest-host acknowledgement
    /// (role split) and publishes from the database, not from its own tree.
    pub fn generation_delivery_active() -> bool {
        remote_delivery::active_publisher().is_some()
    }
}

use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

use super::types::Parser;

#[derive(Error, Debug)]
pub enum VectorConfigError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to reload Vector: {0}")]
    ReloadFailed(String),
    /// Role split (NAN-5133): published, but no ingest host confirmed it.
    #[error("Not confirmed live: {0}")]
    ReloadUnconfirmed(String),
    #[error("Invalid config directory: {0}")]
    InvalidConfigDir(String),
    #[error("No backup available for restore")]
    NoBackupAvailable,
    #[error("Vector validation failed: {0}")]
    ValidationFailed(String),
    #[error("Staging directory error: {0}")]
    StagingError(String),
}

/// NAN-5678: directory for the staging and backup workspaces when they must
/// live outside the Vector config dir ([`VectorConfigManager::with_work_dir`]).
pub const WORK_DIR_ENV: &str = "VECTOR_CONFIG_WORK_DIR";

/// Manages Vector configuration files generated from database parsers
pub struct VectorConfigManager {
    /// Base config directory (e.g., config/vector)
    config_dir: PathBuf,
    /// Directory where parser configs are written
    parsers_dir: PathBuf,
    /// Sources directory (parent of parsers_dir). Retained for cleanup of
    /// credential files written by the removed parser-owned transport path.
    sources_dir: PathBuf,
    /// Staging directory for validation before deployment
    staging_dir: PathBuf,
    /// Backup directory for rollback support
    backup_dir: PathBuf,
    /// Directory for credential files (GCP service account JSON, etc.)
    credentials_dir: PathBuf,
    /// Serializes all deploy operations to prevent concurrent deploys from
    /// corrupting config or overwriting each other's backups.
    ///
    /// NAN-948: wrapped in `Arc` so the same lock can be shared with
    /// `SourceConfigService::update_dynamic_router`, which read-mutate-writes
    /// the same `_router.toml` outside this manager. Without the shared
    /// lock, a parser deploy and a source-config router update can
    /// interleave and lose one of the two updates.
    deploy_lock: Arc<tokio::sync::Mutex<()>>,
}

impl VectorConfigManager {
    /// Create a new config manager
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        let config_dir = config_dir.as_ref().to_path_buf();
        // Parser configs go directly in config_dir with 30- prefix for proper load order
        // (after router at 20-, before generic parser at 50-)
        let sources_dir = config_dir.join("sources");
        let parsers_dir = sources_dir.join("parsers");
        let staging_dir = config_dir.join("staging");
        let backup_dir = config_dir.join("backup");
        let credentials_dir = config_dir.join("credentials");
        Self {
            config_dir,
            parsers_dir,
            sources_dir,
            staging_dir,
            backup_dir,
            credentials_dir,
            deploy_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// NAN-5678: put the staging and backup workspaces under `work_dir`
    /// instead of the config dir. Blank or `None` keeps the defaults.
    ///
    /// On a single node the config dir IS the volume the local Vector runs
    /// `--watch-config` on, and the watcher is recursive: every staged tree
    /// and every backup snapshot written there made Vector load and compile
    /// the whole config again. With ~40 OCSF parsers one load is a minute or
    /// more of single-threaded VRL compilation, so a deploy cost three loads
    /// (the staging/backup writes, the reload signal, and the post-deploy
    /// backup refresh) instead of the one it needs. Only `vector validate`
    /// reads the staged tree from inside the Vector container
    /// (`VECTOR_STAGING_PATH`), so a deployment that moves it out sets
    /// `SKIP_VECTOR_VALIDATION=true` (single-node Compose does) or points
    /// `VECTOR_STAGING_PATH` at the same directory as Vector sees it.
    pub fn with_work_dir(mut self, work_dir: Option<&str>) -> Self {
        if let Some(dir) = work_dir.map(str::trim).filter(|dir| !dir.is_empty()) {
            let dir = PathBuf::from(dir);
            self.staging_dir = dir.join("staging");
            self.backup_dir = dir.join("backup");
        }
        self
    }

    /// Create with default config directory
    pub fn with_defaults() -> Self {
        Self::new("config/vector")
    }

    /// Hand out a clone of the deploy lock so other services can serialize
    /// their `_router.toml` mutations against this manager's deploys.
    /// NAN-948 — without this shared lock, `SourceConfigService` and the
    /// parser deploy path can race on the read-mutate-write of `_router.toml`.
    pub fn deploy_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.deploy_lock)
    }

    /// Get the base config directory
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Convert parser name to a safe identifier for Vector.
    ///
    /// Delegates to [`crate::vector_naming::safe_name`] — see there for why the
    /// transformation is centralised rather than copied per subsystem
    /// (NAN-2196).
    pub(crate) fn safe_name(name: &str) -> String {
        crate::vector_naming::safe_name(name)
    }

    /// Path on disk for a parser-side credential or cert file. Lives directly
    /// under `sources_dir` with a `parsers__` prefix so it survives K8s
    /// ConfigMap key flattening — same path resolves under Docker bind-mounts,
    /// S3-synced K8s, and ConfigMap-synced K8s.
    pub(super) fn parser_creds_path(&self, filename: &str) -> PathBuf {
        self.sources_dir.join(format!("parsers__{}", filename))
    }

    /// Build a VRL route condition for a parser.
    /// Uses match_values when available (the actual source_type values the parser handles),
    /// falling back to safe_name for backward compatibility.
    ///
    /// NAN-4953 audit: `match_values` are tenant input. Each one is escaped as a
    /// VRL string literal here, and callers emit the condition as a TOML basic
    /// string ([`Self::source_router_route_lines`]), so a `"` or `'` in a value
    /// can neither end the VRL literal nor the TOML one.
    fn build_route_condition(parser: &Parser) -> String {
        let values = Self::parser_source_types(parser);
        if values.len() == 1 {
            format!(
                ".source_type == \"{}\"",
                sources::escape_vrl_string(&values[0])
            )
        } else {
            let list = values
                .iter()
                .map(|v| format!("\"{}\"", sources::escape_vrl_string(v)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("includes([{}], .source_type)", list)
        }
    }

    /// NAN-4952: the `[transforms.source_router.route]` entries for the given
    /// routed parsers plus the `generic` catch-all, shared by the active and the
    /// staged router writers so the two files cannot drift. `routed` must come
    /// from [`Self::source_router_parsers`].
    ///
    /// NAN-5071: `log_parsers` is the full deploy set. Every enabled Splunk
    /// HEC parser also gets a `<name>-token_bound` route (its filter always
    /// reads it, [`Self::token_bound_route`]): an event whose source a bound
    /// ingest token decided, presented on a non-HEC lane (HTTP `/ingest`), goes
    /// to that source's parser instead of being stored raw by `generic`.
    pub(super) fn source_router_route_lines(routed: &[&Parser], log_parsers: &[Parser]) -> String {
        let mut lines = String::new();
        for parser in routed {
            lines.push_str(&format!(
                "{} = {}\n",
                Self::safe_name(&parser.name),
                parser_config::toml_basic_string(&Self::build_route_condition(parser))
            ));
        }
        let mut known: Vec<String> = Vec::new();
        for value in routed.iter().flat_map(|p| Self::parser_source_types(p)) {
            if !known.contains(&value) {
                known.push(value);
            }
        }
        let mut token_bound: Vec<String> = Vec::new();
        for parser in Self::token_bound_lane_parsers(log_parsers) {
            // A key a routed parser claims already reaches that parser on
            // this lane; claiming it twice would double-write the event.
            let keys: Vec<String> = Self::parser_source_types(parser)
                .into_iter()
                .filter(|k| !known.contains(k))
                .collect();
            let condition = if keys.is_empty() {
                "false".to_string()
            } else {
                for k in &keys {
                    if !token_bound.contains(k) {
                        token_bound.push(k.clone());
                    }
                }
                Self::token_bound_condition(&keys)
            };
            lines.push_str(&format!(
                "{} = {}\n",
                Self::token_bound_route(&parser.name),
                parser_config::toml_basic_string(&condition)
            ));
        }
        let exclusion_list = Self::vrl_string_list(&known);
        // NAN-1124: also exclude `nano_enrich` so push-enrichment records never
        // fall through to the generic log parser (they're claimed by
        // enrichment_router). Matches the downcased source_type so a mixed-case
        // body value can't leak into the logs pipeline.
        let mut generic = format!(
            "!includes([{exclusion_list}], .source_type) && !starts_with(downcase(to_string(.source_type) ?? \"\"), \"nano_enrich\")"
        );
        // NAN-5071: an event a `-token_bound` route claims is not ALSO raw.
        if !token_bound.is_empty() {
            generic.push_str(&format!(" && !({})", Self::token_bound_condition(&token_bound)));
        }
        lines.push_str(&format!(
            "generic = {}\n\n",
            parser_config::toml_basic_string(&generic)
        ));
        lines
    }

    /// NAN-5071: the `source_router` route a Splunk HEC parser's filter reads
    /// besides `splunk_hec_route`. The `-` can never appear in a
    /// [`crate::vector_naming::safe_name`] (alphanumerics and `_` only), so
    /// this can never equal a routed parser's route key (its safe name):
    /// a duplicate key would make `_router.toml` unparseable and fail every
    /// reload. Vector accepts `-` in a route output name.
    pub(super) fn token_bound_route(parser_name: &str) -> String {
        format!("{}-token_bound", Self::safe_name(parser_name))
    }

    /// NAN-5071: the parsers that get a `-token_bound` route: exactly the
    /// enabled log parsers whose rendered file is a Splunk HEC filter.
    pub(super) fn token_bound_lane_parsers(log_parsers: &[Parser]) -> Vec<&Parser> {
        log_parsers
            .iter()
            .filter(|p| p.enabled && p.kind != "enrichment")
            .filter(|p| matches!(router::transport_of(&p.source_type), router::Transport::SplunkHec))
            .collect()
    }

    /// NAN-5071: the event's source was decided by a source-bound ingest
    /// token (the lane set `.source_type` to the credential's route key) and
    /// is one of `keys`. A multiplex credential (`*`: the platform credential
    /// and the legacy-multiplex install token) and an unauthenticated event
    /// never match, so their declared-type routing is unchanged.
    fn token_bound_condition(keys: &[String]) -> String {
        format!(
            "includes([{}], .source_type) && (to_string(%nano_credential_name) ?? \"\") == .source_type",
            Self::vrl_string_list(keys)
        )
    }

    fn vrl_string_list(values: &[String]) -> String {
        values
            .iter()
            .map(|s| format!("\"{}\"", sources::escape_vrl_string(s)))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Get the source_type values a parser handles.
    /// Returns match_values if set, otherwise falls back to [safe_name].
    pub(super) fn parser_source_types(parser: &Parser) -> Vec<String> {
        crate::vector_naming::claim_keys(parser.match_values.as_deref(), &parser.name)
    }

    /// Check if a parser handles a given source_type value.
    fn parser_handles_source_type(parser: &Parser, source_type: &str) -> bool {
        Self::parser_source_types(parser)
            .iter()
            .any(|v| v == source_type)
    }
}

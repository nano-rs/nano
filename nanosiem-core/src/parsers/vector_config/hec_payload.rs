// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a parser receives for an HEC event, and the parser input contract.
//!
//! # The received record stays whole (NAN-5891)
//!
//! The `splunk_hec_ingest` source decodes each envelope's `event` with the
//! `bytes` codec, so `.message` is the `event` exactly as sent (a string
//! event's text, an object event's JSON in the sender's key order) and Vector
//! writes the envelope (`time`, `host`, `source`, `sourcetype`, `index`,
//! `channel`, indexed `fields`) BESIDE it, never into the record. A record's
//! own `timestamp`, `host`, `event`, `metadata`, `line`, null values and
//! object `message` survive. `/services/collector/raw` has no codec.
//!
//! An HEC STRING event, a `/raw` body, and any event the source does not mark
//! take exactly the pre-NAN-5891 path in `hec_normalize`: `.message` is the
//! text, whatever it holds. With the `bytes` codec an unmarked object event's
//! text is its whole record, so a record-reading parser gets every field and a
//! text parser gets the record's JSON.
//!
//! When the source marks an OBJECT event (`%splunk_hec.event_kind =
//! "object"`, nano-rs/vector NAN-5891), `hec_normalize` also keeps the
//! envelope in `%nano_hec`, never deletes or rewrites a record key, and
//! prepares the text-parser view:
//!
//! - the record has a string `message` (or, with no `message` at all, a string
//!   `line`, the Docker logging driver's key): `.message` = that line, and the
//!   record's other keys (plus indexed fields) wait in `%nano_hec_event` for
//!   `_ocsf_prepare` / `_output` to file under `unmapped` / `ext`;
//! - otherwise: `.message` = the whole record.
//!
//! The whole record waits in `%nano_hec_record`. `{"message": {...}}` with no
//! other key is a wrapper: the inner object is the record (as before). Every
//! `%nano_hec*` key is deleted at the storage step, so none reaches the disk
//! buffer in front of ClickHouse.
//!
//! # The input contract (NAN-5883)
//!
//! A parser declares what it reads with comment lines in its VRL:
//!
//! - `# nano:input=json` / `# nano:input=text` (v1): read by every nano
//!   version, exactly as before;
//! - `# nano:input-v2=json|text|json_or_text` (v2): read from v2.0.36, where
//!   it wins over v1. Older versions ignore it. Content repositories serve
//!   every install, so a parser keeps a v1 line that gives older nano the
//!   behaviour it has today and states its v2.0.36 contract in v2.
//!
//! Per contract, `.message` is (v2.0.36+):
//!
//! | contract       | HTTP `/ingest`  | HEC string event / `/raw` | HEC object event                           | OTLP log |
//! |----------------|-----------------|---------------------------|--------------------------------------------|----------|
//! | `json`         | the request body| the text (1)              | the whole record                           | the body |
//! | `json_or_text` | the request body| the text (1)              | the whole record                           | the body |
//! | `text`         | the request body| the text                  | the record's line, else the whole record (2) | the body |
//!
//! (1) As before NAN-5891: when the text is not a JSON object and the event
//! carried indexed `fields`, a record-reading parser gets one JSON object of
//! the fields and `message` = the text.
//! (2) The line needs a source that marks object events; otherwise a `text`
//! parser gets the whole record, as for a string event carrying that JSON.
//!
//! `json` and `json_or_text` get the same payload (a generated
//! `<parser>_hec_payload` remap restores the whole record); `json_or_text`
//! parsers also take plain text lines, and must tell a record of their source
//! from a forwarder's wrapper (`{"message": "<line>", ...}`) themselves.
//! Indexed `fields` never enter the record: they are filed under `unmapped` /
//! `ext` (a field whose name the record already has goes under `hec_fields`),
//! only where the parser did not set that key.
//!
//! A parser without a declaration falls back to inference from its first
//! structural decoder (comments and the generated blocks the parsers repo
//! expands, such as the source-timezone prelude and the residual spill, never
//! count). Inference only answers `json` or `text`, and it is logged as a WARN
//! at render time: the declaration is the contract.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::parsers::types::Parser;

/// Suffix of the per-parser remap that hands a JSON-input parser the whole
/// HEC record.
pub(super) const HEC_PAYLOAD_SUFFIX: &str = "_hec_payload";

/// The `<parser>_hec_payload` remap body for a parser that DECLARES `json`
/// or `json_or_text` (NAN-5891), on its NAN-5891 root
/// ([`hec_record_view_vrl!`]).
///
/// - An object record: the parser gets the record text back, byte for byte
///   as received; only the indexed fields stay in the stash for `unmapped` /
///   `ext`.
/// - Anything else (a string event, `/raw`): the v2.0.35 behaviour, the same
///   as [`HEC_LEGACY_JSON_PAYLOAD_VRL`].
pub(super) const HEC_JSON_PAYLOAD_VRL: &str = concat!(
    hec_record_view_vrl!(),
    r#"# NAN-5891: this parser declares it reads a JSON object; give it the whole
# HEC record, unmodified, as HTTP /ingest does.
nano_hec_record = %nano_hec_record
if is_object(nano_hec_record) && is_string(nano_hec_record.text) {
    .message = string!(nano_hec_record.text)
    nano_hec_unfiled = nano_hec_record.unfiled
    if is_object(nano_hec_unfiled) && length(object!(nano_hec_unfiled)) > 0 {
        %nano_hec_event = nano_hec_unfiled
    } else {
        del(%nano_hec_event)
    }
} else {
    nano_hec_event = %nano_hec_event
    if is_object(nano_hec_event) {
        nano_hec_parsed, nano_hec_err = parse_json(to_string(.message) ?? "")
        if nano_hec_err != null || !is_object(nano_hec_parsed) {
            .message = encode_json(nano_hec_event)
            del(%nano_hec_event)
        }
    } else {
        del(%nano_hec_event)
    }
}
del(%nano_hec_record)"#
);

/// NAN-5902: the `<parser>_hec_payload` remap body for a parser that declares
/// NO contract and that v2.0.35 classified as reading JSON: exactly the
/// v2.0.35 step, then the lossless record (which it never reads) is dropped
/// before the parser runs (review P1-1). `hec_normalize` hands every event
/// the v2.0.35 shape, so such a parser receives what it received on v2.0.35.
pub(super) const HEC_LEGACY_JSON_PAYLOAD_VRL: &str = r#"# NAN-5902: this parser declares no input contract and reads JSON first:
# the v2.0.35 delivery.
nano_hec_event = %nano_hec_event
if is_object(nano_hec_event) {
    nano_hec_record, nano_hec_err = parse_json(to_string(.message) ?? "")
    if nano_hec_err != null || !is_object(nano_hec_record) {
        .message = encode_json(nano_hec_event)
        del(%nano_hec_event)
    }
} else {
    del(%nano_hec_event)
}
del(%nano_hec_record)"#;

/// NAN-5891: the `<parser>_hec_payload` remap body for a parser that DECLARES
/// `text`: its NAN-5891 root ([`hec_record_view_vrl!`]): an object record's
/// line (or the whole record when it has none), and every other record key
/// in the stash for `unmapped` / `ext`. A string event or `/raw` keeps the
/// v2.0.35 shape.
pub(super) const HEC_TEXT_PAYLOAD_VRL: &str = concat!(
    hec_record_view_vrl!(),
    "del(%nano_hec_record)"
);

/// Which `<parser>_hec_payload` step a parser gets (NAN-5902).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HecDelivery {
    /// No step, as on v2.0.35: undeclared, v2.0.35 says `text`. (Under OCSF
    /// `_source_tz` drops the lossless record before the parser.)
    Legacy,
    /// [`HEC_LEGACY_JSON_PAYLOAD_VRL`]: undeclared, v2.0.35 says `json`.
    LegacyJson,
    /// [`HEC_JSON_PAYLOAD_VRL`]: declared `json` or `json_or_text`.
    Record,
    /// [`HEC_TEXT_PAYLOAD_VRL`]: declared `text`.
    Line,
}

/// Keys an HEC sibling never writes into OCSF `unmapped`: the parsed line
/// itself and the parser-health markers. Spelled out in `OCSF_PREPARE_VRL`; a
/// test keeps the copy equal to this. A sibling named `client_ip` is vendor
/// data and is kept (NAN-5846): nano's ingest provenance lives under
/// `unmapped.nano`, which the prepare step removes in every spelling (nested,
/// dotted, mixed) and rewrites after this merge (`ingest_provenance_vrl!`).
#[cfg(test)]
pub(super) const HEC_SIBLING_SKIP_KEYS_OCSF: &str =
    r#"["message", "parse_error", "parse_fallback", "parse_failure", "claimed_source_type"]"#;

/// The legacy UDM `_output` copy: also the identity fields that lane still
/// restores into `ext` from metadata. Spelled out in the UDM `_output`; a test
/// keeps the copy equal to this.
#[cfg(test)]
pub(super) const HEC_SIBLING_SKIP_KEYS_UDM: &str = r#"["message", "parse_error", "parse_fallback", "parse_failure", "claimed_source_type", "client_ip", "ingest_client_ip", "ingest_peer"]"#;

/// What a parser reads from `.message` (see the module docs for what each
/// transport delivers per mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputContract {
    /// A JSON object record.
    Json,
    /// A text line.
    Text,
    /// A JSON record or a text line (the parser tries `parse_json` first).
    JsonOrText,
}

impl InputContract {
    /// The value spelled in `# nano:input=<value>`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
            Self::JsonOrText => "json_or_text",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(Self::Json),
            "text" => Some(Self::Text),
            "json_or_text" => Some(Self::JsonOrText),
            _ => None,
        }
    }

    /// Whether the parser gets the whole HEC record (`<parser>_hec_payload`).
    pub fn reads_record(self) -> bool {
        matches!(self, Self::Json | Self::JsonOrText)
    }
}

/// How a parser's [`InputContract`] was decided.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InputContractVerdict {
    pub contract: InputContract,
    /// `true`: a `# nano:input=` or `# nano:input-v2=` line declared it.
    /// `false`: inferred.
    pub declared: bool,
    /// The `# nano:input=` (v1) declaration, which every nano version reads.
    pub declared_v1: Option<InputContract>,
    /// The `# nano:input-v2=` declaration, read from v2.0.36 (wins over v1).
    pub declared_v2: Option<InputContract>,
    /// What nano before v2.0.36 decides for the same program (`json` or
    /// `text`): its v1 line, else its old inference.
    pub legacy: InputContract,
    /// What inference answers for the same program (comments and generated
    /// blocks skipped), so a check can compare a declaration with it.
    pub inferred: InputContract,
    /// Problems with the declarations (an unknown value, two different
    /// values). Empty when the program is clean.
    pub warnings: Vec<String>,
    /// A `text` parser whose first decoder is `parse_json`: it reads JSON
    /// records too, so over HEC it should declare `json_or_text` (as `text` it
    /// gets an object record's `message` line, not the record).
    pub reads_json_first: bool,
}

/// Structural decoders: the first one a parser applies tells what its input is.
/// Field-level helpers (`parse_timestamp`, `parse_int`, `parse_url`, ...) are
/// not listed; JSON parsers use them on fields after decoding.
static FIRST_DECODER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\bparse_(json|syslog|regex_all|regex|groks|grok|cef|key_value|csv|xml|common_log|apache_log|nginx_log|klog|glog|logfmt|linux_authorization|aws_[a-z_]+|tokens|ruby_hash|cbor|influxdb)\b",
    )
    .expect("decoder regex")
});

/// Line-format decoders. A parser that tries JSON first but falls back to one
/// of these (nginx: JSON access logs or the combined format) infers as a text
/// parser: a forwarder wrapping its log line in `{"message": ...}` must still
/// reach the text branch. Such a parser should declare `json_or_text`.
static LINE_DECODER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\bparse_(syslog|groks|grok|cef|key_value|csv|xml|common_log|apache_log|nginx_log|klog|glog|logfmt|linux_authorization|aws_alb_log|aws_vpc_flow_log|aws_cloudwatch_log_subscription_message)\b",
    )
    .expect("line decoder regex")
});

/// The v1 declaration every nano version reads (`json` / `text`).
const DECLARATION: &str = "nano:input=";
/// The v2 declaration (`json` / `text` / `json_or_text`), read from v2.0.36
/// and winning over v1 there; older nano versions ignore it.
const DECLARATION_V2: &str = "nano:input-v2=";

/// The generated blocks the parsers repo expands into a parser's VRL
/// (`scripts/residual_spill.py`): `# NAN <name>...` opens one and
/// `# END NAN <name>` closes it. Their code is shared plumbing, never the
/// parser's own decoder, so inference skips it.
fn is_block_start(comment: &str, end: &str) -> bool {
    // `# NAN-2421 residual spill. Generated ...` closes at
    // `# END NAN-2421 residual spill`; `# NAN local clock: ts` at
    // `# END NAN local clock`.
    comment.starts_with(end)
        && comment[end.len()..]
            .chars()
            .next()
            .map_or(true, |c| matches!(c, '.' | ':' | ' '))
}

/// The text of a comment line, or `None` for code.
fn comment_of(line: &str) -> Option<&str> {
    line.trim().strip_prefix('#').map(str::trim)
}

/// The program's own code: comments and generated blocks removed. A block
/// opens at `# NAN <name>...` only when a later `# END NAN <name>` closes it
/// (the longest such name wins, so `# NAN mixed input merge` is not closed by
/// `# END NAN mixed input`); an unclosed start is an ordinary comment.
fn own_code(vrl: &str) -> String {
    let lines: Vec<&str> = vrl.lines().collect();
    let mut code = String::with_capacity(vrl.len());
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let Some(comment) = comment_of(line) else {
            code.push_str(line);
            code.push('\n');
            i += 1;
            continue;
        };
        if comment.starts_with("NAN") {
            let close = lines[i + 1..]
                .iter()
                .enumerate()
                .filter_map(|(offset, l)| {
                    let end = comment_of(l)?.strip_prefix("END ")?.trim();
                    is_block_start(comment, end).then_some((i + 1 + offset, end.len()))
                })
                // Nearest closing line of the longest matching name.
                .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
            if let Some((end_line, _)) = close {
                i = end_line + 1;
                continue;
            }
        }
        i += 1;
    }
    code
}

/// Inference from the first structural decoder of the program's own code,
/// and whether that decoder is `parse_json`.
fn infer(vrl: &str) -> (InputContract, bool) {
    let code = own_code(vrl);
    let first_is_json = FIRST_DECODER
        .captures(&code)
        .is_some_and(|c| &c[1] == "json");
    let contract = if first_is_json && !LINE_DECODER.is_match(&code) {
        InputContract::Json
    } else {
        InputContract::Text
    };
    (contract, first_is_json)
}

/// The input contract of a parser program: its `# nano:input=` declaration,
/// else inference.
pub fn input_contract(vrl: &str) -> InputContractVerdict {
    let mut v1: Option<InputContract> = None;
    let mut v2: Option<InputContract> = None;
    let mut warnings = Vec::new();
    for line in vrl.lines() {
        let Some(comment) = line.trim().strip_prefix('#') else {
            continue;
        };
        let comment = comment.trim().to_ascii_lowercase();
        let (slot, key, value) = if let Some(value) = comment.strip_prefix(DECLARATION_V2) {
            (&mut v2, DECLARATION_V2, value.trim())
        } else if let Some(value) = comment.strip_prefix(DECLARATION) {
            (&mut v1, DECLARATION, value.trim())
        } else {
            continue;
        };
        match InputContract::parse(value) {
            None => warnings.push(format!(
                "unknown input contract `# {key}{}` (use json, text or json_or_text)",
                value.chars().take(64).collect::<String>()
            )),
            Some(c) => {
                if key == DECLARATION && c == InputContract::JsonOrText {
                    warnings.push(
                        "`# nano:input=json_or_text`: nano before v2.0.36 reads it as undeclared and infers; \
                         keep `# nano:input=json|text` for them and add `# nano:input-v2=json_or_text`"
                            .into(),
                    );
                }
                match *slot {
                    None => *slot = Some(c),
                    Some(first) if first != c => warnings.push(format!(
                        "two `# {key}` declarations (`{}` and `{}`); the first one applies",
                        first.as_str(),
                        c.as_str()
                    )),
                    Some(_) => {}
                }
            }
        }
    }
    let (inferred, first_is_json) = infer(vrl);
    let declared = v2.or(v1);
    let contract = declared.unwrap_or(inferred);
    InputContractVerdict {
        contract,
        declared: declared.is_some(),
        declared_v1: v1,
        declared_v2: v2,
        inferred,
        legacy: if legacy_reads_json_object(vrl) { InputContract::Json } else { InputContract::Text },
        warnings,
        reads_json_first: contract == InputContract::Text && first_is_json,
    }
}

/// What nano before v2.0.36 decides (`vrl_reads_json_object` at v2.0.35):
/// the first exact `# nano:input=json|text` line, else the first structural
/// decoder of everything that is not a comment, generated blocks included.
/// The parsers content channel serves every install, so a declaration change
/// must keep this answer (see `# nano:input-v2=`).
fn legacy_reads_json_object(vrl: &str) -> bool {
    let mut code = String::with_capacity(vrl.len());
    for line in vrl.lines() {
        let trimmed = line.trim();
        if let Some(comment) = trimmed.strip_prefix('#') {
            match comment.trim().to_ascii_lowercase().as_str() {
                "nano:input=json" => return true,
                "nano:input=text" => return false,
                _ => continue,
            }
        }
        code.push_str(line);
        code.push('\n');
    }
    let first_is_json = FIRST_DECODER
        .captures(&code)
        .is_some_and(|c| &c[1] == "json");
    first_is_json && !LINE_DECODER.is_match(&code)
}

/// The program whose contract decides `parser`'s: the parser VRL (a compiled
/// processing plan included) or, for a stub parser whose logic lives in its
/// extension, the extension VRL. `None`: a stub without an enabled extension.
fn contract_program<'a>(parser: &'a Parser, runtime_parser_vrl: &'a str) -> Option<&'a str> {
    if !parser.parser_vrl.trim().is_empty() {
        return Some(runtime_parser_vrl);
    }
    if parser.extension_enabled {
        return parser.extension_vrl.as_deref();
    }
    None
}

/// Most (parser, warning) pairs remembered; past it the set starts over, so a
/// warning can repeat but memory stays bounded (review P2-2).
pub(super) const MAX_CONTRACT_WARNED: usize = 4096;

/// Digests of the (parser id, warning) pairs already logged (NAN-5902: once
/// per parser per process; the config is rendered on every deploy, for every
/// parser). A digest, never the warning text (which quotes parser VRL).
static CONTRACT_WARNED: Lazy<std::sync::Mutex<std::collections::HashSet<u64>>> =
    Lazy::new(Default::default);

/// Whether `note` is new for `parser_id` in this process.
pub(super) fn first_warning(parser_id: uuid::Uuid, note: &str) -> bool {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    parser_id.hash(&mut hasher);
    note.hash(&mut hasher);
    let digest = hasher.finish();
    CONTRACT_WARNED.lock().map_or(true, |mut seen| {
        if seen.len() >= MAX_CONTRACT_WARNED && !seen.contains(&digest) {
            seen.clear();
        }
        seen.insert(digest)
    })
}

/// What `parser` receives over HEC (NAN-5902): a parser that declares a
/// contract gets the lossless NAN-5891 view; one that declares none gets
/// exactly the v2.0.35 delivery, v2.0.35's classifier choosing between its
/// two shapes (the v2.0.36 inference only feeds the warnings). Logs
/// the contract warnings once per parser per process.
pub(super) fn parser_hec_delivery(parser: &Parser, runtime_parser_vrl: &str) -> HecDelivery {
    let Some(program) = contract_program(parser, runtime_parser_vrl) else {
        return HecDelivery::Legacy;
    };
    let verdict = input_contract(program);
    let mut notes: Vec<String> = verdict.warnings.clone();
    if verdict.reads_json_first {
        notes.push("its contract is `text` but its first decoder is parse_json: an HEC object record reaches it as the record's `message` line, not the record. If it reads JSON records, keep `# nano:input=text` and add `# nano:input-v2=json_or_text`".into());
    }
    if !verdict.declared {
        notes.push(format!(
            "it declares no input contract, so it receives HEC events exactly as on v2.0.35 (as a `{}` parser; the v2.0.36 inference says `{}`). Add `# nano:input=json` or `# nano:input=text` to its VRL (and `# nano:input-v2=json_or_text` for a parser that reads JSON records and text lines) to receive HEC object records whole",
            verdict.legacy.as_str(),
            verdict.inferred.as_str()
        ));
    }
    for note in notes {
        if first_warning(parser.id, &note) {
            tracing::warn!(parser = %parser.name, "parser input contract: {note}");
        }
    }
    if !verdict.declared {
        // v2.0.35's own decision (its classifier, verbatim), not the v2.0.36
        // inference, which skips generated blocks and may answer differently.
        return match verdict.legacy {
            InputContract::Json => HecDelivery::LegacyJson,
            _ => HecDelivery::Legacy,
        };
    }
    match verdict.contract {
        InputContract::Text => HecDelivery::Line,
        _ => HecDelivery::Record,
    }
}

/// The `<parser>_hec_payload` remap for `delivery`, reading from `input`;
/// `None` when the parser gets no step. An undeclared text parser gets none
/// under OCSF, as on v2.0.35 (`_source_tz` drops the lossless record there);
/// on the UDM lane, which has no `_source_tz`, a step that only drops it
/// (review r2 P2-1).
pub(super) fn hec_payload_transform(
    safe_name: &str,
    input: &str,
    delivery: HecDelivery,
    ocsf: bool,
) -> Option<(String, String)> {
    let body = match delivery {
        HecDelivery::Legacy if ocsf => return None,
        HecDelivery::Legacy => super::parser_config::HEC_RECORD_DROP_VRL,
        HecDelivery::LegacyJson => HEC_LEGACY_JSON_PAYLOAD_VRL,
        HecDelivery::Record => HEC_JSON_PAYLOAD_VRL,
        HecDelivery::Line => HEC_TEXT_PAYLOAD_VRL,
    };
    let name = format!("{safe_name}{HEC_PAYLOAD_SUFFIX}");
    let config = format!(
        "\n[transforms.{name}]\n\
         type = \"remap\"\n\
         inputs = [\"{input}\"]\n\
         source = '''\n\
         {body}\n\
         '''\n"
    );
    Some((config, name))
}

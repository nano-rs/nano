// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5340: what a parser receives for an HEC object event.
//!
//! Vector's `splunk_hec` source spreads an object event over the log root, so
//! `{"event": {"message": "<text>", "seq": 7}}` reaches `hec_normalize` as
//! `.message = "<text>"` with `seq` beside it. Every parser reads `.message`,
//! and most OCSF parsers replace the root, so before this the sibling keys
//! were lost. `hec_normalize` now keeps the whole object in event METADATA
//! (`%nano_hec_event`, which a sender cannot set) whenever such siblings exist.
//! Each parser then gets the payload its input contract expects:
//!
//! - A JSON-input parser (its first structural decode of the input is
//!   `parse_json`, e.g. Generic JSON, Okta, CloudTrail) receives the whole
//!   object as the payload, exactly what HTTP `/ingest` hands it. A generated
//!   `<parser>_hec_payload` remap runs before the parser.
//! - A text parser (syslog, CEF, key-value, regex, ...) keeps `.message` = the
//!   log line and parses exactly as before. The sibling keys are merged into
//!   OCSF `unmapped.*` by `_ocsf_prepare`, or into UDM `ext.*` by `_output`,
//!   only where the parser did not already set that key.
//!
//! A parser can declare its contract explicitly with a comment line
//! `# nano:input=json` or `# nano:input=text`; otherwise it is inferred.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::parsers::types::Parser;

/// Suffix of the per-parser remap that hands a JSON-input parser the whole
/// HEC object.
pub(super) const HEC_PAYLOAD_SUFFIX: &str = "_hec_payload";

/// The `<parser>_hec_payload` remap body. Deleting the stash afterwards keeps
/// `_ocsf_prepare` / `_output` from merging keys the parser already received.
///
/// A `message` that is itself a JSON object is already the record (a string
/// event carrying vendor JSON, with HEC indexed `fields` beside it, as
/// OpenTelemetry-style forwarders send): the parser keeps it, and the stash
/// stays so the prepare step files the sibling keys under `unmapped` / `ext`.
pub(super) const HEC_JSON_PAYLOAD_VRL: &str = r#"# NAN-5340: this parser reads a JSON object; give it the whole HEC event
# object (message and every sibling key), as HTTP /ingest does.
nano_hec_event = %nano_hec_event
if is_object(nano_hec_event) {
    nano_hec_record, nano_hec_err = parse_json(to_string(.message) ?? "")
    if nano_hec_err != null || !is_object(nano_hec_record) {
        .message = encode_json(nano_hec_event)
        del(%nano_hec_event)
    }
} else {
    del(%nano_hec_event)
}"#;

/// Keys an HEC sibling never writes into `unmapped` / `ext`: the parsed line
/// itself, the parser-health markers, and the protected identity fields the
/// prepare steps restore from metadata. Spelled out in `OCSF_PREPARE_VRL` and
/// the UDM `_output`; a test keeps both copies equal to this.
#[cfg(test)]
pub(super) const HEC_SIBLING_SKIP_KEYS: &str = r#"["message", "parse_error", "parse_fallback", "parse_failure", "claimed_source_type", "client_ip", "ingest_client_ip", "ingest_peer"]"#;

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
/// of these (nginx: JSON access logs or the combined format) is a text parser:
/// a forwarder wrapping its log line in `{"message": ...}` must still reach the
/// text branch.
static LINE_DECODER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\bparse_(syslog|groks|grok|cef|key_value|csv|xml|common_log|apache_log|nginx_log|klog|glog|logfmt|linux_authorization|aws_alb_log|aws_vpc_flow_log|aws_cloudwatch_log_subscription_message)\b",
    )
    .expect("line decoder regex")
});

/// Whether `vrl` expects a JSON object as its input payload.
pub(super) fn vrl_reads_json_object(vrl: &str) -> bool {
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

/// Whether `parser`'s input contract is a JSON object. The runtime program is
/// the parser VRL (a compiled processing plan included) or, for a stub parser
/// whose logic lives in its extension, the extension VRL.
pub(super) fn parser_reads_json_object(parser: &Parser, runtime_parser_vrl: &str) -> bool {
    if !parser.parser_vrl.trim().is_empty() {
        return vrl_reads_json_object(runtime_parser_vrl);
    }
    parser.extension_enabled
        && parser
            .extension_vrl
            .as_deref()
            .is_some_and(vrl_reads_json_object)
}

/// The `<parser>_hec_payload` remap, reading from `input`.
pub(super) fn hec_payload_transform(safe_name: &str, input: &str) -> (String, String) {
    let name = format!("{safe_name}{HEC_PAYLOAD_SUFFIX}");
    let config = format!(
        "\n[transforms.{name}]\n\
         type = \"remap\"\n\
         inputs = [\"{input}\"]\n\
         source = '''\n\
         {HEC_JSON_PAYLOAD_VRL}\n\
         '''\n"
    );
    (config, name)
}

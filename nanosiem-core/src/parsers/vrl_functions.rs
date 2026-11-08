// SPDX-License-Identifier: AGPL-3.0-or-later

//! The VRL function registries for tenant- and AI-authored VRL, shared by the
//! guarded compiler and the AI parser prompt catalog (NAN-4808, NAN-4912 P3).
//!
//! **Event parsers compile against an explicit ALLOWLIST**
//! ([`PARSER_VRL_FUNCTIONS`]): pure data transformation only. Anything that
//! observes the host, reaches the network, reads files, or writes outside the
//! event — notably `log`, which would copy raw events into service logs — is
//! absent from the registry, so a call to it is an "undefined function"
//! compile error in every parser path (validate, test, save/publish, deploy,
//! AI drafts), whatever the prompt or a sample says. An allowlist fails
//! closed: a function added by a future VRL release is unavailable until it
//! is reviewed into one of the lists here (a test enforces that every stdlib
//! function is classified).
//!
//! **Enrichment normalize programs** additionally get the functions in
//! [`ENRICHMENT_EXTRA_VRL_FUNCTIONS`] (`log`, for the shipped dead-letter
//! warnings). They are platform-shipped or admin-authored lane mappings, not
//! AI drafts, and never reach the parser catalog.
//!
//! The prompt catalog is rendered once at runtime from the parser registry of
//! the linked `vrl` crate (VRL 0.38, matching the pinned `nano/v0.61` Vector
//! fork), so the model is told exactly what compiles.

use std::sync::LazyLock;

/// Functions an event parser may call (VRL 0.38 stdlib, reviewed).
pub const PARSER_VRL_FUNCTIONS: &[&str] = &[
    "abs", "append", "array", "assert", "assert_eq", "basename", "bool", "camelcase",
    "ceil", "chunks", "community_id", "compact", "contains", "contains_all", "crc", "decode_base16",
    "decode_base64", "decode_charset", "decode_gzip", "decode_lz4", "decode_mime_q", "decode_percent", "decode_punycode", "decode_snappy",
    "decode_zlib", "decode_zstd", "decrypt", "decrypt_ip", "del", "dirname", "downcase", "encode_base16",
    "encode_base64", "encode_charset", "encode_csv", "encode_gzip", "encode_json", "encode_key_value", "encode_logfmt", "encode_lz4",
    "encode_percent", "encode_punycode", "encode_snappy", "encode_zlib", "encode_zstd", "encrypt", "encrypt_ip", "ends_with",
    "exists", "filter", "find", "flatten", "float", "floor", "for_each", "format_int",
    "format_number", "format_timestamp", "from_entries", "from_unix_timestamp", "get", "haversine", "hmac", "includes",
    "int", "ip_aton", "ip_cidr_contains", "ip_ntoa", "ip_ntop", "ip_pton", "ip_subnet", "ip_to_ipv6",
    "ipv6_to_ipv4", "is_array", "is_boolean", "is_empty", "is_float", "is_integer", "is_ipv4", "is_ipv6",
    "is_json", "is_null", "is_nullish", "is_object", "is_regex", "is_string", "is_timestamp", "join",
    "kebabcase", "keys", "length", "map_keys", "map_values", "match", "match_any", "match_array",
    "match_datadog_query", "md5", "merge", "mod", "now", "object", "object_from_array", "parse_apache_log",
    "parse_aws_alb_log", "parse_aws_cloudwatch_log_subscription_message", "parse_aws_vpc_flow_log", "parse_bytes", "parse_cbor", "parse_cef", "parse_common_log", "parse_csv",
    "parse_duration", "parse_float", "parse_glog", "parse_grok", "parse_groks", "parse_influxdb", "parse_int", "parse_json",
    "parse_key_value", "parse_klog", "parse_linux_authorization", "parse_logfmt", "parse_nginx_log", "parse_query_string", "parse_regex", "parse_regex_all",
    "parse_ruby_hash", "parse_syslog", "parse_timestamp", "parse_tokens", "parse_url", "parse_user_agent", "parse_xml", "parse_yaml",
    "pascalcase", "pop", "push", "random_bool", "random_bytes", "random_float", "random_int", "range",
    "redact", "remove", "replace", "replace_with", "round", "screamingsnakecase", "seahash", "set",
    "sha1", "sha2", "sha3", "shannon_entropy", "sieve", "slice", "snakecase", "split",
    "split_path", "starts_with", "string", "strip_ansi_escape_codes", "strip_whitespace", "strlen", "tag_types_externally", "tally",
    "tally_value", "timestamp", "to_bool", "to_entries", "to_float", "to_int", "to_regex", "to_string",
    "to_syslog_facility", "to_syslog_facility_code", "to_syslog_level", "to_syslog_severity", "to_unix_timestamp", "truncate", "unflatten", "unique",
    "unnest", "upcase", "uuid_from_friendly_id", "uuid_v4", "uuid_v7", "values", "xxhash", "zip",
];

/// Stdlib functions deliberately unavailable to event parsers, with why.
/// Kept as a list (not just "absent") so the classification test can tell
/// "reviewed and refused" from "new and unreviewed", and so the connector's
/// own refusal list can be checked against it.
pub const PARSER_EXCLUDED_VRL_FUNCTIONS: &[&str] = &[
    // network egress (DNS-tunnel exfiltration)
    "dns_lookup",
    // network egress (DNS-tunnel exfiltration)
    "reverse_dns",
    // network egress (SSRF / exfiltration)
    "http_request",
    // reads host environment (secrets)
    "get_env_var",
    // reads host identity (reconnaissance)
    "get_hostname",
    // reads host configuration
    "get_timezone_name",
    // writes event content to service logs (exfiltration past source-data access controls)
    "log",
    // reads a descriptor file from the host
    "encode_proto",
    // reads a descriptor file from the host
    "parse_proto",
    // reads a schema file from the host
    "validate_json_schema",
    // optional `psl` argument reads a file from the host
    "parse_etld",
    // compiler introspection, not data transformation
    "type_def",
];

/// Extra functions enrichment normalize programs need on top of the parser
/// registry: `log` for the dead-letter warning before `abort`.
pub const ENRICHMENT_EXTRA_VRL_FUNCTIONS: &[&str] = &["log"];

/// Which registry a program compiles against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VrlRegistry {
    /// Event parsers (log sources, extensions, AI drafts, source-config remaps).
    #[default]
    Parser,
    /// Enrichment normalize lanes.
    Enrichment,
}

impl VrlRegistry {
    fn admits(self, name: &str) -> bool {
        PARSER_VRL_FUNCTIONS.contains(&name)
            || (self == Self::Enrichment && ENRICHMENT_EXTRA_VRL_FUNCTIONS.contains(&name))
    }

    /// The compiler function set for this registry.
    pub fn functions(self) -> Vec<Box<dyn vrl::compiler::Function>> {
        vrl::stdlib::all()
            .into_iter()
            .filter(|f| self.admits(f.identifier()))
            .collect()
    }
}

/// The event-parser function set ([`VrlRegistry::Parser`]).
pub fn parser_vrl_functions() -> Vec<Box<dyn vrl::compiler::Function>> {
    VrlRegistry::Parser.functions()
}

/// One line per function: `name(arg:kind,opt?:kind) -> |arg1,arg2| { ... } : return_kind`.
fn signature(f: &dyn vrl::compiler::Function) -> String {
    let args = f
        .parameters()
        .iter()
        .map(|p| {
            format!(
                "{}{}:{}",
                p.keyword,
                if p.required { "" } else { "?" },
                p.kind()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let closure = f
        .closure()
        .and_then(|definition| {
            definition.inputs.first().map(|input| {
                let variables = (1..=input.variables.len())
                    .map(|n| format!("arg{n}"))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(" -> |{variables}| {{ ... }}")
            })
        })
        .unwrap_or_default();
    let result = vrl::compiler::Parameter::required("result", f.return_kind(), "").kind();
    format!("{}({}){} : {}", f.identifier(), args, closure, result)
}

static CATALOG: LazyLock<String> = LazyLock::new(|| {
    let mut entries = parser_vrl_functions()
        .iter()
        .map(|f| signature(f.as_ref()))
        .collect::<Vec<_>>();
    entries.sort();
    entries.join("\n")
});

/// Names and signatures of every function an event parser may call, sorted,
/// one per line. Optional arguments are marked `?`.
pub fn vrl_function_catalog() -> &'static str {
    CATALOG.as_str()
}

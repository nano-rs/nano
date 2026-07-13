// SPDX-License-Identifier: AGPL-3.0-or-later

//! TypeID encoding/decoding for human-readable prefixed identifiers
//!
//! Implements the TypeID spec (https://github.com/jetify-com/typeid):
//! - UUID stored as native UUID in database (no schema changes)
//! - Serialized as `prefix_base32suffix` in JSON/API responses
//! - Base32 uses Crockford alphabet (lowercase)
//! - UUIDv7 gives time-ordered, sortable identifiers
//!
//! Usage in model structs:
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! pub struct Alert {
//!     #[serde(with = "typeid::alert")]
//!     #[schema(value_type = String)]
//!     pub id: Uuid,
//! }
//! ```

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// Crockford's base32 alphabet (lowercase): 0-9 a-h j-k m-n p-t v-z
/// Excludes: i, l, o, u to avoid ambiguity
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Reverse lookup table: ASCII byte → 5-bit value (0xFF = invalid)
const DECODE_TABLE: [u8; 128] = {
    let mut table = [0xFFu8; 128];
    let mut i = 0u8;
    while i < 32 {
        table[ALPHABET[i as usize] as usize] = i;
        i += 1;
    }
    table
};

// ============================================================================
// Core encode/decode
// ============================================================================

/// Encode a UUID as a 26-character base32 Crockford string.
///
/// The 128-bit UUID is treated as a big-endian integer with 2 zero bits
/// prepended (130 bits total), split into 26 groups of 5 bits.
pub fn encode_suffix(uuid: &Uuid) -> String {
    let n = u128::from_be_bytes(*uuid.as_bytes());
    let mut buf = [0u8; 26];
    for i in 0..26 {
        let shift = 5 * (25 - i);
        buf[i] = ALPHABET[((n >> shift) & 0x1f) as usize];
    }
    // SAFETY: all bytes are ASCII from ALPHABET
    unsafe { String::from_utf8_unchecked(buf.to_vec()) }
}

/// Decode a 26-character base32 Crockford string back to a UUID.
pub fn decode_suffix(s: &str) -> Result<Uuid, TypeIdError> {
    if s.len() != 26 {
        return Err(TypeIdError::InvalidSuffixLength(s.len()));
    }

    let bytes = s.as_bytes();

    // First character must be <= '7' (values 0-7) to fit in 128 bits
    let first = DECODE_TABLE.get(bytes[0] as usize).copied().unwrap_or(0xFF);
    if first > 7 {
        return Err(TypeIdError::Overflow);
    }

    let mut n: u128 = 0;
    for &b in bytes {
        if b > 127 {
            return Err(TypeIdError::InvalidCharacter(b as char));
        }
        let val = DECODE_TABLE[b as usize];
        if val == 0xFF {
            return Err(TypeIdError::InvalidCharacter(b as char));
        }
        n = (n << 5) | val as u128;
    }

    Ok(Uuid::from_bytes(n.to_be_bytes()))
}

/// Encode a UUID with a type prefix: `prefix_base32suffix`
pub fn encode(prefix: &str, uuid: &Uuid) -> String {
    let suffix = encode_suffix(uuid);
    if prefix.is_empty() {
        suffix
    } else {
        format!("{}_{}", prefix, suffix)
    }
}

/// Decode a TypeID string: validate prefix and extract UUID.
/// Also accepts standard UUID format (with hyphens) as a fallback.
pub fn decode(expected_prefix: &str, s: &str) -> Result<Uuid, TypeIdError> {
    // Accept standard UUID format as fallback
    if let Ok(uuid) = Uuid::parse_str(s) {
        return Ok(uuid);
    }

    if expected_prefix.is_empty() {
        return decode_suffix(s);
    }

    let (prefix, suffix) = s
        .rsplit_once('_')
        .ok_or_else(|| TypeIdError::MissingPrefix)?;

    if prefix != expected_prefix {
        return Err(TypeIdError::WrongPrefix {
            expected: expected_prefix.to_string(),
            got: prefix.to_string(),
        });
    }

    decode_suffix(suffix)
}

/// Parse any TypeID string, returning the prefix and UUID.
/// Accepts both `prefix_base32suffix` and bare `base32suffix` formats.
/// Also accepts standard UUID format (with hyphens) for backwards compat during transition.
pub fn parse_any(s: &str) -> Result<(String, Uuid), TypeIdError> {
    // Try standard UUID format first (36 chars with hyphens)
    if let Ok(uuid) = Uuid::parse_str(s) {
        return Ok((String::new(), uuid));
    }

    if let Some((prefix, suffix)) = s.rsplit_once('_') {
        let uuid = decode_suffix(suffix)?;
        Ok((prefix.to_string(), uuid))
    } else {
        let uuid = decode_suffix(s)?;
        Ok((String::new(), uuid))
    }
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug, Clone, thiserror::Error)]
pub enum TypeIdError {
    #[error("invalid suffix length: expected 26, got {0}")]
    InvalidSuffixLength(usize),

    #[error("invalid character in TypeID: '{0}'")]
    InvalidCharacter(char),

    #[error("TypeID suffix overflow (first char must be 0-7)")]
    Overflow,

    #[error("missing type prefix separator '_'")]
    MissingPrefix,

    #[error("wrong type prefix: expected '{expected}', got '{got}'")]
    WrongPrefix { expected: String, got: String },
}

// ============================================================================
// TypeIdParam — generic path parameter extractor
// ============================================================================

/// A parsed TypeID that can be used as an Axum path parameter.
/// Accepts both TypeID format (`alert_01h455...`) and standard UUID format.
///
/// Use with `Path<TypeIdParam>` in handlers:
/// ```ignore
/// pub async fn get_alert(Path(id): Path<TypeIdParam>) -> ... {
///     let alert = repo.get_alert(*id).await?;
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeIdParam(pub Uuid);

impl TypeIdParam {
    pub fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl std::ops::Deref for TypeIdParam {
    type Target = Uuid;
    fn deref(&self) -> &Uuid {
        &self.0
    }
}

impl FromStr for TypeIdParam {
    type Err = TypeIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, uuid) = parse_any(s)?;
        Ok(TypeIdParam(uuid))
    }
}

impl fmt::Display for TypeIdParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as bare base32 (no prefix — prefix depends on context)
        write!(f, "{}", encode_suffix(&self.0))
    }
}

impl<'de> Deserialize<'de> for TypeIdParam {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        TypeIdParam::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for TypeIdParam {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_suffix(&self.0))
    }
}

// ============================================================================
// Macro for generating per-prefix serde modules
// ============================================================================

/// Generate a serde module for a TypeID prefix.
///
/// Creates `$mod_name::serialize` / `$mod_name::deserialize` for `Uuid` fields,
/// and `$mod_name::opt::serialize` / `$mod_name::opt::deserialize` for `Option<Uuid>`.
///
/// Also creates `$mod_name::vec` for `Vec<Uuid>` fields.
macro_rules! typeid_prefix {
    ($mod_name:ident, $prefix:literal) => {
        pub mod $mod_name {
            use super::*;

            pub const PREFIX: &str = $prefix;

            pub fn serialize<S: Serializer>(uuid: &Uuid, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&encode(PREFIX, uuid))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
                let s = String::deserialize(d)?;
                decode(PREFIX, &s).map_err(serde::de::Error::custom)
            }

            /// Serde module for `Option<Uuid>` fields
            pub mod opt {
                use super::*;

                pub fn serialize<S: Serializer>(
                    uuid: &Option<Uuid>,
                    s: S,
                ) -> Result<S::Ok, S::Error> {
                    match uuid {
                        Some(u) => s.serialize_some(&encode(PREFIX, u)),
                        None => s.serialize_none(),
                    }
                }

                pub fn deserialize<'de, D: Deserializer<'de>>(
                    d: D,
                ) -> Result<Option<Uuid>, D::Error> {
                    let opt = Option::<String>::deserialize(d)?;
                    match opt {
                        Some(s) if s.is_empty() => Ok(None),
                        Some(s) => decode(PREFIX, &s)
                            .map(Some)
                            .map_err(serde::de::Error::custom),
                        None => Ok(None),
                    }
                }
            }

            /// Serde module for `Vec<Uuid>` fields
            pub mod vec {
                use super::*;

                pub fn serialize<S: Serializer>(
                    uuids: &Vec<Uuid>,
                    s: S,
                ) -> Result<S::Ok, S::Error> {
                    use serde::ser::SerializeSeq;
                    let mut seq = s.serialize_seq(Some(uuids.len()))?;
                    for uuid in uuids {
                        seq.serialize_element(&encode(PREFIX, uuid))?;
                    }
                    seq.end()
                }

                pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Uuid>, D::Error> {
                    let strings = Vec::<String>::deserialize(d)?;
                    strings
                        .into_iter()
                        .map(|s| decode(PREFIX, &s).map_err(serde::de::Error::custom))
                        .collect()
                }
            }
        }
    };
}

// ============================================================================
// Prefix definitions — one per entity type
// ============================================================================

typeid_prefix!(alert, "alert");
typeid_prefix!(case, "case");
typeid_prefix!(case_alert, "calrt");
typeid_prefix!(case_entity, "cent");
typeid_prefix!(case_wall, "cwall");
typeid_prefix!(case_relation, "crel");
typeid_prefix!(case_grouping_rule, "cgrp");
typeid_prefix!(rule, "rule");
typeid_prefix!(user, "user");
typeid_prefix!(group, "group");
typeid_prefix!(role, "role");
typeid_prefix!(session, "sess");
typeid_prefix!(api_key, "key");
typeid_prefix!(oidc_provider, "oidc");
typeid_prefix!(oidc_group_mapping, "ogmap");
typeid_prefix!(notebook, "nb");
typeid_prefix!(notebook_entry, "nbent");
typeid_prefix!(notebook_tab, "nbtab");
typeid_prefix!(notebook_share, "nbshr");
typeid_prefix!(notebook_ref, "nbref");
typeid_prefix!(parser, "parser");
typeid_prefix!(log_source, "lsrc");
typeid_prefix!(cloud_credential, "cred");
typeid_prefix!(enrichment, "enrich");
typeid_prefix!(enrichment_run, "erun");
typeid_prefix!(rule_repo, "rrep");
typeid_prefix!(parser_repo, "prep");
typeid_prefix!(repo_rule, "rrule");
typeid_prefix!(repo_parser, "rparser");
typeid_prefix!(webhook, "whook");
typeid_prefix!(lookup, "lookup");
typeid_prefix!(job, "job");
typeid_prefix!(audit, "audit");
typeid_prefix!(notification, "notif");
typeid_prefix!(catalog, "catalog");
typeid_prefix!(saved_search, "search");
typeid_prefix!(shared_search, "ssearch");
typeid_prefix!(pattern, "pattern");
typeid_prefix!(feed, "feed");
typeid_prefix!(health, "health");
typeid_prefix!(ip_allowlist, "ipallow");
typeid_prefix!(signal, "signal");
typeid_prefix!(incident, "inc");
typeid_prefix!(source_config, "srcfg");
typeid_prefix!(dashboard, "dash");
typeid_prefix!(upload, "upload");
typeid_prefix!(queue, "queue");
typeid_prefix!(queue_routing_rule, "qrr");
typeid_prefix!(siem_health_suppression, "hsupp");
typeid_prefix!(playbook, "pb");
typeid_prefix!(playbook_repo, "pbrep");
typeid_prefix!(repo_playbook, "rpb");
typeid_prefix!(playbook_version, "pbver");
typeid_prefix!(playbook_run, "pbrun");
typeid_prefix!(playbook_approval, "pbappr");
typeid_prefix!(slo, "slo");
typeid_prefix!(synth, "synth");
typeid_prefix!(metric_monitor, "mon");
typeid_prefix!(report, "report");
typeid_prefix!(report_run, "reprun");
typeid_prefix!(report_artifact, "repart");

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let uuid = Uuid::now_v7();
        let suffix = encode_suffix(&uuid);
        assert_eq!(suffix.len(), 26);
        let decoded = decode_suffix(&suffix).unwrap();
        assert_eq!(uuid, decoded);
    }

    #[test]
    fn test_encode_with_prefix() {
        let uuid = Uuid::now_v7();
        let encoded = encode("alert", &uuid);
        assert!(encoded.starts_with("alert_"));
        assert_eq!(encoded.len(), 6 + 26); // "alert_" + 26 chars
    }

    #[test]
    fn test_decode_with_prefix() {
        let uuid = Uuid::now_v7();
        let encoded = encode("alert", &uuid);
        let decoded = decode("alert", &encoded).unwrap();
        assert_eq!(uuid, decoded);
    }

    #[test]
    fn test_wrong_prefix_rejected() {
        let uuid = Uuid::now_v7();
        let encoded = encode("alert", &uuid);
        let result = decode("case", &encoded);
        assert!(matches!(result, Err(TypeIdError::WrongPrefix { .. })));
    }

    #[test]
    fn test_first_char_max_7() {
        // All valid UUIDs should produce first char 0-7
        for _ in 0..1000 {
            let uuid = Uuid::now_v7();
            let suffix = encode_suffix(&uuid);
            let first = suffix.as_bytes()[0];
            let val = DECODE_TABLE[first as usize];
            assert!(val <= 7, "first char '{}' has value {}", first as char, val);
        }
    }

    #[test]
    fn test_nil_uuid() {
        let suffix = encode_suffix(&Uuid::nil());
        assert_eq!(suffix, "00000000000000000000000000");
        let decoded = decode_suffix(&suffix).unwrap();
        assert_eq!(decoded, Uuid::nil());
    }

    #[test]
    fn test_max_uuid() {
        let uuid = Uuid::max();
        let suffix = encode_suffix(&uuid);
        assert_eq!(suffix, "7zzzzzzzzzzzzzzzzzzzzzzzzz");
        let decoded = decode_suffix(&suffix).unwrap();
        assert_eq!(decoded, uuid);
    }

    #[test]
    fn test_parse_any_typeid() {
        let uuid = Uuid::now_v7();
        let encoded = encode("alert", &uuid);
        let (prefix, decoded) = parse_any(&encoded).unwrap();
        assert_eq!(prefix, "alert");
        assert_eq!(decoded, uuid);
    }

    #[test]
    fn test_parse_any_bare_uuid() {
        let uuid = Uuid::now_v7();
        let s = uuid.to_string();
        let (prefix, decoded) = parse_any(&s).unwrap();
        assert_eq!(prefix, "");
        assert_eq!(decoded, uuid);
    }

    #[test]
    fn test_serde_roundtrip() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "alert")]
            id: Uuid,
            #[serde(with = "case::opt")]
            case_id: Option<Uuid>,
        }

        let original = TestStruct {
            id: Uuid::now_v7(),
            case_id: Some(Uuid::now_v7()),
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("alert_"));
        assert!(json.contains("case_"));

        let deserialized: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_option_none() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "case::opt")]
            case_id: Option<Uuid>,
        }

        let original = TestStruct { case_id: None };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_option_empty_string_is_none() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "cloud_credential::opt")]
            cred_id: Option<Uuid>,
        }

        // Empty string should deserialize as None, not error
        let json = r#"{"cred_id": ""}"#;
        let deserialized: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized.cred_id, None);

        // Null should also work
        let json = r#"{"cred_id": null}"#;
        let deserialized: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized.cred_id, None);
    }

    #[test]
    fn test_typeid_param_from_str() {
        let uuid = Uuid::now_v7();

        // TypeID format
        let encoded = encode("alert", &uuid);
        let param: TypeIdParam = encoded.parse().unwrap();
        assert_eq!(*param, uuid);

        // Standard UUID format
        let param: TypeIdParam = uuid.to_string().parse().unwrap();
        assert_eq!(*param, uuid);
    }
}

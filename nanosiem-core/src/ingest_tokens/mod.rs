// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3770: named, revocable per-sender ingest tokens (open core / dedicated).
//!
//! An admin issues one token per sender. The value is returned once and never
//! stored: PostgreSQL keeps its SHA-256 and a display prefix
//! (`migrations/postgres/358_ingest_tokens.sql`). [`IngestTokenService`]
//! renders the active hashes into Vector's hashed tokens file, which the HEC
//! (`02-hec-source.toml`) and HTTP (`00-base.toml`) ingest sources re-read
//! within seconds (`valid_tokens_file`, nano-rs/vector fork). A revoke
//! therefore takes effect with no Vector reload and no listener restart.
//!
//! Vector stamps `%nano_credential_id` / `%nano_credential_name` on every event
//! a named token sent; the lake sink stores the id as
//! `metadata.nano_credential_id` (the same stamp hosted collector-v2 bases
//! write). The install-wide `VECTOR_AUTH_TOKEN` stays accepted through the
//! sources' static fallback unless an admin disables it
//! ([`IngestTokenSettings::install_token_enabled`]); its events carry no stamp.
//!
//! Secrets: the token value exists only in the create response. The file holds
//! hashes only and is written 0600; nothing here logs its content.
//!
//! NAN-3806: a token decides the source, 100% token based. Every token is
//! bound to exactly one push-capable log source ([`BindableSource`]). The file
//! entry's `name` (stamped by the fork as `%nano_credential_name`) carries the
//! bound source's route key ([`route_key`]), and the HEC / HTTP lanes set
//! `.source_type` from it; a `sourcetype` / `X-Source-Type` the sender declares
//! never selects the parser (it survives only as the raw `claimed_source_type`
//! field). A token with no bound source is left out of the file, so Vector
//! refuses it (HTTP 401) until an admin binds it. The install token is listed
//! the same way (under [`INSTALL_CREDENTIAL_ID`]) only while it is enabled and
//! bound; the sources' static install-token fallback is off whenever an
//! install token is configured. Platform pullers in this API (the collector
//! scheduler) authenticate with [`platform_pull_token`], the one credential
//! whose events keep the source type they declare: they are the platform's
//! own integrations, each stream declaring its type from a reviewed manifest.

mod file;
mod repository;
mod service;
mod usage;
#[cfg(test)]
mod vector_lane_tests;

pub use file::{
    render_tokens_file, write_tokens_file, TokenFileEntry, DEFAULT_TOKENS_FILE,
    PLATFORM_PULL_ROUTE,
};
pub use repository::{IngestTokenRepository, IngestTokenRepositoryError};
pub use service::{IngestTokenService, IngestTokenServiceError};
pub use usage::{parse_credential_request_counts, CREDENTIAL_REQUESTS_METRIC};

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac as _};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Public marker every issued token starts with (greppable in sender configs).
pub const TOKEN_MARKER: &str = "nit_";
/// Random alphanumeric characters after the marker (~238 bits).
const TOKEN_RANDOM_LEN: usize = 40;
/// Characters of the random part kept as the display prefix.
const PREFIX_RANDOM_LEN: usize = 8;
/// Longest accepted token name.
pub const MAX_NAME_LEN: usize = 100;

/// Credential id the install token (`VECTOR_AUTH_TOKEN`) is listed under in
/// Vector's file once it is bound (`metadata.nano_credential_id` of its events).
pub const INSTALL_CREDENTIAL_ID: Uuid = Uuid::from_u128(0x6e61_6e6f_0000_4000_8000_0000_0000_0001);
/// Credential id of the platform pull credential ([`platform_pull_token`]).
/// The Vector lanes key on it (`config/vector/00-base.toml`,
/// `02-hec-source.toml`), so it never changes.
pub const PLATFORM_PULL_CREDENTIAL_ID: Uuid =
    Uuid::from_u128(0x6e61_6e6f_0000_4000_8000_0000_0000_0002);
/// HMAC domain of [`platform_pull_token`].
const PLATFORM_PULL_DOMAIN: &str = "nanosiem.platform-pull-ingest.v1";
/// Marker of the derived platform pull credential.
pub const PLATFORM_PULL_MARKER: &str = "npp_";

/// Log source transports a token can be bound to: the push lanes (HTTP ingest,
/// HEC, Vector-native, and every routed label). OTLP and the fetch transports
/// (Kafka, S3/SQS, Pub/Sub, Event Hubs) never receive pushed events.
/// Mirrors `parsers::vector_config::router::transport_of`.
pub fn is_push_capable(source_type: &str) -> bool {
    !matches!(
        source_type,
        "opentelemetry"
            | "otlp"
            | "kafka"
            | "aws_s3"
            | "aws_sqs"
            | "s3"
            | "gcp_pubsub"
            | "pubsub"
            | "azure_event_hubs"
    )
}

/// The `.source_type` value a log source's parser is routed on: its first
/// match value, else its safe name. Exactly the router's first claim
/// (`VectorConfigManager::parser_source_types`), so an event stamped with it
/// reaches that source's parser and no other.
pub fn route_key(match_values: Option<&[String]>, name: &str) -> String {
    match match_values {
        Some([first, ..]) => first.clone(),
        _ => crate::vector_naming::safe_name(name),
    }
}

/// The platform pull credential: HMAC-SHA256 of [`PLATFORM_PULL_DOMAIN`] keyed
/// by the install token, as `npp_<hex>`. Only holders of `VECTOR_AUTH_TOKEN`
/// (this API's in-process pullers) can derive it; nano-api lists its hash in
/// Vector's file under [`PLATFORM_PULL_CREDENTIAL_ID`]. `None` for a blank
/// install token.
pub fn platform_pull_token(install_token: &str) -> Option<String> {
    if install_token.trim().is_empty() {
        return None;
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(install_token.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(PLATFORM_PULL_DOMAIN.as_bytes());
    Some(format!(
        "{PLATFORM_PULL_MARKER}{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

/// The ingest token the in-process platform pullers send to Vector's HTTP
/// ingest: [`platform_pull_token`] of `VECTOR_AUTH_TOKEN`.
pub fn platform_pull_token_from_env() -> Option<String> {
    std::env::var("VECTOR_AUTH_TOKEN")
        .ok()
        .and_then(|token| platform_pull_token(&token))
}

/// A log source a token can be bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BindableSource {
    pub source_id: Uuid,
    pub name: String,
    /// The source's transport label (`routed`, `splunk_hec`, ...).
    pub source_type: String,
    /// The `.source_type` every event of a bound token is routed on.
    pub route_key: String,
    pub enabled: bool,
}

/// One issued token, as listed. Never carries the value or its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IngestToken {
    /// Credential id: the `metadata.nano_credential_id` its events carry.
    pub credential_id: Uuid,
    pub name: String,
    /// `nit_` plus the first 8 characters, to recognise a token in a sender config.
    pub token_prefix: String,
    /// `active`, `unbound` (no source yet: refused until bound) or `revoked`.
    pub state: String,
    /// The log source every event sent with this token lands in. `None` =
    /// unbound: Vector refuses the token until an admin binds it.
    pub source_id: Option<Uuid>,
    /// Name of the bound source (`None` when unbound or the source was deleted).
    pub source_name: Option<String>,
    /// The `.source_type` its events are routed on.
    pub route_key: Option<String>,
    pub source_bound_at: Option<DateTime<Utc>>,
    /// Requests Vector accepted with this token (sampled, approximate).
    pub request_count: i64,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    /// Approximate: sampled from Vector's per-credential request counter.
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Uuid>,
    /// Whether `POST /api/ingest-tokens/{credential_id}/revoke` applies.
    pub revocable: bool,
}

/// Per-tenant ingest token settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IngestTokenSettings {
    /// Whether the install-wide `VECTOR_AUTH_TOKEN` ("Install token (legacy)")
    /// is still accepted (only while it is also bound). Enabled by default.
    pub install_token_enabled: bool,
    /// The log source the install token is bound to. `None` = refused.
    pub install_token_source_id: Option<Uuid>,
    pub install_token_source_bound_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

impl Default for IngestTokenSettings {
    fn default() -> Self {
        Self {
            install_token_enabled: true,
            install_token_source_id: None,
            install_token_source_bound_at: None,
            updated_at: None,
            updated_by: None,
        }
    }
}

/// A freshly generated token. `value` is the only copy of the secret.
pub struct GeneratedToken {
    pub value: String,
    pub prefix: String,
    pub sha256_hex: String,
}

impl std::fmt::Debug for GeneratedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedToken")
            .field("value", &"<redacted>")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// Generates a new token from the OS-seeded thread RNG.
pub fn generate_token() -> GeneratedToken {
    let mut rng = rand::rng();
    let random: String = (0..TOKEN_RANDOM_LEN)
        .map(|_| char::from(rng.sample(rand::distr::Alphanumeric)))
        .collect();
    let value = format!("{TOKEN_MARKER}{random}");
    GeneratedToken {
        prefix: format!("{TOKEN_MARKER}{}", &random[..PREFIX_RANDOM_LEN]),
        sha256_hex: sha256_hex(&value),
        value,
    }
}

/// Lowercase hex SHA-256, the form Vector's tokens file keys on.
pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Validates and normalises a token name.
pub fn normalize_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(format!("Name must be 1 to {MAX_NAME_LEN} characters"));
    }
    if name.chars().any(char::is_control) {
        return Err("Name must not contain control characters".into());
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_unique_and_shaped() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a.value, b.value);
        assert!(a.value.starts_with(TOKEN_MARKER));
        assert_eq!(a.value.len(), TOKEN_MARKER.len() + TOKEN_RANDOM_LEN);
        assert!(a.value[TOKEN_MARKER.len()..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric()));
        assert!(a.value.starts_with(&a.prefix));
        assert_eq!(a.prefix.len(), TOKEN_MARKER.len() + PREFIX_RANDOM_LEN);
        assert_eq!(a.sha256_hex, sha256_hex(&a.value));
        assert_eq!(a.sha256_hex.len(), 64);
        // The prefix check in migration 358.
        let re = regex::Regex::new("^nit_[A-Za-z0-9]{8}$").unwrap();
        assert!(re.is_match(&a.prefix));
    }

    #[test]
    fn debug_never_prints_the_value() {
        let token = generate_token();
        let printed = format!("{token:?}");
        assert!(!printed.contains(&token.value));
        assert!(!printed.contains(&token.sha256_hex));
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn route_key_is_the_routers_first_claim() {
        let values = vec!["apache_access".to_string(), "apache".to_string()];
        assert_eq!(route_key(Some(&values), "Apache HTTP"), "apache_access");
        assert_eq!(route_key(Some(&[]), "Apache HTTP"), "apache_http");
        assert_eq!(route_key(None, "Apache HTTP"), "apache_http");
    }

    #[test]
    fn push_capable_transports() {
        for st in ["routed", "splunk_hec", "vector", "apache_access", "http"] {
            assert!(is_push_capable(st), "{st}");
        }
        for st in ["otlp", "opentelemetry", "kafka", "aws_s3", "s3", "gcp_pubsub", "azure_event_hubs"] {
            assert!(!is_push_capable(st), "{st}");
        }
    }

    #[test]
    fn platform_pull_token_is_derived_and_distinct() {
        assert_eq!(platform_pull_token(""), None);
        assert_eq!(platform_pull_token("  "), None);
        let a = platform_pull_token("install-token-a").unwrap();
        assert!(a.starts_with(PLATFORM_PULL_MARKER));
        assert_eq!(a.len(), PLATFORM_PULL_MARKER.len() + 64);
        assert_eq!(platform_pull_token("install-token-a").unwrap(), a);
        assert_ne!(platform_pull_token("install-token-b").unwrap(), a);
        assert_ne!(a, "install-token-a");
        assert_ne!(INSTALL_CREDENTIAL_ID, PLATFORM_PULL_CREDENTIAL_ID);
    }

    #[test]
    fn names_are_validated() {
        assert_eq!(normalize_name("  firewall-01 ").unwrap(), "firewall-01");
        assert!(normalize_name("").is_err());
        assert!(normalize_name("   ").is_err());
        assert!(normalize_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(normalize_name("bad\nname").is_err());
    }
}

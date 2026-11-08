// SPDX-License-Identifier: AGPL-3.0-or-later
//! Validated key configuration. Never derive Debug for secret-bearing types.
//!
//! Port of main's NAN-4401 CP2a ring with two clickhouse/dev compatibility
//! rules (NAN-4933: "existing single-key installs keep decrypting with no
//! manual step"):
//!
//! - a 16–31 byte plain key (accepted by every earlier dev release, zero
//!   padded) stays accepted as `legacy-0`, with a warning to rotate;
//! - `legacy_decrypt_ids` may be omitted, meaning "every non-active key", so
//!   the common rotation config (new active + old key) cannot silently strand
//!   the old ciphertext by forgetting the list.
use super::CryptoError;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

const MAX_CONFIG_BYTES: usize = 65536;
const MAX_KEYS: usize = 32;
/// Immutable id of the root imported from a pre-ring single key.
pub const LEGACY_ID: &str = "legacy-0";

/// Status/CLI text for a short pre-ring key (never contains key material).
pub const SHORT_KEY_WARNING: &str = "this key came from a NANOSIEM_ENCRYPTION_KEY shorter than 32 bytes \
     (zero padded, weaker than policy); rotate to a generated 32-byte key \
     (openssl rand -base64 32) and retire it";

pub(super) struct KeyRing {
    pub active: String,
    pub keys: BTreeMap<String, Zeroizing<[u8; 32]>>,
    /// Unmarked-ciphertext decrypt candidates other than the active key.
    pub legacy: Vec<String>,
    /// Ids whose material came from a pre-ring key shorter than 32 bytes
    /// (zero padded). Accepted for existing installs; reported as a warning.
    pub short: BTreeSet<String>,
}

/// How a ring key may be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// Encrypts every new write.
    Active,
    /// Decrypts existing ciphertext; never encrypts.
    DecryptOnly,
    /// Only opens v2 envelopes that name it (not a legacy decrypt candidate).
    V2Only,
}

/// Non-secret description of a ring key.
#[derive(Clone, Debug, serde::Serialize, utoipa::ToSchema)]
pub struct RingKeyInfo {
    pub id: String,
    pub role: KeyRole,
    /// First 16 hex chars of HMAC-SHA256(root, fixed domain). Identifies the
    /// material behind an id (detects id reuse) without revealing it; anyone
    /// able to verify a guess with this could already do so with a stored
    /// ciphertext's GCM tag.
    pub fingerprint: String,
    /// Set when this key is weaker than policy (a pre-ring key shorter than
    /// 32 bytes): shown by the status endpoint and CLI, not only logged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    active: String,
    keys: Vec<Entry>,
    #[serde(default)]
    legacy_decrypt_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    key: Option<String>,
    legacy: Option<String>,
}
impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
        if let Some(key) = &mut self.legacy {
            key.zeroize();
        }
    }
}

fn invalid(message: &'static str) -> CryptoError {
    CryptoError::Configuration(message)
}

pub(super) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Historical interpretation: first 32 UTF-8 bytes, zero padded. NOT hex.
fn old_bytes(input: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0; 32]);
    let length = input.len().min(32);
    out[..length].copy_from_slice(&input[..length]);
    out
}

const PUBLIC_VALUES: [&str; 4] = [
    "nanosiem-default-key-32bytes!!",
    "CHANGE_ME",
    "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32",
    "your-encryption-key-change-in-production",
];

fn public_material(key: &[u8; 32]) -> bool {
    key.iter().all(|b| *b == 0)
        || key.starts_with(b"nanosiem-default-key-32bytes!!")
        || PUBLIC_VALUES
            .iter()
            .any(|value| old_bytes(value.as_bytes()).as_ref() == key)
}

/// Whether a plain configuration string resolves to known public material.
pub(super) fn is_public_plain(value: &str) -> bool {
    public_material(&old_bytes(value.as_bytes()))
}

fn fingerprint(key: &[u8; 32]) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    mac.update(b"nano.credential-key.fingerprint.v1");
    hex::encode(&mac.finalize().into_bytes()[..8])
}

impl KeyRing {
    pub(super) fn selected(id: &str, root: &[u8]) -> Result<Self, CryptoError> {
        if !valid_id(id) {
            return Err(CryptoError::InvalidEnvelope);
        }
        let mut ring = Self::raw(root)?;
        let key = ring
            .keys
            .remove(LEGACY_ID)
            .ok_or(CryptoError::InvalidEnvelope)?;
        ring.active = id.into();
        ring.keys.insert(id.into(), key);
        ring.legacy.clear();
        Ok(ring)
    }

    /// Exactly 32 bytes, refusing public material.
    pub fn raw(key: &[u8]) -> Result<Self, CryptoError> {
        let key: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidKeyLength)?;
        if public_material(&key) {
            return Err(invalid("public/default material cannot be an active root"));
        }
        Ok(Self::single(Zeroizing::new(key)))
    }

    /// Historical pad/truncate with no policy check. Only for the raw test
    /// constructor and the gated public development key.
    pub(super) fn raw_unchecked(key: &[u8]) -> Self {
        Self::single(old_bytes(key))
    }

    fn single(key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            active: LEGACY_ID.into(),
            keys: BTreeMap::from([(LEGACY_ID.into(), key)]),
            legacy: Vec::new(),
            short: BTreeSet::new(),
        }
    }

    pub(super) fn active_key(&self) -> &Zeroizing<[u8; 32]> {
        &self.keys[&self.active]
    }

    /// Active key first, then the explicit legacy candidates.
    pub(super) fn decrypt_candidates(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.active).chain(self.legacy.iter().filter(|id| **id != self.active))
    }

    pub(super) fn describe(&self) -> Vec<RingKeyInfo> {
        self.keys
            .iter()
            .map(|(id, key)| RingKeyInfo {
                id: id.clone(),
                role: if *id == self.active {
                    KeyRole::Active
                } else if self.legacy.contains(id) {
                    KeyRole::DecryptOnly
                } else {
                    KeyRole::V2Only
                },
                fingerprint: fingerprint(key),
                warning: self.short.contains(id).then(|| SHORT_KEY_WARNING.to_string()),
            })
            .collect()
    }

    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        if input.is_empty() {
            return Err(invalid("missing or oversized NANOSIEM_ENCRYPTION_KEY"));
        }
        if !input.trim_start().starts_with('{') {
            if input.len() < 16 {
                return Err(invalid("legacy key must contain at least 16 UTF-8 bytes"));
            }
            if is_public_plain(input) {
                return Err(invalid(
                    "NANOSIEM_ENCRYPTION_KEY is a public placeholder; configure a generated key \
                     (keep the old value as a decrypt-only legacy-0 ring entry to read old data)",
                ));
            }
            if input.len() < 32 {
                // Earlier dev releases accepted (and zero padded) 16-31 byte
                // keys. Keep reading/writing with it; rotation moves off it.
                tracing::warn!(
                    "SECURITY WARNING: NANOSIEM_ENCRYPTION_KEY is shorter than 32 bytes; rotate \
                     to a generated 32-byte ring key (see docs: credential key rotation)"
                );
            }
            // Permanent compatibility: this was ASCII/UTF-8 truncation, NOT hex decoding.
            let mut ring = Self::single(old_bytes(input.as_bytes()));
            if input.len() < 32 {
                ring.short.insert(LEGACY_ID.into());
            }
            return Ok(ring);
        }
        if input.len() > MAX_CONFIG_BYTES {
            return Err(invalid("oversized credential ring JSON"));
        }
        let config: Config = serde_json::from_str(input).map_err(|_| {
            invalid("invalid credential ring JSON (version, active, keys required)")
        })?;
        if config.version != 1
            || config.keys.is_empty()
            || config.keys.len() > MAX_KEYS
            || !valid_id(&config.active)
        {
            return Err(invalid("unsupported or invalid credential ring"));
        }
        // Omitted list = every non-active key decrypts (dev rotation default).
        let listed: Vec<String> = match &config.legacy_decrypt_ids {
            Some(ids) => ids.clone(),
            None => config
                .keys
                .iter()
                .map(|entry| entry.id.clone())
                .filter(|id| *id != config.active)
                .collect(),
        };
        let legacy: BTreeSet<_> = listed.iter().cloned().collect();
        if legacy.len() != listed.len() || legacy.len() > MAX_KEYS {
            return Err(invalid("duplicate or excessive legacy decrypt ids"));
        }
        let mut keys = BTreeMap::new();
        let mut short_ids = BTreeSet::new();
        let mut public = false;
        for entry in &config.keys {
            if !valid_id(&entry.id) || keys.contains_key(&entry.id) {
                return Err(invalid("invalid or duplicate credential key id"));
            }
            if entry.legacy.is_some() && entry.id != LEGACY_ID {
                return Err(invalid("historical legacy imports must retain the immutable id legacy-0"));
            }
            let (key, short) = match (&entry.key, &entry.legacy) {
                (Some(encoded), None) => {
                    let bytes = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| invalid("ring root must be standard base64 encoding exactly 32 bytes"))?);
                    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| invalid("a ring key must be exactly 32 bytes (standard base64 of 32 random bytes, e.g. `openssl rand -base64 32`); shorter keys are accepted only as the pre-ring legacy-0 import"))?;
                    (Zeroizing::new(key), false)
                }
                (None, Some(value)) if value.len() >= 16 => (old_bytes(value.as_bytes()), value.len() < 32),
                _ => return Err(invalid("each ring entry requires exactly one 32-byte base64 key or legacy string of at least 16 UTF-8 bytes")),
            };
            let known_public = public_material(&key);
            if (short || known_public) && (entry.id == config.active || !legacy.contains(&entry.id))
            {
                return Err(invalid("short/public legacy material must be an explicit decrypt-only legacy entry; configure a new valid active root"));
            }
            public |= known_public;
            if short {
                short_ids.insert(entry.id.clone());
            }
            keys.insert(entry.id.clone(), key);
        }
        if !keys.contains_key(&config.active) || legacy.iter().any(|id| !keys.contains_key(id)) {
            return Err(invalid("active or legacy decrypt id is absent from ring"));
        }
        if public {
            tracing::warn!("SECURITY WARNING: PUBLIC DEFAULT credential key remains as explicit decrypt-only material; old data is insecure; let the re-wrap finish, then retire it");
        }
        let mut seen = BTreeSet::new();
        for (id, key) in &keys {
            if !seen.insert(fingerprint(key)) {
                tracing::warn!(key_id = %id, "credential ring lists the same key material under two ids");
            }
        }
        Ok(Self {
            active: config.active,
            keys,
            legacy: listed,
            short: short_ids,
        })
    }
}

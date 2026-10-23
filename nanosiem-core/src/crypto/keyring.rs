//! Validated key configuration. Never derive Debug for secret-bearing types.
use super::CryptoError;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

const MAX_CONFIG_BYTES: usize = 65536;
const MAX_KEYS: usize = 32;
pub(super) const LEGACY_ID: &str = "legacy-0";

pub(super) struct KeyRing {
    pub active: String,
    pub keys: BTreeMap<String, Zeroizing<[u8; 32]>>,
    pub legacy: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    active: String,
    keys: Vec<Entry>,
    legacy_decrypt_ids: Vec<String>,
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

fn old_bytes(input: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0; 32]);
    let length = input.len().min(32);
    out[..length].copy_from_slice(&input[..length]);
    out
}

fn public_material(key: &[u8; 32]) -> bool {
    key.iter().all(|b| *b == 0)
        || key.starts_with(b"nanosiem-default-key-32bytes!!")
        || [
            "nanosiem-default-key-32bytes!!",
            "CHANGE_ME",
            "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32",
            "your-encryption-key-change-in-production",
        ]
        .iter()
        .any(|value| old_bytes(value.as_bytes()).as_ref() == key)
}

impl KeyRing {
    pub fn raw(key: &[u8]) -> Result<Self, CryptoError> {
        let key: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidKeyLength)?;
        if public_material(&key) {
            return Err(invalid("public/default material cannot be an active root"));
        }
        Ok(Self {
            active: LEGACY_ID.into(),
            keys: BTreeMap::from([(LEGACY_ID.into(), Zeroizing::new(key))]),
            legacy: vec![LEGACY_ID.into()],
        })
    }

    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        if input.is_empty() {
            return Err(invalid("missing or oversized NANOSIEM_ENCRYPTION_KEY"));
        }
        if !input.trim_start().starts_with('{') {
            if input.len() < 16 {
                return Err(invalid("legacy key must contain at least 16 UTF-8 bytes"));
            }
            if input.len() < 32 {
                return Err(invalid("convert NANOSIEM_ENCRYPTION_KEY to ring JSON with a new valid active root and the old string in a decrypt-only legacy entry"));
            }
            // Permanent compatibility: this was ASCII/UTF-8 truncation, NOT hex decoding.
            return Self::raw(old_bytes(input.as_bytes()).as_ref());
        }
        if input.len() > MAX_CONFIG_BYTES {
            return Err(invalid("oversized credential ring JSON"));
        }
        let config: Config = serde_json::from_str(input).map_err(|_| {
            invalid(
                "invalid credential ring JSON (version, active, keys, legacy_decrypt_ids required)",
            )
        })?;
        if config.version != 1
            || config.keys.is_empty()
            || config.keys.len() > MAX_KEYS
            || !valid_id(&config.active)
        {
            return Err(invalid("unsupported or invalid credential ring"));
        }
        let legacy: BTreeSet<_> = config.legacy_decrypt_ids.iter().cloned().collect();
        if legacy.len() != config.legacy_decrypt_ids.len() || legacy.len() > MAX_KEYS {
            return Err(invalid("duplicate or excessive legacy decrypt ids"));
        }
        let mut keys = BTreeMap::new();
        let mut public = false;
        for entry in &config.keys {
            if !valid_id(&entry.id) || keys.contains_key(&entry.id) {
                return Err(invalid("invalid or duplicate credential key id"));
            }
            if entry.legacy.is_some() && entry.id != LEGACY_ID {
                return Err(invalid("historical legacy imports must retain the immutable id legacy-0 for artifact signature verification"));
            }
            let (key, short) = match (&entry.key, &entry.legacy) {
                (Some(encoded), None) => {
                    let bytes = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| invalid("ring root must be standard base64 encoding exactly 32 bytes"))?);
                    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| CryptoError::InvalidKeyLength)?;
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
            keys.insert(entry.id.clone(), key);
        }
        if !keys.contains_key(&config.active) || legacy.iter().any(|id| !keys.contains_key(id)) {
            return Err(invalid("active or legacy decrypt id is absent from ring"));
        }
        if public {
            tracing::warn!("SECURITY WARNING: PUBLIC DEFAULT credential key remains as explicit decrypt-only material; old data is insecure; rotate all pending legacy rows before removing it");
        }
        // This release still emits unmarked ciphertext under its active root.
        let mut legacy = config.legacy_decrypt_ids;
        if !legacy.contains(&config.active) {
            legacy.push(config.active.clone());
        }
        Ok(Self {
            active: config.active,
            keys,
            legacy,
        })
    }
}

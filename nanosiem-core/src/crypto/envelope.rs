//! Versioned bytes survive B/J/T serializers that retain only ciphertext and nonce.
use super::{CryptoError, EncryptedData};
use base64::{engine::general_purpose::STANDARD, Engine};
use uuid::Uuid;

pub const V2_NONCE_PREFIX: &str = "nck2:";
const MAGIC: &[u8] = b"NCK\x02\x01"; // version 2, AES-256-GCM

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialScope {
    Tenant(Uuid),
    Account(Uuid),
    Deployment,
    Platform,
}

/// Created by the caller from trusted identity; never reconstructed from ciphertext.
#[derive(Clone)]
pub struct CredentialContext {
    pub scope: CredentialScope,
    pub purpose: &'static str,
    pub row: String,
}
impl CredentialContext {
    pub fn new(scope: CredentialScope, purpose: &'static str, row: impl ToString) -> Self {
        Self {
            scope,
            purpose,
            row: row.to_string(),
        }
    }
    pub(super) fn info(&self) -> Result<Vec<u8>, CryptoError> {
        let (kind, id) = match self.scope {
            CredentialScope::Tenant(id) => (b"tenant".as_slice(), Some(id)),
            CredentialScope::Account(id) => (b"account".as_slice(), Some(id)),
            CredentialScope::Deployment => (b"deployment".as_slice(), None),
            CredentialScope::Platform => (b"platform".as_slice(), None),
        };
        if id.is_some_and(|id| id.is_nil())
            || self.purpose.is_empty()
            || self.purpose.len() > 128
            || self.row.is_empty()
            || self.row.len() > 512
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        let mut out = Vec::new();
        field(&mut out, kind);
        field(
            &mut out,
            id.as_ref()
                .map(|id| id.as_bytes().as_slice())
                .unwrap_or_default(),
        );
        field(&mut out, self.purpose.as_bytes());
        Ok(out)
    }
    pub(super) fn aad(&self, header: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = self.info()?;
        field(&mut out, header);
        field(&mut out, self.row.as_bytes());
        Ok(out)
    }
}
fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub(super) fn header(id: &str) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.push(id.len() as u8);
    out.extend_from_slice(id.as_bytes());
    out
}
pub(super) fn parse(bytes: &[u8]) -> Result<(&str, &[u8], &[u8]), CryptoError> {
    if bytes.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(CryptoError::InvalidEnvelope);
    }
    let length = *bytes.get(MAGIC.len()).ok_or(CryptoError::InvalidEnvelope)? as usize;
    let end = MAGIC.len() + 1 + length;
    if length == 0 || length > 64 || bytes.len() < end + 16 {
        return Err(CryptoError::InvalidEnvelope);
    }
    let id = std::str::from_utf8(&bytes[MAGIC.len() + 1..end])
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    if !super::keyring::valid_id(id) {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok((id, &bytes[..end], &bytes[end..]))
}

impl EncryptedData {
    pub fn from_bytea(ciphertext: &[u8], nonce: &str) -> Self {
        Self {
            ciphertext: STANDARD.encode(ciphertext),
            nonce: nonce.into(),
        }
    }
    pub fn to_bytea(&self) -> Result<(Vec<u8>, String), CryptoError> {
        Ok((
            STANDARD
                .decode(&self.ciphertext)
                .map_err(|_| CryptoError::InvalidEnvelope)?,
            self.nonce.clone(),
        ))
    }
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        serde_json::from_slice(bytes).map_err(|_| CryptoError::InvalidEnvelope)
    }
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        serde_json::to_vec(self).map_err(|_| CryptoError::InvalidEnvelope)
    }
    pub fn from_text_bytea(ciphertext: &[u8], nonce: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            ciphertext: std::str::from_utf8(ciphertext)
                .map_err(|_| CryptoError::InvalidEnvelope)?
                .into(),
            nonce: nonce.into(),
        })
    }
    /// D's SQL version column is authoritative; do not guess from random legacy bytes.
    pub fn from_raw_nonce(
        ciphertext: &[u8],
        nonce: &[u8],
        version: i16,
    ) -> Result<Self, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonce);
        }
        let encoded = STANDARD.encode(nonce);
        let nonce = match version {
            1 => encoded,
            2 => format!("{V2_NONCE_PREFIX}{encoded}"),
            _ => return Err(CryptoError::InvalidEnvelope),
        };
        Ok(Self::from_bytea(ciphertext, &nonce))
    }
    pub fn to_raw_nonce(&self) -> Result<(Vec<u8>, Vec<u8>, i16), CryptoError> {
        let (nonce, version) = match self.nonce.strip_prefix(V2_NONCE_PREFIX) {
            Some(nonce) => (nonce, 2),
            None => (self.nonce.as_str(), 1),
        };
        let raw = STANDARD
            .decode(nonce)
            .map_err(|_| CryptoError::InvalidNonce)?;
        if raw.len() != 12 {
            return Err(CryptoError::InvalidNonce);
        }
        Ok((self.to_bytea()?.0, raw, version))
    }
}

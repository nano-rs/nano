// SPDX-License-Identifier: AGPL-3.0-or-later
//! A selected, validated key for contextual v2 reads. No legacy probe or writer.
use super::{keyring, CredentialScope, CryptoError, EncryptedData, EncryptionService};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Header inspection is not authentication. Always decrypt with trusted context.
/// The strict format gate runs before a customer authority unwraps any root.
pub fn v2_key_id(value: &EncryptedData) -> Result<String, CryptoError> {
    if value.ciphertext.len().saturating_add(value.nonce.len()) > 2 * 1024 * 1024 {
        return Err(CryptoError::InvalidEnvelope);
    }
    let nonce = value
        .nonce
        .strip_prefix(super::envelope::V2_NONCE_PREFIX)
        .ok_or(CryptoError::InvalidEnvelope)?;
    super::decode_nonce(nonce)?;
    let bytes = STANDARD
        .decode(&value.ciphertext)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let (id, _, _) = super::envelope::parse(&bytes)?;
    Ok(id.to_owned())
}

pub struct V2CredentialReader {
    service: EncryptionService,
}
impl V2CredentialReader {
    /// Use the same root/ID validation as the upstream ring. The ring contains
    /// exactly this selected key, and exposes neither legacy reads nor writes.
    pub fn from_root(id: &str, root: &[u8]) -> Result<Self, CryptoError> {
        let ring = keyring::KeyRing::selected(id, root)?;
        Ok(Self {
            service: EncryptionService {
                ring: Arc::new(ring),
                context: None,
            },
        })
    }
    pub fn open(
        &self,
        scope: CredentialScope,
        purpose: &'static str,
        row: &str,
        value: &EncryptedData,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if v2_key_id(value)? != self.service.active_key_id() {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(Zeroizing::new(
            self.service
                .with_context(scope, purpose, row)
                .decrypt(value)?,
        ))
    }
}

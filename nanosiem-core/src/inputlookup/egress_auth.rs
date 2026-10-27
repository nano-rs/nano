// SPDX-License-Identifier: AGPL-3.0-or-later
//! Short-lived CONNECT capabilities. Tokens deliberately have no Debug representation.
//!
//! One HMAC construction, domain-separated by purpose (NAN-4369). Each purpose
//! signs a distinct message prefix AND is deployed with its own key, so an
//! inputlookup token can never authorize a SOAR tunnel or the reverse.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;

/// What a CONNECT capability is for. Every field of the purpose is signed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EgressPurpose {
    /// Shared inputlookup URL fetches: `v1|tenant|host|exp` (unchanged wire form).
    InputLookup,
    /// A native SOAR vendor call for one tenant connection at one revision:
    /// `soar-v1|tenant|connection|revision|host|exp`.
    Soar { connection: Uuid, revision: i64 },
    SoarSmtp {
        connection: Uuid,
        revision: i64,
        port: u16,
    },
}

impl EgressPurpose {
    fn message(self, tenant: Uuid, host: &str, exp: i64) -> Option<String> {
        match self {
            Self::InputLookup => Some(format!("v1|{tenant}|{host}|{exp}")),
            Self::Soar { connection, revision } if !connection.is_nil() && revision >= 0 => Some(
                format!("soar-v1|{tenant}|{connection}|{revision}|{host}|{exp}"),
            ),
            Self::Soar { .. } => None,
            Self::SoarSmtp {
                connection,
                revision,
                port,
            } if !connection.is_nil() && revision > 0 && port > 0 => Some(format!(
                "soar-smtp-v1|{tenant}|{connection}|{revision}|{host}|{port}|{exp}"
            )),
            Self::SoarSmtp { .. } => None,
        }
    }
}

pub fn sign(key: &[u8], tenant: Uuid, host: &str, exp: i64) -> Option<String> {
    sign_for(key, EgressPurpose::InputLookup, tenant, host, exp)
}

pub fn verify(key: &[u8], tenant: Uuid, host: &str, token: &str, exp: i64, now: i64) -> bool {
    verify_for(key, EgressPurpose::InputLookup, tenant, host, token, exp, now)
}

pub fn sign_for(
    key: &[u8],
    purpose: EgressPurpose,
    tenant: Uuid,
    host: &str,
    exp: i64,
) -> Option<String> {
    if key.len() < 32 || tenant.is_nil() {
        return None;
    }
    let message = purpose.message(tenant, host, exp)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(message.as_bytes());
    Some(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub fn verify_for(
    key: &[u8],
    purpose: EgressPurpose,
    tenant: Uuid,
    host: &str,
    token: &str,
    exp: i64,
    now: i64,
) -> bool {
    if key.len() < 32
        || tenant.is_nil()
        || exp <= now
        || exp > now.saturating_add(60)
        || token.len() > 64
        || super::storage_policy::normalize_entry(host).ok().as_deref() != Some(host)
        || host.starts_with("*.")
    {
        return false;
    }
    let Some(message) = purpose.message(tenant, host, exp) else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(token) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return false;
    };
    mac.update(message.as_bytes());
    mac.verify_slice(&bytes).is_ok()
}

/// Constant-time comparison for the separate helper service credential.
pub fn service_token_matches(expected: &[u8], supplied: &[u8]) -> bool {
    if expected.len() < 32 {
        return false;
    }
    // HMAC verification avoids length-dependent comparisons of secret bytes.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(expected) else {
        return false;
    };
    mac.update(b"inputlookup-helper-auth");
    let digest = mac.finalize().into_bytes();
    let Ok(mut candidate) = Hmac::<Sha256>::new_from_slice(supplied) else {
        return false;
    };
    candidate.update(b"inputlookup-helper-auth");
    candidate.verify_slice(&digest).is_ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn smtp_tokens_bind_exact_port_and_cannot_authorize_https_or_another_tenant() {
        use super::*;
        let key = [0x42; 32];
        let tenant = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let purpose = EgressPurpose::SoarSmtp { connection, revision: 1, port: 587 };
        let token = sign_for(&key,purpose,tenant,"smtp.example.com",1050).unwrap();
        assert!(verify_for(&key,purpose,tenant,"smtp.example.com",&token,1050,1000));
        for other in [EgressPurpose::SoarSmtp { connection,revision:1,port:465 }, EgressPurpose::SoarSmtp { connection,revision:2,port:587 }, EgressPurpose::Soar { connection,revision:1 }, EgressPurpose::InputLookup] {
            assert!(!verify_for(&key,other,tenant,"smtp.example.com",&token,1050,1000));
        }
        assert!(!verify_for(&key,purpose,Uuid::new_v4(),"smtp.example.com",&token,1050,1000));
        assert!(!verify_for(&key,purpose,tenant,"other.example.com",&token,1050,1000));
        assert!(!verify_for(&key,purpose,tenant,"smtp.example.com",&token,1050,1050));
    }
    use super::*;
    #[test]
    fn capability_binds_tenant_host_and_replay_window() {
        let key = [42; 32];
        let tenant = Uuid::new_v4();
        let token = sign(&key, tenant, "feeds.example.com", 1060).unwrap();
        assert!(verify(
            &key,
            tenant,
            "feeds.example.com",
            &token,
            1060,
            1000
        ));
        assert!(verify(
            &key,
            tenant,
            "feeds.example.com",
            &token,
            1060,
            1059
        ));
        for now in [999, 1060, 1061] {
            assert!(!verify(
                &key,
                tenant,
                "feeds.example.com",
                &token,
                1060,
                now
            ));
        }
        assert!(!verify(
            &key,
            Uuid::new_v4(),
            "feeds.example.com",
            &token,
            1060,
            1000
        ));
        assert!(!verify(
            &key,
            tenant,
            "other.example.com",
            &token,
            1060,
            1000
        ));
        assert!(!verify(
            &[43; 32],
            tenant,
            "feeds.example.com",
            &token,
            1060,
            1000
        ));
        assert!(!verify(
            &key,
            tenant,
            "feeds.example.com",
            &token,
            1059,
            1000
        ));
        assert!(service_token_matches(&key, &key));
        assert!(!service_token_matches(&key, &[43; 32]));
    }

    #[test]
    fn soar_capability_binds_connection_revision_and_is_domain_separated() {
        let key = [42; 32];
        let tenant = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let soar = EgressPurpose::Soar { connection, revision: 3 };
        let token = sign_for(&key, soar, tenant, "acme.okta.com", 1060).unwrap();
        assert!(verify_for(&key, soar, tenant, "acme.okta.com", &token, 1060, 1000));
        // Another revision, connection, tenant or host: denied.
        for other in [
            EgressPurpose::Soar { connection, revision: 4 },
            EgressPurpose::Soar { connection: Uuid::new_v4(), revision: 3 },
        ] {
            assert!(!verify_for(&key, other, tenant, "acme.okta.com", &token, 1060, 1000));
        }
        assert!(!verify_for(&key, soar, Uuid::new_v4(), "acme.okta.com", &token, 1060, 1000));
        assert!(!verify_for(&key, soar, tenant, "evil.okta.com", &token, 1060, 1000));
        // Expired, or too far in the future: denied.
        assert!(!verify_for(&key, soar, tenant, "acme.okta.com", &token, 1060, 1060));
        assert!(!verify_for(&key, soar, tenant, "acme.okta.com", &token, 1060, 999));
        // Domain separation: neither purpose's token verifies as the other,
        // even under the same key.
        assert!(!verify(&key, tenant, "acme.okta.com", &token, 1060, 1000));
        let lookup = sign(&key, tenant, "acme.okta.com", 1060).unwrap();
        assert!(!verify_for(&key, soar, tenant, "acme.okta.com", &lookup, 1060, 1000));
        // A nil connection or a negative revision never signs.
        assert!(sign_for(&key, EgressPurpose::Soar { connection: Uuid::nil(), revision: 1 }, tenant, "acme.okta.com", 1060).is_none());
        assert!(sign_for(&key, EgressPurpose::Soar { connection, revision: -1 }, tenant, "acme.okta.com", 1060).is_none());
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Short-lived CONNECT capabilities. Tokens deliberately have no Debug representation.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;

pub fn sign(key: &[u8], tenant: Uuid, host: &str, exp: i64) -> Option<String> {
    if key.len() < 32 || tenant.is_nil() {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(format!("v1|{tenant}|{host}|{exp}").as_bytes());
    Some(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub fn verify(key: &[u8], tenant: Uuid, host: &str, token: &str, exp: i64, now: i64) -> bool {
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
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(token) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return false;
    };
    mac.update(format!("v1|{tenant}|{host}|{exp}").as_bytes());
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
}

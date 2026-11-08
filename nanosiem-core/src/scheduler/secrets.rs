// SPDX-License-Identifier: AGPL-3.0-or-later

//! Secret handling for scheduled-job auth headers (NAN-1358).
//!
//! `ScheduledJob.auth_headers` can hold credentials for the remote ingestion
//! source (e.g. an `Authorization` bearer). Two rules:
//!
//! 1. **Never return them in cleartext** in an API response — values are masked
//!    with the shared [`REDACTED_PLACEHOLDER`].
//! 2. A write that echoes the placeholder back (or omits headers entirely) must
//!    **preserve** the stored secret, not overwrite it — so a read-modify-write
//!    round-trip (any client, including a stale frontend) can't wipe credentials
//!    and break ingestion.

use std::collections::HashMap;

/// Placeholder substituted for secret auth-header values in API responses.
///
/// Re-exported from [`crate::config_secrets`], the canonical definition shared
/// with the config-JSON redactor (NAN-2067/2068/2069) and the Vector-config
/// snapshot redactor, so the masking UX — and the sentinel clients echo back on
/// a read-modify-write — cannot drift between surfaces.
pub use crate::config_secrets::REDACTED_PLACEHOLDER;

/// Mask every auth-header value with [`REDACTED_PLACEHOLDER`], in place, before
/// the owning job is serialized into an API response. Keys are preserved so
/// callers can see *which* headers are configured without learning their values.
/// Call as `redact_auth_headers(&mut job.auth_headers)`.
pub fn redact_auth_headers(headers: &mut Option<HashMap<String, String>>) {
    if let Some(headers) = headers.as_mut() {
        for value in headers.values_mut() {
            *value = REDACTED_PLACEHOLDER.to_string();
        }
    }
}

/// Resolve the auth headers an upsert should persist, given the request's
/// `incoming` headers and the currently `existing` stored headers.
///
/// The result maps onto `UpdateScheduledJob.auth_headers`
/// (`Option<Option<HashMap<..>>>`):
/// - `None`               → leave stored headers unchanged (request omitted them);
/// - `Some(Some(merged))` → replace stored headers with `merged`.
///
/// When `incoming` is present, each entry is resolved as:
/// - value == [`REDACTED_PLACEHOLDER`] → keep the stored value for that key
///   (the client echoed a masked header back), or drop it if nothing is stored;
/// - any other value → a new/updated secret;
/// - keys absent from `incoming` → dropped;
/// - an empty map → clears all headers.
pub fn merge_auth_headers(
    incoming: Option<HashMap<String, String>>,
    existing: Option<&HashMap<String, String>>,
) -> Option<Option<HashMap<String, String>>> {
    let incoming = match incoming {
        // Request didn't include auth_headers → preserve whatever is stored.
        None => return None,
        Some(map) => map,
    };

    let mut merged = HashMap::with_capacity(incoming.len());
    for (key, value) in incoming {
        if value == REDACTED_PLACEHOLDER {
            if let Some(stored) = existing.and_then(|e| e.get(&key)) {
                merged.insert(key, stored.clone());
            }
            // else: masked value for an unknown key — drop it (nothing to keep).
        } else {
            merged.insert(key, value);
        }
    }
    Some(Some(merged))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn redact_masks_values_keeps_keys() {
        let mut headers = Some(map(&[("Authorization", "Bearer sekret"), ("X-Api", "abc123")]));
        redact_auth_headers(&mut headers);
        let h = headers.unwrap();
        assert_eq!(h["Authorization"], REDACTED_PLACEHOLDER);
        assert_eq!(h["X-Api"], REDACTED_PLACEHOLDER);
        assert_eq!(h.len(), 2, "keys are preserved");
    }

    #[test]
    fn redact_noop_when_no_headers() {
        let mut headers: Option<HashMap<String, String>> = None;
        redact_auth_headers(&mut headers);
        assert!(headers.is_none());
    }

    #[test]
    fn merge_none_preserves_stored() {
        // Request omitted headers entirely -> leave stored unchanged.
        assert_eq!(merge_auth_headers(None, Some(&map(&[("Authorization", "real")]))), None);
    }

    #[test]
    fn merge_placeholder_keeps_stored_secret() {
        let existing = map(&[("Authorization", "Bearer real-secret")]);
        let incoming = map(&[("Authorization", REDACTED_PLACEHOLDER)]);
        let merged = merge_auth_headers(Some(incoming), Some(&existing)).unwrap().unwrap();
        assert_eq!(merged["Authorization"], "Bearer real-secret", "secret preserved on round-trip");
    }

    #[test]
    fn merge_real_value_updates_and_drops_missing_keys() {
        let existing = map(&[("Authorization", "old"), ("X-Old", "gone")]);
        let incoming = map(&[("Authorization", "new-secret")]);
        let merged = merge_auth_headers(Some(incoming), Some(&existing)).unwrap().unwrap();
        assert_eq!(merged["Authorization"], "new-secret", "real value updates");
        assert!(!merged.contains_key("X-Old"), "key absent from request is dropped");
    }

    #[test]
    fn merge_empty_map_clears() {
        let existing = map(&[("Authorization", "real")]);
        let merged = merge_auth_headers(Some(HashMap::new()), Some(&existing)).unwrap().unwrap();
        assert!(merged.is_empty(), "empty map clears all headers");
    }

    #[test]
    fn merge_placeholder_for_unknown_key_is_dropped() {
        let incoming = map(&[("X-Ghost", REDACTED_PLACEHOLDER)]);
        let merged = merge_auth_headers(Some(incoming), None).unwrap().unwrap();
        assert!(merged.is_empty(), "masked value with no stored secret is dropped");
    }
}

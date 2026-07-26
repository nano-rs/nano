// SPDX-License-Identifier: AGPL-3.0-or-later

//! Secret redaction and round-trip-safe merge for admin-supplied config JSON
//! (NAN-2067 / NAN-2068 / NAN-2069).
//!
//! Two current storage columns accept free-form JSON that legitimately carry
//! operational secrets, and both were serialized verbatim to any principal
//! holding the corresponding read-only `*:view` capability:
//!
//! - `source_configurations.connection_config` (NAN-2067) — Kafka SASL
//!   passwords, AWS secret access keys / session tokens;
//! - custom-enrichment `config.auth_config` (NAN-2069) — bearer tokens, API
//!   keys, basic-auth passwords, OAuth client secrets.
//!
//! The retired `log_sources.source_config` column was also protected here
//! until migration 271 moved any remaining transport configuration into
//! `source_configurations` and removed the column.
//!
//! This module is the single policy point for two paired operations:
//!
//! 1. [`redact_config_secrets`] masks secret values before serialization, so a
//!    `*:view` holder learns *which* secrets are configured but not their
//!    values.
//! 2. [`merge_config_secrets`] resolves a write against the stored row so a
//!    read-modify-write round-trip — any client, including a stale frontend
//!    that echoes the mask straight back — cannot wipe a stored credential and
//!    break ingestion. This is the failure mode NAN-1358 hit on scheduled-job
//!    auth headers; [`crate::scheduler::secrets`] solves the same problem for
//!    the flat `HashMap` shape and shares this placeholder.
//!
//! **Both halves are required.** Redacting reads without merging writes
//! converts a disclosure bug into a data-loss bug.
//!
//! ## Write contract for a secret-bearing key
//!
//! | incoming value           | result                       |
//! |--------------------------|------------------------------|
//! | key absent               | secret cleared               |
//! | [`REDACTED_PLACEHOLDER`] | stored value preserved       |
//! | JSON `null`              | secret cleared               |
//! | any other value          | secret replaced              |
//!
//! This mirrors [`crate::scheduler::secrets::merge_auth_headers`] exactly:
//! preservation is driven by the client **echoing the placeholder back**, not
//! by omission. That matters because real clients clear a secret *by omitting
//! it* — `TlsConfigSection.handleClear` sets `key_content` to `undefined`, and
//! `SourceConfigurationDetail` sends `{}` to purge legacy HEC `valid_tokens`.
//! Treating omission as "preserve" would silently defeat both.
//!
//! The round-trip is still safe because every redacted read carries the
//! placeholder, so a read-modify-write echoes it back and the secret survives.
//! Note the distinction from a *field-level* omission: when a request omits
//! `connection_config` entirely, the caller never reaches
//! this function and the stored column is untouched.
//!
//! Non-secret keys use ordinary replace semantics.
//!
//! ## `_credentials` is different
//!
//! The subtree is not client-authored, so an incoming one is always ignored.
//! It remains protected because migration 271 deliberately preserves legacy
//! transport JSON while moving it into `source_configurations`. An explicit
//! `null` still clears it.

use crate::config_safety::MAX_CONFIG_DEPTH;
use serde_json::Value;

/// Marker substituted for secret values in API responses.
///
/// Canonical definition — [`crate::scheduler::secrets`] and
/// [`crate::parsers::vector_config::redaction`] re-export this so the masking
/// UX (and the round-trip sentinel clients echo back) cannot drift.
pub const REDACTED_PLACEHOLDER: &str = "***REDACTED***";

/// Object keys whose values are bearer secrets and must never reach an API
/// response.
///
/// Grounded in the keys the Vector source generators and the enrichment
/// runtime actually read — see `parsers::vector_config::sources` (Kafka / AWS /
/// GCP) and `custom_enrichment::types::AuthConfig` (bearer / API-key / basic /
/// OAuth2) — plus common aliases so a new generator that picks a conventional
/// name is covered by default.
///
/// Deliberately EXCLUDED because they are identifiers or public material, not
/// secrets, and redacting them would break legitimate read-only inspection:
/// `access_key_id`, `username`, `sasl_username`, `client_id`, `token_url`,
/// `scope`, `header_name`, `auth_type`, and the certificate siblings of
/// `key_content` — `crt_content` (client certificate) and `ca_content` /
/// `tls_ca_cert` (CA certificate) are public by construction; only the private
/// key is secret.
pub const SECRET_CONFIG_KEYS: &[&str] = &[
    // Kafka SASL
    "sasl_password",
    // AWS
    "secret_access_key",
    "session_token",
    // GCP service-account JSON
    "credentials_json",
    // TLS client private key (`connection_config.tls.key_content`).
    "key_content",
    // Custom-enrichment AuthConfig
    "token",
    "api_key",
    "password",
    "client_secret",
    // Splunk HEC (array-valued)
    "valid_tokens",
    // Conventional aliases — defense in depth for future generators.
    "secret",
    "secret_key",
    "private_key",
    "passphrase",
    "auth_token",
    "bearer_token",
    "access_token",
    "refresh_token",
];

/// Object keys whose ENTIRE subtree is credential material, regardless of the
/// leaf key names inside it.
///
/// `_credentials` was injected by the retired log-source deploy path from the
/// encrypted credential store. Every leaf under it is secret by construction,
/// so migrated legacy data is masked wholesale rather than relying on
/// [`SECRET_CONFIG_KEYS`] covering each leaf.
///
/// **Why merge preserves a stored subtree instead of dropping it.** The
/// subtree is legacy credential material. Migration 271 preserves it in
/// `source_configurations.connection_config`, so redaction and round-trip-safe
/// merging must continue until an operator explicitly replaces or clears it.
pub const SECRET_CONFIG_SUBTREES: &[&str] = &["_credentials"];

/// True when `key` names a secret-bearing scalar value.
pub fn is_secret_config_key(key: &str) -> bool {
    SECRET_CONFIG_KEYS.contains(&key)
}

/// True when `key` names a subtree that is credential material in its entirety.
pub fn is_secret_config_subtree(key: &str) -> bool {
    SECRET_CONFIG_SUBTREES.contains(&key)
}

/// Mask every secret value in `v`, in place, before it is serialized into an
/// API response.
///
/// A JSON `null` is left as `null` so callers can still distinguish
/// "not configured" from "configured but hidden" — the `has_*` signal the
/// finding asks for, without disclosing the value. Idempotent: re-redacting
/// already-masked JSON is a no-op.
pub fn redact_config_secrets(v: &mut Value) {
    redact_inner(v, 0);
}

fn redact_inner(v: &mut Value, depth: usize) {
    if depth > MAX_CONFIG_DEPTH {
        // Refuse to walk deeper than the write-side validator allows. Anything
        // this deep could not have been stored through a validated write path;
        // mask the whole node rather than risk leaving a secret unvisited.
        *v = Value::String(REDACTED_PLACEHOLDER.to_string());
        return;
    }
    match v {
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_inner(item, depth + 1);
            }
        }
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if is_secret_config_subtree(k) {
                    mask_subtree(val, depth + 1);
                } else if is_secret_config_key(k) {
                    mask_value(val);
                } else {
                    redact_inner(val, depth + 1);
                }
            }
        }
        _ => {}
    }
}

/// Mask a single secret-keyed value, preserving `null` and array shape.
fn mask_value(v: &mut Value) {
    match v {
        // Preserve "not configured".
        Value::Null => {}
        // `valid_tokens`-style arrays: collapse to a single masked element so
        // the count is not disclosed either.
        Value::Array(_) => {
            *v = Value::Array(vec![Value::String(REDACTED_PLACEHOLDER.to_string())]);
        }
        _ => *v = Value::String(REDACTED_PLACEHOLDER.to_string()),
    }
}

/// Mask every leaf under a secret subtree, preserving the key structure so a
/// viewer can still see which credential fields are populated.
fn mask_subtree(v: &mut Value, depth: usize) {
    if depth > MAX_CONFIG_DEPTH {
        *v = Value::String(REDACTED_PLACEHOLDER.to_string());
        return;
    }
    match v {
        Value::Null => {}
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                mask_subtree(item, depth + 1);
            }
        }
        Value::Object(map) => {
            for (_, val) in map.iter_mut() {
                mask_subtree(val, depth + 1);
            }
        }
        _ => *v = Value::String(REDACTED_PLACEHOLDER.to_string()),
    }
}

/// Remove every secret-bearing key from `v` entirely, rather than masking it.
///
/// Use this for artifacts that are meant to be **shared and re-imported**, not
/// merely displayed — a marketplace export manifest, for example. Masking is
/// wrong there: the placeholder is data, so repository sync would persist
/// `***REDACTED***` verbatim and an install without an override would
/// authenticate with the literal mask (NAN-2069). Omission instead yields an
/// honest manifest — the importer supplies their own credential.
///
/// For a response a human is going to *look at*, prefer
/// [`redact_config_secrets`], which keeps the key so the reader can see which
/// secrets are configured.
pub fn strip_config_secrets(v: &mut Value) {
    strip_inner(v, 0);
}

fn strip_inner(v: &mut Value, depth: usize) {
    if depth > MAX_CONFIG_DEPTH {
        *v = Value::Null;
        return;
    }
    match v {
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                strip_inner(item, depth + 1);
            }
        }
        Value::Object(map) => {
            map.retain(|k, _| !is_secret_config_key(k) && !is_secret_config_subtree(k));
            for (_, val) in map.iter_mut() {
                strip_inner(val, depth + 1);
            }
        }
        _ => {}
    }
}

/// True if `v` contains no secret value in cleartext — every secret-keyed leaf
/// is either `null` or the placeholder.
///
/// Intended for tests and defense-in-depth assertions at serialization
/// boundaries.
pub fn is_fully_redacted(v: &Value) -> bool {
    let mut probe = v.clone();
    redact_config_secrets(&mut probe);
    probe == *v
}

/// Resolve the config an upsert should persist, given the request's `incoming`
/// JSON and the currently stored `existing` JSON.
///
/// Applies the write contract documented at the module level: secret keys are
/// preserved when the request omits them or echoes back
/// [`REDACTED_PLACEHOLDER`], cleared only on an explicit `null`, and replaced
/// on any real value. Non-secret keys follow ordinary replace semantics.
///
/// `existing` is `None` on create, in which case masked/omitted secrets simply
/// have nothing to restore and are dropped.
pub fn merge_config_secrets(incoming: Value, existing: Option<&Value>) -> Value {
    merge_inner(incoming, existing, 0)
}

fn merge_inner(incoming: Value, existing: Option<&Value>, depth: usize) -> Value {
    if depth > MAX_CONFIG_DEPTH {
        return incoming;
    }

    // Arrays of objects can carry secrets too (e.g. `outputs[].auth.token`),
    // and redaction masks them, so the merge has to descend as well or an
    // echoed read persists `***REDACTED***` over the real value.
    //
    // Elements are paired BY INDEX. A round-trip from a client that preserves
    // order — which every read-modify-write UI does — restores correctly. A
    // request that reorders elements while echoing placeholders would restore
    // a stored secret into its positional neighbour; supply real values (or
    // `null`) when reordering.
    if let Value::Array(incoming_items) = incoming {
        let existing_items = existing.and_then(Value::as_array);
        return Value::Array(
            incoming_items
                .into_iter()
                .enumerate()
                .map(|(i, item)| {
                    merge_inner(item, existing_items.and_then(|e| e.get(i)), depth + 1)
                })
                .collect(),
        );
    }

    let Value::Object(incoming_map) = incoming else {
        // Non-object at this position: ordinary replace. Secret-key handling
        // happens in the parent frame, which knows the key name.
        return incoming;
    };

    let existing_map = existing.and_then(Value::as_object);
    let mut out = serde_json::Map::with_capacity(incoming_map.len());

    // Which keys the request actually mentioned. Needed because a key can be
    // mentioned and still not land in `out` (an explicitly-nulled subtree, a
    // masked secret with nothing stored) — without this, the preserve pass
    // below would resurrect exactly what the caller asked to remove.
    let incoming_keys: std::collections::HashSet<String> = incoming_map.keys().cloned().collect();

    for (key, value) in incoming_map {
        let stored = existing_map.and_then(|m| m.get(&key));

        if is_secret_config_subtree(&key) {
            // System-injected credential material: the client never authors it,
            // so the request's version is ignored entirely. An explicit `null`
            // is still honoured as a removal, so an operator can drop a legacy
            // subtree without hand-editing the database.
            if value.is_null() {
                continue;
            }
            if let Some(stored) = stored {
                out.insert(key, stored.clone());
            }
            continue;
        }

        if is_secret_config_key(&key) {
            match resolve_secret_write(value, stored) {
                Some(resolved) => {
                    out.insert(key, resolved);
                }
                // Masked value with nothing stored to restore — drop the key
                // rather than persist the placeholder as if it were a secret.
                None => continue,
            }
            continue;
        }

        out.insert(key, merge_inner(value, stored, depth + 1));
    }

    // Only the system-owned subtree survives omission. Scalar secrets follow
    // replace semantics (see the module-level write contract): clients clear
    // them by omitting them, and every redacted read carries the placeholder
    // that preserves them on a genuine round-trip.
    if let Some(existing_map) = existing_map {
        for (key, stored) in existing_map {
            if out.contains_key(key) || incoming_keys.contains(key) {
                continue;
            }
            if is_secret_config_subtree(key) {
                out.insert(key.clone(), stored.clone());
            }
        }
    }

    Value::Object(out)
}

/// Resolve one secret-keyed write. `None` means "drop the key".
fn resolve_secret_write(incoming: Value, stored: Option<&Value>) -> Option<Value> {
    match &incoming {
        // Explicit clear — the only way to remove a stored secret.
        Value::Null => Some(Value::Null),
        Value::String(s) if s == REDACTED_PLACEHOLDER => stored.cloned(),
        // A masked array (`["***REDACTED***"]`) echoed back from a redacted read.
        Value::Array(arr) if arr.len() == 1 && arr[0].as_str() == Some(REDACTED_PLACEHOLDER) => {
            stored.cloned()
        }
        _ => Some(incoming),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- redaction -------------------------------------------------------

    #[test]
    fn redacts_kafka_and_aws_secrets_but_keeps_identifiers() {
        let mut v = json!({
            "bootstrap_servers": "broker:9092",
            "sasl_username": "svc-ingest",
            "sasl_password": "super-secret-pw",
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI",
            "session_token": "FwoGZXIv",
        });
        redact_config_secrets(&mut v);

        assert_eq!(v["sasl_password"], REDACTED_PLACEHOLDER);
        assert_eq!(v["secret_access_key"], REDACTED_PLACEHOLDER);
        assert_eq!(v["session_token"], REDACTED_PLACEHOLDER);
        // Identifiers and connection metadata stay readable.
        assert_eq!(v["bootstrap_servers"], "broker:9092");
        assert_eq!(v["sasl_username"], "svc-ingest");
        assert_eq!(v["access_key_id"], "AKIAEXAMPLE");
    }

    #[test]
    fn redacts_enrichment_auth_config_keeping_non_secret_metadata() {
        let mut v = json!({
            "auth_config": {
                "auth_type": "oauth2",
                "client_id": "public-client",
                "client_secret": "shh",
                "token_url": "https://idp/token",
                "scope": "read",
                "token": "bearer-secret",
                "api_key": "key-secret",
                "header_name": "X-API-Key",
                "username": "svc",
                "password": "pw-secret",
            }
        });
        redact_config_secrets(&mut v);
        let a = &v["auth_config"];

        for secret in ["client_secret", "token", "api_key", "password"] {
            assert_eq!(a[secret], REDACTED_PLACEHOLDER, "{secret} not masked");
        }
        assert_eq!(a["auth_type"], "oauth2");
        assert_eq!(a["client_id"], "public-client");
        assert_eq!(a["token_url"], "https://idp/token");
        assert_eq!(a["scope"], "read");
        assert_eq!(a["header_name"], "X-API-Key");
        assert_eq!(a["username"], "svc");
    }

    #[test]
    fn redacts_whole_credentials_subtree_regardless_of_leaf_names() {
        let mut v = json!({
            "_credentials": {
                "credentials_json": "{\"type\":\"service_account\"}",
                "access_key_id": "AKIAEXAMPLE",
                "some_future_key": "also-secret",
            }
        });
        redact_config_secrets(&mut v);

        let c = &v["_credentials"];
        // Even access_key_id — non-secret at top level — is masked inside
        // `_credentials`, because the whole subtree is credential material.
        assert_eq!(c["access_key_id"], REDACTED_PLACEHOLDER);
        assert_eq!(c["credentials_json"], REDACTED_PLACEHOLDER);
        assert_eq!(c["some_future_key"], REDACTED_PLACEHOLDER);
        // Structure is preserved so the UI can show which fields are set.
        assert!(c.as_object().unwrap().contains_key("credentials_json"));
    }

    #[test]
    fn redacts_tls_private_key_but_not_certificates() {
        // `source_config.tls` — only the private key is secret; the client
        // certificate and CA chain are public and stay inspectable.
        let mut v = json!({
            "tls": {
                "key_content": "-----BEGIN PRIVATE KEY-----\nMIIE...",
                "crt_content": "-----BEGIN CERTIFICATE-----\nMIIB...",
                "ca_content": "-----BEGIN CERTIFICATE-----\nMIIC...",
                "verify_hostname": true,
            }
        });
        redact_config_secrets(&mut v);

        assert_eq!(v["tls"]["key_content"], REDACTED_PLACEHOLDER);
        assert!(
            v["tls"]["crt_content"]
                .as_str()
                .unwrap()
                .contains("BEGIN CERTIFICATE"),
            "client certificate is public material and must stay readable"
        );
        assert!(v["tls"]["ca_content"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert_eq!(v["tls"]["verify_hostname"], true);
    }

    #[test]
    fn redacts_nested_and_arrayed_secrets() {
        let mut v = json!({
            "outputs": [{ "auth": { "token": "t1" } }, { "auth": { "token": "t2" } }],
            "valid_tokens": ["hec-a", "hec-b"],
        });
        redact_config_secrets(&mut v);

        assert_eq!(v["outputs"][0]["auth"]["token"], REDACTED_PLACEHOLDER);
        assert_eq!(v["outputs"][1]["auth"]["token"], REDACTED_PLACEHOLDER);
        // Array collapses to one element so the token COUNT is not disclosed.
        assert_eq!(v["valid_tokens"], json!([REDACTED_PLACEHOLDER]));
    }

    #[test]
    fn null_secret_stays_null_as_a_has_flag() {
        let mut v = json!({ "token": null, "api_key": "set" });
        redact_config_secrets(&mut v);
        assert_eq!(
            v["token"],
            json!(null),
            "unconfigured stays distinguishable"
        );
        assert_eq!(v["api_key"], REDACTED_PLACEHOLDER);
    }

    #[test]
    fn redaction_is_idempotent() {
        let mut once = json!({ "sasl_password": "p", "valid_tokens": ["a", "b"] });
        redact_config_secrets(&mut once);
        let mut twice = once.clone();
        redact_config_secrets(&mut twice);
        assert_eq!(once, twice);
    }

    #[test]
    fn strip_removes_secret_keys_entirely_for_shareable_artifacts() {
        // Export manifests are re-imported verbatim, so a masked value would be
        // persisted and used as the credential. Omission is the honest shape.
        let mut v = json!({
            "auth_config": {
                "auth_type": "bearer",
                "token": "real-token",
                "client_id": "public-client",
            },
            "_credentials": { "sasl_password": "real-pw" },
            "rate_limit_per_min": 60,
        });
        strip_config_secrets(&mut v);

        let bytes = serde_json::to_string(&v).unwrap();
        assert!(!bytes.contains("real-token"));
        assert!(!bytes.contains("real-pw"));
        assert!(
            !bytes.contains(REDACTED_PLACEHOLDER),
            "stripping must not leave a placeholder behind — it would be \
             persisted verbatim on re-import"
        );
        assert!(
            v["auth_config"].get("token").is_none(),
            "key removed, not masked"
        );
        assert!(v.get("_credentials").is_none());
        // Non-secret structure is preserved so the manifest stays usable.
        assert_eq!(v["auth_config"]["auth_type"], "bearer");
        assert_eq!(v["auth_config"]["client_id"], "public-client");
        assert_eq!(v["rate_limit_per_min"], 60);
    }

    #[test]
    fn is_fully_redacted_detects_cleartext() {
        assert!(is_fully_redacted(
            &json!({ "sasl_password": REDACTED_PLACEHOLDER })
        ));
        assert!(is_fully_redacted(
            &json!({ "bootstrap_servers": "broker:9092" })
        ));
        assert!(!is_fully_redacted(&json!({ "sasl_password": "cleartext" })));
        assert!(!is_fully_redacted(
            &json!({ "nested": { "deep": { "token": "cleartext" } } })
        ));
    }

    #[test]
    fn deeply_nested_payload_is_masked_not_skipped() {
        // Beyond MAX_CONFIG_DEPTH the walker masks rather than giving up, so a
        // hand-crafted row can't smuggle a secret past redaction.
        let mut v = json!("leaf");
        for _ in 0..(MAX_CONFIG_DEPTH + 4) {
            v = json!({ "n": v });
        }
        redact_config_secrets(&mut v);
        assert!(
            !serde_json::to_string(&v).unwrap().contains("leaf"),
            "deep leaf survived redaction"
        );
    }

    // ---- merge (round-trip safety) --------------------------------------

    #[test]
    fn placeholder_echo_preserves_stored_secret() {
        let existing = json!({ "sasl_password": "real-pw", "bootstrap_servers": "a:9092" });
        let incoming =
            json!({ "sasl_password": REDACTED_PLACEHOLDER, "bootstrap_servers": "b:9092" });

        let merged = merge_config_secrets(incoming, Some(&existing));

        assert_eq!(
            merged["sasl_password"], "real-pw",
            "secret survived round-trip"
        );
        assert_eq!(merged["bootstrap_servers"], "b:9092", "non-secret updated");
    }

    #[test]
    fn omitting_a_secret_clears_it_so_ui_clear_gestures_still_work() {
        // Real clients clear by omission: `TlsConfigSection.handleClear` sets
        // `key_content` to `undefined`, and `SourceConfigurationDetail` sends
        // `{}` to purge legacy HEC `valid_tokens`. Preserve-on-omit would
        // silently defeat both, so omission drops — matching
        // `scheduler::secrets::merge_auth_headers`.
        let existing = json!({ "key_content": "-----BEGIN PRIVATE KEY-----", "group_id": "g1" });
        let merged = merge_config_secrets(json!({ "group_id": "g2" }), Some(&existing));

        assert!(
            merged.get("key_content").is_none(),
            "clear-by-omission honoured"
        );
        assert_eq!(merged["group_id"], "g2");
    }

    #[test]
    fn real_value_replaces_and_explicit_null_clears() {
        let existing = json!({ "token": "old", "api_key": "old-key" });

        let merged = merge_config_secrets(json!({ "token": "new" }), Some(&existing));
        assert_eq!(merged["token"], "new", "real value updates");

        let cleared = merge_config_secrets(json!({ "token": null }), Some(&existing));
        assert_eq!(cleared["token"], json!(null), "explicit null clears");
    }

    #[test]
    fn secrets_inside_arrays_of_objects_round_trip() {
        // Redaction descends into arrays, so merge must too — otherwise an
        // echoed read persists the placeholder over a real token.
        let stored = json!({
            "outputs": [
                { "name": "a", "auth": { "token": "tok-a" } },
                { "name": "b", "auth": { "token": "tok-b" } },
            ]
        });

        let mut wire = stored.clone();
        redact_config_secrets(&mut wire);
        let merged = merge_config_secrets(wire, Some(&stored));

        assert_eq!(merged, stored, "array element secrets were not restored");
    }

    #[test]
    fn explicit_null_clears_the_credentials_subtree() {
        // Otherwise a legacy subtree could never be removed through the API.
        let existing = json!({ "_credentials": { "sasl_password": "legacy" }, "group_id": "g" });
        let merged = merge_config_secrets(
            json!({ "_credentials": null, "group_id": "g" }),
            Some(&existing),
        );
        assert!(merged.get("_credentials").is_none());
    }

    #[test]
    fn rotating_one_secret_does_not_disturb_an_echoed_sibling() {
        // The realistic edit: the UI echoes every masked secret back and the
        // user types a new value into exactly one field.
        let existing = json!({ "sasl_password": "old-pw", "secret_access_key": "aws-real" });
        let incoming = json!({
            "sasl_password": "rotated",
            "secret_access_key": REDACTED_PLACEHOLDER,
        });

        let merged = merge_config_secrets(incoming, Some(&existing));

        assert_eq!(merged["sasl_password"], "rotated");
        assert_eq!(merged["secret_access_key"], "aws-real");
    }

    #[test]
    fn non_secret_key_absent_from_request_is_dropped() {
        let existing = json!({ "group_id": "g1", "topics": ["t"] });
        let merged = merge_config_secrets(json!({ "group_id": "g2" }), Some(&existing));

        assert_eq!(merged["group_id"], "g2");
        assert!(
            merged.get("topics").is_none(),
            "ordinary config keys keep replace semantics"
        );
    }

    #[test]
    fn nested_secret_round_trips() {
        let existing = json!({ "auth_config": { "client_id": "id", "client_secret": "real" } });
        let incoming = json!({
            "auth_config": { "client_id": "id2", "client_secret": REDACTED_PLACEHOLDER }
        });

        let merged = merge_config_secrets(incoming, Some(&existing));

        assert_eq!(merged["auth_config"]["client_secret"], "real");
        assert_eq!(merged["auth_config"]["client_id"], "id2");
    }

    #[test]
    fn masked_array_echo_preserves_stored_tokens() {
        let existing = json!({ "valid_tokens": ["a", "b"] });
        let incoming = json!({ "valid_tokens": [REDACTED_PLACEHOLDER] });

        let merged = merge_config_secrets(incoming, Some(&existing));

        assert_eq!(merged["valid_tokens"], json!(["a", "b"]));
    }

    #[test]
    fn client_cannot_author_or_wipe_the_credentials_subtree() {
        let existing = json!({ "_credentials": { "sasl_password": "real" }, "group_id": "g" });

        // Attempt to overwrite with attacker-chosen material: ignored.
        let hijack = json!({ "_credentials": { "sasl_password": "attacker" }, "group_id": "g" });
        let merged = merge_config_secrets(hijack, Some(&existing));
        assert_eq!(merged["_credentials"]["sasl_password"], "real");

        // Attempt to drop it by omission: preserved.
        let omit = json!({ "group_id": "g" });
        let merged = merge_config_secrets(omit, Some(&existing));
        assert_eq!(merged["_credentials"]["sasl_password"], "real");
    }

    #[test]
    fn create_with_no_existing_drops_masked_secrets() {
        // Nothing stored to restore — persisting the placeholder as a literal
        // secret would be worse than dropping the key.
        let merged = merge_config_secrets(
            json!({ "sasl_password": REDACTED_PLACEHOLDER, "group_id": "g" }),
            None,
        );
        assert!(merged.get("sasl_password").is_none());
        assert_eq!(merged["group_id"], "g");

        // A client that never supplies `_credentials` on create gets none.
        let merged = merge_config_secrets(json!({ "_credentials": { "x": "y" } }), None);
        assert!(merged.get("_credentials").is_none());
    }

    #[test]
    fn redact_then_merge_is_lossless_for_every_secret_key() {
        // The core round-trip invariant, exercised over the whole key set: read
        // (redacted) -> client echoes it back verbatim -> stored value unchanged.
        let mut stored = serde_json::Map::new();
        for (i, key) in SECRET_CONFIG_KEYS.iter().enumerate() {
            stored.insert((*key).to_string(), json!(format!("secret-{i}")));
        }
        let stored = Value::Object(stored);

        let mut wire = stored.clone();
        redact_config_secrets(&mut wire);
        assert!(
            !serde_json::to_string(&wire).unwrap().contains("secret-"),
            "a secret leaked through redaction"
        );

        let merged = merge_config_secrets(wire, Some(&stored));
        assert_eq!(merged, stored, "round-trip mutated stored secrets");
    }
}

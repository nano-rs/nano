// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared character-safety validation for admin-supplied connection/source
//! config JSON.
//!
//! Vector config is generated from this JSON. Some generators interpolate
//! string scalars directly into TOML; a newline or other control character in
//! a value can close the current TOML string and inject attacker-controlled
//! sections (`[sinks.exfil]`, `[transforms.injected]`, …). This module rejects
//! such characters at write time — defense-in-depth that holds even where a
//! generator still uses string interpolation rather than structured TOML
//! serialization.
//!
//! `SourceConfigService` validates connection configuration through this
//! shared implementation (NAN-689 / NAN-1371).

/// Maximum nesting depth walked before refusing to validate — bounds stack use
/// on a malicious deeply-nested payload (NAN-946).
pub(crate) const MAX_CONFIG_DEPTH: usize = 32;

/// True for characters that must never appear in a config string scalar:
/// newlines, CR, NUL, all other C0 controls, and DEL. Tab is allowed.
pub(crate) fn is_unsafe_scalar_char(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\0' | '\x7f') || (c.is_control() && c != '\t')
}

/// Validate a config object's NAME — it lands in a generated TOML section /
/// comment header, so reject empty and any control character at the API
/// boundary rather than relying solely on generator-level escaping. Returns the
/// human-readable error message on violation.
pub(crate) fn validate_config_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if let Some(c) = name.chars().find(|c| is_unsafe_scalar_char(*c)) {
        return Err(format!(
            "name contains disallowed control character (U+{code:04X})",
            code = c as u32,
        ));
    }
    Ok(())
}

/// Recursively reject control characters in every string scalar (and object
/// key) of `v`. Values stored under a key listed in `exempt_keys` are skipped:
/// those are file-written multi-line blobs (PEM certs, GCP credential JSON)
/// whose content is never interpolated into TOML — only a generated file path
/// is — so they legitimately contain newlines.
///
/// `path` is used to produce a helpful error. Returns the human-readable error
/// message on the first violation; callers wrap it in their own error type.
pub(crate) fn validate_safe_config_strings(
    v: &serde_json::Value,
    path: &str,
    exempt_keys: &[&str],
) -> Result<(), String> {
    validate_inner(v, path, exempt_keys, 0)
}

fn validate_inner(
    v: &serde_json::Value,
    path: &str,
    exempt_keys: &[&str],
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_CONFIG_DEPTH {
        return Err(format!(
            "{path} exceeds maximum nesting depth of {MAX_CONFIG_DEPTH} — refusing to \
             validate deeply-nested config"
        ));
    }
    match v {
        serde_json::Value::String(s) => {
            if let Some(c) = s.chars().find(|c| is_unsafe_scalar_char(*c)) {
                return Err(format!(
                    "{path} contains disallowed control character (U+{code:04X})",
                    code = c as u32,
                ));
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                validate_inner(item, &format!("{path}[{i}]"), exempt_keys, depth + 1)?;
            }
        }
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                // Reject control chars in keys too — they'd produce malformed
                // TOML headers if interpolated unquoted.
                if k.chars().any(is_unsafe_scalar_char) {
                    return Err(format!(
                        "{path} contains disallowed control character in key '{k}'"
                    ));
                }
                // Skip file-written multi-line blobs (their content is never
                // interpolated into TOML).
                if exempt_keys.contains(&k.as_str()) {
                    continue;
                }
                validate_inner(val, &format!("{path}.{k}"), exempt_keys, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_newline_in_scalar() {
        let v = json!({ "bootstrap_servers": "localhost:9092\"\n[sinks.exfil]" });
        let err = validate_safe_config_strings(&v, "cfg", &[]).unwrap_err();
        assert!(err.contains("U+000A"), "{err}");
    }

    #[test]
    fn rejects_control_chars_in_arrays_and_keys() {
        assert!(
            validate_safe_config_strings(&json!({ "topics": ["ok", "ev\nil"] }), "cfg", &[])
                .is_err()
        );
        let mut map = serde_json::Map::new();
        map.insert("bad\nkey".to_string(), json!("v"));
        assert!(validate_safe_config_strings(&serde_json::Value::Object(map), "cfg", &[]).is_err());
    }

    #[test]
    fn allows_clean_config_and_tab() {
        let v =
            json!({ "bootstrap_servers": "a:9092,b:9092", "group_id": "g\t1", "topics": ["x"] });
        assert!(validate_safe_config_strings(&v, "cfg", &[]).is_ok());
    }

    #[test]
    fn exempts_file_written_multiline_blobs() {
        // PEM cert / GCP creds JSON legitimately contain newlines; they're
        // written to a file, not interpolated.
        let v = json!({
            "_credentials": {
                "tls_ca_cert": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
                "credentials_json": "{\n  \"type\": \"service_account\"\n}",
                "sasl_password": "secret"
            }
        });
        assert!(
            validate_safe_config_strings(&v, "cfg", &["tls_ca_cert", "credentials_json"]).is_ok()
        );
        // …but a non-exempt sibling with a newline is still rejected.
        let bad = json!({ "_credentials": { "sasl_password": "p\nass" } });
        assert!(
            validate_safe_config_strings(&bad, "cfg", &["tls_ca_cert", "credentials_json"])
                .is_err()
        );
    }

    #[test]
    fn validate_config_name_rejects_empty_and_control_chars() {
        assert!(validate_config_name("").is_err());
        assert!(validate_config_name("evil]\n[sinks.x").is_err());
        assert!(validate_config_name("my kafka feed-1").is_ok());
    }

    #[test]
    fn rejects_excessive_nesting() {
        let mut v = json!("leaf");
        for _ in 0..(MAX_CONFIG_DEPTH + 2) {
            v = json!([v]);
        }
        assert!(validate_safe_config_strings(&v, "cfg", &[]).is_err());
    }
}

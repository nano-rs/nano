// SPDX-License-Identifier: AGPL-3.0-or-later

//! Snapshot redaction for persisted Vector configs (NAN-690).
//!
//! Both source-config and parser deployment flows persist a fully-rendered
//! Vector TOML to `*.config_snapshot` for forensic / audit value, and both
//! corresponding HTTP endpoints (`GET /api/source-configurations/{id}/deployments`,
//! `GET /api/log-sources/{id}/deployments`) return that column to anyone
//! holding the relevant `*:view` permission.
//!
//! The generated TOML inlines real Kafka SASL passwords, AWS S3 secret access
//! keys / session tokens (lifted from AES-256-GCM-encrypted `cloud_credentials`),
//! and Splunk HEC `valid_tokens`. Returning the snapshot raw bypasses the
//! credential encryption boundary and, in HEC's case, preserves rotated tokens
//! forever.
//!
//! [`redact_config_snapshot`] is the single point that scrubs those keys
//! before the value is written to either deployment table. The on-disk Vector
//! config still contains real values — only the persisted snapshot is sanitised.

/// Scalar-string TOML keys whose values are bearer secrets and must not
/// appear in any persisted snapshot.
const SCALAR_SECRET_KEYS: &[&str] = &["password", "secret_access_key", "session_token"];

/// Array-of-string TOML keys whose values are bearer secrets and must not
/// appear in any persisted snapshot.
///
/// NOTE: redaction assumes a single-line array (`key = ["a", "b"]`). The two
/// HEC generators today emit exactly that shape; if a future change switches
/// to a multi-line array (`key = [\n  "a",\n  "b",\n]`), only the opening
/// line will be scrubbed and individual element lines will leak through. Pin
/// the single-line invariant in tests on whichever generator changes.
const ARRAY_SECRET_KEYS: &[&str] = &["valid_tokens"];

/// Marker that replaces secret values in persisted snapshots.
pub const REDACTED_PLACEHOLDER: &str = "***REDACTED***";

/// Return a copy of the Vector TOML with secret-bearing key/value lines
/// scrubbed. Idempotent — safe to call on already-redacted output.
pub fn redact_config_snapshot(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        // Only line-shaped `key = value` assignments get rewritten. Anything
        // without `=` (blank lines, headers, raw `[section]` markers, comments)
        // passes through untouched — defensive guard against accidentally
        // synthesising a `key = "***REDACTED***"` line out of stray text that
        // happened to start with one of the key names.
        if !line.contains('=') {
            out.push_str(line);
            continue;
        }

        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        let key = trimmed.split('=').next().map(str::trim).unwrap_or("");

        if SCALAR_SECRET_KEYS.contains(&key) {
            out.push_str(indent);
            out.push_str(key);
            out.push_str(" = \"");
            out.push_str(REDACTED_PLACEHOLDER);
            out.push('"');
            if line.ends_with('\n') {
                out.push('\n');
            }
        } else if ARRAY_SECRET_KEYS.contains(&key) {
            out.push_str(indent);
            out.push_str(key);
            out.push_str(" = [\"");
            out.push_str(REDACTED_PLACEHOLDER);
            out.push_str("\"]");
            if line.ends_with('\n') {
                out.push('\n');
            }
        } else {
            out.push_str(line);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_kafka_sasl_password() {
        let toml = "[sources.demo_source]\n\
                    type = \"kafka\"\n\
                    bootstrap_servers = \"broker:9092\"\n\
                    \n\
                    [sources.demo_source.sasl]\n\
                    enabled = true\n\
                    mechanism = \"SCRAM-SHA-256\"\n\
                    username = \"svc-ingest\"\n\
                    password = \"super-secret-pw\"\n";

        let redacted = redact_config_snapshot(toml);

        assert!(
            !redacted.contains("super-secret-pw"),
            "password leaked into snapshot:\n{redacted}"
        );
        assert!(redacted.contains("password = \"***REDACTED***\""));
        assert!(redacted.contains("username = \"svc-ingest\""));
        assert!(redacted.contains("mechanism = \"SCRAM-SHA-256\""));
        assert!(redacted.contains("bootstrap_servers = \"broker:9092\""));
    }

    #[test]
    fn redacts_aws_s3_secret_access_key_and_session_token() {
        let toml = "[sources.aws_demo_source.auth]\n\
                    access_key_id = \"AKIAEXAMPLE\"\n\
                    secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n\
                    session_token = \"FwoGZXIvYXdzEJr//////////w==SESSION\"\n\
                    region = \"us-east-1\"\n";

        let redacted = redact_config_snapshot(toml);

        assert!(
            !redacted.contains("wJalrXUtnFEMI"),
            "AWS secret_access_key leaked:\n{redacted}"
        );
        assert!(
            !redacted.contains("FwoGZXIv"),
            "AWS session_token leaked:\n{redacted}"
        );
        assert!(redacted.contains("secret_access_key = \"***REDACTED***\""));
        assert!(redacted.contains("session_token = \"***REDACTED***\""));
        assert!(redacted.contains("access_key_id = \"AKIAEXAMPLE\""));
        assert!(redacted.contains("region = \"us-east-1\""));
    }

    #[test]
    fn redacts_splunk_hec_valid_tokens() {
        let toml = "[sources.hec_source]\n\
                    type = \"splunk_hec\"\n\
                    address = \"0.0.0.0:8088\"\n\
                    valid_tokens = [\"codex_fake_hec_secret_token\", \"another-token\"]\n";

        let redacted = redact_config_snapshot(toml);

        assert!(
            !redacted.contains("codex_fake_hec_secret_token"),
            "HEC token leaked:\n{redacted}"
        );
        assert!(!redacted.contains("another-token"));
        assert!(redacted.contains("valid_tokens = [\"***REDACTED***\"]"));
        assert!(redacted.contains("address = \"0.0.0.0:8088\""));
    }

    #[test]
    fn preserves_indentation_and_other_lines() {
        let toml = "# header\n  password = \"x\"\nother = \"keep\"\n";
        assert_eq!(
            redact_config_snapshot(toml),
            "# header\n  password = \"***REDACTED***\"\nother = \"keep\"\n"
        );
    }

    #[test]
    fn passthrough_on_lines_without_equals() {
        // Defensive: a stray line that happens to start with a secret key name
        // but is not actually an assignment must not be rewritten.
        let toml = "password\n[sources.foo]\nvalid_tokens\n";
        assert_eq!(redact_config_snapshot(toml), toml);
    }

    #[test]
    fn is_idempotent() {
        let toml = "password = \"secret\"\nsession_token = \"abc\"\nvalid_tokens = [\"t\"]\n";
        let once = redact_config_snapshot(toml);
        let twice = redact_config_snapshot(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn handles_missing_trailing_newline() {
        let toml = "password = \"x\"";
        assert_eq!(redact_config_snapshot(toml), "password = \"***REDACTED***\"");
    }
}

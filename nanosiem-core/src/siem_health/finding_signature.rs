// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable signature for /health AI recommendations
//!
//! The AI's recommendations have small variations between runs ("7.7% fill"
//! one day, "8.1%" the next) that should not affect whether a suppression
//! matches. We compute a deterministic signature from the title only, after
//! stripping volatile tokens (numbers, percentages, whitespace), and hash
//! the result. Two recommendations of the same class will produce the same
//! signature even if their numeric details drift; a meaningful regression
//! (e.g. fill rate going from 8% → 90%) is communicated to the AI through
//! the verbatim title in the prompt's suppression context, not through a
//! changed signature — the LLM decides whether the regression warrants
//! re-raising the finding.
//!
//! Description and priority deliberately do *not* feed the signature: the
//! AI rewrites the description every run, and priority changes mid-run
//! shouldn't break a suppression.
//!
//! Signature format: hex-encoded first 16 bytes of SHA-256 (32 chars). Not
//! cryptographically meaningful — this is just a stable opaque identifier.
//!
//! NAN-615.
use sha2::{Digest, Sha256};

/// Compute the stable suppression signature for a recommendation title.
pub fn signature_for_title(title: &str) -> String {
    let normalized = normalize_title(title);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

/// Lowercase, strip numeric tokens (so "7.7%" and "8.1%" collapse), drop
/// punctuation that frequently varies, and collapse whitespace.
fn normalize_title(title: &str) -> String {
    let lower = title.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_space = true;
    for ch in lower.chars() {
        if ch.is_ascii_digit() || ch == '.' || ch == ',' || ch == '%' || ch == '(' || ch == ')' {
            // Skip — these are the volatile bits.
            continue;
        }
        if ch.is_whitespace() || ch == '-' || ch == ':' || ch == ';' || ch == '"' || ch == '\'' {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
            continue;
        }
        out.push(ch);
        prev_space = false;
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable_across_numeric_drift() {
        // The exact case from the user report: src_ip fill rate drifts run
        // to run, but the suppression must continue to match.
        let a = signature_for_title("Fix src_ip extraction for windows_sysmon (7.7% fill rate)");
        let b = signature_for_title("Fix src_ip extraction for windows_sysmon (8.1% fill rate)");
        let c = signature_for_title("Fix src_ip extraction for windows_sysmon (12% fill rate)");
        assert_eq!(a, b, "numeric drift in fill rate must not change signature");
        assert_eq!(a, c, "different precision must not change signature");
    }

    #[test]
    fn signature_differs_for_different_classes() {
        let a = signature_for_title("Fix src_ip extraction for windows_sysmon (7.7% fill rate)");
        let b = signature_for_title("Fix src_ip extraction for aws_cloudtrail (7.7% fill rate)");
        assert_ne!(a, b, "different source_type must produce different signature");

        let c = signature_for_title("Configure at least one active webhook for alert delivery");
        let d = signature_for_title(
            "Investigate and restore the enrichment pipeline immediately",
        );
        assert_ne!(c, d);
    }

    #[test]
    fn signature_is_case_and_whitespace_insensitive() {
        let a = signature_for_title("Fix src_ip extraction for windows_sysmon");
        let b = signature_for_title("FIX src_ip Extraction  for   windows_sysmon");
        let c = signature_for_title("  fix src_ip extraction for windows_sysmon  ");
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn signature_strips_punctuation_that_drifts() {
        // Trailing parentheticals frequently get added/removed by the AI.
        let a = signature_for_title("Resolve 100% ext field usage across Windows, proxy sources");
        let b = signature_for_title("Resolve 95% ext field usage across Windows: proxy sources");
        assert_eq!(a, b);
    }

    #[test]
    fn signature_format_is_hex_32_chars() {
        let sig = signature_for_title("Some recommendation");
        assert_eq!(sig.len(), 32);
        assert!(
            sig.chars().all(|c| c.is_ascii_hexdigit()),
            "signature must be hex"
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Built-in identity normalizers (NAN-3483).
//!
//! Every pull provider emits raw user objects onto the `nano_enrich` lane
//! tagged `kind=identity, source=<provider>`. The lane maps them into the
//! directory with a per-source normalize VRL. Before NAN-3483 that VRL only
//! existed in the parsers repo: unless an operator imported `okta_identity`
//! by hand, the static fallback lane sent every identity record to the AD
//! normalizer, which dead-lettered all of them (no `external_id`) while the
//! sync reported `completed`.
//!
//! These are the parsers-repo `enrichments/identity/<source>/parser.yaml`
//! `normalize_vrl` bodies (nano-rs/parsers @216d960, identical on `main` and
//! `ocsf-1.9`), compiled into the binary so each provider has a normalizer by
//! default. One deliberate change: AD, Google and Okta keep `suspended` as its
//! own account_status instead of folding it into `disabled` (NAN-3489 status
//! alignment); the parsers repo should take the same change. An imported, enabled enrichment parser for the same source still
//! wins, in the lane and in the sync's in-process check alike.

/// One built-in per-source identity normalizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinIdentityNormalizer {
    /// The `.source` discriminator the lane routes on (`enrich_source`).
    pub source: &'static str,
    /// The parsers-repo parser this body mirrors.
    pub parser_name: &'static str,
    /// The normalize VRL body.
    pub normalize_vrl: &'static str,
}

/// Built-in normalizers, one per identity source the platform knows.
pub const BUILTIN_IDENTITY_NORMALIZERS: &[BuiltinIdentityNormalizer] = &[
    BuiltinIdentityNormalizer {
        source: "ad",
        parser_name: "ad_identity",
        normalize_vrl: include_str!("normalizers/ad.vrl"),
    },
    BuiltinIdentityNormalizer {
        source: "entra",
        parser_name: "entra_identity",
        normalize_vrl: include_str!("normalizers/entra.vrl"),
    },
    BuiltinIdentityNormalizer {
        source: "google",
        parser_name: "google_identity",
        normalize_vrl: include_str!("normalizers/google.vrl"),
    },
    BuiltinIdentityNormalizer {
        source: "okta",
        parser_name: "okta_identity",
        normalize_vrl: include_str!("normalizers/okta.vrl"),
    },
    BuiltinIdentityNormalizer {
        source: "workday",
        parser_name: "workday_identity",
        normalize_vrl: include_str!("normalizers/workday.vrl"),
    },
];

/// The built-in normalizer for `source`, if the platform ships one.
pub fn builtin_identity_normalizer(source: &str) -> Option<&'static BuiltinIdentityNormalizer> {
    BUILTIN_IDENTITY_NORMALIZERS
        .iter()
        .find(|n| n.source == source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pull_provider_source_has_a_builtin() {
        for source in ["entra", "google", "okta", "workday"] {
            assert!(
                builtin_identity_normalizer(source).is_some(),
                "{source} has no built-in identity normalizer"
            );
        }
        assert!(builtin_identity_normalizer("ad").is_some());
        assert!(builtin_identity_normalizer("onelogin").is_none());
    }

    #[test]
    fn builtins_are_unique_and_non_empty() {
        let mut seen = std::collections::HashSet::new();
        for n in BUILTIN_IDENTITY_NORMALIZERS {
            assert!(seen.insert(n.source), "duplicate source {}", n.source);
            assert!(
                !n.normalize_vrl.trim().is_empty(),
                "{} VRL is empty",
                n.source
            );
            // Embedded verbatim inside a TOML `'''` literal by the lane writer.
            assert!(
                !n.normalize_vrl.contains("'''"),
                "{} VRL breaks TOML",
                n.source
            );
        }
    }
}

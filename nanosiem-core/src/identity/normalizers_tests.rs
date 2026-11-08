// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for `identity::normalizers` (NAN-3483).

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

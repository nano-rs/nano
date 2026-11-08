// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3226: internal names are never sent to external enrichment providers.

use super::is_internal_artifact;
use nanosiem_core::internal_domains::InternalDomains;
use nanosiem_enterprise::agent_enrichment::ArtifactType;

#[test]
fn internal_artifacts_are_never_sent_to_external_providers() {
    let internal = InternalDomains::with_suffixes(["prod"]);
    assert!(is_internal_artifact("db1.prod", ArtifactType::Domain, &internal));
    assert!(is_internal_artifact("fs.corp.local", ArtifactType::Domain, &internal));
    assert!(is_internal_artifact("https://db1.prod/x", ArtifactType::Url, &internal));
    assert!(!is_internal_artifact("myprod.com", ArtifactType::Domain, &internal));
    assert!(!is_internal_artifact("https://example.com/prod", ArtifactType::Url, &internal));
    assert!(!is_internal_artifact("10.0.0.1", ArtifactType::IpAddress, &internal));
}

#[test]
fn a_refused_suffix_never_skips_enrichment() {
    let internal = nanosiem_core::internal_domains::store::with_tenant(["com"]);
    assert!(!is_internal_artifact("evil.com", ArtifactType::Domain, &internal));
}

/// IDNA: a U-label artifact under an A-label suffix (and the reverse) is the
/// same internal name, so it is never sent to an external provider.
#[test]
fn u_label_artifacts_match_a_label_suffixes() {
    let stored = nanosiem_core::internal_domains::store::with_tenant(["xn--bcher-kva.example"]);
    assert!(is_internal_artifact("db.bücher.example", ArtifactType::Domain, &stored));
    assert!(is_internal_artifact("https://db.bücher.example/x", ArtifactType::Url, &stored));
    let typed_u = nanosiem_core::internal_domains::store::with_tenant(["bücher.example"]);
    assert!(is_internal_artifact("db.xn--bcher-kva.example", ArtifactType::Domain, &typed_u));
    assert!(!is_internal_artifact("db.bucher.example", ArtifactType::Domain, &typed_u));
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5032: classification of platform-owned source types.

use super::reserved_source_types::{classify, Reservation};

#[test]
fn audit_and_findings_are_enforced_case_insensitively() {
    for v in ["audit", " AUDIT ", "findings", "Findings"] {
        assert_eq!(classify(v), Reservation::Enforced, "{v}");
    }
}

#[test]
fn warn_only_names_and_prefixes() {
    for v in ["signal", "signals", "nano_custom", "__nano:unresolved_source__"] {
        assert_eq!(classify(v), Reservation::WarnOnly, "{v}");
    }
}

#[test]
fn platform_lanes_and_ordinary_sources_are_not_reserved() {
    for v in ["nano_enrich", "nano_enrich_ioc", "nano_operational", "syslog", "linux_audit", "auditd", "audit_trail"] {
        assert_eq!(classify(v), Reservation::None, "{v}");
    }
}

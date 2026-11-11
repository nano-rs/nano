// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5264: draft state of a never-published source.
//!
//! A repository import is created linked and deployed without a publish, so it
//! has no active version. Deploy renders the working copy in that case, which
//! means nothing is unpublished until the working copy changes after the
//! deploy. The draft-status endpoint used to report `has_draft_changes: true`
//! for every such source.

use super::versioning::unversioned_has_draft;
use crate::log_sources::types::LogSource;

fn source(deployed: bool, deployed_at: Option<&str>, updated_at: &str) -> LogSource {
    serde_json::from_value(serde_json::json!({
        "id": "lsrc_00000000000000000000000000",
        "name": "Microsoft Sysmon (OCSF)",
        "description": null,
        "source_type": "routed",
        "parser_vrl": ". = {\"class_uid\": 1007}",
        "output_fields": null,
        "category": null,
        "vendor": null,
        "product": null,
        "icon": null,
        "color": null,
        "match_field": null,
        "match_pattern": null,
        "match_values": ["windows_sysmon"],
        "validated": true,
        "validation_error": null,
        "deployed": deployed,
        "deployed_at": deployed_at,
        "enabled": true,
        "stale_alert_enabled": false,
        "stale_threshold_minutes": 60,
        "sampling_ratio": null,
        "sampling_exclude_condition": null,
        "source_parser_repository_id": null,
        "source_parser_path": null,
        "created_at": "2026-11-10T00:00:00Z",
        "updated_at": updated_at,
    }))
    .expect("LogSource fixture should deserialize")
}

#[test]
fn an_imported_and_deployed_source_is_not_a_draft() {
    // The deploy UPDATE sets deployed_at and (via trigger) updated_at to the
    // same statement timestamp.
    let ls = source(true, Some("2026-11-10T01:00:00Z"), "2026-11-10T01:00:00Z");
    assert!(!unversioned_has_draft(&ls));
}

#[test]
fn an_edit_after_the_deploy_is_a_draft() {
    let ls = source(true, Some("2026-11-10T01:00:00Z"), "2026-11-10T01:05:00Z");
    assert!(unversioned_has_draft(&ls));
}

#[test]
fn an_undeployed_source_with_a_parser_is_a_draft() {
    assert!(unversioned_has_draft(&source(false, None, "2026-11-10T01:00:00Z")));
    // `deployed` without a timestamp cannot prove what is live: keep the draft.
    assert!(unversioned_has_draft(&source(true, None, "2026-11-10T01:00:00Z")));
}

#[test]
fn an_empty_source_is_never_a_draft() {
    let mut ls = source(false, None, "2026-11-10T01:00:00Z");
    ls.parser_vrl.clear();
    ls.extension_vrl = None;
    assert!(!unversioned_has_draft(&ls));
}

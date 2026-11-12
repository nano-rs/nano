// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5321: saving a VRL draft must not undeploy a published source.

use super::{deployed_reset_flags, DeployedResetFlags};
use crate::log_sources::types::UpdateLogSource;

#[test]
fn save_vrl_is_a_draft_change_not_a_config_change() {
    let flags = deployed_reset_flags(&UpdateLogSource {
        parser_vrl: Some(".x = 1".into()),
        ..Default::default()
    });
    assert_eq!(
        flags,
        DeployedResetFlags { config_changed: false, draft_changed: true, output_fields_changed: false }
    );
}

#[test]
fn extension_and_output_fields_are_draft_changes() {
    let flags = deployed_reset_flags(&UpdateLogSource {
        extension_vrl: Some(String::new()),
        extension_enabled: Some(true),
        output_fields: Some(serde_json::json!(["a"])),
        ..Default::default()
    });
    assert!(!flags.config_changed);
    assert!(flags.draft_changed);
    assert!(flags.output_fields_changed);
}

#[test]
fn routing_sampling_and_normalize_still_undeploy() {
    for update in [
        UpdateLogSource { match_values: Some(vec!["a".into()]), ..Default::default() },
        UpdateLogSource { sampling_ratio: Some(0.5), ..Default::default() },
        UpdateLogSource { source_type: Some("x".into()), ..Default::default() },
        UpdateLogSource { normalize_vrl: Some(".y = 1".into()), ..Default::default() },
    ] {
        let flags = deployed_reset_flags(&update);
        assert!(flags.config_changed, "{update:?}");
        assert!(!flags.draft_changed, "{update:?}");
    }
}

#[test]
fn metadata_only_update_changes_nothing() {
    let flags = deployed_reset_flags(&UpdateLogSource { name: Some("n".into()), ..Default::default() });
    assert!(!flags.config_changed && !flags.draft_changed);
}

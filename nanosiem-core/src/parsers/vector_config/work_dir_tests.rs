// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5678: with a work dir, the staging and backup workspaces never touch
//! the config dir. On a single node that dir is the volume Vector watches
//! recursively with `--watch-config`, so every staged tree and backup
//! snapshot written there cost a full Vector config load (all parsers' VRL
//! compiled again) on top of the reload the deploy asked for.

use super::*;

use crate::parsers::types::Parser;

fn parser(name: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: "routed".to_string(),
        parser_vrl: ".parsed = true".to_string(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled: true,
        validated: true,
        validation_error: None,
        category: None,
        vendor: None,
        product: None,
        kind: "log".to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        match_values: Some(vec![format!("{name}_key")]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Every path under `root`, relative, for "what got written here".
fn tree(root: &std::path::Path) -> std::collections::BTreeSet<String> {
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut std::collections::BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            out.insert(path.strip_prefix(root).unwrap().to_string_lossy().to_string());
            if path.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = std::collections::BTreeSet::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn blank_or_missing_work_dir_keeps_the_config_dir_layout() {
    let config = std::path::Path::new("/cfg");
    for work in [None, Some(""), Some("   ")] {
        let mgr = VectorConfigManager::new(config).with_work_dir(work);
        assert_eq!(mgr.staging_dir(), config.join("staging"));
        assert_eq!(mgr.backup_dir(), config.join("backup"));
    }
    let mgr = VectorConfigManager::new(config).with_work_dir(Some("/work"));
    assert_eq!(mgr.staging_dir(), std::path::Path::new("/work/staging"));
    assert_eq!(mgr.backup_dir(), std::path::Path::new("/work/backup"));
    assert_eq!(mgr.parsers_dir(), config.join("sources/parsers"), "the active tree does not move");
}

/// The whole deploy sequence (stage, back up, promote, restore) with a work
/// dir writes nothing new into the watched config dir outside the active
/// parsers tree (the promoted files and promotion's ownership manifest).
#[tokio::test]
async fn stage_backup_promote_and_restore_stay_out_of_the_watched_dir() {
    let config = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let mgr = VectorConfigManager::new(config.path()).with_work_dir(work.path().to_str());

    mgr.deploy_parsers(&[parser("first")]).await.unwrap();
    let before = tree(config.path());

    mgr.stage_parsers(&[parser("first"), parser("second")]).await.unwrap();
    let backup = mgr.backup_current().await.unwrap();
    mgr.promote_staged().await.unwrap();
    assert!(mgr.parsers_dir().join("second.toml").exists(), "promoted into the active tree");
    mgr.restore_backup(&backup).await.unwrap();
    assert!(!mgr.parsers_dir().join("second.toml").exists(), "restored from the work-dir backup");

    let after = tree(config.path());
    let added: Vec<_> = after
        .difference(&before)
        .filter(|path| !path.starts_with("sources/parsers/"))
        .collect();
    assert!(added.is_empty(), "nothing new in the watched config dir: {added:?}");
    assert!(!config.path().join("staging").exists());
    assert!(!config.path().join("backup").exists());
    assert!(work.path().join("backup").exists(), "the backup lives in the work dir");
}

/// NAN-5678 review: a delete keeps the rows when the render without them was
/// not applied. A write the deploy refuses (here: two sources generating one
/// file name) reports `tree_kept: false`, and the active tree is untouched.
#[tokio::test]
async fn a_refused_render_reports_the_tree_was_not_kept() {
    let config = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let mgr = VectorConfigManager::new(config.path()).with_work_dir(work.path().to_str());
    mgr.deploy_parsers(&[parser("first")]).await.unwrap();
    let before = std::fs::read(mgr.parsers_dir().join("first.toml")).unwrap();

    let mut twin = parser("first");
    twin.match_values = Some(vec!["other_key".to_string()]);
    let failure = mgr
        .deploy_and_reload_locked_graded(&[parser("first"), twin])
        .await
        .expect_err("an identity collision refuses the render");
    assert!(!failure.tree_kept, "{failure:?}");
    assert_eq!(std::fs::read(mgr.parsers_dir().join("first.toml")).unwrap(), before);
}

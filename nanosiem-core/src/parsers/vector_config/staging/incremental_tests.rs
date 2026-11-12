// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5132: only the changed source re-renders.
//!
//! The render is deterministic (no `# Generated at:` stamp), so a deploy that
//! adds one source writes exactly the new parser file plus the shared files
//! whose content depends on the source set. Promotion rewrites nothing else,
//! and the result is byte-identical to a full render of the same set.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use super::*;
use tempfile::TempDir;

fn parser(name: &str, vrl: &str, match_values: Option<Vec<&str>>) -> Parser {
    // A fixed id per name, so two renders stamp the same `_nano_parser_id`.
    let mut bytes = [0u8; 16];
    for (i, b) in name.bytes().enumerate() {
        bytes[i % 16] ^= b.wrapping_add(i as u8);
    }
    let id = uuid::Uuid::from_bytes(bytes);
    let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    Parser {
        activation_parked: false,
        id,
        name: name.to_string(),
        description: None,
        source_type: "http".to_string(),
        parser_vrl: vrl.to_string(),
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
        match_values: match_values.map(|v| v.into_iter().map(str::to_string).collect()),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: at,
        updated_at: at,
    }
}

fn fleet() -> Vec<Parser> {
    vec![
        parser("Apache Access", ".vendor = \"apache\"", Some(vec!["apache", "httpd"])),
        parser("Okta", ".vendor = \"okta\"\n.user = .actor", None),
        parser("Zeek Conn", "parsed = parse_json(.message) ?? {}\n.dest_port = parsed.id_resp_p", Some(vec!["zeek_conn"])),
        parser("Sampled", ". = .", None),
    ]
}

/// Every file in the active parsers dir, by name.
fn snapshot(manager: &VectorConfigManager) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(manager.parsers_dir())
        .expect("active dir")
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| (e.file_name().to_string_lossy().to_string(), std::fs::read(e.path()).unwrap()))
        .collect()
}

async fn deploy(manager: &VectorConfigManager, parsers: &[Parser]) {
    manager.stage_parsers(parsers).await.expect("stage");
    manager.promote_staged().await.expect("promote");
}

#[tokio::test]
async fn the_same_set_renders_the_same_bytes() {
    let (a, b) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let (ma, mb) = (VectorConfigManager::new(a.path()), VectorConfigManager::new(b.path()));
    deploy(&ma, &fleet()).await;
    // A later render (other process, other second) of the same set.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    deploy(&mb, &fleet()).await;
    let (sa, sb) = (snapshot(&ma), snapshot(&mb));
    assert!(!sa.is_empty());
    for (name, bytes) in &sa {
        assert!(
            sb.get(name) == Some(bytes),
            "{name} differs between two renders of the same source set"
        );
    }
    assert_eq!(sa.len(), sb.len());
}

#[tokio::test]
async fn adding_a_source_matches_a_full_render_and_touches_only_what_depends_on_it() {
    let all = fleet();
    let (before_set, added) = (&all[..all.len() - 1], &all[all.len() - 1]);

    // Incremental: N-1 deployed, then one source added.
    let inc = TempDir::new().unwrap();
    let incremental = VectorConfigManager::new(inc.path());
    deploy(&incremental, before_set).await;
    let before = snapshot(&incremental);
    deploy(&incremental, &all).await;
    let after = snapshot(&incremental);

    // Full: the N set rendered from scratch.
    let full_dir = TempDir::new().unwrap();
    let full = VectorConfigManager::new(full_dir.path());
    deploy(&full, &all).await;
    assert_eq!(after, snapshot(&full), "incremental and full renders differ");

    let mut changed: BTreeSet<String> = after
        .iter()
        .filter(|(name, bytes)| before.get(*name) != Some(*bytes))
        .map(|(name, _)| name.clone())
        .collect();
    let expected: BTreeSet<String> = [
        format!("{}.toml", VectorConfigManager::safe_name(&added.name)),
        "_router.toml".to_string(),
        "_combiner.toml".to_string(),
        ".nano-generated".to_string(),
    ]
    .into_iter()
    .collect();
    // The OCSF sink may change with the source set (it lists every parser) or
    // not (NAN-5132 stable fan-in slots, #9297, keep it constant). Either is
    // allowed, so this test holds whichever of the two PRs merges first.
    changed.remove("_ocsf_sink.toml");
    assert_eq!(changed, expected, "files rewritten by adding one source");
    for name in before.keys() {
        assert!(after.contains_key(name), "{name} disappeared");
    }
}

#[tokio::test]
async fn promotion_leaves_unchanged_files_untouched() {
    let tmp = TempDir::new().unwrap();
    let manager = VectorConfigManager::new(tmp.path());
    let all = fleet();
    deploy(&manager, &all[..2]).await;

    // Age every active file; a rewrite would bump its mtime.
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    for name in snapshot(&manager).keys() {
        let file = std::fs::File::options()
            .write(true)
            .open(manager.parsers_dir().join(name))
            .unwrap();
        file.set_modified(old).unwrap();
    }

    // Redeploying the same set rewrites nothing but the ownership manifest.
    deploy(&manager, &all[..2]).await;
    let rewritten: Vec<String> = snapshot(&manager)
        .keys()
        .filter(|name| {
            std::fs::metadata(manager.parsers_dir().join(name))
                .and_then(|m| m.modified())
                .map(|m| m != old)
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    assert_eq!(rewritten, vec![".nano-generated".to_string()]);

    // A changed parser rewrites its own file (and nothing it does not affect).
    let mut edited = all[..2].to_vec();
    edited[1].parser_vrl = ".vendor = \"okta\"\n.user = .actor\n.edited = true".to_string();
    deploy(&manager, &edited).await;
    let okta = format!("{}.toml", VectorConfigManager::safe_name("Okta"));
    let apache = format!("{}.toml", VectorConfigManager::safe_name("Apache Access"));
    let modified = |name: &str| {
        std::fs::metadata(manager.parsers_dir().join(name)).unwrap().modified().unwrap()
    };
    assert_ne!(modified(&okta), old, "the edited parser's file was not rewritten");
    assert_eq!(modified(&apache), old, "an untouched parser's file was rewritten");
    assert_eq!(modified("_router.toml"), old, "a VRL edit does not change the router");
}

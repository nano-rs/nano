// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2305 — removing a source is one coherent write, never an unlink.
//!
//! `LogSourceService::delete` used to unlink the parser TOML on its own and
//! only afterwards ask for a redeploy. Between those two steps `_combiner.toml`
//! named a transform whose file no longer existed, and Vector treats an input
//! naming a missing component as fatal to the WHOLE config — so any reload in
//! that window (a concurrent deploy's, or `--watch-config` reacting to the
//! unlink itself) was rejected and Vector carried on with the pre-delete
//! topology.
//!
//! The fix deletes by REGENERATING from the surviving sources under the deploy
//! lock. That correctness argument rests entirely on `deploy_parsers` pruning
//! the orphan and rewriting the combiner in the same pass, which is what these
//! tests pin. If that pruning is ever dropped, deletion silently goes back to
//! leaving a dangling `source_router.<deleted>` input behind — with no unlink
//! anywhere to make it obvious where the file came from.

use super::*;

use tempfile::TempDir;

fn log_parser(name: &str) -> Parser {
    Parser {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: name.to_string(),
        parser_vrl: ". = parse_json!(.message)".to_string(),
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
        match_values: None,
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Deleting by regeneration has to leave NO trace of the removed source: not
/// the parser file, and not an input naming it. Both halves matter — a pruned
/// file with a stale combiner input is the exact config Vector refuses, and a
/// clean combiner beside an orphaned parser file is the NAN-2296 rename bug.
#[tokio::test]
async fn regenerating_without_a_source_removes_its_file_and_its_combiner_input() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let keep = log_parser("apache_http_server");
    let drop_me = log_parser("github_public_events");

    manager
        .deploy_parsers(&[keep.clone(), drop_me.clone()])
        .await
        .expect("initial deploy");

    let parsers_dir = manager.parsers_dir();
    assert!(parsers_dir.join("github_public_events.toml").exists());
    let combiner = fs::read_to_string(parsers_dir.join("_combiner.toml"))
        .await
        .expect("combiner");
    assert!(
        combiner.contains("github_public_events"),
        "test is not exercising anything if the source was never wired in"
    );

    // The delete path: republish from the survivors only.
    manager
        .deploy_parsers(&[keep])
        .await
        .expect("redeploy without the deleted source");

    assert!(
        !parsers_dir.join("github_public_events.toml").exists(),
        "the deleted source's parser file survived the regeneration — deletion no longer removes \
         it, and nothing else does either"
    );
    let combiner = fs::read_to_string(parsers_dir.join("_combiner.toml"))
        .await
        .expect("combiner");
    assert!(
        !combiner.contains("github_public_events"),
        "_combiner.toml still names the deleted source; Vector rejects a config whose input names \
         a missing component, so this would freeze the whole pipeline:\n{combiner}"
    );
    assert!(
        combiner.contains("apache_http_server"),
        "regeneration dropped a surviving source:\n{combiner}"
    );
}

/// The hazard the delete path must not reintroduce, stated as a property:
/// unlinking a parser file on its own leaves the combiner pointing at it. This
/// is why `remove_parser_config` is no longer called for a deployed source —
/// not as a tidy-up, but because on its own it PRODUCES the broken config.
#[tokio::test]
async fn unlinking_a_parser_file_alone_leaves_a_dangling_combiner_input() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let keep = log_parser("apache_http_server");
    let drop_me = log_parser("github_public_events");
    manager
        .deploy_parsers(&[keep, drop_me])
        .await
        .expect("initial deploy");

    manager
        .remove_parser_config("github_public_events")
        .await
        .expect("unlink");

    let parsers_dir = manager.parsers_dir();
    assert!(!parsers_dir.join("github_public_events.toml").exists());
    let combiner = fs::read_to_string(parsers_dir.join("_combiner.toml"))
        .await
        .expect("combiner");
    assert!(
        combiner.contains("github_public_events"),
        "if this ever stops holding, `remove_parser_config` has grown into a complete removal and \
         the ordering constraint in LogSourceService::delete can be relaxed — until then, an \
         unlink on its own is a config Vector will refuse:\n{combiner}"
    );
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2301 — the backup is the rollback target, so it has to be whole,
//! coherent, and honest about "there was nothing here".
//!
//! NAN-2302 — and restoring it has to be as careful as taking it: the active
//! tree is never emptied, the previous backup outlives the new one's assembly,
//! and the coherence gate covers the whole component graph instead of one
//! prefix.

use super::*;
use crate::parsers::types::Parser;
use tempfile::TempDir;

async fn manager_with_active(files: &[(&str, &str)]) -> (TempDir, VectorConfigManager) {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());
    fs::create_dir_all(&manager.parsers_dir).await.expect("mkdir");
    for (name, body) in files {
        fs::write(manager.parsers_dir.join(name), body)
            .await
            .expect("write active");
    }
    (tmp, manager)
}

/// A coherent tree: every `source_router.<name>` input has a matching route.
fn coherent() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "_router.toml",
            "[transforms.source_router.route]\napache = '.source_type == \"apache\"'\n",
        ),
        (
            "apache.toml",
            "[transforms.apache_parse]\ninputs = [\"source_router.apache\"]\n",
        ),
    ]
}

#[tokio::test]
async fn backup_then_restore_round_trips_a_coherent_tree() {
    let (_tmp, manager) = manager_with_active(&coherent()).await;

    let gen = manager.backup_current().await.expect("backup");
    assert!(manager.backup_dir().join(BACKUP_COMPLETE_MARKER).exists());

    fs::write(manager.parsers_dir.join("apache.toml"), "CLOBBERED")
        .await
        .unwrap();
    manager.restore_backup(&gen).await.expect("restore");

    assert_eq!(
        fs::read_to_string(manager.parsers_dir.join("apache.toml"))
            .await
            .unwrap(),
        "[transforms.apache_parse]\ninputs = [\"source_router.apache\"]\n"
    );
    // The marker describes the backup, not a Vector config — it must not be
    // left behind in the active tree to be re-copied into the next backup.
    assert!(!manager.parsers_dir.join(BACKUP_COMPLETE_MARKER).exists());
}

/// The headline risk. NAN-2296's failure state is a regenerated `_router.toml`
/// beside a stale parser TOML naming a route that no longer exists. Snapshotting
/// that and later restoring it re-creates the dangling input and takes the whole
/// Vector config down — which is exactly the outage NAN-2296 fixed.
#[tokio::test]
async fn a_poisoned_active_tree_is_refused_as_a_rollback_target() {
    let (_tmp, manager) = manager_with_active(&coherent()).await;
    let first = manager.backup_current().await.expect("first backup");

    // Now poison the active tree the way a rename used to.
    fs::write(
        manager.parsers_dir.join("apache__old_.toml"),
        "[transforms.apache__old__parse]\ninputs = [\"source_router.apache__old_\"]\n",
    )
    .await
    .unwrap();

    let err = manager
        .backup_current()
        .await
        .expect_err("a tree with a dangling router input must not become the rollback target");
    let msg = format!("{err}");
    assert!(msg.contains("apache__old_"), "unexpected error: {msg}");

    // And the earlier, coherent backup is still intact — an older but loadable
    // rollback target beats a fresh unloadable one.
    assert!(manager.backup_dir().join(BACKUP_COMPLETE_MARKER).exists());
    assert!(!manager.backup_dir().join("apache__old_.toml").exists());
    assert!(manager.backup_dir().join("apache.toml").exists());
}

/// "No previous tree" is a real state, not an absence of information. It used to
/// return Ok having already deleted the old backup, so the caller believed it
/// had a rollback target when it had none and a failed deploy stayed live.
#[tokio::test]
async fn an_absent_active_tree_records_an_empty_rollback_target() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let gen = manager.backup_current().await.expect("backup");
    assert!(manager.backup_dir().join(BACKUP_COMPLETE_MARKER).exists());

    // A deploy then promotes something...
    fs::create_dir_all(&manager.parsers_dir).await.unwrap();
    fs::write(manager.parsers_dir.join("apache.toml"), "NEW")
        .await
        .unwrap();

    // ...and rolling back removes it, rather than silently leaving it live.
    manager.restore_backup(&gen).await.expect("restore");
    assert!(!manager.parsers_dir.join("apache.toml").exists());
}

/// An unmarked backup is either a partial write or a pre-NAN-2301 directory of
/// unknown integrity. Restoring it would publish a tree that was never whole.
#[tokio::test]
async fn an_unmarked_backup_is_refused() {
    let (_tmp, manager) = manager_with_active(&coherent()).await;
    let gen = manager.backup_current().await.expect("backup");

    fs::remove_file(manager.backup_dir().join(BACKUP_COMPLETE_MARKER))
        .await
        .unwrap();

    manager
        .restore_backup(&gen)
        .await
        .expect_err("an unmarked backup must not be restored");
    // The active tree is untouched by the refusal.
    assert!(manager.parsers_dir.join("apache.toml").exists());
}

/// The destructive path the generation token exists to close.
///
/// Fresh install records an EMPTY backup. A later, legitimate tree fails to
/// snapshot — a coherence-gate refusal, a permissions blip, anything — so the
/// empty snapshot survives as the newest backup. That deploy then fails its
/// reload. Without the token the rollback restores the empty snapshot and
/// deletes a live config that was never in trouble.
#[tokio::test]
async fn a_generation_from_an_earlier_attempt_is_refused() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    // Deploy 1, fresh install: nothing to back up, so an EMPTY snapshot. This
    // is the dangerous one — restoring it deletes whatever is live.
    let first = manager.backup_current().await.expect("first backup");

    // A real config goes live, and deploy 2 snapshots it.
    fs::create_dir_all(&manager.parsers_dir).await.unwrap();
    for (name, body) in coherent() {
        fs::write(manager.parsers_dir.join(name), body).await.unwrap();
    }
    let second = manager.backup_current().await.expect("second backup");
    assert_ne!(first, second);

    // Deploy 1's token must no longer open the door. Without this check a
    // caller holding a stale generation could restore an unrelated starting
    // state over a healthy config — and when that state is the empty
    // first-install snapshot, "restore" means "delete everything".
    manager
        .restore_backup(&first)
        .await
        .expect_err("a generation from an earlier attempt must not be restorable");
    assert!(manager.parsers_dir.join("apache.toml").exists());

    // The current attempt's own token still works.
    manager
        .restore_backup(&second)
        .await
        .expect("the snapshot taken for this attempt restores");
}

/// The other half of the destructive path: when a snapshot FAILS, the deploy
/// gets no token at all, so there is nothing for it to restore with. The stale
/// backup stays on disk untouched rather than becoming this deploy's rollback
/// target by default.
#[tokio::test]
async fn a_failed_snapshot_yields_no_token_and_leaves_the_old_backup_alone() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let first = manager.backup_current().await.expect("first backup");

    fs::create_dir_all(&manager.parsers_dir).await.unwrap();
    for (name, body) in coherent() {
        fs::write(manager.parsers_dir.join(name), body).await.unwrap();
    }
    fs::write(
        manager.parsers_dir.join("apache__old_.toml"),
        "[transforms.apache__old__parse]\ninputs = [\"source_router.apache__old_\"]\n",
    )
    .await
    .unwrap();

    // Poisoned tree: no snapshot, so the caller has no generation to roll back
    // with, and the earlier backup is still exactly as it was.
    assert!(manager.backup_current().await.is_err());
    let marker = fs::read_to_string(manager.backup_dir().join(BACKUP_COMPLETE_MARKER))
        .await
        .unwrap();
    assert_eq!(marker.trim(), format!("{}", DisplayGeneration(&first)));
}

/// Small shim so the test can compare against the opaque generation without
/// exposing its inner value on the public type.
struct DisplayGeneration<'a>(&'a BackupGeneration);
impl std::fmt::Display for DisplayGeneration<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0 .0)
    }
}

/// The gate parses TOML rather than scanning lines, so a `source_router.x`
/// appearing in a comment or inside a parser's VRL body is not a route
/// reference. A false positive here fails the backup, and a failed backup is
/// what leaves a deploy with no rollback target.
#[tokio::test]
async fn the_gate_ignores_router_names_in_comments_and_vrl_bodies() {
    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.source_router.route]\napache = '.source_type == \"apache\"'\n",
        ),
        (
            "apache.toml",
            "# migrated from source_router.legacy_apache\n\
             [transforms.apache_parse]\n\
             inputs = [\"source_router.apache\"]\n\
             type = \"remap\"\n\
             source = '''\n\
             .note = \"source_router.not_a_real_route\"\n\
             '''\n",
        ),
    ])
    .await;

    manager
        .backup_current()
        .await
        .expect("a comment and a VRL string literal are not route references");
}

/// Multi-line `inputs` arrays are normal TOML. The line scan this replaced saw
/// only the `inputs = [` line and missed the entry entirely.
#[tokio::test]
async fn the_gate_sees_dangling_inputs_in_multi_line_arrays() {
    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.source_router.route]\napache = '.source_type == \"apache\"'\n",
        ),
        (
            "stale.toml",
            "[transforms.stale_parse]\ninputs = [\n  \"source_router.gone\",\n]\n",
        ),
    ])
    .await;

    let err = manager
        .backup_current()
        .await
        .expect_err("a dangling input spread over lines is still dangling");
    assert!(format!("{err}").contains("gone"));
}

/// An absent router is not a clean bill of health: a parser consuming
/// `source_router.x` with no router at all is exactly as dangling.
#[tokio::test]
async fn the_gate_refuses_source_router_inputs_with_no_router_at_all() {
    let (_tmp, manager) = manager_with_active(&[(
        "apache.toml",
        "[transforms.apache_parse]\ninputs = [\"source_router.apache\"]\n",
    )])
    .await;

    manager
        .backup_current()
        .await
        .expect_err("no router means every source_router input dangles");
}

// ---------------------------------------------------------------------------
// NAN-2302: the restore publishes atomically
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn inode_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("stat").ino()
}

/// The active parsers directory must survive a restore as the SAME directory.
///
/// `restore_backup` used to `remove_dir_all(parsers_dir)` and copy the backup
/// into a freshly created directory. Two things follow from that, and both are
/// checked here:
///
/// 1. There is a window in which the active config is gone or half-written. Any
///    copy error or process death lands in it, and an input naming a missing
///    component is fatal to the WHOLE Vector config — so a half-restored tree is
///    a total ingest outage produced by the code whose job is to end one.
/// 2. The directory gets a new inode. `sources/parsers` is its OWN bind mount in
///    the Vector container (docker-compose.yml mounts it separately because the
///    parent is read-only) and its own mount path in the Kubernetes pod. A bind
///    mount follows the inode it was created from, so replacing the directory
///    leaves Vector reading the tree we then delete.
///
/// Contents still mirror the snapshot exactly; only the directory's identity and
/// the dotfiles that are not ours survive.
#[cfg(unix)]
#[tokio::test]
async fn restore_publishes_into_the_live_directory_without_recreating_it() {
    let (_tmp, manager) = manager_with_active(&coherent()).await;

    let gen = manager.backup_current().await.expect("backup");
    let before = inode_of(&manager.parsers_dir);

    // Written AFTER the snapshot, so it survives only because the prune leaves
    // dotfiles alone — not because the snapshot happened to contain it. Matches
    // `promote_staged`: `.gitkeep` and friends are not ours to delete.
    fs::write(manager.parsers_dir.join(".gitkeep"), "")
        .await
        .unwrap();

    // A deploy goes bad: it clobbers one file and adds an orphan.
    fs::write(manager.parsers_dir.join("apache.toml"), "CLOBBERED")
        .await
        .unwrap();
    fs::write(manager.parsers_dir.join("orphan.toml"), "added after the snapshot")
        .await
        .unwrap();

    manager.restore_backup(&gen).await.expect("restore");

    assert_eq!(
        before,
        inode_of(&manager.parsers_dir),
        "the active parsers directory was replaced rather than published into — \
         that breaks the bind mount Vector reads it through"
    );
    assert!(
        manager.parsers_dir.join(".gitkeep").exists(),
        "a dotfile that is not ours was destroyed by the rollback"
    );
    // Still a faithful mirror of the snapshot.
    assert_eq!(
        fs::read_to_string(manager.parsers_dir.join("apache.toml"))
            .await
            .unwrap(),
        "[transforms.apache_parse]\ninputs = [\"source_router.apache\"]\n"
    );
    assert!(
        !manager.parsers_dir.join("orphan.toml").exists(),
        "a file added after the snapshot survived the rollback"
    );
}

/// A restore that cannot finish must not have touched the active config.
///
/// The old order — delete the active tree, then copy — meant a copy that failed
/// for any reason left NOTHING behind. Everything fallible now happens in a
/// workspace beside the active tree.
///
/// Runs as a normal user only: the fault is an unreadable source file, and root
/// reads it anyway.
#[cfg(unix)]
#[tokio::test]
async fn a_restore_that_cannot_finish_leaves_the_active_config_alone() {
    use std::os::unix::fs::PermissionsExt;

    let (_tmp, manager) = manager_with_active(&coherent()).await;
    let gen = manager.backup_current().await.expect("backup");

    // Make one file in the snapshot unreadable, so assembling the restored tree
    // fails partway through.
    let victim = manager.backup_dir().join("apache.toml");
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::read(&victim).is_ok() {
        // Running as root (self-hosted CI containers do). Permissions cannot
        // create the fault, and there is no portable substitute.
        eprintln!("skipping: running as root, cannot make a file unreadable");
        return;
    }

    let err = manager.restore_backup(&gen).await;
    // Restore permissions before asserting, so a failure does not leave the
    // temp dir undeletable.
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).expect("chmod back");

    assert!(err.is_err(), "an unreadable snapshot must not restore");
    assert!(
        manager.parsers_dir.join("apache.toml").exists()
            && manager.parsers_dir.join("_router.toml").exists(),
        "a failed restore deleted the active config it was supposed to protect"
    );
}

/// The completion marker is left OUT of the restored tree rather than copied in
/// and deleted afterwards.
///
/// The old order leaked it permanently whenever the process died in between:
/// NAN-2296's prune skips dotfiles, so nothing removes it, and the next
/// `backup_current` copies it straight back into the new snapshot — where it
/// looks exactly like a completion marker for a tree nobody finished writing.
#[tokio::test]
async fn the_restored_tree_is_assembled_without_the_completion_marker() {
    let (_tmp, manager) = manager_with_active(&coherent()).await;
    manager.backup_current().await.expect("backup");

    let workspace = manager.parsers_dir.with_file_name(".assembled");
    manager
        .copy_dir_filtered(manager.backup_dir(), &workspace, &[BACKUP_COMPLETE_MARKER])
        .await
        .expect("assemble");

    assert!(
        !workspace.join(BACKUP_COMPLETE_MARKER).exists(),
        "the marker reached the tree that gets published over the active config"
    );
    assert!(workspace.join("apache.toml").exists());
    assert!(workspace.join("_router.toml").exists());
}

/// A marker stranded in the active tree by a pre-NAN-2302 restore is cleaned up
/// rather than carried forward forever.
#[tokio::test]
async fn a_stranded_marker_in_the_active_tree_is_removed_by_the_next_restore() {
    let (_tmp, manager) = manager_with_active(&coherent()).await;
    let gen = manager.backup_current().await.expect("backup");

    // What a crash between "copy the marker in" and "delete it" used to leave.
    fs::write(manager.parsers_dir.join(BACKUP_COMPLETE_MARKER), "stale")
        .await
        .unwrap();

    manager.restore_backup(&gen).await.expect("restore");
    assert!(!manager.parsers_dir.join(BACKUP_COMPLETE_MARKER).exists());
}

/// The previous backup outlives the new one's arrival.
///
/// The swap used to be `remove_dir_all(backup_dir)` then `rename(staging,
/// backup_dir)`. Anything that stopped the rename — process death, a rename
/// failure — left NO rollback target at all, at the exact moment a deploy was
/// about to need one. The rename-aside order means the failure path can always
/// put the old snapshot back.
#[tokio::test]
async fn a_failed_swap_puts_the_previous_backup_back() {
    let (_tmp, manager) = manager_with_active(&coherent()).await;
    let first = manager.backup_current().await.expect("first backup");

    // A staging path that does not exist: the second rename fails, standing in
    // for every way the new snapshot can fail to land.
    let missing = manager.backup_dir().with_file_name(".never-written");
    manager
        .swap_in_backup(&missing)
        .await
        .expect_err("swapping in a snapshot that is not there must fail");

    assert!(
        manager.backup_dir().join(BACKUP_COMPLETE_MARKER).exists(),
        "the previous rollback target was destroyed by a swap that never completed"
    );
    assert!(manager.backup_dir().join("apache.toml").exists());

    // And it is still the same snapshot, so its generation still restores.
    manager
        .restore_backup(&first)
        .await
        .expect("the surviving snapshot is intact and restorable");
}

/// A successful backup leaves no workspace directories behind.
#[tokio::test]
async fn the_swap_cleans_up_after_itself() {
    let (tmp, manager) = manager_with_active(&coherent()).await;
    manager.backup_current().await.expect("first backup");
    manager.backup_current().await.expect("second backup");

    let mut leftovers = Vec::new();
    let mut entries = fs::read_dir(tmp.path()).await.unwrap();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.contains(".tmp-") || name.contains(".retired-") {
            leftovers.push(name);
        }
    }
    assert!(leftovers.is_empty(), "workspace directories leaked: {leftovers:?}");
}

// ---------------------------------------------------------------------------
// NAN-2302: the coherence gate covers the component graph
// ---------------------------------------------------------------------------

/// The `_combiner.toml` case. It unions every enabled parser's `<name>_output`,
/// so a parser file removed or renamed without regenerating the combiner leaves
/// an input no component declares — fatal to the whole config, exactly like the
/// NAN-2296 router shape, and invisible to a gate that only inspected inputs
/// beginning `source_router.`.
#[tokio::test]
async fn the_gate_catches_a_combiner_wired_to_a_parser_that_is_gone() {
    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.source_router]\ntype = \"route\"\n\n\
             [transforms.source_router.route]\napache = '.source_type == \"apache\"'\n",
        ),
        (
            "apache.toml",
            "[transforms.apache_parse]\ntype = \"remap\"\ninputs = [\"source_router.apache\"]\n\n\
             [transforms.apache_output]\ntype = \"remap\"\ninputs = [\"apache_parse\"]\n",
        ),
        (
            "_combiner.toml",
            "[transforms.db_parsers_combined]\ntype = \"remap\"\n\
             inputs = [\"apache_output\", \"sysmon_output\"]\n",
        ),
    ])
    .await;

    let err = manager
        .backup_current()
        .await
        .expect_err("a combiner input no parser declares must not be recorded as restorable");
    assert!(format!("{err}").contains("sysmon_output"), "{err}");
}

/// The enrichment lane has its own router, and its routes rot the same way.
#[tokio::test]
async fn the_gate_catches_a_dangling_enrichment_router_route() {
    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.enrichment_router]\ntype = \"route\"\n\n\
             [transforms.enrichment_router.route]\nip_context = 'true'\n",
        ),
        (
            "_enrichment.toml",
            "[transforms.enrichment_normalize_ad]\ntype = \"remap\"\n\
             inputs = [\"enrichment_router.identity\"]\n",
        ),
    ])
    .await;

    let err = manager
        .backup_current()
        .await
        .expect_err("an enrichment route the router no longer emits is dangling");
    assert!(format!("{err}").contains("enrichment_router.identity"), "{err}");
}

/// NAN-1584's shape: the OCSF sink forks every enabled parser's
/// `<name>_ocsf_prepare`, so a sink left wired to a parser that no longer emits
/// one is a broken config the old gate could not see.
#[tokio::test]
async fn the_gate_catches_an_ocsf_sink_fork_no_parser_emits() {
    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.source_router]\ntype = \"route\"\n\n\
             [transforms.source_router.route]\napache = 'true'\n",
        ),
        (
            "apache.toml",
            "[transforms.apache_parse]\ntype = \"remap\"\ninputs = [\"source_router.apache\"]\n",
        ),
        (
            "_ocsf_sink.toml",
            "[sinks.clickhouse_ocsf_logs]\ntype = \"clickhouse\"\n\
             inputs = [\"apache_ocsf_prepare\"]\n",
        ),
    ])
    .await;

    let err = manager
        .backup_current()
        .await
        .expect_err("an OCSF fork no parser emits is dangling");
    assert!(format!("{err}").contains("apache_ocsf_prepare"), "{err}");
}

/// The gate must read `_pipeline.toml`, and `_pipeline.toml` is not valid TOML.
///
/// It carries `max_bytes = ${VECTOR_BATCH_MAX_BYTES:-52428800}` — an unquoted
/// interpolation Vector substitutes before parsing. Without mirroring that
/// substitution the file never parses, the gate loses every declaration it
/// makes, and it has to fall silent to avoid reporting `prepare_output` and
/// friends as missing. The dangling combiner input below is what silence costs.
#[tokio::test]
async fn the_gate_reads_files_that_use_env_interpolation() {
    let pipeline = "[transforms.prepare_output]\ntype = \"remap\"\ninputs = [\"generic_parser\"]\n\n\
                    [transforms.generic_parser]\ntype = \"remap\"\ninputs = [\"source_router.generic\"]\n\n\
                    [sinks.clickhouse_logs]\ntype = \"clickhouse\"\ninputs = [\"prepare_output\"]\n\n\
                    [sinks.clickhouse_logs.batch]\nmax_bytes = ${VECTOR_BATCH_MAX_BYTES:-52428800}\n";

    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.source_router]\ntype = \"route\"\n\n\
             [transforms.source_router.route]\ngeneric = 'true'\n",
        ),
        ("_pipeline.toml", pipeline),
        (
            "_combiner.toml",
            "[transforms.db_parsers_combined]\ntype = \"remap\"\ninputs = [\"ghost_output\"]\n",
        ),
    ])
    .await;

    let err = manager
        .backup_current()
        .await
        .expect_err("the gate must still see the graph through env interpolation");
    assert!(format!("{err}").contains("ghost_output"), "{err}");

    // And the components the interpolated file DOES declare are honoured: with
    // the combiner healed, the same tree is coherent.
    fs::write(
        manager.parsers_dir.join("_combiner.toml"),
        "[transforms.db_parsers_combined]\ntype = \"remap\"\ninputs = [\"prepare_output\"]\n",
    )
    .await
    .unwrap();
    manager
        .backup_current()
        .await
        .expect("prepare_output is declared by the interpolated pipeline");
}

/// The gate covers the parser tree, not the whole Vector config.
///
/// `_router.toml` consumes `vector_merge` and `otlp_logs_prep` from the base
/// configs and `<source>_route` from `sources/configs`; dispatch-bound parsers
/// consume a source-config filter directly. None of those are in this tree, and
/// flagging them would fail every backup on every real deployment — which costs
/// the deploy in progress its rollback target.
#[tokio::test]
async fn the_gate_does_not_flag_components_that_live_outside_the_tree() {
    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.source_router]\ntype = \"route\"\n\
             inputs = [\"vector_merge\", \"otlp_logs_prep\", \"aws_alb_route\", \"http_ingestion_route\"]\n\n\
             [transforms.source_router.route]\napache = 'true'\n",
        ),
        (
            "aws_alb_access_logs.toml",
            "[transforms.aws_alb_access_logs_filter]\ntype = \"filter\"\ninputs = [\"aws_alb_route\"]\n",
        ),
    ])
    .await;

    manager
        .backup_current()
        .await
        .expect("components declared in sibling config directories are not dangling");
}

/// `foo_parse.dropped` is a named output on a non-route transform. Whether a
/// transform has one depends on its type and settings, which this tree cannot
/// decide, so it is accepted rather than guessed at.
#[tokio::test]
async fn the_gate_accepts_named_outputs_on_declared_non_route_components() {
    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.source_router]\ntype = \"route\"\n\n\
             [transforms.source_router.route]\napache = 'true'\n",
        ),
        (
            "apache.toml",
            "[transforms.apache_parse]\ntype = \"remap\"\ninputs = [\"source_router.apache\"]\n\n\
             [transforms.apache_output]\ntype = \"remap\"\n\
             inputs = [\"apache_parse\", \"apache_parse.dropped\"]\n",
        ),
    ])
    .await;

    manager
        .backup_current()
        .await
        .expect("a .dropped output on a declared transform is not a dangling reference");
}

/// A route transform's built-in `_unmatched` output is not a declared route.
#[tokio::test]
async fn the_gate_accepts_the_builtin_unmatched_route_output() {
    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.source_router]\ntype = \"route\"\n\n\
             [transforms.source_router.route]\napache = 'true'\n",
        ),
        (
            "catchall.toml",
            "[transforms.catchall]\ntype = \"remap\"\ninputs = [\"source_router._unmatched\"]\n",
        ),
    ])
    .await;

    manager
        .backup_current()
        .await
        .expect("_unmatched is emitted by every route transform");
}

/// A file the parser cannot read degrades the gate; it does not fail the backup.
///
/// `toml::from_str` is stricter than Vector's own loader — `_pipeline.toml`
/// proved that — so "we could not parse it" is not evidence the config is
/// broken. Treating it as a refusal would fail backups on configs Vector loads
/// fine, and a refused backup is what leaves a deploy with no rollback target.
#[tokio::test]
async fn an_unparseable_file_degrades_the_gate_instead_of_failing_the_backup() {
    let (_tmp, manager) = manager_with_active(&[
        (
            "_router.toml",
            "[transforms.source_router]\ntype = \"route\"\n\n\
             [transforms.source_router.route]\napache = 'true'\n",
        ),
        // Not TOML at all, and not something this gate gets to veto.
        ("_pipeline.toml", "this is [not valid = toml @@@\n"),
        (
            "_combiner.toml",
            "[transforms.db_parsers_combined]\ntype = \"remap\"\ninputs = [\"prepare_output\"]\n",
        ),
    ])
    .await;

    manager
        .backup_current()
        .await
        .expect("an unreadable file must not be turned into a refusal to record a rollback target");
}

/// An unreadable `_router.toml` means we do not know which routes exist, so the
/// route checks stay quiet rather than reporting every route as deleted.
#[tokio::test]
async fn an_unparseable_router_silences_the_route_checks() {
    let (_tmp, manager) = manager_with_active(&[
        ("_router.toml", "[transforms.source_router\nbroken = \n"),
        (
            "apache.toml",
            "[transforms.apache_parse]\ntype = \"remap\"\ninputs = [\"source_router.apache\"]\n",
        ),
    ])
    .await;

    manager
        .backup_current()
        .await
        .expect("an unreadable router is not proof that a route was deleted");
}

// ---------------------------------------------------------------------------
// The gate against a real generated tree
// ---------------------------------------------------------------------------

fn log_parser(name: &str) -> Parser {
    Parser {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        // "routed" is what puts a parser behind `source_router`.
        source_type: "routed".to_string(),
        parser_vrl: ".parsed = true\n".to_string(),
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
        match_values: Some(vec![name.to_string()]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// The false-positive guard that matters most: a tree produced by the real
/// generators must pass the gate.
///
/// Every widening of this check is a new way to refuse a backup, and a refused
/// backup means the deploy in progress has no rollback target. So the gate is
/// run against what `stage_parsers` + `promote_staged` actually write —
/// `_router.toml`, `_combiner.toml`, `_pipeline.toml`, `_enrichment.toml` and
/// the per-parser files — rather than against hand-written fixtures that agree
/// with it by construction.
#[tokio::test]
async fn a_tree_from_the_real_generators_passes_the_gate() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let parsers = vec![log_parser("apache_http_server"), log_parser("sysmon_json")];
    manager.stage_parsers(&parsers).await.expect("stage");
    manager.promote_staged().await.expect("promote");

    // Sanity: the tree really is the generated one, not an empty directory that
    // would pass the gate for the wrong reason.
    for expected in ["_router.toml", "_combiner.toml", "_pipeline.toml", "_enrichment.toml"] {
        assert!(
            manager.parsers_dir.join(expected).exists(),
            "{expected} missing — the fixture is not a real generated tree"
        );
    }

    manager
        .backup_current()
        .await
        .expect("the tree this codebase generates must be recordable as a rollback target");
}

/// And it round-trips: the generated tree restores byte-for-byte.
#[tokio::test]
async fn a_tree_from_the_real_generators_round_trips_through_a_rollback() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let parsers = vec![log_parser("apache_http_server")];
    manager.stage_parsers(&parsers).await.expect("stage");
    manager.promote_staged().await.expect("promote");

    let mut before = Vec::new();
    let mut entries = fs::read_dir(&manager.parsers_dir).await.unwrap();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        let name = entry.file_name().to_string_lossy().to_string();
        before.push((name, fs::read_to_string(entry.path()).await.unwrap()));
    }
    before.sort();

    let gen = manager.backup_current().await.expect("backup");

    // A bad deploy lands.
    fs::write(manager.parsers_dir.join("_router.toml"), "WRECKED")
        .await
        .unwrap();
    fs::write(manager.parsers_dir.join("late_arrival.toml"), "x")
        .await
        .unwrap();

    manager.restore_backup(&gen).await.expect("restore");

    let mut after = Vec::new();
    let mut entries = fs::read_dir(&manager.parsers_dir).await.unwrap();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        let name = entry.file_name().to_string_lossy().to_string();
        after.push((name, fs::read_to_string(entry.path()).await.unwrap()));
    }
    after.sort();

    assert_eq!(before, after, "the rollback did not reproduce the snapshot exactly");
}

// ---------------------------------------------------------------------------
// Graph unit tests
// ---------------------------------------------------------------------------

fn graph(docs: &[(&str, &str)]) -> ComponentGraph {
    let owned: Vec<(String, String)> = docs
        .iter()
        .map(|(n, b)| (n.to_string(), b.to_string()))
        .collect();
    ComponentGraph::from_documents(&owned)
}

#[test]
fn route_names_are_read_per_router_not_pooled() {
    let toml = "\
[transforms.aws_alb_route_unclaimed]\n\
type = \"filter\"\n\
condition = 'x'\n\
\n\
[transforms.source_router]\n\
type = \"route\"\n\
\n\
[transforms.source_router.route]\n\
apache_http_server = 'includes([\"apache\"], .source_type)'\n\
generic = '!includes([\"apache\"], .source_type)'\n\
\n\
[transforms.enrichment_router]\n\
type = \"route\"\n\
\n\
[transforms.enrichment_router.route]\n\
identity = 'x'\n";

    let g = graph(&[("_router.toml", toml)]);
    let source = g.route_names("source_router").expect("source_router is a route");
    assert!(source.contains("apache_http_server"));
    assert!(source.contains("generic"));
    // Belongs to a different route table — counting it would mask a dangling
    // input against the source router.
    assert!(!source.contains("identity"));
    // Not a route key at all.
    assert!(!source.contains("type"));
    assert!(!source.contains("condition"));

    assert!(g.route_names("enrichment_router").unwrap().contains("identity"));
    // A filter is not a route, so it has no named outputs to validate against.
    assert!(g.route_names("aws_alb_route_unclaimed").is_none());
}

#[test]
fn references_are_collected_across_files_and_resolved_against_declarations() {
    let g = graph(&[
        (
            "_router.toml",
            "[transforms.source_router]\ntype = \"route\"\n\n\
             [transforms.source_router.route]\na = 'x'\nb_2 = 'x'\n",
        ),
        (
            "a.toml",
            "[transforms.a_parse]\ntype = \"remap\"\ninputs = [\"source_router.a\", \"a_filter\"]\n\n\
             [transforms.a_filter]\ntype = \"filter\"\ninputs = [\"source_router.b_2\"]\n",
        ),
    ]);

    assert!(g.dangling().is_empty(), "{:?}", g.dangling());

    // A dispatch-bound parser consumes a source-config filter, not a route, and
    // that filter is declared outside this tree.
    let external = graph(&[(
        "kafka.toml",
        "[transforms.kafka_parse]\ntype = \"remap\"\ninputs = [\"kafka_prod_filter\"]\n",
    )]);
    assert!(external.dangling().is_empty());

    // But a route the router does not emit is reported, wherever it is named.
    let broken = graph(&[
        (
            "_router.toml",
            "[transforms.source_router]\ntype = \"route\"\n\n\
             [transforms.source_router.route]\na = 'x'\n",
        ),
        (
            "stale.toml",
            "[transforms.stale_parse]\ntype = \"remap\"\ninputs = [\"source_router.b_2\"]\n",
        ),
    ]);
    let problems = broken.dangling();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("source_router.b_2"), "{problems:?}");
}

/// One deleted `_router.toml` dangles every parser at once. The error is logged
/// AND persisted on the deployment record, so the listing is capped while the
/// count stays honest.
#[test]
fn the_dangling_report_is_capped_but_reports_the_true_count() {
    let mut docs: Vec<(String, String)> = Vec::new();
    for i in 0..75 {
        docs.push((
            format!("parser_{i}.toml"),
            format!(
                "[transforms.parser_{i}_parse]\ntype = \"remap\"\ninputs = [\"source_router.gone_{i}\"]\n"
            ),
        ));
    }
    // No `_router.toml` at all: absent, not unparseable, so every reference is
    // provably dangling rather than merely unverifiable.
    let problems = ComponentGraph::from_documents(&docs).dangling();

    assert_eq!(problems.len(), 21, "20 findings plus one summary line");
    assert!(
        problems.last().unwrap().contains("55 more"),
        "the true overflow count must survive the cap: {:?}",
        problems.last()
    );
}

#[test]
fn env_interpolation_is_substituted_the_way_vector_does_it() {
    assert_eq!(substitute_env("max_bytes = ${A:-52428800}\n"), "max_bytes = 52428800\n");
    // No default: Vector substitutes the empty string.
    assert_eq!(substitute_env("x = \"${A}\"\n"), "x = \"\"\n");
    assert_eq!(substitute_env("no interpolation here"), "no interpolation here");
    // Unterminated: left alone so the parse fails honestly rather than silently
    // producing a different document.
    assert_eq!(substitute_env("x = ${UNCLOSED"), "x = ${UNCLOSED");
}

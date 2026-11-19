// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5611: unchanged renders write nothing; changed ones replace atomically.

use super::*;
use std::time::{Duration, SystemTime};

fn mtime(path: &Path) -> SystemTime {
    std::fs::metadata(path).unwrap().modified().unwrap()
}

#[cfg(unix)]
fn inode(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().ino()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn temp_leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('.'))
        .collect()
}

#[tokio::test]
async fn unchanged_content_is_not_written() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("apache.toml");
    std::fs::write(&file, "[transforms.x]\ntype = \"remap\"\n").unwrap();
    let before = mtime(&file);
    std::thread::sleep(Duration::from_millis(20));
    assert!(!write_if_changed(&file, "[transforms.x]\ntype = \"remap\"\n").await.unwrap());
    assert_eq!(mtime(&file), before);
    assert!(temp_leftovers(dir.path()).is_empty());
}

#[tokio::test]
async fn a_new_generated_at_stamp_alone_is_not_a_change() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("kafka_feed.toml");
    let render = |at: &str| format!("# Auto-generated\n# DO NOT EDIT\n# Generated at: {at}\n\n[sources.k]\ntype = \"kafka\"\n");
    std::fs::write(&file, render("2026-11-17T10:00:00Z")).unwrap();
    assert!(!write_if_changed(&file, render("2026-11-17T11:00:00Z")).await.unwrap());
    assert!(std::fs::read_to_string(&file).unwrap().contains("10:00:00Z"));
    // A content change still writes, with its own stamp.
    let changed = render("2026-11-17T12:00:00Z").replace("kafka\"", "kafka\"\nextra = 1");
    assert!(write_if_changed(&file, &changed).await.unwrap());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), changed);
}

#[cfg(unix)]
#[tokio::test]
async fn a_change_replaces_the_file_atomically_with_its_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs__feed_password");
    std::fs::write(&file, "old-secret").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let old_inode = inode(&file);
    assert!(write_if_changed(&file, "new-secret").await.unwrap());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "new-secret");
    // A new inode: renamed into place, never written through in place.
    assert_ne!(inode(&file), old_inode);
    assert_eq!(mode(&file), 0o600);
    assert!(temp_leftovers(dir.path()).is_empty());
}

#[tokio::test]
async fn a_missing_file_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("_combiner.toml");
    assert!(write_if_changed(&file, "x = 1\n").await.unwrap());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "x = 1\n");
    assert!(write_if_changed_sync(&file, "x = 2\n").unwrap());
    assert!(!write_if_changed_sync(&file, "x = 2\n").unwrap());
    assert!(temp_leftovers(dir.path()).is_empty());
}

#[tokio::test]
async fn a_failed_write_leaves_the_old_file_and_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    // The target is a directory: the rename fails.
    let target = dir.path().join("busy.toml");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("inner"), "x").unwrap();
    assert!(write_if_changed(&target, "x = 1\n").await.is_err());
    assert!(target.is_dir());
    assert!(temp_leftovers(dir.path()).is_empty());
}

#[tokio::test]
async fn the_fingerprint_covers_what_vector_reads_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for sub in ["sources/configs", "sources/parsers", "credentials", "backup", "staging"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    std::fs::write(root.join("sources/parsers/apache.toml"), "a = 1\n").unwrap();
    std::fs::write(root.join("sources/configs/http_ingestion.toml"), "# x\n# y\n# Generated at: t1\nb = 1\n").unwrap();
    std::fs::write(root.join("sources/configs__feed_password"), "s1").unwrap();
    let base = tree_fingerprint(root).await.unwrap();

    // Not read by Vector, or not content: no change.
    std::fs::write(root.join("sources/configs/_nano_activation.toml"), "[sources.nano_activation_1]\n").unwrap();
    std::fs::write(root.join("sources/configs/.http_ingestion.toml.tmp-1"), "partial").unwrap();
    std::fs::write(root.join(".nano-pipeline-identity"), "2.0.33/fsync/off\n").unwrap();
    std::fs::write(root.join("backup/apache.toml"), "old\n").unwrap();
    std::fs::write(root.join("staging/apache.toml"), "new\n").unwrap();
    std::fs::write(root.join("sources/configs/http_ingestion.toml"), "# x\n# y\n# Generated at: t2\nb = 1\n").unwrap();
    assert_eq!(tree_fingerprint(root).await.unwrap(), base);

    // A parser, a source config, a secret: each is a change.
    std::fs::write(root.join("sources/parsers/apache.toml"), "a = 2\n").unwrap();
    let parser = tree_fingerprint(root).await.unwrap();
    assert_ne!(parser, base);
    std::fs::write(root.join("sources/configs__feed_password"), "s2").unwrap();
    let secret = tree_fingerprint(root).await.unwrap();
    assert_ne!(secret, parser);
    std::fs::write(root.join("credentials/legacy"), "c").unwrap();
    assert_ne!(tree_fingerprint(root).await.unwrap(), secret);
    // A removed file is a change too.
    let now = tree_fingerprint(root).await.unwrap();
    std::fs::remove_file(root.join("sources/parsers/apache.toml")).unwrap();
    assert_ne!(tree_fingerprint(root).await.unwrap(), now);
}

#[tokio::test]
async fn deploying_the_same_parsers_twice_writes_nothing_the_second_time() {
    let dir = tempfile::tempdir().unwrap();
    let manager = super::super::VectorConfigManager::new(dir.path());
    manager.deploy_parsers(&[]).await.unwrap();
    let parsers_dir = dir.path().join("sources/parsers");
    let files: Vec<PathBuf> = std::fs::read_dir(&parsers_dir).unwrap().flatten().map(|e| e.path()).collect();
    assert!(!files.is_empty());
    let before: Vec<SystemTime> = files.iter().map(|f| mtime(f)).collect();
    let fingerprint = tree_fingerprint(dir.path()).await.unwrap();
    std::thread::sleep(Duration::from_millis(20));
    manager.deploy_parsers(&[]).await.unwrap();
    let after: Vec<SystemTime> = files.iter().map(|f| mtime(f)).collect();
    assert_eq!(before, after, "no file of an unchanged render is rewritten");
    assert_eq!(tree_fingerprint(dir.path()).await.unwrap(), fingerprint);
    // A tampered file is put back.
    std::fs::write(parsers_dir.join("_combiner.toml"), "WRECKED").unwrap();
    manager.deploy_parsers(&[]).await.unwrap();
    assert_eq!(tree_fingerprint(dir.path()).await.unwrap(), fingerprint);
}

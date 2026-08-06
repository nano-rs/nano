// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the generation delivery read API (NAN-1931). The traversal cases
//! are the point: every malformed path must fail closed before touching disk.

use super::*;
use std::path::PathBuf;

fn generation_name(generation: i64) -> String {
    format!("{generation:020}")
}

/// Build a publications root with one generation. `ready` controls whether the
/// `.ready` marker is written.
fn publications_with_generation(generation: i64, ready: bool) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let publications = root.path().join("publications");
    let generation_dir = publications.join(generation_name(generation));
    std::fs::create_dir_all(generation_dir.join("configs")).unwrap();
    std::fs::create_dir_all(generation_dir.join("parsers")).unwrap();
    std::fs::write(generation_dir.join("_manifest.json"), b"{\"version\":1}").unwrap();
    std::fs::write(generation_dir.join("_checksums.sha256"), b"abc  configs/a.toml\n").unwrap();
    std::fs::write(generation_dir.join("configs/a.toml"), b"[x]\na = 1\n").unwrap();
    std::fs::write(generation_dir.join("parsers/p.toml"), b"[y]\nb = 2\n").unwrap();
    if ready {
        std::fs::write(generation_dir.join(".ready"), b"ready\n").unwrap();
    }
    (root, publications)
}

#[tokio::test]
async fn serves_files_from_a_ready_generation() {
    let (_root, publications) = publications_with_generation(47, true);
    let bytes = read_generation_file(&publications, 47, "configs/a.toml")
        .await
        .unwrap()
        .expect("file must be served");
    assert_eq!(bytes, b"[x]\na = 1\n");

    let manifest = read_manifest(&publications, 47).await.unwrap().unwrap();
    assert_eq!(manifest, b"{\"version\":1}");
}

#[tokio::test]
async fn refuses_to_serve_a_generation_without_ready_marker() {
    let (_root, publications) = publications_with_generation(47, false);
    assert!(read_generation_file(&publications, 47, "configs/a.toml")
        .await
        .unwrap()
        .is_none());
    assert!(read_manifest(&publications, 47).await.unwrap().is_none());
}

#[tokio::test]
async fn missing_generation_and_missing_file_are_none_not_errors() {
    let (_root, publications) = publications_with_generation(47, true);
    assert!(read_generation_file(&publications, 48, "configs/a.toml")
        .await
        .unwrap()
        .is_none());
    assert!(read_generation_file(&publications, 47, "configs/absent.toml")
        .await
        .unwrap()
        .is_none());
    // Root that does not exist at all.
    assert!(
        latest_ready_generation(&publications.join("nope"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn traversal_attempts_fail_closed_without_touching_disk() {
    let (root, publications) = publications_with_generation(47, true);
    // A juicy target OUTSIDE the generation that naive joins would reach.
    std::fs::write(root.path().join("secret.txt"), b"leak").unwrap();

    for path in [
        "../secret.txt",
        "../../secret.txt",
        "configs/../../secret.txt",
        "/etc/passwd",
        "/secret.txt",
        "..",
        ".",
        "",
        "configs/./a.toml",
        "configs/..",
        "configs\\..\\..\\secret.txt",
        "configs/a.toml\u{0}",
        "configs/a\ntoml",
    ] {
        let result = read_generation_file(&publications, 47, path).await;
        assert!(
            matches!(result, Err(VectorConfigDeliveryError::InvalidPath)),
            "path {path:?} must be rejected, got {result:?}"
        );
    }
}

#[tokio::test]
async fn non_positive_or_absurd_generations_are_invalid() {
    let (_root, publications) = publications_with_generation(47, true);
    for generation in [0, -1, i64::MIN] {
        let result = read_generation_file(&publications, generation, "configs/a.toml").await;
        assert!(
            matches!(result, Err(VectorConfigDeliveryError::InvalidGeneration)),
            "generation {generation} must be rejected, got {result:?}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_escape_inside_a_generation_is_refused() {
    let (root, publications) = publications_with_generation(47, true);
    std::fs::write(root.path().join("secret.txt"), b"leak").unwrap();
    let generation_dir = publications.join(generation_name(47));

    // Symlink LEAF pointing outside: the canonicalization containment check
    // resolves it out of the generation root and fails closed.
    std::os::unix::fs::symlink(
        root.path().join("secret.txt"),
        generation_dir.join("configs/link.toml"),
    )
    .unwrap();
    let result = read_generation_file(&publications, 47, "configs/link.toml").await;
    assert!(
        matches!(result, Err(VectorConfigDeliveryError::InvalidPath)),
        "leaf symlink escape must be rejected, got {result:?}"
    );

    // Symlinked INTERMEDIATE directory pointing outside: the candidate path
    // resolves to a real file, so only the canonicalization containment check
    // catches it. Fail closed.
    let outside = root.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("evil.toml"), b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, generation_dir.join("linked_dir")).unwrap();
    let result = read_generation_file(&publications, 47, "linked_dir/evil.toml").await;
    assert!(
        matches!(result, Err(VectorConfigDeliveryError::InvalidPath)),
        "intermediate symlink escape must be rejected, got {result:?}"
    );
}

/// The generation DIRECTORY itself being a symlink out of the publications root.
/// Anchoring containment only on the generation directory would canonicalize
/// that symlink to its target and then find every file trivially "inside" it —
/// the escape this level of the check exists to close. Requesting a plain file
/// name (no traversal in the path itself) is what makes it dangerous: nothing
/// but the root-anchored containment stands in the way.
#[cfg(unix)]
#[tokio::test]
async fn symlinked_generation_directory_escaping_the_root_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let publications = root.path().join("publications");
    std::fs::create_dir_all(&publications).unwrap();

    // A real, ready generation tree living OUTSIDE the publications root.
    let outside = root.path().join("outside_gen");
    std::fs::create_dir_all(outside.join("configs")).unwrap();
    std::fs::write(outside.join(".ready"), b"ready\n").unwrap();
    std::fs::write(outside.join("configs/secret.toml"), b"leak").unwrap();

    // The generation number resolves to a symlink pointing at that outside tree.
    std::os::unix::fs::symlink(&outside, publications.join(generation_name(47))).unwrap();

    let result = read_generation_file(&publications, 47, "configs/secret.toml").await;
    assert!(
        matches!(result, Err(VectorConfigDeliveryError::InvalidPath)),
        "a generation directory that symlinks out of the publications root must be rejected, got {result:?}"
    );
}

#[tokio::test]
async fn latest_ready_generation_picks_highest_ready_only() {
    let root = tempfile::tempdir().unwrap();
    let publications = root.path().join("publications");
    for (generation, ready) in [(3_i64, true), (7, true), (9, false)] {
        let dir = publications.join(generation_name(generation));
        std::fs::create_dir_all(&dir).unwrap();
        if ready {
            std::fs::write(dir.join(".ready"), b"ready\n").unwrap();
        }
    }
    // Noise that must be ignored: temp dirs, non-numeric, wrong-width names.
    std::fs::create_dir_all(publications.join(".00000000000000000011.tmp-x")).unwrap();
    std::fs::create_dir_all(publications.join("not-a-generation")).unwrap();
    std::fs::create_dir_all(publications.join("123")).unwrap();

    assert_eq!(
        latest_ready_generation(&publications).await.unwrap(),
        Some(7),
        "9 is not ready; 7 is the newest ready generation"
    );
}

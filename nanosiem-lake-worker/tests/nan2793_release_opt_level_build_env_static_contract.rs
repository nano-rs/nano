// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2793: no image build or CI workflow may override the release opt-level.
//!
//! `nan2793_release_profile_static_contract.rs` pins `[profile.release]` in
//! `.cargo/config.toml`, but `CARGO_PROFILE_RELEASE_OPT_LEVEL`, a
//! `--config profile.release.opt-level=...` flag, or `-C opt-level` in
//! RUSTFLAGS all take precedence over that file. Scan every Dockerfile, shell
//! script and CI workflow so a size override cannot be reintroduced at build
//! time either.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Every Dockerfile, shell script and CI workflow in the repo: the places a
/// `cargo build --release` can be invoked with env or flag overrides.
fn build_files() -> Vec<PathBuf> {
    const SKIP_DIRS: &[&str] = &[".git", "target", "vendor", "node_modules", "dist"];
    fn is_build_file(path: &Path) -> bool {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let in_workflows = path
            .parent()
            .is_some_and(|p| p.ends_with(".github/workflows"));
        name.starts_with("Dockerfile")
            || name.ends_with(".Dockerfile")
            || name.ends_with(".sh")
            || (in_workflows && (name.ends_with(".yml") || name.ends_with(".yaml")))
    }
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with("target") {
                    walk(&path, out);
                }
            } else if kind.is_file() && is_build_file(&path) {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&workspace_root(), &mut files);
    for required in ["Dockerfile", "Dockerfile.search", "nanosiem-web/Dockerfile"] {
        assert!(
            files.iter().any(|f| f.ends_with(required)),
            "scan must cover {required}"
        );
    }
    // The hosted deployer recipe is absent from the public export; when it
    // exists, the same scanner must still include it.
    let deployer = workspace_root().join("scripts/worker-deployer/build-binary.Dockerfile");
    if deployer.exists() {
        assert!(files.contains(&deployer), "scan must cover the hosted deployer");
    }
    files
}

fn overrides_opt_level(line: &str) -> bool {
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("CARGO_PROFILE_RELEASE_OPT_LEVEL")
        || compact.contains("-Copt-level")
        || compact.contains("profile.release.opt-level")
}

#[test]
fn image_builds_and_ci_do_not_override_release_opt_level() {
    for path in build_files() {
        // Non-UTF-8 files cannot carry a readable override; skip them.
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            assert!(
                !overrides_opt_level(line),
                "{}:{}: overrides the release opt-level (NAN-2793): {line}",
                path.display(),
                n + 1
            );
        }
    }
}

#[test]
fn override_detector_catches_known_forms() {
    assert!(overrides_opt_level("ENV CARGO_PROFILE_RELEASE_OPT_LEVEL=z"));
    assert!(overrides_opt_level(r#"ENV RUSTFLAGS="-C opt-level=s""#));
    assert!(overrides_opt_level("cargo build --release --config profile.release.opt-level='z'"));
    assert!(!overrides_opt_level(r#"ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold""#));
}

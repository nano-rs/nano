//! NAN-2793: release binaries must be optimized for speed.
//!
//! The workspace release profile lives in `.cargo/config.toml`, which every
//! image build copies into its context (`COPY . .`, `git archive`). It was
//! `opt-level = "z"` for nine months and made every lake stage 5-60x more
//! CPU-hungry than the code it runs. Pin the profile so a size setting cannot
//! come back silently.

fn release_profile() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let config = std::fs::read_to_string(root.join(".cargo/config.toml"))
        .expect("workspace .cargo/config.toml");
    let start = config
        .find("[profile.release]")
        .expect(".cargo/config.toml defines [profile.release]");
    let body = &config[start + "[profile.release]".len()..];
    let end = body.find("\n[").unwrap_or(body.len());
    body[..end].to_string()
}

fn setting(profile: &str, key: &str) -> Option<String> {
    profile.lines().find_map(|line| {
        let line = line.split('#').next().unwrap_or("").trim();
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim().trim_matches('"').to_string())
    })
}

#[test]
fn release_profile_optimizes_for_speed_not_size() {
    let profile = release_profile();
    assert_eq!(
        setting(&profile, "opt-level").as_deref(),
        Some("3"),
        "release opt-level must be 3; \"s\"/\"z\" made bronze admission 8x and ed25519 verify 59x slower (NAN-2793)"
    );
}

#[test]
fn workspace_manifest_does_not_override_release_opt_level() {
    // A `[profile.release.package.<crate>]` opt-level in Cargo.toml would
    // quietly re-size-optimize one crate (the ed25519 or JSON hot path) under
    // the workspace default; keep the single source of truth above.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("workspace Cargo.toml");
    let in_release = manifest
        .split("\n[")
        .filter(|section| section.starts_with("profile.release"))
        .any(|section| {
            section
                .lines()
                .any(|line| line.trim_start().starts_with("opt-level"))
        });
    assert!(
        !in_release,
        "set the release opt-level only in .cargo/config.toml"
    );
}

#[test]
fn release_profile_unwinds_panics() {
    // NAN-3080: `panic = "abort"` turned one rule's panic into a jobs
    // process crash (exit 139) and made every catch_unwind / JoinError
    // isolation path unreachable in production.
    let profile = release_profile();
    assert_ne!(
        setting(&profile, "panic").as_deref(),
        Some("abort"),
        "release panics must unwind so per-task isolation works (NAN-3080)"
    );
}

#[test]
fn release_profile_uses_thin_lto() {
    // NAN-3450: fat LTO with codegen-units = 1 serialized every release link
    // onto one core (api image cold build >28 min vs 17:36 with thin LTO).
    let profile = release_profile();
    assert_eq!(
        setting(&profile, "lto").as_deref(),
        Some("thin"),
        "release LTO must be thin (NAN-3450)"
    );
    assert_eq!(
        setting(&profile, "codegen-units").as_deref(),
        Some("16"),
        "release codegen-units must be 16 (NAN-3450)"
    );
}

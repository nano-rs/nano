// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4952 / NAN-4953 on the pinned Vector image.
//!
//! * `draft_published_transitions_pass_vector_validate`: real bundles rendered
//!   by `VectorConfigManager` for a draft (disabled) source, then a normal
//!   source beside it, then the draft published, then unpublished — for every
//!   `source_type` spelling that reaches `source_router` (`http` and
//!   unrecognized labels included). Each state must pass `vector validate`
//!   with the flags production uses. Before NAN-4952 the `http` / label states
//!   rendered a parser reading `source_router.<name>` with no such route, and
//!   Vector refused the whole config.
//! * `a_parser_with_secret_syntax_never_expands`: a parser whose VRL holds
//!   `${SECRET}` / `$SECRET` runs on a Vector that has `SECRET` in its
//!   environment and env interpolation ON (the production flag). The event
//!   carries the literal text.
//! * `pre_upgrade_parser_files_are_migrated_before_vector_starts`: a parser file
//!   and an `_enrichment.toml` rendered before NAN-4953 (no escape header) sit in
//!   the dynamic volume; the entrypoint escapes them before Vector reads them.
//!
//! Needs docker:
//!
//! ```text
//! NANOSIEM_TEST_VECTOR_IMAGE=ghcr.io/nano-rs/vector:0.61.0-nano.5-debian \
//!   cargo test -p nanosiem-core --test draft_parser_env_vector -- --ignored --test-threads=1
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use nanosiem_core::parsers::{Parser, VectorConfigManager};
use uuid::Uuid;

const FAKE_SECRET: &str = "nan4953-not-for-tenants";

fn image() -> String {
    std::env::var("NANOSIEM_TEST_VECTOR_IMAGE")
        .expect("NANOSIEM_TEST_VECTOR_IMAGE must name the pinned Vector image")
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn parser(name: &str, source_type: &str, enabled: bool, vrl: &str) -> Parser {
    Parser {
        id: Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: source_type.to_string(),
        parser_vrl: vrl.to_string(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled,
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Every static top-level `config/vector/*.toml` the product ships.
fn copy_static(dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    for entry in std::fs::read_dir(repo().join("config/vector")).unwrap().flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "toml") {
            std::fs::copy(&path, dest.join(entry.file_name())).unwrap();
        }
    }
}

fn validate(static_dir: &Path, dynamic: &Path, label: &str) {
    let output = std::process::Command::new("docker")
        .args(["run", "--rm"])
        .args(["-e", "VECTOR_AUTH_TOKEN=validate-only"])
        .args(["-e", "CLICKHOUSE_URL=http://clickhouse:8123"])
        .args(["-e", "CLICKHOUSE_USER=nanosiem", "-e", "CLICKHOUSE_PASSWORD=nanosiem"])
        .arg("-v")
        .arg(format!("{}:/etc/vector:ro", static_dir.display()))
        .arg("-v")
        .arg(format!("{}:/etc/vector/dynamic:ro", dynamic.display()))
        .args([
            image().as_str(),
            "--dangerously-allow-env-var-interpolation",
            "validate",
            "--no-environment",
            "--config-dir",
            "/etc/vector",
            "--config-dir",
            "/etc/vector/dynamic/sources/parsers",
            "--config-dir",
            "/etc/vector/dynamic/sources/configs",
        ])
        .output()
        .expect("docker must be runnable");
    assert!(
        output.status.success(),
        "[{label}] bundle failed vector validate:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn draft_published_transitions_pass_vector_validate() {
    for spelling in ["routed", "http", "acme_vpn_label"] {
        let work = tempfile::tempdir().unwrap();
        let static_dir = work.path().join("config");
        let dynamic = work.path().join("dynamic");
        copy_static(&static_dir);
        std::fs::create_dir_all(static_dir.join("dynamic")).unwrap();
        for d in ["sources/configs", "sources/parsers", "ingest-tokens"] {
            std::fs::create_dir_all(dynamic.join(d)).unwrap();
        }
        let vector = VectorConfigManager::new(&dynamic);
        let mut draft = parser("draft_feed", spelling, false, ".parsed = \"draft\"");
        let normal = parser("normal_feed", "routed", true, ".parsed = \"normal\"");

        vector.deploy_parsers(&[draft.clone()]).await.unwrap();
        validate(&static_dir, &dynamic, &format!("{spelling}: draft deployed"));

        vector.deploy_parsers(&[draft.clone(), normal.clone()]).await.unwrap();
        validate(&static_dir, &dynamic, &format!("{spelling}: draft + normal source"));

        draft.enabled = true;
        draft.parser_vrl = ".parsed = \"published\"".to_string();
        vector.deploy_parsers(&[draft.clone(), normal.clone()]).await.unwrap();
        validate(&static_dir, &dynamic, &format!("{spelling}: draft parser published"));

        draft.enabled = false;
        vector.deploy_parsers(&[draft.clone(), normal.clone()]).await.unwrap();
        validate(&static_dir, &dynamic, &format!("{spelling}: published -> draft"));
    }
}

/// A Vector container started through the real entrypoint with `SECRET` in its
/// environment and env interpolation on, reading only `dynamic/`.
struct LiveVector {
    name: String,
    dynamic: tempfile::TempDir,
    _validation: tempfile::TempDir,
}

/// Feeds `source_router.leaky` from a demo source and prints every event, so
/// the rendered parser file runs exactly as generated.
const HARNESS: &str = "[sources.demo]\ntype = \"demo_logs\"\nformat = \"shuffle\"\nlines = [\"hello\"]\ninterval = 0.3\n\n\
[transforms.source_router]\ntype = \"route\"\ninputs = [\"demo\"]\nroute.leaky = \"true\"\n\n\
[sinks.out]\ntype = \"console\"\ninputs = [\"leaky_output\"]\nencoding.codec = \"json\"\n";

impl LiveVector {
    fn start(prepare: impl FnOnce(&Path)) -> Self {
        let validation = tempfile::tempdir().unwrap();
        let dynamic = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dynamic.path().join("sources/configs")).unwrap();
        std::fs::create_dir_all(dynamic.path().join("sources/parsers")).unwrap();
        std::fs::write(dynamic.path().join("sources/parsers/zz_harness.toml"), HARNESS).unwrap();
        prepare(dynamic.path());
        let name = format!("nan4953-vector-{}", Uuid::new_v4().simple());
        let status = std::process::Command::new("docker")
            .args(["run", "-d", "--rm", "--name", &name, "-e"])
            .arg(format!("SECRET={FAKE_SECRET}"))
            .args(["--entrypoint", "/bin/sh", "-v"])
            .arg(format!("{}:/etc/vector/.nano:ro", repo().join("config/vector/.nano").display()))
            .arg("-v")
            .arg(format!("{}:/etc/vector/dynamic", dynamic.path().display()))
            .arg("-v")
            .arg(format!("{}:/var/lib/nano-validation", validation.path().display()))
            .args([
                image().as_str(),
                "/etc/vector/.nano/vector-entrypoint.sh",
                "--dangerously-allow-env-var-interpolation",
                "--config-dir",
                "/etc/vector/dynamic/sources/parsers",
                "--config-dir",
                "/etc/vector/dynamic/sources/configs",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        Self { name, dynamic, _validation: validation }
    }

    fn logs(&self) -> String {
        let out = std::process::Command::new("docker").args(["logs", &self.name]).output().unwrap();
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    }

    async fn wait_for(&self, needle: &str) -> String {
        for _ in 0..80 {
            let logs = self.logs();
            if logs.contains(needle) {
                return logs;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("never saw {needle:?}; logs:\n{}", self.logs());
    }

    fn file(&self, rel: &str) -> String {
        std::fs::read_to_string(self.dynamic.path().join(rel)).unwrap()
    }
}

impl Drop for LiveVector {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker").args(["rm", "-f", &self.name]).output();
    }
}

/// Render the parser file the way a deploy does and return its text.
async fn rendered_parser_file(vrl: &str) -> String {
    let work = tempfile::tempdir().unwrap();
    let vector = VectorConfigManager::new(work.path());
    vector
        .deploy_parsers(&[parser("leaky", "routed", true, vrl)])
        .await
        .unwrap();
    std::fs::read_to_string(work.path().join("sources/parsers/leaky.toml")).unwrap()
}

// `.message` survives the generated `_output` reshaping.
const LEAK_VRL: &str = ".message = \"tenant-said ${SECRET} and $SECRET\"";

#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn a_parser_with_secret_syntax_never_expands() {
    let rendered = rendered_parser_file(LEAK_VRL).await;
    assert!(rendered.starts_with("# nano-env-escaped: v1\n"), "{rendered}");
    let c = LiveVector::start(|dynamic| {
        std::fs::write(dynamic.join("sources/parsers/leaky.toml"), &rendered).unwrap();
    });
    let logs = c.wait_for("tenant-said").await;
    assert!(!logs.contains(FAKE_SECRET), "the secret expanded:\n{logs}");
    assert!(logs.contains("tenant-said ${SECRET} and $SECRET"), "{logs}");
}

#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn pre_upgrade_parser_files_are_migrated_before_vector_starts() {
    // What a pre-NAN-4953 deploy wrote: the same document, unescaped, no header.
    let escaped = rendered_parser_file(LEAK_VRL).await;
    let pre_upgrade = nanosiem_core::vector_env::unescape_file(&escaped);
    assert!(!pre_upgrade.starts_with("# nano-env-escaped"), "{pre_upgrade}");
    // A pre-upgrade enrichment lane: tenant VRL in a ''' block beside a nano
    // value that must keep interpolating.
    let enrichment = "[transforms.enrich_probe]\ntype = \"remap\"\ninputs = [\"demo\"]\nsource = '''\n\
.enrich = \"lane-said ${SECRET}\"\n.nano_owned = \"${NANO_PROBE:-kept-default}\"\n'''\n\n\
# nano-owned interpolation outside the VRL blocks is left alone: ${NANO_PROBE:-x}\n\
[sinks.enrich_out]\ntype = \"console\"\ninputs = [\"enrich_probe\"]\nencoding.codec = \"json\"\n";
    let c = LiveVector::start(|dynamic| {
        std::fs::write(dynamic.join("sources/parsers/leaky.toml"), &pre_upgrade).unwrap();
        std::fs::write(dynamic.join("sources/parsers/_enrichment.toml"), enrichment).unwrap();
    });
    let logs = c.wait_for("tenant-said").await;
    let logs = if logs.contains("lane-said") { logs } else { c.wait_for("lane-said").await };
    assert!(!logs.contains(FAKE_SECRET), "a pre-upgrade file expanded the secret:\n{logs}");
    assert!(logs.contains("tenant-said ${SECRET} and $SECRET"), "{logs}");
    assert!(logs.contains("lane-said ${SECRET}"), "{logs}");

    let migrated = c.file("sources/parsers/leaky.toml");
    assert!(migrated.starts_with("# nano-env-escaped: v1\n"), "{migrated}");
    let lane = c.file("sources/parsers/_enrichment.toml");
    assert!(lane.starts_with("# nano-env-escaped: v1 tenant-vrl\n"), "{lane}");
    assert!(lane.contains(".enrich = \"lane-said $${SECRET}\""), "{lane}");
    assert!(lane.contains("left alone: ${NANO_PROBE:-x}\n"), "outside the VRL blocks is untouched:\n{lane}");
}

/// Codex P2: the migration keeps what the pre-upgrade Vector ran. An existing
/// `$$` already meant a literal `$` to it; only a lone `$` is doubled.
#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn pre_upgrade_migration_keeps_existing_double_dollars() {
    let vrl = ".message = \"keep $$HOME and $$1 lone ${SECRET} end\"";
    let pre_upgrade = nanosiem_core::vector_env::unescape_file(&rendered_parser_file(vrl).await);
    assert!(pre_upgrade.contains("keep $$HOME and $$1 lone ${SECRET}"), "{pre_upgrade}");
    let c = LiveVector::start(|dynamic| {
        std::fs::write(dynamic.join("sources/parsers/leaky.toml"), &pre_upgrade).unwrap();
    });
    let logs = c.wait_for("lone").await;
    assert!(!logs.contains(FAKE_SECRET), "the secret expanded:\n{logs}");
    // Exactly what the pre-upgrade Vector delivered for the `$$` forms.
    assert!(logs.contains("keep $HOME and $1 lone ${SECRET} end"), "{logs}");
    let migrated = c.file("sources/parsers/leaky.toml");
    assert!(migrated.contains("keep $$HOME and $$1 lone $${SECRET} end"), "{migrated}");
    assert_eq!(migrated.matches("# nano-env-escaped").count(), 1, "{migrated}");
}

fn docker(args: &[&str]) -> std::process::Output {
    let out = std::process::Command::new("docker").args(args).output().expect("docker must be runnable");
    assert!(
        out.status.success(),
        "docker {args:?} failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Codex P2: nano-api re-renders a parser while the entrypoint is migrating.
/// The writer holds the shared config lock (as nano-api's deploys do); the
/// entrypoint must wait for it and leave the fresh, already escaped file
/// alone: no stale rename over it, no second header, no double escape.
/// A named volume keeps both containers on one kernel, so `flock` is real.
#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn the_migration_never_overwrites_a_concurrent_api_render() {
    let old = nanosiem_core::vector_env::unescape_file(
        &rendered_parser_file(".message = \"old-render ${SECRET}\"").await,
    );
    let fresh = rendered_parser_file(".message = \"fresh-render $1\"").await;
    let id = Uuid::new_v4().simple().to_string();
    let volume = format!("nan4953-race-{id}");
    let writer = format!("nan4953-writer-{id}");
    let vector = format!("nan4953-vector-{id}");
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("old.toml"), &old).unwrap();
    std::fs::write(work.path().join("fresh.toml"), &fresh).unwrap();
    std::fs::write(work.path().join("harness.toml"), HARNESS).unwrap();
    let seed = format!("{}:/seed:ro", work.path().display());
    let vol = format!("{volume}:/etc/vector/dynamic");
    docker(&["volume", "create", &volume]);
    let cleanup = || {
        let _ = std::process::Command::new("docker").args(["rm", "-f", &writer, &vector]).output();
        let _ = std::process::Command::new("docker").args(["volume", "rm", "-f", &volume]).output();
    };
    let image = image();
    // Seed the pre-upgrade state.
    docker(&[
        "run", "--rm", "--entrypoint", "/bin/sh", "-v", &vol, "-v", &seed, &image, "-c",
        "mkdir -p /etc/vector/dynamic/sources/parsers /etc/vector/dynamic/sources/configs \
         && cp /seed/old.toml /etc/vector/dynamic/sources/parsers/leaky.toml \
         && cp /seed/harness.toml /etc/vector/dynamic/sources/parsers/zz_harness.toml \
         && touch /etc/vector/dynamic/.nano-config.lock",
    ]);
    // The "api": takes the lock, then (3s later, while the entrypoint is already
    // waiting) writes the fresh escaped render the way deploy_parsers does.
    docker(&[
        "run", "-d", "--name", &writer, "--entrypoint", "/bin/sh", "-v", &vol, "-v", &seed, &image, "-c",
        "flock /etc/vector/dynamic/.nano-config.lock sh -c 'sleep 3; cat /seed/fresh.toml > /etc/vector/dynamic/sources/parsers/leaky.toml'",
    ]);
    tokio::time::sleep(Duration::from_millis(800)).await;
    let nano_dir = format!("{}:/etc/vector/.nano:ro", repo().join("config/vector/.nano").display());
    let secret = format!("SECRET={FAKE_SECRET}");
    docker(&[
        "run", "-d", "--name", &vector, "-e", &secret, "--entrypoint", "/bin/sh", "-v", &nano_dir, "-v", &vol,
        &image, "/etc/vector/.nano/vector-entrypoint.sh", "--dangerously-allow-env-var-interpolation",
        "--config-dir", "/etc/vector/dynamic/sources/parsers", "--config-dir", "/etc/vector/dynamic/sources/configs",
    ]);
    let mut logs = String::new();
    for _ in 0..80 {
        let out = std::process::Command::new("docker").args(["logs", &vector]).output().unwrap();
        logs = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        if logs.contains("fresh-render") || logs.contains("old-render") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let file = std::process::Command::new("docker")
        .args(["run", "--rm", "--entrypoint", "cat", "-v", &vol, &image, "/etc/vector/dynamic/sources/parsers/leaky.toml"])
        .output()
        .unwrap();
    let file = String::from_utf8_lossy(&file.stdout).to_string();
    cleanup();
    assert!(logs.contains("fresh-render $1"), "the fresh render must be what runs:\n{logs}");
    assert!(!logs.contains("old-render"), "the stale migrated file replaced the fresh render:\n{logs}");
    assert!(!logs.contains(FAKE_SECRET), "{logs}");
    assert_eq!(file, fresh, "the entrypoint must not touch an already escaped render");
}

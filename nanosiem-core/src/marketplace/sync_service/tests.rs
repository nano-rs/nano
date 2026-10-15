// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the NAN-3490 connector-runtime marker written by sync.

use super::*;
use serde_json::json;

fn manifest(extra: &str) -> MarketplaceManifest {
    serde_yaml::from_str(&format!(
        "name: Feed\nslug: feed\ncategory: identity\ndescription: d\n{extra}"
    ))
    .expect("manifest parses")
}

#[test]
fn manifest_without_runtime_or_spec_keeps_config_unchanged() {
    let m = manifest("");
    let config = json!({ "streams": [], "x": 1 });
    assert_eq!(apply_connector_runtime(config.clone(), &m, None).unwrap(), config);
}

#[test]
fn spec_and_sha_are_recorded() {
    let m = manifest("runtime: connector\nconnector_spec: connector.yaml\n");
    let out = apply_connector_runtime(json!({ "x": 1 }), &m, Some("version: 1\n")).unwrap();
    assert_eq!(out["x"], 1);
    assert_eq!(out["runtime"], "connector");
    assert_eq!(out["connector_spec"], "version: 1\n");
    // sha256("version: 1\n")
    assert_eq!(
        out["connector_spec_sha256"].as_str().unwrap(),
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"version: 1\n"))
    );
    assert_eq!(out["connector_spec_sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn deno_runtime_with_a_spec_defaults_and_records_both() {
    // A shipped manifest before cutover: Deno still runs, the spec rides along.
    let m = manifest("connector_spec: connector.yaml\n");
    let out = apply_connector_runtime(json!({}), &m, Some("s")).unwrap();
    assert_eq!(out["runtime"], "deno");
    assert_eq!(out["connector_spec"], "s");
}

#[test]
fn bad_runtime_or_missing_spec_is_refused() {
    let m = manifest("runtime: python\n");
    assert!(apply_connector_runtime(json!({}), &m, None).is_err());
    let m = manifest("runtime: connector\n");
    assert!(apply_connector_runtime(json!({}), &m, None).is_err());
}

#[test]
fn connector_spec_must_be_a_plain_regular_file_next_to_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.yaml");
    std::fs::write(dir.path().join("connector.yaml"), "version: 1\n").unwrap();

    let ok = manifest("connector_spec: connector.yaml\n");
    assert_eq!(read_connector_spec(&manifest_path, &ok).unwrap().as_deref(), Some("version: 1\n"));
    assert_eq!(read_connector_spec(&manifest_path, &manifest("")).unwrap(), None);

    for bad in ["../connector.yaml", "sub/connector.yaml", ".hidden.yaml", "missing.yaml", "''"] {
        let m = manifest(&format!("connector_spec: {bad}\n"));
        assert!(read_connector_spec(&manifest_path, &m).is_err(), "{bad} must be refused");
    }

    std::fs::create_dir(dir.path().join("adir")).unwrap();
    assert!(read_connector_spec(&manifest_path, &manifest("connector_spec: adir\n")).is_err());

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(dir.path().join("connector.yaml"), dir.path().join("link.yaml")).unwrap();
        assert!(read_connector_spec(&manifest_path, &manifest("connector_spec: link.yaml\n")).is_err());
    }

    std::fs::write(dir.path().join("big.yaml"), vec![b'#'; MAX_MANIFEST_SIZE as usize + 1]).unwrap();
    assert!(read_connector_spec(&manifest_path, &manifest("connector_spec: big.yaml\n")).is_err());
}

/// NAN-3490 item 5: `hosted_connector_spec` is read under the same file
/// rules as `connector_spec` and recorded with its own sha256, beside (not
/// instead of) the portable spec.
#[test]
fn hosted_connector_spec_is_read_like_connector_spec_and_recorded_with_its_sha() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.yaml");
    std::fs::write(dir.path().join("connector.yaml"), "version: 1\n").unwrap();
    std::fs::write(dir.path().join("connector.hosted.yaml"), "version: 1\n# hosted\n").unwrap();
    let m = manifest("runtime: connector\nconnector_spec: connector.yaml\nhosted_connector_spec: connector.hosted.yaml\n");
    let hosted = read_hosted_connector_spec(&manifest_path, &m).unwrap();
    assert_eq!(hosted.as_deref(), Some("version: 1\n# hosted\n"));
    let config = apply_connector_runtime(json!({ "x": 1 }), &m, read_connector_spec(&manifest_path, &m).unwrap().as_deref()).unwrap();
    let out = apply_hosted_connector_spec(config, hosted.as_deref());
    assert_eq!(out["connector_spec"], "version: 1\n");
    assert_eq!(out["hosted_connector_spec"], "version: 1\n# hosted\n");
    assert_eq!(
        out["hosted_connector_spec_sha256"].as_str().unwrap(),
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"version: 1\n# hosted\n"))
    );
    // Without one, nothing changes.
    assert_eq!(apply_hosted_connector_spec(json!({ "x": 1 }), None), json!({ "x": 1 }));
    assert_eq!(read_hosted_connector_spec(&manifest_path, &manifest("")).unwrap(), None);
    // Same refusals as connector_spec.
    std::fs::create_dir(dir.path().join("adir")).unwrap();
    std::fs::write(dir.path().join("big.yaml"), vec![b'#'; MAX_MANIFEST_SIZE as usize + 1]).unwrap();
    for bad in ["../connector.yaml", "sub/x.yaml", ".hidden.yaml", "missing.yaml", "''", "adir", "big.yaml"] {
        let m = manifest(&format!("hosted_connector_spec: {bad}\n"));
        let e = read_hosted_connector_spec(&manifest_path, &m).unwrap_err();
        assert!(e.starts_with("hosted_connector_spec "), "{bad}: {e}");
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(dir.path().join("connector.hosted.yaml"), dir.path().join("link.yaml")).unwrap();
        assert!(read_hosted_connector_spec(&manifest_path, &manifest("hosted_connector_spec: link.yaml\n")).is_err());
    }
    // Export strips the platform-only keys.
    let lifted = CollectorManifestFields::take_from(&out);
    assert_eq!(lifted.remainder, json!({ "x": 1 }));
}

/// Export (`CollectorManifestFields::take_from`) must lift the runtime marker
/// back out of `config`, so an exported manifest names its spec instead of
/// carrying the spec text nested under `config:`.
#[test]
fn export_lifts_the_runtime_marker_back_out_of_config() {
    let m = manifest("runtime: connector\nconnector_spec: connector.yaml\n");
    let config = apply_connector_runtime(json!({ "poll_schedule": "*/5 * * * *" }), &m, Some("version: 1\n")).unwrap();
    let lifted = CollectorManifestFields::take_from(&config);
    assert_eq!(lifted.runtime.as_deref(), Some("connector"));
    assert_eq!(lifted.connector_spec.as_deref(), Some("version: 1\n"));
    assert_eq!(lifted.remainder, json!({ "poll_schedule": "*/5 * * * *" }));
}

// ---------------------------------------------------------------------------
// NAN-3514: the skip-at-same-commit decision also keys on SYNC_SCHEMA_VERSION.
// ---------------------------------------------------------------------------

const HEAD: &str = "92f5ac9c0000000000000000000000000000000";

fn synced_repo(commit: Option<&str>, status: Option<&str>, version: i32) -> EnrichmentMarketplaceRepo {
    EnrichmentMarketplaceRepo {
        managed_by_platform: true,
        id: Uuid::now_v7(),
        name: "nano-integrations".into(),
        slug: "nano-integrations".into(),
        description: None,
        url: "https://github.com/nano-rs/nano-integrations".into(),
        branch: "main".into(),
        enrichments_path: "enrichments/".into(),
        auto_sync_enabled: true,
        sync_interval_hours: 24,
        last_synced_at: Some(chrono::Utc::now()),
        last_sync_commit: commit.map(str::to_string),
        last_sync_schema_version: version,
        last_sync_status: status.map(str::to_string),
        last_sync_error: None,
        enrichment_count: 3,
        enabled: true,
        created_by: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn sync_schema_version_starts_above_the_unrecorded_default() {
    // Rows written before NAN-3514 read 0 (column default); the running code
    // must differ so every deployed repo re-syncs once.
    const _: () = assert!(SYNC_SCHEMA_VERSION > 0);
}

#[test]
fn same_commit_with_absent_version_runs_a_full_sync() {
    // The r27 case: nano-integrations synced at 92f5ac9c before the column existed.
    let repo = synced_repo(Some(HEAD), Some("success"), 0);
    assert!(!is_up_to_date(&repo, HEAD));
}

#[test]
fn same_commit_with_older_version_runs_a_full_sync() {
    let repo = synced_repo(Some(HEAD), Some("success"), SYNC_SCHEMA_VERSION - 1);
    assert!(!is_up_to_date(&repo, HEAD));
}

#[test]
fn same_commit_with_newer_version_skips_so_a_roll_does_not_flip_flop() {
    // Mid-roll, an old pod sees the row a new pod recorded: it must not
    // re-sync (and downgrade) the same commit.
    let repo = synced_repo(Some(HEAD), Some("success"), SYNC_SCHEMA_VERSION + 1);
    assert!(is_up_to_date(&repo, HEAD));
    let failed = synced_repo(Some(HEAD), Some("error"), SYNC_SCHEMA_VERSION + 1);
    assert!(!is_up_to_date(&failed, HEAD));
}

#[test]
fn same_commit_with_current_version_skips() {
    let repo = synced_repo(Some(HEAD), Some("success"), SYNC_SCHEMA_VERSION);
    assert!(is_up_to_date(&repo, HEAD));
}

#[test]
fn new_commit_syncs_whatever_the_version() {
    let repo = synced_repo(Some(HEAD), Some("success"), SYNC_SCHEMA_VERSION);
    assert!(!is_up_to_date(&repo, "0123456789abcdef0123456789abcdef01234567"));
    let never = synced_repo(None, None, 0);
    assert!(!is_up_to_date(&never, HEAD));
}

#[test]
fn failed_last_sync_at_same_commit_and_version_syncs() {
    let repo = synced_repo(Some(HEAD), Some("failed"), SYNC_SCHEMA_VERSION);
    assert!(!is_up_to_date(&repo, HEAD));
}

/// End to end through `run_sync` against a local git repo: the skip path
/// never touches the database, so a lazy pool that cannot connect proves a
/// skip; a re-parse reaches the catalog lookup and fails on that pool.
#[tokio::test]
async fn run_sync_reparses_at_same_commit_only_when_the_version_changed() {
    let Some(commit) = local_git_repo_commit() else {
        eprintln!("git not available; skipping");
        return;
    };
    let (data_dir, slug, commit) = commit;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy("postgres://nobody@127.0.0.1:1/none")
        .unwrap();
    let repository = MarketplaceRepository::new(pool);
    let mut repo = synced_repo(Some(&commit), Some("success"), SYNC_SCHEMA_VERSION);
    repo.slug = slug;
    repo.url = "https://github.com/nano-rs/nano-integrations".into();

    // validate_repo_url does DNS for SSRF checks; skip when offline.
    if validate_repo_url(&repo.url).await.is_err() {
        eprintln!("DNS unavailable; skipping");
        return;
    }

    let skipped = run_sync(&repo, &repository, &data_dir.path().to_path_buf()).await.unwrap();
    assert_eq!(skipped.commit.as_deref(), Some(commit.as_str()));
    assert_eq!(skipped.enrichments_added + skipped.enrichments_updated, 0);

    repo.last_sync_schema_version = 0;
    let reparsed = run_sync(&repo, &repository, &data_dir.path().to_path_buf()).await;
    assert!(
        matches!(reparsed, Err(MarketplaceError::Database(_))),
        "an old version must reach the catalog writes, got {reparsed:?}"
    );
}

/// A one-commit git repo at `<data_dir>/enrichment_repos/<slug>` holding one
/// manifest, with an `origin` so `git_pull` succeeds offline. Returns
/// `(data_dir, slug, HEAD)`.
fn local_git_repo_commit() -> Option<(tempfile::TempDir, String, String)> {
    use std::process::Command;
    let data_dir = tempfile::tempdir().ok()?;
    let slug = "nano-integrations".to_string();
    let origin = data_dir.path().join("origin");
    let manifest_dir = origin.join("enrichments/identity/okta_users");
    std::fs::create_dir_all(&manifest_dir).ok()?;
    std::fs::write(
        manifest_dir.join("manifest.yaml"),
        "name: Okta Users\nslug: okta_users\ncategory: identity\ndescription: d\n",
    )
    .ok()?;
    let git = |dir: &std::path::Path, args: &[&str]| {
        Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    git(&origin, &["init", "-q", "-b", "main"])?;
    git(&origin, &["add", "."])?;
    git(&origin, &["commit", "-q", "-m", "init"])?;
    let clone = data_dir.path().join("enrichment_repos").join(&slug);
    std::fs::create_dir_all(clone.parent()?).ok()?;
    git(
        data_dir.path(),
        &["clone", "-q", "-b", "main", origin.to_str()?, clone.to_str()?],
    )?;
    let head = git(&clone, &["rev-parse", "HEAD"])?;
    Some((data_dir, slug, String::from_utf8(head.stdout).ok()?.trim().to_string()))
}

// ------------------------------------------------------------ NAN-3503 components

/// The shipped nano-integrations layouts (PR #13 at 784c91d), laid out as
/// sync finds them: `(file name next to the manifest, text)`.
fn shipped(slug: &str) -> Vec<(&'static str, &'static str)> {
    macro_rules! fx {
        ($p:literal) => {
            include_str!(concat!("../../../../nano-connector/tests/fixtures/", $p))
        };
    }
    match slug {
        "google_workspace" => vec![
            ("manifest.yaml", fx!("directory/google_workspace.manifest.yaml")),
            ("connector.yaml", fx!("specs/google_workspace.yaml")),
            ("connector.hosted.yaml", fx!("specs/google_workspace_hosted.yaml")),
            ("directory.connector.yaml", fx!("directory/google_workspace_directory.connector.yaml")),
            ("directory.connector.hosted.yaml", fx!("directory/google_workspace_directory.connector.hosted.yaml")),
        ],
        "entra_directory" => vec![
            ("manifest.yaml", fx!("directory/entra_directory.manifest.yaml")),
            ("connector.yaml", fx!("directory/entra_directory.connector.yaml")),
            ("connector.hosted.yaml", fx!("directory/entra_directory.connector.hosted.yaml")),
        ],
        "okta_users" => vec![
            ("manifest.yaml", fx!("directory/okta_users.manifest.yaml")),
            ("connector.yaml", fx!("directory/okta_users.connector.yaml")),
            ("connector.hosted.yaml", fx!("directory/okta_users.connector.hosted.yaml")),
        ],
        other => panic!("no fixture for {other}"),
    }
}

fn lay_out(files: &[(&str, &str)]) -> (tempfile::TempDir, std::path::PathBuf, MarketplaceManifest) {
    let dir = tempfile::tempdir().unwrap();
    for (name, text) in files {
        std::fs::write(dir.path().join(name), text).unwrap();
    }
    let path = dir.path().join("manifest.yaml");
    let manifest: MarketplaceManifest = serde_yaml::from_str(files[0].1).expect("shipped manifest parses");
    (dir, path, manifest)
}

fn sha(text: &str) -> String {
    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(text.as_bytes()))
}

#[test]
fn sync_schema_version_covers_components() {
    const _: () = assert!(SYNC_SCHEMA_VERSION >= 3);
}

#[test]
fn google_workspace_records_audit_logs_and_directory_components() {
    let files = shipped("google_workspace");
    let (_dir, path, manifest) = lay_out(&files);
    let config = catalog_config(&path, &manifest).unwrap();
    assert_eq!(config["categories"], json!(["logs", "identity"]));
    let components = config["components"].as_array().unwrap();
    assert_eq!(components.len(), 2);

    let logs = &components[0];
    assert_eq!((logs["id"].as_str(), logs["kind"].as_str()), (Some("audit_logs"), Some("logs")));
    assert_eq!(logs["streams"], json!(["login", "admin", "token", "drive"]));
    assert_eq!(logs["default"], true);
    assert_eq!(
        logs["setup"]["scopes"],
        json!(["https://www.googleapis.com/auth/admin.reports.audit.readonly"])
    );
    assert!(logs.get("connector_spec").is_none(), "a logs component runs the entry's spec");

    let dir = &components[1];
    assert_eq!((dir["id"].as_str(), dir["kind"].as_str()), (Some("directory"), Some("identity")));
    assert_eq!(dir["default"], false);
    assert_eq!(dir["config_fields"], json!(["ADMIN_EMAIL", "PRIVILEGED_GROUPS"]));
    assert_eq!(dir["setup"]["scopes"].as_array().unwrap().len(), 2);
    assert_eq!(dir["setup"]["steps"].as_array().unwrap().len(), 4);
    let spec = files[3].1;
    let hosted = files[4].1;
    assert_eq!(dir["connector_spec"], spec);
    assert_eq!(dir["connector_spec_sha256"], sha(spec));
    assert_eq!(dir["hosted_connector_spec"], hosted);
    assert_eq!(dir["hosted_connector_spec_sha256"], sha(hosted));

    // The entry's own (log) specs are unchanged beside the components.
    assert_eq!(config["connector_spec"], files[1].1);
    assert_eq!(config["hosted_connector_spec"], files[2].1);
    assert_eq!(config["streams"].as_array().unwrap().len(), 4);
    // Export strips the platform-only layout.
    let lifted = CollectorManifestFields::take_from(&config);
    assert!(lifted.remainder.get("components").is_none());
    assert!(lifted.remainder.get("categories").is_none());
}

#[test]
fn directory_only_entries_record_one_identity_component() {
    for (slug, fields) in [
        ("entra_directory", json!(["DIRECTORY_ID", "CLIENT_ID", "PRIVILEGED_GROUPS"])),
        ("okta_users", json!(["OKTA_DOMAIN", "CLIENT_ID", "PRIVILEGED_GROUPS"])),
    ] {
        let files = shipped(slug);
        let (_dir, path, manifest) = lay_out(&files);
        let config = catalog_config(&path, &manifest).unwrap();
        assert_eq!(config["categories"], json!(["identity"]), "{slug}");
        let components = config["components"].as_array().unwrap();
        assert_eq!(components.len(), 1, "{slug}");
        let c = &components[0];
        assert_eq!((c["id"].as_str(), c["kind"].as_str(), c["default"].as_bool()), (Some("directory"), Some("identity"), Some(true)));
        assert_eq!(c["config_fields"], fields, "{slug}");
        assert!(!c["setup"]["steps"].as_array().unwrap().is_empty());
        assert!(!c["setup"]["permissions"].as_array().unwrap().is_empty());
        assert_eq!(c["connector_spec_sha256"], sha(files[1].1));
        assert_eq!(c["hosted_connector_spec_sha256"], sha(files[2].1));
        // Identity streams stay recorded as manifest streams, marked as such.
        assert!(config["streams"].as_array().unwrap().iter().all(|s| s["source_type"] == "nano_identity"));
        assert_eq!(config["runtime"], "connector");
    }
}

#[test]
fn manifest_without_layout_keeps_config_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let m = manifest("");
    let config = json!({ "x": 1 });
    assert_eq!(apply_components(config.clone(), &dir.path().join("manifest.yaml"), &m).unwrap(), config);
}

#[test]
fn malformed_layouts_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.yaml");
    std::fs::write(dir.path().join("dir.yaml"), "version: 1\n").unwrap();
    let base = "streams:\n  - {id: a, label: A, source_type: x_a}\n  - {id: b, label: B, source_type: x_b}\n  - {id: u, label: U, source_type: nano_identity}\nconfig_fields:\n  - {name: F, label: F}\n";
    let ok = format!("{base}categories: [logs, identity]\ncomponents:\n  - {{id: logs, label: Logs, kind: logs, streams: [a, b]}}\n  - {{id: directory, label: Directory, kind: identity, connector_spec: dir.yaml, config_fields: [F]}}\n");
    let out = apply_components(json!({}), &path, &manifest(&ok)).unwrap();
    assert_eq!(out["components"][1]["connector_spec"], "version: 1\n");
    assert!(out["components"][1].get("hosted_connector_spec").is_none());
    for (why, bad) in [
        ("unknown category", "categories: [metrics]\n"),
        ("bad id", "components:\n  - {id: Logs, label: L, kind: logs, streams: [a]}\n"),
        ("duplicate id", "components:\n  - {id: l, label: L, kind: logs, streams: [a]}\n  - {id: l, label: L, kind: logs, streams: [b]}\n"),
        ("unknown kind", "components:\n  - {id: l, label: L, kind: metrics, streams: [a]}\n"),
        ("empty label", "components:\n  - {id: l, label: ' ', kind: logs, streams: [a]}\n"),
        ("logs without streams", "components:\n  - {id: l, label: L, kind: logs}\n"),
        ("unknown stream", "components:\n  - {id: l, label: L, kind: logs, streams: [zz]}\n"),
        ("identity stream as logs", "components:\n  - {id: l, label: L, kind: logs, streams: [u]}\n"),
        ("stream claimed twice", "components:\n  - {id: l, label: L, kind: logs, streams: [a]}\n  - {id: m, label: M, kind: logs, streams: [a]}\n"),
        ("logs with a spec", "components:\n  - {id: l, label: L, kind: logs, streams: [a], connector_spec: dir.yaml}\n"),
        ("identity without spec", "components:\n  - {id: d, label: D, kind: identity}\n"),
        ("identity with streams", "components:\n  - {id: d, label: D, kind: identity, connector_spec: dir.yaml, streams: [a]}\n"),
        ("identity spec path", "components:\n  - {id: d, label: D, kind: identity, connector_spec: ../dir.yaml}\n"),
        ("missing hosted twin", "components:\n  - {id: d, label: D, kind: identity, connector_spec: dir.yaml, hosted_connector_spec: gone.yaml}\n"),
        ("undeclared config field", "components:\n  - {id: d, label: D, kind: identity, connector_spec: dir.yaml, config_fields: [G]}\n"),
    ] {
        let m = manifest(&format!("{base}{bad}"));
        assert!(apply_components(json!({}), &path, &m).is_err(), "{why} must be refused");
    }
}

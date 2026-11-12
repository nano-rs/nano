// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3514: the skip-at-same-commit decision also keys on SYNC_SCHEMA_VERSION.

use super::*;
use uuid::Uuid;

const HEAD: &str = "92f5ac9c0000000000000000000000000000000";

fn synced_repo(commit: Option<&str>, status: Option<&str>, version: i32) -> EnrichmentMarketplaceRepo {
    EnrichmentMarketplaceRepo {
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
    // A version from newer code (rollback) is also a mismatch, not a skip.
    let repo = synced_repo(Some(HEAD), Some("success"), SYNC_SCHEMA_VERSION + 1);
    assert!(!is_up_to_date(&repo, HEAD));
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

/// End to end through `run_sync` against a local git repo. The skip path
/// never touches the database (it reports the stored `enrichment_count`), so
/// a lazy pool that cannot connect proves the skip; a re-parse reaches the
/// catalog and fails on that pool.
#[tokio::test]
async fn run_sync_reparses_at_same_commit_only_when_the_version_changed() {
    let Some(commit) = local_git_repo_commit() else {
        eprintln!("git not available; skipping");
        return;
    };
    let (data_dir, slug, commit) = commit;
    // The parse/record logic is source-independent; drive it through the
    // local git repository (first-party URLs read content channels in
    // production, NAN-4955).
    super::TEST_GIT_SOURCE.with(|f| f.set(true));
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
    assert_eq!(skipped.enrichment_count, 3, "current version at the same commit skips");

    repo.last_sync_schema_version = 0;
    // A re-parse reaches the catalog. On this unreachable pool the catalog
    // read fails, and since NAN-4930 that fails the sync instead of being
    // treated as "new entry" and reported as success.
    let reparsed = run_sync(&repo, &repository, &data_dir.path().to_path_buf()).await;
    assert!(
        matches!(reparsed, Err(MarketplaceError::Database(_))),
        "an old version must re-parse and surface catalog failures, got {reparsed:?}"
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

// ---- NAN-5284: `runtime: connector` maps to the official lookup -------------

fn agent_manifest(slug: &str, runtime: Option<&str>) -> MarketplaceManifest {
    let yaml = format!(
        "name: {slug}\nslug: {slug}\ncategory: agent\ndescription: d\n{}",
        runtime.map(|r| format!("runtime: {r}\nconnector_spec: connector.yaml\n")).unwrap_or_default()
    );
    serde_yaml::from_str(&yaml).expect("manifest")
}

#[test]
fn nan5284_connector_runtime_selects_the_official_lookup_only_in_enterprise() {
    let shodan = agent_manifest("shodan", Some("connector"));
    assert_eq!(shodan.runtime.as_deref(), Some("connector"));
    assert_eq!(shodan.connector_spec.as_deref(), Some("connector.yaml"));
    let expected = if cfg!(feature = "enterprise") { "lookup" } else { "deno" };
    assert_eq!(execution_backend_for(&shodan), expected);
}

#[test]
fn nan5284_other_manifests_keep_their_backend() {
    // `runtime: deno` (today's manifests), no runtime, or a slug with no
    // official spec all stay on Deno.
    assert_eq!(execution_backend_for(&agent_manifest("shodan", Some("deno"))), "deno");
    assert_eq!(execution_backend_for(&agent_manifest("shodan", None)), "deno");
    assert_eq!(execution_backend_for(&agent_manifest("acme-intel", Some("connector"))), "deno");
    let mut data = agent_manifest("shodan", Some("connector"));
    data.category = "data".into();
    assert_eq!(execution_backend_for(&data), "deno");
}

#[test]
fn nan5284_sync_schema_version_was_bumped_for_the_new_derivation() {
    const _: () = assert!(SYNC_SCHEMA_VERSION >= 2);
}

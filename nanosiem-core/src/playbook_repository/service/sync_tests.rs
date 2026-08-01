// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the sync-side file filter and the per-repository kind gate.

use super::*;
use crate::playbooks::split_frontmatter;

fn extensions() -> Vec<String> {
    vec!["md".to_string(), "markdown".to_string()]
}

fn repo_with_kinds(kinds: &[&str]) -> PlaybookRepository {
    PlaybookRepository {
        id: Uuid::nil(),
        name: "stock".to_string(),
        slug: "nano-rs/playbooks".to_string(),
        description: None,
        url: "https://github.com/nano-rs/playbooks".to_string(),
        branch: "main".to_string(),
        playbooks_path: None,
        auto_sync_enabled: Some(false),
        sync_interval_hours: Some(24),
        last_synced_at: None,
        last_sync_commit: None,
        last_sync_status: None,
        last_sync_error: None,
        playbook_count: Some(0),
        enabled: Some(true),
        allowed_kinds: kinds.iter().map(|k| k.to_string()).collect(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        created_by: None,
    }
}

#[test]
fn hunt_readme_is_not_synced_as_a_hunt() {
    // The nano-rs/playbooks repo ships hunts/README.md — the authoring
    // contract itself. A naive *.md walk hands documentation to the hunt
    // parser. The existing category folders have no READMEs, so this case
    // never arose before hunts landed.
    assert!(!is_syncable_playbook_file(
        "hunts/README.md",
        &extensions()
    ));
    assert!(!is_syncable_playbook_file("README.md", &extensions()));
    assert!(!is_syncable_playbook_file(
        "identity/readme.MD",
        &extensions()
    ));
    assert!(!is_syncable_playbook_file(
        "CONTRIBUTING.md",
        &extensions()
    ));
}

#[test]
fn real_hunt_and_playbook_paths_are_synced() {
    for path in [
        "hunts/service_account_interactive_logon.md",
        "hunts/lolbin_unusual_parent.md",
        "identity/credential_reuse.md",
        "network/beaconing.markdown",
    ] {
        assert!(
            is_syncable_playbook_file(path, &extensions()),
            "{path} should sync"
        );
    }
}

#[test]
fn non_markdown_is_skipped() {
    for path in ["LICENSE", "hunts/notes.txt", "scripts/build.sh"] {
        assert!(!is_syncable_playbook_file(path, &extensions()));
    }
}

#[test]
fn kind_comes_from_frontmatter_not_from_the_directory() {
    // A file living under hunts/ that does not declare `kind: hunt` is a
    // response playbook, and one living under identity/ that DOES declare it
    // is a hunt. The directory a repository syncs from is operator-
    // configurable; inferring from it would silently reclassify every file in
    // a folder the day someone retargets the repo.
    let declared = "---\nkind: hunt\ntitle: t\n---\n/query: x\n";
    let undeclared = "---\ntitle: t\n---\n/query: x\n";

    let (fm, _) = split_frontmatter(declared).unwrap();
    assert_eq!(catalog_kind(fm.as_ref()), PlaybookKind::Hunt);

    let (fm, _) = split_frontmatter(undeclared).unwrap();
    assert_eq!(catalog_kind(fm.as_ref()), PlaybookKind::Response);

    // No frontmatter at all is a response playbook, as every pre-NAN-2238
    // file is.
    assert_eq!(catalog_kind(None), PlaybookKind::Response);
}

#[test]
fn only_a_deliberate_refusal_drops_a_path_from_the_catalog() {
    // `synced_paths` is the keep-list: anything missing from it is deleted by
    // `delete_not_in_paths`, and deleting a `repository_playbooks` row cascades
    // to the `playbook_imports` row recording where a library playbook came
    // from. So a transient GitHub 502 or an unparseable file must NOT remove a
    // path — only the kind gate does, and only on purpose.
    let mut keep: Vec<String> = ["a.md", "b.md", "c.md"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    drop_from_catalog(&mut keep, "b.md");
    assert_eq!(keep, vec!["a.md".to_string(), "c.md".to_string()]);

    // Idempotent, and never touches a neighbour.
    drop_from_catalog(&mut keep, "b.md");
    drop_from_catalog(&mut keep, "not-in-list.md");
    assert_eq!(keep, vec!["a.md".to_string(), "c.md".to_string()]);
}

#[test]
fn a_hunts_only_repository_refuses_response_playbooks_and_vice_versa() {
    let hunts_only = repo_with_kinds(&["hunt"]);
    assert!(repo_accepts_kind(&hunts_only, "hunt"));
    assert!(!repo_accepts_kind(&hunts_only, "response"));

    let runbooks_only = repo_with_kinds(&["response"]);
    assert!(repo_accepts_kind(&runbooks_only, "response"));
    assert!(!repo_accepts_kind(&runbooks_only, "hunt"));

    // The 9000057 default, which every existing row takes: nothing that
    // worked before stops working.
    let both = repo_with_kinds(&["response", "hunt"]);
    assert!(repo_accepts_kind(&both, "response"));
    assert!(repo_accepts_kind(&both, "hunt"));
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! CRUD + partial-update coverage for the artifact-analysis store (NAN-1977).
//!
//! This repo hand-writes its SQL (no compile-time `query!` verification), so the
//! bind order, the summary projection, and the COALESCE partial-update semantics
//! are only validated at runtime — that's what this exercises. `created_by` is
//! left NULL to avoid seeding a `users` FK; the column is nullable by design.
//!
//! `#[ignore]`d DB suite — run via `pg-integration-tests` CI or
//! `docker compose up -d postgres` + `cargo test -- --ignored`.

mod common;

use nanosiem_core::{ArtifactRepository, ArtifactRepositoryError, NewArtifact, UpdateArtifact};

fn sample_new() -> NewArtifact {
    NewArtifact {
        name: "invoice_check.ps1".into(),
        sha256: "9f2c41a7d0be".into(),
        size_bytes: 2048,
        source: "integration test".into(),
        verdict: "queued".into(),
        score: None,
        original: "powershell -w hidden -enc SQBFAFgA...".into(),
        deobfuscated: None,
        passes: serde_json::json!([]),
        iocs: serde_json::json!([]),
        mitre: serde_json::json!([]),
        behavior: None,
        layer_chain: None,
        agent_note: None,
        entropy: Some(5.9),
        summary: None,
        status_line: Some("queued · awaiting analysis".into()),
        case_tag: None,
        correlation: None,
        analysis_secs: None,
        engine: None,
        case_id: None,
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn artifact_crud_and_coalesce_partial_update() {
    let pool = common::migrated_pool().await;
    let repo = ArtifactRepository::new(pool.clone());

    // create — created_by NULL (nullable column, ON DELETE SET NULL).
    let created = repo.create(&sample_new(), None).await.expect("create");
    assert_eq!(created.verdict, "queued");
    assert_eq!(created.original, "powershell -w hidden -enc SQBFAFgA...");
    assert!(created.deobfuscated.is_none());
    assert!(created.created_by.is_none());

    // find_by_id returns the fully-hydrated record (incl. the specimen text).
    let got = repo.find_by_id(created.id).await.expect("find_by_id");
    assert_eq!(got.id, created.id);
    assert_eq!(got.original, created.original);

    // list returns the row as a summary projection.
    let list = repo.list().await.expect("list");
    assert!(
        list.iter().any(|a| a.id == created.id),
        "created artifact should appear in the shared list"
    );

    // Analysis write-back: only the provided fields change; untouched columns
    // (original, entropy, status_line) survive via COALESCE.
    let patch = UpdateArtifact {
        verdict: Some("malicious".into()),
        score: Some(0.94),
        deobfuscated: Some("IEX $wc.DownloadString($url)".into()),
        passes: Some(serde_json::json!([{ "n": 1, "title": "base64 decode", "done": true }])),
        iocs: Some(serde_json::json!([{ "kind": "ip", "value": "185.220.101.42", "hot": true }])),
        mitre: Some(serde_json::json!(["T1059.001", "T1105"])),
        summary: Some("powershell downloader".into()),
        ..Default::default()
    };
    let updated = repo.update(created.id, &patch).await.expect("update");
    assert_eq!(updated.verdict, "malicious");
    assert_eq!(updated.score, Some(0.94));
    assert_eq!(
        updated.deobfuscated.as_deref(),
        Some("IEX $wc.DownloadString($url)")
    );
    assert_eq!(updated.mitre, serde_json::json!(["T1059.001", "T1105"]));
    // Untouched by the patch — proves COALESCE leaves omitted columns alone.
    assert_eq!(updated.original, created.original);
    assert_eq!(updated.entropy, Some(5.9));
    assert_eq!(updated.status_line.as_deref(), Some("queued · awaiting analysis"));
    assert!(updated.updated_at >= created.updated_at);

    // sha256-only patch (the ingest hash write-back) leaves the analysis intact.
    let sha_patch = UpdateArtifact {
        sha256: Some("deadbeefcafe".into()),
        ..Default::default()
    };
    let sha_updated = repo.update(created.id, &sha_patch).await.expect("sha update");
    assert_eq!(sha_updated.sha256, "deadbeefcafe");
    assert_eq!(sha_updated.verdict, "malicious", "verdict survives a sha-only patch");

    // delete, then a second delete surfaces NotFound.
    repo.delete(created.id).await.expect("delete");
    assert!(matches!(
        repo.find_by_id(created.id).await,
        Err(ArtifactRepositoryError::NotFound(_))
    ));
    assert!(matches!(
        repo.delete(created.id).await,
        Err(ArtifactRepositoryError::NotFound(_))
    ));
}

// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::parts::part_log::LocalObjectStore;

fn user(feed: &str, id: &str, version: i64) -> IdentityRow {
    let mut row = IdentityRow::new(feed, id, SourceKind::Pull, version);
    row.username = id.to_string();
    row.email = format!("{id}@example.com");
    row.display_name = format!("User {id}");
    row.groups = vec!["staff".into(), format!("team-{}", version % 3)];
    row.account_enabled = Some(true);
    row.account_status = "active".into();
    row
}

fn tombstone(feed: &str, id: &str, version: i64) -> IdentityRow {
    let mut row = IdentityRow::new(feed, id, SourceKind::Pull, version);
    row.deleted = true;
    row
}

struct Fixture {
    _dir: tempfile::TempDir,
    objects: LocalObjectStore,
    root: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let objects = LocalObjectStore::new(dir.path().join("r2")).unwrap();
    let root = dir.path().to_path_buf();
    Fixture {
        _dir: dir,
        objects,
        root,
    }
}

fn stage(store: &IdentityStore<'_>, rows: Vec<IdentityRow>) -> PathBuf {
    let path = store
        .scratch()
        .join(format!("stage-{}.parquet", Uuid::new_v4()));
    write_sorted_rows(&path, rows).unwrap();
    path
}

async fn view(store: &IdentityStore<'_>) -> IdentityView {
    let manifest = store.current().await.unwrap().unwrap();
    store.load_view(&manifest).await.unwrap()
}

async fn all_rows(store: &IdentityStore<'_>) -> Vec<IdentityRow> {
    let view = view(store).await;
    (0..view.len()).map(|i| view.row(i).unwrap()).collect()
}

#[tokio::test]
async fn delta_round_trip_preserves_every_column() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let mut full = user("okta", "u1", 10);
    full.source_kind = SourceKind::Push;
    full.snapshot_id = Some("run-1".into());
    full.observed_at = Some(1_700_000_000_000);
    full.upn = "u1@corp".into();
    full.manager_upn = "boss@corp".into();
    full.mfa_enabled = Some(false);
    full.last_sign_in_at = Some(1_700_000_000_001);
    full.created_in_directory_at = Some(1);
    full.employee_type = "contractor".into();
    full.last_observed_at = Some(2);
    full.is_admin = Some(true);
    full.groups = vec![];
    let published = store
        .append_delta(None, vec![full.clone(), user("okta", "u0", 1)])
        .await
        .unwrap();
    assert!(published.changed && !published.compacted);
    assert_eq!(published.manifest.deltas.len(), 1);
    let rows = all_rows(&store).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].external_id, "u0", "rows are sorted by key");
    assert_eq!(rows[1], full);
}

#[tokio::test]
async fn highest_version_wins_and_tombstones_remove_rows() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let m1 = store
        .append_delta(None, vec![user("okta", "a", 5), user("okta", "b", 5)])
        .await
        .unwrap();
    // An older replay of `a` must not regress it; `b` is deleted.
    let mut stale = user("okta", "a", 4);
    stale.title = "stale".into();
    let m2 = store
        .append_delta(
            Some(m1.manifest.revision),
            vec![stale, tombstone("okta", "b", 6)],
        )
        .await
        .unwrap();
    let mut newer = user("okta", "a", 7);
    newer.title = "new".into();
    store
        .append_delta(Some(m2.manifest.revision), vec![newer])
        .await
        .unwrap();
    let view = view(&store).await;
    assert_eq!(view.len(), 1);
    assert_eq!(view.get("okta", "a").unwrap().unwrap().title, "new");
    assert!(view.get("okta", "b").unwrap().is_none());
}

#[tokio::test]
async fn duplicate_keys_in_one_batch_keep_the_last_highest_version() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let mut first = user("okta", "a", 3);
    first.title = "first".into();
    let mut second = user("okta", "a", 3);
    second.title = "second".into();
    store
        .append_delta(None, vec![first, second, user("okta", "a", 2)])
        .await
        .unwrap();
    assert_eq!(all_rows(&store).await[0].title, "second");
}

#[tokio::test]
async fn compaction_matches_the_merged_view_and_retires_files_one_generation_later() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let mut expected = None;
    for i in 0..5 {
        let p = store
            .append_delta(
                expected,
                vec![
                    user("okta", &format!("u{i}"), 10 + i),
                    tombstone("okta", "u0", 12),
                ],
            )
            .await
            .unwrap();
        expected = Some(p.manifest.revision);
    }
    let before = all_rows(&store).await;
    let delta_keys: Vec<String> = f.objects.list("identity/deltas/").await.unwrap();
    assert_eq!(delta_keys.len(), 5);
    let compacted = store.compact(expected).await.unwrap();
    assert!(compacted.compacted);
    assert!(compacted.manifest.deltas.is_empty());
    assert_eq!(compacted.manifest.retired.len(), 5);
    assert_eq!(all_rows(&store).await, before);
    // Still present: a reader pinned to the previous revision has grace.
    assert_eq!(f.objects.list("identity/deltas/").await.unwrap().len(), 5);
    store
        .append_delta(
            Some(compacted.manifest.revision),
            vec![user("okta", "z", 1)],
        )
        .await
        .unwrap();
    assert_eq!(f.objects.list("identity/deltas/").await.unwrap().len(), 1);
}

#[tokio::test]
async fn delta_threshold_triggers_automatic_compaction() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let mut expected = None;
    let mut compacted = false;
    for i in 0..=COMPACT_AFTER_DELTAS as i64 {
        let p = store
            .append_delta(expected, vec![user("okta", &format!("u{i}"), 1)])
            .await
            .unwrap();
        expected = Some(p.manifest.revision);
        compacted |= p.compacted;
    }
    assert!(compacted);
    let manifest = store.current().await.unwrap().unwrap();
    assert!(manifest.deltas.is_empty());
    assert_eq!(
        manifest.snapshot.unwrap().rows,
        COMPACT_AFTER_DELTAS as u64 + 1
    );
}

#[tokio::test]
async fn replace_feed_is_exact_for_that_feed_only_and_idempotent() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let mut push = user("okta-push", "a", 1);
    push.source_kind = SourceKind::Push;
    let p = store
        .append_delta(
            None,
            vec![user("okta", "a", 1), user("okta", "gone", 1), push],
        )
        .await
        .unwrap();
    // The full run lists `a` (older version than stored: a full run is
    // authoritative for its feed) and `new`, not `gone`.
    let staged = vec![
        stage(&store, vec![user("okta", "new", 1)]),
        stage(&store, vec![user("okta", "a", 1)]),
    ];
    let replaced = store
        .replace_feed(Some(p.manifest.revision), "okta", &staged)
        .await
        .unwrap();
    assert!(replaced.changed);
    let keys: Vec<(String, String)> = all_rows(&store)
        .await
        .into_iter()
        .map(|r| (r.feed_id, r.external_id))
        .collect();
    assert_eq!(
        keys,
        vec![
            ("okta".into(), "a".into()),
            ("okta".into(), "new".into()),
            ("okta-push".into(), "a".into()),
        ]
    );
    let again = store
        .replace_feed(Some(replaced.manifest.revision), "okta", &staged)
        .await
        .unwrap();
    assert!(
        !again.changed,
        "re-running the same full snapshot is a no-op"
    );
    assert_eq!(again.manifest, replaced.manifest);
}

#[tokio::test]
async fn replace_feed_refuses_rows_of_another_feed() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let staged = vec![stage(&store, vec![user("entra", "a", 1)])];
    assert!(store.replace_feed(None, "okta", &staged).await.is_err());
}

#[tokio::test]
async fn delete_feed_removes_only_that_feed() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let p = store
        .append_delta(None, vec![user("okta", "a", 1), user("entra", "a", 1)])
        .await
        .unwrap();
    store
        .delete_feed(Some(p.manifest.revision), "okta")
        .await
        .unwrap();
    let rows = all_rows(&store).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].feed_id, "entra");
}

#[tokio::test]
async fn stale_expected_revision_is_a_conflict() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let first = store
        .append_delta(None, vec![user("okta", "a", 1)])
        .await
        .unwrap();
    store
        .append_delta(Some(first.manifest.revision), vec![user("okta", "b", 1)])
        .await
        .unwrap();
    assert!(store
        .append_delta(Some(first.manifest.revision), vec![user("okta", "c", 1)])
        .await
        .is_err());
    assert!(store
        .append_delta(None, vec![user("okta", "c", 1)])
        .await
        .is_err());
}

#[tokio::test]
async fn invalid_rows_are_refused_before_anything_is_written() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let mut bad_feed = user("okta", "a", 1);
    bad_feed.feed_id = "okta/../other".into();
    let mut control = user("okta", "a", 1);
    control.display_name = "x\u{0}y".into();
    let mut status = user("okta", "a", 1);
    status.account_status = "frozen".into();
    for row in [
        bad_feed,
        control,
        status,
        user("okta", "a", 0),
        user("okta", "", 1),
    ] {
        assert!(store.append_delta(None, vec![row]).await.is_err());
    }
    assert!(store.append_delta(None, Vec::new()).await.is_err());
    assert!(store.current().await.unwrap().is_none());
    assert!(f.objects.list("identity/").await.unwrap().is_empty());
}

#[test]
fn merge_refuses_an_unsorted_input() {
    let dir = tempfile::tempdir().unwrap();
    let unsorted = dir.path().join("unsorted.parquet");
    let batch = encode(&[user("okta", "b", 1), user("okta", "a", 1)], true).unwrap();
    let mut writer =
        ArrowWriter::try_new(File::create(&unsorted).unwrap(), schema(), None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    let error =
        merge_files(&[(unsorted, true)], None, &dir.path().join("out.parquet")).unwrap_err();
    assert!(error.to_string().contains("ascending"), "{error}");
}

/// NAN-3503: `is_admin` round-trips; files without it keep the legacy
/// schema byte for byte, and legacy + current files merge into one view.
#[tokio::test]
async fn is_admin_column_is_backward_compatible() {
    let dir = tempfile::tempdir().unwrap();
    // A file with no is_admin anywhere is written in the legacy schema.
    let legacy = dir.path().join("legacy.parquet");
    write_sorted_rows(&legacy, vec![user("okta:users", "a", 1)]).unwrap();
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&legacy).unwrap()).unwrap();
    assert_eq!(reader.schema().fields(), legacy_schema().fields());
    // One row with is_admin switches the file to the current schema.
    let current = dir.path().join("current.parquet");
    let mut admin = IdentityRow::new("okta:groups", "a", SourceKind::Pull, 2);
    admin.groups = vec!["Admins".into()];
    admin.is_admin = Some(true);
    let mut plain = IdentityRow::new("okta:groups", "b", SourceKind::Pull, 2);
    plain.groups = vec!["Staff".into()];
    write_sorted_rows(&current, vec![admin.clone(), plain.clone()]).unwrap();
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&current).unwrap()).unwrap();
    assert_eq!(reader.schema().fields(), schema().fields());
    // A merge of both keeps every row and every is_admin value.
    let out = dir.path().join("merged.parquet");
    merge_files(&[(legacy, true), (current, true)], None, &out).unwrap();
    let mut rows = Vec::new();
    for_each_merged_row(&out, |row| rows.push(row)).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0], admin);
    assert_eq!(rows[1], plain);
    assert_eq!(rows[2].feed_id, "okta:users");
    assert_eq!(rows[2].is_admin, None);
    // A merge of legacy-only inputs stays legacy.
    let only = dir.path().join("only.parquet");
    write_sorted_rows(&only, vec![user("okta:users", "z", 1)]).unwrap();
    let out = dir.path().join("merged-legacy.parquet");
    merge_files(&[(only, true)], None, &out).unwrap();
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&out).unwrap()).unwrap();
    assert_eq!(reader.schema().fields(), legacy_schema().fields());
    // The coordinator's JSON rows accept the new field.
    let row: IdentityRow = serde_json::from_value(serde_json::json!({
        "feed_id": "f:groups", "external_id": "x", "source_kind": "pull", "version": 1,
        "groups": ["role:Global Administrator"], "is_admin": true
    }))
    .unwrap();
    assert_eq!(row.is_admin, Some(true));
}

/// NAN-3503 contract statuses are accepted and round-trip; anything else
/// is still refused.
#[test]
fn widened_account_statuses_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let rows: Vec<IdentityRow> = ["active", "disabled", "staged", "locked", "deprovisioned"]
        .iter()
        .enumerate()
        .map(|(i, status)| {
            let mut row = user("okta:users", &format!("u{i}"), 1);
            row.account_status = status.to_string();
            row
        })
        .collect();
    let path = dir.path().join("statuses.parquet");
    write_sorted_rows(&path, rows.clone()).unwrap();
    let mut read = Vec::new();
    for_each_merged_row(&path, |row| read.push(row)).unwrap();
    assert_eq!(read, rows);
    let mut bad = user("okta:users", "x", 1);
    bad.account_status = "frozen".into();
    assert!(write_sorted_rows(&dir.path().join("bad.parquet"), vec![bad]).is_err());
    let json: IdentityRow = serde_json::from_value(serde_json::json!({
        "feed_id": "entra:users", "external_id": "x", "source_kind": "pull", "version": 1,
        "account_status": "deprovisioned", "account_enabled": false
    }))
    .unwrap();
    json.validate().unwrap();
}

#[tokio::test]
async fn view_lookup_list_and_stats() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let mut pushed = user("okta-push", "x9", 1);
    pushed.source_kind = SourceKind::Push;
    pushed.email = "Alice@Example.com".into();
    let mut alice = user("okta", "alice", 1);
    alice.email = "alice@example.com".into();
    let mut disabled = user("okta", "bob", 1);
    disabled.account_status = "disabled".into();
    store
        .append_delta(None, vec![alice, pushed, disabled])
        .await
        .unwrap();
    let view = view(&store).await;
    let found = view.lookup("ALICE@example.com").unwrap();
    assert_eq!(
        found.len(),
        2,
        "lookup spans feeds for the provenance merge"
    );
    let (total, page) = view
        .list(
            &ListFilter {
                search: Some("ali".into()),
                ..Default::default()
            },
            0,
            10,
        )
        .unwrap();
    assert_eq!((total, page.len()), (2, 2));
    let (total, page) = view
        .list(
            &ListFilter {
                source_kind: Some(SourceKind::Push),
                ..Default::default()
            },
            0,
            10,
        )
        .unwrap();
    assert_eq!((total, page[0].external_id.as_str()), (1, "x9"));
    let (total, page) = view.list(&ListFilter::default(), 1, 1).unwrap();
    assert_eq!((total, page.len()), (3, 1));
    let stats = view.stats();
    assert_eq!(stats.total, 3);
    assert_eq!(stats.by_feed["okta"], 2);
    assert_eq!(stats.by_account_status["disabled"], 1);
    assert_eq!(stats.by_source_kind["push"], 1);
}

/// Negative cross-tenant test: a store bound to tenant B sees nothing of
/// tenant A, even sharing one object store, and refuses A's manifest.
#[tokio::test]
async fn other_tenant_cannot_read_or_overwrite() {
    let f = fixture();
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let a = IdentityStore::new(tenant_a, &f.objects, &f.root.join("a")).unwrap();
    let published = a
        .append_delta(None, vec![user("okta", "secret", 1)])
        .await
        .unwrap();

    let b = IdentityStore::new(tenant_b, &f.objects, &f.root.join("b")).unwrap();
    assert!(b.current().await.is_err(), "B refuses A's pointer");
    assert!(
        b.load_view(&published.manifest).await.is_err(),
        "B refuses A's manifest"
    );
    assert!(b
        .append_delta(None, vec![user("okta", "x", 1)])
        .await
        .is_err());
    assert!(b
        .append_delta(
            Some(published.manifest.revision),
            vec![user("okta", "x", 1)]
        )
        .await
        .is_err());

    // Production roots each tenant at its own prefix: B's store is empty.
    let b_objects = LocalObjectStore::new(f.root.join("r2-b")).unwrap();
    let b = IdentityStore::new(tenant_b, &b_objects, &f.root.join("b2")).unwrap();
    assert!(b.current().await.unwrap().is_none());
    // A's data is untouched by B's attempts.
    assert_eq!(all_rows(&a).await.len(), 1);
}

#[tokio::test]
async fn tampered_file_is_refused() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let published = store
        .append_delta(None, vec![user("okta", "a", 1)])
        .await
        .unwrap();
    let key = object_key(FileKind::Delta, &published.manifest.deltas[0].sha256);
    f.objects.delete(&key).await.unwrap();
    f.objects.put_if_absent(&key, b"not parquet").await.unwrap();
    let fresh = IdentityStore::new(
        published.manifest.tenant_id,
        &f.objects,
        &f.root.join("fresh"),
    )
    .unwrap();
    assert!(fresh.load_view(&published.manifest).await.is_err());
}

/// 500k-user sizing check (NAN-3500). Run with
/// `cargo test --release -p nanosiem-lake-worker lean_identity_snapshot -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "sizing benchmark"]
async fn bench_500k_users_full_snapshot() {
    let f = fixture();
    let store = IdentityStore::new(Uuid::new_v4(), &f.objects, &f.root.join("w")).unwrap();
    let make = |i: usize| {
        let mut row = user("okta", &format!("00u{i:09}"), 1_700_000_000_000);
        row.upn = format!("user{i}@corp.example.com");
        row.first_name = format!("First{i}");
        row.last_name = format!("Last{i}");
        row.department = format!("Dept {}", i % 50);
        row.title = "Engineer".into();
        row.manager_upn = format!("mgr{}@corp.example.com", i % 5000);
        row.company = "Example Corp".into();
        row.office_location = "HQ".into();
        row.city = "Montreal".into();
        row.country = "CA".into();
        row.employee_id = format!("E{i}");
        row
    };
    const USERS: usize = 500_000;
    let started = std::time::Instant::now();
    let mut staged = Vec::new();
    for chunk in (0..USERS)
        .collect::<Vec<_>>()
        .chunks(IDENTITY_MAX_BATCH_ROWS)
    {
        staged.push(stage(&store, chunk.iter().map(|i| make(*i)).collect()));
    }
    let staged_at = started.elapsed();
    let published = store.replace_feed(None, "okta", &staged).await.unwrap();
    let written_at = started.elapsed();
    let snapshot = published.manifest.snapshot.clone().unwrap();
    let reader =
        IdentityStore::new(published.manifest.tenant_id, &f.objects, &f.root.join("r")).unwrap();
    let read_start = std::time::Instant::now();
    let view = reader.load_view(&published.manifest).await.unwrap();
    let read_at = read_start.elapsed();
    let lookup_start = std::time::Instant::now();
    assert_eq!(view.lookup("user123456@corp.example.com").unwrap().len(), 1);
    assert!(view.get("okta", "00u000250000").unwrap().is_some());
    let lookup_at = lookup_start.elapsed();
    let delta_start = std::time::Instant::now();
    reader
        .append_delta(
            Some(published.manifest.revision),
            (0..1000)
                .map(|i| {
                    let mut r = make(i);
                    r.version += 1;
                    r.title = "Staff".into();
                    r
                })
                .collect(),
        )
        .await
        .unwrap();
    let delta_at = delta_start.elapsed();
    eprintln!(
        "500k users: stage {staged_at:?}, stage+snapshot {written_at:?} ({} bytes, {} rows); \
         cold read+view {read_at:?}; lookup+get {lookup_at:?}; 1k-row delta {delta_at:?}",
        snapshot.bytes, snapshot.rows
    );
    assert_eq!(view.len(), USERS);
    assert!(written_at < std::time::Duration::from_secs(60));
    assert!(read_at < std::time::Duration::from_secs(60));
}

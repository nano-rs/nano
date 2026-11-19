// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5668: an interrupted MITRE catalog apply backs off instead of
//! crash-looping nano-jobs, and large content files read back in slices.
//!
//! Real PostgreSQL (migrated, its own database per run). Proves:
//! 1. a `syncing` state left by a killed process is recorded as a failure
//!    (interrupted reason, backoff armed) on the next attempt, and both the
//!    content-channel apply and the scheduler then back off without parsing;
//! 2. an ordinary failure does NOT block the content-channel apply;
//! 3. `read_tree` / `read_file_capped` return byte-exact large files read in
//!    slices, refuse an over-cap file before reading it, and report a missing
//!    one.
//!
//! ```text
//! NANOSIEM_TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:<port>/postgres \
//!   cargo test -p nanosiem-core --test mitre_sync_interrupted_integration -- --ignored --nocapture
//! ```

use nanosiem_core::content_bundle::store::{CappedFile, ContentStore, READ_SLICE_BYTES};
use nanosiem_core::mitre::{MitreRepository, MitreSync, MitreSyncError, MitreSyncOutcome};

async fn fresh_pg() -> sqlx::PgPool {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL")
        .expect("NANOSIEM_TEST_DATABASE_URL must target a disposable PostgreSQL");
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("mi_{}", &uuid::Uuid::now_v7().simple().to_string()[18..]);
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .unwrap();
    let (base, _) = url.rsplit_once('/').unwrap();
    let pool = sqlx::PgPool::connect(&format!("{base}/{name}")).await.unwrap();
    nanosiem_core::db::run_postgres_migrations(&pool).await.unwrap();
    pool
}

async fn state(pool: &sqlx::PgPool) -> (String, i32, bool, Option<String>) {
    sqlx::query_as(
        "SELECT status::text, consecutive_failures, COALESCE(next_retry_at > NOW(), FALSE), last_error \
         FROM mitre_sync_state WHERE singleton",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "needs NANOSIEM_TEST_DATABASE_URL (disposable PostgreSQL)"]
async fn interrupted_apply_backs_off_and_ordinary_failure_does_not_block_apply() {
    let pool = fresh_pg().await;
    let sync = MitreSync::new(MitreRepository::new(pool.clone()));

    // A process killed mid-sync leaves the state at `syncing`.
    sqlx::query("UPDATE mitre_sync_state SET status = 'syncing', last_started_at = NOW() WHERE singleton")
        .execute(&pool)
        .await
        .unwrap();

    // 1. The next content apply records the interruption and backs off
    //    before touching the body (garbage here would otherwise fail digest).
    let outcome = sync.apply_content(b"not the pinned bundle").await.unwrap();
    assert_eq!(outcome, MitreSyncOutcome::RetryBackoff);
    let (status, failures, backing_off, error) = state(&pool).await;
    assert_eq!(status, "failed");
    assert_eq!(failures, 1);
    assert!(backing_off, "an interrupted attempt must arm the retry backoff");
    assert!(error.as_deref().is_some_and(|e| e.starts_with("interrupted:")), "{error:?}");

    // ...and so does the scheduler, without re-counting the interruption.
    assert_eq!(sync.sync_if_due().await.unwrap(), MitreSyncOutcome::RetryBackoff);
    assert_eq!(state(&pool).await.1, 1);

    // A second boot that finds the same backoff still does nothing.
    assert_eq!(
        sync.apply_content(b"not the pinned bundle").await.unwrap(),
        MitreSyncOutcome::RetryBackoff
    );

    // 2. Once the backoff passes, an ordinary failure (digest mismatch) is
    //    recorded, and it does NOT block the next content apply.
    sqlx::query("UPDATE mitre_sync_state SET next_retry_at = NOW() - INTERVAL '1 second' WHERE singleton")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        sync.apply_content(b"not the pinned bundle").await,
        Err(MitreSyncError::DigestMismatch { .. })
    ));
    let (status, failures, backing_off, error) = state(&pool).await;
    assert_eq!((status.as_str(), failures, backing_off), ("failed", 2, true));
    assert!(error.as_deref().is_some_and(|e| e.contains("digest mismatch")), "{error:?}");
    assert!(matches!(
        sync.apply_content(b"not the pinned bundle").await,
        Err(MitreSyncError::DigestMismatch { .. })
    ), "an ordinary failure must not hold back a content apply");
    // The scheduler honours every backoff.
    assert_eq!(sync.sync_if_due().await.unwrap(), MitreSyncOutcome::RetryBackoff);
}

#[tokio::test]
#[ignore = "needs NANOSIEM_TEST_DATABASE_URL (disposable PostgreSQL)"]
async fn large_content_files_read_back_exactly_in_slices() {
    let pool = fresh_pg().await;
    // 3.5 slices with a non-repeating pattern, so a misplaced slice shows.
    let large: Vec<u8> = (0..(READ_SLICE_BYTES as usize * 7 / 2))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let exact: Vec<u8> = vec![7u8; READ_SLICE_BYTES as usize];
    let small = b"small file".to_vec();
    sqlx::query("INSERT INTO content_channel_state (channel) VALUES ('mitre-attack.v19-1')")
        .execute(&pool)
        .await
        .unwrap();
    for (path, content) in [("big.json", &large), ("exact.bin", &exact), ("small.txt", &small)] {
        sqlx::query(
            "INSERT INTO content_channel_files (channel, path, blob_sha1, size, content) \
             VALUES ('mitre-attack.v19-1', $1, $2, $3, $4)",
        )
        .bind(path)
        .bind("0".repeat(40))
        .bind(content.len() as i64)
        .bind(content)
        .execute(&pool)
        .await
        .unwrap();
    }
    let store = ContentStore::new(pool.clone());

    let tree = store.read_tree("mitre-attack.v19-1", &[]).await.unwrap();
    assert_eq!(tree.len(), 3);
    assert!(tree["big.json"] == large, "sliced read must be byte-exact");
    assert!(tree["exact.bin"] == exact);
    assert_eq!(tree["small.txt"], small);

    assert_eq!(
        store.read_file("mitre-attack.v19-1", "/big.json").await.unwrap().as_deref(),
        Some(large.as_slice())
    );
    assert_eq!(
        store.read_file_capped("mitre-attack.v19-1", "big.json", 1024).await.unwrap(),
        CappedFile::TooLarge(large.len() as u64)
    );
    assert_eq!(
        store.read_file_capped("mitre-attack.v19-1", "absent.json", 1024).await.unwrap(),
        CappedFile::Missing
    );
    assert_eq!(store.read_file("mitre-attack.v19-1", "absent.json").await.unwrap(), None);
}

/// Install (sliced upload of a large file, batched small files) round-trips
/// byte-exact through `read_tree`, and a re-install replaces the files.
#[tokio::test]
#[ignore = "needs NANOSIEM_TEST_DATABASE_URL (disposable PostgreSQL)"]
async fn install_uploads_large_files_in_slices_and_round_trips() {
    use nanosiem_core::content_bundle::{channels, contract, tree};
    let pool = fresh_pg().await;
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x37; 32]);
    let ring = nanosiem_core::platform_enrichment::portable::KeyRing::from_hex(&[(
        "fixture-nan5668",
        &hex::encode(key.verifying_key().as_bytes()),
    )])
    .unwrap();
    let seal = |sequence: u64, files: &tree::Files| {
        let payload = tree::pack(files).unwrap();
        let now = chrono::Utc::now() - chrono::Duration::minutes(1);
        let channel = channels::by_id("mitre-attack.v19-1").unwrap();
        let bytes = contract::seal(
            contract::SealInput {
                channel: channel.id,
                sequence,
                produced_at: now,
                upstream: contract::Upstream {
                    commit: "c".repeat(40),
                    committed_at: now - chrono::Duration::hours(1),
                },
            },
            &payload,
            &tree::summarize(files),
            "fixture-nan5668",
            &key,
            &ring,
        )
        .unwrap()
        .1;
        contract::verify_bytes(&bytes, &ring).unwrap()
    };
    let large: Vec<u8> = (0..(READ_SLICE_BYTES as usize * 5 / 2 + 7))
        .map(|i| (i.wrapping_mul(2_246_822_519) >> 11) as u8)
        .collect();
    let mut files = tree::Files::new();
    files.insert("enterprise-attack/enterprise-attack.json".into(), large.clone());
    files.insert("README.md".into(), b"readme".to_vec());
    files.insert("LICENSE.txt".into(), vec![b'x'; READ_SLICE_BYTES as usize]);
    let store = ContentStore::new(pool.clone());

    assert!(store.install(&seal(1, &files), "offline", "file").await.unwrap());
    assert!(store.read_tree("mitre-attack.v19-1", &[]).await.unwrap() == files);
    let (sha, size): (String, i64) = sqlx::query_as(
        "SELECT blob_sha1, size FROM content_channel_files WHERE path = 'enterprise-attack/enterprise-attack.json'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((sha, size), (tree::git_blob_sha1(&large), large.len() as i64));

    // A new tree replaces every file, including the sliced one.
    files.insert(
        "enterprise-attack/enterprise-attack.json".into(),
        large[..large.len() - 3].to_vec(),
    );
    files.remove("README.md");
    assert!(store.install(&seal(2, &files), "offline", "file").await.unwrap());
    assert!(store.read_tree("mitre-attack.v19-1", &[]).await.unwrap() == files);
}

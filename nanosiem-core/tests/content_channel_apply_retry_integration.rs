// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4955 review P2: a content channel whose apply failed is not "current".
//!
//! Real PostgreSQL (migrated, its own database per run), a fixture-signed
//! bundle and an applier that fails on demand. Proves:
//! 1. import → apply fails → `ApplyFailed` (explicit partial failure), the
//!    snapshot stays installed with `apply_error`, status says apply_pending;
//! 2. re-import of the SAME bundle re-runs the applier (forced) → `Reapplied`;
//! 3. a further re-import is `Current` (no apply);
//! 4. a re-sealed descriptor over an unchanged tree after a failed apply is
//!    handed to the applier with `tree_changed = true` (an applier that skips
//!    unchanged trees would otherwise never retry it).
//!
//! ```text
//! NANOSIEM_TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:<port>/postgres \
//!   cargo test -p nanosiem-core --test content_channel_apply_retry_integration -- --ignored --nocapture
//! ```

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use nanosiem_core::content_bundle::channels::{self, Channel};
use nanosiem_core::content_bundle::consumer::{
    ChannelError, ChannelOutcome, ContentApplier, ContentConfig, ContentConsumer,
};
use nanosiem_core::content_bundle::contract::{self, SealInput, Upstream, VerifiedContent};
use nanosiem_core::content_bundle::store::ContentStore;
use nanosiem_core::content_bundle::tree::{self, Files};
use nanosiem_core::platform_enrichment::portable::KeyRing;

const KEY_ID: &str = "fixture-apply-retry";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}
fn ring() -> KeyRing {
    KeyRing::from_hex(&[(KEY_ID, &hex::encode(key().verifying_key().as_bytes()))]).unwrap()
}

fn bundle(channel: &str, sequence: u64, files: &Files) -> Vec<u8> {
    let payload = tree::pack(files).unwrap();
    let ch = channels::by_id(channel).unwrap();
    let now = Utc::now() - Duration::minutes(1);
    let commit = if ch.repo.is_empty() { String::new() } else { "c".repeat(40) };
    contract::seal(
        SealInput { channel, sequence, produced_at: now, upstream: Upstream { commit, committed_at: now - Duration::hours(1) } },
        &payload,
        &tree::summarize(files),
        KEY_ID,
        &key(),
        &ring(),
    )
    .unwrap()
    .1
}

#[derive(Default)]
struct FlakyApplier {
    fail: AtomicBool,
    calls: AtomicUsize,
    forced: Mutex<Vec<bool>>,
}

#[async_trait]
impl ContentApplier for FlakyApplier {
    async fn apply(&self, _ch: &'static Channel, _v: &VerifiedContent, tree_changed: bool) -> Result<String, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.forced.lock().unwrap().push(tree_changed);
        if self.fail.load(Ordering::SeqCst) {
            Err("simulated PostgreSQL outage during apply".into())
        } else {
            Ok("applied".into())
        }
    }
}

async fn fresh_pg() -> sqlx::PgPool {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL")
        .expect("NANOSIEM_TEST_DATABASE_URL must target a disposable PostgreSQL");
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("cc_{}", &uuid::Uuid::now_v7().simple().to_string()[18..]);
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
    let (base, _) = url.rsplit_once('/').unwrap();
    let pool = sqlx::PgPool::connect(&format!("{base}/{name}")).await.unwrap();
    nanosiem_core::db::run_postgres_migrations(&pool).await.unwrap();
    pool
}

fn consumer(pool: &sqlx::PgPool, applier: Arc<FlakyApplier>) -> ContentConsumer {
    let work = tempfile::tempdir().unwrap().keep();
    let mut config = ContentConfig::from_env(true, nanosiem_core::schema::SchemaId::Ocsf, true);
    config.work_dir = work.join("cc");
    ContentConsumer::new(ContentStore::new(pool.clone()), config, applier).with_ring(ring())
}

fn files(extra: &str) -> Files {
    [("playbooks/triage/playbook.yaml", "name: triage\n"), ("README.md", extra)]
        .iter()
        .map(|(p, c)| (p.to_string(), c.as_bytes().to_vec()))
        .collect()
}

#[tokio::test]
#[ignore = "needs NANOSIEM_TEST_DATABASE_URL (disposable PostgreSQL)"]
async fn failed_apply_is_retried_on_reimport_and_never_reported_current() {
    let pool = fresh_pg().await;
    let applier = Arc::new(FlakyApplier::default());
    let c = consumer(&pool, applier.clone());
    let b1 = bundle("playbooks.main", 100, &files("v1"));

    // 1. apply fails: explicit partial failure, snapshot installed, pending.
    applier.fail.store(true, Ordering::SeqCst);
    let err = c.import_bytes(b1.clone()).await.unwrap_err();
    assert!(matches!(err, ChannelError::ApplyFailed(_)), "{err:?}");
    let row = c.store().get("playbooks.main").await.unwrap().unwrap();
    assert_eq!(row.sequence, Some(100));
    assert!(row.apply_error.as_deref().is_some_and(|e| e.contains("simulated")));
    let status = c.status().await.unwrap();
    let st = status.channels.iter().find(|s| s.channel == "playbooks.main").unwrap();
    assert!(st.installed && st.apply_pending);

    // 2. same bundle again, apply now works: re-applied (forced), not "current".
    applier.fail.store(false, Ordering::SeqCst);
    let out = c.import_bytes(b1.clone()).await.unwrap();
    assert_eq!(out, ChannelOutcome::Reapplied { sequence: 100 });
    assert_eq!(applier.calls.load(Ordering::SeqCst), 2);
    assert_eq!(applier.forced.lock().unwrap()[1], true);
    let row = c.store().get("playbooks.main").await.unwrap().unwrap();
    assert!(row.apply_error.is_none() && row.applied_at.is_some());

    // 3. nothing pending any more: current, no apply.
    assert_eq!(c.import_bytes(b1.clone()).await.unwrap(), ChannelOutcome::Current { sequence: 100 });
    assert_eq!(applier.calls.load(Ordering::SeqCst), 2);

    // 4. re-sealed descriptor (new sequence) over the SAME tree after a failed
    //    apply: the applier gets tree_changed = true.
    applier.fail.store(true, Ordering::SeqCst);
    let b2 = bundle("playbooks.main", 200, &files("v2"));
    assert!(matches!(c.import_bytes(b2).await, Err(ChannelError::ApplyFailed(_))));
    applier.fail.store(false, Ordering::SeqCst);
    let resealed = bundle("playbooks.main", 300, &files("v2"));
    let out = c.import_bytes(resealed).await.unwrap();
    assert!(matches!(out, ChannelOutcome::Installed { sequence: 300, tree_changed: false, .. }), "{out:?}");
    assert_eq!(*applier.forced.lock().unwrap().last().unwrap(), true, "pending apply forces the applier on an unchanged tree");
    let row = c.store().get("playbooks.main").await.unwrap().unwrap();
    assert!(row.apply_error.is_none());
}

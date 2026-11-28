// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5668: peak heap of the MITRE ATT&CK catalog apply.
//!
//! nano-jobs on an 8 GB host runs under a few hundred MiB, and the v19.1
//! bundle alone is 53 MB. These tests count live heap bytes with a global
//! allocator (this file is its own test binary, so nothing else is affected).
//!
//! The ignored tests measure the real pinned bundle:
//!
//! ```text
//! MITRE_BUNDLE_PATH=/path/enterprise-attack.json \
//!   cargo test -p nanosiem-core --test mitre_bundle_memory -- --ignored --nocapture real_bundle
//! MITRE_BUNDLE_PATH=... NANOSIEM_TEST_DATABASE_URL=postgres://... \
//!   cargo test -p nanosiem-core --test mitre_bundle_memory -- --ignored --nocapture pg_path
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            if new_size >= layout.size() {
                let grow = new_size - layout.size();
                let live = LIVE.fetch_add(grow, Ordering::Relaxed) + grow;
                PEAK.fetch_max(live, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        new
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Run `f` and return its result with the peak live heap it added above the
/// heap live when it started. Tests in this binary run on one thread
/// (`serial` mutex) so the counters belong to the measured closure.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let out = f();
    let peak = PEAK.load(Ordering::Relaxed);
    (out, peak.saturating_sub(base))
}

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

const MIB: usize = 1024 * 1024;

/// A bundle shaped like ATT&CK: a couple of catalog objects buried in prose
/// the catalog never stores (relationship and group descriptions, citations).
fn synthetic_bundle(prose_objects: usize) -> Vec<u8> {
    let prose = "Adversaries have been observed doing this. ".repeat(48); // ~2 KiB
    let mut objects = vec![
        serde_json::json!({
            "type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Execution",
            "x_mitre_shortname": "execution", "description": prose,
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}]
        }),
        serde_json::json!({
            "type": "attack-pattern", "id": "attack-pattern--1", "name": "Command and Scripting Interpreter",
            "description": prose,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]
        }),
    ];
    for i in 0..prose_objects {
        objects.push(if i % 2 == 0 {
            serde_json::json!({
                "type": "relationship", "id": format!("relationship--{i}"), "relationship_type": "uses",
                "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1", "description": prose,
                "external_references": [{"source_name": "Vendor report", "description": prose, "url": "https://example.com/report"}]
            })
        } else {
            serde_json::json!({
                "type": "intrusion-set", "id": format!("intrusion-set--{i}"), "name": "Group",
                "description": prose, "aliases": ["G1", "G2"]
            })
        });
    }
    serde_json::to_vec(&serde_json::json!({"type": "bundle", "id": "bundle--synthetic", "objects": objects}))
        .unwrap()
}

/// NAN-5668 regression guard: decoding must not hold the bundle's prose.
/// A `Vec<StixObject>` decode of this body holds about as much heap as the
/// body itself; the streaming decode holds a few KiB of retained objects plus
/// one object in flight.
#[test]
fn streaming_decode_does_not_hold_the_bundle_prose() {
    let _guard = SERIAL.lock().unwrap();
    let body = synthetic_bundle(4_000);
    assert!(body.len() > 8 * MIB, "fixture must be large enough to matter: {}", body.len());

    let (filtered, peak) =
        measure(|| nanosiem_core::mitre::decode_filtered_bundle(&body).expect("decodes"));
    assert_eq!(filtered.object_count, 4_002);
    assert_eq!(filtered.bundle.objects.len(), 2, "only the tactic and the technique are kept");
    assert!(
        peak < MIB,
        "streaming decode peaked at {} KiB above the {} MiB body; it must not retain prose",
        peak / 1024,
        body.len() / MIB
    );

    // Contrast: the full typed decode the sync used before NAN-5668.
    let (full, full_peak) =
        measure(|| serde_json::from_slice::<nanosiem_core::mitre::StixBundle>(&body).expect("decodes"));
    assert_eq!(full.objects.len(), 4_002);
    assert!(
        full_peak > body.len() / 2,
        "the guard's fixture must expose a whole-bundle decode (peaked at {} MiB)",
        full_peak / MIB
    );
}

#[test]
#[ignore = "needs MITRE_BUNDLE_PATH pointing at the pinned v19.1 enterprise-attack.json"]
fn real_bundle_parse_peak_heap() {
    let _guard = SERIAL.lock().unwrap();
    let path = std::env::var("MITRE_BUNDLE_PATH").expect("MITRE_BUNDLE_PATH");
    let body = std::fs::read(path).expect("bundle readable");
    let (catalog, peak) =
        measure(|| nanosiem_core::mitre::MitreSync::parse_pinned_body(&body).expect("parses"));
    println!(
        "NAN-5668 parse: body={} MiB, peak heap above body={} MiB, tactics={} techniques={} aliases={}",
        body.len() / MIB,
        peak / MIB,
        catalog.tactics.len(),
        catalog.techniques.len(),
        catalog.aliases.len()
    );
    assert_eq!(catalog.tactics.len(), 15);
    assert_eq!(catalog.techniques.len(), 697);
    assert_eq!(catalog.aliases.len(), 149);
    // Measured 5 MiB after NAN-5668 (32 MiB before).
    assert!(peak < 16 * MIB, "parse peaked {} MiB above the body", peak / MIB);
}

/// The content consumer's first install of the channel: verify a sealed
/// container (fixture key), write it to PostgreSQL, then apply the verified
/// bytes in place. Measured against a scratch database of its own.
#[test]
#[ignore = "needs MITRE_BUNDLE_PATH and a scratch NANOSIEM_TEST_DATABASE_URL"]
fn real_bundle_install_path_peak_heap() {
    use nanosiem_core::content_bundle::{channels, contract, tree};
    let _guard = SERIAL.lock().unwrap();
    let path = std::env::var("MITRE_BUNDLE_PATH").expect("MITRE_BUNDLE_PATH");
    let url = nanosiem_test_db::require_pg_url();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let ring = nanosiem_core::platform_enrichment::portable::KeyRing::from_hex(&[(
        "fixture-nan5668",
        &hex::encode(key.verifying_key().as_bytes()),
    )])
    .unwrap();
    let container = {
        let mut files = tree::Files::new();
        files.insert(
            nanosiem_core::mitre::MITRE_CONTENT_PATH.to_string(),
            std::fs::read(&path).expect("bundle readable"),
        );
        let payload = tree::pack(&files).unwrap();
        let now = chrono::Utc::now() - chrono::Duration::minutes(1);
        let channel = channels::by_id("mitre-attack.v19-1").unwrap();
        contract::seal(
            contract::SealInput {
                channel: channel.id,
                sequence: 1,
                produced_at: now,
                upstream: contract::Upstream {
                    commit: "c".repeat(40),
                    committed_at: now - chrono::Duration::hours(1),
                },
            },
            &payload,
            &tree::summarize(&files),
            "fixture-nan5668",
            &key,
            &ring,
        )
        .unwrap()
        .1
    };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let admin = sqlx::PgPool::connect(&url).await.expect("scratch postgres");
        let name = format!("nan5668_install_{}", &uuid::Uuid::now_v7().simple().to_string()[20..]);
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.unwrap();
        let (base, _) = url.rsplit_once('/').unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&format!("{base}/{name}"))
            .await
            .unwrap();
        nanosiem_core::db::run_postgres_migrations(&pool).await.unwrap();
        let store = nanosiem_core::content_bundle::store::ContentStore::new(pool.clone());
        let base_live = LIVE.load(Ordering::Relaxed);
        PEAK.store(base_live, Ordering::Relaxed);
        let verified = contract::verify_bytes(&container, &ring).expect("verifies");
        drop(container);
        let after_verify = PEAK.load(Ordering::Relaxed).saturating_sub(base_live);
        store.install(&verified, "offline", "file").await.expect("installs");
        let after_install = PEAK.load(Ordering::Relaxed).saturating_sub(base_live);
        let catalog = nanosiem_core::mitre::MitreSync::parse_pinned_body(
            verified.files().get(nanosiem_core::mitre::MITRE_CONTENT_PATH).unwrap(),
        )
        .expect("parses");
        let peak = PEAK.load(Ordering::Relaxed).saturating_sub(base_live);
        drop((verified, catalog));
        let after_drop = LIVE.load(Ordering::Relaxed).saturating_sub(base_live);
        println!(
            "NAN-5668 install path: peak heap through verify={} MiB, through install={} MiB, through apply={} MiB, live after drop (pool buffers)={} MiB",
            after_verify / MIB,
            after_install / MIB,
            peak / MIB,
            after_drop / MIB
        );
    });
}

#[test]
#[ignore = "needs MITRE_BUNDLE_PATH and a scratch NANOSIEM_TEST_DATABASE_URL"]
fn real_bundle_pg_path_peak_heap() {
    let _guard = SERIAL.lock().unwrap();
    let path = std::env::var("MITRE_BUNDLE_PATH").expect("MITRE_BUNDLE_PATH");
    let url = nanosiem_test_db::require_pg_url();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("scratch postgres");
        for ddl in [
            "CREATE TABLE IF NOT EXISTS content_channel_state (channel TEXT PRIMARY KEY)",
            "CREATE TABLE IF NOT EXISTS content_channel_files (channel TEXT NOT NULL, path TEXT NOT NULL, \
             blob_sha1 TEXT NOT NULL, size BIGINT NOT NULL, content BYTEA NOT NULL, PRIMARY KEY (channel, path))",
        ] {
            sqlx::query(sqlx::AssertSqlSafe(ddl)).execute(&pool).await.unwrap();
        }
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM content_channel_files WHERE channel = 'mitre-attack.v19-1')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if !present {
            let body = std::fs::read(&path).expect("bundle readable");
            sqlx::query("INSERT INTO content_channel_state (channel) VALUES ('mitre-attack.v19-1') ON CONFLICT DO NOTHING")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO content_channel_files (channel, path, blob_sha1, size, content) \
                 VALUES ('mitre-attack.v19-1', 'enterprise-attack/enterprise-attack.json', $1, $2, $3)",
            )
            .bind("0".repeat(40))
            .bind(body.len() as i64)
            .bind(&body)
            .execute(&pool)
            .await
            .unwrap();
        }
        // Start from a pool whose connections have never carried the bundle.
        pool.close().await;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let sync = nanosiem_core::mitre::MitreSync::new(nanosiem_core::mitre::MitreRepository::new(
            pool.clone(),
        ));
        let base = LIVE.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let catalog = sync.load_pinned_catalog().await.expect("loads");
        let peak = PEAK.load(Ordering::Relaxed).saturating_sub(base);
        let retained = LIVE.load(Ordering::Relaxed).saturating_sub(base);
        drop(catalog);
        let after_drop = LIVE.load(Ordering::Relaxed).saturating_sub(base);
        println!(
            "NAN-5668 scheduler path (read_file + parse): peak heap={} MiB, live with catalog={} MiB, live after drop (pool buffers)={} MiB",
            peak / MIB,
            retained / MIB,
            after_drop / MIB
        );

        // The content consumer's re-apply: read the whole channel tree back,
        // then hand the bundle to the applier (which now parses it in place).
        let store = nanosiem_core::content_bundle::store::ContentStore::new(pool.clone());
        let base = LIVE.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let files = store.read_tree("mitre-attack.v19-1", &[]).await.expect("tree");
        let catalog = nanosiem_core::mitre::MitreSync::parse_pinned_body(
            files.get(nanosiem_core::mitre::MITRE_CONTENT_PATH).expect("bundle in tree"),
        )
        .expect("parses");
        let peak = PEAK.load(Ordering::Relaxed).saturating_sub(base);
        drop((files, catalog));
        let after_drop = LIVE.load(Ordering::Relaxed).saturating_sub(base);
        println!(
            "NAN-5668 re-apply path (read_tree + parse in place): peak heap={} MiB, live after drop (pool buffers)={} MiB",
            peak / MIB,
            after_drop / MIB
        );
    });
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4164, native: the first bare-keyword search after a roll. On a large hosted tenant
//! it spent 3.6-6.6 s in select_token on every roll (T59, T61, T62, and
//! T64 after a 1.55 GB page-cache warm): the cell runs at its cgroup memory
//! limit, so the hot volume's page cache does not keep what a warm reads,
//! and a cold probe faulted several header pages per row group before its
//! bloom block.
//!
//! A fresh pod is modelled as a fresh engine on the same volume with the
//! page cache dropped (`POSIX_FADV_DONTNEED`), dropped AGAIN after the
//! before-warm hook (the eviction a busy cell sees). The production hook loads each
//! token index's group layout into the engine; the first search then reads
//! (by `mincore`) only bloom blocks, at most one page per group and token,
//! where a fresh engine without the hook reads the section headers too. The
//! rows are identical. Needs a disk-backed temp directory (tmpfs pages
//! cannot be evicted): `TMPDIR=~/.cache/tmp`.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=... TMPDIR=...
//! cargo test -p nanosiem-lake-worker --lib part_query::local_hot_window::token_warm_native -- --ignored --nocapture --test-threads=1
//! ```

use super::super::density::native::{engine_with_job_cap, ingest_parts, ordered_uids, request, rows_of, TENANT};
use super::super::fetch::PartFile;
use super::super::PartQueryEngine;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

const PARTS: usize = 6;
const PER_PART: usize = 2_000;
const NEEDLE: &str = "qzneedle7731";

fn is_needle(i: usize) -> bool {
    i % 1_777 == 5
}

fn event(i: usize, time: &str) -> Value {
    let mut state = (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut raw = if is_needle(i) { format!("user={NEEDLE} ") } else { String::new() };
    while raw.len() < 600 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        raw.push_str(&format!("k{} {state:016x} ", state % 97));
    }
    json!({
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
        "time": time, "message": format!("connection seq {i}"), "raw_data_size": raw.len(), "raw_data": raw, "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": "fixture_conn", "tenant_uid": TENANT,
                     "product": {"name": "fixture_conn", "vendor_name": "fixture"}},
        "src_endpoint": {"ip": "10.2.2.2"},
        "dst_endpoint": {"ip": "203.0.113.9", "port": 443},
    })
}

fn evict(paths: &[PathBuf]) {
    for path in paths {
        let file = std::fs::File::open(path).unwrap();
        file.sync_all().ok();
        // SAFETY: advisory call on an open descriptor.
        unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    }
}

/// Pages of `paths` in the page cache.
fn resident(paths: &[PathBuf]) -> usize {
    paths
        .iter()
        .map(|path| {
            let file = std::fs::File::open(path).unwrap();
            // SAFETY: read-only map of an immutable, leased object.
            let map = unsafe { memmap2::Mmap::map(&file).unwrap() };
            let mut pages = vec![0_u8; map.len().div_ceil(4_096)];
            // SAFETY: `pages` holds one byte per page of the mapping.
            unsafe { libc::mincore(map.as_ptr() as *mut libc::c_void, map.len(), pages.as_mut_ptr()) };
            pages.iter().filter(|page| **page & 1 == 1).count()
        })
        .sum()
}

/// The token files of every part, leased (a leased path lives only while
/// leased), with their total row groups.
async fn token_files(engine: &PartQueryEngine) -> (super::super::fetch::LocalParts, Vec<PathBuf>, usize) {
    let (parts, ..) = engine.snapshot(i64::MIN, i64::MAX).await.unwrap();
    let records = engine.fetcher().records(&parts).await.unwrap();
    let wanted = parts
        .iter()
        .zip(&records)
        .flat_map(|(part, record)| (0..record.files.data.len()).map(move |index| (part.clone(), PartFile::Tokens(index))))
        .collect::<Vec<_>>();
    let groups = records.iter().flat_map(|record| record.files.data.iter().map(|data| data.row_groups as usize)).sum();
    let leased = engine.fetcher().ensure_files(&wanted).await.unwrap();
    let paths = wanted.iter().map(|(part, file)| leased.path(&part.part_id, *file).unwrap().path.clone()).collect();
    (leased, paths, groups)
}

/// One search through the production path, with its select_token phases.
async fn search(engine: &PartQueryEngine, query: &str, now: DateTime<Utc>) -> (Vec<String>, Value) {
    let request = request(query, now, 100);
    engine.clear_locator_cache();
    crate::query_timing::measure("nan4164", async {
        let answer = engine.broad_npl(&request).await.map_err(|error| error.to_string())?;
        let p = crate::query_timing::current().expect("request scope");
        let p = p.lock().unwrap();
        let phases = json!({
            "select_token_ms": p.select_token_ms, "lease_ms": p.select_token_lease_ms,
            "evidence_ms": p.select_token_evidence_ms, "density_token_ms": p.density_token_ms,
            "probes": p.token_probes, "excluded": p.token_probe_excluded, "probe_ms": p.token_probe_ms,
            "decodes": p.token_decodes, "read_ms": p.token_read_ms, "decode_ms": p.token_decode_ms,
        });
        Ok::<_, String>((ordered_uids(&rows_of(&answer)), phases))
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER; disk-backed TMPDIR"]
async fn layouts_loaded_before_warm_leave_the_first_search_only_bloom_blocks() {
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let time = |i: usize| now - Duration::seconds(i as i64 * 3 + 30);
    let batches = (0..PARTS)
        .map(|n| ((PARTS - 1 - n) * PER_PART..(PARTS - n) * PER_PART).map(|i| event(i, &time(i).to_rfc3339())).collect())
        .collect();
    ingest_parts(root.path(), now, batches).await;
    let expected = (0..PARTS * PER_PART).filter(|i| is_needle(*i)).map(|i| format!("uid-{i:08}")).collect::<Vec<_>>();

    // Control: a fresh engine (new pod), page cache dropped, no hook.
    let control = engine_with_job_cap(root.path(), 3 << 29, 4).await;
    let (leased, paths, groups) = token_files(&control).await;
    evict(&paths);
    if resident(&paths) > 0 {
        eprintln!("NAN4164 SKIP: page cache not evictable under {} (tmpfs?); set TMPDIR to a disk", root.path().display());
        return;
    }
    let (absent_rows, cold) = search(&control, "zzqxneverseen41", now).await;
    let cold_pages = resident(&paths);
    let (rows, _) = search(&control, NEEDLE, now).await;
    assert!(absent_rows.is_empty());
    assert_eq!(rows, expected);
    drop((leased, control));

    // A fresh engine through the production hook, then the eviction a busy cell
    // sees between the warm and the first search.
    let engine = engine_with_job_cap(root.path(), 3 << 29, 4).await;
    let (leased, paths, _) = token_files(&engine).await;
    evict(&paths);
    let (parts, ..) = engine.snapshot(i64::MIN, i64::MAX).await.unwrap();
    let hook = engine.before_warm_hook();
    hook(parts).await;
    assert!(paths.len() >= PARTS);
    evict(&paths);
    let (absent_rows, first) = search(&engine, "zzqxneverseen42", now).await;
    let first_pages = resident(&paths);
    let (rows, _) = search(&engine, NEEDLE, now).await;
    println!("NAN4164 token files={} groups={groups}: cold engine read {cold_pages} pages {cold}; after the hook and an eviction {first_pages} pages {first}", paths.len());
    assert!(absent_rows.is_empty());
    assert_eq!(rows, expected, "rows unchanged");
    assert!(cold_pages > 0, "a cold engine reads token pages");
    // One bloom block per group (a one-token keyword), no header page.
    assert!(first_pages <= groups, "{first_pages} pages for {groups} groups");
    assert!(first_pages * 2 <= cold_pages, "the layouts halve the pages a cold search reads at least");
    drop(leased);
}

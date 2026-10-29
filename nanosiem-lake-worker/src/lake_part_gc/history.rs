// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact disk-backed GC membership/removal proofs. The verified cursor and
//! history changes commit in ONE SQLite transaction. Crash recovery can only
//! expose the previous complete prefix or the next complete prefix. No bloom
//! filter, object-listing absence or aged-out ID is an absence proof.
//! Live membership is paged too: a replay prefix can have many more live
//! parts than the tail. Only one entry's validation working set lives in RAM.
use super::planner::{Removal, RemovalKind};
use crate::parts::{
    part_log::{LiveSet, LogEntry, LogOp, PartRef},
    PartId,
};
use anyhow::{ensure, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex,
};

#[derive(Debug)]
pub(crate) struct PagedHistory {
    db: Mutex<Connection>,
    path: PathBuf,
    #[cfg(unix)]
    file_id: (u64, u64),
    failed: AtomicBool,
    refs: AtomicUsize,
    #[cfg(test)]
    peak_resident_refs: AtomicUsize,
    cache_bytes: AtomicUsize,
    data_version: i64,
    digest: Mutex<Option<[u8; 32]>>,
}

impl PagedHistory {
    pub(crate) fn open(path: &Path, create: bool, cache_bytes: u64) -> Result<Self> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | if create {
                OpenFlags::SQLITE_OPEN_CREATE
            } else {
                OpenFlags::empty()
            };
        let db = Connection::open_with_flags(path, flags)?;
        // A bounded page cache, no mmap or in-memory sort/temporary tables.
        // DELETE journal bounds scratch to the current transaction; FULL and
        // the single transaction also bind the snapshot to exact history.
        db.execute_batch(
            "PRAGMA page_size=4096;
            PRAGMA mmap_size=0; PRAGMA temp_store=FILE;
            PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            PRAGMA cache_spill=ON;",
        )?;
        let cache_kib = i64::try_from(cache_bytes / 1024).context("GC cache size overflow")?.max(64);
        db.pragma_update(None, "cache_size", -cache_kib)?;
        if create {
            db.execute_batch("CREATE TABLE IF NOT EXISTS known (id TEXT PRIMARY KEY) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS removals (id TEXT PRIMARY KEY, proof TEXT NOT NULL) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS live (id TEXT PRIMARY KEY, body TEXT NOT NULL, adopted INTEGER NOT NULL, original_key TEXT) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS live_original_key ON live(original_key) WHERE original_key IS NOT NULL;
                CREATE INDEX IF NOT EXISTS live_unresolved ON live(id) WHERE adopted=1 AND original_key IS NULL;
                CREATE TABLE IF NOT EXISTS cursor (singleton INTEGER PRIMARY KEY CHECK(singleton=1), seq INTEGER NOT NULL, sha TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS snapshot (singleton INTEGER PRIMARY KEY CHECK(singleton=1), body BLOB NOT NULL, sha TEXT NOT NULL, refs INTEGER NOT NULL, digest BLOB NOT NULL);")?;
        }
        let check: String = db.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        ensure!(check == "ok", "GC history integrity check failed");
        let refs: usize = db.query_row(
            "SELECT (SELECT count(*) FROM known) + (SELECT count(*) FROM removals)",
            [],
            |r| r.get(0),
        )?;
        let data_version = db.query_row("PRAGMA data_version", [], |r| r.get(0))?;
        #[cfg(unix)]
        let file_id = {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(path)?;
            (metadata.dev(), metadata.ino())
        };
        Ok(Self {
            db: Mutex::new(db),
            path: path.into(),
            #[cfg(unix)]
            file_id,
            failed: AtomicBool::new(false),
            refs: AtomicUsize::new(refs),
            #[cfg(test)]
            peak_resident_refs: AtomicUsize::new(0),
            cache_bytes: AtomicUsize::new(cache_kib as usize * 1024),
            data_version,
            digest: Mutex::new(None),
        })
    }

    pub(crate) fn check(&self) -> Result<()> {
        ensure!(
            !self.failed.load(Ordering::SeqCst),
            "GC history storage failed; verified reload required"
        );
        ensure!(self.path.is_file(), "GC history storage unavailable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(&self.path)?;
            ensure!(
                (metadata.dev(), metadata.ino()) == self.file_id,
                "GC history storage replaced"
            );
        }
        Ok(())
    }

    pub(crate) fn check_head(&self, head: Option<(u64, &str, u64)>) -> Result<()> {
        self.with(|db| {
            let cursor: Option<(u64, String)> = db
                .query_row("SELECT seq,sha FROM cursor WHERE singleton=1", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            ensure!(
                cursor.as_ref().map(|(seq, sha)| (*seq, sha.as_str()))
                    == head.map(|(seq, sha, _)| (seq, sha)),
                "GC history cursor differs from verified view"
            );
            Ok(())
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.check()?;
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("GC history lock poisoned"))?;
        let result = (|| {
            let version: i64 = db.query_row("PRAGMA data_version", [], |r| r.get(0))?;
            ensure!(version == self.data_version, "GC history changed outside its verified view");
            let value = f(&db)?;
            let version: i64 = db.query_row("PRAGMA data_version", [], |r| r.get(0))?;
            ensure!(version == self.data_version, "GC history changed during a verified read");
            // SQLite's target is soft, especially with dirty B-tree pages.
            // Reserve eight targets (1/128 of role memory), over the measured
            // 4.3x fold peak. Reclaim clean pages before refusing further work.
            let reservation = self.cache_bytes.load(Ordering::SeqCst).saturating_mul(8);
            if Self::cache_used(&db)? > reservation {
                let rc = unsafe { rusqlite::ffi::sqlite3_db_release_memory(db.handle()) };
                ensure!(rc == rusqlite::ffi::SQLITE_OK, "GC SQLite cache reclamation failed");
                ensure!(Self::cache_used(&db)? <= reservation, "GC SQLite cache exceeds role reservation");
            }
            Ok(value)
        })();
        if result.as_ref().is_err_and(|error| !error.is::<crate::parts::part_log::GcInvalidEntry>()) {
            self.failed.store(true, Ordering::SeqCst);
        }
        result
    }

    fn begin(db: &Connection) -> Result<()> {
        if db.is_autocommit() {
            db.execute_batch("BEGIN IMMEDIATE")?;
        }
        Ok(())
    }

    /// Discard a cache whose head could not be verified and replay genesis.
    pub(crate) fn reset(&self) -> Result<()> {
        self.with(|db| {
            Self::begin(db)?;
            db.execute_batch("DELETE FROM known; DELETE FROM removals; DELETE FROM live; DELETE FROM snapshot; DELETE FROM cursor;")?;
            self.refs.store(0, Ordering::SeqCst);
            *self.digest.lock().map_err(|_| anyhow::anyhow!("GC history digest poisoned"))? = Some([0; 32]);
            Ok(())
        })
    }

    pub(crate) fn refs(&self) -> usize {
        self.refs.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn apply(&self, entry: &LogEntry, sha: &str) -> Result<()> {
        self.apply_inner(entry, sha, None)
    }

    pub(crate) fn apply_live(&self, live: &mut LiveSet, entry: &LogEntry, sha: &str) -> Result<()> {
        self.apply_inner(entry, sha, Some(live))
    }

    fn apply_inner(&self, entry: &LogEntry, sha: &str, live: Option<&mut LiveSet>) -> Result<()> {
        self.with(|db| {
            Self::begin(db)?;
            let mut digest = self.digest.lock().map_err(|_| anyhow::anyhow!("GC history digest poisoned"))?;
            if digest.is_none() { *digest = Some(Self::read_digest(db)?); }
            let digest = digest.as_mut().unwrap();
            if let Some(live) = live {
                let mut next = live.gc_working_set(entry, sha, |id| {
                    let id = id.to_string();
                    let (part, seen): (Option<String>, bool) = db.prepare_cached(
                        "SELECT (SELECT body FROM live WHERE id=?1), EXISTS(SELECT 1 FROM known WHERE id=?1)"
                    )?.query_row([&id], |r| Ok((r.get(0)?, r.get(1)?)))?;
                    Ok((part.map(|body| serde_json::from_str(&body)).transpose()?, seen))
                })?;
                let removed = match &entry.op {
                    LogOp::Merge { supersedes, .. } | LogOp::Rewrite { supersedes, .. } => supersedes.as_slice(),
                    LogOp::Retire { parts, .. } => parts.as_slice(),
                    _ => &[],
                };
                for id in removed {
                    let id = id.to_string();
                    let (body, original): (String, Option<String>) = db.prepare_cached(
                        "SELECT body,original_key FROM live WHERE id=?"
                    )?.query_row([&id], |r| Ok((r.get(0)?, r.get(1)?)))?;
                    Self::xor_row(digest, "live", &id, &body);
                    if let Some(key) = original { Self::xor_row(digest, "original", &id, &key); }
                    db.prepare_cached("DELETE FROM live WHERE id=?")?.execute([&id])?;
                }
                for part in next.parts() {
                    let id = part.part_id.to_string();
                    let body = serde_json::to_string(part)?;
                    db.prepare_cached("INSERT INTO live(id,body,adopted) VALUES (?,?,?)")?.execute(params![id, body, !part.sorted])?;
                    Self::xor_row(digest, "live", &id, &body);
                }
                #[cfg(test)]
                self.peak_resident_refs.fetch_max(next.resident_refs(), Ordering::SeqCst);
                next.gc_clear_resident();
                *live = next;
            }
            let previous: Option<(u64, String)> = db.query_row("SELECT seq,sha FROM cursor WHERE singleton=1", [],
                |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            ensure!(previous.as_ref().map_or(entry.seq == 0 && entry.prev_sha256 == crate::parts::part_log::GENESIS_PREV,
                |(seq, sha)| seq.checked_add(1) == Some(entry.seq) && *sha == entry.prev_sha256),
                "GC history write cursor differs from verified entry");
            let mut added = 0;
            let mut known = db.prepare_cached("INSERT OR IGNORE INTO known(id) VALUES (?)")?;
            let mut removal = db.prepare_cached("INSERT INTO removals(id,proof) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET proof=excluded.proof")?;
            let (ids, kind) = match &entry.op {
                LogOp::Merge { supersedes, .. } => (supersedes.as_slice(), RemovalKind::Merge),
                LogOp::Rewrite { supersedes, .. } => (supersedes.as_slice(), RemovalKind::Rewrite),
                LogOp::Retire { parts, .. } => (parts.as_slice(), RemovalKind::Retire),
                _ => (&[][..], RemovalKind::Retire),
            };
            let proof = serde_json::to_string(&Removal { seq: entry.seq, entry_sha256: sha.into(), kind, committed_at_ms: entry.appended_at_ms })?;
            for id in ids {
                let id = id.to_string();
                let previous: Option<String> = db.query_row("SELECT proof FROM removals WHERE id=?", [&id], |r| r.get(0)).optional()?;
                if let Some(previous) = &previous { Self::xor_row(digest, "removals", &id, previous); }
                removal.execute(params![id, proof])?;
                Self::xor_row(digest, "removals", &id, &proof);
                added += usize::from(previous.is_none());
            }
            match &entry.op {
                LogOp::Add { parts, .. } | LogOp::Adopt { parts } => {
                    for part in parts {
                        let id = part.part_id.to_string();
                        let inserted = known.execute([&id])?;
                        if inserted > 0 { Self::xor_row(digest, "known", &id, ""); }
                        added += inserted;
                    }
                }
                LogOp::Merge { output, .. } | LogOp::Rewrite { output, .. } => {
                    let id = output.part_id.to_string();
                    let inserted = known.execute([&id])?;
                    if inserted > 0 { Self::xor_row(digest, "known", &id, ""); }
                    added += inserted;
                }
                _ => {}
            }
            db.execute("INSERT INTO cursor(singleton,seq,sha) VALUES (1,?,?) ON CONFLICT(singleton) DO UPDATE SET seq=excluded.seq,sha=excluded.sha",
                params![entry.seq, sha])?;
            self.refs.fetch_add(added, Ordering::SeqCst);
            Ok(())
        })
    }

    pub(crate) fn is_live(&self, id: &PartId) -> Result<bool> {
        self.with(|db| Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM live WHERE id=?)", [id.to_string()], |r| r.get(0))?))
    }

    pub(crate) fn protects_key(&self, key: &str) -> Result<bool> {
        self.with(|db| Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM live WHERE original_key=?)", [key], |r| r.get(0))?))
    }

    /// Resolve adopted original keys one at a time, bounded independently of
    /// total live/history cardinality. Sorted live parts need no provenance:
    /// their directory's PartId is sufficient to protect every file.
    pub(crate) fn unresolved_adopted(&self) -> Result<Option<PartRef>> {
        self.with(|db| {
            let body: Option<String> = db.query_row("SELECT body FROM live WHERE adopted=1 AND original_key IS NULL LIMIT 1", [], |r| r.get(0)).optional()?;
            body.map(|body| serde_json::from_str(&body).context("GC live reference malformed")).transpose()
        })
    }

    pub(crate) fn protect_original(&self, part: &PartId, key: &str) -> Result<()> {
        ensure!(key.len() <= 4096, "GC adopted key exceeds budget");
        self.with(|db| {
            Self::begin(db)?;
            ensure!(db.execute("UPDATE live SET original_key=? WHERE id=? AND original_key IS NULL", params![key, part.to_string()])? == 1, "GC adopted part changed");
            let mut digest = self.digest.lock().map_err(|_| anyhow::anyhow!("GC history digest poisoned"))?;
            if let Some(digest) = digest.as_mut() { Self::xor_row(digest, "original", &part.to_string(), key); }
            else { *digest = Some(Self::read_digest(db)?); }
            Ok(())
        })
    }

    pub(crate) fn known(&self, id: &PartId, head: Option<(u64, &str, u64)>) -> Result<bool> {
        self.with(|db| {
            // Cursor and proof come from one SQLite read snapshot, including
            // when another process attempts to advance the same cache.
            let (seq, sha, known): (Option<u64>, Option<String>, bool) = db.query_row(
                "SELECT (SELECT seq FROM cursor WHERE singleton=1), (SELECT sha FROM cursor WHERE singleton=1), EXISTS(SELECT 1 FROM known WHERE id=?)",
                [id.to_string()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            ensure!(seq.zip(sha.as_deref()) == head.map(|(seq, sha, _)| (seq, sha)), "GC history read cursor differs");
            Ok(known)
        })
    }

    pub(crate) fn removal(
        &self,
        id: &PartId,
        head: Option<(u64, &str, u64)>,
    ) -> Result<Option<Removal>> {
        self.with(|db| {
            let (seq, sha, proof): (Option<u64>, Option<String>, Option<String>) = db.query_row(
                "SELECT (SELECT seq FROM cursor WHERE singleton=1), (SELECT sha FROM cursor WHERE singleton=1), (SELECT proof FROM removals WHERE id=?)",
                [id.to_string()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            ensure!(seq.zip(sha.as_deref()) == head.map(|(seq, sha, _)| (seq, sha)), "GC history read cursor differs");
            proof.map(|json| serde_json::from_str(&json).context("GC history removal malformed")).transpose()
        })
    }

    pub(crate) fn load_snapshot(&self, max_bytes: u64) -> Result<Option<Vec<u8>>> {
        self.with(|db| {
            // Length, reference count and body are the SAME read snapshot;
            // another process cannot replace a small body with a large one
            // between admission and allocation.
            let tx = db.unchecked_transaction()?;
            let len: Option<u64> = tx.query_row("SELECT length(body) FROM snapshot WHERE singleton=1", [], |r| r.get(0)).optional()?;
            ensure!(len.is_none_or(|len| len <= max_bytes), "persisted GC view exceeds byte budget");
            let refs: usize = tx.query_row("SELECT (SELECT count(*) FROM known) + (SELECT count(*) FROM removals)", [], |r| r.get(0))?;
            let saved: Option<(Vec<u8>, String, usize, Vec<u8>)> = tx.query_row("SELECT body,CASE WHEN length(sha)=64 THEN sha END,refs,CASE WHEN length(digest)=32 THEN digest END FROM snapshot WHERE singleton=1", [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).optional()?;
            let digest = Self::read_digest(&tx)?;
            let body = if let Some((body, sha, expected_refs, expected_digest)) = saved {
                ensure!(crate::parts::sha256_hex(&body) == sha, "GC snapshot checksum differs");
                ensure!(refs == expected_refs && digest.as_slice() == expected_digest, "GC history checksum differs");
                Some(body)
            } else { None };
            tx.commit()?;
            *self.digest.lock().map_err(|_| anyhow::anyhow!("GC history digest poisoned"))? = Some(digest);
            self.refs.store(refs, Ordering::SeqCst);
            Ok(body)
        })
    }

    pub(crate) fn save_snapshot(&self, body: &[u8], head: Option<(u64, &str, u64)>) -> Result<()> {
        self.with(|db| {
            Self::begin(db)?;
            let cursor: Option<(u64, String)> = db.query_row("SELECT seq,sha FROM cursor WHERE singleton=1", [],
                |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            ensure!(cursor.as_ref().map(|(seq, sha)| (*seq, sha.as_str())) == head.map(|(seq, sha, _)| (seq, sha)),
                "GC snapshot cursor differs from verified view");
            let mut digest = self.digest.lock().map_err(|_| anyhow::anyhow!("GC history digest poisoned"))?;
            if digest.is_none() { *digest = Some(Self::read_digest(db)?); }
            db.execute("INSERT INTO snapshot(singleton,body,sha,refs,digest) VALUES (1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET body=excluded.body,sha=excluded.sha,refs=excluded.refs,digest=excluded.digest",
                params![body, crate::parts::sha256_hex(body), self.refs(), digest.as_ref().unwrap().as_slice()])?;
            db.execute_batch("COMMIT")?;
            Ok(())
        })
    }

    // Order-independent checksum of the exact tables, maintained in O(new
    // rows) while folding. Restart checks every row with bounded memory; SQLite
    // quick_check alone cannot detect a valid-looking changed ID/proof/blob.
    fn xor_row(digest: &mut [u8; 32], table: &str, id: &str, proof: &str) {
        let mut hash = Sha256::new();
        for value in [table, id, proof] {
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
        for (byte, row) in digest.iter_mut().zip(hash.finalize()) { *byte ^= row; }
    }

    fn read_digest(db: &Connection) -> Result<[u8; 32]> {
        let mut digest = [0; 32];
        // CASE checks lengths before materializing corrupt variable-length
        // cells. Valid PartIds fit 64 bytes and a serialized Removal fits 512.
        for (table, sql) in [
            ("known", "SELECT CASE WHEN length(id)<=64 THEN id END,'' FROM known"),
            ("removals", "SELECT CASE WHEN length(id)<=64 THEN id END,CASE WHEN length(proof)<=512 THEN proof END FROM removals"),
            ("live", "SELECT CASE WHEN length(id)<=64 THEN id END,CASE WHEN length(body)<=4096 AND adopted=(json_extract(body,'$.sorted')=0) THEN body END FROM live"),
            ("original", "SELECT CASE WHEN length(id)<=64 THEN id END,CASE WHEN length(original_key)<=4096 THEN original_key END FROM live WHERE original_key IS NOT NULL"),
        ] {
            let mut statement = db.prepare(sql)?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let proof: String = row.get(1)?;
                Self::xor_row(&mut digest, table, &id, &proof);
            }
        }
        Ok(digest)
    }

    pub(crate) fn resize_cache(&self, bytes: u64) -> Result<()> {
        let kib = i64::try_from(bytes / 1024).context("GC cache size overflow")?.max(64);
        let bytes = kib as usize * 1024;
        if self.cache_bytes.load(Ordering::SeqCst) == bytes { return Ok(()); }
        self.with(|db| {
            db.pragma_update(None, "cache_size", -kib)?;
            if bytes < self.cache_bytes.load(Ordering::SeqCst) { db.execute_batch("PRAGMA shrink_memory")?; }
            self.cache_bytes.store(bytes, Ordering::SeqCst);
            Ok(())
        })
    }

    #[cfg(test)]
    pub(crate) fn peak_resident_refs(&self) -> usize {
        self.peak_resident_refs.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn cache_bytes(&self) -> Result<usize> {
        self.with(Self::cache_used)
    }

    fn cache_used(db: &Connection) -> Result<usize> {
        let (mut current, mut high) = (0, 0);
        // SQLite allocates its page cache through C, outside Rust's
        // allocator. Ask the active production connection for actual use.
        let rc = unsafe {
            rusqlite::ffi::sqlite3_db_status(
                db.handle(),
                rusqlite::ffi::SQLITE_DBSTATUS_CACHE_USED,
                &mut current,
                &mut high,
                0,
            )
        };
        ensure!(rc == rusqlite::ffi::SQLITE_OK, "GC SQLite memory measurement failed");
        Ok(current as usize)
    }

    pub(crate) fn max_disk_bytes(&self) -> Result<u64> {
        self.with(|db| {
            let pages: u64 = db.query_row("PRAGMA max_page_count", [], |r| r.get(0))?;
            Ok(pages.saturating_mul(4096))
        })
    }

    pub(crate) fn disk_bytes(&self) -> Result<u64> {
        self.with(|db| {
            let pages: u64 = db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            Ok(pages.saturating_mul(4096))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lake_part_gc::planner::tests::{part_ref, Chain, T0};
    use crate::parts::{
        part_log::{LiveSet, SourceRef},
        Level,
    };

    #[test]
    fn part_gc_history_rejects_valid_sqlite_with_corrupted_rows_or_snapshot() {
        for mutation in [
            "UPDATE snapshot SET body=X'636f7272757074'",
            "DELETE FROM known",
            "UPDATE known SET id='1790330400002-0000000000000002' WHERE id=(SELECT min(id) FROM known)",
            "UPDATE removals SET proof=replace(proof,'merge','retire')",
            "DELETE FROM live",
            "UPDATE live SET adopted=1",
            "UPDATE live SET original_key='wrong/key'",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("history.sqlite");
            let history = PagedHistory::open(&path, true, 2 * 1024 * 1024).unwrap();
            let mut chain = Chain::new();
            chain.add(1, T0 + 1);
            chain.push(LogOp::Merge { output: part_ref(3, Level::Minute),
                supersedes: vec![part_ref(1, Level::L0).part_id] }, T0 + 3);
            let mut live = LiveSet::default();
            for (entry, sha) in &chain.entries { history.apply_live(&mut live, entry, sha).unwrap(); }
            let (entry, sha) = chain.entries.last().unwrap();
            history.save_snapshot(b"verified", Some((entry.seq, sha, entry.writer_epoch))).unwrap();
            drop(history);
            Connection::open(&path).unwrap().execute_batch(mutation).unwrap();
            // quick_check still passes; the committed checksums must refuse.
            let reopened = PagedHistory::open(&path, false, 2 * 1024 * 1024).unwrap();
            assert!(reopened.load_snapshot(1024).is_err(), "{mutation}");
            assert!(reopened.known(&part_ref(1, Level::L0).part_id,
                Some((entry.seq, sha, entry.writer_epoch))).is_err(), "failure is latched");
        }
    }

    #[test]
    fn part_gc_history_refuses_external_changes_and_resizes_its_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite");
        let history = PagedHistory::open(&path, true, 32 * 1024 * 1024).unwrap();
        history.resize_cache(2 * 1024 * 1024).unwrap();
        history.with(|db| {
            let kib: i64 = db.query_row("PRAGMA cache_size", [], |r| r.get(0))?;
            assert_eq!(kib, -2048);
            Ok(())
        }).unwrap();
        history.save_snapshot(b"empty", None).unwrap();
        Connection::open(&path).unwrap().execute("INSERT INTO known VALUES ('unexpected')", []).unwrap();
        assert!(history.known(&part_ref(1, Level::L0).part_id, None).is_err());
    }

    #[test]
    fn part_gc_measured_resident_identity_charge() {
        let _measurement = crate::test_heap::MEASUREMENT.lock().unwrap();
        // Separate thread: no pre-existing allocations get freed in the
        // measurement window. Source cardinality is independent of parts.
        for (parts, sources) in [(1_000, 1), (1, 1_000)] {
            let result = std::thread::spawn(move || {
                let mut chain = Chain::new();
                chain.push(
                    LogOp::Add {
                        parts: (1..=parts).map(|n| part_ref(n, Level::L0)).collect(),
                        consumed: (0..sources)
                            .map(|n| SourceRef {
                                key: format!("bronze/{n}"),
                                version: "1".into(),
                                sha256: "d".repeat(64),
                            })
                            .collect(),
                        edge_log: None,
                    },
                    T0 + 20_000,
                );
                crate::test_heap::track_current_thread(true);
                let start = crate::test_heap::reset_peak();
                let mut live = LiveSet::default();
                for (entry, sha) in &chain.entries {
                    live.apply(entry, sha).unwrap();
                }
                let refs = live.resident_refs();
                let retained = crate::test_heap::live() - start;
                let peak = crate::test_heap::peak() - start;
                // Includes B-tree nodes and string capacities, not a JSON
                // size estimate. Parsed-entry/read-ahead are separate bounds.
                assert!(retained > 0 && (retained as usize) < refs * 2048);
                assert!((peak as usize) < refs * 2048);
                eprintln!("GC_RESIDENT_MEMORY parts={parts} sources={sources} refs={refs} retained_bytes={retained} peak_bytes={peak} charged_bytes={}", refs * 2048);
                drop(live);
                crate::test_heap::track_current_thread(false);
            });
            result.join().unwrap();
        }
    }

    #[test]
    fn part_gc_history_live_state_and_cursor_rollback_together() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite");
        let history = PagedHistory::open(&path, true, 1024 * 1024).unwrap();
        let mut chain = Chain::new();
        chain.add(1, T0 + 1);
        let mut live = LiveSet::default();
        for (entry, sha) in &chain.entries { history.apply_live(&mut live, entry, sha).unwrap(); }
        history.save_snapshot(&serde_json::to_vec(&live).unwrap(), live.head()).unwrap();
        chain.push(LogOp::Merge { output: part_ref(3, Level::Minute),
            supersedes: vec![part_ref(1, Level::L0).part_id] }, T0 + 3);
        let (entry, sha) = chain.entries.last().unwrap();
        history.apply_live(&mut live, entry, sha).unwrap();
        assert!(!history.is_live(&part_ref(1, Level::L0).part_id).unwrap());
        assert!(history.is_live(&part_ref(3, Level::Minute).part_id).unwrap());
        drop(history); // Crash before snapshot/commit.
        let recovered = PagedHistory::open(&path, false, 1024 * 1024).unwrap();
        let mut live: LiveSet = serde_json::from_slice(&recovered.load_snapshot(100_000).unwrap().unwrap()).unwrap();
        recovered.check_head(live.head()).unwrap();
        assert!(recovered.is_live(&part_ref(1, Level::L0).part_id).unwrap());
        assert!(!recovered.is_live(&part_ref(3, Level::Minute).part_id).unwrap());
        recovered.apply_live(&mut live, entry, sha).unwrap();
        recovered.save_snapshot(&serde_json::to_vec(&live).unwrap(), live.head()).unwrap();
        drop(recovered);
        let committed = PagedHistory::open(&path, false, 1024 * 1024).unwrap();
        committed.load_snapshot(100_000).unwrap();
        committed.check_head(live.head()).unwrap();
        assert!(!committed.is_live(&part_ref(1, Level::L0).part_id).unwrap());
        assert!(committed.is_live(&part_ref(3, Level::Minute).part_id).unwrap());
    }

    #[test]
    fn part_gc_history_snapshot_and_proofs_commit_or_rollback_together() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite");
        let history = PagedHistory::open(&path, true, 4 * 1024 * 1024).unwrap();
        let mut chain = Chain::new();
        chain.add(1, T0 + 1);
        for (entry, sha) in &chain.entries {
            history.apply(entry, sha).unwrap();
        }
        history.save_snapshot(b"prefix1", Some((1, &chain.entries[1].1, 1))).unwrap();
        chain.add(2, T0 + 2);
        let (entry, sha) = chain.entries.last().unwrap();
        history.apply(entry, sha).unwrap();
        assert!(history
            .known(
                &part_ref(2, Level::L0).part_id,
                Some((entry.seq, sha, entry.writer_epoch))
            )
            .unwrap());
        drop(history); // Crash before snapshot/COMMIT.
        let recovered = PagedHistory::open(&path, false, 4 * 1024 * 1024).unwrap();
        assert_eq!(recovered.load_snapshot(100).unwrap().unwrap(), b"prefix1");
        assert!(recovered
            .known(
                &part_ref(1, Level::L0).part_id,
                Some((1, &chain.entries[1].1, 1))
            )
            .unwrap());
        assert!(!recovered
            .known(
                &part_ref(2, Level::L0).part_id,
                Some((1, &chain.entries[1].1, 1))
            )
            .unwrap());
        recovered.apply(entry, sha).unwrap();
        recovered.save_snapshot(b"prefix2", Some((entry.seq, sha, entry.writer_epoch))).unwrap();
        drop(recovered);
        let committed = PagedHistory::open(&path, false, 4 * 1024 * 1024).unwrap();
        assert_eq!(committed.load_snapshot(100).unwrap().unwrap(), b"prefix2");
        assert!(committed
            .known(
                &part_ref(2, Level::L0).part_id,
                Some((entry.seq, sha, entry.writer_epoch))
            )
            .unwrap());
    }
}

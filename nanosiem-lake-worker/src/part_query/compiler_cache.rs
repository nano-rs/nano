// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-engine compiler output reuse. Discovery, authorization, host evidence and
//! execution remain outside this cache; only the exact compiler exchange is kept.
use super::{CompiledQuery, CompilerRequest, QueryResult, internal};
use std::{
    collections::VecDeque,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 128;
const MAX_DOCUMENT: u64 = 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
struct FileIdentity {
    path: PathBuf,
    resolved: PathBuf,
    device: u64,
    inode: u64,
    bytes: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileIdentity {
    fn read(path: &Path, now: i64) -> Option<Self> {
        // A compiler replaced by a FIFO/device must not block an async worker
        // while observing its identity. Such inputs never qualify for reuse.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .ok()?;
        let m = file.metadata().ok()?;
        // A coarse-timestamp filesystem cannot distinguish two writes in the
        // same tick. Fresh or future observations bypass reuse, never authority.
        if !m.is_file() || now.saturating_sub(m.mtime()) <= 2 || now.saturating_sub(m.ctime()) <= 2
        {
            return None;
        }
        let current = std::fs::metadata(path).ok()?;
        if (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ) != (
            current.dev(),
            current.ino(),
            current.len(),
            current.mtime(),
            current.mtime_nsec(),
            current.ctime(),
            current.ctime_nsec(),
        ) {
            return None;
        }
        Some(Self {
            path: path.to_owned(),
            resolved: path.canonicalize().ok()?,
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            mode: m.mode(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        })
    }

    fn bytes(&self) -> usize {
        128 + self.path.capacity() + self.resolved.capacity()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Identity {
    files: Vec<FileIdentity>,
    document: Vec<u8>,
}

impl Identity {
    fn read(compiler: &Path) -> Option<Self> {
        let now =
            i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
        let launch = nanosiem_lake_cell::worker_launch::compiler_launch_path(compiler).ok()?;
        Self::observe(
            compiler,
            launch,
            Path::new("/cell/release/metadata/worker-launch-v1.json"),
            now,
        )
    }

    fn observe(compiler: &Path, launch: &Path, metadata: &Path, now: i64) -> Option<Self> {
        let mut files = vec![FileIdentity::read(compiler, now)?];
        let mut document = Vec::new();
        if launch != compiler {
            // A native launch also depends on its closed loader/library package.
            // A compiler-only stat would miss replacement of one of those files.
            let stamp = FileIdentity::read(metadata, now)?;
            if stamp.bytes == 0 || stamp.bytes > MAX_DOCUMENT {
                return None;
            }
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(metadata)
                .ok()?
                .take(MAX_DOCUMENT + 1)
                .read_to_end(&mut document)
                .ok()?;
            if document.len() as u64 != stamp.bytes || FileIdentity::read(metadata, now)? != stamp {
                return None;
            }
            let parsed: nanosiem_lake_cell::worker_launch::WorkerLaunchDocument =
                serde_json::from_slice(&document).ok()?;
            if parsed.files.is_empty() || parsed.files.len() > 1024 {
                return None;
            }
            files.push(stamp);
            files.push(FileIdentity::read(launch, now)?);
            let root = compiler.parent()?.parent()?;
            for path in parsed
                .files
                .keys()
                .filter(|p| Path::new(p).starts_with(root))
            {
                // The launcher rejects symlinks in its native package. Reuse
                // must not turn a later symlink replacement into a cache hit.
                if std::fs::symlink_metadata(path)
                    .ok()?
                    .file_type()
                    .is_symlink()
                {
                    return None;
                }
                files.push(FileIdentity::read(Path::new(path), now)?);
            }
        }
        Some(Self { files, document })
    }

    fn bytes(&self) -> usize {
        self.document.capacity()
            + self.files.capacity() * std::mem::size_of::<FileIdentity>()
            + self.files.iter().map(FileIdentity::bytes).sum::<usize>()
    }
}

struct Entry {
    identity: Identity,
    input: Vec<u8>,
    output: Arc<Vec<u8>>,
}

impl Entry {
    fn bytes(&self) -> usize {
        256 + self.identity.bytes() + self.input.capacity() + self.output.capacity()
    }
}

#[derive(Default)]
pub(super) struct Cache {
    entries: Mutex<VecDeque<Entry>>,
}

impl Cache {
    pub(super) async fn compile(
        &self,
        path: &Path,
        request: &CompilerRequest<'_>,
        timeout: u64,
    ) -> QueryResult<CompiledQuery> {
        let input = serde_json::to_vec(request).map_err(internal)?;
        let identity = Identity::read(path);
        let hit = identity.as_ref().and_then(|identity| {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let index = entries
                .iter()
                .position(|e| e.identity == *identity && e.input == input)?;
            let entry = entries.remove(index)?;
            let output = entry.output.clone();
            entries.push_back(entry);
            Some(output)
        });
        if let Some(output) = hit {
            if Identity::read(path) == identity {
                return serde_json::from_slice(&output).map_err(internal);
            }
        }
        // No lock across a process spawn/await. Concurrent cold misses may do
        // duplicate work under the existing request admission bound; failures
        // and cancellations never create a resident entry or block other keys.
        let output = super::run_compiler_output(path, &input, timeout).await?;
        let compiled: CompiledQuery = serde_json::from_slice(&output)
            .map_err(|error| internal(format!("compiler output failed: {error}")))?;
        if compiled.dataset != request.dataset
            || compiled.limit != request.limit
            || compiled.table_view != request.table_view
        {
            return Err(internal("compiler substituted a request binding"));
        }
        if let Some(identity) =
            identity.filter(|before| Identity::read(path).as_ref() == Some(before))
        {
            let entry = Entry {
                identity,
                input,
                output: Arc::new(output),
            };
            let bytes = entry.bytes();
            if bytes <= MAX_BYTES {
                let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
                entries.retain(|old| old.identity == entry.identity && old.input != entry.input);
                let mut resident = entries.iter().map(Entry::bytes).sum::<usize>();
                while entries.len() >= MAX_ENTRIES || resident.saturating_add(bytes) > MAX_BYTES {
                    let Some(old) = entries.pop_front() else {
                        break;
                    };
                    resident = resident.saturating_sub(old.bytes());
                }
                entries.push_back(entry);
            }
        }
        Ok(compiled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn request() -> CompilerRequest<'static> {
        CompilerRequest {
            stats_page: false,
            stats_page_offset: 0,
            query: "* | head 1",
            dataset: "logs",
            start: "2026-10-01T00:00:00Z",
            end: "2026-10-02T00:00:00Z",
            limit: 2,
            table_view: false,
            event_contract: "ocsf-1.9",
            snapshot_field_types: Default::default(),
            lowercased_fields: vec![],
        }
    }

    fn compiler(path: &Path, calls: &Path, valid: bool) {
        let output = if valid {
            r#"{"schema_version":1,"profile":"ocsf","dataset":"logs","source_placeholder":"__nano_lake_source__","query_sha256":"query","start":"2026-10-01T00:00:00Z","end":"2026-10-02T00:00:00Z","limit":2,"table_view":false,"required_columns":[],"sql":"SELECT 1"}"#
        } else {
            "invalid compiler output"
        };
        std::fs::write(
            path,
            format!(
                "#!/bin/sh\nprintf x >> '{}'\ncat >/dev/null\nprintf '%s' '{}'\n",
                calls.display(),
                output
            ),
        )
        .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[tokio::test]
    async fn exact_inputs_reuse_only_successful_output_and_replacement_invalidates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compiler");
        let calls = dir.path().join("calls");
        compiler(&path, &calls, true);
        // Let mtime AND ctime leave the conservative coarse-filesystem window.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let cache = Cache::default();
        let base = request();
        cache.compile(&path, &base, 5).await.unwrap();
        cache.compile(&path, &base, 5).await.unwrap();
        assert_eq!(std::fs::read(&calls).unwrap().len(), 1);
        let variants: [fn(&mut CompilerRequest<'static>); 8] = [
            |r| r.query = "class_uid=1007 | head 1",
            |r| r.start = "2026-09-30T00:00:00Z",
            |r| r.end = "2026-10-03T00:00:00Z",
            |r| r.stats_page = true,
            |r| r.stats_page_offset = 1,
            |r| r.event_contract = "another-contract",
            |r| {
                r.snapshot_field_types
                    .insert("class_uid".into(), "long".into());
            },
            |r| r.lowercased_fields.push("device.hostname".into()),
        ];
        for (i, mutate) in variants.iter().enumerate() {
            let mut changed = base.clone();
            mutate(&mut changed);
            cache.compile(&path, &changed, 5).await.unwrap();
            cache.compile(&path, &changed, 5).await.unwrap();
            assert_eq!(std::fs::read(&calls).unwrap().len(), i + 2);
        }
        for mutate in [
            |r: &mut CompilerRequest<'static>| r.limit = 3,
            |r: &mut CompilerRequest<'static>| r.table_view = true,
            |r: &mut CompilerRequest<'static>| r.dataset = "risk",
        ] {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert!(
                cache.compile(&path, &changed, 5).await.is_err(),
                "a cached binding must not satisfy different inputs"
            );
        }
        let oversized = "x".repeat(MAX_BYTES);
        let huge = CompilerRequest {
            query: &oversized,
            ..base.clone()
        };
        let entries_before = cache.entries.lock().unwrap().len();
        let calls_before = std::fs::read(&calls).unwrap().len();
        cache.compile(&path, &huge, 5).await.unwrap();
        cache.compile(&path, &huge, 5).await.unwrap();
        assert_eq!(
            cache.entries.lock().unwrap().len(),
            entries_before,
            "oversized exchanges bypass retention"
        );
        assert_eq!(std::fs::read(&calls).unwrap().len(), calls_before + 2);
        for i in 0..MAX_ENTRIES + 2 {
            let query = format!("distinct-query-{i}");
            let different = CompilerRequest {
                query: &query,
                ..base.clone()
            };
            cache.compile(&path, &different, 5).await.unwrap();
        }
        {
            let entries = cache.entries.lock().unwrap();
            assert_eq!(entries.len(), MAX_ENTRIES);
            assert!(entries.iter().map(Entry::bytes).sum::<usize>() <= MAX_BYTES);
        }
        // Exercise byte-driven eviction with individually cacheable exchanges,
        // separately from the entry-count cap and oversized-entry bypass.
        for i in 0..16 {
            let query = format!("{i}-{}", "x".repeat(MAX_BYTES / 8));
            let different = CompilerRequest {
                query: &query,
                ..base.clone()
            };
            cache.compile(&path, &different, 5).await.unwrap();
        }
        {
            let entries = cache.entries.lock().unwrap();
            assert!(entries.len() > 1 && entries.len() < MAX_ENTRIES);
            let resident = entries.iter().map(Entry::bytes).sum::<usize>();
            assert!(resident > MAX_BYTES / 2 && resident <= MAX_BYTES);
        }
        let before = std::fs::read(&calls).unwrap().len();
        let replacement = dir.path().join("replacement");
        compiler(&replacement, &calls, false);
        std::fs::rename(&replacement, &path).unwrap();
        assert!(cache.compile(&path, &base, 5).await.is_err());
        assert!(cache.compile(&path, &base, 5).await.is_err());
        assert_eq!(
            std::fs::read(&calls).unwrap().len(),
            before + 2,
            "replacement/error output must never reuse or populate a success"
        );
        std::fs::remove_file(&path).unwrap();
        assert!(cache.compile(&path, &base, 5).await.is_err());
        // Separate engine/tenant ownership does not inherit this engine's memo.
        let fresh = Cache::default();
        assert!(fresh.entries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn production_engine_partitions_tenants_and_reapplies_source_policy() {
        use super::super::{BroadNplRequest, EngineSettings, PartQueryEngine};
        use crate::part_query::{
            fetch::{PartFetcher, StoreObjectSource, parts_key_prefix},
            log_view::PartLogView,
        };
        use crate::parts::part_log::LocalObjectStore;
        use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};

        async fn engine(root: &Path, tenant: &str, compiler: &Path) -> PartQueryEngine {
            let store = Arc::new(LocalObjectStore::new(root.join("objects")).unwrap());
            let keys = crate::part_query::log_view::tests::trusted();
            let view = PartLogView::open(store.as_ref(), tenant, keys.clone())
                .await
                .unwrap();
            let source = Arc::new(StoreObjectSource::local(
                "test",
                store.clone(),
                root.join("objects"),
            ));
            let cache = ReaderObjectCache::open(
                ReaderObjectCacheSettings {
                    root: root.join("cache"),
                    max_bytes: 1 << 20,
                    query_max_bytes: 1 << 20,
                    fetch_concurrency: 1,
                    fetch_deadline: std::time::Duration::from_secs(5),
                },
                tenant,
                "test",
                &parts_key_prefix(tenant).unwrap(),
                source,
            )
            .unwrap();
            let fetcher = PartFetcher::new(tenant, "test", store.clone(), keys, cache).unwrap();
            // Only statement execution is fake; compilation uses the production
            // constructor, policy processing, tenant guard and subprocess cache.
            let (executor, _lanes) =
                crate::executor::NativeExecutor::test_lanes(1, std::time::Duration::from_millis(1));
            PartQueryEngine::new(
                EngineSettings {
                    tenant_id: tenant.into(),
                    bucket: "test".into(),
                    compiler: compiler.into(),
                    max_query_bytes: 1 << 20,
                    max_memory_bytes: 1 << 20,
                    max_execution_seconds: 5,
                    threads: 1,
                },
                store,
                view,
                fetcher,
                executor,
            )
            .unwrap()
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compiler");
        let calls = dir.path().join("calls");
        compiler(&path, &calls, true);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let tenant_a = "00000000-0000-0000-0000-000000000001";
        let tenant_b = "00000000-0000-0000-0000-000000000002";
        let a = engine(&dir.path().join("a"), tenant_a, &path).await;
        let b = engine(&dir.path().join("b"), tenant_b, &path).await;
        let mut request: BroadNplRequest = serde_json::from_value(serde_json::json!({
            "request_id": "test", "tenant_id": tenant_a, "dataset": "logs", "query": "* | head 1",
            "start": "2026-10-01T00:00:00Z", "end": "2026-10-02T00:00:00Z", "limit": 1, "table_view": false
        })).unwrap();
        for _ in 0..2 {
            a.compile(&request, Default::default()).await.unwrap();
        }
        assert_eq!(std::fs::read(&calls).unwrap().len(), 1);
        // Both a warm hit and a cold miss for another tenant are refused before
        // any compiler call or evidence lookup. Stats compilation uses the guard too.
        request.tenant_id = tenant_b.into();
        assert!(a.compile(&request, Default::default()).await.is_err());
        request.query = "different query".into();
        assert!(
            a.compile_with_stats_page(&request, Default::default(), true)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&calls).unwrap().len(), 1);
        request.query = "* | head 1".into();
        for _ in 0..2 {
            b.compile(&request, Default::default()).await.unwrap();
        }
        assert_eq!(
            std::fs::read(&calls).unwrap().len(),
            2,
            "tenant B must compile independently"
        );

        request.tenant_id = tenant_a.into();
        request.deny_source_types.insert("private_source".into());
        for _ in 0..2 {
            a.compile(&request, Default::default()).await.unwrap();
        }
        assert_eq!(
            std::fs::read(&calls).unwrap().len(),
            3,
            "changed source policy must miss"
        );
        let entries = a.compilations.entries.lock().unwrap();
        let input: serde_json::Value =
            serde_json::from_slice(&entries.back().unwrap().input).unwrap();
        assert!(input["query"].as_str().unwrap().contains("private_source"));
        drop(entries);
        request.deny_source_types.clear();
        a.compile(&request, Default::default()).await.unwrap();
        assert_eq!(
            std::fs::read(&calls).unwrap().len(),
            3,
            "unscoped plan remains a separate entry"
        );
    }

    #[test]
    fn bundled_library_manifest_and_symlink_changes_invalidate_identity() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("compiler");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::create_dir_all(root.join("lib")).unwrap();
        let worker = root.join("bin/worker");
        let launch = root.join("bin/launch");
        let library = root.join("lib/runtime.so");
        let metadata = dir.path().join("manifest.json");
        for path in [&worker, &launch, &library] {
            std::fs::write(path, b"original").unwrap();
        }
        let document = nanosiem_lake_cell::worker_launch::WorkerLaunchDocument {
            schema_version: 1,
            compiler_linkage: Default::default(),
            package_sha256: "a".repeat(64),
            files: [&worker, &launch, &library]
                .into_iter()
                .map(|p| (p.display().to_string(), "b".repeat(64)))
                .collect(),
        };
        let raw = serde_json::to_vec(&document).unwrap();
        std::fs::write(&metadata, &raw).unwrap();
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
            + 10;
        let original = Identity::observe(&worker, &launch, &metadata, now).unwrap();
        std::fs::write(&library, b"changed library").unwrap();
        assert!(Identity::observe(&worker, &launch, &metadata, now).unwrap() != original);
        std::fs::write(&metadata, b"invalid manifest").unwrap();
        assert!(Identity::observe(&worker, &launch, &metadata, now).is_none());
        std::fs::write(&metadata, &raw).unwrap();
        let moved = root.join("lib/moved.so");
        std::fs::rename(&library, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &library).unwrap();
        assert!(Identity::observe(&worker, &launch, &metadata, now).is_none());
    }

    #[test]
    fn non_regular_compiler_never_blocks_identity_lookup() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compiler-fifo");
        let raw = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
        assert!(FileIdentity::read(&path, i64::MAX).is_none());
    }

    #[test]
    fn file_guard_changes_for_in_place_writes_and_inode_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compiler");
        std::fs::write(&path, "first").unwrap();
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
            + 10;
        let first = FileIdentity::read(&path, now).unwrap();
        std::fs::write(&path, "other bytes").unwrap();
        assert!(FileIdentity::read(&path, now).unwrap() != first);
        let other = dir.path().join("new");
        std::fs::write(&other, "first").unwrap();
        std::fs::rename(&other, &path).unwrap();
        assert!(FileIdentity::read(&path, now).unwrap() != first);
        assert!(
            FileIdentity::read(&path, now - 10).is_none(),
            "fresh observations cannot grant reuse"
        );
    }
}

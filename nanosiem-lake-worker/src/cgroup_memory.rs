// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process resource hierarchy discovery, shared by merge guards and query sizing.
use std::path::{Path, PathBuf};
use nanosiem_lake_cell::resources::relative_path;
use std::sync::{Arc, Once, OnceLock};

const ROOT: &str = "/sys/fs/cgroup";
static ROLE: OnceLock<PathBuf> = OnceLock::new();
static CONTAINER: OnceLock<MemoryCgroup> = OnceLock::new();

/// Preserve only read-only resource metric descriptors before a watchdog-only
/// child's jail. Docker has no assigned role leaf, and Landlock deliberately
/// grants no cgroup path in that mode. Never retain a directory descriptor or
/// use this fallback for a hosted role with its own cgroup.
pub fn prepare(role: Option<&Path>) {
    if role.is_none() {
        let mut cgroup = discover();
        cgroup.pin_memory_files();
        let _ = CONTAINER.set(cgroup);
    }
}

/// Install the supervisor's trusted jail path after bootstrap, before threads.
/// CLONE_NEWCGROUP makes membership `/` without remounting cgroupfs. Landlock
/// grants this original leaf, not the mount root. Keep its path, not its limit:
/// the supervisor can resize memory.max while the process is running.
pub fn initialize(role: Option<&Path>) {
    if let Some(role) = role {
        if let Some(relative) = relative_path(role) {
            let _ = ROLE.set(Path::new(ROOT).join(relative));
        }
    }
    static LOGGED: Once = Once::new();
    LOGGED.call_once(|| {
        let cgroup = for_process();
        let limit = cgroup.limit();
        tracing::info!(
            cgroup_memory_max = ?limit.as_ref().map(|limit| limit.bytes),
            cgroup_memory_source = ?limit.as_ref().map(|limit| &limit.path),
            cgroup_memory_dir = %cgroup.dir.display(),
            "process cgroup memory boundary"
        );
    });
}

#[derive(Debug, Clone)]
pub(crate) struct MemoryCgroup {
    pub dir: PathBuf,
    root: PathBuf,
    pub v1: bool,
    files: Option<Arc<std::collections::BTreeMap<PathBuf, std::fs::File>>>,
}

#[derive(Debug)]
pub(crate) struct MemoryLimit {
    pub bytes: u64,
    pub path: PathBuf,
}

impl MemoryCgroup {
    fn pin_memory_files(&mut self) {
        let names: &[&str] = if self.v1 {
            &[
                "memory.limit_in_bytes",
                "memory.usage_in_bytes",
                "memory.stat",
            ]
        } else {
            &["memory.max", "memory.current", "memory.stat", "cpu.max", "cpu.stat"]
        };
        let mut files = std::collections::BTreeMap::new();
        for dir in self
            .dir
            .ancestors()
            .take_while(|dir| dir.starts_with(&self.root))
        {
            for name in names {
                let path = dir.join(name);
                if let Ok(file) = std::fs::File::open(&path) {
                    files.insert(path, file);
                }
            }
        }
        self.files = Some(Arc::new(files));
    }

    pub fn read(&self, path: &Path) -> Option<String> {
        if let Some(files) = &self.files {
            use std::os::unix::fs::FileExt;
            let file = files.get(path)?;
            // Positional reads preserve a fresh view without sharing offsets
            // between concurrent probes. memory.stat fits well below 64 KiB.
            let mut buffer = vec![0; 64 * 1024];
            let length = file.read_at(&mut buffer, 0).ok()?;
            buffer.truncate(length);
            return String::from_utf8(buffer).ok();
        }
        std::fs::read_to_string(path).ok()
    }

    /// v2 CPU follows the same namespace, ancestor and jail rules as memory.
    /// v1's separate CPU hierarchy is not granted by the jail; use the trusted
    /// assignment there instead of probing a different controller mount.
    fn cpu_millis(&self) -> Option<u32> {
        if self.v1 { return None; }
        self.dir.ancestors().take_while(|dir| dir.starts_with(&self.root))
            .filter_map(|dir| self.read(&dir.join("cpu.max")))
            .filter_map(|value| nanosiem_lake_cell::resources::parse_cpu_max(&value))
            .min()
    }

    pub(crate) fn role_cpu_millis(&self, assigned: u32) -> u32 {
        effective_cpu_millis(assigned, self.cpu_millis())
    }

    pub fn cpu_samples(&self) -> Vec<(String, Option<String>)> {
        self.dir.ancestors().take(2).filter(|dir| dir.starts_with(&self.root))
            .filter_map(|dir| Some((self.read(&dir.join("cpu.stat"))?, self.read(&dir.join("cpu.max")))))
            .collect()
    }

    /// Read every visible ancestor: a finite parent can constrain even a
    /// numeric leaf. Unreadable ancestors stay hidden by the existing jail.
    pub fn limit(&self) -> Option<MemoryLimit> {
        let mut tightest: Option<MemoryLimit> = None;
        for dir in self
            .dir
            .ancestors()
            .take_while(|dir| dir.starts_with(&self.root))
        {
            let path = dir.join(if self.v1 {
                "memory.limit_in_bytes"
            } else {
                "memory.max"
            });
            let bytes = self
                .read(&path)
                .and_then(|value| value.trim().parse::<u64>().ok())
                // v1 represents unlimited with a page-aligned LONG_MAX.
                .filter(|bytes| *bytes > 0 && *bytes < (1_u64 << 60));
            if let Some(bytes) = bytes {
                if tightest.as_ref().is_none_or(|limit| bytes < limit.bytes) {
                    tightest = Some(MemoryLimit { bytes, path });
                }
            }
        }
        tightest
    }
}

fn effective_cpu_millis(assigned: u32, cgroup: Option<u32>) -> u32 {
    [Some(assigned), cgroup].into_iter().flatten().filter(|cpu| *cpu > 0).min()
        .unwrap_or_else(|| nanosiem_lake_cell::resources::detect_capacity(&Default::default(), None).cpu_millicores)
}

/// The role/container capacity, using the shared cell detector for host
/// fallbacks and this module's namespace-aware hierarchy for finite limits.
/// Read every call so a resized role takes effect without a new env knob.
pub fn process_capacity() -> nanosiem_lake_cell::resources::CellCapacity {
    capacity_for(&for_process(), nanosiem_lake_cell::resources::detect_capacity(
        &nanosiem_lake_cell::config::ResourceConfig::default(), None))
}

pub(crate) fn capacity_for(cg: &MemoryCgroup, mut capacity: nanosiem_lake_cell::resources::CellCapacity)
    -> nanosiem_lake_cell::resources::CellCapacity {
    if let Some(limit) = cg.limit() {
        capacity.memory_bytes = limit.bytes;
        capacity.memory_source = "cgroup";
    }
    if let Some(cpu) = cg.cpu_millis() {
        capacity.cpu_millicores = capacity.cpu_millicores.min(cpu);
        capacity.cpu_source = "cgroup";
    }
    capacity
}

pub(crate) fn for_process() -> MemoryCgroup {
    // Avoid reading mountinfo on the frequent merge probe when the assignment
    // already supplies the exact path allowed by Landlock.
    if let Some(dir) = ROLE.get() {
        return MemoryCgroup {
            dir: dir.clone(),
            root: ROOT.into(),
            v1: false,
            files: None,
        };
    }
    if let Some(cgroup) = CONTAINER.get() {
        return cgroup.clone();
    }
    discover()
}

fn discover() -> MemoryCgroup {
    resolve(
        Path::new(ROOT),
        &std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default(),
        &std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default(),
        None,
    )
}

/// Same resolver for real procfs/cgroupfs and filesystem fixtures. `role` is
/// the original mount-relative JailSpec::cgroup_dir, never a tenant input.
pub(crate) fn resolve(root: &Path, membership: &str, mountinfo: &str, role: Option<&Path>) -> MemoryCgroup {
    let location = nanosiem_lake_cell::resources::resolve_cgroup(root, membership, mountinfo, role);
    MemoryCgroup { dir: location.dir, root: location.root, v1: location.v1, files: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nan4825_role_cpu_uses_visible_ancestors_and_live_resizes() {
        let root = tempfile::tempdir().unwrap();
        let role = Path::new("tenant/query");
        let leaf = root.path().join(role);
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(root.path().join("cpu.max"), "1600000 100000").unwrap();
        std::fs::write(leaf.join("cpu.max"), "max 100000").unwrap();
        std::fs::write(leaf.join("cpu.stat"), "usage_usec 100\n").unwrap();
        let mut cg = resolve(root.path(), "0::/", "", Some(role));
        cg.pin_memory_files();
        assert_eq!(cg.cpu_millis(), Some(16_000));
        assert_eq!(effective_cpu_millis(32_000, cg.cpu_millis()), 16_000);
        assert_eq!(effective_cpu_millis(4_000, cg.cpu_millis()), 4_000);
        let host = nanosiem_lake_cell::resources::CellCapacity {
            memory_bytes: 64 * 1024 * 1024 * 1024, cpu_millicores: 32_000,
            memory_source: "host", cpu_source: "host",
        };
        assert_eq!(capacity_for(&cg, host.clone()).cpu_millicores, cg.role_cpu_millis(32_000));
        assert_eq!(capacity_for(&cg, nanosiem_lake_cell::resources::CellCapacity {
            cpu_millicores: 4_000, ..host.clone()
        }).cpu_millicores, cg.role_cpu_millis(4_000));
        assert_eq!(cg.cpu_samples(), vec![("usage_usec 100\n".into(), Some("max 100000".into()))]);
        std::fs::write(leaf.join("cpu.max"), "350000 100000").unwrap();
        assert_eq!(effective_cpu_millis(32_000, cg.cpu_millis()), 3_500);
        assert_eq!(effective_cpu_millis(0, cg.cpu_millis()), 3_500);
        assert_eq!(capacity_for(&cg, host).cpu_millicores, cg.role_cpu_millis(32_000));
        assert_eq!(cg.cpu_samples(), vec![("usage_usec 100\n".into(), Some("350000 100000".into()))]);
        assert_eq!(effective_cpu_millis(32_000, None), 32_000);
        let from_shared_model = nanosiem_lake_cell::resources::detect_capacity(
            &Default::default(), Some(&leaf));
        assert_eq!(cg.cpu_millis(), Some(from_shared_model.cpu_millicores));
    }

    #[test]
    fn nan4827_role_and_parent_limits_drive_runtime_sizing_after_resizes() {
        use nanosiem_lake_cell::budget::{GIB, MIB};
        assert_eq!(crate::landing::bucket_drop_limits(GIB, 8000).0, 4);
        let lanes = crate::landing::bucket_drop_limits(2268 * MIB, 64000).0;
        assert_eq!(lanes, 8);
        let (request, burst) = nanosiem_lake_cell::trusted_local::landing_cpu_budget(64000);
        assert!(lanes as u32 * 1000 >= request && burst >= request);
        assert_eq!(nanosiem_lake_cell::budget::query_threads(64000), 64);
        for (memory, cpu) in [(2 * GIB, 4000), (3413114880, 4000), (8 * GIB, 8000), (32 * GIB, 16000), (64 * GIB, 32000), (64 * GIB, 64000)] {
            let root = tempfile::tempdir().unwrap();
            let leaf = root.path().join("tenant/landing");
            std::fs::create_dir_all(&leaf).unwrap();
            std::fs::write(leaf.join("memory.max"), memory.to_string()).unwrap();
            std::fs::write(leaf.join("cpu.max"), format!("{} 100000", cpu * 100)).unwrap();
            let cg = resolve(root.path(), "0::/tenant/landing", "", None);
            let host = nanosiem_lake_cell::resources::CellCapacity { memory_bytes: 128 * GIB, cpu_millicores: 64000,
                memory_source: "host", cpu_source: "host" };
            let capacity = capacity_for(&cg, host.clone());
            assert_eq!((capacity.memory_bytes, capacity.cpu_millicores), (memory, cpu));
            let (lanes, bytes) = crate::landing::landing_limits(capacity.memory_bytes, capacity.cpu_millicores);
            assert_eq!(lanes, (cpu / 1000) as usize);
            let (bucket_lanes, _) = crate::landing::bucket_drop_limits(capacity.memory_bytes, capacity.cpu_millicores);
            assert_eq!(bucket_lanes, lanes);
            // Dedicated query borrowing grows beyond the old eight-thread cap.
            // Agent lanes still yield to analysts through the production pool.
            let budget = crate::part_query::memory_budget::QueryMemoryBudget::derive_for_role(memory, None, cpu);
            let (threads, _) = crate::part_query::server::role_statement_limits(&budget, None);
            assert_eq!(threads, budget.threads as u64);
            assert!(threads <= u64::from(cpu / 1000));
            let pool = crate::thread_budget::ThreadBudget::new(threads);
            let analyst = pool.grant(crate::thread_budget::Priority::Interactive);
            let agent = pool.grant(crate::thread_budget::Priority::Agent);
            assert_eq!(analyst.threads(), threads);
            assert_eq!(agent.threads(), 1);
            if cpu >= 8000 { assert!(analyst.threads() > agent.threads()); }

            if memory <= 3413114880 { assert!(bytes <= 256 * MIB); }
            else { assert!(bytes > 256 * MIB); }
            let (query, fetches) = crate::reader_object_cache::resource_limits(memory, cpu, 16 * GIB);
            assert!(query <= memory / 4 && fetches <= (memory / (64 * MIB)) as usize);
            let result = crate::part_query::memory_budget::QueryMemoryBudget::rust_paged_result_bytes(memory, 30);
            assert!(result * 30 * 12 <= memory / 2);
            // A tighter parent wins over the numeric role leaf.
            std::fs::write(root.path().join("tenant/memory.max"), (memory / 2).to_string()).unwrap();
            std::fs::write(root.path().join("tenant/cpu.max"), "50000 100000").unwrap();
            let shrunk = capacity_for(&cg, host);
            assert_eq!((shrunk.memory_bytes, shrunk.cpu_millicores), (memory / 2, 500));
            assert_eq!(crate::landing::landing_limits(shrunk.memory_bytes, shrunk.cpu_millicores).0, 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nan4810_preopened_docker_metrics_survive_landlock_without_path_access() {
        const CHILD: &str = "NAN4810_LANDLOCK_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cgroup_memory::tests::nan4810_preopened_docker_metrics_survive_landlock_without_path_access", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let groups: Vec<_> = [false, true]
            .into_iter()
            .map(|v1| {
                let hierarchy = root.path().join(if v1 { "v1/memory" } else { "v2" });
                let leaf = hierarchy.join("docker/container");
                std::fs::create_dir_all(&leaf).unwrap();
                let (limit, current) = if v1 {
                    ("memory.limit_in_bytes", "memory.usage_in_bytes")
                } else {
                    ("memory.max", "memory.current")
                };
                std::fs::write(leaf.join(limit), "2090000000\n").unwrap();
                std::fs::write(leaf.join(current), "600000000\n").unwrap();
                std::fs::write(leaf.join("memory.stat"), "file 1234\n").unwrap();
                if !v1 {
                    std::fs::write(leaf.join("cpu.max"), "1600000 100000\n").unwrap();
                    std::fs::write(leaf.join("cpu.stat"), "usage_usec 100\n").unwrap();
                }
                let membership = if v1 {
                    "7:memory:/docker/container\n"
                } else {
                    "0::/docker/container\n"
                };
                let mut cg = resolve(
                    &root.path().join(if v1 { "v1" } else { "v2" }),
                    membership,
                    "",
                    None,
                );
                cg.pin_memory_files();
                (cg, leaf.join(limit), leaf.join(current))
            })
            .collect();
        // Reproduce the cgroup ReadFile denial imposed by the real jail.
        // Restrict only this subprocess; retain no path or directory grant.
        let access_read_file: u64 = 1 << 2;
        let ruleset = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &access_read_file,
                std::mem::size_of::<u64>(),
                0,
            )
        };
        assert!(
            ruleset >= 0,
            "Landlock required: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0) },
            0
        );
        unsafe {
            libc::close(ruleset as i32);
        }
        for (cg, limit, current) in groups {
            assert_eq!(
                std::fs::read_to_string(&limit).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(cg.limit().unwrap().bytes, 2_090_000_000);
            assert_eq!(cg.limit().unwrap().path, limit);
            assert_eq!(cg.read(&current).as_deref(), Some("600000000\n"));
            assert_eq!(
                cg.read(&cg.dir.join("memory.stat")).as_deref(),
                Some("file 1234\n")
            );
            if !cg.v1 {
                let host = nanosiem_lake_cell::resources::CellCapacity {
                    cpu_millicores: 16000, memory_bytes: 4 * 1024 * 1024 * 1024,
                    cpu_source: "host", memory_source: "host",
                };
                assert_eq!(capacity_for(&cg, host.clone()).cpu_millicores, 16000);
                assert_eq!(cg.cpu_samples(), vec![("usage_usec 100\n".into(), Some("1600000 100000\n".into()))]);
                std::fs::write(cg.dir.join("cpu.max"), "800000 100000\n").unwrap();
                assert_eq!(capacity_for(&cg, host).cpu_millicores, 8000);
            }
            // A kernel resize remains visible through the read-only descriptor.
            std::fs::write(&limit, "1900000000\n").unwrap();
            assert_eq!(cg.limit().unwrap().bytes, 1_900_000_000);
            assert_eq!(
                std::fs::read_to_string(&limit).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            use std::os::unix::fs::FileExt;
            assert!(cg.files.as_ref().unwrap()[&limit]
                .write_at(b"1", 0)
                .is_err());
        }
    }

    #[test]
    fn nan4810_namespaced_role_uses_the_jail_leaf_and_rereads_resizes() {
        let root = tempfile::tempdir().unwrap();
        let role = Path::new("tenants/s7/ingest");
        let leaf = root.path().join(role);
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(root.path().join("memory.max"), "16000000000").unwrap();
        std::fs::write(leaf.join("memory.max"), "3413114880").unwrap();
        let cg = resolve(root.path(), "0::/\n", "", Some(role));
        let limit = cg.limit().unwrap();
        assert_eq!(limit.bytes, 3_413_114_880);
        assert_eq!(limit.path, leaf.join("memory.max"));
        assert_eq!(cg.dir, leaf);
        std::fs::write(limit.path, "3200000000").unwrap();
        assert_eq!(cg.limit().unwrap().bytes, 3_200_000_000);
    }

    #[test]
    fn nan4810_v1_and_v2_inherit_limits_and_skip_unlimited_nodes() {
        for v1 in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let hierarchy = if v1 {
                root.path().join("memory")
            } else {
                root.path().into()
            };
            let parent = hierarchy.join("tenant");
            let leaf = parent.join("ingest");
            std::fs::create_dir_all(&leaf).unwrap();
            let file = if v1 {
                "memory.limit_in_bytes"
            } else {
                "memory.max"
            };
            let unlimited = if v1 { "9223372036854771712" } else { "max" };
            std::fs::write(leaf.join(file), unlimited).unwrap();
            std::fs::write(parent.join(file), "3413114880").unwrap();
            let membership = if v1 {
                "0::/unified\n7:cpu,memory:/tenant/ingest\n"
            } else {
                "0::/tenant/ingest\n"
            };
            let cg = resolve(root.path(), membership, "", None);
            assert_eq!(cg.limit().unwrap().path, parent.join(file));
            std::fs::write(leaf.join(file), "4000000000").unwrap();
            assert_eq!(cg.limit().unwrap().bytes, 3_413_114_880);
            std::fs::write(parent.join(file), unlimited).unwrap();
            assert_eq!(cg.limit().unwrap().bytes, 4_000_000_000);
            std::fs::write(leaf.join(file), unlimited).unwrap();
            assert!(cg.limit().is_none());
        }
    }

    #[test]
    fn nan4810_docker_mounts_with_and_without_cgroup_namespaces() {
        for v1 in [false, true] {
            for namespaced in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let mount = root.path().join("container cgroup");
                std::fs::create_dir_all(&mount).unwrap();
                let file = if v1 {
                    "memory.limit_in_bytes"
                } else {
                    "memory.max"
                };
                std::fs::write(mount.join(file), "2090000000").unwrap();
                let path = if namespaced { "/" } else { "/docker/container" };
                let membership = if v1 {
                    format!("7:memory:{path}\n")
                } else {
                    format!("0::{path}\n")
                };
                let fs = if v1 {
                    "cgroup cgroup rw,memory"
                } else {
                    "cgroup2 cgroup rw"
                };
                let mountinfo = format!(
                    "31 20 0:27 /docker/container {} rw - {fs}\n",
                    mount.display().to_string().replace(' ', "\\040")
                );
                let cg = resolve(root.path(), &membership, &mountinfo, None);
                assert_eq!(cg.dir, mount);
                assert_eq!(cg.limit().unwrap().bytes, 2_090_000_000);
            }
        }
    }
}

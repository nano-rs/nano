// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process memory hierarchy discovery, shared by merge guards and query sizing.
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Once, OnceLock};

const ROOT: &str = "/sys/fs/cgroup";
static ROLE: OnceLock<PathBuf> = OnceLock::new();
static CONTAINER: OnceLock<MemoryCgroup> = OnceLock::new();

/// Preserve only read-only memory metric descriptors before a watchdog-only
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
        let names = if self.v1 {
            [
                "memory.limit_in_bytes",
                "memory.usage_in_bytes",
                "memory.stat",
            ]
        } else {
            ["memory.max", "memory.current", "memory.stat"]
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
pub(crate) fn resolve(
    root: &Path,
    membership: &str,
    mountinfo: &str,
    role: Option<&Path>,
) -> MemoryCgroup {
    if let Some(relative) = role.and_then(relative_path) {
        return MemoryCgroup {
            dir: root.join(relative),
            root: root.into(),
            v1: false,
            files: None,
        };
    }
    let entries: Vec<_> = membership
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, ':');
            let (Some(id), Some(controllers), Some(path)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return None;
            };
            if controllers
                .split(',')
                .any(|controller| controller == "memory")
            {
                Some((path, true))
            } else if id == "0" && controllers.is_empty() {
                Some((path, false))
            } else {
                None
            }
        })
        .collect();
    // Hybrid hosts may have v2 present while memory still belongs to v1.
    let (membership, v1) = entries
        .iter()
        .find(|(_, v1)| *v1)
        .or_else(|| entries.first())
        .copied()
        .unwrap_or(("/", false));
    let fallback_root = if v1 { root.join("memory") } else { root.into() };
    let Some(relative) = relative_path(Path::new(membership)) else {
        return MemoryCgroup {
            dir: fallback_root.clone(),
            root: fallback_root,
            v1,
            files: None,
        };
    };
    let membership = Path::new("/").join(&relative);
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<_> = before.split_whitespace().collect();
        let fs: Vec<_> = after.split_whitespace().collect();
        if fields.len() < 5 || fs.len() < 3 {
            continue;
        }
        let matches = if v1 {
            fs[0] == "cgroup" && fs[2].split(',').any(|controller| controller == "memory")
        } else {
            fs[0] == "cgroup2"
        };
        if !matches {
            continue;
        }
        let mount_root = unescape(fields[3]);
        let mount = PathBuf::from(unescape(fields[4]));
        // A mount of a subtree exposes /docker/<id> directly at its mount
        // point. When membership is namespaced to `/`, the mount is our root.
        let inside = membership
            .strip_prefix(&mount_root)
            .ok()
            .or_else(|| (membership == Path::new("/")).then_some(Path::new("")));
        if let Some(inside) = inside {
            return MemoryCgroup {
                dir: mount.join(inside),
                root: mount,
                v1,
                files: None,
            };
        }
    }
    MemoryCgroup {
        dir: fallback_root.join(relative),
        root: fallback_root,
        v1,
        files: None,
    }
}

fn relative_path(path: &Path) -> Option<PathBuf> {
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => relative.push(name),
            Component::RootDir | Component::CurDir => {}
            _ => return None,
        }
    }
    Some(relative)
}

fn unescape(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

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

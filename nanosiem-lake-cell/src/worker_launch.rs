// SPDX-License-Identifier: AGPL-3.0-or-later
//! H02 static shim: immutable paths select a bundled loader or static compiler.
//! The trusted native installer writes this manifest from verified package
//! seals into the read-only root; it is not caller/runtime configuration.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::Command,
};
const METADATA: &str = "/cell/release/metadata/worker-launch-v1.json";
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LaunchError {
    #[error("native_worker_launch_denied")]
    Denied,
    #[error("native_worker_artifact_denied")]
    Artifact,
    #[error("native_worker_exec_failed")]
    Exec,
}
/// Authenticated producer metadata, never a caller-selected execution switch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompilerLinkage {
    #[default]
    BundledGnu,
    StaticMusl,
}
impl CompilerLinkage {
    pub fn is_bundled(&self) -> bool {
        *self == Self::BundledGnu
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLaunchDocument {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "CompilerLinkage::is_bundled")]
    pub compiler_linkage: CompilerLinkage,
    pub package_sha256: String,
    /// Exact absolute namespace paths and SHA-256s from the verified snapshot.
    pub files: BTreeMap<String, String>,
}
/// Only file observations/bytes are replaceable in tests; execution remains
/// private and accepts neither raw argv nor a caller-selected program.
pub trait WorkerFiles {
    fn read_metadata(&self) -> Result<Vec<u8>, LaunchError>;
    fn check_digest(&self, path: &Path, expected: &str) -> Result<(), LaunchError>;
}
#[derive(Debug)]
pub struct WorkerExec {
    loader: Option<PathBuf>,
    program: PathBuf,
    library: PathBuf,
    args: Vec<OsString>,
}
impl WorkerExec {
    pub fn loader(&self) -> Option<&Path> {
        self.loader.as_deref()
    }
    pub fn program(&self) -> &Path {
        &self.program
    }
    fn command(&self) -> Command {
        let mut c = Command::new(self.loader.as_ref().unwrap_or(&self.program));
        c.env_clear().current_dir("/");
        if self.loader.is_some() {
            c.arg("--inhibit-cache")
                .arg("--glibc-hwcaps-mask")
                .arg("")
                .arg("--library-path")
                .arg(&self.library)
                .arg(&self.program);
        }
        c.args(&self.args);
        c
    }
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
        && value != "0".repeat(64)
}
fn filename(path: &str, root: &str) -> bool {
    path.strip_prefix(&format!("{root}/lib/"))
        .is_some_and(|name| {
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
pub fn prepare_worker_exec(
    executable: &Path,
    args: &[OsString],
    files: &dyn WorkerFiles,
) -> Result<WorkerExec, LaunchError> {
    // Kernel-derived current_exe, never argv[0], selects one of three names.
    let kind = match executable.to_str() {
        Some("/cell/workers/ingest/bin/launch") => "ingest",
        Some("/cell/workers/query/bin/launch") => "query",
        Some("/cell/workers/compiler/bin/launch") => "compiler",
        _ => return Err(LaunchError::Denied),
    };
    if (kind == "compiler" && !args.is_empty())
        || (kind != "compiler"
            && args != [OsString::from("--cell-control-fd"), OsString::from("3")])
    {
        return Err(LaunchError::Denied);
    }
    let raw = files.read_metadata()?;
    if raw.is_empty() || raw.len() > 1024 * 1024 {
        return Err(LaunchError::Artifact);
    }
    let document: WorkerLaunchDocument =
        serde_json::from_slice(&raw).map_err(|_| LaunchError::Artifact)?;
    if !matches!(
        (document.schema_version, document.compiler_linkage),
        (1, CompilerLinkage::BundledGnu) | (2 | 3, CompilerLinkage::StaticMusl)
    ) || !digest(&document.package_sha256)
        || document.files.is_empty()
        || document.files.len() > 1024
    {
        return Err(LaunchError::Artifact);
    }
    // Validate every manifest path before asking the filesystem to open any.
    for (p, h) in &document.files {
        if !digest(h)
            || !["ingest", "query", "compiler"].iter().any(|name| {
                let root = format!("/cell/workers/{name}");
                p == &format!("{root}/bin/worker")
                    || p == &format!("{root}/bin/launch")
                    || filename(p, &root)
            })
        {
            return Err(LaunchError::Artifact);
        }
    }
    let static_compiler = document.compiler_linkage == CompilerLinkage::StaticMusl;
    if static_compiler
        && document
            .files
            .keys()
            .any(|p| p.starts_with("/cell/workers/compiler/lib/"))
    {
        return Err(LaunchError::Artifact);
    }
    let root = format!("/cell/workers/{kind}");
    let loader = (!(kind == "compiler" && static_compiler))
        .then(|| PathBuf::from(format!("{root}/lib/ld.so")));
    let program = PathBuf::from(format!("{root}/bin/worker"));
    for p in [loader.as_deref(), Some(program.as_path()), Some(executable)]
        .into_iter()
        .flatten()
    {
        if !document
            .files
            .contains_key(p.to_str().ok_or(LaunchError::Artifact)?)
        {
            return Err(LaunchError::Artifact);
        }
    }
    for (p, h) in document
        .files
        .iter()
        .filter(|(p, _)| p.starts_with(&format!("{root}/")))
    {
        files.check_digest(Path::new(p), h)?;
    }
    Ok(WorkerExec {
        loader,
        program,
        library: PathBuf::from(format!("{root}/lib")),
        args: args.to_vec(),
    })
}
struct NativeFiles;
fn opened(path: &Path) -> Result<File, LaunchError> {
    use std::{ffi::CString, os::fd::FromRawFd};
    if !path.is_absolute() {
        return Err(LaunchError::Artifact);
    }
    let mut parent = File::open("/").map_err(|_| LaunchError::Artifact)?;
    let parts = path.components().skip(1).collect::<Vec<_>>();
    for (i, part) in parts.iter().enumerate() {
        let std::path::Component::Normal(name) = part else {
            return Err(LaunchError::Artifact);
        };
        let name = CString::new(name.as_encoded_bytes()).map_err(|_| LaunchError::Artifact)?;
        let last = i + 1 == parts.len();
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | if last {
                        libc::O_NONBLOCK
                    } else {
                        libc::O_DIRECTORY
                    },
            )
        };
        if fd < 0 {
            return Err(LaunchError::Artifact);
        }
        let next = unsafe { File::from_raw_fd(fd) };
        let m = next.metadata().map_err(|_| LaunchError::Artifact)?;
        // Outside the service's mapped range, on the immutable root. A file
        // owned by the mapped service/tenant is never its own execution trust.
        if m.uid() != 65534
            || m.mode() & 0o022 != 0
            || last && (m.mode() & 0o222 != 0 || !m.is_file() || m.nlink() != 1)
        {
            return Err(LaunchError::Artifact);
        }
        parent = next;
    }
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(parent.as_raw_fd(), &mut stat) } != 0
        || stat.f_flag & libc::ST_RDONLY == 0
    {
        return Err(LaunchError::Artifact);
    }
    Ok(parent)
}
impl WorkerFiles for NativeFiles {
    fn read_metadata(&self) -> Result<Vec<u8>, LaunchError> {
        let mut b = vec![];
        opened(Path::new(METADATA))?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut b)
            .map_err(|_| LaunchError::Artifact)?;
        Ok(b)
    }
    fn check_digest(&self, path: &Path, expected: &str) -> Result<(), LaunchError> {
        let mut f = opened(path)?;
        let size = f.metadata().map_err(|_| LaunchError::Artifact)?.len();
        if size == 0 || size > 4 * 1024 * 1024 * 1024 {
            return Err(LaunchError::Artifact);
        }
        let mut h = Sha256::new();
        let mut b = [0; 65536];
        let mut total = 0u64;
        loop {
            let n = f.read(&mut b).map_err(|_| LaunchError::Artifact)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > size {
                return Err(LaunchError::Artifact);
            }
            h.update(&b[..n]);
        }
        if total != size || format!("{:x}", h.finalize()) != expected {
            return Err(LaunchError::Artifact);
        }
        Ok(())
    }
}
/// Keep the actual compiler program as the identity/cache pin; only execution is
/// redirected through the closed native shim. Hosted compiler paths retain
/// their existing behavior. A misspelled native path has no host fallback.
pub fn compiler_launch_path(compiler: &Path) -> Result<&Path, LaunchError> {
    if compiler == Path::new("/cell/workers/compiler/bin/worker") {
        Ok(Path::new("/cell/workers/compiler/bin/launch"))
    } else if compiler.starts_with("/cell") {
        Err(LaunchError::Denied)
    } else {
        Ok(compiler)
    }
}

pub fn run_worker_launcher() -> Result<(), LaunchError> {
    let executable = std::env::current_exe().map_err(|_| LaunchError::Denied)?;
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let plan = prepare_worker_exec(&executable, &args, &NativeFiles)?;
    let _error = plan.command().exec();
    Err(LaunchError::Exec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Files {
        document: WorkerLaunchDocument,
        checks: AtomicUsize,
        corrupt: bool,
    }
    impl WorkerFiles for Files {
        fn read_metadata(&self) -> Result<Vec<u8>, LaunchError> {
            Ok(serde_json::to_vec(&self.document).unwrap())
        }
        fn check_digest(&self, _: &Path, _: &str) -> Result<(), LaunchError> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            if self.corrupt {
                Err(LaunchError::Artifact)
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn compiler_execution_redirect_preserves_the_actual_identity_pin() {
        let identity = Path::new("/cell/workers/compiler/bin/worker");
        assert_eq!(
            compiler_launch_path(identity).unwrap(),
            Path::new("/cell/workers/compiler/bin/launch")
        );
        assert_ne!(compiler_launch_path(identity).unwrap(), identity);
        assert_eq!(
            compiler_launch_path(Path::new("/usr/local/bin/lake_query_compile")).unwrap(),
            Path::new("/usr/local/bin/lake_query_compile")
        );
        assert_eq!(
            compiler_launch_path(Path::new("/cell/workers/compiler/bin/wrong")),
            Err(LaunchError::Denied)
        );
    }
    fn files() -> Files {
        Files {
            document: WorkerLaunchDocument {
                schema_version: 1,
                compiler_linkage: CompilerLinkage::BundledGnu,
                package_sha256: "a".repeat(64),
                files: ["ingest", "query", "compiler"]
                    .into_iter()
                    .flat_map(|kind| {
                        ["bin/launch", "bin/worker", "lib/ld.so", "lib/libc.so.6"].map(
                            move |name| (format!("/cell/workers/{kind}/{name}"), "b".repeat(64)),
                        )
                    })
                    .collect(),
            },
            checks: AtomicUsize::new(0),
            corrupt: false,
        }
    }
    fn args() -> Vec<OsString> {
        vec!["--cell-control-fd".into(), "3".into()]
    }
    #[test]
    fn query_uses_only_bundled_loader_with_cache_and_hwcaps_disabled() {
        let f = files();
        let plan =
            prepare_worker_exec(Path::new("/cell/workers/query/bin/launch"), &args(), &f).unwrap();
        let c = plan.command();
        assert_eq!(c.get_program(), "/cell/workers/query/lib/ld.so");
        assert_eq!(
            c.get_args().collect::<Vec<_>>(),
            [
                "--inhibit-cache",
                "--glibc-hwcaps-mask",
                "",
                "--library-path",
                "/cell/workers/query/lib",
                "/cell/workers/query/bin/worker",
                "--cell-control-fd",
                "3"
            ]
            .map(std::ffi::OsStr::new)
        );
        assert_eq!(
            c.get_envs().count(),
            0,
            "no explicit environment overrides; hostile-LD live execution remains a required gate"
        );
        assert_eq!(f.checks.load(Ordering::SeqCst), 4);
    }
    #[test]
    fn compiler_is_same_closed_exec_with_json_stdio_and_no_extra_arguments() {
        let f = files();
        let p =
            prepare_worker_exec(Path::new("/cell/workers/compiler/bin/launch"), &[], &f).unwrap();
        assert_eq!(p.program(), Path::new("/cell/workers/compiler/bin/worker"));
        assert_eq!(
            p.command().get_args().last(),
            Some(std::ffi::OsStr::new("/cell/workers/compiler/bin/worker"))
        );
    }
    #[test]
    fn argv_or_host_path_cannot_select_an_executable() {
        for path in [
            "/bin/launch",
            "/cell/workers/query/bin/../bin/launch",
            "/cell/workers/query/bin/worker",
            "/cell/workers/foreign/bin/launch",
        ] {
            let f = files();
            assert_eq!(
                prepare_worker_exec(Path::new(path), &args(), &f).err(),
                Some(LaunchError::Denied),
                "{path}"
            );
            assert_eq!(f.checks.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn extra_arguments_and_wrong_fd_refuse_before_artifact_io() {
        for (kind, args) in [
            ("compiler", args()),
            ("query", vec![]),
            ("ingest", vec!["--cell-control-fd".into(), "4".into()]),
            ("query", vec!["--skip-jail".into()]),
        ] {
            let f = files();
            assert_eq!(
                prepare_worker_exec(
                    Path::new(&format!("/cell/workers/{kind}/bin/launch")),
                    &args,
                    &f
                )
                .err(),
                Some(LaunchError::Denied)
            );
            assert_eq!(f.checks.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn host_library_or_parent_escape_in_manifest_has_zero_file_opens() {
        for path in [
            "/usr/lib/libc.so.6",
            "/cell/workers/query/lib/../../outside.so",
            "/cell/workers/query/lib/alias/libc.so.6",
        ] {
            let mut f = files();
            f.document.files.insert(path.into(), "c".repeat(64));
            assert_eq!(
                prepare_worker_exec(Path::new("/cell/workers/query/bin/launch"), &args(), &f).err(),
                Some(LaunchError::Artifact)
            );
            assert_eq!(f.checks.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn missing_loader_or_program_or_self_refuses_before_file_opens() {
        for path in ["lib/ld.so", "bin/worker", "bin/launch"] {
            let mut f = files();
            f.document
                .files
                .remove(&format!("/cell/workers/query/{path}"));
            assert_eq!(
                prepare_worker_exec(Path::new("/cell/workers/query/bin/launch"), &args(), &f).err(),
                Some(LaunchError::Artifact)
            );
            assert_eq!(f.checks.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn artifact_hash_or_filesystem_observation_failure_has_no_exec_plan() {
        let mut f = files();
        f.corrupt = true;
        assert_eq!(
            prepare_worker_exec(Path::new("/cell/workers/query/bin/launch"), &args(), &f).err(),
            Some(LaunchError::Artifact)
        );
    }
    #[test]
    fn malformed_hash_and_unsupported_schema_refuse() {
        let mut f = files();
        f.document.package_sha256 = "0".repeat(64);
        assert_eq!(
            prepare_worker_exec(Path::new("/cell/workers/query/bin/launch"), &args(), &f).err(),
            Some(LaunchError::Artifact)
        );
        let mut f = files();
        f.document.schema_version = 2;
        assert_eq!(
            prepare_worker_exec(Path::new("/cell/workers/query/bin/launch"), &args(), &f).err(),
            Some(LaunchError::Artifact)
        );
    }
    fn static_files() -> Files {
        let mut f = files();
        f.document.schema_version = 2;
        f.document.compiler_linkage = CompilerLinkage::StaticMusl;
        f.document
            .files
            .retain(|p, _| !p.starts_with("/cell/workers/compiler/lib/"));
        f
    }
    #[test]
    fn v2_static_compiler_has_no_loader_library_argument_or_program_override() {
        let f = static_files();
        let p =
            prepare_worker_exec(Path::new("/cell/workers/compiler/bin/launch"), &[], &f).unwrap();
        assert_eq!(p.loader(), None);
        assert_eq!(
            p.command().get_program(),
            "/cell/workers/compiler/bin/worker"
        );
        assert_eq!(p.command().get_args().count(), 0);
        assert_eq!(p.command().get_envs().count(), 0);
        assert_eq!(f.checks.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn v2_query_still_requires_its_bundled_loader() {
        let f = static_files();
        let p =
            prepare_worker_exec(Path::new("/cell/workers/query/bin/launch"), &args(), &f).unwrap();
        assert_eq!(p.command().get_program(), "/cell/workers/query/lib/ld.so");
        assert!(p.command().get_args().any(|p| p == "--inhibit-cache"));
    }
    #[test]
    fn crossed_version_linkage_never_opens_files() {
        for (version, linkage) in [
            (1, CompilerLinkage::StaticMusl),
            (2, CompilerLinkage::BundledGnu),
            (3, CompilerLinkage::BundledGnu),
            (4, CompilerLinkage::StaticMusl),
        ] {
            let mut f = static_files();
            f.document.schema_version = version;
            f.document.compiler_linkage = linkage;
            assert_eq!(
                prepare_worker_exec(Path::new("/cell/workers/compiler/bin/launch"), &[], &f).err(),
                Some(LaunchError::Artifact)
            );
            assert_eq!(f.checks.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn v2_static_compiler_refuses_any_compiler_library_projection_before_opens() {
        let mut f = static_files();
        f.document
            .files
            .insert("/cell/workers/compiler/lib/ld.so".into(), "b".repeat(64));
        assert_eq!(
            prepare_worker_exec(Path::new("/cell/workers/compiler/bin/launch"), &[], &f).err(),
            Some(LaunchError::Artifact)
        );
        assert_eq!(f.checks.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn v2_static_compiler_still_checks_actual_retained_byte_digests() {
        let mut f = static_files();
        f.corrupt = true;
        assert_eq!(
            prepare_worker_exec(Path::new("/cell/workers/compiler/bin/launch"), &[], &f).err(),
            Some(LaunchError::Artifact)
        );
        assert!(f.checks.load(Ordering::SeqCst) > 0);
    }
    #[test]
    fn legacy_launch_metadata_does_not_gain_a_new_field_on_serialization() {
        let f = files();
        let value = serde_json::to_value(f.document).unwrap();
        assert!(value.get("compiler_linkage").is_none());
    }
    #[test]
    fn v3_reader_preserves_static_compiler_and_bundled_ingest_closure() {
        let mut f = static_files();
        f.document.schema_version = 3;
        let compiler =
            prepare_worker_exec(Path::new("/cell/workers/compiler/bin/launch"), &[], &f).unwrap();
        assert_eq!(compiler.loader(), None);
        assert_eq!(compiler.command().get_args().count(), 0);
        let ingest =
            prepare_worker_exec(Path::new("/cell/workers/ingest/bin/launch"), &args(), &f).unwrap();
        assert_eq!(
            ingest.loader(),
            Some(Path::new("/cell/workers/ingest/lib/ld.so"))
        );
        assert_eq!(
            ingest.program(),
            Path::new("/cell/workers/ingest/bin/worker")
        );
        assert_eq!(f.checks.load(Ordering::SeqCst), 6);
    }
    #[test]
    fn v3_reader_still_denies_corrupt_bytes_and_compiler_gnu_libraries() {
        for fault in ["digest", "gnu"] {
            let mut f = static_files();
            f.document.schema_version = 3;
            if fault == "digest" {
                f.corrupt = true;
            } else {
                f.document
                    .files
                    .insert("/cell/workers/compiler/lib/ld.so".into(), "b".repeat(64));
            }
            assert_eq!(
                prepare_worker_exec(Path::new("/cell/workers/compiler/bin/launch"), &[], &f).err(),
                Some(LaunchError::Artifact),
                "{fault}"
            );
            assert_eq!(
                f.checks.load(Ordering::SeqCst),
                if fault == "digest" { 1 } else { 0 }
            );
        }
    }
}

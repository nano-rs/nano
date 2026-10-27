// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sovereign app-tier runtime facts (NAN-4666).
//!
//! The Rust app tier (api, search, jobs) learns that it runs as a sovereign
//! installation from the installer's facts, never from an environment switch.
//! Those facts are the same private directory the C06 control plane reads:
//! the K01 chart materializes it at [`SOVEREIGN_ROOT`] in every app container,
//! and the Linux H05 units must provide the same layout.
//!
//! | file | content |
//! |---|---|
//! | `deployment.json` | the C06 deployment binding, carrying the C01 installation document |
//! | `product-postgres-runtime` | product-schema runtime DSN, `sslmode=verify-full` only |
//! | `product-postgres-ca` | CA bundle that verifies the product PostgreSQL server |
//!
//! The directory and every file must belong to the process's effective UID
//! and be private (dir no group/other bits, files `0600`/`0400`); symlinks,
//! FIFOs and oversized files are refused.
//!
//! Detection is the directory itself:
//! - [`SOVEREIGN_ROOT`] absent: not sovereign; hosted and open-core behavior is
//!   unchanged and nothing here is consulted.
//! - present: sovereign. Every fact must load and validate, or the process
//!   refuses to boot. There is no `localhost` or environment fallback.
//!
//! A sovereign runtime implies one fixed policy (no knobs):
//! - airgap-equivalent runtime: every internet egress scheduler is off and
//!   content arrives through the C12 offline import, whether the C01
//!   connectivity is `connected` or `air_gapped` (install-time image pulls are
//!   the only allowed internet use);
//! - private AI endpoints are allowed for customer-configured provider
//!   `base_url`s (the only AI a sovereign install has);
//! - docs search is off;
//! - the license runs locked unless a valid offline license is installed;
//! - the product database comes from the facts above.

use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::Path,
    sync::OnceLock,
};
use zeroize::Zeroizing;

/// Fixed mount point. Not configurable: an environment-selected path would be
/// a switch, and the chart and H05 units render this exact path.
pub const SOVEREIGN_ROOT: &str = "/app/sovereign";
pub const DEPLOYMENT_FILE: &str = "deployment.json";
pub const PRODUCT_POSTGRES_RUNTIME_FILE: &str = "product-postgres-runtime";
pub const PRODUCT_POSTGRES_CA_FILE: &str = "product-postgres-ca";

const MAX_DEPLOYMENT_BYTES: u64 = 131_072;
const MAX_MATERIAL_BYTES: u64 = 65_536;
const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_CONTRACT_COUNTER: u64 = (1_u64 << 53) - 1;

/// Environment variables that would contradict the facts. In a sovereign
/// runtime the facts are the only source, so a present value is a
/// misconfiguration and refuses boot instead of being silently ignored.
const CONFLICTING_ENV: [&str; 6] = [
    "DATABASE_URL",
    "LICENSE_URL",
    "HEARTBEAT_URL",
    "LICENSE_TOKEN",
    "HEARTBEAT_TOKEN",
    "CORS_ORIGINS",
];

/// Fixed, secret-free refusal reasons.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SovereignRuntimeError {
    #[error("sovereign installation facts are unreadable ({0})")]
    Unavailable(&'static str),
    #[error("sovereign installation material {0} is not private to this process")]
    InsecureMaterial(&'static str),
    #[error("sovereign deployment binding is invalid ({0})")]
    InvalidDeployment(&'static str),
    #[error("sovereign installation document is invalid ({0})")]
    InvalidInstallation(&'static str),
    #[error("sovereign product database transport is invalid ({0})")]
    InvalidTransport(&'static str),
    #[error("{0} is set, but a sovereign runtime takes it only from installation facts")]
    ConflictingEnvironment(&'static str),
    #[error("DEPLOYMENT_MODE {0:?} conflicts with a sovereign installation")]
    ConflictingDeploymentMode(String),
    #[error("sovereign installation facts are present but this is the open-core build; sovereign requires the enterprise build")]
    OpenCoreBuild,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SovereignTarget {
    Aws,
    Gcp,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SovereignConnectivity {
    Connected,
    AirGapped,
}

/// License posture a sovereign runtime implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SovereignLicenseMode {
    /// Locked until a valid, non-expired offline license is installed.
    LockedUnlessValid,
}

/// Validated sovereign facts for the app tier. No `Debug`: it holds the
/// product database credential.
pub struct SovereignRuntime {
    installation_id: String,
    organization_id: String,
    revision: u64,
    release_epoch: u64,
    target: SovereignTarget,
    connectivity: SovereignConnectivity,
    domain: String,
    database_url: Zeroizing<String>,
}

impl SovereignRuntime {
    /// Load and validate every fact under `root`. Pure apart from reading
    /// `root`; the process-wide entry point is [`process_runtime`].
    pub fn load(root: &Path) -> Result<Self, SovereignRuntimeError> {
        // Every leaf is opened relative to this one pinned, checked directory
        // descriptor, so swapping the root after the check cannot redirect a read.
        let dir = open_root(root)?;
        let deployment = read_private(&dir, DEPLOYMENT_FILE, MAX_DEPLOYMENT_BYTES)?;
        let wire: DeploymentWire = serde_json::from_slice(&deployment)
            .map_err(|_| SovereignRuntimeError::InvalidDeployment("not the C06 binding"))?;
        wire.validate()?;
        let document = decode_canonical_base64(&wire.installation_document)?;
        let installation: InstallationWire = serde_json::from_slice(&document)
            .map_err(|_| SovereignRuntimeError::InvalidInstallation("not a C01 v1 document"))?;
        installation.validate()?;

        let dsn = read_private(&dir, PRODUCT_POSTGRES_RUNTIME_FILE, MAX_MATERIAL_BYTES)?;
        // The CA must exist and be private; PostgreSQL TLS reads it by path.
        read_private(&dir, PRODUCT_POSTGRES_CA_FILE, MAX_MATERIAL_BYTES)?;
        let database_url = product_database_url(&dsn, &root.join(PRODUCT_POSTGRES_CA_FILE))?;

        Ok(Self {
            installation_id: installation.derived.installation_id,
            organization_id: installation.derived.organization_id,
            revision: installation.derived.revision,
            release_epoch: installation.derived.release_epoch,
            target: installation.target.kind(),
            connectivity: installation.inputs.connectivity,
            domain: installation.inputs.domain,
            database_url,
        })
    }

    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn release_epoch(&self) -> u64 {
        self.release_epoch
    }
    pub fn target(&self) -> SovereignTarget {
        self.target
    }
    pub fn connectivity(&self) -> SovereignConnectivity {
        self.connectivity
    }
    /// Customer domain from C01; the browser origin is `https://{domain}`.
    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn browser_origin(&self) -> String {
        format!("https://{}", self.domain.trim_end_matches('.'))
    }
    /// Product-schema PostgreSQL URL with `sslmode=verify-full` and the
    /// installation CA bound by path.
    pub fn database_url(&self) -> &str {
        self.database_url.as_str()
    }

    /// Internet egress schedulers never run in a sovereign runtime.
    pub const fn egress_jobs_enabled(&self) -> bool {
        false
    }
    /// Customer-configured AI provider endpoints may be private.
    pub const fn private_ai_endpoints_allowed(&self) -> bool {
        true
    }
    pub const fn docs_search_enabled(&self) -> bool {
        false
    }
    pub const fn license_mode(&self) -> SovereignLicenseMode {
        SovereignLicenseMode::LockedUnlessValid
    }
}

/// Detect a sovereign installation at `root`. `Ok(None)` only when `root`
/// does not exist; any other state of `root` is sovereign and must validate.
pub fn detect_at(
    root: &Path,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<SovereignRuntime>, SovereignRuntimeError> {
    match std::fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(SovereignRuntimeError::Unavailable("installation root")),
        Ok(_) => {}
    }
    if !cfg!(feature = "enterprise") {
        return Err(SovereignRuntimeError::OpenCoreBuild);
    }
    refuse_conflicting_env(&env)?;
    SovereignRuntime::load(root).map(Some)
}

fn refuse_conflicting_env(
    env: &impl Fn(&str) -> Option<String>,
) -> Result<(), SovereignRuntimeError> {
    for name in CONFLICTING_ENV {
        if env(name).is_some() {
            return Err(SovereignRuntimeError::ConflictingEnvironment(name));
        }
    }
    match env("DEPLOYMENT_MODE").as_deref() {
        None | Some("") | Some("selfhosted") | Some("self-hosted") => Ok(()),
        Some(other) => Err(SovereignRuntimeError::ConflictingDeploymentMode(
            other.to_string(),
        )),
    }
}

static PROCESS: OnceLock<Result<Option<SovereignRuntime>, SovereignRuntimeError>> = OnceLock::new();

/// The process's sovereign facts, loaded once from [`SOVEREIGN_ROOT`].
/// Every app-tier binary calls this at boot and refuses to start on `Err`.
pub fn process_runtime() -> Result<Option<&'static SovereignRuntime>, SovereignRuntimeError> {
    PROCESS
        .get_or_init(|| detect_at(Path::new(SOVEREIGN_ROOT), |name| std::env::var(name).ok()))
        .as_ref()
        .map(Option::as_ref)
        .map_err(Clone::clone)
}

/// Boot gate: `Ok(true)` for a valid sovereign runtime, `Ok(false)` when not
/// sovereign, `Err` (refuse to start) for missing or invalid facts.
pub fn require_at_boot() -> Result<bool, SovereignRuntimeError> {
    let runtime = process_runtime()?;
    if let Some(runtime) = runtime {
        tracing::info!(
            installation_id = runtime.installation_id(),
            target = ?runtime.target(),
            connectivity = ?runtime.connectivity(),
            "sovereign runtime: installation facts loaded; egress schedulers off, private AI endpoints allowed, docs search off, license locked unless valid"
        );
    }
    Ok(runtime.is_some())
}

/// Whether the process must behave as an offline (airgap-equivalent)
/// runtime. Invalid facts count as sovereign here so a call site that runs
/// before, or despite, the boot gate still fails closed on egress.
pub fn airgap_equivalent() -> bool {
    !matches!(process_runtime(), Ok(None))
}

/// Whether customer-configured AI endpoints may be private. Only a valid
/// sovereign runtime grants it; invalid facts deny (the SSRF-safe side).
pub fn private_ai_endpoints_allowed() -> bool {
    matches!(process_runtime(), Ok(Some(runtime)) if runtime.private_ai_endpoints_allowed())
}

fn open_root(root: &Path) -> Result<File, SovereignRuntimeError> {
    const ROOT: &str = "installation root";
    let dir = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                SovereignRuntimeError::InsecureMaterial(ROOT)
            }
            _ => SovereignRuntimeError::Unavailable(ROOT),
        })?;
    let metadata = dir
        .metadata()
        .map_err(|_| SovereignRuntimeError::Unavailable(ROOT))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o077 != 0
    {
        return Err(SovereignRuntimeError::InsecureMaterial(ROOT));
    }
    Ok(dir)
}

fn read_private(
    dir: &File,
    name: &'static str,
    limit: u64,
) -> Result<Zeroizing<Vec<u8>>, SovereignRuntimeError> {
    // `name` is one of the fixed leaf constants (no `/`), resolved only
    // inside the pinned directory and never through a symlink.
    let c_name =
        std::ffi::CString::new(name).map_err(|_| SovereignRuntimeError::Unavailable(name))?;
    // SAFETY: `dir` is an open directory descriptor and `c_name` is a valid
    // NUL-terminated string; the returned descriptor is owned below.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ELOOP) => SovereignRuntimeError::InsecureMaterial(name),
            _ => SovereignRuntimeError::Unavailable(name),
        });
    }
    // SAFETY: `fd` was just returned by openat and nothing else owns it.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file
        .metadata()
        .map_err(|_| SovereignRuntimeError::Unavailable(name))?;
    if !before.file_type().is_file()
        || before.uid() != effective_uid()
        || before.mode() & 0o7077 != 0
        || before.mode() & 0o400 == 0
        || before.len() < 1
        || before.len() > limit
    {
        return Err(SovereignRuntimeError::InsecureMaterial(name));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(before.len() as usize + 1));
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SovereignRuntimeError::Unavailable(name))?;
    let after = file
        .metadata()
        .map_err(|_| SovereignRuntimeError::Unavailable(name))?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
    {
        return Err(SovereignRuntimeError::InsecureMaterial(name));
    }
    Ok(bytes)
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// C06 `deployment.json` wire, field for field (`deploymentSchema` in
/// the hosted control plane's sovereign validation): both readers accept exactly
/// the same file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeploymentWire {
    installation_document: String,
    postgres: PostgresRefs,
    coordination: CoordinationRefs,
    identity: IdentityRefs,
    release_digest: String,
    listen: Listen,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PostgresRefs {
    runtime_url: Reference,
    migrator_url: Reference,
    ca: Reference,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinationRefs {
    url: Reference,
    ca: Reference,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IdentityRefs {
    session_secret: Reference,
    oidc_client: Reference,
    #[serde(default)]
    bootstrap_approval: Option<Reference>,
    recovery_authority: Reference,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listen {
    host: String,
    port: u16,
}

impl DeploymentWire {
    fn validate(&self) -> Result<(), SovereignRuntimeError> {
        let invalid = SovereignRuntimeError::InvalidDeployment;
        let mut references = vec![
            &self.postgres.runtime_url,
            &self.postgres.migrator_url,
            &self.postgres.ca,
            &self.coordination.url,
            &self.coordination.ca,
            &self.identity.session_secret,
            &self.identity.oidc_client,
            &self.identity.recovery_authority,
        ];
        references.extend(self.identity.bootstrap_approval.as_ref());
        if references
            .iter()
            .any(|reference| !reference_id(&reference.id))
        {
            return Err(invalid("private reference"));
        }
        if self.postgres.runtime_url.id == self.postgres.migrator_url.id
            || self
                .identity
                .bootstrap_approval
                .as_ref()
                .is_some_and(|approval| approval.id == self.identity.recovery_authority.id)
        {
            return Err(invalid("purpose separation"));
        }
        let digest = self.release_digest.strip_prefix("sha256:").unwrap_or("");
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(invalid("release digest"));
        }
        if self.listen.host.is_empty() || self.listen.host.len() > 253 || self.listen.port == 0 {
            return Err(invalid("listen"));
        }
        if self.installation_document.len() < 4 || self.installation_document.len() > 87_384 {
            return Err(invalid("installation document size"));
        }
        Ok(())
    }
}

/// C06 private reference id: `^[a-z0-9][a-z0-9_-]{0,63}$`.
fn reference_id(value: &str) -> bool {
    identifier(value)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

fn decode_canonical_base64(value: &str) -> Result<Zeroizing<Vec<u8>>, SovereignRuntimeError> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine
        .decode(value)
        .map_err(|_| SovereignRuntimeError::InvalidDeployment("installation document encoding"))?;
    if engine.encode(&bytes) != value {
        return Err(SovereignRuntimeError::InvalidDeployment(
            "installation document encoding",
        ));
    }
    Ok(Zeroizing::new(bytes))
}

/// The C01 v1 facts the app tier uses. The installer validated the whole
/// document and C06 binds its exact bytes to the PostgreSQL head; this reader
/// still refuses anything outside the v1 shape it depends on.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationWire {
    schema_version: u32,
    inputs: InputsWire,
    derived: DerivedWire,
    target: TargetWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputsWire {
    domain: String,
    idp: IdpWire,
    #[serde(default = "connected")]
    connectivity: SovereignConnectivity,
    #[serde(default)]
    #[allow(dead_code)]
    offline_source: Option<serde_json::Value>,
}

fn connected() -> SovereignConnectivity {
    SovereignConnectivity::Connected
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdpWire {
    kind: String,
    issuer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedWire {
    installation_id: String,
    organization_id: String,
    revision: u64,
    release_epoch: u64,
}

/// Target-specific inputs/derived state are not app-tier facts.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TargetWire {
    Aws {},
    Gcp {},
    Linux {},
}

impl TargetWire {
    fn kind(&self) -> SovereignTarget {
        match self {
            Self::Aws {} => SovereignTarget::Aws,
            Self::Gcp {} => SovereignTarget::Gcp,
            Self::Linux {} => SovereignTarget::Linux,
        }
    }
}

impl InstallationWire {
    fn validate(&self) -> Result<(), SovereignRuntimeError> {
        let invalid = SovereignRuntimeError::InvalidInstallation;
        if self.schema_version != 1 {
            return Err(invalid("schema version"));
        }
        if !identifier(&self.derived.installation_id) || !identifier(&self.derived.organization_id)
        {
            return Err(invalid("identifiers"));
        }
        for counter in [self.derived.revision, self.derived.release_epoch] {
            if !(1..=MAX_CONTRACT_COUNTER).contains(&counter) {
                return Err(invalid("counters"));
            }
        }
        if !dns_name(&self.inputs.domain) {
            return Err(invalid("domain"));
        }
        if self.inputs.idp.kind != "oidc"
            || !url::Url::parse(&self.inputs.idp.issuer).is_ok_and(|url| url.scheme() == "https")
        {
            return Err(invalid("identity provider"));
        }
        Ok(())
    }
}

fn dns_name(value: &str) -> bool {
    let name = value.strip_suffix('.').unwrap_or(value);
    !name.is_empty()
        && name.len() <= 253
        && name.bytes().any(|c| c.is_ascii_alphabetic())
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        && matches!(url::Host::parse(value), Ok(url::Host::Domain(_)))
}

/// Validate the product runtime DSN with the C06 PostgreSQL transport rules
/// (one `sslmode=verify-full` parameter, a login, a database, no fragment, no
/// whitespace), then bind the installation CA by path for TLS verification.
fn product_database_url(
    dsn: &[u8],
    ca_path: &Path,
) -> Result<Zeroizing<String>, SovereignRuntimeError> {
    let invalid = SovereignRuntimeError::InvalidTransport;
    let value = std::str::from_utf8(dsn).map_err(|_| invalid("encoding"))?;
    if value != value.trim() || value.contains(['\r', '\n', '\0']) {
        return Err(invalid("whitespace"));
    }
    let mut url = url::Url::parse(value).map_err(|_| invalid("url"))?;
    if !matches!(url.scheme(), "postgresql" | "postgres")
        || url.host_str().is_none_or(str::is_empty)
        || url.fragment().is_some()
        || url.path().len() <= 1
        || url.username().is_empty()
    {
        return Err(invalid("shape"));
    }
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if pairs.len() != 1 || pairs[0].0 != "sslmode" || pairs[0].1 != "verify-full" {
        return Err(invalid("sslmode must be exactly verify-full"));
    }
    let login = urlencoding::decode(url.username()).map_err(|_| invalid("login"))?;
    if login.is_empty() || login.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid("login"));
    }
    let ca = ca_path.to_str().ok_or(invalid("ca path"))?;
    url.query_pairs_mut().append_pair("sslrootcert", ca);
    Ok(Zeroizing::new(url.into()))
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: AGPL-3.0-or-later

//! `nanosiem-lake-cell trusted-local init`: the single-tenant open-core
//! cell's identity and configuration (NAN-3492).
//!
//! A self-hosted install has no control plane: one tenant per box, and the
//! trust boundary is the host. This command renders everything the cell and
//! the app services need, from the lab path that already exists in the
//! binaries (dev key directory, in-process `LocalPartSigner`, query bootstrap
//! document, local parts directory):
//!
//! ```text
//! <out>/
//!   tenant_id                      the install's tenant UUID (0644)
//!   cell/cell.json                 supervisor config (0644)
//!   cell/placement.json            one resident tenant, role budgets sized
//!                                  from host memory and CPU (0644)
//!   cell/secret/                   dev key dir (0700, supervisor only)
//!     router.token                 full router bearer (0400)
//!     <T>/ingest.token             lab ingest credentials: signer seed,
//!                                  bronze location + listing input (0400)
//!     <T>/query.token              query bootstrap document (0400)
//!   app/routes.json                tenant → cell route for api/search/jobs (0644)
//!   app/router-query.token         query-only router bearer (0400)
//!   app/lake-cell.env              env for api/search/jobs (0644)
//! ```
//!
//! Contract (stable; install.sh depends on it):
//! - Idempotent: a re-run keeps the tenant id, signer seed and router
//!   tokens, and re-renders configs and budgets (for example after the host
//!   was resized or the bronze credentials rotated). Only `--force` mints a
//!   new tenant and new keys, which orphans every existing part.
//! - Bronze object-store credentials come from the environment
//!   (`NANO_LAKE_ACCESS_KEY_ID`, `NANO_LAKE_SECRET_ACCESS_KEY`), never argv.
//!   A re-run without them keeps the credentials already rendered.
//! - Exit codes: 0 written (a JSON summary on stdout, no secrets); 2 usage;
//!   3 existing state is inconsistent or conflicts with the flags and
//!   `--force` was not given (nothing is written); 1 any other failure.

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use crate::budget::{TenantBudget, GIB, MIB};

/// Exit code: existing state conflicts (no `--force`).
pub const EXIT_CONFLICT: i32 = 3;
/// Exit code: bad usage.
pub const EXIT_USAGE: i32 = 2;

const INGEST_LAB_KIND: &str = "nano.lake.ingest-lab-credentials.v1";
const QUERY_BOOTSTRAP_FORMAT: &str = "nano.lake-query-bootstrap.v1";
const SIGNER_KEY_ID: &str = "trusted-local-signer-0001";

/// A conflict that `--force` would override (exit 3).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Conflict(pub String);

/// A usage error (exit 2).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Usage(pub String);

#[derive(Debug, Clone)]
pub struct InitArgs {
    pub out: PathBuf,
    pub tenant_id: Option<uuid::Uuid>,
    pub force: bool,
    pub cell_id: String,
    /// Where `<out>/cell` is mounted inside the cell container.
    pub cell_config_root: PathBuf,
    /// The cell's data volume inside its container (`data/`, `state/`).
    pub cell_data_root: PathBuf,
    /// Where `<out>/app` is mounted inside the api/search/jobs containers.
    pub app_config_root: PathBuf,
    pub listen: String,
    /// The router origin the app services call, e.g. `http://lake-cell:8790`.
    pub cell_origin: String,
    pub bronze_endpoint: String,
    pub bronze_region: String,
    pub bronze_bucket: String,
    pub bronze_prefix: String,
    pub bin_dir: PathBuf,
    pub chdb_library: PathBuf,
    pub chdb_sha256: Option<String>,
    pub compiler: PathBuf,
    /// Memory for the cell's tenant processes; default half the host.
    pub memory_bytes: Option<u64>,
    /// CPUs for the cell's tenant processes; default every online host CPU.
    pub cpus: Option<u32>,
    /// NAN-4693: root that host facts are read from (`/proc/meminfo`,
    /// `/sys/devices/system/cpu/online`); `/` in production, a fixture in tests.
    pub host_root: PathBuf,
    /// `uid:gid` owning `app/` files (the app services' user).
    pub app_owner: Option<(u32, u32)>,
    pub require_landlock: bool,
}

impl Default for InitArgs {
    fn default() -> Self {
        Self {
            out: PathBuf::new(),
            tenant_id: None,
            force: false,
            cell_id: "local".into(),
            cell_config_root: "/etc/nano-cell".into(),
            cell_data_root: "/var/lib/nano-cell".into(),
            app_config_root: "/etc/nano-lake-cell".into(),
            listen: "0.0.0.0:8790".into(),
            cell_origin: "http://lake-cell:8790".into(),
            bronze_endpoint: "http://lake-object-store:9000".into(),
            bronze_region: "us-east-1".into(),
            bronze_bucket: "nano-lake".into(),
            bronze_prefix: "bronze-v2".into(),
            bin_dir: "/usr/local/bin".into(),
            chdb_library: "/usr/local/lib/nano-chdb/libchdb.so".into(),
            chdb_sha256: None,
            compiler: "/usr/local/bin/lake_query_compile".into(),
            memory_bytes: None,
            cpus: None,
            host_root: "/".into(),
            app_owner: None,
            require_landlock: true,
        }
    }
}

const USAGE: &str = "usage: nanosiem-lake-cell trusted-local init --out <dir> [--tenant-id <uuid>] [--force] \
[--cell-id <id>] [--cell-config-root <path>] [--cell-data-root <path>] [--app-config-root <path>] \
[--listen <addr:port>] [--cell-origin <url>] [--bronze-endpoint <url>] [--bronze-region <r>] \
[--bronze-bucket <b>] [--bronze-prefix <p>] [--bin-dir <path>] [--chdb-library <path>] [--chdb-sha256 <hex>] \
[--compiler <path>] [--memory-bytes <n>] [--cpus <n>] [--app-owner <uid:gid>] [--no-require-landlock]";

pub fn usage() -> &'static str {
    USAGE
}

/// Parse `init`'s flags (everything after `trusted-local init`).
pub fn parse_args(args: &[String]) -> std::result::Result<InitArgs, Usage> {
    let mut out = InitArgs::default();
    let mut have_out = false;
    let mut i = 0;
    let bad = |m: String| Usage(format!("{m}\n{USAGE}"));
    while i < args.len() {
        let flag = args[i].as_str();
        let take = |i: &mut usize| -> std::result::Result<String, Usage> {
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| Usage(format!("{flag} needs a value\n{USAGE}")))
        };
        match flag {
            "--out" => { out.out = take(&mut i)?.into(); have_out = true; }
            "--tenant-id" => {
                let v = take(&mut i)?;
                let id = uuid::Uuid::parse_str(&v).map_err(|_| bad(format!("--tenant-id {v:?} is not a UUID")))?;
                if id.is_nil() || id.as_hyphenated().to_string() != v {
                    return Err(bad("--tenant-id must be a lowercase hyphenated, non-nil UUID".into()));
                }
                out.tenant_id = Some(id);
            }
            "--force" => out.force = true,
            "--cell-id" => out.cell_id = take(&mut i)?,
            "--cell-config-root" => out.cell_config_root = take(&mut i)?.into(),
            "--cell-data-root" => out.cell_data_root = take(&mut i)?.into(),
            "--app-config-root" => out.app_config_root = take(&mut i)?.into(),
            "--listen" => out.listen = take(&mut i)?,
            "--cell-origin" => out.cell_origin = take(&mut i)?,
            "--bronze-endpoint" => out.bronze_endpoint = take(&mut i)?,
            "--bronze-region" => out.bronze_region = take(&mut i)?,
            "--bronze-bucket" => out.bronze_bucket = take(&mut i)?,
            "--bronze-prefix" => out.bronze_prefix = take(&mut i)?,
            "--bin-dir" => out.bin_dir = take(&mut i)?.into(),
            "--chdb-library" => out.chdb_library = take(&mut i)?.into(),
            "--chdb-sha256" => out.chdb_sha256 = Some(take(&mut i)?),
            "--compiler" => out.compiler = take(&mut i)?.into(),
            "--memory-bytes" => {
                let v = take(&mut i)?;
                out.memory_bytes = Some(v.parse().map_err(|_| bad(format!("--memory-bytes {v:?} is not a number")))?);
            }
            "--cpus" => {
                let v = take(&mut i)?;
                out.cpus = Some(v.parse().map_err(|_| bad(format!("--cpus {v:?} is not a number")))?);
            }
            "--app-owner" => {
                let v = take(&mut i)?;
                let parsed = v.split_once(':').and_then(|(u, g)| Some((u.parse().ok()?, g.parse().ok()?)));
                out.app_owner = Some(parsed.ok_or_else(|| bad(format!("--app-owner {v:?} must be uid:gid")))?);
            }
            "--no-require-landlock" => out.require_landlock = false,
            other => return Err(bad(format!("unknown flag {other:?}"))),
        }
        i += 1;
    }
    if !have_out {
        return Err(bad("--out is required".into()));
    }
    out.validate().map_err(|e| bad(e.to_string()))?;
    Ok(out)
}

impl InitArgs {
    fn validate(&self) -> Result<()> {
        ensure!(!self.cell_id.is_empty() && self.cell_id.len() <= 63
            && self.cell_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "--cell-id must be 1-63 of [a-z0-9-]");
        for (name, path) in [("--cell-config-root", &self.cell_config_root), ("--cell-data-root", &self.cell_data_root),
            ("--app-config-root", &self.app_config_root), ("--bin-dir", &self.bin_dir),
            ("--chdb-library", &self.chdb_library), ("--compiler", &self.compiler)] {
            ensure!(path.is_absolute(), "{name} must be an absolute path");
        }
        ensure!(self.listen.parse::<std::net::SocketAddr>().is_ok(), "--listen must be addr:port");
        for (name, url) in [("--cell-origin", &self.cell_origin), ("--bronze-endpoint", &self.bronze_endpoint)] {
            ensure!((url.starts_with("http://") || url.starts_with("https://")) && !url.trim_end_matches('/').contains('?'),
                "{name} must be an http(s) origin");
        }
        ensure!(!self.bronze_bucket.is_empty() && !self.bronze_bucket.contains('/'), "--bronze-bucket is invalid");
        ensure!(!self.bronze_prefix.contains(".."), "--bronze-prefix is invalid");
        if let Some(sha) = &self.chdb_sha256 {
            ensure!(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()), "--chdb-sha256 must be 64 hex");
        }
        ensure!(self.memory_bytes.is_none_or(|m| m >= 2 * GIB), "--memory-bytes must be at least 2 GiB");
        ensure!(self.cpus.is_none_or(|c| (1..=1024).contains(&c)), "--cpus must be 1..1024");
        Ok(())
    }

    /// The TCP port ingest connects to for bronze reads.
    fn bronze_port(&self) -> Result<u16> {
        let rest = self.bronze_endpoint.split_once("://").map(|(_, r)| r).unwrap_or_default();
        let host = rest.split('/').next().unwrap_or_default();
        match host.rsplit_once(':') {
            Some((_, port)) if !port.contains(']') => port.parse().context("--bronze-endpoint port"),
            _ => Ok(if self.bronze_endpoint.starts_with("https://") { 443 } else { 80 }),
        }
    }
}

/// Role budgets for the one tenant, sized from the memory and CPU the cell
/// may use (never from eps: at low eps the eps-derived query budget is
/// 128 MiB and aggregations fail with MEMORY_LIMIT_EXCEEDED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sizing {
    pub memory_bytes: u64,
    pub cpus: u32,
    /// eps chosen only so the eps-derived ingest cap does not undercut the
    /// placed ingest limit (the supervisor takes the smaller of the two).
    pub eps: u32,
    pub ingest: (u32, u32, u64, u64),
    pub detect: (u32, u32, u64, u64),
    pub query: (u32, u32, u64, u64),
}

fn round_mib(bytes: u64) -> u64 {
    bytes / MIB * MIB
}

pub fn size(memory_bytes: u64, cpus: u32) -> Sizing {
    let cpus = cpus.max(1);
    // query 50 %, ingest 25 %, detect 15 %; the rest covers the fixed
    // product/maintenance budgets and the supervisor.
    let query_mem = round_mib(memory_bytes / 2).max(GIB);
    let ingest_mem = round_mib(memory_bytes / 4).max(512 * MIB);
    let detect_mem = round_mib(memory_bytes / 100 * 15).max(256 * MIB);
    let milli = cpus.saturating_mul(1000);
    let query_cpu = (milli / 4 * 3).max(1000);
    let ingest_cpu = (milli / 2).max(1000);
    let detect_cpu = (milli / 4).max(500);
    // `eps` is only a sizing input here: the role budgets above are explicit,
    // but the supervisor still caps ingest at the eps-derived
    // `ingest_memory_cap_bytes`, so pick the smallest eps whose cap covers
    // the placed ingest limit (the curve extrapolates linearly).
    let eps = (20..=1_000_000)
        .step_by(10)
        .find(|eps| TenantBudget::from_eps(*eps as f64).ingest_memory_cap_bytes >= ingest_mem)
        .unwrap_or(1_000_000);
    let req = |mem: u64| round_mib(mem / 4).max(64 * MIB);
    Sizing {
        memory_bytes,
        cpus,
        eps,
        ingest: (250.min(ingest_cpu), ingest_cpu, req(ingest_mem), ingest_mem),
        detect: (100.min(detect_cpu), detect_cpu, req(detect_mem), detect_mem),
        query: (250.min(query_cpu), query_cpu, req(query_mem), query_mem),
    }
}

/// Host facts the cell is sized from (NAN-4693).
///
/// `init` runs in a one-shot container (`lean-init`), not in the lake-cell
/// container it sizes, so its OWN cgroup (`memory.max`, `cpu.max`) says
/// nothing about the cell's budget: a capped or small init container used to
/// write a floor placement (2 GiB / 1 CPU -> eps 60, ~330 rows/s) for a cell
/// on a large host. The cell's budget is the host's: `MemTotal` (the host,
/// or the Docker Desktop VM) and the online CPU set. Neither honours the
/// caller's cgroup limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFacts {
    pub memory_bytes: u64,
    pub cpus: u32,
}

pub fn detect_host(root: &Path) -> Result<HostFacts> {
    let meminfo_path = root.join("proc/meminfo");
    let meminfo = std::fs::read_to_string(&meminfo_path).with_context(|| format!("read {}", meminfo_path.display()))?;
    let memory_bytes = meminfo.lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        .context("MemTotal missing from /proc/meminfo")? * 1024;
    let cpus = std::fs::read_to_string(root.join("sys/devices/system/cpu/online")).ok()
        .and_then(|v| count_cpu_list(v.trim()))
        // No sysfs (unusual runtimes): fall back to the scheduler's view.
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1));
    Ok(HostFacts { memory_bytes, cpus: cpus.clamp(1, 1024) })
}

/// Count a kernel CPU list such as `0-31` or `0,2-5,8`.
fn count_cpu_list(list: &str) -> Option<u32> {
    let mut n = 0_u32;
    for part in list.split(',').filter(|p| !p.is_empty()) {
        let span = match part.split_once('-') {
            Some((a, b)) => b.parse::<u32>().ok()?.checked_sub(a.parse::<u32>().ok()?)?.checked_add(1)?,
            None => { part.parse::<u32>().ok()?; 1 }
        };
        n = n.checked_add(span)?;
    }
    (n > 0).then_some(n)
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0_u8; N];
    getrandom::fill(&mut out).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    Ok(out)
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Write `bytes` atomically with `mode`.
fn write_file(path: &Path, bytes: &[u8], mode: u32, owner: Option<(u32, u32)>) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = path.parent().context("no parent")?;
    let temp = dir.join(format!(".{}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("file")));
    let _ = std::fs::remove_file(&temp);
    {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(&temp, Some(uid), Some(gid))?;
    }
    std::fs::rename(&temp, path)?;
    Ok(())
}

fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn read_json(path: &Path) -> Result<Option<Value>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).with_context(|| format!("{} does not parse", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

fn read_token(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(v) => {
            let v = v.trim().to_string();
            ensure!(v.len() >= 32, "{} holds no usable token", path.display());
            Ok(Some(v))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// What an earlier run left behind, if anything.
struct Existing {
    tenant: uuid::Uuid,
    seed: [u8; 32],
    router_token: String,
    query_token: String,
    bronze_keys: Option<(String, String)>,
}

fn load_existing(out: &Path) -> Result<Option<Existing>> {
    let tenant_file = out.join("tenant_id");
    let tenant = match std::fs::read_to_string(&tenant_file) {
        Ok(v) => uuid::Uuid::parse_str(v.trim()).map_err(|_| Conflict(format!("{} is not a UUID", tenant_file.display())))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if out.join("cell/secret").exists() {
                return Err(Conflict("cell/secret exists without tenant_id; refusing to guess the tenant".into()).into());
            }
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };
    let secret = out.join("cell/secret");
    let ingest = read_json(&secret.join(tenant.to_string()).join("ingest.token"))?
        .ok_or_else(|| Conflict(format!("tenant {tenant} has no ingest.token; its signer seed is lost")))?;
    ensure!(ingest.get("kind").and_then(Value::as_str) == Some(INGEST_LAB_KIND)
        && ingest.get("tenant_id").and_then(Value::as_str) == Some(&tenant.to_string()),
        Conflict("ingest.token belongs to another tenant or kind".into()));
    let seed: [u8; 32] = ingest.get("lab_signer_seed_hex").and_then(Value::as_str)
        .and_then(|h| hex::decode(h).ok()).and_then(|b| b.try_into().ok())
        .ok_or_else(|| Conflict("ingest.token holds no 32-byte signer seed".into()))?;
    let router_token = read_token(&secret.join("router.token"))?
        .ok_or_else(|| Conflict("router.token is missing".into()))?;
    let query_token = read_token(&out.join("app/router-query.token"))?
        .ok_or_else(|| Conflict("app/router-query.token is missing".into()))?;
    let bronze_keys = ingest.get("bronze").and_then(|b| {
        Some((b.get("access_key_id")?.as_str()?.to_string(), b.get("secret_access_key")?.as_str()?.to_string()))
    });
    Ok(Some(Existing { tenant, seed, router_token, query_token, bronze_keys }))
}

/// Run `init`. Returns the JSON summary printed on stdout.
pub fn init(args: &InitArgs, env: &dyn Fn(&str) -> Option<String>) -> Result<Value> {
    std::fs::create_dir_all(&args.out).with_context(|| format!("create {}", args.out.display()))?;
    let existing = if args.force { None } else { load_existing(&args.out)? };
    if let (Some(existing), Some(wanted)) = (&existing, args.tenant_id) {
        if existing.tenant != wanted {
            return Err(Conflict(format!("this install already has tenant {}; --tenant-id {wanted} needs --force", existing.tenant)).into());
        }
    }
    let created = existing.is_none();
    let tenant = match existing.as_ref().map(|e| e.tenant).or(args.tenant_id) {
        Some(tenant) => tenant,
        None => uuid::Builder::from_random_bytes(random_bytes::<16>()?).into_uuid(),
    };
    let tenant_s = tenant.as_hyphenated().to_string();
    let seed = match &existing { Some(e) => e.seed, None => random_bytes::<32>()? };
    let router_token = match &existing { Some(e) => e.router_token.clone(), None => format!("nlr1.{}", hex::encode(random_bytes::<32>()?)) };
    let query_token = match &existing { Some(e) => e.query_token.clone(), None => format!("nlq1.{}", hex::encode(random_bytes::<32>()?)) };
    ensure!(router_token != query_token, "router tokens collided");
    let env_keys = match (env("NANO_LAKE_ACCESS_KEY_ID"), env("NANO_LAKE_SECRET_ACCESS_KEY")) {
        (Some(a), Some(s)) if !a.is_empty() && !s.is_empty() => Some((a, s)),
        _ => None,
    };
    let (access_key, secret_key) = env_keys.or_else(|| existing.as_ref().and_then(|e| e.bronze_keys.clone()))
        .ok_or_else(|| anyhow::anyhow!("NANO_LAKE_ACCESS_KEY_ID and NANO_LAKE_SECRET_ACCESS_KEY must be set (bronze read credentials)"))?;

    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_hex = hex::encode(signing.verifying_key().to_bytes());
    let chdb_sha256 = match &args.chdb_sha256 {
        Some(sha) => sha.to_ascii_lowercase(),
        None => sha256_file(&args.chdb_library).context("hash the chDB library (pass --chdb-sha256 when it is not on this filesystem)")?,
    };
    // NAN-4693: explicit flags win; otherwise host facts, never this
    // (init) container's own cgroup limits.
    let host = match (args.memory_bytes, args.cpus) {
        (Some(_), Some(_)) => None,
        _ => Some(detect_host(&args.host_root)?),
    };
    let memory = args.memory_bytes.unwrap_or_else(|| host.map_or(0, |h| h.memory_bytes) / 2);
    let cpus = args.cpus.unwrap_or_else(|| host.map_or(1, |h| h.cpus));
    let sizing = size(memory.max(2 * GIB), cpus);

    // Documents.
    let ingest_token = json!({
        "kind": INGEST_LAB_KIND,
        "tenant_id": tenant_s,
        "writer_epoch": 1,
        "bronze": {
            "endpoint": args.bronze_endpoint, "region": args.bronze_region, "bucket": args.bronze_bucket,
            "prefix": args.bronze_prefix, "access_key_id": access_key, "secret_access_key": secret_key,
        },
        "bronze_list": {},
        "lab_signer_key_id": SIGNER_KEY_ID,
        "lab_signer_seed_hex": hex::encode(seed),
    });
    let query_doc = json!({
        "format": QUERY_BOOTSTRAP_FORMAT,
        "tenant_id": tenant_s,
        "bucket": args.bronze_bucket,
        "trusted_signer_keys": [{"key_id": SIGNER_KEY_ID, "public_key_hex": public_hex}],
        "engine": {
            "chdb_library": args.chdb_library, "chdb_sha256": chdb_sha256, "compiler": args.compiler,
        },
    });
    let cfg_root = &args.cell_config_root;
    let mut connect_ports = vec![args.bronze_port()?];
    connect_ports.dedup();
    let chdb_dir = args.chdb_library.parent().context("--chdb-library has no directory")?;
    let cell = json!({
        "cell_id": args.cell_id,
        "mode": "dedicated",
        // The single-tenant open-core cell is trusted-local by construction;
        // init owns the flag (the open configure step no longer patches it).
        "trusted_local": true,
        "data_dir": args.cell_data_root.join("data"),
        "state_dir": args.cell_data_root.join("state"),
        "ingest_binary": args.bin_dir.join("nanosiem-lake-ingest"),
        "query_binary": args.bin_dir.join("nanosiem-lake-query"),
        "extra_ro_paths": [chdb_dir],
        "warm_query": 0,
        "warm_ingest": 0,
        "tcp_connect_ports": connect_ports,
        "require_landlock": args.require_landlock,
        "isolation": {"cgroup": "auto", "watchdog": true},
        "listen_tcp": args.listen,
        "router_token_file": cfg_root.join("secret/router.token"),
        "router_query_token_file": cfg_root.join("secret/router-query.token"),
        "placement_file": cfg_root.join("placement.json"),
        "dev_key_dir": cfg_root.join("secret"),
    });
    let (i, d, q) = (sizing.ingest, sizing.detect, sizing.query);
    let placement = json!({
        "cell_id": args.cell_id,
        "revision": 1,
        "tenants": [{
            "tenant_id": tenant_s,
            "eps": sizing.eps as f64,
            "ingest": "resident",
            "ingest_request_millicores": i.0, "ingest_limit_millicores": i.1,
            "ingest_request_memory_bytes": i.2, "ingest_limit_memory_bytes": i.3,
            "detect_request_millicores": d.0, "detect_limit_millicores": d.1,
            "detect_request_memory_bytes": d.2, "detect_limit_memory_bytes": d.3,
            "query_request_millicores": q.0, "query_limit_millicores": q.1,
            "query_request_memory_bytes": q.2, "query_limit_memory_bytes": q.3,
        }],
    });
    // Self-check against the supervisor's own validation before writing.
    let parsed_cell: crate::config::CellConfig = serde_json::from_value(cell.clone()).context("rendered cell.json")?;
    parsed_cell.validate().context("rendered cell.json")?;
    let parsed_placement: crate::config::Placement = serde_json::from_value(placement.clone()).context("rendered placement.json")?;
    parsed_placement.validate(&parsed_cell).context("rendered placement.json")?;
    let routes = json!({ tenant_s.clone(): {
        "cell_origin": args.cell_origin.trim_end_matches('/'),
        "assignment_generation": 1, "part_log_writer_epoch": 1, "worker_revision": 1,
    }});
    let app_root = &args.app_config_root;
    let app_env = format!(
        "# Rendered by nanosiem-lake-cell trusted-local init (NAN-3492). Do not edit.\n\
         NANO_TRUSTED_LOCAL=1\n\
         NANO_LAKE_TENANT_ID={tenant_s}\n\
         NANO_LAKE_CELL_ROUTES_FILE={}\n\
         NANO_LAKE_CELL_ROUTER_TOKEN_FILE={}\n",
        app_root.join("routes.json").display(),
        app_root.join("router-query.token").display(),
    );

    // Write: secrets first, tenant_id last (its presence marks a complete run).
    let out = &args.out;
    let secret = out.join("cell/secret");
    ensure_dir(&out.join("cell"), 0o755)?;
    ensure_dir(&secret, 0o700)?;
    ensure_dir(&secret.join(&tenant_s), 0o700)?;
    ensure_dir(&out.join("app"), 0o755)?;
    write_file(&secret.join("router.token"), router_token.as_bytes(), 0o400, None)?;
    write_file(&secret.join("router-query.token"), query_token.as_bytes(), 0o400, None)?;
    write_file(&secret.join(&tenant_s).join("ingest.token"), &serde_json::to_vec(&ingest_token)?, 0o400, None)?;
    write_file(&secret.join(&tenant_s).join("query.token"), &serde_json::to_vec(&query_doc)?, 0o400, None)?;
    write_file(&out.join("app/router-query.token"), query_token.as_bytes(), 0o400, args.app_owner)?;
    write_file(&out.join("cell/cell.json"), &serde_json::to_vec_pretty(&cell)?, 0o644, None)?;
    write_file(&out.join("cell/placement.json"), &serde_json::to_vec_pretty(&placement)?, 0o644, None)?;
    write_file(&out.join("app/routes.json"), &serde_json::to_vec_pretty(&routes)?, 0o644, args.app_owner)?;
    write_file(&out.join("app/lake-cell.env"), app_env.as_bytes(), 0o644, args.app_owner)?;
    write_file(&out.join("tenant_id"), format!("{tenant_s}\n").as_bytes(), 0o644, None)?;
    Ok(json!({
        "tenant_id": tenant_s,
        "created": created,
        "signer_key_id": SIGNER_KEY_ID,
        "signer_public_key_hex": public_hex,
        "sizing": {
            "memory_bytes": sizing.memory_bytes, "cpus": sizing.cpus, "eps": sizing.eps,
            "query_limit_memory_bytes": q.3, "ingest_limit_memory_bytes": i.3, "detect_limit_memory_bytes": d.3,
        },
    }))
}

/// CLI entry: `trusted-local <subcommand> ...`. Returns the exit code.
pub fn main(args: &[String]) -> i32 {
    if args.first().map(String::as_str) != Some("init") {
        eprintln!("{USAGE}");
        return EXIT_USAGE;
    }
    let parsed = match parse_args(&args[1..]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return EXIT_USAGE;
        }
    };
    match init(&parsed, &|name| std::env::var(name).ok()) {
        Ok(summary) => {
            println!("{summary}");
            0
        }
        Err(e) if e.downcast_ref::<Conflict>().is_some() => {
            eprintln!("trusted-local init refused: {e:#} (re-run with --force to mint a new tenant and keys)");
            EXIT_CONFLICT
        }
        Err(e) => {
            eprintln!("trusted-local init failed: {e:#}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn args(out: &Path) -> InitArgs {
        InitArgs { out: out.to_path_buf(), chdb_sha256: Some("a".repeat(64)), memory_bytes: Some(16 * GIB), cpus: Some(8), ..Default::default() }
    }

    fn env(name: &str) -> Option<String> {
        match name {
            "NANO_LAKE_ACCESS_KEY_ID" => Some("access".into()),
            "NANO_LAKE_SECRET_ACCESS_KEY" => Some("secret".into()),
            _ => None,
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn init_renders_a_valid_cell_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let first = init(&args(&out), &env).unwrap();
        assert_eq!(first["created"], true);
        let tenant = first["tenant_id"].as_str().unwrap().to_string();
        assert!(uuid::Uuid::parse_str(&tenant).is_ok());
        let secret = out.join("cell/secret");
        assert_eq!(mode(&secret), 0o700);
        assert_eq!(mode(&secret.join(&tenant).join("ingest.token")), 0o400);
        assert_eq!(mode(&out.join("app/router-query.token")), 0o400);
        // The supervisor accepts the dev key dir.
        crate::secrets::DirKeySource::new(secret.clone()).unwrap();
        let ingest: Value = serde_json::from_slice(&std::fs::read(secret.join(&tenant).join("ingest.token")).unwrap()).unwrap();
        assert_eq!(ingest["bronze"]["access_key_id"], "access");
        assert!(ingest["bronze_list"].is_object());
        let query: Value = serde_json::from_slice(&std::fs::read(secret.join(&tenant).join("query.token")).unwrap()).unwrap();
        assert_eq!(query["trusted_signer_keys"][0]["public_key_hex"], first["signer_public_key_hex"]);
        let cell: Value = serde_json::from_slice(&std::fs::read(out.join("cell/cell.json")).unwrap()).unwrap();
        assert_eq!(cell["trusted_local"], true, "init owns the trusted-local flag");
        assert_eq!(cell["mode"], "dedicated");
        let env_file = std::fs::read_to_string(out.join("app/lake-cell.env")).unwrap();
        assert!(env_file.contains(&format!("NANO_LAKE_TENANT_ID={tenant}\n")));
        // The explicit trusted-local opt-in for api/search/jobs comes only from init.
        assert!(env_file.contains("\nNANO_TRUSTED_LOCAL=1\n"), "{env_file}");
        // routes.json carries exactly this tenant's assignment route.
        let routes: Value = serde_json::from_slice(&std::fs::read(out.join("app/routes.json")).unwrap()).unwrap();
        assert_eq!(routes[&tenant]["cell_origin"], "http://lake-cell:8790");
        let token = std::fs::read_to_string(out.join("app/router-query.token")).unwrap();
        assert_eq!(token, std::fs::read_to_string(secret.join("router-query.token")).unwrap());
        assert_ne!(token, std::fs::read_to_string(secret.join("router.token")).unwrap());

        // Re-run without credentials in env: same tenant, seed and tokens.
        let seed = ingest["lab_signer_seed_hex"].clone();
        let mut bigger = args(&out);
        bigger.memory_bytes = Some(32 * GIB);
        let second = init(&bigger, &|_| None).unwrap();
        assert_eq!(second["created"], false);
        assert_eq!(second["tenant_id"], tenant.as_str());
        let again: Value = serde_json::from_slice(&std::fs::read(secret.join(&tenant).join("ingest.token")).unwrap()).unwrap();
        assert_eq!(again["lab_signer_seed_hex"], seed);
        assert_eq!(again["bronze"]["secret_access_key"], "secret");
        assert_eq!(std::fs::read_to_string(out.join("app/router-query.token")).unwrap(), token);
        let placement: Value = serde_json::from_slice(&std::fs::read(out.join("cell/placement.json")).unwrap()).unwrap();
        assert_eq!(placement["tenants"][0]["query_limit_memory_bytes"], 16 * GIB, "re-render resizes");

        // A different --tenant-id conflicts; --force re-mints.
        let mut other = args(&out);
        other.tenant_id = Some(uuid::Builder::from_random_bytes([7; 16]).into_uuid());
        let error = init(&other, &env).unwrap_err();
        assert!(error.downcast_ref::<Conflict>().is_some());
        other.force = true;
        let forced = init(&other, &env).unwrap();
        assert_eq!(forced["created"], true);
        assert_eq!(forced["tenant_id"], other.tenant_id.unwrap().to_string());
    }

    #[test]
    fn lost_seed_is_a_conflict_not_a_silent_remint() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let first = init(&args(&out), &env).unwrap();
        let tenant = first["tenant_id"].as_str().unwrap();
        std::fs::remove_file(out.join("cell/secret").join(tenant).join("ingest.token")).unwrap();
        let error = init(&args(&out), &env).unwrap_err();
        assert!(error.downcast_ref::<Conflict>().is_some(), "{error:#}");
    }

    #[test]
    fn credentials_are_required_on_first_run() {
        let dir = tempfile::tempdir().unwrap();
        assert!(init(&args(&dir.path().join("out")), &|_| None).is_err());
        assert!(!dir.path().join("out/tenant_id").exists());
    }

    /// A root that looks like a tiny one-shot init container (cgroup 1 GiB /
    /// 1 CPU) on a large host (64 GiB, 68 online CPUs; deliberately not this
    /// test host's CPU count, so a fallback to the caller's own scheduler view
    /// cannot pass by accident).
    fn tiny_container_on_big_host() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let put = |rel: &str, body: &str| {
            let path = root.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        };
        put("proc/meminfo", &format!("MemTotal:       {} kB\nMemFree:         1024 kB\n", 64 * GIB / 1024));
        put("sys/devices/system/cpu/online", "0-1,4-69\n");
        put("sys/fs/cgroup/memory.max", &format!("{}\n", GIB));
        put("sys/fs/cgroup/cpu.max", "100000 100000\n");
        root
    }

    /// NAN-4693 (production path): `init` with no sizing flags, run in a
    /// capped init container, must place the tenant for the HOST the cell
    /// runs on, not for the init container's own cgroup (which used to give
    /// the 2 GiB / 1 CPU floor: eps 60, ingest 1 core / 512 MiB).
    #[test]
    fn tiny_init_container_still_places_a_host_sized_tenant() {
        let host = tiny_container_on_big_host();
        assert_eq!(detect_host(host.path()).unwrap(), HostFacts { memory_bytes: 64 * GIB, cpus: 68 });
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let a = InitArgs { memory_bytes: None, cpus: None, host_root: host.path().to_path_buf(), ..args(&out) };
        let summary = init(&a, &env).unwrap();
        let placement: Value = serde_json::from_slice(&std::fs::read(out.join("cell/placement.json")).unwrap()).unwrap();
        let t = &placement["tenants"][0];
        let want = size(32 * GIB, 68);
        assert_eq!(summary["sizing"]["memory_bytes"], 32 * GIB, "half the host, not half the init cgroup");
        assert_eq!(summary["sizing"]["cpus"], 68, "online host CPUs, not the init cpu.max");
        assert_eq!(t["query_limit_memory_bytes"], want.query.3);
        assert_eq!(t["ingest_limit_memory_bytes"], want.ingest.3);
        assert_eq!(t["ingest_limit_millicores"], want.ingest.1);
        assert_eq!(t["query_limit_millicores"], want.query.1);
        assert_eq!(t["eps"], want.eps as f64);
        assert!(t["ingest_limit_millicores"].as_u64().unwrap() >= 30_000 && t["eps"].as_f64().unwrap() > 1_000.0, "{t}");
        // Explicit flags still win over host facts.
        let flagged = init(&InitArgs { host_root: host.path().to_path_buf(), ..args(&out) }, &env).unwrap();
        assert_eq!(flagged["sizing"]["memory_bytes"], 16 * GIB);
        assert_eq!(flagged["sizing"]["cpus"], 8);
    }

    #[test]
    fn cpu_lists_count_ranges_and_refuse_garbage() {
        assert_eq!(count_cpu_list("0-31"), Some(32));
        assert_eq!(count_cpu_list("0,2-5,8"), Some(6));
        assert_eq!(count_cpu_list("0"), Some(1));
        assert_eq!(count_cpu_list(""), None);
        assert_eq!(count_cpu_list("5-2"), None);
        assert_eq!(count_cpu_list("x"), None);
        assert_eq!(count_cpu_list("0-4294967295"), None, "overflow is refused, not a panic");
    }

    #[test]
    fn sizing_follows_host_memory_not_eps() {
        let small = size(4 * GIB, 2);
        assert_eq!(small.query.3, 2 * GIB);
        assert!(small.query.1 >= 1000);
        let big = size(64 * GIB, 32);
        assert_eq!(big.query.3, 32 * GIB);
        assert_eq!(big.ingest.3, 16 * GIB);
        assert!(big.detect.3 >= crate::budget::DETECT_RULES_MIN_MEMORY_BYTES);
        for s in [&small, &big] {
            assert!(TenantBudget::from_eps(s.eps as f64).ingest_memory_cap_bytes >= s.ingest.3);
            for (rq, lim, rm, lm) in [s.ingest, s.detect, s.query] {
                assert!(rq > 0 && lim >= rq && rm > 0 && lm >= rm);
            }
        }
    }

    #[test]
    fn flags_parse_and_refuse_bad_values() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let parsed = parse_args(&s(&["--out", "/x", "--cpus", "4", "--app-owner", "1000:1000", "--no-require-landlock"])).unwrap();
        assert_eq!(parsed.cpus, Some(4));
        assert_eq!(parsed.app_owner, Some((1000, 1000)));
        assert!(!parsed.require_landlock);
        assert!(parse_args(&s(&[])).is_err(), "--out is required");
        assert!(parse_args(&s(&["--out", "/x", "--tenant-id", "default"])).is_err());
        assert!(parse_args(&s(&["--out", "/x", "--tenant-id", "6F3D1060-5B8E-4D4C-9A3E-0E2B7C9C7106"])).is_err());
        assert!(parse_args(&s(&["--out", "/x", "--memory-bytes", "1024"])).is_err());
        assert!(parse_args(&s(&["--out", "/x", "--wat"])).is_err());
        assert_eq!(args(Path::new("/x")).bronze_port().unwrap(), 9000);
    }
}

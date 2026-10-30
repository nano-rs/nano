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
use serde::{Deserialize, Serialize};
use crate::config::RoleBudget;
use std::path::{Path, PathBuf};

use crate::budget::{ingest_query_for_resources, TenantBudget, GIB, MIB};

/// Exit code: existing state conflicts (no `--force`).
pub const EXIT_CONFLICT: i32 = 3;
/// Exit code: bad usage.
pub const EXIT_USAGE: i32 = 2;

const INGEST_LAB_KIND: &str = "nano.lake.ingest-lab-credentials.v1";
const QUERY_BOOTSTRAP_FORMAT: &str = "nano.lake-query-bootstrap.v1";
const SIGNER_KEY_ID: &str = "trusted-local-signer-0001";
/// `nanosiem_lake_worker::lean_platform_feeds::ALL_BUNDLED_GRANTS_SCHEMA`
/// (this crate sits below the worker; a worker test pins the equality).
pub const ALL_BUNDLED_GRANTS_SCHEMA: &str = "nano/lake-cell-platform-grants-all-bundled/1";

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
    /// Memory for the cell's tenant processes; default the host's cell pool.
    pub memory_bytes: Option<u64>,
    /// CPUs for the cell's tenant processes; default every online host CPU.
    pub cpus: Option<u32>,
    /// NAN-4749: the sustained events per second the install must admit.
    /// Sizes the ingest role for that rate ([`crate::budget::ingest_memory_for_eps`]) and
    /// places the tenant at it; unset keeps the host-derived sizing.
    pub target_eps: Option<u32>,
    /// NAN-4693: root that host facts are read from (`/proc/meminfo`,
    /// `/sys/devices/system/cpu/online`); `/` in production, a fixture in tests.
    pub host_root: PathBuf,
    /// `uid:gid` owning `app/` files (the app services' user).
    pub app_owner: Option<(u32, u32)>,
    pub require_landlock: bool,
    /// NAN-4759: the node platform feed volume inside the cell container
    /// (`<feed_dir>/bundles`: content-addressed bundles and `current.json`,
    /// kept by the `lean-platform-feeds` service).
    pub feed_dir: PathBuf,
    /// NAN-4759: `<policy_root>/<tenant>/policy.json`, outside `feed_dir`.
    pub policy_root: PathBuf,
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
            target_eps: None,
            host_root: "/".into(),
            app_owner: None,
            require_landlock: true,
            feed_dir: "/var/lib/nano-platform-feeds".into(),
            policy_root: "/var/lib/nano-platform-policy".into(),
        }
    }
}

const USAGE: &str = "usage: nanosiem-lake-cell trusted-local init --out <dir> [--tenant-id <uuid>] [--force] \
[--cell-id <id>] [--cell-config-root <path>] [--cell-data-root <path>] [--app-config-root <path>] \
[--listen <addr:port>] [--cell-origin <url>] [--bronze-endpoint <url>] [--bronze-region <r>] \
[--bronze-bucket <b>] [--bronze-prefix <p>] [--bin-dir <path>] [--chdb-library <path>] [--chdb-sha256 <hex>] \
[--compiler <path>] [--memory-bytes <n>] [--cpus <n>] [--target-eps <n>] [--app-owner <uid:gid>] [--no-require-landlock] \
[--feed-dir <path>] [--policy-root <path>]";

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
            "--feed-dir" => out.feed_dir = take(&mut i)?.into(),
            "--policy-root" => out.policy_root = take(&mut i)?.into(),
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
            "--target-eps" => {
                let v = take(&mut i)?;
                out.target_eps = Some(v.parse().map_err(|_| bad(format!("--target-eps {v:?} is not a number")))?);
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
            ("--chdb-library", &self.chdb_library), ("--compiler", &self.compiler),
            ("--feed-dir", &self.feed_dir), ("--policy-root", &self.policy_root)] {
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
        ensure!(self.memory_bytes.is_none_or(|m| m >= 512 * MIB), "--memory-bytes must be at least 512 MiB");
        ensure!(self.cpus.is_none_or(|c| (1..=1024).contains(&c)), "--cpus must be 1..1024");
        ensure!(self.target_eps.is_none_or(|e| (1..=MAX_TARGET_EPS).contains(&e)), "--target-eps must be 1..{MAX_TARGET_EPS}");
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
    /// eps chosen so the eps-derived ingest cap does not undercut the
    /// placed ingest limit (the supervisor takes the smaller of the two),
    /// or the `--target-eps` when that is higher (NAN-4749).
    pub eps: u32,
    pub ingest: (u32, u32, u64, u64),
    pub detect: (u32, u32, u64, u64),
    pub query: (u32, u32, u64, u64),
    pub local_resources: LocalResources,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalResources {
    /// Template only: generated open-core cells keep product_state_role off.
    pub product: RoleBudget,
    /// Valid native-role template, inactive in generated open-core plans.
    /// Compose's lean-landing owns the funded landing memory instead.
    pub landing: RoleBudget,
    /// Template only: trusted-local ingest compacts its embedded state.
    pub maintenance: RoleBudget,
}

/// One host CPU plan, in shares out of 10,000. The cell receives 60%;
/// Compose siblings receive 40%. These are contention weights, never quotas:
/// unused capacity is lent to any runnable role. Query outranks ingestion;
/// ingest admission owns the backlog rather than competing with analysts.
pub const HOST_CPU_SHARES: u32 = 10_000;
pub const CELL_CPU_SHARES: u32 = 6_000;
pub const COMPOSE_CPU_SHARES: [(&str, u32); 20] = [
    ("postgres", 150), ("lake-object-store", 300), ("dragonfly", 50),
    ("nano-api", 200), ("nano-search", 1200), ("nano-jobs", 100),
    ("vector", 250), ("tenzir", 250), ("lean-landing", 1000),
    ("connector-runner", 100), ("nano-web", 30), ("nginx", 30),
    ("lean-otel", 100), ("lean-enrichment", 50), ("lean-job-runner", 40),
    ("lean-result-gc", 20), ("lean-audit", 40), ("lean-platform-feeds", 20),
    ("lean-audit-vector", 50), ("lean-hec-proxy", 20),
];

pub fn role_cpu_shares(role: crate::contract::Role) -> u32 {
    use crate::contract::Role;
    match role {
        Role::Query => 3000, Role::Ingest => 1500, Role::Detect => 500,
        Role::Product => 300, Role::Landing => 600, Role::Maintenance => 100,
    }
}

/// Watchdog-only installs have no role cgroups. Linux nice weights provide
/// the same ordering without CAP_SYS_NICE; set before exec so every runtime
/// and native thread inherits it. Query stays at nice 0, ingest at nice 3.
pub fn role_nice(role: crate::contract::Role) -> i32 {
    const NICE_WEIGHTS: [u32; 20] = [1024, 820, 655, 526, 423, 335, 272, 215, 172, 137,
        110, 87, 70, 56, 45, 36, 29, 23, 18, 15];
    let target = role_cpu_shares(role) * 1024 / role_cpu_shares(crate::contract::Role::Query);
    NICE_WEIGHTS.iter().enumerate().min_by_key(|(_, weight)| weight.abs_diff(target)).unwrap().0 as i32
}

pub fn cpu_share_millicores(capacity: u32, shares: u32) -> u32 {
    (u64::from(capacity) * u64::from(shares) / u64::from(HOST_CPU_SHARES)) as u32
}

/// The open-core bucket-drop converter's (request, burst) CPU budget.
/// Keep this with the renderer's plan so concurrency and weights cannot drift.
pub fn landing_cpu_budget(capacity: u32) -> (u32, u32) {
    let shares = COMPOSE_CPU_SHARES.iter().find(|(name, _)| *name == "lean-landing").unwrap().1;
    (cpu_share_millicores(capacity, shares).max(1), capacity.max(1))
}

fn round_mib(bytes: u64) -> u64 {
    bytes / MIB * MIB
}

#[derive(Deserialize)]
struct StartupFloor {
    guard_mib: u64,
    peak_bytes: u64,
    #[serde(default)]
    idle_rss_bytes: u64,
}

impl StartupFloor {
    fn bytes(&self) -> u64 {
        // Captures can report idle RSS above the recorded startup peak. Pay
        // both measurements plus 25% headroom, rounded UP, before surplus.
        (self.guard_mib * MIB)
            .max((self.peak_bytes.max(self.idle_rss_bytes) * 5).div_ceil(4))
            .div_ceil(MIB) * MIB
    }
}

#[derive(Deserialize)]
struct StartupMemory {
    minimum_host_gib: u64,
    kernel_reserve_mib: u64,
    cell_mib: std::collections::BTreeMap<String, u64>,
    services: std::collections::BTreeMap<String, StartupFloor>,
}

fn startup_memory() -> &'static StartupMemory {
    static POLICY: std::sync::OnceLock<StartupMemory> = std::sync::OnceLock::new();
    POLICY.get_or_init(|| serde_json::from_str(include_str!("../../config/lean-startup-memory.json"))
        .expect("compiled lean startup memory policy"))
}

pub fn minimum_install_memory_bytes() -> u64 {
    minimum_install_memory_for_ingest(true)
}

fn selected_service(name: &str, vector: bool) -> bool {
    if vector { name != "tenzir" } else { name != "vector" && name != "connector-runner" && name != "lean-hec-proxy" }
}

fn compose_startup_minimum(vector: bool) -> u64 {
    startup_memory().services.iter().filter(|(name, _)| selected_service(name, vector))
        .map(|(name, floor)| service_startup_minimum(name, floor)).sum()
}

fn service_startup_minimum(name: &str, floor: &StartupFloor) -> u64 {
    if name == "lean-landing" {
        floor.bytes().max(crate::landing_budget::memory_for_lanes(1))
    } else {
        floor.bytes()
    }
}

fn small_cell_memory_for_eps(eps: u32) -> u64 {
    let policy = startup_memory();
    let budget = TenantBudget::from_eps(eps as f64);
    let fixed = policy.cell_mib.iter().filter(|(name, _)| name.as_str() != "query" && name.as_str() != "ingest")
        .map(|(_, mib)| mib * MIB).sum::<u64>();
    fixed + budget.ingest_memory_cap_bytes
        + budget.query_memory_cap_bytes.max(policy.cell_mib["query"] * MIB)
}

fn minimum_install_memory_for_ingest(vector: bool) -> u64 {
    let minimum = compose_startup_minimum(vector) + small_cell_memory_for_eps(20);
    // A nominal 8 GiB VM loses up to 512 MiB to kernel reservation. Pay
    // service/cell floors plus 5% OS space from the actual MemTotal; tolerance
    // never rounds the measured host capacity up or weakens the budget fit.
    ((minimum * 100).div_ceil(95).div_ceil(MIB) * MIB)
        .max(startup_memory().minimum_host_gib * GIB - startup_memory().kernel_reserve_mib * MIB)
}

fn small_cell_supported_eps(memory: u64) -> u32 {
    (20..=MAX_TARGET_EPS).take_while(|eps| small_cell_memory_for_eps(*eps) <= memory).last().unwrap_or(0)
}

/// Startup minima are paid first. Compose shares surplus by weight, and the
/// cell receives the remainder of the 95% envelope. Unsupported hosts still
/// render diagnostic output; install.sh refuses them before any mutation.
pub fn host_cell_memory_bytes(host_memory: u64) -> u64 {
    host_cell_memory_for_ingest(host_memory, true)
}

fn host_cell_memory_for_ingest(host_memory: u64, vector: bool) -> u64 {
    let minimum = compose_startup_minimum(vector);
    round_mib(host_memory_share(host_memory, 95).saturating_sub(host_memory_share(host_memory, 45).max(minimum)))
}

fn host_memory_share(memory: u64, percent: u64) -> u64 {
    memory / 100 * percent + memory % 100 * percent / 100
}

pub fn size(memory_bytes: u64, cpus: u32) -> Sizing {
    size_for(memory_bytes, cpus, None)
}

/// Highest `--target-eps` accepted.
pub const MAX_TARGET_EPS: u32 = 1_000_000;

/// [`size`] for a target rate (NAN-4749). With `target_eps` the ingest role
/// gets at least [`crate::budget::ingest_memory_for_eps`] (up to half the cell's memory,
/// taken from query's share, preserving the shared two-slot floor) and the tenant
/// is placed at `target_eps` (owner pacing, part cache), or the
/// memory-derived eps when that is higher. With no rate, use the same shared
/// ingest floor within the available query surplus: background merges need
/// headroom alongside admission, even without an explicit target rate.
pub fn size_for(memory_bytes: u64, cpus: u32, target_eps: Option<u32>) -> Sizing {
    let cpus = cpus.max(1);
    // Keep native overhead inside the cell before sharing the remainder.
    // QueryMemoryBudget reserves 384 MiB outside a >=128 MiB engine;
    // Open core runs landing separately in Compose, and leaves the separate
    // product and maintenance roles disabled. Keep valid auxiliary templates
    // without reserving memory for processes the supervisor does not start.
    // Below the supported full-install shape, render diagnostic budgets only.
    let cell_floor = &startup_memory().cell_mib;
    let full_install = memory_bytes >= small_cell_memory_for_eps(20);
    let small_eps = if memory_bytes < 4 * GIB { small_cell_supported_eps(memory_bytes) } else { 0 };
    let (product_mem, landing_mem, maintenance_mem, supervisor_mem) = if full_install {
        (round_mib(memory_bytes / 25).max(512 * MIB),
         round_mib(memory_bytes / 25).max(GIB),
         round_mib(memory_bytes / 100).max(512 * MIB),
         round_mib(memory_bytes / 100).max(64 * MIB))
    } else {
        (round_mib(memory_bytes / 25), round_mib(memory_bytes / 25),
         round_mib(memory_bytes / 100), round_mib(memory_bytes / 100))
    };
    let core = memory_bytes.saturating_sub(supervisor_mem);
    let mut base_query = round_mib(core / 9 * 5);
    let mut base_ingest = round_mib(core / 18 * 5);
    let mut detect_mem = round_mib(core.saturating_sub(base_query + base_ingest));
    if small_eps > 0 {
        // The existing hobby/small-tenant curve budgets a bounded low-rate
        // ingest worker, rather than reserving the larger-host role split.
        // Query still keeps its native runtime headroom and two 64 MiB slots.
        let budget = TenantBudget::from_eps(small_eps as f64);
        base_ingest = budget.ingest_memory_cap_bytes;
        base_query = budget.query_memory_cap_bytes.max(cell_floor["query"] * MIB);
        detect_mem = cell_floor["detect"] * MIB;
    } else if full_install {
        // Below the old 4 GiB cell split, preserve the actual role floors
        // instead of dropping the auxiliary roles into diagnostic sizing.
        base_ingest = base_ingest.max(512 * MIB);
        detect_mem = detect_mem.max(cell_floor["detect"] * MIB);
        base_query = round_mib(core.saturating_sub(base_ingest + detect_mem));
    }
    let (ingest_mem, query_mem) = ingest_query_for_resources(base_ingest, base_query,
        target_eps.unwrap_or(crate::budget::PARALLEL_FLUSH_EPS as u32), round_mib(memory_bytes / 2),
        cpus.saturating_mul(1000));
    let milli = cpus.saturating_mul(1000);
    let cpu_request = |role| cpu_share_millicores(milli, role_cpu_shares(role));
    use crate::contract::Role;
    // `eps` is a sizing input here: the role budgets above are explicit,
    // but the supervisor still caps ingest at the eps-derived
    // `ingest_memory_cap_bytes`, so pick the smallest eps whose cap covers
    // the placed ingest limit (the curve extrapolates linearly). A target
    // rate above that places the tenant at the target.
    let covering = (20..=MAX_TARGET_EPS)
        .step_by(10)
        .find(|eps| TenantBudget::from_eps(*eps as f64).ingest_memory_cap_bytes >= ingest_mem)
        .unwrap_or(MAX_TARGET_EPS);
    let eps = if small_eps > 0 { small_eps } else { covering.max(target_eps.unwrap_or(0)) };
    let req = |mem: u64| round_mib(mem / 4).max(MIB).min(mem);
    let auxiliary = |mem: u64, role| {
        RoleBudget { request_millicores: cpu_request(role), limit_millicores: milli,
            request_memory_bytes: req(mem), limit_memory_bytes: mem }
    };
    Sizing {
        memory_bytes,
        cpus,
        eps,
        ingest: (cpu_request(Role::Ingest), milli, req(ingest_mem), ingest_mem),
        detect: (cpu_request(Role::Detect), milli, req(detect_mem), detect_mem),
        query: (cpu_request(Role::Query), milli, req(query_mem), query_mem),
        local_resources: LocalResources {
            product: auxiliary(product_mem, Role::Product),
            landing: auxiliary(landing_mem, Role::Landing),
            maintenance: auxiliary(maintenance_mem, Role::Maintenance),
        },
    }
}

/// Compose's running services share at least 45% of host RAM, with startup
/// minima reserved before surplus is divided by weight. The cell takes the
/// remainder of the 95% host envelope. CPU quotas
/// permit each service to burst across the host, as the role quotas do.
/// JSON is valid YAML and avoids introducing operator environment knobs.
pub fn compose_resources(sizing: &Sizing, host: HostFacts, sovereign: bool) -> Value {
    compose_resources_for_ingest(sizing, host, sovereign, true)
}

fn compose_resources_for_ingest(sizing: &Sizing, host: HostFacts, sovereign: bool, vector_ingest: bool) -> Value {
    let weights = [
        ("postgres", 8), ("lake-object-store", 16), ("dragonfly", 5),
        ("nano-api", 10), ("nano-search", 8), ("nano-jobs", 12),
        ("vector", 8), ("tenzir", 8), ("lean-landing", 8),
        ("connector-runner", 4), ("nano-web", 1), ("nginx", 1),
        ("lean-otel", 4), ("lean-enrichment", 2), ("lean-job-runner", 2),
        ("lean-result-gc", 1), ("lean-audit", 1), ("lean-platform-feeds", 1),
        ("lean-audit-vector", 4), ("lean-hec-proxy", 1),
    ];
    let total: u64 = weights.iter().filter(|(name, _)| selected_service(name, vector_ingest) && *name != "lean-landing").map(|(_, w)| w).sum();
    let policy = startup_memory();
    let compose_minimum = compose_startup_minimum(vector_ingest);
    let pool = host_memory_share(host.memory_bytes, 45).max(compose_minimum);
    // Replace the single-lane minimum with whole fitted lanes, after paying
    // every sibling's startup floor. Landing gets at most one third of the
    // pool; unused lane demand returns to the other services by weight.
    let landing_floor = service_startup_minimum("lean-landing", &policy.services["lean-landing"]);
    let landing_budget = (pool / 3).max(landing_floor)
        .min(pool - (compose_minimum - landing_floor));
    let (lanes, _) = crate::landing_budget::limits(landing_budget, host.cpus.saturating_mul(1000));
    let landing = crate::landing_budget::memory_for_lanes(lanes);
    let surplus = pool - (compose_minimum - landing_floor) - landing;
    let mut services = serde_json::Map::new();
    for (name, weight) in weights {
        if !selected_service(name, vector_ingest) { continue; }
        let cpu_shares = COMPOSE_CPU_SHARES.iter().find(|(service, _)| *service == name).unwrap().1;
        let memory = if name == "lean-landing" { landing } else {
            service_startup_minimum(name, &policy.services[name]) + round_mib(surplus / total * weight)
        };
        services.insert(name.into(), json!({
            "mem_limit": memory, "memswap_limit": memory,
            "cpus": host.cpus, "cpu_shares": cpu_shares,
            "deploy": {"resources": {"limits": {"memory": memory.to_string(), "cpus": host.cpus}}},
        }));
    }
    services.insert("lake-cell".into(), json!({
        "mem_limit": sizing.memory_bytes, "memswap_limit": sizing.memory_bytes,
        "cpus": sizing.cpus, "cpu_shares": CELL_CPU_SHARES,
    }));
    let pg_memory = services["postgres"]["mem_limit"].as_u64().unwrap();
    let mut pg = vec!["-c".to_owned(), "max_connections=200".into(), "-c".into(),
        format!("shared_buffers={}MB", (pg_memory / 4 / MIB).max(1)),
        "-c".into(), "tcp_keepalives_idle=30".into(), "-c".into(), "tcp_keepalives_interval=10".into(),
        "-c".into(), "tcp_keepalives_count=3".into(), "-c".into(), "tcp_user_timeout=45s".into()];
    if sovereign {
        for option in ["ssl=on", "ssl_cert_file=/etc/nano-sovereign-pg/server.crt",
            "ssl_key_file=/etc/nano-sovereign-pg/server.key", "ssl_min_protocol_version=TLSv1.2",
            "hba_file=/etc/nano-sovereign-pg/pg_hba.conf"] {
            pg.extend(["-c".into(), option.into()]);
        }
    }
    services["postgres"]["command"] = json!(pg);
    let dragonfly = services["dragonfly"]["mem_limit"].as_u64().unwrap();
    let dragonfly_maxmemory_mib = (dragonfly / 100 * 60 / MIB).max(1);
    let dragonfly_threads = u64::from((host.cpus / 4).clamp(1, 32))
        .min(dragonfly_maxmemory_mib / 256).max(1);
    services["dragonfly"]["command"] = json!([
        format!("--maxmemory={dragonfly_maxmemory_mib}mb"),
        format!("--proactor_threads={dragonfly_threads}"),
        "--cache_mode=false".to_owned(), "--dir=/data".to_owned(), "--dbfilename=nano-dragonfly".to_owned(),
        "--snapshot_cron=${NANO_DRAGONFLY_SNAPSHOT_CRON:-* * * * *}".to_owned(),
    ]);
    if vector_ingest {
        let runner_memory = services["connector-runner"]["mem_limit"].as_u64().unwrap();
        // Match the runner's check_vrl_memory: 256 MiB address space plus
        // 3 x 64 MiB call I/O per worker, and a 256 MiB daemon reserve.
        // Emit both existing settings so the worker cap and its sizing stay paired.
        let runner_workers = (runner_memory.saturating_sub(256 * MIB) / (448 * MIB)).clamp(1, 4);
        services["connector-runner"]["environment"] = json!({
            "CONNECTOR_VRL_MAX_WORKERS": runner_workers.to_string(),
            "CONNECTOR_VRL_WORKER_AS_BYTES": (256 * MIB).to_string(),
        });
        let vector = services["vector"]["mem_limit"].as_u64().unwrap();
        services["vector"]["environment"] = json!({
            // The queue and its active batch together use <= 1/8 of the container.
            "VECTOR_LAKE_BUFFER_MAX_BYTES": (vector / 16).to_string(),
            "VECTOR_LAKE_BATCH_MAX_BYTES": (vector / 16).to_string(),
        });
    }
    if host.memory_bytes <= 8 * GIB {
        // Trial hosts need fewer live worker stacks and database backends,
        // not limits below their measured idle footprint. Existing runtime
        // settings are rendered automatically; larger hosts retain defaults.
        for name in ["nano-api", "nano-search", "nano-jobs"] {
            services[name]["environment"] = json!({
                "PG_MIN_CONNECTIONS": "0", "PG_MAX_CONNECTIONS": "4",
                "PG_IDLE_TIMEOUT": "10", "TOKIO_WORKER_THREADS": "2",
            });
        }
        services["lean-audit-vector"]["environment"] = json!({"VECTOR_THREADS": "1"});
        if vector_ingest {
            services["vector"]["environment"]["VECTOR_THREADS"] = json!("1");
        }
        let command = services["postgres"]["command"].as_array_mut().unwrap();
        for setting in command.iter_mut() {
            match setting.as_str() {
                Some("max_connections=200") => *setting = json!("max_connections=128"),
                Some(value) if value.starts_with("shared_buffers=") => *setting = json!("shared_buffers=16MB"),
                _ => {},
            }
        }
        for setting in ["work_mem=1MB", "maintenance_work_mem=16MB", "autovacuum_work_mem=16MB",
            "autovacuum_max_workers=1", "autovacuum_worker_slots=2"] {
            command.extend([json!("-c"), json!(setting)]);
        }
    }
    json!({"services": services, "x-nano-host-sizing": {
        "memory_bytes": host.memory_bytes, "cpus": host.cpus,
        "minimum_install_memory_bytes": minimum_install_memory_for_ingest(vector_ingest),
        "compose_minimum_memory_bytes": compose_minimum,
        "cell_minimum_memory_bytes": small_cell_memory_for_eps(20),
        "supported": host.memory_bytes >= minimum_install_memory_for_ingest(vector_ingest),
        "ingest_agent": if vector_ingest { "vector" } else { "tenzir" },
        "supported_eps": sizing.eps,
    }})
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
    let vector_ingest = env("NANO_VECTOR_PROFILE").as_deref() != Some("none");
    let memory = args.memory_bytes.unwrap_or_else(|| host_cell_memory_for_ingest(host.map_or(0, |h| h.memory_bytes), vector_ingest));
    let cpus = args.cpus.unwrap_or_else(|| host.map_or(1, |h| h.cpus));
    let sizing = size_for(memory.max(512 * MIB), cpus, args.target_eps);
    if let Some(target) = args.target_eps.filter(|_| memory < 4 * GIB && memory >= small_cell_memory_for_eps(20)) {
        ensure!(target <= sizing.eps, "this small-host allocation supports {} EPS; requested --target-eps {target} needs a larger host", sizing.eps);
    }
    let compose_host = host.unwrap_or(HostFacts { memory_bytes: memory.saturating_mul(2), cpus });
    let compose = compose_resources_for_ingest(&sizing, compose_host,
        env("NANO_LEAN_PG_DSN_DIR").is_some(), vector_ingest);
    if compose_host.memory_bytes >= minimum_install_memory_for_ingest(vector_ingest) {
        let total: u64 = compose["services"].as_object().unwrap().values()
            .map(|s| s["mem_limit"].as_u64().unwrap()).sum();
        ensure!(total <= host_memory_share(compose_host.memory_bytes, 95),
            "requested cell memory plus service startup minimums exceeds 95% of the host; omit --memory-bytes for host sizing");
    }

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
    // Bootstrap and data can be separate mounts. Carry the demand ceiling;
    // the reader clamps it against its actual cache filesystem at startup.
    let cache_bytes = TenantBudget::from_eps(sizing.eps as f64).cache_disk_bytes;
    let query_doc = json!({
        "format": QUERY_BOOTSTRAP_FORMAT,
        "tenant_id": tenant_s,
        "bucket": args.bronze_bucket,
        "trusted_signer_keys": [{"key_id": SIGNER_KEY_ID, "public_key_hex": public_hex}],
        "engine": {
            "chdb_library": args.chdb_library, "chdb_sha256": chdb_sha256, "compiler": args.compiler,
            "cache_bytes": cache_bytes,
            "cache_query_bytes": (sizing.query.3 / 4).min(cache_bytes / 4).max(1),
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
        // Landing runs in the separately budgeted lean-landing container.
        "tenzir_landing": false,
        "product_state_role": false,
        "prevalence_maintenance": false,
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
        // NAN-4759: platform enrichment (IPinfo Lite geo/ASN, ThreatFox, Tor)
        // through the same bundle dir + per-tenant policy a hosted cell reads.
        "feed_dir": args.feed_dir,
        "platform_bundle_dir": args.feed_dir.join("bundles"),
    });
    let (i, d, q) = (sizing.ingest, sizing.detect, sizing.query);
    let placement = json!({
        "cell_id": args.cell_id,
        "revision": 1,
        "tenants": [{
            "tenant_id": tenant_s,
            "eps": sizing.eps as f64,
            "ingest": "resident",
            "landing": false,
            "ingest_request_millicores": i.0, "ingest_limit_millicores": i.1,
            "ingest_request_memory_bytes": i.2, "ingest_limit_memory_bytes": i.3,
            "detect_request_millicores": d.0, "detect_limit_millicores": d.1,
            "detect_request_memory_bytes": d.2, "detect_limit_memory_bytes": d.3,
            "query_request_millicores": q.0, "query_limit_millicores": q.1,
            "query_request_memory_bytes": q.2, "query_limit_memory_bytes": q.3,
            "local_resources": sizing.local_resources,
            "platform_policy_file": args.policy_root.join(&tenant_s).join("policy.json"),
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
    write_file(&out.join("compose.resources.json"), &serde_json::to_vec_pretty(&compose)?, 0o644, None)?;
    write_file(&out.join("app/routes.json"), &serde_json::to_vec_pretty(&routes)?, 0o644, args.app_owner)?;
    write_file(&out.join("app/lake-cell.env"), app_env.as_bytes(), 0o644, args.app_owner)?;
    // NAN-4759: the self-hosted default grant (every bundled feed, at the
    // installed bundle's revision, until its hard expiry), read by the
    // `lean-platform-feeds` publisher (`lean_platform_feeds`).
    ensure_dir(&out.join("platform-grants"), 0o755)?;
    let grants = json!({"schema": ALL_BUNDLED_GRANTS_SCHEMA, "tenant_id": tenant_s, "rows": []});
    // One tenant per install: a `--force` re-mint drops the old tenant's grant.
    for entry in std::fs::read_dir(out.join("platform-grants"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") && path.file_stem().is_some_and(|s| s != tenant_s.as_str()) {
            std::fs::remove_file(path)?;
        }
    }
    write_file(&out.join("platform-grants").join(format!("{tenant_s}.json")), &serde_json::to_vec_pretty(&grants)?, 0o644, None)?;
    write_file(&out.join("tenant_id"), format!("{tenant_s}\n").as_bytes(), 0o644, None)?;
    Ok(json!({
        "tenant_id": tenant_s,
        "created": created,
        "signer_key_id": SIGNER_KEY_ID,
        "signer_public_key_hex": public_hex,
        "sizing": {
            "memory_bytes": sizing.memory_bytes, "cpus": sizing.cpus, "eps": sizing.eps,
            "target_eps": args.target_eps,
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
    fn nan4843_all_startup_minima_fit_the_derived_host_threshold() {
        let policy = startup_memory();
        assert_eq!(policy.services.len(), COMPOSE_CPU_SHARES.len());
        let minimum = minimum_install_memory_bytes();
        let cell_minimum = small_cell_memory_for_eps(20);
        assert_eq!(policy.cell_mib["ingest"] * MIB, TenantBudget::from_eps(20.0).ingest_memory_cap_bytes);
        let compose_minimum = compose_startup_minimum(true);
        assert!(host_cell_memory_bytes(minimum) >= cell_minimum);
        assert!(compose_startup_minimum(true) + cell_minimum <= host_memory_share(minimum, 95));
        assert_eq!(minimum, 7683 * MIB);
        // Idle RSS is paid even when that exposes an unsupported host.
        assert!(!policy.cell_mib.contains_key("landing"));
        assert_eq!(cell_minimum, 1037 * MIB);
        assert_eq!(policy.services["lean-landing"].bytes(), crate::landing_budget::memory_for_lanes(1));
        let small = size(host_cell_memory_bytes(minimum), 8);
        assert!(small.eps >= 20);
        assert!(small_cell_memory_for_eps(small.eps) <= small.memory_bytes);
        assert!(small_cell_memory_for_eps(small.eps + 1) > small.memory_bytes);
        for memory in [minimum, 9 * GIB, 12 * GIB, 15_965 * MIB, 16 * GIB, 24 * GIB, 32 * GIB, 64 * GIB, 256 * GIB] {
            for cpus in 2..=64 {
                for sovereign in [false, true] {
                    let sizing = size(host_cell_memory_bytes(memory), cpus);
                    let rendered = compose_resources(&sizing, HostFacts { memory_bytes: memory, cpus }, sovereign);
                    let services = rendered["services"].as_object().unwrap();
                    let total: u64 = services.values().map(|v| v["mem_limit"].as_u64().unwrap()).sum();
                    assert!(total <= host_memory_share(memory, 95), "total={total} memory={memory}");
                    for (name, floor) in policy.services.iter().filter(|(name, _)| selected_service(name, true)) {
                        assert!(floor.peak_bytes > 0, "every service has measurement evidence: {name}");
                        let limit = services[name]["mem_limit"].as_u64().unwrap();
                        assert!(limit >= floor.bytes(), "{name}");
                        assert_eq!(services[name]["memswap_limit"], limit);
                        assert_eq!(services[name]["deploy"]["resources"]["limits"]["memory"], limit.to_string());
                    }
                    for (name, value) in [("ingest", sizing.ingest.3), ("query", sizing.query.3), ("detect", sizing.detect.3)] {
                        assert!(value >= policy.cell_mib[name] * MIB, "{name}");
                    }
                    if memory == minimum || memory == 16 * GIB {
                        if cpus == 8 && !sovereign {
                            println!("NAN4843_RENDER {}", json!({"memory": memory, "cpus": cpus, "compose": rendered}));
                        }
                    }
                    assert_eq!(rendered["x-nano-host-sizing"]["compose_minimum_memory_bytes"], compose_minimum);
                }
            }
        }
    }

    #[test]
    fn nan4843_initializer_budgets_only_the_selected_ingest_agent() {
        for (vector, memory) in [(false, 7934 * MIB), (true, 7934 * MIB), (false, 8 * GIB), (true, 8 * GIB)] {
            let host = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(host.path().join("proc")).unwrap();
            std::fs::create_dir_all(host.path().join("sys/devices/system/cpu")).unwrap();
            std::fs::write(host.path().join("proc/meminfo"), format!("MemTotal: {} kB\n", memory / 1024)).unwrap();
            std::fs::write(host.path().join("sys/devices/system/cpu/online"), "0-7").unwrap();
            let out = host.path().join("out");
            let args = InitArgs { host_root: host.path().into(), memory_bytes: None, cpus: None, ..args(&out) };
            let get_env = |name: &str| if name == "NANO_VECTOR_PROFILE" {
                Some(if vector { "lean" } else { "none" }.to_owned())
            } else { env(name) };
            init(&args, &get_env).unwrap();
            let rendered: Value = serde_json::from_slice(&std::fs::read(out.join("compose.resources.json")).unwrap()).unwrap();
            let services = rendered["services"].as_object().unwrap();
            assert_eq!(services.contains_key("vector"), vector);
            assert_eq!(services.contains_key("connector-runner"), vector);
            assert_eq!(services.contains_key("tenzir"), !vector);
            assert_eq!(rendered["x-nano-host-sizing"]["minimum_install_memory_bytes"], if vector { 7683 * MIB } else { 7680 * MIB });
            assert_eq!(rendered["x-nano-host-sizing"]["supported"], true);
            // The 9.1M storage probe reached 458 MiB process RSS. Both agents
            // reserve its measured peak plus 25%; reclaimable cgroup file
            // cache is accounted separately.
            assert!(services["lake-object-store"]["mem_limit"].as_u64().unwrap() >= 573 * MIB);
            let cell = services["lake-cell"]["mem_limit"].as_u64().unwrap();
            let eps = rendered["x-nano-host-sizing"]["supported_eps"].as_u64().unwrap() as u32;
            assert!(small_cell_memory_for_eps(eps) <= cell);
            assert!(small_cell_memory_for_eps(eps + 1) > cell);
            assert!(services.values().map(|s| s["mem_limit"].as_u64().unwrap()).sum::<u64>() <= memory / 100 * 95);
            let before = std::fs::read(out.join("cell/placement.json")).unwrap();
            assert!(init(&InitArgs { target_eps: Some(eps + 1), ..args.clone() }, &get_env).is_err());
            assert_eq!(std::fs::read(out.join("cell/placement.json")).unwrap(), before);
            let placement: crate::config::Placement = serde_json::from_slice(&before).unwrap();
            let cfg: crate::config::CellConfig = serde_json::from_slice(&std::fs::read(out.join("cell/cell.json")).unwrap()).unwrap();
            let tenant = &placement.tenants[0];
            assert!(!crate::supervisor::landing_wanted(cfg.tenzir_landing, Some(tenant)));
            let capacity = crate::resources::CellCapacity { cpu_millicores: 8000, memory_bytes: cell,
                cpu_source: "config", memory_source: "config" };
            let limits = crate::resources::TenantLimits::from_placement_for_cell(tenant, &capacity, &cfg);
            // The real supervisor pays only active roles. Auxiliary templates
            // become reservations only if their existing feature is enabled.
            assert!(!cfg.product_state_role && !cfg.prevalence_maintenance);
            assert!(limits.memory_hard_bytes + 64 * MIB <= cell);
            let active = tenant.effective_role_budget(crate::contract::Role::Ingest).limit_memory_bytes
                + tenant.effective_role_budget(crate::contract::Role::Query).limit_memory_bytes
                + tenant.effective_role_budget(crate::contract::Role::Detect).limit_memory_bytes;
            assert_eq!(limits.memory_hard_bytes, active);
            let mut enabled = cfg.clone();
            enabled.prevalence_maintenance = true;
            let with_maintenance = crate::resources::TenantLimits::from_placement_for_cell(tenant, &capacity, &enabled);
            assert_eq!(with_maintenance.memory_hard_bytes, active + tenant.local_resources.as_ref().unwrap().maintenance.limit_memory_bytes);
            let mut hosted = cfg.clone();
            hosted.trusted_local = false;
            assert_eq!(crate::resources::TenantLimits::from_placement_for_cell(tenant, &capacity, &hosted).memory_hard_bytes,
                crate::resources::TenantLimits::from_placement(tenant, &capacity, &hosted.resources).memory_hard_bytes);
            let with_product = crate::supervisor::with_product_role(limits.clone(), tenant);
            assert_eq!(with_product.memory_hard_bytes, active + tenant.local_resources.as_ref().unwrap().product.limit_memory_bytes);
            // Re-run against a grown host, with no sizing overrides. Keep
            // identity while replacing both placement and Compose budgets.
            let token = std::fs::read(out.join("app/router-query.token")).unwrap();
            std::fs::write(host.path().join("proc/meminfo"), format!("MemTotal: {} kB\n", 16 * GIB / 1024)).unwrap();
            std::fs::write(host.path().join("sys/devices/system/cpu/online"), "0-15").unwrap();
            assert_eq!(init(&args, &get_env).unwrap()["created"], false);
            let grown: Value = serde_json::from_slice(&std::fs::read(out.join("compose.resources.json")).unwrap()).unwrap();
            assert_eq!(grown["services"]["lake-cell"]["mem_limit"], 8 * GIB);
            assert_eq!(grown["services"]["lake-cell"]["cpus"], 16);
            assert!(grown["x-nano-host-sizing"]["supported_eps"].as_u64().unwrap() > u64::from(eps));
            let grown_placement: crate::config::Placement = serde_json::from_slice(&std::fs::read(out.join("cell/placement.json")).unwrap()).unwrap();
            assert_eq!(grown_placement.tenants[0].tenant_id, tenant.tenant_id);
            assert!(grown_placement.tenants[0].effective_role_budget(crate::contract::Role::Ingest).limit_memory_bytes
                > tenant.effective_role_budget(crate::contract::Role::Ingest).limit_memory_bytes);
            assert_eq!(std::fs::read(out.join("app/router-query.token")).unwrap(), token);
            println!("NAN4843_SELECTED {}", rendered["x-nano-host-sizing"]);
        }
    }

    #[test]
    fn nan4850_initializer_caps_cover_recorded_idle_rss() {
        let measurements: Value = serde_json::from_str(include_str!("../../config/lean-startup-memory.json")).unwrap();
        for vector in [true, false] {
            for memory in [7934 * MIB, 8 * GIB, minimum_install_memory_for_ingest(vector), 16 * GIB, 32 * GIB, 64 * GIB] {
                let host = tempfile::tempdir().unwrap();
                std::fs::create_dir_all(host.path().join("proc")).unwrap();
                std::fs::create_dir_all(host.path().join("sys/devices/system/cpu")).unwrap();
                std::fs::write(host.path().join("proc/meminfo"), format!("MemTotal: {} kB\n", memory / 1024)).unwrap();
                std::fs::write(host.path().join("sys/devices/system/cpu/online"), "0-7").unwrap();
                let out = host.path().join("out");
                let args = InitArgs { host_root: host.path().into(), memory_bytes: None, cpus: None, ..args(&out) };
                let get_env = |name: &str| if name == "NANO_VECTOR_PROFILE" {
                    Some(if vector { "lean" } else { "none" }.to_owned())
                } else { env(name) };
                init(&args, &get_env).unwrap();
                let rendered: Value = serde_json::from_slice(&std::fs::read(out.join("compose.resources.json")).unwrap()).unwrap();
                for (name, measurement) in measurements["services"].as_object().unwrap() {
                    if !selected_service(name, vector) { continue; }
                    if let Some(idle) = measurement["idle_rss_bytes"].as_u64() {
                        let cap = rendered["services"][name]["mem_limit"].as_u64().unwrap();
                        assert!(cap * 4 >= idle * 5, "{name}: cap {cap} under idle RSS {idle} plus 25% at host {memory}");
                    }
                }
                assert_eq!(rendered["x-nano-host-sizing"]["supported"], memory >= minimum_install_memory_for_ingest(vector));
                if memory >= 7934 * MIB {
                    assert_eq!(rendered["x-nano-host-sizing"]["supported"], true);
                }
            }
        }
        // Neither 8 GiB profile funds the existing 150 EPS sustained curve;
        // a 300 EPS burst and the required soak still need live qualification.
        for vector in [true, false] {
            assert!(host_cell_memory_for_ingest(8 * GIB, vector) < small_cell_memory_for_eps(150));
        }
    }

    #[test]
    fn nan4844_landing_lanes_preserve_all_selected_service_floors() {
        for memory in [8 * GIB, 9 * GIB, 12 * GIB, 15_965 * MIB, 16 * GIB, 24 * GIB, 32 * GIB, 64 * GIB, 128 * GIB, 256 * GIB] {
            for cpus in 1..=64 {
                for vector in [true, false] {
                    let sizing = size(host_cell_memory_for_ingest(memory, vector), cpus);
                    let rendered = compose_resources_for_ingest(&sizing, HostFacts { memory_bytes: memory, cpus }, false, vector);
                    let services = rendered["services"].as_object().unwrap();
                    assert!(services.values().map(|s| s["mem_limit"].as_u64().unwrap()).sum::<u64>() <= host_memory_share(memory, 95));
                    for (name, floor) in startup_memory().services.iter().filter(|(n, _)| selected_service(n, vector)) {
                        assert!(services[name]["mem_limit"].as_u64().unwrap() >= service_startup_minimum(name, floor), "{name}");
                    }
                    let landing = services["lean-landing"]["mem_limit"].as_u64().unwrap();
                    let (lanes, flight) = crate::landing_budget::limits(landing, cpus * 1000);
                    assert!(lanes >= 1);
                    assert_eq!(landing, crate::landing_budget::memory_for_lanes(lanes));
                    assert_eq!(flight, lanes as u64 * crate::landing_budget::MAX_LANDING_BYTES);
                    assert_eq!(crate::landing_budget::limits(landing - 1, cpus * 1000).0, lanes - 1);
                    if memory == 8 * GIB { assert_eq!(lanes, 1); }
                    if memory == 15_965 * MIB && cpus >= 2 && !vector { assert_eq!(lanes, 2); }
                    if memory == 16 * GIB && cpus >= 2 { assert_eq!(lanes, 2); }
                }
            }
        }
    }

    #[test]
    fn nan4843_capacity_table_uses_production_sizing() {
        for (gib, cpus) in [(8, 4), (16, 8), (32, 16), (64, 32), (128, 64)] {
            for vector in [true, false] {
                let host = HostFacts { memory_bytes: gib * GIB, cpus };
                let sizing = size(host_cell_memory_for_ingest(host.memory_bytes, vector), cpus);
                let compose = compose_resources_for_ingest(&sizing, host, false, vector);
                let total: u64 = compose["services"].as_object().unwrap().values()
                    .map(|s| s["mem_limit"].as_u64().unwrap()).sum();
                assert!(total <= host.memory_bytes / 100 * 95);
                for (name, floor) in startup_memory().services.iter().filter(|(name, _)| selected_service(name, vector)) {
                    assert!(compose["services"][name]["mem_limit"].as_u64().unwrap() >= floor.bytes());
                }
                println!("NAN4843_CAPACITY {}", json!({"memory": host.memory_bytes, "cpus": cpus,
                    "vector": vector, "compose": compose}));
            }
        }
    }

    #[test]
    fn nan4843_explicit_cell_override_cannot_overcommit_a_supported_host() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let error = init(&InitArgs { memory_bytes: Some(4 * GIB), ..args(&out) }, &env).unwrap_err();
        assert!(error.to_string().contains("exceeds 95%"));
        assert!(!out.join("cell/placement.json").exists());
        assert!(!out.join("cell/secret").exists());
    }

    #[test]
    fn nan4842_dragonfly_startup_fits_host_pool() {
        // 15,965 MiB of usable RAM on a nominal 16 GiB host produced 173mb
        // with the old allocator; cover it alongside every supported shape.
        let old_pool = (15_965 * MIB) / 100 * 45;
        let old_jobs = (old_pool / 104 * 12).max(GIB);
        let old_limit = round_mib((old_pool - old_jobs - GIB - 512 * MIB) / 80 * 5);
        assert_eq!(old_limit / 100 * 60 / MIB, 173);
        for memory in [8 * GIB, 12 * GIB, 15_965 * MIB, 16 * GIB, 24 * GIB, 32 * GIB, 64 * GIB] {
            for cpus in 2..=64 {
                for sovereign in [false, true] {
                    let rendered = compose_resources(&size(host_cell_memory_bytes(memory).max(512 * MIB), cpus), HostFacts { memory_bytes: memory, cpus }, sovereign);
                    let services = rendered["services"].as_object().unwrap();
                    let command = services["dragonfly"]["command"].as_array().unwrap();
                    let maxmemory = command[0].as_str().unwrap().strip_prefix("--maxmemory=").unwrap()
                        .strip_suffix("mb").unwrap().parse::<u64>().unwrap() * MIB;
                    let threads = command[1].as_str().unwrap().strip_prefix("--proactor_threads=").unwrap()
                        .parse::<u64>().unwrap();
                    assert!(maxmemory >= 256 * MIB);
                    assert!((1..=32).contains(&threads));
                    assert!(threads <= u64::from((cpus / 4).max(1)));
                    assert!(maxmemory >= 256 * MIB * threads, "memory={memory} cpus={cpus}");
                    assert_eq!(threads, u64::from((cpus / 4).clamp(1, 32)).min(maxmemory / (256 * MIB)));
                    if memory == 8 * GIB {
                        assert_eq!(maxmemory, 256 * MIB);
                        assert_eq!(threads, 1);
                    }
                    let limit = services["dragonfly"]["mem_limit"].as_u64().unwrap();
                    assert!(limit * 60 >= maxmemory * 100);
                    let siblings: u64 = services.iter().filter(|(name, _)| name.as_str() != "lake-cell")
                        .map(|(_, service)| service["mem_limit"].as_u64().unwrap()).sum();
                    assert!(siblings <= (memory / 100 * 45).max(rendered["x-nano-host-sizing"]["compose_minimum_memory_bytes"].as_u64().unwrap()));
                    println!("NAN4842_RENDER {}", json!({"memory": memory, "cpus": cpus, "sovereign": sovereign,
                        "dragonfly": services["dragonfly"], "siblings": siblings}));
                }
            }
        }
    }

    /// Exercise the production initializer, not a copy of its sizing math.
    /// Render lines can also be fed to Docker Compose's daemon-free validator.
    #[test]
    fn nan4827_host_shapes_render_all_roles_and_containers() {
        for (memory, cpus, ingest, query, detect, product, landing) in [
            (2 * GIB, 4, 140 * MIB, 281 * MIB, 86 * MIB, 20 * MIB, 20 * MIB),
            (3413114880, 4, 140 * MIB, 281 * MIB, 86 * MIB, 20 * MIB, 20 * MIB),
            (8 * GIB, 8, 434 * MIB, 759 * MIB, 256 * MIB, 512 * MIB, 1024 * MIB),
            (32 * GIB, 16, 8 * GIB, 5324 * MIB, 2705 * MIB, 655 * MIB, 1024 * MIB),
            (64 * GIB, 32, 10 * GIB, 16793 * MIB, 5408 * MIB, 1310 * MIB, 1310 * MIB),
            (64 * GIB, 64, 10 * GIB, 16793 * MIB, 5408 * MIB, 1310 * MIB, 1310 * MIB),
        ] {
            let host = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(host.path().join("proc")).unwrap();
            std::fs::create_dir_all(host.path().join("sys/devices/system/cpu")).unwrap();
            std::fs::write(host.path().join("proc/meminfo"), format!("MemTotal: {} kB\n", memory / 1024)).unwrap();
            std::fs::write(host.path().join("sys/devices/system/cpu/online"), format!("0-{}", cpus - 1)).unwrap();
            let out = host.path().join("out");
            init(&InitArgs { host_root: host.path().into(), memory_bytes: None, cpus: None, ..args(&out) }, &env).unwrap();
            let placement: crate::config::Placement = serde_json::from_slice(&std::fs::read(out.join("cell/placement.json")).unwrap()).unwrap();
            let t = &placement.tenants[0];
            use crate::contract::Role;
            assert_eq!(t.effective_role_budget(Role::Ingest).limit_memory_bytes, ingest);
            assert_eq!(t.effective_role_budget(Role::Query).limit_memory_bytes, query);
            assert_eq!(t.effective_role_budget(Role::Detect).limit_memory_bytes, detect);
            assert_eq!(t.effective_role_budget(Role::Product).limit_memory_bytes, product);
            assert_eq!(t.effective_role_budget(Role::Landing).limit_memory_bytes, landing);
            let requests: u32 = Role::ALL.into_iter().map(|r| t.effective_role_budget(r).request_millicores).sum();
            let siblings: u32 = COMPOSE_CPU_SHARES.iter().map(|(_, w)| cpu_share_millicores(cpus * 1000, *w)).sum();
            assert!(requests + siblings <= cpus * 1000, "all host guarantees fit");
            assert_eq!(Role::ALL.into_iter().map(role_cpu_shares).sum::<u32>(), CELL_CPU_SHARES);
            assert_eq!(COMPOSE_CPU_SHARES.iter().map(|(_, w)| w).sum::<u32>() + CELL_CPU_SHARES, HOST_CPU_SHARES);
            let query_weight = crate::resources::role_cpu_weight(t, Role::Query);
            assert!(query_weight > crate::resources::role_cpu_weight(t, Role::Ingest));
            assert!(query_weight > crate::resources::role_cpu_weight(t, Role::Landing));
            assert_eq!(role_nice(Role::Query), 0);
            assert_eq!(role_nice(Role::Ingest), 3);
            assert!(role_nice(Role::Query) < role_nice(Role::Landing));
            let limits = crate::resources::TenantLimits::from_placement(t,
                &crate::resources::CellCapacity { cpu_millicores: cpus * 1000, memory_bytes: host_cell_memory_bytes(memory).max(512 * MIB),
                    cpu_source: "config", memory_source: "config" }, &crate::config::ResourceConfig::default());
            assert_eq!(limits.cpu_guarantee_millicores, requests);
            assert_eq!(limits.cpu_ceiling_millicores, cpus * 1000);
            // Exercise the real cgroup writer as well as the placement weights.
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("cgroup.controllers"), "cpu memory pids io\n").unwrap();
            std::fs::write(root.path().join("cgroup.procs"), "").unwrap();
            let tree = crate::limits::CgroupTree::adopt_root(root.path().into(), "/".into(), vec![], false).unwrap();
            tree.ensure_tenant(&t.tenant_id, 0, &limits).unwrap();
            for role in Role::ALL {
                tree.set_role_cpu_weight(&t.tenant_id, role, crate::resources::role_cpu_weight(t, role)).unwrap();
                let actual: u32 = std::fs::read_to_string(tree.tenant_dir(&t.tenant_id).join(role.as_str()).join("cpu.weight")).unwrap().parse().unwrap();
                assert_eq!(actual, crate::resources::role_cpu_weight(t, role));
            }

            for role in Role::ALL {
                let budget = t.effective_role_budget(role);
                assert_eq!(budget.limit_millicores, cpus * 1000, "idle host can lend all cores to {role:?}");
                assert!(budget.limit_millicores >= budget.request_millicores);
            }
            let role_total: u64 = Role::ALL.into_iter().filter(|r| matches!(r, Role::Ingest | Role::Query | Role::Detect))
                .map(|r| t.effective_role_budget(r).limit_memory_bytes).sum();
            assert!(role_total < memory / 2);
            assert!(t.effective_role_budget(Role::Ingest).limit_millicores > 1000);
            let rendered: Value = serde_json::from_slice(&std::fs::read(out.join("compose.resources.json")).unwrap()).unwrap();
            let services = rendered["services"].as_object().unwrap();
            let total: u64 = services.values().map(|v| v["mem_limit"].as_u64().unwrap()).sum();
            if memory >= minimum_install_memory_bytes() {
                assert!(total <= host_memory_share(memory, 95), "total={total} memory={memory}");
            } else {
                assert_eq!(rendered["x-nano-host-sizing"]["supported"], false);
            }
            assert_eq!(services["lake-cell"]["mem_limit"], host_cell_memory_bytes(memory).max(512 * MIB));
            for service in services.values() {
                assert_eq!(service["mem_limit"], service["memswap_limit"]);
                assert!(service["mem_limit"].as_u64().unwrap() > 0);
            }
            assert_eq!(services["nano-search"]["cpus"], cpus);
            if memory >= 8 * GIB {
                assert!(services["nano-jobs"]["mem_limit"].as_u64().unwrap() >= GIB);
            }
            println!("NAN4827_RENDER {}", json!({"memory": memory, "cpus": cpus, "compose": rendered}));
            // Sovereign output preserves the security flags even though compose
            // replaces command lists rather than appending them.
            let sovereign = compose_resources(&size(host_cell_memory_bytes(memory).max(512 * MIB), cpus), HostFacts { memory_bytes: memory, cpus }, true);
            let command = sovereign["services"]["postgres"]["command"].as_array().unwrap();
            assert!(command.contains(&json!("ssl=on")));
            assert!(command.contains(&json!("hba_file=/etc/nano-sovereign-pg/pg_hba.conf")));
            println!("NAN4827_SOVEREIGN {}", json!({"memory": memory, "cpus": cpus, "compose": sovereign}));
        }
        // Physical disk ceilings, including a volume smaller than old floors.
        assert_eq!(crate::budget::cache_disk_budget(30 * GIB, 10 * GIB), 2 * GIB);
        assert_eq!(crate::budget::cache_disk_budget(30 * GIB, 1000 * GIB), 30 * GIB);
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
        // NAN-4759: platform feeds through the hosted bundle-dir + policy path.
        assert_eq!(cell["feed_dir"], "/var/lib/nano-platform-feeds");
        assert_eq!(cell["platform_bundle_dir"], "/var/lib/nano-platform-feeds/bundles");
        let placement: Value = serde_json::from_slice(&std::fs::read(out.join("cell/placement.json")).unwrap()).unwrap();
        assert_eq!(placement["tenants"][0]["platform_policy_file"], format!("/var/lib/nano-platform-policy/{tenant}/policy.json"));
        let grants: Value = serde_json::from_slice(&std::fs::read(out.join(format!("platform-grants/{tenant}.json"))).unwrap()).unwrap();
        assert_eq!(grants, serde_json::json!({"schema": ALL_BUNDLED_GRANTS_SCHEMA, "tenant_id": tenant, "rows": []}));
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
        assert_eq!(placement["tenants"][0]["query_limit_memory_bytes"], 18022 * MIB, "re-render resizes");

        // A different --tenant-id conflicts; --force re-mints.
        let mut other = args(&out);
        other.tenant_id = Some(uuid::Builder::from_random_bytes([7; 16]).into_uuid());
        let error = init(&other, &env).unwrap_err();
        assert!(error.downcast_ref::<Conflict>().is_some());
        other.force = true;
        let forced = init(&other, &env).unwrap();
        assert_eq!(forced["created"], true);
        assert_eq!(forced["tenant_id"], other.tenant_id.unwrap().to_string());
        let grant_files: Vec<_> = std::fs::read_dir(out.join("platform-grants")).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(grant_files, vec![std::ffi::OsString::from(format!("{}.json", other.tenant_id.unwrap()))], "re-mint drops the old grant");
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
    fn a_sixteen_gib_host_keeps_inactive_templates_without_reserving_them() {
        // init gives half of a 16 GiB Docker host to the cell.
        let s = size(8 * GIB, 8);
        let base = size_for(8 * GIB, 8, Some(100));
        assert_eq!(s.ingest.3 + s.query.3, base.ingest.3 + base.query.3);
        let local = &s.local_resources;
        assert!(s.ingest.3 + s.query.3 + s.detect.3 + 64 * MIB <= s.memory_bytes);
        assert!(local.product.limit_memory_bytes >= 512 * MIB);
        assert!(local.maintenance.limit_memory_bytes >= 512 * MIB);
        assert!(s.query.3 >= crate::budget::QUERY_MEMORY_FLOOR_BYTES);
        // Nominal 16 GiB hosts report slightly less usable RAM. There is no
        // hard capacity threshold that would send them back to a 2 GiB role.
        let usable = size(8 * GIB - 512 * MIB, 8);
        assert!(usable.ingest.3 > 3 * GIB / 2);
        assert!(usable.query.3 >= crate::budget::QUERY_MEMORY_FLOOR_BYTES);
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
        assert!(small.query.3 > GIB);
        assert_eq!(small.query.3, size_for(4 * GIB, 2, Some(100)).query.3);
        assert!(small.query.1 >= 1000);
        let big = size(64 * GIB, 32);
        assert_eq!(big.query.3, 36045 * MIB);
        assert_eq!(big.ingest.3, 18022 * MIB);
        assert!(big.detect.3 >= crate::budget::DETECT_RULES_MIN_MEMORY_BYTES);
        for s in [&small, &big] {
            assert!(TenantBudget::from_eps(s.eps as f64).ingest_memory_cap_bytes >= s.ingest.3);
            for (rq, lim, rm, lm) in [s.ingest, s.detect, s.query] {
                assert!(rq > 0 && lim >= rq && rm > 0 && lm >= rm);
            }
        }
    }

    /// NAN-4749: a target rate sizes ingest for full parallel L0 flushes
    /// and places the tenant at that rate; no target keeps the host sizing.
    #[test]
    fn a_target_eps_sizes_ingest_for_the_rate() {
        // The 1.0.11 bakeoff shape: 16 GiB for the cell, 8 CPUs.
        let host = size(16 * GIB, 8);
        assert_eq!(size_for(16 * GIB, 8, None), host, "no target: unchanged");
        let need = crate::budget::ingest_memory_for_resources(10_000.0, 8_000);
        assert_eq!(host.ingest.3, need);
        let target = size_for(16 * GIB, 8, Some(10_000));
        assert_eq!(target.ingest.3, need);
        assert_eq!(target.eps, 10_000, "placed at the target rate");
        // The default already leaves full-flush and merge headroom. A target
        // changes pacing without increasing the total role memory envelope.
        assert_eq!(target.query.3, host.query.3);
        assert_eq!(target.ingest.3 + target.query.3 + target.detect.3, host.ingest.3 + host.query.3 + host.detect.3);
        assert!(TenantBudget::from_eps(target.eps as f64).ingest_memory_cap_bytes >= target.ingest.3);
        // A small box gives ingest at most half its memory and query >= 1 GiB.
        let small = size_for(4 * GIB, 2, Some(10_000));
        assert!(small.ingest.3 >= 512 * MIB && small.ingest.3 <= 2 * GIB);
        assert_eq!(small.query.3, size_for(4 * GIB, 2, Some(100)).query.3);
        // A big box already covers the rate: the host sizing stands.
        let big = size_for(64 * GIB, 32, Some(10_000));
        assert_eq!(big.ingest.3, size(64 * GIB, 32).ingest.3);
        assert!(big.eps >= 10_000);
        // A low rate never shrinks ingest below the host share.
        assert!(size_for(16 * GIB, 8, Some(100)).ingest.3 >= 3 * GIB);
        // A small cell retains its bounded small-host curve; init refuses
        // targets above that curve instead of overcommitting the roles.
        let floor = size_for(2 * GIB, 1, Some(10_000));
        assert_eq!((floor.ingest, floor.query), (size(2 * GIB, 1).ingest, size(2 * GIB, 1).query));
        assert_eq!(floor.eps, size(2 * GIB, 1).eps);
        assert!(floor.eps < 10_000);
    }

    #[test]
    fn init_places_the_target_rate() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let summary = init(&InitArgs { target_eps: Some(10_000), ..args(&out) }, &env).unwrap();
        let placement: Value = serde_json::from_slice(&std::fs::read(out.join("cell/placement.json")).unwrap()).unwrap();
        let t = &placement["tenants"][0];
        assert_eq!(t["eps"], 10_000.0);
        let need = crate::budget::ingest_memory_for_resources(10_000.0, 8_000);
        assert_eq!(t["ingest_limit_memory_bytes"], need);
        assert_eq!(summary["sizing"]["target_eps"], 10_000);
        // A re-run without the target retains the default merge headroom.
        init(&args(&out), &env).unwrap();
        let placement: Value = serde_json::from_slice(&std::fs::read(out.join("cell/placement.json")).unwrap()).unwrap();
        assert_eq!(placement["tenants"][0]["ingest_limit_memory_bytes"], need);
    }

    #[test]
    fn flags_parse_and_refuse_bad_values() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let parsed = parse_args(&s(&["--out", "/x", "--cpus", "4", "--app-owner", "1000:1000", "--no-require-landlock"])).unwrap();
        assert_eq!(parsed.cpus, Some(4));
        assert_eq!(parse_args(&s(&["--out", "/x", "--target-eps", "10000"])).unwrap().target_eps, Some(10_000));
        assert!(parse_args(&s(&["--out", "/x", "--target-eps", "0"])).is_err());
        assert!(parse_args(&s(&["--out", "/x", "--target-eps", "ten"])).is_err());
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

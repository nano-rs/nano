// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cell configuration (NAN-2871). Rendered by the platform as a ConfigMap; see
//! `docs-internal/NAN-2865-cell-placement-spec.md`.
//!
//! Two files:
//! - the **cell config** (static per cell Deployment): paths, binaries, uid
//!   range, timeouts, listeners;
//! - the **placement** (which tenants live on this cell, with their eps):
//!   re-read every `placement_reload_secs` and on SIGHUP, so moving a tenant
//!   needs no restart.

use crate::contract::TenantId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellMode {
    /// Many tenants per cell (default).
    Pooled,
    /// A cell of one: exactly one placed tenant (hard-isolation option).
    Dedicated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupPolicy {
    /// Use cgroup v2 delegation if the subtree is writable, else watchdog.
    Auto,
    /// Refuse to start without cgroup delegation.
    Require,
    /// Never touch cgroups (watchdog only).
    Off,
}

fn default_idle() -> u64 {
    600
}
/// `query_idle_timeout_secs` default.
pub const DEFAULT_QUERY_IDLE_SECS: u64 = 3_600;
/// `query_resident_ingest_window_secs` default.
pub const DEFAULT_QUERY_RESIDENT_INGEST_WINDOW_SECS: u64 = 86_400;
fn default_query_idle() -> u64 {
    DEFAULT_QUERY_IDLE_SECS
}
fn default_query_resident_ingest_window() -> u64 {
    DEFAULT_QUERY_RESIDENT_INGEST_WINDOW_SECS
}
fn default_warm() -> usize {
    2
}
fn default_uid_base() -> u32 {
    crate::uidmap::DEFAULT_UID_BASE
}
fn default_uid_slots() -> u32 {
    crate::uidmap::DEFAULT_UID_SLOTS
}
fn default_spawn_timeout() -> u64 {
    20
}
fn default_grace() -> u64 {
    10_000
}
fn default_stall_kill() -> u64 {
    300
}
fn default_ports() -> Vec<u16> {
    vec![443]
}
fn default_true() -> bool {
    true
}
fn default_reload() -> u64 {
    30
}
fn default_warm_mem() -> u64 {
    128 * crate::budget::MIB
}
fn default_system_paths() -> Vec<PathBuf> {
    [
        "/usr",
        "/lib",
        "/lib64",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/etc/pki",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/localtime",
        "/etc/ld.so.cache",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}
fn default_query_grace() -> u64 {
    600
}
fn default_cgroup_mount() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellConfig {
    pub cell_id: String,
    #[serde(default = "pooled")]
    pub mode: CellMode,
    /// Open-core single-tenant host trust boundary. Landlock is opportunistic
    /// when require_landlock is false; hosted cells must leave this disabled.
    #[serde(default)]
    pub trusted_local: bool,
    /// Tenant data root: `<data_dir>/tenants/<T>/…`. Must be 0755 root-owned
    /// (or supervisor-owned); tenant dirs below are created by the supervisor.
    pub data_dir: PathBuf,
    /// Supervisor-private state (uid map). 0700, never visible to tenants.
    pub state_dir: PathBuf,
    /// Read-only enrichment feeds, the only input shared across tenants.
    #[serde(default)]
    pub feed_dir: Option<PathBuf>,
    /// Immutable, node-shared platform artifact inside `feed_dir` (legacy
    /// fixed path; every bundle update needs a config re-render).
    #[serde(default)]
    pub platform_bundle_file: Option<PathBuf>,
    /// Directory (`feed_dir` or below it) of content-addressed
    /// `platform-<sha256>.nanpfb` bundles. Each tenant process opens the one
    /// its policy's `bundle_sha256` names and verifies the content hash, so a
    /// bundle update needs no re-render. Exclusive with `platform_bundle_file`.
    #[serde(default)]
    pub platform_bundle_dir: Option<PathBuf>,
    pub ingest_binary: PathBuf,
    pub query_binary: PathBuf,
    /// Extra read+execute paths for tenant processes (e.g. libchdb's dir).
    #[serde(default)]
    pub extra_ro_paths: Vec<PathBuf>,
    #[serde(default = "default_system_paths")]
    pub system_ro_paths: Vec<PathBuf>,

    #[serde(default = "default_idle")]
    pub idle_timeout_secs: u64,
    /// Idle reap window for `query[T]` (NAN-2989; default 1 h, was the
    /// 10 min `idle_timeout_secs`). A reaped query pays a cold start on the
    /// next search.
    #[serde(default = "default_query_idle")]
    pub query_idle_timeout_secs: u64,
    /// Keep `query[T]` resident (never idle-reaped, and started by the
    /// keeper) while the tenant's ingest reported work within this window
    /// (NAN-2989; default 24 h). 0 disables: query is then on demand only.
    #[serde(default = "default_query_resident_ingest_window")]
    pub query_resident_ingest_window_secs: u64,
    /// NAN-3008 (default true): `query[T]` is always resident for every
    /// placed tenant: the keeper starts it at cell start and after any crash
    /// or roll, before a search arrives, and it is never idle-reaped. An
    /// unplaced tenant's processes are still reaped. `false` falls back to
    /// the NAN-2989 rule (resident while ingest or search is recent).
    #[serde(default = "default_true")]
    pub query_resident: bool,
    /// With `query_resident = false`: a search within this window also keeps
    /// query resident (NAN-3008; default 24 h, 0 disables).
    #[serde(default = "default_query_resident_ingest_window")]
    pub query_resident_search_window_secs: u64,
    /// Warm, unassigned processes kept per role.
    #[serde(default = "default_warm")]
    pub warm_query: usize,
    #[serde(default)]
    pub warm_ingest: usize,
    /// cgroup cap for the whole warm pool (per warm process).
    #[serde(default = "default_warm_mem")]
    pub warm_memory_bytes_each: u64,
    #[serde(default = "default_spawn_timeout")]
    pub spawn_timeout_secs: u64,
    #[serde(default = "default_grace")]
    pub shutdown_grace_ms: u64,
    /// A process with no heartbeat for this long is killed (and paged).
    #[serde(default = "default_stall_kill")]
    pub stall_kill_secs: u64,

    #[serde(default = "default_uid_base")]
    pub uid_base: u32,
    #[serde(default = "default_uid_slots")]
    pub uid_slots: u32,
    #[serde(default = "default_ports")]
    pub tcp_connect_ports: Vec<u16>,
    #[serde(default = "default_true")]
    pub require_landlock: bool,
    /// Limits mode selection (NAN-2872): `{"cgroup": "auto"|"require"|"off",
    /// "watchdog": true}`. Replaces the former top-level `cgroup` field.
    #[serde(default)]
    pub isolation: IsolationConfig,
    #[serde(default = "default_cgroup_mount")]
    pub cgroup_mount: PathBuf,
    /// Per-tenant resource enforcement (NAN-2872): guarantees, burst
    /// ceilings, contention thresholds, the watchdog interval.
    #[serde(default)]
    pub resources: ResourceConfig,

    /// TCP listener for nanosiem-api / nanosiem-search (bearer-authenticated).
    #[serde(default)]
    pub listen_tcp: Option<String>,
    /// Unix listener (same-pod sidecars, tests). Bearer-authenticated, and
    /// the peer uid (SO_PEERCRED) must not be a tenant uid.
    #[serde(default)]
    pub listen_unix: Option<PathBuf>,
    /// File holding the router bearer token (mounted Secret).
    pub router_token_file: PathBuf,
    /// Optional **query-only** router token (nanosiem-api / jobs / search):
    /// accepted on `/v1/tenants/{t}/query[/…]`, `/v1/tenants/{t}/detect[/…]`,
    /// `GET /v1/status` and a `POST /v1/tenants/{t}/wake` whose role is
    /// `query` (`router-query-token-wake`); every other route answers 403. Must differ from the full
    /// token. File mode must not grant group/other access (e.g. 0400).
    #[serde(default)]
    pub router_query_token_file: Option<PathBuf>,
    /// After the query token rotates, the previous one is still accepted
    /// for this long (app pods mid-roll), then refused. Full token: no
    /// grace.
    #[serde(default = "default_query_grace")]
    pub router_query_token_grace_secs: u64,
    /// Optional read-only token accepted only on GET /v1/lean-cell-alerts.
    #[serde(default)]
    pub router_alerts_token_file: Option<PathBuf>,
    /// Grace period for the previous alerts token after rotation.
    #[serde(default = "default_query_grace")]
    pub router_alerts_token_grace_secs: u64,
    /// NAN-3289 migration switch. `true` (default): the cluster-wide query
    /// token keeps its pre-NAN-3289 reach (every tenant's query and detect
    /// routes, detection commits) beside the per-tenant tokens
    /// ([`crate::tenant_token`]), and an unsigned durable-job spec is still
    /// admitted (`x-nano-cell-job-auth: legacy`). `false` (the follow-up flip,
    /// once every caller presents per-tenant tokens and the job runners sign):
    /// the cluster query token reaches only `GET /v1/status`, `/healthz` and
    /// a query-role wake (the control plane's prewarm probe); every tenant
    /// route needs that tenant's token, and unsigned job specs are refused.
    #[serde(default = "default_true")]
    pub router_accept_cluster_query_token: bool,
    /// Serve `/metrics` without auth (for an in-cluster scraper).
    #[serde(default)]
    pub metrics_public: bool,

    /// Placement file (JSON [`Placement`]); reloaded periodically and on SIGHUP.
    pub placement_file: PathBuf,
    #[serde(default = "default_reload")]
    pub placement_reload_secs: u64,

    /// Control-plane bootstrap-token endpoint; if unset, `dev_key_dir` is used.
    #[serde(default)]
    pub control_url: Option<String>,
    #[serde(default)]
    pub cell_identity_file: Option<PathBuf>,
    #[serde(default)]
    pub dev_key_dir: Option<PathBuf>,
    /// Owner-signing config handed to `ingest` processes (release-pinned,
    /// rendered by the platform). Required for ingest in production cells.
    #[serde(default)]
    pub part_signing: Option<crate::contract::PartSigning>,
    /// NAN-2884 knob, rendered by the platform in lockstep with
    /// `controlPlane.owner.lakePartRequireChecksum`. Default false (cap on).
    #[serde(default)]
    pub owner_requires_checksum: bool,
    /// `ingest.idle_exit`; unset = by input (edge tenants stay up).
    #[serde(default)]
    pub ingest_idle_exit: Option<bool>,
    /// `ingest.day_merges`: default false, `h` stays the top level until
    /// control authorizes multi-hour parts (NAN-2886).
    #[serde(default)]
    pub ingest_day_merges: bool,
    /// `ingest.keyword_index` (NAN-3032, cell feature
    /// `lean_keyword_index_v1`): ingest writes v2 token block indexes.
    /// Default false. Query of the same image reads v1 and v2.
    #[serde(default)]
    pub ingest_keyword_index: bool,
    /// `identity_observations` (NAN-3058, cell feature
    /// `lean_identity_observations_v1`): ingest derives the per-part IP →
    /// host/user observation index and query[T] backfills the parts of the
    /// last 30 days that predate it. Default false. Query of the same image
    /// always serves the index it finds.
    #[serde(default)]
    pub identity_observations: bool,
    /// `identity_directory_enrich` (NAN-3503, cell feature
    /// `lean_identity_directory_enrich_v1`): ingest loads the tenant identity
    /// directory from its R2 enrichment prefix (pinned by revision, re-read on
    /// the enrichment refresh) and stamps department, title, manager, groups
    /// and admin onto matched `actor.user` / `user` objects plus one
    /// `enrichments[]` entry of type `identity`. Default false: events are
    /// unchanged.
    #[serde(default)]
    pub identity_directory_enrich: bool,
    /// `prevalence_maintenance` (cell feature `lean_prevalence_maintenance_v1`):
    /// run `maintenance[T]`, the tenant prevalence SlateDB compactor, beside
    /// every resident ingest. Required whenever prevalence is on: ingest
    /// never compacts (the owner refuses its compactions), so without it L0
    /// reaches SlateDB's cap and stamping stalls. Default false.
    #[serde(default)]
    pub prevalence_maintenance: bool,
    /// `product_state_role` (NAN-3148, cell feature
    /// `lean_product_state_role_v1`): run `product[T]` beside every running
    /// query[T]. It builds prevalence/risk product state under its own
    /// cgroup budget and publishes versioned snapshots; query[T] then only
    /// reads them and never builds product state on its CPU quota. Default
    /// false (query[T] builds in-process, as before).
    #[serde(default)]
    pub product_state_role: bool,
    /// `tenzir_landing` (NAN-4137, cell feature `lean_tenzir_landing_v1`):
    /// run `landing[T]`, the hosted OCSF bucket-drop converter, for every
    /// tenant placed with `landing: true` on the cell that writes for it.
    /// Its status rides the status push as the tenant's `landing` entry.
    /// Default false: no landing role, a byte-identical status push.
    #[serde(default)]
    pub tenzir_landing: bool,
    /// `detect.runs_rules` (cell feature `detect_runs_rules_v1`): detect[T]
    /// runs its tenant's rule searches in its own engine, under its own
    /// budget, and the router sends every `/v1/tenants/{t}/detect/...`
    /// request there, never to query[T]. Applies per tenant only when the
    /// placed detect budget holds the engine
    /// ([`TenantPlacement::detect_runs_rules`]); otherwise that tenant keeps
    /// the legacy path (detect route served by query[T]). Default false.
    #[serde(default)]
    pub detect_runs_rules: bool,
    /// `ingest.flush`: L0 flush policy override (NAN-2984). Unset = the
    /// ingest code default (5–10 s by rate; the 10 s cap bounds
    /// arrival→searchable at low rates).
    #[serde(default)]
    pub ingest_flush: Option<crate::contract::IngestFlush>,
    /// `ingest.merge_policy` (cell feature `ingest_merge_policy_v1`): merge
    /// policy overrides for ingest (hour seal, sealed-hour re-merge
    /// debounce and defer cap, merges per tick). Unset = the ingest code
    /// defaults.
    #[serde(default)]
    pub ingest_merge_policy: Option<crate::contract::IngestMergePolicy>,
    /// Zero-downtime rolls (NAN-3004, cell feature `cell_zero_downtime_roll_v1`):
    /// writer handover between the pods of this cell, `/readyz` only when
    /// warm, graceful drain on SIGTERM. Unset = one pod, `Recreate` (as before).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zero_downtime_roll: Option<crate::handover::HandoverConfig>,
    /// Egress watchdog (NAN-3440, cell feature `upstream_readiness_v1`):
    /// HTTPS targets (R2, control plane) probed every interval; `/healthz`
    /// reports `upstream_ready: false` while two targets (R2 AND control) have
    /// both been unreachable for `not_ready_after_secs`. A signal only:
    /// `/readyz` never gates on it. Unset = off (as before).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_readiness: Option<crate::upstream::UpstreamReadinessConfig>,
}

/// How a cell isolates tenant resources (rendered by the platform into the
/// release-pinned `cell.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationConfig {
    /// `require` when the probe reports a writable (delegated) cgroup, i.e.
    /// the node-side delegator is present; `auto` otherwise.
    #[serde(default = "auto")]
    pub cgroup: CgroupPolicy,
    /// The graduated guarantee/burst watchdog. Always on; `false` is
    /// rejected (it is the only enforcement without delegation and the
    /// dynamic layer with it).
    #[serde(default = "default_true")]
    pub watchdog: bool,
    /// NAN-3523 opt-out, **dev/test only**: let a `pooled` cell admit
    /// tenants while limits are watchdog-only (and accept `cgroup: "off"` on
    /// one). Without it a pooled cell refuses to start tenant processes
    /// until kernel limits are adopted, and `pooled` + `off` is rejected:
    /// one tenant's memory burst faster than the watchdog poll would OOM the
    /// pod and every tenant on it. The platform never renders it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_pooled_watchdog_only: bool,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self { cgroup: CgroupPolicy::Auto, watchdog: true, allow_pooled_watchdog_only: false }
    }
}

fn pooled() -> CellMode {
    CellMode::Pooled
}
fn auto() -> CgroupPolicy {
    CgroupPolicy::Auto
}

impl CellConfig {
    /// The owner-sign CA bundle's directory is granted read-only to every
    /// ingest jail, so it must be a dedicated, non-root directory that no
    /// child can write (a tenant-planted CA would let it impersonate the
    /// owner signer).
    fn validate_part_signing_ca(&self, ca: &std::path::Path) -> anyhow::Result<()> {
        use std::path::Component;
        anyhow::ensure!(
            ca.is_absolute() && ca.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
            "part_signing.ca_file must be absolute and normalized"
        );
        let dir = self.part_signing_ca_dir().ok_or_else(|| anyhow::anyhow!("part_signing.ca_file needs a parent directory"))?;
        anyhow::ensure!(dir != std::path::Path::new("/"), "part_signing.ca_file must sit in a dedicated directory, not /");
        for writable in [&self.data_dir, &self.state_dir] {
            anyhow::ensure!(
                !dir.starts_with(writable) && !writable.starts_with(dir),
                "part_signing.ca_file directory overlaps child-writable state"
            );
        }
        Ok(())
    }

    /// Directory holding `part_signing.ca_file` (read-only in ingest jails).
    pub fn part_signing_ca_dir(&self) -> Option<&std::path::Path> {
        self.part_signing.as_ref()?.ca_file.as_deref()?.parent()
    }

    pub fn cgroup_policy(&self) -> CgroupPolicy {
        self.isolation.cgroup
    }

    /// A shared platform bundle is configured (fixed file or directory).
    pub fn has_platform_bundle(&self) -> bool {
        self.platform_bundle_file.is_some() || self.platform_bundle_dir.is_some()
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
    /// Idle reap window for `role` (query has its own, NAN-2989).
    pub fn idle_timeout_for(&self, role: crate::contract::Role) -> Duration {
        match role {
            crate::contract::Role::Query => Duration::from_secs(self.query_idle_timeout_secs),
            _ => self.idle_timeout(),
        }
    }
    /// `None` when the ingest-activity residency rule is off.
    pub fn query_resident_ingest_window(&self) -> Option<Duration> {
        (self.query_resident_ingest_window_secs > 0).then(|| Duration::from_secs(self.query_resident_ingest_window_secs))
    }
    /// `None` when the search-activity residency rule is off.
    pub fn query_resident_search_window(&self) -> Option<Duration> {
        (self.query_resident_search_window_secs > 0).then(|| Duration::from_secs(self.query_resident_search_window_secs))
    }
    pub fn spawn_timeout(&self) -> Duration {
        Duration::from_secs(self.spawn_timeout_secs)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.cell_id.is_empty() && self.cell_id.len() <= 63, "cell_id");
        anyhow::ensure!(self.data_dir.is_absolute() && self.state_dir.is_absolute(), "paths must be absolute");
        if let Some(bundle) = &self.platform_bundle_file {
            let feed = self.feed_dir.as_ref().ok_or_else(|| anyhow::anyhow!("platform bundle needs feed_dir"))?;
            anyhow::ensure!(feed.is_absolute() && bundle.is_absolute() && bundle.parent() == Some(feed.as_path()), "platform bundle must be a direct feed_dir file");
        }
        if let Some(dir) = &self.platform_bundle_dir {
            use std::path::Component;
            anyhow::ensure!(self.platform_bundle_file.is_none(), "platform_bundle_file and platform_bundle_dir are mutually exclusive");
            let feed = self.feed_dir.as_ref().ok_or_else(|| anyhow::anyhow!("platform bundle dir needs feed_dir"))?;
            anyhow::ensure!(
                feed.is_absolute() && dir.is_absolute()
                    && dir.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
                    && dir.starts_with(feed),
                "platform bundle dir must be feed_dir or a normalized directory below it"
            );
        }
        anyhow::ensure!(self.listen_tcp.is_some() || self.listen_unix.is_some(), "no listener configured");
        anyhow::ensure!(self.idle_timeout_secs > 0, "idle_timeout_secs must be > 0");
        anyhow::ensure!(self.query_idle_timeout_secs > 0, "query_idle_timeout_secs must be > 0");
        anyhow::ensure!(self.control_url.is_some() || self.dev_key_dir.is_some(), "no key source configured");
        if self.trusted_local {
            anyhow::ensure!(self.mode == CellMode::Dedicated, "trusted_local requires dedicated mode");
            anyhow::ensure!(self.control_url.is_none() && self.cell_identity_file.is_none()
                && self.dev_key_dir.is_some() && self.part_signing.is_none(),
                "trusted_local requires local keys and forbids hosted control/owner credentials");
        }
        self.resources.validate()?;
        anyhow::ensure!(self.isolation.watchdog, "isolation.watchdog must be true (the watchdog is always on)");
        anyhow::ensure!(
            !(self.mode == CellMode::Pooled && self.isolation.cgroup == CgroupPolicy::Off) || self.isolation.allow_pooled_watchdog_only,
            "isolation.cgroup \"off\" on a pooled cell runs every tenant without kernel limits (one tenant's burst can OOM them all): \
             use cgroup \"auto\"/\"require\", mode \"dedicated\", or (dev/test only) isolation.allow_pooled_watchdog_only"
        );
        if let Some(flush) = &self.ingest_flush {
            flush.validate()?;
        }
        if let Some(policy) = &self.ingest_merge_policy {
            policy.validate()?;
        }
        if let Some(h) = &self.zero_downtime_roll {
            h.validate()?;
        }
        if let Some(u) = &self.upstream_readiness {
            u.validate()?;
        }
        if let Some(signing) = &self.part_signing {
            anyhow::ensure!(signing.url.starts_with("https://"), "part_signing.url must be https");
            anyhow::ensure!(!signing.trusted_keys.is_empty(), "part_signing needs trusted keys");
            anyhow::ensure!(
                signing.trusted_keys.iter().any(|k| k.key_id == signing.signer_key_id),
                "part_signing.signer_key_id must be one of its trusted keys"
            );
            for key in &signing.trusted_keys {
                anyhow::ensure!(
                    key.public_key_hex.len() == 64 && key.public_key_hex.bytes().all(|b| b.is_ascii_hexdigit()),
                    "part_signing trusted key {} is not 32-byte hex",
                    key.key_id
                );
            }
            if let Some(ca) = &signing.ca_file {
                self.validate_part_signing_ca(ca)?;
            }
        }
        Ok(())
    }
}

/// `IoMaxRule::device` placeholder for the whole disk under `data_dir`
/// (NAN-3523). The cell resolves it at cgroup adoption from
/// `stat(data_dir).st_dev`, mapped to its whole disk via `/sys/dev/block`
/// (io.max rejects partitions), so the renderer needs no per-node device.
/// Unresolvable: no io.max for that rule, a WARN and the `io_max_unresolved`
/// signal; the cell still starts.
pub const IO_MAX_DATA_VOLUME: &str = "data_volume";

/// One `io.max` rule applied to every tenant cgroup (delegated mode only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoMaxRule {
    /// Block device as `MAJ:MIN` (e.g. `259:0`), or [`IO_MAX_DATA_VOLUME`].
    pub device: String,
    #[serde(default)]
    pub rbps: Option<u64>,
    #[serde(default)]
    pub wbps: Option<u64>,
    #[serde(default)]
    pub riops: Option<u64>,
    #[serde(default)]
    pub wiops: Option<u64>,
}

impl IoMaxRule {
    /// The `io.max` line, e.g. `259:0 rbps=1048576 wbps=max riops=max wiops=max`.
    pub fn line(&self) -> String {
        let v = |x: Option<u64>| x.map(|n| n.to_string()).unwrap_or_else(|| "max".into());
        format!("{} rbps={} wbps={} riops={} wiops={}", self.device, v(self.rbps), v(self.wbps), v(self.riops), v(self.wiops))
    }

    /// The rule targets the data volume and is resolved at adoption.
    pub fn is_data_volume(&self) -> bool {
        self.device == IO_MAX_DATA_VOLUME
    }

    fn valid_device(&self) -> bool {
        if self.is_data_volume() {
            return true;
        }
        let mut it = self.device.split(':');
        let ok = |p: Option<&str>| p.is_some_and(|x| !x.is_empty() && x.len() <= 10 && x.bytes().all(|b| b.is_ascii_digit()));
        ok(it.next()) && ok(it.next()) && it.next().is_none()
    }
}

/// Per-tenant resource enforcement (NAN-2872). Every tenant gets a
/// **guarantee** (its placement request, which the cell is packed by) and
/// may **burst** into the cell's unused capacity up to a **ceiling**. Over
/// the guarantee is allowed while the cell has headroom; under contention the
/// supervisor throttles (never kills) the tenants above their weighted
/// share. A SIGKILL happens only at a tenant's hard memory ceiling, or when
/// the cell is about to hit its pod memory limit, and then only to the
/// tenant furthest over its guarantee. See `resources.rs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResourceConfig {
    /// Watchdog sampling interval.
    pub interval_ms: u64,
    pub memory_metric: crate::procfs::MemoryMetric,
    /// Cell capacity. Unset: the container's own cgroup `cpu.max` /
    /// `memory.max`, else the node's CPUs / MemTotal. The platform renders the
    /// container limits here.
    pub cell_cpu_millicores: Option<u32>,
    pub cell_memory_bytes: Option<u64>,
    /// CPU ceiling = max(budget limit, factor × guarantee), capped at the
    /// cell. 0 = the whole cell.
    pub cpu_burst_factor: f64,
    /// Hard memory ceiling = factor × the budget's soft limit, capped at the
    /// cell.
    pub memory_hard_factor: f64,
    /// Cell CPU demand ≥ enter × capacity is contention; below exit it ends.
    pub cpu_contention_enter: f64,
    pub cpu_contention_exit: f64,
    pub memory_contention_enter: f64,
    pub memory_contention_exit: f64,
    /// Cell memory ≥ this × capacity: kill the tenant furthest over its
    /// guarantee (never one within it) before the pod limit OOMs the cell.
    pub memory_kill_ratio: f64,
    /// Over-guarantee this long emits `tenant_sustained_pressure`.
    pub sustained_pressure_secs: u64,
    /// Back at or under the guarantee this long resets the pressure clock.
    pub pressure_reset_secs: u64,
    /// EWMA time constant for CPU demand.
    pub cpu_smoothing_secs: f64,
    /// SIGSTOP/SIGCONT duty-cycle period (watchdog mode).
    pub throttle_period_ms: u64,
    /// Lowest duty cycle a throttled tenant is held at.
    pub min_duty: f64,
    /// NAN-3008: never SIGSTOP a tenant's `query[T]` (its uid) in the
    /// watchdog duty cycle. Interactive search keeps running while the
    /// tenant's ingest/detect absorb the throttle, so a legacy EPS-derived
    /// cell total can never starve a cold query start (19 s seen live at a
    /// 450 m cell). Memory ceilings and kills still apply. Delegated
    /// (cgroup) enforcement uses role budgets instead.
    pub query_unthrottled: bool,
    /// Write `cpu.max.burst` (= one period of the ceiling quota) where the
    /// kernel supports it.
    pub cpu_max_burst: bool,
    /// `io.max` rules for every tenant cgroup.
    pub io_max: Vec<IoMaxRule>,
    /// Restart backoff after a limit kill or crash: base × 2^(n-1), capped.
    pub restart_backoff_base_ms: u64,
    pub restart_backoff_max_ms: u64,
    /// NAN-3523: `memory.min` on the supervisor's `init/` cgroup (delegated
    /// mode), capped at 1/16 of the cell's memory.
    pub supervisor_memory_min_bytes: u64,
    /// NAN-3523: the `oom_score_adj` every tenant and warm process raises
    /// itself to before exec (at least the supervisor's + 500, ≤ 1000).
    pub tenant_oom_score_adj: i32,
    /// NAN-3523: per-tenant local-disk soft/hard ceilings (see
    /// [`crate::disk_ceiling`]).
    pub tenant_disk: crate::disk_ceiling::TenantDiskConfig,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            interval_ms: 1000,
            memory_metric: crate::procfs::MemoryMetric::Anon,
            cell_cpu_millicores: None,
            cell_memory_bytes: None,
            cpu_burst_factor: 4.0,
            memory_hard_factor: 1.25,
            cpu_contention_enter: 0.90,
            cpu_contention_exit: 0.80,
            memory_contention_enter: 0.85,
            memory_contention_exit: 0.75,
            memory_kill_ratio: 0.95,
            sustained_pressure_secs: 900,
            pressure_reset_secs: 60,
            cpu_smoothing_secs: 3.0,
            throttle_period_ms: 100,
            min_duty: 0.05,
            query_unthrottled: true,
            cpu_max_burst: true,
            io_max: vec![],
            restart_backoff_base_ms: 1000,
            restart_backoff_max_ms: 60_000,
            supervisor_memory_min_bytes: 256 * 1024 * 1024,
            tenant_oom_score_adj: 500,
            tenant_disk: crate::disk_ceiling::TenantDiskConfig::default(),
        }
    }
}

impl ResourceConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        let r = |v: f64| v.is_finite() && v > 0.0 && v <= 1.0;
        anyhow::ensure!((50..=60_000).contains(&self.interval_ms), "resources.interval_ms must be 50..=60000");
        anyhow::ensure!(self.cpu_burst_factor.is_finite() && self.cpu_burst_factor >= 0.0, "resources.cpu_burst_factor");
        anyhow::ensure!(self.memory_hard_factor.is_finite() && self.memory_hard_factor >= 1.0, "resources.memory_hard_factor must be ≥ 1");
        anyhow::ensure!(r(self.cpu_contention_enter) && r(self.cpu_contention_exit) && self.cpu_contention_exit <= self.cpu_contention_enter,
            "resources.cpu_contention_exit ≤ enter, both in (0, 1]");
        anyhow::ensure!(r(self.memory_contention_enter) && r(self.memory_contention_exit)
            && self.memory_contention_exit <= self.memory_contention_enter, "resources.memory_contention_exit ≤ enter, both in (0, 1]");
        anyhow::ensure!(r(self.memory_kill_ratio) && self.memory_kill_ratio >= self.memory_contention_enter,
            "resources.memory_kill_ratio must be in [memory_contention_enter, 1]");
        anyhow::ensure!(self.min_duty > 0.0 && self.min_duty <= 1.0, "resources.min_duty");
        anyhow::ensure!((10..=10_000).contains(&self.throttle_period_ms), "resources.throttle_period_ms");
        anyhow::ensure!(self.cpu_smoothing_secs.is_finite() && self.cpu_smoothing_secs >= 0.0, "resources.cpu_smoothing_secs");
        anyhow::ensure!(self.restart_backoff_base_ms <= self.restart_backoff_max_ms, "resources.restart_backoff_base_ms ≤ max");
        anyhow::ensure!((0..=1000).contains(&self.tenant_oom_score_adj), "resources.tenant_oom_score_adj must be 0..=1000");
        for rule in &self.io_max {
            anyhow::ensure!(rule.valid_device(), "resources.io_max device {:?} is not MAJ:MIN or {IO_MAX_DATA_VOLUME:?}", rule.device);
        }
        self.tenant_disk.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBudget {
    pub request_millicores: u32,
    pub limit_millicores: u32,
    pub request_memory_bytes: u64,
    pub limit_memory_bytes: u64,
}

/// How the supervisor runs a placed tenant's `ingest[T]` (C1, NAN-2865).
/// Rendered by the platform only for images reporting the
/// `lean_ingest_resident_v1` cell feature: `TenantPlacement` refuses unknown
/// fields, so an older supervisor rejects the whole placement on this key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestMode {
    /// Started by `/wake` (or a query), reaped after `idle_timeout_secs`
    /// without work. The behavior before this field existed.
    #[default]
    OnDemand,
    /// Started on placement (boot and every reload) without a wake, exempt
    /// from the idle reap, respawned with the restart backoff after any exit
    /// or crash. Stall kills, cgroup limits and the watchdog still apply.
    /// Interim for edge-log (`do`/`drain`) tenants until the metrics-only
    /// wake path exists: nothing else wakes their ingest.
    Resident,
}

impl IngestMode {
    pub fn as_str(self) -> &'static str {
        match self {
            IngestMode::OnDemand => "on_demand",
            IngestMode::Resident => "resident",
        }
    }
}

/// The lowest over-commit hold rate a placement may carry (rows/s): a hold slows
/// ingest, it never stops it (NAN-3522).
pub const MIN_INGEST_HOLD_EPS: f64 = 1.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlacement {
    pub tenant_id: TenantId,
    /// Average ingest rate the budget is derived from.
    pub eps: f64,
    /// `"on_demand"` (default) or `"resident"`; any other value refuses the
    /// placement. Gated by the `lean_ingest_resident_v1` cell feature.
    #[serde(default)]
    pub ingest: IngestMode,
    /// Atomically replaced current policy in a tenant-private read-only directory.
    #[serde(default)]
    pub platform_policy_file: Option<PathBuf>,
    /// Tenant-private custom snapshot directory containing current.json.
    #[serde(default)]
    pub custom_context_root: Option<PathBuf>,
    /// The tenant's stored prevalence rarity threshold (1..=10000), passed to
    /// its processes in the assignment. Absent: the worker default 3.
    /// Placement refuses unknown fields, so
    /// render it only for `lean_prevalence_rarity_threshold_v1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prevalence_rarity_threshold: Option<u64>,
    #[serde(default)] pub ingest_request_millicores: Option<u32>,
    #[serde(default)] pub ingest_limit_millicores: Option<u32>,
    #[serde(default)] pub ingest_request_memory_bytes: Option<u64>,
    #[serde(default)] pub ingest_limit_memory_bytes: Option<u64>,
    #[serde(default)] pub detect_request_millicores: Option<u32>,
    #[serde(default)] pub detect_limit_millicores: Option<u32>,
    #[serde(default)] pub detect_request_memory_bytes: Option<u64>,
    #[serde(default)] pub detect_limit_memory_bytes: Option<u64>,
    #[serde(default)] pub query_request_millicores: Option<u32>,
    #[serde(default)] pub query_limit_millicores: Option<u32>,
    #[serde(default)] pub query_request_memory_bytes: Option<u64>,
    #[serde(default)] pub query_limit_memory_bytes: Option<u64>,
    /// NAN-3522 over-commit hold (cell feature `lean_ingest_hold_v2`): ingest[T]
    /// commits at most this many rows per second. Nothing is dropped: the rest
    /// waits in the tenant's edge log / Bronze and drains at this rate. Absent
    /// (the default): no hold. The platform renders it only for a tenant held at
    /// its abuse ceiling, and lifts it before any replay window runs out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_hold_eps: Option<f64>,
    /// NAN-3522: the hold's lease (unix ms). The hold applies only before
    /// it: past it (or without it) ingest[T] runs at full speed whatever
    /// the platform does, so a control-plane outage can never strand a hold
    /// past the edge log's replay window. The platform renews it while it
    /// watches the backlog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_hold_until: Option<u64>,
    /// NAN-4137 (cell feature `lean_tenzir_landing_v1`): the tenant has at
    /// least one active OCSF bucket-drop (Tenzir) source, so the cell keeps
    /// landing[T] running for it (on a cell with `tenzir_landing`). Absent:
    /// false. Placement refuses unknown fields: render it only for that feature.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub landing: bool,
    /// Trusted-local host sizing. Absent on hosted placements: legacy budgets
    /// remain unchanged until the control plane negotiates a new contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_resources: Option<crate::trusted_local::LocalResources>,
}

/// product[T]'s fixed budget (NAN-3148): never placed, never shared with
/// query[T]'s quota.
fn product_budget() -> RoleBudget {
    RoleBudget {
        request_millicores: crate::budget::PRODUCT_REQUEST_MILLICORES,
        limit_millicores: crate::budget::PRODUCT_LIMIT_MILLICORES,
        request_memory_bytes: crate::budget::PRODUCT_REQUEST_MEMORY_BYTES,
        limit_memory_bytes: crate::budget::PRODUCT_LIMIT_MEMORY_BYTES,
    }
}

/// landing[T]'s fixed budget (NAN-4137).
fn landing_budget() -> RoleBudget {
    RoleBudget {
        request_millicores: crate::budget::LANDING_REQUEST_MILLICORES,
        limit_millicores: crate::budget::LANDING_LIMIT_MILLICORES,
        request_memory_bytes: crate::budget::LANDING_REQUEST_MEMORY_BYTES,
        limit_memory_bytes: crate::budget::LANDING_LIMIT_MEMORY_BYTES,
    }
}

impl TenantPlacement {
    /// NAN-3522: the hold in force at `now_ms`: `ingest_hold_eps` only while
    /// its lease (`ingest_hold_until`) has not passed. No lease, no hold.
    pub fn effective_ingest_hold_eps(&self, now_ms: u64) -> Option<f64> {
        self.ingest_hold_eps.filter(|_| self.ingest_hold_until.is_some_and(|until| now_ms < until))
    }

    pub fn effective_role_budget(&self, role: crate::contract::Role) -> RoleBudget {
        use crate::budget::{TenantBudget, DETECT_LIMIT_MILLICORES, DETECT_REQUEST_HOBBY_MILLICORES, DETECT_REQUEST_STANDARD_MILLICORES, MIB, QUERY_LIMIT_MILLICORES, QUERY_REQUEST_MILLICORES};
        use crate::contract::Role;
        if let Some(b) = self.role_budget(role) { return b; }
        let b = TenantBudget::from_eps(self.eps);
        match role {
            Role::Ingest => RoleBudget { request_millicores: b.request_millicores, limit_millicores: b.limit_millicores,
                request_memory_bytes: b.request_memory_bytes, limit_memory_bytes: b.limit_memory_bytes },
            Role::Detect => RoleBudget { request_millicores: if self.eps < 100.0 { DETECT_REQUEST_HOBBY_MILLICORES } else { DETECT_REQUEST_STANDARD_MILLICORES },
                limit_millicores: DETECT_LIMIT_MILLICORES, request_memory_bytes: 128 * MIB, limit_memory_bytes: 256 * MIB },
            Role::Query => RoleBudget { request_millicores: QUERY_REQUEST_MILLICORES, limit_millicores: QUERY_LIMIT_MILLICORES,
                request_memory_bytes: 256 * MIB, limit_memory_bytes: b.query_memory_cap_bytes },
            Role::Maintenance => RoleBudget {
                request_millicores: crate::budget::MAINTENANCE_REQUEST_MILLICORES,
                limit_millicores: crate::budget::MAINTENANCE_LIMIT_MILLICORES,
                request_memory_bytes: crate::budget::MAINTENANCE_REQUEST_MEMORY_BYTES,
                limit_memory_bytes: crate::budget::MAINTENANCE_LIMIT_MEMORY_BYTES },
            Role::Product => product_budget(),
            Role::Landing => landing_budget(),
        }
    }

    /// Does detect[T] run this tenant's rule searches itself? Only when the
    /// cell enables it (`detect_runs_rules`) AND the tenant's detect memory
    /// limit can hold the engine; a legacy 256 MiB detect budget keeps rule
    /// searches on query[T] rather than failing every rule.
    pub fn detect_runs_rules(&self, cell_enabled: bool) -> bool {
        cell_enabled
            && self.effective_role_budget(crate::contract::Role::Detect).limit_memory_bytes
                >= crate::budget::DETECT_RULES_MIN_MEMORY_BYTES
    }

    pub fn legacy(tenant_id: TenantId, eps: f64) -> Self {
        Self { tenant_id, eps, ingest: IngestMode::OnDemand, platform_policy_file: None, custom_context_root: None,
            prevalence_rarity_threshold: None,
            ingest_request_millicores: None, ingest_limit_millicores: None,
            ingest_request_memory_bytes: None, ingest_limit_memory_bytes: None,
            detect_request_millicores: None, detect_limit_millicores: None,
            detect_request_memory_bytes: None, detect_limit_memory_bytes: None,
            query_request_millicores: None, query_limit_millicores: None,
            query_request_memory_bytes: None, query_limit_memory_bytes: None, ingest_hold_eps: None,
            ingest_hold_until: None, landing: false, local_resources: None }
    }

    pub fn role_budget(&self, role: crate::contract::Role) -> Option<RoleBudget> {
        use crate::contract::Role;
        if let Some(local) = &self.local_resources {
            match role {
                Role::Product => return Some(local.product),
                Role::Landing => return Some(local.landing),
                Role::Maintenance => return Some(local.maintenance),
                _ => {}
            }
        }
        let values = match role {
            Role::Ingest => (self.ingest_request_millicores, self.ingest_limit_millicores, self.ingest_request_memory_bytes, self.ingest_limit_memory_bytes),
            Role::Detect => (self.detect_request_millicores, self.detect_limit_millicores, self.detect_request_memory_bytes, self.detect_limit_memory_bytes),
            Role::Query => (self.query_request_millicores, self.query_limit_millicores, self.query_request_memory_bytes, self.query_limit_memory_bytes),
            // Fixed, never placed: the compactor's bounded budget.
            Role::Maintenance => return Some(RoleBudget {
                request_millicores: crate::budget::MAINTENANCE_REQUEST_MILLICORES,
                limit_millicores: crate::budget::MAINTENANCE_LIMIT_MILLICORES,
                request_memory_bytes: crate::budget::MAINTENANCE_REQUEST_MEMORY_BYTES,
                limit_memory_bytes: crate::budget::MAINTENANCE_LIMIT_MEMORY_BYTES }),
            // Fixed, never placed: the product-state builder (NAN-3148).
            Role::Product => return Some(product_budget()),
            // Fixed, never placed: the landing converter (NAN-4137).
            Role::Landing => return Some(landing_budget()),
        };
        match values {
            (Some(request_millicores), Some(limit_millicores), Some(request_memory_bytes), Some(limit_memory_bytes)) =>
                Some(RoleBudget { request_millicores, limit_millicores, request_memory_bytes, limit_memory_bytes }),
            _ => None,
        }
    }

    pub fn has_role_budgets(&self) -> bool {
        self.ingest_request_millicores.is_some() || self.ingest_limit_millicores.is_some()
            || self.ingest_request_memory_bytes.is_some() || self.ingest_limit_memory_bytes.is_some()
            || self.detect_request_millicores.is_some() || self.detect_limit_millicores.is_some()
            || self.detect_request_memory_bytes.is_some() || self.detect_limit_memory_bytes.is_some()
            || self.query_request_millicores.is_some() || self.query_limit_millicores.is_some()
            || self.query_request_memory_bytes.is_some() || self.query_limit_memory_bytes.is_some()
            || self.local_resources.is_some()
    }
}

/// The tenants placed on this cell (rendered by the platform).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Placement {
    /// Must equal the cell's `cell_id` (guards against a mis-mounted file).
    pub cell_id: String,
    /// Monotonic placement revision (for status/metrics).
    #[serde(default)]
    pub revision: u64,
    pub tenants: Vec<TenantPlacement>,
}

impl Placement {
    /// Where the placed tenants' role budgets come from (NAN-2993):
    /// `"placement"` when every tenant carries the twelve `role_budgets_v1`
    /// fields, `"legacy_eps"` when any tenant falls back to the eps-derived
    /// budgets, `"none"` with no tenants placed.
    pub fn role_budget_source(&self) -> &'static str {
        if self.tenants.is_empty() {
            "none"
        } else if self.tenants.iter().all(TenantPlacement::has_role_budgets) {
            "placement"
        } else {
            "legacy_eps"
        }
    }

    pub fn validate(&self, cfg: &CellConfig) -> anyhow::Result<()> {
        anyhow::ensure!(self.cell_id == cfg.cell_id, "placement is for cell {:?}, not {:?}", self.cell_id, cfg.cell_id);
        let mut seen = std::collections::HashSet::new();
        for t in &self.tenants {
            anyhow::ensure!(seen.insert(&t.tenant_id), "tenant {} placed twice", t.tenant_id);
            anyhow::ensure!(t.eps.is_finite() && t.eps >= 0.0, "tenant {} has bad eps", t.tenant_id);
            if let Some(hold) = t.ingest_hold_eps {
                // A hold never stops ingest: zero, negative or NaN would strand the backlog.
                anyhow::ensure!(hold.is_finite() && hold >= crate::config::MIN_INGEST_HOLD_EPS,
                    "tenant {} ingest_hold_eps must be at least {}", t.tenant_id, crate::config::MIN_INGEST_HOLD_EPS);
            }
            anyhow::ensure!(t.prevalence_rarity_threshold.is_none_or(|n| (1..=10_000).contains(&n)),
                "tenant {} prevalence_rarity_threshold must be 1..=10000", t.tenant_id);
            if let Some(policy) = &t.platform_policy_file {
                let tenant = t.tenant_id.as_str();
                anyhow::ensure!(tenant.parse::<uuid::Uuid>().is_ok(), "platform policy tenant must be UUID");
                anyhow::ensure!(policy.is_absolute() && policy.file_name().is_some_and(|n| n == "policy.json")
                    && policy.parent().and_then(|p| p.file_name()).is_some_and(|n| n == tenant),
                    "platform policy must be <tenant UUID>/policy.json");
                anyhow::ensure!(cfg.has_platform_bundle(), "platform policy needs shared bundle");
            }
            if let Some(root) = &t.custom_context_root {
                anyhow::ensure!(t.tenant_id.as_str().parse::<uuid::Uuid>().is_ok(), "custom context tenant must be UUID");
                anyhow::ensure!(root.is_absolute() && root.file_name().is_some_and(|n| n == t.tenant_id.as_str()),
                    "custom context root must end in tenant UUID");
            }
            anyhow::ensure!(!cfg.has_platform_bundle() || t.platform_policy_file.is_some(), "shared bundle needs every placed tenant policy");
            if t.has_role_budgets() {
                for role in crate::contract::Role::ALL {
                    let b = t.role_budget(role).ok_or_else(|| anyhow::anyhow!("tenant {}: missing {} role budget field in placement.json", t.tenant_id, role.as_str()))?;
                    anyhow::ensure!(b.request_millicores > 0 && b.limit_millicores >= b.request_millicores
                        && b.request_memory_bytes > 0 && b.limit_memory_bytes >= b.request_memory_bytes,
                        "tenant {}: invalid {} role budget in placement.json", t.tenant_id, role.as_str());
                }
            } else {
                tracing::warn!(tenant = %t.tenant_id, "placement lacks role budgets; using legacy EPS-derived limits until the control plane updates placement.json");
            }
        }
        anyhow::ensure!(cfg.trusted_local || self.tenants.iter().all(|t| t.local_resources.is_none()),
            "local_resources requires trusted_local");
        if cfg.mode == CellMode::Dedicated {
            anyhow::ensure!(self.tenants.len() <= 1, "a dedicated cell holds exactly one tenant");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(extra: serde_json::Value) -> serde_json::Result<CellConfig> {
        let mut v = serde_json::json!({
            "cell_id": "cell-a", "data_dir": "/d", "state_dir": "/s", "ingest_binary": "/b", "query_binary": "/b",
            "listen_unix": "/r.sock", "router_token_file": "/t", "placement_file": "/p", "dev_key_dir": "/k"
        });
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        serde_json::from_value(v)
    }

    #[test]
    fn trusted_local_is_single_tenant_and_has_no_hosted_authority() {
        let local = serde_json::json!({"trusted_local": true, "mode": "dedicated", "require_landlock": false});
        let cfg = cell(local.clone()).unwrap();
        cfg.validate().unwrap();
        assert!(!cell(serde_json::json!({})).unwrap().trusted_local);
        for extra in [
            serde_json::json!({"mode": "pooled"}),
            serde_json::json!({"control_url": "https://control.example"}),
            serde_json::json!({"cell_identity_file": "/hosted-token"}),
            serde_json::json!({"dev_key_dir": null}),
        ] {
            let mut value = local.clone();
            value.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            assert!(cell(value).unwrap().validate().is_err());
        }
        let placement: Placement = serde_json::from_value(serde_json::json!({
            "cell_id":"cell-a", "tenants":[{"tenant_id":"a","eps":1}, {"tenant_id":"b","eps":1}]
        })).unwrap();
        assert!(placement.validate(&cfg).is_err());
    }

    #[test]
    fn isolation_block() {
        let d = cell(serde_json::json!({})).unwrap();
        assert_eq!(d.isolation, IsolationConfig { cgroup: CgroupPolicy::Auto, watchdog: true, allow_pooled_watchdog_only: false });
        assert!(!serde_json::to_value(&d).unwrap()["isolation"].as_object().unwrap().contains_key("allow_pooled_watchdog_only"));
        d.validate().unwrap();
        let r = cell(serde_json::json!({"isolation": {"cgroup": "require", "watchdog": true}})).unwrap();
        assert_eq!(r.cgroup_policy(), CgroupPolicy::Require);
        let o = cell(serde_json::json!({"isolation": {"cgroup": "off"}})).unwrap();
        assert_eq!((o.cgroup_policy(), o.isolation.watchdog), (CgroupPolicy::Off, true));
        assert!(cell(serde_json::json!({"isolation": {"watchdog": false}})).unwrap().validate().is_err());
        assert!(cell(serde_json::json!({"isolation": {"cgroup": "sometimes"}})).is_err());
        assert!(cell(serde_json::json!({"isolation": {"cgroup": "auto", "extra": 1}})).is_err());
        // The former top-level field is gone (unknown fields are refused).
        assert!(cell(serde_json::json!({"cgroup": "auto"})).is_err());
    }

    /// NAN-3523: `off` on a pooled cell (the default mode) is refused
    /// unless explicitly opted out; dedicated cells may run watchdog-only.
    #[test]
    fn pooled_cells_refuse_cgroup_off() {
        let err = cell(serde_json::json!({"isolation": {"cgroup": "off"}})).unwrap().validate().unwrap_err().to_string();
        assert!(err.contains("pooled") && err.contains("allow_pooled_watchdog_only"), "{err}");
        assert!(cell(serde_json::json!({"mode": "pooled", "isolation": {"cgroup": "off"}})).unwrap().validate().is_err());
        cell(serde_json::json!({"mode": "dedicated", "isolation": {"cgroup": "off"}})).unwrap().validate().unwrap();
        cell(serde_json::json!({"mode": "pooled", "isolation": {"cgroup": "auto"}})).unwrap().validate().unwrap();
        cell(serde_json::json!({"mode": "pooled", "isolation": {"cgroup": "require"}})).unwrap().validate().unwrap();
        let opted = cell(serde_json::json!({"isolation": {"cgroup": "off", "allow_pooled_watchdog_only": true}})).unwrap();
        opted.validate().unwrap();
        assert!(opted.isolation.allow_pooled_watchdog_only);
    }

    /// NAN-2984: `ingest_flush` is optional (code default when absent),
    /// bounds-checked, and refuses unknown keys.
    #[test]
    fn ingest_flush_config() {
        let none = cell(serde_json::json!({})).unwrap();
        assert_eq!(none.ingest_flush, None);
        let set = cell(serde_json::json!({"ingest_flush": {"min_age_ms": 2000, "max_age_ms": 8000, "target_rows": 2000}})).unwrap();
        set.validate().unwrap();
        assert_eq!(set.ingest_flush, Some(crate::contract::IngestFlush { min_age_ms: 2_000, max_age_ms: 8_000, target_rows: 2_000 }));
        let ceiling = crate::contract::IngestFlush::MAX_TARGET_ROWS;
        for rows in [65_537, ceiling] {
            cell(serde_json::json!({"ingest_flush": {"min_age_ms": 2000, "max_age_ms": 8000, "target_rows": rows}}))
                .unwrap().validate().unwrap();
        }
        assert!(cell(serde_json::json!({"ingest_flush": {"min_age_ms": 2000, "max_age_ms": 8000, "target_rows": ceiling + 1}}))
            .unwrap().validate().is_err());
        for bad in [
            serde_json::json!({"min_age_ms": 500, "max_age_ms": 8000, "target_rows": 2000}),
            serde_json::json!({"min_age_ms": 2000, "max_age_ms": 180000, "target_rows": 2000}),
            serde_json::json!({"min_age_ms": 9000, "max_age_ms": 8000, "target_rows": 2000}),
            serde_json::json!({"min_age_ms": 2000, "max_age_ms": 8000, "target_rows": 0}),
        ] {
            assert!(cell(serde_json::json!({"ingest_flush": bad.clone()})).unwrap().validate().is_err(), "{bad}");
        }
        assert!(cell(serde_json::json!({"ingest_flush": {"min_age_ms": 2000, "max_age_ms": 8000, "target_rows": 2000, "x": 1}})).is_err());
        assert!(cell(serde_json::json!({"ingest_flush": {"max_age_ms": 8000}})).is_err());
    }

    /// NAN-2989: query residency knobs default in code (1 h idle, resident
    /// while ingest worked in the last 24 h) and are overridable.
    #[test]
    fn query_residency_config() {
        use crate::contract::Role;
        let d = cell(serde_json::json!({})).unwrap();
        d.validate().unwrap();
        assert_eq!(d.idle_timeout_for(Role::Query), Duration::from_secs(3_600));
        assert_eq!(d.idle_timeout_for(Role::Detect), Duration::from_secs(600));
        assert_eq!(d.idle_timeout_for(Role::Ingest), Duration::from_secs(600));
        assert_eq!(d.query_resident_ingest_window(), Some(Duration::from_secs(86_400)));
        // NAN-3008 defaults: always resident, search window 24 h, query never duty-cycled.
        assert!(d.query_resident && d.resources.query_unthrottled);
        assert_eq!(d.query_resident_search_window(), Some(Duration::from_secs(86_400)));
        let off = cell(serde_json::json!({"query_resident": false, "query_resident_search_window_secs": 0, "resources": {"query_unthrottled": false}})).unwrap();
        off.validate().unwrap();
        assert!(!off.query_resident && !off.resources.query_unthrottled && off.query_resident_search_window().is_none());
        let c = cell(serde_json::json!({"query_idle_timeout_secs": 7200, "query_resident_ingest_window_secs": 0})).unwrap();
        c.validate().unwrap();
        assert_eq!(c.idle_timeout_for(Role::Query), Duration::from_secs(7_200));
        assert_eq!(c.query_resident_ingest_window(), None);
        assert!(cell(serde_json::json!({"query_idle_timeout_secs": 0})).unwrap().validate().is_err());
    }

    /// `ingest_merge_policy` is optional, per-field optional, range-checked.
    #[test]
    fn ingest_merge_policy_config() {
        assert_eq!(cell(serde_json::json!({})).unwrap().ingest_merge_policy, None);
        let set = cell(serde_json::json!({"ingest_merge_policy": {"sealed_remerge_debounce_ms": 900000, "max_merges_per_tick": 1}})).unwrap();
        set.validate().unwrap();
        let policy = set.ingest_merge_policy.unwrap();
        assert_eq!(policy.sealed_remerge_debounce_ms, Some(900_000));
        assert_eq!(policy.max_merges_per_tick, Some(1));
        assert_eq!(policy.hour_seal_ms, None);
        for bad in [
            serde_json::json!({"hour_seal_ms": 1000}),
            serde_json::json!({"max_merges_per_tick": 0}),
            serde_json::json!({"sealed_remerge_max_defer_ms": 86_400_001}),
            serde_json::json!({"sealed_remerge_debounce_ms": 3_600_000, "sealed_remerge_max_defer_ms": 600_000}),
        ] {
            assert!(cell(serde_json::json!({"ingest_merge_policy": bad.clone()})).unwrap().validate().is_err(), "{bad}");
        }
        assert!(cell(serde_json::json!({"ingest_merge_policy": {"x": 1}})).is_err());
    }

    #[test]
    fn platform_bundle_dir_config() {
        let ok = cell(serde_json::json!({"feed_dir": "/feeds", "platform_bundle_dir": "/feeds"})).unwrap();
        ok.validate().unwrap();
        assert!(ok.has_platform_bundle());
        cell(serde_json::json!({"feed_dir": "/feeds", "platform_bundle_dir": "/feeds/platform"})).unwrap().validate().unwrap();
        // Outside feed_dir, relative, `..`, no feed_dir, or together with the file: refused.
        for bad in [
            serde_json::json!({"feed_dir": "/feeds", "platform_bundle_dir": "/other"}),
            serde_json::json!({"feed_dir": "/feeds", "platform_bundle_dir": "feeds"}),
            serde_json::json!({"feed_dir": "/feeds", "platform_bundle_dir": "/feeds/../etc"}),
            serde_json::json!({"platform_bundle_dir": "/feeds"}),
            serde_json::json!({"feed_dir": "/feeds", "platform_bundle_dir": "/feeds", "platform_bundle_file": "/feeds/b"}),
        ] {
            assert!(cell(bad.clone()).unwrap().validate().is_err(), "{bad}");
        }
        // A placed tenant policy is satisfied by the directory form too.
        let placed: Placement = serde_json::from_value(serde_json::json!({"cell_id":"cell-a","tenants":[{
            "tenant_id":"6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00","eps":20.0,
            "platform_policy_file":"/policies/6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00/policy.json"}]})).unwrap();
        placed.validate(&ok).unwrap();
        let unpolicied: Placement = serde_json::from_value(serde_json::json!({"cell_id":"cell-a","tenants":[{"tenant_id":"t1","eps":20.0}]})).unwrap();
        assert!(unpolicied.validate(&ok).is_err(), "a shared bundle needs every placed tenant policy");
    }

    #[test]
    fn placement_role_budget_contract_is_all_or_none() {
        let cfg = cell(serde_json::json!({})).unwrap();
        let old: Placement = serde_json::from_value(serde_json::json!({"cell_id":"cell-a","tenants":[{"tenant_id":"t1","eps":20.0}]})).unwrap();
        old.validate(&cfg).unwrap();
        let mut v = serde_json::json!({"cell_id":"cell-a","tenants":[{"tenant_id":"t1","eps":300.0,
            "ingest_request_millicores":400,"ingest_limit_millicores":2000,
            "ingest_request_memory_bytes":2684354560u64,"ingest_limit_memory_bytes":6979321856u64,
            "detect_request_millicores":150,"detect_limit_millicores":500,
            "detect_request_memory_bytes":134217728u64,"detect_limit_memory_bytes":268435456u64,
            "query_request_millicores":250,"query_limit_millicores":3000,
            "query_request_memory_bytes":268435456u64,"query_limit_memory_bytes":4892233728u64} ]});
        let placed: Placement = serde_json::from_value(v.clone()).unwrap();
        placed.validate(&cfg).unwrap();
        assert_eq!(placed.role_budget_source(), "placement");
        assert_eq!(old.role_budget_source(), "legacy_eps");
        assert_eq!(Placement { cell_id: "cell-a".into(), revision: 0, tenants: vec![] }.role_budget_source(), "none");
        let mut mixed = placed.clone();
        mixed.tenants.push(TenantPlacement::legacy(TenantId::new("t2").unwrap(), 20.0));
        assert_eq!(mixed.role_budget_source(), "legacy_eps");
        assert_eq!(placed.tenants[0].effective_role_budget(crate::contract::Role::Detect).request_millicores, 150);
        v["tenants"][0].as_object_mut().unwrap().remove("detect_limit_millicores");
        assert!(serde_json::from_value::<Placement>(v.clone()).unwrap().validate(&cfg).is_err());
        v["tenants"][0]["detect_limit_millicores"] = serde_json::json!(100);
        assert!(serde_json::from_value::<Placement>(v).unwrap().validate(&cfg).is_err());
    }

    #[test]
    fn placement_ingest_mode_is_strict_and_defaults_to_on_demand() {
        let cfg = cell(serde_json::json!({})).unwrap();
        let parse = |tenant: serde_json::Value| serde_json::from_value::<Placement>(serde_json::json!({"cell_id":"cell-a","tenants":[tenant]}));
        let old = parse(serde_json::json!({"tenant_id":"t1","eps":20.0})).unwrap();
        assert_eq!(old.tenants[0].ingest, IngestMode::OnDemand);
        assert_eq!(TenantPlacement::legacy(TenantId::new("t1").unwrap(), 1.0).ingest, IngestMode::OnDemand);
        let on_demand = parse(serde_json::json!({"tenant_id":"t1","eps":20.0,"ingest":"on_demand"})).unwrap();
        assert_eq!(on_demand, old);
        let resident = parse(serde_json::json!({"tenant_id":"t1","eps":20.0,"ingest":"resident"})).unwrap();
        resident.validate(&cfg).unwrap();
        assert_eq!(resident.tenants[0].ingest, IngestMode::Resident);
        for bad in [serde_json::json!("warm"), serde_json::json!("Resident"), serde_json::json!(""), serde_json::json!(true), serde_json::json!(null)] {
            assert!(parse(serde_json::json!({"tenant_id":"t1","eps":20.0,"ingest":bad})).is_err(), "ingest {bad} accepted");
        }
        // Still deny_unknown_fields: a near-miss key is refused, not ignored.
        assert!(parse(serde_json::json!({"tenant_id":"t1","eps":20.0,"ingest_mode":"resident"})).is_err());
    }

    /// NAN-3440: `upstream_readiness` is optional (off when absent),
    /// validated at load, and refuses unknown keys.
    #[test]
    fn upstream_readiness_config() {
        let none = cell(serde_json::json!({})).unwrap();
        assert!(none.upstream_readiness.is_none());
        assert!(!serde_json::to_value(&none).unwrap().as_object().unwrap().contains_key("upstream_readiness"));
        let targets = serde_json::json!([{"name": "r2", "url": "https://acct.r2.cloudflarestorage.com/"},
            {"name": "control", "url": "https://api.nano.rs/api/health"}]);
        let on = cell(serde_json::json!({"upstream_readiness": {"targets": targets.clone(),
            "interval_secs": 15, "timeout_secs": 5, "not_ready_after_secs": 180}})).unwrap();
        on.validate().unwrap();
        assert_eq!(on.upstream_readiness.as_ref().unwrap().targets.len(), 2);
        for bad in [
            serde_json::json!({"targets": [{"name": "r2", "url": "http://acct.r2.cloudflarestorage.com/"}]}),
            serde_json::json!({"targets": [{"name": "r2", "url": "https://a.example/"}, {"name": "r2", "url": "https://b.example/"}]}),
            serde_json::json!({"targets": targets.clone(), "interval_secs": 10, "timeout_secs": 10}),
            serde_json::json!({"targets": targets.clone(), "interval_secs": 120, "not_ready_after_secs": 180}),
        ] {
            assert!(cell(serde_json::json!({"upstream_readiness": bad.clone()})).unwrap().validate().is_err(), "{bad}");
        }
        assert!(cell(serde_json::json!({"upstream_readiness": {"targets": targets, "extra": 1}})).is_err());
    }

    #[test]
    fn resource_config_defaults_and_validation() {
        let d = ResourceConfig::default();
        d.validate().unwrap();
        assert_eq!(d.interval_ms, 1000);
        let parsed: ResourceConfig = serde_json::from_str(r#"{"interval_ms": 500, "io_max": [{"device": "259:0", "wbps": 1048576}]}"#).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.io_max[0].line(), "259:0 rbps=max wbps=1048576 riops=max wiops=max");
        assert_eq!(parsed.sustained_pressure_secs, 900);
        let dv: ResourceConfig = serde_json::from_str(r#"{"io_max": [{"device": "data_volume", "rbps": 1, "wbps": 2}]}"#).unwrap();
        dv.validate().unwrap();
        assert!(dv.io_max[0].is_data_volume());
        for bad in [
            r#"{"interval_ms": 0}"#,
            r#"{"cpu_contention_enter": 0.5, "cpu_contention_exit": 0.9}"#,
            r#"{"memory_kill_ratio": 0.5}"#,
            r#"{"memory_hard_factor": 0.5}"#,
            r#"{"io_max": [{"device": "sda"}]}"#,
            r#"{"io_max": [{"device": "8:0\n+memory"}]}"#,
            r#"{"io_max": [{"device": "data_volume:1"}]}"#,
            r#"{"io_max": [{"device": "auto"}]}"#,
        ] {
            let c: ResourceConfig = serde_json::from_str(bad).unwrap();
            assert!(c.validate().is_err(), "{bad} accepted");
        }
        assert!(serde_json::from_str::<ResourceConfig>(r#"{"nope": 1}"#).is_err());
    }
}

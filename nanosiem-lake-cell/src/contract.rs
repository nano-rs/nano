// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cell ⇄ tenant-process contract (NAN-2871, lean lake phase 5).
//!
//! This is the whole interface between the cell supervisor and the per-tenant
//! `ingest[T]` / `query[T]` processes that phases 2 and 3 build. A tenant
//! binary is started with exactly one argument pair and one inherited fd:
//!
//! ```text
//! <tenant-binary> --cell-control-fd 3
//! ```
//!
//! fd 3 is a connected `AF_UNIX`/`SOCK_SEQPACKET` socket to the supervisor.
//! The environment is empty except `LANG`, `PATH`, `HOME`, `TMPDIR` and
//! `RUST_LOG`. **Nothing secret is ever passed in argv or env.** The process
//! lifecycle over fd 3 is:
//!
//! 1. child → `Hello` (pid, protocol version). The child is *unassigned*
//!    ("warm"): it may load libraries (libchdb) but must stay
//!    single-threaded and must not open tenant data.
//! 2. supervisor → `Assign` (tenant, role, [`JailSpec`], directories, caps).
//! 3. child applies the jail **in-process** ([`crate::jail::apply`]): drops to
//!    the tenant uid/gid, `PR_SET_DUMPABLE=0`, `no_new_privs`, landlock,
//!    seccomp. The drop is irreversible. child → `Jailed`.
//! 4. supervisor checks `/proc/<pid>/status` shows the tenant uid, then sends
//!    `Secrets` with a sealed memfd attached (`SCM_RIGHTS`). The child reads it
//!    once and closes it. The memfd holds the tenant-scoped bootstrap token
//!    the control plane minted for this assignment; the child exchanges it
//!    for its real credentials. The supervisor never holds tenant keys.
//! 5. child → `Ready`. From here on:
//!    - supervisor → `Rpc` with a connected `SOCK_STREAM` attached: one
//!      routed request (HTTP/1.1) per stream. Tenant processes never listen.
//!    - supervisor → `Wake { reason }` (data arrival, detection schedule).
//!    - supervisor → `Shutdown { grace_ms }`; child exits 0 within the grace.
//!    - child → `Heartbeat` at least every [`HEARTBEAT_INTERVAL_MAX`]. The
//!      supervisor derives stall/lag signals from it (the NAN-2780 pattern).
//!    - child → `Fatal { error }` just before exiting on an unrecoverable
//!      error.
//!
//! [`crate::child`] implements the child side; phase 2/3 binaries call
//! [`crate::child::bootstrap`] first thing in `main`, before starting any
//! runtime or thread.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Bumped on any incompatible change to [`ToChild`] / [`ToSupervisor`].
pub const PROTOCOL_VERSION: u32 = 2;

/// The fd number the control socket is installed at in the child.
pub const CONTROL_FD: i32 = 3;

/// The argv flag naming the control fd.
pub const CONTROL_FD_FLAG: &str = "--cell-control-fd";

/// Largest control message (JSON) in either direction.
pub const MAX_CONTROL_MESSAGE: usize = 64 * 1024;

/// A child that has not sent a heartbeat for this long is late.
pub const HEARTBEAT_INTERVAL_MAX: Duration = Duration::from_secs(15);

/// NAN-3524: the platform route a LEAN tenant's `lake_part_receipt_reconcile`
/// Job exchanges its projected token at, `{control_url}/v1/lake/cells/{cell}/<leaf>`,
/// for a read-only `lake_part_read` credential. No cell process uses it.
pub const RECEIPT_RECONCILE_EXCHANGE_LEAF: &str = "receipt-reconcile-exchange";
/// NAN-3524: that Job's projected-token audience (cells use `nano-lake-cell`).
pub const RECEIPT_RECONCILE_AUDIENCE: &str = "nano-lake-receipt-reconcile";

/// Largest secret blob delivered over the secrets memfd.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Holds write credentials and the tenant signing key; writes parts.
    Ingest,
    /// Scheduled detections and the tenant finding drain; holds scoped part
    /// writer, signing, and tenant-RLS finding_drain authority.
    Detect,
    /// Holds read-only credentials; never sees the signing key.
    Query,
    /// The tenant prevalence SlateDB compactor (`lean_prevalence_maintenance_v1`):
    /// a read-only state credential and the owner's MAINTENANCE bearer
    /// (`writer_class: maintenance`); no part, log or signing authority.
    /// Resident beside ingest when `prevalence_maintenance` is set.
    Maintenance,
    /// NAN-3148 (`lean_product_state_role_v1`): builds the tenant's product
    /// state (prevalence explorer windows, 30-day history, detail and the
    /// risk ledger) under its OWN cgroup budget and publishes versioned
    /// snapshots that query[T] only reads. Served by the query binary, runs
    /// as query's uid with query's read-only credential class; it never
    /// receives a routed request. Resident beside query[T] when the cell
    /// sets `product_state_role`.
    Product,
}

/// Number of roles (sizes per-role arrays).
pub const ROLES: usize = 5;

impl Role {
    pub const ALL: [Role; ROLES] = [Role::Ingest, Role::Detect, Role::Query, Role::Maintenance, Role::Product];

    /// The role a bootstrap token is minted and exchanged for. product[T]
    /// holds exactly query[T]'s read-only authority, so it asks for that
    /// class: the control plane needs no new role.
    pub fn credential_role(self) -> Role {
        match self {
            Role::Product => Role::Query,
            other => other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Ingest => "ingest",
            Role::Detect => "detect",
            Role::Query => "query",
            Role::Maintenance => "maintenance",
            Role::Product => "product",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "ingest" => Some(Role::Ingest),
            "detect" => Some(Role::Detect),
            "query" => Some(Role::Query),
            "maintenance" => Some(Role::Maintenance),
            "product" => Some(Role::Product),
            _ => None,
        }
    }

}

/// A validated tenant id: `[a-z0-9][a-z0-9_-]{0,62}`. It is used as a path
/// component and a cgroup name, so it is validated at every boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    pub fn new(s: &str) -> Result<Self, InvalidTenantId> {
        let ok = !s.is_empty()
            && s.len() <= 63
            && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(InvalidTenantId(s.chars().take(80).collect()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for TenantId {
    type Error = InvalidTenantId;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        TenantId::new(&s)
    }
}

impl From<TenantId> for String {
    fn from(t: TenantId) -> String {
        t.0
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid tenant id {0:?}: want [a-z0-9][a-z0-9_-]{{0,62}}")]
pub struct InvalidTenantId(pub String);

/// Why a process was woken or spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeReason {
    /// The raw-handoff DO reported new objects for the tenant.
    DataArrival,
    /// An interactive or API query.
    Query,
    /// A scheduled detection run.
    Detection,
    /// Warm-up requested by placement (e.g. just moved to this cell).
    Prewarm,
}

impl WakeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            WakeReason::DataArrival => "data_arrival",
            WakeReason::Query => "query",
            WakeReason::Detection => "detection",
            WakeReason::Prewarm => "prewarm",
        }
    }
}

/// What the tenant process may touch. Built by the supervisor, applied by
/// the child in [`crate::jail::apply`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailSpec {
    pub uid: u32,
    pub gid: u32,
    /// Directories the process may read and write (its own role dir, its
    /// tmp dir, and for ingest the tenant parts dir).
    pub rw_paths: Vec<PathBuf>,
    /// Directories the process may only read (query: the tenant parts dir;
    /// both: the shared read-only feed dir).
    pub ro_paths: Vec<PathBuf>,
    /// System paths needed to run (libs, CA bundle, resolver config).
    /// Read + execute only.
    pub system_ro_paths: Vec<PathBuf>,
    /// TCP ports the process may connect to (R2/HTTPS: 443). Binding any TCP
    /// port is always denied.
    pub tcp_connect_ports: Vec<u16>,
    /// The cgroup directory (relative to the cgroup2 mount) the process is
    /// in; granted read-only so the engine can read its own limits.
    pub cgroup_dir: Option<PathBuf>,
    /// Refuse to run if landlock is not fully enforced.
    pub require_landlock: bool,
    /// RLIMIT_NPROC for the tenant uid (the pids fallback without cgroups).
    pub max_processes: Option<u64>,
    /// RLIMIT_CORE is always 0; RLIMIT_NOFILE soft/hard.
    pub max_open_files: u64,
}

/// Directories and caps handed to the tenant process in `Assign`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assignment {
    pub tenant: TenantId,
    pub role: Role,
    pub cell_id: String,
    /// The tenant root, `<cell data>/tenants/<T>` (not writable by the role).
    pub tenant_dir: PathBuf,
    /// Shared ingest→query part directory (`<tenant>/parts`).
    pub parts_dir: PathBuf,
    /// The role's private state directory (0700).
    pub state_dir: PathBuf,
    /// The role's private tmp directory (0700). No shared `/tmp`.
    pub tmp_dir: PathBuf,
    /// Read-only enrichment feed files (the only shared input).
    pub feed_dir: Option<PathBuf>,
    /// Supervisor-rendered enrichment paths; never taken from ambient env.
    #[serde(default)]
    pub platform_bundle_file: Option<PathBuf>,
    /// Directory of content-addressed `platform-<sha256>.nanpfb` bundles; the
    /// tenant policy's `bundle_sha256` selects one. Exclusive with the file.
    #[serde(default)]
    pub platform_bundle_dir: Option<PathBuf>,
    #[serde(default)]
    pub platform_policy_file: Option<PathBuf>,
    #[serde(default)]
    pub custom_context_root: Option<PathBuf>,
    /// Memory the engine should stay under (chDB `max_server_memory_usage`).
    pub memory_cap_bytes: u64,
    /// CPU budget in millicores (engine thread sizing).
    pub cpu_millis: u32,
    /// Tenant ingest rate the budget was derived from.
    pub eps: f64,
    pub jail: JailSpec,
    /// The control plane base URL the process exchanges its bootstrap token
    /// at (`POST {control_url}/v1/lake/cells/{cell_id}/credential-exchange`).
    /// Not a secret. `None` for dev cells with a directory key source.
    #[serde(default)]
    pub control_url: Option<String>,
    /// The tenant's stored prevalence rarity threshold (`host_count < N` is
    /// rare), copied from its placement. `None`: no stored value, and the
    /// worker applies the default 3 (see
    /// `nanosiem_lake_worker::prevalence::rarity_threshold_for`). Older
    /// children ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prevalence_rarity_threshold: Option<u64>,
    /// Where and how `ingest` and `detect` get part provenance owner-signed. Rendered by
    /// the platform into the release-pinned cell config (never from tenant
    /// input); the supervisor copies it verbatim. `None` for query.
    #[serde(default)]
    pub part_signing: Option<PartSigning>,
    /// NAN-2884: true only when the owner trusts R2's stored checksum
    /// (`controlPlane.owner.lakePartRequireChecksum`); lifts ingest's interim
    /// 2 GiB part cap. Defaults to false. The platform renders it in lockstep
    /// with the owner flag, never ahead of it.
    #[serde(default)]
    pub owner_requires_checksum: bool,
    /// Whether `ingest[T]` exits after 10 idle minutes. `None`: the process
    /// decides by input (edge-log tenants stay up, since nothing wakes them
    /// until the metrics-only wake token exists; bronze/lab tenants exit).
    #[serde(default)]
    pub ingest_idle_exit: Option<bool>,
    /// Plan `d` parts (default false: `h` is the top level). Interim until
    /// control's writer authority covers multi-hour parts (NAN-2886).
    #[serde(default)]
    pub ingest_day_merges: bool,
    /// NAN-3032 (`lean_keyword_index_v1`): write v2 `tokens.nti` token block
    /// indexes. Default false (v1). Readers understand both.
    #[serde(default)]
    pub ingest_keyword_index: bool,
    /// NAN-3058 (`lean_identity_observations_v1`): ingest writes identity
    /// observation rows into its parts; query backfills older parts.
    /// Default false. Older children ignore it.
    #[serde(default)]
    pub identity_observations: bool,
    /// NAN-3503 (`lean_identity_directory_enrich_v1`): ingest stamps the
    /// tenant identity directory (R2 enrichment prefix) onto `actor.user` /
    /// `user` and appends `enrichments[]` type `identity`. Default false.
    /// Older children ignore it.
    #[serde(default)]
    pub identity_directory_enrich: bool,
    /// L0 flush policy override for `ingest[T]` (NAN-2984). `None`: the
    /// ingest code default (10 s age cap). Older children ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_flush: Option<IngestFlush>,
    /// Merge policy overrides for `ingest[T]` (cell feature
    /// `ingest_merge_policy_v1`). `None`: the ingest code defaults, which
    /// already debounce sealed-hour re-merges during a catch-up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_merge_policy: Option<IngestMergePolicy>,
    /// NAN-3522 over-commit hold for `ingest[T]`: commit at most this many
    /// rows/s (token bucket); the rest stays in the edge log / Bronze and
    /// drains at this rate. `None`: no hold. Older children ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_hold_eps: Option<f64>,
    /// query: hold readiness (`/v1/status` 503 `not_ready`) until the startup
    /// prewarm completes, whatever the bootstrap says (NAN-3004). Set only for
    /// the startup warm of a zero-downtime pod, whose readiness waits on it
    /// while the old pod serves; a respawn after that stays lazy (NAN-2989).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub query_prewarm_before_ready: bool,
    /// detect: open the part-query engine and serve the tenant's rule
    /// searches, detection gate and prevalence in THIS process, under
    /// detect's own cgroup (cell `detect_runs_rules` and a detect budget of
    /// at least [`crate::budget::DETECT_RULES_MIN_MEMORY_BYTES`]). Unset:
    /// finding drain only, and the router forwards `/detect/...` to query[T].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub detect_runs_rules: bool,
    /// query: product state is built by product[T] (NAN-3148, cell
    /// `product_state_role`) and published under `<tenant_dir>/product`;
    /// this process only reads those snapshots and never builds product
    /// state itself. Unset: query[T] builds it in-process (legacy).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub product_state_role: bool,
    /// query/product (NAN-3799): product[T]'s published directory. On a
    /// cell with the persistent A/B hot volume (NAN-3647) it lives there,
    /// `<hot>/tenants/<T>/product`, so a rolled cell serves the windows it
    /// finds at once and rebuilds them in the background. Unset (older
    /// supervisors): `<tenant_dir>/product`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_dir: Option<PathBuf>,
    /// NAN-3492: the cell is the explicitly trusted-local single-tenant
    /// install (cell.json `trusted_local`, rendered by `trusted-local
    /// init`). Gates hosted-only absences such as platform enrichment.
    /// Unset on every hosted cell; older children ignore it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trusted_local: bool,
}

/// When `ingest[T]` cuts an L0 part (NAN-2984): at most `max_age_ms` after
/// the first buffered row arrived, sooner (down to `min_age_ms`) once the
/// tenant's rate fills `target_rows`. The age cap is the ingest share of
/// arrival→searchable at low rates; lowering it raises L0 parts/hour
/// (3,600 s / interval), owner-sign calls and R2 PUTs proportionally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestFlush {
    pub min_age_ms: u64,
    pub max_age_ms: u64,
    pub target_rows: u64,
}

impl IngestFlush {
    /// Accepted ages: at least 1 s between parts, at most the 2-minute
    /// visibility ceiling. Mirrors `FlushPolicy::validate` in the worker.
    pub const AGE_FLOOR_MS: u64 = 1_000;
    pub const AGE_CEILING_MS: u64 = 120_000;
    /// The ingest per-flush row cap (`FLUSH_MAX_ROWS`).
    pub const MAX_TARGET_ROWS: u64 = 65_536;

    pub fn validate(&self) -> anyhow::Result<()> {
        let ages = Self::AGE_FLOOR_MS..=Self::AGE_CEILING_MS;
        anyhow::ensure!(
            ages.contains(&self.min_age_ms) && ages.contains(&self.max_age_ms),
            "ingest_flush ages must be within {}..={} ms",
            Self::AGE_FLOOR_MS,
            Self::AGE_CEILING_MS
        );
        anyhow::ensure!(self.min_age_ms <= self.max_age_ms, "ingest_flush.min_age_ms exceeds max_age_ms");
        anyhow::ensure!(
            (1..=Self::MAX_TARGET_ROWS).contains(&self.target_rows),
            "ingest_flush.target_rows must be 1..={}",
            Self::MAX_TARGET_ROWS
        );
        Ok(())
    }
}

/// Merge policy overrides for `ingest[T]` (cell feature
/// `ingest_merge_policy_v1`). Every field is optional; an absent field keeps
/// the ingest code default. The lean test tenant's catch-up wedge (2026-09-29): a
/// resume ~1.6 h behind fed every L0 into an already-sealed hour, and each
/// one planned a synchronous rewrite of the whole hour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestMergePolicy {
    /// An hour is sealed (eligible for its `h` merge) this long after it ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hour_seal_ms: Option<u64>,
    /// A sealed hour re-merges once its newest unmerged part is this old...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_remerge_debounce_ms: Option<u64>,
    /// ...or once its oldest unmerged part is this old.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_remerge_max_defer_ms: Option<u64>,
    /// Merges run per ingest tick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_merges_per_tick: Option<u32>,
}

impl IngestMergePolicy {
    pub const HOUR_SEAL_MS: std::ops::RangeInclusive<u64> = 60_000..=86_400_000;
    pub const DEBOUNCE_MS: std::ops::RangeInclusive<u64> = 0..=21_600_000;
    pub const MAX_DEFER_MS: std::ops::RangeInclusive<u64> = 60_000..=86_400_000;
    pub const MERGES_PER_TICK: std::ops::RangeInclusive<u32> = 1..=16;
    /// The ingest code defaults (mirrors `MergePolicy::default` in the worker).
    pub const DEFAULT_DEBOUNCE_MS: u64 = 300_000;
    pub const DEFAULT_MAX_DEFER_MS: u64 = 1_800_000;

    pub fn validate(&self) -> anyhow::Result<()> {
        let within = |value: Option<u64>, range: &std::ops::RangeInclusive<u64>, name: &str| {
            anyhow::ensure!(value.is_none_or(|v| range.contains(&v)),
                "ingest_merge_policy.{name} must be within {}..={}", range.start(), range.end());
            Ok(())
        };
        within(self.hour_seal_ms, &Self::HOUR_SEAL_MS, "hour_seal_ms")?;
        within(self.sealed_remerge_debounce_ms, &Self::DEBOUNCE_MS, "sealed_remerge_debounce_ms")?;
        within(self.sealed_remerge_max_defer_ms, &Self::MAX_DEFER_MS, "sealed_remerge_max_defer_ms")?;
        anyhow::ensure!(
            self.max_merges_per_tick.is_none_or(|v| Self::MERGES_PER_TICK.contains(&v)),
            "ingest_merge_policy.max_merges_per_tick must be within {}..={}",
            Self::MERGES_PER_TICK.start(),
            Self::MERGES_PER_TICK.end()
        );
        let debounce = self.sealed_remerge_debounce_ms.unwrap_or(Self::DEFAULT_DEBOUNCE_MS);
        let defer = self.sealed_remerge_max_defer_ms.unwrap_or(Self::DEFAULT_MAX_DEFER_MS);
        anyhow::ensure!(debounce <= defer, "ingest_merge_policy.sealed_remerge_debounce_ms exceeds sealed_remerge_max_defer_ms");
        Ok(())
    }
}

/// Non-secret owner-signing configuration for `ingest[T]` (part contract
/// §4.4): the owner's pooled-cell `lake-parts:sign` URL, the release signer
/// key id records must name, and the public keys to verify with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartSigning {
    pub url: String,
    pub signer_key_id: String,
    pub trusted_keys: Vec<TrustedSignerKey>,
    /// PEM bundle (one or more CA certs, for rotation overlap) that is the
    /// ONLY trust root for the owner's TLS certificate; system roots are never
    /// used. Required by `ingest` for an `https` URL. Re-read on every
    /// credential refresh. Cell feature `lean_part_sign_ca_v1`: older images
    /// reject this key (`deny_unknown_fields`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSignerKey {
    pub key_id: String,
    /// 32-byte ed25519 public key, lowercase hex.
    pub public_key_hex: String,
}

/// Supervisor → child.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToChild {
    Assign { protocol_version: u32, assignment: Box<Assignment> },
    /// A sealed memfd is attached. Sent once in the handshake and again in
    /// answer to `RefreshSecrets`.
    Secrets,
    /// A connected stream socket carrying one routed request is attached.
    Rpc { request_id: u64 },
    /// Only the supervisor's Detect→ingest handoff may carry a finding append.
    FindingAppend { request_id: u64 },
    /// A connected stream to this tenant's ingest appender, requested by
    /// Detect. The supervisor creates both ends and checks the source role.
    PeerRpc { request_id: u64 },
    Wake { reason: WakeReason },
    Shutdown { grace_ms: u64 },
}

/// Child → supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToSupervisor {
    Hello { pid: u32, protocol_version: u32 },
    Jailed { uid: u32, gid: u32, landlock: String, seccomp: bool },
    Ready,
    Heartbeat(Heartbeat),
    Fatal { error: String },
    /// After `Ready`: ask for a fresh bootstrap secret (the previous one was
    /// single-use and its credentials are nearing expiry). The supervisor
    /// mints a new one and answers with `Secrets` + memfd, rate-limited.
    RefreshSecrets,
    /// Detect alone may ask for a preopened stream to its tenant's ingest.
    ConnectIngest { request_id: u64 },
    /// Ingest finished the routed append, including any durable response.
    FindingAppendComplete { request_id: u64 },
}

/// Liveness plus the progress facts the stall/lag signals are built on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Query-only bounded selection evidence and background warm progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_evidence_cache: Option<serde_json::Value>,
    /// Credential refresh has not succeeded before the final 10% of its
    /// lifetime. Old children omit this field (rolling upgrade compatible).
    #[serde(default)]
    pub credential_refresh_at_risk: bool,
    /// Monotonic completed-startup-work revision. None once serving.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_progress: Option<u64>,
    /// The process has work in hand (queued objects, merges, running query).
    pub busy: bool,
    /// ingest: age in seconds of the oldest admitted-but-not-yet-searchable
    /// data (arrival → part-log append). detect: age of the oldest
    /// unpublished finding-outbox row. query: 0.
    #[serde(default)]
    pub lag_seconds: f64,
    /// Ingest: age since arrival of the oldest live L0 part. Independent
    /// of successful ingestion, so fresh commits cannot hide a merge stall.
    #[serde(default)]
    pub oldest_unmerged_l0_age_seconds: f64,
    /// NAN-3701, ingest: seconds the most overdue L0 has waited past its
    /// merge-policy deadline (a lone L0 waiting for its hour to seal is not
    /// overdue). Old children omit it (0: never fires).
    #[serde(default)]
    pub l0_merge_overdue_seconds: f64,
    /// NAN-3774, ingest: seconds the tenant's prevalence state has been
    /// behind the part-log head without a break (opening, rotating,
    /// catching up, or its store not responding). Ingest commits regardless;
    /// this is the derived product's own lag. Old children omit it (0).
    #[serde(default)]
    pub prevalence_behind_seconds: f64,
    /// NAN-3774, ingest: committed part-log entries not yet in the
    /// prevalence state. Old children omit it (0).
    #[serde(default)]
    pub prevalence_behind_entries: u64,
    /// NAN-3781, ingest: seconds the tenant's prevalence state has been
    /// unavailable (open or use failed; rows go unstamped) without a break.
    /// Old children omit it (0).
    #[serde(default)]
    pub prevalence_degraded_seconds: f64,
    /// NAN-3781, ingest: total degraded seconds since process start.
    /// Old children omit it (0).
    #[serde(default)]
    pub prevalence_degraded_seconds_total: f64,
    /// Unix ms of the last unit of forward progress (part appended, merge
    /// finished, query answered). 0 = none yet.
    #[serde(default)]
    pub last_progress_unix_ms: u64,
    /// Pending work units (objects, merges, queued queries; detect: unpublished
    /// finding-outbox rows).
    #[serde(default)]
    pub queue_depth: u64,
    /// ingest: objects refused whole (admission/shape/digest/missing) and
    /// rows refused inside admitted objects, since process start. Every
    /// refusal is also recorded durably in the part log (`reject`).
    #[serde(default)]
    pub objects_rejected: u64,
    #[serde(default)]
    pub rows_rejected: u64,
    /// ingest: a commit (sign/upload/append/ack) is failing and being
    /// retried in-process; the buffer is held (nothing lost, nothing acked).
    #[serde(default)]
    pub retrying: bool,
    /// Optional short free-form state for operators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// ingest: superseded part files kept because lake-part deletion is not
    /// authorized (grant disabled, not delivered, unreadable, no sanctioned
    /// path), with the parts and bytes pending (possibly 0). `None` while
    /// deletion is authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_gc_blocked: Option<PartGcBlocked>,
    /// ingest: lake part files deleted through the sanctioned GC pass (each
    /// with an exact Worker absence receipt) since process start
    /// (`lean_part_gc_sanctioned_v1`). Exported as `lake_part_gc_deleted_total`.
    #[serde(default)]
    pub part_gc_deleted_total: u64,
    /// ingest: rows committed to the part log since process start
    /// (`IngestHealth.rows_committed_total`). NAN-3522: the status push
    /// reports it per tenant as the lean over-commit meter. Old children
    /// omit it (0).
    #[serde(default)]
    pub rows_committed_total: u64,
    /// ingest (NAN-3503, `identity_directory_enrich` on): the identity
    /// directory installed for ingest stamping and its background refresh
    /// state. Old children and flag-off ingest omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_directory: Option<IdentityDirectoryStatus>,
}

/// Ingest's installed identity directory (NAN-3503).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IdentityDirectoryStatus {
    /// Installed manifest revision (UUIDv7); `None` before the first build
    /// or after the tenant's directory was removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Seconds since the installed revision was published (from its UUIDv7
    /// timestamp): how stale the stamped identity context is.
    #[serde(default)]
    pub revision_age_seconds: f64,
    /// Consecutive failed background refreshes (0 after a success).
    #[serde(default)]
    pub refresh_failures: u64,
}

impl IdentityDirectoryStatus {
    /// `lake_identity_directory_installed{cell,tenant}` (0/1),
    /// `lake_identity_directory_revision_age_seconds{cell,tenant}` (only
    /// while installed) and
    /// `lake_identity_directory_refresh_failures{cell,tenant}`. The revision
    /// itself stays in the heartbeat: as a label it would start a new series
    /// per revision.
    pub fn metric_lines(&self, cell_id: &str, tenant: &str) -> String {
        let mut lines = format!(
            "lake_identity_directory_installed{{cell=\"{cell_id}\",tenant=\"{tenant}\"}} {}\n",
            u8::from(self.revision.is_some())
        );
        if self.revision.is_some() {
            lines.push_str(&format!(
                "lake_identity_directory_revision_age_seconds{{cell=\"{cell_id}\",tenant=\"{tenant}\"}} {:.3}\n",
                self.revision_age_seconds
            ));
        }
        lines.push_str(&format!(
            "lake_identity_directory_refresh_failures{{cell=\"{cell_id}\",tenant=\"{tenant}\"}} {}\n",
            self.refresh_failures
        ));
        lines
    }
}

/// Prometheus line for one tenant's sanctioned lake-part deletes.
pub fn part_gc_deleted_metric_line(cell_id: &str, tenant: &str, deleted: u64) -> String {
    format!("lake_part_gc_deleted_total{{cell=\"{cell_id}\",tenant=\"{tenant}\"}} {deleted}\n")
}

/// Superseded lake parts ingest is keeping because the delete gate is closed
/// (`lean_part_gc_gate_v1`). Exported as `lake_part_gc_blocked{reason}`
/// (parts) and `lake_part_gc_blocked_bytes{reason}` (data bytes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartGcBlocked {
    /// Stable snake_case reason label (see `part_ingest::part_gc_gate`).
    pub reason: String,
    /// Superseded parts past the grace window that were not deleted.
    pub parts: u64,
    /// Their data bytes.
    pub bytes: u64,
    /// Safe input diagnostic; never a bearer or URL.
    #[serde(default)]
    pub detail: String,
    /// Continuous blockage with pending parts (resets on success or no backlog).
    #[serde(default)]
    pub blocked_seconds: u64,
}

impl PartGcBlocked {
    /// Prometheus lines for one tenant's blocked lake-part GC. The reason is
    /// reduced to `[a-z0-9_]` so it can never break the exposition.
    pub fn metric_lines(&self, cell_id: &str, tenant: &str) -> String {
        let reason: String = self
            .reason
            .chars()
            .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' { c } else { '_' })
            .take(64)
            .collect();
        let labels = format!("cell=\"{cell_id}\",tenant=\"{tenant}\",reason=\"{reason}\"");
        let detail: String = self.detail.chars()
            .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' { c } else { '_' })
            .take(64)
            .collect();
        format!("lake_part_gc_blocked_seconds{{{labels},detail=\"{detail}\"}} {}\nlake_part_gc_blocked{{{labels}}} {}\nlake_part_gc_blocked_bytes{{{labels}}} {}\n", self.blocked_seconds, self.parts, self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_evidence_status_is_optional_and_round_trips() {
        let old: Heartbeat = serde_json::from_str(r#"{"busy":false}"#).unwrap();
        assert!(old.selection_evidence_cache.is_none());
        assert!(!serde_json::to_string(&old).unwrap().contains("selection_evidence_cache"));
        let status = serde_json::json!({"entries": 1504, "bytes": 1000,
            "prewarm": {"state": "yielded", "completed_files": 1504}});
        let beat = Heartbeat { selection_evidence_cache: Some(status.clone()), ..Heartbeat::default() };
        let decoded: Heartbeat = serde_json::from_slice(&serde_json::to_vec(&beat).unwrap()).unwrap();
        assert_eq!(decoded.selection_evidence_cache, Some(status));
    }

    #[test]
    fn credential_refresh_risk_is_backward_compatible() {
        let old: Heartbeat = serde_json::from_str(r#"{"busy":false}"#).unwrap();
        assert!(!old.credential_refresh_at_risk);
        let risk = Heartbeat { credential_refresh_at_risk: true, ..Heartbeat::default() };
        let decoded: Heartbeat = serde_json::from_slice(&serde_json::to_vec(&risk).unwrap()).unwrap();
        assert!(decoded.credential_refresh_at_risk);
    }

    #[test]
    fn identity_directory_status_is_optional_and_exported() {
        let old: Heartbeat = serde_json::from_str(r#"{"busy":false}"#).unwrap();
        assert!(old.identity_directory.is_none());
        assert!(!serde_json::to_string(&old).unwrap().contains("identity_directory"));
        let status = IdentityDirectoryStatus {
            revision: Some("0192-rev".into()),
            revision_age_seconds: 42.5,
            refresh_failures: 3,
        };
        let beat = Heartbeat { identity_directory: Some(status.clone()), ..Heartbeat::default() };
        let decoded: Heartbeat = serde_json::from_slice(&serde_json::to_vec(&beat).unwrap()).unwrap();
        assert_eq!(decoded.identity_directory, Some(status.clone()));
        let lines = status.metric_lines("c1", "t1");
        assert!(lines.contains("lake_identity_directory_installed{cell=\"c1\",tenant=\"t1\"} 1\n"), "{lines}");
        assert!(lines.contains("lake_identity_directory_revision_age_seconds{cell=\"c1\",tenant=\"t1\"} 42.500\n"), "{lines}");
        assert!(!lines.contains("0192-rev"), "revision is never a label: {lines}");
        assert!(lines.contains("lake_identity_directory_refresh_failures{cell=\"c1\",tenant=\"t1\"} 3\n"), "{lines}");
        let none = IdentityDirectoryStatus::default().metric_lines("c1", "t1");
        assert!(none.contains("lake_identity_directory_installed{cell=\"c1\",tenant=\"t1\"} 0\n"));
        assert!(!none.contains("revision_age_seconds"));
    }

    #[test]
    fn gc_blocked_metrics_preserve_old_heartbeats_and_bound_detail() {
        let old: PartGcBlocked = serde_json::from_value(serde_json::json!({
            "reason": "grant_disabled", "parts": 3, "bytes": 4096
        })).unwrap();
        assert_eq!(old.blocked_seconds, 0);
        assert!(old.detail.is_empty());
        let blocked = PartGcBlocked { detail: "missing\"\nroute".into(), blocked_seconds: 7201, ..old };
        let lines = blocked.metric_lines("c", "t");
        assert!(lines.contains("lake_part_gc_blocked_seconds{cell=\"c\",tenant=\"t\",reason=\"grant_disabled\",detail=\"missing__route\"} 7201\n"));
    }

    #[test]
    fn tenant_ids_are_path_safe() {
        for good in ["tenant1", "a", "t-2_x", "0abc"] {
            TenantId::new(good).unwrap();
        }
        for bad in ["", "..", "a/b", "A", "-a", "_a", "a b", "a.b", &"x".repeat(64), "t\0"] {
            assert!(TenantId::new(bad).is_err(), "{bad:?} accepted");
        }
        let err = serde_json::from_str::<TenantId>("\"../etc\"");
        assert!(err.is_err());
    }

    #[test]
    fn messages_round_trip() {
        let m = ToSupervisor::Heartbeat(Heartbeat { busy: true, lag_seconds: 1.5, ..Default::default() });
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"type\":\"heartbeat\""));
        let back: ToSupervisor = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ToSupervisor::Heartbeat(h) if h.busy));
        let w: ToChild = serde_json::from_str(r#"{"type":"wake","reason":"data_arrival"}"#).unwrap();
        assert!(matches!(w, ToChild::Wake { reason: WakeReason::DataArrival }));
    }
}

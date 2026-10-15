// SPDX-License-Identifier: AGPL-3.0-or-later

//! Boot-resolved schema profile shared by every request handler.
//!
//! NAN-2361: under the canonical lake backend the profile carries the physical
//! field inventory of the active immutable snapshot, which is derived by parsing
//! the tenant source manifest (tens of MB of JSON, measured ~42ms and ~84MB of
//! transient RSS). `ApiConfig::try_schema_profile()` used to be called from
//! request handlers, so every `/api/schema/fields`, prevalence discovery,
//! marketplace coverage, and rule-import request re-read and re-parsed it. The
//! profile is now built once at boot and handed out as a cheap `Arc` clone.
//!
//! A profile pinned once is not enough on its own: the generation manager
//! promotes a new immutable generation on its own cadence (a 900s minimum
//! interval in the compose stack) and atomically rewrites the worker config to
//! point at a NEW manifest. Without a refresh the API keeps resolving OCSF field
//! names against a generation its assigned worker no longer serves — the same
//! stale-manifest class already closed for the host copy. The refresher below
//! re-resolves the worker config's ACTIVE manifest on a low-frequency tick and
//! republishes the profile only when the manifest BYTES changed.

use arc_swap::ArcSwap;
use nanosiem_core::schema::{SchemaProfile, LAKE_WORKER_CONFIG_ENV};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// The tenant this deployment is allowed to serve, when the operator pins one.
/// Same variable the lake tuning reader uses (`state/schedulers.rs`).
const LAKE_TENANT_ID_ENV: &str = "NANO_LAKE_TENANT_ID";

/// How often the refresher looks for a promoted generation.
///
/// Promotions are floor-limited to 900s, so a 60s tick bounds staleness at ~7%
/// of a generation's life while costing one small JSON read per minute — the
/// multi-MB manifest is only hashed/parsed when the cheap keys already moved.
pub const SCHEMA_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Identity of the immutable manifest a published profile was built from.
///
/// `len`/`mtime` are the cheap change key (avoid hashing tens of MB every tick);
/// `digest` is the authority — a changed cheap key is always confirmed by
/// re-hashing before anything is swapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedManifest {
    pub path: String,
    pub digest: String,
    pub generation_id: Option<String>,
    pub tenant_id: Option<String>,
    len: u64,
    mtime: Option<SystemTime>,
}

/// Drift snapshot for the detailed health payload.
///
/// Deliberately cheap: it reads the small worker config and compares the pinned
/// identity against it WITHOUT hashing the manifest, so an authenticated health
/// poll can never turn into multi-MB work on the request path.
#[derive(Clone, Debug)]
pub struct SchemaDriftStatus {
    pub pinned_digest: Option<String>,
    pub pinned_generation_id: Option<String>,
    pub pinned_manifest_path: Option<String>,
    pub pinned_tenant_id: Option<String>,
    pub active_generation_id: Option<String>,
    /// The digest the worker config DECLARES for its active manifest. Reported,
    /// never trusted as proof — adoption still re-hashes the bytes.
    pub active_declared_digest: Option<String>,
    pub active_tenant_id: Option<String>,
    pub drifted: bool,
    pub error: Option<String>,
}

/// Result of one refresh tick. Returned (not just logged) so the behaviour is
/// testable without scraping log output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// No lake worker config is configured (legacy/UDM deployments).
    Disabled,
    /// The active manifest is the pinned one; nothing was rebuilt.
    Unchanged,
    /// A promoted generation was adopted.
    Swapped {
        generation_id: Option<String>,
        digest: String,
    },
    /// An identity fence tripped. The previous profile is retained.
    Refused(String),
    /// Transient failure (unreadable/invalid manifest, failed rebuild). The
    /// previous profile is retained — a bad refresh must never blank the field
    /// inventory or take down a serving API.
    Failed(String),
}

/// What the worker config points at right now.
struct ActiveManifest {
    path: String,
    generation_id: Option<String>,
    tenant_id: Option<String>,
    declared_digest: Option<String>,
    len: u64,
    mtime: Option<SystemTime>,
}

impl ActiveManifest {
    fn pin(self, digest: String) -> PinnedManifest {
        PinnedManifest {
            path: self.path,
            digest,
            generation_id: self.generation_id,
            tenant_id: self.tenant_id,
            len: self.len,
            mtime: self.mtime,
        }
    }

    /// True when the cheap key says this is the very file already pinned.
    fn matches_cheap_key(&self, pinned: &PinnedManifest) -> bool {
        pinned.path == self.path && pinned.len == self.len && pinned.mtime == self.mtime
    }
}

/// The published pair: a profile and the manifest identity it was built from.
/// Swapped together so a reader can never see a profile attributed to the wrong
/// generation.
struct Published {
    profile: Arc<dyn SchemaProfile>,
    manifest: Option<PinnedManifest>,
}

/// Clone-shared handle to the active schema profile.
///
/// Swappable so a generation promotion can publish a new field inventory
/// without a process restart; readers are wait-free and always observe a whole
/// profile (never a half-published one).
#[derive(Clone)]
pub struct SharedSchemaProfile {
    // `ArcSwap` cannot hold an unsized `dyn` payload directly (it stores a thin
    // pointer), hence `Published` owning the inner `Arc<dyn ...>`.
    current: Arc<ArcSwap<Published>>,
}

impl SharedSchemaProfile {
    /// Wrap the boot-resolved profile. Call once, from state construction.
    pub fn new(profile: Arc<dyn SchemaProfile>) -> Self {
        Self::with_manifest(profile, None)
    }

    /// Wrap the boot-resolved profile together with the manifest identity it was
    /// built from, so drift against a later promotion is detectable.
    pub fn with_manifest(profile: Arc<dyn SchemaProfile>, manifest: Option<PinnedManifest>) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(Published { profile, manifest })),
        }
    }

    /// The active profile. Cheap enough for the request path — one atomic load
    /// plus an `Arc` clone, no I/O.
    pub fn load(&self) -> Arc<dyn SchemaProfile> {
        self.current.load().profile.clone()
    }

    /// The manifest identity the active profile was built from, when the
    /// deployment resolves its schema from a lake worker config.
    pub fn pinned_manifest(&self) -> Option<PinnedManifest> {
        self.current.load().manifest.clone()
    }

    /// Publish a rebuilt profile with the manifest identity it came from.
    pub fn store(&self, profile: Arc<dyn SchemaProfile>, manifest: Option<PinnedManifest>) {
        self.current.store(Arc::new(Published { profile, manifest }));
    }

    /// Publish the worker-served profile when it is installed and differs from
    /// the active one; `true` when it was published. The pinned manifest
    /// identity is kept (a worker-served schema has none of its own).
    ///
    /// NAN-3492: a trusted-local lean install has no worker config, so the
    /// manifest refresh below is a no-op there and this profile stayed the one
    /// resolved at boot: `/api/schema/fields`, query validation and the
    /// Search page's rarity slider never saw a field stored after the API
    /// started.
    pub fn adopt_installed_lake_profile(&self) -> bool {
        self.adopt(nanosiem_core::schema::installed_lake_profile())
    }

    fn adopt(&self, installed: Option<Arc<dyn SchemaProfile>>) -> bool {
        let Some(installed) = installed else {
            return false;
        };
        if Arc::ptr_eq(&self.load(), &installed) {
            return false;
        }
        self.store(installed, self.pinned_manifest());
        true
    }

    /// One refresh tick against the env-configured worker config.
    pub fn refresh_once(
        &self,
        rebuild: &dyn Fn() -> Result<Arc<dyn SchemaProfile>, String>,
    ) -> RefreshOutcome {
        match worker_config_path() {
            Some(path) => self.refresh_from_worker_config(&path, rebuild),
            None => RefreshOutcome::Disabled,
        }
    }

    /// One refresh tick against an explicit worker config path.
    ///
    /// `rebuild` is injected rather than called directly so the fence/retention
    /// behaviour can be tested without a real multi-MB manifest, and so the
    /// production caller keeps using `ApiConfig::try_schema_profile()` (which
    /// re-reads the same env the worker config came from).
    pub fn refresh_from_worker_config(
        &self,
        worker_config_path: &str,
        rebuild: &dyn Fn() -> Result<Arc<dyn SchemaProfile>, String>,
    ) -> RefreshOutcome {
        let published = self.current.load();
        let active = match observe_active_manifest(worker_config_path) {
            Ok(active) => active,
            Err(error) => {
                tracing::error!(
                    %error,
                    "lake schema refresh could not resolve the active manifest; retaining the pinned profile"
                );
                return RefreshOutcome::Failed(error);
            }
        };

        if published
            .manifest
            .as_ref()
            .is_some_and(|pinned| active.matches_cheap_key(pinned))
        {
            return RefreshOutcome::Unchanged;
        }

        // Fence BEFORE hashing or rebuilding: a manifest belonging to another
        // tenant is never a candidate, however fresh it looks.
        let pinned_tenant = published
            .manifest
            .as_ref()
            .and_then(|pinned| pinned.tenant_id.clone());
        if let Err(error) = check_tenant(active.tenant_id.as_deref(), pinned_tenant.as_deref()) {
            tracing::error!(
                %error,
                manifest = %active.path,
                "refusing a cross-tenant lake manifest; retaining the pinned profile"
            );
            return RefreshOutcome::Refused(error);
        }

        let digest = match digest_file(&active.path) {
            Ok(digest) => digest,
            Err(error) => {
                tracing::error!(
                    %error,
                    "lake schema refresh could not digest the active manifest; retaining the pinned profile"
                );
                return RefreshOutcome::Failed(error);
            }
        };

        if let Some(pinned) = published.manifest.as_ref() {
            if pinned.digest == digest {
                // Same bytes reachable under a new path or restamped mtime (the
                // operator refresh script rewrites the host copy). Adopt the new
                // cheap key so later ticks short-circuit again, but don't pay for
                // a rebuild the field inventory would not change.
                self.store(published.profile.clone(), Some(active.pin(digest)));
                return RefreshOutcome::Unchanged;
            }
        }

        let profile = match rebuild() {
            Ok(profile) => profile,
            Err(error) => {
                tracing::error!(
                    %error,
                    manifest = %active.path,
                    "lake schema profile rebuild failed; retaining the pinned profile"
                );
                return RefreshOutcome::Failed(error);
            }
        };

        // The rebuild re-reads the worker config itself, so a promotion that
        // raced it may have produced a profile NEWER than `active`. Recording
        // `active` is still safe: the next tick sees a cheap-key difference and
        // swaps again, bounding staleness by one interval instead of pinning a
        // wrong identity forever.
        let pinned = active.pin(digest.clone());
        let generation_id = pinned.generation_id.clone();
        self.store(profile, Some(pinned));
        tracing::info!(
            generation = generation_id.as_deref().unwrap_or("unknown"),
            digest = &digest[..digest.len().min(16)],
            "adopted a promoted lake schema generation"
        );
        RefreshOutcome::Swapped {
            generation_id,
            digest,
        }
    }

    /// Cheap drift probe for the detailed health payload. `None` when this
    /// deployment does not resolve its schema from a lake worker config, so the
    /// legacy payload stays byte-identical.
    pub fn drift_status(&self) -> Option<SchemaDriftStatus> {
        let worker_config_path = worker_config_path()?;
        let pinned = self.pinned_manifest();
        let mut status = SchemaDriftStatus {
            pinned_digest: pinned.as_ref().map(|p| p.digest.clone()),
            pinned_generation_id: pinned.as_ref().and_then(|p| p.generation_id.clone()),
            pinned_manifest_path: pinned.as_ref().map(|p| p.path.clone()),
            pinned_tenant_id: pinned.as_ref().and_then(|p| p.tenant_id.clone()),
            active_generation_id: None,
            active_declared_digest: None,
            active_tenant_id: None,
            drifted: false,
            error: None,
        };

        match observe_active_manifest(&worker_config_path) {
            Ok(active) => {
                status.active_generation_id = active.generation_id.clone();
                status.active_declared_digest = active.declared_digest.clone();
                status.active_tenant_id = active.tenant_id.clone();
                status.drifted = match pinned.as_ref() {
                    // No identity pinned at all: we cannot show agreement with
                    // what the worker serves, which is exactly the silent case.
                    None => true,
                    Some(pinned) => {
                        !active.matches_cheap_key(pinned)
                            || active
                                .declared_digest
                                .as_deref()
                                .is_some_and(|declared| declared != pinned.digest)
                    }
                };
            }
            Err(error) => {
                // Agreement is unproven, which is drift as far as an operator is
                // concerned — the profile in use may describe a dead generation.
                status.drifted = true;
                status.error = Some(error);
            }
        }
        Some(status)
    }
}

/// Resolve the manifest identity the boot profile was built from.
///
/// Best-effort by design: the profile itself is already built and fail-closed by
/// `ApiConfig::try_schema_profile()`, so a hiccup here must not fail boot. It
/// only costs drift visibility until the first successful refresh tick, which
/// treats a missing identity as "changed" and re-pins it.
pub fn resolve_pinned_manifest() -> Option<PinnedManifest> {
    let worker_config_path = worker_config_path()?;
    let active = observe_active_manifest(&worker_config_path)
        .inspect_err(|error| {
            tracing::warn!(
                %error,
                "could not stamp the boot lake manifest identity; drift reporting starts at the first refresh"
            );
        })
        .ok()?;
    let digest = digest_file(&active.path)
        .inspect_err(|error| {
            tracing::warn!(%error, "could not digest the boot lake manifest");
        })
        .ok()?;
    Some(active.pin(digest))
}

fn worker_config_path() -> Option<String> {
    std::env::var(LAKE_WORKER_CONFIG_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
}

fn configured_tenant_id() -> Option<String> {
    std::env::var(LAKE_TENANT_ID_ENV)
        .ok()
        .map(|tenant| tenant.trim().to_string())
        .filter(|tenant| !tenant.is_empty())
}

/// The product never takes the worker's word on tenant: a candidate manifest is
/// adopted only when its tenant matches the operator-configured tenant (when one
/// is configured) AND the tenant already pinned. An unstated tenant cannot prove
/// either, so it fails closed.
fn check_tenant(active: Option<&str>, pinned: Option<&str>) -> Result<(), String> {
    for (expected, source) in [
        (configured_tenant_id(), LAKE_TENANT_ID_ENV),
        (pinned.map(str::to_string), "the pinned manifest"),
    ] {
        let Some(expected) = expected else { continue };
        match active {
            Some(active) if active == expected => {}
            Some(active) => {
                return Err(format!(
                    "worker config is assigned tenant {active:?} but {source} expects {expected:?}"
                ))
            }
            None => {
                return Err(format!(
                    "worker config states no assigned tenant but {source} expects {expected:?}"
                ))
            }
        }
    }
    Ok(())
}

fn observe_active_manifest(worker_config_path: &str) -> Result<ActiveManifest, String> {
    let raw = std::fs::read_to_string(worker_config_path).map_err(|error| {
        format!("failed to read {LAKE_WORKER_CONFIG_ENV}={worker_config_path:?}: {error}")
    })?;
    let config: serde_json::Value = serde_json::from_str(&raw).map_err(|error| {
        format!("{LAKE_WORKER_CONFIG_ENV}={worker_config_path:?} is not valid JSON: {error}")
    })?;
    let path = config
        .pointer("/tenant/source_manifest/path")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| {
            format!(
                "{LAKE_WORKER_CONFIG_ENV}={worker_config_path:?} has no active tenant source manifest"
            )
        })?
        .to_string();
    let metadata = std::fs::metadata(&path)
        .map_err(|error| format!("failed to stat lake schema manifest {path:?}: {error}"))?;

    Ok(ActiveManifest {
        path,
        generation_id: string_at(&config, "/generation_id"),
        tenant_id: string_at(&config, "/assigned_tenant_id"),
        declared_digest: string_at(&config, "/tenant/source_manifest/sha256"),
        len: metadata.len(),
        mtime: metadata.modified().ok(),
    })
}

fn string_at(config: &serde_json::Value, pointer: &str) -> Option<String> {
    config
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

/// Streamed so a multi-MB manifest is not pulled into RSS just to be hashed.
fn digest_file(path: &str) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("failed to read lake schema manifest {path:?}: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read lake schema manifest {path:?}: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Low-frequency refresh loop. Per-instance: every API process serves requests
/// from its own profile, so this is not leader-gated.
///
/// Each tick runs on a blocking thread — a tick that finds a promotion hashes
/// and re-parses tens of MB, which must not stall the async runtime.
pub async fn run_schema_refresh_loop<F>(shared: SharedSchemaProfile, rebuild: F)
where
    F: Fn() -> Result<Arc<dyn SchemaProfile>, String> + Send + Sync + 'static,
{
    let rebuild = Arc::new(rebuild);
    let mut ticker = tokio::time::interval(SCHEMA_REFRESH_INTERVAL);
    ticker.tick().await; // The boot profile is already current.
    loop {
        ticker.tick().await;
        let shared = shared.clone();
        let rebuild = rebuild.clone();
        let outcome =
            tokio::task::spawn_blocking(move || shared.refresh_once(rebuild.as_ref())).await;
        match outcome {
            Ok(RefreshOutcome::Disabled) => {
                tracing::debug!("lake schema refresh disabled (no worker config configured)");
                return;
            }
            Ok(_) => {}
            Err(error) => {
                // Retain and retry: the profile slot is untouched on panic.
                tracing::error!(%error, "lake schema refresh task failed; retaining the pinned profile");
            }
        }
    }
}

#[cfg(test)]
mod tests;

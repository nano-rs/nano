// SPDX-License-Identifier: AGPL-3.0-or-later

//! Directory identity context stamped onto events at ingest (NAN-3503).
//!
//! The lean cell loads the tenant's identity directory
//! ([`crate::lean_identity_snapshot`], pinned by manifest revision) into an
//! in-memory index of merged people ([`crate::lean_identity_merge`]) keyed by
//! lowercase e-mail / UPN and, separately, by username. Ingest then matches
//! `actor.user` and `user` and:
//!
//! * fills OCSF 1.9 `user` attributes only where the event has none
//!   (`org.ou_name`, `org.name`, `ldap_person.job_title`,
//!   `ldap_person.manager`, `ldap_person.employee_uid`,
//!   `ldap_person.office_location`, `groups[].name`, `type_id`/`type`), never
//!   overwriting a vendor value and never writing an object that would fail
//!   the OCSF `at_least_one` constraints the admission validator enforces;
//! * appends one `enrichments[]` entry (`type = "identity"`) per matched
//!   object, carrying the merged facts in `data`.
//!
//! Behind cell flag `identity_directory_enrich` (default off): with no
//! directory installed, events are untouched.

use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

use crate::enrichment::IngestEnrichmentMetrics;
use crate::lean_identity_merge::{IdentityMerger, MergedIdentity};
use crate::lean_identity_snapshot::{IdentityManifest, IdentityStore, for_each_merged_row};
use crate::parts::part_log::ObjectStore;

/// OCSF user objects matched and stamped, in order.
pub const IDENTITY_OBJECTS: [&str; 2] = ["actor.user", "user"];
/// Groups written into one event (`user.groups` and `data.groups`).
pub const MAX_STAMPED_GROUPS: usize = 50;
/// The `enrichments[].type` of identity entries.
pub const IDENTITY_ENRICHMENT_TYPE: &str = "identity";

const AMBIGUOUS: u32 = u32::MAX;
/// A pinned directory is rebuilt at most this often: delta connectors can
/// publish a revision per page, and a 500k-person index costs seconds.
/// Directory rows (all feeds and sub-feeds) an ingest index is built from.
/// Above it the build is refused and ingest keeps its pinned index (or
/// stamps nothing): it bounds the ingest process's resident index.
pub const MAX_INGEST_DIRECTORY_ROWS: u64 = 2_000_000;
pub const MIN_REBUILD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// A tenant's merged directory, indexed for ingest lookups. Immutable; a new
/// manifest revision builds a new one.
pub struct IdentityDirectory {
    tenant_id: Uuid,
    revision: Uuid,
    people: Vec<MergedIdentity>,
    /// Lowercase e-mail / UPN -> person; [`AMBIGUOUS`] when two people claim it.
    by_address: HashMap<Box<str>, u32>,
    /// Lowercase username -> person; [`AMBIGUOUS`] likewise.
    by_username: HashMap<Box<str>, u32>,
}

impl std::fmt::Debug for IdentityDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityDirectory")
            .field("tenant_id", &self.tenant_id)
            .field("revision", &self.revision)
            .field("people", &self.people.len())
            .finish()
    }
}

fn index_key(map: &mut HashMap<Box<str>, u32>, key: Box<str>, person: u32) {
    map.entry(key)
        .and_modify(|existing| {
            if *existing != person {
                *existing = AMBIGUOUS;
            }
        })
        .or_insert(person);
}

impl IdentityDirectory {
    /// Index merged people. Lookup keys move out of each person into the maps.
    pub fn build(tenant_id: Uuid, revision: Uuid, mut people: Vec<MergedIdentity>) -> Result<Self> {
        ensure!(!tenant_id.is_nil(), "identity directory tenant is nil");
        ensure!(people.len() < AMBIGUOUS as usize, "identity directory is too large");
        let mut by_address = HashMap::new();
        let mut by_username = HashMap::new();
        for (index, person) in people.iter_mut().enumerate() {
            let index = index as u32;
            for key in std::mem::take(&mut person.address_keys).into_vec() {
                index_key(&mut by_address, key, index);
            }
            for key in std::mem::take(&mut person.username_keys).into_vec() {
                index_key(&mut by_username, key, index);
            }
        }
        by_address.shrink_to_fit();
        by_username.shrink_to_fit();
        people.shrink_to_fit();
        Ok(Self {
            tenant_id,
            revision,
            people,
            by_address,
            by_username,
        })
    }

    /// Stream a merged identity file (from [`IdentityStore::materialize`])
    /// through the merger: the input rows are never all resident.
    pub fn from_merged_file(tenant_id: Uuid, revision: Uuid, path: &Path) -> Result<Self> {
        let mut merger = IdentityMerger::default();
        for_each_merged_row(path, |row| merger.push(&row))?;
        Self::build(tenant_id, revision, merger.finish())
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn revision(&self) -> Uuid {
        self.revision
    }

    pub fn len(&self) -> usize {
        self.people.len()
    }

    pub fn is_empty(&self) -> bool {
        self.people.is_empty()
    }

    fn resolve(&self, map: &HashMap<Box<str>, u32>, value: &str) -> Option<&MergedIdentity> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        // Hot path: values are usually already lowercase ASCII (parsers
        // lowercase e-mail addresses), so look them up without allocating.
        let owned;
        let key = if !value.bytes().any(|b| b.is_ascii_uppercase() || !b.is_ascii()) {
            value
        } else {
            owned = if value.is_ascii() {
                value.to_ascii_lowercase()
            } else {
                value.to_lowercase()
            };
            owned.as_str()
        };
        match map.get(key) {
            Some(index) if *index != AMBIGUOUS => self.people.get(*index as usize),
            _ => None,
        }
    }

    pub fn by_address(&self, value: &str) -> Option<&MergedIdentity> {
        self.resolve(&self.by_address, value)
    }

    pub fn by_username(&self, value: &str) -> Option<&MergedIdentity> {
        self.resolve(&self.by_username, value)
    }

    /// Approximate resident heap bytes (people, interned text counted once,
    /// both indexes), for sizing reports.
    pub fn approx_heap_bytes(&self) -> usize {
        use std::collections::HashSet;
        let mut seen: HashSet<*const u8> = HashSet::new();
        let mut text = 0usize;
        let mut count = |value: &Arc<str>, text: &mut usize| {
            if seen.insert(value.as_ptr()) {
                *text += value.len() + 16;
            }
        };
        for person in &self.people {
            for value in [&person.provider, &person.feed_id, &person.external_id] {
                count(value, &mut text);
            }
            for value in [
                &person.email,
                &person.upn,
                &person.username,
                &person.display_name,
                &person.department,
                &person.title,
                &person.manager_upn,
                &person.manager_display_name,
                &person.company,
                &person.office_location,
                &person.employee_id,
                &person.employee_type,
                &person.account_status,
            ]
            .into_iter()
            .flatten()
            {
                count(value, &mut text);
            }
            for group in person.groups.iter() {
                count(group, &mut text);
            }
            text += person.groups.len() * std::mem::size_of::<Arc<str>>();
        }
        let map_bytes = |map: &HashMap<Box<str>, u32>| {
            // hashbrown: one control byte + one (Box<str>, u32) bucket per slot.
            map.capacity() * (1 + std::mem::size_of::<(Box<str>, u32)>())
                + map.keys().map(|key| key.len()).sum::<usize>()
        };
        self.people.capacity() * std::mem::size_of::<MergedIdentity>()
            + text
            + map_bytes(&self.by_address)
            + map_bytes(&self.by_username)
    }
}

/// The tenant's current directory, shared between the background refresh
/// (writer) and every enricher generation (readers). Lock-free: ingest loads
/// the pointer per event and never waits on a build.
#[derive(Clone, Default)]
pub struct IdentityDirectoryHandle(Arc<HandleState>);

#[derive(Default)]
struct HandleState {
    directory: arc_swap::ArcSwapOption<IdentityDirectory>,
    /// Consecutive failed (or panicked) background refreshes.
    refresh_failures: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for IdentityDirectoryHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("IdentityDirectoryHandle")
            .field(&self.current().map(|directory| directory.revision()))
            .finish()
    }
}

impl IdentityDirectoryHandle {
    /// A handle holding `directory` (tests, the lab).
    pub fn with(directory: Option<Arc<IdentityDirectory>>) -> Self {
        let handle = Self::default();
        handle.install(directory);
        handle
    }

    pub fn current(&self) -> Option<Arc<IdentityDirectory>> {
        self.0.directory.load_full()
    }

    pub fn install(&self, directory: Option<Arc<IdentityDirectory>>) {
        self.0.directory.store(directory);
    }

    /// Consecutive failed background refreshes (0 after a success).
    pub fn refresh_failures(&self) -> u64 {
        self.0.refresh_failures.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn record_refresh(&self, ok: bool) {
        let failures = &self.0.refresh_failures;
        if ok {
            failures.store(0, std::sync::atomic::Ordering::Relaxed);
        } else {
            failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Heartbeat view: installed revision, its age (from the UUIDv7
    /// timestamp) and the consecutive refresh failures.
    pub fn status(&self) -> nanosiem_lake_cell::contract::IdentityDirectoryStatus {
        let revision = self.current().map(|directory| directory.revision());
        nanosiem_lake_cell::contract::IdentityDirectoryStatus {
            revision: revision.map(|revision| revision.to_string()),
            revision_age_seconds: revision.map_or(0.0, |revision| revision_age_seconds(revision, std::time::SystemTime::now())),
            refresh_failures: self.refresh_failures(),
        }
    }
}

/// Seconds between the UUIDv7 `revision`'s timestamp and `now` (0 when the
/// revision carries no timestamp or is from the future).
pub fn revision_age_seconds(revision: Uuid, now: std::time::SystemTime) -> f64 {
    let Some(timestamp) = revision.get_timestamp() else {
        return 0.0;
    };
    let (seconds, nanos) = timestamp.to_unix();
    let published = std::time::UNIX_EPOCH + std::time::Duration::new(seconds, nanos);
    now.duration_since(published).map_or(0.0, |age| age.as_secs_f64())
}

/// Reads the tenant's identity directory from its R2 enrichment prefix (the
/// `enrichment_reader` store) and builds the ingest index per revision.
pub struct LeanIdentityDirectories<'a> {
    store: IdentityStore<'a>,
    tenant_id: Uuid,
    min_rebuild_interval: std::time::Duration,
    last_build: std::sync::Mutex<Option<std::time::Instant>>,
    /// Test hook: extra time inside the blocking build.
    build_delay: std::time::Duration,
}

impl<'a> LeanIdentityDirectories<'a> {
    /// `objects` must be rooted at exactly this tenant's enrichment prefix;
    /// every manifest is also checked to name `tenant_id`.
    pub fn new(tenant_id: Uuid, objects: &'a dyn ObjectStore, scratch: &Path) -> Result<Self> {
        Ok(Self {
            store: IdentityStore::new(tenant_id, objects, scratch)?,
            tenant_id,
            min_rebuild_interval: MIN_REBUILD_INTERVAL,
            last_build: std::sync::Mutex::new(None),
            build_delay: std::time::Duration::ZERO,
        })
    }

    /// Test hook: make every build take at least this much longer.
    #[doc(hidden)]
    pub fn with_build_delay(mut self, delay: std::time::Duration) -> Self {
        self.build_delay = delay;
        self
    }

    /// Override [`MIN_REBUILD_INTERVAL`] (tests).
    pub fn with_min_rebuild_interval(mut self, interval: std::time::Duration) -> Self {
        self.min_rebuild_interval = interval;
        self
    }

    pub async fn current(&self) -> Result<Option<IdentityManifest>> {
        self.store.current().await
    }

    pub async fn load(&self, manifest: &IdentityManifest) -> Result<IdentityDirectory> {
        ensure!(
            manifest.row_upper_bound() <= MAX_INGEST_DIRECTORY_ROWS,
            "identity directory exceeds the ingest index cap of {MAX_INGEST_DIRECTORY_ROWS} rows"
        );
        let path = self.store.materialize(manifest).await?;
        let (tenant, revision, delay) = (self.tenant_id, manifest.revision, self.build_delay);
        // The merge + index is CPU-bound for seconds on a large directory.
        tokio::task::spawn_blocking(move || {
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            IdentityDirectory::from_merged_file(tenant, revision, &path)
        })
        .await
            .context("identity directory build task")?
    }

    /// The directory for the current revision: `pinned` again when the
    /// revision has not moved, `None` when the tenant has no directory.
    pub async fn refresh(
        &self,
        pinned: Option<&Arc<IdentityDirectory>>,
    ) -> Result<Option<Arc<IdentityDirectory>>> {
        let Some(manifest) = self.current().await? else {
            return Ok(None);
        };
        if let Some(pinned) = pinned {
            let recent = self
                .last_build
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some_and(|built| built.elapsed() < self.min_rebuild_interval);
            if pinned.revision == manifest.revision || recent {
                return Ok(Some(pinned.clone()));
            }
        }
        let directory = Arc::new(self.load(&manifest).await?);
        *self.last_build.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::time::Instant::now());
        Ok(Some(directory))
    }

    /// One background refresh step into `handle`. Additive: a directory
    /// that cannot be read or built (R2 blip, foreign or tampered manifest,
    /// over the cap) keeps the installed one and logs; a directory bound to
    /// another tenant is never installed. Returns whether it installed a
    /// different directory; a failure also counts on the handle (backoff,
    /// heartbeat) and a success resets that count.
    pub async fn refresh_into(&self, handle: &IdentityDirectoryHandle, tenant: &str) -> bool {
        let pinned = handle.current();
        let next = async {
            let next = self.refresh(pinned.as_ref()).await?;
            if let Some(directory) = &next {
                ensure!(
                    directory.tenant_id().to_string() == tenant,
                    "identity directory tenant differs from the ingest tenant"
                );
            }
            Ok::<_, anyhow::Error>(next)
        }
        .await;
        match next {
            Ok(next) => {
                let changed = match (&pinned, &next) {
                    (Some(pinned), Some(next)) => !Arc::ptr_eq(pinned, next),
                    (None, None) => false,
                    _ => true,
                };
                if changed {
                    if let Some(directory) = &next {
                        tracing::info!(revision = %directory.revision(), people = directory.len(), "identity directory installed for ingest enrichment");
                    } else {
                        tracing::info!("tenant identity directory removed; identity stamping paused");
                    }
                    handle.install(next);
                }
                handle.record_refresh(true);
                changed
            }
            Err(error) => {
                handle.record_refresh(false);
                tracing::warn!(
                    error = %format!("{error:#}"),
                    consecutive_failures = handle.refresh_failures(),
                    "identity directory refresh failed; keeping the installed directory"
                );
                false
            }
        }
    }
}

/// How often the background task re-reads the identity pointer (one R2 GET).
pub const IDENTITY_REFRESH_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// Ceiling of the refresh backoff after consecutive failures.
pub const IDENTITY_REFRESH_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Sleep before the next refresh: `every` while healthy, doubled per
/// consecutive failure up to [`IDENTITY_REFRESH_MAX_BACKOFF`] (never below
/// `every`), so a broken manifest or R2 outage is not re-materialized every
/// tick.
pub fn identity_refresh_delay(every: std::time::Duration, failures: u64) -> std::time::Duration {
    if failures == 0 {
        return every;
    }
    let factor = 1u32 << failures.min(16) as u32;
    every.saturating_mul(factor).min(IDENTITY_REFRESH_MAX_BACKOFF.max(every))
}

/// The background refresh: off the ingest loop and its lock. Ingest starts
/// with an empty handle (cold start never waits on a build) and stamps once
/// the first directory is installed. A panic inside one refresh is caught,
/// logged at ERROR and counted as a failure: the task never dies silently
/// (its JoinHandle is only aborted on shutdown), so stamping cannot stay
/// pinned to a stale directory without the heartbeat showing it.
pub async fn run_identity_refresh(
    directories: &LeanIdentityDirectories<'_>,
    handle: IdentityDirectoryHandle,
    tenant: String,
    every: std::time::Duration,
) {
    use futures::FutureExt;
    loop {
        let step = std::panic::AssertUnwindSafe(directories.refresh_into(&handle, &tenant));
        if let Err(panic) = step.catch_unwind().await {
            handle.record_refresh(false);
            let message = panic
                .downcast_ref::<&str>()
                .map(|message| message.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic".into());
            tracing::error!(
                panic = %message,
                consecutive_failures = handle.refresh_failures(),
                "identity directory refresh panicked; keeping the installed directory"
            );
        }
        tokio::time::sleep(identity_refresh_delay(every, handle.refresh_failures())).await;
    }
}

/// Provider name for `enrichments[].provider`, from the feed prefix when it
/// names a known directory, else the feed prefix itself.
pub fn provider_name(provider: &str) -> String {
    let lower = provider.to_ascii_lowercase();
    if lower.contains("google") || lower.starts_with("gws") {
        "google_workspace".into()
    } else if lower.contains("entra") || lower.contains("azure") {
        "entra_directory".into()
    } else if lower.contains("okta") {
        "okta_users".into()
    } else {
        provider.to_string()
    }
}

/// OCSF 1.9 `email_t`: `^[a-zA-Z0-9!#$%&'*+-/=?^_`{|}~.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$`.
fn is_ocsf_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+,-./=?^_`{|}~".contains(&b));
    let Some((label, rest)) = domain.split_once('.') else {
        return false;
    };
    local_ok
        && !label.is_empty()
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn text(value: &Option<Arc<str>>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|value| !value.is_empty())
}

fn absent(target: &Map<String, Value>, name: &str) -> bool {
    target.get(name).is_none_or(Value::is_null)
}

fn put(target: &mut Map<String, Value>, name: &str, value: Option<&str>) -> bool {
    match value {
        Some(value) if absent(target, name) => {
            target.insert(name.to_string(), Value::String(value.to_string()));
            true
        }
        _ => false,
    }
}

/// Find the person for one OCSF user object: `email_addr`, then `uid_alt`
/// (address or username), then `uid` when it is an address, then `name`
/// (address, else exact username). Returns `(field, value, person)`.
fn match_user<'d>(
    user: &Map<String, Value>,
    directory: &'d IdentityDirectory,
) -> (bool, Option<(&'static str, String, &'d MergedIdentity)>) {
    let field = |name: &str| {
        user.get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let mut candidate = false;
    if let Some(email) = field("email_addr") {
        candidate = true;
        if let Some(person) = directory.by_address(email) {
            return (true, Some(("email_addr", email.to_string(), person)));
        }
    }
    if let Some(alt) = field("uid_alt") {
        candidate = true;
        let person = if alt.contains('@') {
            directory.by_address(alt)
        } else {
            directory.by_username(alt)
        };
        if let Some(person) = person {
            return (true, Some(("uid_alt", alt.to_string(), person)));
        }
    }
    if let Some(uid) = field("uid").filter(|uid| uid.contains('@')) {
        candidate = true;
        if let Some(person) = directory.by_address(uid) {
            return (true, Some(("uid", uid.to_string(), person)));
        }
    }
    if let Some(name) = field("name") {
        candidate = true;
        let person = if name.contains('@') {
            directory.by_address(name)
        } else {
            directory.by_username(name)
        };
        if let Some(person) = person {
            return (true, Some(("name", name.to_string(), person)));
        }
    }
    (candidate, None)
}

fn object_at_mut<'a>(event: &'a mut Map<String, Value>, path: &str) -> Option<&'a mut Map<String, Value>> {
    let mut current = event;
    for part in path.split('.') {
        current = current.get_mut(part)?.as_object_mut()?;
    }
    Some(current)
}

/// Fill absent OCSF attributes of one matched user object. Every object
/// written satisfies its OCSF `at_least_one` constraint; an existing
/// attribute of the wrong shape is left alone.
///
/// `account_state_current`: the event happened close enough to now that the
/// directory's present account state describes it (see
/// [`ACCOUNT_STATE_WINDOW_MS`]).
fn stamp_user(user: &mut Map<String, Value>, person: &MergedIdentity, account_state_current: bool) {
    // organization: at_least_one [name, uid].
    let department = text(&person.department);
    let company = text(&person.company);
    match user.get_mut("org") {
        Some(Value::Object(org)) => {
            put(org, "name", company);
            if org.contains_key("name") || org.contains_key("uid") {
                put(org, "ou_name", department);
            }
        }
        None | Some(Value::Null) if company.is_some() => {
            let mut org = Map::new();
            put(&mut org, "name", company);
            put(&mut org, "ou_name", department);
            user.insert("org".into(), Value::Object(org));
        }
        _ => {}
    }

    // ldap_person (no constraint); its manager is a user: at_least_one
    // [account, name, uid], so it needs the manager's UPN as `name`.
    let mut ldap = Map::new();
    put(&mut ldap, "job_title", text(&person.title));
    put(&mut ldap, "employee_uid", text(&person.employee_id));
    put(&mut ldap, "office_location", text(&person.office_location));
    let manager_upn = text(&person.manager_upn);
    let mut manager = Map::new();
    if let Some(upn) = manager_upn {
        put(&mut manager, "name", Some(upn));
        put(&mut manager, "email_addr", Some(upn).filter(|upn| is_ocsf_email(upn)));
        put(&mut manager, "full_name", text(&person.manager_display_name));
    }
    match user.get_mut("ldap_person") {
        Some(Value::Object(existing)) => {
            for (name, value) in ldap {
                if absent(existing, &name) {
                    existing.insert(name, value);
                }
            }
            // A manager the vendor already describes (any attribute) is left
            // exactly as it is: mixing the directory's manager into it could
            // describe two different people.
            match existing.get_mut("manager") {
                None | Some(Value::Null) if !manager.is_empty() => {
                    existing.insert("manager".into(), Value::Object(manager));
                }
                _ => {}
            }
        }
        None | Some(Value::Null) => {
            if !manager.is_empty() {
                ldap.insert("manager".into(), Value::Object(manager));
            }
            if !ldap.is_empty() {
                user.insert("ldap_person".into(), Value::Object(ldap));
            }
        }
        _ => {}
    }

    // groups: group objects, at_least_one [name, uid].
    if absent(user, "groups") && !person.groups.is_empty() {
        let groups = person
            .groups
            .iter()
            .take(MAX_STAMPED_GROUPS)
            .map(|group| json!({ "name": &**group }))
            .collect();
        user.insert("groups".into(), Value::Array(groups));
    }

    // account state: OCSF `account.is_disabled` / `is_locked`, only on an
    // account the event already names (account: at_least_one [name, uid]).
    // Today's state is stamped only onto events from about now: a late or
    // backfilled login must not read as "disabled account signed in".
    if let Some(Value::Object(account)) = user.get_mut("account").filter(|_| account_state_current) {
        if ["name", "uid"].iter().any(|key| !absent(account, key)) {
            let (disabled, locked) = account_flags(person);
            for (name, value) in [("is_disabled", disabled), ("is_locked", locked)] {
                if let Some(value) = value.filter(|_| absent(account, name)) {
                    account.insert(name.into(), Value::Bool(value));
                }
            }
        }
    }

    // type_id 2 = Admin (sibling caption `type`). Like the account flags,
    // today's admin role is stamped only onto events from about now; the
    // raw `is_admin` stays in `enrichments[].data` either way.
    if account_state_current && person.is_admin == Some(true) && absent(user, "type_id") && absent(user, "type") {
        user.insert("type_id".into(), Value::from(2));
        user.insert("type".into(), Value::String("Admin".into()));
    }
}

/// `(account.is_disabled, account.is_locked)` from the merged status, else
/// from `account_enabled`. Only a reported lockout (`locked`) sets
/// `is_locked`: `active` says nothing about lockout (Entra, for one, reports
/// lockouts separately). `staged`, `unknown` and `anonymized` say nothing.
///
/// `suspended` sets neither: with the v2 status set off, the connectors fold
/// a lockout into it (Okta `LOCKED_OUT` -> `suspended`), so it cannot tell a
/// temporary lockout from an admin suspension; reporting a locked-out user
/// as disabled would be wrong. The raw status stays in
/// `enrichments[].data.account_status`. `account_enabled` is only consulted
/// when no status was reported at all.
pub(crate) fn account_flags(person: &MergedIdentity) -> (Option<bool>, Option<bool>) {
    match text(&person.account_status) {
        Some("active") => (Some(false), None),
        Some("disabled" | "deprovisioned" | "deleted") => (Some(true), None),
        Some("locked") => (None, Some(true)),
        Some(_) => (None, None),
        None => (person.account_enabled.map(|enabled| !enabled), None),
    }
}

fn enrichment_entry(
    path: &str,
    matched_field: &str,
    value: &str,
    person: &MergedIdentity,
) -> Value {
    let mut data = Map::new();
    let mut put_text = |name: &str, value: &Option<Arc<str>>| {
        if let Some(value) = text(value) {
            data.insert(name.into(), Value::String(value.into()));
        }
    };
    put_text("department", &person.department);
    put_text("title", &person.title);
    put_text("manager", &person.manager_upn);
    put_text("manager_name", &person.manager_display_name);
    put_text("account_status", &person.account_status);
    put_text("employee_type", &person.employee_type);
    if !person.groups.is_empty() {
        data.insert(
            "groups".into(),
            Value::Array(
                person
                    .groups
                    .iter()
                    .take(MAX_STAMPED_GROUPS)
                    .map(|group| Value::String(group.to_string()))
                    .collect(),
            ),
        );
        if person.groups_truncated || person.groups.len() > MAX_STAMPED_GROUPS {
            data.insert("groups_truncated".into(), Value::Bool(true));
        }
    }
    if let Some(enabled) = person.account_enabled {
        data.insert("account_enabled".into(), Value::Bool(enabled));
    }
    if let Some(admin) = person.is_admin {
        data.insert("is_admin".into(), Value::Bool(admin));
    }
    data.insert("feed_id".into(), Value::String(person.feed_id.to_string()));
    data.insert(
        "matched_field".into(),
        Value::String(format!("{path}.{matched_field}")),
    );
    json!({
        "name": path,
        "value": value,
        "type": IDENTITY_ENRICHMENT_TYPE,
        "provider": provider_name(&person.provider),
        "data": Value::Object(data),
    })
}

/// How far an event's `time` may be from ingest time (either way) for the
/// directory's current account state to be stamped as OCSF
/// `account.is_disabled` / `is_locked`. A fixed constant for now: the value
/// is a correctness bound, not a tuning knob, and the raw status always
/// stays in `enrichments[].data.account_status`.
pub const ACCOUNT_STATE_WINDOW_MS: i64 = 15 * 60 * 1000;

/// Whether `event.time` is within the window of `now_ms`. Stamping runs
/// before normalization, so `time` may still be an RFC 3339 string; it is
/// read exactly as the part writer reads it. An event without a usable time
/// is never considered current.
fn account_state_current(event: &Map<String, Value>, now_ms: i64) -> bool {
    crate::iceberg::ocsf_time_millis(event.get("time"))
        // abs_diff: a hostile `time` (i64::MIN) must not overflow on ingest.
        .is_some_and(|time| now_ms.abs_diff(time) <= ACCOUNT_STATE_WINDOW_MS.unsigned_abs())
}

/// Match and stamp every identity object of one event.
pub(crate) fn enrich_identity(
    event: &mut Map<String, Value>,
    directory: &IdentityDirectory,
    now_ms: i64,
    metrics: &mut IngestEnrichmentMetrics,
) -> Result<()> {
    let current = account_state_current(event, now_ms);
    for path in IDENTITY_OBJECTS {
        let Some(user) = object_at_mut(event, path) else {
            continue;
        };
        let (candidate, matched) = match_user(user, directory);
        if candidate {
            metrics.identity_candidates = metrics.identity_candidates.saturating_add(1);
        }
        let Some((field, value, person)) = matched else {
            continue;
        };
        metrics.identity_hits = metrics.identity_hits.saturating_add(1);
        stamp_user(user, person, current);
        if event.get("enrichments").is_some_and(Value::is_null) {
            event.remove("enrichments");
        }
        // A vendor `enrichments` of another shape is left as it is.
        let Some(enrichments) = event
            .entry("enrichments")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
        else {
            continue;
        };
        // One identity entry per object: a replay or re-enrichment never
        // stacks a second one.
        let present = enrichments.iter().any(|existing| {
            existing.get("type").and_then(Value::as_str) == Some(IDENTITY_ENRICHMENT_TYPE)
                && existing.get("name").and_then(Value::as_str) == Some(path)
        });
        if !present {
            enrichments.push(enrichment_entry(path, field, &value, person));
            metrics.identity_attached = metrics.identity_attached.saturating_add(1);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "identity_enrichment_tests.rs"]
mod tests;

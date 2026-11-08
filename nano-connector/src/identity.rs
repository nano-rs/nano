// SPDX-License-Identifier: AGPL-3.0-or-later

//! `kind: identity` delivery (NAN-3503, ported to the ClickHouse product in
//! G22): directory sync of a feed's users and group memberships into the
//! user directory.
//!
//! ```text
//!  users stream, full  ─► normalize ─► Directory::upsert (replace) per page
//!                         end of stream ─► managers ─► shrink guard
//!                                     ─► Directory::retire_absent ─► engine saves cursor
//!  users stream, delta ─► normalize ─► Directory::upsert (patch; `deleted` = tombstone)
//!                         + managers, per page ─► engine saves cursor
//!  memberships streams ─► {member, group} ─► interned per-member groups (bounded)
//!                         end of run ─► Directory::replace_groups
//! ```
//!
//! On main the target was the lake's lean enrichment coordinator (staged,
//! atomically committed snapshots). Here the [`Directory`] is the ClickHouse
//! `user_registry` (see `nanosiem_core::identity::directory_feed`). Upserting
//! a full run's pages as they arrive is safe: they are the vendor's current
//! truth. The destructive half of a snapshot (retiring users the run did not
//! return) happens only once the walk is complete and the shrink guard
//! passed, and only then does the engine move the cursor.
//!
//! Memory: the run's `external_id -> manager reference` map, the full run's
//! set of seen ids, the pending `(user, manager id)` pairs, and the
//! membership aggregate (interned group names, a `u32` per membership).
//!
//! Shrink guard: a full run that would leave fewer than half the users of the
//! previous full run fails before anything is retired, unless the feed config
//! sets `identity_allow_shrink: true`. An empty full run is refused the same
//! way.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nanosiem_core::identity::directory_feed::{DIRECTORY_TEXT_FIELDS, DirectoryRow};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::engine::Sink;
use crate::spec::IdentityMode;

/// The users stream id (one users stream per feed).
pub const USERS_SUBFEED: &str = "users";
/// Groups kept per member.
pub const MAX_GROUPS_PER_MEMBER: usize = 4096;
/// Text bytes per field.
const MAX_TEXT: usize = 4096;
/// Feed config key that lets a full run drop more than half the users.
pub const ALLOW_SHRINK_CONFIG: &str = "identity_allow_shrink";
/// Most users a full run stages before publishing (NAN-4931 review: a full
/// run is staged in memory so the shrink guard runs before any write).
pub const MAX_STAGED_USERS: usize = 1_000_000;
/// Rows per directory upsert when a staged full run is published.
const PUBLISH_CHUNK: usize = 5_000;

/// One fenced directory write (see [`WriteFence`]).
pub type FencedWrite<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;

/// NAN-4931 review: every directory write of a run is fenced by the feed's
/// lease. The runner's fence holds the feed row (FOR SHARE) while the write
/// runs and refuses it when the claim's lease generation is no longer
/// current, so a pause, reset, delete or re-pin waits for an in-flight write
/// and every later write of the old run is refused.
#[async_trait::async_trait]
pub trait WriteFence: Send + Sync {
    async fn run<'a>(&'a self, op: FencedWrite<'a>) -> Result<(), String>;
}

/// No fence (tests and local preview).
pub struct NoFence;

#[async_trait::async_trait]
impl WriteFence for NoFence {
    async fn run<'a>(&'a self, op: FencedWrite<'a>) -> Result<(), String> {
        op.await
    }
}

/// Engine-facing delivery of identity streams. Calls arrive in order: per
/// users stream `users_begin`, its pages, `users_finish`; then membership
/// pages (possibly concurrent, from fan-out), then `memberships_finish`.
/// `abort` may come at any point after a failure.
#[async_trait::async_trait]
pub trait IdentityTarget: Send + Sync {
    /// Whether delta runs are safe (patch rows). `false`: the engine runs
    /// every users stream full.
    fn delta_supported(&self) -> bool {
        true
    }
    /// `guard`: the shrink guard for a full run.
    async fn users_begin(&self, stream: &str, mode: IdentityMode, guard: ShrinkGuard) -> Result<(), String>;
    /// One page of canonical user rows. Returns once the rows are applied.
    async fn users_page(&self, stream: &str, mode: IdentityMode, rows: &[Value]) -> Result<(), String>;
    /// Full: resolve what is pending and commit the snapshot (only then may
    /// the engine save the cursor); returns the committed user count.
    /// Delta: nothing (`None`).
    async fn users_finish(&self, stream: &str, mode: IdentityMode) -> Result<Option<u64>, String>;
    async fn memberships_page(&self, stream: &str, events: &[Value]) -> Result<(), String>;
    /// Apply the aggregated memberships.
    async fn memberships_finish(&self) -> Result<(), String>;
    /// Drop everything buffered for an uncommitted run (best effort).
    async fn abort(&self);
}

/// A full run's shrink guard: the previous full run's user count (from the
/// checkpoint) and whether the feed config allows a large drop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShrinkGuard {
    pub previous_rows: Option<u64>,
    pub allow: bool,
}

impl ShrinkGuard {
    /// `Err` when `rows` is less than half of the previous full run.
    pub fn check(&self, stream: &str, rows: u64) -> Result<(), String> {
        let Some(previous) = self.previous_rows else { return Ok(()) };
        if self.allow || rows.saturating_mul(2) >= previous {
            return Ok(());
        }
        tracing::error!(
            target: "nano_connector::audit",
            stream, previous_rows = previous, rows,
            "identity full run would drop more than half the directory; refused (set feed config `{ALLOW_SHRINK_CONFIG}: true` if intended)"
        );
        Err(format!(
            "identity_shrink_refused: the full run of `{stream}` found {rows} users, less than half of the previous {previous}; the directory was left unchanged (set feed config `{ALLOW_SHRINK_CONFIG}: true` if this is intended)"
        ))
    }
}

/// Where identity rows land. The runner's implementation writes the
/// ClickHouse `user_registry`; tests use [`MemoryDirectory`].
#[async_trait::async_trait]
pub trait Directory: Send + Sync {
    /// Upsert rows (`patch`: absent fields unchanged). Returns rows written.
    async fn upsert(&self, rows: &[DirectoryRow], patch: bool) -> Result<u64, String>;
    /// Stored users' manager references (upn, else email, else username).
    async fn references(&self, ids: &[String]) -> Result<HashMap<String, String>, String>;
    /// Set `manager_upn` on `(user, manager reference)` pairs.
    async fn set_managers(&self, pairs: &[(String, String)]) -> Result<u64, String>;
    /// Tombstone every live user not in `seen`; returns how many.
    async fn retire_absent(&self, seen: &HashSet<String>) -> Result<u64, String>;
    /// Set every live user's groups from a complete membership walk.
    /// Returns `(users changed, members not in the directory)`.
    async fn replace_groups(&self, groups: &HashMap<String, Vec<String>>) -> Result<(u64, u64), String>;
}

/// What a run delivered (runner metrics and the run record).
#[derive(Debug, Default)]
pub struct IdentityStats {
    /// User rows written (upserts and tombstones).
    pub rows: AtomicU64,
    pub tombstones: AtomicU64,
    /// Users retired because a committed full run did not return them.
    pub retired: AtomicU64,
    pub managers_resolved: AtomicU64,
    pub managers_unresolved: AtomicU64,
    pub members: AtomicU64,
    pub groups: AtomicU64,
    /// Users whose groups changed.
    pub groups_applied: AtomicU64,
    /// Members the walk named that are not in the directory.
    pub members_unmatched: AtomicU64,
}

#[derive(Default)]
struct Members {
    names: HashMap<Box<str>, u32>,
    list: Vec<Box<str>>,
    by_member: HashMap<Box<str>, Vec<u32>>,
    pairs: u64,
}

#[derive(Default)]
struct State {
    /// external_id -> manager reference (upn, else email, else username).
    references: HashMap<String, String>,
    /// Full run: ids the walk returned.
    seen: Option<HashSet<String>>,
    /// Full run: rows that named their manager by id only.
    pending: Vec<(String, String)>,
    /// Full run: rows staged until the walk completes and the shrink guard
    /// passes; nothing is written before that.
    staged: Vec<DirectoryRow>,
    guard: ShrinkGuard,
    members: Members,
}

/// Delivers a `kind: identity` run for one feed into a [`Directory`].
pub struct IdentitySink {
    dir: Arc<dyn Directory>,
    fence: Arc<dyn WriteFence>,
    max_memberships: u64,
    state: Mutex<State>,
    pub stats: IdentityStats,
}

/// Strip control characters and cap the length (on a char boundary).
pub fn clean_text(s: &str) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_control()).collect();
    if out.len() > MAX_TEXT {
        let mut end = MAX_TEXT;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out.trim().to_string()
}

fn text_of(v: &Value) -> Option<String> {
    let s = match v {
        Value::String(s) => clean_text(s),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    (!s.is_empty()).then_some(s)
}

fn bool_of(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" => Some(false),
            _ => None,
        },
        Value::Number(n) => n.as_i64().map(|n| n != 0),
        _ => None,
    }
}

/// The contract's statuses onto the directory's (`active`, `disabled`,
/// `suspended`, `deleted`, `anonymized`, `unknown`).
pub fn account_status(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "active" | "enabled" => "active",
        "disabled" | "deprovisioned" | "deactivated" => "disabled",
        "suspended" | "locked" | "locked_out" => "suspended",
        "deleted" => "deleted",
        "anonymized" => "anonymized",
        _ => "unknown",
    }
}

/// One program row, normalized: the directory row, its own reference and
/// the manager id it names (when it names one by id only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedUser {
    pub row: DirectoryRow,
    pub reference: Option<String>,
    pub manager_external_id: Option<String>,
}

/// A program's canonical user row. Only known columns are kept.
pub fn normalize_user(ev: &Value) -> Result<NormalizedUser, String> {
    let o = ev.as_object().ok_or("an identity users event must be an object")?;
    let external_id = o
        .get("external_id")
        .and_then(text_of)
        .filter(|s| s.len() <= 256)
        .ok_or("an identity users row needs a non-empty `external_id` (at most 256 bytes)")?;
    let mut text = BTreeMap::new();
    for f in DIRECTORY_TEXT_FIELDS {
        if let Some(t) = o.get(*f).and_then(text_of) {
            text.insert((*f).to_string(), t);
        }
    }
    let time = |f: &str| o.get(f).filter(|v| !v.is_null()).and_then(crate::engine::event_time_ms);
    let groups = match o.get("groups") {
        Some(Value::Array(gs)) => {
            let mut g: Vec<String> = gs.iter().filter_map(text_of).collect();
            g.sort();
            g.dedup();
            g.truncate(MAX_GROUPS_PER_MEMBER);
            Some(g)
        }
        _ => None,
    };
    let manager_external_id =
        if text.contains_key("manager_upn") { None } else { o.get("manager_external_id").and_then(text_of) };
    let row = DirectoryRow {
        external_id,
        account_status: o.get("account_status").and_then(text_of).map(|s| account_status(&s).to_string()),
        account_enabled: o.get("account_enabled").and_then(bool_of),
        mfa_enabled: o.get("mfa_enabled").and_then(bool_of),
        last_sign_in_at: time("last_sign_in_at"),
        created_in_directory_at: time("created_in_directory_at"),
        groups,
        deleted: o.get("deleted").and_then(bool_of).unwrap_or(false),
        keep_manager: manager_external_id.is_some(),
        text,
    };
    let reference = ["upn", "email", "username"].iter().find_map(|k| row.text.get(*k).cloned());
    Ok(NormalizedUser { row, reference, manager_external_id })
}

impl IdentitySink {
    pub fn new(dir: Arc<dyn Directory>, max_memberships: u64) -> Self {
        Self { dir, fence: Arc::new(NoFence), max_memberships, state: Mutex::new(State::default()), stats: IdentityStats::default() }
    }

    /// Fence every directory write with the run's lease.
    pub fn with_fence(mut self, fence: Arc<dyn WriteFence>) -> Self {
        self.fence = fence;
        self
    }

    /// Resolve `(user, manager id)` pairs from the run's map, then from the
    /// stored directory, and write the ones that resolve.
    async fn resolve_managers(&self, st: &mut State, pairs: Vec<(String, String)>) -> Result<(), String> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut resolved = Vec::with_capacity(pairs.len());
        let mut unknown = Vec::new();
        for (user, manager) in pairs {
            match st.references.get(&manager) {
                Some(r) => resolved.push((user, r.clone())),
                None => unknown.push((user, manager)),
            }
        }
        if !unknown.is_empty() {
            let ids: Vec<String> = unknown.iter().map(|(_, m)| m.clone()).collect();
            let stored = self.dir.references(&ids).await?;
            for (user, manager) in unknown {
                match stored.get(&manager) {
                    Some(r) => resolved.push((user, r.clone())),
                    None => {
                        self.stats.managers_unresolved.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        self.stats.managers_resolved.fetch_add(resolved.len() as u64, Ordering::Relaxed);
        self.dir.set_managers(&resolved).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Sink for IdentitySink {
    async fn push(&self, _source_type: &str, _events: &[Value]) -> Result<(), String> {
        Err("the identity sink takes rows only from kind: identity streams".into())
    }
    fn identity(&self) -> Option<&dyn IdentityTarget> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl IdentityTarget for IdentitySink {
    async fn users_begin(&self, _stream: &str, mode: IdentityMode, guard: ShrinkGuard) -> Result<(), String> {
        let mut st = self.state.lock().await;
        st.pending.clear();
        st.staged.clear();
        st.guard = guard;
        // A delta that turned into a full run starts a clean seen set.
        st.seen = (mode == IdentityMode::Full).then(HashSet::new);
        Ok(())
    }

    async fn users_page(&self, _stream: &str, mode: IdentityMode, rows: &[Value]) -> Result<(), String> {
        let mut guard = self.state.lock().await;
        let st = &mut *guard;
        let mut out = Vec::with_capacity(rows.len());
        let mut pairs = Vec::new();
        for ev in rows {
            let u = normalize_user(ev)?;
            if u.row.deleted {
                self.stats.tombstones.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(r) = &u.reference {
                st.references.insert(u.row.external_id.clone(), r.clone());
            }
            if let Some(m) = &u.manager_external_id {
                if !u.row.deleted {
                    pairs.push((u.row.external_id.clone(), m.clone()));
                }
            }
            if mode == IdentityMode::Full {
                st.seen.get_or_insert_with(HashSet::new).insert(u.row.external_id.clone());
            }
            out.push(u.row);
        }
        match mode {
            // A delta page is applied completely (managers too), under the
            // lease, before the engine moves the cursor past it.
            IdentityMode::Delta => {
                self.fence
                    .run(Box::pin(async {
                        let n = self.dir.upsert(&out, true).await?;
                        self.stats.rows.fetch_add(n, Ordering::Relaxed);
                        self.resolve_managers(st, pairs).await
                    }))
                    .await
            }
            // A full run is staged; it is published at the end, after the
            // shrink guard, when every user was seen.
            IdentityMode::Full => {
                if st.staged.len() + out.len() > MAX_STAGED_USERS {
                    return Err(format!("cap reached: an identity full run stages at most {MAX_STAGED_USERS} users"));
                }
                st.staged.extend(out);
                st.pending.extend(pairs);
                Ok(())
            }
        }
    }

    async fn users_finish(&self, stream: &str, mode: IdentityMode) -> Result<Option<u64>, String> {
        if mode == IdentityMode::Delta {
            return Ok(None);
        }
        let mut guard = self.state.lock().await;
        let st = &mut *guard;
        let seen = st.seen.take().unwrap_or_default();
        let staged = std::mem::take(&mut st.staged);
        let pending = std::mem::take(&mut st.pending);
        let rows = seen.len() as u64;
        // The guard runs BEFORE anything is written: a refused run leaves
        // the directory exactly as it was.
        if rows == 0 && !st.guard.allow {
            // A vendor answering "no users" must not wipe the directory.
            return Err(format!(
                "identity full run of `{stream}` returned no users; the directory was left unchanged (set feed config `{ALLOW_SHRINK_CONFIG}: true` if this is intended)"
            ));
        }
        st.guard.check(stream, rows)?;
        // Publish the staged snapshot, managers and retirement under one
        // lease hold: a pause, reset or delete waits for it, and a run whose
        // lease was lost publishes nothing.
        self.fence
            .run(Box::pin(async {
                for chunk in staged.chunks(PUBLISH_CHUNK) {
                    let n = self.dir.upsert(chunk, false).await?;
                    self.stats.rows.fetch_add(n, Ordering::Relaxed);
                }
                self.resolve_managers(st, pending).await?;
                let retired = self.dir.retire_absent(&seen).await?;
                self.stats.retired.fetch_add(retired, Ordering::Relaxed);
                Ok(())
            }))
            .await?;
        Ok(Some(rows))
    }

    async fn memberships_page(&self, _stream: &str, events: &[Value]) -> Result<(), String> {
        let mut st = self.state.lock().await;
        let m = &mut st.members;
        for ev in events {
            let (Some(member), Some(group)) = (ev.get("member").and_then(text_of), ev.get("group").and_then(text_of)) else {
                return Err("an identity membership event needs `member` and `group`".into());
            };
            if member.len() > 256 {
                return Err("an identity membership `member` exceeds 256 bytes".into());
            }
            m.pairs += 1;
            if m.pairs > self.max_memberships {
                return Err(format!(
                    "cap reached: more than {} identity memberships (limits.max_identity_memberships)",
                    self.max_memberships
                ));
            }
            let gid = match m.names.get(group.as_str()) {
                Some(id) => *id,
                None => {
                    let id = m.list.len() as u32;
                    m.list.push(group.clone().into_boxed_str());
                    m.names.insert(group.into_boxed_str(), id);
                    id
                }
            };
            m.by_member.entry(member.into_boxed_str()).or_default().push(gid);
        }
        self.stats.members.store(m.by_member.len() as u64, Ordering::Relaxed);
        self.stats.groups.store(m.list.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn memberships_finish(&self) -> Result<(), String> {
        let members = std::mem::take(&mut self.state.lock().await.members);
        if members.by_member.is_empty() {
            // An empty walk is more likely a scope or permission gap than a
            // directory without groups: keep the stored groups.
            tracing::warn!(target: "nano_connector::audit", "identity memberships walk found no memberships; the stored groups are kept");
            return Ok(());
        }
        let Members { list, by_member, .. } = members;
        let mut groups = HashMap::with_capacity(by_member.len());
        for (member, mut gids) in by_member {
            gids.sort_unstable_by(|a, b| list[*a as usize].cmp(&list[*b as usize]));
            gids.dedup();
            if gids.len() > MAX_GROUPS_PER_MEMBER {
                tracing::warn!(groups = gids.len(), "identity member has more groups than the directory keeps; truncating");
                gids.truncate(MAX_GROUPS_PER_MEMBER);
            }
            groups.insert(member.into_string(), gids.iter().map(|g| list[*g as usize].to_string()).collect::<Vec<_>>());
        }
        self.fence
            .run(Box::pin(async {
                let (changed, unmatched) = self.dir.replace_groups(&groups).await?;
                self.stats.groups_applied.fetch_add(changed, Ordering::Relaxed);
                self.stats.members_unmatched.fetch_add(unmatched, Ordering::Relaxed);
                Ok(())
            }))
            .await
    }

    async fn abort(&self) {
        let mut st = self.state.lock().await;
        st.seen = None;
        st.pending.clear();
        st.staged.clear();
        st.members = Members::default();
    }
}

/// An in-memory [`Directory`] keyed by external id (tests, preview).
#[derive(Default)]
pub struct MemoryDirectory {
    pub users: std::sync::Mutex<BTreeMap<String, nanosiem_core::identity::UserRecordUpsert>>,
}

impl MemoryDirectory {
    pub fn get(&self, id: &str) -> Option<nanosiem_core::identity::UserRecordUpsert> {
        self.users.lock().expect("directory").get(id).cloned()
    }
    pub fn live(&self) -> Vec<String> {
        self.users.lock().expect("directory").values().filter(|u| u.account_status != "deleted").map(|u| u.external_id.clone()).collect()
    }
}

fn as_stored(u: &nanosiem_core::identity::UserRecordUpsert) -> nanosiem_core::identity::types::UserRegistryRow {
    let s = |v: &Option<String>| v.clone().unwrap_or_default();
    let ms = |v: &Option<chrono::DateTime<chrono::Utc>>| v.map(|t| t.timestamp_millis()).unwrap_or(0);
    nanosiem_core::identity::types::UserRegistryRow {
        provider_id: String::new(),
        external_id: u.external_id.clone(),
        username: s(&u.username),
        upn: s(&u.upn),
        email: s(&u.email),
        display_name: s(&u.display_name),
        first_name: s(&u.first_name),
        last_name: s(&u.last_name),
        department: s(&u.department),
        title: s(&u.title),
        manager_upn: s(&u.manager_upn),
        manager_display_name: s(&u.manager_display_name),
        company: s(&u.company),
        office_location: s(&u.office_location),
        city: s(&u.city),
        country: s(&u.country),
        groups: u.groups.clone(),
        account_enabled: u.account_enabled as u8,
        account_status: u.account_status.clone(),
        mfa_enabled: u.mfa_enabled.unwrap_or(false) as u8,
        last_sign_in_at: ms(&u.last_sign_in_at),
        created_in_directory_at: ms(&u.created_in_directory_at),
        phone: s(&u.phone),
        employee_id: s(&u.employee_id),
        employee_type: s(&u.employee_type),
        sync_hash: u.sync_hash.clone(),
        last_synced_at: 0,
        version: 0,
    }
}

#[async_trait::async_trait]
impl Directory for MemoryDirectory {
    async fn upsert(&self, rows: &[DirectoryRow], patch: bool) -> Result<u64, String> {
        let mut users = self.users.lock().expect("directory");
        for r in rows {
            let stored = users.get(&r.external_id).map(as_stored);
            let up = nanosiem_core::identity::directory_feed::merge(r, stored.as_ref(), patch);
            users.insert(r.external_id.clone(), up);
        }
        Ok(rows.len() as u64)
    }
    async fn references(&self, ids: &[String]) -> Result<HashMap<String, String>, String> {
        let users = self.users.lock().expect("directory");
        Ok(ids
            .iter()
            .filter_map(|id| {
                let u = users.get(id).filter(|u| u.account_status != "deleted")?;
                let r = [&u.upn, &u.email, &u.username].into_iter().find_map(|v| v.clone())?;
                Some((id.clone(), r))
            })
            .collect())
    }
    async fn set_managers(&self, pairs: &[(String, String)]) -> Result<u64, String> {
        let mut users = self.users.lock().expect("directory");
        let mut n = 0;
        for (user, manager) in pairs {
            if let Some(u) = users.get_mut(user) {
                u.manager_upn = Some(manager.clone());
                n += 1;
            }
        }
        Ok(n)
    }
    async fn retire_absent(&self, seen: &HashSet<String>) -> Result<u64, String> {
        let mut users = self.users.lock().expect("directory");
        let mut n = 0;
        for u in users.values_mut().filter(|u| u.account_status != "deleted" && !seen.contains(&u.external_id)) {
            u.account_status = "deleted".into();
            u.account_enabled = false;
            n += 1;
        }
        Ok(n)
    }
    async fn replace_groups(&self, groups: &HashMap<String, Vec<String>>) -> Result<(u64, u64), String> {
        let mut users = self.users.lock().expect("directory");
        let unmatched = groups.keys().filter(|m| !users.get(*m).is_some_and(|u| u.account_status != "deleted")).count() as u64;
        let mut n = 0;
        for u in users.values_mut().filter(|u| u.account_status != "deleted") {
            let want = groups.get(&u.external_id).cloned().unwrap_or_default();
            if want != u.groups {
                u.groups = want;
                n += 1;
            }
        }
        Ok((n, unmatched))
    }
}

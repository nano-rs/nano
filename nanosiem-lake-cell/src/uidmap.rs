// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant → uid/gid allocation for a cell (NAN-2871).
//!
//! Each tenant placed on the cell gets a stable *slot*. The slot fixes:
//!
//! - `ingest[T]` uid = `base + 2·slot`
//! - `query[T]`  uid = `base + 2·slot + 1`
//! - `detect[T]` uid = `base + 2·max_slots + slot` (preserves existing ids)
//! - tenant gid      = `base + 2·slot` (all roles; lets readers read parts)
//!
//! Three uids per tenant keep the roles apart (least privilege: readers can
//! never read ingest's state dir or signal it). The map is persisted in the
//! supervisor's private state dir so a restart keeps ownership of existing
//! tenant directories stable. Slots are never reused while the map holds
//! them, so no new tenant can inherit files owned by an old one.
//!
//! The default base (20000) keeps every id below 65536, so the cell also
//! works inside a Kubernetes user-namespaced pod (`hostUsers: false`).
//!
//! NAN-3875: the map must live wherever tenant-owned files outlive the pod.
//! With a zero-downtime roll the state dir is per-pod ephemeral while the
//! A/B hot volume persists, so the supervisor keeps the map ON that volume
//! (see `Supervisor::new`). Allocation never follows first-touch order
//! alone: at boot the supervisor records every tenant tree's on-disk
//! ownership as a *claim* ([`UidMap::set_disk_claims`]). A tenant without a
//! slot takes the slot its own tree claims (when free); every other new slot
//! skips the slots any tree claims. Only PLACED tenants are ever foreign to
//! one another ([`UidMap::foreign_ids`]); a removed tenant's slot is released
//! once the purge has verified its trees and processes gone.
//! [`UidMap::load_or_recover`] moves a corrupt map aside instead of failing
//! the cell; the claims rebuild it.

use crate::contract::{Role, TenantId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

pub const DEFAULT_UID_BASE: u32 = 20_000;
pub const DEFAULT_UID_SLOTS: u32 = 20_000;
/// 65534 is the Linux overflow uid for unmapped host processes; never assign
/// it or include it in the supervisor's tenant-process sweep.
const DETECT_UID_END: u32 = 65_534;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Persisted {
    base: u32,
    slots: BTreeMap<TenantId, u32>,
}

#[derive(Debug)]
pub struct UidMap {
    path: PathBuf,
    max_slots: u32,
    state: Persisted,
    /// NAN-3875: the slot each tenant's on-disk tree(s) name, recorded at
    /// boot. `None`: the tree's ownership names no single slot (half
    /// walked, volumes disagree, not a tenant gid). Never persisted.
    claims: BTreeMap<TenantId, Option<u32>>,
}

/// One tenant tree's ownership on disk: (tenant, root gid, `parts/` uid).
pub type TreeOwnership = (TenantId, u32, Option<u32>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantIds {
    pub slot: u32,
    pub ingest_uid: u32,
    pub query_uid: u32,
    pub detect_uid: u32,
    pub gid: u32,
}

impl TenantIds {
    pub fn uid(&self, role: Role) -> u32 {
        match role {
            Role::Ingest => self.ingest_uid,
            Role::Detect => self.detect_uid,
            Role::Query => self.query_uid,
            // Runs as ingest's uid (same tenant writer trust domain); its
            // authority differs by credential: read-only state plus the
            // owner's maintenance bearer, never part/log/signing grants.
            Role::Maintenance => self.ingest_uid,
            // Query's uid (same read-only trust domain, NAN-3148): query[T]
            // reads the snapshots it publishes and writes its demand inbox.
            Role::Product => self.query_uid,
        }
    }
}

impl UidMap {
    /// Load `path` (creating an empty map if absent). A persisted base that
    /// differs from `base` is an error: silently re-basing would hand
    /// existing files to the wrong uids.
    pub fn load(path: &Path, base: u32, max_slots: u32) -> io::Result<Self> {
        if base == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "uid base must be > 0"));
        }
        base.checked_add(max_slots.saturating_mul(2))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "uid range overflows"))?;
        if base as u64 + max_slots as u64 * 2 >= DETECT_UID_END as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no user namespace ids remain for detect role"));
        }
        let detect_slots = (DETECT_UID_END - base - 2 * max_slots).min(max_slots);
        let state = match std::fs::read(path) {
            Ok(bytes) => {
                let s: Persisted =
                    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if s.base != base {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("uid map base {} != configured {base}", s.base),
                    ));
                }
                if s.slots.values().any(|slot| *slot >= detect_slots) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        "persisted uid slot exceeds configured three-role range"));
                }
                let distinct: std::collections::BTreeSet<u32> = s.slots.values().copied().collect();
                if distinct.len() != s.slots.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "persisted uid map gives two tenants one slot"));
                }
                s
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Persisted { base, slots: BTreeMap::new() },
            Err(e) => return Err(e),
        };
        Ok(Self { path: path.to_path_buf(), max_slots, state, claims: BTreeMap::new() })
    }

    /// NAN-3875: [`Self::load`], but a map that cannot be used (unreadable,
    /// unparsable, another base, out-of-range or duplicate slots) is moved
    /// aside (`uids.json.bad-<unix ms>`) and replaced by an empty one: the
    /// on-disk claims then rebuild it, instead of the cell failing to boot
    /// and every tenant on it staying down. Returns where the bad map went.
    /// Invalid CONFIG (base 0, range overflow) still fails.
    pub fn load_or_recover(path: &Path, base: u32, max_slots: u32) -> io::Result<(Self, Option<PathBuf>)> {
        match Self::load(path, base, max_slots) {
            Ok(m) => Ok((m, None)),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => Err(e),
            Err(e) => {
                let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
                let aside = path.with_extension(format!("json.bad-{ms}"));
                std::fs::rename(path, &aside)
                    .map_err(|re| io::Error::new(re.kind(), format!("uid map unusable ({e}) and could not be moved aside: {re}")))?;
                tracing::error!(error = %e, aside = %aside.display(), "uid map unusable; moved aside, rebuilding from tenant tree ownership");
                Ok((Self::load(path, base, max_slots)?, Some(aside)))
            }
        }
    }

    pub fn get(&self, tenant: &TenantId) -> Option<TenantIds> {
        self.state.slots.get(tenant).map(|s| self.ids(*s))
    }

    /// The tenant's ids, allocating (and persisting) a slot on first use.
    ///
    /// NAN-3875: a tenant without a slot first takes the slot its own tree
    /// claims on disk, when no tenant holds it. Otherwise it gets the lowest
    /// slot that no tenant holds AND no tree on disk claims, so a new slot
    /// never makes a tenant own another tree (live or stale). The order
    /// tenants are first touched in therefore never decides whose files a
    /// uid owns.
    pub fn get_or_allocate(&mut self, tenant: &TenantId) -> io::Result<TenantIds> {
        if let Some(ids) = self.get(tenant) {
            return Ok(ids);
        }
        let used: std::collections::BTreeSet<u32> = self.state.slots.values().copied().collect();
        let own = self.claims.get(tenant).copied().flatten().filter(|s| !used.contains(s));
        let claimed: std::collections::BTreeSet<u32> = self.claims.iter()
            .filter(|(t, _)| *t != tenant).filter_map(|(_, s)| *s).collect();
        let slot = match own {
            Some(s) => s,
            None => (0..self.detect_slots())
                .find(|s| !used.contains(s) && !claimed.contains(s))
                .ok_or_else(|| io::Error::other("cell uid slots exhausted"))?,
        };
        self.state.slots.insert(tenant.clone(), slot);
        if let Err(e) = self.persist() {
            self.state.slots.remove(tenant);
            return Err(e);
        }
        Ok(self.ids(slot))
    }

    /// NAN-3875: forget a tenant whose trees and processes the purge has
    /// verified gone: its slot (and claim) become reusable. Persisted.
    pub fn release(&mut self, tenant: &TenantId) -> io::Result<()> {
        self.claims.remove(tenant);
        if let Some(slot) = self.state.slots.remove(tenant) {
            if let Err(e) = self.persist() {
                self.state.slots.insert(tenant.clone(), slot);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Every id held by a PLACED tenant other than `tenant`: the slot the
    /// map gives it, or (not allocated yet) the slot its own tree claims on
    /// disk. A directory of `tenant`'s tree owned by one of these is another
    /// live tenant's: `tenant_dirs` refuses it instead of reclaiming it.
    /// Unplaced (removed, destroyed) tenants are never foreign.
    pub fn foreign_ids(&self, tenant: &TenantId, placed: &std::collections::BTreeSet<TenantId>) -> std::collections::BTreeSet<u32> {
        let held: std::collections::BTreeSet<u32> = self.state.slots.values().copied().collect();
        placed.iter().filter(|t| *t != tenant)
            // A claim counts only while its slot is free: a held slot will
            // never be granted to the claimant, so its ids are the holder's.
            .filter_map(|t| self.state.slots.get(t).copied()
                .or_else(|| self.claims.get(t).copied().flatten().filter(|s| !held.contains(s))))
            .flat_map(|s| { let i = self.ids(s); [i.ingest_uid, i.query_uid, i.detect_uid, i.gid] })
            .collect()
    }

    fn detect_slots(&self) -> u32 {
        (DETECT_UID_END - self.state.base - 2 * self.max_slots).min(self.max_slots)
    }

    /// The slot a tenant tree's ownership names: its root's gid is the
    /// tenant gid (`base + 2·slot`), and `parts/` (when present) is owned by
    /// the ingest uid, which is the same number.
    pub fn slot_from_ownership(&self, root_gid: u32, parts_uid: Option<u32>) -> Option<u32> {
        let off = root_gid.checked_sub(self.state.base)?;
        if off % 2 != 0 || off / 2 >= self.detect_slots() || parts_uid.is_some_and(|u| u != root_gid) {
            return None;
        }
        Some(off / 2)
    }

    /// NAN-3875: record what the trees on disk claim (several observations
    /// per tenant when it has trees on several volumes; they must agree).
    /// Returns the tenants whose ownership names no single slot.
    pub fn set_disk_claims(&mut self, observed: &[TreeOwnership]) -> Vec<TenantId> {
        let mut claims: BTreeMap<TenantId, Option<u32>> = BTreeMap::new();
        for (t, gid, parts) in observed {
            let slot = self.slot_from_ownership(*gid, *parts);
            claims.entry(t.clone()).and_modify(|c| if *c != slot { *c = None }).or_insert(slot);
        }
        let unclaimed = claims.iter().filter(|(_, s)| s.is_none()).map(|(t, _)| t.clone()).collect();
        self.claims = claims;
        unclaimed
    }

    /// The tenant trees under each of `roots` (a missing root is skipped):
    /// metadata only, never following a link.
    pub fn observe_trees(roots: &[PathBuf]) -> io::Result<Vec<TreeOwnership>> {
        use std::os::unix::fs::MetadataExt;
        let mut observed = Vec::new();
        for root in roots {
            let entries = match std::fs::read_dir(root) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for e in entries {
                let e = e?;
                let Some(Ok(t)) = e.file_name().to_str().map(TenantId::new) else { continue };
                let md = std::fs::symlink_metadata(e.path())?;
                if !md.is_dir() {
                    continue;
                }
                let parts = std::fs::symlink_metadata(e.path().join("parts")).ok().filter(|m| m.is_dir()).map(|m| m.uid());
                observed.push((t, md.gid(), parts));
            }
        }
        Ok(observed)
    }

    fn ids(&self, slot: u32) -> TenantIds {
        let first = self.state.base + slot * 2;
        TenantIds { slot, ingest_uid: first, query_uid: first + 1, detect_uid: self.state.base + self.max_slots * 2 + slot, gid: first }
    }

    /// Every tenant with a slot (placed now or earlier: their uids may still
    /// run processes).
    pub fn all(&self) -> Vec<(TenantId, TenantIds)> {
        self.state.slots.iter().map(|(t, s)| (t.clone(), self.ids(*s))).collect()
    }

    /// The uid range this cell's tenants live in, including detect's reserved
    /// high range. The platform's unchanged 20,000-slot cell config leaves 5,534
    /// usable stable detect slots inside a 65,536-id pod user namespace.
    pub fn tenant_uid_range(&self) -> (u32, u32) {
        let detect_slots = (DETECT_UID_END - self.state.base - 2 * self.max_slots).min(self.max_slots);
        (self.state.base, self.state.base + self.max_slots * 2 + detect_slots)
    }

    /// Is `uid` one of this cell's tenant uids?
    pub fn is_tenant_uid(&self, uid: u32) -> bool {
        let (_, end) = self.tenant_uid_range();
        uid >= self.state.base && uid < end
    }

    fn persist(&self) -> io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(io::Error::other)?;
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_distinct_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("uids.json");
        let a = TenantId::new("a").unwrap();
        let b = TenantId::new("b").unwrap();
        let (ia, ib) = {
            let mut m = UidMap::load(&p, 20_000, 10).unwrap();
            (m.get_or_allocate(&a).unwrap(), m.get_or_allocate(&b).unwrap())
        };
        assert_eq!(ia.ingest_uid, 20_000);
        assert_eq!(ia.query_uid, 20_001);
        assert_eq!(ib.ingest_uid, 20_002);
        assert_ne!(ia.gid, ib.gid);
        let mut m = UidMap::load(&p, 20_000, 10).unwrap();
        assert_eq!(m.get_or_allocate(&b).unwrap(), ib);
        assert_eq!(ia.detect_uid, 20_020);
        assert!(m.is_tenant_uid(20_019) && m.is_tenant_uid(20_020) && !m.is_tenant_uid(20_030) && !m.is_tenant_uid(0));
        assert!(UidMap::load(&p, 30_000, 10).is_err(), "re-basing must be refused");
    }

    fn tid(s: &str) -> TenantId {
        TenantId::new(s).unwrap()
    }

    fn set(ts: &[&TenantId]) -> std::collections::BTreeSet<TenantId> {
        ts.iter().map(|t| (*t).clone()).collect()
    }

    /// NAN-3875: allocation order, other tenants arriving or leaving the
    /// placement, and reloads never change an existing tenant's ids.
    #[test]
    fn adding_or_removing_tenants_never_moves_others() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("uids.json");
        let (a, b, c, d) = (tid("aaaa"), tid("bbbb"), tid("cccc"), tid("dddd"));
        let (ia, ib) = {
            let mut m = UidMap::load(&p, 20_000, 10).unwrap();
            // b first: allocation order is not a property of the tenant.
            let ib = m.get_or_allocate(&b).unwrap();
            (m.get_or_allocate(&a).unwrap(), ib)
        };
        // A new tenant (a burner) is born on a later boot, and a reload
        // touches tenants in the opposite order.
        let ic = {
            let mut m = UidMap::load(&p, 20_000, 10).unwrap();
            let ic = m.get_or_allocate(&c).unwrap();
            assert_eq!(m.get_or_allocate(&a).unwrap(), ia);
            assert_eq!(m.get_or_allocate(&b).unwrap(), ib);
            ic
        };
        // The burner is destroyed (purged, released) and d arrives.
        let mut m = UidMap::load(&p, 20_000, 10).unwrap();
        m.release(&c).unwrap();
        let id = m.get_or_allocate(&d).unwrap();
        assert_eq!((m.get(&a), m.get(&b), m.get(&c)), (Some(ia), Some(ib), None));
        assert_eq!(id.slot, ic.slot, "a released slot is reusable");
        let m = UidMap::load(&p, 20_000, 10).unwrap();
        assert_eq!((m.get(&a), m.get(&b), m.get(&d)), (Some(ia), Some(ib), Some(id)), "persisted");
        for (x, y) in [(ia, ib), (ia, id), (ib, id)] {
            assert!(x.ingest_uid != y.ingest_uid && x.query_uid != y.query_uid && x.detect_uid != y.detect_uid && x.gid != y.gid);
        }
        let foreign = m.foreign_ids(&a, &set(&[&a, &b]));
        assert!(!foreign.contains(&ia.ingest_uid) && !foreign.contains(&ia.detect_uid));
        assert!([ib.ingest_uid, ib.query_uid, ib.detect_uid, ib.gid].iter().all(|u| foreign.contains(u)));
        assert!(!foreign.contains(&id.ingest_uid), "an unplaced tenant is never foreign");
    }

    /// The review scenario: four trees on the hot volume, two live tenants
    /// and two stale burners from an older pod on the same slots, so the
    /// ownership is "ambiguous" slot-wise. Whatever order the live tenants
    /// are touched in, each gets the slot its own tree names, and no stale
    /// tree makes either of them foreign.
    #[test]
    fn four_trees_two_stale_both_spawn_orders() {
        let (s, b, x, y) = (tid("tenant-a"), tid("buddy"), tid("burner-x"), tid("burner-y"));
        let trees = [(s.clone(), 20_002, Some(20_002)), (b.clone(), 20_000, Some(20_000)),
            (x.clone(), 20_000, Some(20_000)), (y.clone(), 20_002, None)];
        let placed = set(&[&s, &b]);
        for (stale_in_map, order) in [(false, [&s, &b]), (false, [&b, &s]), (true, [&s, &b]), (true, [&b, &s])] {
            let dir = tempfile::tempdir().unwrap();
            let mut m = UidMap::load(&dir.path().join("u.json"), 20_000, 10).unwrap();
            if stale_in_map {
                // The older pod's map still holds the burners on slots 0/1.
                m.get_or_allocate(&x).unwrap();
                m.get_or_allocate(&y).unwrap();
            }
            assert!(m.set_disk_claims(&trees).is_empty());
            for t in order {
                m.get_or_allocate(t).unwrap();
            }
            let (is, ib) = (m.get(&s).unwrap(), m.get(&b).unwrap());
            if stale_in_map {
                // Their own slots are held by unplaced burners: fresh slots
                // that no tree claims; the old owners are not foreign, so the
                // trees are reclaimed (never refused).
                assert!(is.slot >= 2 && ib.slot >= 2 && is.slot != ib.slot, "{order:?}");
            } else {
                assert_eq!((is.slot, ib.slot), (1, 0), "{order:?}");
            }
            let fs = m.foreign_ids(&s, &placed);
            assert!(fs.contains(&ib.gid) && !fs.contains(&is.gid));
            if stale_in_map {
                // tenant-a's tree is owned by slot 1 ids (burner-y's): not foreign.
                assert!(!fs.contains(&20_002) && !fs.contains(&20_003));
            }
        }
    }

    /// A tree whose walk was interrupted (root gid and parts disagree)
    /// claims nothing; its tenant gets a slot no tree claims, and another
    /// placed tenant's claimed slot is foreign to it before that tenant
    /// is even allocated.
    #[test]
    fn half_walked_tree_claims_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (tid("aaaa"), tid("bbbb"));
        let mut m = UidMap::load(&dir.path().join("u.json"), 20_000, 10).unwrap();
        let unclaimed = m.set_disk_claims(&[(a.clone(), 20_000, Some(20_002)), (b.clone(), 20_002, Some(20_002))]);
        assert_eq!(unclaimed, vec![a.clone()]);
        let ia = m.get_or_allocate(&a).unwrap();
        assert!(ia.slot != 1, "never the slot b's tree claims");
        let fa = m.foreign_ids(&a, &set(&[&a, &b]));
        assert!(fa.contains(&20_002) && fa.contains(&20_003), "b's claimed ids are foreign to a");
        assert_eq!(m.get_or_allocate(&b).unwrap().slot, 1);
    }

    /// A destroyed tenant's leftover tree never makes a live tenant foreign,
    /// and its slot is reused only after the purge releases it.
    #[test]
    fn stale_destroyed_tree_is_never_foreign() {
        let dir = tempfile::tempdir().unwrap();
        let (live, gone) = (tid("live"), tid("gone"));
        let mut m = UidMap::load(&dir.path().join("u.json"), 20_000, 10).unwrap();
        m.set_disk_claims(&[(gone.clone(), 20_000, Some(20_000))]);
        assert_eq!(m.get_or_allocate(&live).unwrap().slot, 1, "skips the slot the stale tree claims");
        assert!(m.foreign_ids(&live, &set(&[&live])).is_empty());
        m.release(&gone).unwrap();
        assert_eq!(m.get_or_allocate(&tid("next")).unwrap().slot, 0);
    }

    /// Two PLACED tenants whose trees truly claim one slot: the first takes
    /// it, the second gets another slot and the first's ids are foreign to
    /// it (its hot tree is rebuilt; durable data is refused).
    #[test]
    fn two_live_tenants_claiming_one_slot_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (tid("aaaa"), tid("bbbb"));
        let mut m = UidMap::load(&dir.path().join("u.json"), 20_000, 10).unwrap();
        m.set_disk_claims(&[(a.clone(), 20_000, None), (b.clone(), 20_000, None)]);
        let ib = m.get_or_allocate(&b).unwrap();
        let ia = m.get_or_allocate(&a).unwrap();
        assert_eq!(ib.slot, 0);
        assert_ne!(ia.slot, 0);
        assert!(m.foreign_ids(&a, &set(&[&a, &b])).contains(&20_000));
    }

    /// A placed tenant whose (stale) tree claims a slot another placed
    /// tenant already holds never makes the holder's own tree foreign.
    #[test]
    fn a_claim_on_a_held_slot_is_never_foreign_to_its_holder() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (tid("aaaa"), tid("bbbb"));
        let mut m = UidMap::load(&dir.path().join("u.json"), 20_000, 10).unwrap();
        let ia = m.get_or_allocate(&a).unwrap();
        m.set_disk_claims(&[(b.clone(), ia.gid, None)]);
        assert!(m.foreign_ids(&a, &set(&[&a, &b])).is_empty(), "b is not allocated and its claim is a's slot");
        let ib = m.get_or_allocate(&b).unwrap();
        assert_ne!(ib.slot, ia.slot);
        assert!(!m.foreign_ids(&a, &set(&[&a, &b])).contains(&ia.gid));
    }

    #[test]
    fn corrupt_map_is_moved_aside_and_rebuilt() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("uids.json");
        for bad in [&b"{not json"[..], br#"{"base":30000,"slots":{}}"#, br#"{"base":20000,"slots":{"a":0,"b":0}}"#,
            br#"{"base":20000,"slots":{"a":99}}"#] {
            std::fs::write(&p, bad).unwrap();
            assert!(UidMap::load(&p, 20_000, 10).is_err());
            let (mut m, aside) = UidMap::load_or_recover(&p, 20_000, 10).unwrap();
            let aside = aside.expect("moved aside");
            assert_eq!(std::fs::read(&aside).unwrap(), bad, "the bad map is kept for forensics");
            assert!(!p.exists() && m.all().is_empty());
            m.set_disk_claims(&[(tid("a"), 20_004, None)]);
            assert_eq!(m.get_or_allocate(&tid("a")).unwrap().slot, 2, "rebuilt from the tree's ownership");
            std::fs::remove_file(&p).unwrap();
        }
        let (m, aside) = UidMap::load_or_recover(&p, 20_000, 10).unwrap();
        assert!(aside.is_none() && m.all().is_empty(), "absent is not corrupt");
        assert!(UidMap::load_or_recover(&p, 0, 10).is_err(), "bad config still fails");
    }

    #[test]
    fn observe_trees_reads_ownership_without_following_links() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let tenants = dir.path().join("tenants");
        std::fs::create_dir_all(tenants.join("aaaa")).unwrap();
        std::os::unix::fs::symlink(dir.path(), tenants.join("bbbb")).unwrap();
        let gid = std::fs::metadata(tenants.join("aaaa")).unwrap().gid();
        let seen = UidMap::observe_trees(&[tenants, dir.path().join("missing")]).unwrap();
        assert_eq!(seen, vec![(tid("aaaa"), gid, None)], "a symlinked tree is never observed");
    }

    #[test]
    fn exhaustion() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = UidMap::load(&dir.path().join("u.json"), 100, 1).unwrap();
        m.get_or_allocate(&TenantId::new("a").unwrap()).unwrap();
        assert!(m.get_or_allocate(&TenantId::new("b").unwrap()).is_err());
    }
}

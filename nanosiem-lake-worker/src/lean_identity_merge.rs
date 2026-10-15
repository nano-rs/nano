// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-person, per-field merge of identity directory rows (NAN-3503; the
//! minimal reader-side piece of NAN-3502).
//!
//! The R2 store keeps every feed's row with its provenance
//! ([`crate::lean_identity_snapshot`]); readers merge them here:
//!
//! * **Linking.** Rows are the same person when they share a provider-scoped
//!   id (`(feed prefix before ':', external_id)`, which joins one provider's
//!   `<feed>:users` and `<feed>:groups` sub-feeds) or a lowercase e-mail
//!   address / UPN. A bare username links only rows that carry neither an
//!   e-mail nor a UPN (the contract's `email -> upn -> username` cascade).
//!   A membership row keyed by an address (`member` given as e-mail or UPN)
//!   links on that address too.
//! * **Fields.** Per field the highest-precedence non-empty value wins:
//!   `pull > push > observed`, then the newest `version`, then the larger
//!   value (so the result never depends on input order).
//! * **Groups** are the sorted, de-duplicated union of every row of the
//!   provider whose row wins the field; **`is_admin`** is the OR over that
//!   provider's sub-feeds (Google `isAdmin` on the users row, a privileged
//!   role on the groups row).
//! * **Account state** (`account_enabled`, `account_status`) comes from users
//!   rows only, never from a membership sub-feed.
//!
//! The merge is a streaming fold with union-by-size, so memory is one
//! accumulator per person plus the link keys, never the input rows.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::lean_identity_snapshot::{IdentityRow, SourceKind};

/// Membership sub-feed suffix (`<feed>:groups`, contract "Membership aggregation").
pub const GROUPS_SUFFIX: &str = ":groups";
/// Groups kept per merged person; the rest are dropped and flagged.
pub const MAX_MERGED_GROUPS: usize = 256;

/// One person after the merge. Text is interned: departments, titles,
/// managers and group names repeat across a directory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergedIdentity {
    /// Feed prefix (before `:`) of the winning users row.
    pub provider: Arc<str>,
    /// Full feed id of the winning users row.
    pub feed_id: Arc<str>,
    pub external_id: Arc<str>,
    pub email: Option<Arc<str>>,
    pub upn: Option<Arc<str>>,
    pub username: Option<Arc<str>>,
    pub display_name: Option<Arc<str>>,
    pub department: Option<Arc<str>>,
    pub title: Option<Arc<str>>,
    pub manager_upn: Option<Arc<str>>,
    pub manager_display_name: Option<Arc<str>>,
    pub company: Option<Arc<str>>,
    pub office_location: Option<Arc<str>>,
    pub employee_id: Option<Arc<str>>,
    pub employee_type: Option<Arc<str>>,
    pub account_status: Option<Arc<str>>,
    pub account_enabled: Option<bool>,
    pub is_admin: Option<bool>,
    pub groups: Box<[Arc<str>]>,
    pub groups_truncated: bool,
    /// Lowercase e-mail addresses and UPNs of every merged row.
    pub address_keys: Box<[Box<str>]>,
    /// Lowercase usernames of every merged row.
    pub username_keys: Box<[Box<str>]>,
}

/// Merge the rows of one person (or of many: rows are clustered first) into
/// merged identities, ordered by provider, feed and external id.
pub fn merge_identity_rows<'a>(rows: impl IntoIterator<Item = &'a IdentityRow>) -> Vec<MergedIdentity> {
    let mut merger = IdentityMerger::default();
    for row in rows {
        merger.push(row);
    }
    let mut merged = merger.finish();
    merged.sort_by(|a, b| {
        (&a.provider, &a.feed_id, &a.external_id).cmp(&(&b.provider, &b.feed_id, &b.external_id))
    });
    merged
}

/// Field precedence: source kind rank above version.
fn precedence(row: &IdentityRow) -> u64 {
    let rank: u64 = match row.source_kind {
        SourceKind::Pull => 2,
        SourceKind::Push => 1,
        SourceKind::Observed => 0,
    };
    (rank << 62) | (row.version.clamp(0, (1 << 62) - 1) as u64)
}

pub fn provider_of(feed_id: &str) -> &str {
    feed_id.split_once(':').map_or(feed_id, |(prefix, _)| prefix)
}

fn is_groups_feed(feed_id: &str) -> bool {
    feed_id.ends_with(GROUPS_SUFFIX)
}

type Slot = Option<(u64, Arc<str>)>;

#[derive(Default)]
struct ProviderFacts {
    provider: Arc<str>,
    groups_order: u64,
    groups: HashSet<Arc<str>>,
    admin_order: u64,
    admin: Option<bool>,
}

#[derive(Default)]
struct Accumulator {
    /// `(order, feed_id, external_id)` of the winning row; users rows beat
    /// membership rows regardless of order.
    primary: Option<(bool, u64, Arc<str>, Arc<str>)>,
    text: [Slot; TEXT_FIELDS],
    account_enabled: Option<(u64, bool)>,
    providers: Vec<ProviderFacts>,
    link_keys: Vec<Arc<str>>,
    address_keys: HashSet<Box<str>>,
    username_keys: HashSet<Box<str>>,
}

const TEXT_FIELDS: usize = 13;
const EMAIL: usize = 0;
const UPN: usize = 1;
const USERNAME: usize = 2;
const DISPLAY_NAME: usize = 3;
const DEPARTMENT: usize = 4;
const TITLE: usize = 5;
const MANAGER_UPN: usize = 6;
const MANAGER_DISPLAY_NAME: usize = 7;
const COMPANY: usize = 8;
const OFFICE_LOCATION: usize = 9;
const EMPLOYEE_ID: usize = 10;
const EMPLOYEE_TYPE: usize = 11;
const ACCOUNT_STATUS: usize = 12;

fn better(order: u64, value: &str, slot: &Slot) -> bool {
    match slot {
        None => true,
        Some((current, existing)) => order > *current || (order == *current && value > &**existing),
    }
}

impl Accumulator {
    fn offer(&mut self, field: usize, order: u64, value: &str, interner: &mut Interner) {
        let value = value.trim();
        if value.is_empty() || !better(order, value, &self.text[field]) {
            return;
        }
        self.text[field] = Some((order, interner.get(value)));
    }

    fn provider(&mut self, provider: &str, interner: &mut Interner) -> &mut ProviderFacts {
        let index = match self.providers.iter().position(|facts| &*facts.provider == provider) {
            Some(index) => index,
            None => {
                self.providers.push(ProviderFacts {
                    provider: interner.get(provider),
                    ..ProviderFacts::default()
                });
                self.providers.len() - 1
            }
        };
        &mut self.providers[index]
    }

    fn fold_row(&mut self, row: &IdentityRow, interner: &mut Interner) {
        let order = precedence(row);
        let groups_row = is_groups_feed(&row.feed_id);
        let users = !groups_row;
        let replace_primary = match &self.primary {
            None => true,
            Some((was_users, was_order, feed, external)) => {
                (users, order, &*row.feed_id, &*row.external_id)
                    > (*was_users, *was_order, &**feed, &**external)
            }
        };
        if replace_primary {
            self.primary = Some((users, order, interner.get(&row.feed_id), Arc::from(row.external_id.as_str())));
        }
        for (field, value) in [
            (EMAIL, &row.email),
            (UPN, &row.upn),
            (USERNAME, &row.username),
            (DISPLAY_NAME, &row.display_name),
            (DEPARTMENT, &row.department),
            (TITLE, &row.title),
            (MANAGER_UPN, &row.manager_upn),
            (MANAGER_DISPLAY_NAME, &row.manager_display_name),
            (COMPANY, &row.company),
            (OFFICE_LOCATION, &row.office_location),
            (EMPLOYEE_ID, &row.employee_id),
            (EMPLOYEE_TYPE, &row.employee_type),
        ] {
            self.offer(field, order, value, interner);
        }
        if users {
            self.offer(ACCOUNT_STATUS, order, &row.account_status, interner);
            if let Some(enabled) = row.account_enabled {
                if self.account_enabled.is_none_or(|(current, value)| {
                    order > current || (order == current && enabled > value)
                }) {
                    self.account_enabled = Some((order, enabled));
                }
            }
        }
        let provider = provider_of(&row.feed_id);
        let groups: Vec<Arc<str>> = row
            .groups
            .iter()
            .map(|group| group.trim())
            .filter(|group| !group.is_empty())
            .map(|group| interner.get(group))
            .collect();
        let facts = self.provider(provider, interner);
        if !groups.is_empty() {
            facts.groups_order = facts.groups_order.max(order);
            facts.groups.extend(groups);
        }
        if let Some(admin) = row.is_admin {
            facts.admin_order = facts.admin_order.max(order);
            facts.admin = Some(facts.admin.unwrap_or(false) || admin);
        }
        for value in [&row.email, &row.upn] {
            let value = value.trim();
            if !value.is_empty() {
                self.address_keys.insert(value.to_lowercase().into_boxed_str());
            }
        }
        let username = row.username.trim();
        if !username.is_empty() {
            self.username_keys.insert(username.to_lowercase().into_boxed_str());
        }
    }

    fn absorb(&mut self, other: Accumulator) {
        if let Some(theirs) = other.primary {
            let replace = match &self.primary {
                None => true,
                Some((u, o, f, e)) => (theirs.0, theirs.1, &*theirs.2, &*theirs.3) > (*u, *o, &**f, &**e),
            };
            if replace {
                self.primary = Some(theirs);
            }
        }
        for (field, slot) in other.text.into_iter().enumerate() {
            if let Some((order, value)) = slot {
                if better(order, &value, &self.text[field]) {
                    self.text[field] = Some((order, value));
                }
            }
        }
        if let Some((order, enabled)) = other.account_enabled {
            if self
                .account_enabled
                .is_none_or(|(current, value)| order > current || (order == current && enabled > value))
            {
                self.account_enabled = Some((order, enabled));
            }
        }
        for theirs in other.providers {
            match self.providers.iter_mut().find(|facts| facts.provider == theirs.provider) {
                Some(mine) => {
                    mine.groups_order = mine.groups_order.max(theirs.groups_order);
                    mine.groups.extend(theirs.groups);
                    mine.admin_order = mine.admin_order.max(theirs.admin_order);
                    mine.admin = match (mine.admin, theirs.admin) {
                        (None, None) => None,
                        (a, b) => Some(a.unwrap_or(false) || b.unwrap_or(false)),
                    };
                }
                None => self.providers.push(theirs),
            }
        }
        self.link_keys.extend(other.link_keys);
        self.address_keys.extend(other.address_keys);
        self.username_keys.extend(other.username_keys);
    }

    fn finish(self) -> MergedIdentity {
        let text = |field: usize| self.text[field].as_ref().map(|(_, value)| value.clone());
        // The provider whose rows win the field supplies every group / the
        // admin flag of that provider's sub-feeds; ties: larger provider id.
        let groups_provider = self
            .providers
            .iter()
            .filter(|facts| !facts.groups.is_empty())
            .max_by(|a, b| (a.groups_order, &a.provider).cmp(&(b.groups_order, &b.provider)));
        let mut groups: Vec<Arc<str>> = groups_provider
            .map(|facts| facts.groups.iter().cloned().collect())
            .unwrap_or_default();
        groups.sort();
        let groups_truncated = groups.len() > MAX_MERGED_GROUPS;
        groups.truncate(MAX_MERGED_GROUPS);
        let is_admin = self
            .providers
            .iter()
            .filter(|facts| facts.admin.is_some())
            .max_by(|a, b| (a.admin_order, &a.provider).cmp(&(b.admin_order, &b.provider)))
            .and_then(|facts| facts.admin);
        let (feed_id, external_id) = self
            .primary
            .as_ref()
            .map(|(_, _, feed, external)| (feed.clone(), external.clone()))
            .unwrap_or_default();
        let mut address_keys: Vec<Box<str>> = self.address_keys.iter().cloned().collect();
        address_keys.sort();
        let mut username_keys: Vec<Box<str>> = self.username_keys.iter().cloned().collect();
        username_keys.sort();
        MergedIdentity {
            provider: Arc::from(provider_of(&feed_id)),
            feed_id,
            external_id,
            email: text(EMAIL),
            upn: text(UPN),
            username: text(USERNAME),
            display_name: text(DISPLAY_NAME),
            department: text(DEPARTMENT),
            title: text(TITLE),
            manager_upn: text(MANAGER_UPN),
            manager_display_name: text(MANAGER_DISPLAY_NAME),
            company: text(COMPANY),
            office_location: text(OFFICE_LOCATION),
            employee_id: text(EMPLOYEE_ID),
            employee_type: text(EMPLOYEE_TYPE),
            account_status: text(ACCOUNT_STATUS),
            account_enabled: self.account_enabled.map(|(_, value)| value),
            is_admin,
            groups: groups.into_boxed_slice(),
            groups_truncated,
            address_keys: address_keys.into_boxed_slice(),
            username_keys: username_keys.into_boxed_slice(),
        }
    }
}

/// Shares repeated text (departments, titles, managers, group names).
#[derive(Default)]
struct Interner(HashSet<Arc<str>>);

impl Interner {
    fn get(&mut self, value: &str) -> Arc<str> {
        if let Some(existing) = self.0.get(value) {
            return existing.clone();
        }
        let value: Arc<str> = Arc::from(value);
        self.0.insert(value.clone());
        value
    }
}

/// Streaming union-find merge: push rows in any order, then [`Self::finish`].
#[derive(Default)]
pub struct IdentityMerger {
    interner: Interner,
    /// Link key -> accumulator slot.
    links: HashMap<Arc<str>, usize>,
    people: Vec<Option<Accumulator>>,
    free: Vec<usize>,
}

impl IdentityMerger {
    fn link_keys(row: &IdentityRow) -> Vec<String> {
        let mut keys = vec![format!("p\u{0}{}\u{0}{}", provider_of(&row.feed_id), row.external_id)];
        let mut addressed = false;
        for value in [&row.email, &row.upn] {
            let value = value.trim();
            if !value.is_empty() {
                keys.push(format!("a\u{0}{}", value.to_lowercase()));
                addressed = true;
            }
        }
        // A membership row keyed by address (`member` = e-mail or UPN).
        if is_groups_feed(&row.feed_id) && row.external_id.contains('@') {
            keys.push(format!("a\u{0}{}", row.external_id.trim().to_lowercase()));
            addressed = true;
        }
        let username = row.username.trim();
        if !addressed && !username.is_empty() {
            keys.push(format!("u\u{0}{}", username.to_lowercase()));
        }
        keys
    }

    pub fn push(&mut self, row: &IdentityRow) {
        if row.deleted {
            return;
        }
        let keys = Self::link_keys(row);
        let mut slots: Vec<usize> = keys.iter().filter_map(|key| self.links.get(key.as_str()).copied()).collect();
        slots.sort_unstable();
        slots.dedup();
        // Union by size: the largest accumulator absorbs the others.
        let target = match slots
            .iter()
            .copied()
            .max_by_key(|slot| self.people[*slot].as_ref().map_or(0, |acc| acc.link_keys.len()))
        {
            Some(target) => target,
            None => {
                let accumulator = Accumulator::default();
                match self.free.pop() {
                    Some(slot) => {
                        self.people[slot] = Some(accumulator);
                        slot
                    }
                    None => {
                        self.people.push(Some(accumulator));
                        self.people.len() - 1
                    }
                }
            }
        };
        for slot in slots.into_iter().filter(|slot| *slot != target) {
            let absorbed = self.people[slot].take().expect("live accumulator");
            for key in &absorbed.link_keys {
                self.links.insert(key.clone(), target);
            }
            self.people[target].as_mut().expect("live accumulator").absorb(absorbed);
            self.free.push(slot);
        }
        let accumulator = self.people[target].as_mut().expect("live accumulator");
        for key in keys {
            if !self.links.contains_key(key.as_str()) {
                let key: Arc<str> = Arc::from(key);
                self.links.insert(key.clone(), target);
                accumulator.link_keys.push(key);
            }
        }
        accumulator.fold_row(row, &mut self.interner);
    }

    pub fn finish(self) -> Vec<MergedIdentity> {
        drop(self.links);
        self.people
            .into_iter()
            .flatten()
            .map(Accumulator::finish)
            .collect()
    }
}

#[cfg(test)]
#[path = "lean_identity_merge_tests.rs"]
mod tests;

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded, process-local candidate hints. Never an authorization or data cache.
//! A restart or another replica costs a miss; every hint is read through the
//! tenant-pinned control store and checked against current authority and data.
use super::{DurableSearchCredentialAuthority, DurableSearchJobAuthority, SearchRequest};
use crate::auth::ScopeSet;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use uuid::Uuid;

const CAPACITY: usize = 4096;
const TTL: Duration = Duration::from_secs(2 * 60 * 60);
type Key = [u8; 32];

pub(super) fn key(
    request: &SearchRequest,
    canonical: &str,
    user: Uuid,
    scope: &ScopeSet,
    authority: Option<&DurableSearchJobAuthority>,
) -> Option<Key> {
    let authority = authority.cloned().map(|mut value| {
        // Session renewal is not an authority change (same rule as settled_reuse).
        if matches!(
            value.credential,
            DurableSearchCredentialAuthority::Session { .. }
        ) {
            value.credential = DurableSearchCredentialAuthority::Session {
                access_jti: Uuid::nil(),
                credential_time_micros: 0,
            };
        }
        value
    });
    let bytes = serde_json::to_vec(&(
        user,
        scope.deny_set(),
        authority,
        canonical,
        request.time_range.start,
        request.time_range.end,
        request.limit,
        request.offset.unwrap_or(0),
        request.table_view,
        request.dataset.as_deref().unwrap_or("logs"),
    ))
    .ok()?;
    Some(Sha256::digest(bytes).into())
}

#[derive(Default)]
pub(super) struct RecentReuseJobs {
    entries: Mutex<HashMap<Key, (String, Instant)>>,
}
impl RecentReuseJobs {
    pub(super) fn global() -> &'static Self {
        static JOBS: OnceLock<RecentReuseJobs> = OnceLock::new();
        JOBS.get_or_init(Self::default)
    }
    pub(super) fn record(&self, key: Key, id: &str) {
        self.record_at(key, id, Instant::now());
    }
    fn record_at(&self, key: Key, id: &str, now: Instant) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.retain(|_, (_, at)| now.saturating_duration_since(*at) < TTL);
        if entries.len() >= CAPACITY && !entries.contains_key(&key) {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(key, _)| *key)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, (id.to_owned(), now));
    }
    pub(super) fn candidate(&self, key: Key) -> Option<String> {
        self.candidate_at(key, Instant::now())
    }
    fn candidate_at(&self, key: Key, now: Instant) -> Option<String> {
        let mut entries = self.entries.lock().ok()?;
        let (id, at) = entries.get(&key)?;
        if now.saturating_duration_since(*at) >= TTL {
            entries.remove(&key);
            return None;
        }
        Some(id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_matches_reuse_identity_and_fences() {
        use super::super::TimeRangeInput;
        let now = chrono::Utc::now();
        let request = SearchRequest {
            query: "x=1".into(),
            time_range: TimeRangeInput::new(
                now - chrono::Duration::hours(2),
                now - chrono::Duration::hours(1),
            ),
            limit: Some(500),
            offset: None,
            include_sql: None,
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: true,
            table_view: true,
            request_id: None,
            async_mode: false,
            priority: None,
            dataset: None,
        };
        let user = Uuid::from_u128(2);
        let scope = ScopeSet::from_denied(Default::default());
        let authority = DurableSearchJobAuthority {
            tenant_id: Uuid::from_u128(1),
            user_id: user,
            credential: DurableSearchCredentialAuthority::Session {
                access_jti: Uuid::new_v4(),
                credential_time_micros: 1,
            },
            membership_authority_revision: 1,
            entitlement_assignment_revision: 1,
            retention_revision: 1,
            retention_days: 30,
            irreversible_event_time_floor_micros: 0,
            roles: vec![],
            permissions: vec![],
        };
        let original = key(&request, "x = 1", user, &scope, Some(&authority)).unwrap();
        let mut renewed = authority.clone();
        renewed.credential = DurableSearchCredentialAuthority::Session {
            access_jti: Uuid::new_v4(),
            credential_time_micros: 2,
        };
        assert_eq!(
            Some(original),
            key(&request, "x = 1", user, &scope, Some(&renewed))
        );
        renewed.membership_authority_revision += 1;
        assert_ne!(
            Some(original),
            key(&request, "x = 1", user, &scope, Some(&renewed))
        );
        let mut other_tenant = authority.clone();
        other_tenant.tenant_id = Uuid::new_v4();
        assert_ne!(
            Some(original),
            key(&request, "x = 1", user, &scope, Some(&other_tenant))
        );
        let denied = ScopeSet::from_denied(std::collections::BTreeSet::from(["edr".into()]));
        assert_ne!(
            Some(original),
            key(&request, "x = 1", user, &denied, Some(&authority))
        );
        assert_ne!(
            Some(original),
            key(&request, "x = 2", user, &scope, Some(&authority))
        );
        assert_ne!(
            Some(original),
            key(&request, "x = 1", Uuid::new_v4(), &scope, Some(&authority))
        );
        for change in 0..6 {
            let mut changed = request.clone();
            match change {
                0 => changed.time_range.start += chrono::Duration::seconds(1),
                1 => changed.time_range.end += chrono::Duration::seconds(1),
                2 => changed.limit = Some(100),
                3 => changed.offset = Some(500),
                4 => changed.table_view = false,
                _ => changed.dataset = Some("other".into()),
            }
            assert_ne!(
                Some(original),
                key(&changed, "x = 1", user, &scope, Some(&authority))
            );
        }
        let mut equivalent = request.clone();
        equivalent.dataset = Some("logs".into());
        equivalent.offset = Some(0);
        equivalent.use_cache = false;
        assert_eq!(
            Some(original),
            key(&equivalent, "x = 1", user, &scope, Some(&authority))
        );
    }
    #[test]
    fn exact_candidates_expire_and_memory_is_bounded() {
        let jobs = RecentReuseJobs::default();
        let now = Instant::now();
        jobs.record_at([1; 32], "a", now);
        jobs.record_at([2; 32], "b", now);
        assert_eq!(jobs.candidate_at([1; 32], now).as_deref(), Some("a"));
        assert!(jobs.candidate_at([3; 32], now).is_none());
        assert!(jobs.candidate_at([1; 32], now + TTL).is_none());
        for i in 0..CAPACITY + 10 {
            let key: Key = Sha256::digest(i.to_le_bytes()).into();
            jobs.record_at(key, "job", now);
        }
        assert_eq!(jobs.entries.lock().unwrap().len(), CAPACITY);
    }
}

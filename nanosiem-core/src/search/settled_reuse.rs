// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3809: rules for re-serving an identical settled search.
//!
//! A pasted search URL with an absolute range re-ran the whole search. Two
//! reuse paths now share these rules:
//!
//! - the lean cell's exact in-memory `broad_npl` cache keeps a settled answer
//!   longer (`part_query::result_cache`), and
//! - Search re-serves a finished durable job of the same caller through its
//!   existing result pages (`SearchService::settled_durable_job_for_reuse`).
//!
//! Reuse is never decided on time alone. Each path also requires the exact
//! data identity (the parts overlapping the window), the enrichment read
//! authority, the caller's deny set and the caller's current search
//! authority to be unchanged. The time rule only keeps reuse away from data
//! that is still arriving.

use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeSet;

use super::{DurableLakeTask, DurableSearchCredentialAuthority, DurableSearchJobAuthority, SearchJob, SearchJobBackend, SearchJobStatus, SearchRequest};

/// How far behind "now" an event can still land and be expected in a read.
/// This is the platform's existing late-arrival grace: the follow stream
/// re-reads this far behind its newest delivered event for the same reason
/// (NAN-3244). A window that ends inside it is still settling and is never
/// re-served.
pub const LATE_ARRIVAL_GRACE_SECS: i64 = 300;

/// Whether a window ending at `end` is settled at `now`: it ends at least the
/// late-arrival grace in the past. A relative range ("last 1h") always ends at
/// about now, so it is never settled.
pub fn is_settled_end(end: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    end <= now - Duration::seconds(LATE_ARRIVAL_GRACE_SECS)
}

/// [`is_settled_end`] over unix microseconds (the lean cell's window unit).
pub fn is_settled_end_us(end_us: i64, now: DateTime<Utc>) -> bool {
    end_us <= (now - Duration::seconds(LATE_ARRIVAL_GRACE_SECS)).timestamp_micros()
}

/// Whether a query's answer depends only on the events in its window.
///
/// Conservative and textual on purpose: anything that may read state outside
/// the event data (lookups, IOC feeds, prevalence, risk, `| ai`, enrichment
/// views, typed product views, subsearches) or the clock is refused. A false
/// refusal only costs a re-run.
pub fn query_allows_settled_reuse(query: &str) -> bool {
    static STATEFUL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let stateful = STATEFUL.get_or_init(|| {
        regex::Regex::new(
            r"(?i)\b(inputlookup|outputlookup|lookup|ioc\w*|prevalence\w*|risk\w*|ai|enrich\w*|retro|lateral|baseline|tree|asset\w*|identity|now|today|yesterday|relative_time|random|rand|uuid)\b",
        )
        .expect("static regex")
    });
    !query.contains('[') && !stateful.is_match(query)
}

/// Whether the authority a job was admitted under still describes the caller.
/// Membership, entitlements, retention, roles and permissions must match
/// exactly; a session token refresh (new `access_jti`) for the same user is
/// not an authority change, an automation key must be the same key revision.
pub fn authority_allows_reuse(stored: &DurableSearchJobAuthority, current: &DurableSearchJobAuthority) -> bool {
    let credential = match (&stored.credential, &current.credential) {
        (DurableSearchCredentialAuthority::Session { .. }, DurableSearchCredentialAuthority::Session { .. }) => true,
        (stored @ DurableSearchCredentialAuthority::TenantAutomationKey { .. }, current) => stored == current,
        _ => false,
    };
    credential
        && stored.tenant_id == current.tenant_id
        && stored.user_id == current.user_id
        && stored.membership_authority_revision == current.membership_authority_revision
        && stored.entitlement_assignment_revision == current.entitlement_assignment_revision
        && stored.retention_revision == current.retention_revision
        && stored.retention_days == current.retention_days
        && stored.irreversible_event_time_floor_micros == current.irreversible_event_time_floor_micros
        && stored.roles == current.roles
        && stored.permissions == current.permissions
}

/// The caller-side facts a reusable job must match.
pub struct ReuseCaller<'a> {
    pub user_id: uuid::Uuid,
    pub deny: &'a BTreeSet<String>,
    pub authority: Option<&'a DurableSearchJobAuthority>,
}

/// Whether `job` is a finished, non-empty plain durable search of exactly
/// `request` (with `canonical_query`, the query text the durable lane would
/// submit) by this caller, under this caller's deny set and authority.
/// The cell still has to prove the job's data identity is current.
pub fn job_matches_reuse_request(job: &SearchJob, request: &SearchRequest, canonical_query: &str, caller: &ReuseCaller<'_>) -> bool {
    job.status == SearchJobStatus::Completed
        && job.result_ref.as_ref().is_some_and(|reference| reference.rows > 0 && reference.parts > 0)
        && job_is_this_request(job, request, canonical_query, caller)
}

/// NAN-4277: where a request looks for an in-flight durable job to follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachPoint {
    /// A new request, before any work. It follows only a job a runner has
    /// already claimed (`Running`). A job still `Queued` behind another
    /// tenant job has not started, so the request runs interactively first:
    /// a retry after a deadline escalation gets its own attempt instead of
    /// being pinned to the queue (a large hosted tenant, 2026-10-20: a 1 h
    /// `| head 50` stayed queued 9.5 min behind a 30 d scan and every retry
    /// followed it). If that attempt is slow too, its own escalation
    /// attaches at [`AttachPoint::Submission`].
    NewRequest,
    /// The request is about to submit the same durable job (deadline
    /// escalation, bare `*` long-window route): a queued or running twin is
    /// followed instead of queueing a second copy.
    Submission,
}

/// NAN-3883: an in-flight durable job that is computing exactly this
/// caller's request. A reload, a reopened tab or a history entry of a search
/// that escalated attaches to it instead of starting the same scan again.
/// Nothing settles here: the job answers the identical absolute window.
/// NAN-4277: a `Queued` job is followed only at [`AttachPoint::Submission`].
pub fn job_matches_attach_request(
    job: &SearchJob,
    request: &SearchRequest,
    canonical_query: &str,
    caller: &ReuseCaller<'_>,
    point: AttachPoint,
) -> bool {
    let in_flight = match point {
        AttachPoint::NewRequest => job.status == SearchJobStatus::Running,
        AttachPoint::Submission => matches!(job.status, SearchJobStatus::Queued | SearchJobStatus::Running),
    };
    in_flight && job_is_this_request(job, request, canonical_query, caller)
}

/// The same plain durable search, by the same user, under the same scope and
/// authority, over the same window and page.
fn job_is_this_request(job: &SearchJob, request: &SearchRequest, canonical_query: &str, caller: &ReuseCaller<'_>) -> bool {
    let plain_search = matches!(job.task, Some(DurableLakeTask::SearchNplV1 | DurableLakeTask::SearchNplShedV1 { .. }));
    let authority = match (job.durable_authority.as_ref(), caller.authority) {
        (Some(stored), Some(current)) => authority_allows_reuse(stored, current),
        (None, None) => true,
        _ => false,
    };
    let dataset = |value: Option<&str>| value.unwrap_or("logs").to_string();
    job.backend == SearchJobBackend::LakeDurable
        && plain_search
        && job.user_id == Some(caller.user_id)
        // The exact deny set, not a superset: a changed scope always misses.
        && job.scope_deny.as_ref() == Some(caller.deny)
        && authority
        && job.request.query == canonical_query
        && job.request.time_range.start == request.time_range.start
        && job.request.time_range.end == request.time_range.end
        && job.request.limit == request.limit
        && job.request.offset.unwrap_or(0) == request.offset.unwrap_or(0)
        && job.request.table_view == request.table_view
        && dataset(job.request.dataset.as_deref()) == dataset(request.dataset.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ScopeSet;
    use crate::search::{SearchJobResultRef, TimeRangeInput};
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 14, 12, 0, 0).unwrap()
    }

    #[test]
    fn only_windows_older_than_the_late_arrival_grace_are_settled() {
        let now = now();
        assert!(is_settled_end(now - Duration::hours(1), now));
        assert!(is_settled_end(now - Duration::seconds(LATE_ARRIVAL_GRACE_SECS), now));
        // A relative "last 1h" ends at about now; a range overlapping the
        // late window is still settling.
        assert!(!is_settled_end(now, now));
        assert!(!is_settled_end(now - Duration::seconds(LATE_ARRIVAL_GRACE_SECS - 1), now));
        assert!(is_settled_end_us((now - Duration::hours(1)).timestamp_micros(), now));
        assert!(!is_settled_end_us(now.timestamp_micros(), now));
    }

    #[test]
    fn stateful_queries_are_never_reused() {
        assert!(query_allows_settled_reuse("class_uid=4001 | stats count by src_endpoint.ip"));
        assert!(query_allows_settled_reuse("error | head 100"));
        for query in [
            "* | lookup assets host", "| inputlookup users", "* | ai summarize", "* | where prevalence_min < 3",
            "* | risk", "* | iocfeed", "* | tree", "* | lateral", "* | baseline", "* | eval t=now()",
            "* [ search foo ]", "* | where relative_time(time, \"-1d\") > 0",
        ] {
            assert!(!query_allows_settled_reuse(query), "{query}");
        }
    }

    fn authority(jti: u128, membership: i64) -> DurableSearchJobAuthority {
        DurableSearchJobAuthority {
            tenant_id: uuid::Uuid::from_u128(1),
            user_id: uuid::Uuid::from_u128(2),
            credential: DurableSearchCredentialAuthority::Session { access_jti: uuid::Uuid::from_u128(jti), credential_time_micros: 1 },
            membership_authority_revision: membership,
            entitlement_assignment_revision: 1,
            retention_revision: 1,
            retention_days: 30,
            irreversible_event_time_floor_micros: 0,
            roles: vec!["analyst".into()],
            permissions: vec!["search:execute".into()],
        }
    }

    #[test]
    fn a_token_refresh_reuses_but_an_authority_change_does_not() {
        assert!(authority_allows_reuse(&authority(10, 1), &authority(11, 1)));
        assert!(!authority_allows_reuse(&authority(10, 1), &authority(10, 2)), "membership revoked/changed");
        let mut narrowed = authority(10, 1);
        narrowed.permissions.clear();
        assert!(!authority_allows_reuse(&authority(10, 1), &narrowed));
        let mut other_user = authority(10, 1);
        other_user.user_id = uuid::Uuid::from_u128(3);
        assert!(!authority_allows_reuse(&authority(10, 1), &other_user));
    }

    fn request() -> SearchRequest {
        SearchRequest {
            query: "class_uid = 4001".into(),
            time_range: TimeRangeInput::new(now() - Duration::hours(2), now() - Duration::hours(1)),
            limit: Some(500), offset: Some(0), include_sql: None, skip_histogram: true, skip_field_stats: true,
            use_cache: true, table_view: true, request_id: None, async_mode: false, priority: None, dataset: None,
        }
    }

    fn finished_job(deny: &BTreeSet<String>) -> SearchJob {
        let scope = ScopeSet::from_denied(deny.clone());
        let mut job = SearchJob::new("job-1".into(), request(), &scope);
        job.status = SearchJobStatus::Completed;
        job.backend = SearchJobBackend::LakeDurable;
        job.task = Some(DurableLakeTask::SearchNplV1);
        job.user_id = Some(uuid::Uuid::from_u128(2));
        job.durable_authority = Some(authority(10, 1));
        job.result_ref = Some(SearchJobResultRef {
            tenant_id: Some(uuid::Uuid::from_u128(1)), manifest_uri: "s3://b/m.json".into(), manifest_sha256: "a".repeat(64),
            rows: 42, parts: 1, has_more: false, page_rows: 10_000, retention_proof: None,
        });
        job
    }

    #[test]
    fn only_the_same_callers_finished_identical_job_matches() {
        let deny = BTreeSet::from(["edr".to_string()]);
        let current = authority(11, 1);
        let caller = ReuseCaller { user_id: uuid::Uuid::from_u128(2), deny: &deny, authority: Some(&current) };
        let request = request();
        let job = finished_job(&deny);
        assert!(job_matches_reuse_request(&job, &request, "class_uid = 4001", &caller));

        // A deny-set change misses, even toward a narrower or wider scope.
        let wider = BTreeSet::new();
        assert!(!job_matches_reuse_request(&job, &request, "class_uid = 4001",
            &ReuseCaller { user_id: caller.user_id, deny: &wider, authority: caller.authority }));
        // An authority revocation (membership revision) misses.
        let revoked = authority(11, 2);
        assert!(!job_matches_reuse_request(&job, &request, "class_uid = 4001",
            &ReuseCaller { user_id: caller.user_id, deny: &deny, authority: Some(&revoked) }));
        // Another user, another query, another window or page misses.
        assert!(!job_matches_reuse_request(&job, &request, "class_uid = 4001",
            &ReuseCaller { user_id: uuid::Uuid::from_u128(9), deny: &deny, authority: Some(&current) }));
        assert!(!job_matches_reuse_request(&job, &request, "class_uid = 4002", &caller));
        let mut shifted = request.clone();
        shifted.time_range.end = shifted.time_range.end + Duration::seconds(1);
        assert!(!job_matches_reuse_request(&job, &shifted, "class_uid = 4001", &caller));
        let mut paged = request.clone();
        paged.offset = Some(500);
        assert!(!job_matches_reuse_request(&job, &paged, "class_uid = 4001", &caller));

        // Empty, unfinished, post-processed or typed jobs never match.
        let mut empty = finished_job(&deny);
        empty.result_ref.as_mut().unwrap().rows = 0;
        assert!(!job_matches_reuse_request(&empty, &request, "class_uid = 4001", &caller));
        let mut running = finished_job(&deny);
        running.status = SearchJobStatus::Running;
        assert!(!job_matches_reuse_request(&running, &request, "class_uid = 4001", &caller));
        let mut post = finished_job(&deny);
        post.task = Some(DurableLakeTask::SearchNplPostV1 {
            post_query: "x".into(), requested_limit: 500, requested_offset: 0, required_scan_bytes: 0,
        });
        assert!(!job_matches_reuse_request(&post, &request, "class_uid = 4001", &caller));
    }

    #[test]
    fn a_running_identical_job_is_attached_but_not_a_finished_or_different_one() {
        let deny = BTreeSet::from(["edr".to_string()]);
        let current = authority(11, 1);
        let caller = ReuseCaller { user_id: uuid::Uuid::from_u128(2), deny: &deny, authority: Some(&current) };
        let request = request();
        let mut running = finished_job(&deny);
        running.status = SearchJobStatus::Running;
        running.result_ref = None;
        assert!(job_matches_attach_request(&running, &request, "class_uid = 4001", &caller, AttachPoint::Submission));
        let mut queued = running.clone();
        queued.status = SearchJobStatus::Queued;
        assert!(job_matches_attach_request(&queued, &request, "class_uid = 4001", &caller, AttachPoint::Submission));
        // NAN-4277: a new request follows only a claimed job; a queued one
        // has not started, so the request gets its own interactive attempt.
        assert!(job_matches_attach_request(&running, &request, "class_uid = 4001", &caller, AttachPoint::NewRequest));
        assert!(!job_matches_attach_request(&queued, &request, "class_uid = 4001", &caller, AttachPoint::NewRequest));
        // A relative window that ends now attaches too: nothing is settled.
        let mut live = request.clone();
        live.time_range.end = Utc::now();
        let mut live_job = running.clone();
        live_job.request.time_range.end = live.time_range.end;
        assert!(job_matches_attach_request(&live_job, &live, "class_uid = 4001", &caller, AttachPoint::Submission));

        let done = finished_job(&deny);
        assert!(!job_matches_attach_request(&done, &request, "class_uid = 4001", &caller, AttachPoint::Submission));
        let mut failed = running.clone();
        failed.status = SearchJobStatus::Failed;
        assert!(!job_matches_attach_request(&failed, &request, "class_uid = 4001", &caller, AttachPoint::Submission));
        let wider = BTreeSet::new();
        assert!(!job_matches_attach_request(&running, &request, "class_uid = 4001",
            &ReuseCaller { user_id: caller.user_id, deny: &wider, authority: caller.authority }, AttachPoint::Submission));
        assert!(!job_matches_attach_request(&running, &request, "class_uid = 4001",
            &ReuseCaller { user_id: uuid::Uuid::from_u128(9), deny: &deny, authority: Some(&current) }, AttachPoint::Submission));
        assert!(!job_matches_attach_request(&running, &request, "class_uid = 4002", &caller, AttachPoint::Submission));
        let mut shifted = request.clone();
        shifted.time_range.start = shifted.time_range.start - Duration::seconds(1);
        assert!(!job_matches_attach_request(&running, &shifted, "class_uid = 4001", &caller, AttachPoint::Submission));
    }
}

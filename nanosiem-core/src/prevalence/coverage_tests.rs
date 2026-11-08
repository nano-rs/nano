// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `prevalence::coverage`.

use super::*;
use chrono::TimeZone;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap()
}

/// Every kind covered since `covered_days` (None = empty tables).
fn probe(covered_days: Option<i64>, ingest_days: Option<i64>, head_min: i64, refreshed_min: Option<i64>) -> CoverageProbe {
    let since = covered_days.map(|d| now() - Duration::days(d));
    CoverageProbe {
        covered_since: [since, since, since],
        ingest_since: ingest_days.map(|d| now() - Duration::days(d)),
        ingest_head: Some(now() - Duration::minutes(head_min)),
        refreshed_at: refreshed_min.map(|m| now() - Duration::minutes(m)),
    }
}

fn hash(p: &CoverageProbe, source: CoverageSource, window_start: DateTime<Utc>) -> PrevalenceProductState {
    classify(p, ArtifactKind::Hash, source, window_start, now())
}

#[test]
fn fully_covered_and_fresh_is_ready() {
    let s = hash(&probe(Some(60), Some(60), 1, Some(5)), CoverageSource::Refreshed, now() - Duration::days(7));
    assert_eq!(s.state, PrevalenceCoverageState::Ready);
    assert!(!s.warming && !s.stale && !s.partial);
    assert!(s.miss_is_definitive());
    assert_eq!(s.retry_after_s, None);
    assert_eq!(s.age_s, Some(300));
}

#[test]
fn no_prevalence_rows_is_warming() {
    let s = hash(&probe(None, None, 1, None), CoverageSource::Live, now() - Duration::hours(24));
    assert_eq!(s.state, PrevalenceCoverageState::Warming);
    assert!(!s.miss_is_definitive());
    assert_eq!(s.retry_after_s, Some(600));
}

#[test]
fn young_install_shorter_than_the_window_is_warming() {
    let p = probe(Some(2), Some(2), 1, Some(3));
    assert_eq!(hash(&p, CoverageSource::Refreshed, now() - Duration::days(7)).state, PrevalenceCoverageState::Warming);
    assert_eq!(hash(&p, CoverageSource::Refreshed, now() - Duration::hours(24)).state, PrevalenceCoverageState::Ready);
}

#[test]
fn coverage_within_one_bucket_of_the_window_start_counts_as_covered() {
    let window_start = now() - Duration::hours(24);
    let since = Some(window_start + Duration::minutes(40));
    let p = CoverageProbe { covered_since: [since; 3], ingest_since: since, ingest_head: Some(now()), refreshed_at: None };
    assert_eq!(hash(&p, CoverageSource::Live, window_start).state, PrevalenceCoverageState::Ready);
}

#[test]
fn older_events_than_prevalence_is_partial_not_warming() {
    let s = hash(&probe(Some(3), Some(200), 1, Some(2)), CoverageSource::Refreshed, now() - Duration::days(30));
    assert_eq!(s.state, PrevalenceCoverageState::Partial);
    assert!(s.partial && !s.warming && !s.miss_is_definitive());
}

#[test]
fn snapshot_lagging_ingest_by_two_intervals_is_stale_and_idle_is_not() {
    let window_start = now() - Duration::hours(24);
    let s = hash(&probe(Some(60), Some(60), 1, Some(45)), CoverageSource::Refreshed, window_start);
    assert_eq!(s.state, PrevalenceCoverageState::Stale);
    assert!(s.stale && s.miss_is_definitive());
    assert!(!hash(&probe(Some(60), Some(60), 0, Some(20)), CoverageSource::Refreshed, window_start).stale);
    let idle = hash(&probe(Some(60), Some(60), 120, Some(115)), CoverageSource::Refreshed, window_start);
    assert_eq!(idle.state, PrevalenceCoverageState::Ready);
    let live = hash(&probe(Some(60), Some(60), 1, Some(300)), CoverageSource::Live, window_start);
    assert_eq!((live.state, live.refreshed_at), (PrevalenceCoverageState::Ready, None));
}

#[test]
fn warming_outranks_stale_and_future_heads_are_capped() {
    let mut p = probe(Some(1), Some(1), 1, Some(300));
    p.ingest_head = Some(now() + Duration::days(365));
    let s = hash(&p, CoverageSource::Refreshed, now() - Duration::days(7));
    assert_eq!(s.state, PrevalenceCoverageState::Warming);
    assert!(s.warming && s.stale);
    assert_eq!(s.ingest_head, Some(now()));
}

/// P1-1: a covered hash table never vouches for an empty domain table.
#[test]
fn each_kind_has_its_own_coverage_and_combining_is_conservative() {
    let mut p = probe(Some(60), Some(60), 1, None);
    p.set_covered_since(ArtifactKind::Domain, None);
    p.set_covered_since(ArtifactKind::Ip, Some(now() - Duration::days(2)));
    let window_start = now() - Duration::days(30);
    let report = CoverageReport::new(
        classify(&p, ArtifactKind::Hash, CoverageSource::Live, window_start, now()),
        classify(&p, ArtifactKind::Domain, CoverageSource::Live, window_start, now()),
        classify(&p, ArtifactKind::Ip, CoverageSource::Live, window_start, now()),
    );
    assert_eq!(report.kind(ArtifactKind::Hash).state, PrevalenceCoverageState::Ready);
    assert_eq!(report.kind(ArtifactKind::Domain).state, PrevalenceCoverageState::Warming);

    let mut domain_miss = PrevalenceData::empty("unseen.example.com".into(), ArtifactType::Domain);
    let mut hash_miss = PrevalenceData::empty("ab".repeat(32), ArtifactType::HashSha256);
    report.apply(&mut domain_miss);
    report.apply(&mut hash_miss);
    assert_eq!(domain_miss.host_count, None, "uncovered kind: unknown");
    assert!(!domain_miss.is_rare);
    assert_eq!(hash_miss.host_count, Some(0), "covered kind: a definitive zero");

    let combined = report.combined(&[ArtifactKind::Hash, ArtifactKind::Domain]);
    assert_eq!(combined.state, PrevalenceCoverageState::Warming);
    assert_eq!(combined.covered_since, None, "an empty kind leaves the start unknown");
    let hash_ip = report.combined(&[ArtifactKind::Hash, ArtifactKind::Ip]);
    assert_eq!(hash_ip.covered_since, p.covered_since(ArtifactKind::Ip), "latest start wins");
    assert_eq!(report.combined(&[ArtifactKind::Hash]).state, PrevalenceCoverageState::Ready);
}

/// P1-2: a restricted viewer is only covered where its own attributed rows
/// reach the window start, and never sees cross-source timestamps.
#[test]
fn restricted_viewers_use_their_own_attributed_coverage() {
    let global = hash(&probe(Some(60), Some(60), 1, Some(5)), CoverageSource::Refreshed, now() - Duration::days(30));
    assert_eq!(global.state, PrevalenceCoverageState::Ready);

    let uncovered = restrict(global.clone(), Some(false));
    assert_eq!(uncovered.state, PrevalenceCoverageState::Partial);
    assert!(!uncovered.miss_is_definitive());
    assert_eq!((uncovered.covered_since, uncovered.ingest_head), (None, None));
    assert_eq!(uncovered.refreshed_at, global.refreshed_at, "pipeline refresh time is not source data");

    assert_eq!(restrict(global.clone(), None).state, PrevalenceCoverageState::Partial, "unknown is not covered");
    let covered = restrict(global, Some(true));
    assert_eq!(covered.state, PrevalenceCoverageState::Ready);
    assert_eq!((covered.covered_since, covered.ingest_head), (None, None));

    let warming = hash(&probe(None, None, 1, None), CoverageSource::Live, now() - Duration::days(1));
    assert_eq!(restrict(warming, Some(true)).state, PrevalenceCoverageState::Warming);
}

#[test]
fn serializes_snake_case_and_skips_empty_hints() {
    let s = hash(&probe(Some(60), Some(60), 1, None), CoverageSource::Live, now() - Duration::hours(24));
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(json["state"], "ready");
    assert!(json.get("retry_after_s").is_none());
    assert!(json["refreshed_at"].is_null());
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — service-level tests for what the server is willing to believe.
//!
//! These exercise [`HuntService::prepare_candidate`], which is the gate every
//! agent-authored candidate passes through before any SQL sees it. They run
//! against a scripted [`FakeResolver`] and a LAZY Postgres pool that is never
//! connected — the decisions under test are about combination, not storage, and
//! a test that needs a container to prove an entity was corroborated is a test
//! that does not run in CI.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeZone, Utc};
use sqlx::postgres::PgPoolOptions;

use super::*;
use crate::hunts::evidence::ResolvedEvent;

/// A resolver whose answers are written by the test rather than by ClickHouse.
struct FakeResolver {
    /// canonical event id → (source_type, entity pairs it yields)
    events: BTreeMap<String, (String, Vec<(String, String)>)>,
    prevalence: Option<f64>,
    prior_history: bool,
}

impl FakeResolver {
    fn new() -> Self {
        Self {
            events: BTreeMap::new(),
            prevalence: None,
            prior_history: true,
        }
    }

    fn with_event(mut self, id: &str, source_type: &str, entities: &[(&str, &str)]) -> Self {
        self.events.insert(
            id.to_string(),
            (
                source_type.to_string(),
                entities
                    .iter()
                    .map(|(t, v)| (t.to_string(), v.to_string()))
                    .collect(),
            ),
        );
        self
    }
}

#[async_trait::async_trait]
impl EvidenceResolver for FakeResolver {
    async fn resolve(
        &self,
        event_ids: &[String],
        _scope: &ScopeSet,
    ) -> Result<ResolvedEvidence, HuntError> {
        let mut events = Vec::new();
        let mut observed: BTreeSet<(String, String)> = BTreeSet::new();
        let mut unresolved = Vec::new();
        for id in event_ids {
            match self.events.get(id) {
                Some((source_type, entities)) => {
                    observed.extend(entities.iter().cloned());
                    events.push(ResolvedEvent {
                        canonical_event_id: id.clone(),
                        timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
                        source_type: source_type.clone(),
                        summary: String::new(),
                        row: serde_json::json!({}),
                        entities: entities.iter().cloned().collect(),
                    });
                }
                None => unresolved.push(id.clone()),
            }
        }
        Ok(ResolvedEvidence {
            events,
            observed_entities: observed,
            unresolved,
        })
    }

    async fn had_prior_history(
        &self,
        _entity_type: &str,
        _entity_value: &str,
        _window_start: DateTime<Utc>,
        _scope: &ScopeSet,
    ) -> Result<bool, HuntError> {
        Ok(self.prior_history)
    }

    async fn asset_prevalence(
        &self,
        _entity_type: &str,
        _entity_value: &str,
        _window_start: DateTime<Utc>,
        _window_end: DateTime<Utc>,
        _scope: &ScopeSet,
    ) -> Result<Option<f64>, HuntError> {
        Ok(self.prevalence)
    }

    async fn silent_source_types(
        &self,
        candidates: &[String],
        _since: DateTime<Utc>,
    ) -> Result<Vec<String>, HuntError> {
        Ok(candidates.to_vec())
    }
}

/// A pool that is never dialled. `connect_lazy` only parses the URL, so this
/// costs nothing and never touches a network.
fn service(resolver: FakeResolver) -> HuntService {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://hunts:hunts@127.0.0.1:1/hunts")
        .expect("lazy pool");
    HuntService::new(HuntRepository::new(pool), Arc::new(resolver))
}

fn candidate(entity_type: &str, entity_value: &str, ids: &[&str], signals: &[&str]) -> LeadCandidate {
    LeadCandidate {
        entity_type: entity_type.to_string(),
        entity_value: entity_value.to_string(),
        mitre_technique: Some("T1021".to_string()),
        signals: signals.iter().map(|s| s.to_string()).collect(),
        evidence_event_ids: ids.iter().map(|s| s.to_string()).collect(),
        narrative: Some("something happened".to_string()),
    }
}

fn known(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_lowercase()).collect()
}

fn window() -> (DateTime<Utc>, DateTime<Utc>) {
    (
        Utc.timestamp_opt(1_699_900_000, 0).unwrap(),
        Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
    )
}

async fn prepare(
    svc: &HuntService,
    candidate: &LeadCandidate,
    signals: &BTreeSet<String>,
) -> Option<PreparedLead> {
    let (start, end) = window();
    svc.prepare_candidate(candidate, signals, start, end, &ScopeSet::unrestricted())
        .await
        .expect("resolver does not fail")
}

#[tokio::test]
async fn an_entity_that_appears_in_no_evidence_is_refused() {
    // THE corroboration rule. Without it the agent picks its own fingerprint
    // input, and a suppressed finding walks past its suppression by being
    // reported against a slightly different entity.
    let svc = service(FakeResolver::new().with_event("e1", "sysmon", &[("host", "srv-web06")]));
    let signals = known(&["t1021"]);

    let good = prepare(&svc, &candidate("host", "srv-web06", &["e1"], &["T1021"]), &signals).await;
    assert!(good.is_some(), "a corroborated entity was refused");

    let fabricated = prepare(
        &svc,
        &candidate("host", "attacker-chosen", &["e1"], &["T1021"]),
        &signals,
    )
    .await;
    assert!(
        fabricated.is_none(),
        "an entity appearing in no resolved evidence was accepted"
    );
}

#[tokio::test]
async fn an_unknown_signal_is_dropped_not_fatal() {
    // Dropping is the whole point: rejecting the candidate would let one junk
    // signal delete a finding, while HASHING it would let one junk signal mint
    // a fresh fingerprint and escape a suppression.
    let svc = service(FakeResolver::new().with_event("e1", "sysmon", &[("host", "srv-web06")]));
    let prepared = prepare(
        &svc,
        &candidate("host", "srv-web06", &["e1"], &["T1021", "nonce-8f3a"]),
        &known(&["t1021"]),
    )
    .await
    .expect("candidate survives an unknown signal");

    let kept: Vec<&str> = prepared.signals.iter().map(|s| s.as_str()).collect();
    assert_eq!(kept, vec!["t1021"]);
}

#[tokio::test]
async fn a_candidate_with_nothing_readable_behind_it_is_refused() {
    // A lead with a narrative and no evidence is an assertion. The bench cannot
    // check it and the score has nothing to measure.
    let svc = service(FakeResolver::new());
    let prepared = prepare(
        &svc,
        &candidate("host", "srv-web06", &["missing"], &["T1021"]),
        &known(&["t1021"]),
    )
    .await;
    assert!(prepared.is_none());
}

#[tokio::test]
async fn an_unknown_entity_type_is_refused_before_it_reaches_the_check_constraint() {
    // `hunt_leads_entity_type_check` would abort the whole commit transaction,
    // taking every good lead in the same report with it.
    let svc = service(FakeResolver::new().with_event("e1", "sysmon", &[("unicorn", "sparkle")]));
    let prepared = prepare(
        &svc,
        &candidate("unicorn", "sparkle", &["e1"], &[]),
        &known(&[]),
    )
    .await;
    assert!(prepared.is_none());
}

#[tokio::test]
async fn a_partially_resolved_candidate_is_stamped_incomplete() {
    // One unresolvable id makes the manifest incomplete, which fails closed for
    // every source-scoped reader. The candidate still commits — the finding is
    // real — it is only its ATTRIBUTION that is in doubt.
    let svc = service(
        FakeResolver::new()
            .with_event("e1", "sysmon", &[("host", "srv-web06")])
            .with_event("e2", "windows_security", &[("host", "srv-web06")]),
    );
    let signals = known(&["t1021"]);

    let whole = prepare(
        &svc,
        &candidate("host", "srv-web06", &["e1", "e2"], &["T1021"]),
        &signals,
    )
    .await
    .expect("prepared");
    assert!(whole.provenance.is_complete());
    assert_eq!(whole.provenance.source_types().len(), 2);

    let partial = prepare(
        &svc,
        &candidate("host", "srv-web06", &["e1", "gone"], &["T1021"]),
        &signals,
    )
    .await
    .expect("prepared");
    assert!(
        !partial.provenance.is_complete(),
        "an unaccounted evidence id still produced a complete manifest"
    );
}

#[tokio::test]
async fn measurements_come_from_the_resolver_not_the_report() {
    // The candidate says nothing about prevalence or novelty and has no field
    // to. Both values on the prepared lead must be the ones the SERVER
    // measured.
    let mut resolver = FakeResolver::new().with_event("e1", "sysmon", &[("host", "srv-web06")]);
    resolver.prevalence = Some(0.004);
    resolver.prior_history = false;
    let svc = service(resolver);

    let prepared = prepare(
        &svc,
        &candidate("host", "srv-web06", &["e1"], &["T1021"]),
        &known(&["t1021"]),
    )
    .await
    .expect("prepared");

    assert_eq!(prepared.prevalence, Some(0.004));
    assert!(
        prepared.first_seen_in_window,
        "no prior history must read as first-seen"
    );
}

#[tokio::test]
async fn knowledge_is_normalized_and_provenance_is_server_derived() {
    let svc = service(FakeResolver::new().with_event(
        "evt-1",
        "windows_security",
        &[("user", "svc_backup")],
    ));
    let candidate = KnowledgeCandidate {
        category: " Service Account ".to_string(),
        subject: " SVC_Backup ".to_string(),
        fact: " runs   nightly\n at 03:00 ".to_string(),
        confidence: Some(0.8),
        evidence_event_ids: vec!["evt-1".to_string(), "missing".to_string()],
        ttl_days: Some(10_000),
    };

    let prepared = svc
        .prepare_knowledge(&candidate, &ScopeSet::unrestricted())
        .await
        .expect("resolver succeeds")
        .expect("valid fact is prepared");

    assert_eq!(prepared.category, "service_account");
    assert_eq!(prepared.subject, "svc_backup");
    assert_eq!(prepared.fact, "runs nightly at 03:00");
    assert_eq!(prepared.evidence_event_ids, vec!["evt-1"]);
    assert_eq!(prepared.ttl_days, crate::hunts::MAX_TTL_DAYS);
    assert_eq!(prepared.provenance.source_types(), &["windows_security".to_string()]);
    assert!(
        !prepared.provenance.is_complete(),
        "one unresolved event must make the fact fail closed for scoped readers"
    );
}

#[tokio::test]
async fn malformed_knowledge_rejects_only_that_fact() {
    let svc = service(FakeResolver::new());
    let candidate = KnowledgeCandidate {
        category: "not/a/category".to_string(),
        subject: "svc_backup".to_string(),
        fact: "nightly job".to_string(),
        confidence: None,
        evidence_event_ids: Vec::new(),
        ttl_days: None,
    };

    let prepared = svc
        .prepare_knowledge(&candidate, &ScopeSet::unrestricted())
        .await
        .expect("invalid claims are a per-fact refusal, not a report error");
    assert!(prepared.is_none());
}

#[test]
fn lookback_windows_are_parsed_and_clamped() {
    assert_eq!(parse_lookback("24h"), Duration::hours(24));
    assert_eq!(parse_lookback("90m"), Duration::minutes(90));
    assert_eq!(parse_lookback("7d"), Duration::days(7));
    assert_eq!(parse_lookback("2w"), Duration::weeks(2));

    // A malformed value must not make a hunt permanently unrunnable.
    assert_eq!(parse_lookback("banana"), Duration::hours(24));
    assert_eq!(parse_lookback(""), Duration::hours(24));
    assert_eq!(parse_lookback("0d"), Duration::hours(24));

    // A decade-wide window is not a hunt.
    assert_eq!(parse_lookback("3650d"), Duration::days(90));
}

/// The Profile matrix and the rail badge must be counted from the SAME stored
/// value, or a rail that says "22 gaps" sits beside a page that draws 25 and
/// neither number can be trusted.
mod huntable_surface_counting {
    use super::super::count_surface;
    use serde_json::json;

    /// Canonical shape — tactic columns holding their techniques, which is what
    /// the Profile screen renders.
    #[test]
    fn counts_the_nested_tactic_shape() {
        let surface = json!({
            "tactics": [
                { "id": "lateral-movement", "name": "Lateral Movement", "techniques": [
                    { "id": "T1021", "name": "Remote Services",  "state": "gap" },
                    { "id": "T1550", "name": "Alternate Material", "state": "covered" }
                ]},
                { "id": "defense-evasion", "name": "Defense Evasion", "techniques": [
                    { "id": "T1218", "name": "System Binary Proxy", "state": "blind" },
                    { "id": "T1070", "name": "Indicator Removal",   "state": "gap" }
                ]}
            ]
        });
        assert_eq!(count_surface(&surface), (2, 1));
    }

    /// The flat map an external producer or a backfill would naturally emit.
    /// Counting zero for it would show an empty rail beside a populated page.
    #[test]
    fn still_counts_the_flat_technique_map() {
        let surface = json!({ "T1021": "gap", "T1218": "blind", "T1550": "covered" });
        assert_eq!(count_surface(&surface), (1, 1));
    }

    /// A shape nobody recognises counts as zero rather than being guessed at —
    /// but note this is indistinguishable from a genuinely empty surface, which
    /// is why the Profile page renders its own legend counts from the matrix it
    /// actually drew rather than trusting these totals alone.
    #[test]
    fn an_unrecognised_shape_counts_zero_rather_than_guessing() {
        assert_eq!(count_surface(&json!([1, 2, 3])), (0, 0));
        assert_eq!(count_surface(&json!("covered")), (0, 0));
        assert_eq!(count_surface(&json!(null)), (0, 0));
    }

    /// Casing and padding come from whatever produced the profile; a "Gap" that
    /// counted as nothing would silently understate the backlog.
    #[test]
    fn state_matching_tolerates_casing_and_padding() {
        let surface = json!({
            "tactics": [{ "techniques": [
                { "id": "T1021", "state": " Gap " },
                { "id": "T1218", "state": "BLIND" }
            ]}]
        });
        assert_eq!(count_surface(&surface), (1, 1));
    }
}

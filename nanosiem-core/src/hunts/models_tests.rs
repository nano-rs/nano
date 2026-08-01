// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hunt model tests.
//!
//! This file existed as a one-byte placeholder that no `#[path]` referenced, so
//! nothing in it would have run. It is wired into `models.rs` now.
//!
//! Currently the Antigravity sweep waiver (NAN-2264), whose "is it in force"
//! question is answered from two nullable timestamps rather than a stored flag
//! — the one piece of that record with a decision in it.

use chrono::{Duration, Utc};

use super::agy_waiver_in_force;

#[test]
fn a_runner_that_was_never_waived_is_not_waived() {
    // The default every existing runner gets when the columns are added, and
    // the only safe direction: a machine nobody has decided about must not
    // start running agy sweeps because a migration ran.
    assert!(!agy_waiver_in_force(None, None));
    // A revocation with no grant is nonsense, but it must still read as "not
    // waived" rather than defaulting open.
    assert!(!agy_waiver_in_force(None, Some(Utc::now())));
}

#[test]
fn a_grant_with_no_revocation_is_in_force() {
    assert!(agy_waiver_in_force(Some(Utc::now()), None));
}

#[test]
fn the_later_of_the_two_timestamps_wins() {
    let now = Utc::now();
    let earlier = now - Duration::hours(2);

    // Revoked after granting: withdrawn. This is the direction that must never
    // fail open — an analyst who withdrew the waiver has to be able to rely on
    // it, and the revocation deliberately leaves `granted_at` in place so the
    // row still shows the decision was once taken.
    assert!(!agy_waiver_in_force(Some(earlier), Some(now)));

    // Granted again after a withdrawal: re-armed. Re-granting must not require
    // clearing the revocation, because clearing it would erase that the waiver
    // was once withdrawn — which is exactly what an incident review looks for.
    assert!(agy_waiver_in_force(Some(now), Some(earlier)));
}

#[test]
fn a_grant_and_a_revocation_at_the_same_instant_read_as_revoked() {
    // A tie cannot happen through the API (each call stamps its own NOW()), but
    // a restore, a clock step or a hand-written row could produce one. Strictly
    // greater-than means the tie resolves CLOSED, which is the direction that
    // does not hand an unattended agent authority nobody can account for.
    let now = Utc::now();
    assert!(!agy_waiver_in_force(Some(now), Some(now)));
}

// =============================================================================
// The lead-state filter contract (NAN-2267)
// =============================================================================

mod lead_states {
    use crate::hunts::models::{parse_lead_states, LEAD_STATES};

    #[test]
    fn a_multi_state_filter_parses_into_every_state_it_names() {
        // The bench's Unreviewed segment sends exactly this. The old contract
        // bound the whole joined string as one equality and matched nothing.
        assert_eq!(
            parse_lead_states("unreviewed,in_review").unwrap(),
            vec!["unreviewed".to_string(), "in_review".to_string()]
        );
    }

    #[test]
    fn a_single_state_still_parses() {
        assert_eq!(
            parse_lead_states("promoted").unwrap(),
            vec!["promoted".to_string()]
        );
    }

    #[test]
    fn an_unknown_state_is_rejected_not_dropped() {
        // Dropping it would silently widen a triage filter; passing it through
        // would bind a value that matches nothing. Both read as "the filter
        // did nothing", so the contract is a 400 that names the bad token.
        let err = parse_lead_states("unreviewed,archived").unwrap_err();
        assert!(err.contains("archived"), "{err}");
        // Every valid state is offered back, so the caller can self-correct.
        for state in LEAD_STATES {
            assert!(err.contains(state), "error does not offer `{state}`: {err}");
        }
    }

    #[test]
    fn whitespace_and_duplicates_are_tolerated_shape_noise() {
        // ` unreviewed , unreviewed,` is a sloppy caller, not an invalid one.
        assert_eq!(
            parse_lead_states(" unreviewed , unreviewed,").unwrap(),
            vec!["unreviewed".to_string()]
        );
    }

    #[test]
    fn every_database_state_is_representable_in_the_filter() {
        // LEAD_STATES mirrors `hunt_leads_state_check`. If the CHECK grows a
        // state this list does not know, that state becomes unfilterable and
        // its leads unreachable from any segment.
        assert_eq!(
            *LEAD_STATES,
            ["unreviewed", "in_review", "promoted", "dismissed"]
        );
    }
}

// =============================================================================
// The lead-detail wire contract (NAN-2267)
// =============================================================================

mod lead_detail_wire {
    use chrono::Utc;
    use uuid::Uuid;

    use crate::hunts::models::{
        HuntLead, HuntLeadDetail, HuntLeadEvidence, HuntLeadProvenance, LEAD_SCORED_BY,
    };
    use crate::hunts::scoring::Contribution;

    fn detail() -> HuntLeadDetail {
        let now = Utc::now();
        HuntLeadDetail {
            lead: HuntLead {
                id: Uuid::nil(),
                sweep_id: Uuid::nil(),
                playbook_id: Uuid::nil(),
                playbook_version: 3,
                hunt_title: Some("Service account interactive logon".into()),
                entity_type: "user".into(),
                entity_value: "svc-deploy".into(),
                mitre_technique: None,
                window_start: now,
                window_end: now,
                narrative: None,
                score: 0.42,
                score_contributions: serde_json::json!([]),
                fingerprint: "fp".into(),
                state: "unreviewed".into(),
                reviewed_by: None,
                reviewed_at: None,
                promoted_case_id: None,
                source_types: vec!["apache".into()],
                source_types_complete: true,
                created_at: now,
                updated_at: now,
            },
            evidence: vec![HuntLeadEvidence {
                id: Uuid::nil(),
                lead_id: Uuid::nil(),
                event_timestamp: now,
                source_type: "apache".into(),
                event_ref: serde_json::json!({}),
                canonical_event_id: "evt-1".into(),
                summary: None,
                position: 0,
                created_at: now,
            }],
            contributions: vec![Contribution {
                factor: "base".into(),
                value: 0.15,
                detail: "hunt matched".into(),
            }],
            provenance: HuntLeadProvenance {
                sweep_id: Uuid::nil(),
                swept_at: Some(now),
                query_sha: None,
                playbook_version: 3,
                scored_by: LEAD_SCORED_BY.to_string(),
            },
        }
    }

    /// The desktop's `WireLeadDetail` reads `detail.lead.score`,
    /// `detail.contributions.map(…)` and `detail.provenance.sweep_id`
    /// UNGUARDED, and TypeScript does not validate at runtime — a missing key
    /// arrives as `undefined`, the `.map` throws out of render, and the whole
    /// window unmounts. That is the crash this test exists to make impossible
    /// to reintroduce: the serialized shape is pinned key-for-key to what
    /// `nano-desktop/src/lib/hunting.ts` declares.
    #[test]
    fn the_detail_serialises_exactly_the_four_keys_the_desktop_declares() {
        let json = serde_json::to_value(detail()).expect("serialises");
        let object = json.as_object().expect("an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["contributions", "evidence", "lead", "provenance"],
            "the wire shape drifted from WireLeadDetail"
        );

        // `lead` must be NESTED. The earlier `#[serde(flatten)]` put the
        // lead's fields at the top level, so `detail.lead` itself arrived
        // `undefined` and the first dereference threw.
        assert!(
            json["lead"].get("score").is_some(),
            "`lead` is not a nested object carrying `score`"
        );
        assert!(json["lead"].get("source_types").is_some());
        assert!(json["lead"].get("source_types_complete").is_some());
    }

    #[test]
    fn contributions_are_the_flat_factor_value_detail_rows_the_bench_maps_over() {
        let json = serde_json::to_value(detail()).expect("serialises");
        let row = &json["contributions"][0];
        for key in ["factor", "value", "detail"] {
            assert!(row.get(key).is_some(), "contribution row lost `{key}`");
        }
    }

    #[test]
    fn provenance_serialises_the_fields_the_provenance_block_renders() {
        // Exactly what BenchView's ProvenanceBlock reads — and nothing more.
        // `query_sha` and `swept_at` may be null, but the keys themselves must
        // exist so the optional reads stay reads rather than dereferences of a
        // missing object.
        let json = serde_json::to_value(detail()).expect("serialises");
        let provenance = json["provenance"].as_object().expect("an object");
        let mut keys: Vec<&str> = provenance.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["playbook_version", "query_sha", "scored_by", "sweep_id", "swept_at"],
            "the provenance shape drifted from WireLeadProvenance"
        );
        assert_eq!(json["provenance"]["scored_by"], "server");
        // TypeID on the wire, not a bare UUID — the desktop renders it as the
        // shareable reference.
        let sweep_id = json["provenance"]["sweep_id"].as_str().expect("a string");
        assert!(
            sweep_id.starts_with("swp_"),
            "sweep_id is not the `swp_` TypeID the rest of the sweep API serves: {sweep_id}"
        );
    }
}

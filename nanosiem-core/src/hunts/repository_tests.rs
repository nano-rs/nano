// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — repository tests.
//!
//! Two flavours. The first builds SQL through the real code paths and asserts
//! what the generated statement does — these catch a dropped predicate the way
//! a live-database test would, without needing a database. The second reads
//! this module's own source to assert structural invariants that no type system
//! can express: that only one code path can write a suppression, and that the
//! fence is reasserted before anything is written.
//!
//! Source-reading tests are a blunt instrument and are used only where the
//! alternative is a comment. `nanosiem-core/src/hunts/` ships in the open
//! mirror, so `include_str!` here does not break the sync-mirror build the way
//! it would against a stripped path.

use std::collections::BTreeSet;

use super::*;

/// This module's own source, for the structural assertions below.
const REPOSITORY_SOURCE: &str = include_str!("repository.rs");

fn restricted() -> ArtifactScope {
    ArtifactScope::from_denied(&BTreeSet::from(["insider_threat".to_string()]))
}

// =============================================================================
// Provenance filtering
// =============================================================================

#[test]
fn the_bench_query_carries_the_provenance_predicate_for_a_restricted_reader() {
    let query = ListLeadsQuery {
        limit: 50,
        ..Default::default()
    };
    let (sql, scoped) = build_leads_sql(&query, &restricted());
    assert!(scoped);
    assert!(
        sql.contains("l.source_types_complete"),
        "the bench query lost the completeness half of the gate: {sql}"
    );
    assert!(
        sql.contains("NOT (l.source_types &&"),
        "the bench query lost the deny-overlap half of the gate: {sql}"
    );
}

#[test]
fn the_predicate_lands_before_limit_so_pagination_is_not_an_oracle() {
    // A post-fetch filter would still PAGE over denied rows, making the page
    // size a count of how many exist. The predicate has to be in the WHERE.
    let query = ListLeadsQuery {
        limit: 50,
        ..Default::default()
    };
    let (sql, _) = build_leads_sql(&query, &restricted());
    let predicate_at = sql.find("source_types &&").expect("predicate present");
    let limit_at = sql.find(" LIMIT ").expect("limit present");
    assert!(
        predicate_at < limit_at,
        "the provenance predicate was emitted after LIMIT: {sql}"
    );
}

#[test]
fn an_unrestricted_reader_gets_byte_identical_sql() {
    // The pre-scoping shape has to survive for callers with no per-source
    // boundary, or every unscoped tenant pays for a feature they do not use.
    let query = ListLeadsQuery {
        limit: 50,
        ..Default::default()
    };
    let (sql, scoped) = build_leads_sql(&query, &ArtifactScope::system());
    assert!(!scoped);
    assert!(!sql.contains("source_types &&"));
}

#[test]
fn filters_and_the_predicate_do_not_fight_over_parameter_positions() {
    // The bind order in `list_leads` is positional. If a filter and the deny
    // array ever disagreed about $n, the query would either error or — worse —
    // compare a UUID against a text[] and quietly return nothing.
    let query = ListLeadsQuery {
        playbook_id: Some(uuid::Uuid::nil()),
        sweep_id: Some(uuid::Uuid::nil()),
        states: vec!["unreviewed".into()],
        reviewed_by: Some(uuid::Uuid::nil()),
        min_score: Some(0.5),
        limit: 25,
        offset: 0,
    };
    let (sql, scoped) = build_leads_sql(&query, &restricted());
    assert!(scoped);
    assert!(sql.contains("l.playbook_id = $1"));
    assert!(sql.contains("l.sweep_id = $2"));
    assert!(sql.contains("l.state = ANY($3)"));
    assert!(sql.contains("l.reviewed_by = $4"));
    assert!(sql.contains("l.score >= $5::float8::numeric"));
    assert!(sql.contains("$6::text[]"), "deny array is not $6: {sql}");
    assert!(sql.contains("LIMIT $7 OFFSET $8"), "{sql}");
}

#[test]
fn the_state_filter_is_an_any_over_a_bound_array_never_an_equality() {
    // The bench's segments are MULTI-state: the Unreviewed tab sends
    // `state=unreviewed,in_review`. The old shape emitted `l.state = $n` and
    // bound the whole comma-joined string, which matched no row ever — the tab
    // read 0 while unreviewed leads sat in the table. A single-state assertion
    // here would have passed against that code, so this pins the ANY form for
    // one state and for two.
    for states in [
        vec!["unreviewed".to_string()],
        vec!["unreviewed".to_string(), "in_review".to_string()],
    ] {
        let query = ListLeadsQuery {
            states,
            limit: 50,
            ..Default::default()
        };
        let (sql, _) = build_leads_sql(&query, &ArtifactScope::system());
        assert!(
            sql.contains("l.state = ANY($1)"),
            "the state filter regressed to a non-array form: {sql}"
        );
        assert!(
            !sql.contains("l.state = $"),
            "an equality state filter reappeared: {sql}"
        );
    }
}

#[test]
fn the_count_carries_the_same_filters_and_the_same_scope_predicate_as_the_page() {
    // The header's "N leads in this queue" must describe exactly the rows the
    // page reads. A count that lost a filter would overstate the queue; one
    // that lost the SCOPE predicate would tell a source-restricted reader how
    // many denied leads exist — the oracle the WHERE-clause placement exists
    // to prevent.
    let query = ListLeadsQuery {
        playbook_id: Some(uuid::Uuid::nil()),
        sweep_id: Some(uuid::Uuid::nil()),
        states: vec!["unreviewed".into(), "in_review".into()],
        reviewed_by: Some(uuid::Uuid::nil()),
        min_score: Some(0.5),
        limit: 25,
        offset: 0,
    };
    let (page, page_scoped) = build_leads_sql(&query, &restricted());
    let (count, count_scoped) = build_leads_count_sql(&query, &restricted());
    assert!(page_scoped && count_scoped);
    // Same WHERE, byte for byte: everything after the shared marker up to the
    // page's ORDER BY must appear verbatim in the count.
    let where_at = page.find(" WHERE 1 = 1").expect("page has the filter");
    let order_at = page.find(" ORDER BY").expect("page has an order");
    let shared = &page[where_at..order_at];
    assert!(
        count.ends_with(shared),
        "the count's WHERE drifted from the page's:\n page: {shared}\ncount: {count}"
    );
    assert!(!count.contains("LIMIT"), "a count took a page window: {count}");
}

#[test]
fn an_empty_state_list_emits_no_state_filter() {
    // "No states" means the caller did not filter — the every-state view (the
    // hunt page, the Mine segment). Emitting `= ANY('{}')` instead would match
    // nothing and turn those pages blank.
    let query = ListLeadsQuery {
        limit: 50,
        ..Default::default()
    };
    let (sql, _) = build_leads_sql(&query, &ArtifactScope::system());
    // The projection legitimately selects `l.state`; it is the FILTER that
    // must not appear.
    assert!(!sql.contains("l.state = ANY"), "{sql}");
    assert!(!sql.contains("l.state = $"), "{sql}");
}

// =============================================================================
// Score-contribution redaction (the referential factors)
// =============================================================================

fn lead_with(contributions: serde_json::Value) -> HuntLead {
    HuntLead {
        id: uuid::Uuid::nil(),
        sweep_id: uuid::Uuid::nil(),
        playbook_id: uuid::Uuid::nil(),
        playbook_version: 1,
        hunt_title: None,
        entity_type: "host".into(),
        entity_value: "srv-web06".into(),
        mitre_technique: None,
        window_start: Utc::now(),
        window_end: Utc::now(),
        narrative: None,
        score: 0.42,
        score_contributions: contributions,
        fingerprint: "fp".into(),
        state: "unreviewed".into(),
        reviewed_by: None,
        reviewed_at: None,
        promoted_case_id: None,
        // The lead itself is readable by the restricted reader below — the
        // point of these tests is the SECOND gate, over factors that describe
        // artifacts this manifest says nothing about.
        source_types: vec!["apache".into()],
        source_types_complete: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn stored(factor: &str, value: f64, detail: &str, basis: Option<ContributionBasis>) -> StoredContribution {
    StoredContribution {
        contribution: Contribution {
            factor: factor.into(),
            value,
            detail: detail.into(),
        },
        basis,
    }
}

fn details(lead: &HuntLead) -> Vec<(String, f64, String)> {
    serde_json::from_value::<Vec<StoredContribution>>(lead.score_contributions.clone())
        .expect("the breakdown is still a contribution list")
        .into_iter()
        .map(|s| (s.contribution.factor, s.contribution.value, s.contribution.detail))
        .collect()
}

#[test]
fn a_referential_detail_is_withheld_rather_than_dropped_or_zeroed() {
    // The disclosure: a stored line telling a reader that a suppression they
    // cannot see EXISTS. Three things must all hold — the line survives (an
    // absent factor reads as "the check never ran"), the signed value survives
    // (the breakdown has to reconcile with the score the reader can already
    // see), and the sentence no longer asserts the artifact.
    let mut lead = lead_with(
        serde_json::to_value(vec![
            stored("base", 0.15, "hunt matched", None),
            stored(
                "suppression",
                -0.15,
                "an active suppression matches this fingerprint",
                Some(ContributionBasis::from_artifacts(
                    vec!["insider_threat".into()],
                    true,
                )),
            ),
        ])
        .unwrap(),
    );
    redact_contributions(&mut lead, &restricted());

    assert_eq!(
        details(&lead),
        vec![
            ("base".to_string(), 0.15, "hunt matched".to_string()),
            (
                "suppression".to_string(),
                -0.15,
                "suppression state withheld".to_string()
            ),
        ]
    );
    // And the manifest that justified withholding is not itself returned —
    // naming the source would leak what the sentence just refused to state.
    assert!(
        !lead.score_contributions.to_string().contains("insider_threat"),
        "the withheld basis was serialized back to the reader: {}",
        lead.score_contributions
    );
}

#[test]
fn a_check_that_referenced_nothing_stays_readable() {
    // "no suppression matched" / "first time this shape has been seen" name no
    // artifact, so there is nothing to withhold — and withholding them would
    // cost every scoped analyst the line that proves the check ran.
    let mut lead = lead_with(
        serde_json::to_value(vec![
            stored(
                "suppression",
                0.0,
                "no suppression matched",
                Some(ContributionBasis::references_nothing()),
            ),
            stored(
                "recurrence",
                0.0,
                "first time this shape has been seen",
                Some(ContributionBasis::references_nothing()),
            ),
        ])
        .unwrap(),
    );
    redact_contributions(&mut lead, &restricted());
    assert_eq!(
        details(&lead)
            .into_iter()
            .map(|(_, _, detail)| detail)
            .collect::<Vec<_>>(),
        vec![
            "no suppression matched".to_string(),
            "first time this shape has been seen".to_string()
        ]
    );
}

#[test]
fn a_basis_the_reader_is_admitted_to_is_left_alone() {
    let mut lead = lead_with(
        serde_json::to_value(vec![stored(
            "recurrence",
            -0.10,
            "seen in 4 prior sweeps",
            Some(ContributionBasis::from_artifacts(vec!["apache".into()], true)),
        )])
        .unwrap(),
    );
    redact_contributions(&mut lead, &restricted());
    assert_eq!(details(&lead)[0].2, "seen in 4 prior sweeps");
}

#[test]
fn a_partially_admitted_basis_is_withheld_whole() {
    // The count is over ALL prior leads. A reader admitted to some of them
    // cannot account for the number, and recomputing a scoped count here would
    // contradict the score that was stored from the global one. Union + AND is
    // exactly "admitted to every contributor".
    let mut lead = lead_with(
        serde_json::to_value(vec![stored(
            "recurrence",
            -0.10,
            "seen in 4 prior sweeps",
            Some(ContributionBasis::from_artifacts(
                vec!["apache".into(), "insider_threat".into()],
                true,
            )),
        )])
        .unwrap(),
    );
    redact_contributions(&mut lead, &restricted());
    assert_eq!(details(&lead)[0].2, "prior occurrences withheld");

    // An INCOMPLETE manifest is withheld too, even when nothing in it is
    // denied: incomplete means the inputs were not all accounted for.
    let mut partial = lead_with(
        serde_json::to_value(vec![stored(
            "recurrence",
            -0.05,
            "seen in 1 prior sweeps",
            Some(ContributionBasis::from_artifacts(vec!["apache".into()], false)),
        )])
        .unwrap(),
    );
    redact_contributions(&mut partial, &restricted());
    assert_eq!(details(&partial)[0].2, "prior occurrences withheld");
}

#[test]
fn a_contribution_stored_before_this_contract_fails_closed() {
    // Rows written by the pre-NAN-2238-hardening commit path carry no basis.
    // "Cannot prove the reader may see it" has to resolve to withheld, or the
    // gate would be off for exactly the rows that were never classified.
    let mut lead = lead_with(serde_json::json!([
        {"factor": "suppression", "value": -0.15,
         "detail": "an active suppression matches this fingerprint"},
        {"factor": "recurrence", "value": -0.10, "detail": "seen in 3 prior sweeps"},
        {"factor": "rarity", "value": 0.25, "detail": "seen on 0.40% of assets"},
    ]));
    redact_contributions(&mut lead, &restricted());
    let rendered = details(&lead);
    assert_eq!(rendered[0].2, "suppression state withheld");
    assert_eq!(rendered[1].2, "prior occurrences withheld");
    // A factor measured from the lead's OWN evidence needs no basis and keeps
    // its detail — the lead's own manifest already gated it.
    assert_eq!(rendered[2].2, "seen on 0.40% of assets");
}

#[test]
fn a_manifest_that_normalizes_to_nothing_is_not_a_free_pass() {
    // `{''}` satisfies the migration's `cardinality(source_types) > 0` CHECK
    // and normalizes away to nothing. If emptiness were judged before
    // normalization, the basis would become the complete-EMPTY manifest —
    // the one state every reader is admitted to — and an unattributed
    // suppression would read as a visible one.
    let basis = ContributionBasis::from_artifacts(vec!["".into(), "   ".into()], true);
    assert!(basis.source_types.is_empty());
    assert!(
        !basis.complete,
        "an empty-after-normalization manifest claimed completeness"
    );

    let mut lead = lead_with(
        serde_json::to_value(vec![stored(
            "suppression",
            -0.15,
            "an active suppression matches this fingerprint",
            Some(basis),
        )])
        .unwrap(),
    );
    redact_contributions(&mut lead, &restricted());
    assert_eq!(details(&lead)[0].2, "suppression state withheld");
}

#[test]
fn an_unrestricted_reader_gets_the_stored_breakdown_untouched() {
    let original = serde_json::json!([
        {"factor": "suppression", "value": -0.15,
         "detail": "an active suppression matches this fingerprint",
         "basis": {"source_types": ["insider_threat"], "complete": true}},
    ]);
    let mut lead = lead_with(original.clone());
    redact_contributions(&mut lead, &ArtifactScope::system());
    assert_eq!(lead.score_contributions, original);
}

#[test]
fn an_unreadable_breakdown_fails_closed_but_still_says_so() {
    // `score_contributions` DEFAULTs to `'{}'` — an empty object, not a list.
    // A shape this code cannot classify must not be handed over unclassified,
    // and must not vanish either.
    let mut lead = lead_with(serde_json::json!({}));
    redact_contributions(&mut lead, &restricted());
    assert_eq!(
        lead.score_contributions,
        serde_json::json!([{"factor": "redacted", "value": 0.0,
                            "detail": "score breakdown withheld"}])
    );

    // Unrestricted readers are unaffected — the pre-existing value survives.
    let mut unrestricted = lead_with(serde_json::json!({}));
    redact_contributions(&mut unrestricted, &ArtifactScope::system());
    assert_eq!(unrestricted.score_contributions, serde_json::json!({}));
}

#[test]
fn every_referential_factor_the_scorer_emits_gets_a_basis() {
    // The binding between `scoring`'s factor NAMES and `REFERENTIAL_FACTORS` is
    // a string match, so a rename on either side would silently turn redaction
    // off for that factor while every other test kept passing. Both directions
    // are pinned: the scorer emits each referential factor, and stamping
    // attaches a basis to those and only those.
    let emitted = score(&ScoreInputs {
        evidence_count: 3,
        distinct_source_types: 2,
        prevalence: Some(0.02),
        first_seen_in_window: true,
        suppressed: false,
        prior_occurrences: 2,
    });
    let names: BTreeSet<&str> = emitted
        .contributions
        .iter()
        .map(|c| c.factor.as_str())
        .collect();
    for (factor, _) in REFERENTIAL_FACTORS {
        assert!(
            names.contains(factor),
            "`{factor}` is redacted but the scorer no longer emits it — a rename \
             turned the gate off"
        );
    }

    let stamped = stamp_contribution_bases(
        emitted.contributions,
        &ContributionBasis::references_nothing(),
        &ContributionBasis::references_nothing(),
    );
    for entry in &stamped {
        let referential = REFERENTIAL_FACTORS
            .iter()
            .any(|(f, _)| *f == entry.contribution.factor);
        assert_eq!(
            entry.basis.is_some(),
            referential,
            "`{}` basis presence disagrees with REFERENTIAL_FACTORS",
            entry.contribution.factor
        );
    }
}

#[test]
fn the_suppression_check_stays_global_and_pays_for_it_at_render() {
    // The decision this feature turns on, pinned in BOTH directions.
    //
    // Global check: scoping it would mean a suppression the sweep principal
    // cannot see stops suppressing, dismissed leads come back, and dismissal
    // memory — the reason the bench is trusted — quietly breaks.
    //
    // Redacted render: leaving it there is a stored line telling a later reader
    // an artifact they are denied EXISTS.
    let commit = function_body(REPOSITORY_SOURCE, "pub async fn commit_sweep_report(");
    assert!(
        commit.contains("FROM hunt_suppressions s"),
        "the commit path no longer measures suppression"
    );
    assert!(
        !commit.contains("sql_predicate"),
        "the suppression / recurrence measurement gained a scope predicate — \
         the score now varies by whoever's key ran the sweep"
    );
    assert!(
        commit.contains("stamp_contribution_bases"),
        "contributions are stored without the provenance of what they refer to, \
         so nothing can be re-evaluated at read time"
    );

    for read in [
        "pub async fn list_leads(",
        "pub async fn get_lead(",
        "pub async fn dismiss_lead(",
    ] {
        let body = function_body(REPOSITORY_SOURCE, read);
        assert!(
            body.contains("redact_contributions"),
            "`{read}` returns a stored score breakdown without re-evaluating it \
             for this reader"
        );
    }
}

// =============================================================================
// The rule-idea locking read
// =============================================================================

#[test]
fn the_rule_idea_lock_carries_the_scope_predicate_itself() {
    // Authorization and the lock have to be the SAME statement.
    // `hunt_rule_ideas.source_types` is re-stamped by any concurrent sweep
    // whose lead accrues into the idea, so a preflight that cleared the caller
    // and then locked unconditionally decides on a row whose manifest may have
    // gained a denied source in between.
    let (sql, scoped) = build_rule_idea_lock_sql(&restricted());
    assert!(scoped);
    assert!(
        sql.contains("i.source_types_complete") && sql.contains("NOT (i.source_types &&"),
        "the locking read lost half the gate: {sql}"
    );
    let predicate_at = sql.find("i.source_types &&").expect("predicate present");
    let lock_at = sql.find(" FOR UPDATE").expect("still a locking read");
    assert!(
        predicate_at < lock_at,
        "the predicate landed after FOR UPDATE, which is a syntax error rather \
         than a gate: {sql}"
    );
    assert!(sql.contains("$2::text[]"), "deny array is not $2: {sql}");

    // Unscoped callers keep the pre-scoping statement byte for byte.
    let (unscoped, scoped) = build_rule_idea_lock_sql(&ArtifactScope::system());
    assert!(!scoped);
    assert_eq!(
        unscoped,
        "SELECT state, basis_sweep_count, basis_promoted_count \
           FROM hunt_rule_ideas i WHERE i.id = $1 FOR UPDATE"
    );
}

#[test]
fn deciding_a_rule_idea_authorizes_under_the_lock_not_before_it() {
    // The old shape was an unlocked scoped preflight followed by an unscoped
    // `FOR UPDATE`. If a separate preflight ever comes back, the race comes
    // back with it.
    let decide = function_body(REPOSITORY_SOURCE, "pub async fn decide_rule_idea(");
    assert!(
        decide.contains("recompute_rule_idea_gate(&mut tx, idea_id, scope)"),
        "the decision path stopped passing the caller's scope into the locking read"
    );
    assert!(
        !decide.contains("sql_predicate"),
        "a second, unlocked scope check reappeared in the decision path"
    );

    // The internal callers are unscoped ON PURPOSE: a counter refresh is server
    // bookkeeping, and failing it for a scoped analyst would either abort a
    // promotion or leave a stale `ready`.
    for internal in [
        "async fn accrue_rule_idea_basis(",
        "pub async fn promote_lead(",
    ] {
        let body = function_body(REPOSITORY_SOURCE, internal);
        assert!(
            body.contains("recompute_rule_idea_gate")
                && body.contains("&ArtifactScope::system()"),
            "`{internal}` no longer states which scope its recount runs under"
        );
    }
}

#[test]
fn rule_ideas_never_label_repository_opening_guidance_as_npl() {
    let prose = "identity-plane writes that extend or entrench access\nwindow: 24h";
    assert_eq!(rule_idea_seed_npl(prose), None);
    assert_eq!(
        rule_idea_seed_npl("candidate service accounts by naming convention and behaviour"),
        None
    );

    let npl = r#"source_type="windows_security" | stats count by user"#;
    assert_eq!(rule_idea_seed_npl(npl), Some(npl));
    assert_eq!(rule_idea_seed_npl("source_type="), None);
}

#[test]
fn every_artifact_table_read_is_scoped() {
    // The migration's CHECK constraints fail closed on WRITE; a SELECT needs
    // the predicate. If a table is added to 9000054 and read here without one,
    // this is the test that says so.
    for (table, manifest_column, complete_column) in ARTIFACT_READ_SITES {
        assert!(
            REPOSITORY_SOURCE.contains(&format!("FROM {table}")),
            "{table} is registered as an artifact read site but is never read here"
        );
        assert!(
            REPOSITORY_SOURCE.contains(&format!("\"{manifest_column}\"")),
            "no read of {table} passes {manifest_column} to sql_predicate"
        );
        assert!(
            REPOSITORY_SOURCE.contains(&format!("\"{complete_column}\"")),
            "no read of {table} passes {complete_column} to sql_predicate"
        );
    }
}

// =============================================================================
// Structural invariants
// =============================================================================

/// Extract one `pub async fn` / `async fn` body by brace matching.
fn function_body(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("function `{signature}` not found"));
    let open = source[start..]
        .find('{')
        .expect("function has a body")
        + start;
    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return source[open..=open + offset].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces in `{signature}`");
}

#[test]
fn suppressions_are_written_from_exactly_two_paths_and_no_others() {
    // Blinding its own successors is the one failure mode of this feature that
    // would be invisible until the bench went quiet for the wrong reason. Until
    // NAN-2240 the answer was "only triage writes"; now there are TWO writers,
    // and the guard is that there are exactly two and each is the one intended.
    //
    // A third insert appearing here means someone added a suppression path
    // without deciding which of the two sets of bounds it is under.
    let occurrences = REPOSITORY_SOURCE.matches("INSERT INTO hunt_suppressions").count();
    assert_eq!(
        occurrences, 2,
        "expected exactly two suppression inserts (analyst triage, agent sweep), found {occurrences}"
    );

    let dismiss = function_body(REPOSITORY_SOURCE, "pub async fn dismiss_lead(");
    assert!(
        dismiss.contains("INSERT INTO hunt_suppressions"),
        "the suppression insert moved out of the analyst triage path"
    );

    // The agent path, and every bound that makes it survivable. These are
    // asserted on the SQL itself rather than on behaviour because each one is a
    // thing a well-meaning refactor would parameterise: an `origin` argument, a
    // nullable expiry, an entity filter "for flexibility". Each would silently
    // restore the failure the original design refused.
    let agent = function_body(REPOSITORY_SOURCE, "pub async fn record_agent_suppression(");
    assert!(
        agent.contains("'agent'"),
        "origin must be the literal 'agent' — a parameter would let this path forge an analyst row"
    );
    assert!(
        !agent.contains("$6"),
        "the agent insert takes five binds; a sixth means a new caller-controlled column"
    );
    assert!(
        agent.contains("NOW() + ($5 || ' days')::INTERVAL"),
        "expiry must be computed from the clamped ttl, never passed in or left NULL"
    );
    assert!(
        agent.contains("FROM hunt_leads l") && agent.contains("l.sweep_id = $1"),
        "the insert must be conditioned on a lead THIS sweep filed — otherwise a sweep \
         could suppress a finding it never saw, including one from another hunt"
    );
    // The fingerprint is READ from the lead, never bound. A bound fingerprint
    // would put a server-derived value back under caller control — and would be
    // unusable anyway, since the agent has no way to obtain one.
    assert!(
        agent.contains("SELECT l.fingerprint"),
        "the fingerprint must come FROM the matched lead, not from a parameter"
    );
    assert!(
        agent.contains("l.source_types") && agent.contains("l.source_types_complete"),
        "provenance must be INHERITED from the lead, never declared by the caller"
    );
    // The entity is READ, to find the lead. It must never be WRITTEN: a
    // suppression carrying an entity is the broad, pattern-matching form, and
    // that form must stay unreachable from the agent path.
    let insert_columns = agent
        .split("INSERT INTO hunt_suppressions")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .expect("the insert names its columns");
    for wide in ["playbook_id", "entity_type", "entity_value"] {
        assert!(
            !insert_columns.contains(wide),
            "`{wide}` is written by the agent insert — the broad suppression forms must \
             stay unreachable from this path"
        );
    }

    // The commit path DOES read `hunt_suppressions` — that is how a lead
    // matching an analyst's dismissal gets its score zeroed. What it must never
    // do is write one.
    let commit = function_body(REPOSITORY_SOURCE, "pub async fn commit_sweep_report(");
    for write in [
        "INSERT INTO hunt_suppressions",
        "UPDATE hunt_suppressions",
        "DELETE FROM hunt_suppressions",
    ] {
        assert!(
            !commit.contains(write),
            "the sweep-report commit path gained `{write}`"
        );
    }
}

#[test]
fn the_commit_path_reasserts_the_fence_before_it_writes_anything() {
    // This is the fence. The schema RECORDS runner/fence/lease on a leased
    // sweep; only reasserting them under lock before the first write makes them
    // mean anything. A stale runner that woke after reassignment must find no
    // row rather than append to work that was already handed to someone else.
    let commit = function_body(REPOSITORY_SOURCE, "pub async fn commit_sweep_report(");

    // The FIRST raw string literal in the body is the locking SELECT. Asserting
    // against the literal rather than against the whole body is deliberate:
    // matching loose text would pass on a mention of `FOR UPDATE` in a comment,
    // which is exactly the reassurance-without-a-control this test exists to
    // rule out.
    let literal_start = commit
        .find("r#\"")
        .expect("the commit path no longer opens with a SQL literal");
    let literal_end = commit[literal_start..]
        .find("\"#")
        .expect("unterminated SQL literal")
        + literal_start;
    let locking_select = &commit[literal_start..literal_end];

    for required in [
        "s.id = $1",
        "s.runner_id = $2",
        "s.runner_fence = $3",
        "r.fence_token = $3",
        "s.lease_expires_at > NOW()",
        "s.status IN ('leased', 'running')",
        "FOR UPDATE OF s",
    ] {
        assert!(
            locking_select.contains(required),
            "the fence reassertion lost `{required}`"
        );
    }

    // Nothing may be written before the lock is held.
    for write in ["INSERT INTO", "UPDATE hunt_"] {
        if let Some(first_write) = commit.find(write) {
            assert!(
                literal_end < first_write,
                "a `{write}` statement precedes the fence reassertion"
            );
        }
    }
}

#[test]
fn knowledge_commits_after_lead_scoring_and_before_the_sweep_finishes() {
    let commit = function_body(REPOSITORY_SOURCE, "pub async fn commit_sweep_report(");
    let lead_loop = commit
        .find("for prepared in &inputs.leads")
        .expect("the report no longer processes prepared leads");
    let knowledge_loop = commit
        .find("for fact in &inputs.knowledge")
        .expect("the report no longer processes prepared knowledge");
    let knowledge_write = commit
        .find("record_prepared_in_tx(&mut tx")
        .expect("prepared knowledge is not written through the report transaction");
    let finish = commit
        .find("UPDATE hunt_sweeps")
        .expect("the report no longer finishes its sweep");

    assert!(
        lead_loop < knowledge_loop && knowledge_loop < knowledge_write,
        "knowledge reached the transaction before lead scoring; it must remain an output only"
    );
    assert!(
        !commit[..knowledge_loop].contains("&inputs.knowledge"),
        "knowledge is consulted before lead scoring finishes"
    );
    assert!(
        knowledge_write < finish,
        "knowledge is still written after the sweep loses its live lease"
    );
    assert!(
        !commit.contains("INSERT INTO hunt_knowledge"),
        "the report repository duplicated knowledge's tombstone/reconfirmation SQL"
    );
}

#[test]
fn the_runner_facing_read_is_not_artifact_scoped_but_the_analyst_one_is() {
    // A queued sweep has an empty manifest, so applying the artifact predicate
    // to the runner's own claim/commit path would make a source-scoped sweep key
    // unable to claim anything at all. The analyst-facing reads DO carry it,
    // because a sweep's trail is agent prose over matched events.
    let claim = function_body(REPOSITORY_SOURCE, "pub async fn claim_next_sweep(");
    assert!(!claim.contains("sql_predicate"));

    // A sweep row is scheduler state, so it is redacted rather than hidden —
    // otherwise "9 hunts swept in the last 24h" reads as zero for every
    // source-scoped analyst and a working feature looks broken. What gets
    // blanked is the agent-authored prose.
    for sweep_read in ["pub async fn list_sweeps(", "pub async fn get_sweep("] {
        let body = function_body(REPOSITORY_SOURCE, sweep_read);
        assert!(
            body.contains("redact_unattributed"),
            "`{sweep_read}` returns a sweep trail without redacting it for a scoped reader"
        );
    }

    for analyst_read in [
        "pub async fn list_leads(",
        "pub async fn get_lead(",
        "pub async fn list_suppressions(",
        "pub async fn latest_profile(",
        "pub async fn list_rule_ideas(",
    ] {
        let body = function_body(REPOSITORY_SOURCE, analyst_read);
        assert!(
            body.contains("sql_predicate") || body.contains("build_leads_sql"),
            "`{analyst_read}` reads a provenance-stamped table without the scope predicate"
        );
    }
}

#[test]
fn the_gate_is_recomputed_from_basis_rows_not_from_the_cached_counters() {
    // `hunt_rule_ideas_counter_guard` is trivially satisfied by writing 3 and 2.
    // The only honest source is `hunt_rule_idea_basis`, so the transition must
    // read from it and must not branch on the cached columns.
    let body = function_body(REPOSITORY_SOURCE, "async fn recompute_rule_idea_gate(");
    assert!(
        body.contains("FROM hunt_rule_idea_basis WHERE idea_id = $1"),
        "the rule-idea gate stopped reading its basis rows"
    );
    assert!(
        body.contains("COUNT(DISTINCT sweep_id)"),
        "the gate counts leads rather than distinct sweeps"
    );
    assert!(
        !body.contains("SELECT basis_sweep_count") && !body.contains("i.basis_sweep_count"),
        "the gate reads the cached counter it is supposed to be recomputing"
    );
}

// =============================================================================
// Small helpers with real failure modes
// =============================================================================

#[test]
fn case_severity_comes_from_the_server_score_when_not_overridden() {
    // An agent has no field to propose a severity and must not gain one
    // sideways: the only inputs here are the derived score and an explicit
    // analyst choice.
    assert_eq!(normalize_case_severity(None, 0.92), "critical");
    assert_eq!(normalize_case_severity(None, 0.70), "high");
    assert_eq!(normalize_case_severity(None, 0.45), "medium");
    assert_eq!(normalize_case_severity(None, 0.10), "low");

    assert_eq!(normalize_case_severity(Some("Medium"), 0.92), "medium");
    // An unrecognised override falls back to the derived value rather than
    // reaching `cases_severity_check` and 500ing.
    assert_eq!(normalize_case_severity(Some("apocalyptic"), 0.92), "critical");
}

#[test]
fn truncation_counts_characters_because_the_check_constraints_do() {
    // Postgres `length()` counts CHARACTERS. Truncating by bytes would both
    // mis-measure a multi-byte narrative and be able to split a UTF-8 sequence.
    let multibyte = "é".repeat(20);
    assert_eq!(truncate_chars(&multibyte, 10).chars().count(), 10);
    assert_eq!(truncate_chars("short", 10), "short");
}

#[test]
fn absurd_counters_saturate_rather_than_wrapping_negative() {
    // `hunt_rule_ideas_counters_nonneg` rejects a negative. A runner reporting a
    // nonsense count should skew a dashboard, not fail the whole commit.
    assert_eq!(clamp_i32(-5), 0);
    assert_eq!(clamp_i32(i64::MAX), i32::MAX);
    assert_eq!(clamp_i32(7), 7);
}

#[test]
fn a_lease_request_cannot_outlast_failover() {
    // Reclaim only reassigns a sweep whose lease has EXPIRED, so an unbounded
    // lease is an unbounded outage for that hunt.
    assert!(MAX_LEASE_SECONDS <= 3600);
    assert!(DEFAULT_LEASE_SECONDS <= MAX_LEASE_SECONDS);
}

#[test]
fn dismissal_always_writes_a_suppression() {
    // The client offers WIDTH and EXPIRY, never whether. Per-machine dismissal
    // memory is worthless — if one analyst kills a lead and another sees it
    // again tomorrow, the bench fills with the same rejects daily. If a
    // conditional ever reappears around the insert, this is the test that says
    // so.
    let dismiss = function_body(REPOSITORY_SOURCE, "pub async fn dismiss_lead(");
    let insert_at = dismiss
        .find("INSERT INTO hunt_suppressions")
        .expect("dismissal no longer writes a suppression");
    let guard = dismiss[..insert_at].rfind("if req.");
    assert!(
        guard.is_none(),
        "the suppression write is behind a request-controlled conditional"
    );
}

#[test]
fn the_suppression_width_dial_is_the_nullable_playbook_id() {
    // `hunt_suppressions.playbook_id` is nullable precisely so a dismissal can
    // be scoped to one hunt or to the tenant. If the mapping inverted, a
    // "this hunt only" dismissal would silently blind every other hunt.
    let dismiss = function_body(REPOSITORY_SOURCE, "pub async fn dismiss_lead(");
    assert!(dismiss.contains("SuppressionWidth::Hunt => Some(lead.playbook_id)"));
    assert!(dismiss.contains("SuppressionWidth::Tenant => None"));
}

// =============================================================================
// Statements that EXECUTE against the local dev Postgres
// =============================================================================
//
// The pure tests above assert the SHAPE of the bench query, which is exactly
// what the bug this file fixed once got past: `l.state = $n` bound with a
// comma-joined string assembles cleanly, prepares cleanly, and matches nothing.
// These run the REAL `list_leads` path against the dev database, `#[ignore]`d
// so `cargo test --lib` stays hermetic. Run:
//
// ```text
// cargo test -p nanosiem-core --lib -- hunts::repository::repository_tests::live --ignored --nocapture
// ```
mod live {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    /// A ONE-connection pool, so the explicit transaction below spans every
    /// statement — including the ones `list_leads` issues internally — and a
    /// ROLLBACK (or the connection closing on a panic) undoes all of it. The
    /// dev database's real leads are read, never mutated.
    async fn pool() -> sqlx::PgPool {
        let url = std::env::var("NANO_TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://nanosiem:nanosiem@localhost:5432/nanosiem".to_string()
        });
        PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("local dev Postgres is reachable")
    }

    #[tokio::test]
    #[ignore = "requires the local dev Postgres on :5432 with the hunt schema"]
    async fn a_two_state_filter_returns_rows_for_both_states() {
        let pool = pool().await;
        sqlx::query("BEGIN").execute(&pool).await.unwrap();

        // The dev bench is all-unreviewed; flip ONE lead inside the
        // transaction so both states exist to be found.
        let flipped: Option<(uuid::Uuid,)> = sqlx::query_as(
            "UPDATE hunt_leads SET state = 'in_review' \
              WHERE id = (SELECT id FROM hunt_leads WHERE state = 'unreviewed' \
                          ORDER BY created_at ASC LIMIT 1) \
              RETURNING id",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let repo = HuntRepository::new(pool.clone());
        let scope = ArtifactScope::system();
        let both = repo
            .list_leads(
                &ListLeadsQuery {
                    states: vec!["unreviewed".into(), "in_review".into()],
                    limit: 200,
                    ..Default::default()
                },
                &scope,
            )
            .await;
        let single = repo
            .list_leads(
                &ListLeadsQuery {
                    states: vec!["in_review".into()],
                    limit: 200,
                    ..Default::default()
                },
                &scope,
            )
            .await;
        let total = repo
            .count_leads(
                &ListLeadsQuery {
                    states: vec!["unreviewed".into(), "in_review".into()],
                    limit: 200,
                    ..Default::default()
                },
                &scope,
            )
            .await;

        // Roll back BEFORE asserting, so a failed assertion cannot strand the
        // flipped state.
        sqlx::query("ROLLBACK").execute(&pool).await.unwrap();

        let (flipped,) = flipped.expect(
            "the dev database has no unreviewed lead to flip — seed at least two leads first",
        );
        let both = both.unwrap();
        let states: BTreeSet<&str> = both.iter().map(|l| l.state.as_str()).collect();
        // BOTH states must come back. Against the broken equality form this
        // query returned zero rows, so asserting one state alone would have
        // passed; the two-state assertion is the regression test.
        assert!(
            states.contains("unreviewed"),
            "the two-state filter dropped the unreviewed rows: {states:?}"
        );
        assert!(
            states.contains("in_review"),
            "the two-state filter dropped the in_review row: {states:?}"
        );
        assert!(
            both.iter().any(|l| l.id == flipped),
            "the flipped lead did not come back under the two-state filter"
        );

        // The header count describes the same queue: everything fits inside
        // the page window here, so the count IS the row count.
        assert_eq!(
            total.unwrap(),
            both.len() as i64,
            "the queue count disagrees with the rows the same filter returned"
        );

        // Single-state callers keep working, and stay exact.
        let single = single.unwrap();
        assert!(
            single.iter().all(|l| l.state == "in_review"),
            "a single-state filter returned other states"
        );
        assert!(
            single.iter().any(|l| l.id == flipped),
            "the single-state filter missed the flipped lead"
        );
    }

    /// Read-only: the detail read serves the contributions and provenance the
    /// bench dereferences unguarded, from a REAL lead and its sweep.
    #[tokio::test]
    #[ignore = "requires the local dev Postgres on :5432 with at least one lead"]
    async fn the_detail_read_serves_contributions_and_provenance_from_the_real_sweep() {
        let pool = pool().await;
        let repo = HuntRepository::new(pool.clone());
        let (lead_id,): (uuid::Uuid,) =
            sqlx::query_as("SELECT id FROM hunt_leads ORDER BY created_at DESC LIMIT 1")
                .fetch_one(&pool)
                .await
                .expect("the dev database has at least one lead");

        let detail = repo
            .get_lead(lead_id, &ArtifactScope::system())
            .await
            .expect("the detail read succeeds");

        assert!(
            !detail.contributions.is_empty(),
            "a scored lead came back with an empty `why` breakdown"
        );
        for contribution in &detail.contributions {
            assert!(!contribution.factor.is_empty());
            assert!(!contribution.detail.is_empty());
        }
        assert_eq!(detail.provenance.sweep_id, detail.lead.sweep_id);
        assert_eq!(
            detail.provenance.playbook_version,
            detail.lead.playbook_version
        );
        assert_eq!(detail.provenance.scored_by, LEAD_SCORED_BY);
        // The sweep that filed a lead has finished by definition — its report
        // commit is what created the lead — so `swept_at` is present.
        assert!(
            detail.provenance.swept_at.is_some(),
            "a committed sweep has no finished_at"
        );
    }
}

#[test]
fn shipping_a_rule_idea_re_derives_the_gate_in_the_same_transaction() {
    // A cached counter must never be what authorizes shipping: the CHECK over
    // those columns is satisfied by writing 3 and 2, and this is one human
    // click away from a detection rule built on attacker-influenced content.
    let decide = function_body(REPOSITORY_SOURCE, "pub async fn decide_rule_idea(");
    let recompute_at = decide
        .find("recompute_rule_idea_gate")
        .expect("the decision path no longer re-derives the gate");
    let gate_at = decide
        .find("clears_gate()")
        .expect("the decision path no longer checks the gate");
    assert!(
        recompute_at < gate_at,
        "the gate is checked against counters that were not recomputed first"
    );
    assert!(
        decide.contains("RuleIdeaVerdict::Send"),
        "shipping is no longer a compile-time literal decision"
    );
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for hunt frontmatter → [`HuntSpecDraft`].
//!
//! The fixtures are the real stock hunts from `nano-rs/playbooks` (frontmatter
//! verbatim, bodies trimmed to the steps that matter here). They are copied in
//! rather than referenced because the sync pipeline's job is to accept THOSE
//! files: if the authoring format and this parser ever drift, a test built from
//! a convenient invention would not notice.

use super::*;
use crate::playbooks::{parse_playbook, split_frontmatter};

/// `service_account_interactive_logon.md` — opens on `/query`, uses
/// `/baseline`, `/pivot`, `/enrichment` and `/lead`.
const SERVICE_ACCOUNT_HUNT: &str = r#"---
kind: hunt
title: "Service account authenticating interactively"
subtitle: "Accounts provisioned for machine-to-machine use logging on the way a person would"
category: identity
owner: "team · soc-leads"
authored: 2026-07-30
schedule: "0 3 * * *"
timezone: "UTC"
lookback_window: 24h
required_source_types:
  - windows_security
mitre_tactic: lateral-movement
mitre_technique: T1078.002
budget:
  max_turns: 30
  max_tool_calls: 90
  max_rows: 4000
  max_wall_seconds: 600
tags:
  - identity
  - service-accounts
  - valid-accounts
---
# Service account authenticating interactively

**Hypothesis:** an account that exists to let one machine talk to another
should never produce the authentication silhouette of a human at a keyboard.

## Establish the population

/query: candidate service accounts by naming convention and behaviour
  window: 30d
  from:   windows_security
  where:  event_id = 4624
  note:   "Do not rely on the naming convention alone."

/baseline: per-account logon-type distribution over the trailing 30 days
  note:   "The comparison that matters is against the account's OWN history."

## Look for the deviation

/pivot: what the account did after the interactive session began
  note:   "Follow the session rather than stopping at the logon."

## Rule out the boring explanation

/enrichment: is the source host one this account normally authenticates from
  note:   "A service account used interactively ON ITS OWN SERVER is sloppy."

## Emit

/lead: interactive logon by a machine-to-machine account
  entity: user
  note:   "Say plainly which benign explanation was checked."
"#;

/// `lolbin_unusual_parent.md` — opens on `/baseline`, not `/query`. The seed
/// has to follow document order rather than preferring a step kind.
const LOLBIN_HUNT: &str = r#"---
kind: hunt
title: "Built-in tooling launched by something that has no business launching it"
subtitle: "Signed system binaries spawned from parents that have never spawned them here before"
category: endpoint
owner: "team · soc-leads"
authored: 2026-07-30
schedule: "0 5 * * *"
timezone: "UTC"
lookback_window: 24h
required_source_types:
  - windows_sysmon
mitre_tactic: defense-evasion
mitre_technique: T1218
budget:
  max_turns: 40
  max_tool_calls: 120
  max_rows: 6000
  max_wall_seconds: 900
tags:
  - endpoint
  - lolbin
  - execution
---
# Built-in tooling launched by something that has no business launching it

## Learn what normal looks like here

/baseline: parent→child pairs observed across the estate, trailing 30 days
  note:   "Build the pair census first."

/query: executions of commonly-abused signed binaries
  window: 24h
  from:   windows_sysmon
  note:   "Cast wide here."
"#;

/// A response playbook, for the negative case: the same pipeline must not
/// promote one to a hunt.
const RESPONSE_PLAYBOOK: &str = r#"---
title: Credential reuse
category: identity
match_signals:
  - offboarded
---
# Credential reuse

/query: recent authentications for the account
/decision: is this the offboarded user
  options:
    - yes
    - no
"#;

fn draft_from(src: &str) -> Result<HuntSpecDraft, HuntSpecError> {
    let (fm, body) = split_frontmatter(src).expect("frontmatter splits");
    let tree = parse_playbook(body);
    HuntSpecDraft::from_frontmatter(fm.as_ref(), &tree)
}

// =============================================================================
// The stock hunts are the spec
// =============================================================================

#[test]
fn parses_the_service_account_stock_hunt() {
    let draft = draft_from(SERVICE_ACCOUNT_HUNT).expect("stock hunt parses");

    assert_eq!(draft.schedule_cron.as_deref(), Some("0 3 * * *"));
    assert_eq!(draft.schedule_timezone, "UTC");
    assert_eq!(draft.lookback_window, "24h");
    assert_eq!(draft.required_source_types, vec!["windows_security"]);
    assert_eq!(draft.mitre_tactic.as_deref(), Some("lateral-movement"));
    assert_eq!(draft.mitre_technique.as_deref(), Some("T1078.002"));
    assert_eq!(draft.budget.max_turns, 30);
    assert_eq!(draft.budget.max_tool_calls, 90);
    assert_eq!(draft.budget.max_rows, 4000);
    assert_eq!(draft.budget.max_wall_seconds, 600);

    // The seed is the opening step plus the parameters that scope it.
    assert!(draft
        .sweep_query
        .starts_with("candidate service accounts by naming convention and behaviour"));
    assert!(draft.sweep_query.contains("from: windows_security"));
    assert!(draft.sweep_query.contains("window: 30d"));
    assert!(draft.sweep_query.contains("where: event_id = 4624"));
}

#[test]
fn the_seed_follows_document_order_not_step_kind() {
    // lolbin opens on /baseline. A parser that looked for the first /query
    // would seed the sweep with the deviation hunt instead of the census it
    // depends on — and the deviation query without the census returns every
    // LOLBin execution in the estate.
    let draft = draft_from(LOLBIN_HUNT).expect("stock hunt parses");
    assert!(draft
        .sweep_query
        .starts_with("parent→child pairs observed across the estate"));
}

#[test]
fn hunt_step_kinds_reach_the_parser() {
    // /baseline and /lead are hunt additions to the shared slash-command
    // grammar. If the regex loses them they silently become prose, the step
    // count collapses, and a hunt that opens on /baseline loses its seed.
    let (_, body) = split_frontmatter(SERVICE_ACCOUNT_HUNT).unwrap();
    let tree = parse_playbook(body);
    let kinds: Vec<&str> = tree
        .phases
        .iter()
        .flat_map(|p| p.steps.iter())
        .map(|s| s.kind.as_str())
        .collect();
    assert_eq!(
        kinds,
        vec!["query", "baseline", "pivot", "enrichment", "lead"]
    );
}

// =============================================================================
// The enable switch
// =============================================================================

#[test]
fn frontmatter_cannot_enable_a_hunt() {
    // The load-bearing test. If a future change adds an `enabled` field to
    // PlaybookFrontmatter or HuntSpecDraft, merge access to a content
    // repository becomes equivalent to `hunts:run` — an autonomous process
    // reading production telemetry on a cron, granted by approving markdown.
    //
    // Expressed the only way Rust allows: the fields do not exist, so the
    // parse ignores them and there is nothing downstream to carry them. Adding
    // either field makes this test's premise false and someone has to come
    // read this comment.
    let hostile = SERVICE_ACCOUNT_HUNT.replace(
        "kind: hunt",
        "kind: hunt\nenabled: true\nauto_promote: true\nnext_due_slot: 2026-07-30T03:00:00Z",
    );

    let (fm, body) = split_frontmatter(&hostile).expect("frontmatter still parses");
    let fm = fm.expect("frontmatter present");
    let draft =
        HuntSpecDraft::from_frontmatter(Some(&fm), &parse_playbook(body)).expect("hunt parses");

    // Serializing the whole draft is the strongest available assertion: it
    // catches a field added under any name that serializes to these strings,
    // not just one we thought to check for.
    let rendered = format!("{draft:?}");
    for forbidden in ["enabled", "auto_promote", "next_due_slot"] {
        assert!(
            !rendered.contains(forbidden),
            "HuntSpecDraft grew a `{forbidden}` field — a merged markdown file can now \
             switch on an unattended sweep against production telemetry. The enable switch \
             belongs in the product, where turning it on is visibly a decision."
        );
    }

    // The suggested cadence IS recorded — the rule is that it is not applied.
    assert_eq!(draft.schedule_cron.as_deref(), Some("0 3 * * *"));
}

// =============================================================================
// Kind is declared, never inferred
// =============================================================================

#[test]
fn a_response_playbook_is_not_promoted_to_a_hunt() {
    let err = draft_from(RESPONSE_PLAYBOOK).expect_err("must refuse");
    assert_eq!(err, HuntSpecError::NotAHunt("response"));
}

#[test]
fn frontmatter_absent_entirely_is_not_a_hunt() {
    let err = draft_from("# just a document\n\nno frontmatter here\n")
        .expect_err("must refuse");
    assert_eq!(err, HuntSpecError::MissingFrontmatter);
}

#[test]
fn an_unknown_kind_fails_the_whole_frontmatter_parse() {
    // Typed enum, not a string: `kind: hnut` must not quietly become a
    // response playbook. The file lands in the catalog as parse_status=failed
    // and is not importable, which is the correct outcome for a typo in the
    // field that decides whether a document executes.
    let src = SERVICE_ACCOUNT_HUNT.replace("kind: hunt", "kind: hnut");
    assert!(split_frontmatter(&src).is_err());
}

// =============================================================================
// Step vocabulary
// =============================================================================

#[test]
fn an_action_step_disqualifies_a_hunt() {
    let src = SERVICE_ACCOUNT_HUNT.replace(
        "/lead: interactive logon by a machine-to-machine account",
        "/action: disable the account",
    );
    let err = draft_from(&src).expect_err("must refuse");
    assert!(matches!(
        err,
        HuntSpecError::ForbiddenStep { ref kind, .. } if kind == "action"
    ));
}

#[test]
fn a_decision_step_disqualifies_a_hunt() {
    let src = SERVICE_ACCOUNT_HUNT.replace(
        "/pivot: what the account did after the interactive session began",
        "/decision: is this expected",
    );
    let err = draft_from(&src).expect_err("must refuse");
    assert!(matches!(
        err,
        HuntSpecError::ForbiddenStep { ref kind, .. } if kind == "decision"
    ));
}

#[test]
fn a_hunt_with_no_data_step_is_refused() {
    let src = r#"---
kind: hunt
title: "Nothing to open with"
category: identity
---
# Nothing to open with

/lead: something
"#;
    assert_eq!(draft_from(src), Err(HuntSpecError::NoOpeningStep));
}

// =============================================================================
// Field validation
// =============================================================================

#[test]
fn defaults_match_the_hunt_specs_column_defaults() {
    let src = r#"---
kind: hunt
title: "Minimal"
category: identity
---
# Minimal

/query: everything
"#;
    let draft = draft_from(src).expect("parses");
    assert_eq!(draft.schedule_cron, None, "no schedule means manual-only");
    assert_eq!(draft.schedule_timezone, "UTC");
    assert_eq!(draft.lookback_window, "24h");
    assert!(draft.required_source_types.is_empty());
    assert_eq!(draft.budget.max_turns, 40);
    assert_eq!(draft.budget.max_tool_calls, 120);
    assert_eq!(draft.budget.max_rows, 5000);
    assert_eq!(draft.budget.max_wall_seconds, 900);
}

#[test]
fn a_malformed_cron_is_refused_at_import() {
    let src = SERVICE_ACCOUNT_HUNT.replace(r#"schedule: "0 3 * * *""#, r#"schedule: "every day""#);
    let err = draft_from(&src).expect_err("must refuse");
    assert!(matches!(err, HuntSpecError::InvalidSchedule { .. }));
}

#[test]
fn six_field_cron_is_accepted_too() {
    let src = SERVICE_ACCOUNT_HUNT.replace(r#"schedule: "0 3 * * *""#, r#"schedule: "0 0 3 * * *""#);
    let draft = draft_from(&src).expect("parses");
    assert_eq!(draft.schedule_cron.as_deref(), Some("0 0 3 * * *"));
}

#[test]
fn budget_beyond_the_ceiling_is_refused() {
    let src = SERVICE_ACCOUNT_HUNT.replace("max_wall_seconds: 600", "max_wall_seconds: 28800");
    let err = draft_from(&src).expect_err("must refuse");
    assert_eq!(
        err,
        HuntSpecError::BudgetTooLarge {
            field: "max_wall_seconds",
            value: 28_800,
            ceiling: MAX_BUDGET_WALL_SECONDS as i64,
        }
    );
}

#[test]
fn a_zero_budget_dimension_is_refused() {
    let src = SERVICE_ACCOUNT_HUNT.replace("max_rows: 4000", "max_rows: 0");
    assert_eq!(
        draft_from(&src),
        Err(HuntSpecError::BudgetNotPositive { field: "max_rows" })
    );
}

#[test]
fn a_partial_budget_block_takes_defaults_for_the_rest() {
    let src = SERVICE_ACCOUNT_HUNT.replace(
        "budget:\n  max_turns: 30\n  max_tool_calls: 90\n  max_rows: 4000\n  max_wall_seconds: 600",
        "budget:\n  max_turns: 12",
    );
    let draft = draft_from(&src).expect("parses");
    assert_eq!(draft.budget.max_turns, 12);
    assert_eq!(draft.budget.max_tool_calls, 120);
}

#[test]
fn lookback_accepts_minutes_hours_days_and_rejects_the_ambiguous_bare_number() {
    for (raw, expect) in [("45m", "45m"), ("6H", "6h"), ("7d", "7d")] {
        let src = SERVICE_ACCOUNT_HUNT.replace("lookback_window: 24h", &format!("lookback_window: {raw}"));
        assert_eq!(draft_from(&src).expect("parses").lookback_window, expect);
    }

    // Unitless is ambiguous — minutes elsewhere in the codebase, hours to
    // anyone reading `24h` on the line above. Refuse rather than guess.
    let src = SERVICE_ACCOUNT_HUNT.replace("lookback_window: 24h", "lookback_window: 24");
    assert_eq!(
        draft_from(&src),
        Err(HuntSpecError::InvalidLookback("24".to_string()))
    );
}

#[test]
fn a_multibyte_lookback_unit_is_refused_rather_than_panicking() {
    // Every string here comes out of a file the product did not write. A
    // byte-indexed split on the last character panics when that character is
    // multi-byte, which turns a typo in a merged markdown file into a downed
    // import path.
    for junk in ["24µ", "24日", "π", "24 h", ""] {
        let src = SERVICE_ACCOUNT_HUNT.replace(
            "lookback_window: 24h",
            &format!("lookback_window: \"{junk}\""),
        );
        // Empty falls back to the default; everything else is a clean refusal.
        // Neither may panic.
        let outcome = draft_from(&src);
        if junk.is_empty() {
            assert_eq!(outcome.expect("parses").lookback_window, "24h");
        } else {
            assert!(
                matches!(outcome, Err(HuntSpecError::InvalidLookback(_))),
                "`{junk}` should be refused, got {outcome:?}"
            );
        }
    }
}

#[test]
fn a_quarter_long_lookback_is_refused() {
    let src = SERVICE_ACCOUNT_HUNT.replace("lookback_window: 24h", "lookback_window: 90d");
    assert_eq!(
        draft_from(&src),
        Err(HuntSpecError::LookbackTooLong("90d".to_string(), 30))
    );
}

#[test]
fn source_types_are_normalized_and_deduped() {
    let src = SERVICE_ACCOUNT_HUNT.replace(
        "required_source_types:\n  - windows_security",
        "required_source_types:\n  - Windows_Security\n  - windows_security\n  - squid-proxy",
    );
    let draft = draft_from(&src).expect("parses");
    assert_eq!(
        draft.required_source_types,
        vec!["windows_security", "squid-proxy"]
    );
}

#[test]
fn a_source_type_with_sql_shaped_punctuation_is_refused() {
    let src = SERVICE_ACCOUNT_HUNT.replace(
        "  - windows_security",
        "  - \"windows_security'; DROP TABLE hunt_specs--\"",
    );
    let err = draft_from(&src).expect_err("must refuse");
    assert!(matches!(err, HuntSpecError::InvalidSourceType(_)));
}

#[test]
fn technique_ids_are_uppercased_and_shape_checked() {
    let src = SERVICE_ACCOUNT_HUNT.replace("mitre_technique: T1078.002", "mitre_technique: t1078.002");
    assert_eq!(
        draft_from(&src).expect("parses").mitre_technique.as_deref(),
        Some("T1078.002")
    );

    let src = SERVICE_ACCOUNT_HUNT.replace("mitre_technique: T1078.002", "mitre_technique: lateral movement");
    assert!(matches!(
        draft_from(&src).expect_err("must refuse"),
        HuntSpecError::InvalidTechnique(_)
    ));
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for query manipulation, including the NAN-704 audit-visibility gate.

use std::collections::BTreeSet;

use super::*;
use crate::query::{parse_query, PrettyPrint};

// ---------------------------------------------------------------------------
// Scope-gate oracle (NAN-1794 audit gate, generalized for NAN-1799 deny sets)
// ---------------------------------------------------------------------------

/// True when `expr` is exactly the mandatory audit-gate conjunct.
fn is_gate(expr: &SearchExpr, excluded: &str) -> bool {
    matches!(
        expr,
        SearchExpr::FieldFilter {
            field,
            op: Comparator::Ne,
            value: Value::String(s),
        } if field.eq_ignore_ascii_case("source_type") && s.eq_ignore_ascii_case(excluded)
    )
}

/// True when `expr` is exactly the mandatory scope-gate conjunct for `deny`.
///
/// Mirrors the two emitted shapes of `mandatory_exclusion`:
///  * `{"audit"}` exactly → the legacy `source_type != "audit"` FieldFilter.
///  * anything else → `InList { field: "source_type", negated: true }` whose
///    string values are set-equal to `deny`.
fn is_scope_gate(expr: &SearchExpr, deny: &BTreeSet<String>) -> bool {
    if deny.len() == 1 && deny.contains("audit") {
        return is_gate(expr, "audit");
    }
    match expr {
        SearchExpr::InList {
            field,
            values,
            negated: true,
        } if field.eq_ignore_ascii_case("source_type") => {
            let got: BTreeSet<String> = values
                .iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect();
            // Every value must be a string AND the set must match exactly —
            // a superset or subset is NOT the injected gate.
            got.len() == values.len() && got == *deny
        }
        _ => false,
    }
}

/// Sound structural oracle for "denied-source rows cannot be read".
///
/// Every base-table scan in the tree — the main query's `Search` leaf AND the
/// `Search` leaf of every subsearch at any depth (join / append / IN-subsearch,
/// including subsearches nested inside `where` / `transaction` / `sequence` /
/// `funnel` conditions) — must carry the mandatory exclusion conjunct
/// (`source_type != "audit"` or `source_type NOT IN (…)`) ANDed at its TOP
/// level.
///
/// This is a *proof*, not a heuristic: `X AND source_type NOT IN (D)` cannot
/// match a row of any source in `D` for ANY `X`, however the user wrote `X`
/// (negation, OR, nested groups…). Checking the top-level AND therefore
/// establishes exclusion without needing a row evaluator. Conversely, a gate
/// merely *mentioned* somewhere inside `X` proves nothing — which is exactly
/// the NAN-1794 bug class.
fn assert_scope_gate_on_every_scan(query: &Query, deny: &BTreeSet<String>, ctx: &str) {
    match query {
        Query::Search(expr) => {
            match expr {
                SearchExpr::And(left, right) if is_scope_gate(right, deny) => {
                    // Gate correctly ANDed at top level. Keep walking the user's
                    // side for subsearches it may carry.
                    assert_expr_subsearches_gated(left, deny, ctx);
                }
                other => panic!(
                    "SCOPE LEAK [{ctx}]: scan is not top-level-ANDed with the \
                     mandatory exclusion of {deny:?}; denied-source rows are \
                     reachable. Got: {other:?}"
                ),
            }
        }
        Query::Piped { source, command } => {
            assert_scope_gate_on_every_scan(source, deny, ctx);
            assert_command_subsearches_gated(command, deny, ctx);
        }
    }
}

/// Audit-flavored wrapper kept so the NAN-1794 tests read unchanged.
fn assert_audit_gate_on_every_scan(query: &Query, excluded: &str, ctx: &str) {
    assert_scope_gate_on_every_scan(query, &BTreeSet::from([excluded.to_string()]), ctx);
}

/// Walk a `SearchExpr` and assert every `InSubsearch` it carries is gated.
fn assert_expr_subsearches_gated(expr: &SearchExpr, deny: &BTreeSet<String>, ctx: &str) {
    match expr {
        SearchExpr::InSubsearch { subsearch, .. } => {
            assert_scope_gate_on_every_scan(subsearch, deny, &format!("{ctx} > IN-subsearch"));
        }
        SearchExpr::And(l, r) | SearchExpr::Or(l, r) => {
            assert_expr_subsearches_gated(l, deny, ctx);
            assert_expr_subsearches_gated(r, deny, ctx);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            assert_expr_subsearches_gated(inner, deny, ctx)
        }
        _ => {}
    }
}

/// Walk a `Command` and assert every subsearch it carries is gated.
fn assert_command_subsearches_gated(command: &Command, deny: &BTreeSet<String>, ctx: &str) {
    match command {
        Command::Join { subsearch, .. } => {
            assert_scope_gate_on_every_scan(subsearch, deny, &format!("{ctx} > join"))
        }
        Command::Append { subsearch, .. } => {
            assert_scope_gate_on_every_scan(subsearch, deny, &format!("{ctx} > append"))
        }
        Command::Where { condition } => {
            assert_expr_subsearches_gated(condition, deny, &format!("{ctx} > where"))
        }
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            if let Some(e) = startswith {
                assert_expr_subsearches_gated(e, deny, &format!("{ctx} > transaction"));
            }
            if let Some(e) = endswith {
                assert_expr_subsearches_gated(e, deny, &format!("{ctx} > transaction"));
            }
        }
        Command::Sequence { conditions, .. } => {
            for c in conditions {
                assert_expr_subsearches_gated(c, deny, &format!("{ctx} > sequence"));
            }
        }
        Command::Funnel { steps, .. } => {
            for (_, c) in steps {
                assert_expr_subsearches_gated(c, deny, &format!("{ctx} > funnel"));
            }
        }
        _ => {}
    }
}

/// Run the malicious nPL through the REAL enforcement path used by every
/// authenticated search surface, and prove audit rows are unreachable.
fn assert_npl_is_audit_gated(npl: &str) {
    let parsed = parse_query(npl).unwrap_or_else(|e| panic!("test nPL must parse: {npl} -> {e:?}"));
    let enforced = enforce_source_type_exclusion(&parsed, "audit");
    assert_audit_gate_on_every_scan(&enforced, "audit", npl);

    // The handler-facing wrapper is string-in/string-out: the enforced AST is
    // pretty-printed and re-parsed downstream. Prove the gate SURVIVES that
    // round-trip — a gate that pretty_print drops is no gate at all.
    let rewritten = enforce_non_audit_query(npl).unwrap_or_else(|e| panic!("{npl} -> {e:?}"));
    let reparsed = parse_query(&rewritten)
        .unwrap_or_else(|e| panic!("enforced query must re-parse: {rewritten} -> {e:?}"));
    assert_audit_gate_on_every_scan(&reparsed, "audit", &format!("{npl} (after round-trip)"));
}

// ---------------------------------------------------------------------------
// NAN-1794 bypass 1: presence-check defeated by negation / OR-embedding
// ---------------------------------------------------------------------------

/// `NOT (source_type != "audit")` is semantically `source_type == "audit"`, but
/// the old presence check walked into the `Not` and saw the exclusion term, so
/// it suppressed injection entirely.
#[test]
fn test_audit_gate_not_bypassed_by_negated_exclusion() {
    assert_npl_is_audit_gated(r#"NOT (source_type != "audit")"#);
}

/// Same trick without the parens/quotes the parser tolerates.
#[test]
fn test_audit_gate_not_bypassed_by_negated_exclusion_unquoted() {
    assert_npl_is_audit_gated("NOT (source_type != audit)");
}

/// OR-embedding: the presence check was satisfied by the LEFT arm, so nothing
/// was injected — and the RIGHT arm happily selects audit rows.
#[test]
fn test_audit_gate_not_bypassed_by_or_embedded_exclusion() {
    assert_npl_is_audit_gated(r#"source_type!="audit" OR source_type="audit""#);
}

/// The exclusion buried in an OR arm alongside an unrelated term.
#[test]
fn test_audit_gate_not_bypassed_by_or_arm_mention() {
    assert_npl_is_audit_gated(r#"source_type="audit" OR (status=500 AND source_type!="audit")"#);
}

/// Plain OR with a non-source_type term. (This form was ALREADY gated — the old
/// presence check only matched a `!=` node — but pin it so a future
/// "optimization" cannot regress it.)
#[test]
fn test_audit_gate_or_with_unrelated_term() {
    assert_npl_is_audit_gated(r#"source_type="audit" OR status=500"#);
}

/// Raw-string variants the parser accepts: case, quoting and whitespace must
/// not change the outcome.
#[test]
fn test_audit_gate_raw_string_variants() {
    for npl in [
        r#"source_type="audit""#,
        "source_type=audit",
        r#"SOURCE_TYPE = "AUDIT""#,
        r#"source_type   !=    "audit""#,
        "NOT source_type != audit",
        r#"NOT (NOT (source_type = "audit"))"#,
    ] {
        assert_npl_is_audit_gated(npl);
    }
}

// ---------------------------------------------------------------------------
// NAN-1794 bypass 2: subsearches were never walked
// ---------------------------------------------------------------------------

#[test]
fn test_audit_gate_applies_to_join_subsearch() {
    assert_npl_is_audit_gated(r#"error | join type=inner user [search source_type="audit"]"#);
}

#[test]
fn test_audit_gate_applies_to_append_subsearch() {
    assert_npl_is_audit_gated(r#"error | append [search source_type="audit"]"#);
}

#[test]
fn test_audit_gate_applies_to_in_subsearch() {
    assert_npl_is_audit_gated(r#"user IN [search source_type="audit" | return user]"#);
}

/// An IN-subsearch nested inside a `| where` condition — the `where` arm of the
/// AST that the original walker never even reached.
#[test]
fn test_audit_gate_applies_to_in_subsearch_inside_where() {
    assert_npl_is_audit_gated(
        r#"error | where user IN [search source_type="audit" | return user]"#,
    );
}

/// Depth: a subsearch inside a subsearch. The walker must recurse, not just
/// peek one level down.
#[test]
fn test_audit_gate_applies_to_nested_subsearches() {
    assert_npl_is_audit_gated(
        r#"error | append [search error | join user [search source_type="audit"]]"#,
    );
}

/// Combined: both bypasses at once, subsearch using the negation trick.
#[test]
fn test_audit_gate_applies_to_negated_exclusion_inside_subsearch() {
    assert_npl_is_audit_gated(r#"error | append [search NOT (source_type != "audit")]"#);
}

// ---------------------------------------------------------------------------
// Non-audit queries must be unaffected (no behavior change)
// ---------------------------------------------------------------------------

/// A normal analyst query keeps ALL of its own semantics; enforcement only ANDs
/// the gate onto the scan.
#[test]
fn test_ordinary_query_semantics_preserved() {
    let parsed = parse_query("error | stats count by src_ip | sort -count | head 10").unwrap();
    let enforced = enforce_source_type_exclusion(&parsed, "audit");
    assert_audit_gate_on_every_scan(&enforced, "audit", "ordinary");

    // The pipeline is untouched: same commands, same order.
    let cmds = |q: &Query| {
        let mut out = vec![];
        let mut cur = q;
        while let Query::Piped { source, command } = cur {
            out.push(format!("{command:?}"));
            cur = source;
        }
        out.reverse();
        out
    };
    assert_eq!(
        cmds(&parsed),
        cmds(&enforced),
        "enforcement must not alter the command pipeline"
    );

    // The user's own search term survives inside the gated group.
    let out = enforce_non_audit_query("error | stats count by src_ip").unwrap();
    assert!(out.contains("error"), "user term dropped: {out}");
    assert!(out.contains("by src_ip"), "pipeline dropped: {out}");
}

/// A legitimate non-audit subsearch keeps working — the gate is added, the
/// subsearch's own predicate is preserved.
#[test]
fn test_legitimate_subsearch_preserved() {
    let npl = r#"source_type=windows_sysmon | join user [search source_type=windows_event]"#;
    assert_npl_is_audit_gated(npl);
    let out = enforce_non_audit_query(npl).unwrap();
    assert!(
        out.contains("windows_event"),
        "subsearch predicate dropped: {out}"
    );
    assert!(
        out.contains("windows_sysmon"),
        "main predicate dropped: {out}"
    );
}

/// A user who legitimately writes the exclusion themselves still gets a correct
/// (idempotent) query — double-gating is semantically identical, and the shape
/// stays parseable.
#[test]
fn test_user_written_exclusion_is_idempotent_and_safe() {
    assert_npl_is_audit_gated(r#"source_type!="audit" AND error"#);
}

// ---------------------------------------------------------------------------
// Existing NAN-704 / NAN-1453 coverage (moved from the inline module)
// ---------------------------------------------------------------------------

// NAN-1453: non-audit-view users have their query rewritten by
// `enforce_non_audit_query`, which round-trips through parse + pretty-print.
// That path strips `earliest=`/`latest=`; these tests pin that the rewrite
// re-attaches the analyst's time window so it isn't silently lost.
#[test]
fn test_enforce_non_audit_query_preserves_earliest() {
    let out = enforce_non_audit_query("actor.user.name=\"mmoore\" earliest=-12h").unwrap();
    assert!(
        out.contains("source_type!=\"audit\""),
        "audit exclusion missing: {out}"
    );
    assert!(out.contains("earliest=-12h"), "earliest= dropped: {out}");
}

#[test]
fn test_enforce_non_audit_query_preserves_earliest_and_latest() {
    let out = enforce_non_audit_query("error earliest=-1h latest=now").unwrap();
    assert!(out.contains("source_type!=\"audit\""), "{out}");
    assert!(out.contains("earliest=-1h"), "earliest= dropped: {out}");
    assert!(out.contains("latest=now"), "latest= dropped: {out}");
}

#[test]
fn test_enforce_non_audit_query_preserves_modifiers_with_pipe() {
    let out = enforce_non_audit_query("error earliest=-12h | stats count").unwrap();
    assert!(out.contains("source_type!=\"audit\""), "{out}");
    assert!(out.contains("earliest=-12h"), "earliest= dropped: {out}");
    assert!(out.contains("stats count"), "pipe command dropped: {out}");
}

#[test]
fn test_enforce_non_audit_query_no_modifiers_unchanged() {
    // No earliest=/latest= → exactly the bare exclusion, no trailing tokens.
    let out = enforce_non_audit_query("error").unwrap();
    assert!(out.contains("source_type!=\"audit\""), "{out}");
    assert!(!out.contains("earliest"), "spurious earliest=: {out}");
    assert!(!out.contains("latest"), "spurious latest=: {out}");
}

#[test]
fn test_strip_post_prevalence_commands() {
    // Query with commands after prevalence enrich should have them stripped
    let query = parse_query("error | prevalence enrich=true | head 10").unwrap();
    let stripped = strip_post_prevalence_commands(&query);

    // The stripped query should only go up to prevalence
    match stripped {
        Query::Piped { source, command } => {
            assert!(matches!(*source, Query::Search(_)));
            assert!(matches!(command, Command::Prevalence { enrich: true, .. }));
        }
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_strip_prevalence_and_after() {
    // Query with prevalence should have it and everything after stripped
    let query = parse_query("error | prevalence hash_prevalence < 5 | head 10").unwrap();
    let stripped = strip_prevalence_and_after(&query);

    // The stripped query should only be the base search
    match stripped {
        Query::Search(_) => {} // Success
        _ => panic!("Expected Search query, got Piped"),
    }
}

#[test]
fn test_strip_prevalence_keeps_commands_before() {
    // Commands before prevalence should be kept
    let query = parse_query("error | head 100 | prevalence enrich=true | tail 10").unwrap();
    let stripped = strip_post_prevalence_commands(&query);

    // Should keep head and prevalence, but not tail
    let mut found_head = false;
    let mut found_prevalence = false;

    let mut current = &stripped;
    loop {
        match current {
            Query::Search(_) => break,
            Query::Piped { source, command } => {
                if matches!(command, Command::Head { count: _ }) {
                    found_head = true;
                }
                if matches!(command, Command::Prevalence { enrich: true, .. }) {
                    found_prevalence = true;
                }
                current = source;
            }
        }
    }

    assert!(found_head, "Should keep head command before prevalence");
    assert!(found_prevalence, "Should keep prevalence command");
}

#[test]
fn test_strip_ai_and_after() {
    let query =
        parse_query(r#"error | head 10 | ai prompt="Classify" | where ai_verdict="TP""#).unwrap();
    let stripped = strip_ai_and_after(&query);

    // Should keep "error | head 10" — ai and where both stripped
    match stripped {
        Query::Piped { source, command } => {
            assert!(matches!(command, Command::Head { count: 10 }));
            assert!(matches!(*source, Query::Search(_)));
        }
        _ => panic!("Expected Piped query with Head"),
    }
}

#[test]
fn test_strip_ai_reinjects_table_fields() {
    // | table after | ai should be re-injected with only database fields
    let query =
        parse_query(r#"error | ai prompt="Classify" | table timestamp, url, ai_verdict"#).unwrap();
    let stripped = strip_ai_and_after(&query);

    // Should be: error | table timestamp, url  (ai_verdict filtered out)
    match &stripped {
        Query::Piped { command, source } => {
            if let Command::Table { fields } = command {
                let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
                assert!(names.contains(&"timestamp"), "Should keep timestamp");
                assert!(names.contains(&"url"), "Should keep url");
                assert!(
                    !names.contains(&"ai_verdict"),
                    "Should filter out ai_verdict"
                );
            } else {
                panic!("Expected Table command, got {:?}", command);
            }
            assert!(matches!(source.as_ref(), Query::Search(_)));
        }
        _ => panic!("Expected Piped query with Table"),
    }
}

#[test]
fn test_strip_ai_keeps_commands_before() {
    let query = parse_query(r#"error | stats count by src_ip | ai prompt="Classify""#).unwrap();
    let stripped = strip_ai_and_after(&query);

    match stripped {
        Query::Piped { command, .. } => {
            assert!(matches!(command, Command::Stats { .. }));
        }
        _ => panic!("Expected Piped query with Stats"),
    }
}

#[test]
fn test_enforce_source_type_exclusion_wraps_or_queries() {
    let parsed = parse_query(r#"source_type="audit" OR user="alice""#).unwrap();
    let rewritten = enforce_source_type_exclusion(&parsed, "audit");

    match rewritten {
        Query::Search(SearchExpr::And(_, right)) => match right.as_ref() {
            SearchExpr::FieldFilter { field, op, value } => {
                assert_eq!(field, "source_type");
                assert_eq!(*op, Comparator::Ne);
                assert_eq!(value, &Value::String("audit".to_string()));
            }
            other => panic!("Expected source_type exclusion filter, got {:?}", other),
        },
        other => panic!("Expected top-level AND after enforcement, got {:?}", other),
    }
}

/// NAN-704: the public string-in / string-out wrapper is what every
/// authenticated search surface (search handler, streaming handler,
/// dashboard panel handler) calls. Confirms the rewrite injects the
/// `source_type != "audit"` clause and survives the round-trip
/// through `pretty_print` so the rewritten string can feed back into
/// the search service.
#[test]
fn test_enforce_non_audit_query_injects_exclusion() {
    let original = r#"source_type="audit" OR user="alice""#;
    let rewritten = enforce_non_audit_query(original).expect("rewrite should succeed");
    assert!(
        rewritten.contains("source_type") && rewritten.contains("audit"),
        "rewritten query should still mention source_type/audit (as exclusion): {}",
        rewritten
    );
    // Round-trip: the rewritten string must itself parse cleanly.
    let _ = parse_query(&rewritten).expect("rewritten query must re-parse");
}

#[test]
fn test_enforce_non_audit_query_rejects_unparseable_input() {
    let result = enforce_non_audit_query("| | invalid");
    assert!(
        result.is_err(),
        "unparseable query should return Err, not silently pass through"
    );
}

// ---------------------------------------------------------------------------
// NAN-1799: deny-SET generalization (per-source RBAC scoping)
// ---------------------------------------------------------------------------

fn deny(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// Run the nPL through the REAL deny-set enforcement path and prove every scan
/// is gated — both on the freshly injected AST and after the string round-trip
/// (pretty_print → reparse) every handler performs.
fn assert_npl_is_scope_gated(npl: &str, deny_set: &BTreeSet<String>) {
    let parsed = parse_query(npl).unwrap_or_else(|e| panic!("test nPL must parse: {npl} -> {e:?}"));
    let enforced = inject_source_type_exclusion_recursive(&parsed, deny_set);
    assert_scope_gate_on_every_scan(&enforced, deny_set, npl);

    let rewritten =
        enforce_source_scope(npl, deny_set).unwrap_or_else(|e| panic!("{npl} -> {e:?}"));
    let reparsed = parse_query(&rewritten)
        .unwrap_or_else(|e| panic!("enforced query must re-parse: {rewritten} -> {e:?}"));
    assert_scope_gate_on_every_scan(&reparsed, deny_set, &format!("{npl} (after round-trip)"));
}

/// A multi-member deny set must be injected at EVERY scan — main search, join,
/// append, IN-subsearch, subsearches nested inside `where`, nested
/// subsearch-in-subsearch, and the NAN-1794 crafted-bypass forms.
#[test]
fn test_scope_gate_multi_member_on_every_scan() {
    let deny_set = deny(&["audit", "insider"]);
    for npl in [
        "error",
        "error | stats count by src_ip | sort -count | head 10",
        r#"error | join type=inner user [search source_type="audit"]"#,
        r#"error | append [search source_type="insider"]"#,
        r#"user IN [search source_type="audit" | return user]"#,
        r#"error | where user IN [search source_type="insider" | return user]"#,
        r#"error | append [search error | join user [search source_type="audit"]]"#,
        r#"NOT (source_type != "insider")"#,
        r#"source_type!="audit" OR source_type="insider""#,
    ] {
        assert_npl_is_scope_gated(npl, &deny_set);
    }
}

/// A single-member NON-audit deny set also takes the `NOT IN` form (only
/// `{"audit"}` exactly gets the legacy `!=` shape).
#[test]
fn test_scope_gate_single_non_audit_member_uses_not_in() {
    let deny_set = deny(&["insider"]);
    assert_npl_is_scope_gated("error | stats count", &deny_set);
    let out = enforce_source_scope("error", &deny_set).unwrap();
    assert!(
        out.contains(r#"source_type NOT IN ("insider")"#),
        "single non-audit member must render as NOT IN: {out}"
    );
}

/// The rendered text for a multi-member set is `source_type NOT IN (…)`, with
/// values in deterministic sorted order regardless of insertion order.
#[test]
fn test_scope_gate_multi_member_renders_sorted_not_in() {
    // Insertion order deliberately reversed — BTreeSet sorts.
    let deny_set = deny(&["insider", "audit"]);
    let out = enforce_source_scope("error", &deny_set).unwrap();
    assert!(
        out.contains(r#"source_type NOT IN ("audit", "insider")"#),
        "multi-member gate must render sorted NOT IN: {out}"
    );
}

// ---------------------------------------------------------------------------
// NAN-2006: pretty_print -> re-parse round-trip authorization bypass
// (Cluster A — F1, F2, F4, F5, F6, F7, F9)
// ---------------------------------------------------------------------------

/// For any attacker-crafted query the enforcement path has only two acceptable
/// outcomes: the mandatory exclusion survives on EVERY scan, or the query is
/// refused (fail-closed). It must NEVER return an `Ok` string that re-parses
/// with a scan the exclusion no longer covers. Cross-checked with the
/// independent `assert_scope_gate_on_every_scan` oracle (not the production
/// verifier), so it genuinely validates the fix rather than restating it.
fn assert_no_scope_leak(payload: &str, deny_set: &BTreeSet<String>) {
    match enforce_source_scope(payload, deny_set) {
        Ok(enforced) => {
            let reparsed = parse_query(&enforced).unwrap_or_else(|e| {
                panic!("enforced query claimed OK but does not re-parse: {enforced} -> {e:?}")
            });
            assert_scope_gate_on_every_scan(&reparsed, deny_set, payload);
        }
        // Fail-closed refusal is a safe outcome: no query runs, nothing leaks.
        Err(_) => {}
    }
}

/// Every F1–F9 breakout payload — a crafted keyword / quoted field name / rex
/// pattern / where-clause that historically re-parsed `source_type=audit` (or an
/// ungated `| append` subsearch) into a position the injected exclusion no
/// longer covered — must be unable to read denied sources, under BOTH the audit
/// deny set and multi-source RBAC deny sets.
#[test]
fn test_nan2006_breakout_payloads_cannot_leak_denied_sources() {
    let payloads = [
        // F1 / F7: single-quoted keyword, quote+paren breakout to a top-level OR arm.
        r#"'x") OR source_type=audit OR ("y'"#,
        // F2: keyword with zero-space `||` OR breakout.
        r#"'x)||source_type=audit||(y'"#,
        // F7: quoted keyword that re-tokenizes into `(*)||(*)`.
        r#""*)||(*""#,
        // F4: quoted-string field name carrying a full OR breakout.
        r#"'src_ip=1) OR source_type=audit OR (user'=1"#,
        // F5 / F9: rex pattern that closes its quote and injects an ungated append.
        r#"error | rex field=message 'x" | append [ source_type="audit" ] | eval k="z'"#,
        // F6: where-clause keyword injecting an ungated append.
        r#"error | where 'x" | append [ source_type="audit" ] | eval k="z'"#,
        // F9 variant: rex with a bracketed append subsearch.
        r#"error | rex field=message '(?<x>.)" | append [search source_type="audit"] junk="'"#,
    ];
    for payload in payloads {
        assert_no_scope_leak(payload, &deny(&["audit"]));
        assert_no_scope_leak(payload, &deny(&["audit", "insider"]));
        assert_no_scope_leak(payload, &deny(&["hr_edr", "windows_dns"]));
    }
}

/// The serialization hardening must not over-reject: legitimate queries whose
/// values / patterns contain characters that are INERT inside a double-quoted
/// literal (`|`, `\`, `'`, parens) still run, gated, rather than being refused.
#[test]
fn test_nan2006_benign_special_chars_still_run_gated() {
    let deny_set = deny(&["audit"]);
    for npl in [
        r#"command_line="a|b|c""#,
        r#"file_path="C:\Windows\System32""#,
        r#"user="O'Connor""#,
        r#"error | rex field=message "(foo|bar)baz""#,
        r#"error | eval msg="a|b" | stats count"#,
    ] {
        assert_npl_is_scope_gated(npl, &deny_set);
    }
}

/// AC3 (NAN-2006): for adversarial inputs, the exact round-trip every handler
/// performs — `parse(pretty_print(inject(parse(x))))` — still carries the
/// top-level source_type guard on every scan.
#[test]
fn test_nan2006_round_trip_preserves_top_level_guard() {
    let deny_set = deny(&["audit"]);
    for payload in [
        r#"'x") OR source_type=audit OR ("y'"#,
        r#"error | rex field=message 'a" | append [ source_type="audit" ]'"#,
    ] {
        let parsed = match parse_query(payload) {
            Ok(p) => p,
            Err(_) => continue, // unparseable input is refused upstream
        };
        let printed = inject_source_type_exclusion_recursive(&parsed, &deny_set).pretty_print();
        let reparsed = parse_query(&printed)
            .unwrap_or_else(|e| panic!("pretty_print output must re-parse: {printed} -> {e:?}"));
        assert_scope_gate_on_every_scan(&reparsed, &deny_set, payload);
    }
}

/// `{"audit"}` exactly must be byte-identical to the legacy audit gate — every
/// existing caller routes through the same path, so any drift here is a
/// regression on NAN-704 / NAN-1453 / NAN-1794 behavior.
#[test]
fn test_scope_gate_pure_audit_byte_identical_to_legacy() {
    let audit = deny(&["audit"]);
    for npl in [
        "error",
        r#"source_type="audit" OR user="alice""#,
        "error earliest=-1h latest=now",
        "error earliest=-12h | stats count",
        r#"error | append [search NOT (source_type != "audit")]"#,
    ] {
        let via_scope = enforce_source_scope(npl, &audit).unwrap();
        let via_legacy = enforce_non_audit_query(npl).unwrap();
        assert_eq!(
            via_scope, via_legacy,
            "deny_set {{\"audit\"}} must be byte-identical to enforce_non_audit_query: {npl}"
        );
        assert!(
            via_scope.contains("source_type!=\"audit\""),
            "pure-audit case must keep the legacy != form: {via_scope}"
        );
        assert!(
            !via_scope.contains("NOT IN"),
            "pure-audit case must NOT switch to NOT IN: {via_scope}"
        );
    }
}

/// An EMPTY deny set returns the input verbatim — byte-identical, including
/// formatting quirks and time modifiers. This is the zero-restricted-sources
/// back-compat guarantee: unrestricted users' queries are not even reparsed.
#[test]
fn test_scope_gate_empty_deny_set_returns_input_verbatim() {
    let empty = BTreeSet::new();
    for npl in [
        "error",
        "error   |   stats   count by src_ip",
        "error earliest=-12h | stats count",
        r#"source_type="audit""#,
        r#"error | join user [search source_type="audit"]"#,
    ] {
        let out = enforce_source_scope(npl, &empty).unwrap();
        assert_eq!(
            out, npl,
            "empty deny set must return the query byte-identical"
        );
    }
}

/// Double application is safe: the second pass re-gates the already-gated
/// query, the result still parses, and every scan still carries the gate at
/// top level. (Semantically `X AND g AND g` ≡ `X AND g`.)
#[test]
fn test_scope_gate_idempotent_double_application() {
    let deny_set = deny(&["audit", "insider"]);
    let npl = r#"error | append [search source_type="insider"]"#;

    let once = enforce_source_scope(npl, &deny_set).unwrap();
    let twice = enforce_source_scope(&once, &deny_set).unwrap();
    let reparsed = parse_query(&twice)
        .unwrap_or_else(|e| panic!("double-enforced query must re-parse: {twice} -> {e:?}"));
    assert_scope_gate_on_every_scan(&reparsed, &deny_set, "double application");
}

/// NAN-1453 parity for the deny-set path: `earliest=`/`latest=` survive the
/// parse → inject → pretty-print rewrite.
#[test]
fn test_scope_gate_preserves_time_modifiers() {
    let deny_set = deny(&["audit", "insider"]);
    let out = enforce_source_scope("error earliest=-12h latest=now | stats count", &deny_set)
        .unwrap();
    assert!(out.contains("source_type NOT IN"), "{out}");
    assert!(out.contains("earliest=-12h"), "earliest= dropped: {out}");
    assert!(out.contains("latest=now"), "latest= dropped: {out}");
    assert!(out.contains("stats count"), "pipe command dropped: {out}");
}

/// Non-empty deny set + unparseable input → Err, never a silent pass-through.
/// (Contrast with the empty-set fast path, which returns the input untouched
/// for the parser downstream to reject.)
#[test]
fn test_scope_gate_rejects_unparseable_input_when_restricted() {
    let result = enforce_source_scope("| | invalid", &deny(&["audit", "insider"]));
    assert!(
        result.is_err(),
        "unparseable query should return Err when a deny set is in force"
    );
}

/// A user's own `source_type NOT IN (…)` mention must NOT satisfy the oracle
/// or suppress injection — same structural rule as the NAN-1794 audit gate.
#[test]
fn test_scope_gate_not_bypassed_by_user_written_not_in() {
    let deny_set = deny(&["audit", "insider"]);
    for npl in [
        r#"NOT (source_type NOT IN ("audit", "insider"))"#,
        r#"source_type NOT IN ("audit", "insider") OR source_type="audit""#,
        // Superset / subset mentions must not be mistaken for the gate either.
        r#"source_type NOT IN ("audit") OR error"#,
        r#"source_type NOT IN ("audit", "insider", "other") OR error"#,
    ] {
        assert_npl_is_scope_gated(npl, &deny_set);
    }
}

/// The pipeline and user predicates survive deny-set enforcement untouched.
#[test]
fn test_scope_gate_preserves_query_semantics() {
    let deny_set = deny(&["audit", "insider"]);
    let out = enforce_source_scope(
        r#"source_type=windows_sysmon | join user [search source_type=windows_event] | stats count by src_ip"#,
        &deny_set,
    )
    .unwrap();
    assert!(out.contains("windows_sysmon"), "main predicate dropped: {out}");
    assert!(out.contains("windows_event"), "subsearch predicate dropped: {out}");
    assert!(out.contains("by src_ip"), "pipeline dropped: {out}");
}

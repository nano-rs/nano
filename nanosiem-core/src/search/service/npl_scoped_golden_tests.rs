// SPDX-License-Identifier: AGPL-3.0-or-later
//! Source-scoped pass over Group A's golden corpus and injection canary
//! (security review 2026-11-08, Group C).
//!
//! The unscoped pass (`npl_golden_corpus_tests`) proves legitimate SQL is
//! byte-identical. This pass renders the same corpus as a LOW-PRIVILEGE analyst
//! (denied `hr_payroll` + `legal_hold`, no `audit:view`) and proves:
//!
//! 1. every query the unscoped pass renders also renders scoped — the
//!    source-scope gate no longer rejects queries its pretty-printer cannot
//!    round-trip (NAN-5021);
//! 2. every scoped rendering carries the deny gate;
//! 3. the SQL shown to that analyst (`DisplaySql`) never names a denied
//!    source (NAN-5043);
//! 4. the injection canary still holds with the gate injected.

use std::collections::BTreeSet;

use super::npl_golden_corpus_tests::{load_corpus, render, render_corpus, sql_only_service, PROFILES};
use super::npl_injection_canary_tests::{assert_canary_safe, CASES, PAYLOADS};
use crate::auth::{compose_viewer_scope, ScopeSet};
use crate::search::display_sql::DisplaySql;

fn analyst() -> ScopeSet {
    compose_viewer_scope(
        &ScopeSet::from_denied(BTreeSet::from([
            "hr_payroll".to_string(),
            "legal_hold".to_string(),
        ])),
        false,
    )
}

#[tokio::test]
async fn scoped_corpus_renders_gated_and_never_shows_denied_names() {
    let corpus = load_corpus();
    let unscoped = render_corpus(&corpus, &ScopeSet::unrestricted()).await;
    let scope = analyst();
    let scoped = render_corpus(&corpus, &scope).await;
    assert_eq!(unscoped.len(), scoped.len());

    let mut newly_rejected = Vec::new();
    let mut ungated = Vec::new();
    let mut leaked = Vec::new();
    for (u, s) in unscoped.iter().zip(&scoped) {
        let q = &corpus[s.index].q;
        if s.sql.starts_with("ERR:") {
            if !u.sql.starts_with("ERR:") {
                newly_rejected.push(format!("[{} #{}] {q} => {}", s.profile, s.index, s.sql));
            }
            continue;
        }
        // Spans/metrics datasets strip the gate by design (no source_type).
        let dataset_query = q.contains("dataset=");
        if !dataset_query && !s.sql.contains("'hr_payroll'") {
            ungated.push(format!("[{} #{}] {q}", s.profile, s.index));
        }
        let shown = DisplaySql::for_scope(s.sql.clone(), &scope);
        if shown.as_str().contains("hr_payroll") || shown.as_str().contains("legal_hold") {
            leaked.push(format!("[{} #{}] {q}", s.profile, s.index));
        }
    }
    assert!(
        newly_rejected.is_empty(),
        "{} corpus queries render unscoped but are refused for a scoped analyst:\n{}",
        newly_rejected.len(),
        newly_rejected.join("\n")
    );
    assert!(ungated.is_empty(), "scoped SQL without the gate:\n{}", ungated.join("\n"));
    assert!(leaked.is_empty(), "shown SQL names a denied source:\n{}", leaked.join("\n"));
}

#[tokio::test]
async fn the_injection_canary_holds_with_the_scope_gate_injected() {
    let scope = analyst();
    for profile in PROFILES {
        let svc = sql_only_service(profile);
        for template in CASES {
            let benign_sql = render(&svc, &template.replace("{N}", "QZXCbenign").replace("{S}", "QZXCbenign"), &scope).await;
            for payload in PAYLOADS {
                let query = template.replace("{N}", payload).replace("{S}", payload);
                let hostile_sql = render(&svc, &query, &scope).await;
                assert_canary_safe(
                    &format!("[scoped {profile}] {query}"),
                    &hostile_sql,
                    &benign_sql,
                    template.contains("{N}") && !payload.contains('.'),
                );
            }
        }
    }
}

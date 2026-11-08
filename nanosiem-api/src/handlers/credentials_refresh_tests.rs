// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4914: the rotation response never confuses "could not refresh the
//! bound sources" with "no bound sources".

use super::*;

fn refresh(outcome: CredentialRefreshOutcome) -> CredentialRefresh {
    CredentialRefresh { source_configuration_id: Uuid::now_v7(), name: "s3".into(), outcome }
}

#[test]
fn an_enumeration_failure_is_a_partial_failure_not_an_empty_success() {
    let report = source_refresh_report(Err("db down".into()));
    assert_eq!(report.status, SourceRefreshStatus::PartialFailure);
    assert!(report.results.is_empty());
    assert_eq!(report.error.as_deref(), Some("db down"));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["status"], "partial_failure");
}

#[test]
fn no_bound_sources_is_none_and_all_redeployed_is_complete() {
    assert_eq!(source_refresh_report(Ok(vec![])).status, SourceRefreshStatus::None);
    let ok = source_refresh_report(Ok(vec![refresh(CredentialRefreshOutcome::Redeployed)]));
    assert_eq!(ok.status, SourceRefreshStatus::Complete);
    assert_eq!(ok.results[0].outcome, "redeployed");
}

#[test]
fn a_pending_edit_or_failure_makes_the_refresh_partial() {
    for outcome in [
        CredentialRefreshOutcome::PendingEdits,
        CredentialRefreshOutcome::NoDeployedSnapshot,
        CredentialRefreshOutcome::Failed("boom".into()),
    ] {
        let r = source_refresh_report(Ok(vec![refresh(CredentialRefreshOutcome::Redeployed), refresh(outcome.clone())]));
        assert_eq!(r.status, SourceRefreshStatus::PartialFailure, "{outcome:?}");
        assert!(r.results[1].message.is_some());
    }
}

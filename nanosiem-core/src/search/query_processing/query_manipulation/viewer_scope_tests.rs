// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5612: the leading `dataset=` selector and the viewer-scope gate every
//! nPL path of the search service runs.

use super::{enforce_viewer_scope, resolve_dataset_selector};
use crate::auth::ScopeSet;
use crate::search::service::sql_only_service_for_tests;
use crate::{SearchError, TimeRangeInput};

fn sel(q: &str, d: Option<&str>) -> (String, Option<String>) {
    resolve_dataset_selector(q, d).unwrap_or_else(|e| panic!("{q}: {e}"))
}

#[test]
fn a_leading_dataset_token_selects_the_dataset() {
    assert_eq!(
        sel("dataset=signals | timechart span=1h count by severity", None),
        ("| timechart span=1h count by severity".into(), Some("signals".into()))
    );
    assert_eq!(sel("dataset=risk", None), ("*".into(), Some("risk".into())));
    assert_eq!(sel("  DATASET=Signals rule_name=x", None), ("rule_name=x".into(), Some("signals".into())));
    // The same dataset named twice just drops the redundant token.
    assert_eq!(sel("dataset=risk | head 1", Some("risk")), ("| head 1".into(), Some("risk".into())));
}

#[test]
fn anything_else_is_left_as_text() {
    for q in ["status=500", "dataset=\"signals\"", "dataset=bogus | head 1", "x dataset=signals", "dataset=signalsx"] {
        assert_eq!(sel(q, None), (q.to_string(), None), "{q}");
        assert_eq!(sel(q, Some("spans")).1.as_deref(), Some("spans"), "{q}");
    }
}

/// Review P3: an explicit request never changes meaning. Another dataset
/// (including an explicit `logs`) keeps the token as ordinary text.
#[test]
fn an_explicit_request_dataset_is_never_overridden() {
    for (q, d) in [("dataset=metrics host=x", "logs"), ("dataset=signals | head 1", "risk"), ("dataset=risk", "logs")] {
        assert_eq!(sel(q, Some(d)), (q.to_string(), Some(d.to_string())), "{q} / {d}");
    }
}

/// Review P2: a field filter that merely contains `dataset=signal…` is not a
/// dataset selector: plain logs searches and rules with such filters keep
/// working for a caller without detections:view.
#[test]
fn field_filters_that_look_like_the_selector_do_not_count() {
    use crate::search::touches_signals_dataset;
    for q in [
        "event.dataset=signalsciences.waf | stats count by src_endpoint.ip",
        "dataset=signal_sciences | stats count",
        "metadata.product.name=x event.dataset=signals",
        "message=\"dataset=signals\"",
    ] {
        assert!(!touches_signals_dataset(None, q), "{q}");
        assert!(!touches_signals_dataset(Some("logs"), q), "{q}");
        assert!(enforce_viewer_scope(q, Some("logs"), &denied()).is_ok(), "{q}");
    }
    for q in [
        "dataset=signals | stats count",
        "* | join risk_entity [dataset=signals | stats count by risk_entity]",
        "user IN [dataset=signal | table risk_entity]",
        "* | where user IN [dataset=signals | table risk_entity]",
    ] {
        assert!(touches_signals_dataset(None, q), "{q}");
    }
    // An explicit logs request keeps a leading token as a field filter.
    assert!(!touches_signals_dataset(Some("logs"), "dataset=signals | stats count"));
}

fn denied() -> ScopeSet {
    ScopeSet::unrestricted().with_signals_denied(true)
}

#[test]
fn the_gate_refuses_signals_without_detections_view_however_it_is_reached() {
    for (q, d) in [
        ("*", Some("signals")),
        ("* | join risk_entity [dataset=signals | stats count by risk_entity]", None),
        ("user IN [dataset=signals | table risk_entity]", Some("logs")),
    ] {
        assert!(matches!(enforce_viewer_scope(q, d, &denied()), Err(SearchError::Forbidden(_))), "{q}");
        assert!(enforce_viewer_scope(q, d, &ScopeSet::unrestricted()).is_ok(), "{q}");
    }
    // Other datasets and plain events are unaffected.
    for d in [None, Some("logs"), Some("risk"), Some("spans")] {
        assert!(enforce_viewer_scope("status=500", d, &denied()).is_ok());
    }
}

/// The gate is the service's, not a handler's: a caller that skips every
/// handler check (a dashboard panel, a report, an AI tool) still gets 403.
#[tokio::test]
async fn the_search_service_refuses_signals_for_a_denied_scope() {
    let svc = sql_only_service_for_tests("ocsf");
    let range = TimeRangeInput::new(
        chrono::DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
        chrono::DateTime::parse_from_rfc3339("2026-11-02T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
    );
    for (q, d) in [
        ("dataset=signals | stats count by rule_name", None),
        ("* | stats count by rule_name", Some("signals")),
    ] {
        let err = svc.explain(q, &range, false, d, &denied()).await.expect_err(q);
        assert!(matches!(err, SearchError::Forbidden(_)), "{q}: {err}");
        let sql = svc.explain(q, &range, false, d, &ScopeSet::unrestricted()).await.expect(q);
        assert!(sql.contains("FROM signals AS s") && sql.contains("UNION ALL"), "{q}: {sql}");
    }
    // The selector reaches risk too.
    let sql = svc
        .explain("dataset=risk | sort -score_24h | head 10", &range, false, None, &denied())
        .await
        .expect("risk");
    assert!(sql.contains("score_24h"), "{sql}");
}

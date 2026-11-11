// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4915 contract tests for the background-job HTTP surface that need no
//! database: the opt-in header, the 409 for unready pages, and the S5 "never a
//! silent empty 200" shape of a job answer.

use axum::extract::FromRequestParts;
use axum::http::{Request, StatusCode};

use super::*;
use crate::handlers::SearchResultResponse;

async fn accept_async(header: Option<&str>) -> bool {
    let mut builder = Request::builder().uri("/api/search");
    if let Some(value) = header {
        builder = builder.header(HEADER_ACCEPT_ASYNC, value);
    }
    let (mut parts, _) = builder.body(()).unwrap().into_parts();
    AcceptAsync::from_request_parts(&mut parts, &()).await.unwrap().0
}

#[tokio::test]
async fn job_answers_are_strictly_opt_in() {
    assert!(!accept_async(None).await, "no header → never a job answer");
    assert!(accept_async(Some("1")).await);
    assert!(accept_async(Some("true")).await);
    assert!(accept_async(Some(" TRUE ")).await);
    assert!(!accept_async(Some("0")).await, "explicit opt-out");
    assert!(!accept_async(Some("yes")).await, "only 1/true opt in");
}

#[test]
fn unready_job_pages_are_a_409_not_an_empty_page() {
    let err = SearchError::JobNotReady("Search job is still running".into());
    assert_eq!(err.status_code(), StatusCode::CONFLICT);
    assert_eq!(err.code(), "JOB_NOT_READY");
}

#[test]
fn a_job_answer_never_serializes_a_results_key() {
    // S5: a client reading `.results` off a job answer must get "absent", not
    // `[]` — an empty array is indistinguishable from "searched, no matches".
    let answer = SearchResultResponse::Async(AsyncSearchResponse {
        job_id: "sjob_01hzzzzzzzzzzzzzzzzzzzzzzz".into(),
        status: "queued".into(),
        attached: Some(false),
        origin: Some(JobOrigin::Escalated),
    });
    let json = serde_json::to_value(&answer).unwrap();
    assert!(json.get("results").is_none(), "job answer leaked a results key: {json}");
    assert!(json.get("total_count").is_none());
    assert_eq!(json["job_id"], "sjob_01hzzzzzzzzzzzzzzzzzzzzzzz");
    assert_eq!(json["origin"], "escalated");
    assert_eq!(json["attached"], false);
}

/// NAN-5277: a `| ai` search is never handed off to a background job (the
/// re-run repeated the model call and held a background worker for minutes).
#[test]
fn ai_searches_are_not_handoff_eligible() {
    assert!(!handoff_eligible(r#"class_uid=1007 | head 20 | ai prompt="Classify""#));
    assert!(!handoff_eligible(
        r#"* | ai prompt="Classify" | where ai_verdict="MALICIOUS""#
    ));
    assert!(handoff_eligible("* | stats count by class_uid"));
    assert!(handoff_eligible("class_uid=3002 | timechart span=1h count by user.name"));
    // An unparseable query keeps the existing behaviour.
    assert!(handoff_eligible("| | |"));
}
